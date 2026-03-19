use crate::{
    config::from_toml_config_args,
    handlers::{PamEventHandler, get_item},
};
use pam::{PamHandle, PamItemType, PamReturnCode};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{ffi::c_int, fs::OpenOptions, io::Write as _, path::PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct WebhookHandler {
    pub(crate) log_path: Option<PathBuf>,
    pub(crate) webhook_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct HookPayload<'a> {
    hook: &'a str,
    flags: c_int,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rhost: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tty: Option<String>,
}

impl WebhookHandler {
    fn send_hook_call(
        &self,
        hook: &str,
        pam_h: &mut PamHandle,
        flags: c_int,
    ) -> Result<(), HookError> {
        let url = self.webhook_url.as_deref().unwrap_or_default();
        if url.is_empty() {
            return Err(HookError::MissingWebhookUrl);
        }
        let payload = HookPayload {
            hook,
            flags,
            user: get_item(pam_h, PamItemType::User),
            rhost: get_item(pam_h, PamItemType::RHost),
            tty: get_item(pam_h, PamItemType::TTY),
        };
        Client::new()
            .post(url)
            .json(&payload)
            .send()
            .inspect_err(|e| {
                let _ = self.log_error(e);
            })?
            .error_for_status()
            .inspect_err(|e| {
                let _ = self.log_error(e);
            })?;
        Ok(())
    }

    fn handle_hook(&self, hook: &str, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        match self.send_hook_call(hook, pam_h, flags) {
            Ok(()) => PamReturnCode::Success,
            Err(_) => PamReturnCode::Service_Err,
        }
    }

    fn log_error<E: std::fmt::Display>(&self, error: E) -> std::io::Result<()> {
        if let Some(path) = &self.log_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let now = chrono::Utc::now();
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|file| writeln!(&file, "{now} {error}"))?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum HookError {
    #[error("missing webhook_url in config")]
    MissingWebhookUrl,
    #[error(transparent)]
    Request(#[from] reqwest::Error),
}

impl PamEventHandler for WebhookHandler {
    fn from_args(args: &[String]) -> Self {
        from_toml_config_args(args)
    }

    fn authenticate(&self, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        self.handle_hook("pam_sm_authenticate", pam_h, flags)
    }

    fn setcred(&self, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        self.handle_hook("pam_sm_setcred", pam_h, flags)
    }

    fn acct_mgmt(&self, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        self.handle_hook("pam_sm_acct_mgmt", pam_h, flags)
    }

    fn open_session(&self, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        self.handle_hook("pam_sm_open_session", pam_h, flags)
    }

    fn close_session(&self, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        self.handle_hook("pam_sm_close_session", pam_h, flags)
    }

    fn chauthtok(&self, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        self.handle_hook("pam_sm_chauthtok", pam_h, flags)
    }
}

#[cfg(test)]
mod tests {
    use super::{HookError, WebhookHandler};
    use pam::{PamHandle, PamReturnCode};
    use std::{
        ffi::CString,
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        os::raw::{c_int, c_void},
        ptr, thread,
    };

    struct PamSession {
        handle: *mut PamHandle,
        _service: CString,
        _user: CString,
        _conv: pam::ffi::pam_conv,
    }

    impl PamSession {
        fn start() -> Self {
            let service = CString::new("login").expect("valid service");
            let user = CString::new("pam-webhook-test").expect("valid user");
            let conv = pam::ffi::pam_conv {
                conv: None,
                appdata_ptr: ptr::null_mut(),
            };

            let mut handle: *mut PamHandle = ptr::null_mut();
            // SAFETY: pointers are valid for call duration; PAM initializes `handle` on success.
            let rc = unsafe {
                pam::ffi::pam_start(
                    service.as_ptr(),
                    user.as_ptr(),
                    &raw const conv,
                    &raw mut handle,
                )
            };
            assert_eq!(
                rc,
                PamReturnCode::Success as c_int,
                "pam_start failed: {rc}"
            );
            assert!(!handle.is_null(), "pam_start returned null handle");

            Self {
                handle,
                _service: service,
                _user: user,
                _conv: conv,
            }
        }

        fn handle_mut(&mut self) -> &mut PamHandle {
            // SAFETY: `handle` is initialized by pam_start and kept valid until Drop.
            unsafe { &mut *self.handle }
        }

        fn set_item(&mut self, item_type: pam::PamItemType, value: &CString) {
            // SAFETY: handle is valid and value pointer lives through hook invocation.
            let rc = unsafe {
                pam::ffi::pam_set_item(
                    self.handle,
                    item_type as c_int,
                    value.as_ptr().cast::<c_void>(),
                )
            };
            assert_eq!(
                rc,
                PamReturnCode::Success as c_int,
                "pam_set_item failed: {rc}"
            );
        }
    }

    impl Drop for PamSession {
        fn drop(&mut self) {
            // SAFETY: handle was created by pam_start and can be released with pam_end.
            unsafe {
                pam::ffi::pam_end(self.handle, PamReturnCode::Success as c_int);
            }
        }
    }

    fn spawn_single_request_server(status: &str) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("get local addr");
        let status_line = status.to_string();

        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("read header");
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    content_length = value.trim().parse::<usize>().expect("parse content-length");
                }
            }

            let mut body = vec![0_u8; content_length];
            reader.read_exact(&mut body).expect("read body");

            let response =
                format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            stream.flush().expect("flush response");

            String::from_utf8(body).expect("body should be UTF-8 JSON")
        });

        (format!("http://{addr}"), join)
    }

    #[test]
    fn send_hook_call_errors_when_webhook_url_missing() {
        let handler = WebhookHandler::default();
        let mut session = PamSession::start();
        let err = handler
            .send_hook_call("pam_sm_authenticate", session.handle_mut(), 0)
            .expect_err("missing url should fail");
        match err {
            HookError::MissingWebhookUrl => {}
            HookError::Request(_) => panic!("expected missing-url error"),
        }
    }

    #[test]
    fn send_hook_call_posts_payload_and_succeeds_on_200() {
        let (url, join) = spawn_single_request_server("200 OK");
        let handler = WebhookHandler {
            log_path: None,
            webhook_url: Some(url),
        };

        let mut session = PamSession::start();
        let user = CString::new("alice").expect("cstr");
        let rhost = CString::new("10.0.0.9").expect("cstr");
        let tty = CString::new("pts/1").expect("cstr");
        session.set_item(pam::PamItemType::User, &user);
        session.set_item(pam::PamItemType::RHost, &rhost);
        session.set_item(pam::PamItemType::TTY, &tty);

        handler
            .send_hook_call("pam_sm_authenticate", session.handle_mut(), 42)
            .expect("200 response should succeed");

        let body = join.join().expect("server thread joined");
        assert!(body.contains("\"hook\":\"pam_sm_authenticate\""));
        assert!(body.contains("\"flags\":42"));
        assert!(body.contains("\"user\":\"alice\""));
        assert!(body.contains("\"rhost\":\"10.0.0.9\""));
        assert!(body.contains("\"tty\":\"pts/1\""));
    }

    #[test]
    fn send_hook_call_fails_on_non_success_status() {
        let (url, join) = spawn_single_request_server("500 Internal Server Error");
        let handler = WebhookHandler {
            log_path: None,
            webhook_url: Some(url),
        };
        let mut session = PamSession::start();
        let user = CString::new("alice").expect("cstr");
        let rhost = CString::new("10.0.0.9").expect("cstr");
        let tty = CString::new("pts/1").expect("cstr");
        session.set_item(pam::PamItemType::User, &user);
        session.set_item(pam::PamItemType::RHost, &rhost);
        session.set_item(pam::PamItemType::TTY, &tty);

        let err = handler
            .send_hook_call("pam_sm_open_session", session.handle_mut(), 1)
            .expect_err("non-success status must fail");
        match err {
            HookError::MissingWebhookUrl => panic!("expected request error"),
            HookError::Request(_) => {}
        }
        let _ = join.join().expect("server thread joined");
    }
}
