use crate::handlers::{
    PamEventHandler, config::from_toml_config_args, get_item, hooks::PamHookType,
};
use hostname::get as get_hostname;
use pam::{PamHandle, PamItemType, PamReturnCode};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{ffi::c_int, fs::OpenOptions, io::Write as _, path::PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct WebhookHandler {
    pub(crate) log_path: Option<PathBuf>,
    pub(crate) webhook_url: Option<String>,
    #[serde(default)]
    pub(crate) exclude_rhosts: Vec<String>,
    #[serde(default)]
    pub(crate) exclude_users: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HookPayload<'a> {
    hook: &'a str,
    flags: c_int,
    hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rhost: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tty: Option<String>,
}

impl WebhookHandler {
    fn is_excluded(&self, user: Option<&str>, rhost: Option<&str>) -> bool {
        rhost.is_some_and(|value| self.exclude_rhosts.iter().any(|excluded| excluded == value))
            || user.is_some_and(|value| self.exclude_users.iter().any(|excluded| excluded == value))
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

impl PamEventHandler for WebhookHandler {
    fn from_args(args: &[String]) -> Self {
        from_toml_config_args(args)
    }

    fn handle_hook(
        &self,
        hook_type: PamHookType,
        pam_h: &mut PamHandle,
        flags: c_int,
    ) -> PamReturnCode {
        let url = self.webhook_url.as_deref().unwrap_or_default();
        if url.is_empty() {
            return PamReturnCode::Service_Err;
        }

        let user = get_item(pam_h, PamItemType::User);
        let rhost = get_item(pam_h, PamItemType::RHost);
        if self.is_excluded(user.as_deref(), rhost.as_deref()) {
            return PamReturnCode::Success;
        }
        let payload = HookPayload {
            hook: hook_type.as_str(),
            flags,
            hostname: get_hostname()
                .ok()
                .and_then(|name| name.into_string().ok())
                .unwrap_or_default(),
            user,
            rhost,
            tty: get_item(pam_h, PamItemType::TTY),
        };

        let response = Client::new()
            .post(url)
            .json(&payload)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status);
        match response {
            Ok(_) => PamReturnCode::Success,
            Err(e) => {
                let _ = self.log_error(e);
                PamReturnCode::Service_Err
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn send_hook_call_fails_when_webhook_url_missing() {
        let handler = WebhookHandler::default();
        let mut session = PamSession::start();

        assert_eq!(
            handler.handle_hook(PamHookType::Authenticate, session.handle_mut(), 0),
            PamReturnCode::Service_Err,
            "missing url should fail"
        );
    }

    #[test]
    fn send_hook_call_posts_payload_and_succeeds_on_200() {
        let (url, join) = spawn_single_request_server("200 OK");
        let handler = WebhookHandler {
            log_path: None,
            webhook_url: Some(url),
            exclude_rhosts: Vec::new(),
            exclude_users: Vec::new(),
        };

        let mut session = PamSession::start();
        let user = CString::new("alice").expect("cstr");
        let rhost = CString::new("10.0.0.9").expect("cstr");
        let tty = CString::new("pts/1").expect("cstr");
        session.set_item(pam::PamItemType::User, &user);
        session.set_item(pam::PamItemType::RHost, &rhost);
        session.set_item(pam::PamItemType::TTY, &tty);

        assert_eq!(
            handler.handle_hook(PamHookType::Authenticate, session.handle_mut(), 42),
            PamReturnCode::Success,
            "200 response should succeed"
        );

        let body = join.join().expect("server thread joined");
        assert!(body.contains("\"hook\":\"pam_sm_authenticate\""));
        assert!(body.contains("\"flags\":42"));
        assert!(body.contains("\"hostname\":"));
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
            exclude_rhosts: Vec::new(),
            exclude_users: Vec::new(),
        };
        let mut session = PamSession::start();
        let user = CString::new("alice").expect("cstr");
        let rhost = CString::new("10.0.0.9").expect("cstr");
        let tty = CString::new("pts/1").expect("cstr");
        session.set_item(pam::PamItemType::User, &user);
        session.set_item(pam::PamItemType::RHost, &rhost);
        session.set_item(pam::PamItemType::TTY, &tty);

        assert_eq!(
            handler.handle_hook(PamHookType::OpenSession, session.handle_mut(), 1),
            PamReturnCode::Service_Err,
            "non-success status must fail"
        );
        let _ = join.join().expect("server thread joined");
    }

    #[test]
    fn send_hook_call_skips_when_rhost_is_excluded() {
        let handler = WebhookHandler {
            log_path: None,
            webhook_url: Some("http://127.0.0.1:9".to_string()),
            exclude_rhosts: vec!["10.0.0.9".to_string()],
            exclude_users: vec!["bob".to_string()],
        };
        let mut session = PamSession::start();
        let user = CString::new("alice").expect("cstr");
        let rhost = CString::new("10.0.0.9").expect("cstr");
        session.set_item(pam::PamItemType::User, &user);
        session.set_item(pam::PamItemType::RHost, &rhost);

        assert_eq!(
            handler.handle_hook(PamHookType::OpenSession, session.handle_mut(), 1),
            PamReturnCode::Success,
            "excluded rhost should skip webhook call"
        );
    }

    #[test]
    fn send_hook_call_skips_when_user_is_excluded() {
        let handler = WebhookHandler {
            log_path: None,
            webhook_url: Some("http://127.0.0.1:9".to_string()),
            exclude_rhosts: vec!["10.0.0.9".to_string()],
            exclude_users: vec!["alice".to_string()],
        };
        let mut session = PamSession::start();
        let user = CString::new("alice").expect("cstr");
        let rhost = CString::new("10.0.0.10").expect("cstr");
        session.set_item(pam::PamItemType::User, &user);
        session.set_item(pam::PamItemType::RHost, &rhost);

        assert_eq!(
            handler.handle_hook(PamHookType::OpenSession, session.handle_mut(), 1),
            PamReturnCode::Success,
            "excluded user should skip webhook call"
        );
    }

    #[test]
    fn exclusion_uses_or_semantics() {
        let handler = WebhookHandler {
            log_path: None,
            webhook_url: Some("http://127.0.0.1:9".to_string()),
            exclude_rhosts: vec!["10.0.0.9".to_string()],
            exclude_users: vec!["alice".to_string()],
        };

        assert!(handler.is_excluded(Some("alice"), Some("10.0.0.10")));
        assert!(handler.is_excluded(Some("bob"), Some("10.0.0.9")));
        assert!(!handler.is_excluded(Some("bob"), Some("10.0.0.10")));
    }
}
