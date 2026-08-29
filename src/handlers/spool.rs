use crate::handlers::{
    PamContext, PamEventHandler, config::from_toml_config_args, hooks::PamHookType,
};
use chrono::Utc;
use hostname::get as get_hostname;
use pam::PamReturnCode;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

const DEFAULT_FLUSH_INTERVAL_MINUTES: u64 = 5;

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct SpoolHandler {
    pub(crate) spool_path: Option<PathBuf>,
    pub(crate) webhook_url: Option<String>,
    pub(crate) flush_interval_minutes: Option<u64>,
    #[serde(default)]
    pub(crate) exclude_rhosts: Vec<String>,
    #[serde(default)]
    pub(crate) exclude_users: Vec<String>,
    pub(crate) log_path: Option<PathBuf>,
}

/// A single event record written to the spool file as a JSON line.
#[derive(Debug, Serialize)]
struct SpoolEntry<'a> {
    hook: &'a str,
    hostname: String,
    timestamp: String,
    #[serde(flatten)]
    context: &'a PamContext,
}

impl SpoolHandler {
    fn is_excluded(&self, user: Option<&str>, rhost: Option<&str>) -> bool {
        rhost.is_some_and(|value| self.exclude_rhosts.iter().any(|excluded| excluded == value))
            || user.is_some_and(|value| self.exclude_users.iter().any(|excluded| excluded == value))
    }

    fn log_error<E: std::fmt::Display>(&self, error: E) -> std::io::Result<()> {
        if let Some(path) = &self.log_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let now = Utc::now();
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|file| writeln!(&file, "{now} {error}"))?;
        }
        Ok(())
    }

    /// Returns the path of the flush-marker file for the given spool file.
    fn flush_marker_path(spool_path: &Path) -> PathBuf {
        let file_name = spool_path
            .file_name()
            .map(|n| format!("{}.flush", n.to_string_lossy()))
            .unwrap_or_else(|| "spool.flush".to_string());
        spool_path.with_file_name(file_name)
    }

    fn read_last_flush(spool_path: &Path) -> Option<i64> {
        fs::read_to_string(Self::flush_marker_path(spool_path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    fn write_last_flush(spool_path: &Path) {
        let _ = fs::write(
            Self::flush_marker_path(spool_path),
            Utc::now().timestamp().to_string(),
        );
    }

    /// Returns `true` when enough time has elapsed since the last successful flush.
    fn should_flush(&self, spool_path: &Path) -> bool {
        let interval = self
            .flush_interval_minutes
            .unwrap_or(DEFAULT_FLUSH_INTERVAL_MINUTES);
        let threshold = i64::try_from(interval)
            .unwrap_or(i64::MAX)
            .saturating_mul(60);
        let now = Utc::now().timestamp();
        match Self::read_last_flush(spool_path) {
            None => true,
            Some(last) => (now - last) >= threshold,
        }
    }

    /// Append one JSON-line entry to the spool file, creating parent directories as needed.
    fn append_spool_entry(&self, spool_path: &Path, entry: &SpoolEntry<'_>) -> std::io::Result<()> {
        if let Some(parent) = spool_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(spool_path)
            .and_then(|file| writeln!(&file, "{json}"))
    }

    /// Attempt to flush all spooled entries to the webhook.
    ///
    /// On success, removes exactly the entries that were sent while preserving any
    /// new entries that were appended to the file during the HTTP round-trip.
    /// Errors are logged but do not propagate — the caller always returns `Success`.
    fn try_flush(&self, spool_path: &Path) {
        let url = match self.webhook_url.as_deref() {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => return,
        };

        let content = match fs::read_to_string(spool_path) {
            Ok(c) => c,
            Err(e) => {
                let _ = self.log_error(format!("spool read error: {e}"));
                return;
            }
        };

        let lines_to_send: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        let num_to_send = lines_to_send.len();

        if num_to_send == 0 {
            Self::write_last_flush(spool_path);
            return;
        }

        let mut entries: Vec<serde_json::Value> = Vec::with_capacity(lines_to_send.len());
        for line in &lines_to_send {
            match serde_json::from_str(line) {
                Ok(v) => entries.push(v),
                Err(e) => {
                    let _ =
                        self.log_error(format!("spool parse error (line will be discarded): {e}"));
                }
            }
        }

        let response = Client::new()
            .post(&url)
            .json(&entries)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status);

        match response {
            Ok(_) => match self.remove_sent_lines(spool_path, num_to_send) {
                Ok(()) => Self::write_last_flush(spool_path),
                Err(e) => {
                    let _ = self.log_error(format!("spool update error after flush: {e}"));
                }
            },
            Err(e) => {
                let _ = self.log_error(format!("spool flush error: {e}"));
            }
        }
    }

    /// Re-read the spool file and drop the first `num_sent` non-empty lines, keeping any
    /// lines that arrived after we started the HTTP request.
    fn remove_sent_lines(&self, spool_path: &Path, num_sent: usize) -> std::io::Result<()> {
        let current = fs::read_to_string(spool_path)?;
        let remaining: Vec<&str> = current
            .lines()
            .filter(|l| !l.trim().is_empty())
            .skip(num_sent)
            .collect();
        if remaining.is_empty() {
            fs::write(spool_path, "")
        } else {
            fs::write(spool_path, remaining.join("\n") + "\n")
        }
    }
}

impl PamEventHandler for SpoolHandler {
    fn from_args(args: &[String]) -> Self {
        from_toml_config_args(args)
    }

    fn handle_hook(&self, hook_type: PamHookType, ctx: &PamContext) -> PamReturnCode {
        let Some(spool_path) = &self.spool_path else {
            return PamReturnCode::Success;
        };

        let user = ctx.user.as_deref();
        let rhost = ctx.rhost.as_deref();
        if self.is_excluded(user, rhost) {
            return PamReturnCode::Success;
        }

        let entry = SpoolEntry {
            hook: hook_type.as_str(),
            hostname: get_hostname()
                .ok()
                .and_then(|name| name.into_string().ok())
                .unwrap_or_default(),
            timestamp: Utc::now().to_rfc3339(),
            context: ctx,
        };

        if let Err(e) = self.append_spool_entry(spool_path, &entry) {
            let _ = self.log_error(format!("spool write error: {e}"));
            return PamReturnCode::Service_Err;
        }

        // Best-effort flush — errors are logged but do not fail the hook.
        if self.should_flush(spool_path) {
            self.try_flush(spool_path);
        }

        PamReturnCode::Success
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
    fn handle_hook_is_noop_when_spool_path_missing() {
        let handler = SpoolHandler::default();
        let mut session = PamSession::start();
        let context = PamContext::from_pam_handle(session.handle_mut(), 0);
        assert_eq!(
            handler.handle_hook(PamHookType::Authenticate, &context),
            PamReturnCode::Success,
            "missing spool_path should be a no-op"
        );
    }

    #[test]
    fn append_spool_entry_creates_parent_dirs_and_writes_json() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spool_path = tmp.path().join("nested/dir/spool.ndjson");
        let handler = SpoolHandler {
            spool_path: Some(spool_path.clone()),
            ..Default::default()
        };
        let mut session = PamSession::start();
        let context = PamContext::from_pam_handle(session.handle_mut(), 7);
        assert_eq!(
            handler.handle_hook(PamHookType::Authenticate, &context),
            PamReturnCode::Success,
            "should write spool entry"
        );

        let content = std::fs::read_to_string(&spool_path).expect("read spool file");
        assert!(
            content.contains("pam_sm_authenticate"),
            "spool entry should contain hook name"
        );
        // Each line must be valid JSON.
        for line in content.lines() {
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "each spool line should be valid JSON: {line}"
            );
        }
    }

    #[test]
    fn should_flush_returns_true_when_no_marker_file() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spool_path = tmp.path().join("spool.ndjson");
        let handler = SpoolHandler {
            flush_interval_minutes: Some(5),
            ..Default::default()
        };
        assert!(
            handler.should_flush(&spool_path),
            "no marker file means flush is overdue"
        );
    }

    #[test]
    fn should_flush_returns_false_when_recently_flushed() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spool_path = tmp.path().join("spool.ndjson");
        SpoolHandler::write_last_flush(&spool_path);
        let handler = SpoolHandler {
            flush_interval_minutes: Some(5),
            ..Default::default()
        };
        assert!(
            !handler.should_flush(&spool_path),
            "just-flushed marker should suppress flush"
        );
    }

    #[test]
    fn remove_sent_lines_keeps_new_lines_appended_after_read() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spool_path = tmp.path().join("spool.ndjson");
        std::fs::write(
            &spool_path,
            "{\"hook\":\"pam_sm_authenticate\"}\n{\"hook\":\"pam_sm_open_session\"}\n{\"hook\":\"pam_sm_close_session\"}\n",
        )
        .expect("write spool");
        let handler = SpoolHandler::default();
        // Pretend we sent the first 2 lines.
        handler
            .remove_sent_lines(&spool_path, 2)
            .expect("remove sent lines");
        let content = std::fs::read_to_string(&spool_path).expect("read spool");
        assert!(
            content.contains("pam_sm_close_session"),
            "third entry should be kept"
        );
        assert!(
            !content.contains("pam_sm_authenticate"),
            "first entry should be removed"
        );
        assert!(
            !content.contains("pam_sm_open_session"),
            "second entry should be removed"
        );
    }

    #[test]
    fn flush_posts_batch_and_clears_spool_on_200() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spool_path = tmp.path().join("spool.ndjson");
        std::fs::write(
            &spool_path,
            "{\"hook\":\"pam_sm_authenticate\"}\n{\"hook\":\"pam_sm_open_session\"}\n",
        )
        .expect("write spool");

        let (url, join) = spawn_single_request_server("200 OK");
        let handler = SpoolHandler {
            spool_path: Some(spool_path.clone()),
            webhook_url: Some(url),
            flush_interval_minutes: Some(0),
            ..Default::default()
        };
        handler.try_flush(&spool_path);

        let body = join.join().expect("server thread");
        // Sent as a JSON array.
        assert!(body.starts_with('['), "body should be a JSON array");
        assert!(body.contains("pam_sm_authenticate"));
        assert!(body.contains("pam_sm_open_session"));

        let remaining = std::fs::read_to_string(&spool_path).expect("read spool after flush");
        assert!(
            remaining.trim().is_empty(),
            "spool should be empty after successful flush"
        );
    }

    #[test]
    fn flush_preserves_spool_on_server_error() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spool_path = tmp.path().join("spool.ndjson");
        std::fs::write(&spool_path, "{\"hook\":\"pam_sm_authenticate\"}\n").expect("write spool");

        let (url, join) = spawn_single_request_server("500 Internal Server Error");
        let handler = SpoolHandler {
            spool_path: Some(spool_path.clone()),
            webhook_url: Some(url),
            flush_interval_minutes: Some(0),
            ..Default::default()
        };
        handler.try_flush(&spool_path);
        let _ = join.join().expect("server thread");

        let remaining = std::fs::read_to_string(&spool_path).expect("read spool after error");
        assert!(
            remaining.contains("pam_sm_authenticate"),
            "spool should be preserved after failed flush"
        );
    }

    #[test]
    fn is_excluded_uses_or_semantics() {
        let handler = SpoolHandler {
            exclude_rhosts: vec!["10.0.0.9".to_string()],
            exclude_users: vec!["alice".to_string()],
            ..Default::default()
        };
        assert!(handler.is_excluded(Some("alice"), Some("10.0.0.10")));
        assert!(handler.is_excluded(Some("bob"), Some("10.0.0.9")));
        assert!(!handler.is_excluded(Some("bob"), Some("10.0.0.10")));
    }

    #[test]
    fn handle_hook_skips_when_user_is_excluded() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spool_path = tmp.path().join("spool.ndjson");
        let handler = SpoolHandler {
            spool_path: Some(spool_path.clone()),
            exclude_users: vec!["alice".to_string()],
            ..Default::default()
        };
        let mut session = PamSession::start();
        let user = CString::new("alice").expect("cstr");
        session.set_item(pam::PamItemType::User, &user);
        let context = PamContext::from_pam_handle(session.handle_mut(), 0);
        assert_eq!(
            handler.handle_hook(PamHookType::Authenticate, &context),
            PamReturnCode::Success,
            "excluded user should be skipped"
        );
        assert!(
            !spool_path.exists(),
            "spool file should not be created for excluded user"
        );
    }
}
