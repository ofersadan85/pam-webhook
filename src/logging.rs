use crate::{
    config::from_toml_config_args,
    handlers::{PamEventHandler, get_item},
};
use pam::{PamHandle, PamItemType, PamReturnCode};
use serde::Deserialize;
use std::{ffi::c_int, fmt::Write as _, fs::OpenOptions, io::Write as _, path::PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct LoggingHandler {
    pub(crate) log_path: Option<PathBuf>,
}

impl LoggingHandler {
    fn append_log_line(&self, line: &str) -> std::io::Result<()> {
        if let Some(path) = &self.log_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|file| writeln!(&file, "{line}"))?;
        }
        Ok(())
    }

    fn log_hook_call(
        &self,
        hook: &str,
        pam_h: &mut PamHandle,
        flags: c_int,
    ) -> Result<(), std::io::Error> {
        let now = chrono::Utc::now();
        let user = get_item(pam_h, PamItemType::User).unwrap_or_default();
        let mut log_line = format!("[pam-webhook] time={now} hook={hook} flags={flags}");
        if !user.is_empty() {
            write!(log_line, " user={user:?}").ok();
        }
        let rhost = get_item(pam_h, PamItemType::RHost).unwrap_or_default();
        if !rhost.is_empty() {
            write!(log_line, " rhost={rhost:?}").ok();
        }
        let tty = get_item(pam_h, PamItemType::TTY).unwrap_or_default();
        if !tty.is_empty() {
            write!(log_line, " tty={tty:?}").ok();
        }
        self.append_log_line(&log_line)
    }

    fn handle_hook(&self, hook: &str, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        match self.log_hook_call(hook, pam_h, flags) {
            Ok(()) => PamReturnCode::Success,
            Err(_) => PamReturnCode::Service_Err,
        }
    }
}

impl PamEventHandler for LoggingHandler {
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
    use super::LoggingHandler;
    use tempfile::tempdir;

    #[test]
    fn append_log_line_creates_parent_dirs_and_appends() {
        let tmp = tempdir().expect("create temp dir");
        let log_path = tmp.path().join("nested/path/pam.log");
        let handler = LoggingHandler {
            log_path: Some(log_path.clone()),
        };

        handler.append_log_line("first").expect("append first line");
        handler
            .append_log_line("second")
            .expect("append second line");

        let content = std::fs::read_to_string(log_path).expect("read log file");
        assert!(content.contains("first"));
        assert!(content.contains("second"));
    }

    #[test]
    fn append_log_line_noop_when_log_path_missing() {
        let handler = LoggingHandler { log_path: None };
        handler
            .append_log_line("this line is intentionally ignored")
            .expect("none path should be a no-op");
    }
}
