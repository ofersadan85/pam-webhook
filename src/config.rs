use crate::handlers::{PamEventHandler, get_item};
use pam_sys::{PamHandle, PamItemType};
use serde::Deserialize;
use std::{
    ffi::c_int,
    fmt::Write as _,
    fs::{OpenOptions, read_to_string},
    io::Write as _,
    path::PathBuf,
};

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Config {
    pub(crate) log_path: Option<PathBuf>,
}

impl Config {
    pub(crate) fn append_log_line(&self, line: &str) -> std::io::Result<()> {
        if let Some(path) = &self.log_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|file| writeln!(&file, "{line}"))
                .inspect_err(|e| {
                    eprintln!(
                        "[pam-webhook] failed to write log file path={} error={e} line={line}",
                        path.display()
                    );
                })?;
        }
        Ok(())
    }

    pub(crate) fn log_hook_call(
        &self,
        hook: &str,
        pam_h: &mut PamHandle,
        flags: c_int,
    ) -> Result<(), std::io::Error> {
        // Placeholder diagnostics for future webhook integration. Keep secrets out.
        let now = chrono::Utc::now();
        let user = get_item(pam_h, PamItemType::USER).unwrap_or_default();
        let mut log_line = format!("[pam-webhook] time={now} hook={hook} flags={flags}",);
        if !user.is_empty() {
            write!(log_line, " user={user:?}").ok();
        }
        let rhost = get_item(pam_h, PamItemType::RHOST).unwrap_or_default();
        if !rhost.is_empty() {
            write!(log_line, " rhost={rhost:?}").ok();
        }
        let tty = get_item(pam_h, PamItemType::TTY).unwrap_or_default();
        if !tty.is_empty() {
            write!(log_line, " tty={tty:?}").ok();
        }
        self.append_log_line(&log_line)
    }
}

impl PamEventHandler for Config {
    fn from_args(args: &[String]) -> Self {
        let mut config = Config::default();
        for arg in args {
            if let Some(path) = arg.strip_prefix("config=") {
                let path = PathBuf::from(path);
                let file_text = read_to_string(&path);
                if let Ok(text) = file_text {
                    if let Ok(parsed) = toml::from_str(&text) {
                        config = parsed;
                    } else {
                        eprintln!(
                            "[pam-webhook] {} failed to parse config from {}",
                            chrono::Utc::now(),
                            path.display()
                        );
                    }
                } else {
                    eprintln!(
                        "[pam-webhook] {} failed to read config from {}",
                        chrono::Utc::now(),
                        path.display()
                    );
                }
            }
        }
        config
    }

    fn authenticate(&self, pam_h: &mut PamHandle, flags: c_int) -> pam_sys::PamReturnCode {
        match self.log_hook_call("pam_sm_authenticate", pam_h, flags) {
            Ok(()) => pam_sys::PamReturnCode::SUCCESS,
            Err(_) => pam_sys::PamReturnCode::SERVICE_ERR,
        }
    }

    fn setcred(&self, pam_h: &mut PamHandle, flags: c_int) -> pam_sys::PamReturnCode {
        match self.log_hook_call("pam_sm_setcred", pam_h, flags) {
            Ok(()) => pam_sys::PamReturnCode::SUCCESS,
            Err(_) => pam_sys::PamReturnCode::SERVICE_ERR,
        }
    }

    fn acct_mgmt(&self, pam_h: &mut PamHandle, flags: c_int) -> pam_sys::PamReturnCode {
        match self.log_hook_call("pam_sm_acct_mgmt", pam_h, flags) {
            Ok(()) => pam_sys::PamReturnCode::SUCCESS,
            Err(_) => pam_sys::PamReturnCode::SERVICE_ERR,
        }
    }

    fn open_session(&self, pam_h: &mut PamHandle, flags: c_int) -> pam_sys::PamReturnCode {
        match self.log_hook_call("pam_sm_open_session", pam_h, flags) {
            Ok(()) => pam_sys::PamReturnCode::SUCCESS,
            Err(_) => pam_sys::PamReturnCode::SERVICE_ERR,
        }
    }

    fn close_session(&self, pam_h: &mut PamHandle, flags: c_int) -> pam_sys::PamReturnCode {
        match self.log_hook_call("pam_sm_close_session", pam_h, flags) {
            Ok(()) => pam_sys::PamReturnCode::SUCCESS,
            Err(_) => pam_sys::PamReturnCode::SERVICE_ERR,
        }
    }

    fn chauthtok(&self, pam_h: &mut PamHandle, flags: c_int) -> pam_sys::PamReturnCode {
        match self.log_hook_call("pam_sm_chauthtok", pam_h, flags) {
            Ok(()) => pam_sys::PamReturnCode::SUCCESS,
            Err(_) => pam_sys::PamReturnCode::SERVICE_ERR,
        }
    }
}
