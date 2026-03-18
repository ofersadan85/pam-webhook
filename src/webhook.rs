use crate::{
    config::from_toml_config_args,
    handlers::{PamEventHandler, get_item},
};
use pam::{PamHandle, PamItemType, PamReturnCode};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::ffi::c_int;

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct WebhookHandler {
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
            .send()?
            .error_for_status()?;
        Ok(())
    }

    fn handle_hook(&self, hook: &str, pam_h: &mut PamHandle, flags: c_int) -> PamReturnCode {
        match self.send_hook_call(hook, pam_h, flags) {
            Ok(()) => PamReturnCode::Success,
            Err(err) => {
                eprintln!(
                    "[pam-webhook] {} webhook request failed hook={hook} error={err}",
                    chrono::Utc::now()
                );
                PamReturnCode::Service_Err
            }
        }
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
