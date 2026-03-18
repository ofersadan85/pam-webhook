use pam::{PamHandle, PamReturnCode};
use std::os::raw::{c_char, c_int};

mod config;
mod handlers;
use handlers::PamEventHandler;
#[cfg(not(any(feature="logging", feature="webhook")))]
mod null;
#[cfg(all(feature = "logging", not(feature = "webhook")))]
mod logging;
#[cfg(feature = "webhook")]
mod webhook;

#[cfg(not(any(feature="logging", feature="webhook")))]
use null::NullHandler as ActiveHandler;
#[cfg(all(feature = "logging", not(feature = "webhook")))]
use logging::LoggingHandler as ActiveHandler;
#[cfg(feature = "webhook")]
use webhook::WebhookHandler as ActiveHandler;

macro_rules! apply_hook {
    ($hook:ident, $target:ident) => {
        /// Called by PAM during authentication (for example when sshd checks credentials).
        ///
        /// # Safety
        /// This function is called by PAM with pointers to C data. Inherently unsafe
        #[unsafe(no_mangle)]
        #[allow(clippy::similar_names)]
        pub unsafe extern "C" fn $target(
            pamh: *mut PamHandle,
            flags: c_int,
            argc: c_int,
            argv: *const *const c_char,
        ) -> c_int {
            let handler = unsafe { ActiveHandler::from_c_args(argc, argv) };
            if pamh.is_null() {
                PamReturnCode::Service_Err as c_int
            } else {
                // Safety: We checked pamh for null above
                // and PAM guarantees that the pointer will be valid for the duration of the call
                let pam_h = unsafe { &mut *pamh };
                handler.$hook(pam_h, flags) as c_int
            }
        }
    };
}

apply_hook!(authenticate, pam_sm_authenticate);
apply_hook!(setcred, pam_sm_setcred);
apply_hook!(acct_mgmt, pam_sm_acct_mgmt);
apply_hook!(open_session, pam_sm_open_session);
apply_hook!(close_session, pam_sm_close_session);
apply_hook!(chauthtok, pam_sm_chauthtok);
