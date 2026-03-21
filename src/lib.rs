use pam::{PamHandle, PamReturnCode};
use std::os::raw::{c_char, c_int};

mod handlers;
use handlers::{MultiHandler, PamContext, PamEventHandler};

/// Macro to create PAM hooks with a consistent pattern
macro_rules! create_hook {
    ($target:ident) => {
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
            let handler = unsafe { MultiHandler::from_c_args(argc, argv) };
            if pamh.is_null() {
                PamReturnCode::Service_Err as c_int
            } else {
                // Safety: We checked pamh for null above
                // and PAM guarantees that the pointer will be valid for the duration of the call
                // Also, we won't actually do any mutations, we'll only use it to *read* PAM items
                // and pass a shared context to the handlers
                let pam_h = unsafe { &mut *pamh };
                if let Ok(hook_type) = stringify!($target).parse() {
                    let ctx = PamContext::from_pam_handle(pam_h, flags);
                    handler.handle_hook(hook_type, &ctx) as c_int
                } else {
                    PamReturnCode::Service_Err as c_int
                }
            }
        }
    };
}

create_hook!(pam_sm_authenticate);
create_hook!(pam_sm_setcred);
create_hook!(pam_sm_acct_mgmt);
create_hook!(pam_sm_open_session);
create_hook!(pam_sm_close_session);
create_hook!(pam_sm_chauthtok);

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    type ExternHookFn =
        unsafe extern "C" fn(*mut PamHandle, c_int, c_int, *const *const c_char) -> c_int;

    fn assert_null_handle_returns_service_err(hook: ExternHookFn) {
        // SAFETY: FFI hook is expected to handle null pamh safely and return service error.
        let rc = unsafe { hook(ptr::null_mut(), 0, 0, ptr::null()) };
        assert_eq!(rc, PamReturnCode::Service_Err as c_int);
    }

    #[test]
    fn all_hooks_return_service_err_for_null_handle() {
        assert_null_handle_returns_service_err(pam_sm_authenticate);
        assert_null_handle_returns_service_err(pam_sm_setcred);
        assert_null_handle_returns_service_err(pam_sm_acct_mgmt);
        assert_null_handle_returns_service_err(pam_sm_open_session);
        assert_null_handle_returns_service_err(pam_sm_close_session);
        assert_null_handle_returns_service_err(pam_sm_chauthtok);
    }
}
