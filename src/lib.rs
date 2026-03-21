use pam::{PamHandle, PamReturnCode};
use std::os::raw::{c_char, c_int};

mod handlers;
use handlers::{MultiHandler, PamEventHandler};

crate::create_hook!(pam_sm_authenticate);
crate::create_hook!(pam_sm_setcred);
crate::create_hook!(pam_sm_acct_mgmt);
crate::create_hook!(pam_sm_open_session);
crate::create_hook!(pam_sm_close_session);
crate::create_hook!(pam_sm_chauthtok);

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
