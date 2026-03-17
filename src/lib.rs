use std::os::raw::{c_char, c_int};

use std::ffi::{CStr, c_void};
use std::ptr;

use pam_sys::raw::pam_get_item;
use pam_sys::{PamHandle, PamItemType, PamReturnCode};

mod args;
use args::parse_args;

/// Called by PAM during authentication (for example when sshd checks credentials).
///
/// # Safety
/// This function is called by PAM with pointers to C data. Inherently unsafe
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = unsafe { parse_args(argc, argv) };
    log_hook_call("pam_sm_authenticate", pamh, flags, &args);
    success_code()
}

/// Called after authentication to establish, refresh, or delete credentials.
///
/// # Safety
/// This function is called by PAM with pointers to C data. Inherently unsafe
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn pam_sm_setcred(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = unsafe { parse_args(argc, argv) };
    log_hook_call("pam_sm_setcred", pamh, flags, &args);
    success_code()
}

/// Called for account policy checks (expiration, access restrictions, time limits).
///
/// # Safety
/// This function is called by PAM with pointers to C data. Inherently unsafe
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = unsafe { parse_args(argc, argv) };
    log_hook_call("pam_sm_acct_mgmt", pamh, flags, &args);
    success_code()
}

/// Called when a new session is opened (for sshd, after login succeeds).
///
/// # Safety
/// This function is called by PAM with pointers to C data. Inherently unsafe
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = unsafe { parse_args(argc, argv) };
    log_hook_call("pam_sm_open_session", pamh, flags, &args);
    success_code()
}

/// Called when a session is closed (for sshd, when the user logs out/disconnects).
///
/// # Safety
/// This function is called by PAM with pointers to C data. Inherently unsafe
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = unsafe { parse_args(argc, argv) };
    log_hook_call("pam_sm_close_session", pamh, flags, &args);
    success_code()
}

/// Called when PAM needs token/password management (password change/update flow).
///
/// # Safety
/// This function is called by PAM with pointers to C data. Inherently unsafe
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let args = unsafe { parse_args(argc, argv) };
    log_hook_call("pam_sm_chauthtok", pamh, flags, &args);
    success_code()
}

// Linux-PAM service modules expose the six pam_sm_* hooks above; there are no
// additional Linux-specific service entrypoints to export for this module type.
fn log_hook_call(hook: &str, pamh: *mut PamHandle, flags: c_int, args: &[String]) {
    // Placeholder diagnostics for future webhook integration. Keep secrets out.
    let user = unsafe { get_item(pamh, PamItemType::USER) };
    let rhost = unsafe { get_item(pamh, PamItemType::RHOST) };
    let tty = unsafe { get_item(pamh, PamItemType::TTY) };
    eprintln!(
        "[pam-webhook] hook={hook} flags={flags} args={args:?} user={user:?} rhost={rhost:?} tty={tty:?}"
    );
}

fn success_code() -> c_int {
    PamReturnCode::SUCCESS as c_int
}

/// Helper to get PAM items as Rust strings. Returns None if the item is not set or on error.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers from PAM and assumes they are valid C strings.
/// The caller must ensure that `pamh` is a valid pointer and that the PAM item being requested is properly set and null-terminated.
unsafe fn get_item(pamh: *mut PamHandle, item: PamItemType) -> Option<String> {
    if pamh.is_null() {
        return None;
    }

    let mut value_ptr: *const c_void = ptr::null();
    let result = unsafe { pam_get_item(pamh.cast_const(), item as c_int, &raw mut value_ptr) };
    if result != PamReturnCode::SUCCESS as c_int || value_ptr.is_null() {
        return None;
    }

    Some(
        // SAFETY: pam_get_item returned PAM_SUCCESS and value_ptr was checked for null.
        unsafe { CStr::from_ptr(value_ptr.cast::<c_char>()) }
            .to_string_lossy()
            .into_owned(),
    )
}
