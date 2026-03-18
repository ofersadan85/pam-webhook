use pam::{PamHandle, PamItemType, PamReturnCode};
use std::{
    ffi::{CStr, c_char, c_int, c_void},
};

/// Trait defining the PAM event handlers. Each method corresponds to a PAM hook.
/// The default implementation of all of them is a no-op and just returns [`PamReturnCode::Success`].
pub(crate) trait PamEventHandler {
    /// Constructor from C args that have already been parsed into a Vec<String>
    /// The args are expected to be in the form "key=value", but this is not enforced by the type system.
    /// Use [`parse_c_args`] to parse raw C args into Vec<String>.
    fn from_args(args: &[String]) -> Self
    where
        Self: Sized + Default;

    /// Constructor from raw C args passed by PAM.
    /// This is a convenience wrapper around `from_args` that handles C string parsing.
    ///
    /// # Safety
    /// See safety in [`parse_c_args`]
    unsafe fn from_c_args(argc: c_int, argv: *const *const c_char) -> Self
    where
        Self: Sized + Default,
    {
        let args = unsafe { parse_c_args(argc, argv) };
        Self::from_args(&args)
    }

    /// Called by PAM during authentication (for example when sshd checks credentials).
    fn authenticate(&self, _pam_h: &mut PamHandle, _flags: c_int) -> PamReturnCode {
        PamReturnCode::Success
    }
    /// Called after authentication to establish, refresh, or delete credentials.
    fn setcred(&self, _pam_h: &mut PamHandle, _flags: c_int) -> PamReturnCode {
        PamReturnCode::Success
    }
    /// Called for account policy checks (expiration, access restrictions, time limits).
    fn acct_mgmt(&self, _pam_h: &mut PamHandle, _flags: c_int) -> PamReturnCode {
        PamReturnCode::Success
    }
    /// Called when a new session is opened (for sshd, after login succeeds).
    fn open_session(&self, _pam_h: &mut PamHandle, _flags: c_int) -> PamReturnCode {
        PamReturnCode::Success
    }
    /// Called when a session is closed (for sshd, on logout).
    fn close_session(&self, _pam_h: &mut PamHandle, _flags: c_int) -> PamReturnCode {
        PamReturnCode::Success
    }
    /// Called to change the user's authentication token (for example, when changing passwords).
    fn chauthtok(&self, _pam_h: &mut PamHandle, _flags: c_int) -> PamReturnCode {
        PamReturnCode::Success
    }
}

/// # Safety
/// This function reads raw C argument pointers passed by PAM.
/// Since PAM is very well tried and tested, we can assume this is safe and valid
/// as long as we handle null pointers and invalid UTF-8 gracefully,
/// which we do currently by skipping invalid entries.
#[allow(clippy::similar_names)]
unsafe fn parse_c_args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    let argc = usize::try_from(argc).unwrap_or(0);
    let mut result = Vec::new();
    if argc == 0 || argv.is_null() {
        return result;
    }
    for i in 0..argc {
        // Safety: argv is not null and has at least argc entries, so argv.add(i) *should* be valid for 0 <= i < argc.
        let arg_ptr = unsafe { *argv.add(i) };
        if arg_ptr.is_null() {
            continue;
        }
        // Safety: arg_ptr is not null and *should* be a valid C string pointer.
        let c_str = unsafe { CStr::from_ptr(arg_ptr) };
        let Ok(arg) = c_str.to_str() else {
            continue;
        };
        result.push(arg.to_string());
    }
    result
}

/// Helper to get PAM items as Rust strings. Returns None if the item is not set or on error.
pub(crate) fn get_item(pamh: &mut PamHandle, item: PamItemType) -> Option<String> {
    let Ok(value_ptr) = pam::get_item(pamh, item) else {
        return None;
    };
    let value_ptr = std::ptr::from_ref::<c_void>(value_ptr).cast::<c_char>();
    Some(
        // SAFETY: pam_get_item returned PAM_SUCCESS and value_ptr was checked for null.
        unsafe { CStr::from_ptr(value_ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}
