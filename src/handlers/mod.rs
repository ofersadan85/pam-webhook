use pam::{PamHandle, PamItemType, PamReturnCode};
use serde::Serialize;
use std::ffi::{CStr, c_char, c_int};

pub(crate) mod hooks;
use hooks::PamHookType;

#[cfg(any(feature = "logging", feature = "webhook"))]
mod config;
#[cfg(feature = "logging")]
mod logging;
#[cfg(feature = "webhook")]
mod webhook;

#[derive(Debug, Serialize)]
pub(crate) struct PamContext {
    flags: c_int,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rhost: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ruser: Option<String>,
}

impl PamContext {
    pub(crate) fn from_pam_handle(pam_h: &mut PamHandle, flags: c_int) -> Self {
        Self {
            flags,
            service: Self::get_item(pam_h, PamItemType::Service),
            user: Self::get_item(pam_h, PamItemType::User),
            tty: Self::get_item(pam_h, PamItemType::TTY),
            rhost: Self::get_item(pam_h, PamItemType::RHost),
            ruser: Self::get_item(pam_h, PamItemType::RUser),
        }
    }

    /// Helper to get PAM items as Rust strings. Returns None if the item is not set or on error.
    fn get_item(pamh: &mut pam::PamHandle, item: pam::PamItemType) -> Option<String> {
        // Use the raw FFI directly to avoid the pam crate's assert!() that panics when
        // pam_get_item returns PAM_SUCCESS but the pointer is null (which legitimately
        // happens for unset items in a freshly created PAM session).
        let mut item_ptr: *const std::ffi::c_void = std::ptr::null();
        let rc = unsafe { pam::ffi::pam_get_item(pamh, item as c_int, &raw mut item_ptr) };
        if rc != pam::ffi::PAM_SUCCESS as c_int || item_ptr.is_null() {
            return None;
        }
        let value_ptr = item_ptr.cast::<c_char>();
        // SAFETY: pam_get_item returned PAM_SUCCESS *and* value_ptr is non-null.
        Some(
            unsafe { CStr::from_ptr(value_ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}

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

    fn handle_hook(&self, _hook_type: PamHookType, _ctx: &PamContext) -> PamReturnCode {
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

#[derive(Default)]
pub(crate) struct MultiHandler {
    handlers: Vec<Box<dyn PamEventHandler>>,
}

impl PamEventHandler for MultiHandler {
    #[allow(clippy::vec_init_then_push, unused)]
    fn from_args(args: &[String]) -> Self
    where
        Self: Sized + Default,
    {
        let mut handlers: Vec<Box<dyn PamEventHandler>> = Vec::new();
        #[cfg(feature = "logging")]
        handlers.push(Box::new(logging::LoggingHandler::from_args(args)));
        #[cfg(feature = "webhook")]
        handlers.push(Box::new(webhook::WebhookHandler::from_args(args)));
        Self { handlers }
    }

    fn handle_hook(&self, hook_type: PamHookType, ctx: &PamContext) -> PamReturnCode {
        for handler in &self.handlers {
            let result = handler.handle_hook(hook_type, ctx);
            if result != PamReturnCode::Success {
                return result;
            }
        }
        PamReturnCode::Success
    }
}

#[cfg(test)]
mod tests {
    use super::{PamEventHandler, parse_c_args};
    use std::ffi::{CString, c_char, c_int};

    #[derive(Debug, Default)]
    struct DummyHandler {
        argc_seen: usize,
    }

    impl PamEventHandler for DummyHandler {
        fn from_args(args: &[String]) -> Self {
            Self {
                argc_seen: args.len(),
            }
        }
    }

    #[test]
    fn parse_c_args_handles_nulls_and_invalid_utf8() {
        let normal = CString::new("config=/tmp/a.toml").expect("valid cstr");
        let invalid_utf8 =
            CString::from_vec_with_nul(vec![0xff, 0x00]).expect("invalid utf8 bytes");

        let argv = [
            normal.as_ptr(),
            std::ptr::null::<c_char>(),
            invalid_utf8.as_ptr(),
        ];

        // SAFETY: argv points to 3 stable C string pointers for the duration of the call.
        let parsed = unsafe { parse_c_args(3, argv.as_ptr()) };
        assert_eq!(parsed, vec!["config=/tmp/a.toml".to_string()]);
    }

    #[test]
    fn parse_c_args_handles_negative_argc() {
        // SAFETY: argv is null and argc is invalid/negative, function should handle gracefully.
        let parsed = unsafe { parse_c_args(-1, std::ptr::null()) };
        assert!(parsed.is_empty());
    }

    #[test]
    fn from_c_args_passes_parsed_args_to_from_args() {
        let arg1 = CString::new("a=1").expect("valid cstr");
        let arg2 = CString::new("b=2").expect("valid cstr");
        let arg_values = [arg1.as_ptr(), arg2.as_ptr()];

        // SAFETY: arg_values points to 2 valid C string pointers.
        let handler = unsafe { DummyHandler::from_c_args(2 as c_int, arg_values.as_ptr()) };
        assert_eq!(handler.argc_seen, 2);
    }
}
