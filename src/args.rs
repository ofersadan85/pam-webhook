use std::ffi::{CStr, c_char, c_int};

#[allow(clippy::similar_names)]
pub(crate) unsafe fn parse_args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    let mut args = Vec::new();
    let argc = usize::try_from(argc).unwrap_or(0);
    for i in 0..argc {
        let arg_ptr = unsafe { *argv.add(i) };
        if !arg_ptr.is_null() {
            let c_str = unsafe { CStr::from_ptr(arg_ptr) };
            if let Ok(str_slice) = c_str.to_str() {
                args.push(str_slice.to_string());
            }
        }
    }
    args
}
