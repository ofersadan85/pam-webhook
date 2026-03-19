use libloading::{Library, Symbol};
use pam::{PamHandle, PamReturnCode};
use std::{
    ffi::{CString, c_char, c_int},
    path::PathBuf,
    process::Command,
    ptr,
    sync::OnceLock,
};
#[cfg(feature = "webhook")]
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    thread,
};

type HookFn = unsafe extern "C" fn(*mut PamHandle, c_int, c_int, *const *const c_char) -> c_int;

const HOOKS: &[&str] = &[
    "pam_sm_authenticate",
    "pam_sm_setcred",
    "pam_sm_acct_mgmt",
    "pam_sm_open_session",
    "pam_sm_close_session",
    "pam_sm_chauthtok",
];

fn so_path() -> PathBuf {
    static SO_PATH: OnceLock<PathBuf> = OnceLock::new();
    SO_PATH
        .get_or_init(|| {
            let mut cmd = Command::new("cargo");
            cmd.arg("build").arg("--release");

            #[cfg(all(feature = "logging", not(feature = "webhook")))]
            {
                cmd.arg("--no-default-features")
                    .arg("--features")
                    .arg("logging");
            }

            #[cfg(not(any(feature = "logging", feature = "webhook")))]
            {
                cmd.arg("--no-default-features");
            }

            let status = cmd.status().expect("run cargo build --release");
            assert!(
                status.success(),
                "release build failed with status: {status}"
            );

            let mut candidates = vec![
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/libpam_webhook.so"),
            ];
            if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
                candidates.push(PathBuf::from(target_dir).join("release/libpam_webhook.so"));
            }
            if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
                candidates.push(PathBuf::from(cargo_home).join("target/release/libpam_webhook.so"));
            }
            if let Ok(home) = std::env::var("HOME") {
                candidates
                    .push(PathBuf::from(home).join(".cargo/target/release/libpam_webhook.so"));
            }

            candidates
                .into_iter()
                .find(|path| path.exists())
                .expect("libpam_webhook.so should exist in a Cargo target directory")
        })
        .clone()
}

fn load_release_library() -> Library {
    let path = so_path();
    // SAFETY: path points to the release cdylib produced by this package.
    unsafe { Library::new(path) }.expect("load libpam_webhook.so")
}

#[cfg(any(
    feature = "webhook",
    all(feature = "logging", not(feature = "webhook"))
))]
fn build_argv(args: &[String]) -> (Vec<CString>, Vec<*const c_char>) {
    let c_strings = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).expect("argv must be valid C strings"))
        .collect::<Vec<_>>();

    let arg_ptrs = c_strings.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    (c_strings, arg_ptrs)
}

fn load_hook<'lib>(lib: &'lib Library, name: &str) -> Symbol<'lib, HookFn> {
    let mut symbol = Vec::from(name.as_bytes());
    symbol.push(0);
    // SAFETY: symbol names are known exports from this cdylib and the expected signature matches module ABI.
    unsafe { lib.get::<HookFn>(&*symbol) }.expect("resolve hook symbol")
}

struct PamSession {
    handle: *mut PamHandle,
    _service: CString,
    _user: CString,
    _conv: pam::ffi::pam_conv,
}

impl PamSession {
    fn start() -> Self {
        let user = CString::new("pam-webhook-test").expect("valid user");
        let conv = pam::ffi::pam_conv {
            conv: None,
            appdata_ptr: ptr::null_mut(),
        };

        let service_names = ["login", "sshd", "su", "other"];
        for service_name in service_names {
            let service = CString::new(service_name).expect("valid service");
            let mut handle: *mut PamHandle = ptr::null_mut();
            // SAFETY: pointers remain valid for call duration, and handle out-pointer is initialized by PAM.
            let rc = unsafe {
                pam::ffi::pam_start(
                    service.as_ptr(),
                    user.as_ptr(),
                    &raw const conv,
                    &raw mut handle,
                )
            };
            if rc == PamReturnCode::Success as c_int && !handle.is_null() {
                return Self {
                    handle,
                    _service: service,
                    _user: user,
                    _conv: conv,
                };
            }
        }

        panic!("failed to create PAM handle with known service names");
    }

    #[cfg(not(any(feature = "logging", feature = "webhook")))]
    fn handle_mut(&mut self) -> &mut PamHandle {
        // SAFETY: `handle` is initialized by pam_start and released in Drop.
        unsafe { &mut *self.handle }
    }

    #[cfg(any(feature = "webhook", feature = "logging"))]
    fn set_item(&mut self, item_type: pam::PamItemType, value: &CString) {
        // SAFETY: handle is valid and the C string pointer remains valid across hook calls.
        let rc = unsafe {
            pam::ffi::pam_set_item(
                self.handle,
                item_type as c_int,
                value.as_ptr().cast::<std::ffi::c_void>(),
            )
        };
        assert_eq!(
            rc,
            PamReturnCode::Success as c_int,
            "pam_set_item failed: {rc}"
        );
    }
}

impl Drop for PamSession {
    fn drop(&mut self) {
        // SAFETY: handle is from pam_start and can be ended once here.
        unsafe {
            pam::ffi::pam_end(self.handle, PamReturnCode::Success as c_int);
        }
    }
}

#[test]
fn exported_hooks_return_service_err_for_null_handle() {
    let lib = load_release_library();
    for hook_name in HOOKS {
        let hook = load_hook(&lib, hook_name);
        // SAFETY: hooks must gracefully handle null handles and return service error.
        let rc = unsafe { hook(ptr::null_mut(), 0, 0, ptr::null()) };
        assert_eq!(
            rc,
            PamReturnCode::Service_Err as c_int,
            "{hook_name} should reject null pam handle"
        );
    }
}

#[cfg(all(feature = "logging", not(feature = "webhook")))]
#[test]
fn logging_mode_hooks_write_log_lines_for_all_exports() {
    let lib = load_release_library();
    let mut session = PamSession::start();
    session.set_item(
        pam::PamItemType::User,
        &CString::new("alice").expect("user cstr"),
    );
    session.set_item(
        pam::PamItemType::RHost,
        &CString::new("192.0.2.10").expect("rhost cstr"),
    );
    session.set_item(
        pam::PamItemType::TTY,
        &CString::new("pts/0").expect("tty cstr"),
    );

    let tmp = tempfile::tempdir().expect("create temp dir");
    let log_path = tmp.path().join("pam/hook.log");
    let cfg_path = tmp.path().join("pam-webhook.toml");
    std::fs::write(
        &cfg_path,
        format!("log_path = \"{}\"\n", log_path.display()),
    )
    .expect("write config");

    let module_args = vec![format!("config={}", cfg_path.display())];
    let (_arg_storage, arg_ptrs) = build_argv(&module_args);

    for hook_name in HOOKS {
        let hook = load_hook(&lib, hook_name);
        // SAFETY: handle and argv are valid for call duration.
        let argc = c_int::try_from(arg_ptrs.len()).expect("argv length must fit in c_int");
        let rc = unsafe { hook(session.handle, 7, argc, arg_ptrs.as_ptr()) };
        assert_eq!(rc, PamReturnCode::Success as c_int, "{hook_name} failed");
    }

    let content = std::fs::read_to_string(log_path).expect("read generated log");
    for hook_name in HOOKS {
        assert!(
            content.contains(hook_name),
            "missing log line for {hook_name}"
        );
    }
}

#[cfg(feature = "webhook")]
#[test]
fn webhook_mode_hooks_emit_http_payloads_for_all_exports() {
    let lib = load_release_library();
    let mut session = PamSession::start();
    session.set_item(
        pam::PamItemType::User,
        &CString::new("alice").expect("user cstr"),
    );
    session.set_item(
        pam::PamItemType::RHost,
        &CString::new("192.0.2.10").expect("rhost cstr"),
    );
    session.set_item(
        pam::PamItemType::TTY,
        &CString::new("pts/0").expect("tty cstr"),
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind webhook capture server");
    let addr = listener.local_addr().expect("get local addr");
    let join = thread::spawn(move || {
        let mut bodies = Vec::new();
        for _ in 0..HOOKS.len() {
            let (mut stream, _) = listener.accept().expect("accept webhook");
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("read header line");
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    content_length = value.trim().parse::<usize>().expect("parse content-length");
                }
            }

            let mut body = vec![0_u8; content_length];
            reader.read_exact(&mut body).expect("read request body");
            bodies.push(String::from_utf8(body).expect("UTF-8 JSON payload"));

            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("write response");
            stream.flush().expect("flush response");
        }
        bodies
    });

    let tmp = tempfile::tempdir().expect("create temp dir");
    let cfg_path = tmp.path().join("pam-webhook.toml");
    std::fs::write(&cfg_path, format!("webhook_url = \"http://{addr}\"\n")).expect("write config");
    let module_args = vec![format!("config={}", cfg_path.display())];
    let (_arg_storage, arg_ptrs) = build_argv(&module_args);

    for hook_name in HOOKS {
        let hook = load_hook(&lib, hook_name);
        // SAFETY: handle and argv remain valid across the FFI boundary.
        let argc = c_int::try_from(arg_ptrs.len()).expect("argv length must fit in c_int");
        let rc = unsafe { hook(session.handle, 123, argc, arg_ptrs.as_ptr()) };
        assert_eq!(rc, PamReturnCode::Success as c_int, "{hook_name} failed");
    }

    let bodies = join.join().expect("webhook server should finish");
    assert_eq!(bodies.len(), HOOKS.len(), "one request per hook expected");
    for (body, hook_name) in bodies.iter().zip(HOOKS.iter()) {
        assert!(body.contains(&format!("\"hook\":\"{hook_name}\"")));
        assert!(body.contains("\"flags\":123"));
        assert!(body.contains("\"user\":\"alice\""));
    }
}

#[cfg(not(any(feature = "logging", feature = "webhook")))]
#[test]
fn nullhandler_mode_all_hooks_return_success_with_valid_handle() {
    let lib = load_release_library();
    let mut session = PamSession::start();

    for hook_name in HOOKS {
        let hook = load_hook(&lib, hook_name);
        // SAFETY: valid pam handle and empty argv.
        let rc = unsafe { hook(session.handle_mut(), 0, 0, ptr::null()) };
        assert_eq!(rc, PamReturnCode::Success as c_int, "{hook_name} failed");
    }
}
