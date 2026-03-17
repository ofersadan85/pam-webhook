use serde::Deserialize;
use std::{
    ffi::{CStr, c_char, c_int},
    fs::{OpenOptions, read_to_string},
    io::{self, Write},
    path::{Path, PathBuf},
};

const DEFAULT_LOG_PATH: &str = "/var/log/pam-webhook.log";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Config {
    pub(crate) log_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from(DEFAULT_LOG_PATH),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("module arguments contain non-UTF-8 data")]
    InvalidUtf8Arg,
    #[error("`config=` was provided without a path")]
    EmptyConfigPath,
    #[error("failed to read config file: {0}")]
    ReadFailed(#[from] io::Error),
    #[error("failed to parse TOML config: {0}")]
    ParseFailed(#[from] toml::de::Error),
}

/// # Safety
/// This function reads raw C argument pointers passed by PAM.
/// Since PAM is very well tried and tested, we can assume this is safe and valid
/// as long as we handle null pointers and invalid UTF-8 gracefully, which we do by returning errors instead of panicking.
#[allow(clippy::similar_names)]
fn parse_c_args(argc: c_int, argv: *const *const c_char) -> Result<PathBuf, ConfigError> {
    let argc = usize::try_from(argc).unwrap_or(0);
    if argc == 0 || argv.is_null() {
        return Err(ConfigError::EmptyConfigPath);
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
            return Err(ConfigError::InvalidUtf8Arg);
        };
        if let Some(path) = arg.strip_prefix("config=") {
            if path.is_empty() {
                return Err(ConfigError::EmptyConfigPath);
            }
            return Ok(PathBuf::from(path));
        }
    }
    Err(ConfigError::EmptyConfigPath)
}

/// # Safety
/// See safety in [`parse_c_args`]
#[allow(clippy::similar_names)]
fn load_config(argc: c_int, argv: *const *const c_char) -> Result<Config, ConfigError> {
    let path: PathBuf = parse_c_args(argc, argv)?;
    let file_text = read_to_string(&path)?;
    let parsed: Config = toml::from_str(&file_text)?;
    Ok(parsed)
}

/// # Safety
/// See safety in [`parse_c_args`]
#[allow(clippy::similar_names)]
pub(crate) fn load_hook_config(hook: &str, argc: c_int, argv: *const *const c_char) -> Config {
    load_config(argc, argv).unwrap_or_else(|e| {
        eprintln!("[pam-webhook] {hook} config load failed: {e}");
        Config::default()
    })
}

pub(crate) fn append_log_line(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|file| writeln!(&file, "{line}"));
    result.inspect_err(|e| {
        eprintln!(
            "[pam-webhook] failed to write log file path={} error={e} line={line}",
            path.display()
        );
    })
}
