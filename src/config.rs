use serde::Deserialize;
use std::{fs::read_to_string, path::PathBuf};

pub(crate) fn from_toml_config_args<T>(args: &[String]) -> T
where
    T: Default + for<'de> Deserialize<'de>,
{
    let mut config = T::default();
    for arg in args {
        if let Some(path) = arg.strip_prefix("config=") {
            let path = PathBuf::from(path);
            let file_text = read_to_string(&path);
            if let Ok(text) = file_text {
                if let Ok(parsed) = toml::from_str(&text) {
                    config = parsed;
                } else {
                    eprintln!(
                        "[pam-webhook] {} failed to parse config from {}",
                        chrono::Utc::now(),
                        path.display()
                    );
                }
            } else {
                eprintln!(
                    "[pam-webhook] {} failed to read config from {}",
                    chrono::Utc::now(),
                    path.display()
                );
            }
        }
    }
    config
}
