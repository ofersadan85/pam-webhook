use serde::Deserialize;
use std::{fs::read_to_string, path::PathBuf};

pub(crate) fn from_toml_config_args<T>(args: &[String]) -> T
where
    T: Default + for<'de> Deserialize<'de>,
{
    args.iter()
        .find_map(|arg| arg.strip_prefix("config="))
        .map(PathBuf::from)
        .and_then(|path| read_to_string(&path).ok())
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default()
}
