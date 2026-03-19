#[cfg(any(feature = "logging", feature = "webhook", test))]
pub(crate) fn from_toml_config_args<T>(args: &[String]) -> T
where
    T: Default + for<'de> serde::Deserialize<'de>,
{
    args.iter()
        .find_map(|arg| arg.strip_prefix("config="))
        .map(std::path::PathBuf::from)
        .and_then(|path| std::fs::read_to_string(&path).ok())
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::from_toml_config_args;
    use serde::Deserialize;
    use tempfile::tempdir;

    #[derive(Debug, Default, Deserialize, PartialEq, Eq)]
    struct DummyConfig {
        value: Option<String>,
    }

    #[test]
    fn returns_default_when_no_config_arg() {
        let args = vec!["foo=bar".to_string()];
        let cfg: DummyConfig = from_toml_config_args(&args);
        assert_eq!(cfg, DummyConfig::default());
    }

    #[test]
    fn returns_default_when_file_missing() {
        let args = vec!["config=/definitely/missing/file.toml".to_string()];
        let cfg: DummyConfig = from_toml_config_args(&args);
        assert_eq!(cfg, DummyConfig::default());
    }

    #[test]
    fn returns_default_on_invalid_toml() {
        let tmp = tempdir().expect("create temp dir");
        let config_path = tmp.path().join("invalid.toml");
        std::fs::write(&config_path, "value = [this is invalid").expect("write invalid TOML");

        let args = vec![format!("config={}", config_path.display())];
        let cfg: DummyConfig = from_toml_config_args(&args);
        assert_eq!(cfg, DummyConfig::default());
    }

    fn create_valid_toml() -> (Vec<String>, tempfile::TempDir) {
        let tmp = tempdir().expect("create temp dir");
        let config_path = tmp.path().join("valid.toml");
        std::fs::write(&config_path, "value = \"configured\"").expect("write valid TOML");
        (vec![format!("config={}", config_path.display())], tmp)
    }

    #[test]
    fn parses_valid_toml() {
        let (args, _tmp) = create_valid_toml();
        let cfg: DummyConfig = from_toml_config_args(&args);
        assert_eq!(
            cfg,
            DummyConfig {
                value: Some("configured".to_string())
            }
        );
    }

    #[test]
    fn ignores_unrelated_args() {
        let (mut args, _tmp) = create_valid_toml();
        args.insert(0, "unrelated=ignored".to_string());
        args.push("foo=bar".to_string());
        let cfg: DummyConfig = from_toml_config_args(&args);
        assert_eq!(
            cfg,
            DummyConfig {
                value: Some("configured".to_string())
            }
        );
    }
}
