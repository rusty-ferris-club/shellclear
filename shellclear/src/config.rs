use crate::data::{SensitiveCommands, ROOT_APP_FOLDER};
use anyhow::Result;
use std::fs;
use std::path::PathBuf;

const CONFIG_SENSITIVE_PATTERNS: &str = "sensitive-patterns.yaml";
const CONFIG_IGNORES: &str = "ignores.yaml";
const SENSITIVE_PATTERN_TEMPLATE: &str = r###"# External sensitive patterns file allows you you add a custom patterns to shellclear

- name: Pattern Name
  test: <PATTERN REGEX>
  secret_group: 0
"###;
const IGNORES_SENSITIVE_PATTERN_TEMPLATE: &str = r###"# List of sensitive patterns id to ignore

- PATTERN_ID
"###;

#[derive(Clone, Debug)]
pub struct Config {
    pub app_path: PathBuf,
    pub sensitive_commands_path: PathBuf,
    pub ignore_sensitive_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self::with_custom_path(dirs::home_dir().unwrap())
    }
}

impl From<Option<&str>> for Config {
    fn from(config_dir: Option<&str>) -> Self {
        match config_dir {
            None => Self::default(),
            Some(cfg_dir_path) => Self::with_custom_path(PathBuf::from(cfg_dir_path)),
        }
    }
}

impl Config {
    #[allow(dead_code)]
    #[must_use]
    pub fn with_custom_path(root: PathBuf) -> Self {
        // todo check if we can remove this get_base_app_folder function
        let app_path = Self::get_base_app_folder(root);
        Self {
            ignore_sensitive_path: app_path.join(CONFIG_IGNORES),
            sensitive_commands_path: app_path.join(CONFIG_SENSITIVE_PATTERNS),
            app_path,
        }
    }

    /// Returns the root shellclear config folder
    fn get_base_app_folder(path: PathBuf) -> PathBuf {
        path.join(ROOT_APP_FOLDER)
    }

    /// Init external configuration
    ///
    /// # Errors
    ///
    /// Will return `Err` when home directory not found or failed to create a file
    pub fn init(&self) -> Result<()> {
        if !self.is_app_path_exists() {
            fs::create_dir_all(&self.app_path)?;
        }

        fs::write(&self.sensitive_commands_path, SENSITIVE_PATTERN_TEMPLATE)?;
        fs::write(
            &self.ignore_sensitive_path,
            IGNORES_SENSITIVE_PATTERN_TEMPLATE,
        )?;
        Ok(())
    }

    /// Is sensitive file is exists
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    #[must_use]
    pub fn is_app_path_exists(&self) -> bool {
        self.app_path.exists()
    }

    /// Delete sensitive pattern file
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    pub fn delete_app_folder(&self) -> Result<()> {
        fs::remove_dir_all(&self.app_path)?;
        Ok(())
    }

    /// Delete sensitive pattern file
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    pub fn delete_sensitive_patterns_file(&self) -> Result<()> {
        fs::remove_file(&self.sensitive_commands_path)?;
        Ok(())
    }

    /// Delete sensitive ignore file
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    pub fn delete_sensitive_ignore_file(&self) -> Result<()> {
        fs::remove_file(&self.ignore_sensitive_path)?;
        Ok(())
    }

    /// Load sensitive pattern file
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found or yaml is invalid
    pub fn load_patterns_from_default_path(&self) -> Result<Vec<SensitiveCommands>> {
        let f = std::fs::File::open(&self.sensitive_commands_path)?;
        let custom_patterns = serde_yaml::from_reader(f)?;
        log::debug!(
            "found {:?} ignore ids. loaded from path: {}",
            custom_patterns,
            &self.sensitive_commands_path.display()
        );
        Ok(custom_patterns)
    }

    /// Load sensitive ignores file
    ///
    /// # Errors
    ///
    /// Will return `Err` yaml is invalid
    pub fn get_ignore_patterns(&self) -> Result<Vec<String>> {
        let f = std::fs::File::open(&self.ignore_sensitive_path)?;
        let ignore_ids = serde_yaml::from_reader(f)?;
        log::debug!(
            "found {:?} ignore ids. loaded from path: {}",
            ignore_ids,
            &self.ignore_sensitive_path.display()
        );
        Ok(ignore_ids)
    }

    /// Write a ignore patterns
    ///
    /// # Errors
    ///
    /// Will return `Err` when has an error to write a file
    pub fn save_ignores_patterns(&self, ignores: &[String]) -> Result<()> {
        Ok(fs::write(
            &self.ignore_sensitive_path,
            serde_yaml::to_string(&ignores)?,
        )?)
    }
}

#[cfg(test)]
mod test_config {
    use crate::{config::IGNORES_SENSITIVE_PATTERN_TEMPLATE, data::ROOT_APP_FOLDER};

    use super::{Config, CONFIG_IGNORES, CONFIG_SENSITIVE_PATTERNS, SENSITIVE_PATTERN_TEMPLATE};
    use insta::assert_debug_snapshot;
    use std::{fs, path::PathBuf};
    use tempdir::TempDir;

    fn new_config(temp_dir: &TempDir) -> Config {
        let path = temp_dir.path().join("app");
        fs::create_dir_all(&path).unwrap();
        Config::with_custom_path(path)
    }

    #[test]
    fn new_config_from_string() {
        let cfg_dir = "home/user1";
        let path = PathBuf::from(cfg_dir);
        let config = Config::from(path.as_os_str().to_str());
        assert_debug_snapshot!(
            config.app_path == PathBuf::from(format!("{}/{}", cfg_dir, ROOT_APP_FOLDER))
        );
        assert_debug_snapshot!(
            config.ignore_sensitive_path
                == PathBuf::from(format!(
                    "{}/{}/{}",
                    cfg_dir, ROOT_APP_FOLDER, CONFIG_IGNORES
                ))
        );
        assert_debug_snapshot!(
            config.sensitive_commands_path
                == PathBuf::from(format!(
                    "{}/{}/{}",
                    cfg_dir, ROOT_APP_FOLDER, CONFIG_SENSITIVE_PATTERNS
                ))
        );
    }

    #[test]
    fn new_config_from_none_use_default() {
        let config = Config::from(None);
        let default_config = Config::default();
        assert_debug_snapshot!(config.app_path == default_config.app_path);
        assert_debug_snapshot!(
            config.ignore_sensitive_path == default_config.ignore_sensitive_path
        );
        assert_debug_snapshot!(
            config.sensitive_commands_path == default_config.sensitive_commands_path
        );
    }

    #[test]
    fn can_init() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(config.init());
        assert_debug_snapshot!(
            fs::read_to_string(config.sensitive_commands_path).unwrap()
                == SENSITIVE_PATTERN_TEMPLATE
        );
        assert_debug_snapshot!(
            fs::read_to_string(config.ignore_sensitive_path).unwrap()
                == IGNORES_SENSITIVE_PATTERN_TEMPLATE
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_get_sensitive_pattern_name() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(config
            .sensitive_commands_path
            .display()
            .to_string()
            .replace(&temp_dir.path().to_str().unwrap(), "")
            .replace('\\', "/"));
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_is_sensitive_pattern_file_exists() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(config.sensitive_commands_path.exists());
        assert_debug_snapshot!(config.init());
        assert_debug_snapshot!(config.sensitive_commands_path.exists());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_delete_sensitive_patterns_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(config.init());
        assert_debug_snapshot!(config.sensitive_commands_path.exists());
        assert_debug_snapshot!(config.delete_sensitive_patterns_file());
        assert_debug_snapshot!(!config.sensitive_commands_path.exists());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_delete_sensitive_ignore_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(config.init());
        assert_debug_snapshot!(config.ignore_sensitive_path.exists());
        assert_debug_snapshot!(config.delete_sensitive_ignore_file());
        assert_debug_snapshot!(!config.ignore_sensitive_path.exists());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_load_patterns_from_default_path() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(config.init());
        assert_debug_snapshot!(config.load_patterns_from_default_path());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_save_ignore_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        config.init().unwrap();
        assert_debug_snapshot!(
            config.save_ignores_patterns(&["patter-1".to_string(), "patter-2".to_string()])
        );
        assert_debug_snapshot!(config.get_ignore_patterns());
        temp_dir.close().unwrap();
    }
}
