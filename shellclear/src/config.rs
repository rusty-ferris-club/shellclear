use crate::data::{SensitiveCommands, ROOT_APP_FOLDER};
use anyhow::Result;
use std::fs;
use std::path::PathBuf;

const CONFIG_SENSITIVE_PATTERNS: &str = "sensitive-patterns.yaml";
const CONFIG_IGNORES: &str = "ignores.yaml";
const SENSITIVE_PATTERN_TEMPLATE: &str = r###"# External sensitive patters file allows you you add a custom patterns to shellclear

- name: Pattern Name
  test: <PATTERN REGEX>
"###;
const IGNORES_SENSITIVE_PATTERN_TEMPLATE: &str = r###"# List of sensitive patters id to ignore

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
}

#[cfg(test)]
mod test_config {
    use crate::config::IGNORES_SENSITIVE_PATTERN_TEMPLATE;

    use super::{Config, SENSITIVE_PATTERN_TEMPLATE};
    use insta::assert_debug_snapshot;
    use std::fs;
    use tempdir::TempDir;

    fn new_config(temp_dir: &TempDir) -> Config {
        let path = temp_dir.path().join("app");
        fs::create_dir_all(&path).unwrap();
        Config::with_custom_path(path)
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
}
