use crate::data::{SensitiveCommands, ROOT_APP_FOLDER};
use anyhow::Result;
use std::fs;
use std::path::PathBuf;

const CONFIG_SENSITIVE_PATTERNS: &str = "sensitive-patterns.yaml";
const SENSITIVE_PATTERN_TEMPLATE: &str = r###"# External sensitive patters file allows you you add a custom patterns to shellclear

- name: Pattern Name
  test: <PATTERN REGEX>
"###;

#[derive(Clone, Debug)]
pub struct Config {
    sensitive_commands_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sensitive_commands_path: Config::get_sensitive_pattern_file(dirs::home_dir().unwrap()),
        }
    }
}

impl Config {
    #[allow(dead_code)]
    fn with_custom_path(root: PathBuf) -> Self {
        Self {
            sensitive_commands_path: Self::get_sensitive_pattern_file(root),
        }
    }
    /// Init external configuration
    ///
    /// # Errors
    ///
    /// Will return `Err` when home directory not found or failed to create a file
    pub fn init(&self) -> Result<String> {
        let file = &self.sensitive_commands_path;
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(file, SENSITIVE_PATTERN_TEMPLATE)?;
        Ok(file.display().to_string())
    }

    /// Get sensitive file path name
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    #[must_use]
    pub fn get_sensitive_pattern_name(&self) -> String {
        self.sensitive_commands_path.display().to_string()
    }

    /// Is sensitive file is exists
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    #[must_use]
    pub fn is_sensitive_pattern_file_exists(&self) -> bool {
        self.sensitive_commands_path.exists()
    }

    /// Delete sensitive pattern file
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    pub fn delete_sensitive_patterns_from_file(&self) -> Result<()> {
        fs::remove_file(&self.sensitive_commands_path)?;
        Ok(())
    }

    /// Load sensitive pattern file
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found or yaml is invalid
    pub fn load_patterns_from_default_path(&self) -> Result<Vec<SensitiveCommands>> {
        self.load_sensitive_patterns_from_file(&self.sensitive_commands_path)
    }

    /// Load sensitive pattern from the given path
    ///
    /// # Errors
    ///
    /// Will return `Err`  yaml is invalid
    fn load_sensitive_patterns_from_file(&self, path: &PathBuf) -> Result<Vec<SensitiveCommands>> {
        let f = std::fs::File::open(path)?;
        Ok(serde_yaml::from_reader(f)?)
    }

    /// Returns the root shellclear config folder
    fn get_sensitive_pattern_file(path: PathBuf) -> PathBuf {
        path.join(format!(".{}", ROOT_APP_FOLDER))
            .join(CONFIG_SENSITIVE_PATTERNS)
    }
}

#[cfg(test)]
mod test_config {
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
        let path = config.init();
        assert_debug_snapshot!(path.is_ok());
        assert_debug_snapshot!(
            fs::read_to_string(path.unwrap()).unwrap() == SENSITIVE_PATTERN_TEMPLATE
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_get_sensitive_pattern_name() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(config
            .get_sensitive_pattern_name()
            .replace(&temp_dir.path().to_str().unwrap(), ""));
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_is_sensitive_pattern_file_exists() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(config.is_sensitive_pattern_file_exists());
        config.init();
        assert_debug_snapshot!(config.is_sensitive_pattern_file_exists());
        temp_dir.close().unwrap()
    }

    #[test]
    fn can_delete_sensitive_patterns_from_file() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        config.init();
        assert_debug_snapshot!(config.is_sensitive_pattern_file_exists());
        assert_debug_snapshot!(config.delete_sensitive_patterns_from_file());
        assert_debug_snapshot!(!config.is_sensitive_pattern_file_exists());
        temp_dir.close().unwrap()
    }

    #[test]
    fn can_load_patterns_from_default_path() {
        let temp_dir = TempDir::new("config-app").unwrap();
        let config = new_config(&temp_dir);
        config.init();
        assert_debug_snapshot!(config.load_patterns_from_default_path());
        temp_dir.close().unwrap()
    }
}
