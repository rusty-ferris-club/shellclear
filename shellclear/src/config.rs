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
            sensitive_commands_path: Config::get_sensitive_pattern_file(&dirs::home_dir().unwrap()),
        }
    }
}

impl Config {
    fn with_custom_path(root: &PathBuf) -> Self {
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

    /// Load sensitive pattern file
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found or yaml is invalid
    pub fn load_patterns_from_default_path(&self) -> Result<Vec<SensitiveCommands>> {
        self.load_patterns_from_file(&self.sensitive_commands_path)
    }

    /// Load sensitive pattern from the given path
    ///
    /// # Errors
    ///
    /// Will return `Err`  yaml is invalid
    fn load_patterns_from_file(&self, path: &PathBuf) -> Result<Vec<SensitiveCommands>> {
        let f = std::fs::File::open(path)?;
        Ok(serde_yaml::from_reader(f)?)
    }

    /// Returns the root shellclear config folder
    fn get_sensitive_pattern_file(path: &PathBuf) -> PathBuf {
        path.join(format!(".{}", ROOT_APP_FOLDER))
            .join(CONFIG_SENSITIVE_PATTERNS)
    }
}
