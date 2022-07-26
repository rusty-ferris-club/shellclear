use crate::data::SensitiveCommands;
use anyhow::anyhow;
use anyhow::Result;
use std::fs;
use std::path::PathBuf;

const CONFIG_FOLDER: &str = env!("CARGO_PKG_NAME");
const CONFIG_SENSITIVE_PATTERNS: &str = "sensitive-patterns.yaml";
const SENSITIVE_PATTERN_TEMPLATE: &str = r###"# External sensitive patters file allows you you add a custom patterns to shellclear

- name: Pattern Name
  test: <PATTERN REGEX>
"###;

#[derive(Default, Clone, Debug)]
pub struct Config {}

impl Config {
    /// Init external configuration
    ///
    /// # Errors
    ///
    /// Will return `Err` when home directory not found or failed to create a file
    pub fn init() -> Result<String> {
        let file = Self::get_sensitive_pattern_file()?;
        fs::write(&file, SENSITIVE_PATTERN_TEMPLATE)?;
        Ok(file.display().to_string())
    }

    /// Get sensitive file path name
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    pub fn get_sensitive_pattern_name() -> Result<String> {
        Ok(Self::get_sensitive_pattern_file()?.display().to_string())
    }

    /// Is sensitive file is exists
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    pub fn is_sensitive_pattern_file_exists() -> Result<bool> {
        Ok(Self::get_sensitive_pattern_file()?.exists())
    }

    /// Load sensitive pattern file
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found or yaml is invalid
    pub fn load_patterns_from_default_path() -> Result<Vec<SensitiveCommands>> {
        Self::load_patterns_from_file(Self::get_sensitive_pattern_file()?)
    }

    /// Load sensitive pattern from the given path
    ///
    /// # Errors
    ///
    /// Will return `Err`  yaml is invalid
    fn load_patterns_from_file(path: PathBuf) -> Result<Vec<SensitiveCommands>> {
        let f = std::fs::File::open(path)?;
        Ok(serde_yaml::from_reader(f)?)
    }

    /// Returns the root config folder
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    fn get_root_config() -> Result<PathBuf> {
        match dirs::home_dir() {
            Some(d) => Ok(d),
            None => return Err(anyhow!("home dir not found")),
        }
    }

    /// Returns the root shellform config folder
    ///
    /// # Errors
    ///
    /// Will return `Err` home directory not found
    fn get_sensitive_pattern_file() -> Result<PathBuf> {
        Ok(Self::get_root_config()?
            .join(format!(".{}", CONFIG_FOLDER))
            .join(CONFIG_SENSITIVE_PATTERNS))
    }
}
