use anyhow::anyhow;
use anyhow::Result;
use std::fmt;
use std::path::Path;
use strum::{EnumIter, IntoEnumIterator};

/// List of all supported shells
#[derive(Debug, EnumIter, Clone)]
pub enum Shell {
    Bash,
    Zshrc,
    Fish,
}

impl fmt::Display for Shell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bash => write!(f, "bash"),
            Self::Zshrc => write!(f, "zshrc"),
            Self::Fish => write!(f, "fish"),
        }
    }
}

/// Zsh history file name
const ZSH_HISTORY_FILE_PATH: &str = ".zsh_history";
/// Bash history file name
const BASH_HISTORY_FILE_PATH: &str = ".bash_history";
const FISH_HISTORY_FILE_PATH: &str = ".local/share/fish/fish_history";

/// History shell details
#[derive(Clone, Debug)]
pub struct History {
    /// shell type
    pub shell: Shell,
    /// history file path
    pub path: String,
    /// history file name
    pub file_name: String,
}

/// return list of all existing history files
pub fn get_all_history_files() -> Result<Vec<History>> {
    let homedir = match dirs::home_dir() {
        Some(h) => h.display().to_string(),
        None => return Err(anyhow!("could not get directory path")),
    };

    // return list of existing shells
    Ok(Shell::iter()
        .map(|shell| {
            let shell_history_path = get_shell_history_path(&shell, &homedir);
            if !Path::new(&shell_history_path).exists() {
                log::debug!("shell {:?} not found", shell);
                return Err(anyhow!("could not get directory path"));
            }
            let file_name = Path::new(&shell_history_path)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            Ok(History {
                shell,
                path: shell_history_path,
                file_name,
            })
        })
        .filter(std::result::Result::is_ok)
        .map(std::result::Result::unwrap)
        .collect::<Vec<_>>())
}

// returns all supported shells types
fn get_shell_history_path(shell_type: &Shell, homedir: &str) -> String {
    match shell_type {
        Shell::Bash => Path::new(homedir)
            .join(BASH_HISTORY_FILE_PATH)
            .display()
            .to_string(),
        Shell::Zshrc => Path::new(homedir)
            .join(ZSH_HISTORY_FILE_PATH)
            .display()
            .to_string(),
        Shell::Fish => Path::new(homedir)
            .join(FISH_HISTORY_FILE_PATH)
            .display()
            .to_string(),
    }
}
