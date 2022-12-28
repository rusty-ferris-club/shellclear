use std::{fmt, path::Path};

use serde_derive::{Deserialize, Serialize};
use strum::{EnumIter, IntoEnumIterator};

/// List of all supported shells
#[derive(Debug, EnumIter, Clone, Eq, Hash, PartialEq)]
pub enum Shell {
    Bash,
    Zshrc,
    Fish,
    PowerShell,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FishHistory {
    pub cmd: String,
    pub when: String,
}

impl fmt::Display for Shell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bash => write!(f, "bash"),
            Self::Zshrc => write!(f, "zshrc"),
            Self::Fish => write!(f, "fish"),
            Self::PowerShell => write!(f, "powershell"),
        }
    }
}

/// Zsh history file name
const ZSH_HISTORY_FILE_PATH: &str = ".zsh_history";
/// Bash history file name
const BASH_HISTORY_FILE_PATH: &str = ".bash_history";
const FISH_HISTORY_FILE_PATH: &str = ".local/share/fish/fish_history";
const POWERSHELL_HISTORY_FILE_PATH: &str =
    "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt";

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
#[must_use]
pub fn get_all_history_files(homedir: &str) -> Vec<History> {
    // return list of existing shells
    Shell::iter()
        .filter_map(|shell| {
            let shell_history_path = get_shell_history_path(&shell, homedir);
            if !Path::new(&shell_history_path).exists() {
                log::debug!("shell {:?} not found", shell);
                return None;
            }
            let file_name = Path::new(&shell_history_path)
                .file_name()?
                .to_str()?
                .to_string();
            Some(History {
                shell,
                path: shell_history_path,
                file_name,
            })
        })
        .collect::<Vec<_>>()
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
        Shell::PowerShell => Path::new(homedir)
            .join(POWERSHELL_HISTORY_FILE_PATH)
            .display()
            .to_string(),
    }
}

#[cfg(test)]
mod state_shell {
    use std::{fs, fs::File};

    use insta::{assert_debug_snapshot, with_settings};
    use tempdir::TempDir;

    use super::{
        get_all_history_files, BASH_HISTORY_FILE_PATH, FISH_HISTORY_FILE_PATH,
        ZSH_HISTORY_FILE_PATH,
    };

    #[test]
    fn can_get_all_history_files() {
        let temp_dir = TempDir::new("terminal").unwrap().path().join("app");

        fs::create_dir_all(&temp_dir).unwrap();
        fs::create_dir_all(temp_dir.join(FISH_HISTORY_FILE_PATH).parent().unwrap()).unwrap();

        File::create(temp_dir.join(ZSH_HISTORY_FILE_PATH)).expect("create failed");
        File::create(temp_dir.join(BASH_HISTORY_FILE_PATH)).expect("create failed");
        File::create(temp_dir.join(FISH_HISTORY_FILE_PATH)).expect("create failed");

        with_settings!({filters => vec![
            (r"//*.+/(app)", "PATH"),
            (r"([C]?:\\.+app\\\\)", "PATH/")// for windows
        ]}, {
            assert_debug_snapshot!(get_all_history_files(&temp_dir.display().to_string()));
        });
    }
}
