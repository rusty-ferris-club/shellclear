use anyhow::anyhow;
use serde_derive::{Deserialize, Serialize};
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
pub fn get_all_history_files(homedir: &str) -> Vec<History> {
    // return list of existing shells
    Shell::iter()
        .map(|shell| {
            let shell_history_path = get_shell_history_path(&shell, homedir);
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
    }
}

#[cfg(test)]
mod state_context {
    use super::{
        get_all_history_files, BASH_HISTORY_FILE_PATH, FISH_HISTORY_FILE_PATH,
        ZSH_HISTORY_FILE_PATH,
    };
    use insta::{assert_debug_snapshot, with_settings};
    use std::fs;
    use std::fs::File;
    use tempdir::TempDir;

    #[test]
    fn can_backup_file() {
        let temp_dir = TempDir::new("terminal").unwrap().path().join("app");

        fs::create_dir_all(&temp_dir).unwrap();
        fs::create_dir_all(&temp_dir.join(FISH_HISTORY_FILE_PATH).parent().unwrap()).unwrap();

        File::create(&temp_dir.join(ZSH_HISTORY_FILE_PATH)).expect("create failed");
        File::create(&temp_dir.join(BASH_HISTORY_FILE_PATH)).expect("create failed");
        File::create(&temp_dir.join(FISH_HISTORY_FILE_PATH)).expect("create failed");

        with_settings!({filters => vec![
            (r"/*.+/(app)", "PATH/"),
            (r"(c?:\\*.+app)", "PATH/")// for windows
        ]}, {
            assert_debug_snapshot!(get_all_history_files(&temp_dir.display().to_string()));
        });
    }
}
