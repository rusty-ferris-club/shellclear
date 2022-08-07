use crate::config::Config;
use crate::data::{FindingSensitiveCommands, SensitiveCommands};
use crate::shell;
use crate::state::ShellContext;
use anyhow::Result;
use log::debug;
use rayon::prelude::*;
use std::fmt::Write;
use std::fs::{write, File};
use std::io::{prelude::*, BufReader};
use std::time::Instant;

pub const SENSITIVE_COMMANDS: &str = include_str!("sensitive-patterns.yaml");

pub struct PatternsEngine {
    commands: Vec<SensitiveCommands>,
}

#[derive(Default, Debug)]
pub struct Findings {
    pub patterns: Vec<FindingSensitiveCommands>,
}

impl Default for PatternsEngine {
    fn default() -> Self {
        Self {
            commands: serde_yaml::from_str(SENSITIVE_COMMANDS).unwrap(),
        }
    }
}

impl Findings {
    #[must_use]
    // add list of finding
    pub fn add_findings(mut self, finding: Vec<FindingSensitiveCommands>) -> Self {
        self.patterns.extend(finding);
        self
    }

    #[must_use]
    // return list of sensitive findings commands
    pub fn get_sensitive_commands(&self) -> Vec<&FindingSensitiveCommands> {
        self.patterns
            .iter()
            .filter(|&f| !f.sensitive_findings.is_empty())
            .collect::<Vec<_>>()
    }
}

impl PatternsEngine {
    /// Load the engine with config
    ///
    /// # Errors
    ///
    /// Will return `Err` when could not load default sensitive commands
    pub fn with_config(config: &Config) -> Result<Self> {
        let sensitive_patterns = {
            let mut patterns: Vec<SensitiveCommands> = serde_yaml::from_str(SENSITIVE_COMMANDS)?;

            if config.is_sensitive_pattern_file_exists() {
                match config.load_patterns_from_default_path() {
                    Ok(p) => patterns.extend(p),
                    Err(e) => log::debug!("could not load external pattern{:?}", e),
                };
            } else {
                log::debug!("config file not found");
            }

            patterns
        };
        Ok(Self {
            commands: sensitive_patterns,
        })
    }
    /// Search sensitive command patterns from the given sehll list
    ///
    /// # Errors
    ///
    /// Will return `Err` when has an error when find sensitive patters in a specific shell
    pub fn find_history_commands_from_shall_list(
        &self,
        shells_context: &Vec<ShellContext>,
        clear: bool,
    ) -> Result<Findings> {
        let mut findings = Findings::default();

        for shell_context in shells_context {
            findings = findings.add_findings(self.find_history_commands(shell_context, clear)?);
        }
        Ok(findings)
    }

    /// Search sensitive command patterns
    ///
    /// # Errors
    ///
    /// Will return `Err` if history file not exists/ could't open
    pub fn find_history_commands(
        &self,
        state_context: &ShellContext,
        clear: bool,
    ) -> Result<Vec<FindingSensitiveCommands>> {
        debug!(
            "clear history commands from path: {}, params: is clear: {}",
            state_context.history.path, clear
        );

        match state_context.history.shell {
            shell::Shell::Fish => self.find_fish(state_context, &self.commands, clear),
            _ => self.find_by_lines(state_context, &self.commands, clear),
        }
    }

    fn find_by_lines(
        &self,
        state_context: &ShellContext,
        sensitive_commands: &Vec<SensitiveCommands>,
        clear: bool,
    ) -> Result<Vec<FindingSensitiveCommands>> {
        let file = File::open(&state_context.history.path)?;
        let reader = BufReader::new(file);

        let start = Instant::now();

        let lines = reader
            .lines()
            .filter(std::result::Result::is_ok)
            .map(std::result::Result::unwrap)
            .collect::<Vec<_>>();

        debug!(
            "time elapsed to read history file: {:?}. found {} commands",
            start.elapsed(),
            lines.len()
        );

        let start = Instant::now();
        let results = lines
            .par_iter()
            .map(|command| {
                let sensitive_findings = sensitive_commands
                    .par_iter()
                    .filter(|v| v.test.is_match(command))
                    .map(std::clone::Clone::clone)
                    .collect::<Vec<_>>();

                let only_command = match command.split_once(';') {
                    Some((_x, y)) => y.to_string(),
                    _ => command.clone(),
                };
                FindingSensitiveCommands {
                    shell_type: state_context.history.shell.clone(),
                    sensitive_findings,
                    command: only_command,
                    data: command.clone(),
                }
            })
            .collect::<Vec<_>>();

        debug!(
            "time elapsed for detect sensitive commands: {:?}",
            start.elapsed()
        );

        if clear {
            let start = Instant::now();
            let mut cleared_history: String = String::new();

            for r in &results {
                if r.sensitive_findings.is_empty() {
                    let _ = writeln!(&mut cleared_history, "{}", r.data);
                }
            }
            if !cleared_history.is_empty() {
                write(&state_context.history.path, cleared_history)?;
                debug!(
                    "time elapsed for backup existing file and write a new history to shell : {:?}",
                    start.elapsed()
                );
            }
        }

        Ok(results)
    }

    fn find_fish(
        &self,
        state_context: &ShellContext,
        sensitive_commands: &Vec<SensitiveCommands>,
        clear: bool,
    ) -> Result<Vec<FindingSensitiveCommands>> {
        let start = Instant::now();
        let history: Vec<shell::FishHistory> =
            serde_yaml::from_reader(File::open(&state_context.history.path)?)?;

        let results = history
            .par_iter()
            .map(|h| {
                let sensitive_findings = sensitive_commands
                    .par_iter()
                    .filter(|v| v.test.is_match(&h.cmd))
                    .map(std::clone::Clone::clone)
                    .collect::<Vec<_>>();

                FindingSensitiveCommands {
                    shell_type: state_context.history.shell.clone(),
                    sensitive_findings,
                    command: h.cmd.clone(),
                    data: serde_yaml::to_string(&h).unwrap(),
                }
            })
            .collect::<Vec<_>>();
        debug!(
            "time elapsed to read history file: {:?}. found {} commands",
            start.elapsed(),
            history.len()
        );

        if clear {
            let start = Instant::now();
            let mut cleared_history: Vec<shell::FishHistory> = Vec::new();

            for command_line in &results {
                if command_line.sensitive_findings.is_empty() {
                    cleared_history.push(serde_yaml::from_str(&command_line.data)?);
                }
            }
            if !cleared_history.is_empty() {
                write(
                    &state_context.history.path,
                    serde_yaml::to_string(&cleared_history).unwrap(),
                )?;
                debug!(
                    "time elapsed for backup existing file and write a new history to shell : {:?}",
                    start.elapsed()
                );
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod test_engine {
    use super::*;
    use insta::assert_debug_snapshot;
    use regex::Regex;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use tempdir::TempDir;

    const TEST_SENSITIVE_COMMANDS: &str = r###"
- name: Find me
  test: FIND_ME=
    "###;

    const TEMP_HISTORY_LINES_CONTENT: &str = "history
ls
echo 'hello you'
rm -f ./file.txt
export FIND_ME=token
";

    const TEMP_HISTORY_FISH: &str = r#"---
- cmd: history
  when: "1656438759"
- cmd: ls
  when: "1656438760"
- cmd: echo 'hello you'
  when: "1656438760"
- cmd: rm -f ./file.txt
  when: "1656438760"
- cmd: export FIND_ME=token
  when: "1656438760"
"#;

    fn create_mock_state(
        temp_dir: &TempDir,
        content: &str,
        shell_type: shell::Shell,
    ) -> ShellContext {
        let app_folder = temp_dir.path().join("app");
        let history_file_name = "history";
        let history_file_path = app_folder.join(history_file_name);
        fs::create_dir_all(&app_folder).unwrap();

        let mut f = File::create(&history_file_path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.sync_all().unwrap();

        ShellContext {
            app_folder_path: app_folder.display().to_string(),
            history: shell::History {
                shell: shell_type,
                path: history_file_path.display().to_string(),
                file_name: history_file_name.to_string(),
            },
        }
    }

    #[test]
    fn can_find_history_commands_line() {
        let temp_dir = TempDir::new("engine").unwrap();

        let en = PatternsEngine {
            commands: serde_yaml::from_str(TEST_SENSITIVE_COMMANDS).unwrap(),
        };
        let state_context =
            create_mock_state(&temp_dir, TEMP_HISTORY_LINES_CONTENT, shell::Shell::Bash);

        let result = en.find_history_commands_from_shall_list(&vec![state_context], false);

        assert_debug_snapshot!(result);
    }

    #[test]
    fn can_clear_command_by_lines() {
        let temp_dir = TempDir::new("engine").unwrap();

        let en = PatternsEngine {
            commands: serde_yaml::from_str(TEST_SENSITIVE_COMMANDS).unwrap(),
        };
        let state_context =
            create_mock_state(&temp_dir, TEMP_HISTORY_LINES_CONTENT, shell::Shell::Bash);

        let result = en.find_history_commands_from_shall_list(&vec![state_context.clone()], true);

        assert_debug_snapshot!(result);
        assert_debug_snapshot!(fs::read_to_string(state_context.history.path));
    }

    #[test]
    fn can_clear_find_fish() {
        let temp_dir = TempDir::new("engine").unwrap();

        let en = PatternsEngine {
            commands: serde_yaml::from_str(TEST_SENSITIVE_COMMANDS).unwrap(),
        };
        let state_context = create_mock_state(&temp_dir, TEMP_HISTORY_FISH, shell::Shell::Fish);

        let result = en.find_history_commands_from_shall_list(&vec![state_context.clone()], true);

        assert_debug_snapshot!(result);
        assert_debug_snapshot!(fs::read_to_string(state_context.history.path).unwrap());
    }

    #[test]
    fn can_find_history_commands_fish() {
        let temp_dir = TempDir::new("engine").unwrap();

        let en = PatternsEngine {
            commands: serde_yaml::from_str(TEST_SENSITIVE_COMMANDS).unwrap(),
        };
        let state_context = create_mock_state(&temp_dir, TEMP_HISTORY_FISH, shell::Shell::Fish);

        let result = en.find_history_commands_from_shall_list(&vec![state_context], false);

        assert_debug_snapshot!(result);
    }
}
