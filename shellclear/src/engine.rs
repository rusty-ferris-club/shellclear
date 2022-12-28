use std::{
    fs::File,
    io::{prelude::*, BufReader},
    time::Instant,
};

use anyhow::Result;
use log::debug;
use rayon::prelude::*;

use crate::shell::Shell;
use crate::{
    config::Config,
    data::{FindingSensitiveCommands, SensitiveCommands},
    masker::Masker,
    shell,
    state::ShellContext,
};

pub const SENSITIVE_COMMANDS: &str = include_str!("sensitive-patterns.yaml");

pub struct PatternsEngine {
    commands: Vec<SensitiveCommands>,
    masker: Masker,
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

            patterns = if config.is_app_path_exists() {
                // load external patterns
                match config.load_patterns_from_default_path() {
                    Ok(p) => patterns.extend(p),
                    Err(e) => debug!("could not load external pattern. {:?}", e),
                };

                // ignore patterns
                match config.get_ignore_patterns() {
                    Ok(ignores) => patterns
                        .iter()
                        .filter(|p| !ignores.contains(&p.id))
                        .cloned()
                        .collect::<Vec<_>>(),
                    Err(e) => {
                        debug!("could not load ignore pattern. {:?}", e);
                        patterns
                    }
                }
            } else {
                debug!(
                    "app config folder not found in path: {}",
                    &config.app_path.display()
                );
                patterns
            };

            patterns
        };
        Ok(Self {
            commands: sensitive_patterns,
            masker: Masker::new(),
        })
    }
    /// Search sensitive command patterns from the given shell list
    ///
    /// # Errors
    ///
    /// Will return `Err` when has an error when find sensitive patterns in a
    /// specific shell
    pub fn find_history_commands_from_shell_list(
        &self,
        shells_context: &Vec<ShellContext>,
    ) -> Result<(Vec<FindingSensitiveCommands>, Vec<FindingSensitiveCommands>)> {
        let mut findings = Vec::new();

        for shell_context in shells_context {
            let history = self.find_history_commands(shell_context)?;

            findings.extend(history);
        }

        let sensitive_findings = findings
            .iter()
            .filter(|f| !f.sensitive_findings.is_empty())
            .cloned()
            .collect::<Vec<_>>();

        Ok((findings, sensitive_findings))
    }

    /// Search sensitive command patterns
    ///
    /// # Errors
    ///
    /// Will return `Err` if history file not exists/ couldn't open
    pub fn find_history_commands(
        &self,
        state_context: &ShellContext,
    ) -> Result<Vec<FindingSensitiveCommands>> {
        debug!(
            "clear history commands from path: {}",
            state_context.history.path
        );

        match state_context.history.shell {
            Shell::Fish => self.find_fish(state_context, &self.commands),
            _ => self.find_by_lines(state_context, &self.commands),
        }
    }

    fn find_by_lines(
        &self,
        state_context: &ShellContext,
        sensitive_commands: &[SensitiveCommands],
    ) -> Result<Vec<FindingSensitiveCommands>> {
        let file = File::open(&state_context.history.path)?;
        let reader = BufReader::new(file);

        let start = Instant::now();

        let lines = reader
            .lines()
            .filter(Result::is_ok)
            .map(Result::unwrap)
            .collect::<Vec<_>>();

        debug!(
            "time elapsed to read history file: {:?}. found {} commands",
            start.elapsed(),
            lines.len()
        );

        let start = Instant::now();
        let mut results = lines
            .par_iter()
            .map(|command| {
                let (secrets, sensitive_findings) =
                    PatternsEngine::find_secrets(command, sensitive_commands);

                let only_command = match command.split_once(';') {
                    Some((_x, y)) => y.to_string(),
                    _ => command.clone(),
                };

                FindingSensitiveCommands {
                    shell_type: state_context.history.shell.clone(),
                    sensitive_findings,
                    command: only_command,
                    data: command.clone(),
                    secrets,
                }
            })
            .collect::<Vec<_>>();

        self.masker.mask_sensitive_findings(results.as_mut());

        debug!(
            "time elapsed for detect sensitive commands: {:?}",
            start.elapsed()
        );

        Ok(results)
    }

    fn find_fish(
        &self,
        state_context: &ShellContext,
        sensitive_commands: &[SensitiveCommands],
    ) -> Result<Vec<FindingSensitiveCommands>> {
        let start = Instant::now();
        let history: Vec<shell::FishHistory> =
            serde_yaml::from_reader(File::open(&state_context.history.path)?)?;

        let mut results = history
            .par_iter()
            .map(|h| {
                let (secrets, sensitive_findings) =
                    PatternsEngine::find_secrets(&h.cmd, sensitive_commands);

                FindingSensitiveCommands {
                    shell_type: state_context.history.shell.clone(),
                    sensitive_findings,
                    command: h.cmd.clone(),
                    data: serde_yaml::to_string(&h).unwrap(),
                    secrets,
                }
            })
            .collect::<Vec<_>>();

        self.masker.mask_sensitive_findings(results.as_mut());

        debug!(
            "time elapsed to read history file: {:?}. found {} commands",
            start.elapsed(),
            history.len()
        );

        Ok(results)
    }

    fn find_secrets(
        command: &str,
        sensitive_commands: &[SensitiveCommands],
    ) -> (Vec<String>, Vec<SensitiveCommands>) {
        let (secrets, sensitive_findings): (Vec<String>, Vec<SensitiveCommands>) =
            sensitive_commands
                .par_iter()
                .filter_map(|v| {
                    Some((
                        v.test
                            .captures(command)?
                            .get(v.secret_group as usize)?
                            .as_str()
                            .to_string(),
                        v.clone(),
                    ))
                })
                .unzip();

        (secrets, sensitive_findings)
    }
}

#[cfg(test)]
mod test_engine {
    use std::{fs, fs::File, io::Write};

    use insta::assert_debug_snapshot;
    use tempdir::TempDir;

    use super::*;

    const TEST_SENSITIVE_COMMANDS: &str = r###"
- name: Find me
  secret_group: 0
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

    fn create_mock_state(temp_dir: &TempDir, content: &str, shell_type: Shell) -> ShellContext {
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
            masker: Masker::new(),
        };
        let state_context = create_mock_state(&temp_dir, TEMP_HISTORY_LINES_CONTENT, Shell::Bash);

        let result = en.find_history_commands_from_shell_list(&vec![state_context]);

        assert_debug_snapshot!(result);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_find_history_commands_fish() {
        let temp_dir = TempDir::new("engine").unwrap();

        let en = PatternsEngine {
            commands: serde_yaml::from_str(TEST_SENSITIVE_COMMANDS).unwrap(),
            masker: Masker::new(),
        };
        let state_context = create_mock_state(&temp_dir, TEMP_HISTORY_FISH, Shell::Fish);

        let result = en.find_history_commands_from_shell_list(&vec![state_context]);

        assert_debug_snapshot!(result);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_find_custom_patterns() {
        let temp_dir = TempDir::new("engine").unwrap();

        let config = Config::with_custom_path(&temp_dir.path().join("app"));
        config.init().unwrap();
        let custom_pattern = r###"
- name: Pattern Name
  test: (FIND_ME)
  secret_group: 1
  id: elad_ignore
"###;
        fs::write(&config.sensitive_commands_path, custom_pattern).unwrap();

        let en = PatternsEngine::with_config(&config).unwrap();
        let state_context = create_mock_state(&temp_dir, TEMP_HISTORY_LINES_CONTENT, Shell::Bash);

        let result = en.find_history_commands_from_shell_list(&vec![state_context]);

        assert_debug_snapshot!(result);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_ignore_patterns() {
        let temp_dir = TempDir::new("engine").unwrap();

        let config = Config::with_custom_path(&temp_dir.path().join("app"));
        config.init().unwrap();
        let custom_pattern = r###"
- elad_ignore
"###;
        fs::write(&config.sensitive_commands_path, custom_pattern).unwrap();

        let en = PatternsEngine::with_config(&config).unwrap();
        let state_context = create_mock_state(&temp_dir, TEMP_HISTORY_LINES_CONTENT, Shell::Bash);

        let result = en.find_history_commands_from_shell_list(&vec![state_context]);

        assert_debug_snapshot!(result);
        temp_dir.close().unwrap();
    }
}
