use std::{
    fmt::Write,
    fs::{write, File},
    io::{prelude::*, BufReader},
    time::Instant,
};

use anyhow::Result;
use log::debug;
use rayon::prelude::*;
use regex::Match;


// TODO: Remove clear param
// TODO: Add masking obj
// TODO: Tests
// TODO: add find secrets to self

use crate::{
    config::Config,
    data::{FindingSensitiveCommands, SensitiveCommands},
    shell,
    state::ShellContext,
};

pub const SENSITIVE_COMMANDS: &str = include_str!("sensitive-patterns.yaml");

pub struct PatternsEngine {
    commands: Vec<SensitiveCommands>,
}

#[derive(Default, Debug)]
pub struct Findings {
    pub patterns: Vec<FindingSensitiveCommands>,
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

            patterns = if config.is_app_path_exists() {
                // load external patterns
                match config.load_patterns_from_default_path() {
                    Ok(p) => patterns.extend(p),
                    Err(e) => log::debug!("could not load external pattern. {:?}", e),
                };

                // ignore patterns
                match config.get_ignore_patterns() {
                    Ok(ignores) => patterns
                        .iter()
                        .filter(|p| !ignores.contains(&p.id))
                        .cloned()
                        .collect::<Vec<_>>(),
                    Err(e) => {
                        log::debug!("could not load ignore pattern. {:?}", e);
                        patterns
                    }
                }
            } else {
                log::debug!(
                    "app config folder not found in path: {}",
                    &config.app_path.display()
                );
                patterns
            };

            patterns
        };
        Ok(Self {
            commands: sensitive_patterns,
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
    /// Will return `Err` if history file not exists/ couldn't open
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
        sensitive_commands: &[SensitiveCommands],
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
        let mut results = lines
            .par_iter()
            .map(|command| {
                let (secrets, sensitive_findings) = find_secrets(command, sensitive_commands);

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


        mask_results(results.as_mut());

        debug!(
            "time elapsed for detect sensitive commands: {:?}",
            start.elapsed()
        );

        if clear {
            let start = Instant::now();
            let mut cleared_history: String = String::new();

            for r in &results {
                // TODO: Remove only when the user passes the --remove flag
                let _ = writeln!(&mut cleared_history, "{}", r.data);
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
        sensitive_commands: &[SensitiveCommands],
        clear: bool,
    ) -> Result<Vec<FindingSensitiveCommands>> {
        let start = Instant::now();
        let history: Vec<shell::FishHistory> =
            serde_yaml::from_reader(File::open(&state_context.history.path)?)?;

        let mut results = history
            .par_iter()
            .map(|h| {
                let (secrets, sensitive_findings) = find_secrets(&h.cmd, sensitive_commands);

                FindingSensitiveCommands {
                    shell_type: state_context.history.shell.clone(),
                    sensitive_findings,
                    command: h.cmd.clone(),
                    data: serde_yaml::to_string(&h).unwrap(),
                    secrets,
                }
            })
            .collect::<Vec<_>>();

        mask_results(results.as_mut());

        debug!(
            "time elapsed to read history file: {:?}. found {} commands",
            start.elapsed(),
            history.len()
        );

        if clear {
            let start = Instant::now();
            let mut cleared_history: Vec<shell::FishHistory> = Vec::new();

            for command_line in &results {
                // TODO: Remove only when the user passes the --remove flag
                cleared_history.push(serde_yaml::from_str(&command_line.data)?);
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

fn find_secrets(command: &str, sensitive_commands: &[SensitiveCommands]) -> (Vec<String>, Vec<SensitiveCommands>) {
    let (secrets, sensitive_findings): (Vec<Option<Match>>, Vec<SensitiveCommands>) = sensitive_commands
        .par_iter()
        .map(|v| {
            let capture = v.test.captures(command)?;

            Some((capture.get(v.secret_group as usize), v.clone()))
        })
        .flatten()
        .unzip();

    let secrets = secrets.iter()
        .flatten()
        .map(|m| m.as_str().to_string())
        .collect();

    (secrets, sensitive_findings)
}

fn mask_results(results: &mut [FindingSensitiveCommands]) {
    for sensitive_command in results {
        for secret in &sensitive_command.secrets {
            let replaced_secret = mask_text::Kind::Percentage(
                secret.clone(),
                80,
                3,
                "*".to_string(),
            ).mask();

            sensitive_command.command = sensitive_command.command.replace(secret, &replaced_secret);
            sensitive_command.data = sensitive_command.data.replace(secret, &replaced_secret)
        }
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

        let result = en.find_history_commands_from_shell_list(&vec![state_context], false);

        assert_debug_snapshot!(result);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_clear_command_by_lines() {
        let temp_dir = TempDir::new("engine").unwrap();

        let en = PatternsEngine {
            commands: serde_yaml::from_str(TEST_SENSITIVE_COMMANDS).unwrap(),
        };
        let state_context =
            create_mock_state(&temp_dir, TEMP_HISTORY_LINES_CONTENT, shell::Shell::Bash);

        let result = en.find_history_commands_from_shell_list(&vec![state_context.clone()], true);

        assert_debug_snapshot!(result);
        assert_debug_snapshot!(fs::read_to_string(state_context.history.path));
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_clear_find_fish() {
        let temp_dir = TempDir::new("engine").unwrap();

        let en = PatternsEngine {
            commands: serde_yaml::from_str(TEST_SENSITIVE_COMMANDS).unwrap(),
        };
        let state_context = create_mock_state(&temp_dir, TEMP_HISTORY_FISH, shell::Shell::Fish);

        let result = en.find_history_commands_from_shell_list(&vec![state_context.clone()], true);

        assert_debug_snapshot!(result);
        assert_debug_snapshot!(fs::read_to_string(state_context.history.path).unwrap());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_find_history_commands_fish() {
        let temp_dir = TempDir::new("engine").unwrap();

        let en = PatternsEngine {
            commands: serde_yaml::from_str(TEST_SENSITIVE_COMMANDS).unwrap(),
        };
        let state_context = create_mock_state(&temp_dir, TEMP_HISTORY_FISH, shell::Shell::Fish);

        let result = en.find_history_commands_from_shell_list(&vec![state_context], false);

        assert_debug_snapshot!(result);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_find_custom_patterns() {
        let temp_dir = TempDir::new("engine").unwrap();

        let config = Config::with_custom_path(temp_dir.path().join("app"));
        config.init().unwrap();
        let custom_pattern = r###"
- name: Pattern Name
  test: FIND_ME
  secret_group: 1
  id: elad_ignore
"###;
        fs::write(&config.sensitive_commands_path, custom_pattern).unwrap();

        let en = PatternsEngine::with_config(&config).unwrap();
        let state_context =
            create_mock_state(&temp_dir, TEMP_HISTORY_LINES_CONTENT, shell::Shell::Bash);

        let result = en.find_history_commands_from_shell_list(&vec![state_context], false);

        assert_debug_snapshot!(result);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_ignore_patterns() {
        let temp_dir = TempDir::new("engine").unwrap();

        let config = Config::with_custom_path(temp_dir.path().join("app"));
        config.init().unwrap();
        let custom_pattern = r###"
- elad_ignore
"###;
        fs::write(&config.sensitive_commands_path, custom_pattern).unwrap();

        let en = PatternsEngine::with_config(&config).unwrap();
        let state_context =
            create_mock_state(&temp_dir, TEMP_HISTORY_LINES_CONTENT, shell::Shell::Bash);

        let result = en.find_history_commands_from_shell_list(&vec![state_context], false);

        assert_debug_snapshot!(result);
        temp_dir.close().unwrap();
    }
}
