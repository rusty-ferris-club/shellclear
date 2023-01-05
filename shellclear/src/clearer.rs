use std::fmt::Write;
use std::fs::write;
use std::time::Instant;

use anyhow::Result;

use crate::engine::ShellCommands;
use crate::ShellContext;

pub struct Clearer {}

impl Clearer {
    /// Load sensitive ignores file
    ///
    /// # Errors
    ///
    /// Will return `Err` when the history file cannot be opened / written to
    pub fn write_findings(
        shells_context: &[ShellContext],
        commands: &ShellCommands,
        remove: bool,
    ) -> Result<()> {
        for context in shells_context {
            let start = Instant::now();
            let mut cleared_history: String = String::new();

            for command in commands
                .get_commands_per_shell(&context.history.shell)
                .unwrap_or(&vec![])
            {
                if remove {
                    if command.detections.is_empty() {
                        writeln!(&mut cleared_history, "{}", command.data)?;
                    }
                } else {
                    writeln!(&mut cleared_history, "{}", command.data)?;
                }
            }

            if !cleared_history.is_empty() {
                write(&context.history.path, cleared_history)?;
                log::debug!(
                    "time elapsed for backup existing file and write a new history to shell : {:?}",
                    start.elapsed()
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use insta::assert_debug_snapshot;
    use regex::Regex;
    use tempdir::TempDir;

    use crate::data::{Command, Detection};
    use crate::shell::History;
    use crate::shell::Shell::Zshrc;

    use super::*;

    fn mock_state(dir: &Path) -> (ShellCommands, Vec<ShellContext>) {
        let state_context = vec![ShellContext {
            app_folder_path: "mock".to_string(),
            history: History {
                shell: Zshrc,
                file_name: "mock".to_string(),
                path: dir.to_str().unwrap().into(),
            },
        }];

        // We test one finding with a secret and one without a secret
        // The secret should be filtered out when using remove = true param
        let findings = vec![
            Command {
                command: "mock".to_string(),
                data: "mock".to_string(),
                detections: vec![],
                shell_type: Zshrc,
                secrets: vec![],
            },
            Command {
                command: "should be removed".to_string(),
                data: "should be removed".to_string(),
                detections: vec![Detection {
                    name: "mock".to_string(),
                    secret_group: 0,
                    id: "mock-id".to_string(),
                    test: Regex::new("").unwrap(),
                }],
                shell_type: Zshrc,
                secrets: vec!["mock".to_string()],
            },
        ];

        let mut commands = ShellCommands::default();

        commands.add_commands(&Zshrc, findings);

        (commands, state_context)
    }

    #[test]
    fn remove_sensitive_commands() {
        let dir = TempDir::new("clearer").unwrap();
        let history = dir.path().join("history");

        let (commands, state_context) = mock_state(&history);

        Clearer::write_findings(&state_context, &commands, true).unwrap();

        let content = fs::read_to_string(history).unwrap();

        assert_debug_snapshot!(content);

        dir.close().unwrap();
    }

    #[test]
    fn persist_sensitive_commands() {
        let dir = TempDir::new("clearer").unwrap();
        let history = dir.path().join("history");

        let (commands, state_context) = mock_state(&history);

        Clearer::write_findings(&state_context, &commands, false).unwrap();

        let content = fs::read_to_string(history).unwrap();

        assert_debug_snapshot!(content);

        dir.close().unwrap();
    }
}
