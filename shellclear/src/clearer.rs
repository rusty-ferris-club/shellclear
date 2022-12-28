use std::collections::HashMap;
use std::fmt::Write;
use std::fs::write;
use std::time::Instant;

use anyhow::Result;

use crate::data::FindingSensitiveCommands;
use crate::shell::Shell;
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
        findings: &[FindingSensitiveCommands],
        remove: bool,
    ) -> Result<()> {
        let findings_per_shell = Clearer::group_findings_by_shell(findings);

        for context in shells_context {
            let start = Instant::now();
            let mut cleared_history: String = String::new();

            for &r in findings_per_shell
                .get(&context.history.shell)
                .unwrap_or(&vec![])
            {
                if remove {
                    if r.sensitive_findings.is_empty() {
                        writeln!(&mut cleared_history, "{}", r.data)?;
                    }
                } else {
                    writeln!(&mut cleared_history, "{}", r.data)?;
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

    fn group_findings_by_shell(
        findings: &[FindingSensitiveCommands],
    ) -> HashMap<Shell, Vec<&FindingSensitiveCommands>> {
        let mut findings_by_shell: HashMap<Shell, Vec<&FindingSensitiveCommands>> = HashMap::new();

        for finding in findings {
            if let Some(vec) = findings_by_shell.get_mut(&finding.shell_type) {
                vec.push(finding);
            } else {
                findings_by_shell.insert(finding.shell_type.clone(), vec![finding]);
            }
        }

        findings_by_shell
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use insta::assert_debug_snapshot;
    use regex::Regex;
    use tempdir::TempDir;

    use crate::data::{FindingSensitiveCommands, SensitiveCommands};
    use crate::shell::History;
    use crate::shell::Shell::Zshrc;

    use super::*;

    fn mock_state(dir: &Path) -> (Vec<FindingSensitiveCommands>, Vec<ShellContext>) {
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
            FindingSensitiveCommands {
                command: "mock".to_string(),
                data: "mock".to_string(),
                sensitive_findings: vec![],
                shell_type: Zshrc,
                secrets: vec![],
            },
            FindingSensitiveCommands {
                command: "should be removed".to_string(),
                data: "should be removed".to_string(),
                sensitive_findings: vec![SensitiveCommands {
                    name: "mock".to_string(),
                    secret_group: 0,
                    id: "mock-id".to_string(),
                    test: Regex::new("").unwrap(),
                }],
                shell_type: Zshrc,
                secrets: vec!["mock".to_string()],
            },
        ];

        (findings, state_context)
    }

    #[test]
    fn remove_sensitive_commands() {
        let dir = TempDir::new("clearer").unwrap();
        let history = dir.path().join("history");

        let (findings, state_context) = mock_state(&history);

        Clearer::write_findings(&state_context, &findings, true).unwrap();

        let content = fs::read_to_string(history).unwrap();

        assert_debug_snapshot!(content);

        dir.close().unwrap();
    }

    #[test]
    fn persist_sensitive_commands() {
        let dir = TempDir::new("clearer").unwrap();
        let history = dir.path().join("history");

        let (findings, state_context) = mock_state(&history);

        Clearer::write_findings(&state_context, &findings, false).unwrap();

        let content = fs::read_to_string(history).unwrap();

        assert_debug_snapshot!(content);

        dir.close().unwrap();
    }
}
