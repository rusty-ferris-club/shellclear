use mask_text::Kind;

use crate::data::Command;

const DEFAULT_PERCENTAGE: u8 = 80;
const DEFAULT_MIN_CHARS: usize = 3;
const DEFAULT_MASK_CHARS: &str = "*";

pub struct Masker {
    percentage: u8,
    min_chars: usize,
    mask_chars: String,
}

impl Masker {
    pub fn new() -> Self {
        Self {
            percentage: DEFAULT_PERCENTAGE,
            min_chars: DEFAULT_MIN_CHARS,
            mask_chars: DEFAULT_MASK_CHARS.to_string(),
        }
    }

    pub fn mask_sensitive_findings(&self, results: &mut [Command]) {
        let commands_with_detections = Masker::get_commands_with_detection(results);

        for command in commands_with_detections {
            let should_mask = command.secrets.iter().any(|secret| {
                let replaced_secret = Kind::Percentage(
                    secret.clone(),
                    self.percentage,
                    self.min_chars,
                    self.mask_chars.clone(),
                )
                .mask();

                // there can still be an false-positive here, if the text is all made up of
                // asterisks
                !command.command.contains(&replaced_secret)
            });

            if !should_mask {
                // If all the secrets are already masked, set the detections to an empty vec,
                // this represents that this command is already masked / no secrets detected
                command.detections = vec![];
                continue;
            }

            // Can be optimized, we can chose to not re-mask the secret, using a map, etc...
            for secret in &command.secrets {
                let replaced_secret = Kind::Percentage(
                    secret.clone(),
                    self.percentage,
                    self.min_chars,
                    self.mask_chars.clone(),
                )
                .mask();

                command.command = command.command.replace(secret, &replaced_secret);
                command.data = command.data.replace(secret, &replaced_secret);
            }
        }
    }

    fn get_commands_with_detection(commands: &mut [Command]) -> Vec<&mut Command> {
        commands
            .iter_mut()
            .filter(|c| !c.detections.is_empty())
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod test_masker {
    use anyhow::Result;
    use insta::assert_debug_snapshot;
    use regex::Regex;

    use crate::{
        data::{Command, Detection},
        masker::Masker,
        shell::Shell::Zshrc,
    };

    #[test]
    fn mask_results() -> Result<()> {
        let mut commands = vec![Command {
            shell_type: Zshrc,
            detections: vec![Detection {
                test: Regex::new("export (MASK_ME)")?,
                name: "mask me mock".to_string(),
                secret_group: 1,
                id: "".to_string(),
            }],
            command: "export MASK_ME".to_string(),
            data: "export MASK_ME".to_string(),
            secrets: vec!["MASK_ME".to_string()],
        }];

        Masker::new().mask_sensitive_findings(commands.as_mut());

        assert_debug_snapshot!(commands);

        Ok(())
    }

    #[test]
    fn remove_already_masked_detection() -> Result<()> {
        let mut commands = [Command {
            shell_type: Zshrc,
            detections: vec![Detection {
                test: Regex::new("export (MASK_ME)")?,
                name: "mask me mock".to_string(),
                secret_group: 1,
                id: "".to_string(),
            }],
            command: "export MA*****".to_string(),
            data: "export MA*****".to_string(),
            secrets: vec!["MASK_ME".to_string()],
        }];

        Masker::new().mask_sensitive_findings(commands.as_mut());

        assert_debug_snapshot!(commands);

        Ok(())
    }
}
