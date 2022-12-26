use mask_text::Kind;

use crate::data::FindingSensitiveCommands;

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
        Masker {
            percentage: DEFAULT_PERCENTAGE,
            min_chars: DEFAULT_MIN_CHARS,
            mask_chars: DEFAULT_MASK_CHARS.to_string(),
        }
    }

    pub fn mask_sensitive_findings(&self, results: &mut [FindingSensitiveCommands]) {
        for sensitive_command in results {
            for secret in &sensitive_command.secrets {
                let replaced_secret = Kind::Percentage(
                    secret.clone(),
                    self.percentage,
                    self.min_chars,
                    self.mask_chars.clone(),
                )
                .mask();

                sensitive_command.command =
                    sensitive_command.command.replace(secret, &replaced_secret);
                sensitive_command.data = sensitive_command.data.replace(secret, &replaced_secret)
            }
        }
    }
}
