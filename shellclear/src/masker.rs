use mask_text::Kind;
use crate::data::FindingSensitiveCommands;

pub struct Masker {
    percentage: u8,
    min_chars: usize,
    mask_chars: String,
}

impl Masker {
    pub fn _with(percentage: u8, min_chars: usize, mask_chars: String) -> Self {
        Masker { percentage, min_chars, mask_chars }
    }

    pub fn new() -> Self {
        Masker { percentage: 80, min_chars: 3, mask_chars: "*".to_string() }
    }

    pub fn mask_sensitive_findings(&self, results: &mut [FindingSensitiveCommands]) {
        for sensitive_command in results {
            for secret in &sensitive_command.secrets {
                let replaced_secret = Kind::Percentage(
                    secret.clone(),
                    self.percentage,
                    self.min_chars,
                    self.mask_chars.clone(),
                ).mask();

                sensitive_command.command = sensitive_command.command.replace(secret, &replaced_secret);
                sensitive_command.data = sensitive_command.data.replace(secret, &replaced_secret)
            }
        }
    }
}