use crate::data::FindingSensitiveCommands;
use crate::shell::FishHistory;
use crate::shell::Shell;
use anyhow::Result;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use lazy_static::lazy_static;
use regex::Regex;

const DATE_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
pub const LIMIT_COMMAND: usize = 100;

pub trait Exporter {
    /// export sensitive findings results
    ///
    /// # Errors
    ///
    /// Will return `Err` export has an error
    fn sensitive_data(&self, findings: &[&FindingSensitiveCommands]) -> Result<()>;
}

lazy_static! {
    static ref ZSHRC_CAPTURE_COMMAND_TIME: Regex = Regex::new(r"^: ([0-9]+):").unwrap();
}

pub fn chunk(text: &str, size: usize) -> String {
    text.chars()
        .collect::<Vec<char>>()
        .chunks(size)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\r\n")
}

/// Get command time execution
///
/// # Errors
///
/// Will return `Err` when conversion error
pub fn extract_time(finding: &FindingSensitiveCommands) -> Result<String> {
    match finding.shell_type {
        Shell::Zshrc => {
            if let Some(c) = ZSHRC_CAPTURE_COMMAND_TIME.captures(&finding.data) {
                if let Some(timestemp) = c.get(1) {
                    return Ok(format!(
                        "{}",
                        convert_str_timestamp_to_date_time(timestemp.as_str())?
                            .format(DATE_TIME_FORMAT)
                    ));
                }
            };
            Ok(finding.data.clone())
        }
        Shell::Fish => {
            let history: FishHistory = serde_yaml::from_str(&finding.data)?;
            Ok(format!(
                "{}",
                convert_str_timestamp_to_date_time(history.when.as_str())?.format(DATE_TIME_FORMAT)
            ))
        }
        _ => Ok("".to_string()),
    }
}

fn convert_str_timestamp_to_date_time(timestamp: &str) -> Result<DateTime<Local>> {
    Ok(Local.from_utc_datetime(&NaiveDateTime::from_timestamp(timestamp.parse::<i64>()?, 0)))
}

#[cfg(test)]
mod test_exporter {
    use super::*;
    use crate::shell::Shell;
    use insta::assert_debug_snapshot;
    use std::str;

    #[test]
    fn can_extract_time_zshrc() {
        let shell_finding = FindingSensitiveCommands {
            shell_type: Shell::Zshrc,
            sensitive_findings: vec![],
            command: "test command".to_string(),
            data: ": 1655110559:0;command data".to_string(),
        };

        let resp = extract_time(&shell_finding);

        assert_debug_snapshot!(resp);
    }

    #[test]
    fn can_extract_time_fish() {
        let shell_finding = FindingSensitiveCommands {
            shell_type: Shell::Fish,
            sensitive_findings: vec![],
            command: "test command".to_string(),
            data: r#"{ cmd: "export test command", when: "1655110559" }"#.to_string(),
        };

        let resp = extract_time(&shell_finding);

        assert_debug_snapshot!(resp);
    }
}
