use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use lazy_static::lazy_static;
use regex::Regex;

use crate::{
    data::Command,
    shell::{FishHistory, Shell},
};

const DATE_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
pub const LIMIT_COMMAND: usize = 100;

pub trait Exporter {
    /// export sensitive findings results
    ///
    /// # Errors
    ///
    /// Will return `Err` export has an error
    fn sensitive_data(&self, findings: &[Command]) -> Result<()>;
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
pub fn extract_time(finding: &Command) -> Result<String> {
    match finding.shell_type {
        Shell::Zshrc => {
            if let Some(c) = ZSHRC_CAPTURE_COMMAND_TIME.captures(&finding.data) {
                if let Some(timestamp) = c.get(1) {
                    return Ok(format!(
                        "{}",
                        convert_str_timestamp_to_date_time(timestamp.as_str())?
                            .format(DATE_TIME_FORMAT)
                    ));
                }
            };
            Ok(String::new())
        }
        Shell::Fish => {
            let history: FishHistory = serde_yaml::from_str(&finding.data)?;
            Ok(format!(
                "{}",
                convert_str_timestamp_to_date_time(history.when.as_str())?.format(DATE_TIME_FORMAT)
            ))
        }
        _ => Ok(String::new()),
    }
}

fn convert_str_timestamp_to_date_time(timestamp: &str) -> Result<DateTime<Utc>> {
    Ok(Utc.from_utc_datetime(&NaiveDateTime::from_timestamp(timestamp.parse::<i64>()?, 0)))
}

#[cfg(test)]
mod test_exporter {
    use std::str;

    use insta::assert_debug_snapshot;

    use super::*;
    use crate::shell::Shell;

    #[test]
    fn can_extract_time_zshrc() {
        let shell_finding = Command {
            shell_type: Shell::Zshrc,
            detections: vec![],
            command: "test command".to_string(),
            data: ": 1655110559:0;command data".to_string(),
            secrets: vec![],
        };

        let resp = extract_time(&shell_finding);

        assert_debug_snapshot!(resp);
    }

    #[test]
    fn can_extract_time_fish() {
        let shell_finding = Command {
            shell_type: Shell::Fish,
            detections: vec![],
            command: "test command".to_string(),
            data: r#"{ cmd: "export test command", when: "1655110559" }"#.to_string(),
            secrets: vec![],
        };

        let resp = extract_time(&shell_finding);

        assert_debug_snapshot!(resp);
    }
}
