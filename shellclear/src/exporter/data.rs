use crate::data::FindingSensitiveCommands;
use crate::shell::Shell;
use anyhow::Result;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use lazy_static::lazy_static;
use regex::Regex;

const DATE_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

pub trait Exporter {
    fn sensitive_data(&self, findings: &[&FindingSensitiveCommands]) -> Result<()>;
}

lazy_static! {
    static ref ZSHRC_CAPTURE_TIME: Regex = Regex::new(r"^: ([0-9]+):").unwrap();
}

// todo:: move under export trait
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
            if let Some(c) = ZSHRC_CAPTURE_TIME.captures(&finding.data) {
                if let Some(timestemp) = c.get(1) {
                    let date_time: DateTime<Local> = Local.from_utc_datetime(
                        &NaiveDateTime::from_timestamp(timestemp.as_str().parse::<i64>()?, 0),
                    );
                    return Ok(format!("{}", date_time.format(DATE_TIME_FORMAT)));
                }
            };
            Ok(finding.data.clone())
        }
        _ => Ok("".to_string()),
    }
}
