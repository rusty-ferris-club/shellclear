use crate::data::FindingSensitiveCommands;
use crate::shell::Shell;
use anyhow::Result;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use console::style;
use lazy_static::lazy_static;
use prettytable::{Cell, Row, Table};
use regex::Regex;

lazy_static! {
    static ref ZSHRC_CAPTURE_TIME: Regex = Regex::new(r"^: ([0-9]+):").unwrap();
}

/// write sensitive command findings to the given out
///
/// # Errors
///
/// Will return `Err` when couldn't write table result to out file
pub fn show_sensitive_findings_in_table(
    out: &mut Vec<u8>,
    findings: &[&FindingSensitiveCommands],
) -> Result<()> {
    let mut table = Table::new();

    table.add_row(Row::new(vec![
        Cell::new("#"),
        Cell::new("Shell"),
        Cell::new("Name"),
        Cell::new("Command"),
    ]));

    let mut count = 0;
    let rows = findings
        .iter()
        .map(|f| {
            count += 1;
            vec![
                Cell::new(&format!("{:?}", count)),
                Cell::new(&format!("{:?}", f.shell_type)),
                Cell::new(
                    f.sensitive_findings
                        .iter()
                        .map(|f| f.name.clone())
                        .collect::<Vec<_>>()
                        .join("\r\n")
                        .as_ref(),
                ),
                Cell::new(&chunk(&f.command, 150)),
            ]
        })
        .collect::<Vec<_>>();

    let should_print = &rows.is_empty();
    for row in rows {
        table.add_row(Row::new(row));
    }

    if !should_print {
        table.print(out)?;
    }
    Ok(())
}

pub fn print_show_sensitive_findings(findings: &[&FindingSensitiveCommands]) {
    let mut count = 0;
    for f in findings.iter() {
        count += 1;
        let finding_names = f
            .sensitive_findings
            .iter()
            .map(|f| f.name.clone())
            .collect::<Vec<_>>()
            .join(",");

        let title = format!(
            "{}. {} {}",
            count,
            finding_names,
            extract_time(f).unwrap_or_else(|_| "".to_string())
        );
        println!("{}", style(title).bold());
        println!("{}", chunk(&f.command, 150));
    }
}

fn chunk(text: &str, size: usize) -> String {
    text.chars()
        .collect::<Vec<char>>()
        .chunks(size)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\r\n")
}

fn extract_time(finding: &FindingSensitiveCommands) -> Result<String> {
    match finding.shell_type {
        Shell::Zshrc => {
            if let Some(c) = ZSHRC_CAPTURE_TIME.captures(&finding.data) {
                if let Some(timestemp) = c.get(1) {
                    let aa = timestemp.as_str().parse::<i64>()?;
                    let date_time: DateTime<Local> =
                        Local.from_utc_datetime(&NaiveDateTime::from_timestamp(aa, 0));
                    return Ok(format!("{}", date_time));
                }
            };
            Ok(finding.data.clone())
        }
        _ => Ok("".to_string()),
    }
}

#[cfg(test)]
mod test_printer {
    use super::*;
    use crate::data::SensitiveCommands;
    use crate::shell::Shell;
    use insta::assert_debug_snapshot;
    use regex::Regex;
    use std::str;

    #[test]
    fn can_print_table() {
        let mut out = Vec::new();

        let shell_finding = FindingSensitiveCommands {
            shell_type: Shell::Zshrc,
            sensitive_findings: vec![
                SensitiveCommands {
                    test: Regex::new("test").unwrap(),
                    name: "test name".to_string(),
                },
                SensitiveCommands {
                    test: Regex::new("test2").unwrap(),
                    name: "test name2".to_string(),
                },
            ],
            command: "test command".to_string(),
            data: "command data".to_string(),
        };
        let findings = vec![&shell_finding];
        let resp = show_sensitive_findings_in_table(&mut out, &findings);

        assert_debug_snapshot!(resp);
        assert_debug_snapshot!(str::from_utf8(&out).unwrap().replace("\r\n", "\n"));
    }
}
