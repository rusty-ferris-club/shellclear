use crate::data::FindingSensitiveCommands;
use anyhow::Result;
use prettytable::{Cell, Row, Table};

/// write sensitive command findings to the given out
///
/// # Errors
///
/// Will return `Err` when couldn't write table result to out file
pub fn show_sensitive_findings(
    out: &mut Vec<u8>,
    findings: &[FindingSensitiveCommands],
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
        .filter(|f| !f.sensitive_findings.is_empty())
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

fn chunk(text: &str, size: usize) -> String {
    text.chars()
        .collect::<Vec<char>>()
        .chunks(size)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\r\n")
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

        let findings = vec![FindingSensitiveCommands {
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
        }];
        let resp = show_sensitive_findings(&mut out, &findings);

        assert_debug_snapshot!(resp);
        assert_debug_snapshot!(str::from_utf8(&out).unwrap().replace("\r\n", "\n"));
    }
}
