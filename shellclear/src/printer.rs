use crate::data::FindingSensitiveCommands;
use anyhow::Result;
use prettytable::{Cell, Row, Table};

pub fn show_sensitive_findings(
    out: &mut Vec<u8>,
    findings: Vec<FindingSensitiveCommands>,
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
                        .map(|f| f.name.to_owned())
                        .collect::<Vec<_>>()
                        .join(",")
                        .as_ref(),
                ),
                Cell::new(&f.command.to_string()),
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

#[cfg(test)]
mod test_printer {
    use super::*;
    use crate::data::SensitiveCommands;
    use crate::shell::Shell;
    use std::str;

    #[test]
    fn can_print_table() {
        let mut out = Vec::new();

        let findings = vec![FindingSensitiveCommands {
            shell_type: Shell::Zshrc,
            sensitive_findings: vec![
                SensitiveCommands {
                    test: "test".to_string(),
                    name: "test name".to_string(),
                },
                SensitiveCommands {
                    test: "test2".to_string(),
                    name: "test name2".to_string(),
                },
            ],
            command: "test command".to_string(),
        }];
        let resp = show_sensitive_findings(&mut out, findings);

        assert!(resp.is_ok());

        #[cfg(target_os = "windows")]
        let expected = "+---+-------+----------------------+--------------+\r\n| # | Shell | Name                 | Command      |\r\n+---+-------+----------------------+--------------+\r\n| 1 | shrc | test name,test name2 | test command |\r\n+---+-------+----------------------+--------------+\r\n";
        #[cfg(not(target_os = "windows"))]
        let expected = "+---+-------+----------------------+--------------+\n| # | Shell | Name                 | Command      |\n+---+-------+----------------------+--------------+\n| 1 | Zshrc | test name,test name2 | test command |\n+---+-------+----------------------+--------------+\n";
        assert_eq!(
            format!("{}", str::from_utf8(&out).unwrap()),
            format!("{}", expected)
        );
    }
}
