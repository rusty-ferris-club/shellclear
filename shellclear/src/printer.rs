use crate::data::FindingSensitiveCommands;
use anyhow::Result;
use prettytable::{Cell, Row, Table};
use std::str;

pub fn show_sensitive_findings(
    out: &mut Vec<u8>,
    findings: Vec<FindingSensitiveCommands>,
) -> Result<()> {
    let mut table = Table::new();

    table.add_row(Row::new(vec![
        Cell::new("Shell"),
        Cell::new("Name"),
        Cell::new("Command"),
    ]));

    for f in findings {
        let cells = vec![
            Cell::new(&format!("{:?}", f.shell_type)),
            Cell::new(
                f.finding
                    .iter()
                    .map(|f| f.name.to_owned())
                    .collect::<Vec<_>>()
                    .join(",")
                    .as_ref(),
            ),
            Cell::new(&f.command.to_string()),
        ];
        table.add_row(Row::new(cells));
    }

    table.print(out)?;
    Ok(())
}

#[cfg(test)]
mod state_context {
    use super::*;
    use crate::data::SensitiveCommands;
    use crate::shell::Shell;

    #[test]
    fn can_print_table() {
        let mut out = Vec::new();

        let findings = vec![FindingSensitiveCommands {
            shell_type: Shell::Zshrc,
            finding: vec![
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
        let expected = "+-------+----------------------+--------------+\n| Shell | Name                 | Command      |\n+-------+----------------------+--------------+\n| Zshrc | test name,test name2 | test command |\n+-------+----------------------+--------------+\n";
        assert_eq!(str::from_utf8(&out).unwrap(), expected);
    }
}
