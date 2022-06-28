use crate::data::FindingSensitiveCommands;
use prettytable::{Cell, Row, Table};

pub fn show_sensitive_findings(findings: Vec<FindingSensitiveCommands>) {
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

    table.printstd();
}
