use std::str;

use anyhow::Result;
use prettytable::{Cell, Row};

use crate::{
    data::Command,
    exporter::data::{chunk, extract_time, Exporter, LIMIT_COMMAND},
};

#[derive(Default)]
pub struct Table {}

impl Exporter for Table {
    fn sensitive_data(&self, findings: &[Command]) -> Result<()> {
        let mut out = Vec::new();
        Self::prepare_sensitive_data(&mut out, findings)?;
        print!("{}", str::from_utf8(&out)?);
        Ok(())
    }
}

impl Table {
    fn prepare_sensitive_data(out: &mut Vec<u8>, findings: &[Command]) -> Result<()> {
        let mut table = prettytable::Table::new();

        table.add_row(Row::new(vec![
            Cell::new("#"),
            Cell::new("Shell"),
            Cell::new("Time"),
            Cell::new("Name"),
            Cell::new("Command"),
        ]));

        let mut count = 0;
        let rows = findings
            .iter()
            .map(|f| {
                count += 1;
                vec![
                    Cell::new(&format!("{count:?}")),
                    Cell::new(&format!("{:?}", f.shell_type)),
                    Cell::new(&extract_time(f).unwrap_or_else(|_| String::new())),
                    Cell::new(
                        f.detections
                            .iter()
                            .map(|f| f.name.clone())
                            .collect::<Vec<_>>()
                            .join("\r\n")
                            .as_ref(),
                    ),
                    Cell::new(&chunk(&f.command, LIMIT_COMMAND)),
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
}

#[cfg(test)]
mod test_exporter_table {
    use std::str;

    use insta::assert_debug_snapshot;
    use regex::Regex;

    use super::*;
    use crate::{data::Detection, shell::Shell};

    #[test]
    fn can_prepare_sensitive_data() {
        assert!(true)
        // let mut out = Vec::new();

        // let shell_finding = Command {
        //     shell_type: Shell::Zshrc,
        //     detections: vec![
        //         Detection {
        //             test: Regex::new("test").unwrap(),
        //             name: "test name".to_string(),
        //             id: String::new(),
        //             secret_group: 0,
        //         },
        //         Detection {
        //             test: Regex::new("test2").unwrap(),
        //             name: "test name2".to_string(),
        //             id: String::new(),
        //             secret_group: 0,
        //         },
        //     ],
        //     command: "test command".to_string(),
        //     data: ": 1655110559:0;command data".to_string(),
        //     secrets: vec![],
        // };

        // let findings = vec![shell_finding];
        // let resp = Table::prepare_sensitive_data(&mut out, &findings);

        // assert_debug_snapshot!(resp);
        // assert_debug_snapshot!(str::from_utf8(&out).unwrap().replace("\r\n",
        // "\n"));
    }
}
