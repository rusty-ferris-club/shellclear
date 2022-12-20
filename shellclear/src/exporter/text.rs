use std::{io::Write, str};

use anyhow::Result;
use console::style;

use crate::{
    data::FindingSensitiveCommands,
    exporter::data::{chunk, extract_time, Exporter, LIMIT_COMMAND},
};

#[derive(Default)]
pub struct Text {}

impl Text {
    fn prepare_sensitive_data(
        out: &mut Vec<u8>,
        findings: &[&FindingSensitiveCommands],
    ) -> Result<()> {
        let mut count = 0;
        for f in findings.iter() {
            count += 1;
            let finding_names = f
                .sensitive_findings
                .iter()
                .map(|f| f.name.clone())
                .collect::<Vec<_>>()
                .join(", ");

            let title = format!(
                "{}. [{}] {} {}",
                count,
                f.shell_type,
                finding_names,
                extract_time(f).unwrap_or_else(|_| "".to_string())
            );

            writeln!(out, "{}", style(title).bold())?;
            writeln!(out, "{}", chunk(&f.command, LIMIT_COMMAND))?;
            writeln!(out)?;
        }
        Ok(())
    }
}

impl Exporter for Text {
    fn sensitive_data(&self, findings: &[&FindingSensitiveCommands]) -> Result<()> {
        let mut out = Vec::new();
        Self::prepare_sensitive_data(&mut out, findings)?;
        print!("{}", str::from_utf8(&out)?);
        Ok(())
    }
}

#[cfg(test)]
mod test_exporter_text {
    use std::str;

    use insta::assert_debug_snapshot;
    use regex::Regex;

    use super::*;
    use crate::{data::SensitiveCommands, shell::Shell};

    #[test]
    fn can_prepare_sensitive_data() {
        let mut out = Vec::new();

        let shell_finding = FindingSensitiveCommands {
            shell_type: Shell::Zshrc,
            sensitive_findings: vec![
                SensitiveCommands {
                    test: Regex::new("test").unwrap(),
                    name: "test name".to_string(),
                    id: "".to_string(),
                    secret_group: 0,
                },
                SensitiveCommands {
                    test: Regex::new("test2").unwrap(),
                    name: "test name2".to_string(),
                    id: "".to_string(),
                    secret_group: 0,
                },
            ],
            command: "test command".to_string(),
            data: ": 1655110559:0;command data".to_string(),
            secrets: vec![],
        };

        let findings = vec![&shell_finding];
        let resp = Text::prepare_sensitive_data(&mut out, &findings);

        assert_debug_snapshot!(resp);
        assert_debug_snapshot!(str::from_utf8(&out)
            .unwrap()
            .replace("\r\n", "\n")
            .replace("\u{1b}[1m", "")
            .replace("\u{1b}[0m", ""));
    }
}
