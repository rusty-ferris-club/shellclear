use std::io::Write;

use crate::data::FindingSensitiveCommands;
use crate::exporter::data::{chunk, extract_time, Exporter};
use anyhow::Result;
use console::style;
use std::str;

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
                .join(",");

            let title = format!(
                "{}. [{}] {} {}",
                count,
                f.shell_type,
                finding_names,
                extract_time(f).unwrap_or_else(|_| "".to_string())
            );

            writeln!(out, "{}", style(title).bold())?;
            writeln!(out, "{}", chunk(&f.command, 150))?;
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
    use super::*;
    use crate::data::SensitiveCommands;
    use crate::shell::Shell;
    use insta::assert_debug_snapshot;
    use regex::Regex;
    use std::str;

    #[test]
    fn can_prepare_sensitive_data() {
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
            data: ": 1655110559:0;command data".to_string(),
        };

        let findings = vec![&shell_finding];
        let resp = Text::prepare_sensitive_data(&mut out, &findings);

        assert_debug_snapshot!(resp);
        assert_debug_snapshot!(str::from_utf8(&out).unwrap().replace("\r\n", "\n"));
    }
}
