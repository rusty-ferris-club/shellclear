use crate::data::FindingSensitiveCommands;
use crate::exporter::data::{chunk, extract_time, Exporter};
use anyhow::Result;
use console::style;

#[derive(Default)]
pub struct Text {}

impl Exporter for Text {
    fn sensitive_data(&self, findings: &[&FindingSensitiveCommands]) -> Result<()> {
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
        Ok(())
    }
}
