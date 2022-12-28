use serde_derive::Deserialize;

use crate::shell::Shell;

pub const ROOT_APP_FOLDER: &str = env!("CARGO_PKG_NAME");

#[derive(Debug)]
pub struct CmdExit {
    pub code: exitcode::ExitCode,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SensitiveCommands {
    #[serde(with = "serde_regex")]
    pub test: regex::Regex,
    pub name: String,
    pub secret_group: u8,
    #[serde(default)]
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct FindingSensitiveCommands {
    pub shell_type: Shell,
    pub sensitive_findings: Vec<SensitiveCommands>,
    pub command: String,
    pub data: String,
    pub secrets: Vec<String>,
}
