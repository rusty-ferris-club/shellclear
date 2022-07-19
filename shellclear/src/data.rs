use crate::shell::Shell;
use serde_derive::Deserialize;

pub struct CmdExit {
    pub code: exitcode::ExitCode,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SensitiveCommands {
    #[serde(with = "serde_regex")]
    pub test: regex::Regex,
    pub name: String,
}

#[derive(Debug)]
pub struct FindingSensitiveCommands {
    pub shell_type: Shell,
    pub sensitive_findings: Vec<SensitiveCommands>,
    pub command: String,
}
