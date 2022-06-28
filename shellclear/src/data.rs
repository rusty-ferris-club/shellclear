use crate::shell::Shell;
use serde_derive::Deserialize;

pub struct CmdExit {
    pub code: exitcode::ExitCode,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SensitiveCommands {
    pub test: String,
    pub name: String,
}
#[derive(Debug)]
pub struct FindingSensitiveCommands {
    pub shell_type: Shell,
    pub finding: Vec<SensitiveCommands>,
    pub command: String,
}
