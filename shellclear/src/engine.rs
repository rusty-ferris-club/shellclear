use crate::data::{FindingSensitiveCommands, SensitiveCommands};
use crate::shell;
use crate::state::ShellContext;
use anyhow::Result;
use log::debug;
use rayon::prelude::*;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use std::fmt::Write;
use std::fs::{write, File};
use std::io::{prelude::*, BufReader};
use std::time::Instant;

pub const SENSITIVE_COMMANDS: &str = include_str!("sensitive-envs.yaml");

#[derive(Debug, Deserialize, Serialize, Clone)]
struct FishHistory {
    pub cmd: String,
    pub when: String,
}

pub fn find_history_commands(
    state_context: &ShellContext,
    clear: bool,
) -> Result<Vec<FindingSensitiveCommands>> {
    debug!(
        "clear history commands from path: {}, params: is clear: {}",
        state_context.history.path, clear
    );

    let sensitive_commands: Vec<SensitiveCommands> = serde_yaml::from_str(SENSITIVE_COMMANDS)?;

    match state_context.history.shell {
        shell::Shell::Fish => find_fish(state_context, sensitive_commands, clear),
        _ => find_by_lines(state_context, sensitive_commands, clear),
    }
}

fn find_by_lines(
    state_context: &ShellContext,
    sensitive_commands: Vec<SensitiveCommands>,
    clear: bool,
) -> Result<Vec<FindingSensitiveCommands>> {
    let mut clear_history_content: String = String::new();

    let start = Instant::now();
    let file = File::open(&state_context.history.path)?;
    let reader = BufReader::new(file);

    let mut findings_results: Vec<FindingSensitiveCommands> = vec![];
    let delete_lines = reader
        .lines()
        .filter(|line| line.is_ok())
        .map(|line| line.unwrap())
        .filter(|line| {
            let findings = sensitive_commands
                .par_iter()
                .filter(|v| Regex::new(&v.test).unwrap().is_match(line))
                .map(|f| f.clone())
                .collect::<Vec<_>>();

            if findings.is_empty() {
                let _ = writeln!(&mut clear_history_content, "{}", line);
                return false;
            }
            findings_results.push(FindingSensitiveCommands {
                shell_type: state_context.history.shell.clone(),
                finding: findings,
                command: line.to_string(),
            });
            true
        })
        .collect::<Vec<_>>();

    debug!(
        "time elapsed for detect sensitive commands: {:?}",
        start.elapsed()
    );

    if clear {
        debug!("deleted history commands: {:?}", delete_lines);
        let start = Instant::now();
        write(&state_context.history.path, clear_history_content)?;
        debug!(
            "time elapsed for backup existing file and write a new history to shell : {:?}",
            start.elapsed()
        );
    }

    Ok(findings_results)
}

fn find_fish(
    state_context: &ShellContext,
    sensitive_commands: Vec<SensitiveCommands>,
    clear: bool,
) -> Result<Vec<FindingSensitiveCommands>> {
    let c = File::open(&state_context.history.path)?;
    let history: Vec<FishHistory> = serde_yaml::from_reader(&c)?;

    let mut clear_history_content: Vec<FishHistory> = Vec::new();

    let findings_results = history
        .iter()
        .filter_map(|h| {
            let findings = sensitive_commands
                .par_iter()
                .filter(|v| Regex::new(&v.test).unwrap().is_match(&h.cmd))
                .map(|f| f.clone())
                .collect::<Vec<_>>();

            if findings.is_empty() {
                clear_history_content.push(h.clone());
                return None;
            }
            Some(FindingSensitiveCommands {
                shell_type: state_context.history.shell.clone(),
                finding: findings,
                command: h.cmd.to_string(),
            })
        })
        // .flatten()
        .collect::<Vec<_>>();

    if clear {
        debug!("deleted history commands: {:?}", findings_results);
        let start = Instant::now();
        write(
            &state_context.history.path,
            serde_yaml::to_string(&clear_history_content)?,
        )?;
        debug!(
            "time elapsed for backup existing file and write a new history to shell : {:?}",
            start.elapsed()
        );
    }

    Ok(findings_results)
}
