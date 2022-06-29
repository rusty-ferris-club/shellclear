use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use shellclear::{engine, printer, FindingSensitiveCommands, ShellContext};
use std::str;

pub fn command() -> Command<'static> {
    Command::new("find")
        .about("find sensitive commands")
        .arg(
            Arg::new("clear")
                .short('c')
                .long("clear")
                .help("Clear the findings from shell history")
                .takes_value(false),
        )
        .arg(
            Arg::new("backup")
                .long("backup")
                .help("Backup history file before delete commands")
                .takes_value(false),
        )
}

pub fn run(
    matches: &ArgMatches,
    shells_context: &Vec<ShellContext>,
) -> Result<shellclear::CmdExit> {
    let mut findings: Vec<FindingSensitiveCommands> = Vec::new();

    for shell_context in shells_context {
        if matches.is_present("backup") {
            match shell_context.backup() {
                Ok(path) => log::debug!("history backup successfully: {}", path),
                Err(e) => {
                    return Ok(shellclear::CmdExit {
                        code: 1,
                        message: Some(format!(
                            "could not backup shell {:?} history. err: {:?}",
                            shell_context.history.shell, e
                        )),
                    })
                }
            }
        }

        let shell_findings =
            match engine::find_history_commands(shell_context, matches.is_present("clear")) {
                Ok(f) => f,
                Err(_e) => continue,
            };
        findings.extend(shell_findings);
    }

    let message = if findings.is_empty() {
        Some("sensitive commands not found".to_string())
    } else {
        let mut out = Vec::new();
        printer::show_sensitive_findings(&mut out, findings)?;
        println!("{}", str::from_utf8(&out)?);
        if matches.is_present("clear") {
            Some("sensitive commands was cleared".to_string())
        } else {
            None
        }
    };

    Ok(shellclear::CmdExit {
        code: exitcode::OK,
        message,
    })
}
