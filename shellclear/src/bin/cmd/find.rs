use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use console::style;
use shellclear::config::Config;
use shellclear::Emojis;
use shellclear::{engine, printer, ShellContext};
use std::str;

pub fn command() -> Command<'static> {
    Command::new("find")
        .about("Find sensitive commands")
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
    config: &Config,
) -> Result<shellclear::CmdExit> {
    let en = engine::PatternsEngine::with_config(config)?;

    let findings =
        en.find_history_commands_from_shall_list(shells_context, matches.is_present("clear"))?;

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
    }

    let sensitive_commands = findings.get_sensitive_commands();
    let emojis = Emojis::default();

    if sensitive_commands.is_empty() {
        return Ok(shellclear::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "{} Your shells is clean from sensitive data!",
                emojis.confetti
            )),
        });
    };

    let message = {
        let mut out = Vec::new();
        let mut message = format!(
            " {} found {} sensitive commands",
            emojis.alarm,
            sensitive_commands.len()
        );
        if !matches.is_present("clear") {
            message = format!("{}. {}", message, "Use --clear flag to clean them");
        }
        println!("\r\n{}\r\n", style(message).yellow());
        printer::show_sensitive_findings(&mut out, &sensitive_commands)?;
        print!("{}", str::from_utf8(&out)?);
        if matches.is_present("clear") {
            Some(format!(
                " {} Sensitive commands was cleared",
                emojis.confetti
            ))
        } else {
            None
        }
    };
    Ok(shellclear::CmdExit {
        code: exitcode::OK,
        message,
    })
}
