use std::time::Instant;
use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use shellclear::{config::Config, engine, Emojis, ShellContext};
use std::fmt::{Write};
use std::fs::write;

pub fn command() -> Command<'static> {
    Command::new("clear")
        .about("Remove or mask the findings from shell history")
        .arg(
            Arg::new("backup")
                .long("backup")
                .help("Backup history file before delete commands")
                .takes_value(false),
        )
        .arg(
            Arg::new("remove")
                .long("remove")
                .help("remove history that contains secrets")
                .takes_value(false),
        )
}

pub fn run(
    matches: &ArgMatches,
    shells_context: &Vec<ShellContext>,
    config: &Config,
) -> Result<shellclear::data::CmdExit> {
    let en = engine::PatternsEngine::with_config(config)?;

    for shell_context in shells_context {
        if matches.is_present("backup") {
            match shell_context.backup() {
                Ok(path) => log::debug!("history backup successful: {}", path),
                Err(e) => {
                    return Ok(shellclear::data::CmdExit {
                        code: 1,
                        message: Some(format!(
                            "could not backup shell {:?} history. err: {:?}",
                            shell_context.history.shell, e
                        )),
                    });
                }
            }
        }
    }

    let findings = en.find_history_commands_from_shell_list(shells_context)?;

    let sensitive_commands = findings.get_all_sensitive_commands();
    let emojis = Emojis::default();


    for context in shells_context {
        let start = Instant::now();
        let mut cleared_history: String = String::new();

        for r in findings.get_sensitive_commands(&context.history.shell) {
            // TODO: Remove only when the user passes the --remove flag
            let _ = writeln!(&mut cleared_history, "{}", r.data);
        }

        if !cleared_history.is_empty() {
            write(&context.history.path, cleared_history)?;
            log::debug!(
                    "time elapsed for backup existing file and write a new history to shell : {:?}",
                    start.elapsed()
                );
        }
    }

    if sensitive_commands.is_empty() {
        return Ok(shellclear::data::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "{} Your shell is clean from sensitive data!",
                emojis.confetti
            )),
        });
    };

    let message = format!(
        " {} shellclear cleared {} sensitive commands",
        emojis.alarm,
        sensitive_commands.len()
    );

    Ok(shellclear::data::CmdExit {
        code: exitcode::OK,
        message: Some(message),
    })
}
