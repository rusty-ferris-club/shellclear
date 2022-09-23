use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use shellclear::{config::Config, engine, Emojis, ShellContext};

pub fn command() -> Command<'static> {
    Command::new("clear")
        .about("Clear the findings from shell history")
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
                    })
                }
            }
        }
    }

    let findings = en.find_history_commands_from_shall_list(shells_context, true)?;

    let sensitive_commands = findings.get_sensitive_commands();
    let emojis = Emojis::default();

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
