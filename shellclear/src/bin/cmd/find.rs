use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use console::style;

use shellclear::{
    config::Config,
    engine,
    exporter::{Exporter, Table, Text},
    Emojis, ShellContext,
};

pub fn command() -> Command<'static> {
    Command::new("find").about("Find sensitive commands").arg(
        Arg::new("format")
            .long("format")
            .help("Finding output format")
            .possible_values(vec!["text", "table"])
            .ignore_case(true)
            .default_value("text")
            .takes_value(true),
    )
}

pub fn run(
    matches: &ArgMatches,
    shells_context: &Vec<ShellContext>,
    config: &Config,
) -> Result<shellclear::data::CmdExit> {
    let en = engine::PatternsEngine::with_config(config)?;

    let sensitive_commands = en
        .find_history_commands_from_shell_list(shells_context)?
        .get_commands_with_secrets();

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
        " {} found {} sensitive commands",
        emojis.alarm,
        sensitive_commands.len()
    );
    println!("\r\n{}\r\n", style(message).yellow());

    let exporter = match matches.value_of("format") {
        Some("table") => Box::<Table>::default() as Box<dyn Exporter>,
        _ => Box::<Text>::default() as Box<dyn Exporter>,
    };

    Ok(
        match exporter.sensitive_data(sensitive_commands.as_slice()) {
            Ok(()) => shellclear::data::CmdExit {
                code: exitcode::OK,
                message: Some(
                    "Run `shellclear clear` to clear command findings from your history"
                        .to_string(),
                ),
            },
            Err(e) => shellclear::data::CmdExit {
                code: exitcode::OK,
                message: Some(e.to_string()),
            },
        },
    )
}
