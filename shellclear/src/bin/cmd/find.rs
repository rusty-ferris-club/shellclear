use anyhow::Result;
use clap::{ArgMatches, Command};
use console::style;
use shellclear::config::Config;
use shellclear::Emojis;
use shellclear::{engine, printer, ShellContext};
use std::str;

pub fn command() -> Command<'static> {
    Command::new("find").about("Find sensitive commands")
}

pub fn run(
    _matches: &ArgMatches,
    shells_context: &Vec<ShellContext>,
    config: &Config,
) -> Result<shellclear::CmdExit> {
    let en = engine::PatternsEngine::with_config(config)?;

    let findings = en.find_history_commands_from_shall_list(shells_context, false)?;

    let sensitive_commands = findings.get_sensitive_commands();
    let emojis = Emojis::default();

    if sensitive_commands.is_empty() {
        return Ok(shellclear::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "{} Your shell are clean from sensitive data!",
                emojis.confetti
            )),
        });
    };

    let mut out = Vec::new();
    let message = format!(
        " {} found {} sensitive commands",
        emojis.alarm,
        sensitive_commands.len()
    );

    println!("\r\n{}\r\n", style(message).yellow());
    printer::show_sensitive_findings(&mut out, &sensitive_commands)?;
    print!("{}", str::from_utf8(&out)?);

    Ok(shellclear::CmdExit {
        code: exitcode::OK,
        message: Some(
            "Run `shellclear --clear` to clear the findings from your history".to_string(),
        ),
    })
}
