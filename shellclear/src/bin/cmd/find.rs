use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use console::style;
use shellclear::Emojis;
use shellclear::{engine, printer, FindingSensitiveCommands, ShellContext};
use std::str;

#[derive(PartialEq)]
enum Format {
    Summary,
    Table,
}

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
        .arg(
            Arg::new("format")
                .long("format")
                .help("Finding output format")
                .possible_values(vec!["summary", "table"])
                .ignore_case(true)
                .default_value("table")
                .takes_value(true),
        )
}

pub fn run(
    matches: &ArgMatches,
    shells_context: &Vec<ShellContext>,
) -> Result<shellclear::CmdExit> {
    let mut findings: Vec<FindingSensitiveCommands> = Vec::new();
    let en = engine::PatternsEngine::default();

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

        findings.extend(en.find_history_commands(shell_context, matches.is_present("clear"))?);
    }

    let format = match matches.value_of("format") {
        Some("summary") => Format::Summary,
        _ => Format::Table,
    };
    let mut out = Vec::new();

    let count_sensitive_commands = findings
        .iter()
        .filter(|f| !f.sensitive_findings.is_empty())
        .count();

    let emojis = Emojis::default();

    if count_sensitive_commands == 0 {
        return Ok(shellclear::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "{} Your shells is clean from sensitive data!",
                emojis.confetti
            )),
        });
    };

    let message = match format {
        Format::Summary => Some(format!(
            "{} shellclear found {} sensitive commands in your shell history. run `shellclear find` to see more information",
            emojis.alarm,
            style(count_sensitive_commands).red()
        )),
        Format::Table => {
            let mut message = format!(" {} found {} sensitive commands", emojis.alarm,count_sensitive_commands);
            if !matches.is_present("clear") {
                message = format!("{}. {}", message, "Use --clear flag to clean them");
            }
            println!("\r\n{}\r\n", style(message).yellow());
            printer::show_sensitive_findings(&mut out, &findings)?;
            print!("{}", str::from_utf8(&out)?);
            if matches.is_present("clear") {
                Some(format!(
                    "\r\n {} Sensitive commands was cleared\r\n",
                    emojis.confetti
                ))
            } else {
                None
            }
        }
    };
    Ok(shellclear::CmdExit {
        code: exitcode::OK,
        message,
    })
}
