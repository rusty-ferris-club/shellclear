use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use shellclear::config::Config;
use shellclear::promter;

pub fn command() -> Command<'static> {
    Command::new("config")
        .about("Create custom configuration")
        .arg(
            Arg::new("validate")
                .short('v')
                .long("validate")
                .help("Validate configuration file.")
                .takes_value(false),
        )
        .arg(
            Arg::new("delete")
                .short('d')
                .long("delete")
                .help("Delete configuration file.")
                .takes_value(false),
        )
}

pub fn run(matches: &ArgMatches, config: &Config) -> Result<shellclear::CmdExit> {
    let file_path = config.get_sensitive_pattern_name();

    let (message, exit_code) = if matches.is_present("validate") {
        if let Err(e) = config.load_patterns_from_default_path() {
            (
                format!("Config file is invalid. error: `{}`.", e),
                exitcode::CONFIG,
            )
        } else {
            (
                format!("configuration file: {} is valid.", file_path),
                exitcode::OK,
            )
        }
    } else if matches.is_present("delete") {
        if let Err(e) = promter::confirm(format!("Delete {} file?", &file_path).as_str()) {
            log::debug!("{:?}", e);
            return Ok(shellclear::CmdExit {
                code: exitcode::OK,
                message: None,
            });
        }

        if config.is_sensitive_pattern_file_exists() {
            config.delete_sensitive_patterns_from_file()?;
        }

        (
            format!("Config file deleted successfully in path: {}", file_path),
            exitcode::OK,
        )
    } else {
        if config.is_sensitive_pattern_file_exists() {
            let confirm_message = format!(
                "file {} already exists. do you want to override the existing file?",
                file_path,
            );
            if let Err(e) = promter::confirm(&confirm_message) {
                log::debug!("{:?}", e);
                return Ok(shellclear::CmdExit {
                    code: exitcode::OK,
                    message: None,
                });
            }
        }
        config.init()?;
        (
            format!("Config file created successfully in path: {}", file_path),
            exitcode::OK,
        )
    };

    Ok(shellclear::CmdExit {
        code: exit_code,
        message: Some(message),
    })
}
