use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use shellclear::config::Config;
use shellclear::dialog;

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
    let (message, exit_code) = if matches.is_present("validate") {
        if let Err(e) = config.load_patterns_from_default_path() {
            (
                format!("Config file is invalid. error: `{}`.", e),
                exitcode::CONFIG,
            )
        } else {
            (
                format!(
                    "configuration file: {} is valid.",
                    config.sensitive_commands_path.display()
                ),
                exitcode::OK,
            )
        }
    } else if matches.is_present("delete") {
        if let Err(e) =
            dialog::confirm(format!("Delete {} folder?", config.app_path.display()).as_str())
        {
            log::debug!("{:?}", e);
            return Ok(shellclear::CmdExit {
                code: exitcode::OK,
                message: None,
            });
        }

        if config.is_app_path_exists() {
            config.delete_app_folder()?;
        }

        (
            format!(
                "Config file deleted successfully in path: {}",
                config.app_path.display()
            ),
            exitcode::OK,
        )
    } else {
        if config.is_app_path_exists() {
            let confirm_message = format!(
                "folder {} already exists. do you want to override the existing files?",
                config.app_path.display(),
            );
            if let Err(e) = dialog::confirm(&confirm_message) {
                log::debug!("{:?}", e);
                return Ok(shellclear::CmdExit {
                    code: exitcode::OK,
                    message: None,
                });
            }
        }
        config.init()?;
        (
            format!(
                "Config file created successfully in path: {}",
                config.app_path.display()
            ),
            exitcode::OK,
        )
    };

    Ok(shellclear::CmdExit {
        code: exit_code,
        message: Some(message),
    })
}
