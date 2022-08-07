use anyhow::anyhow;
use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use shellclear::config::Config;
use shellclear::dialog;

pub fn command() -> Command<'static> {
    Command::new("config")
        .about("Create custom configuration")
        .subcommand(Command::new("validate").about("Validate configuration file."))
        .subcommand(Command::new("delete").about("Delete configuration file."))
}

pub fn run(subcommand_matches: &ArgMatches, config: &Config) -> Result<shellclear::CmdExit> {
    match subcommand_matches.subcommand() {
        None => run_create_config(config),
        Some(tup) => match tup {
            ("validate", _subcommand_matches) => Ok(run_validate(config)),
            ("delete", _subcommand_matches) => Ok(run_delete(config)?),
            _ => unreachable!(),
        },
    }
}

fn run_create_config(config: &Config) -> Result<shellclear::CmdExit> {
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

    Ok(shellclear::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "Config file created successfully in path: {}",
            config.app_path.display()
        )),
    })
}

fn run_validate(config: &Config) -> shellclear::CmdExit {
    let mut result: Vec<String> = vec![];
    let mut error_found = exitcode::OK;

    match config.load_patterns_from_default_path() {
        Ok(r) => result.push(format!(
            "- found {} external sensitive patterns in path: {}",
            r.len(),
            config.sensitive_commands_path.display(),
        )),
        Err(e) => {
            result.push(format!(
                "- sensitive patterns file {} is invalid. error {}",
                config.sensitive_commands_path.display(),
                e
            ));
            error_found = exitcode::CONFIG;
        }
    }
    match config.get_ignore_patterns() {
        Ok(i) => result.push(format!(
            "- found {} ignore patterns in path: {}",
            i.len(),
            config.sensitive_commands_path.display(),
        )),
        Err(e) => {
            result.push(format!(
                "- ignore file {} is invalid. error {}",
                config.sensitive_commands_path.display(),
                e
            ));
            error_found = exitcode::CONFIG;
        }
    }
    shellclear::CmdExit {
        code: error_found,
        message: Some(result.join("\n\r")),
    }
}

fn run_delete(config: &Config) -> Result<shellclear::CmdExit> {
    if dialog::confirm(format!("Delete {} folder?", config.app_path.display()).as_str()).is_err() {
        return Ok(shellclear::CmdExit {
            code: exitcode::OK,
            message: Some("operation canceled".to_string()),
        });
    };

    if config.is_app_path_exists() {
        config.delete_app_folder()?;
    }

    Ok(shellclear::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "Config folder {} deleted successfully",
            config.app_path.display()
        )),
    })
}
