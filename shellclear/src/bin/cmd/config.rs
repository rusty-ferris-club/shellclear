use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use shellclear::config::Config;
use shellclear::dialog;

pub fn command() -> Command<'static> {
    Command::new("config")
        .about("Create custom configuration")
        .subcommand(Command::new("validate").about("Validate configuration file."))
        .subcommand(
            Command::new("delete")
                .about("Delete configuration file.")
                .arg(
                    Arg::new("force")
                        .long("force")
                        .help("Disable prompt question")
                        .takes_value(false),
                ),
        )
}

pub fn run(subcommand_matches: &ArgMatches, config: &Config) -> Result<shellclear::CmdExit> {
    match subcommand_matches.subcommand() {
        None => run_create_config(config),
        Some(tup) => match tup {
            ("validate", _subcommand_matches) => Ok(run_validate(config)),
            ("delete", matches) => Ok(run_delete(config, matches.is_present("force"))?),
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

fn run_delete(config: &Config, force: bool) -> Result<shellclear::CmdExit> {
    if !force
        && dialog::confirm(format!("Delete {} folder?", config.app_path.display()).as_str())
            .is_err()
    {
        return Ok(shellclear::CmdExit {
            code: exitcode::OK,
            message: Some("operation canceled".to_string()),
        });
    }

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

#[cfg(test)]
mod test_cli_config {
    use super::*;
    use insta::assert_debug_snapshot;
    use std::fs;
    use tempdir::TempDir;

    fn new_config(temp_dir: &TempDir) -> Config {
        let path = temp_dir.path().join("app");
        fs::create_dir_all(&path).unwrap();
        Config::with_custom_path(path)
    }

    #[test]
    fn can_run_create_config() {
        let temp_dir = TempDir::new("config-app-create").unwrap();
        let config = new_config(&temp_dir);

        assert_debug_snapshot!(run_create_config(&config).unwrap().code);
        assert_debug_snapshot!(&config.sensitive_commands_path.exists());
        assert_debug_snapshot!(&config.ignore_sensitive_path.exists());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_validate_config() {
        let temp_dir = TempDir::new("config-app-validate-ok").unwrap();
        let config = new_config(&temp_dir);
        run_create_config(&config).unwrap();
        assert_debug_snapshot!(run_validate(&config).code);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_validate_config_with_error_returned() {
        let temp_dir = TempDir::new("config-app-validate").unwrap();
        let config = new_config(&temp_dir);
        assert_debug_snapshot!(run_validate(&config).code);
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_run_delete_config() {
        let temp_dir = TempDir::new("config-app-delete").unwrap();
        let config = new_config(&temp_dir);

        run_create_config(&config).unwrap();
        assert_debug_snapshot!(&config.ignore_sensitive_path.exists());
        assert_debug_snapshot!(&config.sensitive_commands_path.exists());
        run_delete(&config, true).unwrap();
        assert_debug_snapshot!(&config.ignore_sensitive_path.exists());
        assert_debug_snapshot!(&config.sensitive_commands_path.exists());
        temp_dir.close().unwrap();
    }
}
