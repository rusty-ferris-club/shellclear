use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use shellclear::{config::Config, data::SensitiveCommands, dialog};

use crate::engine::SENSITIVE_COMMANDS;

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
        .subcommand(Command::new("ignores").about("Manage ignores patterns."))
}

pub fn run(subcommand_matches: &ArgMatches, config: &Config) -> Result<shellclear::data::CmdExit> {
    match subcommand_matches.subcommand() {
        None => run_create_config(config),
        Some(tup) => match tup {
            ("validate", _subcommand_matches) => Ok(run_validate(config)),
            ("delete", matches) => Ok(run_delete(config, matches.is_present("force"))?),
            ("ignores", _matches) => Ok(run_ignore(config)?),
            _ => unreachable!(),
        },
    }
}

fn run_create_config(config: &Config) -> Result<shellclear::data::CmdExit> {
    if config.is_app_path_exists() {
        let confirm_message = format!(
            "folder {} already exists. do you want to override the existing files?",
            config.app_path.display(),
        );
        if let Err(e) = dialog::confirm(&confirm_message) {
            log::debug!("{:?}", e);
            return Ok(shellclear::data::CmdExit {
                code: exitcode::OK,
                message: None,
            });
        }
    }
    config.init()?;

    Ok(shellclear::data::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "Config file created successfully in path: {}",
            config.app_path.display()
        )),
    })
}

fn run_validate(config: &Config) -> shellclear::data::CmdExit {
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
    shellclear::data::CmdExit {
        code: error_found,
        message: Some(result.join("\n\r")),
    }
}

fn run_delete(config: &Config, force: bool) -> Result<shellclear::data::CmdExit> {
    if !force
        && dialog::confirm(format!("Delete {} folder?", config.app_path.display()).as_str())
            .is_err()
    {
        return Ok(shellclear::data::CmdExit {
            code: exitcode::OK,
            message: Some("operation canceled".to_string()),
        });
    }

    if config.is_app_path_exists() {
        config.delete_app_folder()?;
    }

    Ok(shellclear::data::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "Config folder {} deleted successfully",
            config.app_path.display()
        )),
    })
}

fn run_ignore(config: &Config) -> Result<shellclear::data::CmdExit> {
    if !config.is_app_path_exists() {
        log::debug!("app folder not found, creating...");
        config.init()?;
    }

    // get all sensitive commands
    let sensitive_patterns: Vec<SensitiveCommands> = serde_yaml::from_str(SENSITIVE_COMMANDS)?;

    let (show_selections, show_ignores) =
        get_patter_ignore_multi_choice(config, &sensitive_patterns);

    let selected_ignores = dialog::multi_choice(
        "Select which pattern you would like to ignore",
        show_selections,
        show_ignores,
        20,
    )?;

    // convert user selections to id's
    let selected_ides = sensitive_patterns
        .iter()
        .filter(|s| selected_ignores.contains(&s.name))
        .map(|s| s.id.to_string())
        .collect::<Vec<_>>();

    log::debug!("selected ignores patterns: {:?}", selected_ides);

    config.save_ignores_patterns(&selected_ides)?;
    Ok(shellclear::data::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}

fn get_patter_ignore_multi_choice(
    config: &Config,
    sensitive_patterns: &[SensitiveCommands],
) -> (Vec<String>, Vec<String>) {
    // get current pattern ignores
    let ignore_patterns = config.get_ignore_patterns().unwrap_or_default();

    // filter ignores
    let show_selections = sensitive_patterns
        .iter()
        .filter(|s| !ignore_patterns.contains(&s.id))
        .map(|s| s.name.clone())
        .collect::<Vec<_>>();

    // filter ignores
    let show_ignores = sensitive_patterns
        .iter()
        .filter(|s| ignore_patterns.contains(&s.id))
        .map(|s| s.name.clone())
        .collect::<Vec<_>>();

    (show_selections, show_ignores)
}

#[cfg(test)]
mod test_cli_config {
    use std::fs;

    use insta::assert_debug_snapshot;
    use regex::Regex;
    use tempdir::TempDir;

    use super::*;

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

    #[test]
    fn can_run_prepare_multi_choice_data() {
        let temp_dir = TempDir::new("config-app-delete").unwrap();
        let config = new_config(&temp_dir);

        config.init().unwrap();
        config.save_ignores_patterns(&["id-3".to_string()]).unwrap();

        let patterns: Vec<SensitiveCommands> = vec![
            SensitiveCommands {
                test: Regex::new("test").unwrap(),
                name: "test-1".to_string(),
                id: "id-1".to_string(),
                secret_group: 0,
            },
            SensitiveCommands {
                test: Regex::new("test").unwrap(),
                name: "test-2".to_string(),
                id: "id-2".to_string(),
                secret_group: 0,
            },
            SensitiveCommands {
                test: Regex::new("test").unwrap(),
                name: "test-3".to_string(),
                id: "id-3".to_string(),
                secret_group: 0,
            },
        ];

        assert_debug_snapshot!(get_patter_ignore_multi_choice(&config, &patterns));
        temp_dir.close().unwrap();
    }
}
