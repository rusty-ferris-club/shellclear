use anyhow::Result;
use clap::{ArgMatches, Command};
use shellclear::config::Config;
use shellclear::promter;

pub fn command() -> Command<'static> {
    Command::new("config").about("Create custom configuration")
}

pub fn run(_matches: &ArgMatches) -> Result<shellclear::CmdExit> {
    let file_path = Config::get_sensitive_pattern_name()?;
    if Config::is_sensitive_pattern_file_exists()? {
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
    Config::init()?;
    Ok(shellclear::CmdExit {
        code: exitcode::OK,
        message: Some(format!(
            "Config file created successfully in path: {}",
            file_path
        )),
    })
}
