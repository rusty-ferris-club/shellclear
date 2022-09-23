use anyhow::Result;
use clap::{crate_name, ArgMatches, Command};
use shellclear::{dialog, ShellContext};

pub fn command() -> Command<'static> {
    Command::new("stash")
        .about("Stash history file")
        .subcommand(Command::new("pop").about("Pop stash history commands"))
        .subcommand(Command::new("restore").about("Restore backup history file"))
}

pub fn run(
    subcommand_matches: &ArgMatches,
    shell_context: &ShellContext,
) -> Result<shellclear::data::CmdExit> {
    match subcommand_matches.subcommand() {
        None => run_stash(shell_context),
        Some(tup) => match tup {
            ("restore", _subcommand_matches) => run_restore(shell_context),
            ("pop", _subcommand_matches) => run_pop(shell_context),
            _ => unreachable!(),
        },
    }
}

fn run_stash(shell_context: &ShellContext) -> Result<shellclear::data::CmdExit> {
    // todo:: check if file exists and remove the unwrap
    if shell_context.is_stash_file_exists()? {
        if let Err(e) = dialog::confirm(
            "Stash file already find. do you want to override? (you can lose all your history \
             commands)",
        ) {
            log::debug!("{:?}", e);
            return Ok(shellclear::data::CmdExit {
                code: exitcode::OK,
                message: None,
            });
        }
    }

    if let Err(err) = shell_context.stash() {
        return Ok(shellclear::data::CmdExit {
            code: 1,
            message: Some(format!("stash failed: {:?}", err)),
        });
    }
    Ok(shellclear::data::CmdExit {
        code: 0,
        message: Some(format!(
            "Shell {:?} stash successfully when open a new tab. Run `{} stash pop` to return your \
             history commands",
            shell_context.history.shell,
            crate_name!()
        )),
    })
}

fn run_pop(shell_context: &ShellContext) -> Result<shellclear::data::CmdExit> {
    if !shell_context.is_stash_file_exists()? {
        return Ok(shellclear::data::CmdExit {
            code: 1,
            message: Some("Stash file not found".to_string()),
        });
    }

    if let Err(err) = shell_context.pop() {
        return Ok(shellclear::data::CmdExit {
            code: 1,
            message: Some(format!("stash pop failed: {:?}", err)),
        });
    }
    Ok(shellclear::data::CmdExit {
        code: 0,
        message: Some(format!(
            "Shell {:?} history pop successfully when open a new tab. ",
            shell_context.history.shell
        )),
    })
}

pub fn run_restore(shell_context: &ShellContext) -> Result<shellclear::data::CmdExit> {
    let mut backup_files = shell_context.get_backup_files()?;
    if backup_files.is_empty() {
        return Ok(shellclear::data::CmdExit {
            code: exitcode::OK,
            message: Some("backup files not found".to_string()),
        });
    }

    if let Some(file) = shell_context.get_stash_file() {
        backup_files.push(file);
    }

    backup_files.sort_by(|a, b| b.cmp(a));
    let restore_from_path = match dialog::select("select backup file", &backup_files) {
        Ok(selection) => &backup_files[selection],
        Err(_e) => {
            return Ok(shellclear::data::CmdExit {
                code: 0,
                message: None,
            });
        }
    };

    if let Some(e) = shell_context.restore(restore_from_path).err() {
        return Ok(shellclear::data::CmdExit {
            code: 1,
            message: Some(format!("restore failed: {:?}", e)),
        });
    }

    Ok(shellclear::data::CmdExit {
        code: exitcode::OK,
        message: Some("History file restored successfully".to_string()),
    })
}
