use anyhow::Result;
use clap::Command;
use shellclear::{promter, ShellContext};

pub fn command() -> Command<'static> {
    Command::new("restore").about("Restore backup history file")
}

pub fn run(shell_context: &ShellContext) -> Result<shellclear::CmdExit> {
    let mut backup_files = shell_context.get_backup_files().unwrap();
    if backup_files.is_empty() {
        return Ok(shellclear::CmdExit {
            code: exitcode::OK,
            message: Some("backup files not found".to_string()),
        });
    }

    if let Some(file) = shell_context.get_stash_file() {
        backup_files.push(file);
    }

    backup_files.sort_by(|a, b| b.cmp(a));
    let restore_from_path = match promter::select("select backup file", &backup_files) {
        Ok(selection) => &backup_files[selection],
        Err(_e) => {
            return Ok(shellclear::CmdExit {
                code: 0,
                message: None,
            });
        }
    };

    if let Some(e) = shell_context.restore(restore_from_path).err() {
        return Ok(shellclear::CmdExit {
            code: 1,
            message: Some(format!("restore failed: {:?}", e)),
        });
    }

    println!("history file restored successfully");
    Ok(shellclear::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
