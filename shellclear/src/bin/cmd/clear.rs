use anyhow::Result;
use clap::{Arg, ArgMatches, Command};

use shellclear::clearer::Clearer;
use shellclear::{config::Config, engine, Emojis, ShellContext};

pub fn command() -> Command<'static> {
    Command::new("clear")
        .about("Remove or mask the findings from shell history")
        .arg(
            Arg::new("backup")
                .long("backup")
                .help("Backup history file before delete commands")
                .takes_value(false),
        )
        .arg(
            Arg::new("remove")
                .long("remove")
                .help("Remove history that contains secrets")
                .takes_value(false),
        )
}

pub fn run(
    matches: &ArgMatches,
    shells_context: &Vec<ShellContext>,
    config: &Config,
) -> Result<shellclear::data::CmdExit> {
    let en = engine::PatternsEngine::with_config(config)?;

    for shell_context in shells_context {
        if matches.is_present("backup") {
            match shell_context.backup() {
                Ok(path) => log::debug!("history backup successful: {}", path),
                Err(e) => {
                    return Ok(shellclear::data::CmdExit {
                        code: 1,
                        message: Some(format!(
                            "could not backup shell {:?} history. err: {:?}",
                            shell_context.history.shell, e
                        )),
                    });
                }
            }
        }
    }

    let (findings, sensitive_commands) =
        en.find_history_commands_from_shell_list(shells_context)?;
    let emojis = Emojis::default();

    Clearer::write_findings(shells_context, &findings, matches.is_present("remove"))?;

    if sensitive_commands.is_empty() {
        return Ok(shellclear::data::CmdExit {
            code: exitcode::OK,
            message: Some(format!(
                "{} Your shell is clean from sensitive data!",
                emojis.confetti
            )),
        });
    };

    let message = format!(
        " {} shellclear cleared {} sensitive commands",
        emojis.alarm,
        sensitive_commands.len()
    );

    Ok(shellclear::data::CmdExit {
        code: exitcode::OK,
        message: Some(message),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;

    use insta::assert_debug_snapshot;
    use tempdir::TempDir;

    use shellclear::shell::{History, Shell};

    use crate::cmd::clear::run;

    use super::*;

    const TEST_SENSITIVE_COMMANDS: &str = r###"
- name: Find me
  secret_group: 0
  test: FIND_ME=
    "###;

    const TEMP_HISTORY_LINES_CONTENT: &str = "history
ls
echo 'hello you'
rm -f ./file.txt
export FIND_ME=token
";

    const TEMP_HISTORY_FISH: &str = r#"---
- cmd: history
  when: "1656438759"
- cmd: ls
  when: "1656438760"
- cmd: echo 'hello you'
  when: "1656438760"
- cmd: rm -f ./file.txt
  when: "1656438760"
- cmd: export FIND_ME=token
  when: "1656438760"
"#;

    fn create_mock_state(
        temp_dir: &TempDir,
        content: &str,
        rules: &str,
        shell_type: Shell,
    ) -> ShellContext {
        let app_folder = temp_dir.path().join("shellclear");
        let history_file_name = "history";
        let history_file_path = app_folder.join(history_file_name);
        fs::create_dir_all(&app_folder).unwrap();

        let mut f = File::create(&history_file_path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.sync_all().unwrap();

        let sensitive_patterns_path = app_folder.join("sensitive-patterns.yaml");

        let mut f = File::create(sensitive_patterns_path).unwrap();
        f.write_all(rules.as_bytes()).unwrap();
        f.sync_all().unwrap();

        ShellContext {
            app_folder_path: app_folder.display().to_string(),
            history: History {
                shell: shell_type,
                path: history_file_path.display().to_string(),
                file_name: history_file_name.to_string(),
            },
        }
    }

    #[test]
    fn can_clear_command_by_lines() {
        let temp_dir = TempDir::new("clear").unwrap();

        let state_context = create_mock_state(
            &temp_dir,
            TEMP_HISTORY_LINES_CONTENT,
            TEST_SENSITIVE_COMMANDS,
            Shell::Bash,
        );

        let args = command().get_matches_from(vec!["clear", "--remove"]);

        let result = run(
            &args,
            &vec![state_context.clone()],
            &Config::from(temp_dir.path().to_str()),
        )
        .unwrap()
        .message
        .unwrap()
        .replace(|c: char| !c.is_ascii(), "");

        assert_debug_snapshot!(result);
        assert_debug_snapshot!(fs::read_to_string(state_context.history.path).unwrap());
        temp_dir.close().unwrap();
    }

    #[test]
    fn can_clear_find_fish() {
        let temp_dir = TempDir::new("clear").unwrap();

        let state_context = create_mock_state(
            &temp_dir,
            TEMP_HISTORY_FISH,
            TEST_SENSITIVE_COMMANDS,
            Shell::Fish,
        );

        let args = command().get_matches_from(vec!["clear", "--remove"]);

        let result = run(
            &args,
            &vec![state_context.clone()],
            &Config::from(temp_dir.path().to_str()),
        )
        .unwrap()
        .message
        .unwrap()
        .replace(|c: char| !c.is_ascii(), "");

        assert_debug_snapshot!(result);
        assert_debug_snapshot!(fs::read_to_string(state_context.history.path).unwrap());
        temp_dir.close().unwrap();
    }
}
