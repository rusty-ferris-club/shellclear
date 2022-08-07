mod cmd;
use anyhow::anyhow;
use console::{style, Style};
use shellclear::{config::Config, dialog, engine, init, Emojis, ShellContext};
use std::process::exit;

const DEFAULT_ERR_EXIT_CODE: i32 = 1;

pub const BANNER: &str = r#"
     _          _ _      _                 
 ___| |__   ___| | | ___| | ___  __ _ _ __ 
/ __| '_ \ / _ \ | |/ __| |/ _ \/ _` | '__|
\__ \ | | |  __/ | | (__| |  __/ (_| | |   
|___/_| |_|\___|_|_|\___|_|\___|\__,_|_| "#;

fn main() {
    let app = cmd::default::command()
        .subcommand(cmd::config::command())
        .subcommand(cmd::find::command())
        .subcommand(cmd::clear::command())
        .subcommand(cmd::stash::command());

    let matches = app.clone().get_matches();

    let env = env_logger::Env::default().filter_or(
        "LOG",
        matches.value_of("log").unwrap_or(log::Level::Info.as_str()),
    );
    env_logger::init_from_env(env);

    let config = Config::default();
    // create app config to store state data
    let shells_context = match init() {
        Ok(s) => s,
        Err(e) => {
            log::error!("{}", e);
            exit(1)
        }
    };

    if matches.is_present("init-shell") {
        // In case of an error, we need to suppress the errors to make sure that when new shell is open the users will not get any errors.
        match engine::PatternsEngine::with_config(&config) {
            Ok(engine) => {
                let emojis = Emojis::default();
                if let Ok(findings) =
                    engine.find_history_commands_from_shall_list(&shells_context, false)
                {
                    let sensitive_commands = findings.get_sensitive_commands();
                    if sensitive_commands.is_empty() {
                        eprintln!(
                            "{} Your shell is clean from sensitive data!",
                            emojis.confetti
                        );
                    } else {
                        eprintln!("{} shellclear found {} sensitive commands in your shell history. run `shellclear find` to see more information", emojis.alarm,style(sensitive_commands.len()).red());
                    }
                }
            }
            Err(e) => {
                log::debug!("could not init engine config. err: {}", e);
            }
        };
        exit(0)
    }

    if !matches.is_present("no_banner") {
        println!(
            "{}{}",
            style(BANNER).magenta(),
            style(app.get_version().unwrap_or("")).dim()
        );
    }

    let res = match matches.subcommand() {
        None => Err(anyhow!("command not found")),
        Some(tup) => match tup {
            ("config", subcommand_matches) => cmd::config::run(subcommand_matches, &config),
            ("find", subcommand_matches) => {
                cmd::find::run(subcommand_matches, &shells_context, &config)
            }
            ("clear", subcommand_matches) => {
                cmd::clear::run(subcommand_matches, &shells_context, &config)
            }
            ("stash", subcommand_matches) => {
                cmd::stash::run(subcommand_matches, select_shell(&shells_context))
            }
            _ => unreachable!(),
        },
    };

    let exit_with = match res {
        Ok(cmd) => {
            if let Some(message) = cmd.message {
                let style = if exitcode::is_success(cmd.code) {
                    Style::new().green()
                } else {
                    Style::new().red()
                };
                eprintln!("\r\n{}\r\n", style.apply_to(message));
            }
            cmd.code
        }
        Err(e) => {
            log::debug!("{:?}", e);
            DEFAULT_ERR_EXIT_CODE
        }
    };
    exit(exit_with)
}

fn select_shell(shell_contexts: &Vec<ShellContext>) -> &ShellContext {
    if shell_contexts.len() == 1 {
        return &shell_contexts[0];
    }
    let selections = shell_contexts
        .iter()
        .map(|f| format!("{:?}     : {}", f.history.shell, f.history.path))
        .collect::<Vec<_>>();

    match dialog::select("Pick your shell", &selections) {
        Ok(selection) => &shell_contexts[selection],
        Err(e) => {
            log::debug!("promter select err: {:?} ", e);
            exit(1)
        }
    }
}
