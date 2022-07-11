mod cmd;
use anyhow::anyhow;
use console::{style, Style};
use shellclear::{init, promter, ShellContext};
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
        .subcommand(cmd::find::command())
        .subcommand(cmd::restore::command())
        .subcommand(cmd::stash::command());

    let matches = app.to_owned().get_matches();

    let env = env_logger::Env::default().filter_or(
        "LOG",
        matches.value_of("log").unwrap_or(log::Level::Info.as_str()),
    );
    env_logger::init_from_env(env);

    if !matches.is_present("no_banner") {
        println!(
            "{}{}",
            style(BANNER).magenta(),
            style(app.get_version().unwrap_or("")).dim()
        );
    }

    if let Err(e) = ctrlc::set_handler(move || {
        let term = console::Term::stdout();
        let _ = term.show_cursor();
    }) {
        log::debug!("{:?}", e);
    }

    // create app config to store state data
    let shells_context = match init() {
        Ok(s) => s,
        Err(e) => {
            log::error!("{}", e);
            exit(1)
        }
    };

    let res = match matches.subcommand() {
        None => Err(anyhow!("command not found")),
        Some(tup) => match tup {
            ("find", subcommand_matches) => cmd::find::run(subcommand_matches, &shells_context),
            ("restore", _subcommand_matches) => cmd::restore::run(select_shell(&shells_context)),
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
                eprintln!("{}", style.apply_to(message));
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

    match promter::select("Pick your shell", &selections) {
        Ok(selection) => &shell_contexts[selection],
        Err(e) => {
            log::debug!("promter select err: {:?} ", e);
            exit(1)
        }
    }
}
