use clap::crate_version;
use clap::{crate_name, AppSettings, Arg, Command};

pub fn command() -> Command<'static> {
    Command::new(crate_name!())
        .version(env!("VERGEN_GIT_SEMVER"))
        .version(crate_version!())
        .setting(AppSettings::ArgRequiredElseHelp)
        .about("Secure shell commands")
        .arg(
            Arg::new("no_banner")
                .long("no-banner")
                .help("Don't show the banner")
                .takes_value(false),
        )
        .arg(
            Arg::new("log")
                .long("log")
                .help("Set logging level")
                .value_name("LEVEL")
                .possible_values(vec![
                    log::LevelFilter::Off.as_str(),
                    log::LevelFilter::Trace.as_str(),
                    log::LevelFilter::Debug.as_str(),
                    log::LevelFilter::Info.as_str(),
                    log::LevelFilter::Warn.as_str(),
                    log::LevelFilter::Error.as_str(),
                ])
                .default_value(log::Level::Info.as_str())
                .ignore_case(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("init-shell")
                .long("init-shell")
                .help("Show sensitive findings summary for MOTD")
                .takes_value(false),
        )
}
