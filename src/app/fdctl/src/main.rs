//! Centralized location for controlling Firedancer configuration.
mod commands;
mod config;
mod security;
mod utility;

use std::{env, path::PathBuf, process::Command};

use config::{Config, UserConfig};

use clap::{Parser, Subcommand};
use log::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,

    /// Location of a configuration TOML file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Location of the Firedancer build binary directory. For example `/home/user/firedancer/build/linux/gcc/x86_65/bin/`
    #[arg(long)]
    binary_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Setup and verify the static configuration of the system
    Configure(commands::ConfigureCli),

    /// Run Firedancer
    Run(commands::RunCli),

    /// Monitor Firedancer
    Monitor,
}

impl CliCommand {
    fn explain_capabilities(&self, config: &Config) -> Vec<String> {
        match self {
            CliCommand::Configure(command) => command.explain_permissions(config),
            CliCommand::Run(command) => command.explain_permissions(config),
            CliCommand::Monitor => vec![],
        }
    }
}

/// Rerun the process as root.
///
/// This will never return, instead the process will wait for the child and exit with the same
/// return code.
pub(crate) fn escalate_root() -> ! {
    let mut command = Command::new("/usr/bin/sudo");
    command.arg("-E");
    command.env_clear();
    for var in [
        "FIREDANCER_CONFIG_TOML",
        "FIREDANCER_BINARY_DIR",
        "RUST_LOG",
        "RUST_BACKTRACE",
    ] {
        if let Ok(value) = env::var(var) {
            command.env(var, value);
        }
    }
    command.arg(env::current_exe().unwrap());
    command.args(env::args().skip(1));

    let status = command.spawn().unwrap().wait().unwrap();
    std::process::exit(status.code().unwrap_or(1));
}

fn main() {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let args = Cli::parse();
    let mut config: Config = UserConfig::load(&args.config).into_config(&args);

    let permission_errors = args.command.explain_capabilities(&config);
    if !permission_errors.is_empty() {
        if config.development.sudo {
            permission_errors.iter().for_each(|x| info!("{}", x));
            info!("Need additional permissions. Config has [development.sudo] enabled so rerunning as root");
            escalate_root();
        } else {
            permission_errors.iter().for_each(|x| error!("{}", x));
            panic!("Not running with correct permissions")
        }
    }

    match args.command {
        CliCommand::Configure(command) => commands::configure(command.stage, &mut config),
        CliCommand::Run(command) => commands::run(command, &mut config),
        CliCommand::Monitor => commands::monitor(&config),
    }
}
