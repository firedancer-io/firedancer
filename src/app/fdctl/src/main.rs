//! Centralized location for controlling Firedancer configuration.
mod commands;
mod config;
mod setns;

use std::path::PathBuf;

use config::{UserConfig, Config, FrankConfig};

use clap::{Parser, Subcommand};

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
    Configure(commands::Configure),

    /// Run Firedancer
    Run(commands::Run),

    /// Monitor Firedancer
    Monitor,
}

impl CliCommand {
    fn needs_root(&self) -> bool {
        match self {
            CliCommand::Configure(_) => true,
            CliCommand::Run(ref command) => command.needs_root(),
            CliCommand::Monitor => false,
        }
    }
}

fn main() {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"));

    let args = Cli::parse();
    if args.command.needs_root() {
        // If this call returns successfully, we were already root and should continue. If it
        // doesn't return, the same binary was started as root and will do the actions for us.
        config::escalate_root();
    }

    let mut config: Config = UserConfig::load(&args.config).into_config(&args);

    match args.command {
        CliCommand::Configure(command) => commands::configure(command.command, &mut config),
        CliCommand::Run(command) => commands::run(command, &mut config),
        CliCommand::Monitor => commands::monitor(&config),
    }
}
