//! Centralized location for controlling Firedancer configuration.
mod commands;
mod config;

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

fn main() {
    if config::escalate_root() {
        // Process replaced with the same one that ran as root, exit.
        return;
    }

    env_logger::init();

    let args = Cli::parse();
    let mut config: Config = UserConfig::load(&args.config).into_config(&args);

    match args.command {
        CliCommand::Configure(command) => commands::configure(command.command, &mut config),
        CliCommand::Run(command) => commands::run(command, &mut config),
        CliCommand::Monitor => commands::monitor(&config),
    }
}
