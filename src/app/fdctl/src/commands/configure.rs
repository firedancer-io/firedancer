mod frank;
mod large_pages;
mod netns;
mod shmem;
mod workspaces;
mod xdp;
mod xdp_leftover;

pub use frank::Frank;
pub use large_pages::LargePages;
pub use netns::NetNs;
pub use shmem::Shmem;
pub use workspaces::Workspaces;
pub use xdp::Xdp;
pub use xdp_leftover::XdpLeftover;

use crate::Config;

use std::fs::metadata;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

use log::*;
use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub(crate) struct Configure {
    #[command(subcommand)]
    pub(crate) command: ConfigureCommand,
}

#[derive(Debug, Subcommand, Copy, Clone)]
pub(crate) enum ConfigureCommand {
    Ensure,
    Verify,
    Clean,
}

#[derive(Debug)]
enum CheckError {
    NotConfigured(String),
    PartiallyConfigured(String),
}
type CheckResult = Result<(), CheckError>;

trait Step {
    fn name(&self) -> &'static str;

    /// If this step supports doing anything, or is just here for undo and check.
    fn supports_do(&self) -> bool;

    /// If the step supports being undone.
    fn supports_undo(&self) -> bool;

    /// Perform the step, assuming that it has not been done before.
    fn step(&mut self, config: &mut Config);

    /// Undo the step. The step may be not performed, partially, or fully performed.
    fn undo(&mut self, config: &Config);

    /// Check if the step has been performed.
    fn check(&mut self, config: &Config) -> CheckResult;
}

fn path_exists(
    path: &str,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_dir: bool,
) -> CheckResult {
    let metadata = match metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return CheckResult::Err(CheckError::PartiallyConfigured(format!(
                "{} does not exist",
                path
            )))
        }
        result => {
            return CheckResult::Err(CheckError::PartiallyConfigured(format!(
                "error reading {} {result:?}",
                &path
            )))
        }
    };

    if expected_dir && !metadata.is_dir() {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!(
            "{path} is a file, not a directory"
        )));
    } else if !expected_dir && metadata.is_dir() {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!(
            "{path} is a directory, not a file"
        )));
    }

    let uid = metadata.uid();
    if uid != expected_uid {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!(
            "owner of {} is {uid}, not {}",
            path, expected_uid
        )));
    }

    let gid = metadata.gid();
    if gid != expected_gid {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!(
            "group of {} is {gid}, not {}",
            path, expected_gid
        )));
    }

    let mode = metadata.permissions().mode();
    if mode != expected_mode {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!(
            "permissions of {} is {mode:o}, not {:o}",
            path, expected_mode
        )));
    }

    CheckResult::Ok(())
}

#[must_use]
fn check_directory(
    path: &str,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> CheckResult {
    path_exists(path, expected_uid, expected_gid, expected_mode, true)
}

#[must_use]
fn check_file(path: &str, expected_uid: u32, expected_gid: u32, expected_mode: u32) -> CheckResult {
    path_exists(path, expected_uid, expected_gid, expected_mode, false)
}

pub(crate) fn configure(command: ConfigureCommand, config: &mut Config) {
    let mut steps: [Box<dyn Step>; 6] = [
        Box::new(Shmem {}),
        Box::new(LargePages {}),
        Box::new(Xdp {}),
        Box::new(XdpLeftover {}),
        Box::new(NetNs {}),
        Box::new(Frank {}),
    ];

    for step in steps.iter_mut() {
        let stage = step.name();

        match command {
            ConfigureCommand::Ensure => {
                match step.check(config) {
                    CheckResult::Err(CheckError::NotConfigured(reason)) => {
                        info!("[Configure] {stage} ... unconfigured ... {reason}")
                    }
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                        if !step.supports_undo() {
                            panic!("[Configure] {stage} ... does not support undo but was not valid ... {reason}");
                        }

                        info!("[Configure] {stage} ... undoing ... {reason}");
                        step.undo(config);
                        match step.check(config) {
                            CheckResult::Ok(()) => (),
                            CheckResult::Err(CheckError::NotConfigured(_)) => (),
                            CheckResult::Err(CheckError::PartiallyConfigured(reason)) => panic!("[Configure] {stage} ... clean was unable to get back to an unconfigured state ... {reason}"),
                        };
                    }
                    CheckResult::Ok(()) => {
                        info!("[Configure] {stage} ... already valid");
                        continue;
                    }
                };

                info!("[Configure] {stage} ... initializing");
                step.step(config);
                match step.check(config) {
                    CheckResult::Err(CheckError::NotConfigured(reason)) => panic!("[Configure] {stage} ... tried to initialize but didn't do anything ... {reason}"),
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => panic!("[Configure] {stage} ... tried to initialize but was still unconfigured ... {reason}"),
                    CheckResult::Ok(()) => (),
                }
            }
            ConfigureCommand::Verify => match step.check(config) {
                CheckResult::Err(CheckError::NotConfigured(reason)) => {
                    panic!("[Configure] {stage} ... not configured ... {reason}")
                }
                CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                    panic!("[Configure] {stage} ... invalid ... {reason}")
                }
                CheckResult::Ok(()) => (),
            },
            ConfigureCommand::Clean => (),
        }
    }

    for step in steps.iter_mut().rev() {
        let stage = step.name();

        match command {
            ConfigureCommand::Ensure | ConfigureCommand::Verify => (),
            ConfigureCommand::Clean => {
                match step.check(config) {
                    CheckResult::Err(CheckError::NotConfigured(_)) => continue,
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                        if !step.supports_undo() {
                            panic!("[Configure] {stage} ... not valid ... {reason:?}");
                        }
                    }
                    CheckResult::Ok(()) => (),
                };

                info!("[Configure] {stage} ... undoing");
                step.undo(config);
                match step.check(config) {
                    CheckResult::Ok(()) => {
                        if step.supports_do() && step.supports_undo() {
                            // If the step does nothing, it's fine if it's fully configured after being undone.
                            panic!("[Configure] {stage} ... not undone")
                        }
                    }
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                        panic!("[Configure] {stage} ... invalid ... {reason}")
                    }
                    CheckResult::Err(CheckError::NotConfigured(_)) => (),
                };
            }
        }
    }
}
