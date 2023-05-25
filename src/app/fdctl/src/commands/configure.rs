mod certs;
mod ethtool;
mod frank;
mod large_pages;
mod netns;
mod shmem;
mod workspace;
mod xdp;
mod xdp_leftover;

use std::fs::metadata;
use std::io::ErrorKind;
use std::os::unix::fs::{
    MetadataExt,
    PermissionsExt,
};

use clap::{
    Args,
    Subcommand,
};
use log::*;

use crate::Config;

type ExplainPermissionType = Option<fn(&Config) -> Vec<Option<String>>>;

struct Stage {
    /// Name of the command
    name: &'static str,

    /// If the command is enabled in this configuration.
    enabled: Option<fn(&Config) -> bool>,

    /// If we can't verify whether the step has been performed correctly or not, we can redo it
    /// every time the step is run.
    always_recreate: bool,

    /// Get a human readable list of permissions required to init the stage that we do not
    /// currently have.
    explain_init_permissions: ExplainPermissionType,

    /// Get a human readable list of permissions required to fini the stage that we do not
    /// currently have.
    explain_fini_permissions: ExplainPermissionType,

    /// Perform the step, assuming that it has not been done before.
    init: Option<fn(config: &mut Config)>,

    /// Undo the step. The step may be not performed, partially, or fully performed.
    fini: Option<fn(config: &Config)>,

    /// Check if the step has been performed.
    check: fn(config: &Config) -> Result<(), CheckError>,
}

impl Stage {
    fn enabled(&self, config: &Config) -> bool {
        if let Some(enabled_function) = self.enabled {
            enabled_function(config)
        } else {
            true
        }
    }

    fn explain_permissions(&self, command: StageCommand, config: &Config) -> Vec<String> {
        match command {
            StageCommand::Init => {
                if self.enabled(config) {
                    if let Some(explain_init_permissions_function) = self.explain_init_permissions {
                        if (self.check)(config).is_err() {
                            return explain_init_permissions_function(config)
                                .into_iter()
                                .flatten()
                                .collect();
                        }
                    }
                }
                vec![]
            }
            StageCommand::Check => vec![],
            StageCommand::Fini => {
                if let Some(explain_fini_permissions_function) = self.explain_fini_permissions {
                    match (self.check)(config) {
                        Ok(()) | Err(CheckError::PartiallyConfigured(_)) => {
                            return explain_fini_permissions_function(config)
                                .into_iter()
                                .flatten()
                                .collect()
                        }
                        Err(CheckError::NotConfigured(_)) => (),
                    }
                }
                vec![]
            }
        }
    }
}

const STAGES: &[Stage] = &[
    large_pages::STAGE,
    shmem::STAGE,
    xdp::STAGE,
    xdp_leftover::STAGE,
    netns::STAGE,
    ethtool::STAGE,
    certs::STAGE,
    workspace::STAGE,
    frank::STAGE,
];

#[derive(Debug, Args, Copy, Clone)]
pub(crate) struct ConfigureCli {
    #[command(subcommand)]
    pub(crate) stage: StageCli,
}

impl ConfigureCli {
    pub(crate) fn explain_permissions(&self, config: &Config) -> Vec<String> {
        match self.stage {
            StageCli::All(group) => STAGES
                .iter()
                .flat_map(|command| command.explain_permissions(group.command, config))
                .collect(),
            other => other
                .stage()
                .explain_permissions(other.command().command, config),
        }
    }
}

#[derive(Debug, Subcommand, Copy, Clone)]
pub(crate) enum StageCli {
    /// Configure all of the below
    All(StageCommandCli),

    /// Make sure the kernel is configured with a minimum number of huge and gigantic pages
    LargePages(StageCommandCli),

    /// Mounts hugetlbfs gigantic and huge filesystems onto the system large pages
    Shmem(StageCommandCli),

    /// Install the Firedancer XDP driver
    Xdp(StageCommandCli),

    /// Check that there are no other XDP drivers on the same interface on the system
    XdpLeftover(StageCommandCli),

    /// Set up virtual network namespaces for use during development
    Netns(StageCommandCli),

    /// Ensures the network device is configured with enough tx / rx queues
    Ethtool(StageCommandCli),

    /// Create new OpenSSL certificates for the QUIC endpoint
    Certs(StageCommandCli),

    /// Creates a Firedancer workspace on top of huge pages
    Workspace(StageCommandCli),

    /// Fully initialize a new Firedancer instance ready to run
    Frank(StageCommandCli),
}

impl StageCli {
    fn stage(&self) -> &Stage {
        match self {
            StageCli::All(_) => unreachable!(),
            StageCli::LargePages(_) => &large_pages::STAGE,
            StageCli::Shmem(_) => &shmem::STAGE,
            StageCli::Xdp(_) => &xdp::STAGE,
            StageCli::XdpLeftover(_) => &xdp_leftover::STAGE,
            StageCli::Netns(_) => &netns::STAGE,
            StageCli::Ethtool(_) => &ethtool::STAGE,
            StageCli::Certs(_) => &certs::STAGE,
            StageCli::Workspace(_) => &workspace::STAGE,
            StageCli::Frank(_) => &frank::STAGE,
        }
    }

    fn command(&self) -> &StageCommandCli {
        match self {
            StageCli::All(argument) => argument,
            StageCli::LargePages(argument) => argument,
            StageCli::Shmem(argument) => argument,
            StageCli::Xdp(argument) => argument,
            StageCli::XdpLeftover(argument) => argument,
            StageCli::Netns(argument) => argument,
            StageCli::Ethtool(argument) => argument,
            StageCli::Certs(argument) => argument,
            StageCli::Workspace(argument) => argument,
            StageCli::Frank(argument) => argument,
        }
    }
}

#[derive(Debug, Args, Copy, Clone)]
pub(crate) struct StageCommandCli {
    #[command(subcommand)]
    pub(crate) command: StageCommand,
}

#[derive(Debug, Subcommand, Copy, Clone)]
pub(crate) enum StageCommand {
    /// Perform the configuration if it is not already valid on the system
    Init,

    /// Check that the configuration is currently valid, program exits with an error if it is not
    Check,

    /// Remove the configuration completely from the system
    Fini,
}

#[derive(Debug)]
enum CheckError {
    NotConfigured(String),
    PartiallyConfigured(String),
}
type CheckResult = Result<(), CheckError>;

macro_rules! not_configured {
    ($fmt:literal) => {
        CheckResult::Err(CheckError::NotConfigured(format!($fmt)))
    };
}

macro_rules! partially_configured {
    ($fmt:literal) => {
        CheckResult::Err(CheckError::PartiallyConfigured(format!($fmt)))
    };
}

pub(crate) use {
    not_configured,
    partially_configured,
};

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
            return partially_configured!("{path} does not exist")
        }
        result => return partially_configured!("error reading {path} {result:?}"),
    };

    let uid = metadata.uid();
    let gid = metadata.gid();
    let mode = metadata.permissions().mode();

    match (expected_dir, metadata.is_dir()) {
        (true, false) => return partially_configured!("{path} is a file, not a directory"),
        (false, true) => return partially_configured!("{path} is a directory, not a file"),
        _ => (),
    }

    if uid != expected_uid {
        return partially_configured!("owner of {path} is {uid}, not {expected_uid}");
    }

    if gid != expected_gid {
        return partially_configured!("group of {path} is {gid}, not {expected_gid}");
    }

    if mode != expected_mode {
        return partially_configured!("permissions of {path} is {mode:o}, not {expected_mode:o}");
    }

    CheckResult::Ok(())
}

fn check_directory(
    path: &str,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> CheckResult {
    path_exists(path, expected_uid, expected_gid, expected_mode, true)
}

fn check_file(path: &str, expected_uid: u32, expected_gid: u32, expected_mode: u32) -> CheckResult {
    path_exists(path, expected_uid, expected_gid, expected_mode, false)
}

fn configure_stage(stage: &Stage, command: StageCommand, config: &mut Config) -> bool {
    let name = stage.name;

    if !stage.enabled(config) {
        info!("[Configure] {name} ... skipping ... not enabled due to config");
        return false;
    }

    match command {
        StageCommand::Init => {
            match (stage.check)(config) {
                CheckResult::Err(CheckError::NotConfigured(reason)) => {
                    info!("[Configure] {name} ... unconfigured ... {reason}")
                }
                CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                    match stage.fini {
                        None => panic!(
                            "[Configure] {name} ... does not support undo but was not valid ... \
                             {reason}"
                        ),
                        Some(undo) => {
                            info!("[Configure] {name} ... undoing ... {reason}");
                            undo(config);
                        }
                    }

                    match (stage.check)(config) {
                        CheckResult::Ok(()) | CheckResult::Err(CheckError::NotConfigured(_)) => (),
                        CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                            if !stage.always_recreate {
                                panic!(
                                    "[Configure] {name} ... clean was unable to get back to an \
                                     unconfigured state ... {reason}"
                                );
                            }
                        }
                    };
                }
                CheckResult::Ok(()) => {
                    info!("[Configure] {name} ... already valid");
                    return false;
                }
            };

            info!("[Configure] {name} ... initializing");
            if let Some(step) = stage.init {
                step(config);
            }
            match (stage.check)(config) {
                CheckResult::Err(CheckError::NotConfigured(reason)) => panic!(
                    "[Configure] {name} ... tried to initialize but didn't do anything ... \
                     {reason}"
                ),
                CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                    if !stage.always_recreate {
                        panic!(
                            "[Configure] {name} ... tried to initialize but was still \
                             unconfigured ... {reason}"
                        );
                    }
                }
                CheckResult::Ok(()) => (),
            }
        }
        StageCommand::Check => match (stage.check)(config) {
            CheckResult::Err(CheckError::NotConfigured(reason)) => {
                error!("[Configure] {name} ... not configured ... {reason}");
                return true;
            }
            CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                if !stage.always_recreate {
                    error!("[Configure] {name} ... invalid ... {reason}");
                    return true;
                } else {
                    info!("[Configure {name} ... not configured ... must always be recreated");
                }
            }
            CheckResult::Ok(()) => (),
        },
        StageCommand::Fini => {
            match (stage.check)(config) {
                CheckResult::Err(CheckError::NotConfigured(reason)) => {
                    info!("[Configure] {name} ... not configured ... {reason:?}");
                    return false;
                }
                CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                    if stage.fini.is_none() {
                        panic!("[Configure] {name} ... not valid ... {reason:?}");
                    }
                }
                CheckResult::Ok(()) => (),
            };

            info!("[Configure] {name} ... undoing");
            if let Some(undo) = stage.fini {
                undo(config);
            }
            match (stage.check)(config) {
                CheckResult::Ok(()) => {
                    if stage.init.is_some() && stage.fini.is_some() {
                        // If the step does nothing, it's fine if it's fully configured after being
                        // undone.
                        panic!("[Configure] {name} ... not undone")
                    }
                }
                CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                    if !stage.always_recreate {
                        panic!("[Configure] {name} ... invalid ... {reason}")
                    }
                }
                CheckResult::Err(CheckError::NotConfigured(_)) => (),
            };
        }
    }
    false
}

fn configure_all(command: StageCommand, config: &mut Config) -> bool {
    let mut should_panic = false;

    match command {
        StageCommand::Init | StageCommand::Check => {
            STAGES.iter().for_each(|step: &Stage| {
                if configure_stage(step, command, config) {
                    should_panic = true;
                }
            });
        }
        StageCommand::Fini => {
            STAGES.iter().rev().for_each(|step| {
                if configure_stage(step, command, config) {
                    should_panic = true;
                }
            });
        }
    };

    should_panic
}

pub(crate) fn configure(stage: StageCli, config: &mut crate::config::Config) {
    let should_panic = match stage {
        StageCli::All(command) => configure_all(command.command, config),
        other => configure_stage(other.stage(), other.command().command, config),
    };

    if should_panic {
        panic!("Configuration is not valid");
    }
}
