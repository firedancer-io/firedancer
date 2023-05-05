//! Binary harness for spinning up a full Firedancer + Solana instance.
//! 
//! Three processes are started,
//! 
//!  1. The root process, this binary. Sets up and verifies operating system configuration
//!     and performs general housekeeping. Monitors both child processes and terminates
//!     the system if anything goes wrong.
//! 
//!  2. The Solana process. A full Solana instance, with some special configuration information
//!     to enable it to talk to Firedancer.
//! 
//!  3. The Firedancer process. A Firedancer instance, with corresponding configuration to
//!     enable it to talk to Solana.
//! 
//! If any process crashes, all three will be bought down.
//! 
//! For packaging, all three processes are contained in the one binary, and switched between
//! based on the command line.
use clap::{Parser, Subcommand, Args};
use std::{env, fs, io};
use std::path::Path;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use log::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,

    /// Location of the Firedancer build binary directory. For example `/home/user/firedancer/build/linux/gcc/x86_65/bin/`
    #[arg(long)]
    binary_dir: ::std::path::PathBuf,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Setup and verify the static configuration of the system
    Configure(Configure),

    /// Run a Firedancer validator node
    Run(Run),
}

#[derive(Debug, Args)]
struct Configure {
    #[command(subcommand)]
    configure_command: ConfigureCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigureCommand {
    Verify,
    Setup,
}

#[derive(Debug, Args)]
struct Run {
    #[command(subcommand)]
    subprocess: Option<Subprocess>,
}

#[derive(Debug, Subcommand)]
enum Subprocess {
    Solana,
    Firedancer,
}

fn verify_shmem_setup() {
    let shmem_path = env::var("FD_SHMEM_PATH").unwrap_or("/mnt/.fd".into());
    if !Path::new(&shmem_path).is_dir() {
        panic!("Shared memory has not been configured at {shmem_path:?}. Run `fd_shmem_cfg init`")
    }

    for size in ["gigantic", "huge", "normal"] {
        let path = format!("{shmem_path}/.{size}");
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => panic!("Shared memory configuration is invalid, expected directory {shmem_path} to exist"),
            result => result.unwrap(),
        };

        if !metadata.is_dir() {
            panic!("Shared memory configuration is invalid, expected {shmem_path} to be a directory");
        }

        let owner = metadata.uid();
        // todo: check owner is current running UIDx

        let mode = metadata.permissions().mode();
        if mode != 0o40700 {
            panic!("Shared memory configuration is invalid, expected directory {shmem_path} to be permissioned as 0o40700 but was {mode:o}");
        }
    }
}

fn verify_memory_pages_allocated() {
    for (size, page_size, expected_pages) in [
            ("huge", 2048, 512),
            ("gigantic", 1048576, 2)
        ] {
        let page_path = format!("/sys/devices/system/node/node0/hugepages/hugepages-{page_size}kB");

        let number_pages = fs::read_to_string(format!("{page_path}/nr_hugepages")).unwrap().trim().parse::<u32>().unwrap();
        let free_pages = fs::read_to_string(format!("{page_path}/free_hugepages")).unwrap().trim().parse::<u32>().unwrap();

        if number_pages != expected_pages {
            panic!("Large page configuration is invalid, expected {expected_pages} {size} pages, but there are {number_pages}");
        }

        if free_pages != expected_pages {
            panic!("Large pages are already in use, only {free_pages} of {expected_pages} {size} pages are free");
        }
    }
}

fn verify_configuration() {
    verify_shmem_setup();
    info!("Verifying shared memory ... configured");

    verify_memory_pages_allocated();
    info!("Verifying large pages ... configured");
}

struct FrankEnvironment {
    build: String,
    wksp: String,
    affinity: String,
    app: String,
    pod: String,
    run_args: String,
    mon_args: String,
    main_cnc: String,
}

fn clean_workspaces() {
    let shmem_path = env::var("FD_SHMEM_PATH").unwrap_or("/mnt/.fd".into());

    for size in ["huge", "gigantic"] {
        for entry in fs::read_dir(format!("{shmem_path}/.{size}")).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
    }
}

fn initialize_workspace(bindir: &Path) -> FrankEnvironment {
    let frank_init = format!("{}/fd_frank_init", bindir.display());
    let status = Command::new(frank_init)
                      .args(["frank1", "0-8", "4", bindir.parent().unwrap().as_os_str().to_str().unwrap()])
                      .status()
                      .unwrap();
    assert!(status.success());

    let cfg = fs::read_to_string("./tmp/frank1.cfg").unwrap();

    let build = &cfg.lines().find(|x| x.starts_with("BUILD=")).unwrap()["BUILD=".len()..];
    let wksp = &cfg.lines().find(|x| x.starts_with("WKSP=")).unwrap()["WKSP=".len()..];
    let affinity = &cfg.lines().find(|x| x.starts_with("AFFINITY=")).unwrap()["AFFINITY=".len()..];
    let app = &cfg.lines().find(|x| x.starts_with("APP=")).unwrap()["APP=".len()..];
    let pod = &cfg.lines().find(|x| x.starts_with("POD=")).unwrap()["POD=".len()..];
    let run_args = &cfg.lines().find(|x| x.starts_with("RUN_ARGS=")).unwrap()["RUN_ARGS=".len()..];
    // Strip leading/trailing quotes
    let run_args = &run_args[1..run_args.len()-1];
    let mon_args = &cfg.lines().find(|x| x.starts_with("MON_ARGS=")).unwrap()["MON_ARGS=".len()..];
    // Strip leading/trailing quotes
    let mon_args = &mon_args[1..mon_args.len()-1];
    let main_cnc = &cfg.lines().find(|x| x.starts_with("MAIN_CNC=")).unwrap()["MAIN_CNC=".len()..];

    FrankEnvironment {
        build: build.into(),
        wksp: wksp.into(),
        affinity: affinity.into(),
        app: app.into(),
        pod: pod.into(),
        run_args: run_args.into(),
        mon_args: mon_args.into(),
        main_cnc: main_cnc.into(),
    }
}

fn set_pod_value(bindir: &Path, pod: &str, type_: &str, name: &str, value: &str) {
    let fd_pod_ctl = format!("{}/fd_pod_ctl", bindir.display());
    let status = Command::new(fd_pod_ctl)
                      .args(["update", pod, type_, name, value])
                      .status()
                      .unwrap();
    assert!(status.success());
}

fn main() {
    env_logger::init();
    
    let args = Cli::parse();

    match args.command {
        CliCommand::Configure(configure) => {
            verify_configuration();
        },
        CliCommand::Run(run) => {
            clean_workspaces();
            verify_configuration();
            let env = initialize_workspace(&args.binary_dir);
            // set_pod_value(&args.binary_dir, &env.pod, "uint", "frank1.pack.cu-limit", "12000001");

            let mut run_args = env.run_args.split_whitespace().map(|x| x.into()).collect::<Vec<String>>();
            run_args.extend(["--tile-cpus".to_string(), "f,0-7".to_string()]);

            let mut child = Command::new(format!("{}/fd_frank_run.bin", args.binary_dir.display()))
                    .args(run_args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();

            let mut mon_args = env.mon_args.split_whitespace().map(|x| x.into()).collect::<Vec<String>>();
            mon_args.extend(["--duration".to_string(), "31536000000000000".to_string()]);

            let mut monitor = Command::new(format!("{}/fd_frank_mon.bin", args.binary_dir.display()))
                    .args(mon_args)
                    .spawn()
                    .unwrap();

            let status = monitor.wait().unwrap();
            assert!(status.success());

            let status = child.wait().unwrap();
            assert!(status.success());
        },
    }
}
