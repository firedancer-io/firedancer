use std::{collections::HashMap, process::{Command, Stdio}};

use clap::{arg, Args};
use libc::{cpu_set_t, sched_setaffinity, CPU_SET, CPU_ZERO, CPU_SETSIZE};

use crate::*;

#[derive(Debug, Args)]
pub(crate) struct Run {
    #[arg(long)]
    clean: bool,

    #[arg(long)]
    configure: bool,

    #[arg(long)]
    debug: bool,

    #[arg(long)]
    monitor: bool,
}

impl Run {
    pub(crate) fn needs_root(&self) -> bool {
        self.clean || self.configure || self.debug || self.monitor
    }
}

pub(crate) fn monitor(config: &Config) {
    let vars_file = std::fs::read_to_string(&format!(
        "{}/config.cfg",
        config.scratch_directory
    ))
    .unwrap();
    let vars: HashMap<&str, &str> = HashMap::from_iter(
        vars_file
            .trim()
            .lines()
            .skip(2)
            .map(|x| x.split_once('=').unwrap()),
    );

    let mut monitor =
        Command::new(format!("{}/fd_frank_mon.bin", config.binary_dir.display()))
            .args([
                "--pod",
                vars["POD"],
                "--cfg",
                &config.name,
                "--log-app",
                &config.name,
                "--log-thread",
                "mon",
                "--duration",
                &"31536000000000000".to_string(),
            ])
            .spawn()
            .unwrap();

    let status = monitor.wait().unwrap();
    assert!(status.success());
}

fn set_affinity_zero() {
    let mut cpuset: cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(0, unsafe {
        CPU_ZERO(&mut cpuset);
        CPU_SET(0, &mut cpuset);
        sched_setaffinity(0, CPU_SETSIZE as usize, &cpuset)
    });
}

pub(crate) fn run(args: Run, config: &mut Config) {
    if args.configure {
        if args.clean {
            super::configure(super::configure::ConfigureCommand::Fini, config);
        }
        super::configure(super::configure::ConfigureCommand::Init, config);
    }

    if config.netns.enabled {
        // Enter network namespace from the parent binary, which runs with CAP_SYS_ADMIN so that this
        // is possible.
        setns::set_network_namespace(&format!("/var/run/netns/{}", &config.tiles.quic.interface));
    }

    let vars_file = std::fs::read_to_string(&format!(
        "{}/config.cfg",
        config.scratch_directory
    ))
    .unwrap();
    let vars: HashMap<&str, &str> = HashMap::from_iter(
        vars_file
            .trim()
            .lines()
            .skip(2)
            .map(|x| x.split_once('=').unwrap()),
    );

    let command = format!("{}/fd_frank_run.bin", config.binary_dir.display());
    let mut run = if args.debug {
        let mut run = Command::new("gdb");
        run.args([&command, "--args"]);
        run
    } else {
        Command::new(command)
    };
    run.args([
        "--pod", &vars["POD"],
        "--cfg", &config.name,
        "--log-app", &config.name,
        "--log-thread", "main",
        "--tile-cpus", &config.layout.affinity,
    ]);

    set_affinity_zero();

    if args.debug || !args.monitor {
        let status = run.spawn().unwrap().wait().unwrap();
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        let mut run = run.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();

        let mut monitor =
            Command::new(format!("{}/fd_frank_mon.bin", config.binary_dir.display()))
                .args([
                    "--pod", &vars["POD"],
                    "--cfg", &config.name,
                    "--log-app", &config.name,
                    "--log-thread", "mon",
                    "--duration", &"31536000000000000".to_string(),
                ])
                .spawn()
                .unwrap();

        let status = monitor.wait().unwrap();
        assert!(status.success());

        let status = run.wait().unwrap();
        assert!(status.success());
    }
}
