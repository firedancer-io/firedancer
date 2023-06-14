use std::collections::HashMap;
use std::process::Stdio;

use clap::{
    arg,
    Args,
};
use libc::{
    RLIMIT_MEMLOCK,
    RLIMIT_NICE,
};

use crate::security::*;
use crate::utility::*;
use crate::Config;

#[derive(Debug, Args)]
pub(crate) struct RunCli {
    /// If needed, configure the environment to make sure Firedancer will run
    #[arg(long)]
    configure: bool,

    /// Launch the Firedancer binary under `gdb` and break immediately
    #[arg(long)]
    debug: bool,

    /// Launch Firedancer in the background and run a monitor in the current
    /// terminal.
    #[arg(long)]
    monitor: bool,
}

const CONFIGURE_STAGE: crate::commands::configure::StageCli =
    crate::commands::configure::StageCli::All(crate::commands::configure::StageCommandCli {
        command: crate::commands::configure::StageCommand::Init,
    });

const CONFIGURE_COMMAND: crate::CliCommand =
    crate::CliCommand::Configure(crate::commands::ConfigureCli {
        stage: CONFIGURE_STAGE,
    });

impl RunCli {
    #[rustfmt::skip]
    pub(crate) fn explain_permissions(&self, config: &Config) -> Vec<String> {
        let run_binary = format!("{}/fd_frank_run.bin", config.binary_dir);

        // If we want to configure before, we also need all the permissions that would be
        // needed to configure.
        let configure = if self.configure {
            CONFIGURE_COMMAND.explain_capabilities(config)
        } else {
            vec![]
        };

        let mlock_limit = config.shmem.workspace_size();
        vec![
            configure,
            vec![
                check_resource("run", &run_binary, RLIMIT_MEMLOCK, mlock_limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory with `mlock(2)`"),
                check_resource("run", &run_binary, RLIMIT_NICE, 40, "call `setpriority(2)` to increase thread priorities"),
                check_file_cap("run", &run_binary, CAP_NET_RAW, "call `bind(2)` to bind to a socket with `SOCK_RAW`"),
                check_file_cap("run", &run_binary, CAP_SYS_ADMIN, "initialize XDP by calling `bpf_obj_get`"),
            ].into_iter().flatten().collect()
        ].into_iter().flatten().collect()
    }
}

fn config_vars(config: &Config) -> HashMap<String, String> {
    let vars_file =
        std::fs::read_to_string(format!("{}/config.cfg", config.scratch_directory)).unwrap();
    HashMap::from_iter(
        vars_file
            .trim()
            .lines()
            .skip(2)
            .map(|x| x.split_once('=').unwrap())
            .map(|(a, b)| (a.to_owned(), b.to_owned())),
    )
}

pub(crate) fn monitor(config: &Config) {
    let name = &config.name;
    let bin = &config.binary_dir;
    let pod = &config_vars(config)["POD"];

    let status = run!(
        status,
        "{bin}/fd_frank_mon.bin --pod {pod} --log-app {name} --log-thread mon --duration \
         31536000000000000"
    );
    assert!(status.success());
}

pub(crate) fn run(args: RunCli, config: &mut Config) {
    if args.configure {
        crate::commands::configure(CONFIGURE_STAGE, config)
    }

    let prefix_gdb = if args.debug {
        format!("gdb {}/fd_frank_run.bin --args", config.binary_dir)
    } else {
        format!("{}/fd_frank_run.bin", config.binary_dir)
    };

    let netns_arg = if config.development.netns.enabled {
        format!("--netns /var/run/netns/{}", config.tiles.quic.interface)
    } else {
        "".to_owned()
    };

    let pod = &config_vars(config)["POD"];
    let name = &config.name;
    let affinity = &config.layout.affinity;
    let quic = &config.tiles.quic;

    #[rustfmt::skip]
    let env = [
        ("QUIC_CONN_CNT", quic.max_concurrent_connections.to_string()),
        ("QUIC_CONN_ID_CNT", quic.max_concurrent_connection_ids_per_connection.to_string()),
        ("QUIC_STREAM_CNT", quic.max_concurrent_streams_per_connection.to_string()),
        ("QUIC_HANDSHAKE_CNT", quic.max_concurrent_handshakes.to_string()),
        ("QUIC_MAX_INFLIGHT_PKTS", quic.max_inflight_quic_packets.to_string()),
        ("QUIC_TX_BUF_SZ", quic.tx_buf_size.to_string()),
        ("QUIC_RX_BUF_SZ", quic.rx_buf_size.to_string()),
    ];

    let mut run = run_builder!(
        cwd = None,
        env = Some(&env),
        cmd = "{prefix_gdb} {netns_arg} --pod {pod} --log-app {name} --log-thread main \
               --tile-cpus {affinity}",
    );

    set_affinity_zero();

    if args.debug || !args.monitor {
        let status = run.status().unwrap();
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        let mut run = run
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        monitor(config);
        assert!(run.wait().unwrap().success());
    }
}
