use super::*;
use crate::*;

use std::{process::Command, fs};

pub struct Frank;

const CNC_APP_SIZE: u32 = 4032;
const POD_SIZE: u32 = 16384;

macro_rules! run {
    ($bin:expr, $command:expr, [ $($e:expr),* ]) => {
        {
            let output = Command::new(format!("{}/{}", $bin.display(), $command))
                .args(&[ $(&$e.to_string(),)* ])
                .output()
                .unwrap();
            if !output.status.success() {
                let stderr = String::from_utf8(output.stderr).unwrap();
                panic!("{}", stderr);
            }
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        }
    }
}

macro_rules! run_no_error {
    ($bin:expr, $command:expr, [ $($e:expr),* ]) => {
        {
            let _ = Command::new(format!("{}/{}", $bin.display(), $command))
                .args(&[ $(&$e.to_string(),)* ])
                .output()
                .unwrap();
        }
    }
}

impl Step for Frank {
    fn name(&self) -> &'static str {
        "frank"
    }

    #[rustfmt::skip]
    fn step(&mut self, config: &mut Config) {
        let bin = &config.binary_dir;
        let name = &config.name;
        let workspace = format!("{}.wksp", &config.name);

        if config.netns.enabled {
            // Enter network namespace here so that network setup commands work correctly.
            setns::set_network_namespace(&format!("/var/run/netns/{}", &config.tiles.quic.interface));
        }

        let output = Command::new("runuser").args(["-u", &config.user, "--", &format!("{}/fd_wksp_ctl", bin.to_str().unwrap()),
            "new", &workspace, &config.shmem.workspace_page_count.to_string(), &config.shmem.workspace_page_size.to_string(), &config.layout.affinity.to_string(), "0600"]).output().unwrap();
        if !output.status.success() {
            panic!("{}", String::from_utf8(output.stderr).unwrap());
        }

        let pod = run!(bin, "fd_pod_ctl", ["new", workspace, POD_SIZE]);

        let main_cnc = run!(bin, "fd_tango_ctl", ["new-cnc", workspace, 0, "tic", CNC_APP_SIZE]);
        run!(bin, "fd_pod_ctl", ["insert", pod, "cstr", format!("{name}.main.cnc"), main_cnc]);

        // Pack tiles
        let cnc = run!(bin, "fd_tango_ctl", ["new-cnc", workspace, 0, "tic", CNC_APP_SIZE]);
        let mcache = run!(bin, "fd_tango_ctl", ["new-mcache", workspace, config.tiles.pack.prq_size, 0, 0]);
        let dcache = run!(bin, "fd_tango_ctl", [ "new-dcache", workspace, "4808", config.tiles.pack.prq_size, 1, 1, 0]);
        let (pack_scratch, cu_est_table) = if std::path::Path::new(&format!("{}/fd_pack_ctl", bin.display())).exists() {
            // TODO: Always enable this when merged with pack changes in 1.2
            let pack_scratch = run!(bin, "fd_pack_ctl", [ "new-scratch", workspace, config.tiles.pack.bank_count, config.tiles.pack.prq_size]);
            let cu_est_table = run!(bin, "fd_pack_ctl", [ "new-cu-est-tbl", workspace, config.tiles.pack.cu_est_table_size, config.tiles.pack.cu_est_history, config.tiles.pack.cu_est_default]);
            (pack_scratch, cu_est_table)
        } else {
            ("".to_string(), "".to_string())
        };
        let return_fseq = run!(bin, "fd_tango_ctl", ["new-fseq", workspace, 0]);
        run!(bin, "fd_pod_ctl", [
            "insert", pod, "cstr", format!("{name}.pack.cnc"), cnc,
            "insert", pod, "cstr", format!("{name}.pack.out-mcache"), mcache,
            "insert", pod, "cstr", format!("{name}.pack.out-dcache"), dcache,
            "insert", pod, "cstr", format!("{name}.pack.scratch"), pack_scratch,
            "insert", pod, "cstr", format!("{name}.pack.cu-est-tbl"), cu_est_table,
            "insert", pod, "cstr", format!("{name}.pack.return-fseq"), return_fseq,
            "insert", pod, "ulong", format!("{name}.pack.bank-cnt"), config.tiles.pack.bank_count,
            "insert", pod, "ulong", format!("{name}.pack.txnq-sz"), config.tiles.pack.prq_size,
            "insert", pod, "ulong", format!("{name}.pack.cu-est-tbl-sz"), config.tiles.pack.cu_est_table_size,
            "insert", pod, "uint", format!("{name}.pack.cu-limit"), config.tiles.pack.cu_limit
        ]);

        // Dedup tiles
        let cnc = run!(bin, "fd_tango_ctl", ["new-cnc", workspace, 0, "tic", CNC_APP_SIZE]);
        let tcache = run!(bin, "fd_tango_ctl", [ "new-tcache", workspace, config.tiles.dedup.tcache_depth, config.tiles.dedup.tcache_map_count]);
        let mcache = run!(bin, "fd_tango_ctl", ["new-mcache", workspace, config.tiles.verify.depth, 0, 0]); // Same as verify tile depth
        let fseq = run!(bin, "fd_tango_ctl", ["new-fseq", workspace, 0]);
        run!(bin, "fd_pod_ctl", [
            "insert", pod, "cstr", format!("{name}.dedup.cnc"), cnc,
            "insert", pod, "cstr", format!("{name}.dedup.tcache"), tcache,
            "insert", pod, "cstr", format!("{name}.dedup.mcache"), mcache,
            "insert", pod, "cstr", format!("{name}.dedup.fseq"), fseq
        ]);

        let mut verify_info = vec![];

        // Verify tiles
        for i in 0..config.layout.verify_tile_count {
            let in_mcache = run!(bin, "fd_tango_ctl", ["new-mcache", workspace, config.tiles.verify.depth, 0, 0]);
            let in_dcache = run!(bin, "fd_tango_ctl", ["new-dcache", workspace, config.tiles.verify.mtu, config.tiles.verify.depth, 1, 1, config.tiles.verify.depth * 32]);
            let in_fseq = run!(bin, "fd_tango_ctl", ["new-fseq", workspace, 0]);
            run!(bin, "fd_pod_ctl", [
                "insert", pod, "cstr", format!("{name}.verifyin.v{i}in.mcache"), in_mcache,
                "insert", pod, "cstr", format!("{name}.verifyin.v{i}in.dcache"), in_dcache,
                "insert", pod, "cstr", format!("{name}.verifyin.v{i}in.fseq"), in_fseq
            ]);

            let cnc = run!(bin, "fd_tango_ctl", ["new-cnc", workspace, 2, "tic", CNC_APP_SIZE]);
            let mcache = run!(bin, "fd_tango_ctl", ["new-mcache", workspace, config.tiles.verify.depth, 0, 0]);
            let dcache = run!(bin, "fd_tango_ctl", ["new-dcache",workspace,config.tiles.verify.mtu,config.tiles.verify.depth,1,1,0]);
            let fseq = run!(bin, "fd_tango_ctl", ["new-fseq", workspace, 0]);
            run!(bin, "fd_pod_ctl", [
                "insert", pod, "cstr", format!("{name}.verify.v{i}.cnc"), cnc,
                "insert", pod, "cstr", format!("{name}.verify.v{i}.mcache"), mcache,
                "insert", pod, "cstr", format!("{name}.verify.v{i}.dcache"), dcache,
                "insert", pod, "cstr", format!("{name}.verify.v{i}.fseq"), fseq
            ]);

            verify_info.push((in_mcache, in_dcache, in_fseq));
        }

        // Initialize XDP
        run_no_error!(bin, "fd_xdp_ctl", ["unhook-iface", name, config.tiles.quic.interface]); // Ok if this fails
        std::thread::sleep(std::time::Duration::from_millis(1_000)); // Work around race condition, ugly hack
        run!(bin, "fd_xdp_ctl", ["hook-iface", name, config.tiles.quic.interface, config.tiles.quic.xdp_mode]);
        let output = Command::new("ip").args(["address", "show", "dev", &config.tiles.quic.interface]).output().unwrap();
        assert!(output.status.success());

        let regex =
            regex::Regex::new("^\\s+inet ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\\/.*$").unwrap();
        let output = String::from_utf8(output.stdout).unwrap();
        let listen_addresses = output
            .lines()
            .map(|x| regex.captures(x))
            .filter(|x| x.is_some())
            .map(|x| x.unwrap().get(1).unwrap().as_str().to_string())
            .collect::<Vec<String>>();
        if listen_addresses.is_empty() {
            panic!("Found no IP addresses on interface {}", config.tiles.quic.interface);
        }
        for addr in &listen_addresses {
            run!(bin, "fd_xdp_ctl", ["listen-udp-port", name, &addr, config.tiles.quic.listen_port, "tpu-quic"]);
        }
        let src_mac_address = Command::new("ip")
            .args(["address", "show", "dev", &config.tiles.quic.interface])
            .output()
            .unwrap();
        assert!(src_mac_address.status.success(), "{}", String::from_utf8(src_mac_address.stderr).unwrap());
        let output = String::from_utf8(src_mac_address.stdout).unwrap();
        let src_mac_address = output
            .lines()
            .find(|x| x.contains("link/ether"))
            .unwrap()
            .trim()
            .split_whitespace()
            .nth(1)
            .unwrap();

        // QUIC tiles
        for i in 0..config.layout.verify_tile_count as usize {
            let cnc = run!(bin, "fd_tango_ctl", ["new-cnc", workspace, 2, "tic", CNC_APP_SIZE]);
            let quic = if std::path::Path::new(&format!("{}/fd_quic_ctl", bin.display())).exists() {
                // TODO: Always enable this when merged with QUIC changes in 1.1
                run!(bin, "fd_quic_ctl", ["new-quic", workspace])
            } else {
                "".to_owned()
            };
            let xsk = run!(bin, "fd_xdp_ctl", ["new-xsk", workspace, config.tiles.quic.xdp_frame_size, config.tiles.quic.xdp_rx_depth, config.tiles.quic.xdp_tx_depth]);
            run!(bin, "fd_xdp_ctl", ["bind-xsk", xsk, name, config.tiles.quic.interface, i]);
            let xsk_aio = run!(bin, "fd_xdp_ctl", ["new-xsk-aio", workspace, config.tiles.quic.xdp_tx_depth, config.tiles.quic.xdp_aio_depth]);

            run!(bin, "fd_pod_ctl", [
                "insert", pod, "cstr", format!("{name}.quic.quic{i}.cnc"), cnc,
                "insert", pod, "cstr", format!("{name}.quic.quic{i}.mcache"), verify_info[i].0,
                "insert", pod, "cstr", format!("{name}.quic.quic{i}.dcache"), verify_info[i].1,
                "insert", pod, "cstr", format!("{name}.quic.quic{i}.fseq"), verify_info[i].2,
                "insert", pod, "cstr", format!("{name}.quic.quic{i}.quic"), quic,
                "insert", pod, "cstr", format!("{name}.quic.quic{i}.xsk"), xsk,
                "insert", pod, "cstr", format!("{name}.quic.quic{i}.xsk_aio"), xsk_aio
            ]);
        }

        // Certificates
        let status = Command::new("runuser").args(["-u", &config.user, "--", "mkdir", "-p", &config.scratch_directory]).status().unwrap();
        assert!(status.success());
        let output = Command::new("runuser")
            .current_dir(&config.scratch_directory)
            .args([
                "-u", &config.user,
                "--",
                "openssl", "req", "-x509", "-newkey", "ed25519", "-days", "365", "-nodes",
                "-keyout", "key.pem",
                "-out", "cert.pem",
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ])
            .output()
            .unwrap();
        if !output.status.success() {
            panic!("{}", String::from_utf8(output.stderr).unwrap());
        }

        run!(bin, "fd_pod_ctl", [
            "insert", pod, "cstr", format!("{name}.quic_cfg.cert_file"), format!("{}/cert.pem", &config.scratch_directory),
            "insert", pod, "cstr", format!("{name}.quic_cfg.key_file"), format!("{}/key.pem", &config.scratch_directory),
            "insert", pod, "cstr", format!("{name}.quic_cfg.ip_addr"), &listen_addresses[0],
            "insert", pod, "ushort", format!("{name}.quic_cfg.listen_port"), config.tiles.quic.listen_port,
            "insert", pod, "cstr", format!("{name}.quic_cfg.src_mac_addr"), src_mac_address,
            "insert", pod, "ulong", format!("{name}.quic_cfg.idle_timeout_ms"), 1000
        ]);

        config.frank = FrankConfig {
            pod: pod.split(":").collect::<Vec<&str>>()[1].parse().unwrap(),
            main_cnc: main_cnc.split(":").collect::<Vec<&str>>()[1]
                .parse()
                .unwrap(),
            src_mac_address: src_mac_address.to_string(),
            listen_addresses,
        };

        config.dump_to_bash();
    }

    fn undo(&mut self, config: &Config) {
        let workspace = format!("{}.wksp", &config.name);

        run!(&config.binary_dir, "fd_xdp_ctl", ["unhook-iface", &config.name, config.tiles.quic.interface]);
        run!(&config.binary_dir, "fd_wksp_ctl", ["delete", workspace]);
        match std::fs::remove_dir_all(&config.scratch_directory) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => panic!("{}", err),
            Ok(()) => (),
        }
    }

    fn check(&mut self, config: &Config) -> CheckResult {
        // HACK ... we can't really verify if a frank workspace is valid to be reused, so it just
        // gets blown away and recreated every time. If we just created one, assume that it's valid.
        if config.frank.pod > 0 {
            return CheckResult::Ok(());
        }

        for size in ["normal", "huge", "gigantic"] {
            let path = format!("{}/.{size}/{}.wksp", &config.shmem.path, &config.name);
            match fs::metadata(&path) {
                Ok(_) => {
                    return CheckResult::Err(CheckError::PartiallyConfigured(format!(
                        "file {} exists",
                        &path
                    )))
                }
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                result => {
                    return CheckResult::Err(CheckError::PartiallyConfigured(format!(
                        "error reading {} {result:?}",
                        &path
                    )))
                }
            };
        }

        CheckResult::Err(CheckError::NotConfigured(format!(
            "no files in {}",
            &config.shmem.path
        )))
    }
}
