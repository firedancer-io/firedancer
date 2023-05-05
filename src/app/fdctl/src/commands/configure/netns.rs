use super::*;
use crate::Config;

use std::process::Command;

pub struct NetNs;

macro_rules! run {
    ($command:expr, $($e:expr),* ) => {
        {
            assert!(Command::new($command).args(&[ $(&$e.to_string(),)* ]).status().unwrap().success());
        }
    }
}

impl Step for NetNs {
    fn name(&self) -> &'static str {
        "netns"
    }

    fn enabled(&self, config: &Config) -> bool {
        config.netns.enabled
    }

    fn supports_do(&self) -> bool {
        true
    }

    fn supports_undo(&self) -> bool {
        true
    }

    #[rustfmt::skip]
    fn step(&mut self, config: &mut Config) {
        run!("ip", "netns", "add", config.netns.interface0);
        run!("ip", "netns", "add", config.netns.interface1);
        run!("ip", "link", "add",  "dev", config.netns.interface0, "netns", config.netns.interface0,
            "type", "veth",
            "peer", "name", config.netns.interface1, "netns", config.netns.interface1,
            "numrxqueues", config.layout.verify_tile_count,
            "numtxqueues", config.layout.verify_tile_count);
        run!("ip", "netns", "exec", config.netns.interface0, "ip", "link", "set", "dev", config.netns.interface0, "address", config.netns.interface0_mac);
        run!("ip", "netns", "exec", config.netns.interface1, "ip", "link", "set", "dev", config.netns.interface1, "address", config.netns.interface1_mac);
        run!("ip", "netns", "exec", config.netns.interface0, "ip", "address", "add", format!("{}/30", &config.netns.interface0_addr), "dev", config.netns.interface0, "scope", "link");
        run!("ip", "netns", "exec", config.netns.interface1, "ip", "address", "add", format!("{}/30", &config.netns.interface1_addr), "dev", config.netns.interface1, "scope", "link");
        run!("ip", "netns", "exec", config.netns.interface0, "ip", "link", "set", "dev", config.netns.interface0, "up");
        run!("ip", "netns", "exec", config.netns.interface1, "ip", "link", "set", "dev", config.netns.interface1, "up");

        // We need one channel for both TX and RX on the NIC for each QUIC tile, but the virtual interfaces
        // default to one channel total.
        run!("nsenter", format!("--net=/var/run/netns/{}", &config.netns.interface0),
            "ethtool", "--set-channels", config.netns.interface0, "rx", config.layout.verify_tile_count, "tx", &config.layout.verify_tile_count);
        run!("nsenter", format!("--net=/var/run/netns/{}", &config.netns.interface1),
            "ethtool", "--set-channels", config.netns.interface1, "rx", config.layout.verify_tile_count, "tx", &config.layout.verify_tile_count);

        // UDP segmentation is a kernel feature that batches multiple UDP packets into one in the kernel
        // before splitting them later when dispatching. This feature is broken with network namespaces
        // so we disable it. Otherwise, we would see very large packets that don't decrypt. Need on both
        // tx and rx sides.
        run!("nsenter", format!("--net=/var/run/netns/{}", config.netns.interface0),
            "ethtool", "-K", config.netns.interface0, "tx-udp-segmentation", "off");
        run!("nsenter", format!("--net=/var/run/netns/{}", &config.netns.interface1),
            "ethtool", "-K", config.netns.interface1, "tx-udp-segmentation", "off");

        // Generic segmentation offload and TX GRE segmentation are similar things on the tx side that
        // also get messed up under netns in unknown ways.
        run!("nsenter", format!("--net=/var/run/netns/{}", config.netns.interface0),
            "ethtool", "-K", config.netns.interface0, "generic-segmentation-offload", "off");
        run!("nsenter", format!("--net=/var/run/netns/{}", &config.netns.interface1),
            "ethtool", "-K", config.netns.interface1, "generic-segmentation-offload", "off");
        run!("nsenter", format!("--net=/var/run/netns/{}", config.netns.interface0),
            "ethtool", "-K", config.netns.interface0, "tx-gre-segmentation", "off");
        run!("nsenter", format!("--net=/var/run/netns/{}", &config.netns.interface1),
            "ethtool", "-K", config.netns.interface1, "tx-gre-segmentation", "off");
    }

    fn undo(&mut self, config: &Config) {
        // Destroys interface1 as well, no need to check failure
        let _ = Command::new("ip")
            .args(["link", "del", "dev", &config.netns.interface0])
            .status()
            .unwrap()
            .success();

        let status1 = Command::new("ip")
            .args(["netns", "delete", &config.netns.interface0])
            .status()
            .unwrap()
            .success();
        let status2 = Command::new("ip")
            .args(["netns", "delete", &config.netns.interface1])
            .status()
            .unwrap()
            .success();

        // If neither of them was present, we wouldn't get to the undo step so make sure we were
        // able to delete whatever is there.
        assert!(status1 || status2);
    }

    fn check(&mut self, config: &Config) -> CheckResult {
        let output = Command::new("ip").args(["netns", "list"]).output().unwrap();
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout).unwrap();
        let namespaces = output.trim().lines().collect::<Vec<&str>>();
        if !namespaces.contains(&config.netns.interface0.as_ref())
            && !namespaces.contains(&config.netns.interface1.as_ref())
        {
            return CheckResult::Err(CheckError::NotConfigured(
                "no network namespace".to_string(),
            ));
        }
        if !namespaces.contains(&config.netns.interface0.as_ref())
            || !namespaces.contains(&config.netns.interface1.as_ref())
        {
            return CheckResult::Err(CheckError::PartiallyConfigured(
                "no network namespace".to_string(),
            ));
        }

        // TODO: Use `ip netns exec .. ip link show` to verify the configuration is correct
        // TODO: Check the ethtool stuff is correct as well

        CheckResult::Ok(())
    }
}
