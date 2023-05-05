use super::*;
use crate::Config;

use std::process::Command;

pub struct EthTool;

macro_rules! run {
    ($command:expr, $($e:expr),* ) => {
        {
            assert!(Command::new($command).args(&[ $(&$e.to_string(),)* ]).status().unwrap().success());
        }
    }
}

impl Step for EthTool {
    fn name(&self) -> &'static str {
        "ethtool"
    }

    fn enabled(&self, config: &Config) -> bool {
        !config.netns.enabled
    }

    fn supports_undo(&self) -> bool {
        false
    }

    #[rustfmt::skip]
    fn step(&mut self, config: &mut Config) {
        // We need one channel for both TX and RX on the NIC for each QUIC tile, but the interface probably
        // defaults to one channel total.
        run!("ethtool", "--set-channels", config.tiles.quic.interface, "combined", config.layout.verify_tile_count);
    }

    fn undo(&mut self, _: &Config) {
    }

    fn check(&mut self, config: &Config) -> CheckResult {
        let output = Command::new("ethtool").args(["--show-channels", &config.tiles.quic.interface]).output().unwrap();
        if !output.status.success() {
            panic!("{}", String::from_utf8(output.stderr).unwrap());
        }
        let output = String::from_utf8(output.stdout).unwrap();
        let mut found = false;
        for line in output.trim().lines() {
            if line.starts_with("Combined:") {
                found = true;
                let count: u32 = line[9..].trim().parse().unwrap();
                if count < config.layout.verify_tile_count {
                    return CheckResult::Err(CheckError::NotConfigured("not enough channels".to_string()));
                }
            }
        }

        if !found {
            panic!("couldn't get number of combined channels from device in ethtool");
        }

        CheckResult::Ok(())
    }
}
