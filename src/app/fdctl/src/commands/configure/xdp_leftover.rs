use super::*;
use crate::Config;

use std::fs;

pub struct XdpLeftover;

impl Step for XdpLeftover {
    fn name(&self) -> &'static str {
        "xdp_leftover"
    }

    fn supports_do(&self) -> bool {
        false
    }

    fn supports_undo(&self) -> bool {
        false
    }

    fn step(&mut self, _: &mut Config) {}

    fn undo(&mut self, _: &Config) {}

    fn check(&mut self, config: &Config) -> CheckResult {
        let mut allowed_filenames: Vec<&str> = vec![&config.name];
        if config.netns.enabled {
            allowed_filenames.push(&config.netns.workspace);
        }

        let xdp_path = format!("/sys/fs/bpf/");

        for entry in fs::read_dir(&xdp_path).unwrap() {
            let entry = entry.unwrap();
            if !allowed_filenames.contains(&entry.file_name().to_str().unwrap()) {
                return CheckResult::Err(CheckError::PartiallyConfigured(format!(
                    "unknown bpf entry {}",
                    entry.path().display()
                )));
            }
        }

        // let output = Command::new("xdp-loader")
        //     .args(["status", &config.quic.interface])
        //     .output()
        //     .unwrap();
        // assert!(output.status.success());
        //
        // if !String::from_utf8(output.stdout).unwrap().contains("No XDP program loaded!") {
        //     CheckResult::Err(CheckError::PartiallyConfigured(format!("`xdp-loader status {}` shows a program is already loaded", &config.quic.interface)))
        // } else {
        //     CheckResult::Ok(())
        // }

        CheckResult::Ok(())
    }
}
