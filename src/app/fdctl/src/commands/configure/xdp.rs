use super::*;
use crate::Config;

use std::fs;
use std::io::ErrorKind;
use std::process::Command;

pub struct Xdp;

impl Step for Xdp {
    fn name(&self) -> &'static str {
        "xdp"
    }

    fn step(&mut self, config: &mut Config) {
        let fd_xdp_ctl = format!("{}/fd_xdp_ctl", config.binary_dir.display());
        let output = Command::new(fd_xdp_ctl)
            .args(["init", &config.name, "0750", &config.user, ""])
            .output()
            .unwrap();
        if !output.status.success() {
            panic!("{}", String::from_utf8(output.stderr).unwrap());
        }
    }

    fn undo(&mut self, config: &Config) {
        let fd_xdp_ctl = format!("{}/fd_xdp_ctl", config.binary_dir.display());
        let output = Command::new(fd_xdp_ctl)
            .args(["fini", &config.name])
            .output()
            .unwrap();
        if !output.status.success() {
            panic!("{}", String::from_utf8(output.stderr).unwrap());
        }
    }

    fn check(&mut self, config: &Config) -> CheckResult {
        let xdp_path = format!("/sys/fs/bpf/{}", config.name);
        match fs::metadata(&xdp_path) {
            Ok(_) => (),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return CheckResult::Err(CheckError::NotConfigured(format!(
                    "{xdp_path} does not exist"
                )))
            }
            result => {
                return CheckResult::Err(CheckError::PartiallyConfigured(format!(
                    "error reading path {xdp_path} {result:?}"
                )))
            }
        };

        check_directory("/sys/fs/bpf", config.uid, 0, 0o40750)?;
        check_directory(&xdp_path, config.uid, 0, 0o40750)?;
        check_file(
            &format!("/sys/fs/bpf/{}/udp_dsts", config.name),
            config.uid,
            0,
            0o100640,
        )?;

        // TODO verify_file_pinned check this is actually a bpf pin and load the map ...
        // TODO verify pinned program is the same as we would load

        CheckResult::Ok(())
    }
}
