use super::*;
use crate::Config;

use std::path::Path;
use std::process::Command;

pub struct Shmem;

impl Step for Shmem {
    fn name(&self) -> &'static str {
        "shmem"
    }

    fn step(&mut self, config: &mut Config) {
        let fd_shmem_cfg = format!("{}/fd_shmem_cfg", config.binary_dir.display());
        let output = Command::new(fd_shmem_cfg)
            .args(["init", "700", &config.user, ""])
            .output()
            .unwrap();
        if !output.status.success() {
            panic!("{}", String::from_utf8(output.stderr).unwrap());
        }
    }

    fn undo(&mut self, config: &Config) {
        let fd_shmem_cfg = format!("{}/fd_shmem_cfg", config.binary_dir.display());
        let output = Command::new(fd_shmem_cfg).args(["fini"]).output().unwrap();
        if !output.status.success() {
            panic!("{}", String::from_utf8(output.stderr).unwrap());
        }
    }

    fn check(&mut self, config: &Config) -> CheckResult {
        if !Path::new(&config.shmem.path).is_dir() {
            return CheckResult::Err(CheckError::NotConfigured(format!(
                "{} does not exist",
                &config.shmem.path
            )));
        }

        check_directory(&config.shmem.path, config.uid, config.gid, 0o40700)?;

        for size in ["gigantic", "huge", "normal"] {
            check_directory(
                &format!("{}/.{size}", &config.shmem.path),
                config.uid,
                config.gid,
                0o40700,
            )?;
        }

        return CheckResult::Ok(());
    }
}
