use super::*;
use crate::Config;

use std::fs;
use std::process::Command;

pub struct LargePages;

impl Step for LargePages {
    fn name(&self) -> &'static str {
        "large_pages"
    }

    fn supports_do(&self) -> bool {
        true
    }

    fn supports_undo(&self) -> bool {
        false
    }

    fn step(&mut self, config: &mut Config) {
        for (size, _, expected_pages) in [
            ("huge", 2048, config.shmem.huge_pages),
            ("gigantic", 1048576, config.shmem.gigantic_pages),
        ] {
            let fd_shmem_cfg = format!("{}/fd_shmem_cfg", config.binary_dir.display());
            let status = Command::new(fd_shmem_cfg)
                .args(["alloc", &expected_pages.to_string(), &size.to_string(), "0"])
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    fn undo(&mut self, _: &Config) {
        // No cleanup to do, this configuration can just stay here
    }

    fn check(&mut self, config: &Config) -> CheckResult {
        for (size, page_size, expected_pages) in [
            ("huge", 2048, config.shmem.huge_pages),
            ("gigantic", 1048576, config.shmem.gigantic_pages),
        ] {
            let page_path =
                format!("/sys/devices/system/node/node0/hugepages/hugepages-{page_size}kB");

            let number_pages = fs::read_to_string(format!("{page_path}/nr_hugepages"))
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap();

            if number_pages != expected_pages {
                return CheckResult::Err(CheckError::NotConfigured(format!(
                    "Expected to find {expected_pages} {size} pages, but there are {number_pages}"
                )));
            }
        }

        CheckResult::Ok(())
    }
}
