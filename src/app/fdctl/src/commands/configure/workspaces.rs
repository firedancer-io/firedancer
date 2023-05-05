use super::*;
use crate::Config;

use std::fs;
use std::io::ErrorKind;

pub struct Workspaces;

impl Step for Workspaces {
    fn name(&self) -> &'static str {
        "workspaces"
    }

    fn supports_do(&self) -> bool {
        false
    }

    fn step(&mut self, _: &mut Config) {}

    fn undo(&mut self, config: &Config) {
        for size in ["huge", "gigantic"] {
            for entry in match fs::read_dir(format!("{}/.{size}", &config.shmem.path)) {
                Ok(entries) => entries,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                err => err.unwrap(),
            } {
                fs::remove_file(entry.unwrap().path()).unwrap();
            }
        }
    }

    fn check(&mut self, config: &Config) -> CheckResult {
        for (size, page_size, expected_pages) in [
            ("huge", 2048, config.shmem.kernel_huge_pages),
            ("gigantic", 1048576, config.shmem.kernel_gigantic_pages),
        ] {
            let page_path =
                format!("/sys/devices/system/node/node0/hugepages/hugepages-{page_size}kB");

            let free_pages = fs::read_to_string(format!("{page_path}/free_hugepages"))
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap();

            if free_pages != expected_pages {
                return CheckResult::Err(CheckError::PartiallyConfigured(format!("Some pages are are already in use, only {free_pages} of {expected_pages} {size} pages are free")));
            }
        }

        CheckResult::Ok(())
    }
}
