use std::fs;

use super::*;
use crate::security::*;
use crate::utility::*;
use crate::Config;

const NAME: &str = "large_pages";

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: None,
    always_recreate: false,
    explain_init_permissions: Some(explain_init_permissions),
    explain_fini_permissions: None,
    init: Some(step),
    fini: None,
    check,
};

fn explain_init_permissions(_: &Config) -> Vec<Option<String>> {
    vec![check_root(
        NAME,
        "write to a system control file `/proc/sys/vm/nr_hugepages`",
    )]
}

fn step(config: &mut Config) {
    let bin = &config.binary_dir;

    for (size, _, expected_pages) in [
        ("huge", 2048, config.shmem.min_kernel_huge_pages),
        ("gigantic", 1048576, config.shmem.min_kernel_gigantic_pages),
    ] {
        run!("{bin}/fd_shmem_cfg alloc {expected_pages} {size} 0");
    }
}

fn check(config: &Config) -> CheckResult {
    for (size, page_size, expected_pages) in [
        ("huge", 2048, config.shmem.min_kernel_huge_pages),
        ("gigantic", 1048576, config.shmem.min_kernel_gigantic_pages),
    ] {
        let page_path = format!("/sys/devices/system/node/node0/hugepages/hugepages-{page_size}kB");

        let number_pages = fs::read_to_string(format!("{page_path}/nr_hugepages"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();

        if number_pages < expected_pages {
            return not_configured!(
                "expected at least {expected_pages} {size} pages, but there are {number_pages}"
            );
        }
    }

    CheckResult::Ok(())
}
