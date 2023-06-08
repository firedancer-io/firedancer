use std::fs;

use super::*;
use crate::security::*;
use crate::Config;

const NAME: &str = "workspace-leftover";

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: None,
    always_recreate: false,
    explain_init_permissions: None,
    explain_fini_permissions: Some(explain_fini_permissions),
    init: None,
    fini: Some(fini),
    check,
};

fn explain_fini_permissions(_: &Config) -> Vec<Option<String>> {
    vec![check_root(
        NAME,
        "check all open file descriptors in `/proc/`",
    )]
}

fn fini(config: &Config) {
    for pid in fs::read_dir("/proc").unwrap() {
        let file_name = pid.unwrap().file_name();
        let pid: u64 = match file_name.to_str().unwrap().parse::<u64>() {
            Ok(x) => x,
            _ => continue,
        };

        let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();

        for line in maps.trim().lines() {
            if line.contains(&config.shmem.gigantic_page_mount_path)
                || line.contains(&config.shmem.huge_page_mount_path)
            {
                let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid)).unwrap();
                error!("process {pid}:{cmdline} has a workspace file descriptor open");
                break;
            }
        }

        let numa_maps = fs::read_to_string(format!("/proc/{}/numa_maps", pid)).unwrap();

        for line in numa_maps.trim().lines() {
            if line.contains("huge") && line.contains("anon") {
                let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
                    .unwrap()
                    .replace('\0', " ");
                error!("process {pid}:{cmdline} has anonymous hugepages leftover");
                break;
            }
        }
    }

    panic!("Not enough free hugepages to proceed, see error log for processes using them");
}

fn check(config: &Config) -> CheckResult {
    let size = &config.shmem.workspace_page_size;
    let page_size = match size.as_ref() {
        "huge" => 2048,
        "gigantic" => 1048576,
        _ => panic!("invalid page size"),
    };

    let page_path = format!("/sys/devices/system/node/node0/hugepages/hugepages-{page_size}kB");
    let free_pages = fs::read_to_string(format!("{page_path}/free_hugepages"))
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();

    let expected_pages = config.shmem.workspace_page_count;
    if free_pages < expected_pages {
        return partially_configured!(
            "expected at least {expected_pages} free {size} pages, but there are {free_pages}, run `fini` to see which processes are using them"
        );
    }

    CheckResult::Ok(())
}
