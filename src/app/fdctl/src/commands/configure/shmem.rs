use super::*;
use crate::security::*;
use crate::utility::*;
use crate::Config;

use std::path::Path;

const NAME: &'static str = "shmem";

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: None,
    always_recreate: false,
    explain_init_permissions: Some(explain_init_permissions),
    explain_fini_permissions: Some(explain_fini_permissions),
    init: Some(step),
    fini: Some(undo),
    check: check,
};

fn explain_init_permissions(_: &Config) -> Vec<Option<String>> {
    vec![check_root(
        NAME,
        "create directories in `/mnt`, mount hugetlbfs filesystems",
    )]
}

fn explain_fini_permissions(_: &Config) -> Vec<Option<String>> {
    vec![check_root(
        NAME,
        "remove directories from `/mnt`, unmount filesystems",
    )]
}

fn try_defragment_memory() {
    std::fs::write("/proc/sys/vm/compact_memory", "1").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(250));
}

fn step(config: &mut Config) {
    try_defragment_memory();

    let proc_meminfo = std::fs::read_to_string("/proc/meminfo").unwrap();
    #[rustfmt::skip]
    let mem_total: u64 = proc_meminfo
        .trim().lines().find(|x| x.starts_with("MemTotal")).unwrap()
        .split_whitespace().nth(1).unwrap()
        .parse::<u64>().unwrap()
        << 10;
    for (mount_path, page_size) in [
        (&config.shmem.gigantic_page_mount_path, 1073741824),
        (&config.shmem.huge_page_mount_path, 2097152),
    ] {
        std::fs::create_dir_all(mount_path).unwrap();
        let mount_size = page_size * (mem_total / page_size);
        run!("mount -v -t hugetlbfs -o pagesize={page_size},size={mount_size} none {mount_path}");
        repermission(mount_path, config.uid, config.uid, 0o700);
        try_defragment_memory();
    }
}

fn undo(config: &Config) {
    try_defragment_memory();
    for mount_path in [
        &config.shmem.gigantic_page_mount_path,
        &config.shmem.huge_page_mount_path,
    ] {
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap();
        let is_mounted = mounts
            .trim()
            .lines()
            .find(|x| x.contains(mount_path))
            .is_some();
        if is_mounted {
            run!("umount -v {mount_path}");
        }

        remove_directory_not_found_ok(mount_path).unwrap();
    }
    try_defragment_memory();
}

fn check(config: &Config) -> CheckResult {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap();

    let huge = &config.shmem.huge_page_mount_path;
    let huge_exists = Path::new(huge)
        .try_exists()
        .map_err(|x| CheckError::PartiallyConfigured(format!("error reading {huge} {x:?}")))?;
    let gigantic = &config.shmem.gigantic_page_mount_path;
    let gigantic_exists = Path::new(gigantic)
        .try_exists()
        .map_err(|x| CheckError::PartiallyConfigured(format!("error reading {gigantic} {x:?}")))?;

    match (huge_exists, gigantic_exists) {
        (false, false) => return not_configured!("mounts {huge} and {gigantic} do not exist"),
        (true, false) | (false, true) => {
            return partially_configured!("only one of {huge} and {gigantic} exists")
        }
        (true, true) => (),
    };

    for (path, size) in [(huge, "2M"), (gigantic, "1024M")] {
        check_directory(path, config.uid, config.gid, 0o40700)?;

        let mount_line = mounts.trim().lines().find(|x| x.contains(path));
        match mount_line {
            None => return partially_configured!("{path} is not a hugetlbfs mount"),
            Some(mount_line) => {
                let parts: Vec<&str> = mount_line.trim().split_whitespace().collect();
                // parts is (device, mount_point, fs_type, options, _dump, _fsck_order)
                if parts[0] != "none" {
                    return partially_configured!(
                        "{path} mount is on unrecognized device, expected `none`"
                    );
                }
                assert_eq!(parts[1], path);
                if parts[2] != "hugetlbfs" {
                    return partially_configured!(
                        "{path} mount has unrecognized filesystem type, expected `hugetlbfs`"
                    );
                }
                if !parts[3].contains(&format!("pagesize={size}")) {
                    return partially_configured!(
                        "{path} mount has unrecognized pagesize expected `pagesize={size}`"
                    );
                }
                if !parts[3].contains("rw") {
                    return partially_configured!(
                        "{path} mount is not mounted read/write, expected `rw`"
                    );
                }
            }
        }
    }

    return CheckResult::Ok(());
}
