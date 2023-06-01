use std::path::Path;

use libc::RLIMIT_MEMLOCK;

use super::*;
use crate::security::*;
use crate::utility::*;

const NAME: &str = "workspace";

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: None,
    // We can't really verify if a frank workspace is valid to be reused, so it just gets blown
    // away and recreated every time.
    always_recreate: true,
    explain_init_permissions: Some(explain_init_permissions),
    explain_fini_permissions: None,
    init: Some(step),
    fini: Some(undo),
    check,
};

fn explain_init_permissions(config: &Config) -> Vec<Option<String>> {
    let path = format!("{}/fd_wksp_ctl", config.binary_dir);

    // We need to be able to `mlock` the entire workspace
    let mlock_limit = config.shmem.workspace_size();
    vec![check_resource(
        NAME,
        &path,
        RLIMIT_MEMLOCK,
        mlock_limit,
        "increase `RLIMIT_MEMLOCK` to lock the workspace in memory",
    )]
}

fn step(config: &mut Config) {
    let prefix = if uid() == 0 {
        format!("runuser -u {user} -- ", user = config.user)
    } else {
        "".to_string()
    };

    run!(
        "{prefix} {bin}/fd_wksp_ctl new {name}.wksp {page_count} {page_size} {affinity} 0600",
        bin = config.binary_dir,
        name = config.name,
        page_count = config.shmem.workspace_page_count,
        page_size = config.shmem.workspace_page_size,
        affinity = config.layout.affinity
    );
}

fn undo(config: &Config) {
    let bin = &config.binary_dir;
    run!("{bin}/fd_wksp_ctl delete {}.wksp", &config.name);
}

fn check(config: &Config) -> CheckResult {
    let mount_path = if config.shmem.workspace_page_size == "gigantic" {
        &config.shmem.gigantic_page_mount_path
    } else {
        &config.shmem.huge_page_mount_path
    };

    let path = format!("{}/{}.wksp", mount_path, &config.name);
    match Path::new(&path).try_exists() {
        Ok(true) => partially_configured!("file {path} exists"),
        Ok(false) => not_configured!("no workspace file in {mount_path}"),
        result => partially_configured!("error reading {path} {result:?}"),
    }
}
