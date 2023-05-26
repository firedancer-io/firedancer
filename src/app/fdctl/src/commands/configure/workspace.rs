use crate::utility::*;

use super::*;

use std::path::Path;

pub(super) const STAGE: Stage = Stage {
    name: "workspace",
    enabled: None,
    // We can't really verify if a frank workspace is valid to be reused, so it just gets blown
    // away and recreated every time.
    always_recreate: true,
    explain_init_permissions: None,
    explain_fini_permissions: None,
    init: Some(step),
    fini: Some(undo),
    check: check,
};

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
