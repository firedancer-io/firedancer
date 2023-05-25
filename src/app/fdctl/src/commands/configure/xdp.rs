use std::path::Path;

use super::*;
use crate::security::*;
use crate::utility::*;
use crate::Config;

const NAME: &str = "xdp";

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: None,
    always_recreate: false,
    explain_init_permissions: Some(explain_init_permissions),
    explain_fini_permissions: None,
    init: Some(step),
    fini: Some(undo),
    check,
};

#[rustfmt::skip]
fn explain_init_permissions(config: &Config) -> Vec<Option<String>> {
    let fd_xdp_ctl = format!("{}/fd_xdp_ctl", config.binary_dir);

    vec![
        check_file_cap(NAME, &fd_xdp_ctl, CAP_SYS_ADMIN, "create a BPF map with `bpf_map_create`"),
    ]
}

fn step(config: &mut Config) {
    run!(
        "{bin}/fd_xdp_ctl init {name} 0750 {user} {user}",
        bin = config.binary_dir,
        name = config.name,
        user = config.user
    );
}

fn undo(config: &Config) {
    run!(
        "{bin}/fd_xdp_ctl fini {name}",
        bin = config.binary_dir,
        name = config.name
    );
}

fn check(config: &Config) -> CheckResult {
    let xdp_path = format!("/sys/fs/bpf/{}", config.name);
    match Path::new(&xdp_path).try_exists() {
        Ok(true) => (),
        Ok(false) => return not_configured!("{xdp_path} does not exist"),
        result => return partially_configured!("error reading path {xdp_path} {result:?}"),
    }

    check_directory("/sys/fs/bpf", config.uid, config.uid, 0o40750)?;
    check_directory(&xdp_path, config.uid, config.uid, 0o40750)?;
    check_file(
        &format!("/sys/fs/bpf/{}/udp_dsts", config.name),
        config.uid,
        config.uid,
        0o100640,
    )?;

    // TODO verify_file_pinned check this is actually a bpf pin and load the map ...
    // TODO verify pinned program is the same as we would load

    CheckResult::Ok(())
}
