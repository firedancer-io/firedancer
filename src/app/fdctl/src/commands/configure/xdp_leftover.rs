use std::fs;

use super::*;
use crate::Config;

pub(super) const STAGE: Stage = Stage {
    name: "xdp_leftover",
    enabled: None,
    always_recreate: false,
    explain_init_permissions: None,
    explain_fini_permissions: None,
    init: None,
    fini: None,
    check,
};

fn check(config: &Config) -> CheckResult {
    for entry in fs::read_dir("/sys/fs/bpf/").unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_str().unwrap() != config.name {
            return partially_configured!("unknown bpf entry {entry:?}");
        }
    }

    CheckResult::Ok(())
}
