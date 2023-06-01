use std::fs;

use super::*;
use crate::Config;

pub(super) const STAGE: Stage = Stage {
    name: "xdp-leftover",
    enabled: None,
    always_recreate: false,
    explain_init_permissions: None,
    explain_fini_permissions: None,
    init: None,
    fini: None,
    check,
};

fn check(config: &Config) -> CheckResult {
    let read_dir = match fs::read_dir("/sys/fs/bpf/") {
        Ok(read_dir) => read_dir,
        result => return partially_configured!("error reading path /sys/fs/bpf/ {result:?}"),
    };

    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            result => return partially_configured!("error reading directory {result:?}"),
        };

        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(name) => name,
            None => {
                return partially_configured!("invalid bpf entry name in /sys/fs/bpf/ {entry:?}")
            }
        };

        if name != config.name {
            return partially_configured!("unknown bpf entry {entry:?}");
        }
    }

    CheckResult::Ok(())
}
