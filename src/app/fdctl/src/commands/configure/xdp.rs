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

    if config.development.netns.enabled {
        vec![
            check_process_cap(NAME, CAP_SYS_ADMIN, "enter a network namespace"),
            check_file_cap(NAME, &fd_xdp_ctl, CAP_SYS_ADMIN, "create a BPF map with `bpf_map_create`"),
        ]
    } else {
        vec![
            check_file_cap(NAME, &fd_xdp_ctl, CAP_SYS_ADMIN, "create a BPF map with `bpf_map_create`"),
            check_file_cap(NAME, &fd_xdp_ctl, CAP_NET_ADMIN, "create an XSK map with `bpf_map_create`"),
        ]
    }
}

#[rustfmt::skip]
fn step(config: &mut Config) {
    let bin = &config.binary_dir;
    let name = &config.name;
    let interface = &config.tiles.quic.interface;
    let address = super::netns::listen_address(config);

    let nsenter = if config.development.netns.enabled {
        format!("nsenter --net=/var/run/netns/{interface}")
    } else {
        "".to_string()
    };

    run!("{nsenter} {bin}/fd_xdp_ctl init {name} 0750 {user} {user}", user = config.user);
    run!("{nsenter} {bin}/fd_xdp_ctl hook-iface {name} {interface} {}", config.tiles.quic.xdp_mode);
    run!("{nsenter} {bin}/fd_xdp_ctl listen-udp-port {name} {address} {} tpu-quic", config.tiles.quic.listen_port);
}

fn undo(config: &Config) {
    let bin = &config.binary_dir;
    let name = &config.name;
    let interface = &config.tiles.quic.interface;

    run!("{bin}/fd_xdp_ctl fini {name}");

    // Work around race condition, ugly hack. Kernel might remove some hooks in the background.
    std::thread::sleep(std::time::Duration::from_millis(1_000));

    remove_directory_not_found_ok(format!("/sys/fs/bpf/{name}/{interface}")).unwrap();
    remove_directory_not_found_ok(format!("/sys/fs/bpf/{name}")).unwrap();
}

#[rustfmt::skip]
fn check(config: &Config) -> CheckResult {
    let xdp_path = format!("/sys/fs/bpf/{}", config.name);
    match Path::new(&xdp_path).try_exists() {
        Ok(true) => (),
        Ok(false) => return not_configured!("{xdp_path} does not exist"),
        result => return partially_configured!("error reading path {xdp_path} {result:?}"),
    }

    check_directory("/sys/fs/bpf", config.uid, config.uid, 0o40750)?;
    check_directory(&xdp_path, config.uid, config.uid, 0o40750)?;

    let udp_dsts = format!("/sys/fs/bpf/{}/udp_dsts", config.name);
    check_file(&udp_dsts, config.uid, config.uid, 0o100640)?;

    let link = format!("/sys/fs/bpf/{}/{}/xdp_link", config.name, config.tiles.quic.interface);
    check_file(&link, config.uid, config.uid, 0o100640)?;

    let link = format!("/sys/fs/bpf/{}/{}/xdp_prog", config.name, config.tiles.quic.interface);
    check_file(&link, config.uid, config.uid, 0o100640)?;

    let link = format!("/sys/fs/bpf/{}/{}/xsks", config.name, config.tiles.quic.interface);
    check_file(&link, config.uid, config.uid, 0o100640)?;

    // TODO: Step into these links and make sure the interior data is correct.

    CheckResult::Ok(())
}
