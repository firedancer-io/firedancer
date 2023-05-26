use super::*;
use crate::security::check_root;
use crate::utility::*;
use crate::Config;

const NAME: &'static str = "netns";

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: Some(enabled),
    always_recreate: false,
    explain_init_permissions: Some(explain_init_permissions),
    explain_fini_permissions: Some(explain_fini_permissions),
    init: Some(step),
    fini: Some(undo),
    check: check,
};

fn enabled(config: &Config) -> bool {
    config.development.netns.enabled
}

fn explain_init_permissions(_: &Config) -> Vec<Option<String>> {
    vec![check_root(NAME, "create and enter network namespaces")]
}

fn explain_fini_permissions(_: &Config) -> Vec<Option<String>> {
    vec![check_root(NAME, "remove network namespaces")]
}

#[rustfmt::skip]
fn step(config: &mut Config) {
    let cfg = &config.development.netns;

    let interface0 = &cfg.interface0;
    let interface1 = &cfg.interface1;
    let tiles = config.layout.verify_tile_count;

    run!("ip netns add {interface0}");
    run!("ip netns add {interface1}");
    run!("ip link add dev {interface0} netns {interface0} type veth peer name {interface1} \
        netns {interface1} numrxqueues {tiles} numtxqueues {tiles}");
    run!("ip netns exec {interface0} ip link set dev {interface0} address {}", cfg.interface0_mac);
    run!("ip netns exec {interface1} ip link set dev {interface1} address {}", cfg.interface1_mac);
    run!("ip netns exec {interface0} ip address add {}/30 dev {interface0} scope link", &cfg.interface0_addr);
    run!("ip netns exec {interface1} ip address add {}/30 dev {interface1} scope link", &cfg.interface1_addr);
    run!("ip netns exec {interface0} ip link set dev {interface0} up");
    run!("ip netns exec {interface1} ip link set dev {interface1} up");

    // We need one channel for both TX and RX on the NIC for each QUIC tile, but the virtual interfaces
    // default to one channel total.
    run!("nsenter --net=/var/run/netns/{interface0} ethtool --set-channels {interface0} rx {tiles} tx {tiles}");
    run!("nsenter --net=/var/run/netns/{interface1} ethtool --set-channels {interface1} rx {tiles} tx {tiles}");

    // UDP segmentation is a kernel feature that batches multiple UDP packets into one in the kernel
    // before splitting them later when dispatching. This feature is broken with network namespaces
    // so we disable it. Otherwise, we would see very large packets that don't decrypt. Need on both
    // tx and rx sides.
    run!("nsenter --net=/var/run/netns/{interface0} ethtool -K {interface0} tx-udp-segmentation off");
    run!("nsenter --net=/var/run/netns/{interface1} ethtool -K {interface1} tx-udp-segmentation off");

    // Generic segmentation offload and TX GRE segmentation are similar things on the tx side that
    // also get messed up under netns in unknown ways.
    run!("nsenter --net=/var/run/netns/{interface0} ethtool -K {interface0} generic-segmentation-offload off");
    run!("nsenter --net=/var/run/netns/{interface1} ethtool -K {interface1} generic-segmentation-offload off");
    run!("nsenter --net=/var/run/netns/{interface0} ethtool -K {interface0} tx-gre-segmentation off");
    run!("nsenter --net=/var/run/netns/{interface1} ethtool -K {interface1} tx-gre-segmentation off");
}

fn undo(config: &Config) {
    let interface0 = &config.development.netns.interface0;
    let interface1 = &config.development.netns.interface1;

    // Destroys interface1 as well, no need to check failure
    run!(no_error, "ip link del dev {interface0}");
    let status1 = run!(status, "ip netns delete {interface0}").success();
    let status2 = run!(status, "ip netns delete {interface1}").success();

    // If neither of them was present, we wouldn't get to the undo step so make sure we were
    // able to delete whatever is there.
    assert!(status1 || status2);
}

fn check(config: &Config) -> CheckResult {
    let cfg = &config.development.netns;

    let namespaces: Vec<String> = run!("ip netns list")
        .trim()
        .lines()
        .map(str::to_owned)
        .collect();
    match (
        namespaces.contains(&cfg.interface0),
        namespaces.contains(&cfg.interface1),
    ) {
        (false, false) => not_configured!("no network namespaces"),
        (true, false) | (false, true) => partially_configured!("no network namespace"),
        (true, true) => {
            // TODO: Use `ip netns exec .. ip link show` to verify the configuration is correct
            // TODO: Check the ethtool stuff is correct as well
            CheckResult::Ok(())
        }
    }
}
