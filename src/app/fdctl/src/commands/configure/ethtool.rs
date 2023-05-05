use super::*;
use crate::security::*;
use crate::utility::*;
use crate::Config;

const NAME: &'static str = "ethtool";

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: Some(enabled),
    always_recreate: false,
    explain_init_permissions: Some(explain_init_permissions),
    explain_fini_permissions: None,
    init: Some(step),
    fini: None,
    check: check,
};

fn enabled(config: &Config) -> bool {
    // If we're running in a network namespace, we configure ethtool on the virtual device as
    // part of netns setup, not here.
    !config.development.netns.enabled
}

fn explain_init_permissions(_: &Config) -> Vec<Option<String>> {
    vec![check_root(
        NAME,
        "increase network device channels with `ethtool --set-channels`",
    )]
}

fn step(config: &mut Config) {
    // We need one channel for both TX and RX on the NIC for each QUIC tile, but the interface probably
    // defaults to one channel total.
    let interface = &config.tiles.quic.interface;
    let verify_tile_count = config.layout.verify_tile_count;
    run!("ethtool --set-channels {interface} combined {verify_tile_count}");
}

fn check(config: &Config) -> CheckResult {
    let interface = &config.tiles.quic.interface;
    let quic_tile_count = config.layout.verify_tile_count;
    let output = run!("ethtool --show-channels {interface}");

    if let Some(position) = output.find("Current hardware settings:") {
        if let Some(line) = output[position..]
            .lines()
            .find(|line| line.starts_with("Combined:"))
        {
            let count: u32 = line[9..].trim().parse().unwrap();
            if count != quic_tile_count {
                // We need exactly one channel per QUIC tile, otherwise the driver will forward
                // packets to channels that we are not reading from.
                return not_configured!(
                    "{count} not the right number of channels, expected {quic_tile_count}"
                );
            } else {
                return Ok(());
            }
        }
    }

    return not_configured!("couldn't parse combined channels from device in ethtool");
}
