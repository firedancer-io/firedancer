use super::*;
use crate::security::*;
use crate::utility::*;
use crate::Config;

const NAME: &str = "ethtool";

pub(super) const STAGE: Stage = Stage {
    name: NAME,
    enabled: Some(enabled),
    always_recreate: false,
    explain_init_permissions: Some(explain_init_permissions),
    explain_fini_permissions: None,
    init: Some(step),
    fini: None,
    check,
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
    // We need one channel for both TX and RX on the NIC for each QUIC tile, but the interface
    // probably defaults to one channel total.
    let interface = &config.tiles.quic.interface;
    let verify_tile_count = config.layout.verify_tile_count;

    let type_ = run!("nmcli -m tabular -t -f GENERAL.TYPE device show {interface}");
    match type_.as_ref() {
        "bond" => {
            // If using a bonded device, we need to set channels on the underlying devices.
            let output = run!("nmcli -m tabular -t -f BOND.SLAVES device show {interface}");
            for device in output.split_whitespace() {
                run!("ethtool --set-channels {device} combined {verify_tile_count}");
            }
        }
        _ => {
            run!("ethtool --set-channels {interface} combined {verify_tile_count}");
        }
    };
}

fn check1(device: &str, expected_channel_count: u32) -> CheckResult {
    let output = run!("ethtool --show-channels {device}");
    if let Some(position) = output.find("Current hardware settings:") {
        if let Some(line) = output[position..]
            .lines()
            .find(|line| line.starts_with("Combined:"))
        {
            let count: u32 = line[9..].trim().parse().unwrap();
            if count != expected_channel_count {
                // We need exactly one channel per QUIC tile, otherwise the driver will forward
                // packets to channels that we are not reading from.
                return not_configured!(
                    "device {device} does not have right number of channels, got {count}, \
                     expected {expected_channel_count}"
                );
            } else {
                return Ok(());
            }
        }
    }

    not_configured!("couldn't parse combined channels from device in ethtool")
}

fn check(config: &Config) -> CheckResult {
    let interface = &config.tiles.quic.interface;
    let quic_tile_count = config.layout.verify_tile_count;

    let type_ = run!("nmcli -m tabular -t -f GENERAL.TYPE device show {interface}");
    match type_.as_ref() {
        "bond" => {
            let output = run!("nmcli -m tabular -t -f BOND.SLAVES device show {interface}");
            for device in output.split_whitespace() {
                check1(device, quic_tile_count)?;
            }
        }
        _ => check1(interface, quic_tile_count)?,
    }

    CheckResult::Ok(())
}
