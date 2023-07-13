use std::ffi::CString;
use std::{
    mem,
    ptr,
};

use libc::*;

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

#[repr(C)]
#[derive(Debug)]
pub struct ethtool_channels {
    cmd: u32,
    max_rx: u32,
    max_tx: u32,
    max_other: u32,
    max_combined: u32,
    rx_count: u32,
    tx_count: u32,
    other_count: u32,
    combined_count: u32,
}

const ETHTOOL_GCHANNELS: u32 = 0x0000003c;

fn check1(device: &str, expected_channel_count: u32) -> CheckResult {
    let (supports_channels, count) = unsafe {
        let socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        assert!(socket >= 0);

        let mut channels: ethtool_channels = mem::zeroed();
        channels.cmd = ETHTOOL_GCHANNELS;

        let mut ifr: ifreq = mem::zeroed();

        let device_name = CString::new(device).unwrap();
        let device_bytes = device_name.as_bytes_with_nul();

        ptr::copy(
            device_bytes.as_ptr() as *const c_char,
            ifr.ifr_name.as_mut_ptr(),
            device_bytes.len(),
        );

        ifr.ifr_ifru.ifru_data = &mut channels as *mut _ as *mut libc::c_char;

        if 0 != ioctl(socket, SIOCETHTOOL, &mut ifr as *mut _) {
            if *libc::__errno_location() == libc::EOPNOTSUPP {
                assert_eq!(0, close(socket));

                // Netowrk device doesn't support setting number of channels,
                // so it must always be 1.
                (false, 1)
            } else {
                panic!(
                    "Couldn't get number of supported device channels: {}",
                    std::io::Error::last_os_error()
                );
            }
        } else {
            assert_eq!(0, close(socket));
            (true, channels.combined_count)
        }
    };

    if count != expected_channel_count {
        // We need exactly one channel per QUIC tile, otherwise the driver will forward
        // packets to channels that we are not reading from.
        if !supports_channels {
            panic!(
                "Network device `{device}` does not support setting number of channels, but you \
                 are running with more than one QUIC tile (expected {expected_channel_count}), \
                 and there must be one channel per tile. You can either use a NIC that supports \
                 multiple channels, or run Firedancer with only one QUIC tile. You can configure \
                 Firedancer to run with only one QUIC tile by setting `layout.verify_tile_count` \
                 to 1 in your configuration file. It is not recommended to do this in production \
                 as it will limit network performance."
            );
        } else {
            not_configured!(
                "device {device} does not have right number of channels, got {count}, expected \
                 {expected_channel_count}"
            )
        }
    } else {
        Ok(())
    }
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
