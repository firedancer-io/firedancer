# Networking (XDP)

## `xdp` network provider

Firedancer's default network provider is XDP, which is an advanced Linux
kernel API for fast networking.

### Recommendations

Firedancer XDP works best with the following system configuration:
- small, simple route table (ideally default gateway-only)
- small local network (~dozen neighbors at most)
- no other traffic-heavy applications running

### Native XDP

XDP is implemented twice in the Linux kernel:
- `skb`: a slow but stable generic code path (Firedancer default)
- `drv`: driver-specific code by the hardware vendor

The `drv` mode is recommended for optimal performance (several times
faster than `skb` mode):

```toml
[layout]
    net_tile_count = 2  # number of NIC interfaces in the bond
[net]
    provider = "xdp"
[net.xdp]
    xdp_mode = "drv"
    xdp_zero_copy = true
    native_bond = true
```

Recommendations when using XDP driver mode:
- always do a test run for each new combination of hardware module and
  kernel version
- bad kernel/hardware combinations may result in packet loss or
  host-wide network outages
- use recent kernel releases for best results (less than ~12 months old,
  avoid long-term support branches)
- driver mode reduces memory isolation by giving Firedancer direct
  access to hardware network buffers; this exposes Firedancer to
  unrelated traffic arriving at the system

### DoubleZero support

Firedancer XDP supports network configuration commonly installed by
DoubleZero, a custom third-party fiber network.

Specifically:
- support for a large number of `/32` routes (`tiles.netlink.max_peer_routes`)
- automatic detection of route table updates without requiring restarts
- support for up to one GRE tunnel

DoubleZero is automatically supported. No changes to the config file are
required. It is not necessary to restart Firedancer when enabling or
disabling `doublezerod`. This is because the above are all standard
Linux iproute2 features – no DoubleZero-specific code exists in
Firedancer.

### Packet capture

`tcpdump` is not able to capture traffic arriving at XDP sockets.

The recommended way to capture Firedancer traffic is using the
`firedancer dump` subcommand.

### Internals

Further documentation on network stack internals:
- [net tile internals](./internals/net_tile.md)
- [netlnk tile internals](./internals/netlink.md)

## `socket` network provider

The socket network provider is a fallback for environments without XDP.
It can be enabled as follows:

```toml
[net]
    provider = "socket"
```
