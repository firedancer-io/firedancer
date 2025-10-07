# Net Tile

Net tiles provide fast networking to a Firedancer system.

At a high level, a net tile acts as a translation layer between the
Internet (IPv4) and the Firedancer messaging subsystem ("tango").

Currently, all versions of Firedancer use the Linux AF_XDP APIs, which
bypass most of the Linux network stack.  AF_XDP bypasses large parts of
the kernel's routing code, avoids expensive context switches, and most
notably offloads (most) data copies to network hardware (often called
"zero copy" I/O).

A net tile never sleeps (busy polling).  It consists of a simple event
loop that passes incoming packets down to app tiles, and routes outgoing
packets to the right network interface.  Internally, it wakes up the
kernel ~20k times a second to do batches of RX and TX.

### Terminology

- NIC: "Network interface"
- XDP: "eXpress Data Path", a family of Linux APIs
- AF_XDP: XDP sockets family
- XSK: "XDP socket" (singular)
- rtnetlink: A Linux API to query various networking information
- netlink: In this context, refers to rtnetlink
- ethtool: A Linux API to configure Ethernet devices
- RX: "Receive" (Packets from outside entering a Firedancer host)
- TX: "Transmit" (Packets sent by a Firedancer app tile)
- UMEM: Buffer space for packets
- UMEM frame: A single buffer that can fit one packet

## XDP modes

The terms `skb` and `drv` are used throughout the codebase and
documentation.  Simply put, `drv` is the fast mode that is not available
everywhere.  `skb` is the slow fallback that is always supported.

The term `skb` comes from [`struct sk_buff`](https://docs.kernel.org/networking/skbuff.html),
a major part of the Linux network stack.

The term `drv` refers to XDP support being implemented in a network
device driver before `struct sk_buff` would be allocated.  `drv` mode
is considered less stable than `skb`.  This is because each device
driver contains a fair amount of XDP implementation boilerplate that
changes rather frequently (due to new XDP features being added to the
kernel and support for new devices being added to drivers).

::: tip HISTORY

The performance target for XDP RX is ~20 million packets per second.

A proof-of-concept net tile rewrite achieved this number on an Ivy
Bridge CPU and an Intel XL710 that was flooded with externally generated
packets.  The kernel configuration was a recent Linux version with i40e
running in XDP drv mode, preferred busy polling, and zero copy I/O.

The net tile achieves far less currently but is being optimized
incrementally.

:::

## XDP Lifecycle

::: info REFERENCE

The XDP API is explained in detail in [`src/waltz/xdp/fd_xsk.h`](https://raw.githubusercontent.com/firedancer-io/firedancer/refs/heads/main/src/waltz/xdp/fd_xsk.h):

https://github.com/firedancer-io/firedancer/blob/main/src/waltz/xdp/fd_xsk.h

:::


### Persistent config

Running `fdctl configure init all` does various NIC configuration.
This configuration persists across Firedancer restarts but gets wiped
after a reboot.

Linux has some undocumented problems with ethtool offloads like GRO and
UDP segmentation.  Those speed up regular sockets I/O, so are often
enabled by default, but cause packet corruption in XDP sockets.

The NIC is configured to steer all Firedancer traffic to a single queue
per net tile.  This is because one XDP socket is required per NIC
channel.  Multiple XDP sockets per net tile does not scale well.

In the future, the net tile may also reconfigure /sys/class/net params
such as `gro_flush_timeout` and `napi_defer_hard_irqs`.  Those change
the scheduling of kernel networking code.

### Ephemeral config

Running `fdctl run` sets up the following ephemeral kernel config.
This part of the setup is scoped to the lifetime of the Firedancer net
tile processes:

- Installs an XDP program
- Deploys various supporting eBPF maps
- Creates AF_XDP sockets and XDP metadata rings
- Binds UMEM regions to AF_XDP sockets
- Creates an rtnetlink socket to monitor for config changes

When a Firedancer instance exits gracefully or gets killed, the kernel
will undo this config:

- Removes the XDP program
- Releases the UMEM region (instead using kernel-allocated packet
  buffers)
- Destroys the rtnetlink socket
- Destroys the XDP socket
- Destroys the eBPF maps

## Topology

### TX Links

The net tile is mostly agnostic to the TX topology.  It only expects
tango standard practices:

- The metadata ring is an mcache
- "mcache publish marks data freed" pattern (assumes TSO memory model)
- The data region is a dcache
- Chunk addressing with base in

The net tile exports flow control information (fseq, fctl) allowing app
tiles to be configured for backpressuring TX, although this is not
recommended.

### RX Links

RX links are inherently unreliable (don't backpressure).  Each app tile
*should* be able to sift through packets at line rate.

The RX topology is created by the `fd_net_tile_topo` API.

For each combination of (net tile, app tile kind) there is one RX mcache.

Multiple app tiles of the same kind will each read from the same RX
mcache but "take turns" picking out packets based on a load balancing
policy.

So, if there are 2 net tiles, 3 quic tiles, and 1 shred tile, the
following RX links exist.

- `net:0` → `quic`
- `net:0` → `shred`
- `net:1` → `quic`
- `net:1` → `shred`

There is one UMEM dcache object per net tile.  All RX mcaches of each
net tile share that same dcache.

- `net:0` → `UMEM:0`
- `net:1` → `UMEM:1`

### UMEM region

A "UMEM" region is the term for XDP packet buffers that appears in the
XDP documentation.  In Firedancer, a UMEM is a 4K aligned memory region
subdivided into 2048 byte frames.  Each frame can carry one Ethernet
packet.  In recent Linux versions UMEMs have become more flexible, but
Firedancer does not use those advanced features.

Each net tile manages a UMEM region allocated via a dcache object.
This UMEM region is bound to one or more XDP sockets.

The UMEM region is used for both RX and TX.  Each frame is statically
assigned for either purpose on startup.

What makes the UMEM region special is that it is shared throughout the
system.  It is accessible to:
- Firedancer app tiles (read-only)
- Firedancer net tiles (read-write)
- The Linux kernel (read-write)
- PCIe network devices (read-write via IOMMU)

With the right XDP flags (`XDP_FLAGS_DRV_MODE` and `XDP_ZEROCOPY`),
this allows for "zero copy I/O".

Wherein PCIe network devices can copy incoming Ethernet packets all the
way to application tiles without software copies along the way and
without compromising on security.

Under the hood, the PCIe device initiates writes to DRAM (DMA) and
signals to the device driver that a new packet arrived.  The driver then
passes a pointer to the packet through to the kernel's XDP code.  Which
in turn passes it to the net tile.  The net tile identifies the
recipient app tile for that packet, and passes along that pointer to
the corresponding mcache.

::: info NOTE BY RIPATEL

Firedancer did not initially have a zero copy RX path.  Yet, changing to
one required less than 500 lines of code to be changed at the net tile.

No changes to app tile code were required.  I've seen the same task take
major refactors in other code bases.

This is the subtle beauty of KB's Tango message queue design, shaped by
over a decade of high-performance networking.

:::

### Security Protections

As any other tile, the net tile and network-facing app tiles are heavily
sandboxed by using seccomp, user namespaces, and dropping capabilities.

UMEM regions and RX mcaches are mapped read-only to app tiles.  This
prevents a malicious app tile from corrupting unrelated traffic.
It does, however, allow any app tile to eavesdrop on any other incoming
packets (including packets that are not sent to Firedancer).

:::tip

Completely isolating control plane traffic from Firedancer requires the
use of separate physical network interfaces.

:::

The net tile read-only maps TX mcaches and dcaches containing outgoing
packets from app tiles.  Each app tile can only access its own TX link
but cannot see any other TX links.

The net tile speculatively copies TX packets but checks for overruns.

## RX Lifecycle

```
    ┌──────┐     ┌──────┐
    │ FILL ┼─────►  RX  │
    └─▲────┘     └────┬─┘
      │               │
      │  ┌────────┐   │
      │  │ MCACHE │   │
      ├──┼  QUIC  ◄───┤
      │  └────────┘   │
      │               │
      │  ┌────────┐   │
      │  │ MCACHE │   │
      └──┼ SHRED  ◄───┘
         └────────┘

Figure visualizing how ownership of RX buffers
transitions across ring buffers / FIFO queues.
```

The RX lifecycle of each incoming packet involves three steps.  The net
tile keeps track of the state of each buffer by storing a pointer to
each buffer in three corresponding rings.

1. FILL ring: Give free packet buffers to the kernel for the NIC to fill
2. RX ring: Reap filled buffers containing newly arrived packets
3. MCACHE: Make packets visible to app tiles while simultaneously
   freeing old buffers

Each RX buffer (in UMEM) endlessly cycles through these three states.

Each step is explained in more detail below.

### FILL ring

There is one FILL ring per XDP socket.

The XDP FILL ring consists of bare 64-bit aligned pointers addressed
relative to the start of the UMEM region.  The FILL ring is allocated by
the kernel and read-write mapped to userspace by the net tile.

The pointers in the fill ring indicate to the kernel / NIC:
"You can write incoming packet data to the buffers behind these pointers".
If the FILL ring is empty, incoming packets will get dropped as there is
no space to write them to.

All RX buffers start out in the FILL ring.  Whenever another buffer
frees up (see below for free conditions), it gets added back to the XDP
FILL ring.

### RX ring

There is one RX ring per XDP socket.

The kernel publishes XDP descriptors of newly arrived packets to the XDP
RX ring: [`struct xdp_desc`](https://elixir.bootlin.com/linux/v6.13.2/source/include/uapi/linux/if_xdp.h#L155)

The net tile consumes XDP descriptors from the XDP RX ring.
After briefly deciding what to do with the packet, the net tile either
frees the buffer immediately (returning it to the FILL ring) or forwards
it to the mcache ring, see below.

::: info LINUX NAPI

The process how the kernel gets notified of a newly arrived packet is
fairly involved and deserves a multi-page writeup itself.

The NAPI kernel docs are a good start:
https://docs.kernel.org/networking/napi.html

:::

### mcache ring (RX)

There is one mcache ring per downstream tile interested in traffic.

The number of UMEM buffers in 'MCACHE' state is equal to the depths of
all mcache RX rings.  The `chunk` field of each mcache slot/line points
to a different UMEM buffer.  Whenever the net tile produces a new
message onto the mcache, it changes the `chunk` field to the new buffer.
The old buffer (based on the previous value of the `chunk` field) is
immediately sent to the FILL ring.

The RX mcache ring does not backpressure.  Too slow app tiles will get
overridden.

The net tile produces tango descriptors of arrived packets to the mcache
ring: [`fd_frag_meta_t`](https://github.com/firedancer-io/firedancer/blob/v0.305.20111/src/tango/fd_tango_base.h#L146)

For incoming packets, a frag_meta is interpreted as follows.
(Outgoing packets use a slightly different schema)

| Name     | Type  | Description                           |
|----------|-------|---------------------------------------|
| `seq`    | `u64` | Local sequence number                 |
| `sig`    | `u64` | Compressed `netmux_sig` fields        |
| `chunk`  | `u32` | wksp offset right shifted by 6 bits   |
| `sz`     | `u16` | Packet size including Ethernet header |
| `ctl`    | `u16` | Low 6 bits of wksp offset             |
| `tsorig` | `u32` | Unused                                |
| `tspub`  | `u32` | Unused                                |

Given the workspace base address (see `fd_wksp.h`) of the UMEM, the
absolute address of a packet is reconstructed as follows:

```c
static inline void const *
rx_pkt_laddr( void * base,
              ulong  chunk,
              ulong  ctl ) {
  return (void *)( (ulong)base + (chunk<<6) + ctl );
}
```

::: info NOTE

The "chunk index" field is a 64 byte aligned offset.  This is fine for
most other tiles because they only produce 64 byte aligned messages.

Most other tiles also don't use the `ctl` field.

The XDP API does not have alignment guarantees for received packets, so
the net tile just reuses the `ctl` field to encode the low bits of the
packet offset (a value in range `[0,63]`).

:::

The sig field allows for fast payload filtering without having to read
packet contents.  It consists of the following bit fields:

| Bits      | Type  | Description                      |
|-----------|-------|----------------------------------|
| `[0,32)`  | `u32` | IPv4 source address (big endian) |
| `[32,40)` | `u8`  | Protocol index                   |
| `[40,44)` | `u4`  | Compressed offset of UDP payload |
| `[44,64)` | `u20` | Load balancing hash              |

The load balancing hash is derived from the packet's IP source address
and source port.  In case there are multiple tiles of the same kind
(e.g. quic), packets with the same load balancing hash will be handled
by the same tile.

## TX Lifecycle

The TX lifecycle of each incoming packet involves three steps:

```
┌──────┐      ┌──────┐
│ FREE ┼──────►  TX  │
└─▲────┘      └────┬─┘
  │                │
  │ ┌────────────┐ │
  └─┼ COMPLETION ◄─┘
    └────────────┘

Figure visualizing how ownership of TX buffers
transitions across ring buffers / FIFO queues.
```

### mcache rings (TX)

App tiles instruct net tiles to send packets via mcache TX rings.
All net tiles listen for new outgoing packets on all TX mcaches, taking
turns according to the packet's load balancing hash.

The frag_meta of these rings is interpreted as follows:

| Name     | Type  | Description                           |
|----------|-------|---------------------------------------|
| `seq`    | `u64` | Local sequence number                 |
| `sig`    | `u64` | Compressed `netmux_sig` fields        |
| `chunk`  | `u32` | wksp offset right shifted by 6 bits   |
| `sz`     | `u16` | Packet size including Ethernet header |
| `ctl`    | `u16` | Ignored                               |
| `tsorig` | `u32` | Ignored                               |
| `tspub`  | `u32` | Ignored                               |

Packet data is 64 byte aligned.

The sig field consists of the following subfields.

| Bits      | Type  | Description                      |
|-----------|-------|----------------------------------|
| `[0,32)`  | `u32` | IPv4 dest address (big endian)   |
| `[40,44)` | `u4`  | Compressed offset of UDP payload |
| `[44,64)` | `u20` | Load balancing hash              |

### FREE, TX rings

Once a net tile found a packet to send in a mcache TX ring, it attempts
to allocate a UMEM TX frame from the tx_free ring.  The packet payload
is copied into the frame, and the frame is entered into the TX ring.

### Completion ring

Once the kernel finished processing the TX frame, it moves it to the
completion ring.

The net tile moves completed frames back to the free ring.

## Loopback

The first net tile (`net:0`) sets up XDP on the loopback device, for
two main reasons:

* For testing and development.
* The Agave code sends local traffic to itself to as part of routine
  operation (e.g., when it's the leader it sends votes to its own TPU
  socket).

The Linux kernel routes outgoing packets addressed to IP addresses
owned by the system via loopback.  (See `ip route show table local`)
The net tile partially matches this behavior.  For better performance
and simplicity, a second XDP socket is used.

Alternatively, the net tile could have sent such traffic out to the
public gateway, in hopes that the traffic gets mirrored back.

But for now, Firedancer also binds XDP to loopback. This is a small performance hit for other traffic, but otherwise won't interfere.

The loopback device only supports XDP in SKB mode.

## Development

### Network Namespace

Firedancer's `[development.netns]` feature allows quick prototyping of
networking code without risking bringing down the entire host's network
stack.  This is particularly useful if you develop on a remote machine.

In short, an `fddev` instance can be "sandboxed" to run in a fake
network environment with fake NICs by passing the `--netns` command-line
argument or by setting `[development.netns] enabled = true` in the
config file.  More details on this mechanism below.

Linux applications can be configured to run in a new "network namespace"
which is a clean environment without any existing network configuration:

```console
$ sudo unshare -n
# ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
```

The `veth` Linux module provides virtual Ethernet device pairs.  They
emulate two physical Ethernet NICs that are directly connected to each
other with a patch cable.

Finally, you can combine network namespaces and `veth` devices to create
two networking contexts, that each have an Ethernet interface, and are
on the same Ethernet network.

The network namespace mounted at `/run/netns/veth_test_xdp_0` is the one
fddev is running in.  And arbitrary test tooling can then be run in
`/run/netns/veth_test_xdp_1` to talk to fddev.  If the net tile has a
bug, the impact is then (hopefully) contained to the network namespaces.

In one terminal, run:

```
$ build/native/gcc/bin/fddev --netns
... creates network namespaces ...
```

In another terminal, connect to fddev in the network namespace:

```
$ ip netns list
veth_test_xdp_0
veth_test_xdp_1

$ sudo ip netns exec veth_test_xdp_1 ip address show
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: veth_test_xdp_1@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 52:f1:7e:da:2c:e1 brd ff:ff:ff:ff:ff:ff link-netns veth_test_xdp_0
    inet 198.18.0.2/30 scope link veth_test_xdp_1
       valid_lft forever preferred_lft forever
    inet6 fe80::50f1:7eff:feda:2ce1/64 scope link
       valid_lft forever preferred_lft forever

$ sudo ip netns exec veth_test_xdp_1 ping -c3 198.18.0.1
PING 198.18.0.1 (198.18.0.1) 56(84) bytes of data.
64 bytes from 198.18.0.1: icmp_seq=1 ttl=64 time=0.038 ms
64 bytes from 198.18.0.1: icmp_seq=2 ttl=64 time=0.031 ms
64 bytes from 198.18.0.1: icmp_seq=3 ttl=64 time=0.038 ms

--- 198.18.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2037ms
rtt min/avg/max/mdev = 0.031/0.035/0.038/0.003 ms
```

### `fddev pktgen`

The `fddev pktgen` subcommand floods an Ethernet neighbor with small
packets.  The purpose of this tool is to benchmark the TX path of the
net tile.

`fddev pktgen` runs a single net tile and a special pktgen tile
generating about 10 million 64 byte sized Ethernet frames per second.

While this application will cause significant load on the Ethernet
network, it cannot harm any other IP networks, because the packets
generated are not routable.

Running pktgen may result in no packets getting sent out.  This happens
typically because the `netlnk` tile couldn't resolve the Ethernet
neighbor behind the IP address `[development.pktgen.fake_dst_ip]`.

To add a fake neighbor, run:

```shell
ip neigh add FAKE_DST_IP dev DEVICE lladdr 00:00:00:00:00:00
```

Where `FAKE_DST_IP` is an IP like `10.0.0.1` and `DEVICE` is the
Linux network device name like `eth0`.

## Considerations

These are the main known considerations and limitations of the
Firedancer v0.4 net tile. This list is likely to become out of date.

- Firedancer does not support IPv6
  - It would be a trivial exercise to add IPv6 support
  - As of February 2025, practically all Solana traffic uses IPv4, to
    the point of command-line apps and public validator dashboards not
    even displaying IPv6 addresses
  - IPv6 is considerably more expensive than IPv4 due to far lower MTUs
    (1280 on IPv6 vs 1500 on IPv4), mandatory UDP checksums, and
    longer addresses requiring a more complex route table lookup routine
- The net tile does not (yet) use `SO_PREFERRED_BUSY_POLL`
- The net tile supports only one external network interface
  (in addition to loopback)
- fdctl does not yet configure IRQ affinity, nor disable NIC interrupts,
  which can lead hard IRQs and ksoftirqd/NAPI stealing CPU time from
  random other pinned tiles
- Firedancer cannot share a network interface with other AF_XDP apps
- The net tile only supports simple route tables, see [Netlink](./netlink.md).
- Running Firedancer is believed to cause a performance detriment to
  apps using Linux networking on the shared interfaces
- The number of RX mcaches is `O(n*m)` where n is the number of net
  tiles and m is the number of app tiles.  It could be `O(max(n,m))`.
- The tx_free ring is probably obsolete.  Buffers could be moved from
  COMPLETION to TX directly.
