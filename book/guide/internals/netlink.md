# Netlink Integration

## Summary

Firedancer's userland networking stack sources configuration from netlink
to allow mostly zero config interoperability with Linux.

This contrasts with other fast networking stacks which typically require
complex network configuration or a dedicated IP address.

The following describes the netlink integration in detail.

## Tile Overview

Firedancer uses XDP for fast networking.  This means that some packet
processing steps traditionally done in the kernel (with UDP sockets) now
have to be done in the Firedancer software.  Specifically routing and
resolving link-level neighbors.

The required information in these steps is requested from the kernel via
the [rtnetlink API](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
Doing all netlink requests in the data path (i.e. in the net tile) bears
security risk and is slow.

The reasons netlink requests are done in a separate tile are:
- **Improved security architecture.** Firedancer's sandbox isolates the
  netlink interface from untrusted user traffic
- **Better performance.** The netlink tile provides shared memory caches
  that greatly reduce the amount of netlink requests.

### "Netbase" shared memory region

The netlink tile keeps a read-only cache of the following information:

- Interface table
- IPv4 route tables `local` and `main`
- Neighbor tables (only for XDP-enabled Ethernet interfaces)

The objects containing the above information are stored in the "netbase"
workspace.  (A workspace is a shared memory region)

### Security

A netlink tile requires an rtnetlink socket.  On startup, it subscribes
to route and neighbor table changes.  It will also issue RTM_GETROUTE
and RTM_GETNEIGH requests.  On RHEL 8 with a Linux 4.18 kernel, all
netlink interactions (including creation of the socket) can be done from
a regular unprivileged user without capabilities.

The kernel's netlink interface exposes a large attack surface.
Therefore, this tile attempts to isolate itself from direct untrusted
inputs.

### Data flows

- `[net tiles] <-- [netbase]` <br/>
   Net tiles have read only access to the shared memory region backing
   the netbase object.  A malicious netlink tile can compromise net tiles
   by corrupting the netbase object, but not vice versa.

- `[changes by sysadmin] --> [netlink] --> [netlink tile]` <br/>
   Route table updates are forwarded to the netlink tile.  This occurs
   rarely (typically if the sysadmin performs manual changes or if due to
   a system daemon).

- `[netlink tile] --> [netbase]` <br/>
   The netlink tile writes neighbor and route table updates to a shared
   memory region.

- `[neighbor discovery] --> [netlink] --> [netlink tile]` <br/>
   Neighbor table updates are forwarded ot the netlink tile.  This path
   has limited throughput (few ~100K updates per second).

- `[untrusted traffic] --> [net tile] --> [app tile]` <br/>
   `--> [net tile] --> [netlink tile] --> [neighbor discovery]` <br/>
   App tiles will blindly respond to the source IP found in untrusted
   packets.  This source IP can be spoofed.  Neighbor solicitation might
   be required in order to find out the MAC address of that IP.  On IPv4,
   these are ARP requests broadcasted to the local network.

   Net tiles cannot solicit neighbors directly, so they notify the
   netlink tile that neighbor solicitation is needed.  (Potentially at
   line rate if network configuration is part of a huge subnet)

   The netlink tile will deduplicate these requests and forward them to
   the kernel.

   This path is the only direct 'untrusted traffic' -> 'netlink tile'
   data flow, so the internal neighbor solicit message format is kept
   as simple as possible for security.

### Neighbor discovery (ARP)

A concurrent open addressed hash table is used to store ARP entries
(henceforth called "neighbor table").  This table attempts to
continuously stay in sync with the kernel.

The netlink tile requests neighbor solicitations via the netlink
equivalent of `ip neigh add dev DEVICE IP use`.

### Routing

The Firedancer network stack supports very simple routing tables as
typically seen on cloud instances, servers directly connected to an
Ethernet switch, or a router.

Only the "local" and "main" routing tables are synchronized.  Policy
based routing and additional routing tables are NOT supported.

Outgoing traffic matching the "local" table is sent to the loopback
device.
