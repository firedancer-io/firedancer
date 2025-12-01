# shredcap v0.1 file format

The *shredcap* container holds Solana block data captures suitable for
replay in a streaming file format.

This document specifies the shredcap v0.1 file format.

## Container

Shredcap is layered on top of [pcapng](https://pcapng.com/).  Shredcap
flows are designed to co-exist with unrelated packet types, such as
regular network traffic.

At a high level, shredcap stores block data via UDP/IP packets.  Each
packet contains a shred in Solana wire format (Turbine).  Readers
require context to identify and interpret shred packets.  This context
is embedded in the form of [interfaces](#interfaces) and
[metadata packets](#metadata-packets).

Readers _should_ transparently handle files with multiple Section Header
Blocks (SHB) by resetting any parse state such as cached interfaces
or endpoints.

## Interfaces

### Network Interface

Each pcapng section in a shredcap file MUST contain at least one network
interface.

A network interface is identified by an Interface Description Block
(IDB) with link type `LINKTYPE_ETHERNET` (1), `LINKTYPE_RAW` (101), or
`LINKTYPE_IPV4` (228).

### Metadata Interface

Each pcapng section in a shredcap file MUST contain exactly one
IDB with the `if_name` option (2) set to the string `shredcap0`.
This IDB is referred to as the *metadata interface*.

## Packet Records

Enhanced Packet Blocks (EPB) may contain shredcap data.
Simple Packet Blocks (SPB) are considered obsolete and MUST be ignored.

### Metadata Packets

Metadata packets are EPBs where the *interface ID* refers to a
[metadata interface](#metadata-interface).

The format for shredcap v0.1 metadata packets is as follows.  All fixed
with integer types are encoded in little endian unless otherwise
specified.

- Metadata Type (uint32)
- Type-specific data (variable size)

#### Bank hash v0

Root slot metadata encodes state transition information after replaying
a Solana block.

The format for shredcap v0.1 bank hash v0 metadata is as follows:

- Metadata Type: `0x1` (bank hash v0)
- Slot number (uint64)
- Bank hash (32 bytes): Bank hash seen after replaying a slot
- Data shred count (uint64): The number of data shreds with block data
  ingested to produce this bank hash

#### Endpoint v0

The format for shredcap v0.1 endpoint v0 metadata is as follows:

- Metadata Type: `0x2` (endpoint v0)
- IPv6 address (16 bytes)
- UDP port number (uint16)
- Gossip socket type (uint32): `0xa` for shreds

Note that IPv4 addresses are encoded as IPv4-mapped IPv6 addresses.

## UDP Packets

UDP packets are EPBs are identified as follows:
- the *interface ID* refers to a network interface
- the packet contains an IPv4 header
- the packet contains an UDP header

### Shred

Shred packets are [UDP packets](#udp-packets) whose IPv4 destination
address and UDP destination port map to an [endpoint](#endpoint) with
gossip socket type `0xa`.
