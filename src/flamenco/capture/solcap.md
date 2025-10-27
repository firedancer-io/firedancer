# Solcap Protocol Specification

## Table of Contents

1. [Introduction](#introduction)
2. [Design Goals](#design-goals)
3. [Architecture Overview](#architecture-overview)
4. [Protocol Layers](#protocol-layers)
5. [File Format](#file-format)
6. [Message Types](#message-types)
7. [Data Structures](#data-structures)
8. [Constants and Enumerations](#constants-and-enumerations)
9. [Alignment and Padding](#alignment-and-padding)

---

## Introduction

**Solcap** (Solana Capture) is a portable, generic file format for structured tracing of Solana validator events. It provides a standardized way to capture runtime data from Solana validators.

---

## Architecture Overview

### Conceptual Layers

Solcap uses a layered architecture with four distinct levels:

```
┌─────────────────────────────────────────────────────┐
│  Layer 4: Message Payload                           │
│  (Account updates, bank preimages, rewards, etc.)   │
├─────────────────────────────────────────────────────┤
│  Layer 3: Internal Chunk Header                     │
│  (Message type identification + slot + txn_idx)     │
├─────────────────────────────────────────────────────┤
│  Layer 2: PCapNG Enhanced Packet Block              │
│  (Packet framing, timestamps, length)               │
├─────────────────────────────────────────────────────┤
│  Layer 1: PCapNG File Structure                     │
│  (Section Header + Interface Description)           │
└─────────────────────────────────────────────────────┘
```

**Layer 1 - Base Layer (PCapNG File Structure):**
- Provides file-level framing and metadata
- Section Header Block (SHB) identifies the file format
- Interface Description Block (IDB) defines capture characteristics

**Layer 2 - Transport Layer (Enhanced Packet Blocks):**
- Wraps each solcap message in a PCapNG Enhanced Packet Block (EPB)
- Provides packet-level framing, timestamps, and length information
- Enables compatibility with standard PCapNG tools

**Layer 3 - Muxing Layer (Internal Chunk Header):**
- Multiplexes different solcap message types within EPBs
- Contains message type identifier (`block_type`)
- Provides temporal context (`slot`) and ordering (`txn_idx`)
- This is the primary demultiplexing layer for solcap

**Layer 4 - Message Layer:**
- Contains the actual solcap message payload
- Format determined by `block_type` in Layer 3
- Includes account updates, bank state, rewards, etc.

---

## Protocol Layers

### Layer 1: Base Layer - PCapNG Framing

The base layer provides file-level structure using the PCapNG format. This ensures compatibility with existing network capture tools while providing a robust container format.

#### File Structure

```
[Section Header Block (SHB)]        ← File identification
[Interface Description Block (IDB)] ← Capture interface metadata
[Enhanced Packet Block (EPB) #1]    ← First message
[Enhanced Packet Block (EPB) #2]    ← Second message
...
[Enhanced Packet Block (EPB) #N]    ← Nth message
```

The Section Header Block and Interface Description Block are written once at the beginning of the file. All subsequent messages are wrapped in Enhanced Packet Blocks.

### Layer 2: Transport Layer - Enhanced Packet Blocks

Each solcap message is encapsulated in a PCapNG Enhanced Packet Block (EPB). The EPB provides:
- Block type identification
- Total block length (for forward seeking)
- Timestamp information
- Packet length (captured vs original)
- Redundant length footer (for backward seeking)

These fields are not directly read in solcap files, and provide no use

**Note**: Any Simple Packet Blocks are disregarded

### Layer 3: Muxing Layer - Message Type Identification

The Internal Chunk Header immediately follows the EPB header within each packet. It serves as the **primary muxing layer** that identifies which type of solcap message follows. The `block_type` field is the discriminator that allows parsers to correctly decode the message payload.

This layer also provides:
- **Temporal context**: The `slot` field indicates which slot this message relates to
- **Ordering**: The `txn_idx` field provides transaction-level ordering within a slot
- **Type routing**: The `block_type` field routes to the appropriate message parser

### Layer 4: Message Layer - Payload Data

The message payload immediately follows the Internal Chunk Header. The format is determined by the `block_type` from Layer 3. Currently defined message types include:

- **Account Updates** (`SOLCAP_WRITE_ACCOUNT_HDR` + `SOLCAP_WRITE_ACCOUNT_DATA`)
- **Bank Preimages** (`SOLCAP_WRITE_BANK_PREIMAGE`)

### Block Alignment

All blocks must be aligned to 4-byte boundaries. Padding bytes (zeros) are inserted after the message payload if needed to achieve this alignment.

---

## Message Types

Solcap defines the following message types for capturing validator runtime events:

### Account State Changes

**Purpose**: Capture all modifications to account state during transaction execution.

- `SOLCAP_WRITE_ACCOUNT_HDR` (1): Account update header
  - Contains account pubkey, metadata, and data length
  - Must be followed by `SOLCAP_WRITE_ACCOUNT_DATA`

- `SOLCAP_WRITE_ACCOUNT_DATA` (2): Account data payload
  - Contains the actual account data bytes
  - Follows immediately after `SOLCAP_WRITE_ACCOUNT_HDR`

### Bank State

**Purpose**: Capture the complete state of a bank (block) after processing.

- `SOLCAP_WRITE_BANK_PREIMAGE` (6): Bank preimage data
  - Contains bank hash, previous bank hash, accounts hash, PoH hash
  - Includes transaction count for the slot
  - Enables verification of deterministic execution

---

## Data Structures

All structures use packed layout (`__attribute__((packed))`) to ensure consistent binary representation across platforms.

### Section Header Block (File Header)

**Note**: Solcap does not use the optional fields section, so the block consists of the 24-byte header followed immediately by the 4-byte redundant length, totaling 28 bytes.

### Interface Description Block

**Note**: Solcap does not use the optional fields section, so the block consists of the 16-byte header followed immediately by the 4-byte redundant length, totaling 20 bytes.
          link_type in the IDB needs to be set to 147 which is a DLT_USER0

### Enhanced Packet Block Header

**Note**: Has a max size of EPB Header Size + Internal Header Size + Account Update Max (Solcap Account Update Hdr + Max Account Data Size (10 mb) )
This is the **primary muxing header** that enables readers to identify and route messages to appropriate handlers.

### Block Footer

All PCapNG blocks end with a redundant 4-byte length field for backward navigation. This is not a separate structure, but simply a `uint32` value written at the end of each block

### Buffer Message Internal Header

```c
struct fd_solcap_buf_msg {
   uint16_t sig;       /* Message signature/type */
   uint64_t slot;      /* Solana slot number */
   uint64_t txn_idx;   /* Transaction index */
   /* Specific field and its data follows immediately after this struct in memory */
};
```

**Field Descriptions:**

This structure is used for in-memory message buffering before writing to the capture file. The `sig` field maps to specific message types via the `SOLCAP_SIG_MAP` macro.

---

## Message Payload Structures

### Account Update Header

```c
struct fd_solcap_account_update_hdr {
   fd_pubkey_t              key;      /* Account public key (32 bytes) */
   fd_solana_account_meta_t info;     /* Account metadata */
   uint64_t                 data_sz;  /* Account data size in bytes */
};

struct __attribute__((packed)) fd_solana_account_meta {
  ulong lamports;
  uchar owner[32];
  uchar executable;
  uchar padding[3];
};
```

**Field Descriptions:**

- `key`: The 32-byte public key of the account being updated
- `info`: Account metadata including lamports, owner, executable flag, rent epoch
- `data_sz`: Size of the account data in bytes

**Note**: The account data immediately follows this structure in the same packet. The data is `data_sz` bytes long.

**Message Encoding**: Account updates are encoded as two consecutive messages:
1. `SOLCAP_WRITE_ACCOUNT_HDR` with this header structure + account data
2. Followed by any necessary padding to 4-byte boundary

### Bank Preimage

```c
struct fd_solcap_bank_preimage {
   fd_hash_t bank_hash;                    /* Bank hash */
   fd_hash_t prev_bank_hash;               /* Previous bank hash */
   fd_hash_t accounts_lt_hash_checksum;    /* Accounts hash */
   fd_hash_t poh_hash;                     /* Proof of History hash */
   uint64_t  signature_cnt;                /* Number of signatures */
};
```

**Field Descriptions:**

- `bank_hash`: The hash of the bank state after processing this slot
- `prev_bank_hash`: The hash of the parent bank (previous slot)
- `accounts_lt_hash_checksum`: Checksum of the accounts hash (Merkle root of account states)
- `poh_hash`: The Proof of History hash for this slot
- `signature_cnt`: Total number of signatures processed in this slot

**Purpose**: This captures the complete state transition of a bank, enabling verification that execution was deterministic and produced the correct hash.

## Alignment and Padding

### Block Alignment

All PCapNG blocks must be aligned to **4-byte boundaries**. This includes:
- Section Header Block (28 bytes, naturally aligned)
- Interface Description Block (20 bytes, naturally aligned)
- Enhanced Packet Blocks (variable length, must be padded)

### Endianness

All multi-byte integers are stored in **little-endian** format, as indicated by the byte order magic `0x1A2B3C4D`. Readers must convert to host byte order if running on big-endian systems. This is where a constraint is placed upon the existing PCapNG file, restricting it slightly

## References

- **PCapNG Specification**: [https://pcapng.com/](https://pcapng.com/)
