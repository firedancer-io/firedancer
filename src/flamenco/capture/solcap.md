# Solcap Protocol Specification

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

- **Account Updates** (`SOLCAP_WRITE_ACCOUNT`)
- **Bank Preimages** (`SOLCAP_WRITE_BANK_PREIMAGE`)
- **Stake Rewards Begin** (`SOLCAP_STAKE_REWARDS_BEGIN`)
- **Stake Reward Events** (`SOLCAP_STAKE_REWARD_EVENT`)
- **Stake Account Payouts** (`SOLCAP_STAKE_ACCOUNT_PAYOUT`)

---

## Message Types

Solcap defines the following message types for capturing validator runtime events:

### Account State Changes

**Purpose**: Capture all modifications to account state during transaction execution.

- `SOLCAP_WRITE_ACCOUNT` (1): Account update
  - Contains account pubkey, metadata, and data length in the header
  - Account data follows immediately after the header

### Bank State

**Purpose**: Capture the complete state of a bank (block) after processing.

- `SOLCAP_WRITE_BANK_PREIMAGE` (2): Bank preimage data
  - Contains bank hash, previous bank hash, accounts hash, PoH hash
  - Includes transaction count for the slot
  - Enables verification of deterministic execution

### Stake Rewards

**Purpose**: Capture stake rewards distribution events for debugging epoch boundaries.

- `SOLCAP_STAKE_ACCOUNT_PAYOUT` (3): Stake account payout details
  - Contains stake account address, lamports, and delegation stake
  - Includes deltas for tracking changes during reward distribution

- `SOLCAP_STAKE_REWARD_EVENT` (4): Individual stake reward calculation event
  - Contains stake and vote account addresses
  - Includes commission, vote rewards, stake rewards, and credits observed

- `SOLCAP_STAKE_REWARDS_BEGIN` (5): Marks the start of stake rewards distribution
  - Contains payout epoch, reward epoch, inflation lamports, and total points
  - Emitted once per epoch boundary before individual reward events

---

## Data Structures

All multi-byte integers are stored in **little-endian** format.

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

This structure is used for in-memory message buffering before writing to the capture file. The `sig` field identifies the message type.

---

## Message Payload Structures

### Account Update Header

```c
struct fd_solcap_account_update_hdr {
   fd_pubkey_t              key;      /* Account public key (32 bytes) */
   fd_solana_account_meta_t info;     /* Account metadata */
   uint64_t                 data_sz;  /* Account data size in bytes */
};

struct fd_solana_account_meta {
  uint64_t lamports;
  uint8_t  owner[32];
  uint8_t  executable;
  uint8_t  padding[3];
};
```

**Field Descriptions:**

- `key`: The 32-byte public key of the account being updated
- `info`: Account metadata including lamports, owner, executable flag, rent epoch
- `data_sz`: Size of the account data in bytes

**Note**: The account data immediately follows this structure in the same packet. The data is `data_sz` bytes long, followed by any necessary padding to 4-byte boundary.

**Message Encoding**: Account updates are encoded as a single `SOLCAP_WRITE_ACCOUNT` message containing the header structure followed by the account data.

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

### Stake Rewards Begin

```c
struct fd_solcap_stake_rewards_begin {
   uint64_t payout_epoch;        /* Epoch when rewards are paid out */
   uint64_t reward_epoch;        /* Epoch being rewarded */
   uint64_t inflation_lamports;  /* Total inflation lamports for rewards */
   uint64_t total_points;        /* Total reward points across all stakes */
};
```

**Field Descriptions:**

- `payout_epoch`: The epoch during which rewards are being distributed
- `reward_epoch`: The epoch for which rewards are being calculated
- `inflation_lamports`: Total lamports from inflation allocated for stake rewards
- `total_points`: Sum of all stake points used for proportional distribution

**Purpose**: Marks the beginning of stake rewards distribution at an epoch boundary. Emitted once before individual reward events.

### Stake Reward Event

```c
struct fd_solcap_stake_reward_event {
   fd_pubkey_t stake_acc_addr;      /* Stake account address */
   fd_pubkey_t vote_acc_addr;       /* Vote account address */
   uint32_t    commission;          /* Validator commission rate */
   int64_t     vote_rewards;        /* Rewards to vote account */
   int64_t     stake_rewards;       /* Rewards to stake account */
   int64_t     new_credits_observed; /* Updated credits observed */
};
```

**Field Descriptions:**

- `stake_acc_addr`: Public key of the stake account receiving rewards
- `vote_acc_addr`: Public key of the vote account the stake delegates to
- `commission`: Validator's commission percentage
- `vote_rewards`: Lamports credited to the vote account
- `stake_rewards`: Lamports credited to the stake account
- `new_credits_observed`: Updated credits observed after reward calculation

**Purpose**: Captures individual stake reward calculations for debugging reward distribution.

### Stake Account Payout

```c
struct fd_solcap_stake_account_payout {
   fd_pubkey_t stake_acc_addr;         /* Stake account address */
   uint64_t    update_slot;            /* Slot of the update */
   uint64_t    lamports;               /* New lamports balance */
   int64_t     lamports_delta;         /* Change in lamports */
   uint64_t    credits_observed;       /* New credits observed */
   int64_t     credits_observed_delta; /* Change in credits observed */
   uint64_t    delegation_stake;       /* New delegation stake */
   int64_t     delegation_stake_delta; /* Change in delegation stake */
};
```

**Field Descriptions:**

- `stake_acc_addr`: Public key of the stake account
- `update_slot`: Slot number when this payout occurred
- `lamports`: New lamports balance after payout
- `lamports_delta`: Change in lamports from this payout
- `credits_observed`: New credits observed value
- `credits_observed_delta`: Change in credits observed
- `delegation_stake`: New delegation stake amount
- `delegation_stake_delta`: Change in delegation stake

**Purpose**: Captures detailed stake account state changes during reward payouts for debugging.

## References

- **PCapNG Specification**: [https://pcapng.com/](https://pcapng.com/)
