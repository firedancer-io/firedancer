#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_proto_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_proto_h

#include "../types/fd_types.h"
#include "../../util/net/fd_pcapng_private.h"
#include <stdbool.h>

/* fd_solana_account_meta_t is the metadata for a Solana account */
struct __attribute__((packed)) fd_solana_account_meta {
  ulong lamports;
  uchar owner[32];
  uchar executable;
  uchar padding[3];
};
typedef struct fd_solana_account_meta fd_solana_account_meta_t;

static inline fd_solana_account_meta_t* fd_solana_account_meta_init(
    fd_solana_account_meta_t* meta, ulong lamports, void const* owner,
    int exec_bit) {
  meta->lamports = lamports;
  fd_memcpy(meta->owner, owner, sizeof(fd_pubkey_t));
  meta->executable = !!exec_bit;
  return meta;
}

/* fd_solcap_proto defines the capture of "solcap" data.

   It is built as a PCapNG format, adhering completely to specification.

   .solcap is a format for capturing Solana runtime data suitable for
   replay and debugging. The format is described below:


   [Section Header Block (file header) ]
   [Interface Description Block (IDB, linktype=147, snaplen=0) ]
   [Enhanced Packet Block #1 (interface_id=0)]
      -- payload start: fd_solcap_chunk_int_hdr
      -- payload rest: packet data (solcap custom format)
   [Enhanced Packet Block #2]
      -- ...

   The solcap format is built as the pcapng format, allowing for easy
   interoperability with existing tools that support pcapng. The format
   of the chunk headers is determined by the pcapng packet blocks.
   See https://pcapng.com/ for more information.

   Section Header Block (SHB) - The file header.
   Interface Description Block (IDB) - The header of the interface.

   Enhanced Packet Block (EPB) - A single solcap message.
   The internal chunk header contains additional metadata about the
   message, used for identifying the message and its position in the
   stream.

      There can be a variety of messages within the EPB blocks, each
      differentiated via an internal chunk header. This internal chunk
      header allows for the reader to process the message in the correct
      encoding scheme. Currently the list of messages is:
      - Account Updates
      - Bank Preimages

      The dumping of the exectuion can be done in multiple ways:
         1. To a 'capture link' which is read by a solcap tile and then
         subsequently written to a file. This is the default when running
         firedancer live or a subcommand that uses a topo (backtest).

         2. To a file directly. This is currently used for block harnesses.
         The neccessity of this path is for the single threaded execution
         mode of the harness.
*/

#define SOLCAP_WRITE_ACCOUNT        (1UL)
#define SOLCAP_WRITE_BANK_PREIMAGE  (2UL)
#define SOLCAP_STAKE_ACCOUNT_PAYOUT (3UL)
#define SOLCAP_STAKE_REWARD_EVENT   (4UL)
#define SOLCAP_STAKE_REWARDS_BEGIN  (5UL)

struct __attribute__((packed)) fd_solcap_buf_msg {
  ushort sig;
  ulong  slot;
  ulong  txn_idx;
  /* Data follows immediately after this struct in memory */
};
typedef struct fd_solcap_buf_msg fd_solcap_buf_msg_t;

/* FD_SOLCAP_V2_FILE_MAGIC identifies a solcap version 2 file. */

#define FD_SOLCAP_V1_FILE_MAGIC       (0x806fe7581b1da4b7UL) /* deprecated */
#define FD_SOLCAP_V2_FILE_MAGIC       FD_PCAPNG_BLOCK_TYPE_SHB /* 0x0A0D0D0A */
#define FD_SOLCAP_V2_BYTE_ORDER_MAGIC FD_PCAPNG_BYTE_ORDER_MAGIC /* 0x1A2B3C4D */

/* Solcap uses standard PCapNG structures for file framing:
   - fd_pcapng_shb_t: Section Header Block (file header)
   - fd_pcapng_idb_t: Interface Description Block
   - fd_pcapng_epb_t: Enhanced Packet Block (wraps each message)

   These are defined in fd_pcapng_private.h and provide correct
   PCapNG compatibility for interoperability with standard tools.
*/

/* PCapNG block type constants for solcap */
#define SOLCAP_PCAPNG_BLOCK_TYPE_IDB FD_PCAPNG_BLOCK_TYPE_IDB /* 1 */
#define SOLCAP_PCAPNG_BLOCK_TYPE_EPB FD_PCAPNG_BLOCK_TYPE_EPB /* 6 */
#define SOLCAP_IDB_HDR_LINK_TYPE     147 /* DLT_USER(0) */
#define SOLCAP_IDB_HDR_SNAP_LEN      0   /* unlimited */

/* fd_solcap_chunk_int_hdr: Internal chunk header (muxing layer)

   This header immediately follows the fd_pcapng_epb_t header within
   each Enhanced Packet Block. It serves as the muxing layer that
   identifies which type of solcap message follows via the block_type
   field, and provides temporal context (slot) and ordering (txn_idx).
*/

struct __attribute__((packed)) fd_solcap_chunk_int_hdr {
   /* 0x00 */ uint block_type; /* Message type (SOLCAP_WRITE_*) */
   /* 0x04 */ uint slot; /* Solana slot number */
   /* 0x08 */ ulong txn_idx; /* Transaction index within slot */
};
typedef struct fd_solcap_chunk_int_hdr fd_solcap_chunk_int_hdr_t;
/*
   The following structures are the solcap messages that can be encoded.
   They are used by the runtime to write messages to the shared buffer
   and written to the file.
*/
struct __attribute__((packed)) fd_solcap_account_update_hdr {
   fd_pubkey_t key;
   fd_solana_account_meta_t info; /* TODO: merge into solcap remove from types.json in future */
   ulong data_sz;
};
typedef struct fd_solcap_account_update_hdr fd_solcap_account_update_hdr_t;

struct __attribute__((packed))fd_solcap_bank_preimage {
   fd_hash_t bank_hash;
   fd_hash_t prev_bank_hash;
   fd_hash_t accounts_lt_hash_checksum;
   fd_hash_t poh_hash;
   ulong     signature_cnt;
};
typedef struct fd_solcap_bank_preimage fd_solcap_bank_preimage_t;

struct __attribute__((packed)) fd_solcap_stake_rewards_begin {
   ulong   payout_epoch;
   ulong   reward_epoch;
   ulong   inflation_lamports;
   ulong   total_points;
};
typedef struct fd_solcap_stake_rewards_begin fd_solcap_stake_rewards_begin_t;

struct __attribute__((packed)) fd_solcap_stake_reward_event {
   fd_pubkey_t stake_acc_addr;
   fd_pubkey_t vote_acc_addr;
   uint        commission;
   long        vote_rewards;
   long        stake_rewards;
   long        new_credits_observed;
};
typedef struct fd_solcap_stake_reward_event fd_solcap_stake_reward_event_t;

struct __attribute__((packed)) fd_solcap_stake_account_payout {
   fd_pubkey_t stake_acc_addr;
   ulong       update_slot;
   ulong       lamports;
   long        lamports_delta;
   ulong       credits_observed;
   long        credits_observed_delta;
   ulong       delegation_stake;
   long        delegation_stake_delta;
};
typedef struct fd_solcap_stake_account_payout fd_solcap_stake_account_payout_t;

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_proto_h */
