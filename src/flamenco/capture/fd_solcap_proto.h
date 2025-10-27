#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_proto_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_proto_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include <sys/types.h>
#include <stdlib.h>
#include <stdbool.h>

#include <bits/stdint-uintn.h>

/* fd_solcap_proto defines the capture data format "solcap".

   .solcap is a portable file format for capturing Solana runtime data
   suitable for replay and debugging. It is laid out below:


   [Section Header Block (file header) ]
   [Interface Description Block (IDB, linktype=147, snaplen=0) ]
   [Enhanced Packet Block #1 (interface_id=0)]
      -- payload start: fd_solcap_chunk_int_hdr
      -- payload rest: packet data (solcap custom format)
   [Enhanced Packet Block #2]
      -- ...

   The solcap format is compatible with the pcapng format, allowing for
   easy interoperability with existing tools that support pcapng. The
   format of the chunk headers is determined by the pcapng packet
   blocks.  See https://pcapng.com/ for more information.

   Section Header Block (SHB) - The file header.
   This is the first block in the file and contains the file header.
   None of this information is used by solcap analysis tools.

   Interface Description Block (IDB) - The header of the interface.
   This is a required block for pcapng files and comes before the first
   Enhanced Packet Block (EPB).

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
      1. To a 'capture link' which is read by a capture tile and then
      subsequently written to a file. This is the default when running
      firedancer live or a subcommand that uses a topo (backtest).

      2. To a file directly. This is currently used for block harnesses.
      The neccessity of this path is for the single threaded execution
      mode of the harness.
*/

#define SOLCAP_WRITE_ACCOUNT_HDR         (1UL)
#define SOLCAP_WRITE_ACCOUNT_DATA        (2UL)
#define SOLCAP_STAKE_ACCOUNT_PAYOUT      (4UL)
#define SOLCAP_STAKE_REWARDS_BEGIN       (5UL)
#define SOLCAP_WRITE_BANK_PREIMAGE       (6UL)
#define SOLCAP_WRITE_STAKE_REWARD_EVENT  (7UL)
#define SOLCAP_WRITE_VOTE_ACCOUNT_PAYOUT (8UL)

#define SOLCAP_SIG_MAP(x) (((const ushort[]){ \
    [SOLCAP_WRITE_ACCOUNT_HDR] = SOLCAP_WRITE_ACCOUNT_DATA, \
})[x])


/* FD_SOLCAP_V2_FILE_MAGIC identifies a solcap version 2 file. */

#define FD_SOLCAP_V1_FILE_MAGIC       (0x806fe7581b1da4b7UL) /* deprecated */
#define FD_SOLCAP_V2_FILE_MAGIC       (0x0A0D0D0AUL) /* used in pcapng */
#define FD_SOLCAP_V2_BYTE_ORDER_MAGIC (0x1A2B3C4DUL) /* used in pcapng */

/* fd_solcap_file_hdr_t is the file header of a capture file. This
   format follows that of the pcapng file format - matching the pcapng
   Section Header Block.
*/

struct __attribute__((packed)) fd_solcap_file_hdr {
   /* 0x00 */ uint32_t block_type; /* 0x0A0D0D0A */
   /* 0x04 */ uint32_t block_len; /* length of the block */
   /* 0x08 */ uint32_t byte_order_magic; /* 0x1a2b3c4d */
   /* 0x0C */ uint32_t major_version; /* 0x00000001 */
   /* 0x10 */ uint32_t minor_version; /* 0x00000001 */
   /* 0x14 */ uint64_t section_len; /* (-1) length of the section */
   /* 0x1C */ /* Optional Section Data - kept as 0 in solcaps */
   /* 0x1C */ uint32_t block_len_redundant; /* length of the block */

 };
typedef struct fd_solcap_file_hdr fd_solcap_file_hdr_t;

/* The fd_solcap_chunk_idb_hdr is the header of the Interface
   Description Block (IDB) used by the pcapng file format, but basically
   unused in solcap, only included for pcapng compatibility.
*/
#define SOLCAP_PCAPNG_BLOCK_TYPE_IDB 1
#define SOLCAP_PCAPNG_BLOCK_TYPE_EPB 6
#define SOLCAP_IDB_HDR_LINK_TYPE     147 /* DLT_USER(0) */
#define SOLCAP_IDB_HDR_SNAP_LEN      0 /* unlimited */

struct __attribute__((packed)) fd_solcap_chunk_idb_hdr {
   /* 0x00 */ uint32_t block_type; /* pcap block type (1) */
   /* 0x04 */ uint32_t block_len; /* total block length */
   /* 0x08 */ uint16_t link_type; /* DLT_USER(0) = 147 */
   /* 0x0a */ uint16_t reserved; /* 0x0000 */
   /* 0x0c */ uint32_t snap_len; /* 0 = unlimited */
   /* options - blank for solcap */
   /* 0x10 */ uint32_t block_len_redundant; /* length of the block */
};
typedef struct fd_solcap_chunk_idb_hdr fd_solcap_chunk_idb_hdr_t;


/* fd_solcap_chunk_epb_hdr is the fixed size header of a chunk.
   It is the header of each solcap message - matching the pcapng
   Enhanced Packet Block (EPB).

   Immediately following this structure is an internal chunk header,
   an encoded solcap message, and a footer.

   fd_solcap_chunk_ftr_t is the footer of the chunk. It is a 4 octet
   length field that is used as a redundant packet size, and for
   backwards navigation on the file.
*/

struct __attribute__((packed)) fd_solcap_chunk_epb_hdr {
   /* 0x00 */ uint32_t block_type; /* pcap block type (6) */
   /* 0x04 */ uint32_t block_len; /* total block length including footer */
   /* 0x08 */ uint32_t interface_id; /* 0 */
   /* 0x0c */ uint32_t timestamp_upper; /* upper 32 bits of timestamp */
   /* 0x10 */ uint32_t timestamp_lower; /* lower 32 bits of timestamp */
   /* 0x14 */ uint32_t captured_packet_len; /* captured packet length */
   /* 0x18 */ uint32_t original_packet_len; /* original packet length */
   /* 0x1c */ /* packet data follows immediately after this structure */
};
typedef struct fd_solcap_chunk_epb_hdr fd_solcap_chunk_epb_hdr_t;

struct __attribute__((packed)) fd_solcap_chunk_int_hdr {
   /* 0x00 */ uint32_t block_type; /* SOLCAP_BLOCK_TYPE_CHUNK */
   /* 0x04 */ uint32_t slot; /* reference slot for the chunk */
   /* 0x08 */ uint64_t txn_idx; /* transaction index */
};
typedef struct fd_solcap_chunk_int_hdr fd_solcap_chunk_int_hdr_t;


struct __attribute__((packed)) fd_solcap_chunk_ftr {
   /* int_hdr + packet_len */ uint32_t block_len_redundant; /* length of the block */
};
typedef struct fd_solcap_chunk_ftr fd_solcap_chunk_ftr_t;

/*
   The following structures are the solcap messages that can be encoded.
   They are used by the runtime to write messages to the shared buffer
   and written to the file.
*/
struct __attribute__((packed)) fd_solcap_account_update_hdr {
   fd_pubkey_t key;
   fd_solana_account_meta_t info;
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

struct fd_solcap_buf_msg_stake_rewards_begin {
   ulong   payout_epoch;
   ulong   reward_epoch;
   ulong   inflation_lamports;
   uint128 total_points;
 };
 typedef struct fd_solcap_buf_msg_stake_rewards_begin fd_solcap_buf_msg_stake_rewards_begin_t;

struct fd_solcap_buf_msg_stake_reward_event {
   fd_pubkey_t stake_acc_addr;
   fd_pubkey_t vote_acc_addr;
   uint        commission;
   long        vote_rewards;
   long        stake_rewards;
   long        new_credits_observed;
 };
 typedef struct fd_solcap_buf_msg_stake_reward_event fd_solcap_buf_msg_stake_reward_event_t;


struct fd_solcap_buf_msg_vote_account_payout {
   fd_pubkey_t vote_acc_addr;
   ulong       update_slot;
   ulong       lamports;
   long        lamports_delta;
 };
 typedef struct fd_solcap_buf_msg_vote_account_payout fd_solcap_buf_msg_vote_account_payout_t;


struct fd_solcap_buf_msg_stake_account_payout {
   fd_pubkey_t stake_acc_addr;
   ulong       update_slot;
   ulong       lamports;
   long        lamports_delta;
   ulong       credits_observed;
   long        credits_observed_delta;
   ulong       delegation_stake;
   long        delegation_stake_delta;
 };
 typedef struct fd_solcap_buf_msg_stake_account_payout fd_solcap_buf_msg_stake_account_payout_t;


#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_proto_h */
