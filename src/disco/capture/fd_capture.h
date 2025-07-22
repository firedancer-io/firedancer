#ifndef HEADER_fd_src_disco_capture_fd_capture_h
#define HEADER_fd_src_disco_capture_fd_capture_h

#include "../../disco/tiles.h"
#include "../../flamenco/types/fd_types.h"

/* The capture tile consumes from input links from replay and writer tiles,
   and uses a solcap writer to write these fragments to a file. It provides
   a centralized mechanism for capture writing that can be accessed by
   multiple threads.

   API for messages sent across input links:
   - write_account(key, meta, data, data_sz, hash)
   - set_slot(slot)
   - write_bank_preimage(bank_hash, prev_bank_hash, account_delta_hash, 
                         accounts_lt_hash_checksum, poh_hash, signature_cnt)
*/

/* Message types for inter-tile communication */
#define FD_CAPTURE_MSG_TYPE_SET_SLOT          0
#define FD_CAPTURE_MSG_TYPE_WRITE_ACCOUNT     1
#define FD_CAPTURE_MSG_TYPE_WRITE_BANK_PREIMAGE 2

/* Message header structure */
struct __attribute__((packed)) fd_capture_msg_hdr {
  ulong magic;     /* FD_CAPTURE_MSG_MAGIC */
  ulong type;      /* Message type (see above) */
  ulong size;      /* Total size of message including header */
};
typedef struct fd_capture_msg_hdr fd_capture_msg_hdr_t;

#define FD_CAPTURE_MSG_MAGIC 0x4341505455524530UL /* "CAPTURE0" */

/* Set slot message */
struct __attribute__((packed)) fd_capture_msg_set_slot {
  fd_capture_msg_hdr_t hdr;
  ulong slot;
};
typedef struct fd_capture_msg_set_slot fd_capture_msg_set_slot_t;

/* Write account message */
struct __attribute__((packed)) fd_capture_msg_write_account {
  fd_capture_msg_hdr_t hdr;
  uchar key[32];                    /* Account public key */
  fd_solana_account_meta_t meta;    /* Account metadata */
  uchar hash[32];                   /* Account hash */
  ulong data_sz;                    /* Size of account data */
  /* Variable length data follows */
};
typedef struct fd_capture_msg_write_account fd_capture_msg_write_account_t;

/* Write bank preimage message */
struct __attribute__((packed)) fd_capture_msg_write_bank_preimage {
  fd_capture_msg_hdr_t hdr;
  uchar bank_hash[32];
  uchar prev_bank_hash[32];
  uchar account_delta_hash[32];
  uchar accounts_lt_hash_checksum[32];
  uchar poh_hash[32];
  ulong signature_cnt;
};
typedef struct fd_capture_msg_write_bank_preimage fd_capture_msg_write_bank_preimage_t;

extern fd_topo_run_tile_t fd_tile_capture;

#endif /* HEADER_fd_src_disco_capture_fd_capture_h */
