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

/* Helper functions to send messages to the capture tile */

/* fd_capture_msg_new creates a new capture message in the provided
   buffer. Returns a pointer to the message header on success, NULL
   on failure. The buffer must be large enough to hold the entire
   message including header and payload. */
static inline fd_capture_msg_hdr_t *
fd_capture_msg_new( void * buf, ulong type, ulong size ) {
  fd_capture_msg_hdr_t * hdr = (fd_capture_msg_hdr_t *)buf;
  hdr->magic = FD_CAPTURE_MSG_MAGIC;
  hdr->type = type;
  hdr->size = size;
  return hdr;
}

/* fd_capture_msg_set_slot creates a set_slot message */
static inline void
fd_capture_msg_set_slot( void * buf, ulong slot ) {
  fd_capture_msg_hdr_t * hdr = fd_capture_msg_new( buf, FD_CAPTURE_MSG_TYPE_SET_SLOT, sizeof(fd_capture_msg_set_slot_t) );
  fd_capture_msg_set_slot_t * msg = (fd_capture_msg_set_slot_t *)hdr;
  msg->slot = slot;
}

/* fd_capture_msg_write_account creates a write_account message */
static inline void
fd_capture_msg_write_account( void *                           buf,
                              void const *                     key,
                              fd_solana_account_meta_t const * meta,
                              void const *                     hash,
                              ulong                            data_sz ) {
  ulong msg_sz = sizeof(fd_capture_msg_write_account_t) + data_sz;
  fd_capture_msg_hdr_t * hdr = fd_capture_msg_new( buf, FD_CAPTURE_MSG_TYPE_WRITE_ACCOUNT, msg_sz );
  fd_capture_msg_write_account_t * msg = (fd_capture_msg_write_account_t *)hdr;
  fd_memcpy( msg->key, key, 32 );
  msg->meta = *meta;
  fd_memcpy( msg->hash, hash, 32 );
  msg->data_sz = data_sz;
}

/* fd_capture_msg_write_bank_preimage creates a write_bank_preimage message */
static inline void
fd_capture_msg_write_bank_preimage( void *       buf,
                                    void const * bank_hash,
                                    void const * prev_bank_hash,
                                    void const * account_delta_hash,
                                    void const * accounts_lt_hash_checksum,
                                    void const * poh_hash,
                                    ulong        signature_cnt ) {
  fd_capture_msg_hdr_t * hdr = fd_capture_msg_new( buf, FD_CAPTURE_MSG_TYPE_WRITE_BANK_PREIMAGE, sizeof(fd_capture_msg_write_bank_preimage_t) );
  fd_capture_msg_write_bank_preimage_t * msg = (fd_capture_msg_write_bank_preimage_t *)hdr;
  fd_memcpy( msg->bank_hash, bank_hash, 32 );
  fd_memcpy( msg->prev_bank_hash, prev_bank_hash, 32 );
  fd_memcpy( msg->account_delta_hash, account_delta_hash, 32 );
  fd_memcpy( msg->accounts_lt_hash_checksum, accounts_lt_hash_checksum, 32 );
  fd_memcpy( msg->poh_hash, poh_hash, 32 );
  msg->signature_cnt = signature_cnt;
}

#endif /* HEADER_fd_src_disco_capture_fd_capture_h */
