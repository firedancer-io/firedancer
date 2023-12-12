#ifndef HEADER_fd_src_flamenco_runtime_fd_blockstore_h
#define HEADER_fd_src_flamenco_runtime_fd_blockstore_h

#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/shred/fd_deshredder.h"
#include "../../ballet/shred/fd_shred.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "stdbool.h"

#define FD_DEFAULT_SLOTS_PER_EPOCH     ( 432000 )
#define FD_DEFAULT_SHREDS_PER_EPOCH    ( ( 1 << 15UL ) * FD_DEFAULT_SLOTS_PER_EPOCH )
#define FD_BLOCKSTORE_MAX_SLOT_FORKS   ( 32 ) /* TODO think more about this */
#define FD_BLOCKSTORE_MAX_SLOT_HISTORY ( 32 )
#define FD_BLOCKSTORE_MAX_BLOCK_SZ     ( FD_SHRED_MAX_SZ * ( 1 << 15UL ) )

// TODO centralize these
// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/clock.rs#L34
#define FD_MS_PER_TICK 6

// https://github.com/firedancer-io/solana/blob/v1.17.5/core/src/repair/repair_service.rs#L55
#define FD_REPAIR_TIMEOUT ( 200 / FD_MS_PER_TICK )

#define FD_BLOCKSTORE_OK                0x00
#define FD_BLOCKSTORE_ERR_MAP_FULL      0x01
#define FD_BLOCKSTORE_ERR_INVALID_SHRED 0x02
#define FD_BLOCKSTORE_ERR_NO_MEM        0x03
#define FD_BLOCKSTORE_ERR_BLOCK_EXISTS  0x04
#define FD_BLOCKSTORE_ERR_UNKNOWN       0xFF

struct fd_blockstore_key {
  ulong slot;
  uint  shred_idx;
};
typedef struct fd_blockstore_key fd_blockstore_key_t;

struct fd_blockstore_slot_meta_map {
  ulong          slot;
  fd_slot_meta_t slot_meta;
  uint           hash;
};
typedef struct fd_blockstore_slot_meta_map fd_blockstore_slot_meta_map_t;

/* clang-format off */
#define MAP_NAME  fd_blockstore_slot_meta_map
#define MAP_T     fd_blockstore_slot_meta_map_t
#define MAP_KEY slot
#include "../../util/tmpl/fd_map_dynamic.c"
/* clang-format on */

/* A map for temporarily holding shreds that have not yet been assembled into a block. This is
 * useful, for example, for receiving shreds out-of-order. */
struct fd_blockstore_shred_map {
  fd_blockstore_key_t key;
  ulong               next;
  union {
    fd_shred_t hdr;             /* data shred header */
    uchar raw[FD_SHRED_MAX_SZ]; /* the shred as raw bytes, including both header and payload. */
  };
};
typedef struct fd_blockstore_shred_map fd_blockstore_shred_map_t;

/* clang-format off */
#define MAP_NAME  fd_blockstore_shred_map
#define MAP_T     fd_blockstore_shred_map_t
#define MAP_KEY_T fd_blockstore_key_t
#define MAP_KEY_EQ(k0,k1) (!(((k0)->slot) ^ ((k1)->slot))) & !(((k0)->shred_idx)^(((k1)->shred_idx))) /* max shred_idx is 2^6 = 64 */
#define MAP_KEY_HASH(key,seed) ((((key)->slot)<<6UL) | (((key)->shred_idx)^seed))
#include "../../util/tmpl/fd_map_giant.c"
/* clang-format on */

/* Bookkeeping for shred idxs, e.g. missing shreds */
#define SET_NAME fd_blockstore_shred_idx_set
#define SET_MAX  FD_SHRED_MAX_PER_SLOT
#include "../../util/tmpl/fd_set.c"

/* A shred that has been deshredded and is part of a block */
struct fd_blockstore_shred {
  fd_shred_t hdr; /* ptr to the data shred header */
  ulong      off; /* offset to the payload relative to the start of the block's data region */
};
typedef struct fd_blockstore_shred fd_blockstore_shred_t;

/* An entry / microblock that has been parsed and is part of a block */
struct fd_blockstore_micro {
  ulong offset;             /* offset into block data */
};
typedef struct fd_blockstore_micro fd_blockstore_micro_t;

struct fd_blockstore_block {
  fd_blockstore_shred_t * shreds;  /* each shred in the block region */
  ulong shreds_cnt;
  fd_blockstore_micro_t * micros;  /* each microblock in the block region */
  ulong micros_cnt;
  uchar *                 data;    /* ptr to the beginning of the block's allocated data region */
  ulong                   sz;      /* block size */
};
typedef struct fd_blockstore_block fd_blockstore_block_t;

struct fd_blockstore_block_map {
  ulong                 slot;
  uint                  hash;
  fd_blockstore_block_t block;
};
typedef struct fd_blockstore_block_map fd_blockstore_block_map_t;

/* clang-format off */
#define MAP_NAME  fd_blockstore_block_map
#define MAP_T     fd_blockstore_block_map_t
#define MAP_KEY slot
#include "../../util/tmpl/fd_map_dynamic.c"
/* clang-format on */

struct fd_blockstore_txn_key {
  ulong v[FD_ED25519_SIG_SZ/sizeof(ulong)];
};
typedef struct fd_blockstore_txn_key fd_blockstore_txn_key_t;

struct fd_blockstore_txn_map {
  fd_blockstore_txn_key_t sig;
  uint hash;
  ulong slot;
  ulong offset;
};
typedef struct fd_blockstore_txn_map fd_blockstore_txn_map_t;

/* clang-format off */
#define MAP_NAME  fd_blockstore_txn_map
#define MAP_T     fd_blockstore_txn_map_t
#define MAP_KEY   sig
#define MAP_KEY_T fd_blockstore_txn_key_t
#define MAP_KEY_EQUAL_IS_SLOW 1
fd_blockstore_txn_key_t fd_blockstore_txn_key_null(void);
#define MAP_KEY_NULL         fd_blockstore_txn_key_null()
int fd_blockstore_txn_key_inval(fd_blockstore_txn_key_t k);
#define MAP_KEY_INVAL(k)     fd_blockstore_txn_key_inval(k)
int fd_blockstore_txn_key_equal(fd_blockstore_txn_key_t k0, fd_blockstore_txn_key_t k1);
#define MAP_KEY_EQUAL(k0,k1) fd_blockstore_txn_key_equal(k0,k1)
uint fd_blockstore_txn_key_hash(fd_blockstore_txn_key_t k);
#define MAP_KEY_HASH(k)      fd_blockstore_txn_key_hash(k)
#include "../../util/tmpl/fd_map_dynamic.c"
/* clang-format on */

struct fd_blockstore {
  fd_alloc_t *                    alloc;
  fd_valloc_t                     valloc;
  fd_blockstore_slot_meta_map_t * slot_meta_map; /* map of slot->slot_meta */
  fd_blockstore_shred_map_t *     shred_map;     /* map of (slot, shred_idx)->shred */
  fd_blockstore_block_map_t *     block_map;     /* map of slot->block */
  fd_blockstore_txn_map_t *       txn_map;       /* map of transaction signature to block/offset */
  ulong                           root;          /* the current root slot */
  ulong                           consumed;      /* the highest contiguous shred-complete slot */
  ulong                           received;      /* the highest received shred-complete slot */
};
typedef struct fd_blockstore fd_blockstore_t;

FD_PROTOTYPES_BEGIN

/* Insert shred into the blockstore, fast O(1).  Fail if this shred is already in the blockstore or
 * the blockstore is full. Returns an error code indicating success or failure.
 *
 * TODO eventually this will need to support "upsert" duplicate shred handling
 */
int
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred );

/* Query blockstore for shred at slot, shred_idx. Returns a pointer to the shred or NULL if not in
 * blockstore. The returned pointer lifetime is until the shred is removed. Check return value for
 * error info.
 *
 * Warning: if the slot of that shred is incomplete, this pointer could become invalid!
 */
fd_shred_t *
fd_blockstore_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx );

/* Query blockstore for block at slot. Returns a pointer to the block or NULL if not in
 * blockstore. The returned pointer lifetime is until the block is removed. Check return value for
 * error info. */
fd_blockstore_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot );

/* Query blockstore for slot_meta at slot. Returns a pointer to the slot_meta or NULL if not in
 * blockstore. The returned pointer lifetime is until the slot meta is removed. Check return value
 * for error info. */
fd_slot_meta_t *
fd_blockstore_slot_meta_query( fd_blockstore_t * blockstore, ulong slot );

/* Returns the missing shreds in a given slot. Note there is a grace period for unreceived shreds.
 * This is calculated using the first timestamp info in SlotMeta and a configurable timeout. */
int
fd_blockstore_missing_shreds_query( fd_blockstore_t *               blockstore,
                                    ulong                           slot,
                                    fd_blockstore_shred_idx_set_t * missing_shreds );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_h */
