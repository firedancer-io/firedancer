#ifndef HEADER_fd_src_flamenco_runtime_fd_blockstore_h
#define HEADER_fd_src_flamenco_runtime_fd_blockstore_h

#include "../../ballet/shred/fd_deshredder.h"
#include "../../ballet/shred/fd_shred.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "stdbool.h"

#define FD_BLOCKSTORE_MAX_SLOT_FORKS ( 32 ) /* TODO think more about this */
#define FD_BLOCKSTORE_MAX_BLOCK_SZ   ( FD_SHRED_MAX_SZ * ( 1 << 15UL ) )

// TODO centralize these
// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/clock.rs#L34
#define FD_MS_PER_TICK 6

// https://github.com/firedancer-io/solana/blob/v1.17.5/core/src/repair/repair_service.rs#L55
#define FD_REPAIR_TIMEOUT ( 200 / FD_MS_PER_TICK )

#define FD_BLOCKSTORE_OK                           0x00
#define FD_BLOCKSTORE_ERR_UPSERT_MAP_FULL          0x10
#define FD_BLOCKSTORE_ERR_UPSERT_UNKNOWN           0x1F
#define FD_BLOCKSTORE_ERR_QUERY_BLOCK_INCOMPLETE   0x20
#define FD_BLOCKSTORE_ERR_QUERY_SHRED_DATA_INVALID 0x21
#define FD_BLOCKSTORE_ERR_QUERY_BUF_TOO_SMALL      0x22
#define FD_BLOCKSTORE_ERR_QUERY_KEY_MISSING        0x23
#define FD_BLOCKSTORE_ERR_QUERY_UNKNOWN            0x2F

struct fd_blockstore_key {
  ulong slot;
  uint  shred_idx;
};
typedef struct fd_blockstore_key fd_blockstore_key_t;

#define SET_NAME fd_blockstore_missing_shreds
#define SET_MAX  FD_SHRED_MAX_PER_SLOT
#include "../../util/tmpl/fd_set.c"

struct fd_blockstore_slot_meta {
  ulong          slot;
  fd_slot_meta_t slot_meta;
  uint           hash;
};
typedef struct fd_blockstore_slot_meta fd_blockstore_slot_meta_t;

/* clang-format off */
#define MAP_NAME  fd_blockstore_slot_meta
#define MAP_T     fd_blockstore_slot_meta_t
#define MAP_KEY slot
#define MAP_LG_SLOT_CNT 20  /* 1 mb slots TODO think about bound */
#include "../../util/tmpl/fd_map.c"
/* clang-format on */

struct fd_blockstore_shred {
  fd_blockstore_key_t key;
  ulong               next;
  union {
    fd_shred_t shred_hdr;
    uchar      shred_data[FD_SHRED_MAX_SZ];
  };
  ulong shred_sz;
};
typedef struct fd_blockstore_shred fd_blockstore_shred_t;

/* clang-format off */
#define MAP_NAME  fd_blockstore_shred
#define MAP_T     fd_blockstore_shred_t
#define MAP_KEY_T fd_blockstore_key_t
#define MAP_KEY_EQ(k0,k1) (!(((k0)->slot) ^ ((k1)->slot))) & !(((k0)->shred_idx)^(((k1)->shred_idx))) /* max shred_idx is 2^6 = 64 */
#define MAP_KEY_HASH(key,seed) ((((key)->slot)<<6UL) | (((key)->shred_idx)^seed))
#include "../../util/tmpl/fd_map_giant.c"
/* clang-format on */

struct fd_blockstore {
  fd_blockstore_slot_meta_t * slot_metas; /* map of slot->slot_meta */
  fd_blockstore_shred_t *     shreds;     /* map of (slot, shred_idx)->shred */
  ulong                       root;       /* the current root slot */
  ulong                       consumed;   /* the highest shred-complete slot */
  ulong                       received;   /* the highest received slot, may be incomplete */
};
typedef struct fd_blockstore fd_blockstore_t;

FD_PROTOTYPES_BEGIN

int
fd_blockstore_upsert_shred( fd_blockstore_t *  blockstore,
                            fd_shred_t const * shred,
                            ulong              shred_sz );

bool
fd_blockstore_upsert_root( fd_blockstore_t * blockstore, ulong root_slot );

fd_shred_t *
fd_blockstore_query_shred( fd_blockstore_t * blockstore, ulong slot, uint shred_idx );

int
fd_blockstore_query_block( fd_blockstore_t * blockstore,
                           ulong             slot,
                           void *            buf,
                           ulong             buf_sz,
                           ulong *           out );

int
fd_blockstore_query_missing_shreds( fd_blockstore_t *                blockstore,
                                    ulong                            slot,
                                    fd_blockstore_missing_shreds_t * missing_shreds );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_h */
