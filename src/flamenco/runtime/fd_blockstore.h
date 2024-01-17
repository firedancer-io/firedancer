#ifndef HEADER_fd_src_flamenco_runtime_fd_blockstore_h
#define HEADER_fd_src_flamenco_runtime_fd_blockstore_h

#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/shred/fd_deshredder.h"
#include "../../ballet/shred/fd_shred.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "stdbool.h"
#include "fd_readwrite_lock.h"

/* FD_BLOCKSTORE_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a blockstore.  ALIGN should be a positive integer power of 2.
   FOOTPRINT is multiple of ALIGN.  These are provided to facilitate
   compile time declarations.  */

#define FD_BLOCKSTORE_ALIGN     ( 128UL )
#define FD_BLOCKSTORE_FOOTPRINT ( 256UL )

#define FD_BLOCKSTORE_MAGIC ( 0xf17eda2ce7b10c00UL ) /* firedancer bloc version 0 */

#define FD_DEFAULT_SLOTS_PER_EPOCH        ( 432000UL )
#define FD_DEFAULT_SHREDS_PER_EPOCH       ( ( 1 << 15UL ) * FD_DEFAULT_SLOTS_PER_EPOCH )
#define FD_BLOCKSTORE_DUP_SHREDS_MAX      ( 32UL ) /* TODO think more about this */
#define FD_DEFAULT_SLOT_HISTORY_MAX       ( 1024UL )
#define FD_BLOCKSTORE_BLOCK_SZ_MAX        ( FD_SHRED_MAX_SZ * ( 1 << 15UL ) )

// TODO centralize these
// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/clock.rs#L34
#define FD_MS_PER_TICK 6

// https://github.com/firedancer-io/solana/blob/v1.17.5/core/src/repair/repair_service.rs#L55
#define FD_REPAIR_TIMEOUT ( 200 / FD_MS_PER_TICK )

#define FD_BLOCKSTORE_OK                0x00
#define FD_BLOCKSTORE_ERR_SHRED_FULL    0x01 /* no space left for shreds */
#define FD_BLOCKSTORE_ERR_SLOT_FULL     0x02 /* no space left for slots */
#define FD_BLOCKSTORE_ERR_TXN_FULL      0x03 /* no space left for txns */
#define FD_BLOCKSTORE_ERR_SHRED_MISSING 0x07
#define FD_BLOCKSTORE_ERR_SLOT_MISSING  0x08
#define FD_BLOCKSTORE_ERR_TXN_MISSING   0x09
#define FD_BLOCKSTORE_ERR_INVALID_SHRED 0x04 /* shred was invalid */
#define FD_BLOCKSTORE_ERR_NO_MEM        0x05 /* no mem */
#define FD_BLOCKSTORE_ERR_INVALID_DESHRED 0x10 /* deshredded block was invalid */
#define FD_BLOCKSTORE_ERR_UNKNOWN       0xFF

struct fd_blockstore_tmp_shred_key {
  ulong slot;
  uint  idx;
};
typedef struct fd_blockstore_tmp_shred_key fd_blockstore_tmp_shred_key_t;

/* A map for temporarily holding shreds that have not yet been assembled into a block ("temporary
 * shreds"). This is useful, for example, for receiving shreds out-of-order. */
struct fd_blockstore_tmp_shred {
  fd_blockstore_tmp_shred_key_t key;
  ulong                         next;
  union {
    fd_shred_t hdr;             /* data shred header */
    uchar raw[FD_SHRED_MAX_SZ]; /* the shred as raw bytes, including both header and payload. */
  };
};
typedef struct fd_blockstore_tmp_shred fd_blockstore_tmp_shred_t;

#define POOL_NAME fd_blockstore_tmp_shred_pool
#define POOL_T    fd_blockstore_tmp_shred_t
#include "../../util/tmpl/fd_pool.c"

/* clang-format off */
#define MAP_NAME               fd_blockstore_tmp_shred_map
#define MAP_ELE_T              fd_blockstore_tmp_shred_t
#define MAP_KEY_T              fd_blockstore_tmp_shred_key_t
#define MAP_KEY_EQ(k0,k1)      (!(((k0)->slot) ^ ((k1)->slot))) & !(((k0)->idx)^(((k1)->idx)))
#define MAP_KEY_HASH(key,seed) ((((key)->slot)<<15UL) | (((key)->idx)^seed)) /* current max shred idx is 32KB = 2 << 15*/
#define MAP_MULTI 1
#include "../../util/tmpl/fd_map_chain.c"
/* clang-format on */

struct fd_blockstore_slot_meta_map {
  ulong          slot;
  fd_slot_meta_t slot_meta;
  uint           hash;
};
typedef struct fd_blockstore_slot_meta_map fd_blockstore_slot_meta_map_t;

#define MAP_NAME fd_blockstore_slot_meta_map
#define MAP_T    fd_blockstore_slot_meta_map_t
#define MAP_KEY  slot
#define MAP_KEY_NULL ULONG_MAX
#define MAP_KEY_INVAL(k) (!(k ^ ULONG_MAX))
#include "../../util/tmpl/fd_map_dynamic.c"

/* A shred that has been deshredded and is part of a block */
/* clang-format off */
struct __attribute__((aligned(128UL))) fd_blockstore_shred {
  fd_shred_t hdr; /* ptr to the data shred header */
  ulong      off; /* offset to the payload relative to the start of the block's data region */
};
typedef struct fd_blockstore_shred fd_blockstore_shred_t;
/* clang-format on */

/* An entry / microblock that has been parsed and is part of a block */
struct fd_blockstore_micro {
  ulong off; /* offset into block data */
};
typedef struct fd_blockstore_micro fd_blockstore_micro_t;

/* A reference to a transaction in a block */
struct fd_blockstore_txn_ref {
  ulong txn_off; /* offset into block data of transaction */
  ulong id_off;  /* offset into block data of transaction identifiers */
  ulong sz;
};
typedef struct fd_blockstore_txn_ref fd_blockstore_txn_ref_t;

struct fd_blockstore_block {
  ulong     shreds_gaddr; /* ptr to the list of fd_blockstore_shred_t */
  ulong     shreds_cnt;
  ulong     micros_gaddr; /* ptr to the list of fd_blockstore_micro_t */
  ulong     micros_cnt;
  ulong     txns_gaddr; /* ptr to the list of fd_blockstore_txn_ref_t */
  ulong     txns_cnt;
  long      ts;         /* timestamp in nanosecs */
  ulong     data_gaddr; /* ptr to the beginning of the block's allocated data region */
  ulong     sz;         /* block size */
  ulong     height;     /* block height */
  fd_hash_t bank_hash;
  uint      flags;
};
typedef struct fd_blockstore_block fd_blockstore_block_t;

struct fd_blockstore_block_map {
  ulong                 slot;
  uint                  hash; /* internal hash used by `fd_map.c`, _not_ the blockhash */
  fd_blockstore_block_t block;
};
typedef struct fd_blockstore_block_map fd_blockstore_block_map_t;

#define MAP_NAME fd_blockstore_block_map
#define MAP_T    fd_blockstore_block_map_t
#define MAP_KEY  slot
#define MAP_KEY_NULL ULONG_MAX
#define MAP_KEY_INVAL(k) (!(k ^ ULONG_MAX))
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_blockstore_txn_key {
  ulong v[FD_ED25519_SIG_SZ / sizeof( ulong )];
};
typedef struct fd_blockstore_txn_key fd_blockstore_txn_key_t;

struct fd_blockstore_txn_map {
  fd_blockstore_txn_key_t sig;
  uint                    hash;
  ulong                   slot;
  ulong                   offset;
  ulong                   sz;
  ulong                   meta_gaddr; /* ptr to the transaction metadata */
  ulong                   meta_sz;    /* metadata size */
  int                     meta_owned; /* does this entry "own" the metadata */
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

// TODO make this private
struct __attribute__( ( aligned( FD_BLOCKSTORE_ALIGN ) ) ) fd_blockstore {

  /* Metadata */

  ulong magic;
  ulong blockstore_gaddr;
  ulong wksp_tag;
  ulong seed;
  fd_readwrite_lock_t lock;

  /* Slot metadata */

  ulong root; /* the current root slot */
  ulong min;  /* the min slot still in the blockstore */
  ulong max;  /* the max slot in the blockstore */

  /* Internal data structures */

  ulong tmp_shred_max;        /* max number of temporary shreds */
  ulong tmp_shred_pool_gaddr; /* pool of temporary shreds */
  ulong tmp_shred_map_gaddr;  /* map of (slot, shred_idx)->shred */

  int   lg_slot_max;
  ulong slot_meta_map_gaddr; /* map of slot->slot_meta */
  ulong block_map_gaddr;
  ulong slot_history_max;    /* maximum block history */
  ulong slot_history_max_with_slop; /* maximum block history with some padding */

  int   lg_txn_max;
  ulong txn_map_gaddr;

  /* The blockstore alloc is used for allocating wksp resources for shred headers, microblock
     headers, and blocks.  This is a fd_alloc. Allocations from this allocator will be tagged with
     wksp_tag and operations on this allocator will use concurrency group 0. */

  ulong alloc_gaddr;
};
typedef struct fd_blockstore fd_blockstore_t;

FD_PROTOTYPES_BEGIN

/* fd_blockstore_{align,footprint} return FD_BLOCKSTORE_{ALIGN,FOOTPRINT}. */

FD_FN_CONST ulong
fd_blockstore_align( void );

FD_FN_CONST ulong
fd_blockstore_footprint( void );

void *
fd_blockstore_new( void * shmem,
                   ulong  wksp_tag,
                   ulong  seed,
                   ulong  tmp_shred_max,
                   int    lg_txn_max,
                   ulong  slot_history_max );

fd_blockstore_t *
fd_blockstore_join( void * shblockstore );

void *
fd_blockstore_leave( fd_blockstore_t * blockstore );

void *
fd_blockstore_delete( void * shblockstore );

/* Accessors */

/* fd_blockstore_wksp returns the local join to the wksp backing the blockstore.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes blockstore is a current local join. */

FD_FN_PURE static inline fd_wksp_t *
fd_blockstore_wksp( fd_blockstore_t * blockstore ) {
  return (fd_wksp_t *)( ( (ulong)blockstore ) - blockstore->blockstore_gaddr );
}

/* fd_blockstore_wksp_tag returns the workspace allocation tag used by the
   blockstore for its wksp allocations.  Will be positive.  Assumes blockstore is a
   current local join. */

FD_FN_PURE static inline ulong
fd_blockstore_wksp_tag( fd_blockstore_t * blockstore ) {
  return blockstore->wksp_tag;
}

/* fd_blockstore_seed returns the hash seed used by the blockstore for various hash
   functions.  Arbitrary value.  Assumes blockstore is a current local join.
   TODO: consider renaming hash_seed? */
FD_FN_PURE static inline ulong
fd_blockstore_seed( fd_blockstore_t * blockstore ) {
  return blockstore->seed;
}

/* fd_blockstore_block_data_laddr returns a local pointer to the block's data. The returned pointer
 * lifetime is until the block is removed. Check return value for error info. */
FD_FN_PURE static inline uchar *
fd_blockstore_block_data_laddr( fd_blockstore_t * blockstore, fd_blockstore_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );
}

/* Operations */

/* Insert shred into the blockstore, fast O(1).  Fail if this shred is already in the blockstore or
 * the blockstore is full. Returns an error code indicating success or
 * failure. slot_meta_opt can be NULL if not known.
 *
 * TODO eventually this will need to support "upsert" duplicate shred handling
 */
int
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_slot_meta_t * slot_meta_opt, fd_shred_t const * shred );

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

/* Get the final poh hash for a given slot */
uchar const *
fd_blockstore_block_query_hash( fd_blockstore_t * blockstore, ulong slot );

/* Get the bank hash for a given slot */
uchar const *
fd_blockstore_block_query_bank_hash( fd_blockstore_t * blockstore, ulong slot );

/* Query blockstore for slot_meta at slot. Returns a pointer to the slot_meta or NULL if not in
 * blockstore. The returned pointer lifetime is until the slot meta is removed. Check return value
 * for error info. */
fd_slot_meta_t *
fd_blockstore_slot_meta_query( fd_blockstore_t * blockstore, ulong slot );

/* Return the slot of the parent block */
ulong
fd_blockstore_slot_parent_query( fd_blockstore_t * blockstore, ulong slot );

/* Returns the transaction data for the given signature */
fd_blockstore_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[FD_ED25519_SIG_SZ] );

/* Delete a block slot */
int
fd_blockstore_remove_slot( fd_blockstore_t * blockstore, ulong slot );

/* Discard all the unassembled shreds for a block */
int
fd_blockstore_discard_shreds( fd_blockstore_t * blockstore, ulong slot );

/* Remove the all slots less than min_slots from blockstore by
   removing them from all relevant internal structures. Used to maintain
   invariant `min_slot = max_slot - FD_BLOCKSTORE_SLOT_HISTORY_MAX`. */
int
fd_blockstore_remove_before( fd_blockstore_t * blockstore, ulong min_slot );

/* Set the height for a block */
void
fd_blockstore_set_height( fd_blockstore_t * blockstore,
                          ulong slot,
                          ulong block_height );

/* Acquire a read lock */
static inline void
fd_blockstore_start_read( fd_blockstore_t * blockstore ) {
  fd_readwrite_start_read( &blockstore->lock );
}

/* Release a read lock */
static inline void
fd_blockstore_end_read( fd_blockstore_t * blockstore ) {
  fd_readwrite_end_read( &blockstore->lock );
}

/* Acquire a write lock */
static inline void
fd_blockstore_start_write( fd_blockstore_t * blockstore ) {
  fd_readwrite_start_write( &blockstore->lock );
}

/* Release a write lock */
static inline void
fd_blockstore_end_write( fd_blockstore_t * blockstore ) {
  fd_readwrite_end_write( &blockstore->lock );
}

void
fd_blockstore_log_block_status( fd_blockstore_t * blockstore, ulong around_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_h */
