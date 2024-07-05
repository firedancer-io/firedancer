#ifndef HEADER_fd_src_flamenco_runtime_fd_blockstore_h
#define HEADER_fd_src_flamenco_runtime_fd_blockstore_h

/* Blockstore is a high-performance database for storing, building, and tracking blocks.

   `fd_blockstore` defines a number of useful types e.g. `fd_block_t`, `fd_block_shred`, etc. */

#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/shred/fd_deshredder.h"
#include "../../ballet/shred/fd_shred.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "fd_readwrite_lock.h"
#include "stdbool.h"

/* FD_BLOCKSTORE_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a blockstore.  ALIGN should be a positive integer power of 2.
   FOOTPRINT is multiple of ALIGN.  These are provided to facilitate
   compile time declarations.  */

/* clang-format off */
#define FD_BLOCKSTORE_ALIGN        (128UL)
#define FD_BLOCKSTORE_FOOTPRINT    (256UL)
#define FD_BLOCKSTORE_MAGIC        (0xf17eda2ce7b10c00UL) /* firedancer bloc version 0 */

/* DO NOT MODIFY. */
#define FD_BUF_SHRED_MAP_MAX (1UL << 24UL) /* 16 million shreds can be buffered */
#define FD_TXN_MAP_LG_MAX    (24)          /* 16 million txns can be stored in the txn map */

/* TODO this can be removed if we explicitly manage a memory pool for
   the fd_block_map_t entries */
#define FD_BLOCKSTORE_CHILD_SLOT_MAX (32UL) /* the maximum # of children a slot can have */

// TODO centralize these
// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/clock.rs#L34
#define FD_MS_PER_TICK 6

// https://github.com/firedancer-io/solana/blob/v1.17.5/core/src/repair/repair_service.rs#L55
#define FD_REPAIR_TIMEOUT (200 / FD_MS_PER_TICK)

#define FD_BLOCKSTORE_OK                  0
#define FD_BLOCKSTORE_OK_SLOT_COMPLETE    1
#define FD_BLOCKSTORE_ERR_SHRED_FULL      -1 /* no space left for shreds */
#define FD_BLOCKSTORE_ERR_SLOT_FULL       -2 /* no space left for slots */
#define FD_BLOCKSTORE_ERR_TXN_FULL        -3 /* no space left for txns */
#define FD_BLOCKSTORE_ERR_SHRED_MISSING   -4
#define FD_BLOCKSTORE_ERR_SLOT_MISSING    -5
#define FD_BLOCKSTORE_ERR_TXN_MISSING     -6
#define FD_BLOCKSTORE_ERR_SHRED_INVALID   -7 /* shred was invalid */
#define FD_BLOCKSTORE_ERR_DESHRED_INVALID -8 /* deshredded block was invalid */
#define FD_BLOCKSTORE_ERR_NO_MEM          -9 /* no mem */
#define FD_BLOCKSTORE_ERR_UNKNOWN         -99

/* clang-format on */

struct fd_shred_key {
  ulong slot;
  uint  idx;
};
typedef struct fd_shred_key fd_shred_key_t;

/* clang-format off */
static const fd_shred_key_t     fd_shred_key_null = { 0 };
#define FD_SHRED_KEY_NULL       fd_shred_key_null
#define FD_SHRED_KEY_INVAL(key) (!((key).slot) & !((key).idx))
#define FD_SHRED_KEY_EQ(k0,k1)  (!(((k0).slot) ^ ((k1).slot))) & !(((k0).idx) ^ (((k1).idx)))
#define FD_SHRED_KEY_HASH(key)  ((uint)(((key).slot)<<15UL) | (((key).idx))) /* current max shred idx is 32KB = 2 << 15*/
/* clang-format on */

/* fd_buf_shred is a thin wrapper around fd_shred_t that facilitates
   buffering data shreds before all the shreds for a slot have been
   received. After all shreds are received, these buffered shreds are
   released back into memory pool and future queries for the shreds are
   offset into the block data directly.

   The blockstore is only aware of data shreds and all APIs involving
   shreds refers to data shreds.

   Shreds are buffered into a map as they are received:

   | 0 | 1 | 2 | x | x | 5 | x |
             ^           ^
             c           r

   c = "consumed" = contiguous window starting from index 0
   r = "received" = highest index received so far

   Shred memory layout while stored in the map:

   | shred hdr | shred payload |
*/
struct fd_buf_shred {
  fd_shred_key_t key;
  ulong          next;
  union {
    fd_shred_t hdr;                  /* data shred header */
    uchar      raw[FD_SHRED_MAX_SZ]; /* the data shred as raw bytes, both header and payload. */
  };
};
typedef struct fd_buf_shred fd_buf_shred_t;

#define POOL_NAME fd_buf_shred_pool
#define POOL_T    fd_buf_shred_t
#include "../../util/tmpl/fd_pool.c"

/* clang-format off */
#define MAP_NAME               fd_buf_shred_map
#define MAP_ELE_T              fd_buf_shred_t
#define MAP_KEY_T              fd_shred_key_t
#define MAP_KEY_EQ(k0,k1)      FD_SHRED_KEY_EQ(*k0,*k1)
#define MAP_KEY_HASH(key,seed) (FD_SHRED_KEY_HASH(*key) ^ seed)
#define MAP_MULTI 1
#include "../../util/tmpl/fd_map_chain.c"
/* clang-format on */

#define DEQUE_NAME fd_blockstore_slot_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

/* A shred that has been deshredded and is part of a block (beginning at off) */
struct fd_block_shred {
  fd_shred_t hdr; /* ptr to the data shred header */
  uchar      merkle[FD_SHRED_MERKLE_ROOT_SZ + FD_SHRED_MERKLE_NODE_SZ*9U /* FD_FEC_SET_MAX_BMTREE_DEPTH */];
  ulong      merkle_sz;
  ulong      off; /* offset to the payload relative to the start of the block's data region */
};
typedef struct fd_block_shred fd_block_shred_t;

/* A microblock (otherwise known as an "entry" in Solana parlance) that has been parsed and is part
   of a block (beginning at off) */
struct fd_block_micro {
  ulong off; /* offset into block data */
};
typedef struct fd_block_micro fd_block_micro_t;

/* A transaction that has been parsed and is part of a block (beginning at txn_off) */
struct fd_block_txn_ref {
  ulong txn_off; /* offset into block data of transaction */
  ulong id_off;  /* offset into block data of transaction identifiers */
  ulong sz;
};
typedef struct fd_block_txn_ref fd_block_txn_ref_t;

/* If the 0th bit is set, this indicates the block is preparing, which
   means it might be partially executed e.g. a subset of the microblocks
   have been executed.  It is not safe to remove, relocate, or modify
   the block in any way at this time.

   Callers holding a pointer to a block should always make sure to
   inspect this flag.

   Other flags mainly provide useful metadata for read-only callers, eg.
   RPC. */

#define FD_BLOCK_FLAG_PREPARING 0 /* xxxxxxx1 */
#define FD_BLOCK_FLAG_PROCESSED 1 /* xxxxxx1x */
#define FD_BLOCK_FLAG_CONFIRMED 2 /* xxxxx1xx */
#define FD_BLOCK_FLAG_FINALIZED 3 /* xxxx1xxx */

/* Remaining bits [4, 8) are reserved.

   To avoid confusion, please use `fd_bits.h` API
   ie. `fd_uchar_set_bit`, `fd_uchar_extract_bit`. */

struct fd_block {

  /* data region

  A block's data region is indexed to support iterating by shred, microblock, or
  transaction. This is done by iterating the headers for each, stored in allocated memory. To
  iterate shred payloads, for example, a caller should iterate the headers in tandem with the data region
  (offsetting by the bytes indicated in the shred header).

  Note random access of individual shred indices is not performant, due to the variable-length
  nature of shreds. */

  ulong data_gaddr;   /* ptr to the beginning of the block's allocated data region */
  ulong data_sz;      /* block size */
  ulong shreds_gaddr; /* ptr to the first fd_block_shred_t */
  ulong shreds_cnt;
  ulong micros_gaddr; /* ptr to the list of fd_blockstore_micro_t */
  ulong micros_cnt;
  ulong txns_gaddr; /* ptr to the list of fd_blockstore_txn_ref_t */
  ulong txns_cnt;
};
typedef struct fd_block fd_block_t;

struct fd_block_map {
  ulong slot; /* map key */
  ulong next; /* reserved for use by fd_map_giant.c */

  /* Ancestry */

  ulong parent_slot;
  ulong child_slots[FD_BLOCKSTORE_CHILD_SLOT_MAX];

  /* Metadata */

  ulong     height;
  fd_hash_t block_hash;
  fd_hash_t bank_hash;
  uchar     flags;
  uchar     reference_tick; /* the tick when the leader prepared the block. */
  long      ts;             /* the wallclock time when we finished receiving the block. */

  /* Windowing */

  uint consumed_idx; /* the highest shred idx of the contiguous window from idx 0. */
  uint received_idx; /* the highest shred idx we've received. */
  uint complete_idx; /* the shred idx with the FD_SHRED_DATA_FLAG_SLOT_COMPLETE flag set. */

  /* Block */

  ulong block_gaddr; /* global address to the start of the allocated fd_block_t */
};
typedef struct fd_block_map fd_block_map_t;

/* clang-format off */
#define MAP_NAME         fd_block_map
#define MAP_T            fd_block_map_t
#define MAP_KEY          slot
#include "../../util/tmpl/fd_map_giant.c"
/* clang-format on */

struct fd_blockstore_txn_key {
  ulong v[FD_ED25519_SIG_SZ / sizeof( ulong )];
};
typedef struct fd_blockstore_txn_key fd_blockstore_txn_key_t;

struct fd_blockstore_txn_map {
  fd_blockstore_txn_key_t sig;
  ulong                   next;
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
int fd_blockstore_txn_key_equal(fd_blockstore_txn_key_t const * k0, fd_blockstore_txn_key_t const * k1);
#define MAP_KEY_EQ(k0,k1)    fd_blockstore_txn_key_equal(k0,k1)
ulong fd_blockstore_txn_key_hash(fd_blockstore_txn_key_t const * k, ulong seed);
#define MAP_KEY_HASH(k,seed) fd_blockstore_txn_key_hash(k, seed)
#include "../../util/tmpl/fd_map_giant.c"

// TODO make this private
struct __attribute__((aligned(FD_BLOCKSTORE_ALIGN))) fd_blockstore_private {

  /* Metadata */

  ulong magic;
  ulong blockstore_gaddr;
  ulong wksp_tag;
  ulong seed;

  /* Concurrency */

  fd_readwrite_lock_t lock;

  /* Slot metadata */

  ulong root; /* the current root slot */

  /* Internal data structures */

  ulong shred_max;        /* max number of temporary shreds */
  ulong shred_pool_gaddr; /* pool of temporary shreds */
  ulong shred_map_gaddr;  /* map of (slot, shred_idx)->shred */

  ulong slot_max;           /* maximum # of blocks. */
  ulong slot_map_gaddr;     /* map of slot->(slot_meta, block) */
  ulong slot_deque_gaddr;   /* deque of slots (ulongs). used to traverse blockstore ancestry. */

  int   lg_txn_max;
  ulong txn_map_gaddr;

  /* The blockstore alloc is used for allocating wksp resources for shred headers, microblock
     headers, and blocks.  This is an fd_alloc. Allocations from this allocator will be tagged with
     wksp_tag and operations on this allocator will use concurrency group 0. */

  ulong alloc_gaddr;
};
/* clang-format on */

struct fd_blockstore_private;
typedef struct fd_blockstore_private fd_blockstore_t;

FD_PROTOTYPES_BEGIN

/* Construction API */

/* TODO document lifecycle methods */

FD_FN_CONST ulong
fd_blockstore_align( void );

FD_FN_CONST ulong
fd_blockstore_footprint( void );

void *
fd_blockstore_new( void * shmem,
                   ulong  wksp_tag,
                   ulong  seed,
                   ulong  shred_max,
                   ulong  slot_max,
                   int    lg_txn_max );

fd_blockstore_t *
fd_blockstore_join( void * shblockstore );

void *
fd_blockstore_leave( fd_blockstore_t * blockstore );

void *
fd_blockstore_delete( void * shblockstore );

/* fd_blockstore_init initializes a blockstore with slot_bank. slot_bank
   should be the bank upon finishing a snapshot load if booting from a
   snapshot, genesis bank otherwise.  Blockstore then initializes fields
   and creates a mock block using this slot bank.  This metadata for
   this block's slot will be populated (fd_block_map_t) but the actual
   block data (fd_block_t) won't exist.  This is needed to bootstrap the
   various componenets for live replay (turbine, repair, etc.) */

fd_blockstore_t * 
fd_blockstore_init( fd_blockstore_t * blockstore, fd_slot_bank_t const * slot_bank );

/* Accessor API */

/* fd_blockstore_wksp returns the local join to the wksp backing the
   blockstore. The lifetime of the returned pointer is at least as long
   as the lifetime of the local join.  Assumes blockstore is a current
   local join. */

FD_FN_PURE static inline fd_wksp_t *
fd_blockstore_wksp( fd_blockstore_t * blockstore ) {
  return (fd_wksp_t *)( ( (ulong)blockstore ) - blockstore->blockstore_gaddr );
}

/* fd_blockstore_wksp_tag returns the workspace allocation tag used by
   the blockstore for its wksp allocations.  Will be positive.  Assumes
   blockstore is a current local join. */

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

/* fd_blockstore_buf_shred_pool returns a pointer in the caller's
   address space to the pool pointer fd_buf_shred_t * in the blockstore
   wksp.  Assumes blockstore is local join.  Lifetime of the returned
   pointer is that of the local join. */

FD_FN_PURE static inline fd_buf_shred_t *
fd_blockstore_buf_shred_pool( fd_blockstore_t * blockstore ) {
  return (fd_buf_shred_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                               blockstore->shred_pool_gaddr );
}

/* fd_blockstore_buf_shred_map returns a pointer in the caller's address
   space to the fd_buf_shred_map_t * in the blockstore wksp.  Assumes
   blockstore is local join.  Lifetime of the returned pointer is that
   of the local join. */

FD_FN_PURE static inline fd_buf_shred_map_t *
fd_blockstore_buf_shred_map( fd_blockstore_t * blockstore ) {
  return (fd_buf_shred_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                   blockstore->shred_map_gaddr );
}

/* fd_block_map returns a pointer in the caller's address space to the
   fd_block_map_t in the blockstore wksp.  Assumes blockstore is local
   join.  Lifetime of the returned pointer is that of the local join. */
FD_FN_PURE static inline fd_block_map_t *
fd_blockstore_block_map( fd_blockstore_t * blockstore ) {
  return (fd_block_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                               blockstore->slot_map_gaddr );
}

/* fd_blockstore_txn_map returns a pointer in the caller's address space to the blockstore's
   block map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
   local join. */

FD_FN_PURE static inline fd_blockstore_txn_map_t *
fd_blockstore_txn_map( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_txn_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                        blockstore->txn_map_gaddr );
}

/* fd_blockstore_alloc returns a pointer in the caller's address space to
   the blockstore's allocator. */

FD_FN_PURE static inline fd_alloc_t * /* Lifetime is that of the local join */
fd_blockstore_alloc( fd_blockstore_t * blockstore ) {
  return (fd_alloc_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                           blockstore->alloc_gaddr );
}

/* fd_blockstore_block_data_laddr returns a local pointer to the block's data. The returned pointer
 * lifetime is until the block is removed. Check return value for error info. */

FD_FN_PURE static inline uchar *
fd_blockstore_block_data_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );
}

/* Operations */

/* Insert shred into the blockstore, fast O(1).  Fail if this shred is already in the blockstore or
 * the blockstore is full. Returns an error code indicating success or failure.
 *
 * TODO eventually this will need to support "upsert" duplicate shred handling.
 */
int
fd_buf_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred );

/* Query blockstore for shred at slot, shred_idx. Returns a pointer to the shred or NULL if not in
 * blockstore. The returned pointer lifetime is until the shred is removed. Check return value for
 * error info. This API only works for shreds from incomplete blocks.
 *
 * Callers should hold the read lock during the entirety of its read to ensure the pointer remains
 * valid.
 */
fd_shred_t *
fd_buf_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx );

/* Query blockstore for shred at slot, shred_idx. Copies the shred
 * data to the given buffer and returns the data size. Returns -1 on failure.
 *
 * Callers should hold the read lock during the entirety of this call.
 */
long
fd_buf_shred_query_copy_data( fd_blockstore_t * blockstore,
                              ulong             slot,
                              uint              shred_idx,
                              void *            buf,
                              ulong             buf_max );

/* Query blockstore for block at slot. Returns a pointer to the block or NULL if not in
 * blockstore. The returned pointer lifetime is until the block is removed. Check return value for
 * error info. */
fd_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot );

/* Query blockstore for the block hash at slot. This is the final poh
hash for a slot. */
fd_hash_t const *
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot );

/* Query blockstore for the bank hash for a given slot. */
fd_hash_t const *
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot );

/* Query blockstore for the block map entry at slot. Returns a pointer
   to the slot meta or NULL if not in blockstore. The returned pointer
   lifetime is until the slot meta is removed. */
fd_block_map_t *
fd_blockstore_block_map_query( fd_blockstore_t * blockstore, ulong slot );

/* Query the parent slot of slot. */
ulong
fd_blockstore_parent_slot_query( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_child_slots_query returns a pointer in the caller's
   address space to the slot's array of child slots.  NULL if slot is
   not in the blockstore.  The returned slot array is always of the
   fixed size FD_BLOCKSTORE_CHILD_SLOT_MAX and contiguous, so callers
   should use the first occurrence FD_SLOT_NULL to determine the end of
   the array. */

ulong *
fd_blockstore_child_slots_query( fd_blockstore_t * blockstore, ulong slot );

/* Query the frontier ie. all the blocks that need to be replayed that haven't been. These are the
   slot children of the current frontier that are shred complete. */
fd_block_t *
fd_blockstore_block_frontier_query( fd_blockstore_t * blockstore,
                                    ulong *           parents,
                                    ulong             parents_sz );

/* fd_blockstore_block_data_query_volatile queries the block map entry
   (metadata and block data) in a lock-free thread-safe manner that does
   not block writes.  Copies the metadata (fd_block_map_t) into
   block_map_entry_out.  Allocates a new block data (uchar *) using
   alloc, copies the block data into it, and sets the block_data_out
   pointer.  Caller provides the allocator via alloc for the copied
   block data (an allocator is needed because the block data sz is not
   known apriori).  Returns FD_BLOCKSTORE_SLOT_MISSING if slot is
   missing: caller MUST ignore out pointers in this case. Otherwise this
   call cannot fail and returns FD_BLOCKSTORE_OK. */

int
fd_blockstore_block_data_query_volatile( fd_blockstore_t * blockstore, ulong slot, fd_block_map_t * block_map_entry_out, fd_valloc_t alloc, uchar ** block_data_out, ulong * block_data_out_sz );

/* fd_blockstore_block_map_query_volatile is the same as above except it
   only copies out the metadata (fd_block_map_t).  Returns
   FD_BLOCKSTORE_SLOT_MISSING if slot is missing, otherwise
   FD_BLOCKSTORE_OK. */

int
fd_blockstore_block_map_query_volatile( fd_blockstore_t * blockstore, ulong slot, fd_block_map_t * block_map_entry_out );

/* Query the transaction data for the given signature */
fd_blockstore_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[static FD_ED25519_SIG_SZ] );

/* Query the transaction data for the given signature in a thread
   safe manner. The transaction data is copied out. txn_data_out can
   be NULL if you are only interested in the transaction metadata. */
int
fd_blockstore_txn_query_volatile( fd_blockstore_t * blockstore, uchar const sig[static FD_ED25519_SIG_SZ], fd_blockstore_txn_map_t * txn_out, long * blk_ts, uchar * blk_flags, uchar txn_data_out[FD_TXN_MTU] );

/* Remove slot from blockstore, including all relevant internal structures. */
int
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot );

/* Remove all the unassembled shreds for a slot */
int
fd_blockstore_buffered_shreds_remove( fd_blockstore_t * blockstore, ulong slot );

/* Set the block height. */
void
fd_blockstore_block_height_update( fd_blockstore_t * blockstore, ulong slot, ulong block_height );

/* fd_blockstore_publish publishes root to the blockstore, pruning any
   paths that are not in root's subtree.  Removes all blocks in the
   pruned paths.  Returns FD_BLOCKSTORE_OK on success,
   FD_BLOCKSTORE_ERR_X otherwise.  Caller MUST hold the write lock. */
int
fd_blockstore_publish( fd_blockstore_t * blockstore, ulong root_slot );

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

/* fd_blockstore_log_mem_usage logs the memory usage of blockstore in a
human-readable format.  Caller MUST hold the read lock. */
void
fd_blockstore_log_mem_usage( fd_blockstore_t * blockstore );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_h */
