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

#define FD_BLOCKSTORE_ALIGN     ( 128UL )
#define FD_BLOCKSTORE_FOOTPRINT ( 256UL )

#define FD_BLOCKSTORE_MAGIC ( 0xf17eda2ce7b10c00UL ) /* firedancer bloc version 0 */

#define FD_BLOCKSTORE_SLOT_HISTORY_MAX ( 1UL << 13UL )
#define FD_BLOCKSTORE_BLOCK_SZ_MAX     ( FD_SHRED_MAX_SZ * ( 1 << 15UL ) )

/* TODO think more about these */
#define FD_BLOCKSTORE_NEXT_SLOT_MAX ( 32UL ) /* the maximum # of children a slot can have */
#define FD_BLOCKSTORE_EQV_MAX       ( 32UL ) /* the maximum # of equivocating blocks in a slot */

// TODO centralize these
// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/clock.rs#L34
#define FD_MS_PER_TICK 6

// https://github.com/firedancer-io/solana/blob/v1.17.5/core/src/repair/repair_service.rs#L55
#define FD_REPAIR_TIMEOUT ( 200 / FD_MS_PER_TICK )

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
#define FD_BLOCKSTORE_ERR_UNKNOWN         -10

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

/* fd_blockstore_shred is a thin wrapper around fd_shred_t that supports pooling and mapping data
   shreds that have yet to be assembled into a block. Turbine and Repair can both send shreds
   out-of-order, so these shreds need to be stored and indexed in temporary buffers in the
   blockstore.

   The blockstore only processes data shreds. Parity shreds are handled by a separate layer, the FEC
   set resolver.

   Shreds are buffered into a map as they are received:

   | 0 | 1 | 2 | x | x | 5 | x |
             ^           ^
             c           r

   c = "consumed" = contiguous window starting from index 0
   r = "received" = highest index received so far

   Shred memory layout while stored in the map:

   | shred hdr | shred payload |
*/
struct fd_blockstore_shred {
  fd_shred_key_t key;
  ulong          next;
  union {
    fd_shred_t hdr;                  /* data shred header */
    uchar      raw[FD_SHRED_MAX_SZ]; /* the data shred as raw bytes, both header and payload. */
  };
};
typedef struct fd_blockstore_shred fd_blockstore_shred_t;

#define POOL_NAME fd_blockstore_shred_pool
#define POOL_T    fd_blockstore_shred_t
#include "../../util/tmpl/fd_pool.c"

/* clang-format off */
#define MAP_NAME               fd_blockstore_shred_map
#define MAP_ELE_T              fd_blockstore_shred_t
#define MAP_KEY_T              fd_shred_key_t
#define MAP_KEY_EQ(k0,k1)      FD_SHRED_KEY_EQ(*k0,*k1)
#define MAP_KEY_HASH(key,seed) (FD_SHRED_KEY_HASH(*key) ^ seed)
#define MAP_MULTI 1
#include "../../util/tmpl/fd_map_chain.c"
/* clang-format on */

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

/* If the 0th bit is set, this indicates the block is prepared, and about to be executed.
   Blockstore clients should be careful not to modify or remove blocks while this flag is set.
   
   The remaining flags are mainly metadata. */
#define FD_BLOCK_FLAG_PREPARED  0 /* xxxxxxx1 */
#define FD_BLOCK_FLAG_PROCESSED 1 /* xxxxxx1x */
#define FD_BLOCK_FLAG_EQV_SAFE  2 /* xxxxx1xx */
#define FD_BLOCK_FLAG_CONFIRMED 3 /* xxxx1xxx */
#define FD_BLOCK_FLAG_ROOTED    4 /* xxx1xxxx */
#define FD_BLOCK_FLAG_FINALIZED 5 /* xx1xxxxx */
#define FD_BLOCK_FLAG_GENESIS   6 /* x1xxxxxx */
#define FD_BLOCK_FLAG_SNAPSHOT  7 /* 1xxxxxxx */

struct fd_block {

  /* metadata region */

  long      ts;         /* timestamp in nanosecs */
  ulong     height;     /* block height */
  fd_hash_t bank_hash;
  uchar     flags;

  /* data region

  A block's data region is indexed to support iterating by shred, microblock, or
  transaction. This is done by iterating the headers for each, stored in allocated memory. To
  iterate shred payloads, for example, a caller should iterate the headers in tandem with the data region
  (offsetting by the bytes indicated in the shred header).

  Note random access of individual shred indices is not performant, due to the variable-length
  nature of shreds. */

  ulong data_gaddr;   /* ptr to the beginning of the block's allocated data region */
  ulong data_sz;      /* block size */
  ulong shreds_gaddr; /* ptr to the list of fd_blockstore_shred_t */
  ulong shreds_cnt;
  ulong micros_gaddr; /* ptr to the list of fd_blockstore_micro_t */
  ulong micros_cnt;
  ulong txns_gaddr; /* ptr to the list of fd_blockstore_txn_ref_t */
  ulong txns_cnt;
};
typedef struct fd_block fd_block_t;

struct fd_blockstore_slot_map {
  ulong          slot;
  uint           hash;
  fd_slot_meta_t slot_meta;
  fd_block_t     block;
};
typedef struct fd_blockstore_slot_map fd_blockstore_slot_map_t;

/* clang-format off */
#define MAP_NAME         fd_blockstore_slot_map
#define MAP_T            fd_blockstore_slot_map_t
#define MAP_KEY          slot
#define MAP_KEY_NULL     ULONG_MAX
#define MAP_KEY_INVAL(k) (!(k^ULONG_MAX))
#include "../../util/tmpl/fd_map_dynamic.c"
/* clang-format on */

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
  ulong min;  /* the min slot still in the blockstore */
  ulong max;  /* the max slot in the blockstore */
  ulong smr; /* the super-majority root */

  /* Internal data structures */

  ulong shred_max;        /* max number of temporary shreds */
  ulong shred_pool_gaddr; /* pool of temporary shreds */
  ulong shred_map_gaddr;  /* map of (slot, shred_idx)->shred */

  int   lg_slot_max;
  ulong slot_max;           /* maximum block history */
  ulong slot_max_with_slop; /* maximum block history with some padding */
  ulong slot_map_gaddr;     /* map of slot->(slot_meta, block) */

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

/* fd_blockstore_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as blockstore with depth
   entries.  align returns FD_BLOCKSTORE_ALIGN. lg_txn_max is assumed to be an
   integer greater than or equal to zero. */

FD_FN_CONST ulong
fd_blockstore_align( void );

FD_FN_CONST ulong
fd_blockstore_footprint( void );

/* fd_blockstore_new formats an unused memory region for use as a blockstore.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  depth is the number of
   cache entries (should be an integer power of 2 >= FD_BLOCKSTORE_BLOCK).
   The blockstore will also have an app_sz byte application region for
   application specific usage.  seq0 is the initial fragment sequence
   number a producer should use for this blockstore.

   The cache entries will be initialized such all queries for any
   sequence number will fail immediately after creation.  They will
   further be initialized such that for any consumer initialized to
   start receiving a sequence number at or after seq0 will think it is
   ahead of the producer (such that it will wait for its sequence number
   cleanly instead of immediately trying to recover a gap).  Conversely,
   consumers initialized to start receiving a sequence number before
   seq0 will think they are behind the producer (thus realize it is been
   incorrectly initialized and can recover appropriately).  Anybody who
   looks at the blockstore entries directly will also see the entries are
   initialized to have zero sz (such that they shouldn't try deference
   any fragment payloads), have the SOM and EOM bits set (so they
   shouldn't try to interpret the entry as part of some message spread
   over multiple fragments) and have the ERR bit set (so they don't
   think there is any validity to the meta data or payload).

   The application region will be initialized to zero.

   Returns shmem (and the memory region it points to will be formatted
   as a blockstore, caller is not joined) on success and NULL on failure
   (logs details).  Reasons for failure include obviously bad shmem or
   bad depth. */
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

/* fd_blockstore_shred_pool returns a pointer in the caller's address space to the blockstore's
 * tmp shred pool. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
FD_FN_PURE static inline fd_blockstore_shred_t *
fd_blockstore_shred_pool( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_shred_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                      blockstore->shred_pool_gaddr );
}

/* fd_blockstore_shred_map returns a pointer in the caller's address space to the blockstore's
 * tmp shred map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
FD_FN_PURE static inline fd_blockstore_shred_map_t *
fd_blockstore_shred_map( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_shred_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                          blockstore->shred_map_gaddr );
}

/* fd_blockstore_slot_map returns a pointer in the caller's address space to the blockstore's
 * slot map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
FD_FN_PURE static inline fd_blockstore_slot_map_t *
fd_blockstore_slot_map( fd_blockstore_t * blockstore ) {
  return (fd_blockstore_slot_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                         blockstore->slot_map_gaddr );
}

/* fd_blockstore_txn_map returns a pointer in the caller's address space to the blockstore's
 * block map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
 * local join. */
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
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred );

/* Query blockstore for shred at slot, shred_idx. Returns a pointer to the shred or NULL if not in
 * blockstore. The returned pointer lifetime is until the shred is removed. Check return value for
 * error info. This API only works for shreds from incomplete blocks.
 *
 * Callers should hold the read lock during the entirety of its read to ensure the pointer remains
 * valid.
 */
fd_shred_t *
fd_blockstore_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx );

/* Query blockstore for shred at slot, shred_idx. Copies the shred
 * data to the given buffer and returns the data size. Returns -1 on failure.
 *
 * Callers should hold the read lock during the entirety of this call.
 */
long
fd_blockstore_shred_query_copy_data( fd_blockstore_t * blockstore, ulong slot, uint shred_idx, void * buf, ulong buf_max );

/* Query blockstore for block at slot. Returns a pointer to the block or NULL if not in
 * blockstore. The returned pointer lifetime is until the block is removed. Check return value for
 * error info. */
fd_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot );

/* Query blockstore for the block hash at slot. This is the final poh hash for a slot. */
fd_hash_t const *
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot );

/* Query blockstore for the bank hash for a given slot. */
fd_hash_t const *
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot );

/* Query blockstore for slot meta at slot. Returns a pointer to the slot meta or NULL if not in
   blockstore. The returned pointer lifetime is until the slot meta is removed. */
fd_slot_meta_t *
fd_blockstore_slot_meta_query( fd_blockstore_t * blockstore, ulong slot );

/* Query the parent slot of slot. */
ulong
fd_blockstore_parent_slot_query( fd_blockstore_t * blockstore, ulong slot );

/* Query the child slots of slot. `next_slot_out` must be at least   */
int
fd_blockstore_next_slot_query( fd_blockstore_t * blockstore, ulong slot , ulong ** next_slot_out, ulong * next_slot_len_out);

/* Query the frontier ie. all the blocks that need to be replayed that haven't been. These are the
   slot children of the current frontier that are shred complete. */
fd_block_t *
fd_blockstore_block_frontier_query( fd_blockstore_t * blockstore,
                                    ulong *           parents,
                                    ulong             parents_sz );

/* Query the transaction data for the given signature */
fd_blockstore_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[FD_ED25519_SIG_SZ] );

/* Remove slot from blockstore, including all relevant internal structures. */
int
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot );

/* Remove all the unassembled shreds for a slot */
int
fd_blockstore_buffered_shreds_remove( fd_blockstore_t * blockstore, ulong slot );

/* Remove all slots less than min_slots from blockstore by
   removing them from all relevant internal structures. Used to maintain
   invariant `min_slot = max_slot - FD_BLOCKSTORE_SLOT_HISTORY_MAX`. */
int
fd_blockstore_slot_history_remove( fd_blockstore_t * blockstore, ulong min_slot );

/* Clear out the blockstore, removing all slots. */
int
fd_blockstore_clear( fd_blockstore_t * blockstore );

/* Determine if a slot is ancient and we should ignore shreds. */
static inline int
fd_blockstore_is_slot_ancient( fd_blockstore_t * blockstore, ulong slot ) {
  return ( slot + blockstore->slot_max <= blockstore->max );
}

/* Set the block height. */
void
fd_blockstore_block_height_set( fd_blockstore_t * blockstore, ulong slot, ulong block_height );

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

void
fd_blockstore_log_mem_usage( fd_blockstore_t * blockstore );

void
fd_blockstore_snapshot_insert( fd_blockstore_t * blockstore, fd_slot_bank_t const * slot_bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_h */
