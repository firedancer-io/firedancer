#ifndef HEADER_fd_src_flamenco_runtime_fd_blockstore_h
#define HEADER_fd_src_flamenco_runtime_fd_blockstore_h

/* Blockstore is a high-performance database for in-memory indexing and
   durably storing blocks.

   `fd_blockstore` defines a number of useful types e.g. `fd_block_t`,
   `fd_block_shred`, etc.

   The blockstore alloc is used for allocating wksp resources for shred
   headers, microblock headers, and blocks.  This is an fd_alloc.
   Allocations from this allocator will be tagged with wksp_tag and
   operations on this allocator will use concurrency group 0. */

#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/shred/fd_deshredder.h"
#include "../../ballet/shred/fd_shred.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "fd_rwseq_lock.h"
#include "stdbool.h"
#include <fcntl.h>

/* FD_BLOCKSTORE_ALIGN specifies the alignment needed for blockstore.
   ALIGN is double x86 cache line to mitigate various kinds of false
   sharing (eg. ACLPF adjacent cache line prefetch). */

#define FD_BLOCKSTORE_ALIGN (128UL)

/* FD_BLOCKSTORE_MAGIC defines a magic number for verifying the memory
   of blockstore is not corrupted. */

#define FD_BLOCKSTORE_MAGIC (0xf17eda2ce7b10c00UL) /* firedancer bloc version 0 */

/* DO NOT MODIFY. */
// #define FD_BUF_SHRED_MAP_MAX (1UL << 24UL) /* 16 million shreds can be buffered */

/* TODO this can be removed if we explicitly manage a memory pool for
   the fd_block_map_t entries */
#define FD_BLOCKSTORE_CHILD_SLOT_MAX    (32UL)        /* the maximum # of children a slot can have */
#define FD_BLOCKSTORE_ARCHIVE_MIN_SIZE  (1UL << 26UL) /* 64MB := ceil(MAX_DATA_SHREDS_PER_SLOT*1228) */

/* FD_SLICE_ALIGN specifies the alignment needed for a block slice.
   ALIGN is double x86 cache line to mitigate various kinds of false
   sharing (eg. ACLPF adjacent cache line prefetch). */

#define FD_SLICE_ALIGN (128UL)

/* FD_SLICE_MAX specifies the maximum size of an entry batch. This is
   equivalent to the maximum size of a block (ie. a block with a single
   entry batch). */

#define FD_SLICE_MAX (FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT)

/* 64 ticks per slot, and then one min size transaction per microblock
   for all the remaining microblocks.
   This bound should be used along with the transaction parser and tick
   verifier to enforce the assumptions.
   This is NOT a standalone conservative bound against malicious
   validators.
   A tighter bound could probably be derived if necessary. */

#define FD_MICROBLOCK_MAX_PER_SLOT ((FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT - 64UL*sizeof(fd_microblock_hdr_t)) / (sizeof(fd_microblock_hdr_t)+FD_TXN_MIN_SERIALIZED_SZ) + 64UL) /* 200,796 */
/* 64 ticks per slot, and a single gigantic microblock containing min
   size transactions. */
#define FD_TXN_MAX_PER_SLOT ((FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT - 65UL*sizeof(fd_microblock_hdr_t)) / (FD_TXN_MIN_SERIALIZED_SZ)) /* 272,635 */

// TODO centralize these
// https://github.com/firedancer-io/solana/blob/v1.17.5/sdk/program/src/clock.rs#L34
#define FD_MS_PER_TICK 6

// https://github.com/firedancer-io/solana/blob/v1.17.5/core/src/repair/repair_service.rs#L55
#define FD_REPAIR_TIMEOUT (200 / FD_MS_PER_TICK)

#define FD_BLOCKSTORE_SUCCESS                  0
#define FD_BLOCKSTORE_SUCCESS_SLOT_COMPLETE    1
#define FD_BLOCKSTORE_ERR_INVAL   (-1)
#define FD_BLOCKSTORE_ERR_AGAIN   (-2)
#define FD_BLOCKSTORE_ERR_CORRUPT (-3)
#define FD_BLOCKSTORE_ERR_EMPTY   (-4)
#define FD_BLOCKSTORE_ERR_FULL    (-5)
#define FD_BLOCKSTORE_ERR_KEY     (-6)
#define FD_BLOCKSTORE_ERR_SHRED_FULL      -1 /* no space left for shreds */
#define FD_BLOCKSTORE_ERR_SLOT_FULL       -2 /* no space left for slots */
#define FD_BLOCKSTORE_ERR_SHRED_MISSING   -4
#define FD_BLOCKSTORE_ERR_SLOT_MISSING    -5
#define FD_BLOCKSTORE_ERR_SHRED_INVALID   -7 /* shred was invalid */
#define FD_BLOCKSTORE_ERR_DESHRED_INVALID -8 /* deshredded block was invalid */
#define FD_BLOCKSTORE_ERR_NO_MEM          -9 /* no mem */
#define FD_BLOCKSTORE_ERR_UNKNOWN         -99

static inline char const * fd_blockstore_strerror( int err ) {
  switch( err ) {
  case FD_BLOCKSTORE_SUCCESS:     return "success";
  case FD_BLOCKSTORE_ERR_INVAL:   return "bad input";
  case FD_BLOCKSTORE_ERR_AGAIN:   return "try again";
  case FD_BLOCKSTORE_ERR_CORRUPT: return "corruption detected";
  case FD_BLOCKSTORE_ERR_EMPTY:   return "empty";
  case FD_BLOCKSTORE_ERR_FULL:    return "full";
  case FD_BLOCKSTORE_ERR_KEY:     return "key not found";
  default: break;
  }
  return "unknown";
}

struct fd_shred_key {
  ulong slot;
  uint  idx;
};
typedef struct fd_shred_key fd_shred_key_t;

static const fd_shred_key_t     fd_shred_key_null = { 0 };
#define FD_SHRED_KEY_NULL       fd_shred_key_null
#define FD_SHRED_KEY_INVAL(key) (!((key).slot) & !((key).idx))
#define FD_SHRED_KEY_EQ(k0,k1)  (!(((k0).slot) ^ ((k1).slot))) & !(((k0).idx) ^ (((k1).idx)))
#define FD_SHRED_KEY_HASH(key)  ((uint)(((key).slot)<<15UL) | (((key).idx))) /* current max shred idx is 32KB = 2 << 15*/

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
struct __attribute__((aligned(128UL))) fd_buf_shred {
  fd_shred_key_t key;
  ulong          prev;
  ulong          next;
  ulong          memo;
  int            eqvoc; /* we've seen an equivocating version of this
                             shred (same key but different payload). */
  union {
    fd_shred_t hdr;                  /* shred header */
    uchar      buf[FD_SHRED_MIN_SZ]; /* the entire shred buffer, both header and payload. */
  };
};
typedef struct fd_buf_shred fd_buf_shred_t;

#define POOL_NAME  fd_buf_shred_pool
#define POOL_ELE_T fd_buf_shred_t
#include "../../util/tmpl/fd_pool_para.c"

#define MAP_NAME               fd_buf_shred_map
#define MAP_ELE_T              fd_buf_shred_t
#define MAP_KEY_T              fd_shred_key_t
#define MAP_KEY_EQ(k0,k1)      (FD_SHRED_KEY_EQ(*k0,*k1))
#define MAP_KEY_EQ_IS_SLOW     1
#define MAP_KEY_HASH(key,seed) (FD_SHRED_KEY_HASH(*key)^seed)
#include "../../util/tmpl/fd_map_chain_para.c"

#define DEQUE_NAME fd_slot_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

/* fd_block_shred_t is a shred that has been assembled into a block. The
   shred begins at `off` relative to the start of the block's data
   region. */
struct fd_block_shred {
  fd_shred_t hdr; /* ptr to the data shred header */
  ulong      off; /* offset to the payload relative to the start of the block's data region */
};
typedef struct fd_block_shred fd_block_shred_t;

/*
 * fd_block_entry_batch_t is a microblock/entry batch within a block.
 * The offset is relative to the start of the block's data region,
 * and indicates where the batch ends.  The (exclusive) end offset of
 * batch i is the (inclusive) start offset of batch i+1.  The 0th batch
 * always starts at offset 0.
 * On the wire, the presence of one of the COMPLETE flags in a data
 * shred marks the end of a batch.
 * In other words, batch ends are aligned with shred ends, and batch
 * starts are aligned with shred starts.  Usually a batch comprises
 * multiple shreds, and a block comprises multiple batches.
 * This information is useful because bincode deserialization needs to
 * be performed on a per-batch basis.  Precisely a single array of
 * microblocks/entries is expected to be deserialized from a batch.
 * Trailing bytes in each batch are ignored by default.
 */
struct fd_block_entry_batch {
  ulong end_off; /* exclusive */
};
typedef struct fd_block_entry_batch fd_block_entry_batch_t;

/* fd_block_micro_t is a microblock ("entry" in Solana parlance) within
   a block. The microblock begins at `off` relative to the start of the
   block's data region. */
struct fd_block_micro {
  ulong off; /* offset into block data */
};
typedef struct fd_block_micro fd_block_micro_t;

/* If the 0th bit is set, this indicates the block is preparing, which
   means it might be partially executed e.g. a subset of the microblocks
   have been executed.  It is not safe to remove, relocate, or modify
   the block in any way at this time.

   Callers holding a pointer to a block should always make sure to
   inspect this flag.

   Other flags mainly provide useful metadata for read-only callers, eg.
   RPC. */

#define FD_BLOCK_FLAG_RECEIVING 0 /* xxxxxxx1 still receiving shreds */
#define FD_BLOCK_FLAG_COMPLETED 1 /* xxxxxx1x received the block ie. all shreds (SLOT_COMPLETE) */
#define FD_BLOCK_FLAG_REPLAYING 2 /* xxxxx1xx replay in progress (DO NOT REMOVE) */
#define FD_BLOCK_FLAG_PROCESSED 3 /* xxxx1xxx successfully replayed the block */
#define FD_BLOCK_FLAG_EQVOCSAFE 4 /* xxxx1xxx 52% of cluster has voted on this (slot, bank hash) */
#define FD_BLOCK_FLAG_CONFIRMED 5 /* xxx1xxxx 2/3 of cluster has voted on this (slot, bank hash) */
#define FD_BLOCK_FLAG_FINALIZED 6 /* xx1xxxxx 2/3 of cluster has rooted this slot */
#define FD_BLOCK_FLAG_DEADBLOCK 7 /* x1xxxxxx failed to replay the block */

/* Rewards assigned after block is executed */

struct fd_block_rewards {
  ulong collected_fees;
  fd_hash_t leader;
  ulong post_balance;
};
typedef struct fd_block_rewards fd_block_rewards_t;

/* Remaining bits [4, 8) are reserved.

   To avoid confusion, please use `fd_bits.h` API
   ie. `fd_uchar_set_bit`, `fd_uchar_extract_bit`. */

#define SET_NAME fd_block_set
#define SET_MAX  FD_SHRED_BLK_MAX
#include "../../util/tmpl/fd_set.c"

struct fd_block_info {
  ulong slot; /* map key */
  ulong next; /* reserved for use by fd_map_giant.c */

  /* Ancestry */

  ulong parent_slot;
  ulong child_slots[FD_BLOCKSTORE_CHILD_SLOT_MAX];
  ulong child_slot_cnt;

  /* Metadata */

  /* To be banished after offline ledger replay is removed. These fields
     are not used for replay. */
  ulong     block_height;
  fd_hash_t block_hash;
  fd_hash_t bank_hash;

  ulong     fec_cnt;        /* the number of FEC sets in the slot */
  uchar     flags;
  long      ts;             /* the wallclock time when we finished receiving the block. */

  /* Windowing

     Shreds are buffered into a map as they are received:

     | 0 | 1 | 2 | x | x | 5 | x |
           ^   ^           ^
           c   b           r

     c = "consumed" = contiguous shred idxs that have been consumed.
                      the "consumer" is replay and the idx is
                      incremented after replaying each block slice.
     b = "buffered" = contiguous shred idxs that have been buffered.
                      when buffered == block_slice_end the next slice of
                      a block is ready for replay.
     r = "received" = highest shred idx received so far. used to detect
                      when repair is needed.
  */

  uint consumed_idx; /* the highest shred idx we've contiguously consumed (consecutive from 0). */
  uint buffered_idx; /* the highest shred idx we've contiguously buffered (consecutive from 0). */
  uint received_idx; /* the highest shred idx we've received (can be out-of-order). */

  uint data_complete_idx; /* the highest shred idx wrt contiguous entry batches (inclusive). */
  uint slot_complete_idx; /* the highest shred idx for the entire slot (inclusive). */

  /* This is a bit vec (fd_set) that tracks every shred idx marked with
     FD_SHRED_DATA_FLAG_DATA_COMPLETE. The bit position in the fd_set
     corresponds to the shred's index. Note shreds can be received
     out-of-order so higher bits might be set before lower bits. */

  fd_block_set_t data_complete_idxs[FD_SHRED_BLK_MAX / sizeof(ulong)];

  /* Helpers for batching tick verification */

  ulong ticks_consumed;
  ulong tick_hash_count_accum;
  fd_hash_t in_poh_hash; /* TODO: might not be best place to hold this */

  /* Block */

  ulong block_gaddr; /* global address to the start of the allocated fd_block_t */
};
typedef struct fd_block_info fd_block_info_t;

#define MAP_NAME                  fd_block_map
#define MAP_ELE_T                 fd_block_info_t
#define MAP_KEY                   slot
#define MAP_ELE_IS_FREE(ctx, ele) ((ele)->slot == ULONG_MAX)
#define MAP_ELE_FREE(ctx, ele)    ((ele)->slot =  ULONG_MAX)
#define MAP_ELE_MOVE(ctx,dst,src) do { MAP_ELE_T * _src = (src); (*(dst)) = *_src; _src->MAP_KEY = (MAP_KEY_T)ULONG_MAX; } while(0)
#define MAP_KEY_HASH(key, seed)   (void)(seed), (*(key))
#include "../../util/tmpl/fd_map_slot_para.c"

#define BLOCK_INFO_LOCK_CNT  1024UL
#define BLOCK_INFO_PROBE_CNT 2UL
/*
   Rationale for block_map parameters:
    - each lock manages block_max / lock_cnt elements, so with block_max
      at 4096, each lock would manage 4 contiguous elements.
    - Since keys are unique and increment by 1, we can index key to map
      bucket by taking key % ele_max directly. This way in theory we
      have perfect hashing and never need to probe.
       - This breaks when we store more than 4096 contiguous slots,
         i.e.: slot 0 collides with slot 4096, but this is at heart an
         OOM issue.
    - Causes possible contention - consider if we execute n, but are
      storing shreds for n+1 -- these are managed by the same lock.
      Perhaps opportunity for optimization.
*/

/* fd_block_idx is an in-memory index of finalized blocks that have been
   archived to disk.  It records the slot together with the byte offset
   relative to the start of the file. */

struct fd_block_idx {
  ulong     slot;
  ulong     next;
  uint      hash;
  ulong     off;
  fd_hash_t block_hash;
  fd_hash_t bank_hash;
};
typedef struct fd_block_idx fd_block_idx_t;

#define MAP_NAME          fd_block_idx
#define MAP_T             fd_block_idx_t
#define MAP_KEY           slot
#define MAP_KEY_HASH(key) ((uint)(key)) /* finalized slots are guaranteed to be unique so perfect hashing */
#define MAP_KEY_INVAL(k)  (k == ULONG_MAX)
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_blockstore_archiver outlines the format of metadata
   at the start of an archive file - needed so that archive
   files can be read back on initialization. */

struct fd_blockstore_archiver {
  ulong fd_size_max;      /* maximum size of the archival file */
  ulong num_blocks;       /* number of blocks in the archival file. needed for reading back */
  ulong head;             /* location of least recently written block */
  ulong tail;             /* location after most recently written block */
};
typedef struct fd_blockstore_archiver fd_blockstore_archiver_t;
#define FD_BLOCKSTORE_ARCHIVE_START sizeof(fd_blockstore_archiver_t)

/*   CONCURRENCY NOTES FOR BLOCKSTORE ENJOINERS:

   With the parallelization of the shred map and block map, parts of the
   blockstore are concurrent, and parts are not. Block map and shred map
   have their own locks, which are managed through the
   query_try/query_test APIs. When accessing buf_shred_t and
   block_info_t items then, the caller does not need to use
   blockstore_start/end_read/write. However, the
   blockstore_start/end_read/write still protects the blockstore_shmem_t
   object. If you are reading and writing any blockstore_shmem fields
   and at the same time accessing the block_info_t or buf_shred_t, you
   should call both the blockstore_start/end_read/write APIs AND the map
   query_try/test APIs. These are locks of separate concerns and will
   not deadlock with each other. TODO update docs when we switch to
   fenced read/write for primitive fields in shmem_t. */
struct __attribute__((aligned(FD_BLOCKSTORE_ALIGN))) fd_blockstore_shmem {

  /* Metadata */

  ulong magic;
  ulong blockstore_gaddr;
  ulong wksp_tag;
  ulong seed;

  /* Persistence */

  fd_blockstore_archiver_t archiver;
  ulong mrw_slot; /* most recently written slot */

  /* Slot metadata */

  ulong lps; /* latest processed slot */
  ulong hcs; /* highest confirmed slot */
  ulong wmk; /* watermark. DO NOT MODIFY DIRECTLY. */

  /* Config limits */

  ulong shred_max; /* maximum # of shreds that can be held in memory */
  ulong block_max; /* maximum # of blocks that can be held in memory */
  ulong idx_max;   /* maximum # of blocks that can be indexed from the archival file */
  ulong alloc_max; /* maximum bytes that can be allocated */

  //ulong block_map_gaddr;  /* map of slot->(slot_meta, block) */
  ulong block_idx_gaddr;  /* map of slot->byte offset in archival file */
  ulong slot_deque_gaddr; /* deque of slot numbers */

  ulong alloc_gaddr;
};
typedef struct fd_blockstore_shmem fd_blockstore_shmem_t;

/* fd_blockstore_t is a local join to the blockstore.  This is specific
   to the local address space should not be shared across tiles. */

struct fd_blockstore {

  /* shared memory region */

  fd_blockstore_shmem_t * shmem; /* read/writes to shmem must call fd_blockstore_start_read()*/

  /* local join handles */

  fd_buf_shred_pool_t shred_pool[1];
  fd_buf_shred_map_t  shred_map[1];
  fd_block_map_t      block_map[1];
};
typedef struct fd_blockstore fd_blockstore_t;

FD_PROTOTYPES_BEGIN

/* Construction API */

FD_FN_CONST static inline ulong
fd_blockstore_align( void ) {
  return FD_BLOCKSTORE_ALIGN;
}

/* fd_blockstore_footprint returns the footprint of the entire
   blockstore shared memory region occupied by `fd_blockstore_shmem_t`
   including data structures. */

FD_FN_CONST static inline ulong
fd_blockstore_footprint( ulong shred_max, ulong block_max, ulong idx_max ) {
  /* TODO -- when removing, make change in fd_blockstore_new as well */
  block_max      = fd_ulong_pow2_up( block_max );
  ulong lock_cnt = fd_ulong_min( block_max, BLOCK_INFO_LOCK_CNT );

  int lg_idx_max = fd_ulong_find_msb( fd_ulong_pow2_up( idx_max ) );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_blockstore_shmem_t), sizeof(fd_blockstore_shmem_t) ),
      alignof(fd_buf_shred_t),        sizeof(fd_buf_shred_t) * shred_max ),
      fd_buf_shred_pool_align(),      fd_buf_shred_pool_footprint() ),
      fd_buf_shred_map_align(),       fd_buf_shred_map_footprint( shred_max ) ),
      alignof(fd_block_info_t),        sizeof(fd_block_info_t) * block_max ),
      fd_block_map_align(),           fd_block_map_footprint( block_max, lock_cnt, BLOCK_INFO_PROBE_CNT ) ),
      fd_block_idx_align(),           fd_block_idx_footprint( lg_idx_max ) ),
      fd_slot_deque_align(),          fd_slot_deque_footprint( block_max ) ),
      fd_alloc_align(),               fd_alloc_footprint() ),
    fd_blockstore_align() );
}

/* fd_blockstore_new formats a memory region with the appropriate
   alignment and footprint into a blockstore.  shmem points in the
   caller's address space of the memory region to format.  Returns shmem
   on success (blockstore has ownership of the memory region) and NULL
   on failure (no changes, logs details).  Caller is not joined on
   return.  The blockstore will be empty and unlocked. */

void *
fd_blockstore_new( void * shmem,
                   ulong  wksp_tag,
                   ulong  seed,
                   ulong  shred_max,
                   ulong  block_max,
                   ulong  idx_max );

/* fd_blockstore_join joins a blockstore.  ljoin points to a
   fd_blockstore_t compatible memory region in the caller's address
   space used to hold info about the local join, shblockstore points in
   the caller's address space to the memory region containing the
   blockstore.  Returns a handle to the caller's local join on success
   (join has ownership of the ljoin region) and NULL on failure (no
   changes, logs details). */

fd_blockstore_t *
fd_blockstore_join( void * ljoin, void * shblockstore );

void *
fd_blockstore_leave( fd_blockstore_t * blockstore );

void *
fd_blockstore_delete( void * shblockstore );

/* fd_blockstore_init initializes a blockstore with the given
   `slot_bank`.  This bank is used for initializing fields (SMR, etc.),
   and should be the bank upon finishing a snapshot load if booting from
   a snapshot, genesis bank otherwise.  It is also used to "fake" the
   snapshot block as if that block's data were available.  The metadata
   for this block's slot will be populated (fd_block_map_t) but the
   actual block data (fd_block_t) won't exist. This is done to bootstrap
   the various components for live replay (turbine, repair, etc.)

   `fd` is a file descriptor for the blockstore archival file.  As part
   of `init`, blockstore rebuilds an in-memory index of the archival
   file.  */

fd_blockstore_t *
fd_blockstore_init( fd_blockstore_t *      blockstore,
                    int                    fd,
                    ulong                  fd_size_max,
                    ulong                  slot );

/* fd_blockstore_fini finalizes a blockstore.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */

void
fd_blockstore_fini( fd_blockstore_t * blockstore );

/* Accessors */

/* fd_blockstore_wksp returns the local join to the wksp backing the
   blockstore. The lifetime of the returned pointer is at least as long
   as the lifetime of the local join.  Assumes blockstore is a current
   local join. */

FD_FN_PURE static inline fd_wksp_t *
fd_blockstore_wksp( fd_blockstore_t * blockstore ) {
  return (fd_wksp_t *)( ( (ulong)blockstore->shmem ) - blockstore->shmem->blockstore_gaddr );
}

/* fd_blockstore_wksp_tag returns the workspace allocation tag used by
   the blockstore for its wksp allocations.  Will be positive.  Assumes
   blockstore is a current local join. */

FD_FN_PURE static inline ulong
fd_blockstore_wksp_tag( fd_blockstore_t const * blockstore ) {
  return blockstore->shmem->wksp_tag;
}

/* fd_blockstore_seed returns the hash seed used by the blockstore for various hash
   functions.  Arbitrary value.  Assumes blockstore is a current local join.
   TODO: consider renaming hash_seed? */
FD_FN_PURE static inline ulong
fd_blockstore_seed( fd_blockstore_t const * blockstore ) {
  return blockstore->shmem->seed;
}

/* fd_block_idx returns a pointer in the caller's address space to the
   fd_block_idx_t in the blockstore wksp.  Assumes blockstore is local
   join.  Lifetime of the returned pointer is that of the local join. */

FD_FN_PURE static inline fd_block_idx_t *
fd_blockstore_block_idx( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->shmem->block_idx_gaddr );
}

/* fd_slot_deque returns a pointer in the caller's address space to the
   fd_slot_deque_t in the blockstore wksp.  Assumes blockstore is local
   join.  Lifetime of the returned pointer is that of the local join. */

FD_FN_PURE static inline ulong *
fd_blockstore_slot_deque( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore), blockstore->shmem->slot_deque_gaddr );
}

/* fd_blockstore_alloc returns a pointer in the caller's address space to
   the blockstore's allocator. */

FD_FN_PURE static inline fd_alloc_t * /* Lifetime is that of the local join */
fd_blockstore_alloc( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore), blockstore->shmem->alloc_gaddr );
}

/* fd_blockstore_shred_test returns 1 if a shred keyed by (slot, idx) is
   already in the blockstore and 0 otherwise.  */

int
fd_blockstore_shred_test( fd_blockstore_t * blockstore, ulong slot, uint idx );

/* fd_buf_shred_query_copy_data queries the blockstore for shred at
   slot, shred_idx. Copies the shred data to the given buffer and
   returns the data size. Returns -1 on failure.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */

long
fd_buf_shred_query_copy_data( fd_blockstore_t * blockstore,
                              ulong             slot,
                              uint              shred_idx,
                              void *            buf,
                              ulong             buf_max );

/* fd_blockstore_block_hash_query performs a blocking query (concurrent
   writers are not blocked) for the block hash of slot.  Returns
   FD_BLOCKSTORE_SUCCESS on success and FD_BLOCKSTORE_ERR_KEY if slot is
   not in blockstore.  Cannot fail.  On success, a copy of the block
   hash will be populated in `block_hash`.  Retains no interest in
   `slot` or `block_hash`.

   The block hash is the final poh hash for a slot and available on the
   last microblock header. */

int
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot, fd_hash_t * block_hash );

/* fd_blockstore_bank_hash_query performs a blocking query (concurrent
   writers are not blocked) for the bank hash of slot.  Returns
   FD_BLOCKSTORE_SUCCESS on success and FD_BLOCKSTORE_ERR_KEY if slot is
   not in blockstore.  Cannot fail.  On success, a copy of the bank hash
   will be populated in `bank_hash`.  Retains no interest in `slot` or
   `bank_hash`.

   The bank hash is a hash of the execution state (the "bank") after
   executing the block for a given slot. */

int
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot, fd_hash_t * bank_hash );

/* fd_blockstore_block_map_query queries the blockstore for the block
   map entry at slot.  Returns a pointer to the slot meta or NULL if not
   in blockstore.

   IMPORTANT! This should only be used for single-threaded / offline
   use-cases as it does not test the query. Read notes below for
   block_map usage in live. */

fd_block_info_t *
fd_blockstore_block_map_query( fd_blockstore_t * blockstore, ulong slot );

/* IMPORTANT! NOTES FOR block_map USAGE:

   The block_info entries must be queried using the query_try/query_test
   pattern. This will frequently look like:

   int err = FD_MAP_ERR_AGAIN;
   loop while( err == FD_MAP_ERR_AGAIN )
      block_map_query_t query;
      err = fd_block_map_query_try( nonblocking );
      block_info_t * ele = fd_block_map_query_ele(query);
      if ERROR is FD_MAP_ERR_KEY, then the slot is not found.
      if ERROR is FD_MAP_ERR_AGAIN, then immediately continue.
         // important to handle ALL possible return err codes *before*
         // accessing the ele, as the ele will be the sentinel (usually NULL)
      speculatively execute <stuff>
         - no side effects
         - no early return
      err = fd_block_map_query_test(query)
   end loop

   Some accessors are provided to callers that already do this pattern,
   and handle the looping querying. For example, block_hash_copy, and
   parent_slot_query. However, for most caller use cases, it would be
   much more effecient to use the query_try/query_test pattern directly.

   Example: if you are accessing a block_info_t m, and m->parent_slot to
   the blockstore->shmem->smr, then you will need to start_write on the
   blockstore, query_try for the block_info_t object, set
   shmem->smr = meta->parent_slot, and then query_test, AND call
   blockstore_end_write. In the case that there's block_info contention,
   i.e. another thread is removing the block_info_t object of interest
   as we are trying to access it, the query_test will ERR_AGAIN, we will
   loop back and try again, hit the FD_MAP_ERR_KEY condition
   (and exit the loop gracefully), and we will have an incorrectly set
   shmem->smr.

   So depending on the complexity of what's being executed, it's easiest
   to directly copy what you need from the block_info_t into a variable
   outside the context of the loop, and use it further below, ex:

   ulong map_item = NULL_ITEM;
   loop {
     query_try
     map_item = ele->map_item; // like parent_slot
     query_test
   }
   check if map_item is NULL_ITEM
   fd_blockstore_start_write
   use map_item
   fd_blockstore_end_write

   Writes and updates (blocking). The pattern is:
   int err = fd_block_map_prepare( &slot, query, blocking );
   block_info_t * ele = fd_block_map_query_ele(query);

   IF slot was an existing key, then ele->slot == slot, and you are MODIFYING
      <modify ele>
   If slot was not an existing key, then ele->slot == 0, and you are INSERTING
      ele->slot = slot;
      <initialize ele>

   fd_block_map_publish(query); // will always succeed */

/* fd_blockstore_parent_slot_query queries the parent slot of slot.

   This is non-blocking. */
ulong
fd_blockstore_parent_slot_query( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_block_map_query_volatile is the same as above except it
   only copies out the metadata (fd_block_map_t).  Returns
   FD_BLOCKSTORE_SLOT_MISSING if slot is missing, otherwise
   FD_BLOCKSTORE_SUCCESS. */

int
fd_blockstore_block_map_query_volatile( fd_blockstore_t * blockstore,
                                        int               fd,
                                        ulong             slot,
                                        fd_block_info_t * block_info_out ) ;

/* fd_blockstore_block_info_test tests if a block meta entry exists for
   the given slot.  Returns 1 if the entry exists and 0 otherwise.

   IMPORTANT!  Caller MUST NOT be in a block_map_t prepare when calling
   this function. */
int
fd_blockstore_block_info_test( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_block_info_remove removes a block meta entry for
   the given slot.  Returns SUCCESS if the entry exists and an
   error code otherwise.

   IMPORTANT!  Caller MUST NOT be in a block_map_t prepare when calling
   this function. */
int
fd_blockstore_block_info_remove( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_slot_remove removes slot from blockstore, including all
   relevant internal structures.

   IMPORTANT! Caller MUST NOT be in a block_map_t prepare when calling
   this function. */
void
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot );

/* Operations */

/* fd_blockstore_shred_insert inserts shred into the blockstore, fast
   O(1).  Returns the current `consumed_idx` for the shred's slot if
   insert is successful, otherwise returns FD_SHRED_IDX_NULL on error.
   Reasons for error include this shred is already in the blockstore or
   the blockstore is full.

   fd_blockstore_shred_insert will manage locking, so the caller
   should NOT be acquiring the blockstore read/write lock before
   calling this function. */

void
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred );

/* fd_blockstore_buffered_shreds_remove removes all the unassembled shreds
   for a slot */
void
fd_blockstore_shred_remove( fd_blockstore_t * blockstore, ulong slot, uint idx );

/* fd_blockstore_slice_query queries for the block slice beginning from
   shred `start_idx`, ending at `end_idx`, inclusive. Validates start
   and end_idx as valid batch boundaries. Copies at most `max` bytes of
   the shred payloads, and returns FD_BLOCKSTORE_NO_MEM if the buffer is
   too small.

   Returns FD_BLOCKSTORE_SUCCESS (0) on success and a FD_MAP_ERR
   (negative) on failure.  On success, `buf` will be populated with the
   copied slice and `buf_sz` will contain the number of bytes copied.
   Caller must ignore the values of `buf` and `buf_sz` on failure.

   Implementation is lockfree and safe with concurrent operations on
   blockstore. */

int
fd_blockstore_slice_query( fd_blockstore_t * blockstore,
                           ulong             slot,
                           uint              start_idx,
                           uint              end_idx,
                           ulong             max,
                           uchar *           buf,
                           ulong *           buf_sz );

/* fd_blockstore_shreds_complete should be a replacement for anywhere that is
   querying for an fd_block_t * for existence but not actually using the block data.
   Semantically equivalent to query_block( slot ) != NULL.

   Implementation is lockfree and safe with concurrent operations on
   blockstore. */
int
fd_blockstore_shreds_complete( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_publish publishes all blocks until the current
   blockstore smr (`blockstore->smr`).  Publishing entails 1. pruning
   and 2. archiving.  Pruning removes any blocks that are not part of
   the same fork as the smr (hence the name pruning, like pruning the
   branches of a tree).  Archiving removes from memory any slots < smr
   that are on the same fork, but writes those blocks out to disk using
   the provided file descriptor to the archival file `fd`.

   Note that slots < smr are ancestors of the smr, and are therefore
   finalized slots which is why they are archived.  Blocks removed as a
   result of pruning are not finalized, and therefore not archived.

   IMPORTANT!  Caller MUST hold the write lock when calling this
   function. */

void
fd_blockstore_publish( fd_blockstore_t * blockstore, int fd, ulong wmk );

void
fd_blockstore_log_block_status( fd_blockstore_t * blockstore, ulong around_slot );

/* fd_blockstore_log_mem_usage logs the memory usage of blockstore in a
   human-readable format.  Caller MUST hold the read lock. */

void
fd_blockstore_log_mem_usage( fd_blockstore_t * blockstore );

FD_PROTOTYPES_END

#ifndef BLOCK_ARCHIVING
#define BLOCK_ARCHIVING 0
#endif

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_h */
