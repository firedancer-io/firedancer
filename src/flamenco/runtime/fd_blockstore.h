#ifndef HEADER_fd_src_flamenco_runtime_fd_blockstore_h
#define HEADER_fd_src_flamenco_runtime_fd_blockstore_h

/* Blockstore is a high-performance database for storing, building, and
   tracking blocks.

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

/* FD_BLOCKSTORE_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a blockstore.  ALIGN should be a positive integer power of 2.
   FOOTPRINT is multiple of ALIGN.  These are provided to facilitate
   compile time declarations.  */

/* clang-format off */
#define FD_BLOCKSTORE_ALIGN     (128UL)
#define FD_BLOCKSTORE_FOOTPRINT (256UL)
#define FD_BLOCKSTORE_MAGIC     (0xf17eda2ce7b10c00UL) /* firedancer bloc version 0 */

/* DO NOT MODIFY. */
// #define FD_BUF_SHRED_MAP_MAX (1UL << 24UL) /* 16 million shreds can be buffered */
// #define FD_TXN_MAP_LG_MAX    (24)          /* 16 million txns can be stored in the txn map */

/* TODO this can be removed if we explicitly manage a memory pool for
   the fd_block_map_t entries */
#define FD_BLOCKSTORE_CHILD_SLOT_MAX    (32UL)        /* the maximum # of children a slot can have */
#define FD_BLOCKSTORE_ARCHIVE_MIN_SIZE  (1UL << 26UL) /* 64MB := ceil(MAX_DATA_SHREDS_PER_SLOT*1228) */

/* Maximum size of an entry batch is the entire block */
#define FD_MBATCH_MAX (FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT)
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
    fd_shred_t hdr;                  /* shred header */
    uchar      buf[FD_SHRED_MAX_SZ]; /* the entire shred buffer, both header and payload. */
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
#define MAP_KEY_EQ(k0,k1)      (FD_SHRED_KEY_EQ(*k0,*k1))
#define MAP_KEY_HASH(key,seed) (FD_SHRED_KEY_HASH(*key)^seed)
#include "../../util/tmpl/fd_map_chain.c"
/* clang-format on */

#define DEQUE_NAME fd_slot_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

/* fd_block_shred_t is a shred that has been assembled into a block. The
   shred begins at `off` relative to the start of the block's data
   region. */
struct fd_block_shred {
  fd_shred_t hdr; /* ptr to the data shred header */
  uchar      merkle[FD_SHRED_MERKLE_ROOT_SZ + FD_SHRED_MERKLE_NODE_SZ*9U /* FD_FEC_SET_MAX_BMTREE_DEPTH */];
  ulong      merkle_sz;
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

/* fd_block_txn_t is a transaction that has been parsed and is part of a
   block. The transaction begins at `off` relative to the start of the
   block's data region. */
struct fd_block_txn {
  ulong txn_off; /* offset into block data of transaction */
  ulong id_off;  /* offset into block data of transaction identifiers */
  ulong sz;
};
typedef struct fd_block_txn fd_block_txn_t;

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

struct fd_block {

  /* Computed rewards */

  fd_block_rewards_t rewards;

  /* data region

  A block's data region is indexed to support iterating by shred,
  microblock/entry batch, microblock/entry, or transaction.
  This is done by iterating the headers for each, stored in allocated
  memory.
  To iterate shred payloads, for example, a caller should iterate the headers in tandem with the data region
  (offsetting by the bytes indicated in the shred header).

  Note random access of individual shred indices is not performant, due to the variable-length
  nature of shreds. */

  ulong data_gaddr;   /* ptr to the beginning of the block's allocated data region */
  ulong data_sz;      /* block size */
  ulong shreds_gaddr; /* ptr to the first fd_block_shred_t */
  ulong shreds_cnt;
  ulong batch_gaddr;  /* list of fd_block_entry_batch_t */
  ulong batch_cnt;
  ulong micros_gaddr; /* ptr to the list of fd_block_micro_t */
  ulong micros_cnt;
  ulong txns_gaddr;   /* ptr to the list of fd_block_txn_t */
  ulong txns_cnt;
  ulong txns_meta_gaddr; /* ptr to the allocation for txn meta data */
  ulong txns_meta_sz;
};
typedef struct fd_block fd_block_t;

#define SET_NAME fd_block_set
#define SET_MAX  FD_SHRED_MAX_PER_SLOT
#include "../../util/tmpl/fd_set.c"

struct fd_block_map {
  ulong slot; /* map key */
  ulong next; /* reserved for use by fd_map_giant.c */

  /* Ancestry */

  ulong parent_slot;
  ulong child_slots[FD_BLOCKSTORE_CHILD_SLOT_MAX];
  ulong child_slot_cnt;

  /* Metadata */

  ulong     block_height;
  fd_hash_t block_hash;
  fd_hash_t bank_hash;
  fd_hash_t merkle_hash;    /* the last FEC set's merkle hash */
  ulong     fec_cnt;        /* the number of FEC sets in the slot */
  uchar     flags;
  uchar     reference_tick; /* the tick when the leader prepared the block. */
  long      ts;             /* the wallclock time when we finished receiving the block. */

  /* Windowing */

  uint consumed_idx; /* the highest shred idx we've contiguously received from idx 0 (inclusive). */
  uint received_idx; /* the highest shred idx we've received + 1 (exclusive). */
  uint replayed_idx; /* the highest shred idx we've replayed (inclusive). */

  uint data_complete_idx; /* the highest shred idx wrt contiguous entry batches (inclusive). */
  uint slot_complete_idx; /* the highest shred idx for the entire slot (inclusive). */

  /* This is a bit vec (fd_set) that tracks every shred idx marked with
     FD_SHRED_DATA_FLAG_DATA_COMPLETE. The bit position in the fd_set
     corresponds to the shred's index. Note shreds can be received
     out-of-order so higher bits might be set before lower bits. */

  fd_block_set_t data_complete_idxs[FD_SHRED_MAX_PER_SLOT / sizeof(ulong)];

  /* Helpers for batching tick verification */

  ulong ticks_consumed;
  ulong tick_hash_count_accum;
  fd_hash_t in_poh_hash; /* TODO: might not be best place to hold this */

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
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_txn_key {
  ulong v[FD_ED25519_SIG_SZ / sizeof( ulong )];
};
typedef struct fd_txn_key fd_txn_key_t;

struct fd_txn_map {
  fd_txn_key_t sig;
  ulong        next;
  ulong        slot;
  ulong        offset;
  ulong        sz;
  ulong        meta_gaddr; /* ptr to the transaction metadata */
  ulong        meta_sz;    /* metadata size */
};
typedef struct fd_txn_map fd_txn_map_t;

/* clang-format off */
int fd_txn_key_equal(fd_txn_key_t const * k0, fd_txn_key_t const * k1);
ulong fd_txn_key_hash(fd_txn_key_t const * k, ulong seed);

#define MAP_NAME             fd_txn_map
#define MAP_T                fd_txn_map_t
#define MAP_KEY              sig
#define MAP_KEY_T            fd_txn_key_t
#define MAP_KEY_EQ(k0,k1)    fd_txn_key_equal(k0,k1)
#define MAP_KEY_HASH(k,seed) fd_txn_key_hash(k, seed)
#include "../../util/tmpl/fd_map_giant.c"

/* fd_blockstore_archiver outlines the format of metadata
   at the start of an archive file - needed so that archive
   files can be read back on initialization. */

struct fd_blockstore_archiver {
  ulong magic;
  ulong fd_size_max;      /* maximum size of the archival file */
  ulong num_blocks;       /* number of blocks in the archival file. needed for reading back */
  ulong head;             /* location of least recently written block */
  ulong tail;             /* location after most recently written block */
};
typedef struct fd_blockstore_archiver fd_blockstore_archiver_t;
#define FD_BLOCKSTORE_ARCHIVE_START sizeof(fd_blockstore_archiver_t)

struct __attribute__((aligned(FD_BLOCKSTORE_ALIGN))) fd_blockstore {
/* clang-format on */

  /* Metadata */

  ulong magic;
  ulong blockstore_gaddr;
  ulong wksp_tag;
  ulong seed;

  /* Concurrency */

  fd_rwseq_lock_t lock;

  /* Persistence */

  fd_blockstore_archiver_t archiver;
  ulong mrw_slot; /* most recently written slot */

  /* Slot metadata */

  ulong lps; /* latest processed slot */
  ulong hcs; /* highest confirmed slot */
  ulong smr; /* supermajority root. DO NOT MODIFY DIRECTLY. */
  ulong wmk; /* watermark. DO NOT MODIFY DIRECTLY. */

  /* Config limits */

  ulong shred_max; /* maximum # of shreds that can be held in memory */
  ulong block_max; /* maximum # of blocks that can be held in memory */
  ulong idx_max;   /* maximum # of blocks that can be indexed from the archival file */
  ulong txn_max;   /* maximum # of transactions that can be indexed from blocks */
  ulong alloc_max; /* maximum bytes that can be allocated */

  /* Owned */

  ulong shred_pool_gaddr; /* memory pool for buffering shreds before block assembly */
  ulong shred_map_gaddr;  /* map of (slot, shred_idx)->shred */
  ulong block_map_gaddr;  /* map of slot->(slot_meta, block) */
  ulong block_idx_gaddr;  /* map of slot->byte offset in archival file */
  ulong slot_deque_gaddr; /* deque of slot numbers */
  ulong txn_map_gaddr;
  ulong alloc_gaddr;
};
typedef struct fd_blockstore fd_blockstore_t;

FD_PROTOTYPES_BEGIN

/* Construction API */

/* TODO document lifecycle methods */

FD_FN_CONST static inline ulong
fd_blockstore_align( void ) {
  return alignof(fd_blockstore_t);
}

FD_FN_CONST static inline ulong
fd_blockstore_footprint( ulong shred_max, ulong block_max, ulong idx_max, ulong txn_max ) {
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
    FD_LAYOUT_INIT,
      alignof(fd_blockstore_t),  sizeof(fd_blockstore_t) ),
      fd_buf_shred_pool_align(), fd_buf_shred_pool_footprint( shred_max ) ),
      fd_buf_shred_map_align(),  fd_buf_shred_map_footprint( shred_max ) ),
      fd_block_map_align(),      fd_block_map_footprint( block_max ) ),
      fd_block_idx_align(),      fd_block_idx_footprint( lg_idx_max ) ),
      fd_slot_deque_align(),     fd_slot_deque_footprint( block_max ) ),
      fd_txn_map_align(),        fd_txn_map_footprint( txn_max ) ),
      fd_alloc_align(),          fd_alloc_footprint() ),
    fd_blockstore_align() );
}

void *
fd_blockstore_new( void * shmem,
                   ulong  wksp_tag,
                   ulong  seed,
                   ulong  shred_max,
                   ulong  block_max,
                   ulong  idx_max,
                   ulong  txn_max );

fd_blockstore_t *
fd_blockstore_join( void * shblockstore );

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
fd_blockstore_init( fd_blockstore_t * blockstore, int fd, ulong fd_size_max, fd_slot_bank_t const * slot_bank );

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
  return (fd_wksp_t *)( ( (ulong)blockstore ) - blockstore->blockstore_gaddr );
}

/* fd_blockstore_wksp_tag returns the workspace allocation tag used by
   the blockstore for its wksp allocations.  Will be positive.  Assumes
   blockstore is a current local join. */

FD_FN_PURE static inline ulong
fd_blockstore_wksp_tag( fd_blockstore_t const * blockstore ) {
  return blockstore->wksp_tag;
}

/* fd_blockstore_seed returns the hash seed used by the blockstore for various hash
   functions.  Arbitrary value.  Assumes blockstore is a current local join.
   TODO: consider renaming hash_seed? */
FD_FN_PURE static inline ulong
fd_blockstore_seed( fd_blockstore_t const * blockstore ) {
  return blockstore->seed;
}

/* fd_blockstore_buf_shred_pool returns a pointer in the caller's
   address space to the pool pointer fd_buf_shred_t * in the blockstore
   wksp.  Assumes blockstore is local join.  Lifetime of the returned
   pointer is that of the local join. */

FD_FN_PURE static inline fd_buf_shred_t *
fd_blockstore_shred_pool( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->shred_pool_gaddr );
}

/* fd_blockstore_buf_shred_map returns a pointer in the caller's address
   space to the fd_buf_shred_map_t * in the blockstore wksp.  Assumes
   blockstore is local join.  Lifetime of the returned pointer is that
   of the local join. */

FD_FN_PURE static inline fd_buf_shred_map_t *
fd_blockstore_shred_map( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->shred_map_gaddr );
}

/* fd_block_map returns a pointer in the caller's address space to the
   fd_block_map_t in the blockstore wksp.  Assumes blockstore is local
   join.  Lifetime of the returned pointer is that of the local join. */

FD_FN_PURE static inline fd_block_map_t *
fd_blockstore_block_map( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->block_map_gaddr );
}

/* fd_block_idx returns a pointer in the caller's address space to the
   fd_block_idx_t in the blockstore wksp.  Assumes blockstore is local
   join.  Lifetime of the returned pointer is that of the local join. */

FD_FN_PURE static inline fd_block_idx_t *
fd_blockstore_block_idx( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), blockstore->block_idx_gaddr );
}

/* fd_slot_deque returns a pointer in the caller's address space to the
   fd_slot_deque_t in the blockstore wksp.  Assumes blockstore is local
   join.  Lifetime of the returned pointer is that of the local join. */

FD_FN_PURE static inline ulong *
fd_blockstore_slot_deque( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore), blockstore->slot_deque_gaddr );
}

/* fd_txn_map returns a pointer in the caller's address space to the blockstore's
   block map. Assumes blockstore is local join. Lifetime of the returned pointer is that of the
   local join. */

FD_FN_PURE static inline fd_txn_map_t *
fd_blockstore_txn_map( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore), blockstore->txn_map_gaddr );
}

/* fd_blockstore_alloc returns a pointer in the caller's address space to
   the blockstore's allocator. */

FD_FN_PURE static inline fd_alloc_t * /* Lifetime is that of the local join */
fd_blockstore_alloc( fd_blockstore_t * blockstore ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore), blockstore->alloc_gaddr );
}

/* fd_blockstore_block_data_laddr returns a local pointer to the block's
   data.  The returned pointer lifetime is until the block is removed. */

FD_FN_PURE static inline uchar *
fd_blockstore_block_data_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->data_gaddr );
}

FD_FN_PURE static inline fd_block_entry_batch_t *
fd_blockstore_block_batch_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->batch_gaddr );
}

FD_FN_PURE static inline fd_block_micro_t *
fd_blockstore_block_micro_laddr( fd_blockstore_t * blockstore, fd_block_t * block ) {
  return fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), block->micros_gaddr );
}

/* fd_buf_shred_query queries the blockstore for shred at slot,
   shred_idx.  Returns a pointer to the shred or NULL if not in
   blockstore.  The returned pointer lifetime is until the shred is
   removed.  Check return value for error info.  This API only works for
   shreds from incomplete blocks.

   Callers should hold the read lock during the entirety of its read to
   ensure the pointer remains valid. */
fd_shred_t *
fd_buf_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx );

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

/* fd_blockstore_block_query queries blockstore for block at slot.
   Returns a pointer to the block or NULL if not in blockstore.  The
   returned pointer lifetime is until the block is removed.  Check
   return value for error info.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */
fd_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_block_hash_query queries blockstore for the block hash
   at slot. This is the final poh hash for a slot.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */
fd_hash_t const *
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_bank_hash_query query blockstore for the bank hash for
   a given slot.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */
fd_hash_t const *
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_block_map_query queries the blockstore for the block
   map entry at slot.  Returns a pointer to the slot meta or NULL if not
   in blockstore.  The returned pointer lifetime is until the slot meta
   is removed.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */
fd_block_map_t *
fd_blockstore_block_map_query( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_parent_slot_query queries the parent slot of slot.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */
ulong
fd_blockstore_parent_slot_query( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_child_slots_query queries slot's child slots.  Return
   values are saved in slots_out and slot_cnt.  Returns FD_BLOCKSTORE_OK
   on success, FD_BLOCKSTORE_ERR_SLOT_MISSING if slot is not in the
   blockstore.  The returned slot array is always <= the max size
   FD_BLOCKSTORE_CHILD_SLOT_MAX and contiguous.  Empty slots in the
   array are set to FD_SLOT_NULL.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */

int
fd_blockstore_child_slots_query( fd_blockstore_t * blockstore, ulong slot, ulong ** slots_out, ulong * slot_cnt );

/* fd_blockstore_block_frontier_query query the frontier i.e. all the
   blocks that need to be replayed that haven't been.  These are the
   slot children of the current frontier that are shred complete.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */
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
fd_blockstore_block_data_query_volatile( fd_blockstore_t *    blockstore,
                                         int                  fd,
                                         ulong                slot,
                                         fd_valloc_t          alloc,
                                         fd_hash_t *          parent_block_hash_out,
                                         fd_block_map_t *     block_map_entry_out,
                                         fd_block_rewards_t * block_rewards_out,
                                         uchar **             block_data_out,
                                         ulong *              block_data_sz_out );

/* fd_blockstore_block_map_query_volatile is the same as above except it
   only copies out the metadata (fd_block_map_t).  Returns
   FD_BLOCKSTORE_SLOT_MISSING if slot is missing, otherwise
   FD_BLOCKSTORE_OK. */

int
fd_blockstore_block_map_query_volatile( fd_blockstore_t * blockstore,
                                        int               fd,
                                        ulong             slot,
                                        fd_block_map_t *  block_map_entry_out );

/* fd_blockstore_txn_query queries the transaction data for the given
   signature.

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function. */
fd_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[static FD_ED25519_SIG_SZ] );

/* Query the transaction data for the given signature in a thread
   safe manner. The transaction data is copied out. txn_data_out can
   be NULL if you are only interested in the transaction metadata. */
int
fd_blockstore_txn_query_volatile( fd_blockstore_t * blockstore,
                                  int               fd,
                                  uchar const       sig[static FD_ED25519_SIG_SZ],
                                  fd_txn_map_t *    txn_out,
                                  long *            blk_ts,
                                  uchar *           blk_flags,
                                  uchar             txn_data_out[FD_TXN_MTU] );

/* fd_blockstore_slot_remove removes slot from blockstore, including all
   relevant internal structures.

   IMPORTANT!  Caller MUST hold the write lock when calling this
   function. */
void
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot );

/* Operations */

  /* fd_blockstore_shred_insert inserts shred into the blockstore, fast
   O(1).  Returns the current `consumed_idx` for the shred's slot if
   insert is successful, otherwise returns FD_SHRED_IDX_NULL on error.
   Reasons for error include this shred is already in the blockstore or
   the blockstore is full. */

int
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred );

/* fd_blockstore_buffered_shreds_remove removes all the unassembled shreds
   for a slot

   IMPORTANT!  Caller MUST hold the write lock when calling this
   function. */
int
fd_blockstore_buffered_shreds_remove( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_batch_assemble assembles shreds for a given batch starting at shred_idx 
   Shred payloads are copied contiguously into block_data_out, and the total size
   of the concatenated shred data is returned in block_data_sz. The caller provides the
   max buffer size. Function will check if the provided shred_idx is the start of a batch
   Returns an error code on success or failure. 

   IMPORTANT!  Caller MUST hold the read lock when calling this
   function.
 */
int
fd_blockstore_batch_assemble( fd_blockstore_t * blockstore, 
                               ulong slot, 
                               uint batch_idx,
                               ulong block_data_max, 
                               uchar * block_data_out, 
                               ulong * block_data_sz );

/* fd_blockstore_shreds_complete should be a replacement for anywhere that is 
   querying for an fd_block_t * for existence but not actually using the block data. 
   Semantically equivalent to query_block( slot ) != NULL.

   IMPORTANT! Caller MUST hold the read lock when calling this function */
bool
fd_blockstore_shreds_complete( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_block_height_update sets the block height.

   IMPORTANT!  Caller MUST hold the write lock when calling this
   function. */
void
fd_blockstore_block_height_update( fd_blockstore_t * blockstore, ulong slot, ulong block_height );

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

/* fd_blockstore_start_read acquires the read lock */
static inline void
fd_blockstore_start_read( fd_blockstore_t * blockstore ) {
  fd_rwseq_start_read( &blockstore->lock );
}

/* fd_blockstore_end_read releases the read lock */
static inline void
fd_blockstore_end_read( fd_blockstore_t * blockstore ) {
  fd_rwseq_end_read( &blockstore->lock );
}

/* fd_blockstore_start_write acquire the write lock */
static inline void
fd_blockstore_start_write( fd_blockstore_t * blockstore ) {
  fd_rwseq_start_write( &blockstore->lock );
}

/* fd_blockstore_end_write releases the write lock */
static inline void
fd_blockstore_end_write( fd_blockstore_t * blockstore ) {
  fd_rwseq_end_write( &blockstore->lock );
}

void
fd_blockstore_log_block_status( fd_blockstore_t * blockstore, ulong around_slot );

/* fd_blockstore_log_mem_usage logs the memory usage of blockstore in a
   human-readable format.  Caller MUST hold the read lock. */

void
fd_blockstore_log_mem_usage( fd_blockstore_t * blockstore );

FD_PROTOTYPES_END

/* fd_blockstore_ser is a serialization context for archiving a block to
   disk. */

struct fd_blockstore_ser {
  fd_block_map_t * block_map;
  fd_block_t     * block;
  uchar          * data;
};
typedef struct fd_blockstore_ser fd_blockstore_ser_t;

/* Archives a block and block map entry to fd at blockstore->off, and does
   any necessary bookkeeping.
   If fd is -1, no write is attempted. Returns written size */
ulong
fd_blockstore_block_checkpt( fd_blockstore_t * blockstore, 
                             fd_blockstore_ser_t * ser, 
                             int fd, 
                             ulong slot );

/* Restores a block and block map entry from fd at given offset. As this used by
   rpcserver, it must return an error code instead of throwing an error on failure. */
int
fd_blockstore_block_meta_restore( fd_blockstore_archiver_t * archvr,
                                  int fd,
                                  fd_block_idx_t * block_idx_entry,
                                  fd_block_map_t * block_map_entry_out,
                                  fd_block_t * block_out );

/* Reads block data from fd into a given buf. Modifies data_off similarly to
   meta_restore */
int 
fd_blockstore_block_data_restore( fd_blockstore_archiver_t * archvr,
                                  int fd,
                                  fd_block_idx_t * block_idx_entry,
                                  uchar * buf_out,
                                  ulong buf_max,
                                  ulong data_sz );

/* Returns 0 if the archive metadata is valid */
bool
fd_blockstore_archiver_verify( fd_blockstore_t * blockstore, fd_blockstore_archiver_t * archiver );

ulong
fd_blockstore_archiver_lrw_slot( fd_blockstore_t * blockstore, int fd, fd_block_map_t * lrw_block_map, fd_block_t * lrw_block );

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_h */
