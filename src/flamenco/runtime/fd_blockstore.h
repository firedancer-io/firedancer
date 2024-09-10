#ifndef HEADER_fd_src_flamenco_runtime_fd_blockstore_h
#define HEADER_fd_src_flamenco_runtime_fd_blockstore_h

/* Blockstore is a high-performance database that stores shreds and
   blocks, and indexes microblocks (entries) and transactions. */

#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/shred/fd_deshredder.h"
#include "../../ballet/shred/fd_shred.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "fd_readwrite_lock.h"
#include "stdbool.h"

/* FD_BLOCKSTORE_USE_HANDHOLDING:  Define this to non-zero at compile
   time to turn on additional runtime checks and logging. */

#ifndef FD_BLOCKSTORE_USE_HANDHOLDING
#define FD_BLOCKSTORE_USE_HANDHOLDING 1
#endif

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
#include "../../util/tmpl/fd_map_chain.c"
/* clang-format on */

#define DEQUE_NAME fd_blockstore_slot_deque
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

/* fd_block_shred_t saves the shred header and offset for a data shred
   that is already part of a block.  Note the payload is in the
   allocated region. */

struct fd_block_shred {
  fd_shred_t hdr; /* ptr to the data shred header */
  ulong      off; /* offset to the payload relative to the start of the allocated region */
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

/* If the 2nd bit (FD_BLOCK_FLAG_REPLAYING) is set, this indicates the
   block is actively replaying, which means it might be partially
   executed eg. a subset of the microblocks have been executed.  It is
   not safe to modify or remove the `fd_block_map_t` at this time.

   Callers holding a pointer to a block should always make sure to
   inspect this flag.  Other flags mainly provide useful metadata for
   read-only callers, eg. RPC.

   IMPORTANT!  To avoid confusion, please use `fd_bits.h` API when
   reading and writing flags eg.

   fd_uchar_set_bit( block_meta->flags, FD_BLOCK_FLAG_REPLAYING );

   int c = fd_uchar_extract_bit( block_meta->flags,
                                 FD_BLOCK_FLAG_REPLAYING ); */

#define FD_BLOCK_FLAG_REPLAYING 0 /* xxxxxxx1 replay in progress (DO NOT REMOVE) */
#define FD_BLOCK_FLAG_PROCESSED 1 /* xxxxxx1x successfully replayed the block */
#define FD_BLOCK_FLAG_DEADBLOCK 2 /* xxxxx1xx failed to replay the block */
#define FD_BLOCK_FLAG_EQVOCSAFE 3 /* xxxx1xxx 52% of cluster has voted for this slot */
#define FD_BLOCK_FLAG_CONFIRMED 4 /* xxx1xxxx 2/3 of cluster has voted for this slot */
#define FD_BLOCK_FLAG_FINALIZED 5 /* xx1xxxxx 2/3 of cluster has rooted this slot */

/* fd_block_data_t

 ┌───────────┬─────────────────────┬─────────────────────┐
 │ block     │ fd_block_shred_t(s) │ fd_block_micro_t(s) │
 └───────────┴─────────────────────┴─────────────────────┘
 ▲           ▲                     ▲
 data_gaddr  shred_gaddr           micro_gaddr

 data_gaddr points to the beginning of an allocated memory region of
 data_sz that contains a concatenation of the block data itself, shred
 headers and payload offsets into mem (fd_block_shred_t), and
 microblock offsets into mem (fd_block_micro_t).

 shred_gaddr, shred_cnt, micro_gaddr, micro_cnt are additional fields
 to support iterating by shred or microblock.
 
 Additionally, there are two separately allocated memory regions,
 txn_gaddr and txn_meta_gaddr that contain the transaction offsets into
 mem and transaction meta within a block, respectively.

 IMPORTANT!  Random access of fd_block_shred_t or fd_block_micro_t is
 not performant, as it requires scanning from index 0. */

struct fd_block_data {
  ulong data_gaddr;  /* ptr to the beginning of the block data's allocated memory region */
  ulong data_sz;
  ulong shred_gaddr; /* ptr to the first fd_block_shred_t */
  ulong shred_cnt;
  ulong micro_gaddr; /* ptr to the first fd_blockstore_micro_t */
  ulong micro_cnt;
  ulong txn_gaddr;
  ulong txn_cnt;
  ulong txn_meta_gaddr;
  ulong txn_meta_sz;
};
typedef struct fd_block_data fd_block_data_t;

/* fd_block_meta_t stores useful metadata about the block eg. ancestry,
   shred windowing. */

struct fd_block_meta {

  /* Ancestry */

  ulong parent_slot;
  ulong child_slots[FD_BLOCKSTORE_CHILD_SLOT_MAX];
  ulong child_slot_cnt;

  /* Metadata */

  ulong     block_height;   /* the # blocks since genesis (<= # slots due to skips) */
  fd_hash_t block_hash;     /* last microblock ("entry") hash */
  fd_hash_t bank_hash;      /* hash of the relevant state _after_ executing this block */
  fd_hash_t merkle_hash;    /* last FEC set's merkle root */
  uchar     flags;          /* block state transitions, see FD_BLOCK_FLAG_* above */
  uchar     reference_tick; /* the tick when the leader prepared the block. */
  long      ts;             /* the wallclock time when we finished receiving the block. */

  /* Windowing */

  uint consumed_idx; /* the highest shred idx of the contiguous window from idx 0 (inclusive). */
  uint received_idx; /* the highest shred idx we've received (exclusive). */
  uint complete_idx; /* the shred idx with FD_SHRED_DATA_FLAG_SLOT_COMPLETE. */
};
typedef struct fd_block_meta fd_block_meta_t;

struct fd_block {
  ulong slot; /* map key */
  ulong next; /* reserved for use by fd_map_giant.c */

  fd_block_meta_t meta;
  fd_block_data_t data;
};
typedef struct fd_block fd_block_t;

/* clang-format off */
#define MAP_NAME         fd_block_map
#define MAP_T            fd_block_t
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

  ulong min;  /* minimum slot in the blockstore with a block. we retain
                 blocks prior to the smr to serve repair and RPC */
  ulong max;  /* maximum slot in the blockstore with a block */
  ulong lps;  /* latest processed slot */
  ulong hcs;  /* highest confirmed slot */
  ulong smr;  /* supermajority root. DO NOT MODIFY DIRECTLY, instead use fd_blockstore_publish */

  /* Internal data structures */

  ulong shred_max;        /* max number of temporary shreds */
  ulong shred_pool_gaddr; /* pool of temporary shreds */
  ulong shred_map_gaddr;  /* map of (slot, shred_idx)->shred */

  ulong block_max;          /* maximum # of blocks */
  ulong block_map_gaddr;    /* map of slot->fd_block_t */
  ulong slot_deque_gaddr;   /* deque of slots (ulongs) used to traverse blockstore ancestry */

  int   lg_txn_max;
  ulong txn_map_gaddr;

  /* The blockstore alloc is used for allocating wksp resources for
     shred headers, microblock headers, and blocks.  This is an
     fd_alloc.  Allocations from this allocator will be tagged with
     wksp_tag and operations on this allocator will use concurrency
     group 0. */

  ulong alloc_gaddr;
};
/* clang-format on */

struct fd_blockstore_private;
typedef struct fd_blockstore_private fd_blockstore_t;

FD_PROTOTYPES_BEGIN

/* Construction API */

/* fd_blockstore_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as blockstore with up
   to shred_max shreds, slot_max blocks and lg_txn_max transactions. */

FD_FN_CONST ulong
fd_blockstore_align( void );

FD_FN_CONST ulong
fd_blockstore_footprint( void );

/* fd_blockstore_new formats an unused memory region for use as a
   blockstore.  shmem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_blockstore_new( void * shmem,
                   ulong  wksp_tag,
                   ulong  seed,
                   ulong  shred_max,
                   ulong  slot_max,
                   int    lg_txn_max );

/* fd_blockstore_join joins the caller to the blockstore.  shblockstore
   points to the first byte of the memory region backing the blockstore
   in the caller's address space.

   Returns a pointer in the local address space to blockstore on
   success. */

fd_blockstore_t *
fd_blockstore_join( void * shblockstore );

/* fd_blockstore_leave leaves a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include blockstore is NULL. */

void *
fd_blockstore_leave( fd_blockstore_t * blockstore );

/* fd_blockstore_delete unformats a memory region used as a blockstore.
   Assumes only the nobody is joined to the region.  Returns a pointer
   to the underlying shared memory region or NULL if used obviously in
   error (e.g. blockstore is obviously not a blockstore ... logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_blockstore_delete( void * shblockstore );

/* fd_blockstore_init initializes a blockstore with slot_bank.  slot_bank
   should be the bank upon finishing a snapshot load if booting from a
   snapshot, genesis bank otherwise.  Blockstore then initializes fields
   and creates a mock block using this slot bank.  This metadata for
   this block's slot will be populated (fd_block_map_t) but the actual
   block data (fd_block_map_t) won't exist.  This is needed to bootstrap the
   various componenets for live replay (turbine, repair, etc.) */

void
fd_blockstore_init( fd_blockstore_t * blockstore, ulong slot );

/* Accessor API */

/* fd_blockstore_wksp returns the local join to the wksp backing the
   blockstore.  The lifetime of return pointer is at least as long as
   the lifetime of the local join.  Assumes blockstore is a current
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

/* fd_blockstore_seed returns the hash seed used by the blockstore for
   various hash functions.  Arbitrary value.  Assumes blockstore is a
   current local join. */

FD_FN_PURE static inline ulong
fd_blockstore_seed( fd_blockstore_t * blockstore ) {
  return blockstore->seed;
}

/* fd_blockstore_buf_shred_pool returns a pointer in the caller's
   address space to the pool pointer fd_buf_shred_t * in the blockstore
   wksp.  Assumes blockstore is local join.  Lifetime of returned
   pointer is duration of blockstore join. */

FD_FN_PURE static inline fd_buf_shred_t *
fd_blockstore_buf_shred_pool( fd_blockstore_t * blockstore ) {
  return (fd_buf_shred_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                               blockstore->shred_pool_gaddr );
}

/* fd_blockstore_buf_shred_map returns a pointer in the caller's address
   space to the fd_buf_shred_map_t * in the blockstore wksp.  Assumes
   blockstore is local join.  Lifetime of return pointer is that of the
   local join. */

FD_FN_PURE static inline fd_buf_shred_map_t *
fd_blockstore_buf_shred_map( fd_blockstore_t * blockstore ) {
  return (fd_buf_shred_map_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                                   blockstore->shred_map_gaddr );
}

/* fd_block_map returns a pointer in the caller's address space to the
   fd_block_map_t in the blockstore wksp.  Assumes blockstore is local
   join.  Lifetime of return pointer is duration of blockstore join. */
FD_FN_PURE static inline fd_block_t *
fd_blockstore_block_map( fd_blockstore_t * blockstore ) {
  return (fd_block_t *)fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ),
                                               blockstore->block_map_gaddr );
}

/* fd_blockstore_txn_map returns a pointer in the caller's address space
   to the blockstore's block map.  Assumes blockstore is local join.
   Lifetime of return pointer is that of the local join. */

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

FD_FN_PURE static inline ulong
fd_blockstore_block_cnt( fd_blockstore_t * blockstore ) {
  return blockstore->max - blockstore->min + 1;
}

/* Operations */

/* fd_blockstore_shred_insert inserts shred keyed by slot and shred
   index into blockstore, fast O(1).

   If there is an equivocating shred (ie. shred with the same key but
   different payload) that is already in the blockstore, it will keep
   the existing shred (if handholding is enabled, explicitly checks and
   logs a warning).

   It is caller's, not blockstore's, responsibility to incorporate
   additional equivocation logic. */
int
fd_blockstore_shred_insert( fd_blockstore_t * blockstore, fd_shred_t const * shred );

/* fd_blockstore_shred_query queries for shred keyed by slot and idx in
   blockstore, O(1) but see below caveat.  Returns a pointer to the
   shred or NULL if not found.  The return pointer is const because
   shreds should never be modified in-place after insertion into the
   blockstore ... callers should remove and re-insert if performing
   modifications.

   Caveat: implementation is O(1) but with a large constant refactor if
   the block is completed (received all shreds).  This is because the
   shred is copied into the block data region which only indexes the
   first shred, and requires idx iterations to query the shred at idx
   (but idx is bounded to 1 << 15, the max # of shreds in a block).

   IMPORTANT SAFETY TIP!  Callers must hold the read lock when calling
   this function _and must the pointer_. */

fd_shred_t const *
fd_blockstore_shred_query( fd_blockstore_t * blockstore, ulong slot, uint shred_idx );

/* fd_blockstore_shred_query_volatile implements the same as above, but
   does not require the caller to hold the read lock.  The shred is
   copied into buf, which must be at least FD_SHRED_MAX_SZ big (U.B.
   otherwise). */

long
fd_blockstore_shred_query_volatile( fd_blockstore_t * blockstore,
                                    ulong             slot,
                                    uint              shred_idx,
                                    uchar             buf[static FD_SHRED_MAX_SZ] );

/* fd_blockstore_block_query queries for the block (both meta and data)
   keyed by slot. Returns a pointer in the local address space to the
   block or NULL if not in blockstore.  The return pointer lifetime is
   until the block is removed. */

FD_FN_PURE static inline fd_block_t *
fd_blockstore_block_query( fd_blockstore_t * blockstore, ulong slot ) {
  return fd_block_map_query( fd_blockstore_block_map( blockstore ), &slot, NULL );
}

/* fd_blockstore_block_meta_query queries for the block meta keyed by
   slot.  Returns a pointer to the block meta or NULL if not in
   blockstore.  The return pointer lifetime is until slot is removed. */

FD_FN_PURE static inline fd_block_meta_t *
fd_blockstore_block_meta_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_t * block = fd_blockstore_block_query( blockstore, slot );
  if( FD_UNLIKELY( !block ) ) return NULL;
  return &block->meta;
}

/* fd_blockstore_block_data_query queries for the block data keyed by
   slot.  Returns a pointer to the block data entry or NULL if not in
   blockstore.  The return pointer lifetime is until slot is removed. */

FD_FN_PURE static inline fd_block_data_t *
fd_blockstore_block_data_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_t * block = fd_blockstore_block_query( blockstore, slot );
  if( FD_UNLIKELY( !block || !block->data.data_gaddr ) ) return NULL;
  return &block->data;
}

/* fd_blockstore_block_data_query_volatile queries the block map entry
   (metadata and block data) in a lock-free thread-safe manner that does
   not block writes.

   Returns FD_BLOCKSTORE_SLOT_MISSING if slot is missing: caller MUST
   ignore out pointers in this case. Otherwise this call cannot fail and
   returns FD_BLOCKSTORE_OK. 

   Copies the metadata (fd_block_map_t) into block_meta_out.
   Allocates a new block data (uchar *) using alloc, copies the block
   data into it, and sets the block_data_out pointer.  Caller provides
   the allocator via alloc for the copied block data (an allocator is
   needed because the block data sz is not known apriori).  */

int
fd_blockstore_block_data_query_volatile( fd_blockstore_t * blockstore,
                                         ulong             slot,
                                         fd_block_meta_t *      block_meta_out,
                                         fd_valloc_t       alloc,
                                         uchar **          block_data_out,
                                         ulong *           block_data_out_sz );

/* fd_blockstore_block_meta_query_volatile is the same as above except it
   only copies out the metadata (fd_block_map_t).  Returns
   FD_BLOCKSTORE_SLOT_MISSING if slot is missing, otherwise
   FD_BLOCKSTORE_OK. */

int
fd_blockstore_block_meta_query_volatile( fd_blockstore_t * blockstore, ulong slot, fd_block_meta_t * block_meta_out );

/* fd_blockstore_block_hash_query queries for slot's block hash. Returns
   a pointer in the local address space to the block or NULL if not in
   blockstore.  The return pointer lifetime is until the block is
   removed. */

FD_FN_PURE static inline fd_hash_t const *
fd_blockstore_block_hash_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_t * block = fd_blockstore_block_query( blockstore, slot );
  if( FD_UNLIKELY( !block || block->data.data_gaddr == 0 ) ) return NULL;
  return &block->meta.block_hash;
}

/* fd_blockstore_bank_hash_query queries for the bank hash for slot. */

FD_FN_PURE static inline fd_hash_t const *
fd_blockstore_bank_hash_query( fd_blockstore_t * blockstore, ulong slot ) {
  fd_block_meta_t * block_meta = fd_blockstore_block_meta_query( blockstore, slot );
  if( FD_UNLIKELY( !block_meta ) ) return NULL;
  return &block_meta->bank_hash;
}

/* fd_blockstore_parent_slot_query queries and returns slot's parent
   slot.  Always a valid slot (not FD_SLOT_NULL). */

ulong
fd_blockstore_parent_slot_query( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_child_slots_query queries slot's child slots.  Return
   values are saved in slots_out and slot_cnt.  Returns FD_BLOCKSTORE_OK
   on success, FD_BLOCKSTORE_ERR_SLOT_MISSING if slot is not in the
   blockstore.  The returned slot array is always <= the max size
   FD_BLOCKSTORE_CHILD_SLOT_MAX and contiguous.  Empty slots in the
   array are set to FD_SLOT_NULL. */

int
fd_blockstore_child_slots_query( fd_blockstore_t * blockstore, ulong slot, ulong ** slots_out, ulong * slot_cnt );


/* fd_blockstore_txn_query queries the transaction data for sig */

fd_blockstore_txn_map_t *
fd_blockstore_txn_query( fd_blockstore_t * blockstore, uchar const sig[static FD_ED25519_SIG_SZ] );

/* fd_blockstore_txn_query_volatile queries the transaction data for sig
   in a thread-safe manner. The transaction data is copied out.
   txn_data_out can be NULL if you are only interested in the
   transaction metadata. */

int
fd_blockstore_txn_query_volatile( fd_blockstore_t * blockstore, uchar const sig[static FD_ED25519_SIG_SZ], fd_blockstore_txn_map_t * txn_out, long * blk_ts, uchar * blk_flags, uchar txn_data_out[FD_TXN_MTU] );

/* fd_blockstore_slot_remove removes all elements (blocks, shreds, etc.)
   keyed by slot from the blockstore. */

void
fd_blockstore_slot_remove( fd_blockstore_t * blockstore, ulong slot );

/* fd_blockstore_publish publishes root to the blockstore, pruning any
   paths that are not in root's subtree.  Removes all blocks in the
   pruned paths.  Returns FD_BLOCKSTORE_OK on success,
   FD_BLOCKSTORE_ERR_X otherwise.  Caller MUST hold the write lock. */

int
fd_blockstore_publish( fd_blockstore_t * blockstore, ulong root_slot );

/* fd_blockstore_start_read acquires the blockstore rw lock for read.
   Blocks until the lock is acquired.

   IMPORTANT SAFETY TIP!  Caller must pair every call to start_read with
   end_read, and never attempt to acquire the rw lock while holding the
   lock (otherwise deadlock).  Blockstore can be an invalid state if a
   caller crashes while holding the lock. */

static inline void
fd_blockstore_start_read( fd_blockstore_t * blockstore ) {
  fd_readwrite_start_read( &blockstore->lock );
}

/* fd_blockstore_end_read releases the blockstore rw lock for read. */

static inline void
fd_blockstore_end_read( fd_blockstore_t * blockstore ) {
  fd_readwrite_end_read( &blockstore->lock );
}

/* fd_blockstore_start_read acquires the blockstore rw lock for write.
   Blocks until the lock is acquired.

   IMPORTANT SAFETY TIP!  Caller must pair every call to start_write
   with end_write, and never attempt to acquire the rw lock while
   holding the lock (otherwise deadlock).  Blockstore can be an invalid
   state if a caller crashes while holding the lock. */

static inline void
fd_blockstore_start_write( fd_blockstore_t * blockstore ) {
  fd_readwrite_start_write( &blockstore->lock );
}

/* fd_blockstore_end_write releases the blockstore rw lock for write. */

static inline void
fd_blockstore_end_write( fd_blockstore_t * blockstore ) {
  fd_readwrite_end_write( &blockstore->lock );
}

/* fd_blockstore_log_mem_usage logs the block status of around_slot in a
   human-readable format.  Caller MUST hold the read lock before
   calling this function. */

void
fd_blockstore_log_block_status( fd_blockstore_t * blockstore, ulong around_slot );

/* fd_blockstore_log_mem_usage logs the memory usage of blockstore in a
   human-readable format.  Caller MUST hold the read lock before
   calling this function. */

void
fd_blockstore_log_mem_usage( fd_blockstore_t * blockstore );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_h */
