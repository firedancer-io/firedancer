#ifndef HEADER_fd_src_discof_rotor_fd_chainer_h
#define HEADER_fd_src_discof_rotor_fd_chainer_h

/* Fec chainer is an API for reassembling shreds and FECs into slots.
   It maintains 2 levels of granularity:

   FECs, and BLOCKs (short for "slot versions").  BLOCKs are keyed by
   slot in a MAP_MULTI: the several versions of a slot chain off the
   same slot key and are distinguished by their block_id.  FECs are
   keyed by their unique merkle root, and can be shared by multiple
   blocks.

   The block_id for the turbine version is all-zero until finalization,
   after which point it will be impossible to distinguish from other
   versions. Thus, it is marked with a `turbine` flag (prevents extra
   trailing turbine shreds from creating unbounded block contexts).
   notar-fallback / SafeToNotar versions carry a real block_id from
   their cert.

   Under alpenglow, we can simplify equivocation handling. As turbine
   shreds arrive, each (slot, fec_set_idx) only accepts shreds of the
   first-seen root. Any shred with a different root is dropped.

   When a notar-fallback cert or a SafeToNotar is received for a
   block_id of a slot we don't have yet, we can add additional versions.
   No correct node ever stores more than 7 distinct blocks per slot
   (Corollary 50).

   A cert or SafeToNotar should trigger getParentandFecCount requests.
   The response should trigger getSliceHash (2.8, Definition 19)
   requests. Extra versions of a FEC set only exists once a getFecRoot
   response creates the sentinel with that root. Equivocating FEC shreds
   are accepted iff the sentinel already exists.  If the sentinel does
   not exist, the FEC shreds are dropped. This way -- turbine shreds are
   accepted without concern for whether the FEC sets belong to the "same
   slot", but votor-driven events guarantee repair of shreds that
   verifiably belong to the same slot.

   Note that in the uncommon but not impossible case where we may be
   taking a long to complete a block, we may receive a votor event for
   an honest slot that we are still in the process of receiving from
   turbine.  Since we can't compute the block_id for a slot still
   incomplete from turbine, we would create a redundant BLOCK entry for,
   logically, the same slot.  In effect, this would generate an extra
   getParentAndFecCount request and getFecRoot requests, but since we
   already have most of the data for the slot, we can avoid
   re-requesting the shreds.  This case should be rare enough that the
   redundancy is worth the simplicity.

   Note much of the complexity in chainer surrounds the fact that
   different versions of the block can share FEC sets.  It would be
   simpler to just repair the FEC sets independently per block, but
   fec_resolver de-duplicates FEC sets for as long as it lives in the
   resolver, which means it is currently not feasible to receive
   multiple FEC_COMPLETE messages for the same FEC set.  Thus once a
   shred is received for a FEC set, we have to update tracking for all
   versions of a block that share that FEC set.

   *Parent Discovery*

   The trickiness with chaining is that there's 3 different sources of
   parent information. Shreds contain parent_off field, which may or may
   not be removed in the future. The block header contains the initial
   replay parent_slot, and there can be an updateParent marker anywhere
   in the middle of the block.

   In the case where we are disconnected momentarily, or we are catching
   up, we won't ever receive shreds for the original parent slot, only
   for the updated parent slot. */

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../disco/store/fd_store.h"

#define FD_CHAINER_MAGIC (0xf17eda2ce7c4a112UL) /* firedancer chainer v1 */

#define FD_CHAINER_SLOT_VER_MAX 7 /* see Corollary 50 */

FD_STATIC_ASSERT( FD_FEC_SHRED_CNT==32UL, fd_chainer_fec_bitmap );

struct fd_chainer_fec {
  fd_hash_t merkle_root; /* key */
  uint      slot;        /* slot this FEC belongs to */
  uint      data_idxs;   /* received data shreds in this FEC */
  uint      next;        /* reserved by pool and map_chain */
  uint      prev;        /* reserved by map_chain (doubly-linked chains) */
  uint      fec_set_idx  : 28; /* position within the slot (multiple of FD_FEC_SHRED_CNT) */
  uint      complete     : 1;  /* set is reconstructable and may be delivered */
  uint      slot_complete: 1;
  uint      data_complete: 1;
  uint      is_leader    : 1;
};
typedef struct fd_chainer_fec fd_chainer_fec_t;
FD_STATIC_ASSERT( sizeof(fd_chainer_fec_t)==52UL, fd_chainer_fec );

#define POOL_NAME  fd_fec_pool
#define POOL_T     fd_chainer_fec_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_map
#define MAP_ELE_T fd_chainer_fec_t
#define MAP_IDX_T uint
#define MAP_KEY   merkle_root
#define MAP_KEY_T fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0)->uc, (k1)->uc, sizeof(fd_hash_t) ))
#define MAP_KEY_HASH(key,seed) ( (seed) ^ fd_ulong_load_8( (key)->uc ) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define AG_UNKNOWN_SLOT ULONG_MAX
struct fd_chainer_block {
  ulong           slot; /* MAP_MULTI key */
  ulong           next; /* reserved by pool and map_chain */
  ulong           prev; /* reserved by map_chain */

  uchar           turbine;          /* 1 for the block created through turbine */
  fd_hash_t       block_id;
  uint            complete_idx;
  uint            buffered_idx;     /* idx of highest buffered shred */
  uint            buffered_fec_idx; /* last shred idx of highest buffered FEC set we have received completion for */

  ulong           parent_slot;       /* AG_UNKNOWN_SLOT if unknown */
  fd_hash_t       parent_block_id;   /* block_id of the parent slot */
  uint            parent_slot_batch; /* fec_idx of the last known parent_slot information.
                                        before FLH is activated, can only be 0 or UINT_MAX. After FLH
                                        is activated, can be 0 or UINT_MAX or a multiple of FD_FEC_SHRED_CNT,
                                        and can only update to a non-zero fec_idx value once.  */

  long            complete_ts;       /* fd_log_wallclock at which every FEC set became reconstructable, 0 until then */

  /* delivery to replay */
  uchar           connected;         /* ancestor chain reaches the root */
  uint            delivered_idx;     /* last shred idx of highest fec_set_idx contiguously delivered to replay, UINT_MAX = none */
};
typedef struct fd_chainer_block fd_chainer_block_t;

#define POOL_NAME fd_block_pool
#define POOL_T    fd_chainer_block_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_block_map
#define MAP_ELE_T fd_chainer_block_t
#define MAP_KEY   slot
#define MAP_MULTI 1 /* several versions of a slot share the slot key */
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1 /* remove a specific version, not an arbitrary slot match */
#include "../../util/tmpl/fd_map_chain.c"


#define DEQUE_NAME bfs
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct out_ele {
  uint block_idx;  /* block pool idx */
  uint fec_idx;    /* fd_fec_pool idx */
};
typedef struct out_ele out_ele_t;

/* out_queue holds pool indices of FECs that have been delivered
   (contiguous from root and connected) and are awaiting publish to
   replay by the repair tile.  Sized to the max number of FECs.  Since
   out_ele maintains pool indices, the out_queue must be drained between
   any chainer call that can modify the pool. */

#define DEQUE_NAME out_queue
#define DEQUE_T    out_ele_t
#include "../../util/tmpl/fd_deque_dynamic.c"

struct fd_chainer {
  ulong root;             /* root slot, ULONG_MAX if unset */
  ulong highest_repaired; /* max slot ever marked fully_delivered (contiguous-from-root repaired tip) */
  ulong wksp_gaddr;       /* wksp gaddr of fd_chainer in the backing wksp, non-zero gaddr */

  fd_chainer_fec_t   * fec_pool;
  fd_fec_map_t       * fec_map;

  fd_chainer_block_t * block_pool;
  fd_block_map_t     * block_map;
  uint               * fec_tbl;     /* fec_tbl[ block_idx*fec_blk_max + k ] = fd_fec_pool idx of the FEC
                                       that block owns at FEC set k, UINT_MAX if none */
  ulong                fec_blk_max; /* max FEC sets per block (max_shreds_per_block/FD_FEC_SHRED_CNT) */

  ulong              * bfs;         /* bfs queue */
  out_ele_t          * out_queue;   /* delivered FEC pool idxs awaiting publish to replay */

  ulong magic; /* ==fd_chainer_MAGIC */
};
typedef struct fd_chainer fd_chainer_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_chainer_align( void ) {
  return fd_ulong_max( alignof(fd_chainer_t), 128UL );
}

/* fd_chainer_footprint returns the footprint for ele_max slots, each
   with up to fd_chainer_SLOT_VER_MAX versions of up to
   max_shreds_per_block data shreds (FD_SHRED_BLK_MAX in production,
   larger under bench limits).  Returns 0 if max_shreds_per_block is not
   a positive multiple of FD_FEC_SHRED_CNT, exceeds the 28-bit
   fec_set_idx, or asks for more FEC elements than the uint pool and map
   indices can address. */

FD_FN_CONST static inline ulong
fd_chainer_footprint( ulong ele_max,
                      ulong max_shreds_per_block ) {
  if( FD_UNLIKELY( !max_shreds_per_block || max_shreds_per_block%FD_FEC_SHRED_CNT || max_shreds_per_block>FD_SHRED_BLK_MAX_RAISED ) ) return 0UL;
  ulong blk_max       = ele_max * FD_CHAINER_SLOT_VER_MAX;
  ulong fec_blk_max   = max_shreds_per_block / FD_FEC_SHRED_CNT;
  ulong fec_max       = blk_max * fec_blk_max;
  if( FD_UNLIKELY( !fd_fec_pool_footprint( fec_max ) ) ) return 0UL;
  ulong fec_chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  ulong blk_chain_cnt = fd_block_map_chain_cnt_est( blk_max );
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
      alignof(fd_chainer_t),   sizeof(fd_chainer_t)                     ),
      fd_fec_pool_align(),     fd_fec_pool_footprint  ( fec_max       ) ),
      fd_fec_map_align(),      fd_fec_map_footprint   ( fec_chain_cnt ) ),
      fd_block_pool_align(),   fd_block_pool_footprint( blk_max       ) ),
      alignof(uint),           fec_max*sizeof(uint)                     ), /* fec_tbl */
      fd_block_map_align(),    fd_block_map_footprint ( blk_chain_cnt ) ),
      bfs_align(),             bfs_footprint          ( blk_max       ) ),
      out_queue_align(),       out_queue_footprint    ( fec_max       ) ),
    fd_chainer_align() );
}

void *
fd_chainer_new( void * shmem,
                ulong  ele_max,
                ulong  max_shreds_per_block,
                ulong  seed );

fd_chainer_t *
fd_chainer_join( void * chainer );

FD_FN_PURE static inline fd_wksp_t *
fd_chainer_wksp( fd_chainer_t * chainer ) {
  return (fd_wksp_t *)( ( (ulong)chainer ) - chainer->wksp_gaddr );
}

/* fd_chainer_highest_repaired_slot returns the highest slot on the
   contiguously-repaired chain from root (the analog of
   fd_forest_highest_repaired_slot) */

FD_FN_PURE static inline ulong
fd_chainer_highest_repaired_slot( fd_chainer_t const * chainer ) {
  return chainer->highest_repaired;
}

int
fd_chainer_verify( fd_chainer_t const * chainer );

/* Creates {slot, block_id} as the root. */

void
fd_chainer_init( fd_chainer_t *    chainer,
                 ulong             slot,
                 fd_hash_t const * block_id );


/* Every mutator below that can create a block returns that block, or
   NULL if everything it touched already existed.  The pointer is valid
   until the next fd_chainer_publish. */

/* fd_chainer_shred_insert inserts a shred into the chainer.  If the
   parent_slot is provided, parent_block_id must also be provided.
   Otherwise caller should pass AG_UNKNOWN_SLOT for parent_slot.

   Returns the turbine block if this call created it, else NULL. */

fd_chainer_block_t *
fd_chainer_shred_insert( fd_chainer_t *        chainer,
                         ulong                 slot,
                         uint                  shred_idx,
                         int                   slot_complete,
                         fd_hash_t const *     mr,
                         ulong                 parent_slot,
                         fd_hash_t const *     parent_block_id );

/* fd_chainer_fec_complete returns the turbine block if this call
   created it, else NULL.  If opt_rejected is non-NULL it is set to 1
   when the set was rejected (no block of slot owns the root: an
   unauthorized equivocation, dropped, nothing completed) and 0
   otherwise. */

fd_chainer_block_t *
fd_chainer_fec_complete( fd_chainer_t *        chainer,
                         ulong                 slot,
                         uint                  fec_set_idx,
                         int                   slot_complete,
                         int                   data_complete,
                         int                   is_leader,
                         fd_hash_t *           mr,
                         int *                 opt_rejected );

/* fd_chainer_fec_evicted clears out the received shreds for a given
   FEC set, and also updates shred tracking for slots that have this FEC
   root.

   The set must be one that is still in progress, i.e., eviction that
   fd_fec_resolver reports: a set that completes can never be chosen as
   the spill victim. */

void
fd_chainer_fec_evicted( fd_chainer_t * chainer,
                        ulong          slot,
                        uint           fec_set_idx,
                        fd_hash_t *    merkle_root );


/* fd_chainer_verified_block_insert returns {slot, block_id} if this
   call created it, NULL if it already existed. */
fd_chainer_block_t *
fd_chainer_verified_block_insert( fd_chainer_t * chainer,
                                  ulong          slot,
                                  fd_hash_t      block_id );

/* fd_chainer_verified_parent_fec_count is chainer's entrypoint for
   updating information on what a slots fec set count, parent slot, and
   parent block id are.  This mirrors the Alpenglow repair type
   getParentAndFecSetCount.  The information should be verified before
   calling this function; chainer does no verification.  Will CRIT if
   {slot, block_id} does not exist in the chainer yet, otherwise creates
   {parent_slot, parent_block_id} if it doesn't exist yet.  Returns the
   PARENT block if this call created it, else NULL. */

fd_chainer_block_t *
fd_chainer_verified_parent_fec_count( fd_chainer_t * chainer,
                                      ulong          slot,
                                      fd_hash_t *    block_id,
                                      uint           fec_set_cnt,
                                      ulong          parent_slot,
                                      fd_hash_t *    parent_block_id );

/* fd_chainer_verified_hash_insert is chainer's entrypoint for updating
   information on what a block's FEC root is.  This mirrors the Alpenglow
   repair type getFecSetRoot.  The information should be verified before
   calling this function; chainer does no verification.  Will CRIT if
   {slot, block_id} does not exist in the chainer yet, otherwise creates
   the FEC entry if it doesn't exist yet and updates bookkeeping.
   Returns the slot's turbine block if the replayed completion created
   it, else NULL. */

fd_chainer_block_t *
fd_chainer_verified_hash_insert( fd_chainer_t * chainer,
                                 ulong          slot,
                                 fd_hash_t *    block_id,
                                 uint           fec_set_idx,
                                 fd_hash_t *    mr );

/* fd_chainer_fec_query returns the FEC that the version of slot
   identified by block_id owns at fec_set_idx, or NULL. */

fd_chainer_fec_t *
fd_chainer_fec_query( fd_chainer_t const * chainer,
                      ulong                slot,
                      uint                 fec_set_idx,
                      fd_hash_t const *    block_id );

/* fd_chainer_shred_test returns 1 if block has data shred shred_idx --
   i.e. it owns the FEC at shred_idx's position and that FEC's presence
   bitmap has the shred.  The per-shred bitmap lives on the (shared) FEC,
   so this indexes block's fec_tbl row then tests fd_chainer_fec.data_idxs.
   Returns 0 for shred_idx at or beyond max_shreds_per_block. */

int
fd_chainer_shred_test( fd_chainer_t const *       chainer,
                       fd_chainer_block_t const * block,
                       uint                       shred_idx );

/* fd_chainer_publish advances the root to slot.  block_id identifies
   which version of slot is being rooted; every other version of it is
   pruned along with the slots below.  Pass NULL (or a block_id no
   version matches) to keep all versions of slot.  If store is non-NULL,
   each pruned FEC set is removed from it (rotor is the store
   publisher).

   IMPORTANT! The out_queue must be drained before calling this
   function, else there could be stale references to pruned blocks.

   Versions touched: every version of every slot below slot, and every
   version of slot other than {slot, block_id}, is pruned and gone from
   the chainer.  Nothing is created, abandoned or completed. */

void
fd_chainer_publish( fd_chainer_t *    chainer,
                    ulong             slot,
                    fd_hash_t const * block_id,
                    fd_store_t *      store );

static inline fd_chainer_block_t *
fd_chainer_block_query( fd_chainer_t const * chainer,
                        ulong                slot,
                        fd_hash_t const *    block_id ) {
  fd_chainer_block_t * block_pool = chainer->block_pool;
  fd_block_map_t     * block_map  = chainer->block_map;
  for( ulong idx = fd_block_map_idx_query_const( block_map, &slot, ULONG_MAX, block_pool );
             idx != ULONG_MAX;
             idx = fd_block_map_idx_next_const( idx, ULONG_MAX, block_pool ) ) {
    fd_chainer_block_t * block = fd_block_pool_ele( block_pool, idx );
    if( FD_UNLIKELY( fd_hash_eq( &block->block_id, block_id ) ) ) return block;
  }
  return NULL;
}

/* fd_chainer_block_fecs returns block's row of chainer->fec_tbl:
   fecs[ k ] is the fd_fec_pool idx of the FEC block owns at FEC set k
   (shred position k*FD_FEC_SHRED_CNT), UINT_MAX if none, for k in
   [0,chainer->fec_blk_max). */

FD_FN_PURE static inline uint *
fd_chainer_block_fecs( fd_chainer_t const *       chainer,
                       fd_chainer_block_t const * block ) {
  return chainer->fec_tbl + fd_block_pool_idx( chainer->block_pool, block )*chainer->fec_blk_max;
}

/* fd_chainer_block_iter_{init,next,ele} iterate the versions of a slot
   (at most FD_CHAINER_SLOT_VER_MAX) via the MAP_MULTI chain.  iter is
   a block pool idx, ULONG_MAX once exhausted.  Fetch next before
   removing the current version.  Usage:

     for( ulong i=fd_chainer_block_iter_init( chainer, slot ); i!=ULONG_MAX; i=fd_chainer_block_iter_next( chainer, i ) ) {
       fd_chainer_block_t * block = fd_chainer_block_iter_ele( chainer, i );
       ...
     } */

FD_FN_PURE static inline ulong
fd_chainer_block_iter_init( fd_chainer_t const * chainer,
                            ulong                slot ) {
  return fd_block_map_idx_query_const( chainer->block_map, &slot, ULONG_MAX, chainer->block_pool );
}

FD_FN_PURE static inline ulong
fd_chainer_block_iter_next( fd_chainer_t const * chainer,
                            ulong                iter ) {
  return fd_block_map_idx_next_const( iter, ULONG_MAX, chainer->block_pool );
}

FD_FN_PURE static inline fd_chainer_block_t *
fd_chainer_block_iter_ele( fd_chainer_t const * chainer,
                           ulong                iter ) {
  return fd_block_pool_ele( chainer->block_pool, iter );
}

/* fd_chainer_turbine_block_query returns slot's turbine version, or
   NULL if none exists.  Its block_id is all-zero until the block is
   whole and finalized; after that it is the only way to find the
   version the turbine stream built, since its key has changed. */

FD_FN_PURE static inline fd_chainer_block_t *
fd_chainer_turbine_block_query( fd_chainer_t const * chainer,
                                ulong                slot ) {
  for( ulong i=fd_chainer_block_iter_init( chainer, slot ); i!=ULONG_MAX; i=fd_chainer_block_iter_next( chainer, i ) ) {
    fd_chainer_block_t * block = fd_chainer_block_iter_ele( chainer, i );
    if( FD_LIKELY( block->turbine ) ) return block;
  }
  return NULL;
}

/* fd_chainer_block_complete returns 1 if every FEC set of the version is
   reconstructable: its tip is known and the complete sets buffered
   contiguously from 0 reach it. */

FD_FN_PURE static inline int
fd_chainer_block_complete( fd_chainer_block_t const * block ) {
  return block->complete_idx!=UINT_MAX && block->buffered_fec_idx==block->complete_idx;
}

/* fd_chainer_slot_query returns any version of slot, or NULL if the slot
   has no versions in the chainer. */

static inline fd_chainer_block_t *
fd_chainer_slot_query( fd_chainer_t * chainer, ulong slot ) {
  fd_chainer_block_t * block_pool = chainer->block_pool;
  fd_block_map_t     * block_map  = chainer->block_map;
  ulong idx = fd_block_map_idx_query_const( block_map, &slot, ULONG_MAX, block_pool );
  return idx==ULONG_MAX ? NULL : fd_block_pool_ele( block_pool, idx );
}

void
fd_chainer_print( fd_chainer_t * chainer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rotor_fd_chainer_h */
