#ifndef HEADER_fd_src_discof_chainer_fd_chainer_h
#define HEADER_fd_src_discof_chainer_fd_chainer_h

/* Fec chainer is an API for reassembling shreds and FECs into slots.
   It maintains 2 levels of granularity:

   FECs, and SLOTVs (short for "slot versions").  SLOTVs are keyed by
   slot in a MAP_MULTI: the several versions of a slot chain off the
   same slot key and are distinguished by their block_id.  FECs are
   keyed by their unique merkle root, and can be shared by multiple
   slotvs.

   The block_id for the turbine version is all-zero until finalization,
   after which point it will be impossible to distinguish from other
   versions. Thus, it is marked with a `turbine` flag (prevents extra
   trailing turbine shreds from creating unbounded slotv contexts).
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
   requests. Extra versionsof a FEC set only exists once a getFecRoot
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
   incomplete from turbine, we would create a redundant SLOTV entry for,
   logically, the same slot.  In effect, this would generate an extra
   getParentAndFecCount request and getFecRoot requests, but since we
   already have most of the data for the slot, we can avoid
   re-requesting the shreds.  This case should be rare enough that the
   redundancy is worth the simplicity.

   *Parent Discovery*

   The trickiness with chaining is that there's 3 different sources of
   parent information. Shreds contain parent_off field, which may or may
   not be removed in the future. The block header contains the initial
   replay parent_slot, and there can be an updateParent marker anywhere
   in the middle of the block.

   In the case where we are disconnected momentarily, or we are catching
   up, we won't ever receive shreds for the original parent slot, only
   for the updated parent slot. We currently assume parent_off will
   update with the parentUpdate marker.
*/

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"

#define FD_CHAINER_MAGIC (0xf17eda2ce7c4a112UL) /* firedancer chainer v1 */

#define FD_CHAINER_SLOT_VER_MAX 7 /* see Corollary 50 */

#define SET_NAME fd_fec_idxs
#define SET_MAX  FD_FEC_SHRED_CNT
#include "../../util/tmpl/fd_set.c"

struct fd_chainer_fec {
  fd_hash_t merkle_root; /* key */
  ulong     next;        /* reserved by pool and map_chain */
  ulong     prev;        /* reserved by map_chain (doubly-linked chains) */

  ulong     slot;        /* slot this FEC belongs to */
  uint      fec_set_idx; /* position within the slot (multiple of FD_FEC_SHRED_CNT) */
  fd_fec_idxs_t data_idxs[fd_fec_idxs_word_cnt];
  uchar     complete;      /* 1 once fd_chainer_fec_complete has run for this
                              FEC, i.e. the set is reconstructable and may
                              be delivered.  A FEC created on first shred
                              (or from a getSliceHash cert, awaiting shreds)
                              is complete==0 until then; delivery and the
                              contiguous-FEC prefix gate on this. */
  uchar     slot_complete;
  uchar     data_complete;
};
typedef struct fd_chainer_fec fd_chainer_fec_t;

#define POOL_NAME fd_fec_pool
#define POOL_T    fd_chainer_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_map
#define MAP_ELE_T fd_chainer_fec_t
#define MAP_KEY   merkle_root
#define MAP_KEY_T fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0)->uc, (k1)->uc, sizeof(fd_hash_t) ))
#define MAP_KEY_HASH(key,seed) ( (seed) ^ fd_ulong_load_8( (key)->uc ) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define AG_UNKNOWN_SLOT ULONG_MAX
struct fd_chainer_slotv {
  ulong           slot; /* MAP_MULTI key */
  ulong           next; /* reserved by pool and map_chain */
  ulong           prev; /* reserved by map_chain */

  uchar           turbine; /* 1 for the slotv created through turbine */
  fd_hash_t       block_id;
  uint            fec[FD_FEC_BLK_MAX]; /* fec[k] = fd_fec_pool idx of the FEC this
                                          version owns. TODO assert pool_idx < UINT_MAX */
  uint            complete_idx;
  uint            buffered_idx;     /* idx of highest buffered shred */
  uint            buffered_fec_idx; /* last shred idx of highest buffered FEC set we have received completion for */

  ulong           parent_slot;       /* AG_UNKNOWN_SLOT if unknown */
  fd_hash_t       parent_block_id;   /* block_id of the parent slot */
  uint            parent_slot_batch; /* fec_idx of the last known parent_slot information.
                                        before FLH is activated, can only be 0 or UINT_MAX. After FLH
                                        is activated, can be 0 or UINT_MAX or a multiple of FD_FEC_SHRED_CNT,
                                        and can only update to a non-zero fec_idx value once.  */

  /* delivery to replay */
  uchar           connected;         /* ancestor chain reaches the root */
  uint            delivered_idx;     /* last shred idx of highest fec_set_idx contiguously delivered to replay, UINT_MAX = none */

  /* repair scheduling.  While an slotv has un-requested work it is
     tracked by a worklist element (fd_sched_ele) in the repair and/or
     orphan treap.  highest_requested stays on the slotv: the sched ele
     is freed whenever the slotv leaves both treaps and recreated on
     re-add, so keeping the high-water mark here preserves it across
     those cycles. */
  uint            highest_requested; /* highest idx we've issued a repair request for, UINT_MAX = none */
};
typedef struct fd_chainer_slotv fd_chainer_slotv_t;

#define POOL_NAME fd_slotv_pool
#define POOL_T    fd_chainer_slotv_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_slotv_map
#define MAP_ELE_T fd_chainer_slotv_t
#define MAP_KEY   slot
#define MAP_MULTI 1 /* several versions of a slot share the slot key */
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1 /* remove a specific version, not an arbitrary slot match */
#include "../../util/tmpl/fd_map_chain.c"

/* fd_sched_ele is a worklist element: the repair (shred-fill) and
   orphan (ancestry) treaps are built from these. An ele exists only
   while its slotv is in at least one treap; it is created on the first
   add and freed once removed from both. */
struct fd_sched_ele {
  ulong slotv_idx;  /* fd_slotv_pool idx */
  ulong slot;
  ulong next;       /* reserved by pool and map_chain */
  ulong prev;       /* reserved by map_chain */
  uchar in_repair;  /* 1 if currently in the repair (shred-fill) treap */
  uchar in_orphan;  /* 1 if currently in the orphan (ancestry) treap */
  struct { ulong parent, left, right, next, prev, prio; } repair;
  struct { ulong parent, left, right, next, prev, prio; } orphan;
};
typedef struct fd_sched_ele fd_sched_ele_t;

#define POOL_NAME fd_sched_pool
#define POOL_T    fd_sched_ele_t
#include "../../util/tmpl/fd_pool.c"

/* keyed by slotv_idx (unique per shadowed slotv) */
#define MAP_NAME  fd_sched_map
#define MAP_ELE_T fd_sched_ele_t
#define MAP_KEY   slotv_idx
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

/* Repair worklist: eles ordered by slot, iterated min-first so repair
   proceeds from the root forward. */
#define TREAP_NAME               fd_sched_repair
#define TREAP_T                  fd_sched_ele_t
#define TREAP_QUERY_T            ulong
#define TREAP_CMP(q,e)           ( ((q)>(e)->slot) - ((q)<(e)->slot) )
#define TREAP_LT(e0,e1)          ( (e0)->slot < (e1)->slot )
#define TREAP_IDX_T              ulong
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_PARENT             repair.parent
#define TREAP_LEFT               repair.left
#define TREAP_RIGHT              repair.right
#define TREAP_NEXT               repair.next
#define TREAP_PREV               repair.prev
#define TREAP_PRIO               repair.prio
#include "../../util/tmpl/fd_treap.c"

/* Orphan worklist: eles whose slotv's immediate parent is not yet
   present, or parent_slot is not known.  An ele leaves this treap once
   its parent slotv exists. */
#define TREAP_NAME               fd_sched_orphan
#define TREAP_T                  fd_sched_ele_t
#define TREAP_QUERY_T            ulong
#define TREAP_CMP(q,e)           ( ((q)>(e)->slot) - ((q)<(e)->slot) )
#define TREAP_LT(e0,e1)          ( (e0)->slot < (e1)->slot )
#define TREAP_IDX_T              ulong
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_PARENT             orphan.parent
#define TREAP_LEFT               orphan.left
#define TREAP_RIGHT              orphan.right
#define TREAP_NEXT               orphan.next
#define TREAP_PREV               orphan.prev
#define TREAP_PRIO               orphan.prio
#include "../../util/tmpl/fd_treap.c"


#define DEQUE_NAME             bfs
#define DEQUE_T                ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct out_ele {
  uint slotv_idx;  /* slotv pool idx */
  uint fec_idx;    /* fd_fec_pool idx */
};
typedef struct out_ele out_ele_t;

/* out_queue holds pool indices of FECs that have been delivered
   (contiguous from root and connected) and are awaiting publish to
   replay by the repair tile.  Sized to the max number of FECs.  Since
   out_ele maintains pool indices, the out_queue must be drained between
   any chainer call that can modify the pool. */
#define DEQUE_NAME             out_queue
#define DEQUE_T                out_ele_t
#include "../../util/tmpl/fd_deque_dynamic.c"

struct fd_chainer {
  ulong root;             /* root slot, ULONG_MAX if unset */
  ulong highest_repaired; /* max slot ever marked fully_delivered (contiguous-from-root repaired tip) */
  ulong wksp_gaddr;       /* wksp gaddr of fd_chainer in the backing wksp, non-zero gaddr */

  fd_chainer_fec_t * fec_pool;
  fd_fec_map_t     * fec_map;

  fd_chainer_slotv_t * slotv_pool;
  fd_slotv_map_t     * slotv_map;

  /* Repair scheduling worklists */
  fd_sched_ele_t    * sched_pool;
  fd_sched_map_t    * sched_map;
  fd_sched_repair_t * repair_treap;
  fd_sched_orphan_t * orphan_treap;

  ulong * bfs;              /* bfs queue */
  out_ele_t * out_queue;    /* delivered FEC pool idxs awaiting publish to replay */

  ulong magic; /* ==FD_CHAINER_MAGIC */
};
typedef struct fd_chainer fd_chainer_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_chainer_align( void ) {
  return fd_ulong_max( alignof(fd_chainer_t), 128UL );
}

FD_FN_CONST static inline ulong
fd_chainer_footprint( ulong ele_max ) {
  ulong blk_max       = ele_max * FD_CHAINER_SLOT_VER_MAX;
  ulong fec_max       = blk_max * FD_FEC_BLK_MAX;
  ulong fec_chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  ulong blk_chain_cnt = fd_slotv_map_chain_cnt_est( blk_max );
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
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_chainer_t),   sizeof(fd_chainer_t)                        ),
      fd_fec_pool_align(),     fd_fec_pool_footprint    ( fec_max )        ),
      fd_fec_map_align(),      fd_fec_map_footprint     ( fec_chain_cnt )  ),
      fd_slotv_pool_align(),   fd_slotv_pool_footprint  ( blk_max )        ),
      fd_slotv_map_align(),    fd_slotv_map_footprint   ( blk_chain_cnt  ) ),
      fd_sched_pool_align(),   fd_sched_pool_footprint  ( blk_max        ) ),
      fd_sched_map_align(),    fd_sched_map_footprint   ( blk_chain_cnt  ) ),
      fd_sched_repair_align(), fd_sched_repair_footprint( blk_max        ) ),
      fd_sched_orphan_align(), fd_sched_orphan_footprint( blk_max        ) ),
      bfs_align(),             bfs_footprint            ( blk_max        ) ),
      out_queue_align(),       out_queue_footprint      ( fec_max )        ),
    fd_chainer_align() );
}

void *
fd_chainer_new( void * shmem, ulong ele_max, ulong seed );

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

void
fd_chainer_init( fd_chainer_t    * chainer,
                 ulong             slot,
                 fd_hash_t const * block_id );

/* fd_chainer_shred_insert inserts a shred into the chainer.  If the
   parent_slot is provided, parent_block_id must also be provided.
   Otherwise caller should pass AG_UNKNOWN_SLOT for parent_slot. */
fd_chainer_slotv_t *
fd_chainer_shred_insert( fd_chainer_t *    chainer,
                         ulong             slot,
                         uint              shred_idx,
                         int               slot_complete,
                         fd_hash_t const * mr,
                         ulong             parent_slot,
                         fd_hash_t const * parent_block_id );

/* 0 if the FEC was accepted, 1 if rejected */
int
fd_chainer_fec_complete( fd_chainer_t * chainer,
                         ulong          slot,
                         uint           fec_set_idx,
                         int            slot_complete,
                         int            data_complete,
                         fd_hash_t    * mr );

/* Clears out the received shreds for a given FEC set, and also updates
   shred tracking for slots that have this FEC root. */
void
fd_chainer_fec_evicted( fd_chainer_t * chainer,
                        ulong          slot,
                        uint           fec_set_idx,
                        fd_hash_t    * merkle_root );

void
fd_chainer_notar_fallback( fd_chainer_t * chainer,
                           ulong          slot,
                           fd_hash_t      block_id );

fd_chainer_slotv_t *
fd_chainer_verified_parent_fec_count( fd_chainer_t * chainer,
                                      ulong          slot,
                                      fd_hash_t    * block_id,
                                      uint           fec_set_cnt,
                                      ulong          parent_slot,
                                      fd_hash_t    * parent_block_id );

void
fd_chainer_verified_hash_insert( fd_chainer_t * chainer,
                                 ulong          slot,
                                 fd_hash_t    * block_id,
                                 uint           fec_set_idx,
                                 fd_hash_t    * mr );

/* fd_chainer_shred_for_block_id_verify returns 1 if mr matches the root
   previously established by a (proof-verified) getFecRoot response for
   the version of the slot identified by block_id.  Returns 0 if the
   version is unknown, the FEC root hasn't been authorized yet, or the
   roots differ.  Used to verify ShredForBlockId responses before
   admitting them to the chainer. */
int
fd_chainer_shred_for_block_id_verify( fd_chainer_t *    chainer,
                                      ulong             slot,
                                      uint              fec_set_idx,
                                      fd_hash_t const * block_id,
                                      fd_hash_t const * mr );

/* fd_chainer_fec_query returns the FEC that the version of slot identified
   by block_id owns at fec_set_idx, or NULL. */
fd_chainer_fec_t *
fd_chainer_fec_query( fd_chainer_t *    chainer,
                      ulong             slot,
                      uint              fec_set_idx,
                      fd_hash_t const * block_id );

/* fd_chainer_shred_test returns 1 if slotv has data shred shred_idx --
   i.e. it owns the FEC at shred_idx's position and that FEC's presence
   bitmap has the shred.  The per-shred bitmap lives on the (shared) FEC,
   so this indexes slotv->fec[] then tests fd_chainer_fec.data_idxs. */

int
fd_chainer_shred_test( fd_chainer_t *             chainer,
                       fd_chainer_slotv_t const * slotv,
                       uint                       shred_idx );

/* fd_chainer_slotv_shred_cnt returns the number of data shreds slotv
   has, summed over the FECs it owns. */

ulong
fd_chainer_slotv_shred_cnt( fd_chainer_t *             chainer,
                            fd_chainer_slotv_t const * slotv );

/* fd_chainer_publish advances the root to slot.  block_id identifies
   which version of slot is being rooted; every other version of it is
   pruned along with the slots below.  Pass NULL (or a block_id no
   version matches) to keep all versions of slot. */

void
fd_chainer_publish( fd_chainer_t *    chainer,
                    ulong             slot,
                    fd_hash_t const * block_id );

static inline fd_chainer_slotv_t *
fd_chainer_slot_version_query( fd_chainer_t *    chainer,
                               ulong             slot,
                               fd_hash_t const * block_id ) {
  fd_chainer_slotv_t     * slotv_pool = chainer->slotv_pool;
  fd_slotv_map_t * slotv_map  = chainer->slotv_map;
  for( ulong idx = fd_slotv_map_idx_query_const( slotv_map, &slot, ULONG_MAX, slotv_pool );
             idx != ULONG_MAX;
             idx = fd_slotv_map_idx_next_const( idx, ULONG_MAX, slotv_pool ) ) {
    fd_chainer_slotv_t * slotv = fd_slotv_pool_ele( slotv_pool, idx );
    if( FD_UNLIKELY( fd_hash_eq( &slotv->block_id, block_id ) ) ) return slotv;
  }
  return NULL;
}

/* fd_chainer_slot_query returns any version of slot, or NULL if the slot
   has no versions in the chainer. */

static inline fd_chainer_slotv_t *
fd_chainer_slot_query( fd_chainer_t * chainer, ulong slot ) {
  fd_chainer_slotv_t     * slotv_pool = chainer->slotv_pool;
  fd_slotv_map_t * slotv_map  = chainer->slotv_map;
  ulong idx = fd_slotv_map_idx_query_const( slotv_map, &slot, ULONG_MAX, slotv_pool );
  return idx==ULONG_MAX ? NULL : fd_slotv_pool_ele( slotv_pool, idx );
}

/* fd_chainer_sched_ele returns the worklist ele shadowing slotv, or NULL
   if the slotv is in neither treap. */

FD_FN_UNUSED static inline fd_sched_ele_t *
fd_chainer_sched_ele( fd_chainer_t * chainer, fd_chainer_slotv_t const * slotv ) {
  ulong slotv_idx = fd_slotv_pool_idx( chainer->slotv_pool, slotv );
  return fd_sched_map_ele_query( chainer->sched_map, &slotv_idx, NULL, chainer->sched_pool );
}

/* fd_chainer_sched_ele_acquire returns the ele shadowing slotv, creating
   (and map-inserting) it if none exists yet. */

static inline fd_sched_ele_t *
fd_chainer_sched_ele_acquire( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  fd_sched_ele_t * ele = fd_chainer_sched_ele( chainer, slotv );
  if( FD_LIKELY( ele ) ) return ele;
  ele            = fd_sched_pool_ele_acquire( chainer->sched_pool );
  ele->slotv_idx = fd_slotv_pool_idx( chainer->slotv_pool, slotv );
  ele->slot      = slotv->slot;
  ele->in_repair = 0;
  ele->in_orphan = 0;
  fd_sched_map_ele_insert( chainer->sched_map, ele, chainer->sched_pool );
  return ele;
}

/* fd_chainer_sched_ele_gc frees ele once it is in neither treap. */

static inline void
fd_chainer_sched_ele_gc( fd_chainer_t * chainer, fd_sched_ele_t * ele ) {
  if( FD_LIKELY( ele->in_repair || ele->in_orphan ) ) return;
  fd_sched_map_ele_remove_fast( chainer->sched_map, ele, chainer->sched_pool );
  fd_sched_pool_ele_release( chainer->sched_pool, ele );
}

/* fd_chainer_{repair,orphan}_{add,remove} add/removes an slotv from the
   repair/orphan worklist treap via its sched ele.  Idempotent via
   ele->in_repair / ele->in_orphan.  _add is called by the chainer
   whenever new requestable work appears (slotv created, complete_idx
   learned, new sentinel); _remove is called by the repair walk once the
   slotv has been fully requested. */

static inline void
fd_chainer_repair_add( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  fd_sched_ele_t * ele = fd_chainer_sched_ele_acquire( chainer, slotv );
  if( FD_UNLIKELY( ele->in_repair ) ) return;
  fd_sched_repair_ele_insert( chainer->repair_treap, ele, chainer->sched_pool );
  ele->in_repair = 1;
}

static inline void
fd_chainer_repair_remove( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  fd_sched_ele_t * ele = fd_chainer_sched_ele( chainer, slotv );
  if( FD_UNLIKELY( !ele || !ele->in_repair ) ) return;
  fd_sched_repair_ele_remove( chainer->repair_treap, ele, chainer->sched_pool );
  ele->in_repair = 0;
  fd_chainer_sched_ele_gc( chainer, ele );
}

static inline void
fd_chainer_orphan_add( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  fd_sched_ele_t * ele = fd_chainer_sched_ele_acquire( chainer, slotv );
  if( FD_UNLIKELY( ele->in_orphan ) ) return;
  fd_sched_orphan_ele_insert( chainer->orphan_treap, ele, chainer->sched_pool );
  ele->in_orphan = 1;
}

static inline void
fd_chainer_orphan_remove( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  fd_sched_ele_t * ele = fd_chainer_sched_ele( chainer, slotv );
  if( FD_UNLIKELY( !ele || !ele->in_orphan ) ) return;
  fd_sched_orphan_ele_remove( chainer->orphan_treap, ele, chainer->sched_pool );
  ele->in_orphan = 0;
  fd_chainer_sched_ele_gc( chainer, ele );
}

/* fd_chainer_in_{repair,orphan} report whether slotv is currently in the
   repair/orphan worklist. */

FD_FN_UNUSED static inline int
fd_chainer_in_repair( fd_chainer_t * chainer, fd_chainer_slotv_t const * slotv ) {
  fd_sched_ele_t * ele = fd_chainer_sched_ele( chainer, slotv );
  return ele && ele->in_repair;
}

FD_FN_UNUSED static inline int
fd_chainer_in_orphan( fd_chainer_t * chainer, fd_chainer_slotv_t const * slotv ) {
  fd_sched_ele_t * ele = fd_chainer_sched_ele( chainer, slotv );
  return ele && ele->in_orphan;
}

void
fd_chainer_print( fd_chainer_t * chainer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_chainer_fd_chainer_h */
