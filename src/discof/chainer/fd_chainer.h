#ifndef HEADER_fd_src_discof_chainer_fd_chainer_h
#define HEADER_fd_src_discof_chainer_fd_chainer_h

/* Fec chainer is an API for reassembling shreds and FECs into slots.
   It maintains 2 levels of granularity:

   FECs, and SLOTVs (short for "slot versions"). SLOTVs are keyed by
   (slot, v) where v is the version number.  FECs are keyed by position
   alone (slot, fec_set_idx) and carry the set of slot versions that
   include it.

   Version 0 is reserved for the turbine version of the slot, and
   notar-fallback / parent-discovery versions are assigned from 1 up.
   Version numbers are therefore NOT densely packed: a slot we only know
   about from a notar-fallback cert has a v1 and no v0 until turbine (or
   block-id repair) delivers something for it. 

   Under alpenglow, we can simplify equivocation handling. As turbine
   shreds arrive, each (slot, fec_set_idx) only accepts shreds of the
   first-seen root. Any shred with a different root is dropped.

   When a notar-fallback cert is received for a block_id of a slot we
   don't have yet, we can add additional versions. Protocol dictates
   only 3 notar-fallbacks can arrive per slot.

   Note for the turbine slotv (v0) - it accepts THE FIRST seen of any
   shred or FEC set. this can be populated by regular turbine shreds or
   by alpenglow blockid repair results.

   A notar-fallback cert should trigger getParentandFecCount requests.
   The response should trigger getFecRoot requests.  The v>=1 version of
   a FEC set only exists once a getFecRoot response creates the sentinel
   with that root. Equivocating FEC shreds are accepted iff the sentinel
   already exists.  If the sentinel does not exist, the FEC shreds are
   dropped.

   This way -- turbine shreds are accepted without concern for whether
   the FEC sets belong to the "same slot", but notar-fallback certs
   guarantee repair of shreds that verifiably belong to the same slot.

   Note that in the uncommon but not impossible case where we may be
   taking a long to complete a block, we may receive a notar-fallback
   cert for an honest slot that we are still in the process of receiving
   from turbine.  Since we can't compute the block_id for a slot still
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
   in the middle of the block. The parent_offs of the shreds do not
   change after a parentUpdate.

   In the case where we are disconnected momentarily, or we are catching
   up, we won't ever receive shreds for the original parent slot, only
   for the updated parent slot. So if we take at face value the
   parent_off described by the shreds (or the initial block header), we
   will end up stalled.  TODO continue here...
*/

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"

#define FD_CHAINER_MAGIC (0xf17eda2ce7c4a112UL) /* firedancer chainer v1 */

#define FD_CHAINER_SLOT_VER_MAX 4 /* Protocol dictates 3 notar-fallbacks per slot + 1 turbine version */

/* slot:47 | fec_set_idx:15 */
#define FD_CHAINER_FEC_KEY( slot, fec_set_idx ) \
  ( ((ulong)(slot))<<17 | ((ulong)(fec_set_idx)) )

#define SET_NAME fd_slotv_set
#define SET_MAX  FD_CHAINER_SLOT_VER_MAX
#include "../../util/tmpl/fd_set.c"
struct fd_fec {
  ulong     key;       /* (slot, fec_set_idx) position, MAP_MULTI key */
  ulong     next;      /* reserved by pool and map_chain */
  ulong     slot_next; /* next FEC of the same slot, in no particular
                          order (fd_fec_pool idx, idx_null terminates).
                          The list is per-slot rather than per-version: a
                          FEC may be shared by several versions but has only
                          this one link, so the head lives on version 0's
                          slotv.  Lets publish release a slot's FECs in
                          O(k) instead of probing every position. */
  fd_hash_t merkle_root; /* unique FEC set identifier */

  fd_slotv_set_t versions[fd_slotv_set_word_cnt]; /* set of the slot versions that have
                                                     this root at this position. */
  uchar     slot_complete;
  uchar     sentinel;      /* 1 if this is a sentinel FEC, i.e. we know
                              this FEC is canonically part of a
                              notar-fallback slot, but we haven't
                              actually completed it yet. */
};
typedef struct fd_fec fd_fec_t;

#define POOL_NAME fd_fec_pool
#define POOL_T    fd_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_fec_map
#define MAP_ELE_T fd_fec_t
#define MAP_KEY   key
#define MAP_MULTI 1 /* up to FD_CHAINER_SLOT_VER_MAX distinct roots may share a (slot, fec_set_idx) */
#include "../../util/tmpl/fd_map_chain.c"

#define SET_NAME fd_shred_idxs
#define SET_MAX  FD_SHRED_BLK_MAX
#include "../../util/tmpl/fd_set.c"

#define FD_CHAINER_SLOTV_KEY( slot, version ) \
  ( ((ulong)(slot))<<17 | (ushort)(version) )
#define FD_CHAINER_SLOTV_SLOT( key )    ( (ulong)(key) >> 17 )
#define FD_CHAINER_SLOTV_VERSION( key ) ( (ulong)(key) & 0x3UL )

#define AG_UNKNOWN_SLOT ULONG_MAX
struct fd_slotv {
  ulong           key; /* (slot:47, v) where v<4 */
  ulong           next; /* reserved by pool and map_chain */
  fd_hash_t       block_id;
  fd_shred_idxs_t shred_idxs[fd_shred_idxs_word_cnt];
  uint            complete_idx;
  uint            buffered_idx;     /* idx of highest buffered shred */
  uint            buffered_fec_idx; /* last shred idx of highest buffered FEC set we have received completion for */
  ulong           fec_head;         /* head of this slot's FEC list (fd_fec_pool idx).
                                       Only maintained on version 0. List follows slot_next pointer. */

  ulong           parent_slot;       /* AG_UNKNOWN_SLOT if unknown */
  fd_hash_t       parent_block_id;   /* block_id of the parent slot */
  uint            parent_slot_batch; /* fec_idx of the last known parent_slot information.
                                        before FLH is activated, can only be 0 or UINT_MAX. After FLH
                                        is activated, can be 0 or UINT_MAX or a multiple of FD_FEC_SHRED_CNT,
                                        and can only update to a non-zero fec_idx value once.  */

  /* delivery to replay */
  uchar           connected;         /* ancestor chain reaches the root */
  uint            delivered_idx;     /* last shred idx of highest fec_set_idx contiguously delivered to replay, UINT_MAX = none */

  /* repair scheduling.  An slotv sits in the repair treap (ordered by
     key = slot then version) while it has un-requested work.  The walk
     issues each missing idx once, advancing highest_requested, and pops
     the slotv when it reaches complete_idx; the chainer re-adds it when
     new work appears. */
  uint            highest_requested; /* highest idx we've issued a repair request for, UINT_MAX = none */
  uchar           in_treap;          /* 1 if currently in the repair (shred-fill) treap */
  uchar           in_orphan;         /* 1 if currently in the orphan (ancestry discovery) treap */
  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong next;
    ulong prev;
    ulong prio;
  } repair;
  /* second, independent set of treap links so an slotv can be in the
     shred-fill treap and the orphan treap at the same time */
  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong next;
    ulong prev;
    ulong prio;
  } orphan;
};
typedef struct fd_slotv fd_slotv_t;

#define POOL_NAME fd_slotv_pool
#define POOL_T    fd_slotv_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_slotv_map
#define MAP_ELE_T fd_slotv_t
#define MAP_KEY   key
#include "../../util/tmpl/fd_map_chain.c"

/* Repair worklist: slotvs ordered by key (slot, then version), iterated
   min-first so repair proceeds from the root forward. */
#define TREAP_NAME               fd_slotv_repair
#define TREAP_T                  fd_slotv_t
#define TREAP_QUERY_T            ulong
#define TREAP_CMP(q,e)           ( ((q)>(e)->key) - ((q)<(e)->key) )
#define TREAP_LT(e0,e1)          ( (e0)->key < (e1)->key )
#define TREAP_IDX_T              ulong
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_PARENT             repair.parent
#define TREAP_LEFT               repair.left
#define TREAP_RIGHT              repair.right
#define TREAP_NEXT               repair.next
#define TREAP_PREV               repair.prev
#define TREAP_PRIO               repair.prio
#include "../../util/tmpl/fd_treap.c"

/* Orphan worklist: slotvs whose immediate parent is not yet present, or
   parent_slot is not known. Same ordering (slot, then version),
   min-first, so we discover ancestry from the bottom (closest to root)
   up.  An slotv leaves this treap once its parent slotv exists. */
#define TREAP_NAME               fd_slotv_orphan
#define TREAP_T                  fd_slotv_t
#define TREAP_QUERY_T            ulong
#define TREAP_CMP(q,e)           ( ((q)>(e)->key) - ((q)<(e)->key) )
#define TREAP_LT(e0,e1)          ( (e0)->key < (e1)->key )
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

struct fd_chainer {
  ulong root;             /* root slot, ULONG_MAX if unset */
  ulong highest_repaired; /* max slot ever marked fully_delivered (contiguous-from-root repaired tip) */
  ulong wksp_gaddr;       /* wksp gaddr of fd_chainer in the backing wksp, non-zero gaddr */

  ulong fec_pool_gaddr;   /* wksp gaddr of fd_fec_pool */
  ulong fec_map_gaddr;    /* wksp gaddr of fd_fec_map (flat, keyed by (slot,fec_set_idx,version)) */

  ulong slotv_pool_gaddr;   /* wksp gaddr of fd_slotv_pool */
  ulong slotv_map_gaddr;    /* wksp gaddr of fd_slotv_map */
  ulong repair_treap_gaddr; /* wksp gaddr of fd_slotv_repair (shred-fill worklist) */
  ulong orphan_treap_gaddr; /* wksp gaddr of fd_slotv_orphan (ancestry worklist) */

  ulong bfs_gaddr;          /* bfs queue for delivery */

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
  ulong fec_max = ele_max * FD_FEC_BLK_MAX;
  ulong fec_chain_cnt  = fd_fec_map_chain_cnt_est( fec_max );
  ulong slot_chain_cnt = fd_slotv_map_chain_cnt_est( ele_max );
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
      alignof(fd_chainer_t),   sizeof(fd_chainer_t)                        ),
      fd_fec_pool_align(),     fd_fec_pool_footprint    ( fec_max )        ),
      fd_fec_map_align(),      fd_fec_map_footprint     ( fec_chain_cnt )  ),
      fd_slotv_pool_align(),   fd_slotv_pool_footprint  ( ele_max )        ),
      fd_slotv_map_align(),    fd_slotv_map_footprint   ( slot_chain_cnt ) ),
      fd_slotv_repair_align(), fd_slotv_repair_footprint( ele_max )        ),
      fd_slotv_orphan_align(), fd_slotv_orphan_footprint( ele_max )        ),
      bfs_align(),             bfs_footprint            ( ele_max )        ),
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

FD_FN_PURE static inline fd_fec_t *
fd_chainer_fec_pool( fd_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->fec_pool_gaddr );
}

FD_FN_PURE static inline fd_fec_map_t *
fd_chainer_fec_map( fd_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->fec_map_gaddr );
}

FD_FN_PURE static inline fd_slotv_t *
fd_chainer_slotv_pool( fd_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->slotv_pool_gaddr );
}

FD_FN_PURE static inline fd_slotv_map_t *
fd_chainer_slotv_map( fd_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->slotv_map_gaddr );
}

FD_FN_PURE static inline fd_slotv_repair_t *
fd_chainer_repair_treap( fd_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->repair_treap_gaddr );
}

FD_FN_PURE static inline fd_slotv_orphan_t *
fd_chainer_orphan_treap( fd_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->orphan_treap_gaddr );
}

FD_FN_PURE static inline ulong *
fd_chainer_bfs( fd_chainer_t * chainer ) {
  return fd_wksp_laddr_fast( fd_chainer_wksp( chainer ), chainer->bfs_gaddr );
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
void
fd_chainer_shred_insert( fd_chainer_t *    chainer,
                         ulong             slot,
                         uint              shred_idx,
                         int               slot_complete,
                         fd_hash_t const * mr,
                         ulong             parent_slot,
                         fd_hash_t const * parent_block_id );

/* 0 if the FEC was accepted, 1 if rejected */
int
fd_chainer_fec_insert( fd_chainer_t * chainer,
                       ulong          slot,
                       uint           fec_set_idx,
                       int            slot_complete,
                       fd_hash_t    * mr );


void
fd_chainer_notar_fallback( fd_chainer_t * chainer,
                           ulong          slot,
                           fd_hash_t      block_id );

fd_slotv_t *
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

/* fd_chainer_fec_query returns a pointer to the FEC entry
   for (slot, fec_set_idx, version) if it exists, NULL otherwise. */
fd_fec_t *
fd_chainer_fec_query( fd_chainer_t * chainer,
                      ulong          slot,
                      uint           fec_set_idx,
                      ulong          version );

/* fd_chainer_publish advances the root to slot.  block_id identifies
   which version of slot is being rooted; every other version of it is
   pruned along with the slots below.  Pass NULL (or a block_id no
   version matches) to keep all versions of slot. */

void
fd_chainer_publish( fd_chainer_t *    chainer,
                    ulong             slot,
                    fd_hash_t const * block_id );

static inline fd_slotv_t *
fd_chainer_slot_version_query( fd_chainer_t *    chainer,
                               ulong             slot,
                               fd_hash_t const * block_id ) {
  fd_slotv_t * slotv_pool = fd_chainer_slotv_pool( chainer );
  fd_slotv_map_t * slotv_map = fd_chainer_slotv_map( chainer );
  /* versions are not dense */
  for( uint version = 0; version < FD_CHAINER_SLOT_VER_MAX; version++ ) {
    ulong slotv_key = FD_CHAINER_SLOTV_KEY( slot, version );
    fd_slotv_t * slotv = fd_slotv_map_ele_query( slotv_map, &slotv_key, NULL, slotv_pool );
    if( FD_UNLIKELY( slotv && fd_hash_eq( &slotv->block_id, block_id ) ) ) return slotv;
  }
  return NULL;
}

/* fd_chainer_slot_query returns 1 if any version of slot exists in the
   chainer, 0 otherwise */

static inline fd_slotv_t *
fd_chainer_slot_query( fd_chainer_t * chainer, ulong slot ) {
  fd_slotv_t     * slotv_pool = fd_chainer_slotv_pool( chainer );
  fd_slotv_map_t * slotv_map  = fd_chainer_slotv_map ( chainer );
  ulong key = FD_CHAINER_SLOTV_KEY( slot, 0 );
  return fd_slotv_map_ele_query( slotv_map, &key, NULL, slotv_pool );
}

/* fd_chainer_{repair,orphan}_{add,remove} add/removes an slotv from the
   repair worklist treap.  Idempotent via slotv->in_treap.  _add is
   called by the chainer whenever new requestable work appears (slotv
   created, complete_idx learned, new sentinel); _remove is called by
   the repair walk once the slotv has been fully requested. */

static inline void
fd_chainer_repair_add( fd_chainer_t * chainer, fd_slotv_t * slotv ) {
  if( FD_UNLIKELY( slotv->in_treap ) ) return;
  fd_slotv_repair_ele_insert( fd_chainer_repair_treap( chainer ), slotv, fd_chainer_slotv_pool( chainer ) );
  slotv->in_treap = 1;
}

static inline void
fd_chainer_repair_remove( fd_chainer_t * chainer, fd_slotv_t * slotv ) {
  if( FD_UNLIKELY( !slotv->in_treap ) ) return;
  fd_slotv_repair_ele_remove( fd_chainer_repair_treap( chainer ), slotv, fd_chainer_slotv_pool( chainer ) );
  slotv->in_treap = 0;
}

static inline void
fd_chainer_orphan_add( fd_chainer_t * chainer, fd_slotv_t * slotv ) {
  if( FD_UNLIKELY( slotv->in_orphan ) ) return;
  fd_slotv_orphan_ele_insert( fd_chainer_orphan_treap( chainer ), slotv, fd_chainer_slotv_pool( chainer ) );
  slotv->in_orphan = 1;
}

static inline void
fd_chainer_orphan_remove( fd_chainer_t * chainer, fd_slotv_t * slotv ) {
  if( FD_UNLIKELY( !slotv->in_orphan ) ) return;
  fd_slotv_orphan_ele_remove( fd_chainer_orphan_treap( chainer ), slotv, fd_chainer_slotv_pool( chainer ) );
  slotv->in_orphan = 0;
}

void
fd_chainer_print( fd_chainer_t * chainer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_chainer_fd_chainer_h */