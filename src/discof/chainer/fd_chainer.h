#ifndef HEADER_fd_src_discof_chainer_fd_chainer_h
#define HEADER_fd_src_discof_chainer_fd_chainer_h

/* Fec chainer is an API for reassembling shreds and FECs into slots.
   It maintains 3 levels of granularity:

   FEC

   SLOTV

   SLOT

   Under alpenglow, we can simplify equivocation handling. As turbine
   shreds arrive, we only accept a single version. Each (slot,
   fec_set_idx) only accepts one version = the first-seen root. Any
   shred bearing a different root is rejected.

   When a notar-fallback cert is received, we can add additional
   versions. Protocol dictates only 3 notar-fallbacks can arrive per
   slot.

   Creating these additional versions should trigger getFecRoot. A
   second version of a FEC set only exists once a getFecRoot response
   creates the sentinel with that root. Equivocating-FEC shreds accepted
   iff the sentinel already exists. No sentinel → drop.

   Parent Discovery:

   The tricky part with chaining is that there's 3 different sources of
   parent information. Shreds contain parent_off field, which may or may
   not be removed in the future. The block header contains the initial
   replay parent_slot, and there can be an updateParent marker anywhere
   in the middle of the block. The parent_offs of the shreds do not
   change after a parentUpdate.

   In the case where we are disconnected momentarily, or we are catching
   up, we won't ever receive shreds for the original parent slot, only
   for the updated parent slot. So if we take at face value the
   parent_off described by the shreds (or the initial block header), we
   will end up stalled.  This is all levels of fucked.
*/

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"

#define FD_CHAINER_MAGIC (0xf17eda2ce7c4a112UL) /* firedancer chainer v1 */

/* slot:47 | fec_set_idx:15 | version:2 */
#define FD_CHAINER_FEC_KEY( slot, fec_set_idx, version ) \
  ( ((ulong)(slot))<<17 | ((ulong)(fec_set_idx))<<2 | (version) )

struct fd_fec {
  ulong     key; /* (slot, fec_set_idx, version) */
  ulong     next; /* reserved by pool and map_chain */
  fd_hash_t merkle_root;
  uchar     slot_complete;
  uchar     data_complete; /* needed to parse UpdateParent */
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
  uint            buffered_idx;

  ulong           parent_slot;       /* ULONG_MAX if unknown */
  fd_hash_t       parent_block_id;   /* block_id of the parent slot */
  uint            parent_slot_batch; /* fec_idx of the last known parent_slot information.
                                        before FLH is activated, can only be 0 or UINT_MAX. After FLH
                                        is activated, can be 0 or UINT_MAX or a multiple of FD_FEC_SHRED_CNT,
                                        and can only update to a non-zero fec_idx value once.  */

  /* delivery to replay */
  uint            delivered_idx;     /* highest fec_set_idx delivered to replay, UINT_MAX = none */
  uchar           connected;         /* ancestor chain reaches the root */
  uchar           fully_delivered;   /* slot_complete FEC has been delivered */

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

#define FD_CHAINER_SLOT_VER_MAX 4 /* should be FD_POOL_NF_CERT_MAX + 1 */

#define DEQUE_NAME             bfs
#define DEQUE_T                ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct fd_chainer {
  ulong root;             /* slotv pool idx of the root, ULONG_MAX if unset */
  ulong highest_repaired; /* max slot ever marked fully_delivered (contiguous-from-root repaired tip) */
  ulong wksp_gaddr;  /* wksp gaddr of fd_chainer in the backing wksp, non-zero gaddr */

  ulong fec_pool_gaddr;   /* wksp gaddr of fd_fec_pool */
  ulong fec_map_gaddr;    /* wksp gaddr of fd_fec_map (flat, keyed by (slot,fec_set_idx,version)) */

  ulong slotv_pool_gaddr;   /* wksp gaddr of fd_slotv_pool */
  ulong slotv_map_gaddr;    /* wksp gaddr of fd_slotv_map */
  ulong repair_treap_gaddr;  /* wksp gaddr of fd_slotv_repair (shred-fill worklist) */
  ulong orphan_treap_gaddr; /* wksp gaddr of fd_slotv_orphan (ancestry worklist) */

  ulong bfs_gaddr;        /* bfs queue for delivery */

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
   fd_forest_highest_repaired_slot) TODO ??? */

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

void
fd_chainer_init( fd_chainer_t * chainer,
                 ulong          slot );
void
fd_chainer_shred_insert( fd_chainer_t * chainer,
                         ulong          slot,
                         uint           shred_idx,
                         int            slot_complete,
                         fd_hash_t const * mr,
                         ulong          parent_slot );

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
                                      fd_hash_t    * parent_block_id );

void
fd_chainer_verified_hash_insert( fd_chainer_t * chainer,
                                 ulong          slot,
                                 fd_hash_t    * block_id,
                                 uint           fec_set_idx,
                                 fd_hash_t    * mr );

void
fd_chainer_publish( fd_chainer_t * chainer,
                    ulong          slot );

static inline fd_slotv_t *
fd_chainer_slot_version_query( fd_chainer_t *    chainer,
                               ulong             slot,
                               fd_hash_t const * block_id ) {
  fd_slotv_t * slotv_pool = fd_chainer_slotv_pool( chainer );
  fd_slotv_map_t * slotv_map = fd_chainer_slotv_map( chainer );
  for( uint version = 0; version < FD_CHAINER_SLOT_VER_MAX; version++ ) {
    ulong slotv_key = FD_CHAINER_SLOTV_KEY( slot, version );
    fd_slotv_t * slotv = fd_slotv_map_ele_query( slotv_map, &slotv_key, NULL, slotv_pool );
    if( FD_LIKELY( slotv ) ) {
      if( FD_UNLIKELY( fd_hash_eq( &slotv->block_id, block_id ) ) ) return slotv;
    } else {
      return NULL;
    }
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
  FD_LOG_INFO(( "fd_chainer_orphan_remove: slotv slot %lu version %lu", FD_CHAINER_SLOTV_SLOT( slotv->key ), FD_CHAINER_SLOTV_VERSION( slotv->key ) ));
  fd_slotv_orphan_ele_remove( fd_chainer_orphan_treap( chainer ), slotv, fd_chainer_slotv_pool( chainer ) );
  slotv->in_orphan = 0;
}

void
fd_chainer_print( fd_chainer_t * chainer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_chainer_fd_chainer_h */