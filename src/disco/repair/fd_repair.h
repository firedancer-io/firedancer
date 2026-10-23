#ifndef HEADER_fd_src_disco_repair_fd_repair_h
#define HEADER_fd_src_disco_repair_fd_repair_h

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../choreo/votor/ag_votor_base.h"
#include "../../choreo/fd_choreo_base.h"

struct fd_mr20 {
  uchar uc[ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_mr20 fd_mr20_t;

typedef fd_hash_t fd_mr32_t;

/* FD_REPAIR_BLK_VERSION_{NUM,DEN} is the number of blk versions rotor
   holds per slot of its window, as the fraction NUM/DEN (2.5).  With
   20% of stake malicious and equivocating AG_EQVOC_BLOCK_HASH_MAX
   versions of each of its slots, the expected count is 2.2 per slot,
   2.5 leaves headroom for the variance of the leader schedule (see
   store_fec_max in src/app/firedancer/topology.c, which sizes Store
   with the same factor). */

#define FD_REPAIR_BLK_VERSION_NUM (5UL)
#define FD_REPAIR_BLK_VERSION_DEN (2UL)

/* fd_repair_blk_max returns the number of blks a rotor with a window of
   slot_max slots holds, ie. ceil( slot_max*NUM/DEN ). */

FD_FN_CONST static inline ulong
fd_repair_blk_max( ulong slot_max ) {
  return ( slot_max*FD_REPAIR_BLK_VERSION_NUM + FD_REPAIR_BLK_VERSION_DEN-1UL ) / FD_REPAIR_BLK_VERSION_DEN;
}

typedef struct fd_repair_blk fd_repair_blk_t;

struct fd_repair_fec {
  fd_mr20_t key;
  fd_mr32_t mr32;
  uint      fec_idx;
  ulong     slot;
  uint      rcvd;
  uchar     complete      : 1;
  uchar     data_complete : 1;
  uchar     is_leader     : 1;
  uchar     notarized     : 1;
  ulong     next;
  ulong     prev;
  uint      data_rcvd;     /* shred tile masks at first completion: bit j set if the data shred with in-type index j was received (vs recovered) */
  uint      parity_rcvd;   /* ... if the parity shred with in-type index j was received */
  uint      repair_rcvd;   /* ... if the data shred with in-type index j arrived by repair */

  int       final_src;     /* FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_* of the last data shred received before it completed, 0 if none */
  long      first_ts;      /* when its first shred arrived, 0 if none yet */
  long      cmpl_ts;       /* when it first completed, 0 if not yet */
};
typedef struct fd_repair_fec fd_repair_fec_t;
FD_STATIC_ASSERT( sizeof(fd_repair_fec_t)==120UL, fd_repair_fec );

#define POOL_NAME fd_repair_fec_pool
#define POOL_T    fd_repair_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_repair_fec_map
#define MAP_ELE_T              fd_repair_fec_t
#define MAP_KEY_T              fd_mr20_t
#define MAP_KEY                key
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_mr20_t)))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash((seed)^FD_LOAD(ulong,(key)->uc))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_repair_blk {
  ulong     slot;
  fd_mr32_t dmr;
  ulong     prev;
  ulong     next;

  /* blks form a left-child, right-sibling tree at root. */

  ulong parent;    /* blk_pool idx of the parent blk, null if not linked */
  ulong child;     /* blk_pool idx of the first child */
  ulong sibling;   /* blk_pool idx of the next child of the same parent */

  uint cmpl_fec_cnt; /* FEC set count of the slot, 0 if not yet known */
  uint rcvd_fec_cnt; /* one past the highest FEC set received, there can be gaps below */
  uint buff_fec_cnt; /* FEC sets [0,buff_fec_cnt) are complete */
  uint cons_fec_cnt; /* FEC sets [0,cons_fec_cnt) are consumed by replay, 0 until the parent is consumed in full */
  uint wait_fec_cnt; /* FEC sets [0,wait_fec_cnt) are complete or have a repair req waiting, kept by the tile */

  ulong     parent_slot;
  fd_mr32_t parent_blk_mr;
  ulong     orphan_next; /* orphan_map chain, while the blk waits for the blk named by parent_blk_mr */
  ulong     orphan_prev;

  /* repair, the treap is the blk's role in its slot_meta */

  uchar in_blk_treap : 1; /* in its role's treap */
  uchar eager        : 1; /* the slot's eager blk, and may be repaired by position */
  uchar meta_req     : 1; /* tile: a META req was made */
  uchar highest_req  : 1; /* tile: a HIGHEST req was made */
  uchar orphan_req   : 1; /* tile: an ORPHAN req was made */

  ulong * fecs; /* fec_pool idx of each FEC set, null if none, fec_blk_max of them */

  long rcvd_fec_ts; /* when rcvd_fec_cnt last grew */
  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;  /* seeded once at pool creation */
  } treap;

  struct {
    uchar cancelled_reason; /* FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_*, 0 if never cancelled */
    uchar reported;         /* given to the report callback, at completion or when freed */
    long  cancelled_ts;     /* when cancelled_reason was first set, 0 if never cancelled */
    uint  last_cmpl_fec_idx;    /* fec_set_idx of the FEC set that most recently completed, UINT_MAX if none */
    long  last_shred_ts;        /* when the blk became contiguous through a FEC set completion, 0 if it has not */
    uint  turbine_shred_cnt;    /* turbine data and coding shreds of its FEC sets, as counted by the shred tile */
    uint  repair_shred_cnt;     /* repair shreds of its FEC sets, as counted by the shred tile */
    uint  recovered_shred_cnt;  /* shreds of its FEC sets recovered from coding shreds */

    /* tile: sent requests, by FD_REPAIR_SERDE_TAG_*, a FEC set req counts once per shred asked for */

    uint  req_window_cnt;
    uint  req_highest_cnt;
    uint  req_orphan_cnt;
    uint  req_shred_bid_cnt;
    uint  req_parent_cnt;
    uint  req_fec_root_cnt;
    long  first_req_ts;         /* tile: when the first req of any kind was sent, 0 if none */

    /* tile: verified responses to its pending requests */

    uint  shred_res_cnt;        /* repair shreds matched to a pending window or ShredForBlockId req */
    uint  parent_res_cnt;       /* ParentAndFecCount responses */
    uint  fec_root_res_cnt;     /* FecRoot responses */
    long  last_shred_res_ts;    /* when the last matched repair shred arrived, 0 if none */
    long  first_meta_res_ts;    /* when the first ParentAndFecCount or FecRoot response arrived, 0 if none */
  } telemetry;
};
typedef struct fd_repair_blk fd_repair_blk_t;

/* blk_map is keyed by slot and holds every blk of a slot. */

#define POOL_NAME fd_repair_blk_pool
#define POOL_T    fd_repair_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_repair_blk_map
#define MAP_ELE_T fd_repair_blk_t
#define MAP_KEY   slot
#define MAP_MULTI 1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

/* orphan_map is keyed by parent_blk_mr and holds every unlinked blk
   that names a parent, ie. parent==null && parent_blk_mr!=hash_null,
   except the root blk.  The blk named may not be held yet, be held
   under a different dmr (an eager blk) or never come.  The key is the
   dmr alone, the parent slot is checked when linking.

   Each call site of add/remove should gate on the blk's state before
   its transition, the root blk is never in the map: it keeps the
   parent_blk_mr it was received with, but waits for nothing. */

#define MAP_NAME               fd_repair_orphan_map
#define MAP_ELE_T              fd_repair_blk_t
#define MAP_KEY_T              fd_mr32_t
#define MAP_KEY                parent_blk_mr
#define MAP_NEXT               orphan_next
#define MAP_PREV               orphan_prev
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_mr32_t)))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash((seed)^FD_LOAD(ulong,(key)->uc))
#define MAP_MULTI              1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME      fd_repair_treap
#define TREAP_T         fd_repair_blk_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ((int)((q)>(e)->slot) - (int)((q)<(e)->slot))
#define TREAP_LT(e0,e1) ((e0)->slot<(e1)->slot || ((e0)->slot==(e1)->slot && (e0)<(e1)))
#define TREAP_PARENT    treap.parent
#define TREAP_LEFT      treap.left
#define TREAP_RIGHT     treap.right
#define TREAP_PRIO      treap.prio
#include "../../util/tmpl/fd_treap.c"

/* slot_meta is a circular buffer. */

struct fd_repair_slot_meta {
  ulong slot;            /* ULONG_MAX if none */
  ulong eager;           /* blk_pool idx of the eager blk, null if none */
  ulong notar;           /* blk_pool idx of the first notar or stronger blk, null if none */
  ulong final;           /* blk_pool idx of the finalized blk, null if none */
  uint  invalidated : 1; /* leader misbehaved: equivocated, conflicting parents, bad block header, etc. */
  uint  skipped     : 1; /* the slot is finalized as skipped */
  uint  leader      : 1; /* we are the slot's leader */
};
typedef struct fd_repair_slot_meta fd_repair_slot_meta_t;

struct fd_repair_deque {
  uint blk_idx;
  uint fec_idx;
};
typedef struct fd_repair_deque fd_repair_deque_t;

#define DEQUE_NAME fd_repair_deque
#define DEQUE_T    fd_repair_deque_t
#include "../../util/tmpl/fd_deque_dynamic.c"

typedef void (* fd_repair_report_fn_t)( void * ctx, struct fd_repair_blk const * blk );

struct fd_repair {
  ulong             root;
  fd_repair_blk_t * root_blk;     /* the root's blk, NULL if not held */
  ulong             catchup_slot;
  int               reconsume;    /* replay sent a MISSING_FEC: the next FEC pushed onto reasm_deque goes with its ancestry from the root */
  ulong             slot_max;
  ulong             fec_blk_max;  /* FEC sets per blk */

  fd_repair_slot_meta_t * slot_meta;   /* indexed by slot % slot_max */
  fd_repair_blk_t *       blk_pool;
  fd_repair_blk_map_t *   blk_map;
  fd_repair_orphan_map_t * orphan_map;
  fd_repair_fec_t *       fec_pool;
  fd_repair_fec_map_t *   fec_map;
  fd_repair_deque_t *     reasm_deque;
  fd_repair_treap_t *     eager_treap; /* a blk is in its role's treap iff in_blk_treap */
  fd_repair_treap_t *     notar_treap;
  fd_repair_treap_t *     final_treap;

  struct {
    fd_repair_report_fn_t report; /* called once per blk, when it completes or when it is freed incomplete, NULL disables */
    void *                ctx;
  } telemetry;
};
typedef struct fd_repair fd_repair_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_repair_align( void );

FD_FN_CONST ulong
fd_repair_footprint( ulong slot_max,
                     ulong fec_max,
                     ulong fec_blk_max );

void *
fd_repair_new( void * shmem,
               ulong  slot_max,
               ulong  fec_max,
               ulong  fec_blk_max,
               ulong  seed );

fd_repair_t *
fd_repair_join( void * shrotor );

void *
fd_repair_leave( fd_repair_t const * rotor );

void *
fd_repair_delete( void * shrotor );

void
fd_repair_init( fd_repair_t *          rotor,
                ulong                  root,
                fd_mr32_t const *      root_blk_mr,
                fd_repair_report_fn_t  report,
                void *                 report_ctx );

void
fd_repair_fini( fd_repair_t * rotor );

/* replay_slot   REPLAY_SIG_SLOT_DEAD

   replay rejected the blk, prune it so it is never redelivered, and if
   it was the eager blk invalidate the slot so turbine can't rebuild it. */

void
fd_repair_blk_dead( fd_repair_t *     rotor,
                    ulong             slot,
                    fd_mr32_t const * blk_mr );

/* votor_out     FD_VOTOR_SIG_CERTED FINAL, FAST_FINAL
   votor_out     FD_VOTOR_SIG_QUORUM IMPLICITLY_FINALIZED

   frees the slot's competing blks, creates the blk if we don't have it
   yet. */

fd_repair_blk_t *
fd_repair_blk_finalized( fd_repair_t *     rotor,
                         ulong             slot,
                         fd_mr32_t const * blk_mr,
                         long              ts );

/* votor_out     FD_VOTOR_SIG_CERTED NOTAR
   votor_out     FD_VOTOR_SIG_REPAIR

   creates a blk to repair by blk id, NULL if we have it or the slot is
   settled. */

fd_repair_blk_t *
fd_repair_blk_notarized( fd_repair_t *     rotor,
                         ulong             slot,
                         fd_mr32_t const * blk_mr );

/* net_repair    ParentAndFecSetCount response

   after its proof verifies against the blk id.  the FEC set count is now
   trusted, creates the parent blk if we don't have it.  counts the
   response, arriving at ts, in the blk's telemetry. */

fd_repair_blk_t *
fd_repair_blk_parented( fd_repair_t *     rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr,
                        ulong             parent_slot,
                        fd_mr32_t const * parent_blk_mr,
                        uint              fec_set_cnt,
                        long              ts );

/* votor_out     FD_VOTOR_SIG_CERTED
   votor_out     FD_VOTOR_SIG_REPAIR

   before the cert is handled.  seeds an empty eager blk for every slot
   up to the cert as if turbine showed its first shred, assumes no
   skips, skipped slots are pruned by finality later. */

void
fd_repair_slot_catchup( fd_repair_t * rotor,
                        ulong         slot );

/* shred_out     SHRED_SIG_FEC_COMPLETE
   shred_out     SHRED_SIG_FEC_COMPLETE_LEADER
   shred_out     SHRED_SIG_FEC_COMPLETE_AGAIN

   the shred tile already inserted the FEC set into the store.  computes
   the eager blk's dmr once it has every FEC set, our leader FECs go to
   the head of the reasm deque.  {turbine,repair,recovered}_cnt
   are the FEC set's shred counts from the shred tile, added to the
   telemetry of each blk holding the FEC set on its first completion.
   {data,parity,repair}_rcvd are its received-shred masks from the
   shred tile, kept on the FEC set from its first completion. */

fd_repair_fec_t *
fd_repair_fec_complete( fd_repair_t *      rotor,
                        fd_shred_t const * last_shred,
                        fd_mr32_t const *  fec_mr,
                        int                is_leader,
                        uint               turbine_cnt,
                        uint               repair_cnt,
                        uint               recovered_cnt,
                        uint               data_rcvd,
                        uint               parity_rcvd,
                        uint               repair_rcvd,
                        long               ts );

/* shred_out     SHRED_SIG_FEC_EVICTED

   the resolver dropped an incomplete FEC set, so ask for every shred
   again. */

void
fd_repair_fec_evicted( fd_repair_t *     rotor,
                       ulong             slot,
                       uint              fec_set_idx,
                       fd_mr20_t const * fec_mr );

/* net_repair    FecSetRoot response

   after its proof verifies against the blk id.  fec_mr is the proven
   20-byte prefix, the FEC set's shreds can be asked for by blk id now.
   counts the response, arriving at ts, in the blk's telemetry. */

fd_repair_fec_t *
fd_repair_fec_notarized( fd_repair_t *     rotor,
                         ulong             slot,
                         fd_mr32_t const * blk_mr,
                         uint              fec_set_idx,
                         fd_mr20_t const * fec_mr,
                         long              ts );

/* replay_slot   REPLAY_SIG_ROOT_ADVANCED

   wait for replay's signal to advance root because of redelivery
   nonsense.  TODO remove this. */

void
fd_repair_root_advanced( fd_repair_t *     rotor,
                         ulong             slot,
                         fd_mr32_t const * blk_mr );

/* shred_out     SHRED_SIG_SRC_* data shreds

   special handling for idx 0 and the last shred idx.  also called by
   fd_repair_fec_complete.  src is the FD_EVENT_BLOCK_RECEIVED_FEC_SETS_
   FINAL_SHRED_SOURCE_* the shred arrived by, it becomes the FEC set's
   final_src until the set completes, 0 leaves final_src alone (eg. a
   reconstructed shred). */

void
fd_repair_shred_insert( fd_repair_t *      rotor,
                        fd_shred_t const * shred,
                        fd_mr32_t const *  fec_mr,
                        int                src,
                        long               ts );

/* shred_out     SHRED_SIG_RESULT_EQVOC

   also called internally on a bad block header or conflicting
   parents.  the eager blk is never repaired again, the slot is only
   reachable by blk id.  reason is the eager blk's block_received
   cancelled_reason, ts its cancelled_time. */

void
fd_repair_slot_invalidated( fd_repair_t * rotor,
                            ulong         slot,
                            int           reason,
                            long          ts );

/* slot must be the root or in the window after it, slots congruent mod
   slot_max share an entry, which is reset for slot first. */

fd_repair_slot_meta_t *
fd_repair_slot_meta( fd_repair_t * rotor,
                     ulong         slot );

/* votor_out     FD_VOTOR_SIG_QUORUM IMPLICITLY_SKIPPED

   SKIP-FINAL, a finalized descendant declares this slot skipped.  frees
   the slot's blks, a skip cert alone is not final. */

void
fd_repair_slot_skipped( fd_repair_t * rotor,
                        ulong         slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_repair_fd_repair_h */
