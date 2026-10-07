#ifndef HEADER_fd_src_choreo_rotor_fd_rotor_h
#define HEADER_fd_src_choreo_rotor_fd_rotor_h

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../votor/ag_votor_base.h"
#include "../fd_choreo_base.h"

struct fd_mr20 {
  uchar uc[ FD_SHRED_MERKLE_NODE_SZ ];
};
typedef struct fd_mr20 fd_mr20_t;

typedef fd_hash_t fd_mr32_t;

struct fd_rotor_fec {
  fd_mr20_t key;
  fd_mr32_t mr32;
  uint      fec_idx;
  ulong     slot;
  uint      rcvd;
  int       complete;
  int       data_complete;
  long      first_ts;      /* when its first shred arrived, 0 if none yet */
  int       is_leader;
  int       notarized;
  ulong     next;
  ulong     prev;
};
typedef struct fd_rotor_fec fd_rotor_fec_t;
FD_STATIC_ASSERT( sizeof(fd_rotor_fec_t)==112UL, fd_rotor_fec );

#define POOL_NAME fec_pool
#define POOL_T    fd_rotor_fec_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fec_map
#define MAP_ELE_T              fd_rotor_fec_t
#define MAP_KEY_T              fd_mr20_t
#define MAP_KEY                key
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_mr20_t)))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash((seed)^FD_LOAD(ulong,(key)->uc))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_rotor_blk {
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

  /* repair, the treap is the blk's role in its slot_meta */

  uchar in_blk_treap : 1; /* in its role's treap */
  uchar eager        : 1; /* the slot's eager blk, and may be repaired by position */
  uchar meta_req     : 1; /* tile: a META req was made */
  uchar highest_req  : 1; /* tile: a HIGHEST req was made */
  uchar orphan_req   : 1; /* tile: an ORPHAN req was made */
  schar connected    : 2; /* 1 if the root or parent is connected, 0 if not, -1 if stale: relinked by connect_ancestors until connect_descendants */

  ulong fecs[FD_FEC_BLK_MAX]; /* fec_pool idx of each FEC set, null if none */

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
  } telemetry;
};
typedef struct fd_rotor_blk fd_rotor_blk_t;

/* blk_map is keyed by slot and holds every blk of a slot. */

#define POOL_NAME blk_pool
#define POOL_T    fd_rotor_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  blk_map
#define MAP_ELE_T fd_rotor_blk_t
#define MAP_KEY   slot
#define MAP_MULTI 1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME      fd_rotor_treap
#define TREAP_T         fd_rotor_blk_t
#define TREAP_QUERY_T   ulong
#define TREAP_CMP(q,e)  ((int)((q)>(e)->slot) - (int)((q)<(e)->slot))
#define TREAP_LT(e0,e1) ((e0)->slot<(e1)->slot || ((e0)->slot==(e1)->slot && (e0)<(e1)))
#define TREAP_PARENT    treap.parent
#define TREAP_LEFT      treap.left
#define TREAP_RIGHT     treap.right
#define TREAP_PRIO      treap.prio
#include "../../util/tmpl/fd_treap.c"

/* slot_meta is a circular buffer. */

struct fd_rotor_slot_meta {
  ulong slot;            /* ULONG_MAX if none */
  ulong eager;           /* blk_pool idx of the eager blk, null if none */
  ulong notar;           /* blk_pool idx of the first notar or stronger blk, null if none */
  ulong final;           /* blk_pool idx of the finalized blk, null if none */
  uint  invalidated : 1; /* leader misbehaved: equivocated, conflicting parents, bad block header, etc. */
  uint  skipped     : 1; /* the slot is finalized as skipped */
  uint  leader      : 1; /* we are the slot's leader */
};
typedef struct fd_rotor_slot_meta fd_rotor_slot_meta_t;

struct fd_rotor_deque {
  uint blk_idx;
  uint fec_idx;
};
typedef struct fd_rotor_deque fd_rotor_deque_t;

#define DEQUE_NAME fd_rotor_deque
#define DEQUE_T    fd_rotor_deque_t
#include "../../util/tmpl/fd_deque_dynamic.c"


typedef void (* fd_rotor_report_fn_t)( void * ctx, struct fd_rotor_blk const * blk );

struct fd_rotor_private {
  ulong            root;
  ulong            catchup_slot;
  ulong            slot_max;

  fd_rotor_slot_meta_t * slot_meta; /* indexed by slot % slot_max */
  fd_rotor_blk_t *       blk_pool;
  blk_map_t *            blk_map;
  fd_rotor_fec_t *       fec_pool;
  fec_map_t *            fec_map;
  fd_rotor_deque_t * reasm_deque;
  fd_rotor_treap_t *     eager_treap; /* a blk is in its role's treap iff in_blk_treap */
  fd_rotor_treap_t *     notar_treap;
  fd_rotor_treap_t *     final_treap;

  struct {
    fd_rotor_report_fn_t report; /* called once per blk, when it completes or when it is freed incomplete, NULL disables */
    void *               ctx;
  } telemetry;
};
typedef struct fd_rotor_private fd_rotor_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_rotor_align( void );

FD_FN_CONST ulong
fd_rotor_footprint( ulong slot_max,
                    ulong fec_max );

void *
fd_rotor_new( void * shmem,
              ulong  slot_max,
              ulong  fec_max,
              ulong  seed );

fd_rotor_t *
fd_rotor_join( void * shrotor );

void *
fd_rotor_leave( fd_rotor_t const * rotor );

void *
fd_rotor_delete( void * shrotor );

void
fd_rotor_init( fd_rotor_t *           rotor,
               ulong                  root,
               fd_mr32_t const *      root_blk_mr,
               fd_rotor_report_fn_t   report,
               void *                 report_ctx );

void
fd_rotor_fini( fd_rotor_t * rotor );

/* replay_slot   REPLAY_SIG_SLOT_DEAD

   replay rejected the blk, prune it so it is never redelivered, and if
   it was the eager blk invalidate the slot so turbine can't rebuild it. */

void
fd_rotor_blk_dead( fd_rotor_t *      rotor,
                   ulong             slot,
                   fd_mr32_t const * blk_mr );

/* votor_out     FD_VOTOR_SIG_CERTED FINAL, FAST_FINAL
   votor_out     FD_VOTOR_SIG_QUORUM IMPLICITLY_FINALIZED

   frees the slot's competing blks, creates the blk if we don't have it
   yet. */

fd_rotor_blk_t *
fd_rotor_blk_finalized( fd_rotor_t *      rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr );

/* votor_out     FD_VOTOR_SIG_CERTED NOTAR
   votor_out     FD_VOTOR_SIG_REPAIR

   creates a blk to repair by blk id, NULL if we have it or the slot is
   settled. */

fd_rotor_blk_t *
fd_rotor_blk_notarized( fd_rotor_t *      rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr );

/* net_repair    ParentAndFecSetCount response

   after its proof verifies against the blk id.  the FEC set count is now
   trusted, creates the parent blk if we don't have it. */

fd_rotor_blk_t *
fd_rotor_blk_parented( fd_rotor_t *      rotor,
                       ulong             slot,
                       fd_mr32_t const * blk_mr,
                       ulong             parent_slot,
                       fd_mr32_t const * parent_blk_mr,
                       uint              fec_set_cnt );

/* votor_out     FD_VOTOR_SIG_CERTED
   votor_out     FD_VOTOR_SIG_REPAIR

   before the cert is handled.  seeds an empty eager blk for every slot
   up to the cert as if turbine showed its first shred, assumes no
   skips, skipped slots are pruned by finality later. */

void
fd_rotor_slot_catchup( fd_rotor_t * rotor,
                       ulong        slot );

/* shred_out     SHRED_SIG_FEC_COMPLETE
   shred_out     SHRED_SIG_FEC_COMPLETE_LEADER
   shred_out     SHRED_SIG_FEC_COMPLETE_AGAIN

   the shred tile already inserted the FEC set into the store.  computes
   the eager blk's dmr once it has every FEC set, our leader FECs go to
   the head of the reasm deque. */

fd_rotor_fec_t *
fd_rotor_fec_complete( fd_rotor_t *       rotor,
                       fd_shred_t const * last_shred,
                       fd_mr32_t const *  fec_mr,
                       int                is_leader,
                       long               ts );

/* shred_out     SHRED_SIG_FEC_EVICTED

   the resolver dropped an incomplete FEC set, so ask for every shred
   again. */

void
fd_rotor_fec_evicted( fd_rotor_t *      rotor,
                      ulong             slot,
                      uint              fec_set_idx,
                      fd_mr20_t const * fec_mr );

/* net_repair    FecSetRoot response

   after its proof verifies against the blk id.  fec_mr is the proven
   20-byte prefix, the FEC set's shreds can be asked for by blk id now. */

fd_rotor_fec_t *
fd_rotor_fec_notarized( fd_rotor_t *      rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr,
                        uint              fec_set_idx,
                        fd_mr20_t const * fec_mr );

/* replay_rotor  REPLAY_SIG_MISSING_FEC

   replay told us they aren't able to process this FEC, so send out the
   full lineage of that fec from the root */

void
fd_rotor_fec_reconsume( fd_rotor_t * rotor );

/* replay_slot   REPLAY_SIG_ROOT_ADVANCED

   wait for replay's signal to advance root because of redelivery
   nonsense.  TODO remove this. */

void
fd_rotor_root_advanced( fd_rotor_t *      rotor,
                        ulong             slot,
                        fd_mr32_t const * blk_mr );

/* shred_out     SHRED_SIG_SRC_* data shreds

   special handling for idx 0 and the last shred idx.  also called by
   fd_rotor_fec_complete. */

void
fd_rotor_shred_insert( fd_rotor_t *       rotor,
                       fd_shred_t const * shred,
                       fd_mr32_t const *  fec_mr,
                       long               ts );

/* shred_out     SHRED_SIG_RESULT_EQVOC

   also called internally on a bad block header or conflicting
   parents.  the eager blk is never repaired again, the slot is only
   reachable by blk id.  reason is the eager blk's block_received
   cancelled_reason. */

void
fd_rotor_slot_invalidated( fd_rotor_t * rotor,
                           ulong        slot,
                           int          reason );

/* slot must be the root or in the window after it, slots congruent mod
   slot_max share an entry, which is reset for slot first. */

fd_rotor_slot_meta_t *
fd_rotor_slot_meta( fd_rotor_t * rotor,
                    ulong        slot );

/* votor_out     FD_VOTOR_SIG_QUORUM IMPLICITLY_SKIPPED

   SKIP-FINAL, a finalized descendant declares this slot skipped.  frees
   the slot's blks, a skip cert alone is not final. */

void
fd_rotor_slot_skipped( fd_rotor_t * rotor,
                       ulong        slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_rotor_fd_rotor_h */
