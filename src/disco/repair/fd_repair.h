#ifndef HEADER_fd_src_disco_repair_fd_repair_h
#define HEADER_fd_src_disco_repair_fd_repair_h

/* fd_repair tracks the root and the blocks of the slots after it as
   they are received over the network via Turbine and Repair, keeps the
   blocks that still need repair for the tile to request, and queues
   their FEC sets for replay on the reasm deque.

   A slot can have more than one block (blk).  The eager blk is built by
   position from every shred of the slot, before its block id is known,
   and gets its block id (the double merkle root, dmr) when it
   completes.  Named blks carry a dmr from a cert, a votor repair event
   or a child's block header, and are repaired by that id.  When the
   eager blk completes with the dmr of a named blk, they are the same
   block and are merged.

   Every blk but the root has a parent (the blk its block header names
   by parent slot and dmr, known from shred 0 or a ParentAndFecCount
   response) and children (the blks linked under it).  A blk is linked
   under its parent once the parent is held.  A named blk creates its
   parent if it is missing, an eager blk waits unlinked as an orphan.

   fd_repair always queues a parent before its child: a blk's first FEC
   set is queued only after its parent's last (the root counts as
   delivered), then its complete FEC sets are queued in index order.
   This guarantees that every fork will be delivered in-order, except
   that our own leader blk goes to the head of the deque, and so does a
   chain that replay asks to be delivered again from the root.  Forks
   are treated as concurrent, and thus fd_repair only provides a partial
   ordering such that it makes no guarantees about the delivery order of
   FEC sets across forks, but in general this will be the order in which
   they become ready.

   Forks manifest in fd_repair as a blk with more than one child, and
   mostly occur across slots due to leader skipping.  For example, the
   leader for slot 14 forks slot 9 when another leader already built
   slot 10 from slot 9, so now the blk of slot 9 has two child blks ie.
   the blk of slot 10 and the blk of slot 14.

   There is a protocol violation called equivocation (also known as
   "duplicates") that can also cause forks.  Unlike skips, equivocation
   is not honest behavior and only happens when validators are behaving
   maliciously or their software has a bug.  Equivocation can result in
   two or more blks for the _same_ slot.  Moreover, there might be two
   FEC sets with the same slot and FEC set index but different payloads.

   fd_repair invalidates the slot when the shreds of the eager blk
   conflict (multiple merkle roots for the same FEC set idx, a parent
   slot mismatch, a bad block header, or multiple shreds marked
   slot_complete), when a proven FEC set root disagrees with it, or when
   replay marks it dead.  The eager blk is then no longer repaired, no
   more of its FEC sets are queued unless it completed first, and the
   slot is only reachable by block id. */

#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../choreo/votor/fd_votor_base.h"
#include "../../choreo/fd_choreo_base.h"
#include "../../flamenco/alpenglow/fd_block_marker.h"

struct fd_mr20 {
  uchar uc[ 20 ];
};
typedef struct fd_mr20 fd_mr20_t;

struct fd_mr32 {
  uchar uc[ 32 ];
};
typedef struct fd_mr32 fd_mr32_t;

union fd_mr {
  fd_mr20_t mr20;
  fd_mr32_t mr32;
};
typedef union fd_mr fd_mr_t;

typedef struct fd_repair_blk fd_repair_blk_t;

struct fd_repair_fec {
  fd_mr_t   mr;
  ulong     slot;
  uint      fec_idx;
  uint      next;
  uint      prev;
  uint      data_rcvd;     /* bit j set if repair holds data shred j, until it completes.  then the shred tile masks: bit j set if the data shred with in-type index j was received (vs recovered) */
  uint      parity_rcvd;   /* ... if the parity shred with in-type index j was received */
  uint      repair_rcvd;   /* ... if the data shred with in-type index j arrived by repair */
  uchar     fec_complete  : 1;
  uchar     data_complete : 1;
  uchar     is_leader     : 1;
  uchar     is_notar      : 1;

  /* block marker */

  fd_update_parent_t update_parent;

  /* metrics */

  long      first_ts;      /* when its first shred arrived, 0 if none yet */
  long      cmpl_ts;       /* when it first completed, 0 if not yet */
};
typedef struct fd_repair_fec fd_repair_fec_t;
FD_STATIC_ASSERT( sizeof(fd_repair_fec_t)==128UL, fd_repair_fec );

#define POOL_NAME  fd_repair_fec_pool
#define POOL_T     fd_repair_fec_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_repair_fec_map
#define MAP_ELE_T              fd_repair_fec_t
#define MAP_IDX_T              uint
#define MAP_KEY_T              fd_mr_t
#define MAP_KEY                mr
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0)->mr20.uc,(k1)->mr20.uc,sizeof(fd_mr20_t)))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash((seed)^FD_LOAD(ulong,(key)->mr20.uc))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_repair_blk {
  ulong     slot;
  fd_mr32_t dmr;

  /* blk_map */

  ulong prev;
  ulong next;

  /* blk_orphan_map */

  ulong orphan_prev;
  ulong orphan_next;

  /* {eager, notar, final}_treap */

  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;  /* seeded once at pool creation */
  } treap;

  /* blks form a left-child, right-sibling tree at root. */

  ulong parent;    /* blk_pool idx of the parent blk, null if not linked */
  ulong child;     /* blk_pool idx of the first child */
  ulong sibling;   /* blk_pool idx of the next child of the same parent */

  uint cmpl_fec_cnt; /* FEC set count of the slot, 0 if not yet known */
  uint rcvd_fec_cnt; /* one past the highest FEC set received, there can be gaps below */
  uint buff_fec_cnt; /* FEC sets [0,buff_fec_cnt) are complete */
  uint cons_fec_cnt; /* FEC sets [init_fec_cnt,cons_fec_cnt) are consumed by replay, init_fec_cnt until the parent is consumed in full */
  uint wait_fec_cnt; /* FEC sets [0,wait_fec_cnt) are complete or have a repair req waiting, kept by the tile */
  uint init_fec_cnt; /* FEC set of its UpdateParent, replay starts there, 0 if none */

  ulong     parent_slot;      /* the parent slot, potentially changed during the block by UpdateParent */
  fd_mr32_t parent_dmr;       /* the parent dmr */
  ulong     init_parent_slot; /* the initial parent slot before any UpdateParent. */

  /* repair, the treap is the blk's role in its slot_meta */

  uchar eager        : 1; /* the slot's eager blk, and may be repaired by position */
  uchar meta_req     : 1; /* tile: a META req was made */
  uchar highest_req  : 1; /* tile: a HIGHEST req was made */
  uchar orphan_req   : 1; /* tile: an ORPHAN req was made */

  uint * fecs; /* fec_pool idx of each FEC set, null if none, fec_blk_max of them */

  long eager_ts; /* eager_ts + eager_delta signals when to start eagerly repairing */

  struct {
    uchar cancelled_reason;     /* FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_*, 0 if never cancelled */
    uchar reported;             /* given to the report callback, at completion or when freed */
    long  cancelled_ts;         /* when cancelled_reason was first set, 0 if never cancelled */
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

#define POOL_NAME  fd_repair_blk_pool
#define POOL_T     fd_repair_blk_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  fd_repair_blk_map
#define MAP_ELE_T fd_repair_blk_t
#define MAP_KEY   slot
#define MAP_MULTI 1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

/* every unlinked blk but the root waits in the orphan map, keyed by
   the dmr of the parent it names, null until it names one. */

#define MAP_NAME               fd_repair_blk_orphan_map
#define MAP_ELE_T              fd_repair_blk_t
#define MAP_KEY_T              fd_mr32_t
#define MAP_KEY                parent_dmr
#define MAP_NEXT               orphan_next
#define MAP_PREV               orphan_prev
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_mr32_t)))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash((seed)^FD_LOAD(ulong,(key)->uc))
#define MAP_MULTI              1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME      fd_repair_treap
#define TREAP_T         fd_repair_blk_t
#define TREAP_QUERY_T   fd_repair_blk_t const *
#define TREAP_CMP(q,e)  ((int)((q)->slot>(e)->slot || ((q)->slot==(e)->slot && (q)>(e))) - (int)((q)->slot<(e)->slot || ((q)->slot==(e)->slot && (q)<(e))))
#define TREAP_LT(e0,e1) ((e0)->slot<(e1)->slot || ((e0)->slot==(e1)->slot && (e0)<(e1)))
#define TREAP_PARENT    treap.parent
#define TREAP_LEFT      treap.left
#define TREAP_RIGHT     treap.right
#define TREAP_PRIO      treap.prio
#include "../../util/tmpl/fd_treap.c"

/* slot_meta is a circular buffer. */

struct __attribute__((aligned(32UL))) fd_repair_slot_meta {
  ulong slot;            /* ULONG_MAX if none */
  uint  eager_blk_idx;   /* blk_pool idx of the eager blk, null if none */
  uint  notar_blk_idx;   /* blk_pool idx of the first notar or stronger blk, null if none */
  uint  final_blk_idx;   /* blk_pool idx of the finalized blk, null if none */
  uchar invalidated : 1; /* leader misbehaved: equivocated, conflicting parents, bad block header, etc. */
  uchar skipped     : 1; /* the slot is finalized as skipped */
  uchar leader      : 1; /* we are the slot's leader */
};
typedef struct fd_repair_slot_meta fd_repair_slot_meta_t;
FD_STATIC_ASSERT( sizeof(fd_repair_slot_meta_t)==32UL, fd_repair_slot_meta );

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

  fd_repair_slot_meta_t *      slot_meta;   /* indexed by slot % slot_max */
  fd_repair_blk_t *            blk_pool;
  fd_repair_blk_map_t *        blk_map;
  fd_repair_blk_orphan_map_t * orphan_map;
  fd_repair_fec_t *            fec_pool;
  fd_repair_fec_map_t *        fec_map;
  fd_repair_deque_t *          reasm_deque;
  fd_repair_treap_t *          eager_treap;
  fd_repair_treap_t *          notar_treap;
  fd_repair_treap_t *          final_treap;

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
fd_repair_join( void * shrepair );

void *
fd_repair_leave( fd_repair_t const * self );

void *
fd_repair_delete( void * shrepair );

void
fd_repair_init( fd_repair_t *          self,
                ulong                  root,
                fd_mr32_t const *      root_blk_mr,
                fd_repair_report_fn_t  report,
                void *                 report_ctx );

void
fd_repair_fini( fd_repair_t * self );

/* replay_slot   REPLAY_SIG_SLOT_DEAD

   replay rejected the blk.  If it was the eager blk the slot is
   invalidated so turbine can't rebuild it.  We do not prune the blk. If
   this blk gets finalized, we want to keep the block data so that if it
   gets re-delivered, we can notify replay that it is a finalized block
   so replay can detect a hard fork.

   latest_fec_idx is the highest fec_set_idx the dead bank held, not
   necessarily the one that failed.  UINT_MAX means the death is final
   (alpenglow_fast_leader_handover is not active on the dead bank), so
   the blk is never exempted as an optimistic prefix.  */

void
fd_repair_blk_dead( fd_repair_t *     self,
                    ulong             slot,
                    fd_mr32_t const * blk_mr,
                    uint              latest_fec_idx );

/* votor_out     FD_VOTOR_SIG_CERTED FINAL, FAST_FINAL
   votor_out     FD_VOTOR_SIG_QUORUM IMPLICITLY_FINALIZED

   frees the slot's competing blks, creates the blk if we don't have it
   yet. */

fd_repair_blk_t *
fd_repair_blk_finalized( fd_repair_t *     self,
                         ulong             slot,
                         fd_mr32_t const * blk_mr,
                         long              ts );

/* votor_out     FD_VOTOR_SIG_CERTED NOTAR
   votor_out     FD_VOTOR_SIG_REPAIR

   creates a blk to repair by blk id, NULL if we have it or the slot is
   settled. */

fd_repair_blk_t *
fd_repair_blk_notarized( fd_repair_t *     self,
                         ulong             slot,
                         fd_mr32_t const * blk_mr );

/* net_repair    ParentAndFecSetCount response

   after its proof verifies against the blk id.  the FEC set count is now
   trusted, creates the parent blk if we don't have it.  counts the
   response, arriving at ts, in the blk's telemetry. */

fd_repair_blk_t *
fd_repair_blk_parented( fd_repair_t *     self,
                        ulong             slot,
                        fd_mr32_t const * blk_mr,
                        ulong             parent_slot,
                        fd_mr32_t const * parent_dmr,
                        uint              fec_set_cnt,
                        long              ts );

/* votor_out     FD_VOTOR_SIG_CERTED
   votor_out     FD_VOTOR_SIG_REPAIR

   before the cert is handled.  seeds an empty eager blk for every slot
   up to the cert as if turbine showed its first shred, assumes no
   skips, skipped slots are pruned by finality later. */

void
fd_repair_slot_catchup( fd_repair_t * self,
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
fd_repair_fec_complete( fd_repair_t *      self,
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
fd_repair_fec_evicted( fd_repair_t *     self,
                       ulong             slot,
                       uint              fec_set_idx,
                       fd_mr_t const *   fec_mr );

/* net_repair    FecSetRoot response

   after its proof verifies against the blk id.  fec_mr is the proven
   20-byte prefix, the FEC set's shreds can be asked for by blk id now.
   counts the response, arriving at ts, in the blk's telemetry. */

fd_repair_fec_t *
fd_repair_fec_notarized( fd_repair_t *     self,
                         ulong             slot,
                         fd_mr32_t const * blk_mr,
                         uint              fec_set_idx,
                         fd_mr_t const *   fec_mr,
                         long              ts );

/* replay_slot   REPLAY_SIG_ROOT_ADVANCED

   wait for replay's signal to advance root because of redelivery
   nonsense.  TODO remove this. */

void
fd_repair_root_advanced( fd_repair_t *     self,
                         ulong             slot,
                         fd_mr32_t const * blk_mr );

/* shred_out     SHRED_SIG_SRC_* data shreds

   special handling for idx 0 and the last shred idx.  also called by
   fd_repair_fec_complete. */

void
fd_repair_shred_insert( fd_repair_t *      self,
                        fd_shred_t const * shred,
                        fd_mr32_t const *  fec_mr,
                        long               ts );

/* shred_out     SHRED_SIG_RESULT_EQVOC

   also called internally on a bad block header or conflicting
   parents.  the eager blk is never repaired again, the slot is only
   reachable by blk id.  reason is the eager blk's block_received
   cancelled_reason, ts its cancelled_time. */

void
fd_repair_slot_invalidated( fd_repair_t * self,
                            ulong         slot,
                            int           reason,
                            long          ts );

/* slot must be the root or in the window after it, slots congruent mod
   slot_max share an entry, which is reset for slot first. */

fd_repair_slot_meta_t *
fd_repair_slot_meta( fd_repair_t * self,
                     ulong         slot );

/* votor_out     FD_VOTOR_SIG_QUORUM IMPLICITLY_SKIPPED

   SKIP-FINAL, a finalized descendant declares this slot skipped.  frees
   the slot's blks, a skip cert alone is not final. */

void
fd_repair_slot_skipped( fd_repair_t * self,
                        ulong         slot );

/* fd_repair_blk_treap_insert queues blk in its role's treap for the
   tile to discover its work.  Returns 0 if already queued, or blk is an
   eager blk that is never repaired. */

int
fd_repair_blk_treap_insert( fd_repair_t *     self,
                            fd_repair_blk_t * blk );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_repair_fd_repair_h */
