#define _GNU_SOURCE

#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_clock_tile.h"
#include <linux/futex.h>
#include "generated/fd_rotor_tile_seccomp.h"
#include "../../disco/shred/fd_shred_tile.h"
#include "../../choreo/rotor/fd_rotor.h"
#include "../../choreo/votor/ag_cert.h"
#include "../genesis/fd_genesi_tile.h"
#include "../restore/utils/fd_ssmsg.h"
#include "../votor/fd_votor_tile.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../choreo/rotor/fd_rotor_serde.h"
#include "../../choreo/rotor/fd_rotor_strat.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/events/generated/fd_event_gen.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_rnonce_ss.h"
#include "../../util/net/fd_net_headers.h"
#include "../../util/pod/fd_pod_format.h"
#include "fd_rotor_tile.h"

/* timeout: tracks a repair request we've made that expires at the given
   time.  If the repair request is not responded by timeout, retry. */

struct timeout {
  long  timeout; /* ns */
  ulong slot;
  ulong blk;     /* blk_pool idx, checked against slot when due */
  uint  fec_idx; /* FEC index, WINDOW_INDEX only */
  uchar tag;     /* FD_ROTOR_SERDE_TAG_*, WINDOW_INDEX for any FEC set */
  uchar attempt;
};
typedef struct timeout timeout_t;

#define PRQ_NAME    timeout_prq
#define PRQ_T       timeout_t
#include "../../util/tmpl/fd_prq.c"

/* pending: an outstanding request we're waiting for to either receive a
   response or get timed out.  one-to-many relationship with timeout
   (there can be many pendings per timeout). */

#define PENDING_TTL ((long)FD_RNONCE_SS_DELTA_MAX<<24) /* a shred reply's nonce stops verifying after this */
#define SIGN_NS     (6500L)                            /* fd_ed25519_sign of a request, test_ed25519 --bench */
#define FEC_SET_P90 (38UL)                             /* p90 fec_set_cnt */

struct pending {
  ulong key;
  ulong next; /* pool next */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  long        ts;          /* sent timestamp, nanos */
  ulong       slot;
  ulong       blk;         /* blk_pool idx */
  fd_mr32_t   dmr;
  fd_pubkey_t peer;        /* id_key of the peer picked */
  uint        fec_idx;     /* FEC index */
  uint        fec_set_cnt; /* the blk's when sent */
  uint        tag;         /* FD_ROTOR_SERDE_TAG_* of the request */
};
typedef struct pending pending_t;

#define POOL_NAME pending_pool
#define POOL_T    pending_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           pending_map
#define MAP_ELE_T                          pending_t
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_MULTI                          1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  pending_dlist
#define DLIST_ELE_T pending_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

/* Messages waiting for their signature, idx in the sig's high 32 bits. */

#define SIGN_MAX     (16UL)
#define SIGN_RESERVE (8UL)  /* sign slots only pongs may take */
#define PING_MAX     (4UL)  /* pings per after_credit */

struct sign {
  ulong  next;
  uchar  buf[ FD_ROTOR_SER_MAX ];
  ulong  sz;
  ulong  sig_off; /* where the signature goes in buf */
  uint   saddr;   /* 0 lets the net tile choose */
  uint   daddr;
  ushort dport;   /* net order */
};
typedef struct sign sign_t;

#define POOL_NAME sign_pool
#define POOL_T    sign_t
#include "../../util/tmpl/fd_pool.c"

/* Peers with a new address get one signed request to elicit a ping. */

#define DEQUE_NAME ping_deque
#define DEQUE_T    fd_pubkey_t
#include "../../util/tmpl/fd_deque_dynamic.c"

#define PING_TTL (500L*1000000L)   /* a ping is answered this long after we sent its peer a request, Agave's 2*DELTA */
#define BAN_TTL  (10L*1000000000L) /* a peer whose response fails to verify is not picked for this long */
#define NO_PEER  (10L*1000000L)    /* a req with no peer to pick waits this long */

static fd_ed25519_sig_t const sig_null = {0};

#define IN_KIND_GENESIS (0)
#define IN_KIND_SHRED   (1)
#define IN_KIND_SNAP    (2)
#define IN_KIND_VOTOR   (3)
#define IN_KIND_NET     (4)
#define IN_KIND_GOSSIP  (5)
#define IN_KIND_REPLAY  (6)
#define IN_KIND_SIGN    (7)
#define IN_KIND_EPOCH   (8)

struct fd_rotor_tile {

  /* Signing */

  fd_pubkey_t      identity_key;
  fd_keyswitch_t * keyswitch;
  int              halt_signing;
  sign_t *         sign_pool;
  ulong            sign_cnt;
  struct {
    ulong       idx;
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       free;
  } sign[SIGN_MAX];
  uchar sign_buf[FD_ED25519_SIG_SZ];

  /* Catchup */

  ulong     cert_slot0;      /* staked: first cert slot, 0 if none yet */
  ulong     turbine_slot0;   /* unstaked: first turbine slot, 0 if none yet */

  /* Snapshot */

  ulong     snapshot_slot;   /* root of the snapshot being loaded, applied at FD_SSMSG_DONE */
  fd_mr32_t snapshot_blk_mr;

  /* Epoch metadata */

  fd_multi_epoch_leaders_t * mleaders;

  /* Rotor data structures */

  ulong              seed;
  fd_rotor_t *       rotor;
  fd_rotor_strat_t * strat;

  /* Requests */

  fd_clock_tile_t   clock[1];
  fd_rng_t          rng[1];
  fd_rnonce_ss_t    rnonce_ss[1];
  timeout_t *       eager_prq;
  timeout_t *       notar_prq;
  timeout_t *       final_prq;
  pending_t *       pending_pool;
  pending_map_t *   pending_map;
  pending_dlist_t * pending_dlist;

  /* Networking */

  int               allow_private_address;
  fd_pubkey_t *     ping_deque;
  fd_ip4_udp_hdrs_t net_hdr[1];
  ushort            net_id;
  uchar             net_buf[ FD_NET_MTU ];

  /* Links */

  int in_kind[32];
  union {
    struct {
      fd_wksp_t * mem;
      ulong       chunk0;
      ulong       wmark;
      ulong       mtu;
      ulong       sign_idx; /* IN_KIND_SIGN, its sign tile in sign */
    };
    fd_net_rx_bounds_t net_rx; /* IN_KIND_NET */
  } in[ 32 ];
  ulong chunk; /* reliable ins, after_frag */

  ulong       net_out_idx;
  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  ulong       replay_out_idx;
  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;
  ulong       replay_out_chunk;

  ulong       rserve_out_idx;  /* ULONG_MAX if rserve is disabled */
  fd_wksp_t * rserve_out_mem;
  ulong       rserve_out_chunk0;
  ulong       rserve_out_wmark;
  ulong       rserve_out_chunk;

  /* Events */

  fd_event_block_received_t * event;

  /* Metrics */

  struct {
    ulong      pkt_tx;
    ulong      request_tx[ FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID+1U ]; /* by FD_ROTOR_SERDE_TAG_* */
    ulong      ping_tx;
    ulong      slot_highest_repaired;
    ulong      slot_current;
    ulong      fec_delivered;
    ulong      shred_old;
    ulong      shred_rx;
    ulong      shred_rx_block_id;
    ulong      shred_rx_positional;
    ulong      shred_rx_unmatched;
    ulong      meta_rx;
    ulong      meta_malformed;
    ulong      meta_unsolicited;
    ulong      parent_fec_count_ok;
    ulong      parent_fec_count_failed;
    ulong      fec_root_ok;
    ulong      fec_root_failed;
    ulong      replay_root_advanced;
    ulong      replay_missing_fec;
    ulong      ping_malformed;
    ulong      ping_unknown_peer;
    ulong      ping_signature_failed;
    ulong      req_cancelled;
    ulong      req_no_peer;
    ulong      req_hedged;
    ulong      req_expired;
    fd_histf_t response_latency[ 1 ];
    fd_histf_t retry_delay[ 1 ];
  } metrics[ 1 ];
};
typedef struct fd_rotor_tile fd_rotor_tile_t;

/* push_timeout inserts req into its blk's role's timeout_prq.  A full
   timeout_prq drops it and rewinds the blk, back into its blk_treap,
   so the work is discovered again. */

static void
push_timeout( fd_rotor_tile_t * ctx,
              fd_rotor_blk_t *  blk,
              timeout_t const * req ) {
  fd_rotor_slot_meta_t const * meta = fd_rotor_slot_meta( ctx->rotor, blk->slot );
  ulong                        idx  = fd_rotor_blk_pool_idx( ctx->rotor->blk_pool, blk );
  timeout_t *                  prq  = meta->final==idx ? ctx->final_prq : meta->notar==idx ? ctx->notar_prq : ctx->eager_prq;
  if( FD_LIKELY( timeout_prq_cnt( prq )<timeout_prq_max( prq ) ) ) {
    timeout_prq_insert( prq, req );
    return;
  }
  if( FD_LIKELY( req->tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX ) ) blk->wait_fec_cnt = fd_uint_min( blk->wait_fec_cnt, req->fec_idx );
  blk->meta_req    = ( blk->meta_req    && req->tag!=FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT );
  blk->highest_req = ( blk->highest_req && req->tag!=FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX      );
  blk->orphan_req  = ( blk->orphan_req  && req->tag!=FD_ROTOR_SERDE_TAG_ORPHAN                    );
  if( FD_UNLIKELY( blk->in_blk_treap ) ) return;
  fd_rotor_treap_ele_insert( meta->final==idx ? ctx->rotor->final_treap : meta->notar==idx ? ctx->rotor->notar_treap : ctx->rotor->eager_treap, blk, ctx->rotor->blk_pool );
  blk->in_blk_treap = 1;
}

/* poll_timeout polls for one or more requests that have timed out. */

static fd_rotor_blk_t *
poll_timeout( fd_rotor_tile_t * ctx,
              long              now,
              timeout_t *       out ) {
  timeout_t * prqs[3] = { ctx->final_prq, ctx->notar_prq, ctx->eager_prq };
  for( ulong c=0UL; c<3; c++ ) {
    timeout_t * prq = prqs[ c ];
    while( timeout_prq_cnt( prq ) && prq[ 0 ].timeout<=now ) {
      timeout_t req = prq[ 0 ];
      timeout_prq_remove_min( prq );

      fd_rotor_blk_t * blk = fd_rotor_blk_map_ele_query( ctx->rotor->blk_map, &req.slot, NULL, ctx->rotor->blk_pool );
      while( blk && fd_rotor_blk_pool_idx( ctx->rotor->blk_pool, blk )!=req.blk ) blk = (fd_rotor_blk_t *)fd_rotor_blk_map_ele_next_const( blk, NULL, ctx->rotor->blk_pool ); /* the req outlived its blk */
      if( FD_UNLIKELY( !blk ) ) { ctx->metrics->req_cancelled++; continue; }
      fd_rotor_slot_meta_t const * meta = fd_rotor_slot_meta( ctx->rotor, blk->slot );
      if( FD_UNLIKELY( meta->final!=req.blk && meta->notar!=req.blk && meta->eager==req.blk && !blk->eager ) ) { ctx->metrics->req_cancelled++; continue; } /* the slot's eager blk, never repaired */
      fd_rotor_fec_t const * fec = fd_rotor_fec_pool_ele_const( ctx->rotor->fec_pool, fd_ulong_if( req.tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX, blk->fecs[ req.fec_idx ], fd_rotor_fec_pool_idx_null( ctx->rotor->fec_pool ) ) );
      if( FD_UNLIKELY( req.tag==FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT && blk->parent_slot!=ULONG_MAX                                      ) ) { ctx->metrics->req_cancelled++; continue; }
      if( FD_UNLIKELY( req.tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX             && fec && fec->complete                                             ) ) { ctx->metrics->req_cancelled++; continue; }
      if( FD_UNLIKELY( req.tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX             && !blk->eager && req.fec_idx>=blk->cmpl_fec_cnt                     ) ) { ctx->metrics->req_cancelled++; continue; } /* of a freed blk whose pool idx was reused */
      if( FD_UNLIKELY( req.tag==FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX     && blk->cmpl_fec_cnt                                                ) ) { ctx->metrics->req_cancelled++; continue; }
      fd_rotor_blk_t const * parent = fd_rotor_blk_pool_ele_const( ctx->rotor->blk_pool, blk->parent );
      if( FD_UNLIKELY( req.tag==FD_ROTOR_SERDE_TAG_ORPHAN && ( blk->connected==1 || blk->parent_slot<=ctx->rotor->root || ( parent && parent->parent_slot!=ULONG_MAX ) ) ) ) { blk->orphan_req = 0; ctx->metrics->req_cancelled++; continue; } /* its ancestry showed up, died with the root, or a lower blk asks */
      long t_eager = fd_rotor_strat_eager_ns( ctx->strat, fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, blk->slot ) );
      if( FD_UNLIKELY( req.tag==FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX     && blk->rcvd_fec_ts+t_eager>now                                     ) ) { /* turbine is not quiet yet */
        req.timeout = blk->rcvd_fec_ts+t_eager;
        push_timeout( ctx, blk, &req );
        continue;
      }
      *out = req;
      return blk;
    }
  }
  return NULL;
}

/* discover new requests translating rotor treaps => repair requests. */

static void
discover( fd_rotor_tile_t * ctx,
          fd_rotor_blk_t *  blk,
          long              now ) {
  fd_rotor_slot_meta_t const * meta = fd_rotor_slot_meta( ctx->rotor, blk->slot );
  ulong                        idx  = fd_rotor_blk_pool_idx( ctx->rotor->blk_pool, blk );
  if( FD_UNLIKELY( blk->slot<=ctx->rotor->root ) ) return;
  if( FD_UNLIKELY( meta->final!=idx && meta->notar!=idx && meta->eager==idx && !blk->eager ) ) return; /* the slot's eager blk, never repaired */

  int       eager   = blk->eager;
  long      t_eager = fd_rotor_strat_eager_ns( ctx->strat, fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, blk->slot ) );
  timeout_t req     = { .slot = blk->slot, .blk = fd_rotor_blk_pool_idx( ctx->rotor->blk_pool, blk ) };

  if( FD_UNLIKELY( !eager && blk->parent_slot==ULONG_MAX && blk->meta_req ) ) return;
  if( FD_UNLIKELY( !eager && blk->parent_slot==ULONG_MAX ) ) {
    blk->meta_req = 1;
    req.tag       = FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT;
    req.timeout   = now;
    push_timeout( ctx, blk, &req );
    return;
  }

  fd_rotor_blk_t const * parent      = fd_rotor_blk_pool_ele_const( ctx->rotor->blk_pool, blk->parent );
  int                    orphan_root = !parent || parent->parent_slot==ULONG_MAX; /* the root of its disconnected subtree, the blks under it wait on it */
  int                    orphaned    = blk->connected!=1 && orphan_root && !blk->orphan_req && blk->parent_slot!=ULONG_MAX && blk->parent_slot>ctx->rotor->root && memcmp( &blk->parent_blk_mr, &hash_null, sizeof(fd_mr32_t) ) && !( eager && meta->invalidated );
  if( FD_UNLIKELY( orphaned ) ) {
    blk->orphan_req = 1;
    req.tag         = FD_ROTOR_SERDE_TAG_ORPHAN; /* its ancestry is unknown, learn up to 11 of it in one reply */
    req.timeout     = fd_long_if( eager, blk->rcvd_fec_ts+t_eager, now ); /* an eager blk's parent may still be on turbine */
    push_timeout( ctx, blk, &req );
  }

  if( FD_UNLIKELY( eager && !blk->cmpl_fec_cnt && !blk->highest_req ) ) {
    blk->highest_req = 1;
    req.tag          = FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX;
    req.timeout      = blk->rcvd_fec_ts+t_eager;
    push_timeout( ctx, blk, &req );
  }

  timeout_t * prq          = meta->final==idx ? ctx->final_prq : meta->notar==idx ? ctx->notar_prq : ctx->eager_prq;
  uint        cmpl_fec_cnt = fd_uint_if( !!blk->cmpl_fec_cnt, blk->cmpl_fec_cnt, fd_uint_if( eager, blk->rcvd_fec_cnt, 0U ) );
  uint        fec_idx      = blk->wait_fec_cnt;
  for( ; fec_idx<cmpl_fec_cnt && timeout_prq_cnt( prq )<timeout_prq_max( prq ); fec_idx++ ) {
    fd_rotor_fec_t const * fec = fd_rotor_fec_pool_ele_const( ctx->rotor->fec_pool, blk->fecs[ fec_idx ] );
    if( FD_LIKELY( fec && fec->complete ) ) continue;
    req.tag     = FD_ROTOR_SERDE_TAG_WINDOW_INDEX;
    req.fec_idx = fec_idx;
    req.timeout = fd_long_if( eager, ( fec ? fec->first_ts : blk->rcvd_fec_ts )+t_eager, now ); /* a partial set waits from its first shred, a missing one from the last set turbine showed */
    push_timeout( ctx, blk, &req );
  }
  blk->wait_fec_cnt = fec_idx;
  if( FD_LIKELY( timeout_prq_cnt( prq )<timeout_prq_max( prq ) ) ) return;
  if( FD_UNLIKELY( blk->in_blk_treap ) ) return;
  fd_rotor_treap_ele_insert( meta->final==idx ? ctx->rotor->final_treap : meta->notar==idx ? ctx->rotor->notar_treap : ctx->rotor->eager_treap, blk, ctx->rotor->blk_pool ); /* timeout_prq filled up, resume later */
  blk->in_blk_treap = 1;
}

FD_STATIC_ASSERT( FD_FEC_BLK_MAX<=FD_EVENT_BLOCK_RECEIVED_FEC_SETS_MAX, block_received_fec_sets );

static void
report_block_received( void *                 ctx_,
                       fd_rotor_blk_t const * blk ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  fd_rotor_tile_t *      ctx       = (fd_rotor_tile_t *)ctx_;
  uint                   fec_cnt   = fd_uint_if( !!blk->cmpl_fec_cnt, blk->cmpl_fec_cnt, blk->rcvd_fec_cnt ); /* an incomplete blk reports what it received */
  fd_rotor_fec_t const * last      = fd_rotor_fec_pool_ele_const( ctx->rotor->fec_pool, fec_cnt ? blk->fecs[ fec_cnt-1U ] : fd_rotor_fec_pool_idx_null( ctx->rotor->fec_pool ) );
  int                    is_leader = last && last->is_leader;
  int                    known_id  = fd_rotor_slot_meta( ctx->rotor, blk->slot )->eager!=fd_rotor_blk_pool_idx( ctx->rotor->blk_pool, blk );
  fd_event_block_received_t * ev = ctx->event;
  fd_memset( ev, 0, FD_EVENT_BLOCK_RECEIVED_PREFIX_SZ );
  ev->slot             = blk->slot;
  ev->parent_slot      = blk->parent_slot;
  ev->cancelled        = !!blk->telemetry.cancelled_reason;
  ev->cancelled_reason = fd_int_if( !!blk->telemetry.cancelled_reason, blk->telemetry.cancelled_reason, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_NOT_CANCELLED );
  ev->cancelled_time   = fd_ulong_if( ev->cancelled, (ulong)blk->telemetry.cancelled_ts, 0UL );
  ev->notarized        = known_id && !is_leader;
  ev->is_leader        = is_leader;
  ev->caught_up        = ctx->metrics->slot_current<=ctx->metrics->slot_highest_repaired+4UL;
  ev->fec_set_count    = blk->cmpl_fec_cnt;
  ev->slot_complete    = !!blk->cmpl_fec_cnt;
  ev->equivocation_detected_shred  = blk->telemetry.cancelled_reason==FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH;
  ev->last_completed_fec_set_index = blk->telemetry.last_cmpl_fec_idx;
  ev->last_shred_received_time     = (ulong)blk->telemetry.last_shred_ts;
  ev->turbine_shred_received       = blk->telemetry.turbine_shred_cnt;
  ev->repair_shred_received        = blk->telemetry.repair_shred_cnt;
  ev->recovered_shred_count        = blk->telemetry.recovered_shred_cnt;
  if( FD_LIKELY( !is_leader ) ) { /* our own blocks are never repaired */
    ev->repair_request_window_count             = blk->telemetry.req_window_cnt;
    ev->repair_request_highest_window_count     = blk->telemetry.req_highest_cnt;
    ev->repair_request_orphan_count             = blk->telemetry.req_orphan_cnt;
    ev->repair_request_shred_for_block_id_count = blk->telemetry.req_shred_bid_cnt;
    ev->repair_request_parent_fec_count         = blk->telemetry.req_parent_cnt;
    ev->repair_request_fec_root_count           = blk->telemetry.req_fec_root_cnt;
    ev->first_repair_request_time               = (ulong)blk->telemetry.first_req_ts;
    ev->repair_shred_responses_received         = blk->telemetry.shred_res_cnt;
    ev->parent_fec_count_responses_received     = blk->telemetry.parent_res_cnt;
    ev->fec_root_responses_received             = blk->telemetry.fec_root_res_cnt;
    ev->last_repair_received_time               = (ulong)blk->telemetry.last_shred_res_ts;
    ev->first_meta_received_time                = (ulong)blk->telemetry.first_meta_res_ts;
  }
  memcpy( ev->block_id,        blk->dmr.uc,           sizeof(fd_mr32_t) );
  memcpy( ev->parent_block_id, blk->parent_blk_mr.uc, sizeof(fd_mr32_t) );
  ev->fec_sets_cnt = fd_ulong_min( fec_cnt, FD_EVENT_BLOCK_RECEIVED_FEC_SETS_MAX );
  for( ulong k=0UL; k<ev->fec_sets_cnt; k++ ) {
    fd_rotor_fec_t const *               fec = fd_rotor_fec_pool_ele_const( ctx->rotor->fec_pool, blk->fecs[ k ] );
    fd_event_block_received_fec_sets_t * f   = &ev->fec_sets[ k ];
    fd_memset( f, 0, sizeof(fd_event_block_received_fec_sets_t) );
    if( FD_UNLIKELY( !fec ) ) continue; /* an incomplete blk can miss FEC sets */
    memcpy( f->merkle_root, fec->mr32.uc, sizeof(fd_mr32_t) );
    f->index                      = (uint)k*FD_FEC_SHRED_CNT;
    f->first_shred_received_time  = (ulong)fec->first_ts;
    f->completed_time             = (ulong)fec->cmpl_ts;
    f->final_shred_source         = fd_int_if( fec->is_leader, FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_LEADER, fec->final_src );
    ev->first_shred_received_time = fd_ulong_if( fec->first_ts && ( !ev->first_shred_received_time || (ulong)fec->first_ts<ev->first_shred_received_time ), (ulong)fec->first_ts, ev->first_shred_received_time );
  }
  fd_event_report_block_received( ev );
}


static inline void
handle_shred( fd_rotor_tile_t * ctx,
              ulong             sig,
              uchar const *     chunk,
              long              rx_ts ) {
  if( FD_UNLIKELY( fd_shred_sig_src( sig )==SHRED_SIG_FEC_EVICTED ) ) {
    fd_fec_evicted_t const * evicted = (fd_fec_evicted_t const *)fd_type_pun_const( chunk );
    if( FD_UNLIKELY( evicted->slot<=ctx->rotor->root || evicted->slot>=ctx->rotor->root+ctx->rotor->slot_max ) ) return; /* outside the window */
    if( FD_UNLIKELY( evicted->fec_set_idx>=FD_SHRED_BLK_MAX ) ) return;
    fd_mr20_t key; memcpy( key.uc, evicted->merkle_root.uc, sizeof(fd_mr20_t) );
    fd_rotor_fec_evicted( ctx->rotor, evicted->slot, evicted->fec_set_idx, &key );
    return;
  }

  ulong slot = ((fd_shred_base_t const *)fd_type_pun_const( chunk ))->shred.slot; /* complete and shred messages share the header position */
  ctx->metrics->shred_old          += (ulong)( slot<=ctx->rotor->root && fd_shred_sig_src( sig )<=SHRED_SIG_SRC_BAD_REPAIR );
  ctx->metrics->slot_current        = fd_ulong_if( slot>ctx->rotor->root && fd_shred_sig_src( sig )<=SHRED_SIG_SRC_BAD_REPAIR, fd_ulong_max( ctx->metrics->slot_current, slot ), ctx->metrics->slot_current );
  int turbine_first = slot>ctx->rotor->root && slot<ctx->rotor->root+ctx->rotor->slot_max && fd_shred_sig_src( sig )==SHRED_SIG_SRC_TURBINE && !ctx->turbine_slot0;
  ctx->turbine_slot0 = fd_ulong_if( turbine_first, slot, ctx->turbine_slot0 );
  if( FD_UNLIKELY( slot<=ctx->rotor->root || slot>=ctx->rotor->root+ctx->rotor->slot_max ) ) return; /* outside the window */

  fd_rotor_strat_peer_t const * self = fd_rotor_strat_query( ctx->strat, &ctx->identity_key );
  if( FD_UNLIKELY( turbine_first && !( self && (ulong)( self-ctx->strat->cur.peers )<ctx->strat->staked_cnt ) ) ) fd_rotor_slot_catchup( ctx->rotor, slot ); /* unstaked has no certs, turbine is untrusted so staked never does this */

  switch( fd_shred_sig_src( sig ) ) {
  case SHRED_SIG_FEC_COMPLETE:
  case SHRED_SIG_FEC_COMPLETE_LEADER:
  case SHRED_SIG_FEC_COMPLETE_AGAIN: {
    fd_fec_complete_t const * complete = (fd_fec_complete_t const *)fd_type_pun_const( chunk );
    fd_shred_t const *        shred    = &complete->last_shred_hdr;
    if( FD_UNLIKELY( shred->idx>=FD_SHRED_BLK_MAX                                                   ) ) return;
    if( FD_UNLIKELY( !shred->data.parent_off || shred->data.parent_off>shred->slot-ctx->rotor->root ) ) return; /* parent is the slot itself, or below the root */

    fd_rotor_fec_t const * fec = fd_rotor_fec_complete( ctx->rotor, shred, &complete->merkle_root, sig==SHRED_SIG_FEC_COMPLETE_LEADER, (uint)complete->turbine_shred_cnt, (uint)complete->repair_shred_cnt, (uint)complete->reconstructed_shred_cnt, rx_ts );
    if( FD_UNLIKELY( sig!=SHRED_SIG_FEC_COMPLETE || !fec || !fec->first_ts ) ) break; /* a first completion from the network */

    fd_rotor_strat_turbine_done( ctx->strat, fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, shred->slot ), rx_ts-fec->first_ts );
    break;
  }
  case SHRED_SIG_SRC_TURBINE:
  case SHRED_SIG_SRC_LEADER:
  case SHRED_SIG_SRC_RECONSTRUCTED:
  case SHRED_SIG_SRC_REPAIR:
  case SHRED_SIG_SRC_BAD_REPAIR: {
    fd_shred_base_t const * msg   = (fd_shred_base_t const *)fd_type_pun_const( chunk );
    fd_shred_t const *      shred = &msg->shred;
    long                    now   = fd_clock_tile_now( ctx->clock );

    if( FD_UNLIKELY( fd_shred_sig_res( sig )==SHRED_SIG_RESULT_EQVOC ) ) {
      fd_rotor_slot_invalidated( ctx->rotor, shred->slot, FD_EVENT_BLOCK_RECEIVED_CANCELLED_REASON_MERKLE_ROOT_MISMATCH, now );
      return;
    }

    if( FD_UNLIKELY( !fd_shred_is_data( fd_shred_type( shred->variant ) ) ) ) return;
    if( FD_UNLIKELY( shred->idx>=FD_SHRED_BLK_MAX ) ) return;

    /* A repair shred answers the request whose nonce it carries: the
       first one ends that request's pick.  A HighestWindowIndex answer
       that does not complete the slot arrives as BAD_REPAIR. */

    int         normal  = fd_rnonce_ss_normal_repair( msg->rnonce );
    int         reply   = fd_shred_sig_src( sig )==SHRED_SIG_SRC_REPAIR || fd_shred_sig_src( sig )==SHRED_SIG_SRC_BAD_REPAIR;
    ulong       key     = (ulong)(uint)slot<<32 | fd_uint_if( normal, shred->idx/FD_FEC_SHRED_CNT, (uint)FD_FEC_BLK_MAX );
    pending_t * pending = reply ? pending_map_ele_query( ctx->pending_map, &key, NULL, ctx->pending_pool ) : NULL;
    for( ; pending; pending = (pending_t *)pending_map_ele_next_const( pending, NULL, ctx->pending_pool ) ) {
      if( FD_LIKELY( fd_rnonce_ss_compute( ctx->rnonce_ss, normal, slot, shred->idx, pending->ts )!=msg->rnonce ) ) continue;
      fd_rotor_strat_request_done( ctx->strat, &pending->peer, now-pending->ts );
      fd_histf_sample( ctx->metrics->response_latency, (ulong)( now-pending->ts ) );
      ctx->metrics->shred_rx_block_id   += (ulong)( pending->tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID );
      ctx->metrics->shred_rx_positional += (ulong)( pending->tag!=FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID );
      fd_rotor_blk_t * blk = fd_rotor_blk_map_ele_query( ctx->rotor->blk_map, &pending->slot, NULL, ctx->rotor->blk_pool );
      while( blk && memcmp( &blk->dmr, &pending->dmr, sizeof(fd_mr32_t) ) ) blk = (fd_rotor_blk_t *)fd_rotor_blk_map_ele_next_const( blk, NULL, ctx->rotor->blk_pool ); /* not by pending->blk, it may be freed or reused, and a notar blk lives on as eager after dedup */
      if( FD_LIKELY( blk && ( pending->tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX || pending->tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID ) ) ) {
        blk->telemetry.shred_res_cnt++;
        blk->telemetry.last_shred_res_ts = rx_ts;
      }
      pending_map_ele_remove_fast( ctx->pending_map,   pending, ctx->pending_pool );
      pending_dlist_ele_remove   ( ctx->pending_dlist, pending, ctx->pending_pool );
      pending_pool_ele_release   ( ctx->pending_pool,  pending );
      break;
    }
    ctx->metrics->shred_rx           += (ulong)reply;
    ctx->metrics->shred_rx_unmatched += (ulong)( reply && !pending );

    if( FD_UNLIKELY( !shred->data.parent_off || shred->data.parent_off>shred->slot-ctx->rotor->root ) ) return; /* parent is the slot itself, or below the root */

    int src = fd_shred_sig_src( sig )==SHRED_SIG_SRC_TURBINE ? FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_TURBINE :
              fd_shred_sig_src( sig )==SHRED_SIG_SRC_LEADER  ? FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_LEADER  :
              reply                                          ? FD_EVENT_BLOCK_RECEIVED_FEC_SETS_FINAL_SHRED_SOURCE_REPAIR  :
                                                               0; /* reconstructed, not received */
    fd_rotor_shred_insert( ctx->rotor, shred, &msg->merkle_root, src, rx_ts );
    break;
  }
  default: FD_LOG_ERR(( "unhandled shred sig src %u", fd_shred_sig_src( sig ) ));
  }
}

static void
handle_snapshot( fd_rotor_tile_t * ctx,
                 ulong             sig,
                 uchar const *     chunk ) {
  switch( fd_ssmsg_sig_message( sig ) ) {
  case FD_SSMSG_MANIFEST_FULL:
  case FD_SSMSG_MANIFEST_INCREMENTAL: {
    fd_snapshot_manifest_t const * manifest = (fd_snapshot_manifest_t const *)fd_type_pun_const( chunk );
    ctx->snapshot_slot = manifest->slot;
    memcpy( ctx->snapshot_blk_mr.uc, manifest->block_id, sizeof(fd_mr32_t) );
    break;
  }
  case FD_SSMSG_DONE:
    fd_rotor_init( ctx->rotor, ctx->snapshot_slot, &ctx->snapshot_blk_mr, report_block_received, ctx );
    break;
  default:
    FD_LOG_ERR(( "unexpected snapshot message %lu", fd_ssmsg_sig_message( sig ) ));
  }
}

static inline void
handle_votor( fd_rotor_tile_t * ctx,
              ulong             sig,
              uchar const *     chunk ) {
  fd_votor_msg_t const *        msg    = (fd_votor_msg_t const *)fd_type_pun_const( chunk );
  long                          now    = fd_clock_tile_now( ctx->clock );
  fd_rotor_strat_peer_t const * self   = fd_rotor_strat_query( ctx->strat, &ctx->identity_key );
  int                           staked = self && (ulong)( self-ctx->strat->cur.peers )<ctx->strat->staked_cnt; /* unstaked catches up from turbine, see handle_shred */

  switch( sig ) {
  case FD_VOTOR_SIG_CERTED: {
    fd_votor_certed_t const * certed = &msg->certed;
    if( FD_UNLIKELY( certed->slot<=ctx->rotor->root || certed->slot>=ctx->rotor->root+ctx->rotor->slot_max ) ) return; /* outside the window */
    if( FD_UNLIKELY( staked && !ctx->cert_slot0 ) ) {
      ctx->cert_slot0 = certed->slot;
      fd_rotor_slot_catchup( ctx->rotor, certed->slot );
    }
    switch( certed->kind ) {
    case AG_CERT_KIND_FINAL:
    case AG_CERT_KIND_FAST_FINAL:     fd_rotor_blk_finalized( ctx->rotor, certed->slot, &certed->block_id, now ); break;
    case AG_CERT_KIND_NOTAR:          fd_rotor_blk_notarized( ctx->rotor, certed->slot, &certed->block_id ); break;
    case AG_CERT_KIND_NOTAR_FALLBACK: break;
    case AG_CERT_KIND_SKIP:           break; /* a skip cert alone is not final, see fd_rotor_slot_skipped */
    default: FD_LOG_ERR(( "unhandled cert kind %u", certed->kind ));
    }
    break;
  }
  case FD_VOTOR_SIG_REPAIR: {
    ulong slot = msg->repair.slot;
    if( FD_UNLIKELY( slot<=ctx->rotor->root || slot>=ctx->rotor->root+ctx->rotor->slot_max ) ) return; /* outside the window */
    fd_rotor_blk_notarized( ctx->rotor, slot, &msg->repair.block_id );
    break;
  }
  case FD_VOTOR_SIG_QUORUM: {
    ulong slot = msg->quorum.slot;
    if( FD_UNLIKELY( slot<=ctx->rotor->root || slot>=ctx->rotor->root+ctx->rotor->slot_max ) ) return; /* outside the window */
    switch( msg->quorum.kind ) {
    case FD_VOTOR_QUORUM_KIND_SAFE_TO_NOTAR:        break; /* replay already has the block */
    case FD_VOTOR_QUORUM_KIND_IMPLICITLY_FINALIZED: fd_rotor_blk_finalized( ctx->rotor, slot, &msg->quorum.block_id, now ); break;
    case FD_VOTOR_QUORUM_KIND_IMPLICITLY_SKIPPED:   fd_rotor_slot_skipped ( ctx->rotor, slot );                        break;
    default: FD_LOG_ERR(( "unhandled quorum kind %u", msg->quorum.kind ));
    }
    break;
  }
  default: FD_LOG_ERR(( "unhandled votor sig %lu", sig ));
  }
}

static inline void
handle_replay( fd_rotor_tile_t * ctx,
               ulong             sig,
               uchar const *     chunk ) {
  switch( sig ) {
  case REPLAY_SIG_ROOT_ADVANCED: {
    fd_replay_root_advanced_t const * root = (fd_replay_root_advanced_t const *)fd_type_pun_const( chunk );
    ctx->metrics->replay_root_advanced++;
    if( FD_UNLIKELY( root->slot<=ctx->rotor->root ) ) return;
    fd_rotor_root_advanced( ctx->rotor, root->slot, &root->block_id );
    break;
  }
  case REPLAY_SIG_SLOT_DEAD: {
    fd_replay_slot_dead_t const * dead = (fd_replay_slot_dead_t const *)fd_type_pun_const( chunk );
    if( FD_UNLIKELY( dead->slot<=ctx->rotor->root ) ) return;
    fd_rotor_blk_dead( ctx->rotor, dead->slot, &dead->block_id );
    break;
  }
  case REPLAY_SIG_MISSING_FEC:
    ctx->metrics->replay_missing_fec++;
    ctx->rotor->reconsume = 1;
    break;
  default: FD_LOG_ERR(( "unhandled replay sig %lu", sig ));
  }
}

static void
handle_gossip( fd_rotor_tile_t *                  ctx,
               ulong                              sig,
               fd_gossip_update_message_t const * msg ) {

  fd_pubkey_t id_key;
  memcpy( id_key.uc, msg->origin, sizeof(fd_pubkey_t) );

  switch( sig ) {
  case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
    fd_gossip_socket_t const * socket = &msg->contact_info->value->sockets[FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR];
    uint                       ip4    = fd_uint_if( !socket->is_ipv6, socket->ip4, 0U );
    ushort                     port   = fd_ushort_bswap( socket->port );
    if( FD_UNLIKELY( fd_pubkey_eq( &id_key, &ctx->identity_key ) || !ip4 || !port || fd_ip4_addr_is_mcast( ip4 ) || ( !ctx->allow_private_address && !fd_ip4_addr_is_public( ip4 ) ) ) ) {
      fd_rotor_strat_contact_info_removed( ctx->strat, &id_key );
      return;
    }

    fd_rotor_strat_contact_info_updated( ctx->strat, &id_key, ip4, port );
    fd_rotor_strat_peer_t const * peer = fd_rotor_strat_query( ctx->strat, &id_key );
    if( FD_UNLIKELY( peer && !peer->ping_ts && !ping_deque_full( ctx->ping_deque ) ) ) ping_deque_push_tail( ctx->ping_deque, id_key ); /* new address */
    break;
  }
  case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE:
    fd_rotor_strat_contact_info_removed( ctx->strat, &id_key );
    break;
  default:
    FD_LOG_ERR(( "unexpected gossip sig %lu", sig ));
  }
}

/* Only answer a ping if it comes from the address of a peer we sent a
   request to in the last PING_TTL. */

static void
handle_ping( fd_rotor_tile_t *    ctx,
             fd_stem_context_t *  stem,
             uchar const *        data,
             ulong                data_sz,
             fd_ip4_hdr_t const * ip4,
             fd_udp_hdr_t const * udp,
             long                 now ) {
  fd_pubkey_t      from;
  fd_hash_t        token;
  fd_ed25519_sig_t sig;
  if( FD_UNLIKELY( !fd_rotor_ping_de( data, data_sz, &from, &token, sig ) && !fd_rotor_block_id_ping_de( data, data_sz, &from, &token, sig ) ) ) { ctx->metrics->ping_malformed++; return; }

  fd_rotor_strat_peer_t * peer = fd_rotor_strat_query( ctx->strat, &from );
  if( FD_UNLIKELY( !peer                                                                  ) ) { ctx->metrics->ping_unknown_peer++; return; }
  if( FD_UNLIKELY( peer->ip4!=ip4->saddr || fd_ushort_bswap( peer->port )!=udp->net_sport ) ) return;
  if( FD_UNLIKELY( now-peer->ping_ts>=PING_TTL                                            ) ) return;
  if( FD_UNLIKELY( ctx->halt_signing || !sign_pool_free( ctx->sign_pool )                 ) ) return;

  peer->ping_ts = now-PING_TTL; /* one verify per request we sent */
  fd_sha512_t sha[1];
  if( FD_UNLIKELY( fd_ed25519_verify( token.uc, sizeof(fd_hash_t), sig, from.uc, sha )!=FD_ED25519_SUCCESS ) ) { ctx->metrics->ping_signature_failed++; return; }

  ulong s = 0UL;
  for( ulong i=1UL; i<ctx->sign_cnt; i++ ) s = fd_ulong_if( ctx->sign[ i ].free>ctx->sign[ s ].free, i, s );
  uchar * preimage = fd_chunk_to_laddr( ctx->sign[ s ].mem, ctx->sign[ s ].chunk );
  memcpy( preimage,      "SOLANA_PING_PONG", 16UL              );
  memcpy( preimage+16UL, token.uc,           sizeof(fd_hash_t) );
  fd_rotor_pong_t pong;
  fd_sha256_hash( preimage, 16UL+sizeof(fd_hash_t), pong.hash.uc );

  sign_t * pending = sign_pool_ele_acquire( ctx->sign_pool );
  *pending    = (sign_t){ .sig_off = FD_ROTOR_PONG_SER_SZ-FD_ED25519_SIG_SZ, .saddr = ip4->daddr, .daddr = ip4->saddr, .dport = udp->net_sport };
  pending->sz = fd_rotor_pong_ser( &pong, sig_null, &ctx->identity_key, pending->buf );
  fd_stem_publish( stem, ctx->sign[ s ].idx, (sign_pool_idx( ctx->sign_pool, pending )<<32)|(ulong)FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519, ctx->sign[ s ].chunk, 16UL+sizeof(fd_hash_t), 0UL, 0UL, 0UL );
  ctx->sign[ s ].chunk = fd_dcache_compact_next( ctx->sign[ s ].chunk, 16UL+sizeof(fd_hash_t), ctx->sign[ s ].chunk0, ctx->sign[ s ].wmark );
  ctx->sign[ s ].free--;
  ctx->metrics->request_tx[ FD_ROTOR_SERDE_TAG_PONG ]++;
}

static void
handle_parent_and_fec_set_count_res( fd_rotor_tile_t *    ctx,
                                     uchar const *        data,
                                     ulong                data_sz,
                                     fd_ip4_hdr_t const * ip4,
                                     fd_udp_hdr_t const * udp,
                                     long                 now ) {
  uint      fec_set_cnt;
  ulong     parent_slot;
  fd_mr32_t parent_blk_mr;
  uchar     proof[ FD_ROTOR_PROOF_MAX ];
  ulong     proof_sz;
  uint      nonce;
  ctx->metrics->meta_rx++;
  if( FD_UNLIKELY( fd_rotor_res_parent_fec_set_count_de( data, data_sz, &fec_set_cnt, &parent_slot, &parent_blk_mr, proof, &proof_sz, &nonce )!=data_sz ) ) { ctx->metrics->meta_malformed++; return; }

  pending_t * pending = pending_map_ele_query( ctx->pending_map, &(ulong){ nonce }, NULL, ctx->pending_pool );
  if( FD_UNLIKELY( !pending || pending->tag!=FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT ) ) { ctx->metrics->meta_unsolicited++; return; }

  fd_rotor_strat_peer_t const * peer  = fd_rotor_strat_query( ctx->strat, &pending->peer );
  int                           valid = !fd_rotor_res_parent_fec_set_count_verify( fec_set_cnt, parent_slot, &parent_blk_mr, proof, proof_sz, &pending->dmr );
  int                           from  = peer && peer->ip4==ip4->saddr && fd_ushort_bswap( peer->port )==udp->net_sport;
  ctx->metrics->parent_fec_count_failed += (ulong)!valid;
  if( FD_UNLIKELY( !valid && !from ) ) return;

  pending_t sent = *pending;
  pending_map_ele_remove_fast( ctx->pending_map,   pending, ctx->pending_pool );
  pending_dlist_ele_remove   ( ctx->pending_dlist, pending, ctx->pending_pool );
  pending_pool_ele_release   ( ctx->pending_pool,  pending );
  if( FD_UNLIKELY( !valid ) ) {
    fd_rotor_strat_request_failed( ctx->strat, &sent.peer, now+BAN_TTL );
    return;
  }
  fd_rotor_strat_request_done( ctx->strat, &sent.peer, now-sent.ts );
  fd_histf_sample( ctx->metrics->response_latency, (ulong)( now-sent.ts ) );
  ctx->metrics->parent_fec_count_ok++;

  if( FD_UNLIKELY( sent.slot<=ctx->rotor->root  ) ) return; /* rooted while in flight */
  if( FD_UNLIKELY( parent_slot<ctx->rotor->root ) ) return; /* on a fork below the root */
  if( FD_UNLIKELY( parent_slot>=sent.slot       ) ) return; /* the leader signed a bad parent */

  fd_rotor_blk_parented( ctx->rotor, sent.slot, &sent.dmr, parent_slot, &parent_blk_mr, fec_set_cnt, now );
}

static void
handle_fec_set_root_res( fd_rotor_tile_t *    ctx,
                         uchar const *        data,
                         ulong                data_sz,
                         fd_ip4_hdr_t const * ip4,
                         fd_udp_hdr_t const * udp,
                         long                 now ) {
  fd_mr20_t fec_mr;
  uchar     proof[ FD_ROTOR_PROOF_MAX ];
  ulong     proof_sz;
  uint      nonce;
  ctx->metrics->meta_rx++;
  if( FD_UNLIKELY( fd_rotor_res_fec_set_root_de( data, data_sz, fec_mr.uc, proof, &proof_sz, &nonce )!=data_sz ) ) { ctx->metrics->meta_malformed++; return; }

  pending_t * pending = pending_map_ele_query( ctx->pending_map, &(ulong){ nonce }, NULL, ctx->pending_pool );
  if( FD_UNLIKELY( !pending || pending->tag!=FD_ROTOR_SERDE_TAG_FEC_SET_ROOT ) ) { ctx->metrics->meta_unsolicited++; return; }

  fd_rotor_strat_peer_t const * peer  = fd_rotor_strat_query( ctx->strat, &pending->peer );
  int                           valid = !fd_rotor_res_fec_set_root_verify( fec_mr.uc, proof, proof_sz, &pending->dmr, pending->fec_idx*FD_FEC_SHRED_CNT, pending->fec_set_cnt );
  int                           from  = peer && peer->ip4==ip4->saddr && fd_ushort_bswap( peer->port )==udp->net_sport;
  ctx->metrics->fec_root_failed += (ulong)!valid;
  if( FD_UNLIKELY( !valid && !from ) ) return;

  pending_t sent = *pending;
  pending_map_ele_remove_fast( ctx->pending_map,   pending, ctx->pending_pool );
  pending_dlist_ele_remove   ( ctx->pending_dlist, pending, ctx->pending_pool );
  pending_pool_ele_release   ( ctx->pending_pool,  pending );
  if( FD_UNLIKELY( !valid ) ) {
    fd_rotor_strat_request_failed( ctx->strat, &sent.peer, now+BAN_TTL );
    return;
  }
  fd_rotor_strat_request_done( ctx->strat, &sent.peer, now-sent.ts );
  fd_histf_sample( ctx->metrics->response_latency, (ulong)( now-sent.ts ) );
  ctx->metrics->fec_root_ok++;

  if( FD_UNLIKELY( sent.slot<=ctx->rotor->root ) ) return; /* rooted while in flight */
  fd_rotor_fec_notarized( ctx->rotor, sent.slot, &sent.dmr, sent.fec_idx*FD_FEC_SHRED_CNT, &fec_mr, now );
}

static void
handle_net( fd_rotor_tile_t *   ctx,
            fd_stem_context_t * stem,
            ulong               sz ) {
  uchar *        data;
  ulong          data_sz;
  fd_ip4_hdr_t * ip4;
  fd_udp_hdr_t * udp;
  if( FD_UNLIKELY( !fd_ip4_udp_hdr_strip( ctx->net_buf, sz, &data, &data_sz, NULL, &ip4, &udp ) ) ) return;
  if( FD_UNLIKELY( data_sz<sizeof(uint)                                                          ) ) return;

  long now = fd_clock_tile_now( ctx->clock );
  if( FD_UNLIKELY( data_sz==FD_ROTOR_PING_DE_SZ ) ) { /* no response has a ping's size */
    handle_ping( ctx, stem, data, data_sz, ip4, udp, now );
    return;
  }
  switch( FD_LOAD( uint, data ) ) {
  case FD_ROTOR_SERDE_TAG_PARENT_FEC_SET_COUNT_RES: handle_parent_and_fec_set_count_res( ctx, data, data_sz, ip4, udp, now ); break;
  case FD_ROTOR_SERDE_TAG_FEC_SET_ROOT_RES:         handle_fec_set_root_res            ( ctx, data, data_sz, ip4, udp, now ); break;
  default: break;
  }
}

/* handle_sign sends the message that was waiting for this signature. */

static void
handle_sign( fd_rotor_tile_t *   ctx,
             fd_stem_context_t * stem,
             ulong               in_idx,
             ulong               sig ) {
  ctx->sign[ ctx->in[ in_idx ].sign_idx ].free++;
  sign_t * pending = sign_pool_ele( ctx->sign_pool, sig>>32 );
  memcpy( pending->buf+pending->sig_off, ctx->sign_buf, FD_ED25519_SIG_SZ );

  uchar *             packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
  fd_ip4_udp_hdrs_t * hdr    = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *ctx->net_hdr;
  hdr->ip4->saddr       = pending->saddr;
  hdr->ip4->daddr       = pending->daddr;
  hdr->ip4->net_id      = fd_ushort_bswap( ctx->net_id++ );
  hdr->ip4->net_tot_len = fd_ushort_bswap( (ushort)( pending->sz+sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) ) );
  hdr->ip4->check       = fd_ip4_hdr_check_fast( hdr->ip4 );
  hdr->udp->net_dport   = pending->dport;
  hdr->udp->net_len     = fd_ushort_bswap( (ushort)( pending->sz+sizeof(fd_udp_hdr_t) ) );
  memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), pending->buf, pending->sz );

  ulong sz = pending->sz+sizeof(fd_ip4_udp_hdrs_t);
  ulong ts = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->net_out_idx, fd_disco_netmux_sig( pending->daddr, pending->dport, pending->daddr, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) ), ctx->net_out_chunk, sz, 0UL, ts, ts );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, sz, ctx->net_out_chunk0, ctx->net_out_wmark );
  sign_pool_ele_release( ctx->sign_pool, pending );
  ctx->metrics->pkt_tx++;
}

static inline void
metrics_write( fd_rotor_tile_t * ctx ) {
  ulong queued  = fd_rotor_treap_ele_cnt( ctx->rotor->eager_treap ) + fd_rotor_treap_ele_cnt( ctx->rotor->notar_treap ) + fd_rotor_treap_ele_cnt( ctx->rotor->final_treap );
  ulong waiting = timeout_prq_cnt( ctx->eager_prq ) + timeout_prq_cnt  ( ctx->notar_prq ) + timeout_prq_cnt( ctx->final_prq );

  FD_MCNT_SET( ROTOR, PKT_TX,                               ctx->metrics->pkt_tx                                                     );
  FD_MCNT_SET( ROTOR, REQUEST_TX_WINDOW_INDEX,              ctx->metrics->request_tx[ FD_ROTOR_SERDE_TAG_WINDOW_INDEX ]              );
  FD_MCNT_SET( ROTOR, REQUEST_TX_HIGHEST_WINDOW_INDEX,      ctx->metrics->request_tx[ FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX ]      );
  FD_MCNT_SET( ROTOR, REQUEST_TX_ORPHAN,                    ctx->metrics->request_tx[ FD_ROTOR_SERDE_TAG_ORPHAN ]                    );
  FD_MCNT_SET( ROTOR, REQUEST_TX_PARENT_AND_FEC_SET_COUNT,  ctx->metrics->request_tx[ FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT ]  );
  FD_MCNT_SET( ROTOR, REQUEST_TX_FEC_SET_ROOT,              ctx->metrics->request_tx[ FD_ROTOR_SERDE_TAG_FEC_SET_ROOT ]              );
  FD_MCNT_SET( ROTOR, REQUEST_TX_WINDOW_INDEX_FOR_BLOCK_ID, ctx->metrics->request_tx[ FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID ] );
  FD_MCNT_SET( ROTOR, REQUEST_TX_PONG,                      ctx->metrics->request_tx[ FD_ROTOR_SERDE_TAG_PONG ]                      );
  FD_MCNT_SET( ROTOR, PING_TX,                              ctx->metrics->ping_tx                                                    );

  FD_MGAUGE_SET( ROTOR, SLOT_HIGHEST_DELIVERED, ctx->metrics->slot_highest_repaired                );
  FD_MGAUGE_SET( ROTOR, SLOT_HIGHEST_RECEIVED,  ctx->metrics->slot_current                         );
  FD_MGAUGE_SET( ROTOR, SLOT_TURBINE_FIRST,     ctx->turbine_slot0                                 );
  FD_MGAUGE_SET( ROTOR, BLK_TREAP_CNT,          queued                                             );
  FD_MGAUGE_SET( ROTOR, PENDING_CNT,            pending_pool_used( ctx->pending_pool )             );
  FD_MGAUGE_SET( ROTOR, TIMEOUT_CNT,            waiting                                            );
  FD_MGAUGE_SET( ROTOR, EAGER_DELAY_NANOS,      (ulong)fd_rotor_strat_eager_ns( ctx->strat, NULL ) );
  FD_MGAUGE_SET( ROTOR, SIGN_CNT,               sign_pool_used( ctx->sign_pool )                   );

  FD_MCNT_SET( ROTOR, FEC_DELIVERED,     ctx->metrics->fec_delivered );
  FD_MCNT_SET( ROTOR, TIMEOUT_CANCELLED, ctx->metrics->req_cancelled );
  FD_MCNT_SET( ROTOR, TIMEOUT_NO_PEER,   ctx->metrics->req_no_peer   );
  FD_MCNT_SET( ROTOR, REQUEST_HEDGED,    ctx->metrics->req_hedged    );
  FD_MCNT_SET( ROTOR, REQUEST_EXPIRED,   ctx->metrics->req_expired   );

  FD_MCNT_SET( ROTOR, SHRED_OLD,           ctx->metrics->shred_old           );
  FD_MCNT_SET( ROTOR, SHRED_RX,            ctx->metrics->shred_rx            );
  FD_MCNT_SET( ROTOR, SHRED_RX_FOR_BLOCK_ID,   ctx->metrics->shred_rx_block_id   );
  FD_MCNT_SET( ROTOR, SHRED_RX_POSITIONAL, ctx->metrics->shred_rx_positional );
  FD_MCNT_SET( ROTOR, SHRED_RX_UNMATCHED,  ctx->metrics->shred_rx_unmatched  );

  FD_MCNT_SET( ROTOR, META_RX,                 ctx->metrics->meta_rx                 );
  FD_MCNT_SET( ROTOR, META_MALFORMED,          ctx->metrics->meta_malformed          );
  FD_MCNT_SET( ROTOR, META_UNSOLICITED,        ctx->metrics->meta_unsolicited        );
  FD_MCNT_SET( ROTOR, PARENT_AND_FEC_SET_COUNT_OK,     ctx->metrics->parent_fec_count_ok     );
  FD_MCNT_SET( ROTOR, PARENT_AND_FEC_SET_COUNT_FAILED, ctx->metrics->parent_fec_count_failed );
  FD_MCNT_SET( ROTOR, FEC_SET_ROOT_OK,             ctx->metrics->fec_root_ok             );
  FD_MCNT_SET( ROTOR, FEC_SET_ROOT_FAILED,         ctx->metrics->fec_root_failed         );

  FD_MCNT_SET( ROTOR, REPLAY_ROOT_ADVANCED, ctx->metrics->replay_root_advanced );
  FD_MCNT_SET( ROTOR, REPLAY_MISSING_FEC,   ctx->metrics->replay_missing_fec   );

  FD_MCNT_SET( ROTOR, PING_MALFORMED,        ctx->metrics->ping_malformed        );
  FD_MCNT_SET( ROTOR, PING_UNKNOWN_PEER,     ctx->metrics->ping_unknown_peer     );
  FD_MCNT_SET( ROTOR, PING_SIGNATURE_FAILED, ctx->metrics->ping_signature_failed );

  FD_MHIST_COPY( ROTOR, RESPONSE_LATENCY_NANOS, ctx->metrics->response_latency );
  FD_MHIST_COPY( ROTOR, RETRY_DELAY_NANOS,      ctx->metrics->retry_delay      );
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong sign_max    = tile->rotor.repair_sign_depth*tile->rotor.repair_sign_cnt;
  ulong timeout_max = tile->rotor.slot_max*(FEC_SET_P90+1UL); /* one blk of the role per slot, each a FEC set req for its p90 FEC sets and a HIGHEST_WINDOW_INDEX or PARENT_AND_FEC_SET_COUNT, a full prq rewinds its blk */
  ulong pending_max = tile->rotor.repair_sign_cnt*(ulong)( PENDING_TTL/SIGN_NS ); /* what the sign tiles can sign within PENDING_TTL, each pending is at least one */
  ulong chain_cnt   = pending_map_chain_cnt_est( pending_max );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_rotor_tile_t),           sizeof(fd_rotor_tile_t)                         );
  l = FD_LAYOUT_APPEND( l, fd_rotor_align(),                   fd_rotor_footprint( tile->rotor.slot_max, tile->rotor.fec_max ) );
  l = FD_LAYOUT_APPEND( l, fd_rotor_strat_align(),             fd_rotor_strat_footprint()                      );
  l = FD_LAYOUT_APPEND( l, fd_multi_epoch_leaders_align(),     fd_multi_epoch_leaders_footprint()              );
  l = FD_LAYOUT_APPEND( l, ping_deque_align(),                 ping_deque_footprint( FD_ROTOR_STRAT_PEER_MAX ) );
  l = FD_LAYOUT_APPEND( l, timeout_prq_align(),                timeout_prq_footprint( timeout_max )            );
  l = FD_LAYOUT_APPEND( l, timeout_prq_align(),                timeout_prq_footprint( timeout_max )            );
  l = FD_LAYOUT_APPEND( l, timeout_prq_align(),                timeout_prq_footprint( timeout_max )            );
  l = FD_LAYOUT_APPEND( l, pending_pool_align(),               pending_pool_footprint( pending_max )           );
  l = FD_LAYOUT_APPEND( l, pending_map_align(),                pending_map_footprint( chain_cnt )              );
  l = FD_LAYOUT_APPEND( l, pending_dlist_align(),              pending_dlist_footprint()                       );
  l = FD_LAYOUT_APPEND( l, sign_pool_align(),                  sign_pool_footprint( sign_max )                 );
  l = FD_LAYOUT_APPEND( l, alignof(fd_event_block_received_t), sizeof(fd_event_block_received_t)               );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
after_credit( fd_rotor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {

  /* Send one reassembled FEC to replay, then repair, which publishes
     only on unreliable links. */

  if( FD_LIKELY( !fd_rotor_deque_empty( ctx->rotor->reasm_deque ) ) ) {
    *opt_poll_in = 0;

    fd_rotor_deque_t        out = fd_rotor_deque_pop_head( ctx->rotor->reasm_deque );
    fd_rotor_blk_t const *  blk = fd_rotor_blk_pool_ele_const( ctx->rotor->blk_pool, out.blk_idx );
    fd_rotor_fec_t const *  fec = fd_rotor_fec_pool_ele_const( ctx->rotor->fec_pool, blk->fecs[ out.fec_idx ] );
    fd_rotor_replay_fec_t * msg = fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk );
    fd_memset( msg, 0, sizeof(fd_rotor_replay_fec_t) );
    msg->slot            = blk->slot;
    msg->fec_set_idx     = out.fec_idx*FD_FEC_SHRED_CNT;
    msg->mr              = fec->mr32;
    msg->parent_slot     = blk->parent_slot;
    msg->parent_block_id = blk->parent_blk_mr;
    msg->slot_complete   = out.fec_idx+1U==blk->cmpl_fec_cnt;
    msg->data_complete   = fec->data_complete;
    msg->is_leader       = fec->is_leader;
    msg->known_id        = fd_rotor_slot_meta( ctx->rotor, blk->slot )->eager!=out.blk_idx;
    msg->block_id        = blk->dmr;
    fd_stem_publish( stem, ctx->replay_out_idx, ROTOR_SIG_FEC_REPLAY, ctx->replay_out_chunk, sizeof(fd_rotor_replay_fec_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out_chunk = fd_dcache_compact_next( ctx->replay_out_chunk, sizeof(fd_rotor_replay_fec_t), ctx->replay_out_chunk0, ctx->replay_out_wmark );
    ctx->metrics->fec_delivered++;
    ctx->metrics->slot_highest_repaired = fd_ulong_if( msg->slot_complete, fd_ulong_max( ctx->metrics->slot_highest_repaired, blk->slot ), ctx->metrics->slot_highest_repaired );

    if( FD_UNLIKELY( msg->slot_complete && ctx->rserve_out_idx!=ULONG_MAX ) ) {
      fd_rotor_block_t * block = fd_chunk_to_laddr( ctx->rserve_out_mem, ctx->rserve_out_chunk );
      block->slot            = blk->slot;
      block->block_id        = blk->dmr;
      block->parent_slot     = blk->parent_slot;
      block->parent_block_id = blk->parent_blk_mr;
      block->fec_set_cnt     = blk->cmpl_fec_cnt;
      for( uint k=0U; k<blk->cmpl_fec_cnt; k++ ) memcpy( block->merkle_roots[ k ], fd_rotor_fec_pool_ele_const( ctx->rotor->fec_pool, blk->fecs[ k ] )->key.uc, FD_SHRED_MERKLE_NODE_SZ );
      ulong sz = FD_ROTOR_BLOCK_SZ( blk->cmpl_fec_cnt );
      fd_stem_publish( stem, ctx->rserve_out_idx, ROTOR_SIG_BLOCK, ctx->rserve_out_chunk, sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
      ctx->rserve_out_chunk = fd_dcache_compact_next( ctx->rserve_out_chunk, sz, ctx->rserve_out_chunk0, ctx->rserve_out_wmark );
    }
    *charge_busy = 1;
  }

  /* Then expire unanswered requests, discover as many blks off the
     blk_treaps as there are free sign slots (a blk yields at least one
     req, a req at least one sign request), and send pings and due
     reqs while sign slots and pending_pool entries last.  A req is one
     peer pick. */

  long now = fd_clock_tile_now( ctx->clock );

  while( !pending_dlist_is_empty( ctx->pending_dlist, ctx->pending_pool ) ) {
    pending_t * pending = pending_dlist_ele_peek_head( ctx->pending_dlist, ctx->pending_pool );
    if( FD_LIKELY( now-pending->ts<PENDING_TTL ) ) break;
    fd_rotor_strat_request_done( ctx->strat, &pending->peer, PENDING_TTL );
    ctx->metrics->req_expired++;
    pending_dlist_ele_pop_head ( ctx->pending_dlist, ctx->pending_pool );
    pending_map_ele_remove_fast( ctx->pending_map,   pending, ctx->pending_pool );
    pending_pool_ele_release   ( ctx->pending_pool,  pending );
  }

  for( ulong d=sign_pool_free( ctx->sign_pool ); d; d-- ) {
    fd_rotor_t *       rotor = ctx->rotor;
    fd_rotor_treap_t * treap = fd_rotor_treap_ele_cnt( rotor->final_treap ) ? rotor->final_treap :
                               fd_rotor_treap_ele_cnt( rotor->notar_treap ) ? rotor->notar_treap :
                               fd_rotor_treap_ele_cnt( rotor->eager_treap ) ? rotor->eager_treap :
                                                                              NULL;
    if( FD_UNLIKELY( !treap ) ) break;
    fd_rotor_blk_t * blk = fd_rotor_treap_fwd_iter_ele( fd_rotor_treap_fwd_iter_init( treap, rotor->blk_pool ), rotor->blk_pool );
    fd_rotor_treap_ele_remove( treap, blk, rotor->blk_pool );
    blk->in_blk_treap = 0;
    discover( ctx, blk, now );
  }
  if( FD_UNLIKELY( ctx->halt_signing ) ) return;

  /* A ping is any signed request: the peer pings before it answers.  No
     one has slot 0 under the null block id, so no one answers it. */

  ulong sent = 0UL;
  ulong ts   = (ulong)now/1000000UL;
  while(    sent<PING_MAX
         && !ping_deque_empty( ctx->ping_deque )
         && sign_pool_free( ctx->sign_pool )>SIGN_RESERVE ) {
    fd_pubkey_t             id_key = ping_deque_pop_head( ctx->ping_deque );
    fd_rotor_strat_peer_t * peer   = fd_rotor_strat_query( ctx->strat, &id_key );
    sent++;
    if( FD_UNLIKELY( !peer || !peer->ip4 || peer->ping_ts ) ) continue; /* gone, or sent to since */
    peer->ping_ts = now;

    sign_t * pending = sign_pool_ele_acquire( ctx->sign_pool );
    *pending    = (sign_t){ .sig_off = sizeof(uint), .daddr = peer->ip4, .dport = fd_ushort_bswap( peer->port ) };
    pending->sz = fd_rotor_req_parent_and_fec_set_count_ser( &(fd_rotor_parent_fec_set_count_t){ .slot = 0UL }, sig_null, &ctx->identity_key, &id_key, ts, fd_rng_uint( ctx->rng ), pending->buf );

    ulong s = 0UL;
    for( ulong i=1UL; i<ctx->sign_cnt; i++ ) s = fd_ulong_if( ctx->sign[ i ].free>ctx->sign[ s ].free, i, s );
    ulong sz = fd_rotor_req_sig_ser( pending->buf, pending->sz, fd_chunk_to_laddr( ctx->sign[ s ].mem, ctx->sign[ s ].chunk ) );
    fd_stem_publish( stem, ctx->sign[ s ].idx, (sign_pool_idx( ctx->sign_pool, pending )<<32)|(ulong)FD_KEYGUARD_SIGN_TYPE_ED25519, ctx->sign[ s ].chunk, sz, 0UL, 0UL, 0UL );
    ctx->sign[ s ].chunk = fd_dcache_compact_next( ctx->sign[ s ].chunk, sz, ctx->sign[ s ].chunk0, ctx->sign[ s ].wmark );
    ctx->sign[ s ].free--;
    ctx->metrics->ping_tx++;
    *charge_busy = 1;
  }

  while( sign_pool_free( ctx->sign_pool )>=SIGN_RESERVE+FD_FEC_SHRED_CNT ) {
    timeout_t        req;
    fd_rotor_blk_t * blk = poll_timeout( ctx, now, &req );
    if( FD_UNLIKELY( !blk ) ) break;

    fd_rotor_fec_t const * fec   = fd_rotor_fec_pool_ele_const( ctx->rotor->fec_pool, fd_ulong_if( req.tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX, blk->fecs[ req.fec_idx ], fd_rotor_fec_pool_idx_null( ctx->rotor->fec_pool ) ) );
    int                    eager = blk->eager;
    uint                   tag   = req.tag!=FD_ROTOR_SERDE_TAG_WINDOW_INDEX ? req.tag                                      : /* a FEC set req becomes what its blk still lacks */
                                   eager                                    ? FD_ROTOR_SERDE_TAG_WINDOW_INDEX              :
                                   !fec                                     ? FD_ROTOR_SERDE_TAG_FEC_SET_ROOT              :
                                                                              FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID;
    int                    meta  = tag==FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT || tag==FD_ROTOR_SERDE_TAG_FEC_SET_ROOT;
    uint                   mask  = fd_uint_if( tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX || tag==FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID, fec ? ~fec->rcvd : UINT_MAX, 1U ); /* bit i is a message for shred i of the FEC set */
    if( FD_UNLIKELY( !mask ) ) { /* every shred arrived, the FEC set completes without repair */
      req.timeout = now+fd_rotor_strat_eager_ns( ctx->strat, fd_multi_epoch_leaders_get_leader_for_slot( ctx->mleaders, blk->slot ) );
      push_timeout( ctx, blk, &req );
      continue;
    }

    fd_rotor_strat_peer_t * peer = fd_rotor_strat_pick( ctx->strat, now, !blk->eager && req.attempt );
    if( FD_UNLIKELY( !peer ) ) {
      ctx->metrics->req_no_peer++;
      req.timeout = now+NO_PEER;
      push_timeout( ctx, blk, &req );
      break;
    }
    peer->ping_ts = now;

    uint nonce = fd_rng_uint( ctx->rng );
    while( meta && pending_map_ele_query_const( ctx->pending_map, &(ulong){ nonce }, NULL, ctx->pending_pool ) ) nonce = fd_rng_uint( ctx->rng );

    if( FD_UNLIKELY( !pending_pool_free( ctx->pending_pool ) ) ) { /* evict the oldest, a reply to it no longer matches */
      pending_t * oldest = pending_dlist_ele_pop_head( ctx->pending_dlist, ctx->pending_pool );
      fd_rotor_strat_request_done( ctx->strat, &oldest->peer, PENDING_TTL ); /* ends the pick, as a timeout */
      pending_map_ele_remove_fast( ctx->pending_map, oldest, ctx->pending_pool );
      pending_pool_ele_release   ( ctx->pending_pool, oldest );
    }
    pending_t * pending = pending_pool_ele_acquire( ctx->pending_pool );
    pending->key         = fd_ulong_if( meta, (ulong)nonce, (ulong)(uint)blk->slot<<32 | fd_uint_if( req.tag==FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX || req.tag==FD_ROTOR_SERDE_TAG_ORPHAN, (uint)FD_FEC_BLK_MAX, req.fec_idx ) ); /* an ORPHAN's first reply is of the slot itself, matched like a HIGHEST */
    pending->ts          = now;
    pending->slot        = blk->slot;
    pending->blk         = req.blk;
    pending->dmr         = blk->dmr;
    pending->peer        = peer->id_key;
    pending->fec_idx     = req.fec_idx;
    pending->fec_set_cnt = blk->cmpl_fec_cnt;
    pending->tag         = tag;
    pending_map_ele_insert     ( ctx->pending_map,   pending, ctx->pending_pool );
    pending_dlist_ele_push_tail( ctx->pending_dlist, pending, ctx->pending_pool );

    for( uint m=mask; m; m=fd_uint_pop_lsb( m ) ) {
      uint             idx          = req.fec_idx*FD_FEC_SHRED_CNT+(uint)fd_uint_find_lsb( m );
      uint             rnonce       = fd_uint_if( meta, nonce, fd_rnonce_ss_compute( ctx->rnonce_ss, tag!=FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX && tag!=FD_ROTOR_SERDE_TAG_ORPHAN, blk->slot, idx, now ) );
      sign_t *         sign         = sign_pool_ele_acquire( ctx->sign_pool );
      *sign = (sign_t){ .sig_off = sizeof(uint), .daddr = peer->ip4, .dport = fd_ushort_bswap( peer->port ) };
      switch( tag ) {
      case FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT:  sign->sz = fd_rotor_req_parent_and_fec_set_count_ser ( &(fd_rotor_parent_fec_set_count_t){ .slot = blk->slot, .block_id = blk->dmr                     }, sig_null, &ctx->identity_key, &peer->id_key, ts, rnonce, sign->buf ); break;
      case FD_ROTOR_SERDE_TAG_FEC_SET_ROOT:              sign->sz = fd_rotor_req_fec_set_root_ser             ( &(fd_rotor_fec_set_root_t){ .slot = blk->slot, .block_id = blk->dmr, .fec_set_idx = idx }, sig_null, &ctx->identity_key, &peer->id_key, ts, rnonce, sign->buf ); break;
      case FD_ROTOR_SERDE_TAG_ORPHAN:                    sign->sz = fd_rotor_req_orphan_ser                   ( &(fd_rotor_orphan_t){ .slot = blk->slot                                               }, sig_null, &ctx->identity_key, &peer->id_key, ts, rnonce, sign->buf ); break;
      case FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX:      sign->sz = fd_rotor_req_highest_window_index_ser     ( &(fd_rotor_highest_shred_t){ .slot = blk->slot, .shred_idx = blk->rcvd_fec_cnt*FD_FEC_SHRED_CNT }, sig_null, &ctx->identity_key, &peer->id_key, ts, rnonce, sign->buf ); break;
      case FD_ROTOR_SERDE_TAG_WINDOW_INDEX:              sign->sz = fd_rotor_req_window_index_ser             ( &(fd_rotor_shred_t){ .slot = blk->slot, .shred_idx = idx                                 }, sig_null, &ctx->identity_key, &peer->id_key, ts, rnonce, sign->buf ); break;
      case FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID: sign->sz = fd_rotor_req_window_index_for_block_id_ser( &(fd_rotor_shred_for_block_id_t){ .slot = blk->slot, .shred_idx = idx, .block_id = blk->dmr }, sig_null, &ctx->identity_key, &peer->id_key, ts, rnonce, sign->buf ); break;
      }

      ulong s = 0UL;
      for( ulong i=1UL; i<ctx->sign_cnt; i++ ) s = fd_ulong_if( ctx->sign[ i ].free>ctx->sign[ s ].free, i, s );
      ulong sz = fd_rotor_req_sig_ser( sign->buf, sign->sz, fd_chunk_to_laddr( ctx->sign[ s ].mem, ctx->sign[ s ].chunk ) );
      fd_stem_publish( stem, ctx->sign[ s ].idx, (sign_pool_idx( ctx->sign_pool, sign )<<32)|(ulong)FD_KEYGUARD_SIGN_TYPE_ED25519, ctx->sign[ s ].chunk, sz, 0UL, 0UL, 0UL );
      ctx->sign[ s ].chunk = fd_dcache_compact_next( ctx->sign[ s ].chunk, sz, ctx->sign[ s ].chunk0, ctx->sign[ s ].wmark );
      ctx->sign[ s ].free--;
    }
    ctx->metrics->request_tx[ tag ] += (ulong)fd_uint_popcnt( mask );
    ctx->metrics->req_hedged        += (ulong)!!req.attempt;

    blk->telemetry.first_req_ts      = fd_long_if( !blk->telemetry.first_req_ts, now, blk->telemetry.first_req_ts );
    uint * req_cnt = NULL;
    switch( tag ) {
    case FD_ROTOR_SERDE_TAG_WINDOW_INDEX:              req_cnt = &blk->telemetry.req_window_cnt;    break;
    case FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX:      req_cnt = &blk->telemetry.req_highest_cnt;   break;
    case FD_ROTOR_SERDE_TAG_ORPHAN:                    req_cnt = &blk->telemetry.req_orphan_cnt;    break;
    case FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID: req_cnt = &blk->telemetry.req_shred_bid_cnt; break;
    case FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT:  req_cnt = &blk->telemetry.req_parent_cnt;    break;
    case FD_ROTOR_SERDE_TAG_FEC_SET_ROOT:              req_cnt = &blk->telemetry.req_fec_root_cnt;  break;
    }
    if( FD_LIKELY( req_cnt ) ) *req_cnt += (uint)fd_uint_popcnt( mask );

    req.timeout = now+( fd_long_max( fd_rotor_strat_hedge_ns( peer ), 1L<<24 )<<fd_uint_min( req.attempt, 3U ) ); /* a re-pick gets a new shred nonce */
    req.attempt = (uchar)fd_uint_min( req.attempt+1U, UCHAR_MAX );
    fd_histf_sample( ctx->metrics->retry_delay, (ulong)( req.timeout-now ) );
    push_timeout( ctx, blk, &req );
    *charge_busy = 1;
  }
}

static int
before_frag( fd_rotor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig ) {
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_GENESIS:
    return 0;
  case IN_KIND_SHRED:
    if( FD_UNLIKELY( ctx->rotor->root==ULONG_MAX ) ) return -1; /* hold until the snapshot or genesis gives the root */
    return 0;
  case IN_KIND_SNAP: {
    ulong msg = fd_ssmsg_sig_message( sig );
    return msg!=FD_SSMSG_MANIFEST_FULL && msg!=FD_SSMSG_MANIFEST_INCREMENTAL && msg!=FD_SSMSG_DONE;
  }
  case IN_KIND_VOTOR:
    if( FD_UNLIKELY( ctx->rotor->root==ULONG_MAX ) ) return -1; /* hold until the snapshot or genesis gives the root */
    return sig!=FD_VOTOR_SIG_CERTED && sig!=FD_VOTOR_SIG_REPAIR && sig!=FD_VOTOR_SIG_QUORUM;
  case IN_KIND_REPLAY:
    return sig!=REPLAY_SIG_ROOT_ADVANCED && sig!=REPLAY_SIG_SLOT_DEAD && sig!=REPLAY_SIG_MISSING_FEC;
  case IN_KIND_EPOCH:
    return 0;
  case IN_KIND_GOSSIP:
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO && sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  case IN_KIND_NET:
    return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR;
  case IN_KIND_SIGN:
    return 0;
  default:
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
during_frag( fd_rotor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig FD_PARAM_UNUSED,
             ulong             chunk,
             ulong             sz,
             ulong             ctl ) {
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_NET:
    memcpy( ctx->net_buf, fd_net_rx_translate_frag( &ctx->in[ in_idx ].net_rx, chunk, ctl, sz ), sz );
    break;
  case IN_KIND_SIGN:
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) {
      FD_LOG_ERR(( "chunk %lu sz %lu from in_kind %d out of bounds, chunk0 %lu wmark %lu",
                   chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    }
    memcpy( ctx->sign_buf, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), FD_ED25519_SIG_SZ );
    break;
  default: /* reliable, read in place by after_frag */
    if( FD_UNLIKELY( sz!=0UL && ( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) ) { /* a snapshot DONE has no payload */
      FD_LOG_ERR(( "chunk %lu sz %lu from in_kind %d out of bounds, chunk0 %lu wmark %lu",
                   chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
    }
    ctx->chunk = chunk;
    break;
  }
}

static void
after_frag( fd_rotor_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq    FD_PARAM_UNUSED,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub  FD_PARAM_UNUSED,
            fd_stem_context_t * stem ) {
  uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, ctx->chunk );

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_NET:
    handle_net( ctx, stem, sz );
    break;
  case IN_KIND_SIGN:
    handle_sign( ctx, stem, in_idx, sig );
    break;
  case IN_KIND_GENESIS: {
    fd_genesis_meta_t const * meta = (fd_genesis_meta_t const *)fd_type_pun_const( src );
    if( FD_UNLIKELY( !meta->bootstrap ) ) break; /* booting from a snapshot */
    fd_rotor_init( ctx->rotor, 0UL, &hash_null, report_block_received, ctx );
    break;
  }
  case IN_KIND_SHRED: { /* tsorig is the shred tile's network rx of the shred, the completing one for a FEC set */
    long now_tick = fd_tickcount();
    long rx_tick  = fd_frag_meta_ts_decomp( tsorig, now_tick );
    if( FD_UNLIKELY( rx_tick>now_tick ) ) rx_tick -= 1L<<32;
    handle_shred( ctx, sig, src, fd_clock_tile_tickcount_to_wallclock( ctx->clock, rx_tick ) );
    break;
  }
  case IN_KIND_SNAP:
    handle_snapshot( ctx, sig, src );
    break;
  case IN_KIND_VOTOR:
    handle_votor( ctx, sig, src );
    break;
  case IN_KIND_REPLAY:
    handle_replay( ctx, sig, src );
    break;
  case IN_KIND_EPOCH: {
    fd_epoch_info_msg_t const * msg = (fd_epoch_info_msg_t const *)fd_type_pun_const( src );
    fd_rotor_strat_epoch_advanced( ctx->strat, fd_epoch_info_msg_id_weights( msg ), msg->staked_id_cnt );
    fd_multi_epoch_leaders_epoch_msg_init( ctx->mleaders, msg );
    fd_multi_epoch_leaders_epoch_msg_fini( ctx->mleaders );
    break;
  }
  case IN_KIND_GOSSIP:
    handle_gossip( ctx, sig, (fd_gossip_update_message_t const *)fd_type_pun_const( src ) );
    break;
  default:
    FD_LOG_ERR(( "unexpected in_kind %d", ctx->in_kind[ in_idx ] ));
  }
}

/* next_deadline is when the tile next has work without a frag: the
   earliest timeout due, or the oldest pending expiring. */

static long
next_deadline( fd_rotor_tile_t * ctx ) {
  long due = LONG_MAX;
  due = fd_long_if( !!timeout_prq_cnt( ctx->eager_prq ), fd_long_min( due, ctx->eager_prq[ 0 ].timeout ), due );
  due = fd_long_if( !!timeout_prq_cnt( ctx->notar_prq ), fd_long_min( due, ctx->notar_prq[ 0 ].timeout ), due );
  due = fd_long_if( !!timeout_prq_cnt( ctx->final_prq ), fd_long_min( due, ctx->final_prq[ 0 ].timeout ), due );
  if( FD_LIKELY( !pending_dlist_is_empty( ctx->pending_dlist, ctx->pending_pool ) ) ) due = fd_long_min( due, pending_dlist_ele_peek_head( ctx->pending_dlist, ctx->pending_pool )->ts+PENDING_TTL );
  if( FD_UNLIKELY( due==LONG_MAX ) ) return LONG_MAX;
  return fd_clock_tile_wallclock_to_tickcount( ctx->clock, due );
}

static inline void
during_housekeeping( fd_rotor_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) fd_clock_tile_recal( ctx->clock );

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_CHECK_CRIT( ctx->halt_signing, "state machine corruption" );
    ctx->halt_signing = 0;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ctx->halt_signing = 1;
    memcpy( ctx->identity_key.uc, ctx->keyswitch->bytes, 32UL );
    if( FD_LIKELY( sign_pool_free( ctx->sign_pool )==sign_pool_max( ctx->sign_pool ) ) ) fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED ); /* every sign request returned */
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rotor_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rotor_tile_t), sizeof(fd_rotor_tile_t) );
  fd_memset( ctx, 0, sizeof(fd_rotor_tile_t) );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ulong) ) );

  uchar const * identity_key = fd_keyload_load( tile->rotor.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_key.uc, identity_key, sizeof(fd_pubkey_t) );

  ulong rnonce_ss_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "rnonce_ss" );
  FD_TEST( rnonce_ss_id!=ULONG_MAX );
  memcpy( ctx->rnonce_ss, fd_topo_obj_laddr( topo, rnonce_ss_id ), sizeof(fd_rnonce_ss_t) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch   = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong  sign_max    = tile->rotor.repair_sign_depth*tile->rotor.repair_sign_cnt;
  ulong  timeout_max = tile->rotor.slot_max*(FEC_SET_P90+1UL);
  ulong  pending_max = tile->rotor.repair_sign_cnt*(ulong)( PENDING_TTL/SIGN_NS );
  ulong  chain_cnt   = pending_map_chain_cnt_est( pending_max );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rotor_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rotor_tile_t),           sizeof(fd_rotor_tile_t)                         );
  ctx->rotor             = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_align(),                   fd_rotor_footprint( tile->rotor.slot_max, tile->rotor.fec_max ) );
  void * strat           = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_strat_align(),             fd_rotor_strat_footprint()                      );
  void * mleaders        = FD_SCRATCH_ALLOC_APPEND( l, fd_multi_epoch_leaders_align(),     fd_multi_epoch_leaders_footprint()              );
  void * ping_deque      = FD_SCRATCH_ALLOC_APPEND( l, ping_deque_align(),                 ping_deque_footprint( FD_ROTOR_STRAT_PEER_MAX ) );
  void * eager_prq       = FD_SCRATCH_ALLOC_APPEND( l, timeout_prq_align(),                timeout_prq_footprint( timeout_max )            );
  void * notar_prq       = FD_SCRATCH_ALLOC_APPEND( l, timeout_prq_align(),                timeout_prq_footprint( timeout_max )            );
  void * final_prq       = FD_SCRATCH_ALLOC_APPEND( l, timeout_prq_align(),                timeout_prq_footprint( timeout_max )            );
  void * pending_pool    = FD_SCRATCH_ALLOC_APPEND( l, pending_pool_align(),               pending_pool_footprint( pending_max )           );
  void * pending_map     = FD_SCRATCH_ALLOC_APPEND( l, pending_map_align(),                pending_map_footprint( chain_cnt )              );
  void * pending_dlist   = FD_SCRATCH_ALLOC_APPEND( l, pending_dlist_align(),              pending_dlist_footprint()                       );
  void * sign_pool       = FD_SCRATCH_ALLOC_APPEND( l, sign_pool_align(),                  sign_pool_footprint( sign_max )                 );
  ctx->event             = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_block_received_t), sizeof(fd_event_block_received_t)               );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->rotor = fd_rotor_join( fd_rotor_new( ctx->rotor, tile->rotor.slot_max, tile->rotor.fec_max, ctx->seed ) );
  FD_TEST( ctx->rotor );
  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders ) );
  FD_TEST( ctx->mleaders );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ctx->strat         = fd_rotor_strat_join( fd_rotor_strat_new( strat, ctx->seed ) );
  ctx->ping_deque    = ping_deque_join( ping_deque_new( ping_deque, FD_ROTOR_STRAT_PEER_MAX ) );
  ctx->eager_prq     = timeout_prq_join( timeout_prq_new( eager_prq, timeout_max ) );
  ctx->notar_prq     = timeout_prq_join( timeout_prq_new( notar_prq, timeout_max ) );
  ctx->final_prq     = timeout_prq_join( timeout_prq_new( final_prq, timeout_max ) );
  ctx->pending_pool  = pending_pool_join( pending_pool_new( pending_pool, pending_max ) );
  ctx->pending_map   = pending_map_join( pending_map_new( pending_map, chain_cnt, ctx->seed ) );
  ctx->pending_dlist = pending_dlist_join( pending_dlist_new( pending_dlist ) );
  ctx->sign_pool     = sign_pool_join( sign_pool_new( sign_pool, sign_max ) );
  FD_TEST( ctx->strat && ctx->ping_deque && ctx->eager_prq && ctx->notar_prq && ctx->final_prq && ctx->pending_pool && ctx->pending_map && ctx->pending_dlist && ctx->sign_pool );
  FD_TEST( fd_rng_join( fd_rng_new( ctx->rng, (uint)ctx->seed, ctx->seed>>32 ) ) );
  fd_clock_tile_init( ctx->clock );
  FD_TEST( fd_histf_join( fd_histf_new( ctx->metrics->response_latency, FD_MHIST_MIN( ROTOR, RESPONSE_LATENCY_NANOS ), FD_MHIST_MAX( ROTOR, RESPONSE_LATENCY_NANOS ) ) ) );
  FD_TEST( fd_histf_join( fd_histf_new( ctx->metrics->retry_delay,      FD_MHIST_MIN( ROTOR, RETRY_DELAY_NANOS      ), FD_MHIST_MAX( ROTOR, RETRY_DELAY_NANOS      ) ) ) );

  FD_TEST( tile->in_cnt<=sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];

    if     ( FD_LIKELY( !strcmp( link->name, "genesi_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESIS;
    else if( FD_LIKELY( !strcmp( link->name, "shred_out"     ) ) ) ctx->in_kind[ i ] = IN_KIND_SHRED;
    else if( FD_LIKELY( !strcmp( link->name, "snapin_manif"  ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAP;
    else if( FD_LIKELY( !strcmp( link->name, "votor_out"     ) ) ) ctx->in_kind[ i ] = IN_KIND_VOTOR;
    else if( FD_LIKELY( !strcmp( link->name, "net_repair"    ) ) ) ctx->in_kind[ i ] = IN_KIND_NET;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_ciaddr" ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_slot"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "replay_rotor"  ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "sign_repair"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else FD_LOG_ERR(( "rotor tile has unexpected input link %lu %s", i, link->name ));
    if( FD_UNLIKELY( ctx->in_kind[ i ]==IN_KIND_NET ) ) { /* net frags are bounded by fd_net_rx, not a dcache */
      fd_net_rx_bounds_init( &ctx->in[ i ].net_rx, link->dcache );
      continue;
    }

    ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;
  }

  ctx->replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "repair_out", 0UL );
  FD_TEST( ctx->replay_out_idx!=ULONG_MAX );
  fd_topo_link_t const * replay_out = &topo->links[ tile->out_link_id[ ctx->replay_out_idx ] ];
  ctx->replay_out_mem    = topo->workspaces[ topo->objs[ replay_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, replay_out->dcache );
  ctx->replay_out_wmark  = fd_dcache_compact_wmark ( ctx->replay_out_mem, replay_out->dcache, replay_out->mtu );
  ctx->replay_out_chunk  = ctx->replay_out_chunk0;

  /* sign tile s takes repair_sign s and answers on sign_repair s */

  ctx->sign_cnt = tile->rotor.repair_sign_cnt;
  FD_TEST( ctx->sign_cnt<=SIGN_MAX );
  for( ulong s=0UL; s<ctx->sign_cnt; s++ ) {
    ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "repair_sign", s );
    ulong in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_repair", s );
    FD_TEST( out_idx!=ULONG_MAX && in_idx!=ULONG_MAX );
    fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ out_idx ] ];
    FD_TEST( sign_out->mtu>=FD_ROTOR_SIG_SER_MAX );
    ctx->sign[ s ].idx         = out_idx;
    ctx->sign[ s ].mem         = topo->workspaces[ topo->objs[ sign_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->sign[ s ].chunk0      = fd_dcache_compact_chunk0( ctx->sign[ s ].mem, sign_out->dcache );
    ctx->sign[ s ].wmark       = fd_dcache_compact_wmark ( ctx->sign[ s ].mem, sign_out->dcache, sign_out->mtu );
    ctx->sign[ s ].chunk       = ctx->sign[ s ].chunk0;
    ctx->sign[ s ].free        = tile->rotor.repair_sign_depth;
    ctx->in[ in_idx ].sign_idx = s;
  }

  ctx->net_out_idx = fd_topo_find_tile_out_link( topo, tile, "repair_net", 0UL );
  FD_TEST( ctx->net_out_idx!=ULONG_MAX );
  fd_topo_link_t const * net_out = &topo->links[ tile->out_link_id[ ctx->net_out_idx ] ];
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out->dcache );
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;
  fd_ip4_udp_hdr_init( ctx->net_hdr, 0UL, 0U, tile->rotor.repair_client_listen_port );
  ctx->allow_private_address = tile->rotor.allow_private_address;

  ctx->rserve_out_idx = fd_topo_find_tile_out_link( topo, tile, "rotor_rserve", 0UL );
  if( FD_LIKELY( ctx->rserve_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * rserve_out = &topo->links[ tile->out_link_id[ ctx->rserve_out_idx ] ];
    ctx->rserve_out_mem    = topo->workspaces[ topo->objs[ rserve_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->rserve_out_chunk0 = fd_dcache_compact_chunk0( ctx->rserve_out_mem, rserve_out->dcache );
    ctx->rserve_out_wmark  = fd_dcache_compact_wmark ( ctx->rserve_out_mem, rserve_out->dcache, rserve_out->mtu );
    ctx->rserve_out_chunk  = ctx->rserve_out_chunk0;
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_rotor_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_rotor_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_rotor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_rotor_tile_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_NEXT_DEADLINE       next_deadline
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

static ulong
max_event_sz( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_event_block_received_t);
}

fd_topo_run_tile_t fd_tile_rotor = {
  .name                     = "rotor",
  .max_event_sz             = max_event_sz,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
