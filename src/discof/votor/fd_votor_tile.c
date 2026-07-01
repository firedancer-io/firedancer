#include "fd_votor_tile.h"
#include "generated/fd_votor_tile_seccomp.h"

#include "../../alpenglow/consensus/fd_votor.h"
#include "../../alpenglow/consensus/fd_pool.h"
#include "../../alpenglow/consensus/fd_epoch_info.h"
#include "../../alpenglow/consensus/fd_vote.h"
#include "../../alpenglow/consensus/fd_cert.h"
#include "../../alpenglow/consensus/pool/fd_slot_state.h"
#include "../../alpenglow/crypto/fd_aggsig.h"
#include "../../alpenglow/fd_alpenglow_base.h"
#include "../../ballet/bls/fd_bls12_381.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco_base.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/stakes/fd_stake_weight.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../waltz/quic/fd_quic.h"
#include "../../waltz/quic/fd_quic_private.h"

#include <errno.h>
#include <unistd.h>
#include <sys/random.h>

/* The Votor tile drives the Alpenglow consensus core.  It broadly processes
   four classes of frags:

   1. Replay slot completions (REPLAY link, REPLAY_SIG_SLOT_COMPLETED).  When
      Replay finishes executing a block, Votor registers the block (and its
      parent) with the pool (fd_pool_add_block) and drives the votor block
      availability handlers (FirstShred + Block).  Any votes the votor emits
      are fed back into the pool (fd_pool_add_vote) and queued for broadcast;
      any certs the pool creates are queued for broadcast.  Mirrors Tower's
      replay_slot_completed.

   2. Dead slots (REPLAY link, REPLAY_SIG_SLOT_DEAD).  A dead slot is an
      invalid block: drive the votor InvalidBlock path so the slot gets
      skipped.

   3. Alpenglow ConsensusMessages (GOSSIP link).  Votes and certs received
      from other validators.  Decoded into fd_ag_vote_t / fd_cert_t and fed into
      the pool via fd_pool_add_vote / fd_pool_add_cert.  (See the .h: FD
      gossip does not carry Alpenglow messages yet, so this is a staged
      ingest path with a fixed wire layout.)

   4. Auxiliary frags: epoch stakes (EPOCH link, used to rebuild the
      validator set / stakes the pool and votor run against) and shred
      version (IPECHO link).

   In all cases the votor / pool emit a stream of actions (votes/certs to
   broadcast, timeouts to schedule) plus, for the pool, repair requests and
   PoolEvents.  The tile drains those streams to a fixpoint, queueing
   FD_VOTOR_SIG_* frags onto the `publishes` deque, then drains the deque one
   frag per after_credit call (exactly like Tower). */

#define LOGGING 0

#define IN_KIND_REPLAY (0)
#define IN_KIND_GOSSIP (1)
#define IN_KIND_EPOCH  (2)
#define IN_KIND_IPECHO (3)
#define IN_KIND_VOTOR  (4)

#define OUT_IDX     0 /* votor_out: consensus output (votes/certs/slot_done/finalized) */
#define OUT_IDX_NET 1 /* votor_net: QUIC TX frames back to the net tile               */

/* QUIC TLS identity key sizes (ephemeral, like the TPU QUIC tile). */
#define ED25519_PRIV_KEY_SZ (32)
#define ED25519_PUB_KEY_SZ  (32)

/* One net_alpenglow input link per net tile. */
#define FD_VOTOR_NET_IN_MAX (32UL)

/* The votor_out link mtu is declared as a literal in topology.c (the
   topology cannot include this header due to an fd_vote type clash);
   keep it in sync. */
FD_STATIC_ASSERT( sizeof(fd_votor_msg_t)<=1024UL, votor_out_mtu );

/* The Alpenglow VAT caps the voting set of validators to 2000.  Only the top
   2000 voters by stake are counted towards consensus rules.  Module
   implementations may round capacities to pow2 for performance, but the
   consensus logic retains at most 2000 voters.

   https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0357-alpenglow_validator_admission_ticket.md */

#define VTR_MAX (2000UL) /* maximum # of unique voting validators */

/* Output-buffer capacities.  A single pool / votor handler invocation emits
   a bounded number of events / messages / timeouts; size generously.  These
   are scratch arrays consumed entirely within votor_slot_completed before the
   next handler call, so they need not be persisted across calls. */

#define EVENTS_MAX   (256UL)
#define REPAIRS_MAX  (256UL)
#define MSGS_MAX     (256UL)
#define TIMEOUTS_MAX (256UL)

/* FIXPOINT_MAX bounds the number of pool/votor drive iterations for a single
   slot completion to guard against a runaway loop. */

#define FIXPOINT_MAX (4096UL)

struct publish {
  ulong          sig;
  fd_votor_msg_t msg;
};
typedef struct publish publish_t;

#define DEQUE_NAME publishes
#define DEQUE_T    publish_t
#include "../../util/tmpl/fd_deque_dynamic.c"

struct in_ctx {
  int         mcache_only;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};
typedef struct in_ctx in_ctx_t;

/* VTR_EPOCH_WINDOW is how many epoch stakes / BLS rank maps votor
   retains concurrently. Certs only reference the current or an
   immediately-adjacent epoch. For some reason Agave maintains 5,
   technically 2 should be enough? */

#define VTR_EPOCH_WINDOW (4UL)

/* vtr_epoch_set_t is one set of epoch stakes. epoch==ULONG_MAX marks an
   empty entry in the epoch map */
struct vtr_epoch_set {
  ulong                     epoch;
  ulong                     validator_cnt;
  int                       have_own_id;  /* 0 if we are unstaked this epoch     */
  void *                    mem;          /* backing alloc for the epoch_info_t  */
  fd_validator_epoch_info_t info;         /* ValidatorEpochInfo: { own_id, epoch=joined
                                             info }; passed by ref to pool add_* calls */
};
typedef struct vtr_epoch_set vtr_epoch_set_t;

struct fd_votor_tile {
  ulong          seed; /* map seed */
  fd_pubkey_t    identity_key[1];
  fd_aggsig_sk_t voting_key[1]; /* our single BLS voting secret key */

  /* owned joins */

  fd_wksp_t *      wksp; /* workspace */
  fd_keyswitch_t * identity_keyswitch;

  fd_votor_t *      votor;      /* the voting state machine             */
  fd_pool_t *       pool;       /* the cert/vote integrator             */

  /* per-epoch validator-set map */
  vtr_epoch_set_t     vtr_epoch_stakes[ VTR_EPOCH_WINDOW ];
  fd_epoch_schedule_t epoch_schedule;  /* from EPOCH msgs; slot -> epoch        */
  int                 have_schedule;

  publish_t * publishes; /* deque of msgs queued for publishing */

  /* static structures.  These are scratch out-buffers drained within a
     single drive; they are members (not stack) only to avoid large stack
     frames in the stem callbacks. */

  fd_pool_evt_t          events  [ EVENTS_MAX   ];
  fd_block_id_t          repairs [ REPAIRS_MAX  ];
  fd_consensus_message_t msgs    [ MSGS_MAX     ];
  fd_votor_timeout_t     timeouts[ TIMEOUTS_MAX ];

  /* heap of timeouts. Every after_credit the min timeout is polled and if it is due, the corresponding event is emitted. */
  fd_timeout_t *      timeouts_pool;
  fd_timeout_heap_t * timeouts_heap;

  /* scratch for validator set staged from the most recent EPOCH msg */

  fd_validator_info_t validators[ VTR_MAX ];

  /* fixed pool / votor dimensions, set once in init_choreo and reused
     verbatim on every epoch rebuild so the re-formatted objects always fit
     the originally allocated scratch regions. */

  ulong slot_max;
  ulong validator_max;
  ulong blockid_max;

  ulong     root_slot;      /* last ROOTED slot published (finalized ∧ replayed) */
  fd_hash_t root_block_id;  /* block id of root_slot (pool's seeded root)        */
  ulong     finalized_slot; /* last FINALIZED slot published (cert-driven)        */
  ulong     reset_slot;     /* last reset target published                       */

  /* highest slot we have actually REPLAYED (its bank is frozen), and its block
     id.  Rooting is gated on this: a finalization cert may arrive ahead of
     replay, but we only root (and tell replay to root the bank) up to a slot we
     have both finalized and replayed -- mirroring Agave's finalized ∧ is_frozen
     gate. */
  ulong     highest_replayed_slot;
  fd_hash_t highest_replayed_block_id;

  /* metadata */

  int    halt_signing;
  ushort shred_version;
  int    init; /* 1 after the first slot completion / votor_new */
  ulong  fixpoint_depth; /* recursion-depth guard for the pool-event cascade */

  /* in/out link setup */

  int      in_kind[ 64UL ];
  in_ctx_t in     [ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
  ulong       out_seq;

  /* QUIC ingress (folded-in alpin tile): an fd_quic server with an
     ephemeral TLS identity that receives Alpenglow ConsensusMessages on
     the dedicated alpenglow port.  The tile-level frag callbacks
     (before/during/after_frag) drive the QUIC machinery; the
     quic_stream_rx callback hands each whole ConsensusMessage to the
     consensus helper votor_handle_consensus_msg.  NULL when the tile is
     run without QUIC config (e.g. the unit test). */

  fd_quic_t *        quic;
  fd_aio_t           quic_tx_aio[1];
  uchar              tls_priv_key[ ED25519_PRIV_KEY_SZ ];
  uchar              tls_pub_key [ ED25519_PUB_KEY_SZ  ];
  fd_sha512_t        quic_sha512[1];
  long               now;
  fd_stem_context_t * stem;
  uchar              net_buf[ FD_NET_MTU ];
  fd_net_rx_bounds_t net_in_bounds[ FD_VOTOR_NET_IN_MAX ];

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  /* metrics */

  struct {
    ulong not_ready;
    ulong replay_slot;
    ulong root_slot;
    ulong reset_slot;

    ulong votes_emitted;
    ulong certs_emitted;
    ulong votes_ingested;
    ulong certs_ingested;
    ulong slashable;
    ulong fixpoint_exceeded;
    ulong certs_dropped_no_epoch;
    ulong votes_dropped_no_epoch;
  } metrics;
};
typedef struct fd_votor_tile fd_votor_tile_t;

/* Compile-time dependency injection.  This macro defaults to the production
   implementation defined below.  Tests can #define it before #include-ing
   this file to substitute a mock for the epoch validator-set readback (which
   in production is derived from the EPOCH msg). */

#ifndef UPDATE_EPOCH_VTRS
#define UPDATE_EPOCH_VTRS update_epoch_vtrs
#endif

void UPDATE_EPOCH_VTRS( fd_votor_tile_t *, fd_epoch_info_msg_t const *, fd_vote_stake_weight_t const *, ulong );

/* fresh_votor_out / fresh_pool_out reset the scratch out-buffers so a handler
   can append into them.  The caller reads the *_cnt fields after the call. */

static inline fd_votor_out_t
fresh_votor_out( fd_votor_tile_t * ctx ) {
  fd_votor_out_t out = {
    .msgs        = ctx->msgs,
    .msg_cnt     = 0UL,
    .msg_max     = MSGS_MAX,
    .timeouts    = ctx->timeouts,
    .timeout_cnt = 0UL,
    .timeout_max = TIMEOUTS_MAX
  };
  return out;
}

static inline fd_pool_out_t
fresh_pool_out( fd_votor_tile_t * ctx ) {
  fd_pool_out_t out = {
    .events      = ctx->events,  .events_cnt  = 0UL, .events_max  = EVENTS_MAX,
    .repairs     = ctx->repairs, .repairs_cnt = 0UL, .repairs_max = REPAIRS_MAX
  };
  return out;
}

/* queue_vote / queue_cert push a vote / cert onto the publishes deque to be
   broadcast over the votor_out link. */

static inline void
queue_vote( fd_votor_tile_t * ctx, fd_ag_vote_t const * vote ) {
  publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
  pub->sig      = FD_VOTOR_SIG_VOTE;
  pub->msg.vote = *vote;
  ctx->metrics.votes_emitted++;
}

static inline void
queue_cert( fd_votor_tile_t * ctx, fd_cert_t const * cert ) {
  publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
  pub->sig      = FD_VOTOR_SIG_CERT;
  pub->msg.cert = *cert;
  ctx->metrics.certs_emitted++;
}

/* epoch_info_vtrs returns the validator set for `epoch`, or NULL if that
   epoch is not retained in the window. */
static fd_validator_epoch_info_t const *
epoch_info_vtrs( fd_votor_tile_t const * ctx, ulong epoch ) {
  vtr_epoch_set_t const * s = &ctx->vtr_epoch_stakes[ epoch % VTR_EPOCH_WINDOW ];
  return s->epoch==epoch ? &s->info : NULL;
}

/* ingest_vote feeds a vote into the pool, draining any resulting events.  Our
   own votes (emitted by votor) are fed back through here so they count
   towards our own certs. */

static int
ingest_vote( fd_votor_tile_t * ctx, fd_ag_vote_t const * vote, fd_validator_epoch_info_t const * ei );

static void
schedule_timeout( fd_votor_tile_t * ctx, ulong slot ) {
  long  now   = fd_log_wallclock();
  ulong first = fd_alpenglow_first_slot_in_window( slot );
  fd_timeout_t * timeout = fd_timeout_pool_ele_acquire( ctx->timeouts_pool );
  timeout->slot = slot;

  /* TODO, ignoring first shred timeout for now */
  timeout->ts   = now + FD_ALPENGLOW_DELTA_TIMEOUT_NS
                      + (long)( slot - first + 1UL ) * FD_ALPENGLOW_DELTA_BLOCK_NS;
  timeout->kind = FD_VOTOR_TIMEOUT_TIMEOUT;
  fd_timeout_heap_ele_insert( ctx->timeouts_heap, timeout, ctx->timeouts_pool );
}

/* drain_votor_out feeds everything the votor just emitted back into the
   system: votes are (a) fed into the pool via ingest_vote and (b) queued for
   broadcast; certs are queued for broadcast.  Timeouts are not persisted here
   — the tile attaches deadlines elsewhere; for now we simply (re)fire any
   emitted timeouts that are immediately due is handled by the caller.  We
   ignore scheduled timeouts beyond logging since the deadline machinery is
   future work (see TODO in after_credit). */

static void
drain_votor_out( fd_votor_tile_t *      ctx,
                 fd_votor_out_t const * out ) {
  for( ulong i=0UL; i<out->msg_cnt; i++ ) {
    fd_consensus_message_t const * m = &out->msgs[ i ];
    if( m->discriminant==FD_CONSENSUS_MESSAGE_VOTE ) {
      /* The votor leaves the signer unset on our own votes.  Resolve it
         now from the vote's slot epoch and stamp it before both
         broadcast and pool ingest. */
      fd_ag_vote_t vote  = m->inner.vote; /* mutable copy */
      ulong     epoch = fd_slot_to_epoch( &ctx->epoch_schedule, fd_vote_slot( &vote ), NULL );
      fd_validator_epoch_info_t const * ei = epoch_info_vtrs( ctx, epoch );
      if( FD_UNLIKELY( !ei ) ) FD_LOG_CRIT(( "own vote for epoch %lu but no validator epoch info", epoch ));
      fd_vote_set_signer( &vote, (ushort)ei->own_id );
      queue_vote ( ctx, &vote );
      ingest_vote( ctx, &vote, ei ); /* count our own vote */
    } else { /* FD_CONSENSUS_MESSAGE_CERT */
      queue_cert( ctx, &m->inner.cert );
    }
  }
  for( ulong i=0UL; i<out->timeout_cnt; i++ ) {
    fd_votor_timeout_t const * t = &out->timeouts[ i ];
    if( t->kind==FD_VOTOR_TIMEOUT_TIMEOUT ) {
      schedule_timeout( ctx, t->slot );
    } else if( t->kind==FD_VOTOR_TIMEOUT_CRASHED_LEADER ) {
      // TODO: ignore first shred timeouts for now
    }
  }
}

/* map_pool_evt_to_votor translates an fd_pool_evt_t (emitted by the pool)
   into the corresponding fd_votor_pool_event_t the votor consumes, returning
   1 if the event maps to a votor event and 0 otherwise (Standstill is handled
   separately). */

static int
map_pool_evt_to_votor( fd_pool_evt_t const *   evt,
                       fd_votor_pool_event_t * out ) {
  switch( evt->kind ) {
  case FD_POOL_EVT_PARENT_READY:
    out->discriminant              = FD_VOTOR_POOL_EVENT_PARENT_READY;
    out->inner.parent_ready.slot   = evt->inner.parent_ready.slot;
    out->inner.parent_ready.parent = evt->inner.parent_ready.parent;
    return 1;
  case FD_POOL_EVT_SAFE_TO_NOTAR:
    out->discriminant        = FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR;
    out->inner.safe_to_notar = evt->inner.block;
    return 1;
  case FD_POOL_EVT_SAFE_TO_SKIP:
    out->discriminant       = FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP;
    out->inner.safe_to_skip = evt->inner.slot;
    return 1;
  case FD_POOL_EVT_CERT_CREATED:
    out->discriminant       = FD_VOTOR_POOL_EVENT_CERT_CREATED;
    out->inner.cert_created = evt->inner.cert;
    return 1;
  case FD_POOL_EVT_STANDSTILL:
    /* Standstill recovery is driven separately (recover_from_standstill);
       we do not feed the bare event into votor here. */
    return 0;
  default:
    FD_LOG_ERR(( "unexpected pool event kind %d", evt->kind ));
    return 0;
  }
}

/* drive_pool_events drains a batch of pool events into the votor, feeding the
   votor's resulting actions back through drain_votor_out (which may itself
   feed votes back into the pool, producing more pool events).  Pool events
   produced by re-ingestion are accumulated into *pending so the caller's
   fixpoint loop picks them up.  Returns the number of votor events processed. */

static ulong
drive_pool_events( fd_votor_tile_t *     ctx,
                   fd_pool_evt_t const * events,
                   ulong                 events_cnt ) {
  ulong processed = 0UL;
  for( ulong i=0UL; i<events_cnt; i++ ) {
    fd_votor_pool_event_t ve[1];
    if( FD_UNLIKELY( !map_pool_evt_to_votor( &events[ i ], ve ) ) ) continue;
    fd_votor_out_t out = fresh_votor_out( ctx );
    fd_votor_handle_pool_event( ctx->votor, ve, &out );
    drain_votor_out( ctx, &out );
    processed++;
  }
  return processed;
}


/* ingest_vote (defined above forward) feeds a single vote into the pool.
   FD_POOL_ERR_DUPLICATE is benign (we re-ingest our own votes).  Any newly
   created certs / events are drained into the votor.  Returns the
   fd_pool_add_vote result. */

static int
ingest_vote( fd_votor_tile_t * ctx, fd_ag_vote_t const * vote, fd_validator_epoch_info_t const * ei ) {
  fd_pool_out_t          out = fresh_pool_out( ctx );
  fd_slashable_offence_t offence[1] = {{ .kind = FD_SLASHABLE_NONE }};


  int err = fd_pool_add_vote( ctx->pool, vote, ei, &out, offence );
  if( FD_UNLIKELY( err==FD_POOL_ERR_SLASHABLE ) ) {
    ctx->metrics.slashable++;
    FD_LOG_WARNING(( "slashable offence kind %d validator %lu slot %lu", offence->kind, offence->validator, offence->slot ));
    return err;
  }
  if( FD_UNLIKELY( err!=FD_POOL_SUCCESS && err!=FD_POOL_ERR_DUPLICATE ) ) return err;

  /* Drive any events the pool just emitted (cert created / parent ready /
     safe to notar / safe to skip) into the votor.  drive_pool_events feeds
     the votor's resulting votes back through ingest_vote (recursively), so
     each event batch is drained to a fixpoint before this call returns.  We
     snapshot the event batch first because the recursive ingest_vote reuses
     ctx->events via fresh_pool_out.  ctx->fixpoint_depth bounds the recursion
     to guard against a runaway cascade. */

  if( out.events_cnt ) {
    fd_pool_evt_t snapshot[ EVENTS_MAX ];
    ulong         snapshot_cnt = out.events_cnt;
    fd_memcpy( snapshot, out.events, snapshot_cnt*sizeof(fd_pool_evt_t) );
    if( FD_UNLIKELY( ++ctx->fixpoint_depth>FIXPOINT_MAX ) ) {
      ctx->metrics.fixpoint_exceeded++;
      FD_LOG_WARNING(( "votor pool-event fixpoint depth exceeded %lu", ctx->fixpoint_depth ));
    } else {
      drive_pool_events( ctx, snapshot, snapshot_cnt );
    }
    ctx->fixpoint_depth--;
  }
  return FD_POOL_SUCCESS;
}

/* ingest_cert feeds a single cert into the pool.  Any newly created events
   are drained into the votor.  Returns the fd_pool_add_cert result. */

static int
ingest_cert( fd_votor_tile_t * ctx, fd_cert_t const * cert, fd_validator_epoch_info_t const * ei ) {
  fd_pool_out_t out = fresh_pool_out( ctx );
  int err = fd_pool_add_cert( ctx->pool, cert, ei, &out );
  if( FD_UNLIKELY( err!=FD_POOL_SUCCESS && err!=FD_POOL_ERR_DUPLICATE ) ) return err;
  if( out.events_cnt ) {
    fd_pool_evt_t snapshot[ EVENTS_MAX ];
    ulong         snapshot_cnt = out.events_cnt;
    fd_memcpy( snapshot, out.events, snapshot_cnt*sizeof(fd_pool_evt_t) );
    drive_pool_events( ctx, snapshot, snapshot_cnt );
  }
  return FD_POOL_SUCCESS;
}

/* publish_slot_done queues the FD_VOTOR_SIG_SLOT_DONE frag for the just
   completed replay slot.  The reset target is the best certified tip: we
   prefer the notarized block of the highest slot with a notar cert at/below
   the completed slot, falling back to the completed block itself. */

static void
publish_slot_done( fd_votor_tile_t *                  ctx,
                   fd_replay_slot_completed_t const * slot_completed ) {
  publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
  pub->sig = FD_VOTOR_SIG_SLOT_DONE;

  fd_votor_slot_done_t * msg = &pub->msg.slot_done;
  msg->replay_slot     = slot_completed->slot;
  msg->replay_bank_idx = slot_completed->bank_idx;

  /* Determine the reset target.  Query parents_ready for the next slot: if a
     valid parent is ready, reset onto it.  Otherwise reset onto the block we
     just completed. */

  msg->reset_slot     = slot_completed->slot;
  msg->reset_block_id = slot_completed->block_id;

  fd_hash_t notarized[1];
  if( FD_LIKELY( fd_pool_get_notarized_block( ctx->pool, slot_completed->slot, notarized ) ) ) {
    msg->reset_slot     = slot_completed->slot;
    msg->reset_block_id = *notarized;
  }
  ctx->reset_slot         = msg->reset_slot;
  ctx->metrics.reset_slot = msg->reset_slot;
}

/* maybe_publish_finalized emits two distinct frags as state advances:

   FD_VOTOR_SIG_FINALIZED -- whenever consensus finalizes a higher slot (a
     final / fast-final cert).  Cert-driven, NOT gated on replay; a pure
     notification ("slot X is finalized").

   FD_VOTOR_SIG_ROOTED    -- whenever the bank root can advance, i.e. the
     highest slot that is BOTH finalized AND replayed (its bank is frozen).
     This is the "root your bank here" command for replay.  It mirrors Agave's
     scan of finalized_blocks for the max whose bank.is_frozen():
     highest_replayed_slot is our frozen-bank frontier, fd_pool_finalized_slot
     the cert frontier, so the rootable slot is min(finalized, replayed).  A
     cert ahead of replay (catchup) leaves ROOTED lagging FINALIZED until replay
     catches up; in steady state finalization trails replay and ROOTED ==
     FINALIZED.

   Called from both the replay path (votor_slot_completed) and the cert RX path
   so whichever of {finalized, replayed} advances second fires the root. */

static void
maybe_publish_finalized( fd_votor_tile_t * ctx ) {
  ulong fin = fd_pool_finalized_slot( ctx->pool );

  /* FINALIZED: consensus finalization advanced (cert-driven). */
  if( FD_UNLIKELY( fin>ctx->finalized_slot ) ) {
    fd_hash_t block_id[1];
    memset( block_id, 0, sizeof(fd_hash_t) );
    fd_pool_get_notarized_block( ctx->pool, fin, block_id );
    publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
    pub->sig                    = FD_VOTOR_SIG_FINALIZED;
    pub->msg.finalized.slot     = fin;
    pub->msg.finalized.block_id = *block_id;
    ctx->finalized_slot         = fin;
  }

  /* ROOTED: the bank root can advance to the highest finalized+replayed slot. */
  ulong rootable = fd_ulong_min( fin, ctx->highest_replayed_slot );
  if( FD_UNLIKELY( rootable>ctx->root_slot ) ) {
    /* block id of the rootable slot: at the replay frontier (catchup) use the
       block we just replayed there; otherwise (finalized trails replay) the
       finalized slot has a notar cert -> read it from the pool. */
    fd_hash_t block_id[1];
    if( rootable==ctx->highest_replayed_slot ) {
      *block_id = ctx->highest_replayed_block_id;
    } else {
      memset( block_id, 0, sizeof(fd_hash_t) );
      fd_pool_get_notarized_block( ctx->pool, rootable, block_id );
    }
    publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
    pub->sig                 = FD_VOTOR_SIG_ROOTED;
    pub->msg.rooted.slot     = rootable;
    pub->msg.rooted.block_id = *block_id;
    ctx->root_slot           = rootable;
    ctx->root_block_id       = *block_id;
    ctx->metrics.root_slot   = rootable;
    FD_LOG_INFO(( "votor rooted slot %lu", rootable ));
  }
}

/* THE CORE DRIVE.  votor_slot_completed is the analog of Tower's
   replay_slot_completed: it registers a completed block with the consensus
   core and drives the resulting voting / certification cascade.

   Returns 1 if backpressure is requested (halt_signing), 0 otherwise. */

static int
votor_slot_completed( fd_votor_tile_t *                  ctx,
                      fd_replay_slot_completed_t const * slot_completed,
                      ulong                              tsorig FD_PARAM_UNUSED,
                      fd_stem_context_t *                stem FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( ctx->halt_signing ) ) return 1; /* backpressure during halt_signing */

  ctx->init                = 1;
  ctx->metrics.replay_slot = slot_completed->slot;

  /* 0. On the first completion after boot, re-root pool (and reset the
        votor) at the snapshot slot.  */

  if( FD_UNLIKELY( ctx->root_slot==ULONG_MAX ) ) {
    ctx->root_slot     = slot_completed->parent_slot;
    ctx->root_block_id = slot_completed->parent_block_id;

    ctx->pool = fd_pool_join( fd_pool_new( fd_pool_leave( ctx->pool ),
                                           ctx->slot_max, ctx->validator_max, ctx->blockid_max, ctx->seed,
                                           ctx->root_slot, &ctx->root_block_id ) );
    FD_TEST( ctx->pool );

    /* fd_votor_new re-emits the genesis window's timeouts (slots 0..3).
       discard them. */
    fd_votor_out_t reset_out = fresh_votor_out( ctx );
    ctx->votor = fd_votor_join( fd_votor_new( fd_votor_leave( ctx->votor ),
                                              ctx->slot_max, ctx->voting_key, ctx->seed, &reset_out ) );
    FD_TEST( ctx->votor );
  }

  ulong epoch = fd_slot_to_epoch( &ctx->epoch_schedule, slot_completed->slot, NULL );
  fd_validator_epoch_info_t const * ei = epoch_info_vtrs( ctx, epoch );
  if( FD_UNLIKELY( !ei ) ) FD_LOG_CRIT(( "block for epoch %lu but no validator epoch info", epoch ));

  /* 1. Build block / parent identifiers from the replay frag. */

  fd_block_id_t block  = { .slot = slot_completed->slot,        .hash = slot_completed->block_id        };
  fd_block_id_t parent = { .slot = slot_completed->parent_slot, .hash = slot_completed->parent_block_id };

  /* 2. Register the block with its parent in the pool.  Requires
        block.slot > parent.slot; the genesis / snapshot slot has no parent in
        the pool so we skip add_block for it. */

  if( FD_LIKELY( block.slot>parent.slot ) ) {
    fd_pool_out_t out = fresh_pool_out( ctx );
    fd_pool_add_block( ctx->pool, &block, &parent, ei, &out );
    if( out.events_cnt ) {
      fd_pool_evt_t snapshot[ EVENTS_MAX ];
      ulong         snapshot_cnt = out.events_cnt;
      fd_memcpy( snapshot, out.events, snapshot_cnt*sizeof(fd_pool_evt_t) );
      drive_pool_events( ctx, snapshot, snapshot_cnt );
    }
  }

  /* 3. Drive votor block availability: FirstShred then Block.  These mirror
        the Rust BlockstoreEvent stream and produce our notar / skip votes. */

  {
    fd_votor_out_t out = fresh_votor_out( ctx );
    fd_votor_blockstore_event_t fs = { .discriminant = FD_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED };
    fs.inner.first_shred = block.slot;
    fd_votor_handle_blockstore_event( ctx->votor, &fs, &out );
    drain_votor_out( ctx, &out );
  }
  {
    fd_votor_out_t out = fresh_votor_out( ctx );
    fd_votor_blockstore_event_t b = { .discriminant = FD_VOTOR_BLOCKSTORE_EVENT_BLOCK };
    b.inner.block.slot            = block.slot;
    b.inner.block.block_id        = block;
    b.inner.block.parent_block_id = parent;
    fd_votor_handle_blockstore_event( ctx->votor, &b, &out );
    drain_votor_out( ctx, &out );
  }

  /* 4. Replay froze this slot's bank -> advance our frozen-bank frontier (the
        analog of Agave's VotorEvent::Block / bank.is_frozen()), then check for
        finalization / root advancement. */

  if( FD_LIKELY( slot_completed->slot > ctx->highest_replayed_slot ) ) {
    ctx->highest_replayed_slot     = slot_completed->slot;
    ctx->highest_replayed_block_id = slot_completed->block_id;
  }

  maybe_publish_finalized( ctx );

  /* 5. Queue the slot_done frag (reset target + echoed bank_idx). */

  publish_slot_done( ctx, slot_completed );

  if( LOGGING ) {
    FD_LOG_NOTICE(( "votor slot_completed slot=%lu parent=%lu finalized=%lu reset=%lu",
                    slot_completed->slot, slot_completed->parent_slot, ctx->root_slot, ctx->reset_slot ));
  }

  return 0;
}

/* votor_slot_dead drives the votor InvalidBlock path for a dead slot. */

static void
votor_slot_dead( fd_votor_tile_t *               ctx,
                 fd_replay_slot_dead_t const *   slot_dead ) {
  if( FD_UNLIKELY( slot_dead->slot < ctx->root_slot ) ) return; /* ignore dead slots before root */
  fd_votor_out_t out = fresh_votor_out( ctx );
  fd_votor_blockstore_event_t ib = { .discriminant = FD_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK };
  ib.inner.invalid_block = slot_dead->slot;
  fd_votor_handle_blockstore_event( ctx->votor, &ib, &out );
  drain_votor_out( ctx, &out );
}

/* votor_handle_consensus_msg is the consensus-core entrypoint for an
   Alpenglow ConsensusMessage received over the network (QUIC).  This is
   the clean seam between the tile's QUIC/networking callbacks and the
   consensus logic: the quic_stream_rx callback calls it with the raw
   on-wire bytes of one reassembled ConsensusMessage.

   Bring-up: do NOT process the message yet, just log its discriminant.
   Agave serializes the ConsensusMessage enum with bincode, so the first
   4 bytes are the variant index (0 = Vote, 1 = Certificate).  See
   votor-messages/src/consensus_message.rs.  When real ingest lands this
   should deserialize into fd_ag_vote_t / fd_cert_t and call ingest_vote /
   ingest_cert (cf. ingest_consensus_msg above). */

static void
votor_handle_consensus_msg( fd_votor_tile_t * ctx,
                            uchar const *     payload,
                            ulong             sz ) {
  (void)ctx;
  if( FD_UNLIKELY( sz<sizeof(uint) ) ) return;
  uint kind = FD_LOAD( uint, payload );

  switch( kind ) {
  case FD_CONSENSUS_MESSAGE_VOTE: {
    /* advance payload past the discriminant */
    payload += sizeof(uint); sz -= sizeof(uint);
    fd_ag_vote_t * vote = (fd_ag_vote_t *)fd_type_pun_const( payload );

    ulong epoch     = fd_slot_to_epoch( &ctx->epoch_schedule, fd_vote_slot( vote ), NULL );
    fd_validator_epoch_info_t const * ei = epoch_info_vtrs( ctx, epoch );
    if( FD_UNLIKELY( !ei ) ) { ctx->metrics.votes_dropped_no_epoch++; break; }

    ingest_vote( ctx, vote, ei );
    maybe_publish_finalized( ctx );
    break;
  }
  case FD_CONSENSUS_MESSAGE_CERT: {
    if( FD_UNLIKELY( !ctx->have_schedule ) ) break;
    /* advance payload past the discriminant */
    payload += sizeof(uint); sz -= sizeof(uint);
    fd_cert_t cert[1];
    int err = fd_cert_de( cert, payload, sz );
    if( FD_UNLIKELY( err!=FD_CERT_DE_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to deserialize certificate: type %s, error %d", fd_cert_type_to_string( cert->discriminant ), err ));
      break;
    }

    /* Verify against the validator set / BLS rank map of the cert's OWN epoch
      (mirrors Agave's get_rank_map(slot)) -- not whatever epoch happens to be
      active.  Drop certs whose epoch we no longer (or do not yet) retain. */
    ulong cert_slot  = fd_cert_slot( cert );
    ulong cert_epoch = fd_slot_to_epoch( &ctx->epoch_schedule, cert_slot, NULL );
    fd_validator_epoch_info_t const * ei = epoch_info_vtrs( ctx, cert_epoch );
    if( FD_UNLIKELY( !ei ) ) { ctx->metrics.certs_dropped_no_epoch++; break; }

    ingest_cert( ctx, cert, ei );
    maybe_publish_finalized( ctx );
    break;
  } default: break; }
}

/* Rank-ordering key for the voter sort: stake descending, tie-broken by
   the compressed BLS pubkey ascending.  bls points into the epoch
   message's pubkey array, which is stable for the duration of the sort. */

struct vtr_rank { ulong stake; uchar const * bls; ushort src; };
typedef struct vtr_rank vtr_rank_t;

#define SORT_NAME        vtr_rank_sort
#define SORT_KEY_T       vtr_rank_t
#define SORT_BEFORE(a,b) ( (a).stake>(b).stake ||                          \
                           ( (a).stake==(b).stake &&                       \
                             memcmp( (a).bls, (b).bls, FD_EPOCH_INFO_BLS_PUBKEY_SZ )<0 ) )
#include "../../util/tmpl/fd_sort.c"

/* update_epoch_vtrs rebuilds the active epoch's validator set from an EPOCH
   msg (the staked validator set + stakes).  The pool and votor are rebuilt
   against the new set. */

FD_FN_UNUSED void
update_epoch_vtrs( fd_votor_tile_t *              ctx,
                   fd_epoch_info_msg_t const *    msg,
                   fd_vote_stake_weight_t const * stakes,
                   ulong                          stake_cnt ) {

  ulong         in_cnt      = fd_ulong_min( stake_cnt, VTR_MAX );
  uchar const * bls_pubkeys = fd_epoch_info_msg_bls_pubkeys( msg );

  /* Keep only vote accounts with non-zero stake and a decodable BLS
     voting key, then order by stake descending, tie-broken by the
     COMPRESSED BLS pubkey ascending; rank == position in that order.

     This ordering is intentionally votor-local.  It must NOT reuse the
     stake-weight sort (vote-key tie-break) that drives the leader
     schedule -- changing that sort would alter the cluster-wide leader
     schedule consumed by the shred / tower / replay / etc. tiles.
     TODO: Agave also drops duplicate BLS / node pubkeys; not handled
     here. Also missing check proof of possession. */

  vtr_rank_t rank[ VTR_MAX ]; /* surviving validators, pre-sort */
  ulong      m = 0UL;
  for( ulong i=0UL; i<in_cnt; i++ ) {
    if( FD_UNLIKELY( stakes[i].stake==0UL ) ) continue;
    fd_aggsig_pk_t probe;
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( probe.v,
                                                         bls_pubkeys + i*FD_EPOCH_INFO_BLS_PUBKEY_SZ,
                                                         1 ) ) ) continue; /* no / invalid BLS key */
    rank[m].stake = stakes[i].stake;
    rank[m].bls   = bls_pubkeys + i*FD_EPOCH_INFO_BLS_PUBKEY_SZ;
    rank[m].src   = (ushort)i;
    m++;
  }
  vtr_rank_sort_inplace( rank, m );

  ulong cnt = m;
  if( FD_UNLIKELY( !cnt ) ) {
    FD_LOG_WARNING(( "epoch %lu has no ranked validators; skipping", msg->epoch ));
    return;
  }

  /* Copy into validator_info TODO think we can just put this directly into epoch_info */
  ushort own_id      = 0;
  int    have_own_id = 0;
  for( ushort r=0UL; r<cnt; r++ ) {
    ushort                src = rank[r].src;
    fd_validator_info_t * vi  = &ctx->validators[ r ];
    memset( vi, 0, sizeof(fd_validator_info_t) );
    vi->id     = r;
    vi->stake  = stakes[src].stake;
    vi->pubkey = stakes[src].id_key;
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( vi->voting_pubkey.v,
                                                         bls_pubkeys + (ulong)src*FD_EPOCH_INFO_BLS_PUBKEY_SZ,
                                                         1 /* big endian */ ) ) ) {
      FD_LOG_CRIT(( "BLS voting pubkey for source %u failed to decompress after the filter", (uint)src ));
    }
    if( FD_UNLIKELY( !memcmp( stakes[src].id_key.uc, ctx->identity_key->uc, sizeof(fd_pubkey_t) ) ) ) {
      own_id      = r;
      have_own_id = 1;
      /* voting_key is the real BLS secret derived once in privileged_init (do
         NOT overwrite it here).  Sanity check: the pubkey it derives to must
         equal the on-chain registered BLS pubkey for our vote account (just
         decompressed into vi->voting_pubkey).  A mismatch means our votes will
         silently fail signature verification, so shout about it. */
      fd_aggsig_pk_t derived[1];
      fd_aggsig_sk_to_pk( derived, ctx->voting_key );
      if( FD_UNLIKELY( memcmp( derived->v, vi->voting_pubkey.v, FD_AGGSIG_PUBKEY_SZ ) ) ) {
        FD_LOG_WARNING(( "BLS KEY MISMATCH: derived voting pubkey != on-chain registered key "
                         "(epoch %lu, rank %u) -- our votes will NOT verify; check the "
                         "authorized-voter keypair matches the vote account's BLS registration",
                         msg->epoch, (uint)r ));
      } else {
        FD_LOG_NOTICE(( "BLS voting key OK: derived pubkey matches on-chain registration (epoch %lu, rank %u)",
                        msg->epoch, (uint)r ));
      }
    }
  }

  /* Insert (or refresh) this epoch's set into the window without disturbing
     other epochs.  The pool / votor are NOT rebuilt here -- the active epoch is
     switched lazily from the replayed tip in votor_slot_completed. */
  ctx->epoch_schedule = msg->epoch_schedule;
  ctx->have_schedule  = 1;

  vtr_epoch_set_t * s = &ctx->vtr_epoch_stakes[ msg->epoch % VTR_EPOCH_WINDOW ];
  /* Don't let a stale (older) re-publish evict a newer epoch sharing this ring
     slot.  Refresh (==) and normal advance (older slot occupant) proceed. */
  if( FD_UNLIKELY( s->epoch!=ULONG_MAX && s->epoch>msg->epoch ) ) {
    FD_LOG_WARNING(( "ignoring stale epoch %lu (slot holds newer epoch %lu)", msg->epoch, s->epoch ));
    return;
  }
  s->epoch         = msg->epoch;
  s->info.own_id   = own_id;
  s->info.epoch    = fd_epoch_info_join( fd_epoch_info_new( s->mem, ctx->validators, cnt ) );
  s->validator_cnt = cnt;
  s->have_own_id   = have_own_id;

  FD_LOG_NOTICE(( "epoch %lu validator set: %lu validators (own_id %u, staked=%d)",
                  msg->epoch, cnt, (uint)own_id, have_own_id ));
}

/* QUIC ingress is enabled when the tile carries QUIC config (set by the
   topology).  The unit test constructs a tile without QUIC config, in
   which case the tile runs consensus only (ctx->quic stays NULL). */

FD_FN_PURE static inline int
votor_quic_enabled( fd_topo_tile_t const * tile ) {
  return tile->quic.max_concurrent_connections!=0UL;
}

static inline fd_quic_limits_t
quic_limits( fd_topo_tile_t const * tile ) {
  fd_quic_limits_t limits = {
    .conn_cnt                    = tile->quic.max_concurrent_connections,
    .handshake_cnt               = tile->quic.max_concurrent_handshakes,
    .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
    .inflight_frame_cnt          = 64UL * tile->quic.max_concurrent_connections,
    .min_inflight_frame_cnt_conn = 32UL
  };
  if( FD_UNLIKELY( !fd_quic_footprint( &limits ) ) ) FD_LOG_ERR(( "Invalid QUIC limits in config" ));
  return limits;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong slot_max      = fd_ulong_pow2_up( tile->tower.max_live_slots );
  ulong validator_max = fd_ulong_pow2_up( VTR_MAX );
  ulong blockid_max   = slot_max;
  ulong pub_max       = slot_max * 8UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_votor_tile_t),  sizeof(fd_votor_tile_t)                                  );
  l = FD_LAYOUT_APPEND( l, fd_votor_align(),          fd_votor_footprint( slot_max )                           );
  l = FD_LAYOUT_APPEND( l, fd_pool_align(),           fd_pool_footprint( slot_max, validator_max, blockid_max ) );
  l = FD_LAYOUT_APPEND( l, fd_timeout_heap_align(),   fd_timeout_heap_footprint( slot_max )                     );
  l = FD_LAYOUT_APPEND( l, fd_timeout_pool_align(),   fd_timeout_pool_footprint( slot_max )                     );
  for( ulong i=0UL; i<VTR_EPOCH_WINDOW; i++ )
    l = FD_LAYOUT_APPEND( l, fd_epoch_info_align(),   fd_epoch_info_footprint( VTR_MAX )                       );
  l = FD_LAYOUT_APPEND( l, publishes_align(),         publishes_footprint( pub_max )                           );
  if( votor_quic_enabled( tile ) ) {
    fd_quic_limits_t limits = quic_limits( tile );
    l = FD_LAYOUT_APPEND( l, fd_quic_align(),         fd_quic_footprint( &limits )                             );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* init_choreo allocates and initializes all Alpenglow consensus structures
   from scratch memory.  scratch must be at least scratch_footprint bytes
   aligned to scratch_align().  The seed field at the start of scratch must be
   pre-initialized (e.g. by privileged_init).  Returns a handle to the
   fd_votor_tile_t in scratch.

   The pool and votor are formatted with a bootstrap single-validator set
   (just us); they are rebuilt against the real validator set on the first
   EPOCH msg (update_epoch_vtrs). */

static fd_votor_tile_t *
init_choreo( void                 * scratch,
             fd_topo_tile_t const * tile ) {
  ulong slot_max      = fd_ulong_pow2_up( tile->tower.max_live_slots );
  ulong validator_max = fd_ulong_pow2_up( VTR_MAX );
  ulong blockid_max   = slot_max;
  ulong pub_max       = slot_max * 8UL;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t)                                  );
  void  * votor         = FD_SCRATCH_ALLOC_APPEND( l, fd_votor_align(),         fd_votor_footprint( slot_max )                           );
  void  * pool          = FD_SCRATCH_ALLOC_APPEND( l, fd_pool_align(),          fd_pool_footprint( slot_max, validator_max, blockid_max ) );
  void  * timeouts_heap = FD_SCRATCH_ALLOC_APPEND( l, fd_timeout_heap_align(),  fd_timeout_heap_footprint( slot_max )                     );
  void  * timeouts_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_timeout_pool_align(),  fd_timeout_pool_footprint( slot_max )                     );
  void  * epoch_mem[ VTR_EPOCH_WINDOW ];
  for( ulong i=0UL; i<VTR_EPOCH_WINDOW; i++ )
    epoch_mem[i]        = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_info_align(),    fd_epoch_info_footprint( VTR_MAX )                       );
  void  * publishes     = FD_SCRATCH_ALLOC_APPEND( l, publishes_align(),        publishes_footprint( pub_max )                           );
  void  * quic_mem      = NULL;
  if( votor_quic_enabled( tile ) ) {
    fd_quic_limits_t limits = quic_limits( tile );
    quic_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &limits ) );
  }
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->slot_max      = slot_max;
  ctx->validator_max = validator_max;
  ctx->blockid_max   = blockid_max;

  for( ulong i=0UL; i<VTR_EPOCH_WINDOW; i++ ) {
    ctx->vtr_epoch_stakes[i].epoch       = ULONG_MAX;
    ctx->vtr_epoch_stakes[i].info.epoch  = NULL;
    ctx->vtr_epoch_stakes[i].info.own_id = 0UL;
    ctx->vtr_epoch_stakes[i].mem         = epoch_mem[i];
  }
  ctx->have_schedule = 0;

  ctx->pool = fd_pool_join( fd_pool_new( pool, slot_max, validator_max, blockid_max, ctx->seed,
                                         0UL, NULL /* genesis baseline; rebuilt rooted at the snapshot on the first slot */ ) );

  fd_votor_out_t boot_out = {
    .msgs        = ctx->msgs,
    .msg_cnt     = 0UL,
    .msg_max     = MSGS_MAX,
    .timeouts    = ctx->timeouts,
    .timeout_cnt = 0UL,
    .timeout_max = TIMEOUTS_MAX
  };
  ctx->votor = fd_votor_join( fd_votor_new( votor, slot_max, ctx->voting_key, ctx->seed, &boot_out ) );

  ctx->timeouts_heap = fd_timeout_heap_join( fd_timeout_heap_new( timeouts_heap, slot_max ) );
  ctx->timeouts_pool = fd_timeout_pool_join( fd_timeout_pool_new( timeouts_pool, slot_max ) );

  ctx->publishes = publishes_join( publishes_new( publishes, pub_max ) );

  /* QUIC server memory is formatted here; the connection config, ephemeral
     TLS identity, TX aio and net links are wired in unprivileged_init
     (which has the topology).  NULL when QUIC is disabled (unit test). */
  ctx->quic = NULL;
  if( quic_mem ) {
    fd_quic_limits_t limits = quic_limits( tile );
    ctx->quic = fd_quic_join( fd_quic_new( quic_mem, &limits ) );
    FD_TEST( ctx->quic );
  }

  FD_TEST( ctx->pool );
  FD_TEST( ctx->votor );
  FD_TEST( ctx->publishes );

  ctx->halt_signing   = 0;
  ctx->shred_version  = 0;
  ctx->init           = 0;
  ctx->fixpoint_depth = 0UL;
  ctx->root_slot      = ULONG_MAX;
  fd_memset( &ctx->root_block_id, 0, sizeof(fd_hash_t) );
  ctx->finalized_slot = 0UL;
  ctx->highest_replayed_slot = 0UL;
  fd_memset( &ctx->highest_replayed_block_id, 0, sizeof(fd_hash_t) );
  ctx->reset_slot     = 0UL;

  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  return ctx;
}

/* ---- QUIC ingress (tile-level networking callbacks) -------------------

   These callbacks handle the QUIC/networking machinery only; the consensus
   logic lives in helpers (votor_handle_consensus_msg and the ingest_*
   functions above).  Modeled on the TPU QUIC tile (fd_quic_tile.c). */

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush ) {
  (void)flush;
  fd_votor_tile_t * ctx = _ctx;
  for( ulong i=0UL; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;
    uint const ip_dst = FD_LOAD( uint, batch[ i ].buf+offsetof( fd_ip4_hdr_t, daddr_c ) );
    uchar * packet_l2 = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
    memset( packet_l2, 0, 12 );
    FD_STORE( ushort, packet_l2+offsetof( fd_eth_hdr_t, net_type ), fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
    fd_memcpy( packet_l3, batch[ i ].buf, batch[ i ].buf_sz );
    ulong sz_l2 = sizeof(fd_eth_hdr_t) + batch[ i ].buf_sz;
    ulong sig   = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
    ulong chunk = ctx->net_out_chunk;
    ulong ctl   = fd_frag_meta_ctl( 0UL, 1, 1, 0 );
    fd_stem_publish( ctx->stem, OUT_IDX_NET, sig, chunk, sz_l2, ctl, 0L, 0L );
    ctx->net_out_chunk = fd_dcache_compact_next( chunk, FD_NET_MTU, ctx->net_out_chunk0, ctx->net_out_wmark );
  }
  if( FD_LIKELY( opt_batch_idx ) ) *opt_batch_idx = batch_cnt;
  return FD_AIO_SUCCESS;
}

static void
quic_tls_cv_sign( void *      signer_ctx,
                  uchar       signature[ static 64 ],
                  uchar const payload[ static 130 ] ) {
  fd_votor_tile_t * ctx = signer_ctx;
  fd_sha512_t * sha512 = fd_sha512_join( ctx->quic_sha512 );
  fd_ed25519_sign( signature, payload, 130UL, ctx->tls_pub_key, ctx->tls_priv_key, sha512 );
  fd_sha512_leave( sha512 );
}

static void
quic_conn_final( fd_quic_conn_t * conn,
                 void *           quic_ctx ) {
  (void)conn; (void)quic_ctx;
}

/* quic_stream_rx fires for each received QUIC stream payload (one whole
   ConsensusMessage on the bring-up fast path) and hands it to the
   consensus core.  Multi-fragment reassembly is a TODO. */

static int
quic_stream_rx( fd_quic_conn_t * conn,
                ulong            stream_id,
                ulong            offset,
                uchar const *    data,
                ulong            data_sz,
                int              fin ) {
  (void)stream_id;
  fd_votor_tile_t * ctx = conn->quic->cb.quic_ctx;
  if( FD_UNLIKELY( !(offset==0UL && fin) ) ) return FD_QUIC_SUCCESS; /* fragmented: drop (TODO reassemble) */
  votor_handle_consensus_msg( ctx, data, data_sz );
  return FD_QUIC_SUCCESS;
}

static inline void
before_credit( fd_votor_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  ctx->stem = stem;
  if( FD_LIKELY( ctx->quic ) ) {
    ctx->now = fd_log_wallclock();
    *charge_busy = fd_quic_service( ctx->quic, ctx->now );
  }
}

static int
before_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)seq;
  /* Only the net_alpenglow links carry netmux-tagged frames; filter them
     to the alpenglow proto.  Consensus links are always processed. */
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_VOTOR ) )
    return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_ALPENGLOW;
  return 0;
}

static void
during_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig FD_PARAM_UNUSED,
             ulong             chunk,
             ulong             sz,
             ulong             ctl ) {
  /* Copy raw network frames out of the (unreliable) net dcache while they
     are still valid; consensus links are read directly in returnable_frag. */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_VOTOR ) ) {
    if( FD_UNLIKELY( sz>FD_NET_MTU ) ) return;
    void const * src = fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz );
    fd_memcpy( ctx->net_buf, src, sz );
  }
}

static void
during_housekeeping( fd_votor_tile_t * ctx ) {

  /* Identity keyswitch state machine (copied from Tower).  Alpenglow uses a
     single fixed BLS voting key, so there is no separate authorized-voter
     keyswitch to drive. */

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: unhalting signing" ));
    FD_TEST( ctx->halt_signing ); /* state machine corruption */
    ctx->halt_signing = 0;
    fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->identity_keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: halting signing" ));
    memcpy( ctx->identity_key, ctx->identity_keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
    ctx->halt_signing = 1;
    ctx->identity_keyswitch->result = ctx->out_seq;
  }
}

static inline void
metrics_write( fd_votor_tile_t * ctx ) {
  FD_MGAUGE_SET( TOWER, REPLAY_SLOT, ctx->metrics.replay_slot );
  FD_MGAUGE_SET( TOWER, ROOT_SLOT,   ctx->metrics.root_slot   );
  FD_MGAUGE_SET( TOWER, RESET_SLOT,  ctx->metrics.reset_slot  );
  FD_MCNT_SET  ( TOWER, FRAG_NOT_READY_DROPPED, ctx->metrics.not_ready );
}

static inline void
after_credit( fd_votor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {

  /* TODO: poll due votor timeouts here (drive try_skip_window via
     fd_votor_handle_timeout_event) once the deadline machinery is wired up.
     The timeouts emitted by the votor handlers carry DELTA_* offsets that
     must be turned into wall-clock deadlines against fd_log_wallclock().  For
     now timeouts are not persisted (see drain_votor_out). */

  while( fd_timeout_heap_ele_cnt( ctx->timeouts_heap ) ) {
    fd_timeout_t * timeout = fd_timeout_heap_ele_peek_min( ctx->timeouts_heap, ctx->timeouts_pool );
    if( FD_LIKELY( timeout->ts > fd_log_wallclock() ) ) break;
    fd_timeout_heap_ele_remove_min( ctx->timeouts_heap, ctx->timeouts_pool );

    /* timeout for this slot is due */
    switch( timeout->kind ) {
    case FD_VOTOR_TIMEOUT_TIMEOUT: {
      fd_votor_timeout_t event = { .kind = FD_VOTOR_TIMEOUT_TIMEOUT, .slot = timeout->slot };
      fd_votor_out_t out = fresh_votor_out( ctx );
      fd_votor_handle_timeout_event( ctx->votor, &event, &out );
      drain_votor_out( ctx, &out );
      break;
    }
    case FD_VOTOR_TIMEOUT_CRASHED_LEADER:
      break;
    default:
      break;
    }
    fd_timeout_pool_ele_release( ctx->timeouts_pool, timeout );
  }

  if( FD_LIKELY( !publishes_empty( ctx->publishes ) ) ) {
    publish_t * pub = publishes_pop_head_nocopy( ctx->publishes );
    ulong ts = fd_frag_meta_ts_comp( fd_tickcount() );

    /* TODO a2a broadcast */
   if( FD_UNLIKELY( pub->sig==FD_VOTOR_SIG_VOTE ) ) {
     uchar buf[ FD_VOTE_SERIALIZED_MAX ];
     FD_TEST( fd_vote_serialize( &pub->msg.vote, buf, sizeof(buf) ) );
     //TODO send
   }

    memcpy( fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk ), &pub->msg, sizeof(fd_votor_msg_t) );
    fd_stem_publish( stem, OUT_IDX, pub->sig, ctx->out_chunk, sizeof(fd_votor_msg_t), 0UL, ts, ts );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_votor_msg_t), ctx->out_chunk0, ctx->out_wmark );
    ctx->out_seq   = stem->seqs[ OUT_IDX ];
    *opt_poll_in   = 0; /* drain the publishes */
    *charge_busy   = 1;
  }
}

static inline int
returnable_frag( fd_votor_tile_t *   ctx,
                 ulong               in_idx,
                 ulong               seq FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl FD_PARAM_UNUSED,
                 ulong               tsorig,
                 ulong               tspub FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {

  ctx->stem = stem;

  /* Network frames (net_alpenglow) are addressed by UMEM frame index, not
     by the normal dcache [chunk0,wmark] range, and were already copied into
     ctx->net_buf in during_frag.  Feed the QUIC server; quic_stream_rx then
     drives the consensus core.  Handled before the dcache bounds check
     below, which does not apply to net frames. */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_VOTOR ) ) {
    if( FD_LIKELY( ctx->quic && sz>=sizeof(fd_eth_hdr_t) ) )
      fd_quic_process_packet( ctx->quic, ctx->net_buf+sizeof(fd_eth_hdr_t), sz-sizeof(fd_eth_hdr_t), ctx->now );
    return 0;
  }

  if( FD_UNLIKELY( !ctx->in[ in_idx ].mcache_only && ( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) )
    FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY: {
    switch( sig ) {
    case REPLAY_SIG_SLOT_COMPLETED:;
      fd_replay_slot_completed_t * slot_completed = (fd_replay_slot_completed_t *)fd_type_pun( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      return votor_slot_completed( ctx, slot_completed, tsorig, stem ); /* may backpressure during halt_signing */
    case REPLAY_SIG_SLOT_DEAD:;
      fd_replay_slot_dead_t * slot_dead = (fd_replay_slot_dead_t *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      votor_slot_dead( ctx, slot_dead );
      break;
    default:
      break;
    }
    return 0;
  }
  case IN_KIND_GOSSIP: {
    if( FD_UNLIKELY( !ctx->init ) ) { ctx->metrics.not_ready++; return 0; } /* don't backpressure gossip on boot */
    return 0;
  }
  case IN_KIND_EPOCH: {
    fd_epoch_info_msg_t const *    msg    = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    FD_TEST( msg->staked_vote_cnt<=MAX_COMPRESSED_STAKE_WEIGHTS );
    FD_TEST( msg->staked_id_cnt<=MAX_SHRED_DESTS );
    fd_vote_stake_weight_t const * stakes = fd_epoch_info_msg_stake_weights( msg );
    UPDATE_EPOCH_VTRS( ctx, msg, stakes, msg->staked_vote_cnt );
    return 0;
  }
  case IN_KIND_IPECHO: {
    FD_TEST( sig && sig<=USHORT_MAX );
    ctx->shred_version = (ushort)sig;
    return 0;
  }
  default: FD_LOG_ERR(( "unexpected input kind %d", ctx->in_kind[ in_idx ] ));
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ctx->seed) ) );

  if( FD_UNLIKELY( !strcmp( tile->tower.identity_key, "" ) ) ) FD_LOG_ERR(( "missing [paths.identity_key]" ));

  /* Alpenglow BLS voting key.  Derived:
       ikm    = ed25519_sign( key, "bls-key-derive-" || "alpenglow" )  (64B)
       bls_sk = blst_keygen( ikm )
     The correct source is the vote account's authorized-voter
     keypair. TODO: switch to the authorized-voter keypair (via the sign tile?). */

  uchar const * id_kp = fd_keyload_load( tile->tower.identity_key, /* pubkey only: */ 0 );
  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( id_kp + 32UL );

  static char const derive_msg[] = "bls-key-derive-alpenglow"; /* "bls-key-derive-" || BLS_KEYPAIR_DERIVE_SEED */
  uchar         ikm[ 64 ];
  fd_sha512_t   _sha[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL,
                   id_kp+32UL /* pubkey */, id_kp /* private */, sha );
  fd_sha512_leave( sha );

  memset( ctx->voting_key, 0, sizeof(ctx->voting_key) );
  fd_aggsig_sk_derive( ctx->voting_key, ikm, sizeof(ikm) );

  /* fd_quic_service / fd_log_wallclock virtualizes clock_gettime via the
     vDSO, whose first call mmaps shared memory; force that before the
     sandbox is installed (see fd_quic_tile.c privileged_init). */
  fd_log_wallclock();
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void *            scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_votor_tile_t * ctx     = init_choreo( scratch, tile );

  ctx->wksp               = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->identity_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );

  FD_TEST( ctx->wksp );
  FD_TEST( ctx->identity_keyswitch );

  FD_TEST( tile->in_cnt<sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link      = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "replay_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "net_alpenglow" ) ) ) ctx->in_kind[ i ] = IN_KIND_VOTOR;
    else FD_LOG_ERR(( "votor tile has unexpected input link %lu %s", i, link->name ));

    if( FD_UNLIKELY( ctx->in_kind[ i ]==IN_KIND_VOTOR ) ) {
      FD_TEST( i<FD_VOTOR_NET_IN_MAX );
      fd_net_rx_bounds_init( &ctx->net_in_bounds[ i ], link->dcache );
    }

    ctx->in[ i ].mcache_only = !link->mtu;
    if( FD_LIKELY( !ctx->in[ i ].mcache_only ) ) {
      ctx->in[ i ].mem    = link_wksp->wksp;
      ctx->in[ i ].mtu    = link->mtu;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    }
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;
  ctx->out_seq    = 0UL;

  /* QUIC ingress setup: ephemeral TLS identity, server config, TX aio (→
     net), and the votor_net out link.  init_choreo already formatted the
     fd_quic when QUIC is enabled. */
  if( FD_LIKELY( ctx->quic ) ) {
    if( FD_UNLIKELY( tile->out_cnt<2UL || strcmp( topo->links[ tile->out_link_id[ OUT_IDX_NET ] ].name, "votor_net" ) ) )
      FD_LOG_ERR(( "votor tile (with QUIC) requires a votor_net output link" ));

    if( FD_UNLIKELY( getrandom( ctx->tls_priv_key, ED25519_PRIV_KEY_SZ, 0 )!=ED25519_PRIV_KEY_SZ ) )
      FD_LOG_ERR(( "getrandom failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    fd_sha512_t * sha512 = fd_sha512_join( fd_sha512_new( ctx->quic_sha512 ) );
    fd_ed25519_public_from_private( ctx->tls_pub_key, ctx->tls_priv_key, sha512 );
    fd_sha512_leave( sha512 );

    fd_aio_t * tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_tx_aio_send ) );
    if( FD_UNLIKELY( !tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

    if( FD_UNLIKELY( tile->quic.ack_delay_millis==0 ) ) FD_LOG_ERR(( "Invalid `ack_delay_millis`" ));
    if( FD_UNLIKELY( tile->quic.ack_delay_millis>=tile->quic.idle_timeout_millis ) ) FD_LOG_ERR(( "Invalid `ack_delay_millis`" ));

    ctx->quic->config.role                       = FD_QUIC_ROLE_SERVER;
    ctx->quic->config.idle_timeout               = tile->quic.idle_timeout_millis * (long)1e6;
    ctx->quic->config.ack_delay                  = tile->quic.ack_delay_millis    * (long)1e6;
    ctx->quic->config.initial_rx_max_stream_data = 2048UL;
    ctx->quic->config.retry                      = tile->quic.retry;
    fd_memcpy( ctx->quic->config.identity_public_key, ctx->tls_pub_key, ED25519_PUB_KEY_SZ );
    ctx->quic->config.sign     = quic_tls_cv_sign;
    ctx->quic->config.sign_ctx = ctx;
    ctx->quic->cb.conn_final   = quic_conn_final;
    ctx->quic->cb.stream_rx    = quic_stream_rx;
    ctx->quic->cb.quic_ctx     = ctx;
    fd_quic_set_aio_net_tx( ctx->quic, tx_aio );
    if( FD_UNLIKELY( !fd_quic_init( ctx->quic ) ) ) FD_LOG_ERR(( "fd_quic_init failed" ));

    fd_topo_link_t const * net_out = &topo->links[ tile->out_link_id[ OUT_IDX_NET ] ];
    ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out->dcache );
    ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
    ctx->net_out_chunk  = ctx->net_out_chunk0;
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_votor_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_votor_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (2UL)        /* MAX over a single returnable_frag: (vote OR cert) AND (slot_done) */
#define STEM_LAZY  (128L*3000L) /* see explanation in fd_pack */

#define STEM_CALLBACK_CONTEXT_TYPE        fd_votor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_votor_tile_t)
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_votor = {
  .name                     = "votor",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
