#include "fd_votor_tile.h"
#include "generated/fd_votor_tile_seccomp.h"

#include "../../alpenglow/consensus/ag_votor.h"
#include "../../alpenglow/consensus/ag_pool.h"
#include "../../alpenglow/consensus/ag_epoch_info.h"
#include "../../alpenglow/consensus/ag_vote.h"
#include "../../alpenglow/consensus/ag_cert.h"
#include "../../alpenglow/consensus/pool/ag_slot_state.h"
#include "../../alpenglow/crypto/ag_aggsig.h"
#include "../../alpenglow/ag_alpenglow_base.h"
#include "../../ballet/bls/fd_bls12_381.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/fd_disco_base.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/stakes/fd_stake_weight.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/io/fd_io.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../waltz/quic/fd_quic.h"
#include "../../waltz/quic/fd_quic_private.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* The Votor tile drives the Alpenglow consensus core.  It broadly processes
   four classes of frags:

   1. Replay slot completions (REPLAY link, REPLAY_SIG_SLOT_COMPLETED).  When
      Replay finishes executing a block, Votor registers the block (and its
      parent) with the pool (ag_pool_add_block) and drives the votor block
      availability handlers (FirstShred + Block).  Any votes the votor emits
      are fed back into the pool (ag_pool_add_vote) and queued for broadcast;
      any certs the pool creates are queued for broadcast.  Mirrors Tower's
      replay_slot_completed.

   2. Dead slots (REPLAY link, REPLAY_SIG_SLOT_DEAD).  A dead slot is an
      invalid block: drive the votor InvalidBlock path so the slot gets
      skipped.

   3. Gossip ContactInfo updates (GOSSIP link).  fd_gossip_update_message_t
      records used to build the peer connection table (pubkey -> alpenglow
      QUIC socket), keyed by gossip identity pubkey and backed by a pool +
      map_chain.  As routable peers are learned, an outbound QUIC client
      connection is established to broadcast our votes/certs to them.
      (Inbound votes/certs from other validators arrive over QUIC on the
      net_alpenglow link, not here — see handle_all2all_message.)

   4. Auxiliary frags: epoch stakes (EPOCH link, used to rebuild the
      validator set / stakes the pool and votor run against) and shred
      version (IPECHO link).

   In all cases the votor / pool emit a stream of actions (votes/certs to
   broadcast, timeouts to schedule) plus, for the pool, repair requests and
   PoolEvents.  As in the Rust reference (Votor::voting_loop), events flow
   through three receivers: pool_receiver (the pool's embedded
   votor_event_channel, which after_credit iterates in place and drains),
   blockstore_receiver (blockstore events are dispatched inline by the replay
   frag handlers) and timeout_receiver (the timeouts_heap, popped by
   after_credit as timeouts come due).  The votor's own votes re-enter the
   pool from handle_votor_out and the PoolEvents that produces stay on the
   pool's channel for a later after_credit iteration.  Emitted votes/certs
   are queued as FD_VOTOR_SIG_* frags onto the `publishes` deque, drained one
   frag per after_credit call (exactly like Tower).

   Rust cross-references below are GitHub permalinks pinned to the commits
   checked out at ~/projects/alpenglow (qkniep/alpenglow @ c415a42) and
   ~/projects/agave-alpenglow (anza-xyz/alpenglow @ 9f284c913f). */

#define LOGGING 0

#define IN_KIND_REPLAY (0)
#define IN_KIND_GOSSIP (1)
#define IN_KIND_EPOCH  (2)
#define IN_KIND_IPECHO (3)
#define IN_KIND_VOTOR  (4)
#define IN_KIND_SIGN   (5)

#define OUT_IDX     0 /* votor_out: consensus output (votes/certs/slot_done/finalized/rooted) */
#define OUT_IDX_NET 1 /* votor_net: QUIC TX frames back to the net tile               */

/* One net_alpenglow input link per net tile. */
#define FD_VOTOR_NET_IN_MAX (32UL)

/* The votor_out link mtu is declared as a literal in topology.c (kept as
   a literal to avoid pulling the alpenglow headers into topology.c); keep
   it in sync. */
FD_STATIC_ASSERT( sizeof(ag_votor_msg_t)<=1024UL, votor_out_mtu );

/* The Alpenglow VAT caps the voting set of validators to 2000.  Only the top
   2000 voters by stake are counted towards consensus rules.  Module
   implementations may round capacities to pow2 for performance, but the
   consensus logic retains at most 2000 voters.

   https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0357-alpenglow_validator_admission_ticket.md */

#define VTR_MAX (2000UL) /* maximum # of unique voting validators */

#define FD_VOTOR_KEYLOG_FLUSH_INTERVAL_NS ((long)100e6)

struct publish {
  ulong          sig;
  ag_votor_msg_t msg;
};
typedef struct publish publish_t;

#define DEQUE_NAME publishes
#define DEQUE_T    publish_t
#include "../../util/tmpl/fd_deque_dynamic.c"

/* peer_t is one entry in the peer connection table: an Alpenglow
   participant we have learned a routable alpenglow QUIC socket for from a
   gossip ContactInfo update, keyed by its gossip identity pubkey.  As entries
   are learned the tile establishes an outbound QUIC client connection to it,
   over which our votes/certs are broadcast.  Backed by a pool + map_chain
   owned by the tile (cf. tower_tile's epoch_vtr_map). */

struct peer {
  fd_pubkey_t      pubkey;         /* map key: gossip node identity pubkey       */
  uint             ip4;            /* alpenglow socket IPv4 addr (network order)  */
  ushort           port;           /* alpenglow socket UDP port (host order)      */
  fd_quic_conn_t * conn;           /* live outbound client conn, or NULL          */
  long             last_connected; /* wallclock (ns) of the last connect attempt  */
  ulong            next;           /* reserved for fd_pool / fd_map_chain         */
};
typedef struct peer peer_t;

#define POOL_NAME peer_pool
#define POOL_T    peer_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               peer_map
#define MAP_ELE_T              peer_t
#define MAP_KEY                pubkey
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_pubkey_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_pubkey_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

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
   immediately-adjacent epoch. For some reason Agave maintains 5
   (MAX_LEADER_SCHEDULE_STAKES,
   https://github.com/anza-xyz/alpenglow/blob/9f284c913f/runtime/src/bank.rs#L221),
   technically 2 should be enough? */

#define VTR_EPOCH_WINDOW (4UL)

/* vtr_epoch_set_t is one set of epoch stakes. epoch==ULONG_MAX marks an
   empty entry in the epoch map */
struct vtr_epoch_set {
  ulong             epoch;
  ulong             validator_cnt;
  ushort            own_id;       /* our ValidatorIndex (rank) in THIS epoch */
  int               have_own_id;  /* 0 if we are unstaked this epoch         */
  void *            mem;
  ag_epoch_info_t * info;
};
typedef struct vtr_epoch_set vtr_epoch_set_t;

struct fd_votor_tile {
  ulong          seed; /* map seed */
  fd_pubkey_t    identity_key[1];
  ag_aggsig_sk_t voting_key[1]; /* our single BLS voting secret key */
  ushort         own_id;        /* our ValidatorIndex in the active epoch */

  /* owned joins */

  fd_wksp_t *      wksp; /* workspace */
  fd_keyswitch_t * identity_keyswitch;
  fd_keyguard_client_t keyguard_client[1];

  ag_votor_t *      votor;      /* the voting state machine             */
  ag_pool_t *       pool;       /* the cert/vote integrator             */

  /* per-epoch validator-set map */
  vtr_epoch_set_t     vtr_epoch_stakes[ VTR_EPOCH_WINDOW ];
  ulong               active_epoch;    /* epoch the pool / votor are built for */
  ag_epoch_info_t *   epoch_info;      /* == active vtr_epoch_stakes entry's info */
  fd_epoch_schedule_t epoch_schedule;  /* from EPOCH msgs; slot -> epoch        */
  int                 have_schedule;

  publish_t * publishes; /* deque of msgs queued for publishing */

  /* Peer connection table: Alpenglow participants we have learned a routable
     alpenglow QUIC socket for (from gossip ContactInfo updates), keyed by
     gossip identity pubkey.  As entries are learned we open an outbound QUIC
     client connection over which votes/certs are broadcast.  peer_by_idx maps
     a gossip contact-info table index back to the occupying pubkey so that
     ContactInfo *remove* events (which carry only the index) can be resolved.
     Backed by a pool + map_chain owned by the tile (cf. tower's epoch_vtr_map). */

  peer_t *     peer_pool;      /* fd_pool handle (element-pointer typed)                          */
  peer_map_t * peer_map;
  fd_pubkey_t * peer_by_idx;   /* [FD_CONTACT_INFO_TABLE_SIZE]; all-zero == empty slot           */
  fd_quic_t *  quic_client;    /* client-role fd_quic for outbound broadcast (NULL when QUIC off) */
  uint         src_ip_addr;    /* our IPv4 (network order); src for client connects              */
  ushort       alpenglow_server_port;
  ushort       alpenglow_client_port;

  /* heap of timeouts (Votor::timeout_receiver), polled by after_credit; a due
     min timeout is popped and dispatched as a timeout event. */
  fd_timeout_t *      timeouts_pool;
  fd_timeout_heap_t * timeouts_heap;

  /* validator set staged from the most recent EPOCH msg.  The pool / votor
     are rebuilt against this set on epoch change. */

  ag_validator_info_t validators[ VTR_MAX ];
  ulong               validator_cnt;
  ulong               epoch;       /* the epoch the current set is for */

  /* fixed pool / votor dimensions, set once in init_choreo and reused
     verbatim on every epoch rebuild so the re-formatted objects always fit
     the originally allocated scratch regions. */

  ulong slot_max;
  ulong validator_max;
  ulong blockid_max;

  ulong     root_slot;      /* last ROOTED slot published (finalized AND replayed) */
  fd_hash_t root_block_id;  /* block id of root_slot (pool's seeded root)          */
  ulong     finalized_slot; /* last FINALIZED slot published (cert-driven)         */
  ulong     reset_slot;     /* last reset target published                         */

  /* frozen-bank frontier: highest replayed slot + its block id.  Rooting is
     gated on min(finalized, replayed), mirroring Agave's finalized AND
     bank.is_frozen() gate. */
  ulong     highest_replayed_slot;
  fd_hash_t highest_replayed_block_id;

  /* metadata */

  int    halt_signing;
  ushort shred_version;
  int    init; /* 1 after the first slot completion / votor_new */

  /* consensus-message ingress drop counters (logged on powers of two) */

  ulong rx_drop_frag;          /* stream frame not (offset==0 && fin)   */
  ulong rx_drop_malformed;     /* ag_consensus_message_de malformed     */
  ulong rx_drop_unsupported;   /* unknown wire version / Genesis kinds  */
  ulong rx_drop_shred_version; /* trailing shred_version mismatch       */
  ulong rx_drop_vote;          /* ag_pool_add_vote rejected             */
  ulong rx_drop_cert;          /* ag_pool_add_cert rejected             */

  /* in/out link setup */

  int      in_kind[ 64UL ];
  in_ctx_t in     [ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
  ulong       out_seq;

  /* QUIC ingress (folded-in alpin tile): an fd_quic server using the
     validator identity key receives Alpenglow ConsensusMessages on
     the dedicated alpenglow port.  The tile-level frag callbacks
     (before/during/after_frag) drive the QUIC machinery; the
     quic_server_stream_rx callback hands each whole ConsensusMessage to the
     consensus helper handle_all2all_message.  NULL when the tile is
     run without QUIC config (e.g. the unit test). */

  fd_quic_t *        quic_server;
  fd_aio_t           quic_tx_aio[1];
  long               now;
  fd_stem_context_t * stem;
  uchar              net_buf[ FD_NET_MTU ];
  fd_net_rx_bounds_t net_in_bounds[ FD_VOTOR_NET_IN_MAX ];

  /* TLS key log file (development only) */
  long                     keylog_next_flush;
  int                      keylog_fd;
  fd_io_buffered_ostream_t keylog_stream;
  char                     keylog_buf[ 4096 ];

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;
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

/* queue_vote / queue_cert push a vote / cert onto the publishes deque to be
   broadcast over the votor_out link. */

static inline void
queue_vote( fd_votor_tile_t * ctx,
            ag_vote_t const * vote ) {
  publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
  pub->sig      = FD_VOTOR_SIG_VOTE;
  pub->msg.vote = *vote;
}

static inline void
queue_cert( fd_votor_tile_t * ctx,
            ag_cert_t const * cert ) {
  publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
  pub->sig      = FD_VOTOR_SIG_CERT;
  pub->msg.cert = *cert;
}

/* voter_stake looks up the stake of validator v in the active epoch info, or
   0 if v is out of range. */

static inline ulong FD_FN_UNUSED
voter_stake( fd_votor_tile_t * ctx,
             ulong             v ) {
  if( FD_UNLIKELY( !ctx->epoch_info || v>=ctx->epoch_info->validator_cnt ) ) return 0UL;
  return ag_epoch_info_validator( ctx->epoch_info, v )->stake;
}

/* epoch_set / epoch_info_vtrs return the entry / validator set for `epoch`,
   or NULL if that epoch is not retained in the window. */

static vtr_epoch_set_t const *
epoch_set( fd_votor_tile_t const * ctx,
           ulong                   epoch ) {
  vtr_epoch_set_t const * s = &ctx->vtr_epoch_stakes[ epoch % VTR_EPOCH_WINDOW ];
  return s->epoch==epoch ? s : NULL;
}

static ag_epoch_info_t const *
epoch_info_vtrs( fd_votor_tile_t const * ctx,
                 ulong                   epoch ) {
  vtr_epoch_set_t const * s = epoch_set( ctx, epoch );
  return s ? s->info : NULL;
}

// ./projects/alpenglow/src/consensus/votor.rs:L306

static void
schedule_timeout( fd_votor_tile_t * ctx,
                  ulong             slot ) {
  long  now   = fd_log_wallclock();
  ulong first = ag_alpenglow_first_slot_in_window( slot );
  fd_timeout_t * timeout = fd_timeout_pool_ele_acquire( ctx->timeouts_pool );
  timeout->slot = slot;

  /* TODO, ignoring first shred timeout for now */
  timeout->ts   = now + AG_ALPENGLOW_DELTA_TIMEOUT_NS
                      + (long)( slot - first + 1UL ) * AG_ALPENGLOW_DELTA_BLOCK_NS;
  timeout->kind = AG_VOTOR_TIMEOUT_TIMEOUT;
  fd_timeout_heap_ele_insert( ctx->timeouts_heap, timeout, ctx->timeouts_pool );
}

/* own-vote loopback: Alpenglow::handle_all2all_message
   https://github.com/qkniep/alpenglow/blob/c415a42/src/consensus.rs#L330 */

static void
handle_votor_out( fd_votor_tile_t * ctx ) {
  ag_votor_out_t const * out = ag_votor_out( ctx->votor );

  for( ulong i=0UL; i<out->timeout_cnt; i++ ) {
    ag_votor_timeout_t const * t = &out->timeouts[ i ];
    if( t->kind==AG_VOTOR_TIMEOUT_TIMEOUT ) schedule_timeout( ctx, t->slot );
  }

  for( ulong i=0UL; i<out->msg_cnt; i++ ) {
    ag_consensus_message_t const * m = &out->msgs[ i ];
    if( m->kind==AG_CONSENSUS_MESSAGE_VOTE ) {
      /* Restamp the signer with our rank in the vote's slot epoch (the rank
         differs per epoch) before both broadcast and pool ingest. */
      ag_vote_t vote  = m->inner.vote;
      ulong     epoch = fd_slot_to_epoch( &ctx->epoch_schedule, ag_vote_slot( &vote ), NULL );
      vtr_epoch_set_t const * s = epoch_set( ctx, epoch );
      if( FD_UNLIKELY( !s ) ) FD_LOG_CRIT(( "own vote for epoch %lu but no validator epoch info", epoch ));
      ag_vote_set_signer( &vote, s->own_id );
      queue_vote( ctx, &vote );
      ag_pool_add_vote( ctx->pool, ctx->shred_version, &vote ); /* count our own vote; the pool events
                                               it emits are consumed by a later
                                               after_credit iteration */
    } else {
      queue_cert( ctx, &m->inner.cert );
    }
  }
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

  ag_votor_slot_done_t * msg = &pub->msg.slot_done;
  msg->replay_slot     = slot_completed->slot;
  msg->replay_bank_idx = slot_completed->bank_idx;

  /* Determine the reset target.  Query parents_ready for the next slot: if a
     valid parent is ready, reset onto it.  Otherwise reset onto the block we
     just completed. */

  msg->reset_slot     = slot_completed->slot;
  msg->reset_block_id = slot_completed->block_id;

  fd_hash_t notarized[1];
  if( FD_LIKELY( ag_pool_get_notarized_block( ctx->pool, slot_completed->slot, notarized ) ) ) {
    msg->reset_slot     = slot_completed->slot;
    msg->reset_block_id = *notarized;
  }
  ctx->reset_slot = msg->reset_slot;
}

/* maybe_publish_finalized emits FD_VOTOR_SIG_FINALIZED whenever the pool's
   finalized slot (cert frontier) advances, and FD_VOTOR_SIG_ROOTED whenever
   the bank root can advance, i.e. min(finalized, replayed) grows (Agave's
   scan of finalized_blocks for the max whose bank.is_frozen()).  Called from
   both the replay and cert RX paths so whichever of {finalized, replayed}
   advances second fires the root. */

static void
maybe_publish_finalized( fd_votor_tile_t * ctx ) {
  ulong fin = ag_pool_finalized_slot( ctx->pool );

  /* FINALIZED: consensus finalization advanced (cert-driven). */
  if( FD_UNLIKELY( fin>ctx->finalized_slot ) ) {
    fd_hash_t block_id[1];
    memset( block_id, 0, sizeof(fd_hash_t) );
    ag_pool_get_finalized_block( ctx->pool, fin, block_id );
    publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
    pub->sig                    = FD_VOTOR_SIG_FINALIZED;
    pub->msg.finalized.slot     = fin;
    pub->msg.finalized.block_id = *block_id;
    ctx->finalized_slot         = fin;
  }

  /* ROOTED: the bank root can advance to the highest finalized+replayed slot. */
  ulong rootable = fd_ulong_min( fin, ctx->highest_replayed_slot );
  if( FD_UNLIKELY( rootable>ctx->root_slot ) ) {
    /* block id of the rootable slot: prefer the certified hash (notar or
       fast-final cert; a slow Final cert carries no hash); at the replay
       frontier fall back to the block we just replayed there.  If neither
       is known (cert lost, e.g. dropped fragmented stream) hold the root
       and retry on the next advance -- never publish a zero block id
       (replay FD_TESTs the block id lookup). */
    fd_hash_t block_id[1];
    int have_id = ag_pool_get_finalized_block( ctx->pool, rootable, block_id );
    if( FD_UNLIKELY( !have_id && rootable==ctx->highest_replayed_slot ) ) {
      *block_id = ctx->highest_replayed_block_id;
      have_id   = 1;
    }
    if( FD_LIKELY( have_id ) ) {
      publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
      pub->sig                 = FD_VOTOR_SIG_ROOTED;
      pub->msg.rooted.slot     = rootable;
      pub->msg.rooted.block_id = *block_id;
      ctx->root_slot           = rootable;
      ctx->root_block_id       = *block_id; /* keep the root block id for the next pool rebuild */
      FD_LOG_INFO(( "votor rooted slot %lu", rootable ));
    }
  }
}

/* votor_set_active_epoch switches the pool / votor to `epoch`'s validator set,
   rebuilding them (which drops in-flight per-slot state -- acceptable across an
   epoch boundary, where the root advances at most one epoch).  Returns 0 if
   `epoch` is not in the window (caller keeps the current active epoch). */

static int
votor_set_active_epoch( fd_votor_tile_t * ctx,
                        ulong             epoch ) {
  vtr_epoch_set_t * s = &ctx->vtr_epoch_stakes[ epoch % VTR_EPOCH_WINDOW ];
  if( FD_UNLIKELY( s->epoch!=epoch ) ) return 0;

  ctx->active_epoch = epoch;
  ctx->epoch        = epoch;
  ctx->epoch_info   = s->info;
  ctx->own_id       = s->own_id; /* 0 (observe-only) when !have_own_id */

  ag_validator_info_t const * vset = ag_epoch_info_validators( s->info );
  ctx->pool = ag_pool_join( ag_pool_new( ag_pool_leave( ctx->pool ),
                                         ctx->slot_max, ctx->validator_max, ctx->blockid_max,
                                         ctx->own_id, vset, s->validator_cnt, ctx->seed,
                                         ctx->root_slot, &ctx->root_block_id ) );
  FD_TEST( ctx->pool );

  ctx->votor = ag_votor_join( ag_votor_new( ag_votor_leave( ctx->votor ),
                                            ctx->slot_max, (ushort)ctx->own_id, ctx->voting_key, ctx->shred_version, ctx->seed ) );
  FD_TEST( ctx->votor );

  FD_LOG_NOTICE(( "votor active epoch -> %lu (%lu validators, own_id %u, staked=%d)",
                  epoch, s->validator_cnt, (uint)s->own_id, s->have_own_id ));
  return 1;
}

/* Alpenglow::handle_disseminator_shred
   https://github.com/qkniep/alpenglow/blob/c415a42/src/consensus.rs#L349

   Returns 1 if backpressure is requested (halt_signing), 0 otherwise. */

static int
handle_replay_message( fd_votor_tile_t *   ctx,
                       ulong               sig,
                       void const *        msg,
                       ulong               tsorig FD_PARAM_UNUSED,
                       fd_stem_context_t * stem FD_PARAM_UNUSED ) {
  switch( sig ) {

  case REPLAY_SIG_SLOT_COMPLETED: {
    fd_replay_slot_completed_t const * slot_completed = fd_type_pun_const( msg );


    if( FD_UNLIKELY( ctx->halt_signing ) ) return 1; /* backpressure during halt_signing */

    ctx->init = 1;

    /* 0. Switch the active consensus epoch to the replayed tip's epoch if it
          changed and we have that epoch's validator set.  This rebuilds the
          pool / votor, so it must run before we register the block below.  At
          snapshot boot replay publishes both epoch E and E+1 before any slot
          completes, so the set is present. */

    if( FD_LIKELY( ctx->have_schedule ) ) {
      if( FD_UNLIKELY( ctx->active_epoch==ULONG_MAX ) ) {
        /* First completion after boot: adopt the snapshot block (this slot's
           parent) as the consensus root so the pool is built rooted there
           instead of genesis. */
        ctx->root_slot     = slot_completed->parent_slot;
        ctx->root_block_id = slot_completed->parent_block_id;
      }
      ulong tip_epoch = fd_slot_to_epoch( &ctx->epoch_schedule, slot_completed->slot, NULL );
      if( FD_UNLIKELY( tip_epoch!=ctx->active_epoch ) ) {
        // TODO verify that this is fine??
        if( FD_UNLIKELY( !votor_set_active_epoch( ctx, tip_epoch ) ) ) {
          FD_LOG_WARNING(( "no validator set for tip epoch %lu (slot %lu); keeping epoch %lu",
                           tip_epoch, slot_completed->slot, ctx->active_epoch ));
        }
      }
    }

    /* 1. Build block / parent identifiers from the replay frag. */

    ag_block_id_t block  = { .slot = slot_completed->slot,        .hash = slot_completed->block_id        };
    ag_block_id_t parent = { .slot = slot_completed->parent_slot, .hash = slot_completed->parent_block_id };

    /* 2. PoolImpl::add_block
          https://github.com/qkniep/alpenglow/blob/c415a42/src/consensus/pool.rs#L500 */

    if( FD_LIKELY( block.slot>parent.slot ) ) {
      ag_pool_add_block( ctx->pool, &block, &parent );
    }

    /* 3. BlockstoreEvent (FirstShred + Block).
          https://github.com/qkniep/alpenglow/blob/c415a42/src/consensus/blockstore.rs#L27 */

    {
      ag_votor_blockstore_event_t fs = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED };
      fs.inner.first_shred = block.slot;
      ag_votor_handle_blockstore_event( ctx->votor, &fs );
      handle_votor_out( ctx );
    }
    {
      ag_votor_blockstore_event_t b = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_BLOCK };
      b.inner.block.slot            = block.slot;
      b.inner.block.block_id        = block;
      b.inner.block.parent_block_id = parent;
      ag_votor_handle_blockstore_event( ctx->votor, &b );
      handle_votor_out( ctx );
    }

    /* 4. Replay froze this slot's bank -> advance our frozen-bank frontier
          (the analog of Agave's VotorEvent::Block / bank.is_frozen()), then
          check for finalization / root advancement. */

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

  case REPLAY_SIG_SLOT_DEAD: {
    fd_replay_slot_dead_t const * slot_dead = fd_type_pun_const( msg );

    if( FD_UNLIKELY( slot_dead->slot < ctx->root_slot ) ) return 0; /* ignore dead slots before root */
    ag_votor_blockstore_event_t ib = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK };
    ib.inner.invalid_block = slot_dead->slot;
    ag_votor_handle_blockstore_event( ctx->votor, &ib );
    handle_votor_out( ctx );
    return 0;
  }

  case REPLAY_SIG_FINAL_CERT: {
    /* finalization cert(s) parsed out of an Alpenglow block footer, already
       verified by replay (verify_footer_final_cert). */
    if( FD_UNLIKELY( !ctx->have_schedule ) ) return 0;
    fd_replay_final_cert_t const * final_cert = fd_type_pun_const( msg );
    for( ulong i=0UL; i<final_cert->cert_cnt; i++ ) {
      ag_cert_t const * cert = fd_type_pun_const( &final_cert->certs[ i ] );
      ulong cert_epoch = fd_slot_to_epoch( &ctx->epoch_schedule, ag_cert_slot( cert ), NULL );
      ag_epoch_info_t const * ei = epoch_info_vtrs( ctx, cert_epoch );
      if( FD_UNLIKELY( !ei ) ) FD_LOG_CRIT(( "no validator epoch info for epoch %lu", cert_epoch ));
      int err = ag_pool_add_cert( ctx->pool, ctx->shred_version, cert, ei );
      /* must succeed because this is from the replay tile */
      if( FD_UNLIKELY( err!=AG_POOL_SUCCESS && err!=AG_ADD_CERT_ERR_DUPLICATE && err!=AG_ADD_CERT_ERR_SLOT_OUT_OF_BOUNDS ) ) {
        FD_LOG_CRIT(( "ag_pool_add_cert failed for cert %lu: %d. first unpruned slot: %lu, slot: %lu, finalized slot: %lu",
                      i, err, ag_pool_first_unpruned_slot( ctx->pool ), ag_cert_slot( cert ), ag_pool_finalized_slot( ctx->pool ) ));
      }
    }
    maybe_publish_finalized( ctx );
    return 0;
  }

  default:
    return 0;
  }
}

/* peer_table_remove drops the peer occupying gossip contact-info slot idx (if
   any), closing its connection and freeing its pool element. */

static void
peer_table_remove( fd_votor_tile_t * ctx,
                   ulong             idx ) {
  if( FD_UNLIKELY( idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) return;
  fd_pubkey_t zero; fd_memset( &zero, 0, sizeof(fd_pubkey_t) );
  fd_pubkey_t key = ctx->peer_by_idx[ idx ];
  if( FD_LIKELY( fd_pubkey_eq( &key, &zero ) ) ) return; /* empty slot */
  peer_t * peer = peer_map_ele_query( ctx->peer_map, &key, NULL, ctx->peer_pool );
  if( FD_LIKELY( peer ) ) {
    if( FD_UNLIKELY( peer->conn ) ) {
      fd_quic_conn_set_context( peer->conn, NULL ); /* a deferred conn_final must not touch the freed peer */
      fd_quic_conn_close( peer->conn, 0U );
    }
    peer_map_ele_remove( ctx->peer_map, &key, NULL, ctx->peer_pool );
    peer_pool_ele_release( ctx->peer_pool, peer );
  }
  memset( &ctx->peer_by_idx[ idx ], 0, sizeof(fd_pubkey_t) );
}

/* handle_contact_info_remove handles a gossip ContactInfo *remove* update,
   which carries only the contact-info table index. */

static void
handle_contact_info_remove( fd_votor_tile_t *                  ctx,
                            fd_gossip_update_message_t const * msg ) {
  peer_table_remove( ctx, msg->contact_info_remove->idx );
}

/* handle_contact_info_update upserts the peer identified by a gossip
   ContactInfo update (origin pubkey + its advertised alpenglow QUIC socket)
   into the connection table and, if it is new, opens an outbound client
   connection to it.  Peers that do not advertise an alpenglow socket are
   ignored — only Alpenglow participants run one, so this naturally bounds the
   table to the participant set. */

static void
handle_contact_info_update( fd_votor_tile_t *                  ctx,
                            fd_gossip_update_message_t const * msg ) {
  ulong idx = msg->contact_info->idx;
  if( FD_UNLIKELY( idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) return;

  fd_pubkey_t zero; fd_memset( &zero, 0, sizeof(fd_pubkey_t) );
  fd_pubkey_t key = FD_LOAD( fd_pubkey_t, msg->origin );

  /* The advertised alpenglow socket (IPv4 only). */
  fd_gossip_socket_t const * sock = &msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW ];
  uint   ip4  = sock->is_ipv6 ? 0U : sock->ip4;
  ushort port = fd_ushort_bswap( sock->port );

  /* If gossip reused this index for a different identity, drop the prior one. */
  fd_pubkey_t prev = ctx->peer_by_idx[ idx ];
  if( FD_UNLIKELY( !fd_pubkey_eq( &prev, &zero ) && !fd_pubkey_eq( &prev, &key ) ) ) peer_table_remove( ctx, idx );

  /* Only track peers that advertise a routable alpenglow socket. */
  if( FD_UNLIKELY( !ip4 || !port ) ) return;

  peer_t * peer = peer_map_ele_query( ctx->peer_map, &key, NULL, ctx->peer_pool );
  if( FD_UNLIKELY( !peer ) ) {
    if( FD_UNLIKELY( !peer_pool_free( ctx->peer_pool ) ) ) {
      FD_LOG_WARNING(( "votor peer connection table full (%lu); dropping peer", VTR_MAX ));
      return;
    }
    peer = peer_pool_ele_acquire( ctx->peer_pool );
    peer->pubkey         = key;
    peer->ip4            = 0U;
    peer->port           = 0;
    peer->conn           = NULL;
    peer->last_connected = 0L;
    peer_map_ele_insert( ctx->peer_map, peer, ctx->peer_pool );
    ctx->peer_by_idx[ idx ] = key;
  }

  /* Update the endpoint; drop any stale conn if it moved. */
  if( FD_UNLIKELY( peer->ip4!=ip4 || peer->port!=port ) ) {
    if( FD_UNLIKELY( peer->conn ) ) {
      fd_quic_conn_set_context( peer->conn, NULL );
      fd_quic_conn_close( peer->conn, 0U );
      peer->conn = NULL;
    }
    peer->ip4  = ip4;
    peer->port = port;
  }

  /* DEBUG (bring-up): only dial one specific peer, and log its contact info as
     it arrives over gossip.  TODO: remove. */
  FD_BASE58_ENCODE_32_BYTES( peer->pubkey.uc, peer_b58 );
  if( strcmp( peer_b58, "8hxz3oFNhR7AgHuaqW85t56N27vaJ38Gmb8EBgf5bRa3" ) ) return;

  /* Open an outbound QUIC client connection so we can broadcast to this peer.
     The client uses its own alpenglow UDP source port.  The peer is stashed as the conn's user
     context so quic_client_conn_final can clear peer->conn in O(1).  Reconnects
     are throttled (>=2s between attempts) so a peer whose connection keeps
     failing to establish is not hammered. */
  if( FD_UNLIKELY( !ctx->quic_client ) ) return;                          /* QUIC disabled (unit test) */
  if( FD_LIKELY  (  peer->conn        ) ) return;                          /* already connected         */
  if( FD_UNLIKELY( peer->last_connected + (long)2e9 > ctx->now ) ) return; /* reconnect throttle        */
  FD_BASE58_ENCODE_32_BYTES( peer->pubkey.uc, pubkey_str );
  FD_LOG_NOTICE(( "votor connecting to quic server %s at " FD_IP4_ADDR_FMT ":%u",
                  pubkey_str, FD_IP4_ADDR_FMT_ARGS( peer->ip4 ), (uint)peer->port ));
  fd_quic_conn_t * conn = fd_quic_connect( ctx->quic_client,
                                           peer->ip4, peer->port, /* dst */
                                           ctx->src_ip_addr, ctx->alpenglow_client_port,  /* src */
                                           ctx->now );
  peer->last_connected = ctx->now;
  if( FD_UNLIKELY( !conn ) ) return; /* out of conn / handshake slots; retried on the next update */
  fd_quic_conn_set_context( conn, peer );
  peer->conn = conn;
}



/* count_drop bumps an ingress drop counter and logs on powers of two. */

static inline void
count_drop( ulong *      cnt,
            char const * what ) {
  (*cnt)++;
  if( FD_UNLIKELY( fd_ulong_is_pow2( *cnt ) ) ) FD_LOG_WARNING(( "votor rx drop: %s (cnt %lu)", what, *cnt ));
}

/* Alpenglow::handle_all2all_message
   https://github.com/qkniep/alpenglow/blob/c415a42/src/consensus.rs#L330 */

static void
handle_all2all_message( fd_votor_tile_t *              ctx,
                        ag_consensus_message_t const * msg ) {

  switch( msg->kind ) {
  case AG_CONSENSUS_MESSAGE_VOTE: {
    int err = ag_pool_add_vote( ctx->pool, ctx->shred_version, &msg->inner.vote );
    switch( err ) {
    case AG_POOL_SUCCESS:
      maybe_publish_finalized( ctx );
      break;
    case AG_ADD_VOTE_ERR_SLASHABLE:
      FD_LOG_WARNING(( "slashable offence detected: validator %u slot %lu", ag_vote_signer( &msg->inner.vote ), ag_vote_slot( &msg->inner.vote ) ));
      break;
    default:
      /* invalid votes are ignored (consensus.rs:338); duplicates and
         out-of-bounds slots are routine from network peers */
      count_drop( &ctx->rx_drop_vote, ag_pool_strerror( err ) );
      break;
    }
    break;
  }
  case AG_CONSENSUS_MESSAGE_CERT: {
    /* Bank::get_rank_map
       https://github.com/anza-xyz/alpenglow/blob/9f284c913f/runtime/src/bank.rs#L2352 */
    ulong cert_slot  = ag_cert_slot( &msg->inner.cert );
    ulong cert_epoch = fd_slot_to_epoch( &ctx->epoch_schedule, cert_slot, NULL );
    ag_epoch_info_t const * ei = epoch_info_vtrs( ctx, cert_epoch );
    if( FD_UNLIKELY( !ei ) ) break;

    int err = ag_pool_add_cert( ctx->pool, ctx->shred_version, &msg->inner.cert, ei );
    if( FD_LIKELY( err==AG_POOL_SUCCESS ) ) {
      maybe_publish_finalized( ctx );
    } else {
      count_drop( &ctx->rx_drop_cert, ag_pool_strerror( err ) );
    }
    break;
  }
  default: break;
  }
}

FD_STATIC_ASSERT( FD_EPOCH_INFO_BLS_PUBKEY_SZ==AG_AGGSIG_PUBKEY_COMPRESSED_SZ, bls_pubkey_sz );

/* update_epoch_vtrs rebuilds the active epoch's validator set from an EPOCH
   msg (the staked validator set + stakes).  The pool and votor are rebuilt
   against the new set. */

FD_FN_UNUSED void
update_epoch_vtrs( fd_votor_tile_t *              ctx,
                   fd_epoch_info_msg_t const *    msg,
                   fd_vote_stake_weight_t const * stakes,
                   ulong                          stake_cnt ) {

  uchar const * bls_pubkeys = fd_epoch_info_msg_bls_pubkeys( msg );

  /* Rank the staked voters: drop zero-stake / bad-BLS voters, order by
     stake descending tie-broken by the compressed BLS pubkey
     (BLSPubkeyToRankMap::new; see ag_epoch_info_rank).  This ordering is
     intentionally votor-local -- it must NOT reuse the stake-weight sort
     (vote-key tie-break) that drives the leader schedule. */
  ulong cnt = ag_epoch_info_rank( ctx->validators, VTR_MAX, stakes, stake_cnt, bls_pubkeys );
  if( FD_UNLIKELY( !cnt ) ) {
    FD_LOG_WARNING(( "epoch %lu has no ranked validators; skipping", msg->epoch ));
    return;
  }

  /* Locate our own rank. */
  ushort own_id      = 0;
  int    have_own_id = 0;
  for( ulong r=0UL; r<cnt; r++ ) {
    ag_validator_info_t const * vi = &ctx->validators[ r ];
    if( FD_LIKELY( memcmp( vi->pubkey.uc, ctx->identity_key->uc, sizeof(fd_pubkey_t) ) ) ) continue;
    own_id      = (ushort)r;
    have_own_id = 1;
    /* voting_key is the real BLS secret derived once in privileged_init (do
       NOT overwrite it here).  Sanity check: the pubkey it derives to must
       equal the on-chain registered BLS pubkey for our vote account (just
       decompressed into vi->voting_pubkey).  A mismatch means our votes will
       silently fail signature verification, so shout about it. */
    ag_aggsig_pk_t derived[1];
    ag_aggsig_sk_to_pk( derived, ctx->voting_key );
    if( FD_UNLIKELY( memcmp( derived->v, vi->voting_pubkey.v, AG_AGGSIG_PUBKEY_SZ ) ) ) {
      FD_LOG_WARNING(( "BLS KEY MISMATCH: derived voting pubkey != on-chain registered key "
                       "(epoch %lu, rank %lu) -- our votes will NOT verify; check the "
                       "authorized-voter keypair matches the vote account's BLS registration",
                       msg->epoch, r ));
    } else {
      FD_LOG_NOTICE(( "BLS voting key OK: derived pubkey matches on-chain registration (epoch %lu, rank %lu)",
                      msg->epoch, r ));
    }
  }

  /* Insert (or refresh) this epoch's set into the window without disturbing
     other epochs.  The pool / votor are NOT rebuilt here -- the active epoch is
     switched lazily from the replayed tip in handle_replay_message. */
  ctx->epoch_schedule = msg->epoch_schedule;
  ctx->have_schedule  = 1;

  vtr_epoch_set_t * s = &ctx->vtr_epoch_stakes[ msg->epoch % VTR_EPOCH_WINDOW ];
  /* Don't let a stale (older) re-publish evict a newer epoch sharing this ring
     slot.  Refresh (==) and normal advance (older slot occupant) proceed. */
  if( FD_UNLIKELY( s->epoch!=ULONG_MAX && s->epoch>msg->epoch ) ) {
    FD_LOG_WARNING(( "ignoring stale epoch %lu (slot holds newer epoch %lu)", msg->epoch, s->epoch ));
    return;
  }
  ag_epoch_info_join( ag_epoch_info_new( s->mem, ctx->validators, cnt ) );
  s->epoch         = msg->epoch;
  s->info          = ag_epoch_info_join( s->mem );
  s->validator_cnt = cnt;
  s->own_id        = own_id;
  s->have_own_id   = have_own_id;
  FD_TEST( s->info );

  /* If we refreshed the currently-active epoch, re-point the verification alias
     at the new set (without rebuilding the pool / dropping state mid-epoch). */
  if( FD_UNLIKELY( msg->epoch==ctx->active_epoch ) ) ctx->epoch_info = s->info;

  FD_LOG_NOTICE(( "epoch %lu validator set: %lu validators (own_id %u, staked=%d)",
                  msg->epoch, cnt, (uint)own_id, have_own_id ));
}

/* QUIC ingress is enabled when the tile carries QUIC config (set by the
   topology).  The unit test constructs a tile without QUIC config, in
   which case the tile runs consensus only (ctx->quic_server stays NULL). */

FD_FN_PURE static inline int
votor_quic_enabled( fd_topo_tile_t const * tile ) {
  return tile->quic.max_concurrent_connections!=0UL;
}

static inline fd_quic_limits_t
quic_server_limits( fd_topo_tile_t const * tile ) {
  fd_quic_limits_t server_limits = {
    .conn_cnt                    = tile->quic.max_concurrent_connections,
    .handshake_cnt               = tile->quic.max_concurrent_handshakes,
    .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
    .inflight_frame_cnt          = 64UL * tile->quic.max_concurrent_connections,
    .min_inflight_frame_cnt_conn = 32UL
  };
  if( FD_UNLIKELY( !fd_quic_footprint( &server_limits ) ) ) FD_LOG_ERR(( "Invalid QUIC limits in config" ));
  return server_limits;
}

/* quic_client_limits sizes the outbound (broadcast) QUIC client instance for
   one persistent connection per Alpenglow participant (VTR_MAX), each carrying
   short-lived unidirectional streams (one ConsensusMessage per stream). */

static inline fd_quic_limits_t
quic_client_limits( fd_topo_tile_t const * tile ) {
  (void)tile;
  fd_quic_limits_t client_limits = {
    .conn_cnt                    = fd_ulong_pow2_up( VTR_MAX ),
    .handshake_cnt               = 256UL,
    .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
    .inflight_frame_cnt          = 16UL * fd_ulong_pow2_up( VTR_MAX ),
    .min_inflight_frame_cnt_conn = 4UL,
    .stream_id_cnt               = 16UL,
    .stream_pool_cnt             = 4096UL,
    .tx_buf_sz                   = 2048UL  /* >= max serialized ConsensusMessage */
  };
  if( FD_UNLIKELY( !fd_quic_footprint( &client_limits ) ) ) FD_LOG_ERR(( "Invalid votor client QUIC limits" ));
  return client_limits;
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
  l = FD_LAYOUT_APPEND( l, ag_votor_align(),          ag_votor_footprint( slot_max )                           );
  l = FD_LAYOUT_APPEND( l, ag_pool_align(),           ag_pool_footprint( slot_max, validator_max, blockid_max ) );
  l = FD_LAYOUT_APPEND( l, fd_timeout_heap_align(),   fd_timeout_heap_footprint( slot_max )                     );
  l = FD_LAYOUT_APPEND( l, fd_timeout_pool_align(),   fd_timeout_pool_footprint( slot_max )                     );
  for( ulong i=0UL; i<VTR_EPOCH_WINDOW; i++ )
    l = FD_LAYOUT_APPEND( l, ag_epoch_info_align(),   ag_epoch_info_footprint( VTR_MAX )                       );
  l = FD_LAYOUT_APPEND( l, publishes_align(),         publishes_footprint( pub_max )                           );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),   peer_pool_footprint( VTR_MAX )                                       );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),    peer_map_footprint( peer_map_chain_cnt_est( VTR_MAX ) )        );
  l = FD_LAYOUT_APPEND( l, alignof(fd_pubkey_t),      sizeof(fd_pubkey_t)*FD_CONTACT_INFO_TABLE_SIZE                             );
  if( votor_quic_enabled( tile ) ) {
    fd_quic_limits_t server_limits = quic_server_limits( tile );
    l = FD_LAYOUT_APPEND( l, fd_quic_align(),         fd_quic_footprint( &server_limits )                             );
    fd_quic_limits_t client_limits = quic_client_limits( tile );
    l = FD_LAYOUT_APPEND( l, fd_quic_align(),         fd_quic_footprint( &client_limits )                            );
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
  void  * votor         = FD_SCRATCH_ALLOC_APPEND( l, ag_votor_align(),         ag_votor_footprint( slot_max )                           );
  void  * pool          = FD_SCRATCH_ALLOC_APPEND( l, ag_pool_align(),          ag_pool_footprint( slot_max, validator_max, blockid_max ) );
  void  * timeouts_heap = FD_SCRATCH_ALLOC_APPEND( l, fd_timeout_heap_align(),  fd_timeout_heap_footprint( slot_max )                     );
  void  * timeouts_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_timeout_pool_align(),  fd_timeout_pool_footprint( slot_max )                     );
  void  * epoch_mem[ VTR_EPOCH_WINDOW ];
  for( ulong i=0UL; i<VTR_EPOCH_WINDOW; i++ )
    epoch_mem[i]        = FD_SCRATCH_ALLOC_APPEND( l, ag_epoch_info_align(),    ag_epoch_info_footprint( VTR_MAX )                       );
  void  * publishes     = FD_SCRATCH_ALLOC_APPEND( l, publishes_align(),        publishes_footprint( pub_max )                           );
  void  * peer_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),  peer_pool_footprint( VTR_MAX )                                );
  void  * peer_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),   peer_map_footprint( peer_map_chain_cnt_est( VTR_MAX ) ) );
  void  * peer_by_idx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pubkey_t),     sizeof(fd_pubkey_t)*FD_CONTACT_INFO_TABLE_SIZE                       );
  void  * quic_server_mem        = NULL;
  void  * quic_client_mem = NULL;
  if( votor_quic_enabled( tile ) ) {
    fd_quic_limits_t server_limits = quic_server_limits( tile );
    quic_server_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &server_limits ) );
    fd_quic_limits_t client_limits = quic_client_limits( tile );
    quic_client_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &client_limits ) );
  }
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  /* Bootstrap single-validator set (just us at index 0).  This lets the pool
     and votor format before we have received the real epoch set. */

  ctx->own_id        = 0UL;
  ctx->validator_cnt = 1UL;
  memset( &ctx->validators[ 0 ], 0, sizeof(ag_validator_info_t) );
  ctx->validators[ 0 ].id    = 0UL;
  ctx->validators[ 0 ].stake = 1UL;
  ag_aggsig_sk_to_pk( &ctx->validators[ 0 ].voting_pubkey, ctx->voting_key );

  ctx->slot_max      = slot_max;
  ctx->validator_max = validator_max;
  ctx->blockid_max   = blockid_max;

  for( ulong i=0UL; i<VTR_EPOCH_WINDOW; i++ ) {
    ctx->vtr_epoch_stakes[i].epoch = ULONG_MAX;
    ctx->vtr_epoch_stakes[i].info  = NULL;
    ctx->vtr_epoch_stakes[i].mem   = epoch_mem[i];
  }
  ctx->active_epoch  = ULONG_MAX;
  ctx->epoch_info    = NULL;
  ctx->have_schedule = 0;

  ctx->pool = ag_pool_join( ag_pool_new( pool, slot_max, validator_max, blockid_max,
                                         ctx->own_id, ctx->validators, 1UL, ctx->seed,
                                         0UL, NULL /* genesis baseline; rebuilt rooted at the snapshot on the first slot */ ) );

  ctx->votor = ag_votor_join( ag_votor_new( votor, slot_max, (ushort)ctx->own_id, ctx->voting_key, ctx->shred_version, ctx->seed ) );

  ctx->timeouts_heap = fd_timeout_heap_join( fd_timeout_heap_new( timeouts_heap, slot_max ) );
  ctx->timeouts_pool = fd_timeout_pool_join( fd_timeout_pool_new( timeouts_pool, slot_max ) );

  ctx->publishes = publishes_join( publishes_new( publishes, pub_max ) );

  ctx->peer_pool   = peer_pool_join( peer_pool_new( peer_pool_mem, VTR_MAX ) );
  ctx->peer_map    = peer_map_join ( peer_map_new ( peer_map_mem, peer_map_chain_cnt_est( VTR_MAX ), ctx->seed ) );
  ctx->peer_by_idx = peer_by_idx;
  memset( ctx->peer_by_idx, 0, sizeof(fd_pubkey_t)*FD_CONTACT_INFO_TABLE_SIZE );
  FD_TEST( ctx->peer_pool );
  FD_TEST( ctx->peer_map  );

  /* QUIC server + client memory is formatted here; the connection config,
     validator identity key, TX aio and net links are wired in
     unprivileged_init (which has the topology).  NULL when QUIC is disabled
     (unit test). */
  ctx->quic_server        = NULL;
  ctx->quic_client = NULL;
  if( quic_server_mem ) {
    fd_quic_limits_t server_limits = quic_server_limits( tile );
    ctx->quic_server = fd_quic_join( fd_quic_new( quic_server_mem, &server_limits ) );
    FD_TEST( ctx->quic_server );
    fd_quic_limits_t client_limits = quic_client_limits( tile );
    ctx->quic_client = fd_quic_join( fd_quic_new( quic_client_mem, &client_limits ) );
    FD_TEST( ctx->quic_client );
  }

  FD_TEST( ctx->pool );
  FD_TEST( ctx->votor );
  FD_TEST( ctx->publishes );

  ctx->halt_signing   = 0;
  ctx->shred_version  = 0;
  ctx->init           = 0;

  ctx->epoch          = ULONG_MAX;
  ctx->root_slot      = ULONG_MAX; /* no root until the first slot completion adopts the snapshot */
  fd_memset( &ctx->root_block_id, 0, sizeof(fd_hash_t) );
  ctx->finalized_slot = 0UL;
  ctx->highest_replayed_slot = 0UL;
  fd_memset( &ctx->highest_replayed_block_id, 0, sizeof(fd_hash_t) );
  ctx->reset_slot     = 0UL;

  return ctx;
}

/* quic_server_conn_new fires when an inbound client finishes its handshake
   with our server -- i.e. a peer has established a link over which it will
   broadcast its votes/certs to us.  fd_tls requires the client to present a
   raw-pubkey ed25519 cert (chain length 1) and a valid CertificateVerify, so
   on a completed handshake hs.srv.client_pubkey holds the cryptographically
   verified peer identity; it should match the peer's node_pubkey in the
   validator set. */

static void
quic_server_conn_new( fd_quic_conn_t * conn,
                      void *           quic_ctx ) {
  (void)quic_ctx;
  fd_quic_tls_hs_t const * hs = conn->tls_hs;
  if( FD_UNLIKELY( !hs ) ) return; /* no handshake state (should not happen on conn_new) */
  FD_BASE58_ENCODE_32_BYTES( hs->hs.srv.client_pubkey, pubkey_str );
  FD_LOG_NOTICE(( "votor accepted connection from quic client %s at " FD_IP4_ADDR_FMT ":%u",
                  pubkey_str, FD_IP4_ADDR_FMT_ARGS( conn->peer[0].ip_addr ), (uint)conn->peer[0].udp_port ));
}

static void
quic_server_conn_final( fd_quic_conn_t * conn,
                        void *           quic_ctx ) {
  (void)conn; (void)quic_ctx;
}

/* quic_client_conn_final clears the owning peer's conn pointer when an outbound
   client connection dies, so handle_contact_info_update re-dials it on the next
   ContactInfo update.  The peer is the conn's user context (set when the conn is
   opened); NULL once the peer has been removed (peer_table_remove nulls it
   first), in which case this is a no-op. */

static void
quic_client_conn_final( fd_quic_conn_t * conn,
                        void *           quic_ctx ) {
  (void)quic_ctx;
  peer_t * peer = fd_quic_conn_get_context( conn );
  if( FD_LIKELY( peer ) ) peer->conn = NULL;
}

/* quic_client_conn_hs_complete fires when an outbound client connection we
   dialed in handle_contact_info_update finishes its handshake -- i.e. the
   broadcast link to this peer is now live.  The peer is the conn's user
   context (NULL once it has been removed, in which case this is a no-op). */

static void
quic_client_conn_hs_complete( fd_quic_conn_t * conn,
                              void *           quic_ctx ) {
  (void)quic_ctx;
  peer_t * peer = fd_quic_conn_get_context( conn );
  if( FD_UNLIKELY( !peer ) ) return;
  FD_BASE58_ENCODE_32_BYTES( peer->pubkey.uc, pubkey_str );
  FD_LOG_NOTICE(( "votor established connection with quic server %s at " FD_IP4_ADDR_FMT ":%u",
                  pubkey_str, FD_IP4_ADDR_FMT_ARGS( peer->ip4 ), (uint)peer->port ));
}

static int
quic_server_stream_rx( fd_quic_conn_t * conn,
                       ulong            stream_id,
                       ulong            offset,
                       uchar const *    data,
                       ulong            data_sz,
                       int              fin ) {
  (void)stream_id;
  fd_votor_tile_t * ctx = conn->quic->cb.quic_ctx;
  if( FD_UNLIKELY( !(offset==0UL && fin) ) ) { count_drop( &ctx->rx_drop_frag, "fragmented stream (TODO reassemble)" ); return FD_QUIC_SUCCESS; }
  if( FD_UNLIKELY( !ctx->init || !ctx->have_schedule ) ) return FD_QUIC_SUCCESS; /* consensus not ready (pre first slot completion / epoch set) */
  ag_consensus_message_t msg[1];
  int err = ag_consensus_message_de( msg, data, data_sz, ctx->shred_version );
  switch( err ) {
  case AG_CONSENSUS_MESSAGE_DE_SUCCESS:           handle_all2all_message( ctx, msg );                                     break;
  case AG_CONSENSUS_MESSAGE_DE_ERR_SHRED_VERSION: count_drop( &ctx->rx_drop_shred_version, "shred_version mismatch"    ); break;
  case AG_CONSENSUS_MESSAGE_DE_ERR_UNSUPPORTED:   count_drop( &ctx->rx_drop_unsupported,   "unsupported version/kind"  ); break;
  default:                                        count_drop( &ctx->rx_drop_malformed,     "malformed consensus message" ); break;
  }
  return FD_QUIC_SUCCESS;
}

static ushort
votor_packet_dst_port( uchar const * l3,
                       ulong         l3_sz ) {
  if( FD_UNLIKELY( l3_sz<sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) ) ) return 0;
  fd_ip4_hdr_t const * ip4 = (fd_ip4_hdr_t const *)fd_type_pun_const( l3 );
  if( FD_UNLIKELY( FD_IP4_GET_VERSION( *ip4 )!=4 || ip4->protocol!=FD_IP4_HDR_PROTOCOL_UDP ) ) return 0;
  ulong ip4_hdr_sz = FD_IP4_GET_LEN( *ip4 );
  if( FD_UNLIKELY( ip4_hdr_sz<sizeof(fd_ip4_hdr_t) || ip4_hdr_sz+sizeof(fd_udp_hdr_t)>l3_sz ) ) return 0;
  fd_udp_hdr_t const * udp = (fd_udp_hdr_t const *)fd_type_pun_const( l3 + ip4_hdr_sz );
  return fd_ushort_bswap( udp->net_dport );
}

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
  fd_keyguard_client_sign( ctx->keyguard_client, signature, payload, 130UL, FD_KEYGUARD_SIGN_TYPE_ED25519 );
}

static void
quic_tls_keylog( void *       _ctx,
                 char const * line ) {
  fd_votor_tile_t *          ctx = _ctx;
  fd_io_buffered_ostream_t * os  = &ctx->keylog_stream;

  ulong line_sz = strlen( line )+1UL;
  ulong peek_sz = fd_io_buffered_ostream_peek_sz( os );
  if( FD_UNLIKELY( peek_sz<line_sz ) ) {
    int err = fd_io_buffered_ostream_flush( os );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_io_buffered_ostream_flush(keylog) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    peek_sz = fd_io_buffered_ostream_peek_sz( os );
  }
  if( FD_UNLIKELY( peek_sz<line_sz ) ) {
    FD_LOG_ERR(( "keylog buffer too small (buf_sz=%lu, line_sz=%lu)", peek_sz, line_sz ));
  }

  char * cur = fd_io_buffered_ostream_peek( os );
  cur = fd_cstr_append_text( cur, line, strlen( line ) );
  cur = fd_cstr_append_char( cur, '\n' );
  fd_io_buffered_ostream_seek( os, line_sz );
}

static inline void
before_credit( fd_votor_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  ctx->stem = stem;
  if( FD_LIKELY( ctx->quic_server ) ) {
    ctx->now = fd_log_wallclock();
    int busy = fd_quic_service( ctx->quic_server, ctx->now );
    busy    |= fd_quic_service( ctx->quic_client, ctx->now );
    *charge_busy = busy;
  }
}

static int
before_frag( fd_votor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)seq;
  /* Only the net_alpenglow links carry netmux-tagged frames; filter them
     to the alpenglow proto, and skip them entirely until the consensus core
     is initialized (first replayed slot) -- there is no pool to ingest into
     yet.  Consensus links are always processed. */
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_VOTOR ) ) {
    if( FD_UNLIKELY( !ctx->init ) ) return 1;
    return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_ALPENGLOW;
  }
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

  if( FD_UNLIKELY( ctx->keylog_stream.wbuf ) ) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now > ctx->keylog_next_flush ) ) {
      int err = fd_io_buffered_ostream_flush( &ctx->keylog_stream );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "fd_io_buffered_ostream_flush(keylog) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
      ctx->keylog_next_flush = now + FD_VOTOR_KEYLOG_FLUSH_INTERVAL_NS;
    }
  }

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
    if( FD_LIKELY( ctx->quic_server ) ) {
      fd_quic_set_identity_public_key( ctx->quic_server, ctx->identity_keyswitch->bytes );
      fd_quic_set_identity_public_key( ctx->quic_client, ctx->identity_keyswitch->bytes );
    }
    fd_keyswitch_state( ctx->identity_keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
    ctx->halt_signing = 1;
    ctx->identity_keyswitch->result = ctx->out_seq;
  }
}

static inline void
after_credit( fd_votor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {

  /* Votor::voting_loop
     https://github.com/qkniep/alpenglow/blob/c415a42/src/consensus/votor.rs#L109

     Drain the pool's votor_event_channel (Votor::pool_receiver) in place --
     the own-vote loopback in handle_votor_out appends to it while we
     iterate -- then the due timeouts (timeout_receiver). */

  int did_work = 0;

  ulong i = 0UL;
  while( i<ag_pool_votor_event_cnt( ctx->pool ) ) {
    ag_pool_event_t event = ag_pool_votor_event_channel( ctx->pool )[ i++ ];
    ag_votor_handle_pool_event( ctx->votor, &event );
    handle_votor_out( ctx );
    did_work = 1;
  }

  /* Drain the pool's repair channel (Pool::repair_sender): block
     versions that gathered (fallback) notar votes or certs but that we
     may not have locally.  Published as NOTARFB frags so the repair
     tile can fetch the missing version.  Must run before
     ag_pool_drain_channels, which resets the channel; the event loop
     above may append entries while it runs, hence the in-place
     iteration. */

  ulong r = 0UL;
  while( r<ag_pool_repair_cnt( ctx->pool ) ) {
    ag_block_id_t block_id = ag_pool_repair_channel( ctx->pool )[ r++ ];
    publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
    pub->sig                         = FD_VOTOR_SIG_NOTARFB;
    pub->msg.notar_fallback.slot     = block_id.slot;
    pub->msg.notar_fallback.block_id = block_id.hash;
    did_work = 1;
  }
  ag_pool_drain_channels( ctx->pool );

  while( fd_timeout_heap_ele_cnt( ctx->timeouts_heap ) ) {
    fd_timeout_t * timeout = fd_timeout_heap_ele_peek_min( ctx->timeouts_heap, ctx->timeouts_pool );
    if( timeout->ts>fd_log_wallclock() ) break;
    ag_votor_timeout_t event = { .kind = timeout->kind, .slot = timeout->slot };
    fd_timeout_heap_ele_remove_min( ctx->timeouts_heap, ctx->timeouts_pool );
    fd_timeout_pool_ele_release( ctx->timeouts_pool, timeout );
    ag_votor_handle_timeout_event( ctx->votor, &event );
    handle_votor_out( ctx );
    did_work = 1;
  }

  if( did_work ) {
    maybe_publish_finalized( ctx );
    *charge_busy = 1;
  }

  if( FD_LIKELY( !publishes_empty( ctx->publishes ) ) ) {
    /* pop_tail: everything pushes at the head, so tail-pop keeps FIFO
       order (replay relies on ROOTED slots arriving monotonically). */
    publish_t * pub = publishes_pop_tail_nocopy( ctx->publishes );
    ulong ts = fd_frag_meta_ts_comp( fd_tickcount() );

    /* TODO a2a broadcast */
    if( FD_UNLIKELY( pub->sig==FD_VOTOR_SIG_VOTE ) ) {
      uchar buf[ AG_VOTE_SERIALIZED_MAX ];
      FD_TEST( ag_vote_serialize( &pub->msg.vote, buf, sizeof(buf), ctx->shred_version ) );
      //TODO send
    }

    memcpy( fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk ), &pub->msg, sizeof(ag_votor_msg_t) );
    fd_stem_publish( stem, OUT_IDX, pub->sig, ctx->out_chunk, sizeof(ag_votor_msg_t), 0UL, ts, ts );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(ag_votor_msg_t), ctx->out_chunk0, ctx->out_wmark );
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
     ctx->net_buf in during_frag.  Dispatch by UDP destination port so a packet
     is only processed by the owning QUIC instance; fd_quic mutates packets in
     place while decrypting. */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_VOTOR ) ) {
    if( FD_LIKELY( ctx->quic_server && ctx->quic_client && sz>=sizeof(fd_eth_hdr_t) ) ) {
      uchar * l3    = ctx->net_buf + sizeof(fd_eth_hdr_t);
      ulong   l3_sz = sz - sizeof(fd_eth_hdr_t);
      ushort  dst_port = votor_packet_dst_port( l3, l3_sz );
      if( FD_LIKELY( dst_port==ctx->alpenglow_server_port ) ) {
        fd_quic_process_packet( ctx->quic_server, l3, l3_sz, ctx->now );
      } else if( FD_LIKELY( dst_port==ctx->alpenglow_client_port ) ) {
        fd_quic_process_packet( ctx->quic_client, l3, l3_sz, ctx->now );
      }
    }
    return 0;
  }

  if( FD_UNLIKELY( !ctx->in[ in_idx ].mcache_only && ( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) )
    FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY:
    /* may backpressure during halt_signing */
    return handle_replay_message( ctx, sig, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), tsorig, stem );
  case IN_KIND_GOSSIP: {
    fd_gossip_update_message_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    if(      sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO        ) handle_contact_info_update( ctx, msg );
    else if( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) handle_contact_info_remove( ctx, msg );
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
    if( FD_LIKELY( ctx->votor ) ) ag_votor_set_shred_version( ctx->votor, ctx->shred_version );
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

  /* TLS key log file (development only) */
  ctx->keylog_fd = -1;
  ctx->keylog_next_flush = 0L;
  memset( &ctx->keylog_stream, 0, sizeof(ctx->keylog_stream) );
  if( FD_UNLIKELY( strcmp( tile->quic.key_log_path, "" ) ) ) {
    ctx->keylog_fd = open( tile->quic.key_log_path, O_WRONLY|O_CREAT|O_APPEND, 0644 );
    if( FD_UNLIKELY( ctx->keylog_fd<0 ) )
      FD_LOG_ERR(( "open(%s, O_WRONLY|O_CREAT|O_APPEND, 0644) failed (%i-%s)",
                   tile->quic.key_log_path, errno, fd_io_strerror( errno ) ));
    fd_io_buffered_ostream_init( &ctx->keylog_stream, ctx->keylog_fd, ctx->keylog_buf, sizeof(ctx->keylog_buf) );
    FD_LOG_WARNING(( "Logging Votor QUIC encryption keys to %s", tile->quic.key_log_path ));
  }

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ctx->seed) ) );

  if( FD_UNLIKELY( !strcmp( tile->tower.identity_key, "" ) ) ) FD_LOG_ERR(( "missing [paths.identity_key]" ));

  /* BLSKeypair::derive_from_signer with BLS_KEYPAIR_DERIVE_SEED
     https://github.com/anza-xyz/alpenglow/blob/9f284c913f/votor-messages/src/consensus_message.rs#L18
     TODO: switch to the authorized-voter keypair (via the sign tile?). */

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
  ag_aggsig_sk_derive( ctx->voting_key, ikm, sizeof(ikm) );

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

  ulong sign_in_idx = ULONG_MAX;
  FD_TEST( tile->in_cnt<sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link      = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "replay_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch"  ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"    ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( FD_LIKELY( !strcmp( link->name, "net_alpenglow" ) ) ) ctx->in_kind[ i ] = IN_KIND_VOTOR;
    else if( FD_LIKELY( !strcmp( link->name, "sign_votor"    ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_SIGN;
      sign_in_idx = i;
    }
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

  /* QUIC ingress setup: validator identity, server config, TX aio (→
     net), and the votor_net out link.  init_choreo already formatted the
     fd_quic when QUIC is enabled. */
  if( FD_LIKELY( ctx->quic_server ) ) {
    if( FD_UNLIKELY( tile->out_cnt<2UL || strcmp( topo->links[ tile->out_link_id[ OUT_IDX_NET ] ].name, "votor_net" ) ) )
      FD_LOG_ERR(( "votor tile (with QUIC) requires a votor_net output link" ));

    if( FD_UNLIKELY( sign_in_idx==ULONG_MAX ) )
      FD_LOG_ERR(( "votor tile (with QUIC) requires a sign_votor input link" ));
    ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "votor_sign", tile->kind_id );
    if( FD_UNLIKELY( sign_out_idx==ULONG_MAX ) )
      FD_LOG_ERR(( "votor tile (with QUIC) requires a votor_sign output link" ));
    fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
    fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
    if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new(
          ctx->keyguard_client,
          sign_out->mcache,
          sign_out->dcache,
          sign_in->mcache,
          sign_in->dcache,
          sign_out->mtu ) ) ) ) {
      FD_LOG_ERR(( "fd_keyguard_client_new failed" ));
    }

    fd_aio_t * tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_tx_aio_send ) );
    if( FD_UNLIKELY( !tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

    if( FD_UNLIKELY( tile->quic.ack_delay_millis==0 ) ) FD_LOG_ERR(( "Invalid `ack_delay_millis`" ));
    if( FD_UNLIKELY( tile->quic.ack_delay_millis>=tile->quic.idle_timeout_millis ) ) FD_LOG_ERR(( "Invalid `ack_delay_millis`" ));

    ctx->quic_server->config.role                       = FD_QUIC_ROLE_SERVER;
    ctx->quic_server->config.idle_timeout               = tile->quic.idle_timeout_millis * (long)1e6;
    ctx->quic_server->config.ack_delay                  = tile->quic.ack_delay_millis    * (long)1e6;
    ctx->quic_server->config.initial_rx_max_stream_data = 2048UL;
    ctx->quic_server->config.retry                      = tile->quic.retry;
    fd_memcpy( ctx->quic_server->config.identity_public_key, ctx->identity_key->uc, sizeof(fd_pubkey_t) );
    ctx->quic_server->config.sign     = quic_tls_cv_sign;
    ctx->quic_server->config.sign_ctx = ctx;
    ctx->quic_server->cb.conn_new     = quic_server_conn_new;
    ctx->quic_server->cb.conn_final   = quic_server_conn_final;
    ctx->quic_server->cb.stream_rx    = quic_server_stream_rx;
    ctx->quic_server->cb.quic_ctx     = ctx;
    if( FD_UNLIKELY( ctx->keylog_fd>=0 ) ) {
      ctx->quic_server->cb.tls_keylog = quic_tls_keylog;
      ctx->keylog_next_flush = fd_log_wallclock() + FD_VOTOR_KEYLOG_FLUSH_INTERVAL_NS;
    }
    fd_quic_set_aio_net_tx( ctx->quic_server, tx_aio );
    if( FD_UNLIKELY( !fd_quic_init( ctx->quic_server ) ) ) FD_LOG_ERR(( "fd_quic_init failed" ));

    fd_topo_link_t const * net_out = &topo->links[ tile->out_link_id[ OUT_IDX_NET ] ];
    ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, net_out->dcache );
    ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
    ctx->net_out_chunk  = ctx->net_out_chunk0;

    /* Outbound broadcast client (peer connection table).  Shares the validator
       identity and TX aio (-> net) with the server, but uses a distinct UDP
       source port so inbound frames can be dispatched without feeding one
       mutable packet buffer to both QUIC instances. */
    ctx->src_ip_addr             = tile->quic.alpenglow_ip_addr;
    ctx->alpenglow_server_port   = tile->quic.alpenglow_listen_port;
    ctx->alpenglow_client_port   = tile->quic.alpenglow_client_listen_port;
    if( FD_UNLIKELY( !ctx->alpenglow_server_port ) ) FD_LOG_ERR(( "votor tile (with QUIC) requires a non-zero alpenglow listen port" ));
    if( FD_UNLIKELY( !ctx->alpenglow_client_port ) ) FD_LOG_ERR(( "votor tile (with QUIC) requires a non-zero alpenglow client port" ));
    if( FD_UNLIKELY( ctx->alpenglow_server_port==ctx->alpenglow_client_port ) ) FD_LOG_ERR(( "votor tile requires distinct alpenglow listen and client ports" ));

    ctx->quic_client->config.role                       = FD_QUIC_ROLE_CLIENT;
    ctx->quic_client->config.idle_timeout               = tile->quic.idle_timeout_millis * (long)1e6;
    ctx->quic_client->config.ack_delay                  = tile->quic.ack_delay_millis    * (long)1e6;
    ctx->quic_client->config.initial_rx_max_stream_data = 2048UL;
    ctx->quic_client->config.retry                      = tile->quic.retry;
    fd_memcpy( ctx->quic_client->config.identity_public_key, ctx->identity_key->uc, sizeof(fd_pubkey_t) );
    ctx->quic_client->config.sign       = quic_tls_cv_sign;
    ctx->quic_client->config.sign_ctx   = ctx;
    ctx->quic_client->cb.conn_final     = quic_client_conn_final;
    ctx->quic_client->cb.conn_hs_complete = quic_client_conn_hs_complete;
    ctx->quic_client->cb.quic_ctx       = ctx;
    if( FD_UNLIKELY( ctx->keylog_fd>=0 ) ) {
      ctx->quic_client->cb.tls_keylog = quic_tls_keylog;
      ctx->keylog_next_flush = fd_log_wallclock() + FD_VOTOR_KEYLOG_FLUSH_INTERVAL_NS;
    }
    fd_quic_set_aio_net_tx( ctx->quic_client, tx_aio );
    if( FD_UNLIKELY( !fd_quic_init( ctx->quic_client ) ) ) FD_LOG_ERR(( "fd_quic_init (client) failed" ));
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_votor_tile_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_votor_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->keylog_fd );
  return sock_filter_policy_fd_votor_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_votor_tile_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_UNLIKELY( ctx->keylog_fd>=0 ) )
    out_fds[ out_cnt++ ] = ctx->keylog_fd;
  return out_cnt;
}

#define STEM_BURST (2UL)        /* MAX over a single returnable_frag: (vote OR cert) AND (slot_done) */
#define STEM_LAZY  (128L*3000L) /* see explanation in fd_pack */

#define STEM_CALLBACK_CONTEXT_TYPE        fd_votor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_votor_tile_t)
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
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
