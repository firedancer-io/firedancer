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
      net_alpenglow link, not here — see handle_consensus_payload.)

   4. Auxiliary frags: epoch stakes (EPOCH link, used to rebuild the
      validator set / stakes the pool and votor run against) and shred
      version (IPECHO link).

   In all cases the votor / pool emit a stream of actions (votes/certs to
   broadcast, timeouts to schedule) plus, for the pool, repair requests and
   PoolEvents.  As in the Rust reference (Votor::voting_loop), events flow
   through three receivers: pool_receiver (the pool's embedded event
   queue, which after_credit pops until empty),
   blockstore_receiver (blockstore events are dispatched inline by the replay
   frag handlers) and timeout_receiver (the timeouts_heap, popped by
   after_credit as timeouts come due).  The votor's own votes re-enter the
   pool from handle_votor_out and the PoolEvents that produces stay on the
   pool's channel for a later after_credit iteration.  Emitted votes/certs
   are queued as FD_VOTOR_SIG_* frags onto the `publishes` deque, drained one
   frag per after_credit call (exactly like Tower).

   The pool's two queues are what we read consensus state from, and that
   event stream is the ONLY such source.  What the pool decided about a slot
   is not queried back out of it -- CertCreated tells us which block a slot
   certified (ctx->certified), ParentReady tells us a window can be built
   on.  One description of the pool's decisions, not two.  TODO: the
   accessors that drained those queues are gone; see
   drain_pool_channels. */

#define LOGGING 0

#define IN_KIND_REPLAY (0)
#define IN_KIND_GOSSIP (1)
#define IN_KIND_EPOCH  (2)
#define IN_KIND_IPECHO (3)
#define IN_KIND_NET    (4)
#define IN_KIND_SIGN   (5)

#define OUT_IDX     0 /* votor_out: consensus output (votes/certs/slot_done/finalized/rooted) */
#define OUT_IDX_NET 1 /* votor_net: QUIC TX frames back to the net tile               */

/* One net_alpenglow input link per net tile. */
#define FD_VOTOR_NET_IN_MAX (32UL)

/* Stream reassembly slot: one in-flight ConsensusMessage.  Messages are
   capped at agave's PACKET_DATA_SIZE (1232); the receiver-side QUIC
   stream limit (initial_rx_max_stream_data) already bounds them. */

#define FD_VOTOR_MSG_MTU       (1232UL)
#define FD_VOTOR_MSG_REASM_CNT (256UL) /* direct-mapped, power of 2 */

struct msg_reasm {
  ulong conn_uid;
  ulong stream_id;
  uint  sz;   /* contiguous bytes buffered so far */
  int   busy;
  uchar buf[ FD_VOTOR_MSG_MTU ];
};
typedef struct msg_reasm msg_reasm_t;

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
  int            bcast; /* also All2All it; 0 for frags we merely echo locally */
  ag_votor_msg_t msg;
};
typedef struct publish publish_t;

#define DEQUE_NAME publishes
#define DEQUE_T    publish_t
#include "../../util/tmpl/fd_deque_dynamic.c"

/* certified_t is our record of which block a slot certified, rebuilt from
   the pool's CertCreated events as we drain them rather than queried back
   out of the pool's slot states.  Only Notar and FastFinal name a block
   (a slow Final cert carries no hash), and those are exactly the two the
   reset target and the ROOTED / FINALIZED block ids are drawn from.

   Direct-mapped by slot over slot_max, the same window the pool retains,
   so there is nothing to prune: a slot that falls out of the window is
   overwritten by the successor that lands on its line, and `slot`
   distinguishes a live line from the stale one it displaced.  We only
   ever look up the frontier -- the finalized slot, the rootable slot and
   the slot replay just completed -- so a displaced line is a line whose
   answer no longer matters. */

struct certified {
  ulong     slot;
  fd_hash_t notar;
  fd_hash_t fast_final;
  int       has_notar;
  int       has_fast_final;
};
typedef struct certified certified_t;

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

/* votor retains exactly two epoch stakes / BLS rank maps -- curr (the
   active epoch E) and next (E+1).  E-1 is unreachable: every slot of E-1
   is below the consensus root, so pool admission rejects it before any
   rank lookup.  E+2 is unverifiable: its stakes snapshot is minted when
   the chain crosses into E+1, so no finalized-lineage rank map for it
   can exist while the root is in E.  Entries arrive one epoch per EPOCH
   msg (stake weights + BLS pubkeys, update_epoch_vtrs); the E+2
   publication doubles as the epoch-advance signal, retiring curr.
   Agave retains 5 (MAX_LEADER_SCHEDULE_STAKES) as legacy slack for
   non-consensus consumers (RPC, snapshots, tower vote verification);
   consensus only ever reads two. */

/* vtr_epoch_set_t is one set of epoch stakes. epoch==ULONG_MAX marks an
   empty entry in the epoch map; info always points at this entry's slice
   of tile scratch, occupied or not. */
struct vtr_epoch_set {
  ulong             epoch;
  ulong             validator_cnt;
  ushort            rank;       /* our ValidatorIndex in THIS epoch  */
  int               have_rank;  /* 0 if we are unstaked this epoch   */
  ag_epoch_info_t * info;
};
typedef struct vtr_epoch_set vtr_epoch_set_t;

struct fd_votor_tile {
  ulong          seed; /* map seed */
  fd_pubkey_t    identity_key[1];
  /* Only the PUBLIC half of the BLS voting key lives here: votes are
     signed by the sign tile over the keyguard (votor_sign / sign_votor,
     FD_KEYGUARD_SIGN_TYPE_BLS12_381).  The pubkey is kept so we can
     check it against the vote account's on-chain BLS registration. */
  ag_aggsig_pk_t voting_pubkey[1];
  /* How the votor signs.  privileged_init installs keyguard_sign
     (-> sign tile); a tile with no sign tile installs its own signer
     before unprivileged_init.  MUST be set before it -- tile scratch is
     not zeroed, so there is no safe "unset" value to test for. */
  ag_aggsig_sign_fn sign_fn;
  void *            sign_ctx;
  ushort         epoch_rank;    /* our ValidatorIndex in the active epoch */

  /* owned joins */

  fd_wksp_t *      wksp; /* workspace */
  fd_keyswitch_t * identity_keyswitch;
  fd_keyguard_client_t keyguard_client[1];

  ag_votor_t *      votor;      /* the voting state machine             */
  ag_pool_t *       pool;       /* the cert/vote integrator             */

  /* per-epoch validator sets: exactly the two epochs consensus can reference */
  vtr_epoch_set_t     curr;            /* the active epoch E */
  vtr_epoch_set_t     next;            /* epoch E+1          */

  /* What the pool has already been told.  ag_pool_set_epoch rotates one
     epoch per call, so sync_pool_epochs cannot simply redeclare the
     window on every mutation -- it has to know which steps it has taken.
     ULONG_MAX in either means the pool has not been given that half of
     the window yet. */

  ulong               pool_curr_epoch;
  ulong               pool_next_epoch;

  ulong               active_epoch;    /* epoch the pool / votor are built for */
  ag_epoch_info_t *   epoch_info;      /* == the active epoch set's info */
  fd_epoch_schedule_t epoch_schedule;  /* from EPOCH msgs; slot -> epoch        */
  int                 have_schedule;

  publish_t * publishes; /* deque of msgs queued for publishing */

  certified_t * certified; /* [slot_max]; slot -> its certified block, from CertCreated events */

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
  ushort       quic_server_port;
  ushort       quic_client_port;

  /* heap of timeouts (Votor::timeout_receiver), polled by after_credit; a due
     min timeout is popped and dispatched as a timeout event. */
  fd_timeout_t *      timeouts_pool;
  fd_timeout_heap_t * timeouts_heap;

  /* Alpenglow::standstill_loop state, plus the recovery bundle buffers
     (PoolEvent::Standstill's Vec<Cert> / Vec<Vote>, which the C core
     hands back through ag_pool_recover_from_standstill's out params).
     standstill_armed gates the very first recovery: a pool rooted at a
     snapshot slot holds no cert behind its finalized slot, so there is
     nothing to re-broadcast until a real finalization lands. */

  ulong       standstill_finalized_slot;
  long        standstill_last_progress;
  long        standstill_poll_deadline;
  int         standstill_armed;
  ag_cert_t * standstill_certs;
  ag_vote_t * standstill_votes;

  /* validator set staged from the most recent EPOCH msg.  The pool / votor
     are rebuilt against this set on epoch change. */

  ag_validator_info_t validators[ VTR_MAX ];
  ulong               validator_cnt;
  ulong               epoch;       /* the epoch the current set is for */

  /* fixed pool / votor dimensions, set once in unprivileged_init and reused
     verbatim on every epoch rebuild so the re-formatted objects always fit
     the originally allocated scratch regions. */

  ulong slot_max;

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

  int    publish_rx;   /* dev: echo received votes/certs onto votor_out */
  int    halt_signing;
  ushort shred_version;
  int    init; /* 1 after the first slot completion / votor_new */

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
     quic_server_stream_rx callback hands each whole ConsensusMessage to
     handle_consensus_payload.  NULL when the tile is run without QUIC
     config (e.g. the unit test). */

  fd_quic_t *        quic_server;
  fd_aio_t           quic_tx_aio[1];
  long               now;
  fd_stem_context_t * stem;
  uchar              net_buf[ FD_NET_MTU ];
  fd_net_rx_bounds_t net_in_bounds[ FD_VOTOR_NET_IN_MAX ];

  /* during_frag staging.  replay_out / gossip_out / replay_epoch are
     consumed RELIABLE (topology.c), so the producer cannot recycle the
     dcache entry underneath us: during_frag just records where the frag
     lives and after_frag reads it in place, no copy.  net_alpenglow is
     UNRELIABLE and still copies into net_buf.  skip_frag marks a frag
     whose during_frag bounds checks failed. */
  int          skip_frag;
  void const * msg;

  /* Stream reassembly: one ConsensusMessage per uni stream, but quinn
     routinely splits a message's data and FIN across frames at packet
     boundaries, so single-frame delivery cannot be assumed.  Direct-
     mapped by (conn_uid, stream_id); a colliding new stream evicts the
     old partial (counted).  Gaps return FD_QUIC_FAILED so the frame is
     not ACKed and the peer retransmits it once the hole fills. */

  msg_reasm_t msg_reasm[ FD_VOTOR_MSG_REASM_CNT ];

  /* TLS key log file (development only) */
  long                     keylog_next_flush;
  int                      keylog_fd;
  fd_io_buffered_ostream_t keylog_stream;
  char                     keylog_buf[ 4096 ];

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  /* QUIC scratch regions carved by init_choreo; fd_quic_new runs over
     them in unprivileged_init, once the topology links are known.  NULL
     when the tile has no QUIC config. */
  void * quic_server_mem;
  void * quic_client_mem;
};
typedef struct fd_votor_tile fd_votor_tile_t;

/* epoch_set returns the retained entry for `epoch`, or NULL if that
   epoch is outside the two-epoch window. */

FD_FN_PURE static vtr_epoch_set_t const *
epoch_set( fd_votor_tile_t const * ctx,
           ulong                   epoch ) {
  if( ctx->curr.epoch==epoch ) return &ctx->curr;
  if( ctx->next.epoch==epoch ) return &ctx->next;
  return NULL;
}

/* keyguard_sign is the ag_aggsig_sign_fn the votor core calls to sign a
   vote's VotePayloadToSign.  It round-trips through the keyguard to the
   sign tile, which holds the BLS voting key; blocking is fine and
   matches every other tile's signing path. */

static void
keyguard_sign( void *            _ctx,
               ag_aggsig_sig_t * sig,
               uchar const *     payload,
               ulong             payload_sz ) {
  fd_votor_tile_t * ctx = _ctx;
  fd_keyguard_client_sign_sz( ctx->keyguard_client, sig->v, AG_AGGSIG_SIG_SZ,
                              payload, payload_sz, FD_KEYGUARD_SIGN_TYPE_BLS12_381 );
}

/* validated_vote / validated_cert are ValidatedVote::try_new and
   ValidatedCert::try_new: every check the pool assumes has already
   happened by the time it is handed a message, which is why
   ag_pool_add_vote / ag_pool_add_cert take no signature, signer or
   threshold error.  Each returns the epoch the message validated
   against, or NULL if it must be dropped.

   The epoch lookup leads because the rest is scored against it: the
   validator set of the message's OWN slot, so a vote or cert either side
   of an epoch boundary resolves to the right rank map and total stake. */

/* The set a message's slot resolves to, resolved the way the pool resolves
   it out of the window sync_pool_epochs pushed: next's from its start slot
   up, else curr's, and curr's for everything while the pool has no next.
   NULL until the first epoch is installed. */

static ag_epoch_info_t const *
epoch_info_for_slot( fd_votor_tile_t const * ctx,
                     ulong                   slot ) {
  if( FD_UNLIKELY( ctx->pool_curr_epoch==ULONG_MAX ) ) return NULL;
  if( FD_UNLIKELY( ctx->pool_next_epoch==ULONG_MAX ) ) return ctx->curr.info;
  ulong next_slot = fd_epoch_slot0( &ctx->epoch_schedule, ctx->pool_next_epoch );
  return slot>=next_slot ? ctx->next.info : ctx->curr.info;
}

static ag_epoch_info_t const *
validated_vote( fd_votor_tile_t const * ctx,
                ag_vote_t const *       vote ) {
  ag_epoch_info_t const * epoch = epoch_info_for_slot( ctx, ag_vote_slot( vote ) );
  if( FD_UNLIKELY( !epoch                                         ) ) return NULL;
  if( FD_UNLIKELY( ag_vote_signer( vote )>=epoch->validator_cnt   ) ) return NULL;

  ag_aggsig_pk_t const * pk = &ag_epoch_info_validator( epoch, ag_vote_signer( vote ) )->voting_pubkey;
  if( FD_UNLIKELY( !ag_vote_check_sig( vote, pk, ctx->shred_version ) ) ) return NULL;
  return epoch;
}

static ag_epoch_info_t const *
validated_cert( fd_votor_tile_t const * ctx,
                ag_cert_t const *       cert ) {
  ag_epoch_info_t const * epoch = epoch_info_for_slot( ctx, ag_cert_slot( cert ) );
  if( FD_UNLIKELY( !epoch                                                ) ) return NULL;
  if( FD_UNLIKELY( !ag_cert_check_threshold( cert, epoch )               ) ) return NULL;
  if( FD_UNLIKELY( !ag_cert_check_sig( cert, ctx->shred_version, epoch ) ) ) return NULL;
  return epoch;
}

/* own-vote loopback: Alpenglow::handle_all2all_message */

static void
handle_votor_out( fd_votor_tile_t * ctx ) {
  ag_votor_out_t const * out = ag_votor_out( ctx->votor );

  /* Arm the timeouts the votor asked for.  It sets the deadlines (relative
     to now); we own the clock and the timer queue.  One clock read for the
     batch, so a whole window's timers share a base. */

  if( FD_UNLIKELY( out->timeout_cnt ) ) {
    long now = fd_log_wallclock();
    for( ulong i=0UL; i<out->timeout_cnt; i++ ) {
      ag_votor_timeout_t const * t = &out->timeouts[ i ];
      if( FD_UNLIKELY( !fd_timeout_pool_free( ctx->timeouts_pool ) ) ) {
        FD_LOG_WARNING(( "votor timeout pool full; dropping %s timeout for slot %lu",
                         t->kind==AG_VOTOR_TIMEOUT_CRASHED_LEADER ? "crashed-leader" : "block", t->slot ));
        continue;
      }
      fd_timeout_t * timeout = fd_timeout_pool_ele_acquire( ctx->timeouts_pool );
      timeout->slot = t->slot;
      timeout->kind = t->kind;
      timeout->ts   = now + t->delay_ns;
      fd_timeout_heap_ele_insert( ctx->timeouts_heap, timeout, ctx->timeouts_pool );
    }
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
      ag_vote_set_signer( &vote, s->rank );
      publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_VOTOR_SIG_VOTE, .bcast = 1, .msg.vote = vote } );

      /* Our own vote goes through the same gate as a peer's -- the
         reference loops own votes back through handle_all2all_message and
         so validates them too.  Failing it means our epoch bookkeeping
         and the pool's have diverged, which is fatal, not droppable. */
      if( FD_UNLIKELY( !validated_vote( ctx, &vote ) ) )
        FD_LOG_CRIT(( "own vote for slot %lu failed validation", ag_vote_slot( &vote ) ));

      ag_pool_add_vote( ctx->pool, &vote ); /* count our own vote; the pool events
                                               it emits are consumed by a later
                                               after_credit iteration */
    } else {
      publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_VOTOR_SIG_CERT, .bcast = 1, .msg.cert = m->inner.cert } );
    }
  }
}

/* note_cert folds one CertCreated event into ctx->certified.  Skip and
   Final certs name no block and so record nothing.

   Unused while the pool drain in drain_pool_channels is a TODO: nothing
   delivers CertCreated events, so this has no caller.  Kept because the
   replacement drain has to call it. */

FD_FN_UNUSED static void
note_cert( fd_votor_tile_t * ctx,
           ag_cert_t const * cert ) {
  if( cert->kind!=AG_CERT_TYPE_NOTAR && cert->kind!=AG_CERT_TYPE_FAST_FINAL ) return;

  ulong         slot = ag_cert_slot( cert );
  certified_t * c    = &ctx->certified[ slot & (ctx->slot_max-1UL) ];
  if( FD_UNLIKELY( c->slot!=slot ) ) { /* displacing a slot that left the window */
    c->slot           = slot;
    c->has_notar      = 0;
    c->has_fast_final = 0;
  }
  if( cert->kind==AG_CERT_TYPE_NOTAR ) { c->notar      = cert->inner.notar.block_hash;      c->has_notar      = 1; }
  else                                 { c->fast_final = cert->inner.fast_final.block_hash; c->has_fast_final = 1; }
}

/* certified_notar returns the block hash slot's Notar cert names, or NULL
   if we have seen no Notar cert for it. */

FD_FN_PURE static fd_hash_t const *
certified_notar( fd_votor_tile_t const * ctx,
                 ulong                   slot ) {
  certified_t const * c = &ctx->certified[ slot & (ctx->slot_max-1UL) ];
  return ( c->slot==slot && c->has_notar ) ? &c->notar : NULL;
}

/* certified_block is certified_notar widened to the fast-final cert,
   which names a block as well.  Notar wins when both are present: they
   name the same block (a fast-final cert is built from the same notar
   votes), and this is the order the pool answered it in. */

FD_FN_PURE static fd_hash_t const *
certified_block( fd_votor_tile_t const * ctx,
                 ulong                   slot ) {
  fd_hash_t const * notar = certified_notar( ctx, slot );
  if( FD_LIKELY( notar ) ) return notar;
  certified_t const * c = &ctx->certified[ slot & (ctx->slot_max-1UL) ];
  return ( c->slot==slot && c->has_fast_final ) ? &c->fast_final : NULL;
}

/* publish_slot_done queues the FD_VOTOR_SIG_SLOT frag for the just
   completed replay slot.  The reset target is the notarized version of
   that slot when consensus has named one -- replay may have executed an
   equivocating version -- falling back to the block replay completed. */

static void
publish_slot_done( fd_votor_tile_t *     ctx,
                   ag_block_id_t const * block,
                   ulong                 bank_idx ) {
  publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
  pub->sig = FD_VOTOR_SIG_SLOT;
  pub->bcast = 0;

  ag_votor_slot_done_t * msg = &pub->msg.slot_done;
  msg->replay_slot     = block->slot;
  msg->replay_bank_idx = bank_idx;

  msg->reset_slot     = block->slot;
  msg->reset_block_id = block->hash;

  fd_hash_t const * notarized = certified_notar( ctx, block->slot );
  if( FD_LIKELY( notarized ) ) {
    msg->reset_slot     = block->slot;
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

  /* FINALIZED: consensus finalization advanced (cert-driven).  Held until
     we have the finalized block id, exactly like ROOTED below.  Two ways
     it can be missing: the CertCreated event that carries it is still on
     the pool's queue (finalization is observable from the pool one drain
     before we have folded the cert in), or the pool was seeded at a
     snapshot slot, which has no cert behind it at all.  In both cases
     holding is right -- the first resolves on the next drain, and the
     second is not a finalization we observed. */

  if( FD_UNLIKELY( fin>ctx->finalized_slot ) ) {
    fd_hash_t const * block_id = certified_block( ctx, fin );
    if( FD_LIKELY( block_id ) ) {
      publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
      pub->sig                    = FD_VOTOR_SIG_FINALIZED;
      pub->bcast                  = 0;
      pub->msg.finalized.slot     = fin;
      pub->msg.finalized.block_id = *block_id;
      ctx->finalized_slot         = fin;
      ctx->standstill_armed       = 1; /* a real final cert now backs the finalized slot */
    }
  }

  /* ROOTED: the bank root can advance to the highest finalized+replayed slot. */
  ulong rootable = fd_ulong_min( fin, ctx->highest_replayed_slot );
  if( FD_UNLIKELY( rootable>ctx->root_slot ) ) {
    /* Only a CERTIFIED block id (notar / fast-final cert) may be rooted:
       the replay frontier block is not necessarily the finalized one
       (e.g. a leader block replay executed at a slot consensus then
       skipped -- rooting it abandons the real fork in the scheduler).
       If we have seen no cert for it, hold the root and retry on the next
       advance. */
    fd_hash_t const * block_id = certified_block( ctx, rootable );
    if( FD_LIKELY( block_id ) ) {
      publish_t * pub = publishes_push_head_nocopy( ctx->publishes );
      pub->sig                 = FD_VOTOR_SIG_ROOTED;
      pub->bcast               = 0;
      pub->msg.rooted.slot     = rootable;
      pub->msg.rooted.block_id = *block_id;
      ctx->root_slot           = rootable;
      ctx->root_block_id       = *block_id; /* keep the root block id for the next pool rebuild */
      FD_LOG_INFO(( "votor rooted slot %lu", rootable ));
    }
  }
}

/* sync_pool_epochs brings the pool's window up to the retained one --
   curr and next, with the start slot of each -- so it can resolve stakes
   and BLS ranks from the epoch of each vote's / cert's OWN slot, Agave's
   Bank::epoch_stakes_from_slot.  The start slots come from our epoch
   schedule, so variable-length warmup epochs need no special casing.

   Must be called after EVERY mutation of curr / next, and in particular
   after update_epoch_vtrs has re-ranked into a retired entry's memory:
   the pool holds these ag_epoch_info_t pointers, so a retired epoch has
   to leave the window before anything reads the pool again.

   ag_pool_set_epoch takes one epoch and rotates, so this is a diff
   against ctx->pool_*, not a redeclaration: calling it twice over an
   unchanged window must not rotate the pool twice.  A set re-ranked in
   place needs no call at all -- the pool holds it by pointer. */

static void
sync_pool_epochs( fd_votor_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->have_schedule ) ) return;

  vtr_epoch_set_t const * curr = &ctx->curr;
  vtr_epoch_set_t const * next = &ctx->next;
  int curr_live = curr->epoch!=ULONG_MAX;
  int next_live = next->epoch!=ULONG_MAX;

  /* next is only ever filled once curr is, and the epoch advance rotates
     next INTO curr, so a live next always sits on a live curr.  That is
     what lets curr's start slot be the bottom of the pool's window. */
  FD_TEST( curr_live || !next_live );
  if( FD_UNLIKELY( !curr_live ) ) return; /* nothing to install; the pool's window starts empty */

  FD_TEST( !next_live || next->epoch==curr->epoch+1UL );
  ulong curr_slot = fd_epoch_slot0( &ctx->epoch_schedule, curr->epoch      );
  ulong next_slot = fd_epoch_slot0( &ctx->epoch_schedule, curr->epoch+1UL  );

  /* rank is 0 (observe-only) when !have_rank */

  if( FD_UNLIKELY( ctx->pool_curr_epoch==ULONG_MAX ) ) {
    /* Empty window: the first epoch handed over is its bottom. */
    ag_pool_set_epoch( ctx->pool, curr->info, curr->rank, curr_slot );
    ctx->pool_curr_epoch = curr->epoch;
    ctx->pool_next_epoch = ULONG_MAX;
  }

  /* An epoch reaches the pool only together with its set, so there is
     nothing to hand over until E+1 has one.  Until then curr answers for
     E+1's slots too -- the window has no upper bound. */
  if( !next_live                          ) return;
  if( ctx->pool_next_epoch==next->epoch   ) return; /* already there; a re-rank needs no call */

  /* Either the pool has never been given a next (this fills it), or the
     window advanced and the pool's next rotates into its curr.  Anything
     else means a mutation went unsynced. */
  FD_TEST( ctx->pool_next_epoch==ULONG_MAX || ctx->pool_next_epoch==curr->epoch );

  ag_pool_set_epoch( ctx->pool, next->info, next->rank, next_slot );
  ctx->pool_curr_epoch = curr->epoch;
  ctx->pool_next_epoch = next->epoch;
}

/* rebuild_pool_at_root re-formats the pool rooted at ctx->root_slot.

   Runs EXACTLY ONCE, on the first slot completion after boot: the pool
   formatted in unprivileged_init is rooted at genesis because the
   snapshot slot is not known until replay reports it.  It is emphatically
   NOT run on epoch changes -- see set_active_epoch. */

static void
rebuild_pool_at_root( fd_votor_tile_t * ctx ) {
  ctx->pool = ag_pool_join( ag_pool_new( ag_pool_leave( ctx->pool ),
                                         ctx->slot_max, ctx->seed ) );
  FD_TEST( ctx->pool );
  ag_pool_set_root( ctx->pool, ctx->root_slot, &ctx->root_block_id );

  /* The window went with the old pool; the next sync installs it afresh. */
  ctx->pool_curr_epoch = ULONG_MAX;
  ctx->pool_next_epoch = ULONG_MAX;
  sync_pool_epochs( ctx );

  /* ctx->certified mirrors the pool's certs, so it is discarded with them.
     A cleared line reads as "no cert seen", which is what a fresh pool
     reports for every slot. */
  memset( ctx->certified, 0, sizeof(certified_t)*ctx->slot_max );

  /* A pool rooted at a snapshot slot holds no cert behind its finalized
     slot, so standstill recovery has nothing to re-broadcast yet. */
  ctx->standstill_armed          = 0;
  ctx->standstill_finalized_slot = ag_pool_finalized_slot( ctx->pool );
  ctx->standstill_last_progress  = fd_log_wallclock();
}

/* set_active_epoch re-points the tile's active-epoch bookkeeping at
   `epoch`.  Returns 0 if `epoch` is not in the retained window (caller
   keeps the current one).

   This no longer rebuilds anything.  The pool scores each vote and cert
   against the epoch of that message's own slot, so it needs no notion of
   a single current epoch; and rebuilding the votor would discard its
   per-slot `voted` history, which is exactly what stops us from
   following a Skip with a Notarize on the same slot after an epoch
   boundary.  What remains is the aliases used for logging, metrics and
   the own-vote rank restamp in handle_votor_out. */

static int
set_active_epoch( fd_votor_tile_t * ctx,
                  ulong             epoch ) {
  vtr_epoch_set_t const * s = epoch_set( ctx, epoch );
  if( FD_UNLIKELY( !s ) ) return 0;

  ctx->active_epoch = epoch;
  ctx->epoch        = epoch;
  ctx->epoch_info   = s->info;
  ctx->epoch_rank   = s->rank; /* 0 (observe-only) when !have_rank */

  /* Keep the votor's default rank current.  Every emitted vote is
     restamped against its own slot's epoch before it leaves
     handle_votor_out, so this only matters as the pre-restamp value. */
  ag_votor_set_validator_index( ctx->votor, s->rank );

  FD_LOG_NOTICE(( "votor active epoch -> %lu (%lu validators, rank %u, staked=%d)",
                  epoch, s->validator_cnt, (uint)s->rank, s->have_rank ));
  return 1;
}

/* seed_consensus_root adopts the replayed tip's parent as the
   consensus root, so the pool is built rooted at the snapshot block
   instead of genesis.  Runs once, on the first slot completion after boot.

   The initial snapshot publish carries a null parent block id; root at the
   completed slot itself then, so the finality tracker is not seeded with a
   zero placeholder that the slot's live notar cert would collide with. */

static void
seed_consensus_root( fd_votor_tile_t *     ctx,
                     ag_block_id_t const * block,
                     ag_block_id_t const * parent ) {
  int parent_id_known = 0UL!=( parent->hash.ul[0] | parent->hash.ul[1] |
                               parent->hash.ul[2] | parent->hash.ul[3] );
  if( FD_LIKELY( parent_id_known ) ) {
    ctx->root_slot     = parent->slot;
    ctx->root_block_id = parent->hash;
  } else {
    ctx->root_slot     = block->slot;
    ctx->root_block_id = block->hash;
  }
}

/* advance_epoch moves the active-epoch bookkeeping up to the replayed
   tip's epoch, and on the very first slot completion re-roots the pool at
   the snapshot block.  At snapshot boot replay publishes both epoch E and
   E+1 before any slot completes, so the validator set is present.

   The active epoch only ever moves FORWARD.  It no longer gates which
   votes and certs the pool will accept -- the pool resolves those per
   slot -- but letting a tip that dips back below the boundary (fork
   replay, or a slot completing out of order) drag it backwards would
   oscillate our own-vote rank and the logging once per slot.  Staying on
   the newer epoch costs nothing: both epochs are live in the pool. */

static void
advance_epoch( fd_votor_tile_t *     ctx,
               ag_block_id_t const * block,
               ag_block_id_t const * parent ) {
  if( FD_UNLIKELY( !ctx->have_schedule ) ) return;

  /* First slot completion after boot: adopt the snapshot block as the
     consensus root and re-root the pool onto it.  Must happen before the
     caller registers the tip's block. */
  if( FD_UNLIKELY( ctx->active_epoch==ULONG_MAX ) ) {
    seed_consensus_root( ctx, block, parent );
    rebuild_pool_at_root( ctx );
  }

  ulong tip_epoch = fd_slot_to_epoch( &ctx->epoch_schedule, block->slot, NULL );
  if( FD_LIKELY( ctx->active_epoch!=ULONG_MAX && tip_epoch<=ctx->active_epoch ) ) return;

  if( FD_UNLIKELY( !set_active_epoch( ctx, tip_epoch ) ) ) {
    FD_LOG_WARNING(( "no validator set for tip epoch %lu (slot %lu); keeping epoch %lu",
                     tip_epoch, block->slot, ctx->active_epoch ));
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

  /* Open an outbound QUIC client connection so we can broadcast to this peer.
     The client uses its own alpenglow UDP source port.  The peer is stashed as the conn's user
     context so quic_client_conn_final can clear peer->conn in O(1).  Reconnects
     are throttled (>=2s between attempts) so a peer whose connection keeps
     failing to establish is not hammered. */
  if( FD_UNLIKELY( !ctx->quic_client ) ) return;                          /* QUIC disabled (unit test) */
  if( FD_LIKELY  (  peer->conn        ) ) return;                          /* already connected         */
  if( FD_UNLIKELY( peer->last_connected + (long)2e9 > ctx->now ) ) return; /* reconnect throttle        */
  fd_quic_conn_t * conn = fd_quic_connect( ctx->quic_client,
                                           peer->ip4, peer->port, /* dst */
                                           ctx->src_ip_addr, ctx->quic_client_port,  /* src */
                                           ctx->now );
  peer->last_connected = ctx->now;
  if( FD_UNLIKELY( !conn ) ) return; /* out of conn / handshake slots; retried on the next update */
  fd_quic_conn_set_context( conn, peer );
  peer->conn = conn;
}

/* broadcast sends one serialized ConsensusMessage to every peer we hold a
   live outbound connection to, one unidirectional QUIC stream per message
   (TrivialAll2All::broadcast sends to every validator in the set).

   Peers without a live conn are skipped: the ContactInfo path re-dials
   them, and Alpenglow tolerates partial delivery (a vote missed by one
   peer is re-derived from the certs that peer receives, or resent by
   standstill recovery). */

static void
broadcast( fd_votor_tile_t * ctx,
           uchar const *     payload,
           ulong             payload_sz ) {
  if( FD_UNLIKELY( !ctx->quic_client ) ) return; /* QUIC disabled (unit test) */

  for( peer_map_iter_t iter = peer_map_iter_init( ctx->peer_map, ctx->peer_pool );
       !peer_map_iter_done( iter, ctx->peer_map, ctx->peer_pool );
       iter = peer_map_iter_next( iter, ctx->peer_map, ctx->peer_pool ) ) {
    peer_t * peer = peer_map_iter_ele( iter, ctx->peer_map, ctx->peer_pool );
    if( FD_UNLIKELY( !peer->conn ) ) continue;

    fd_quic_stream_t * stream = fd_quic_conn_new_stream( peer->conn );
    if( FD_UNLIKELY( !stream ) ) continue; /* out of stream quota */
    fd_quic_stream_send( stream, payload, payload_sz, 1 /* fin */ );
  }
}

/* standstill_poll is Alpenglow::standstill_loop: remember when the pool's
   finalized slot last advanced and, once it has been stuck for
   DELTA_STANDSTILL, pull the recovery bundle out of the pool and
   re-broadcast every cert and vote in it.  The Rust reference splits this
   between Pool (which ships the bundle to Votor as PoolEvent::Standstill)
   and Votor (which broadcasts it); the C core leaves the bundle to the
   caller via ag_pool_recover_from_standstill's out params, so the
   re-broadcast lands here -- the tile is what owns the All2All transport.
   Polled every DELTA_BLOCK like the reference loop. */

static void
standstill_poll( fd_votor_tile_t * ctx ) {
  long now = fd_log_wallclock();
  if( FD_LIKELY( now<ctx->standstill_poll_deadline ) ) return;
  ctx->standstill_poll_deadline = now + AG_DELTA_BLOCK_NS;

  ulong fin = ag_pool_finalized_slot( ctx->pool );
  if( FD_LIKELY( fin>ctx->standstill_finalized_slot ) ) {
    ctx->standstill_finalized_slot = fin;
    ctx->standstill_last_progress  = now;
    return;
  }
  if( FD_LIKELY( now-ctx->standstill_last_progress <= AG_DELTA_STANDSTILL_NS ) ) return;
  ctx->standstill_last_progress = now;

  if( FD_UNLIKELY( !ctx->standstill_armed ) ) return; /* no final cert behind the seeded root yet */

  ulong certs_cnt, votes_cnt;
  ag_pool_recover_from_standstill( ctx->pool,
                                   ctx->standstill_certs, &certs_cnt, AG_POOL_STANDSTILL_CERT_MAX,
                                   ctx->standstill_votes, &votes_cnt, AG_POOL_STANDSTILL_VOTE_MAX );

  FD_LOG_WARNING(( "recovering from standstill at slot %lu: re-broadcasting %lu certs and %lu votes",
                   fin, certs_cnt, votes_cnt ));

  for( ulong i=0UL; i<certs_cnt; i++ ) {
    uchar buf[ AG_CERT_SERIALIZED_MAX ];
    ulong sz = ag_cert_serialize( &ctx->standstill_certs[ i ], buf, sizeof(buf), ctx->shred_version );
    if( FD_LIKELY( sz ) ) broadcast( ctx, buf, sz );
  }
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    uchar buf[ AG_VOTE_SERIALIZED_MAX ];
    ulong sz = ag_vote_serialize( &ctx->standstill_votes[ i ], buf, sizeof(buf), ctx->shred_version );
    if( FD_LIKELY( sz ) ) broadcast( ctx, buf, sz );
  }
}

FD_STATIC_ASSERT( FD_EPOCH_INFO_BLS_PUBKEY_SZ==AG_AGGSIG_PUBKEY_COMPRESSED_SZ, bls_pubkey_sz );

/* update_epoch_vtrs installs one epoch's validator set from an EPOCH msg
   (the staked validator set + stakes + compressed BLS pubkeys). */

static void
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
  ushort rank      = 0;
  int    have_rank = 0;
  for( ulong r=0UL; r<cnt; r++ ) {
    ag_validator_info_t const * vi = &ctx->validators[ r ];
    if( FD_LIKELY( memcmp( vi->pubkey.uc, ctx->identity_key->uc, sizeof(fd_pubkey_t) ) ) ) continue;
    rank      = (ushort)r;
    have_rank = 1;
    /* Sanity check: the BLS pubkey the sign tile will sign under must
       equal the on-chain registered BLS pubkey for our vote account
       (just decompressed into vi->voting_pubkey).  A mismatch means our
       votes will silently fail signature verification, so shout. */
    if( FD_UNLIKELY( memcmp( ctx->voting_pubkey->v, vi->voting_pubkey.v, AG_AGGSIG_PUBKEY_SZ ) ) ) {
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
     the other epoch.  The pool / votor are NOT rebuilt here -- the active
     epoch is switched lazily from the replayed tip in advance_epoch,
     or eagerly below when this msg itself is the epoch-advance signal. */
  ctx->epoch_schedule = msg->epoch_schedule;
  ctx->have_schedule  = 1;

  /* Route the publication into the two retained sets, curr (the active
     epoch E) and next (E+1):
       boot                 : the first publication lands in curr, E+1 in next
       curr / next refresh  : re-rank in place
       next.epoch+1 (E+2)   : epoch advance.  An E+2 publication is only ever
         emitted once the chain crossed into E+1, so switch the active epoch
         to E+1 FIRST (the votor must never lose an epoch it can still vote
         in -- handle_votor_out's rank restamp), then retire curr and reuse
         its region for the new epoch.
       anything else        : stale or unbridgeable, drop. */
  vtr_epoch_set_t * s;
  if(      FD_UNLIKELY( ctx->curr.epoch==ULONG_MAX ) ) s = &ctx->curr;
  else if( msg->epoch==ctx->curr.epoch               ) s = &ctx->curr;
  else if( msg->epoch==ctx->curr.epoch+1UL           ) s = &ctx->next;
  else if( ctx->next.epoch!=ULONG_MAX && msg->epoch==ctx->next.epoch+1UL ) {
    if( FD_UNLIKELY( ctx->active_epoch!=ULONG_MAX && !set_active_epoch( ctx, ctx->next.epoch ) ) )
      FD_LOG_ERR(( "EPOCH msg for %lu but no validator set for %lu", msg->epoch, msg->epoch-1UL ));
    vtr_epoch_set_t retired = ctx->curr;
    ctx->curr = ctx->next;
    ctx->next = retired;
    s = &ctx->next;
  } else {
    FD_LOG_WARNING(( "ignoring EPOCH msg %lu (retained %lu / %lu)", msg->epoch, ctx->curr.epoch, ctx->next.epoch ));
    return;
  }
  ag_epoch_info_init( s->info, ctx->validators, cnt );
  s->epoch         = msg->epoch;
  s->validator_cnt = cnt;
  s->rank          = rank;
  s->have_rank     = have_rank;

  /* If we refreshed the currently-active epoch, re-point the verification alias
     at the new set (without rebuilding the pool / dropping state mid-epoch). */
  if( FD_UNLIKELY( msg->epoch==ctx->active_epoch ) ) ctx->epoch_info = s->info;

  /* Republish the window to the pool.  On the E+2 branch above this is
     what actually retires E: until it runs the pool still maps epoch E
     onto the region we just overwrote with E+2's validator set.  Nothing
     reads the pool in between. */
  sync_pool_epochs( ctx );

  FD_LOG_NOTICE(( "epoch %lu validator set: %lu validators (rank %u, staked=%d)",
                  msg->epoch, cnt, (uint)rank, have_rank ));
}

/* The QUIC limits are needed twice -- once to size scratch, once to format
   the fd_quic in it -- so they live here rather than at either use site;
   the two MUST agree or the layout walk overruns.

   The client (outbound broadcast) instance is sized for one persistent
   connection per Alpenglow participant (VTR_MAX), each carrying short-lived
   unidirectional streams: one ConsensusMessage per stream. */

static inline fd_quic_limits_t
quic_server_limits( fd_topo_tile_t const * tile ) {
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

static inline fd_quic_limits_t
quic_client_limits( void ) {
  fd_quic_limits_t limits = {
    .conn_cnt                    = fd_ulong_pow2_up( VTR_MAX ),
    .handshake_cnt               = 256UL,
    .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
    .inflight_frame_cnt          = 16UL * fd_ulong_pow2_up( VTR_MAX ),
    .min_inflight_frame_cnt_conn = 4UL,
    .stream_id_cnt               = 16UL,
    .stream_pool_cnt             = 4096UL,
    .tx_buf_sz                   = 2048UL  /* >= max serialized ConsensusMessage */
  };
  if( FD_UNLIKELY( !fd_quic_footprint( &limits ) ) ) FD_LOG_ERR(( "Invalid votor client QUIC limits" ));
  return limits;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong slot_max      = fd_ulong_pow2_up( tile->tower.max_live_slots );
  ulong pub_max       = slot_max * 8UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_votor_tile_t),  sizeof(fd_votor_tile_t)                                  );
  l = FD_LAYOUT_APPEND( l, ag_votor_align(),          ag_votor_footprint( slot_max )                           );
  l = FD_LAYOUT_APPEND( l, ag_pool_align(),           ag_pool_footprint( slot_max ) );
  l = FD_LAYOUT_APPEND( l, fd_timeout_heap_align(),   fd_timeout_heap_footprint( slot_max )                     );
  l = FD_LAYOUT_APPEND( l, fd_timeout_pool_align(),   fd_timeout_pool_footprint( slot_max )                     );
  l = FD_LAYOUT_APPEND( l, alignof(ag_epoch_info_t),  sizeof(ag_epoch_info_t)                                  ); /* curr */
  l = FD_LAYOUT_APPEND( l, alignof(ag_epoch_info_t),  sizeof(ag_epoch_info_t)                                  ); /* next */
  l = FD_LAYOUT_APPEND( l, publishes_align(),         publishes_footprint( pub_max )                           );
  l = FD_LAYOUT_APPEND( l, alignof(certified_t),      sizeof(certified_t)*slot_max                             );
  l = FD_LAYOUT_APPEND( l, alignof(ag_cert_t),        sizeof(ag_cert_t)*AG_POOL_STANDSTILL_CERT_MAX            );
  l = FD_LAYOUT_APPEND( l, alignof(ag_vote_t),        sizeof(ag_vote_t)*AG_POOL_STANDSTILL_VOTE_MAX            );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),   peer_pool_footprint( VTR_MAX )                                       );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),    peer_map_footprint( peer_map_chain_cnt_est( VTR_MAX ) )        );
  l = FD_LAYOUT_APPEND( l, alignof(fd_pubkey_t),      sizeof(fd_pubkey_t)*FD_CONTACT_INFO_TABLE_SIZE                             );

  /* A tile with no QUIC config (max_concurrent_connections 0) runs
     consensus only -- no fd_quic is allocated.  MUST stay in step with the
     matching block in unprivileged_init. */

  if( tile->quic.max_concurrent_connections ) {
    fd_quic_limits_t server_limits = quic_server_limits( tile );
    fd_quic_limits_t client_limits = quic_client_limits();
    l = FD_LAYOUT_APPEND( l, fd_quic_align(),          fd_quic_footprint( &server_limits )                      );
    l = FD_LAYOUT_APPEND( l, fd_quic_align(),          fd_quic_footprint( &client_limits )                      );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
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

/* handle_consensus_payload ingests one complete ConsensusMessage stream
   payload from a peer: deserialize, then add the vote or cert it carries
   to the pool. */

static void
handle_consensus_payload( fd_votor_tile_t * ctx,
                          uchar const *     data,
                          ulong             data_sz ) {
  if( FD_UNLIKELY( !ctx->init || !ctx->have_schedule ) ) return; /* consensus not ready (pre first slot completion / epoch set) */

  ag_consensus_message_t msg[1];
  int err = ag_consensus_message_de( msg, data, data_sz, ctx->shred_version );
  if( FD_UNLIKELY( err!=AG_CONSENSUS_MESSAGE_DE_SUCCESS ) ) return; /* shred_version mismatch / unsupported / malformed */

  if( FD_UNLIKELY( msg->kind==AG_CONSENSUS_MESSAGE_CERT ) ) {
    ag_cert_t const * cert = &msg->inner.cert;

    /* dev: echo a peer's cert onto votor_out for a local viewer.  bcast
       is 0: re-broadcasting a peer's message would be an echo storm, and
       it is not ours to sign for. */
    if( FD_UNLIKELY( ctx->publish_rx ) )
      publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_VOTOR_SIG_CERT|FD_VOTOR_SIG_RX, .msg.cert = *cert } );

    /* A cert from outside the active epoch cannot be verified against any
       set we hold; the epoch switch off the replayed tip (advance_epoch)
       is what brings the pool forward. */

    ulong cert_epoch = fd_slot_to_epoch( &ctx->epoch_schedule, ag_cert_slot( cert ), NULL );
    if( FD_UNLIKELY( cert_epoch!=ctx->active_epoch  ) ) return;
    if( FD_UNLIKELY( !validated_cert( ctx, cert )   ) ) return;

    if( FD_LIKELY( ag_pool_add_cert( ctx->pool, cert )==AG_POOL_SUCCESS ) ) maybe_publish_finalized( ctx );
    return;
  }

  ag_vote_t const * vote = &msg->inner.vote;

  /* dev: let a viewer on votor_out see peer traffic, not just our own */
  if( FD_UNLIKELY( ctx->publish_rx ) )
    publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_VOTOR_SIG_VOTE|FD_VOTOR_SIG_RX, .msg.vote = *vote } );

  if( FD_UNLIKELY( !validated_vote( ctx, vote ) ) ) {
    FD_LOG_DEBUG(( "ignoring vote for slot %lu: unknown epoch, unknown signer or bad signature",
                   ag_vote_slot( vote ) ));
    return;
  }

  int add_err = ag_pool_add_vote( ctx->pool, vote );
  switch( add_err ) {
  case AG_POOL_SUCCESS:
    /* finalized/rooted publication happens at the end of after_frag /
       after_credit, not here */
    break;
  case AG_POOL_ERR_SLASHABLE:
    FD_LOG_WARNING(( "slashable offence detected: validator %u slot %lu",
                     ag_vote_signer( vote ), ag_vote_slot( vote ) ));
    break;
  default:
    /* invalid votes are ignored */
    FD_LOG_DEBUG(( "ignoring invalid vote: %s", ag_pool_strerror( add_err ) ));
    break;
  }
}

static int
quic_server_stream_rx( fd_quic_conn_t * conn,
                       ulong            stream_id,
                       ulong            offset,
                       uchar const *    data,
                       ulong            data_sz,
                       int              fin ) {
  fd_votor_tile_t * ctx = conn->quic->cb.quic_ctx;

  /* Fast path: whole message in one frame. */
  if( FD_LIKELY( offset==0UL && fin ) ) {
    handle_consensus_payload( ctx, data, data_sz );
    return FD_QUIC_SUCCESS;
  }
  if( FD_UNLIKELY( data_sz==0UL && !fin ) ) return FD_QUIC_SUCCESS; /* noop */

  /* Slow path: reassemble.  Direct-mapped slot; a different in-flight
     stream on the same slot is evicted (its partial message is lost,
     like any reasm overrun). */
  ulong         conn_uid = fd_quic_conn_uid( conn );
  msg_reasm_t * slot     = &ctx->msg_reasm[ fd_ulong_hash( conn_uid ^ fd_ulong_hash( stream_id ) ) & (FD_VOTOR_MSG_REASM_CNT-1UL) ];

  if( FD_UNLIKELY( !slot->busy || slot->conn_uid!=conn_uid || slot->stream_id!=stream_id ) ) {
    if( FD_UNLIKELY( offset>0UL ) ) return FD_QUIC_SUCCESS; /* stream frag gap, no slot */
    slot->busy      = 1;
    slot->conn_uid  = conn_uid;
    slot->stream_id = stream_id;
    slot->sz        = 0U;
  }

  if( FD_UNLIKELY( offset>(ulong)slot->sz ) ) return FD_QUIC_FAILED; /* gap: don't ACK, peer retransmits in order */

  ulong skip = (ulong)slot->sz - offset; /* already-buffered prefix (dup/overlap) */
  if( FD_LIKELY( skip<data_sz ) ) {
    data    += skip;
    data_sz -= skip;
    if( FD_UNLIKELY( (ulong)slot->sz+data_sz>FD_VOTOR_MSG_MTU ) ) { /* oversized stream */
      slot->busy = 0;
      return FD_QUIC_SUCCESS;
    }
    fd_memcpy( slot->buf+slot->sz, data, data_sz );
    slot->sz += (uint)data_sz;
  }

  if( fin ) {
    slot->busy = 0;
    handle_consensus_payload( ctx, slot->buf, (ulong)slot->sz );
  }
  return FD_QUIC_SUCCESS;
}

static ushort
packet_dst_port( uchar const * l3,
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

/* TODO: drain the pool's two output FIFOs.  ag_pool_next_event /
   ag_pool_next_repair are gone and nothing has replaced them yet, so this
   is a no-op and both queues fill without a reader.  Until it is rebuilt
   the tile learns nothing from the pool: no PoolEvent reaches the votor,
   ctx->certified stays empty (so certified_notar / certified_block answer
   NULL for every slot), and no NOTARFB frag is ever published.

   What the replacement has to preserve:

     - Every event goes to the votor, and CertCreated additionally lands in
       ctx->certified via note_cert -- the only way we learn what a slot
       certified.

     - Pop as you go rather than index.  The own-vote loopback in
       handle_votor_out pushes onto the event queue while we drain, and
       popping picks those up in the same pass.

     - Events before repairs.  An event can push a repair and nothing
       pushes the other way, so one pass in that order leaves both empty.

     - Repairs (Pool::repair_sender) are block versions that gathered
       (fallback) notar votes or certs but that we may not have locally,
       published as NOTARFB frags for the repair tile to fetch. */

static int
drain_pool_channels( fd_votor_tile_t * ctx ) {
  (void)ctx;
  return 0;
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

static inline void
after_credit( fd_votor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {

  /* Standstill recovery first -- it pushes a Standstill event onto the
     pool's queue, which the drain below then dispatches in this same pass
     -- then the pool's two output queues, then the due timeouts
     (timeout_receiver). */

  standstill_poll( ctx );

  int did_work = drain_pool_channels( ctx );

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

    /* All2All broadcast: votes and certs go out to every peer as
       VersionedWireConsensusMessage::V1.  The votor_out publish below is
       the local fanout (replay / repair / shred), not the network path. */
    if( FD_UNLIKELY( pub->bcast && FD_VOTOR_SIG_KIND( pub->sig )==FD_VOTOR_SIG_VOTE ) ) {
      uchar buf[ AG_VOTE_SERIALIZED_MAX ];
      ulong sz = ag_vote_serialize( &pub->msg.vote, buf, sizeof(buf), ctx->shred_version );
      FD_TEST( sz );
      broadcast( ctx, buf, sz );
    } else if( FD_UNLIKELY( pub->bcast && FD_VOTOR_SIG_KIND( pub->sig )==FD_VOTOR_SIG_CERT ) ) {
      uchar buf[ AG_CERT_SERIALIZED_MAX ];
      ulong sz = ag_cert_serialize( &pub->msg.cert, buf, sizeof(buf), ctx->shred_version );
      if( FD_LIKELY( sz ) ) broadcast( ctx, buf, sz );
    }

    memcpy( fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk ), &pub->msg, sizeof(ag_votor_msg_t) );
    fd_stem_publish( stem, OUT_IDX, pub->sig, ctx->out_chunk, sizeof(ag_votor_msg_t), 0UL, ts, ts );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(ag_votor_msg_t), ctx->out_chunk0, ctx->out_wmark );
    ctx->out_seq   = stem->seqs[ OUT_IDX ];
    *opt_poll_in   = 0; /* drain the publishes */
    *charge_busy   = 1;
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
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET ) ) {
    if( FD_UNLIKELY( !ctx->init ) ) return 1;
    return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_ALPENGLOW;
  }
  /* Backpressure slot completions while signing is halted (keyswitch):
     returning -1 leaves the frag on the mcache to be reprocessed.  Best
     effort only -- replay_out is consumed unreliable, so replay may lap us
     while halted. */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY && ctx->halt_signing && sig==REPLAY_SIG_SLOT_COMPLETED ) ) return -1;
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

  ctx->skip_frag = 0;
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_NET: {
    if( FD_UNLIKELY( sz>FD_NET_MTU ) ) { ctx->skip_frag = 1; return; }
    void const * src = fd_net_rx_translate_frag( &ctx->net_in_bounds[ in_idx ], chunk, ctl, sz );
    fd_memcpy( ctx->net_buf, src, sz );
    return;
  }
  case IN_KIND_REPLAY:
  case IN_KIND_GOSSIP:
  case IN_KIND_EPOCH: {
    if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) {
      ctx->skip_frag = 1;
      return;
    }
    ctx->msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    return;
  }
  default: return; /* IN_KIND_IPECHO: sig only */
  }
}

static inline void
after_frag( fd_votor_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub  FD_PARAM_UNUSED,
            fd_stem_context_t * stem ) {

  ctx->stem = stem;

  /* Stem verified the frag was not overrun during during_frag's copy, so a
     still-set skip_frag is genuine producer corruption, not a torn read. */
  if( FD_UNLIKELY( ctx->skip_frag ) )
    FD_LOG_ERR(( "frag %lu (sz %lu) from in %d corrupt", seq, sz, ctx->in_kind[ in_idx ] ));

  switch( ctx->in_kind[ in_idx ] ) {

  case IN_KIND_NET: {
    if( FD_LIKELY( ctx->quic_server && ctx->quic_client && sz>=sizeof(fd_eth_hdr_t) ) ) {
      uchar * l3    = ctx->net_buf + sizeof(fd_eth_hdr_t);
      ulong   l3_sz = sz - sizeof(fd_eth_hdr_t);
      ushort  dst_port = packet_dst_port( l3, l3_sz );
      if( FD_LIKELY( dst_port==ctx->quic_server_port ) ) {
        fd_quic_process_packet( ctx->quic_server, l3, l3_sz, ctx->now );
      } else if( FD_LIKELY( dst_port==ctx->quic_client_port ) ) {
        fd_quic_process_packet( ctx->quic_client, l3, l3_sz, ctx->now );
      }
    }
    break;
  }
  case IN_KIND_REPLAY:
    switch( sig ) {

    /* Replay finished executing a block.  halt_signing backpressure lives
       in before_frag (returns -1 to leave this frag on the mcache). */

    case REPLAY_SIG_SLOT_COMPLETED: {
      fd_replay_slot_completed_t const * sc = fd_type_pun_const( ctx->msg );
      ag_block_id_t block  = { .slot = sc->slot,        .hash = sc->block_id        };
      ag_block_id_t parent = { .slot = sc->parent_slot, .hash = sc->parent_block_id };

      ctx->init = 1;

      advance_epoch( ctx, &block, &parent );

      /* Register the block and its parent with the pool. */

      if( FD_LIKELY( block.slot>parent.slot ) ) {
        ag_pool_add_block( ctx->pool, &block, &parent );
      }

      /* Drive the votor's block availability handlers (first shred + block). */

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

      /* Replay froze this slot's bank -> advance our frozen-bank frontier;
         the finalization / root check runs at the end of after_frag. */

      if( FD_LIKELY( block.slot > ctx->highest_replayed_slot ) ) {
        ctx->highest_replayed_slot     = block.slot;
        ctx->highest_replayed_block_id = block.hash;
      }

      /* Queue the slot_done frag (reset target + echoed bank_idx). */

      publish_slot_done( ctx, &block, sc->bank_idx );

      if( LOGGING ) {
        FD_LOG_NOTICE(( "votor slot_completed slot=%lu parent=%lu finalized=%lu reset=%lu",
                        block.slot, parent.slot, ctx->root_slot, ctx->reset_slot ));
      }
      break;
    }

    /* An invalid block: drive the votor's invalid-block path so the slot
       gets skipped.  Only the slot number is needed; a dead slot has no
       block id consensus can use.  Dead slots below the consensus root are
       ignored -- they can no longer affect consensus, and the votor has
       already retired them. */

    case REPLAY_SIG_SLOT_DEAD: {
      fd_replay_slot_dead_t const * sd = fd_type_pun_const( ctx->msg );
      if( FD_UNLIKELY( sd->slot < ctx->root_slot ) ) break;

      ag_votor_blockstore_event_t ib = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_INVALID_BLOCK };
      ib.inner.invalid_block = sd->slot;
      ag_votor_handle_blockstore_event( ctx->votor, &ib );
      handle_votor_out( ctx );
      break;
    }

    case REPLAY_SIG_FINAL_CERT: {
      /* A CERT message that happens to arrive on the replay link:
         finalization cert(s) lifted out of an Alpenglow block footer,
         already verified there (verify_footer_final_cert).  Duplicates and
         out-of-bounds are routine -- network certs finalize (and prune)
         ahead of replay, so a footer cert for a just-replayed slot can
         trail the prune watermark.  Anything else from a replay-verified
         cert is an invariant violation. */
      if( FD_UNLIKELY( !ctx->have_schedule ) ) break;
      fd_replay_final_cert_t const * final_cert = fd_type_pun_const( ctx->msg );
      for( ulong i=0UL; i<final_cert->cert_cnt; i++ ) {
        ag_cert_t const * cert = fd_type_pun_const( &final_cert->certs[ i ] );

        if( FD_UNLIKELY( ctx->publish_rx ) )
          publishes_push_head( ctx->publishes, (publish_t){ .sig = FD_VOTOR_SIG_CERT|FD_VOTOR_SIG_RX, .msg.cert = *cert } );

        /* A cert whose epoch is not the active one, or that does not
           validate against the set of its own slot, cannot be scored
           here; drop it as out of bounds rather than handing the pool
           something it assumes is already validated. */

        int   err        = AG_POOL_ERR_SLOT_OUT_OF_BOUNDS;
        ulong cert_epoch = fd_slot_to_epoch( &ctx->epoch_schedule, ag_cert_slot( cert ), NULL );
        if( FD_LIKELY( cert_epoch==ctx->active_epoch && validated_cert( ctx, cert ) ) ) {
          err = ag_pool_add_cert( ctx->pool, cert );
          if( FD_LIKELY( err==AG_POOL_SUCCESS ) ) maybe_publish_finalized( ctx );
        }

        if( FD_UNLIKELY( err!=AG_POOL_SUCCESS                &&
                         err!=AG_POOL_ERR_DUPLICATE          &&
                         err!=AG_POOL_ERR_SLOT_OUT_OF_BOUNDS ) ) {
          FD_LOG_CRIT(( "ag_pool_add_cert failed for cert %lu: %d. slot: %lu, finalized slot: %lu",
                        i, err, ag_cert_slot( cert ), ag_pool_finalized_slot( ctx->pool ) ));
        }
      }
      break;
    }

    default: break;
    }
    break;
  case IN_KIND_GOSSIP: {
    fd_gossip_update_message_t const * msg = fd_type_pun_const( ctx->msg );
    if(      sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO        ) handle_contact_info_update( ctx, msg );
    else if( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) handle_contact_info_remove( ctx, msg );
    break;
  }
  case IN_KIND_EPOCH: {
    fd_epoch_info_msg_t const *    msg    = fd_type_pun_const( ctx->msg );
    FD_TEST( msg->staked_vote_cnt<=MAX_COMPRESSED_STAKE_WEIGHTS );
    FD_TEST( msg->staked_id_cnt<=MAX_SHRED_DESTS );
    fd_vote_stake_weight_t const * stakes = fd_epoch_info_msg_stake_weights( msg );
    update_epoch_vtrs( ctx, msg, stakes, msg->staked_vote_cnt );
    break;
  }
  case IN_KIND_IPECHO: {
    FD_TEST( sig && sig<=USHORT_MAX );
    ctx->shred_version = (ushort)sig;
    if( FD_LIKELY( ctx->votor ) ) ag_votor_set_shred_version( ctx->votor, ctx->shred_version );
    break;
  }
  default: FD_LOG_ERR(( "unexpected input kind %d", ctx->in_kind[ in_idx ] ));
  }

  /* Publish any finalized / rooted advance exactly once per frag, rather
     than inside the individual handlers.  (The before_credit quic_service
     ingest path is covered by after_credit: a finalization-advancing cert
     always emits a CertCreated pool event, so did_work fires there.) */
  maybe_publish_finalized( ctx );
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
     TODO: switch to the authorized-voter keypair (via the sign tile?). */

  uchar const * id_kp = fd_keyload_load( tile->tower.identity_key, /* pubkey only: */ 0 );
  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( id_kp + 32UL );

  /* Derive only the PUBLIC half of the BLS voting key here, so we can
     check it against the on-chain registration; the sign tile derives
     the same key independently and is the only holder of the secret.
     The intermediate key material is scrubbed before we continue. */
  static char const derive_msg[] = "bls-key-derive-alpenglow"; /* "bls-key-derive-" || BLS_KEYPAIR_DERIVE_SEED */
  uchar          ikm[ 64 ];
  ag_aggsig_sk_t sk[ 1 ];
  fd_sha512_t   _sha[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL,
                   id_kp+32UL /* pubkey */, id_kp /* private */, sha );
  fd_sha512_leave( sha );

  ag_aggsig_sk_derive( sk, ikm, sizeof(ikm) );
  ag_aggsig_sk_to_pk( ctx->voting_pubkey, sk );
  fd_memzero_explicit( sk,  sizeof(sk)  );
  fd_memzero_explicit( ikm, sizeof(ikm) );

  /* Install the production signer.  unprivileged_init requires this to be
     set; scratch is not zeroed between runs, so it must be written
     explicitly, not defaulted. */
  ctx->sign_fn  = keyguard_sign;
  ctx->sign_ctx = ctx;

  /* fd_quic_service / fd_log_wallclock virtualizes clock_gettime via the
     vDSO, whose first call mmaps shared memory; force that before the
     sandbox is installed (see fd_quic_tile.c privileged_init). */
  fd_log_wallclock();
}

/* init_choreo formats the consensus half of the tile: everything that
   depends only on the tile config and its scratch region -- the votor,
   pool, timeout heap, publish deque, epoch set regions and peer table.
   unprivileged_init calls this first and then wires up the parts that
   need the topology (links, workspaces, keyswitch, QUIC).

   Split out so the unit test can stand a tile up without a topology.
   ctx->seed / sign_fn / sign_ctx must already be set on scratch; see the
   note on those fields. */

static fd_votor_tile_t *
init_choreo( void *                 scratch,
             fd_topo_tile_t const * tile ) {
  ulong slot_max      = fd_ulong_pow2_up( tile->tower.max_live_slots );
  ulong pub_max       = slot_max * 8UL;
  int   quic_on       = tile->quic.max_concurrent_connections!=0UL;

  fd_quic_limits_t server_limits = {0};
  fd_quic_limits_t client_limits = {0};
  if( quic_on ) {
    server_limits = quic_server_limits( tile );
    client_limits = quic_client_limits();
  }

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t)                                   );
  void * votor           = FD_SCRATCH_ALLOC_APPEND( l, ag_votor_align(),         ag_votor_footprint( slot_max )                            );
  void * pool            = FD_SCRATCH_ALLOC_APPEND( l, ag_pool_align(),          ag_pool_footprint( slot_max ) );
  void * timeouts_heap   = FD_SCRATCH_ALLOC_APPEND( l, fd_timeout_heap_align(),  fd_timeout_heap_footprint( slot_max )                     );
  void * timeouts_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_timeout_pool_align(),  fd_timeout_pool_footprint( slot_max )                     );
  void * epoch_curr_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t)                                   );
  void * epoch_next_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t)                                   );
  void * publishes       = FD_SCRATCH_ALLOC_APPEND( l, publishes_align(),        publishes_footprint( pub_max )                            );
  void * certified       = FD_SCRATCH_ALLOC_APPEND( l, alignof(certified_t),     sizeof(certified_t)*slot_max                              );
  void * ss_certs        = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_cert_t),       sizeof(ag_cert_t)*AG_POOL_STANDSTILL_CERT_MAX             );
  void * ss_votes        = FD_SCRATCH_ALLOC_APPEND( l, alignof(ag_vote_t),       sizeof(ag_vote_t)*AG_POOL_STANDSTILL_VOTE_MAX             );
  void * peer_pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),        peer_pool_footprint( VTR_MAX )                            );
  void * peer_map_mem    = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),         peer_map_footprint( peer_map_chain_cnt_est( VTR_MAX ) )   );
  void * peer_by_idx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_pubkey_t),     sizeof(fd_pubkey_t)*FD_CONTACT_INFO_TABLE_SIZE            );
  void * quic_server_mem = NULL;
  void * quic_client_mem = NULL;
  if( quic_on ) {
    quic_server_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),          fd_quic_footprint( &server_limits )                       );
    quic_client_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(),          fd_quic_footprint( &client_limits )                       );
  }
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  /* Set by privileged_init.  Asserted rather than defaulted: tile scratch
     is a wksp object that is NOT zeroed between runs, so testing for NULL
     here would read whatever the previous run left behind. */
  FD_TEST( ctx->sign_fn );

  /* keyguard_sign signs over the keyguard, which is only wired below when
     the tile has QUIC (and hence the votor_sign / sign_votor links).  A
     tile without them must have installed its own signer. */
  if( FD_UNLIKELY( ctx->sign_fn==keyguard_sign && !quic_on ) )
    FD_LOG_ERR(( "votor tile signs over the keyguard but has no sign_votor link" ));

  /* Scalar state first: scratch is not zeroed between runs, and the pool /
     votor constructors below read shred_version. */

  ctx->publish_rx            = 0;
  ctx->halt_signing          = 0;
  ctx->shred_version         = 0;
  ctx->init                  = 0;
  ctx->epoch                 = ULONG_MAX;
  ctx->root_slot             = ULONG_MAX; /* no root until the first slot completion adopts the snapshot */
  ctx->finalized_slot        = 0UL;
  ctx->highest_replayed_slot = 0UL;
  ctx->reset_slot            = 0UL;
  fd_memset( &ctx->root_block_id,             0, sizeof(fd_hash_t) );
  fd_memset( &ctx->highest_replayed_block_id, 0, sizeof(fd_hash_t) );

  ctx->slot_max      = slot_max;

  /* certified is direct-mapped by slot & (slot_max-1), so slot_max has to
     be the power of two scratch_footprint sized it as. */
  FD_TEST( fd_ulong_is_pow2( slot_max ) );
  ctx->certified = certified;
  memset( ctx->certified, 0, sizeof(certified_t)*slot_max );

  fd_memset( ctx->msg_reasm, 0, sizeof(ctx->msg_reasm) );

  ctx->curr.epoch = ULONG_MAX; ctx->curr.info = epoch_curr_mem;
  ctx->next.epoch = ULONG_MAX; ctx->next.info = epoch_next_mem;
  ctx->pool_curr_epoch = ULONG_MAX;
  ctx->pool_next_epoch = ULONG_MAX;
  ctx->active_epoch  = ULONG_MAX;
  ctx->epoch_info    = NULL;
  ctx->have_schedule = 0;

  /* Bootstrap single-validator set (just us at index 0).  ctx->validators
     is the staging buffer update_epoch_vtrs re-ranks into; the pool starts
     with an EMPTY epoch window and admits nothing until the first EPOCH
     msg installs a real set (update_epoch_vtrs -> sync_pool_epochs). */

  ctx->epoch_rank    = (ushort)0;
  ctx->validator_cnt = 1UL;
  memset( &ctx->validators[ 0 ], 0, sizeof(ag_validator_info_t) );
  ctx->validators[ 0 ].id            = 0UL;
  ctx->validators[ 0 ].stake         = 1UL;
  ctx->validators[ 0 ].voting_pubkey = *ctx->voting_pubkey;

  ctx->pool = ag_pool_join( ag_pool_new( pool, slot_max, ctx->seed ) );
  /* genesis baseline; re-rooted at the snapshot on the first slot */
  ag_pool_set_root( ctx->pool, 0UL, NULL );
  ctx->votor = ag_votor_join( ag_votor_new( votor, slot_max, ctx->epoch_rank, ctx->sign_fn, ctx->sign_ctx, ctx->shred_version, ctx->seed ) );

  ctx->timeouts_heap = fd_timeout_heap_join( fd_timeout_heap_new( timeouts_heap, slot_max ) );
  ctx->timeouts_pool = fd_timeout_pool_join( fd_timeout_pool_new( timeouts_pool, slot_max ) );
  ctx->publishes     = publishes_join( publishes_new( publishes, pub_max ) );

  ctx->peer_pool   = peer_pool_join( peer_pool_new( peer_pool_mem, VTR_MAX ) );
  ctx->peer_map    = peer_map_join ( peer_map_new ( peer_map_mem, peer_map_chain_cnt_est( VTR_MAX ), ctx->seed ) );
  ctx->peer_by_idx = peer_by_idx;
  memset( ctx->peer_by_idx, 0, sizeof(fd_pubkey_t)*FD_CONTACT_INFO_TABLE_SIZE );

  ctx->standstill_certs          = ss_certs;
  ctx->standstill_votes          = ss_votes;
  ctx->standstill_finalized_slot = 0UL;
  ctx->standstill_last_progress  = fd_log_wallclock();
  ctx->standstill_poll_deadline  = 0L;
  ctx->standstill_armed          = 0;

  FD_TEST( ctx->pool      );
  FD_TEST( ctx->votor     );
  FD_TEST( ctx->publishes );
  FD_TEST( ctx->peer_pool );
  FD_TEST( ctx->peer_map  );

  /* Handed to unprivileged_init rather than re-walked there: the layout
     above is the only place the QUIC regions are computed. */
  ctx->quic_server_mem = quic_server_mem;
  ctx->quic_client_mem = quic_client_mem;

  return ctx;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_votor_tile_t * ctx = init_choreo( scratch, tile );

  int quic_on = tile->quic.max_concurrent_connections!=0UL;
  fd_quic_limits_t server_limits = {0};
  fd_quic_limits_t client_limits = {0};
  if( quic_on ) {
    server_limits = quic_server_limits( tile );
    client_limits = quic_client_limits();
  }
  void * quic_server_mem = ctx->quic_server_mem;
  void * quic_client_mem = ctx->quic_client_mem;

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
    else if( FD_LIKELY( !strcmp( link->name, "net_alpenglow" ) ) ) ctx->in_kind[ i ] = IN_KIND_NET;
    else if( FD_LIKELY( !strcmp( link->name, "sign_votor"    ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_SIGN;
      sign_in_idx = i;
    }
    else FD_LOG_ERR(( "votor tile has unexpected input link %lu %s", i, link->name ));

    if( FD_UNLIKELY( ctx->in_kind[ i ]==IN_KIND_NET ) ) {
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

  /* QUIC: format both instances in the scratch reserved above, then wire
     the validator identity, config, TX aio (-> net) and votor_net out
     link.  Both stay NULL when the tile has no QUIC config, in which case
     it runs consensus only. */

  ctx->quic_server = NULL;
  ctx->quic_client = NULL;
  if( quic_on ) {
    if( FD_UNLIKELY( tile->out_cnt<2UL || strcmp( topo->links[ tile->out_link_id[ OUT_IDX_NET ] ].name, "votor_net" ) ) )
      FD_LOG_ERR(( "votor tile (with QUIC) requires a votor_net output link" ));

    ctx->quic_server = fd_quic_join( fd_quic_new( quic_server_mem, &server_limits ) );
    ctx->quic_client = fd_quic_join( fd_quic_new( quic_client_mem, &client_limits ) );
    FD_TEST( ctx->quic_server );
    FD_TEST( ctx->quic_client );

    if( FD_UNLIKELY( sign_in_idx==ULONG_MAX ) )
      FD_LOG_ERR(( "votor tile (with QUIC) requires a sign_votor input link" ));
    ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "votor_sign", tile->kind_id );
    if( FD_UNLIKELY( sign_out_idx==ULONG_MAX ) )
      FD_LOG_ERR(( "votor tile (with QUIC) requires a votor_sign output link" ));
    fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
    fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
    if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client, sign_out->mcache, sign_out->dcache, sign_in->mcache, sign_in->dcache, sign_out->mtu, sign_in->mtu ) ) ) ) {
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
    ctx->src_ip_addr      = tile->quic.alpenglow_ip_addr;
    ctx->quic_server_port = tile->quic.alpenglow_listen_port;
    ctx->quic_client_port = tile->quic.alpenglow_client_listen_port;
    ctx->publish_rx       = tile->quic.alpenglow_publish_rx;
    if( FD_UNLIKELY( !ctx->quic_server_port ) ) FD_LOG_ERR(( "votor tile (with QUIC) requires a non-zero alpenglow listen port" ));
    if( FD_UNLIKELY( !ctx->quic_client_port ) ) FD_LOG_ERR(( "votor tile (with QUIC) requires a non-zero alpenglow client port" ));
    if( FD_UNLIKELY( ctx->quic_server_port==ctx->quic_client_port ) ) FD_LOG_ERR(( "votor tile requires distinct alpenglow listen and client ports" ));

    ctx->quic_client->config.role                       = FD_QUIC_ROLE_CLIENT;
    ctx->quic_client->config.idle_timeout               = tile->quic.idle_timeout_millis * (long)1e6;
    ctx->quic_client->config.ack_delay                  = tile->quic.ack_delay_millis    * (long)1e6;
    ctx->quic_client->config.initial_rx_max_stream_data = 2048UL;
    ctx->quic_client->config.retry                      = tile->quic.retry;
    fd_memcpy( ctx->quic_client->config.identity_public_key, ctx->identity_key->uc, sizeof(fd_pubkey_t) );
    ctx->quic_client->config.sign       = quic_tls_cv_sign;
    ctx->quic_client->config.sign_ctx   = ctx;
    ctx->quic_client->cb.conn_final     = quic_client_conn_final;
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

#define STEM_BURST (2UL)        /* MAX over a single stem callback: (vote OR cert) AND (slot_done) */
#define STEM_LAZY  (128L*3000L) /* see explanation in fd_pack */

#define STEM_CALLBACK_CONTEXT_TYPE        fd_votor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_votor_tile_t)
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

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
