#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/fd_version.h"

#include "fd_failover_channel.h"
#include "fd_failover_stream.h"
#include "fd_failover_tls.h"
#include "../tower/fd_tower_tile.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../ballet/txn/fd_txn.h"

#include <sys/socket.h>

#include "generated/fd_failover_tile_seccomp.h"

/* The failover tile owns every socket of the pool link and is the only
   tile that keeps host networking for it.  It holds the junk keypair for
   TLS and nothing else, the staked key never enters this tile.  The
   admin tile keeps the identity switch and stays off the network. */

/* Limits on what an authenticated but misconfigured peer can push.  A
   round trip sample above a minute is dropped, and an advertised STATUS
   cadence above a minute is clamped before it sizes the silence window. */
#define FD_FAILOVER_TILE_RTT_MAX_NANOS   (60000000000UL)
#define FD_FAILOVER_TILE_PEER_MILLIS_MAX (60000UL)

#define FD_FAILOVER_TILE_PEER_MAX (FD_TOPO_FAILOVER_MEMBER_MAX-1UL)

/* One pool peer, its session and what it last told us. */
struct fd_failover_peer {
  fd_failover_channel_t * channel;
  ulong                   member_idx;    /* position in the member list */
  int                     dial;          /* listed after us, so we dial it */
  fd_failover_status_t    status;        /* last STATUS from this peer */
  int                     status_valid;
  long                    status_time;
  ulong                   channel_state;      /* last seen session state, for edge detection */
  int                     session_setup; /* silence window sized for this session */
  long                    last_status;
  int                     status_sent;   /* sent in this session */
  long                    rtt_nanos;
  ulong                   peer_sent_at;  /* sent_at of the newest peer STATUS, 0 if none */
  long                    peer_recv_at;  /* our clock when it arrived */

  fd_failover_consensus_cache_t consensus; /* this peer's streamed tower */
  ulong                         lag_slots;
  int                           cs_sent;   /* our latest tower reached this peer */
};

typedef struct fd_failover_peer fd_failover_peer_t;

struct fd_failover_tile_ctx {
  uchar               identity_pubkey[ 32UL ];
  ulong               role;
  fd_failover_hello_t hello;

  ulong              member_cnt;
  ulong              self_idx;
  ulong              peer_cnt;
  fd_failover_peer_t peers[ FD_FAILOVER_TILE_PEER_MAX ];

  long  status_interval;
  ulong status_interval_millis;
  ulong peer_silence_intervals;
  ulong replication_lag_limit;

  uchar rx[ FD_FAILOVER_PAYLOAD_MAX ];

  ulong       tower_in_idx;
  fd_wksp_t * tower_in_mem;
  ulong       tower_in_chunk0;
  ulong       tower_in_wmark;

  fd_tower_slot_done_t slot_done;
  ulong                slot_done_seq;
  int                  slot_done_fresh;

  ulong replay_slot;
  ulong root_slot;
  ulong last_vote_slot;

  /* Latest locally produced tower and its delivery state. */
  uchar cs_buf[ sizeof(fd_failover_consensus_state_t)+FD_FAILOVER_TOWER_STATE_MAX ];
  ulong cs_sz;
  int   cs_valid;
};

typedef struct fd_failover_tile_ctx fd_failover_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_failover_tile_ctx_t), fd_failover_channel_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong peer_cnt = fd_ulong_sat_sub( tile->failov.member_cnt, 1UL );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t) );
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_failover_channel_align(), fd_failover_channel_footprint() );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static long
duration_nanos( ulong count,
                ulong nanos_per_unit ) {
  return (long)fd_ulong_min( fd_ulong_sat_mul( count, nanos_per_unit ),
                             (ulong)LONG_MAX );
}

/* pool_layout finds this machine in the member list by its junk key and
   lays out one peer per other member.  A member dials everyone listed
   after it and accepts from everyone listed before it.  Returns -1 when
   the junk key is missing from the list or listed twice. */
static int
pool_layout( fd_failover_tile_ctx_t * ctx,
             fd_topo_tile_t const *   tile,
             uchar const *            junk_pubkey ) {
  ctx->member_cnt = tile->failov.member_cnt;
  ctx->self_idx   = ULONG_MAX;
  for( ulong i=0UL; i<ctx->member_cnt; i++ ) {
    if( !fd_memeq( tile->failov.member_junk_pubkey[ i ], junk_pubkey, 32UL ) ) continue;
    if( FD_UNLIKELY( ctx->self_idx!=ULONG_MAX ) ) return -1;
    ctx->self_idx = i;
  }
  if( FD_UNLIKELY( ctx->self_idx==ULONG_MAX ) ) return -1;
  ctx->peer_cnt = 0UL;
  for( ulong i=0UL; i<ctx->member_cnt; i++ ) {
    if( i==ctx->self_idx ) continue;
    fd_failover_peer_t * peer = &ctx->peers[ ctx->peer_cnt++ ];
    peer->member_idx              = i;
    peer->dial                    = ( i>ctx->self_idx );
    peer->lag_slots               = FD_FAILOVER_SLOT_NULL;
    peer->status.replay_slot      = FD_FAILOVER_SLOT_NULL;
    peer->status.turbine_slot     = FD_FAILOVER_SLOT_NULL;
    peer->status.last_vote_slot   = FD_FAILOVER_SLOT_NULL;
    peer->status.root_slot        = FD_FAILOVER_SLOT_NULL;
    peer->status.next_leader_slot = FD_FAILOVER_SLOT_NULL;
  }
  return 0;
}

/* pool_listen_fd returns the listener socket, or -1 when this member only
   dials or has not bound yet. */
static int
pool_listen_fd( fd_failover_tile_ctx_t const * ctx ) {
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    fd_failover_peer_t const * peer = &ctx->peers[ i ];
    if( peer->dial || !peer->channel ) continue;
    int fd = fd_failover_channel_listen_fd( peer->channel );
    if( fd!=-1 ) return fd;
  }
  return -1;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_failover_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  ctx->replay_slot        = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot          = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot     = FD_FAILOVER_SLOT_NULL;

  if( FD_UNLIKELY( !strcmp( tile->failov.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  /* Only public keys are read here, the junk private key below is the
     one secret this tile keeps. */
  uchar const * identity_pubkey = fd_keyload_load( tile->failov.identity_key_path, 1 );
  fd_memcpy( ctx->identity_pubkey, identity_pubkey, 32UL );
  fd_keyload_unload( identity_pubkey, 1 );

  ctx->hello.version = (ushort)FD_FAILOVER_VERSION;
  uchar const * junk_pubkey = fd_keyload_load( tile->failov.junk_identity_path, 1 );
  fd_memcpy( ctx->hello.junk_pubkey, junk_pubkey, 32UL );
  fd_keyload_unload( junk_pubkey, 1 );
  uchar const * staked_pubkey = fd_keyload_load( tile->failov.staked_identity_path, 1 );
  fd_memcpy( ctx->hello.staked_pubkey, staked_pubkey, 32UL );
  fd_keyload_unload( staked_pubkey, 1 );

  if( FD_UNLIKELY( tile->failov.member_cnt<2UL ) ) {
    FD_LOG_ERR(( "[failover.members] lists %lu machines, a pool needs this one and at least one spare", tile->failov.member_cnt ));
  }
  if( FD_UNLIKELY( pool_layout( ctx, tile, ctx->hello.junk_pubkey ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( ctx->hello.junk_pubkey, junk_b58 );
    FD_LOG_ERR(( "this machine's junk identity %s must appear exactly once in [failover.member_junk_pubkeys]", junk_b58 ));
  }

  int is_junk   = fd_memeq( ctx->identity_pubkey, ctx->hello.junk_pubkey,   32UL );
  int is_staked = fd_memeq( ctx->identity_pubkey, ctx->hello.staked_pubkey, 32UL );
  if( FD_UNLIKELY( is_junk==is_staked ) ) {
    FD_LOG_ERR(( "`paths.identity_key` must match exactly one failover identity" ));
  }
  ctx->role       = is_staked ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY;
  ctx->hello.role = (uchar)ctx->role;
  uchar const * vote_account = fd_keyload_load( tile->failov.vote_account_path, 1 );
  fd_memcpy( ctx->hello.vote_account, vote_account, 32UL );
  fd_keyload_unload( vote_account, 1 );
  fd_memcpy( ctx->hello.commit, fd_commit_ref_cstr,
             fd_ulong_min( sizeof(ctx->hello.commit), strlen( fd_commit_ref_cstr ) ) );
  ctx->hello.cfg_hash = tile->failov.cfg_hash;
  ctx->hello.status_interval_millis = (uint)fd_ulong_min( tile->failov.status_interval_millis, UINT_MAX );
  FD_TEST( fd_rng_secure( &ctx->hello.boot_id, 8UL ) );

  /* One session object per peer, each pinned to that member's junk key.
     The junk keypair is loaded once and copied into every TLS context. */
  uchar const * junk_keypair = fd_keyload_load( tile->failov.junk_identity_path, 0 );
  ulong listen_cnt = 0UL;
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    fd_failover_peer_t * peer = &ctx->peers[ i ];
    void * ch_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_failover_channel_align(), fd_failover_channel_footprint() );
    peer->channel = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
    FD_TEST( peer->channel );
    int tls_err = fd_failover_channel_set_identity( peer->channel, junk_keypair, tile->failov.member_junk_pubkey[ peer->member_idx ], &ctx->hello );
    if( FD_UNLIKELY( tls_err ) ) {
      FD_LOG_ERR(( "failover TLS initialization failed for member %lu, check the junk keypair and the member keys", peer->member_idx ));
    }
    listen_cnt += (ulong)!peer->dial;
  }
  fd_keyload_unload( junk_keypair, 0 );

  /* Every accepting peer would bind the same port today. */
  if( FD_UNLIKELY( listen_cnt>1UL ) ) {
    FD_LOG_ERR(( "a member accepts from at most one peer today, [failover.members] lists %lu before this machine", listen_cnt ));
  }
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    fd_failover_peer_t * peer = &ctx->peers[ i ];
    if( peer->dial ) continue;
    /* Listeners bind here, the sandbox forbids bind once it is entered. */
    fd_failover_channel_init_listener( peer->channel, tile->failov.bind_addr, tile->failov.member[ ctx->self_idx ].port );
    fd_failover_channel_expect_peer( peer->channel, tile->failov.member[ peer->member_idx ].ip );
  }

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() )==(ulong)scratch+scratch_footprint( tile ) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void *                   scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_failover_tile_ctx_t * ctx     = (fd_failover_tile_ctx_t *)scratch;

  ctx->tower_in_idx = ULONG_MAX;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_LIKELY( !strcmp( link->name, "tower_out" ) ) ) {
      ctx->tower_in_idx    = i;
      ctx->tower_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->tower_in_chunk0 = fd_dcache_compact_chunk0( ctx->tower_in_mem, link->dcache );
      ctx->tower_in_wmark  = fd_dcache_compact_wmark( ctx->tower_in_mem, link->dcache, link->mtu );
      continue;
    }
    FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  ctx->status_interval        = duration_nanos( tile->failov.status_interval_millis, 1000000UL );
  ctx->status_interval_millis = tile->failov.status_interval_millis;
  ctx->peer_silence_intervals = tile->failov.peer_silence_intervals;
  ctx->replication_lag_limit  = tile->failov.replication_lag_slots;

  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) {
    fd_failover_peer_t * peer = &ctx->peers[ i ];
    fd_failover_channel_set_timing( peer->channel,
                                    FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS,
                                    duration_nanos( fd_ulong_sat_mul( tile->failov.status_interval_millis,
                                                                      tile->failov.peer_silence_intervals ), 1000000UL ),
                                    duration_nanos( tile->failov.retry_backoff_min_millis, 1000000UL ),
                                    duration_nanos( tile->failov.retry_backoff_max_millis, 1000000UL ) );
    if( FD_LIKELY( peer->dial ) ) {
      fd_topo_ip_port_t const * member = &tile->failov.member[ peer->member_idx ];
      fd_failover_channel_init_dialer( peer->channel, member->ip, member->port );
    }
    peer->channel_state = fd_failover_channel_state( peer->channel );
  }
}

/* The peer echoes our STATUS timestamp together with how long it held
   it, so its cadence drops out of the round trip sample. */
static void
peer_rtt_sample( fd_failover_peer_t *         peer,
                 long                         now,
                 fd_failover_status_t const * status ) {
  if( FD_UNLIKELY( !status->echo_sent_at || status->echo_sent_at>(ulong)now ) ) return;
  ulong elapsed = (ulong)now-status->echo_sent_at;
  if( FD_UNLIKELY( status->echo_delay>elapsed || elapsed>FD_FAILOVER_TILE_RTT_MAX_NANOS ) ) return;
  long sample = (long)( elapsed-status->echo_delay );
  peer->rtt_nanos = peer->rtt_nanos
    ? peer->rtt_nanos+(sample-peer->rtt_nanos)/8L
    : sample;
}

static void
peer_update_lag( fd_failover_peer_t * peer ) {
  peer->lag_slots = fd_failover_replication_lag( peer->status_valid,
                                                 &peer->status,
                                                 fd_failover_channel_peer_hello( peer->channel )->boot_id,
                                                 &peer->consensus );
}

/* A session edge invalidates everything the old session told us. */
static void
peer_sync_channel_state( fd_failover_peer_t * peer ) {
  ulong state = fd_failover_channel_state( peer->channel );
  if( FD_LIKELY( state==peer->channel_state ) ) return;

  peer->channel_state      = state;
  peer->status_valid       = 0;
  peer->status_time        = 0L;
  peer->peer_sent_at       = 0UL;
  peer->session_setup      = 0;
  peer->rtt_nanos          = 0L;
  if( FD_UNLIKELY( state==FD_FAILOVER_SESSION_PAIRED ) ) {
    peer->status_sent = 0;
    peer->cs_sent     = 0;
  }
  peer_update_lag( peer );
}

/* Turn the tower's vote transaction into the CONSENSUS_STATE frame every
   spare receives.  A malformed transaction is logged and skipped, the
   spares keep the previous tower. */
static void
prepare_consensus( fd_failover_tile_ctx_t *     ctx,
                   fd_tower_slot_done_t const * done ) {
  if( FD_UNLIKELY( !done->vote_txn_sz || done->vote_txn_sz>sizeof(done->vote_txn) ) ) {
    FD_LOG_WARNING(( "tower produced an invalid vote transaction size" ));
    return;
  }

  uchar txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_compact_tower_sync_serde_t serde;
  if( FD_UNLIKELY( !fd_txn_parse( done->vote_txn, done->vote_txn_sz, txn_mem, NULL ) ||
                   !fd_txn_parse_simple_vote( (fd_txn_t const *)txn_mem, done->vote_txn, &serde ) ) ) {
    FD_LOG_WARNING(( "tower produced an invalid vote transaction" ));
    return;
  }

  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong vote_cnt;
  ulong root;
  if( FD_UNLIKELY( fd_compact_tower_sync_to_votes( &serde, votes, &vote_cnt, &root ) ||
                   !vote_cnt || votes[ vote_cnt-1UL ].slot!=done->vote_slot ) ) {
    FD_LOG_WARNING(( "tower vote transaction does not match its slot metadata" ));
    return;
  }

  ulong state_sz = 0UL;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( &serde,
                                              ctx->cs_buf+sizeof(fd_failover_consensus_state_t),
                                              FD_FAILOVER_TOWER_STATE_MAX,
                                              &state_sz ) ) ) {
    FD_LOG_WARNING(( "tower vote transaction exceeds the failover state limit" ));
    return;
  }

  fd_failover_consensus_state_t msg = {
    .term      = ctx->hello.term,
    .link_seq  = ctx->slot_done_seq,
    .vote_slot = done->vote_slot,
    .mode      = (uchar)FD_FAILOVER_MODE_TOWER,
    .state_len = (ushort)state_sz,
  };
  fd_memcpy( ctx->cs_buf, &msg, sizeof(msg) );
  ctx->cs_sz    = sizeof(msg)+state_sz;
  ctx->cs_valid = 1;
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) ctx->peers[ i ].cs_sent = 0;
}

/* Fold one tower slot_done into the local slot view.  The tower can
   report slots out of order across forks, so the replay slot is a
   running maximum. */
static void
consume_slot_done( fd_failover_tile_ctx_t *     ctx,
                   fd_tower_slot_done_t const * done ) {
  if( FD_LIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || done->replay_slot>ctx->replay_slot ) )
    ctx->replay_slot = done->replay_slot;
  if( FD_LIKELY( done->root_slot!=FD_FAILOVER_SLOT_NULL ) ) ctx->root_slot = done->root_slot;
  if( FD_LIKELY( done->has_vote_txn && done->vote_slot!=FD_FAILOVER_SLOT_NULL ) ) {
    ctx->last_vote_slot = done->vote_slot;
    if( FD_LIKELY( ctx->role==FD_FAILOVER_ROLE_ACTIVE ) ) prepare_consensus( ctx, done );
  }
}

/* Our side of STATUS for one peer. */
static fd_failover_status_t
local_status( fd_failover_tile_ctx_t const * ctx,
              fd_failover_peer_t const *     peer ) {
  fd_failover_status_t status;
  fd_memset( &status, 0, sizeof(status) );
  status.term             = ctx->hello.term;
  status.role             = (uchar)ctx->role;
  status.replay_slot      = ctx->replay_slot;
  status.turbine_slot     = FD_FAILOVER_SLOT_NULL;
  status.last_vote_slot   = ctx->last_vote_slot;
  status.root_slot        = ctx->root_slot;
  status.next_leader_slot = FD_FAILOVER_SLOT_NULL;
  if( FD_UNLIKELY( peer->lag_slots!=FD_FAILOVER_SLOT_NULL && peer->lag_slots>ctx->replication_lag_limit ) ) {
    status.status |= FD_FAILOVER_STATUS_REPLAG;
  }
  status.ack_seq = fd_failover_channel_ack_seq( peer->channel );
  return status;
}

/* Drive one peer's session from the run loop.  Channel time is the
   monotonic clock, wall clock steps must not drop a healthy session. */
static void
peer_poll( fd_failover_tile_ctx_t * ctx,
           fd_failover_peer_t *     peer,
           long                     now,
           int *                    charge_busy ) {
  peer_sync_channel_state( peer );

  ushort type;
  ulong  payload_sz;
  if( FD_UNLIKELY( fd_failover_channel_poll( peer->channel, now, charge_busy, &type, ctx->rx, &payload_sz ) ) ) {
    if( FD_LIKELY( type==(ushort)FD_FAILOVER_MSG_STATUS ) ) {
      fd_failover_status_t status;
      if( FD_UNLIKELY( !fd_failover_status_decode( &status,
                                                   fd_failover_channel_peer_hello( peer->channel ),
                                                   fd_failover_channel_tx_seq( peer->channel ),
                                                   ctx->rx,
                                                   payload_sz ) ) ) {
        fd_failover_channel_protocol_error( peer->channel, now );
        peer_sync_channel_state( peer );
        return;
      }
      peer->status       = status;
      peer->status_valid = 1;
      peer->status_time  = now;
      peer_update_lag( peer );
      peer_rtt_sample( peer, now, &status );
      peer->peer_sent_at = status.sent_at;
      peer->peer_recv_at = now;
    } else if( FD_LIKELY( type==(ushort)FD_FAILOVER_MSG_CONSENSUS_STATE ) ) {
      if( FD_UNLIKELY( !fd_failover_consensus_decode( &peer->consensus,
                                                      ctx->role,
                                                      fd_failover_channel_peer_hello( peer->channel ),
                                                      ctx->rx,
                                                      payload_sz ) ) ) {
        fd_failover_channel_protocol_error( peer->channel, now );
        peer_sync_channel_state( peer );
        return;
      }
      peer_update_lag( peer );
    }
  }

  peer_sync_channel_state( peer );

  if( FD_UNLIKELY( fd_failover_channel_state( peer->channel )!=FD_FAILOVER_SESSION_PAIRED ) ) return;

  if( FD_UNLIKELY( !peer->session_setup ) ) {
    /* Size the silence window from the slower of the two cadences, so
       members with different status_interval_millis settings hold. */
    ulong peer_millis = fd_ulong_min( fd_failover_channel_peer_hello( peer->channel )->status_interval_millis, FD_FAILOVER_TILE_PEER_MILLIS_MAX );
    ulong millis      = fd_ulong_max( ctx->status_interval_millis, peer_millis );
    fd_failover_channel_set_silence( peer->channel,
                                     duration_nanos( fd_ulong_sat_mul( millis, ctx->peer_silence_intervals ), 1000000UL ) );
    peer->session_setup = 1;
  }

  int status_due = !peer->status_sent ||
                   now<peer->last_status ||
                   fd_long_sat_sub( now, peer->last_status )>=ctx->status_interval;
  if( FD_UNLIKELY( status_due && !fd_failover_channel_tx_pending( peer->channel ) ) ) {
    fd_failover_status_t status = local_status( ctx, peer );
    status.sent_at      = (ulong)now;
    status.echo_sent_at = peer->peer_sent_at;
    status.echo_delay   = peer->peer_sent_at ? (ulong)fd_long_sat_sub( now, peer->peer_recv_at ) : 0UL;

    if( FD_LIKELY( !fd_failover_channel_send( peer->channel, now, (ushort)FD_FAILOVER_MSG_STATUS,
                                              (uchar const *)&status, sizeof(status) ) ) ) {
      peer->last_status = now;
      peer->status_sent = 1;
      *charge_busy = 1;
    }
  }

  if( FD_UNLIKELY( ctx->role==FD_FAILOVER_ROLE_ACTIVE &&
                   ctx->cs_valid &&
                   !peer->cs_sent &&
                   !fd_failover_channel_tx_pending( peer->channel ) &&
                   fd_failover_channel_state( peer->channel )==FD_FAILOVER_SESSION_PAIRED &&
                   !fd_failover_channel_send( peer->channel, now, (ushort)FD_FAILOVER_MSG_CONSENSUS_STATE,
                                              ctx->cs_buf, ctx->cs_sz ) ) ) {
    peer->cs_sent = 1;
    *charge_busy = 1;
  }

  peer_sync_channel_state( peer );
}

static inline void
after_credit( fd_failover_tile_ctx_t * ctx,
              fd_stem_context_t *      stem FD_PARAM_UNUSED,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy ) {
  if( FD_UNLIKELY( ctx->slot_done_fresh ) ) {
    ctx->slot_done_fresh = 0;
    consume_slot_done( ctx, &ctx->slot_done );
  }
  long now = fd_failover_clock();
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) peer_poll( ctx, &ctx->peers[ i ], now, charge_busy );
}

static inline int
before_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq FD_PARAM_UNUSED,
             ulong                    sig ) {
  if( FD_LIKELY( in_idx==ctx->tower_in_idx ) ) return sig!=FD_TOWER_SIG_SLOT_DONE;
  return 0;
}

static void
during_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq FD_PARAM_UNUSED,
             ulong                    sig FD_PARAM_UNUSED,
             ulong                    chunk,
             ulong                    sz,
             ulong                    ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx!=ctx->tower_in_idx ) ) return;
  if( FD_UNLIKELY( chunk<ctx->tower_in_chunk0 || chunk>ctx->tower_in_wmark || sz!=sizeof(fd_tower_msg_t) ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->tower_in_chunk0, ctx->tower_in_wmark ));
  }
  fd_memcpy( &ctx->slot_done, fd_chunk_to_laddr_const( ctx->tower_in_mem, chunk ), sizeof(fd_tower_slot_done_t) );
}

static void
after_frag( fd_failover_tile_ctx_t * ctx,
            ulong                    in_idx,
            ulong                    seq,
            ulong                    sig FD_PARAM_UNUSED,
            ulong                    sz FD_PARAM_UNUSED,
            ulong                    tsorig FD_PARAM_UNUSED,
            ulong                    tspub FD_PARAM_UNUSED,
            fd_stem_context_t *      stem FD_PARAM_UNUSED ) {
  if( FD_LIKELY( in_idx!=ctx->tower_in_idx ) ) return;
  ctx->slot_done_seq   = seq;
  ctx->slot_done_fresh = 1;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  /* One policy covers both directions.  A member that only dials has no
     listener, so accept4 is pinned to a descriptor that is never a socket
     and would fail with EBADF.  The channel never calls accept4 on a
     dialing peer anyway. */
  populate_sock_filter_policy_fd_failover_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)pool_listen_fd( ctx ) );
  return sock_filter_policy_fd_failover_tile_instr_cnt;
}

/* Candidates, one listener and the tile's own descriptors.  This tracks
   the member count so the limit survives a larger pool. */
static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  ulong peer_cnt = fd_ulong_sat_sub( tile->failov.member_cnt, 1UL );
  return FD_FAILOVER_CHANNEL_CANDIDATE_MAX*peer_cnt + peer_cnt + 8UL;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  int logfile_fd = fd_log_private_logfile_fd();
  int listen_fd  = pool_listen_fd( ctx );

  ulong required_fds = 1UL + (ulong)(-1!=logfile_fd) + (ulong)(-1!=listen_fd);
  if( FD_UNLIKELY( out_fds_cnt<required_fds ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY(   -1!=logfile_fd ) ) out_fds[ out_cnt++ ] = logfile_fd; /* logfile */
  if( FD_UNLIKELY( -1!=listen_fd  ) ) out_fds[ out_cnt++ ] = listen_fd;  /* pool listener */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_failover_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_failover_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_failov = {
  .name                     = "failov",
  .keep_host_networking     = 1,
  .allow_connect            = 1,
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
