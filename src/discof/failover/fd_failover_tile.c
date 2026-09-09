#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/fd_version.h"

#include "fd_failover_channel.h"
#include "fd_failover_tls.h"

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
  int                     session_setup; /* silence window sized for this session */
  long                    last_status;
  long                    rtt_nanos;
  ulong                   peer_sent_at;  /* sent_at of the newest peer STATUS, 0 if none */
  long                    peer_recv_at;  /* our clock when it arrived */
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

  uchar rx[ FD_FAILOVER_PAYLOAD_MAX ];
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
    peer->member_idx = i;
    peer->dial       = ( i>ctx->self_idx );
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

  /* Every accepting peer would bind the same port today.  One listener
     shared by all peers is the follow-up that lifts the one-spare limit,
     until then the config caps the pool at two members. */
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

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  ctx->status_interval        = duration_nanos( tile->failov.status_interval_millis, 1000000UL );
  ctx->status_interval_millis = tile->failov.status_interval_millis;
  ctx->peer_silence_intervals = tile->failov.peer_silence_intervals;

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

/* Drive one peer's session from the run loop.  Channel time is the
   monotonic clock, wall clock steps must not drop a healthy session. */
static void
peer_poll( fd_failover_tile_ctx_t * ctx,
           fd_failover_peer_t *     peer,
           long                     now,
           int *                    charge_busy ) {
  ushort type;
  ulong  payload_sz;
  if( FD_UNLIKELY( fd_failover_channel_poll( peer->channel, now, charge_busy, &type, ctx->rx, &payload_sz ) ) ) {
    if( FD_LIKELY( type==(ushort)FD_FAILOVER_MSG_STATUS && payload_sz==sizeof(fd_failover_status_t) ) ) {
      fd_memcpy( &peer->status, ctx->rx, sizeof(fd_failover_status_t) );
      peer_rtt_sample( peer, now, &peer->status );
      peer->peer_sent_at = peer->status.sent_at;
      peer->peer_recv_at = now;
    }
  }

  if( FD_UNLIKELY( fd_failover_channel_state( peer->channel )!=FD_FAILOVER_SESSION_PAIRED ) ) {
    peer->last_status   = 0L;
    peer->peer_sent_at  = 0UL;
    peer->session_setup = 0;
    return;
  }
  if( FD_UNLIKELY( !peer->session_setup ) ) {
    /* Size the silence window from the slower of the two cadences, so
       members with different status_interval_millis settings hold. */
    ulong peer_millis = fd_ulong_min( fd_failover_channel_peer_hello( peer->channel )->status_interval_millis, FD_FAILOVER_TILE_PEER_MILLIS_MAX );
    ulong millis      = fd_ulong_max( ctx->status_interval_millis, peer_millis );
    fd_failover_channel_set_silence( peer->channel,
                                     duration_nanos( fd_ulong_sat_mul( millis, ctx->peer_silence_intervals ), 1000000UL ) );
    peer->session_setup = 1;
  }
  if( FD_LIKELY( fd_failover_channel_tx_pending( peer->channel ) ||
                 (now>=peer->last_status &&
                  fd_long_sat_sub( now, peer->last_status )<ctx->status_interval) ) ) return;

  fd_failover_status_t status;
  fd_memset( &status, 0, sizeof(status) );
  status.role             = (uchar)ctx->role;
  status.replay_slot      = FD_FAILOVER_SLOT_NULL;
  status.turbine_slot     = FD_FAILOVER_SLOT_NULL;
  status.last_vote_slot   = FD_FAILOVER_SLOT_NULL;
  status.root_slot        = FD_FAILOVER_SLOT_NULL;
  status.next_leader_slot = FD_FAILOVER_SLOT_NULL;
  status.ack_seq          = fd_failover_channel_ack_seq( peer->channel );
  status.sent_at          = (ulong)now;
  status.echo_sent_at     = peer->peer_sent_at;
  status.echo_delay       = peer->peer_sent_at ? (ulong)fd_long_sat_sub( now, peer->peer_recv_at ) : 0UL;

  if( FD_LIKELY( !fd_failover_channel_send( peer->channel, now, (ushort)FD_FAILOVER_MSG_STATUS,
                                            (uchar const *)&status, sizeof(status) ) ) ) {
    peer->last_status = now;
    *charge_busy = 1;
  }
}

static inline void
after_credit( fd_failover_tile_ctx_t * ctx,
              fd_stem_context_t *      stem FD_PARAM_UNUSED,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy ) {
  long now = fd_failover_clock();
  for( ulong i=0UL; i<ctx->peer_cnt; i++ ) peer_poll( ctx, &ctx->peers[ i ], now, charge_busy );
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
