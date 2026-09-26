#include "../../disco/topo/fd_topo.h"
#include "../../disco/topo/fd_dns_resolve.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../util/fd_version.h"
#include "../../util/net/fd_ip4.h"

#include "fd_failover_channel.h"

#include <string.h>
#include <sys/socket.h>

#include "generated/fd_failover_tile_seccomp.h"

/* The failov tile owns the socket to the other failover machine and is
   the only tile that keeps host networking for it.  It holds this
   machine's junk keypair for TLS and nothing else, the staked key never
   enters this tile.  The sign tile signs our member certificate. */

/* Idle socket poll spacing */
#define FD_FAILOVER_TILE_POLL_NANOS (50000L) /* 50us */

struct fd_failover_tile_ctx {
  fd_keyguard_client_t    keyguard_client[ 1 ];
  int                     member_cert_set;

  fd_failover_hello_t     hello;
  ulong                   role;
  uint                    config_addr;   /* [failover.peer_address] resolved, 0 when gossip finds the active */
  ushort                  port;
  fd_failover_channel_t * channel;
  ulong                   channel_state; /* last seen session state, for edge detection */
  long                    poll_at;       /* next idle socket poll */

  fd_failover_status_t    peer_status;       /* last STATUS from the peer */
  int                     peer_status_valid; /* one arrived in this session */
  long                    status_at;         /* when we last sent STATUS */
  int                     status_sent;       /* sent in this session */

  /* gossip_out, polled unreliably for contact infos */
  ulong                   gossip_in_idx;
  fd_wksp_t *             gossip_in_mem;
  ulong                   gossip_in_chunk0;
  ulong                   gossip_in_wmark;
  ulong                   gossip_in_mtu;

  fd_ip4_port_t           own_gossip;          /* our own gossip socket */
  uchar                   gossip_origin[ 32 ]; /* copied in during_frag */
  fd_ip4_port_t           gossip_socket;       /* copied in during_frag, zero for a remove or IPv6 */
  uint                    staked_addr;         /* from a staked contact info that is not ours, 0 none */
  long                    staked_seen_at;      /* our clock when that one arrived, 0 never */

  uchar                   rx[ FD_FAILOVER_PAYLOAD_MAX ];
};

typedef struct fd_failover_tile_ctx fd_failover_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_failover_tile_ctx_t), fd_failover_channel_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t)  );
  l = FD_LAYOUT_APPEND( l, fd_failover_channel_align(),     fd_failover_channel_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_failover_tile_ctx_t * ctx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_failover_tile_ctx_t), sizeof(fd_failover_tile_ctx_t)  );
  void *                   channel_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_failover_channel_align(),     fd_failover_channel_footprint() );
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );

  /* [failover.junk_identity_key] is this machine's junk key, the keypair
     goes into HELLO and TLS.  We read only the public half of the staked
     [paths.identity_key]. */
  uchar const * junk_keypair  = fd_keyload_load( tile->failov.identity_key_path, 0 );
  uchar const * staked_pubkey = fd_keyload_load( tile->failov.staked_key_path,   1 ); /* public key only, like the other tiles' identity loads */
  fd_memcpy( ctx->hello.junk_pubkey,   junk_keypair+32UL, 32UL );
  fd_memcpy( ctx->hello.staked_pubkey, staked_pubkey,     32UL );
  fd_keyload_unload( staked_pubkey, 1 );

  if( FD_UNLIKELY( fd_memeq( ctx->hello.junk_pubkey, ctx->hello.staked_pubkey, 32UL ) ) ) {
    FD_LOG_ERR(( "[failover.junk_identity_key] `%s` is the staked [paths.identity_key], each failover machine boots under its own key", tile->failov.identity_key_path ));
  }

  /* The vote key is a base58 pubkey or a keypair file, same as in the
     tower tile. */
  if( FD_UNLIKELY( !fd_base58_decode_32( tile->failov.vote_account_path, ctx->hello.vote_account ) ) ) {
    if( FD_UNLIKELY( !strcmp( tile->failov.vote_account_path, "" ) ) ) FD_LOG_ERR(( "missing [paths.vote_account]" ));
    uchar const * vote_account = fd_keyload_load( tile->failov.vote_account_path, 1 );
    fd_memcpy( ctx->hello.vote_account, vote_account, 32UL );
    fd_keyload_unload( vote_account, 1 );
  }

  /* Every boot runs the junk key, so we start as a standby. */
  ctx->role          = FD_FAILOVER_ROLE_STANDBY;
  ctx->hello.version = (ushort)FD_FAILOVER_VERSION;
  ctx->hello.role    = (uchar)ctx->role;
  ctx->hello.mode    = (uchar)FD_FAILOVER_MODE_TOWER;
  while( FD_UNLIKELY( !ctx->hello.boot_id ) ) FD_TEST( fd_rng_secure( &ctx->hello.boot_id, sizeof(ulong) ) );
  /* The commit field has the hash bytes, a build without one leaves it
     zero. */
  if( FD_LIKELY( strlen( fd_commit_ref_cstr )==2UL*sizeof(ctx->hello.commit) &&
                 fd_hex_decode( ctx->hello.commit, fd_commit_ref_cstr, sizeof(ctx->hello.commit) )!=sizeof(ctx->hello.commit) ) ) {
    fd_memset( ctx->hello.commit, 0, sizeof(ctx->hello.commit) );
  }
  ctx->hello.cfg_hash = fd_failover_cfg_hash( ctx->hello.staked_pubkey, ctx->hello.vote_account, ctx->hello.mode );
  ctx->port = tile->failov.port;

  /* Same resolution as the gossip tile, so our own staked contact info
     is never taken for the peer's. */
  ctx->own_gossip = tile->failov.gossip_addr;
  if( FD_UNLIKELY( tile->failov.gossip_host[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( !fd_dns_resolve_address( tile->failov.gossip_host, &ctx->own_gossip.addr ) ) ) {
      FD_LOG_ERR(( "could not resolve [gossip.host] `%s`", tile->failov.gossip_host ));
    }
  }

  ctx->channel = fd_failover_channel_join( fd_failover_channel_new( channel_mem ) );
  FD_TEST( ctx->channel );
  if( FD_UNLIKELY( fd_failover_channel_set_identity( ctx->channel, junk_keypair, &ctx->hello ) ) ) {
    FD_LOG_ERR(( "failover TLS setup failed for [failover.junk_identity_key] `%s`", tile->failov.identity_key_path ));
  }
  fd_keyload_unload( junk_keypair, 0 );

  /* Every member listens on all interfaces, and the sandbox forbids
     bind.  A configured peer address is dialed while we stand by and
     keeps its room on the listener.  Without one we dial nothing until
     gossip gives us the active's address. */
  fd_failover_channel_init_listener( ctx->channel, 0U, tile->failov.port );
  if( FD_UNLIKELY( tile->failov.peer_address[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( !fd_dns_resolve_address( tile->failov.peer_address, &ctx->config_addr ) || !ctx->config_addr ) ) {
      FD_LOG_ERR(( "could not resolve [failover.peer_address] `%s`", tile->failov.peer_address ));
    }
    if( FD_UNLIKELY( ctx->config_addr==ctx->own_gossip.addr || ctx->config_addr==tile->failov.gossip_addr.addr ) ) {
      FD_LOG_ERR(( "[failover.peer_address] `%s` is this machine's own address `" FD_IP4_ADDR_FMT "`, set it to the other failover machine",
                   tile->failov.peer_address, FD_IP4_ADDR_FMT_ARGS( ctx->config_addr ) ));
    }
    fd_failover_channel_expect_peer( ctx->channel, ctx->config_addr );
    fd_failover_channel_init_dialer( ctx->channel, ctx->config_addr, tile->failov.port );
    FD_LOG_NOTICE(( "failover peer is `%s` at `" FD_IP4_ADDR_FMT "` from [failover.peer_address], we dial it while we stand by",
                    tile->failov.peer_address, FD_IP4_ADDR_FMT_ARGS( ctx->config_addr ) ));
  } else {
    FD_LOG_NOTICE(( "no [failover.peer_address], we find the active through the staked identity's contact info in gossip" ));
  }
  ctx->channel_state = fd_failover_channel_state( ctx->channel );

  char junk_b58  [ FD_BASE58_ENCODED_32_SZ ];
  char staked_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( ctx->hello.junk_pubkey,   NULL, junk_b58   );
  fd_base58_encode_32( ctx->hello.staked_pubkey, NULL, staked_b58 );
  FD_LOG_NOTICE(( "failover is on, booting as a standby under junk identity `%s` for staked identity `%s`, listening on [failover.port] `%u`, "
                  "this machine votes only after `failover promote` or a handoff", junk_b58, staked_b58, (uint)tile->failov.port ));

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() )==(ulong)scratch+scratch_footprint( tile ) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_failover_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ctx->gossip_in_idx = ULONG_MAX;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_LIKELY( !strcmp( link->name, "gossip_out" ) ) ) {
      ctx->gossip_in_idx    = i;
      ctx->gossip_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->gossip_in_chunk0 = fd_dcache_compact_chunk0( ctx->gossip_in_mem, link->dcache );
      ctx->gossip_in_wmark  = fd_dcache_compact_wmark ( ctx->gossip_in_mem, link->dcache, link->mtu );
      ctx->gossip_in_mtu    = link->mtu;
      continue;
    }
    if( FD_UNLIKELY( strcmp( link->name, "sign_failov" ) ) ) FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_failov", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "failov_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX && sign_out_idx!=ULONG_MAX );
  fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];

  fd_sleep_t * sleep = NULL;
  if( FD_UNLIKELY( topo->sleep_obj_id!=ULONG_MAX ) ) {
    sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
    FD_TEST( sleep );
  }

  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                                     sign_out->mcache,
                                                                     sign_out->dcache,
                                                                     sign_in->mcache,
                                                                     sign_in->dcache,
                                                                     sign_out->mtu,
                                                                     sign_in->mtu,
                                                                     sleep,
                                                                     sign_out->id,
                                                                     fd_topo_find_link_consumer( topo, sign_out ) ) ) ) ) {
    FD_LOG_ERR(( "failed to construct keyguard" ));
  }
}

/* Before we pair, the sign tile signs our member certificate with the
   staked key.  It checks the message is the cert prefix and its own
   junk pubkey. */
static void
request_member_cert( fd_failover_tile_ctx_t * ctx ) {
  uchar msg [ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  uchar cert[ 64 ];
  fd_failover_member_cert_msg( msg, ctx->hello.junk_pubkey );
  fd_keyguard_client_sign( ctx->keyguard_client, cert, msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_ED25519 );
  if( FD_UNLIKELY( fd_failover_channel_set_member_cert( ctx->channel, cert ) ) ) {
    FD_LOG_ERR(( "the sign tile signed our member certificate with a key other than the staked [paths.identity_key]" ));
  }
  ctx->member_cert_set = 1;
  FD_LOG_NOTICE(( "the sign tile signed our member certificate with the staked identity, we can pair now" ));
}

/* A session edge invalidates everything the old session told us. */
static void
sync_session( fd_failover_tile_ctx_t * ctx ) {
  ulong state = fd_failover_channel_state( ctx->channel );
  if( FD_LIKELY( state==ctx->channel_state ) ) return;
  ctx->channel_state     = state;
  ctx->peer_status_valid = 0;
  ctx->status_sent       = 0;
}

/* Our side of STATUS.  The slots stay unknown until the tower tile
   feeds us. */
static fd_failover_status_t
local_status( fd_failover_tile_ctx_t const * ctx,
              long                           now ) {
  fd_failover_status_t status;
  fd_memset( &status, 0, sizeof(status) );
  status.role           = (uchar)ctx->role;
  status.replay_slot    = FD_FAILOVER_SLOT_NULL;
  status.root_slot      = FD_FAILOVER_SLOT_NULL;
  status.last_vote_slot = FD_FAILOVER_SLOT_NULL;
  status.sent_at        = (ulong)now;
  status.echo_sent_at   = ctx->peer_status_valid ? ctx->peer_status.sent_at : 0UL;
  return status;
}

/* Drive the session from the run loop.  Channel time is the monotonic
   clock, wall clock steps must not drop a healthy session. */
static void
peer_poll( fd_failover_tile_ctx_t * ctx,
           long                     now,
           int *                    charge_busy ) {
  sync_session( ctx );

  ushort type;
  ulong  payload_sz;
  if( FD_UNLIKELY( fd_failover_channel_poll( ctx->channel, now, charge_busy, &type, ctx->rx, &payload_sz ) ) ) {
    if( FD_LIKELY( type==(ushort)FD_FAILOVER_MSG_STATUS ) ) {
      fd_failover_status_t status;
      if( FD_UNLIKELY( !fd_failover_status_decode( &status, ctx->rx, payload_sz ) ) ) {
        fd_failover_channel_protocol_error( ctx->channel, now );
        sync_session( ctx );
        return;
      }
      ctx->peer_status       = status;
      ctx->peer_status_valid = 1;
    }
  }

  sync_session( ctx );
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED ) ) return;

  /* The first STATUS goes out right after pairing, then one per
     interval. */
  int status_due = !ctx->status_sent ||
                   now<ctx->status_at ||
                   fd_long_sat_sub( now, ctx->status_at )>=FD_FAILOVER_STATUS_INTERVAL_NANOS;
  if( FD_UNLIKELY( status_due && !fd_failover_channel_tx_pending( ctx->channel ) ) ) {
    fd_failover_status_t status = local_status( ctx, now );
    if( FD_LIKELY( !fd_failover_channel_send( ctx->channel, now, (ushort)FD_FAILOVER_MSG_STATUS,
                                              (uchar const *)&status, sizeof(status) ) ) ) {
      ctx->status_at   = now;
      ctx->status_sent = 1;
      *charge_busy     = 1;
    }
  }

  sync_session( ctx );
}

/* Without [failover.peer_address] the peer's address comes from gossip,
   from the newest staked contact info that is not ours, which is how
   the active shows up.  A remove, IPv6 or zero address never clears what
   we know.  The member certificate authenticates the peer, so a wrong
   address only costs the pairing.  We dial it only while we are a
   standby.  With a configured address gossip only says when an active
   last published. */
static void
gossip_commit( fd_failover_tile_ctx_t * ctx,
               long                     now ) {
  uint addr = ctx->gossip_socket.addr;
  if( FD_UNLIKELY( !addr ) ) return;
  if( FD_LIKELY( !fd_memeq( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL ) ) ) return;
  if( FD_UNLIKELY( addr==ctx->own_gossip.addr && ctx->gossip_socket.port==ctx->own_gossip.port ) ) return;
  ctx->staked_seen_at = now;

  if( FD_UNLIKELY( ctx->config_addr ) ) return;
  if( FD_LIKELY( addr==ctx->staked_addr ) ) return;
  uint old_addr = ctx->staked_addr;
  ctx->staked_addr = addr;
  fd_failover_channel_init_dialer( ctx->channel, addr, ctx->port );
  sync_session( ctx );
  if( FD_LIKELY( !old_addr ) ) {
    FD_LOG_NOTICE(( "gossip shows the staked identity at `" FD_IP4_ADDR_FMT "`, we dial it while we stand by", FD_IP4_ADDR_FMT_ARGS( addr ) ));
  } else {
    FD_LOG_NOTICE(( "gossip shows the staked identity moved from `" FD_IP4_ADDR_FMT "` to `" FD_IP4_ADDR_FMT "`, we dial the new address while we stand by",
                    FD_IP4_ADDR_FMT_ARGS( old_addr ), FD_IP4_ADDR_FMT_ARGS( addr ) ));
  }
}

static inline int
before_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq FD_PARAM_UNUSED,
             ulong                    sig ) {
  if( FD_LIKELY( in_idx==ctx->gossip_in_idx ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO && sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }
  return 0;
}

static void
during_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq FD_PARAM_UNUSED,
             ulong                    sig,
             ulong                    chunk,
             ulong                    sz,
             ulong                    ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx!=ctx->gossip_in_idx ) ) return;
  if( FD_UNLIKELY( chunk<ctx->gossip_in_chunk0 || chunk>ctx->gossip_in_wmark || sz>ctx->gossip_in_mtu ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->gossip_in_chunk0, ctx->gossip_in_wmark ));
  }
  /* The link is unreliable, so we only copy here and after_frag commits
     once the stem has checked the copy.  A remove leaves the socket
     zero. */
  fd_gossip_update_message_t const * msg = fd_chunk_to_laddr_const( ctx->gossip_in_mem, chunk );
  fd_memcpy( ctx->gossip_origin, msg->origin, 32UL );
  ctx->gossip_socket.addr = 0U;
  ctx->gossip_socket.port = (ushort)0;
  if( FD_LIKELY( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) ) {
    fd_gossip_socket_t const * socket = &msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ];
    ctx->gossip_socket.addr = fd_uint_if  ( !socket->is_ipv6, socket->ip4,  0U        );
    ctx->gossip_socket.port = fd_ushort_if( !socket->is_ipv6, socket->port, (ushort)0 );
  }
}

static void
after_frag( fd_failover_tile_ctx_t * ctx,
            ulong                    in_idx,
            ulong                    seq    FD_PARAM_UNUSED,
            ulong                    sig    FD_PARAM_UNUSED,
            ulong                    sz     FD_PARAM_UNUSED,
            ulong                    tsorig FD_PARAM_UNUSED,
            ulong                    tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *      stem   FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx!=ctx->gossip_in_idx ) ) return;
  gossip_commit( ctx, fd_failover_clock() );
}

static inline void
after_credit( fd_failover_tile_ctx_t * ctx,
              fd_stem_context_t *      stem        FD_PARAM_UNUSED,
              int *                    opt_poll_in FD_PARAM_UNUSED,
              int *                    charge_busy ) {
  if( FD_UNLIKELY( !ctx->member_cert_set ) ) request_member_cert( ctx );

  /* Each socket poll is a syscall or two for a protocol that runs at the
     status cadence, so while nothing arrives the socket is asked every
     FD_FAILOVER_TILE_POLL_NANOS.  Traffic brings the next ask forward. */
  long now = fd_failover_clock();
  if( FD_LIKELY( now<ctx->poll_at ) ) return;
  int busy = 0;
  peer_poll( ctx, now, &busy );
  ctx->poll_at = busy ? now : now+FD_FAILOVER_TILE_POLL_NANOS;
  if( busy ) *charge_busy = 1;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_failover_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_failover_channel_listen_fd( ctx->channel ) );
  return sock_filter_policy_fd_failover_tile_instr_cnt;
}

/* Candidates, the listener and the tile's own descriptors. */
static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return FD_FAILOVER_CHANNEL_CANDIDATE_MAX + 1UL + 8UL;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_failover_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  int logfile_fd = fd_log_private_logfile_fd();
  int listen_fd  = fd_failover_channel_listen_fd( ctx->channel );

  ulong required_fds = 1UL + (ulong)(-1!=logfile_fd) + (ulong)(-1!=listen_fd);
  if( FD_UNLIKELY( out_fds_cnt<required_fds ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY(   -1!=logfile_fd ) ) out_fds[ out_cnt++ ] = logfile_fd; /* logfile */
  if( FD_UNLIKELY( -1!=listen_fd  ) ) out_fds[ out_cnt++ ] = listen_fd;  /* failover listener */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

/* A frame on our sockets does not wake a parked tile, so we never park. */
#define STEM_NEVER_PARK 1

#define STEM_CALLBACK_CONTEXT_TYPE  fd_failover_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_failover_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_BEFORE_FRAG  before_frag
#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag

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
