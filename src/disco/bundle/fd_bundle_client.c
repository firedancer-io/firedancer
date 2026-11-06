/* fd_bundle_client.c steps gRPC related tasks. */

#define _GNU_SOURCE /* SOL_TCP */
#include "fd_bundle_auth.h"
#include "fd_bundle_tile_private.h"
#include "fd_bundle_tile.h"
#include "proto/bam_api.pb.h"
#include "proto/block_engine.pb.h"
#include "proto/bundle.pb.h"
#include "proto/packet.pb.h"
#include "../keyguard/fd_keyguard.h"
#include "../waker/fd_waker.h"
#include "../fd_txn_m.h"
#include "../../waltz/h2/fd_h2_conn.h"
#include "../../waltz/http/fd_url.h" /* fd_url_unescape */
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../third_party/nanopb/pb_decode.h"
#include "../../util/net/fd_ip4.h"

#include <fcntl.h>
#include <errno.h>
#include <unistd.h> /* close */
#include <poll.h> /* poll */
#include <sys/epoll.h>
#include <sys/socket.h> /* socket */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define FD_BUNDLE_CLIENT_REQUEST_TIMEOUT ((long)8e9) /* 8 seconds */
#define FD_BUNDLE_CONN_TIMEOUT_NS        ((long)3e9) /* TCP connect plus TLS and HTTP/2 setup */
#define FD_BUNDLE_BAM_HEARTBEAT_INTERVAL ((long)5e9)
#define FD_BUNDLE_BAM_HEARTBEAT_TIMEOUT  ((long)6e9)  /* without a BuilderHeartBeat */
#define FD_BUNDLE_BAM_CONFIG_INTERVAL    ((long)1e9)  /* until a builder is known */
#define FD_BUNDLE_BAM_CONFIG_REFRESH     ((long)60e9) /* once a builder is known */
#define FD_BUNDLE_BAM_LOGIN_CUTOFF_SLOTS (40UL)       /* the node refuses logins this close to our leader slot */
#define FD_BUNDLE_BAM_LOGIN_RECHECK      ((long)4e8)  /* about a slot */

FD_STATIC_ASSERT( FD_BUNDLE_STRATEGY_FIFO==block_engine_SchedulingStrategy_SCHEDULING_STRATEGY_FIFO, strategy_wire );
FD_STATIC_ASSERT( FD_BUNDLE_STRATEGY_FBA ==block_engine_SchedulingStrategy_SCHEDULING_STRATEGY_FBA,  strategy_wire );
FD_STATIC_ASSERT( FD_BUNDLE_STRATEGY_MREV==block_engine_SchedulingStrategy_SCHEDULING_STRATEGY_MREV, strategy_wire );

/* fd_bundle_protocols describes how the client talks to each kind of
   block engine.  A Jito session logs in and subscribes to packets and
   bundles, a BAM session logs in on a scheduler stream. */

#define FD_BUNDLE_SESSION_JITO (0)
#define FD_BUNDLE_SESSION_BAM  (1)

struct fd_bundle_protocol {
  int          session;            /* FD_BUNDLE_SESSION_* */
  ulong        subs;               /* FD_BUNDLE_SUB_* streams, all required for a healthy connection */
  char const * bundles_path;
  int          set_strategy;       /* SetStrategy, acknowledged before subscribing */
  int          leader_window;      /* SubmitLeaderWindowInfo at the start of each leader slot */
  int          leader_state;       /* LeaderState for every leader state update from pack */
  ulong        login_cutoff_slots; /* the server refuses logins this close to our leader slot, or 0 */
};

typedef struct fd_bundle_protocol fd_bundle_protocol_t;

#define SUB( x ) (1UL<<FD_BUNDLE_SUB_##x)

static fd_bundle_protocol_t const fd_bundle_protocols[] = {
  [ FD_BUNDLE_PROTOCOL_JITO ] = {
    .session            = FD_BUNDLE_SESSION_JITO,
    .subs               = SUB( PACKETS )|SUB( BUNDLES ),
    .bundles_path       = "/block_engine.BlockEngineValidator/SubscribeBundles",
  },
  [ FD_BUNDLE_PROTOCOL_HARMONIC ] = {
    .session            = FD_BUNDLE_SESSION_JITO,
    .subs               = SUB( PACKETS )|SUB( BUNDLES )|SUB( BLOCKS ),
    /* Harmonic serves bundles on SubscribeBundles2 only */
    .bundles_path       = "/block_engine.BlockEngineValidator/SubscribeBundles2",
    .set_strategy       = 1,
    .leader_window      = 1,
  },
  [ FD_BUNDLE_PROTOCOL_BAM ] = {
    .session            = FD_BUNDLE_SESSION_BAM,
    .leader_state       = 1,
    .login_cutoff_slots = FD_BUNDLE_BAM_LOGIN_CUTOFF_SLOTS,
  },
};

#undef SUB

/* fd_bundle_subs describes each stream a Jito session subscribes to.
   path is NULL for the protocol's bundles_path. */

static struct {
  ulong                request_ctx;
  char const *         path;
  pb_msgdesc_t const * desc;
} const fd_bundle_subs[ FD_BUNDLE_SUB_CNT ] = {
  [ FD_BUNDLE_SUB_PACKETS ] = { FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets, "/block_engine.BlockEngineValidator/SubscribePackets", &block_engine_SubscribePacketsRequest_msg },
  [ FD_BUNDLE_SUB_BUNDLES ] = { FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles, NULL,                                                   &block_engine_SubscribeBundlesRequest_msg },
  [ FD_BUNDLE_SUB_BLOCKS  ] = { FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks,  "/block_engine.BlockEngineValidator/SubscribeBlocks2", &block_engine_SubscribeBlocksRequest_msg  },
};

/* fd_bundle_sub_idx returns the FD_BUNDLE_SUB_* of a subscription
   request, or ULONG_MAX if it is not one. */

static ulong
fd_bundle_sub_idx( ulong request_ctx ) {
  for( ulong i=0UL; i<FD_BUNDLE_SUB_CNT; i++ ) if( fd_bundle_subs[ i ].request_ctx==request_ctx ) return i;
  return ULONG_MAX;
}

static inline fd_bundle_protocol_t const *
fd_bundle_client_protocol( fd_bundle_tile_t const * ctx ) {
  if( FD_UNLIKELY( (ulong)ctx->protocol>=sizeof(fd_bundle_protocols)/sizeof(fd_bundle_protocols[0]) ) ) {
    FD_LOG_CRIT(( "unexpected bundle protocol %d", ctx->protocol )); /* unreachable */
  }
  return &fd_bundle_protocols[ ctx->protocol ];
}


__attribute__((weak)) long
fd_bundle_now( fd_bundle_tile_t const * ctx ) {
  return fd_clock_tile_now( ctx->clock );
}

/* fd_bundle_conn_close closes conn and resets its Jito session, and
   backs off before it reconnects */

static void
fd_bundle_conn_close( fd_bundle_conn_t * conn ) {
  fd_bundle_auther_reset( &conn->auther );
  conn->builder       = (fd_bundle_builder_t){0};
  conn->strategy_set  = 0;
  conn->strategy_wait = 0;
  fd_memset( conn->sub, 0, sizeof(conn->sub) );

  if( FD_UNLIKELY( conn->tcp_sock >= 0 ) ) {
    if( FD_UNLIKELY( 0!=close( conn->tcp_sock ) ) ) {
      FD_LOG_ERR(( "close(tcp_sock=%i) failed (%i-%s)", conn->tcp_sock, errno, fd_io_strerror( errno ) ));
    }
    conn->tcp_sock = -1;
    conn->tcp_sock_connected = 0;
    conn->sock_in_epoll = 0;
    conn->epoll_out_armed = 0;
  }
  conn->defer_reset = 0;
  fd_memset( conn->rtt, 0, sizeof(fd_rtt_estimate_t) );
  fd_bundle_conn_backoff( conn, fd_bundle_now( conn->ctx ) );
  fd_grpc_client_reset( conn->grpc_client );
}

/* fd_bundle_conn_reset closes conn and resets the session on it, which
   for the block engine conn includes its BAM and Harmonic block state. */

static void
fd_bundle_conn_reset( fd_bundle_conn_t * conn ) {
  if( conn==conn->ctx->conn ) fd_bundle_client_reset( conn->ctx );
  else                        fd_bundle_conn_close( conn );
}

void
fd_bundle_client_reset( fd_bundle_tile_t * ctx ) {
  /* A reset while our block is streaming can lose part of it, and a new
     stream does not say where it resumes, so the rest is dropped */
  if( FD_UNLIKELY( ctx->conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live &&
                   ctx->leader_state->slot!=ULONG_MAX &&
                   fd_bundle_now( ctx )<ctx->leader_state->slot_end_ns ) ) {
    FD_LOG_WARNING(( "Block engine connection reset during leader slot %lu, dropping the rest of its block", ctx->leader_state->slot ));
    ctx->harmonic.block_lost_slot = ctx->leader_state->slot;
  }

  fd_memset( &ctx->bam, 0, sizeof(ctx->bam) );
  fd_bundle_conn_close( ctx->conn );
}

static int
fd_bundle_conn_do_connect( fd_bundle_conn_t const * conn,
                           uint                     ip4_addr ) {
  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = ip4_addr,
    .sin_port        = fd_ushort_bswap( conn->server_tcp_port )
  };
  int err = connect( conn->tcp_sock, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) );
  /* FD_LIKELY is used here as EINPROGRESS is expected even to local tcp ports */
  if( FD_LIKELY( err==-1 ) ) {
    return errno;
  }
  return 0;
}

static int
fd_bundle_conn_get_connect_result( fd_bundle_conn_t const * conn ) {
  int so_err = 0;
  socklen_t so_err_sz = sizeof(so_err);
  if( FD_UNLIKELY( getsockopt( conn->tcp_sock, SOL_SOCKET, SO_ERROR, &so_err, &so_err_sz )==-1 ) ) {
    return errno;
  }
  return so_err;
}

static void
fd_bundle_conn_create( fd_bundle_conn_t * conn ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  fd_bundle_conn_reset( conn );

  /* FIXME IPv6 support */
  fd_addrinfo_t hints = {0};
  hints.ai_family = AF_INET;
  fd_addrinfo_t * res = NULL;
  uchar scratch[ 4096 ];
  void * pscratch = scratch;
  int err = fd_getaddrinfo( conn->server_fqdn, &hints, &res, &pscratch, sizeof(scratch) );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_getaddrinfo `%s` failed (%d-%s)", conn->server_fqdn, err, fd_gai_strerror( err ) ));
    fd_bundle_conn_reset( conn );
    ctx->metrics.transport_fail_cnt++;
    return;
  }
  uint const ip4_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  conn->server_ip4_addr = ip4_addr;

  int tcp_sock = socket( AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( tcp_sock<0 ) ) {
    FD_LOG_ERR(( "socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  conn->tcp_sock = tcp_sock;

  struct epoll_event ev = { .events = EPOLLIN|EPOLLOUT, .data.fd = tcp_sock };
  if( FD_UNLIKELY( -1==epoll_ctl( FD_WAKER_INNER_FD( ctx->waker_client_idx ), EPOLL_CTL_ADD, tcp_sock, &ev ) ) ) {
    FD_LOG_ERR(( "epoll_ctl(ADD,tcp_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  conn->sock_in_epoll   = 1;
  conn->epoll_out_armed = 1;

  if( FD_UNLIKELY( 0!=setsockopt( tcp_sock, SOL_SOCKET, SO_RCVBUF, &ctx->so_rcvbuf, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_RCVBUF,%i) failed (%i-%s)", ctx->so_rcvbuf, errno, fd_io_strerror( errno ) ));
  }

  int tcp_nodelay = 1;
  if( FD_UNLIKELY( 0!=setsockopt( tcp_sock, SOL_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fcntl( tcp_sock, F_SETFL, O_NONBLOCK )==-1 ) ) {
    FD_LOG_ERR(( "fcntl(tcp_sock,F_SETFL,O_NONBLOCK) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  char const * scheme = conn->is_ssl ? "https" : "http";

  FD_LOG_INFO(( "Connecting to %s://" FD_IP4_ADDR_FMT ":%hu (%.*s)",
                scheme,
                FD_IP4_ADDR_FMT_ARGS( ip4_addr ), conn->server_tcp_port,
                (int)conn->server_sni_len, conn->server_sni ));

  int connect_err = fd_bundle_conn_do_connect( conn, ip4_addr );
  /* FD_LIKELY as EINPROGRESS is expected */
  if( FD_LIKELY( connect_err ) ) {
    if( FD_UNLIKELY( connect_err!=EINPROGRESS ) ) {
      FD_LOG_WARNING(( "connect(tcp_sock," FD_IP4_ADDR_FMT ":%u) failed (%i-%s)",
                      FD_IP4_ADDR_FMT_ARGS( ip4_addr ), conn->server_tcp_port,
                      connect_err, fd_io_strerror( connect_err ) ));
      fd_bundle_conn_reset( conn );
      ctx->metrics.transport_fail_cnt++;
      return;
    }
  }

  if( conn->is_ssl ) {
    fd_tls_t * tls = conn->tls;
    ulong sni_len = strlen( conn->server_sni );
    fd_memcpy( tls->server_name, conn->server_sni, sni_len );
    tls->server_name[ sni_len ] = '\0';
    tls->server_name_len = (ushort)sni_len;
    if( FD_UNLIKELY( !fd_rng_secure( tls->kex_private_key, 32UL ) ) ) FD_LOG_CRIT(( "fd_rng_secure failed" ));
    fd_x25519_public( tls->kex_public_key, tls->kex_private_key );
    fd_tlsrec_conn_init( conn->tls_conn, tls, 0 );
  }

  fd_grpc_client_reset( conn->grpc_client );
  fd_keepalive_init( conn->keepalive, ctx->rng, ctx->keepalive_interval, ctx->keepalive_interval, fd_bundle_now( ctx ) );
  conn->conn_deadline = fd_bundle_now( ctx ) + FD_BUNDLE_CONN_TIMEOUT_NS;
}

static int
fd_bundle_conn_drive_io( fd_bundle_conn_t * conn,
                         long               now,
                         int *              charge_busy ) {
  if( conn->is_ssl ) {
    return fd_grpc_client_rxtx_tls( conn->grpc_client, conn->tls_conn, conn->tcp_sock, now, charge_busy );
  }

  return fd_grpc_client_rxtx_socket( conn->grpc_client, conn->tcp_sock, now, charge_busy );
}

/* fd_bundle_builder_due returns 1 if builder info should be requested
   now: none in flight and the next request is due. */

static inline int
fd_bundle_builder_due( fd_bundle_builder_t const * builder,
                       long                        now ) {
  return !builder->wait && now>=builder->next;
}

static void
fd_bundle_client_request_builder_info( fd_bundle_conn_t * conn ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( conn->grpc_client ) ) ) return;

  block_engine_BlockBuilderFeeInfoRequest req = block_engine_BlockBuilderFeeInfoRequest_init_default;
  static char const path[] = "/block_engine.BlockEngineValidator/GetBlockBuilderFeeInfo";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo,
      &block_engine_BlockBuilderFeeInfoRequest_msg, &req,
      conn->auther.access_token, conn->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  conn->builder.wait = 1;
}

/* fd_bundle_client_subscribe subscribes conn to the FD_BUNDLE_SUB_*
   stream sub. */

static void
fd_bundle_client_subscribe( fd_bundle_conn_t * conn,
                            ulong              sub ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( conn->grpc_client ) ) ) return;

  /* Only the blocks request has fields */
  block_engine_SubscribeBlocksRequest req = block_engine_SubscribeBlocksRequest_init_default;
  fd_cstr_ncpy( req.version,     fd_version_cstr,    sizeof(req.version)     );
  fd_cstr_ncpy( req.commit_hash, fd_commit_ref_cstr, sizeof(req.commit_hash) );

  char const * path = fd_bundle_subs[ sub ].path ? fd_bundle_subs[ sub ].path : fd_bundle_client_protocol( conn->ctx )->bundles_path;
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      path, strlen( path ),
      fd_bundle_subs[ sub ].request_ctx,
      fd_bundle_subs[ sub ].desc, &req,
      conn->auther.access_token, conn->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_HEADER,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  conn->sub[ sub ].wait = 1;
}

static void
fd_bundle_client_set_strategy( fd_bundle_conn_t * conn ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( conn->grpc_client ) ) ) return;

  block_engine_SetStrategyRequest req = { .strategy = (block_engine_SchedulingStrategy)conn->ctx->strategy };
  static char const path[] = "/block_engine.BlockEngineValidator/SetStrategy";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy,
      &block_engine_SetStrategyRequest_msg, &req,
      conn->auther.access_token, conn->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  conn->strategy_wait = 1;
}

/* fd_bundle_client_submit_leader_window_info sends the queued leader
   window notice.  Returns 1 if sent, 0 if the client is busy. */

static int
fd_bundle_client_submit_leader_window_info( fd_bundle_tile_t * ctx,
                                            long               now ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( ctx->conn->grpc_client ) ) ) return 0;

  /* start_timestamp is the send time, which only measures latency */
  block_engine_SubmitLeaderWindowInfoRequest req = block_engine_SubmitLeaderWindowInfoRequest_init_default;
  req.slot                    = ctx->harmonic.leader_window_slot;
  req.has_start_timestamp     = 1;
  req.start_timestamp.seconds = now/(long)1e9;
  req.start_timestamp.nanos   = (int)( now%(long)1e9 );
  req.has_end_timestamp       = 1;
  req.end_timestamp.seconds   = ctx->harmonic.leader_window_end_ns/(long)1e9;
  req.end_timestamp.nanos     = (int)( ctx->harmonic.leader_window_end_ns%(long)1e9 );

  static char const path[] = "/block_engine.BlockEngineValidator/SubmitLeaderWindowInfo";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      ctx->conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubmitLeaderWindowInfo,
      &block_engine_SubmitLeaderWindowInfoRequest_msg, &req,
      ctx->conn->auther.access_token, ctx->conn->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return 0;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  ctx->harmonic.leader_window_pending = 0;
  FD_LOG_INFO(( "Submitted leader window info for slot %lu", ctx->harmonic.leader_window_slot ));
  return 1;
}

int
fd_bundle_client_leader_state_update( fd_bundle_tile_t * ctx,
                                      int                new_slot ) {
  fd_bundle_protocol_t const * protocol = fd_bundle_client_protocol( ctx );
  if( protocol->leader_state ) {
    ctx->bam.leader_state_pending = 1;
    return 1;
  }
  if( !new_slot ) return 0;
  ctx->harmonic.block_seq = 0UL;
  if( !protocol->leader_window ) return 0;
  if( FD_UNLIKELY( ctx->harmonic.leader_window_pending ) ) {
    FD_LOG_WARNING(( "Leader window info for slot %lu was never sent (superseded by slot %lu)",
                     ctx->harmonic.leader_window_slot, ctx->leader_state->slot ));
  }
  ctx->harmonic.leader_window_pending = 1;
  ctx->harmonic.leader_window_slot    = ctx->leader_state->slot;
  ctx->harmonic.leader_window_end_ns  = ctx->leader_state->slot_end_ns;
  return 1;
}

void
fd_bundle_conn_send_ping( fd_bundle_conn_t * conn ) {
  if( FD_UNLIKELY( !conn->grpc_client ) ) return; /* no client */
  fd_h2_conn_t * h2_conn = fd_grpc_client_h2_conn( conn->grpc_client );
  if( FD_UNLIKELY( !h2_conn ) ) return; /* no conn */
  if( FD_UNLIKELY( h2_conn->flags ) ) return; /* conn busy */
  fd_h2_rbuf_t * rbuf_tx = fd_grpc_client_rbuf_tx( conn->grpc_client );

  if( FD_LIKELY( fd_h2_tx_ping( h2_conn, rbuf_tx ) ) ) {
    long now = fd_bundle_now( conn->ctx );
    fd_keepalive_tx( conn->keepalive, conn->ctx->rng, now );
    FD_LOG_DEBUG(( "Keepalive TX (deadline=+%gs)", (double)( conn->keepalive->ts_deadline-now )/1e9 ));
  }
}

static void
fd_bundle_conn_epoll_out( fd_bundle_conn_t * conn,
                          int                want ) {
  if( FD_UNLIKELY( !conn->sock_in_epoll ) ) return;
  if( FD_LIKELY( want==(int)conn->epoll_out_armed ) ) return;
  struct epoll_event ev = { .events = EPOLLIN | (want ? EPOLLOUT : 0U), .data.fd = conn->tcp_sock };
  if( FD_UNLIKELY( -1==epoll_ctl( FD_WAKER_INNER_FD( conn->ctx->waker_client_idx ), EPOLL_CTL_MOD, conn->tcp_sock, &ev ) ) )
    FD_LOG_ERR(( "epoll_ctl(MOD,tcp_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  conn->epoll_out_armed = !!want;
}

/* fd_bundle_client_login_refused returns 1 if the server would refuse a
   login now, this close to our next leader slot, so the client does not
   dial until it passes. */

static int
fd_bundle_client_login_refused( fd_bundle_tile_t const * ctx ) {
  ulong cutoff = fd_bundle_client_protocol( ctx )->login_cutoff_slots;
  if( !cutoff || ctx->next_leader_slot==ULONG_MAX || ctx->reset_slot==ULONG_MAX ) return 0;
  return fd_ulong_sat_sub( ctx->next_leader_slot, ctx->reset_slot )<cutoff;
}

/* fd_bundle_conn_next_deadline returns when conn next needs to be
   stepped absent any fd event, for transport timers only. */

static long
fd_bundle_conn_next_deadline( fd_bundle_conn_t const * conn,
                              long                     now ) {
  /* Connecting: completion/failure arrives as an EPOLLOUT/EPOLLERR
     event, or the setup times out. */
  if( FD_UNLIKELY( conn->tcp_sock>=0 && !conn->tcp_sock_connected ) ) return conn->conn_deadline;

  /* Disconnected: next action is the reconnect attempt. */
  if( FD_UNLIKELY( conn->tcp_sock<0 ) ) return fd_long_max( conn->backoff_until, now );

  /* Decrypted TLS bytes buffered in the gRPC client do not make the fd
     readable: drain now or they wait for the next unrelated event.
     Except while TX is blocked: then they are held because the HTTP/2
     rings are full behind the parked send, and only the EPOLLOUT armed
     for that send can make progress. */
  if( FD_UNLIKELY( conn->is_ssl &&
                   fd_grpc_client_tls_rx_pending( conn->grpc_client ) &&
                   !fd_grpc_client_tls_tx_pending( conn->grpc_client ) ) ) return now;

  long deadline = fd_grpc_client_next_deadline( conn->grpc_client );
  if( FD_LIKELY( conn->keepalive->interval ) )
    deadline = fd_long_min( deadline, conn->keepalive->inflight ? conn->keepalive->ts_deadline
                                                                : conn->keepalive->ts_next_tx );
  if( FD_UNLIKELY( conn->backoff_until>now ) )
    deadline = fd_long_min( deadline, conn->backoff_until );
  if( FD_UNLIKELY( !fd_grpc_client_is_connected( conn->grpc_client ) ) )
    deadline = fd_long_min( deadline, conn->conn_deadline );
  return deadline;
}

long
fd_bundle_client_next_deadline( fd_bundle_tile_t const * ctx,
                                long                     now ) {
  fd_bundle_conn_t const * conn = ctx->conn;
  if( FD_UNLIKELY( conn->tcp_sock<0 && fd_bundle_client_login_refused( ctx ) ) ) return now + FD_BUNDLE_BAM_LOGIN_RECHECK;

  long deadline = fd_bundle_conn_next_deadline( conn, now );
  if( FD_UNLIKELY( !conn->tcp_sock_connected ) ) return deadline;
  if( fd_bundle_client_protocol( ctx )->session==FD_BUNDLE_SESSION_BAM ) {
    if( ctx->bam.stream )
      deadline = fd_long_min( deadline, fd_long_min( ctx->bam.heartbeat_next, ctx->bam.heartbeat_rx+FD_BUNDLE_BAM_HEARTBEAT_TIMEOUT ) );
    if( ctx->bam.stream_accepted & !ctx->bam.builder.wait )
      deadline = fd_long_min( deadline, ctx->bam.builder.next );
  } else if( FD_LIKELY( conn->builder.avail & !conn->builder.wait ) ) {
    deadline = fd_long_min( deadline, conn->builder.next );
  }
  return deadline;
}

static void
fd_bundle_client_bam_request_challenge( fd_bundle_tile_t * ctx ) {
  bam_api_AuthChallengeRequest req = bam_api_AuthChallengeRequest_init_default;
  static char const path[] = "/bam_api.BamNodeApi/GetAuthChallenge";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      ctx->conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge,
      &bam_api_AuthChallengeRequest_msg, &req,
      NULL, 0UL,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  ctx->bam.challenge_wait = 1;
}

/* fd_bundle_client_bam_open_stream signs the challenge and opens the
   scheduler stream with the signed challenge as its first message. */

static void
fd_bundle_client_bam_open_stream( fd_bundle_tile_t * ctx,
                                  long               now ) {
  ulong const challenge_sz = strlen( ctx->bam.challenge );
  uchar       payload[ FD_KEYGUARD_BAM_AUTH_MTU ];
  uchar       signature[ 64 ];
  fd_memcpy( payload, FD_KEYGUARD_BAM_AUTH_LABEL, FD_KEYGUARD_BAM_AUTH_LABEL_SZ );
  fd_memcpy( payload+FD_KEYGUARD_BAM_AUTH_LABEL_SZ, ctx->bam.challenge, challenge_sz );
  fd_keyguard_client_sign( ctx->keyguard_client, signature, payload, FD_KEYGUARD_BAM_AUTH_LABEL_SZ+challenge_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );

  bam_api_SchedulerMessage msg = {
    .which_versioned_msg = bam_api_SchedulerMessage_v0_tag,
    .versioned_msg.v0    = { .which_msg = bam_api_SchedulerMessageV0_auth_proof_tag }
  };
  bam_types_AuthProof * proof = &msg.versioned_msg.v0.msg.auth_proof;
  fd_cstr_ncpy( proof->challenge_to_sign, ctx->bam.challenge, sizeof(proof->challenge_to_sign) );
  fd_base58_encode_32( ctx->identity_pubkey, NULL, proof->validator_pubkey );
  fd_base58_encode_64( signature,            NULL, proof->signature        );

  static char const path[] = "/bam_api.BamNodeApi/InitSchedulerStream";
  fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start(
      ctx->conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream,
      &bam_api_SchedulerMessage_msg, &msg,
      NULL, 0UL,
      1 /* is_streaming */
  );
  if( FD_UNLIKELY( !stream ) ) return;
  fd_grpc_client_deadline_set(
      stream,
      FD_GRPC_DEADLINE_HEADER,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  ctx->bam.stream         = stream;
  ctx->bam.challenge[ 0 ] = '\0';
  ctx->bam.heartbeat_next = now;
  ctx->bam.heartbeat_rx   = now; /* the timeout runs from here until the first heartbeat */
}

static int
fd_bundle_client_bam_send( fd_bundle_tile_t *                 ctx,
                           bam_api_SchedulerMessageV0 const * v0 ) {
  bam_api_SchedulerMessage msg = {
    .which_versioned_msg = bam_api_SchedulerMessage_v0_tag,
    .versioned_msg.v0    = *v0
  };
  return fd_grpc_client_stream_send_msg( ctx->conn->grpc_client, ctx->bam.stream, &bam_api_SchedulerMessage_msg, &msg );
}

static void
fd_bundle_client_bam_request_config( fd_bundle_tile_t * ctx ) {
  bam_api_ConfigRequest req = bam_api_ConfigRequest_init_default;
  static char const path[] = "/bam_api.BamNodeApi/GetBuilderConfig";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      ctx->conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig,
      &bam_api_ConfigRequest_msg, &req,
      NULL, 0UL,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  ctx->bam.builder.wait = 1;
}

/* fd_bundle_client_step_bam drives the BAM session: log in with a
   signed challenge as the first message of the scheduler stream, then
   answer pings, send heartbeats, and poll the builder config once the
   node accepted the stream. */

static int
fd_bundle_client_step_bam( fd_bundle_tile_t * ctx,
                           long               now ) {
  if( FD_UNLIKELY( !ctx->bam.stream ) ) {
    if( ctx->bam.challenge[ 0 ] ) {
      fd_bundle_client_bam_open_stream( ctx, now );
      return 1;
    }
    if( !ctx->bam.challenge_wait ) {
      fd_bundle_client_bam_request_challenge( ctx );
      return 1;
    }
  } else if( !fd_grpc_client_stream_send_is_blocked( ctx->conn->grpc_client ) ) {
    if( FD_UNLIKELY( ctx->bam.pong_pending ) ) {
      bam_api_SchedulerMessageV0 v0 = { .which_msg = bam_api_SchedulerMessageV0_pong_tag, .msg.pong = { .id = ctx->bam.pong_id } };
      if( fd_bundle_client_bam_send( ctx, &v0 ) ) ctx->bam.pong_pending = 0;
      return 1;
    }
    if( FD_UNLIKELY( ctx->bam.leader_state_pending ) ) {
      fd_pack_leader_state_t const * state = ctx->leader_state;
      bam_api_SchedulerMessageV0 v0 = { .which_msg = bam_api_SchedulerMessageV0_leader_state_tag, .msg.leader_state = {
        .slot                     = state->slot,
        .tick                     = (uint)state->tick,
        .slot_cu_budget_remaining = (uint)fd_ulong_min( state->cus_remaining, UINT_MAX ) } };
      if( now>=state->slot_end_ns || fd_bundle_client_bam_send( ctx, &v0 ) ) ctx->bam.leader_state_pending = 0;
      return 1;
    }
    if( FD_UNLIKELY( now>=ctx->bam.heartbeat_next ) ) {
      bam_api_SchedulerMessageV0 v0 = { .which_msg = bam_api_SchedulerMessageV0_heart_beat_tag, .msg.heart_beat = { .time_sent_microseconds = (ulong)now/1000UL } };
      if( fd_bundle_client_bam_send( ctx, &v0 ) ) ctx->bam.heartbeat_next = now + FD_BUNDLE_BAM_HEARTBEAT_INTERVAL;
      return 1;
    }
  }

  if( FD_UNLIKELY( ctx->bam.stream_accepted && fd_bundle_builder_due( &ctx->bam.builder, now ) ) ) {
    fd_bundle_client_bam_request_config( ctx );
    ctx->bam.builder.next = now + FD_BUNDLE_BAM_CONFIG_INTERVAL;
    return 1;
  }

  /* Send a PING */
  if( FD_UNLIKELY( fd_keepalive_should_tx( ctx->conn->keepalive, now ) ) ) {
    fd_bundle_conn_send_ping( ctx->conn );
    return 1;
  }

  return 0;
}

int
fd_bundle_client_step_reconnect( fd_bundle_tile_t * ctx,
                                 long               now ) {
  if( fd_bundle_client_protocol( ctx )->session==FD_BUNDLE_SESSION_BAM ) return fd_bundle_client_step_bam( ctx, now );

  fd_bundle_conn_t * conn = ctx->conn;

  /* Drive auth */
  if( FD_UNLIKELY( conn->auther.needs_poll ) ) {
    fd_bundle_auther_poll( &conn->auther, conn->grpc_client, ctx->keyguard_client );
    return 1;
  }
  if( FD_UNLIKELY( conn->auther.state!=FD_BUNDLE_AUTH_STATE_DONE_WAIT ) ) return 0;

  /* The leader window notice is time critical, and is only useful while
     the block stream is live and the slot has not ended */
  if( FD_UNLIKELY( ctx->harmonic.leader_window_pending ) ) {
    if( FD_UNLIKELY( now>=ctx->harmonic.leader_window_end_ns ) ) {
      FD_LOG_WARNING(( "Leader window info for slot %lu was never sent (slot ended)", ctx->harmonic.leader_window_slot ));
      ctx->harmonic.leader_window_pending = 0;
    } else if( conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live && fd_bundle_client_submit_leader_window_info( ctx, now ) ) {
      return 1;
    }
  }

  /* Request block builder info */
  if( FD_UNLIKELY( fd_bundle_builder_due( &conn->builder, now ) ) ) {
    fd_bundle_client_request_builder_info( conn );
    return 1;
  }

  fd_bundle_protocol_t const * protocol = fd_bundle_client_protocol( ctx );

  if( FD_UNLIKELY( protocol->set_strategy && !conn->strategy_set ) ) {
    /* Set the scheduling strategy before subscribing */
    if( !conn->strategy_wait ) {
      fd_bundle_client_set_strategy( conn );
      return 1;
    }
  } else {
    for( ulong sub=0UL; sub<FD_BUNDLE_SUB_CNT; sub++ ) {
      if( FD_UNLIKELY( fd_ulong_extract_bit( protocol->subs, (int)sub ) && !conn->sub[ sub ].live && !conn->sub[ sub ].wait ) ) {
        fd_bundle_client_subscribe( conn, sub );
        return 1;
      }
    }
  }

  /* Send a PING */
  if( FD_UNLIKELY( fd_keepalive_should_tx( conn->keepalive, now ) ) ) {
    fd_bundle_conn_send_ping( conn );
    return 1;
  }

  return 0;
}

/* fd_bundle_conn_step (re)connects conn, times it out, and drives its
   I/O.  Returns 1 if conn is connected and its I/O was driven, 0 if it
   is not connected (or was just reset). */

static int
fd_bundle_conn_step( fd_bundle_conn_t * conn,
                     int *              charge_busy ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  if( FD_UNLIKELY( conn->tcp_sock>=0 &&
                   !( conn->tcp_sock_connected && fd_grpc_client_is_connected( conn->grpc_client ) ) &&
                   fd_bundle_now( ctx )>=conn->conn_deadline ) ) {
    FD_LOG_INFO(( "Bundle connect to " FD_IP4_ADDR_FMT ":%hu timed out (%s)", FD_IP4_ADDR_FMT_ARGS( conn->server_ip4_addr ), conn->server_tcp_port,
                  conn->tcp_sock_connected ? "TLS/HTTP/2 setup" : "TCP connect" ));
    fd_bundle_conn_reset( conn );
    ctx->metrics.transport_fail_cnt++;
    *charge_busy = 1;
    return 0;
  }

  /* Wait for TCP socket to connect */
  if( FD_UNLIKELY( !conn->tcp_sock_connected ) ) {
    if( FD_UNLIKELY( conn->tcp_sock < 0 ) ) goto reconnect;

    struct pollfd pfds[1] = {
      { .fd = conn->tcp_sock, .events = POLLOUT }
    };
    int poll_res = fd_syscall_poll( pfds, 1, 0 );
    if( FD_UNLIKELY( poll_res<0 ) ) {
      FD_LOG_ERR(( "fd_syscall_poll(tcp_sock) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( poll_res==0 ) return 0;

    int connect_result = 0;
    if( pfds[0].revents & (POLLERR|POLLHUP) ) {
      connect_result = fd_bundle_conn_get_connect_result( conn );
    connect_failed:
      FD_LOG_INFO(( "Bundle gRPC connect attempt failed (%i-%s)", connect_result, fd_io_strerror( connect_result ) ));
      fd_bundle_conn_reset( conn );
      ctx->metrics.transport_fail_cnt++;
      *charge_busy = 1;
      return 0;
    }
    if( FD_UNLIKELY( !(pfds[0].revents & POLLOUT) ) ) return 0;
    connect_result = fd_bundle_conn_get_connect_result( conn );
    if( FD_UNLIKELY( connect_result!=0 ) ) {
      goto connect_failed;
    }
    FD_LOG_DEBUG(( "Bundle TCP socket connected" ));
    conn->tcp_sock_connected = 1;
    fd_bundle_conn_epoll_out( conn, 0 );
    *charge_busy = 1;
  }

  /* gRPC conn died? */
  if( FD_UNLIKELY( !conn->grpc_client ) ) {
    long sleep_start;
  reconnect:
    sleep_start = fd_bundle_now( ctx );
    if( FD_UNLIKELY( fd_bundle_conn_should_stall( conn, sleep_start ) ) ) {
      long wait_dur = conn->backoff_until - sleep_start;
      fd_log_sleep( fd_long_min( wait_dur, 1e6 ) );
      return 0;
    }
    fd_bundle_conn_create( conn );
    *charge_busy = 1;
    return 0;
  }

  /* Did a HTTP/2 PING time out */
  long check_ts = ctx->cached_ts = fd_bundle_now( ctx );
  if( FD_UNLIKELY( fd_keepalive_is_timeout( conn->keepalive, check_ts ) ) ) {
    FD_LOG_WARNING(( "Bundle gRPC timed out (HTTP/2 PING went unanswered for %.2f seconds)",
                     (double)( check_ts - conn->keepalive->ts_last_tx )/1e9 ));
    conn->keepalive->inflight = 0;
    conn->defer_reset = 1;
    *charge_busy = 1;
    return 0;
  }

  /* Drive I/O, SSL handshake, and any inflight requests */
  if( FD_UNLIKELY( -1==fd_bundle_conn_drive_io( conn, check_ts, charge_busy ) || conn->defer_reset /* new error? */ ) ) {
    fd_bundle_conn_reset( conn );
    ctx->metrics.transport_fail_cnt++;
    *charge_busy = 1;
    return 0;
  }
  return 1;
}

/* fd_bundle_conn_flush sends conn's queued bytes, and arms EPOLLOUT
   only on write demand: unsent HTTP/2 bytes, or a TLS handshake blocked
   on write (a permanently armed idle-writable socket would keep the
   epoll set ready forever). */

static void
fd_bundle_conn_flush( fd_bundle_conn_t * conn,
                      int *              charge_busy ) {
  if( FD_UNLIKELY( conn->tcp_sock_connected && fd_grpc_client_tx_pending( conn->grpc_client ) ) ) {
    int flush_err = conn->is_ssl ? fd_grpc_client_tls_flush     ( conn->grpc_client, conn->tcp_sock )
                                 : fd_grpc_client_tx_flush_socket( conn->grpc_client, conn->tcp_sock );
    if( FD_UNLIKELY( -1==flush_err ) ) {
      fd_bundle_conn_reset( conn );
      conn->ctx->metrics.transport_fail_cnt++;
      *charge_busy = 1;
      return;
    }
  }

  if( FD_LIKELY( conn->tcp_sock_connected && conn->grpc_client ) ) {
    int want = fd_grpc_client_tx_pending( conn->grpc_client );
    want |= conn->is_ssl && fd_grpc_client_tls_tx_pending( conn->grpc_client );
    fd_bundle_conn_epoll_out( conn, want );
  }
}

static void
fd_bundle_client_log_status( fd_bundle_tile_t * ctx ) {
  int status = fd_bundle_client_status( ctx );

  int const connected_now    = ( status==FD_BUNDLE_STATE_CONNECTED );
  int const connected_before = ( ctx->bundle_status_logged==FD_BUNDLE_STATE_CONNECTED );

  if( FD_UNLIKELY( connected_now!=connected_before ) ) {
    long ts = fd_log_wallclock();
    if( FD_LIKELY( ts-(ctx->last_bundle_status_log_nanos) >= (long)1e6 ) ) {
      if( connected_now ) FD_LOG_INFO(( "Connected to bundle server" ));
      else                FD_LOG_INFO(( "Disconnected from bundle server" ));
      ctx->last_bundle_status_log_nanos = ts;
      ctx->bundle_status_logged = (uchar)status;
    }
  }
}

void
fd_bundle_client_step( fd_bundle_tile_t * ctx,
                       int *              charge_busy ) {
  fd_bundle_conn_t * conn = ctx->conn;
  int const may_dial = conn->tcp_sock>=0 || !fd_bundle_client_login_refused( ctx );
  if( FD_LIKELY( may_dial && fd_bundle_conn_step( conn, charge_busy ) ) ) {
    long now = fd_bundle_now( ctx );
    if( FD_UNLIKELY( ctx->bam.stream && now-ctx->bam.heartbeat_rx>=FD_BUNDLE_BAM_HEARTBEAT_TIMEOUT ) ) {
      FD_LOG_WARNING(( "BAM node sent no heartbeat for %.2f seconds. Reconnecting ...",
                       (double)( now-ctx->bam.heartbeat_rx )/1e9 ));
      conn->defer_reset = 1;
      *charge_busy = 1;
    } else if( !fd_grpc_client_request_is_blocked( conn->grpc_client ) && !fd_bundle_conn_should_stall( conn, now ) ) {
      *charge_busy |= fd_bundle_client_step_reconnect( ctx, now );
    }
  }

  /* Edge-trigger logging with rate limiting */
  fd_bundle_client_log_status( ctx );
  fd_bundle_conn_flush( conn, charge_busy );
}

void
fd_bundle_conn_backoff( fd_bundle_conn_t * conn,
                        long               now ) {
  uint iter = conn->backoff_iter;
  if( now < conn->backoff_reset ) iter = 0U;
  iter++;

  /* FIXME proper backoff */
  long wait_ns = (long)2e9;
  wait_ns = (long)( fd_rng_ulong( conn->ctx->rng ) & ( (1UL<<fd_ulong_find_msb_w_default( (ulong)wait_ns, 0 ))-1UL ) );

  conn->backoff_until = now +   wait_ns;
  conn->backoff_reset = now + 2*wait_ns;

  conn->backoff_iter = iter;
}

static void
fd_bundle_client_grpc_conn_established( void * app_ctx ) {
  (void)app_ctx;
  FD_LOG_INFO(( "Bundle gRPC connection established" ));
}

static void
fd_bundle_client_grpc_conn_dead( void * app_ctx,
                                 uint   h2_err,
                                 int    closed_by ) {
  fd_bundle_conn_t * conn = app_ctx;
  FD_LOG_INFO(( "Bundle gRPC connection closed %s (%u-%s)",
                closed_by ? "by peer" : "due to error",
                h2_err, fd_h2_strerror( h2_err ) ));
  conn->defer_reset = 1;
}

static inline int
fd_bundle_txn_sz_valid( ulong txn_sz ) {
  return txn_sz && txn_sz<=FD_TXN_MTU;
}

/* Every bundle source (Jito and Harmonic bundles, Harmonic blocks and
   BAM batches) buffers a bundle with bundle_open, bundle_push for each
   transaction and bundle_close.  A bundle that is too large, has an
   invalid transaction or does not fit is dropped whole on close.
   bundle_abort drops a bundle that failed to decode. */

static void
fd_bundle_client_bundle_open( fd_bundle_tile_t *          ctx,
                              fd_bundle_builder_t const * builder,
                              int                         atomic,
                              int                         want_result ) {
  ctx->bundle_seq++;
  ctx->bundle.builder     = builder;
  ctx->bundle.cnt0        = pending_txn_cnt( ctx->pending_txns );
  ctx->bundle.txn_cnt     = 0UL;
  ctx->bundle.atomic      = (uchar)atomic;
  ctx->bundle.want_result = (uchar)want_result;
  ctx->bundle.invalid     = 0;
  ctx->bundle.full        = 0;
}

static void
fd_bundle_client_bundle_push( fd_bundle_tile_t * ctx,
                              void const *       txn,
                              ulong              txn_sz,
                              uint               source_ipv4 ) {
  ctx->bundle.txn_cnt++;
  if( FD_UNLIKELY( !fd_bundle_txn_sz_valid( txn_sz ) ) ) ctx->bundle.invalid = 1;
  if( FD_UNLIKELY( pending_txn_full( ctx->pending_txns ) ) ) ctx->bundle.full = 1;
  if( FD_UNLIKELY( ctx->bundle.invalid | ctx->bundle.full | (ctx->bundle.txn_cnt>FD_BUNDLE_CLIENT_MAX_TXN_PER_BUNDLE) ) ) return;

  fd_bundle_pending_txn_t * entry = pending_txn_push_tail_nocopy( ctx->pending_txns );
  *entry = (fd_bundle_pending_txn_t) {
    .payload_sz       = (ushort)txn_sz,
    .source_ipv4      = source_ipv4,
    .first_seen_nanos = fd_bundle_now( ctx ),
    .sig              = 1UL,
    .bundle_seq       = ctx->bundle_seq,
    .commission       = ctx->bundle.builder->commission,
    .want_result      = ctx->bundle.want_result,
  };
  fd_memcpy( entry->payload, txn, txn_sz );
  fd_memcpy( entry->commission_pubkey, ctx->bundle.builder->pubkey, 32UL );
  ctx->metrics.txn_received_cnt++;
}

static void
fd_bundle_client_bundle_abort( fd_bundle_tile_t * ctx ) {
  while( pending_txn_cnt( ctx->pending_txns )>ctx->bundle.cnt0 ) pending_txn_pop_tail_nocopy( ctx->pending_txns );
  ctx->bundle.txn_cnt = 0UL;
}

/* bundle_close sets the bundle's slot and seq (see fd_txn_m_t), and
   returns 1 if it was kept, 0 if dropped. */

static int
fd_bundle_client_bundle_close( fd_bundle_tile_t * ctx,
                               ulong              slot,
                               ulong              seq ) {
  ulong const n = ctx->bundle.txn_cnt;
  if( FD_UNLIKELY( !n ) ) return 0;
  if( FD_UNLIKELY( ctx->bundle.invalid | ctx->bundle.full | (n>FD_BUNDLE_CLIENT_MAX_TXN_PER_BUNDLE) ) ) {
    if( ctx->bundle.full ) ctx->metrics.backpressure_drop_cnt += n;
    else                   FD_LOG_DEBUG(( "Dropping bundle %lu with %lu transactions", seq, n ));
    fd_bundle_client_bundle_abort( ctx );
    return 0;
  }
  for( ulong i=ctx->bundle.cnt0; i<ctx->bundle.cnt0+n; i++ ) {
    fd_bundle_pending_txn_t * entry = pending_txn_peek_index( ctx->pending_txns, i );
    entry->bundle_txn_cnt = n;
    entry->block_slot     = slot;
    entry->block_seq      = seq;
    entry->atomic         = ctx->bundle.atomic;
  }
  ctx->bundle.txn_cnt = 0UL;
  return 1;
}

/* Buffers a regular transaction for deferred publishing by after_credit. */

static void
fd_bundle_tile_publish_txn(
    fd_bundle_tile_t * ctx,
    void const *       txn,
    ulong              txn_sz,  /* <=FD_TXN_MTU */
    uint               source_ipv4
) {
  if( FD_UNLIKELY( pending_txn_full( ctx->pending_txns ) ) ) {
    ctx->metrics.backpressure_drop_cnt++;
    return;
  }

  fd_bundle_pending_txn_t * entry = pending_txn_push_tail_nocopy( ctx->pending_txns );
  *entry = (fd_bundle_pending_txn_t) {
    .payload_sz       = (ushort)txn_sz,
    .source_ipv4      = source_ipv4,
    .first_seen_nanos = fd_bundle_now( ctx ),
    .bundle_txn_cnt   = 1UL,
  };
  fd_memcpy( entry->payload, txn, txn_sz );
  ctx->metrics.txn_received_cnt++;
}

/* Called for each transaction in a bundle. */

static bool
fd_bundle_client_visit_pb_bundle_txn(
    pb_istream_t *     istream,
    pb_field_t const * field,
    void **            arg
) {
  (void)field;
  fd_bundle_tile_t * ctx = *arg;

  packet_Packet packet = packet_Packet_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &packet_Packet_msg, &packet ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (packet.Packet) failed" ));
    return false;
  }

  uint _ip4; uint ip4 = fd_uint_if( packet.has_meta, fd_cstr_to_ip4_addr( packet.meta.addr, &_ip4 ) ? _ip4 : ctx->conn->server_ip4_addr, ctx->conn->server_ip4_addr );
  fd_bundle_client_bundle_push( ctx, packet.data.bytes, packet.data.size, ip4 );
  return true;
}

static void
fd_bundle_client_sample_rx_delay(
    fd_bundle_tile_t *                ctx,
    google_protobuf_Timestamp const * ts
) {
  ulong tsorig = (ulong)ts->seconds*(ulong)1e9 + (ulong)ts->nanos;
  fd_histf_sample( ctx->metrics.msg_rx_delay, fd_ulong_sat_sub( (ulong)ctx->cached_ts, tsorig ) );
}

/* Called for each BundleUuid in a SubscribeBundlesResponse. */

static bool
fd_bundle_client_visit_pb_bundle_uuid(
    pb_istream_t *     istream,
    pb_field_t const * field,
    void **            arg
) {
  (void)field;
  fd_bundle_conn_t * conn = *arg;
  fd_bundle_tile_t * ctx  = conn->ctx;

  fd_bundle_client_bundle_open( ctx, &conn->builder, 1, 0 );
  bundle_BundleUuid bundle = bundle_BundleUuid_init_default;
  bundle.bundle.packets = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bundle_txn,
    .arg          = ctx
  };
  if( FD_UNLIKELY( !pb_decode( istream, &bundle_BundleUuid_msg, &bundle ) ) ) {
    fd_bundle_client_bundle_abort( ctx );
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (bundle.BundleUuid) failed: %s", istream->errmsg ));
    return false;
  }

  if( fd_bundle_client_bundle_close( ctx, 0UL, 0UL ) ) ctx->metrics.bundle_received_cnt++;
  fd_bundle_client_sample_rx_delay( ctx, &bundle.bundle.header.ts );
  return true;
}

/* Handle a SubscribeBundlesResponse from a SubscribeBundles gRPC call. */

static void
fd_bundle_client_handle_bundle_batch(
    fd_bundle_conn_t * conn,
    pb_istream_t *     istream
) {
  fd_bundle_tile_t * ctx = conn->ctx;
  if( FD_UNLIKELY( !conn->builder.avail ) ) {
    ctx->metrics.missing_builder_info_fail_cnt++; /* unreachable */
    return;
  }

  block_engine_SubscribeBundlesResponse res = block_engine_SubscribeBundlesResponse_init_default;
  res.bundles = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bundle_uuid,
    .arg          = conn
  };
  if( FD_UNLIKELY( !pb_decode( istream, &block_engine_SubscribeBundlesResponse_msg, &res ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block_engine.SubscribeBundlesResponse) failed: %s", istream->errmsg ));
    return;
  }
}

/* Called for each 'Packet' (a regular transaction) of a
   SubscribePacketsResponse. */

static bool
fd_bundle_client_visit_pb_packet(
    pb_istream_t *     istream,
    pb_field_t const * field,
    void **            arg
) {
  (void)field;
  fd_bundle_tile_t * ctx = *arg;

  packet_Packet packet = packet_Packet_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &packet_Packet_msg, &packet ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (packet.Packet) failed" ));
    return false;
  }

  if( FD_UNLIKELY( !fd_bundle_txn_sz_valid( packet.data.size ) ) ) {
    FD_LOG_WARNING(( "Bundle server delivered an empty or oversize transaction, ignoring" ));
    return true;
  }

  uint _ip4; uint ip4 = fd_uint_if( packet.has_meta, fd_cstr_to_ip4_addr( packet.meta.addr, &_ip4 ) ? _ip4 : 0U, 0U );
  fd_bundle_tile_publish_txn( ctx, packet.data.bytes, packet.data.size, ip4 );
  ctx->metrics.packet_received_cnt++;

  return true;
}

/* Handle a SubscribePacketsResponse from a SubscribePackets gRPC call. */

static void
fd_bundle_client_handle_packet_batch(
    fd_bundle_tile_t * ctx,
    pb_istream_t *     istream
) {
  block_engine_SubscribePacketsResponse res = block_engine_SubscribePacketsResponse_init_default;
  res.batch.packets = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_packet,
    .arg          = ctx
  };
  if( FD_UNLIKELY( !pb_decode( istream, &block_engine_SubscribePacketsResponse_msg, &res ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block_engine.SubscribePacketsResponse) failed" ));
    return;
  }

  fd_bundle_client_sample_rx_delay( ctx, &res.header.ts );
}

/* Called for each Transaction in a Block.  Consecutive transactions
   with the same nonzero bundle_id form a bundle, every other
   transaction is a bundle of one.  A dropped bundle keeps its block_seq
   so the gap is visible downstream. */

static bool
fd_bundle_client_visit_pb_block_txn(
    pb_istream_t *     istream,
    pb_field_t const * field,
    void **            arg
) {
  (void)field;
  fd_bundle_conn_t * conn = *arg;
  fd_bundle_tile_t * ctx  = conn->ctx;

  block_Transaction txn = block_Transaction_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &block_Transaction_msg, &txn ) ) ) return false;

  if( !txn.bundle_id || txn.bundle_id!=ctx->harmonic.block_bundle_id ) {
    fd_bundle_client_bundle_close( ctx, ctx->leader_state->slot, ctx->harmonic.block_seq );
    fd_bundle_client_bundle_open( ctx, &conn->builder, !!txn.bundle_id, 0 );
    ctx->harmonic.block_bundle_id = txn.bundle_id;
    ctx->harmonic.block_seq++;
  }
  fd_bundle_client_bundle_push( ctx, txn.transaction.bytes, txn.transaction.size, conn->server_ip4_addr );
  return true;
}

/* Handle a Block from a SubscribeBlocks2 stream.  A Block that is not
   for our current leader slot, is for a slot a reset cut off, or fails
   to decode, is dropped whole. */

static void
fd_bundle_client_handle_block(
    fd_bundle_conn_t * conn,
    pb_istream_t *     istream
) {
  fd_bundle_tile_t * ctx = conn->ctx;
  ulong const txn_cnt0 = pending_txn_cnt( ctx->pending_txns );
  ulong const seq0     = ctx->harmonic.block_seq;
  ctx->harmonic.block_bundle_id = 0UL;
  ctx->bundle.txn_cnt           = 0UL;

  block_Block block = block_Block_init_default;
  block.transactions = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_block_txn,
    .arg          = conn
  };
  int const decoded = pb_decode( istream, &block_Block_msg, &block );
  if( FD_LIKELY( decoded && block.slot==ctx->leader_state->slot && block.slot!=ctx->harmonic.block_lost_slot ) ) {
    fd_bundle_client_bundle_close( ctx, block.slot, ctx->harmonic.block_seq );
    return;
  }

  if( FD_UNLIKELY( !decoded ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block.Block) failed: %s", istream->errmsg ));
  } else if( block.slot==ctx->harmonic.block_lost_slot ) {
    FD_LOG_DEBUG(( "Dropping block for slot %lu, cut off by a reset", block.slot ));
  } else {
    FD_LOG_INFO(( "Dropping block for slot %lu while leader for slot %lu", block.slot, ctx->leader_state->slot ));
    ctx->harmonic.block_seq = seq0; /* a Block for another slot does not use up this slot's sequence */
  }
  while( pending_txn_cnt( ctx->pending_txns )>txn_cnt0 ) pending_txn_pop_tail_nocopy( ctx->pending_txns );
}

/* fd_bundle_client_set_builder applies the block builder's base58
   pubkey and its commission in percent to builder.  Returns 1 on
   success, 0 if either is invalid. */

static int
fd_bundle_client_set_builder( fd_bundle_tile_t *    ctx,
                              fd_bundle_builder_t * builder,
                              char const *          pubkey,
                              ulong                 commission ) {
  if( FD_UNLIKELY( commission > 100 ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Block builder commission out of range (0-100): %lu", commission ));
    return 0;
  }

  fd_pubkey_t decoded_builder_pubkey;
  if( FD_UNLIKELY( !fd_base58_decode_32( pubkey, decoded_builder_pubkey.uc ) ||
                   fd_pubkey_check_zero( &decoded_builder_pubkey ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "Invalid block builder pubkey", pubkey, strlen( pubkey ) ));
    return 0;
  }

  builder->commission = (uchar)commission; /* Apply update atomically */
  fd_memcpy( builder->pubkey, decoded_builder_pubkey.uc, sizeof(builder->pubkey) );
  builder->avail = 1;
  return 1;
}

/* Handle a BlockBuilderFeeInfoResponse from a GetBlockBuilderFeeInfo
   gRPC call. */

static void
fd_bundle_client_handle_builder_fee_info(
    fd_bundle_conn_t * conn,
    pb_istream_t *     istream
) {
  fd_bundle_tile_t * ctx = conn->ctx;
  block_engine_BlockBuilderFeeInfoResponse res = block_engine_BlockBuilderFeeInfoResponse_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &block_engine_BlockBuilderFeeInfoResponse_msg, &res ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block_engine.BlockBuilderFeeInfoResponse) failed" ));
    return;
  }
  if( FD_UNLIKELY( !fd_bundle_client_set_builder( ctx, &conn->builder, res.pubkey, res.commission ) ) ) return;

  long validity_duration_ns = (long)( 60e9 * 5. ); /* 5 minutes */
  conn->builder.next = fd_bundle_now( ctx ) + validity_duration_ns;
}

static void
fd_bundle_client_bam_handle_challenge( fd_bundle_tile_t * ctx,
                                       pb_istream_t *     istream ) {
  bam_api_AuthChallengeResponse res = bam_api_AuthChallengeResponse_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &bam_api_AuthChallengeResponse_msg, &res ) || !res.challenge_to_sign[ 0 ] ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Invalid BAM auth challenge" ));
    fd_bundle_conn_backoff( ctx->conn, fd_bundle_now( ctx ) );
    return;
  }
  fd_cstr_ncpy( ctx->bam.challenge, res.challenge_to_sign, sizeof(ctx->bam.challenge) );
}

/* Called for each Packet of an AtomicTxnBatch.  A batch reverts on
   error (is atomic) if all its packets do. */

static bool
fd_bundle_client_visit_pb_bam_packet( pb_istream_t *     istream,
                                      pb_field_t const * field,
                                      void **            arg ) {
  (void)field;
  fd_bundle_tile_t * ctx = *arg;

  bam_types_Packet packet = bam_types_Packet_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &bam_types_Packet_msg, &packet ) ) ) return false;
  int const atomic = packet.has_meta && packet.meta.has_flags && packet.meta.flags.revert_on_error;
  if( FD_UNLIKELY( ctx->bundle.txn_cnt && atomic!=ctx->bundle.atomic ) ) ctx->bundle.invalid = 1;
  ctx->bundle.atomic = (uchar)atomic;
  fd_bundle_client_bundle_push( ctx, packet.data.bytes, packet.data.size, ctx->conn->server_ip4_addr );
  return true;
}

/* Called for each AtomicTxnBatch, which is one bundle.

   TODO: Report dropped batches to BAM as not committed. */

static bool
fd_bundle_client_visit_pb_bam_batch( pb_istream_t *     istream,
                                     pb_field_t const * field,
                                     void **            arg ) {
  (void)field;
  fd_bundle_tile_t * ctx = *arg;

  fd_bundle_client_bundle_open( ctx, &ctx->bam.builder, 0, 1 );
  bam_types_AtomicTxnBatch batch = bam_types_AtomicTxnBatch_init_default;
  batch.packets = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bam_packet,
    .arg          = ctx
  };
  if( FD_UNLIKELY( !pb_decode( istream, &bam_types_AtomicTxnBatch_msg, &batch ) ) ) {
    fd_bundle_client_bundle_abort( ctx );
    return false;
  }
  /* As in jito-solana, only a batch that reverts on error may hold
     more than one transaction */
  if( FD_UNLIKELY( !ctx->bundle.atomic && ctx->bundle.txn_cnt>1UL ) ) ctx->bundle.invalid = 1;
  if( fd_bundle_client_bundle_close( ctx, batch.max_schedule_slot, batch.seq_id ) ) ctx->metrics.bundle_received_cnt++;
  return true;
}

/* Set the decoders of the nested oneofs of a SchedulerResponse, called
   before each oneof submessage is decoded. */

static bool
fd_bundle_client_bam_resp_cb( pb_istream_t *     istream,
                              pb_field_t const * field,
                              void **            arg ) {
  (void)istream;
  fd_bundle_tile_t * ctx = *arg;
  if( field->tag!=bam_api_SchedulerResponseV0_multiple_atomic_txn_batch_tag ) return true;
  if( FD_UNLIKELY( !ctx->bam.builder.avail ) ) {
    ctx->metrics.missing_builder_info_fail_cnt++;
    return true;
  }
  ((bam_types_MultipleAtomicTxnBatch *)field->pData)->batches = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_visit_pb_bam_batch,
    .arg          = ctx
  };
  return true;
}

static bool
fd_bundle_client_bam_versioned_msg_cb( pb_istream_t *     istream,
                                       pb_field_t const * field,
                                       void **            arg ) {
  (void)istream;
  if( field->tag!=bam_api_SchedulerResponse_v0_tag ) return true;
  ((bam_api_SchedulerResponseV0 *)field->pData)->cb_resp = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_bam_resp_cb,
    .arg          = *arg
  };
  return true;
}

/* Handle a SchedulerResponse from the scheduler stream.  The first one
   shows the node accepted the login. */

static void
fd_bundle_client_bam_handle_response( fd_bundle_tile_t * ctx,
                                      pb_istream_t *     istream ) {
  bam_api_SchedulerResponse res = bam_api_SchedulerResponse_init_default;
  res.cb_versioned_msg = (pb_callback_t) {
    .funcs.decode = fd_bundle_client_bam_versioned_msg_cb,
    .arg          = ctx
  };
  if( FD_UNLIKELY( !pb_decode( istream, &bam_api_SchedulerResponse_msg, &res ) ||
                   res.which_versioned_msg!=bam_api_SchedulerResponse_v0_tag ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Invalid BAM scheduler response. Reconnecting ..." ));
    ctx->conn->defer_reset = 1;
    return;
  }

  ctx->bam.stream_accepted = 1;

  bam_api_SchedulerResponseV0 const * v0 = &res.versioned_msg.v0;
  if( v0->which_resp==bam_api_SchedulerResponseV0_ping_tag ) {
    ctx->bam.pong_pending = 1;
    ctx->bam.pong_id      = v0->resp.ping.id;
  } else if( v0->which_resp==bam_api_SchedulerResponseV0_heart_beat_tag ) {
    ctx->bam.heartbeat_seen = 1;
    ctx->bam.heartbeat_rx   = fd_bundle_now( ctx );
  }
}

/* fd_bundle_client_bam_socket parses a BAM socket.  Returns 1 on
   success, 0 if it is not a nonzero IPv4 address with a port that
   leaves room for the QUIC port (6 higher). */

static int
fd_bundle_client_bam_socket( bam_types_Socket const * sock,
                             uint *                   ip4,
                             ushort *                 port ) {
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( sock->ip, ip4 ) || !*ip4 || !sock->port || sock->port>USHORT_MAX-6U ) ) return 0;
  *port = (ushort)sock->port;
  return 1;
}

static void
fd_bundle_client_bam_handle_config( fd_bundle_tile_t * ctx,
                                    pb_istream_t *     istream ) {
  bam_api_ConfigResponse res = bam_api_ConfigResponse_init_default;
  if( FD_UNLIKELY( !pb_decode( istream, &bam_api_ConfigResponse_msg, &res ) ) ) {
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (bam_api.ConfigResponse) failed" ));
    return;
  }
  if( res.has_block_engine_config &&
      fd_bundle_client_set_builder( ctx, &ctx->bam.builder, res.block_engine_config.builder_pubkey, res.block_engine_config.builder_commission ) ) {
    ctx->bam.builder.next = fd_bundle_now( ctx ) + FD_BUNDLE_BAM_CONFIG_REFRESH;
  }

  /* As in FireBAM, only a valid pair replaces the TPU, which is kept
     across reconnects */
  bam_types_BamConfig const * cfg = &res.bam_config;
  fd_bundle_tpu_t tpu = {0};
  if( res.has_bam_config && cfg->has_tpu_sock && cfg->has_tpu_fwd_sock &&
      fd_bundle_client_bam_socket( &cfg->tpu_sock,     &tpu.ip4,     &tpu.port     ) &&
      fd_bundle_client_bam_socket( &cfg->tpu_fwd_sock, &tpu.fwd_ip4, &tpu.fwd_port ) ) {
    ctx->conn->tpu = tpu;
  }
}

static void
fd_bundle_client_grpc_tx_complete(
    void * app_ctx,
    ulong  request_ctx
) {
  (void)app_ctx; (void)request_ctx;
}

void
fd_bundle_client_grpc_rx_start(
    void * app_ctx,
    ulong  request_ctx
) {
  fd_bundle_conn_t * conn = app_ctx;
  ulong sub = fd_bundle_sub_idx( request_ctx );
  if( sub!=ULONG_MAX ) {
    conn->sub[ sub ].live = 1;
    conn->sub[ sub ].wait = 0;
  }
}

void
fd_bundle_client_grpc_rx_msg(
    void *       app_ctx,
    void const * protobuf,
    ulong        protobuf_sz,
    ulong        request_ctx
) {
  fd_bundle_conn_t * conn = app_ctx;
  fd_bundle_tile_t * ctx  = conn->ctx;
  ctx->metrics.proto_received_bytes += protobuf_sz;
  pb_istream_t istream = pb_istream_from_buffer( protobuf, protobuf_sz );
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
    if( FD_UNLIKELY( !fd_bundle_auther_handle_challenge_resp( &conn->auther, protobuf, protobuf_sz ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      fd_bundle_conn_backoff( conn, fd_bundle_now( ctx ) );
    }
    break;
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    if( FD_UNLIKELY( !fd_bundle_auther_handle_tokens_resp( &conn->auther, protobuf, protobuf_sz ) ) ) {
      ctx->metrics.decode_fail_cnt++;
      fd_bundle_conn_backoff( conn, fd_bundle_now( ctx ) );
    }
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    fd_bundle_client_handle_bundle_batch( conn, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    fd_bundle_client_handle_packet_batch( ctx, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    fd_bundle_client_handle_builder_fee_info( conn, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks:
    fd_bundle_client_handle_block( conn, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy:
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubmitLeaderWindowInfo:
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge:
    fd_bundle_client_bam_handle_challenge( ctx, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream:
    fd_bundle_client_bam_handle_response( ctx, &istream );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig:
    fd_bundle_client_bam_handle_config( ctx, &istream );
    break;
  default:
    FD_LOG_ERR(( "Received unexpected gRPC message (request_ctx=%lu)", request_ctx ));
  }
}

static void
fd_bundle_client_request_failed( fd_bundle_conn_t * conn,
                                 ulong              request_ctx ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  fd_bundle_conn_backoff( conn, fd_bundle_now( ctx ) );
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    fd_bundle_auther_handle_request_fail( &conn->auther );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    conn->builder.wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks: {
    ulong sub = fd_bundle_sub_idx( request_ctx );
    conn->sub[ sub ].live = 0;
    conn->sub[ sub ].wait = 0;
    break;
  }
  case FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy:
    conn->strategy_wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge:
    ctx->bam.challenge_wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream:
    ctx->bam.stream = NULL;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig:
    ctx->bam.builder.wait = 0;
    break;
  }
}

void
fd_bundle_client_grpc_rx_end(
    void *                app_ctx,
    ulong                 request_ctx,
    fd_grpc_resp_hdrs_t * resp
) {
  fd_bundle_conn_t * conn = app_ctx;
  fd_bundle_tile_t * ctx  = conn->ctx;
  if( FD_UNLIKELY( resp->h2_status!=200 ) ) {
    FD_LOG_WARNING(( "gRPC request failed (HTTP status %u)", resp->h2_status ));
    fd_bundle_client_request_failed( conn, request_ctx );
    fd_bundle_auther_reset( &conn->auther );
    conn->defer_reset = 1;
    return;
  }

  resp->grpc_msg_len = (uint)fd_url_unescape( resp->grpc_msg, resp->grpc_msg_len );
  if( !resp->grpc_msg_len ) {
    fd_memcpy( resp->grpc_msg, "unknown error", 13 );
    resp->grpc_msg_len = 13;
  }

  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks: {
    ulong sub = fd_bundle_sub_idx( request_ctx );
    conn->sub[ sub ].live = 0;
    conn->sub[ sub ].wait = 0;
    fd_bundle_conn_backoff( conn, fd_bundle_now( ctx ) );
    conn->defer_reset = 1;
    FD_LOG_INFO(( "%s stream failed (gRPC status %u-%s). Reconnecting ...",
                  fd_bundle_request_ctx_cstr( request_ctx ),
                  resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ) ));
    return;
  }
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    conn->builder.wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy:
    conn->strategy_wait = 0;
    conn->strategy_set  = resp->grpc_status==FD_GRPC_STATUS_OK;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream:
    ctx->bam.stream = NULL;
    fd_bundle_conn_backoff( conn, fd_bundle_now( ctx ) );
    conn->defer_reset = 1;
    FD_LOG_INFO(( "InitSchedulerStream stream failed (gRPC status %u-%s). Reconnecting ...",
                  resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ) ));
    return;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge:
    ctx->bam.challenge_wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig:
    ctx->bam.builder.wait = 0;
    break;
  default:
    break;
  }

  if( FD_UNLIKELY( resp->grpc_status!=FD_GRPC_STATUS_OK ) ) {
    FD_LOG_INFO(( "gRPC request failed (gRPC status %u-%s): %.*s",
                  resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ),
                  (int)resp->grpc_msg_len, resp->grpc_msg ));
    fd_bundle_client_request_failed( conn, request_ctx );
    if( resp->grpc_status==FD_GRPC_STATUS_UNAUTHENTICATED ||
        resp->grpc_status==FD_GRPC_STATUS_PERMISSION_DENIED ) {
      fd_bundle_auther_reset( &conn->auther );
    }
    return;
  }
}

void
fd_bundle_client_grpc_rx_timeout(
    void * app_ctx,
    ulong  request_ctx,  /* FD_BUNDLE_CLIENT_REQ_{...} */
    int    deadline_kind /* FD_GRPC_DEADLINE_{HEADER|RX_END} */
) {
  (void)deadline_kind;
  FD_LOG_WARNING(( "Request timed out: %s", fd_bundle_request_ctx_cstr( request_ctx ) ));
  fd_bundle_conn_t * conn = app_ctx;
  conn->defer_reset = 1;
}

static void
fd_bundle_client_grpc_ping_ack( void * app_ctx ) {
  fd_bundle_conn_t * conn = app_ctx;
  fd_bundle_tile_t * ctx  = conn->ctx;
  long rtt_sample = fd_keepalive_rx( conn->keepalive, fd_bundle_now( ctx ) );
  if( FD_LIKELY( rtt_sample ) ) {
    fd_rtt_sample( conn->rtt, (float)rtt_sample, 0 );
    FD_LOG_DEBUG(( "Keepalive ACK" ));
  }
  ctx->metrics.ping_ack_cnt++;
}

fd_grpc_client_callbacks_t fd_bundle_client_grpc_callbacks = {
  .conn_established = fd_bundle_client_grpc_conn_established,
  .conn_dead        = fd_bundle_client_grpc_conn_dead,
  .tx_complete      = fd_bundle_client_grpc_tx_complete,
  .rx_start         = fd_bundle_client_grpc_rx_start,
  .rx_msg           = fd_bundle_client_grpc_rx_msg,
  .rx_end           = fd_bundle_client_grpc_rx_end,
  .rx_timeout       = fd_bundle_client_grpc_rx_timeout,
  .ping_ack         = fd_bundle_client_grpc_ping_ack,
};

/* fd_bundle_conn_status returns the FD_BUNDLE_STATE_* of conn's
   transport, before any session on it. */

static int
fd_bundle_conn_status( fd_bundle_conn_t const * conn ) {
  if( FD_UNLIKELY( ( !conn->tcp_sock_connected ) |
                   ( !conn->grpc_client        ) ) ) {
    return FD_BUNDLE_STATE_DISCONNECTED;
  }

  fd_h2_conn_t * h2_conn = fd_grpc_client_h2_conn( conn->grpc_client );
  if( FD_UNLIKELY( !h2_conn ) ) {
    return FD_BUNDLE_STATE_DISCONNECTED; /* no conn */
  }
  if( FD_UNLIKELY( h2_conn->flags &
      ( FD_H2_CONN_FLAGS_DEAD |
        FD_H2_CONN_FLAGS_SEND_GOAWAY ) ) ) {
    return FD_BUNDLE_STATE_DISCONNECTED;
  }

  if( FD_UNLIKELY( h2_conn->flags &
      ( FD_H2_CONN_FLAGS_CLIENT_INITIAL      |
        FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0 |
        FD_H2_CONN_FLAGS_WAIT_SETTINGS_0     |
        FD_H2_CONN_FLAGS_SERVER_INITIAL ) ) ) {
    return FD_BUNDLE_STATE_CONNECTING; /* connection is not ready */
  }

  if( FD_UNLIKELY( fd_keepalive_is_timeout( conn->keepalive, fd_bundle_now( conn->ctx ) ) ) ) {
    return FD_BUNDLE_STATE_DISCONNECTED; /* possible timeout */
  }

  if( FD_UNLIKELY( !fd_grpc_client_is_connected( conn->grpc_client ) ) ) {
    return FD_BUNDLE_STATE_CONNECTING;
  }

  return FD_BUNDLE_STATE_CONNECTED;
}

int
fd_bundle_client_status( fd_bundle_tile_t const * ctx ) {
  int status = fd_bundle_conn_status( ctx->conn );
  if( FD_UNLIKELY( status!=FD_BUNDLE_STATE_CONNECTED ) ) return status;

  if( fd_bundle_client_protocol( ctx )->session==FD_BUNDLE_SESSION_BAM ) {
    if( FD_UNLIKELY( !ctx->bam.stream || !ctx->bam.heartbeat_seen || !ctx->bam.builder.avail ) ) {
      return FD_BUNDLE_STATE_CONNECTING; /* not logged in, no heartbeat or no builder yet */
    }
  } else {
    fd_bundle_conn_t const * conn = ctx->conn;
    if( FD_UNLIKELY( conn->auther.state != FD_BUNDLE_AUTH_STATE_DONE_WAIT ) ) {
      return FD_BUNDLE_STATE_CONNECTING; /* not authenticated */
    }

    if( FD_UNLIKELY( !conn->builder.avail ) ) return FD_BUNDLE_STATE_CONNECTING; /* no builder yet */
    ulong const subs = fd_bundle_client_protocol( ctx )->subs;
    for( ulong sub=0UL; sub<FD_BUNDLE_SUB_CNT; sub++ ) {
      if( FD_UNLIKELY( fd_ulong_extract_bit( subs, (int)sub ) && !conn->sub[ sub ].live ) ) {
        return FD_BUNDLE_STATE_CONNECTING; /* not fully subscribed */
      }
    }
  }

  /* As far as we know, the bundle connection is alive and well. */
  return FD_BUNDLE_STATE_CONNECTED;
}

#undef DISCONNECTED
#undef CONNECTING
#undef CONNECTED

FD_FN_CONST char const *
fd_bundle_request_ctx_cstr( ulong request_ctx ) {
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
    return "GenerateAuthChallenge";
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    return "GenerateAuthTokens";
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    return "SubscribePackets";
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles:
    return "SubscribeBundles";
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    return "GetBlockBuilderFeeInfo";
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks:
    return "SubscribeBlocks2";
  case FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy:
    return "SetStrategy";
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubmitLeaderWindowInfo:
    return "SubmitLeaderWindowInfo";
  case FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge:
    return "GetAuthChallenge";
  case FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream:
    return "InitSchedulerStream";
  case FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig:
    return "GetBuilderConfig";
  default:
    return "unknown";
  }
}
