/* fd_bundle_client.c steps gRPC related tasks. */

#define _GNU_SOURCE /* SOL_TCP */
#include "fd_bundle_auth.h"
#include "fd_bundle_tile_private.h"
#include "fd_bundle_tile.h"
#include "../keyguard/fd_keyguard.h"
#include "../waker/fd_waker.h"
#include "../fd_txn_m.h"
#include "../pack/fd_pack.h"
#include "../../flamenco/runtime/fd_runtime_err.h"
#include "../../waltz/h2/fd_h2_conn.h"
#include "../../waltz/http/fd_url.h" /* fd_url_unescape */
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/pb/fd_pb_encode.h"
#include "../../ballet/pb/fd_pb_tokenize.h"
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

/* fd_bundle_protocols describes how the client talks to each kind of
   bundle server.  The session hooks drive the session on a connected
   conn: a Jito session (fd_bundle_client_jito_*) logs in and subscribes
   to streams, a BAM session (fd_bundle_client_bam_*) logs in on a
   scheduler stream.  step drives it and returns 1 if it did work,
   status returns its FD_BUNDLE_STATE_*, deadline when it next needs a
   step (absent any fd event), and reset clears it.  leader_update, if
   any, queues the session's notice of a leader state update from pack,
   and returns 1 if it queued one.  report, if any, reports the result
   of a bundle whose block builder wants it. */

struct fd_bundle_request {
  ulong        id; /* FD_BUNDLE_CLIENT_REQ_* */
  char const * path;
};

typedef struct fd_bundle_request fd_bundle_request_t;

struct fd_bundle_protocol {
  char const *        name;
  int                 builder;                   /* a block builder, which pack follows */
  char const *        subs[ FD_BUNDLE_SUB_CNT ]; /* path of each FD_BUNDLE_SUB_* stream, NULL if none, all required for a healthy connection */
  fd_bundle_request_t poll;                      /* block builder info, or for the relayer its TPU, polled while it is valid */
  fd_bundle_request_t endpoints;                 /* the shred receiver, requested once per connection when forwarding shreds, or none */
  int                 set_strategy;              /* SetStrategy, acknowledged before subscribing */
  ulong               login_cutoff_slots;        /* the server refuses logins this close to our leader slot, or 0 */

  int  (* step         )( fd_bundle_conn_t * conn, long now );
  int  (* status       )( fd_bundle_conn_t const * conn );
  long (* deadline     )( fd_bundle_conn_t const * conn, long now );
  void (* reset        )( fd_bundle_conn_t * conn );
  int  (* leader_update)( fd_bundle_conn_t * conn, int new_slot );
  void (* report       )( fd_bundle_conn_t * conn, fd_bundle_result_t const * res );
};

typedef struct fd_bundle_protocol fd_bundle_protocol_t;

static int  fd_bundle_client_jito_step    ( fd_bundle_conn_t *       conn, long now );
static int  fd_bundle_client_jito_status  ( fd_bundle_conn_t const * conn );
static long fd_bundle_client_jito_deadline( fd_bundle_conn_t const * conn, long now );
static void fd_bundle_client_jito_reset   ( fd_bundle_conn_t *       conn );
static int  fd_bundle_client_bam_step     ( fd_bundle_conn_t *       conn, long now );
static int  fd_bundle_client_bam_status   ( fd_bundle_conn_t const * conn );
static long fd_bundle_client_bam_deadline ( fd_bundle_conn_t const * conn, long now );
static void fd_bundle_client_bam_reset    ( fd_bundle_conn_t *       conn );

static int  fd_bundle_client_harmonic_leader_update( fd_bundle_conn_t * conn, int new_slot );
static int  fd_bundle_client_bam_leader_update     ( fd_bundle_conn_t * conn, int new_slot );
static void fd_bundle_client_bam_report            ( fd_bundle_conn_t * conn, fd_bundle_result_t const * res );

#define BLOCK_ENGINE "/block_engine.BlockEngineValidator/"
#define SESSION( kind ) .step     = fd_bundle_client_##kind##_step,     \
                        .status   = fd_bundle_client_##kind##_status,   \
                        .deadline = fd_bundle_client_##kind##_deadline, \
                        .reset    = fd_bundle_client_##kind##_reset

static fd_bundle_protocol_t const fd_bundle_protocols[] = {
  [ FD_BUNDLE_PROTOCOL_JITO ] = {
    .name               = "jito",
    .subs               = { [ FD_BUNDLE_SUB_PACKETS ] = BLOCK_ENGINE "SubscribePackets",
                            [ FD_BUNDLE_SUB_BUNDLES ] = BLOCK_ENGINE "SubscribeBundles" },
    .poll               = { FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo, BLOCK_ENGINE "GetBlockBuilderFeeInfo" },
    SESSION( jito ),
  },
  [ FD_BUNDLE_PROTOCOL_HARMONIC ] = {
    .name               = "harmonic",
    .builder            = 1,
    .subs               = { [ FD_BUNDLE_SUB_PACKETS ] = BLOCK_ENGINE "SubscribePackets",
                            /* Harmonic serves bundles on SubscribeBundles2 only */
                            [ FD_BUNDLE_SUB_BUNDLES ] = BLOCK_ENGINE "SubscribeBundles2",
                            [ FD_BUNDLE_SUB_BLOCKS  ] = BLOCK_ENGINE "SubscribeBlocks2" },
    .poll               = { FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo, BLOCK_ENGINE "GetBlockBuilderFeeInfo" },
    .endpoints          = { FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockEngineEndpoints, BLOCK_ENGINE "GetBlockEngineEndpoints" },
    .set_strategy       = 1,
    SESSION( jito ),
    .leader_update      = fd_bundle_client_harmonic_leader_update,
  },
  [ FD_BUNDLE_PROTOCOL_BAM ] = {
    .name               = "bam",
    .builder            = 1,
    .poll               = { FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig, "/bam_api.BamNodeApi/GetBuilderConfig" },
    .login_cutoff_slots = FD_BUNDLE_BAM_LOGIN_CUTOFF_SLOTS,
    SESSION( bam ),
    .leader_update      = fd_bundle_client_bam_leader_update,
    .report             = fd_bundle_client_bam_report,
  },
  [ FD_BUNDLE_PROTOCOL_RELAYER ] = {
    .name               = "relayer",
    .subs               = { [ FD_BUNDLE_SUB_RELAYER ] = "/relayer.Relayer/SubscribePackets" },
    .poll               = { FD_BUNDLE_CLIENT_REQ_Relayer_GetTpuConfigs, "/relayer.Relayer/GetTpuConfigs" },
    SESSION( jito ),
  },
};

#undef SESSION
#undef BLOCK_ENGINE

/* fd_bundle_subs describes each FD_BUNDLE_SUB_* stream. */

static struct {
  ulong request_ctx;
  int   version; /* the request carries our version and commit hash */
} const fd_bundle_subs[ FD_BUNDLE_SUB_CNT ] = {
  [ FD_BUNDLE_SUB_PACKETS ] = { FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets,  0 },
  [ FD_BUNDLE_SUB_BUNDLES ] = { FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles,  0 },
  [ FD_BUNDLE_SUB_BLOCKS  ] = { FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks,   1 },
  [ FD_BUNDLE_SUB_RELAYER ] = { FD_BUNDLE_CLIENT_REQ_Relayer_SubscribePackets, 0 },
};

/* fd_bundle_sub_idx returns the FD_BUNDLE_SUB_* of a subscription
   request, or ULONG_MAX if it is not one. */

static ulong
fd_bundle_sub_idx( ulong request_ctx ) {
  for( ulong i=0UL; i<FD_BUNDLE_SUB_CNT; i++ ) if( fd_bundle_subs[ i ].request_ctx==request_ctx ) return i;
  return ULONG_MAX;
}

static inline fd_bundle_protocol_t const *
fd_bundle_conn_protocol( fd_bundle_conn_t const * conn ) {
  if( FD_UNLIKELY( (ulong)conn->protocol>=sizeof(fd_bundle_protocols)/sizeof(fd_bundle_protocols[0]) ) ) {
    FD_LOG_CRIT(( "unexpected bundle protocol %d", conn->protocol )); /* unreachable */
  }
  return &fd_bundle_protocols[ conn->protocol ];
}

char const *
fd_bundle_conn_name( fd_bundle_conn_t const * conn ) {
  return fd_bundle_conn_protocol( conn )->name;
}

fd_bundle_conn_t *
fd_bundle_client_builder( fd_bundle_tile_t * ctx ) {
  for( ulong i=0UL; i<ctx->conn_cnt; i++ ) {
    if( fd_bundle_conn_protocol( &ctx->conn[ i ] )->builder ) return &ctx->conn[ i ];
  }
  return NULL;
}


__attribute__((weak)) long
fd_bundle_now( fd_bundle_tile_t const * ctx ) {
  return fd_clock_tile_now( ctx->clock );
}

static void
fd_bundle_client_jito_reset( fd_bundle_conn_t * conn ) {
  fd_bundle_tile_t * ctx = conn->ctx;

  /* A reset while our block is streaming can lose part of it, and a new
     stream does not say where it resumes, so the rest is dropped */
  if( FD_UNLIKELY( conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live &&
                   ctx->leader_state->slot!=ULONG_MAX &&
                   fd_bundle_now( ctx )<ctx->leader_state->slot_end_ns ) ) {
    FD_LOG_WARNING(( "Block engine connection reset during leader slot %lu, dropping the rest of its block", ctx->leader_state->slot ));
    conn->harmonic.block_lost = 1;
  }

  fd_bundle_auther_reset( &conn->auther );
  conn->builder       = (fd_bundle_builder_t){0};
  conn->strategy_set   = 0;
  conn->strategy_wait  = 0;
  conn->endpoints_sent = 0;
  fd_memset( conn->sub, 0, sizeof(conn->sub) );
}

static void
fd_bundle_client_bam_reset( fd_bundle_conn_t * conn ) {
  fd_memset( &conn->bam, 0, sizeof(conn->bam) );
  conn->builder = (fd_bundle_builder_t){0};
}

void
fd_bundle_conn_reset( fd_bundle_conn_t * conn ) {
  fd_bundle_conn_protocol( conn )->reset( conn );

  if( FD_UNLIKELY( conn->tcp_sock >= 0 ) ) {
    if( FD_UNLIKELY( 0!=close( conn->tcp_sock ) ) ) {
      FD_LOG_ERR(( "close(tcp_sock=%i) failed (%i-%s)", conn->tcp_sock, errno, fd_io_strerror( errno ) ));
    }
    conn->tcp_sock = -1;
    conn->tcp_sock_connected = 0;
    conn->sock_in_epoll = 0;
    conn->epoll_out_armed = 0;
  }
  fd_tlsrec_conn_fini( conn->tls_conn );
  fd_memzero_explicit( conn->tls->kex_private_key, 32UL );
  conn->defer_reset = 0;
  fd_memset( conn->rtt, 0, sizeof(fd_rtt_estimate_t) );
  fd_bundle_conn_backoff( conn, fd_bundle_now( conn->ctx ) );
  fd_grpc_client_reset( conn->grpc_client );
}

void
fd_bundle_client_reset( fd_bundle_tile_t * ctx ) {
  for( ulong i=0UL; i<ctx->conn_cnt; i++ ) fd_bundle_conn_reset( &ctx->conn[ i ] );
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

/* fd_bundle_client_request starts the unary request req with an empty
   message.  Returns 1 if it was started. */

static int
fd_bundle_client_request( fd_bundle_conn_t *          conn,
                          fd_bundle_request_t const * req ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( conn->grpc_client ) ) ) return 0;

  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      req->path, strlen( req->path ),
      req->id,
      (uchar const *)"", 0UL, /* empty request message */
      conn->auther.access_token, conn->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return 0;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );
  return 1;
}

static void
fd_bundle_client_request_builder_info( fd_bundle_conn_t * conn ) {
  conn->builder.wait = (uchar)fd_bundle_client_request( conn, &fd_bundle_conn_protocol( conn )->poll );
}

/* fd_bundle_client_subscribe subscribes conn to the FD_BUNDLE_SUB_*
   stream sub. */

static void
fd_bundle_client_subscribe( fd_bundle_conn_t * conn,
                            ulong              sub ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( conn->grpc_client ) ) ) return;

  uchar           req[ 128 ];
  fd_pb_encoder_t enc[1]; fd_pb_encoder_init( enc, req, sizeof(req) );
  if( fd_bundle_subs[ sub ].version ) {
    FD_TEST( fd_pb_push_cstr( enc, 1U, fd_version_cstr    ) ); /* version */
    FD_TEST( fd_pb_push_cstr( enc, 2U, fd_commit_ref_cstr ) ); /* commit_hash */
  }

  char const * path = fd_bundle_conn_protocol( conn )->subs[ sub ];
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      path, strlen( path ),
      fd_bundle_subs[ sub ].request_ctx,
      req, fd_pb_encoder_out_sz( enc ),
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

  uchar           req[ 32 ];
  fd_pb_encoder_t enc[1]; fd_pb_encoder_init( enc, req, sizeof(req) );
  FD_TEST( fd_pb_push_int32( enc, 1U, conn->strategy ) ); /* strategy */

  static char const path[] = "/block_engine.BlockEngineValidator/SetStrategy";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy,
      req, fd_pb_encoder_out_sz( enc ),
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

/* fd_bundle_client_push_timestamp adds a google.protobuf.Timestamp
   field holding ns nanoseconds since the Unix epoch. */

static void
fd_bundle_client_push_timestamp( fd_pb_encoder_t * enc,
                                 uint              field_id,
                                 long              ns ) {
  FD_TEST( fd_pb_submsg_open( enc, field_id ) );
  FD_TEST( fd_pb_push_int64( enc, 1U, ns/(long)1e9 ) );          /* seconds */
  FD_TEST( fd_pb_push_int32( enc, 2U, (int)( ns%(long)1e9 ) ) ); /* nanos */
  FD_TEST( fd_pb_submsg_close( enc ) );
}

/* fd_bundle_client_submit_leader_window_info sends the queued leader
   window notice.  Returns 1 if sent, 0 if the client is busy. */

static int
fd_bundle_client_submit_leader_window_info( fd_bundle_conn_t * conn ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( conn->grpc_client ) ) ) return 0;

  uchar           req[ 128 ];
  fd_pb_encoder_t enc[1]; fd_pb_encoder_init( enc, req, sizeof(req) );
  fd_bundle_client_push_timestamp( enc, 1U, ctx->leader_state->slot_start_ns ); /* start_timestamp */
  FD_TEST( fd_pb_push_uint64( enc, 2U, ctx->leader_state->slot ) );             /* slot */
  fd_bundle_client_push_timestamp( enc, 3U, ctx->leader_state->slot_end_ns );    /* end_timestamp */

  static char const path[] = "/block_engine.BlockEngineValidator/SubmitLeaderWindowInfo";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubmitLeaderWindowInfo,
      req, fd_pb_encoder_out_sz( enc ),
      conn->auther.access_token, conn->auther.access_token_sz,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return 0;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  conn->leader_pending = 0;
  FD_LOG_INFO(( "Submitted leader window info for slot %lu", ctx->leader_state->slot ));
  return 1;
}

/* Harmonic numbers its block stream per leader slot, and gets a leader
   window notice at the start of each */

static int
fd_bundle_client_harmonic_leader_update( fd_bundle_conn_t * conn,
                                         int                new_slot ) {
  if( !new_slot ) return 0;
  if( FD_UNLIKELY( conn->leader_pending ) ) {
    FD_LOG_WARNING(( "Leader window info was never sent (superseded by slot %lu)", conn->ctx->leader_state->slot ));
  }
  fd_memset( &conn->harmonic, 0, sizeof(conn->harmonic) );
  conn->leader_pending = 1;
  return 1;
}

/* BAM gets every leader state update */

static int
fd_bundle_client_bam_leader_update( fd_bundle_conn_t * conn,
                                    int                new_slot ) {
  (void)new_slot;
  conn->leader_pending = 1;
  return 1;
}

int
fd_bundle_client_leader_state_update( fd_bundle_tile_t * ctx,
                                      int                new_slot ) {
  int queued = 0;
  for( ulong i=0UL; i<ctx->conn_cnt; i++ ) {
    fd_bundle_protocol_t const * protocol = fd_bundle_conn_protocol( &ctx->conn[ i ] );
    if( protocol->leader_update ) queued |= protocol->leader_update( &ctx->conn[ i ], new_slot );
  }
  return queued;
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

/* fd_bundle_conn_login_refused returns 1 if conn's server would refuse
   a login now, this close to our next leader slot, so the client does
   not dial it until it passes. */

static int
fd_bundle_conn_login_refused( fd_bundle_conn_t const * conn ) {
  fd_bundle_tile_t const * ctx = conn->ctx;
  ulong cutoff = fd_bundle_conn_protocol( conn )->login_cutoff_slots;
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
  if( FD_LIKELY( conn->keepalive->interval && conn->keepalive->inflight ) )
    deadline = fd_long_min( deadline, conn->keepalive->ts_deadline );
  if( FD_UNLIKELY( conn->backoff_until>now ) )
    deadline = fd_long_min( deadline, conn->backoff_until );
  if( FD_UNLIKELY( !fd_grpc_client_is_connected( conn->grpc_client ) ) )
    deadline = fd_long_min( deadline, conn->conn_deadline );
  return deadline;
}

/* fd_bundle_conn_session_deadline returns when conn next needs to be
   stepped absent any fd event, for transport and session timers. */

static long
fd_bundle_conn_session_deadline( fd_bundle_conn_t const * conn,
                                 long                     now ) {
  if( FD_UNLIKELY( conn->tcp_sock<0 && fd_bundle_conn_login_refused( conn ) ) ) return now + FD_BUNDLE_BAM_LOGIN_RECHECK;

  long deadline = fd_bundle_conn_next_deadline( conn, now );
  if( FD_UNLIKELY( !conn->tcp_sock_connected ) ) return deadline;
  return fd_long_min( deadline, fd_bundle_conn_protocol( conn )->deadline( conn, now ) );
}

static void
fd_bundle_client_bam_request_challenge( fd_bundle_conn_t * conn ) {
  static char const path[] = "/bam_api.BamNodeApi/GetAuthChallenge";
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge,
      (uchar const *)"", 0UL, /* empty request message */
      NULL, 0UL,
      0 /* is_streaming */
  );
  if( FD_UNLIKELY( !request ) ) return;
  fd_grpc_client_deadline_set(
      request,
      FD_GRPC_DEADLINE_RX_END,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  conn->bam.challenge_wait = 1;
}

/* fd_bundle_client_bam_msg_open starts encoding into buf a
   SchedulerMessage whose v0 holds msg field field_id.  The caller adds
   the msg's fields, then fd_bundle_client_bam_msg_close finishes it. */

static void
fd_bundle_client_bam_msg_open( fd_pb_encoder_t * enc,
                               uchar *           buf,
                               ulong             buf_sz,
                               uint              field_id ) {
  fd_pb_encoder_init( enc, buf, buf_sz );
  FD_TEST( fd_pb_submsg_open( enc, 1U       ) ); /* v0 */
  FD_TEST( fd_pb_submsg_open( enc, field_id ) ); /* msg */
}

static void
fd_bundle_client_bam_msg_close( fd_pb_encoder_t * enc ) {
  FD_TEST( fd_pb_submsg_close( enc ) );
  FD_TEST( fd_pb_submsg_close( enc ) );
}

/* fd_bundle_client_bam_open_stream signs the challenge and opens the
   scheduler stream with the signed challenge as its first message. */

static void
fd_bundle_client_bam_open_stream( fd_bundle_conn_t * conn,
                                  long               now ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  ulong const challenge_sz = strlen( conn->bam.challenge );
  uchar       payload[ FD_KEYGUARD_BAM_AUTH_MTU ];
  uchar       signature[ 64 ];
  fd_memcpy( payload, FD_KEYGUARD_BAM_AUTH_LABEL, FD_KEYGUARD_BAM_AUTH_LABEL_SZ );
  fd_memcpy( payload+FD_KEYGUARD_BAM_AUTH_LABEL_SZ, conn->bam.challenge, challenge_sz );
  fd_keyguard_client_sign( ctx->keyguard_client, signature, payload, FD_KEYGUARD_BAM_AUTH_LABEL_SZ+challenge_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );

  char pubkey_b58   [ FD_BASE58_ENCODED_32_SZ ];
  char signature_b58[ FD_BASE58_ENCODED_64_SZ ];
  fd_base58_encode_32( ctx->identity_pubkey, NULL, pubkey_b58    );
  fd_base58_encode_64( signature,            NULL, signature_b58 );

  uchar           msg[ 512 ];
  fd_pb_encoder_t enc[1];
  fd_bundle_client_bam_msg_open( enc, msg, sizeof(msg), 4U );     /* auth_proof */
  FD_TEST( fd_pb_push_cstr( enc, 1U, conn->bam.challenge ) );      /* challenge_to_sign */
  FD_TEST( fd_pb_push_cstr( enc, 2U, pubkey_b58         ) );      /* validator_pubkey */
  FD_TEST( fd_pb_push_cstr( enc, 3U, signature_b58      ) );      /* signature */
  fd_bundle_client_bam_msg_close( enc );

  static char const path[] = "/bam_api.BamNodeApi/InitSchedulerStream";
  fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start(
      conn->grpc_client,
      path, sizeof(path)-1,
      FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream,
      msg, fd_pb_encoder_out_sz( enc ),
      NULL, 0UL,
      1 /* is_streaming */
  );
  if( FD_UNLIKELY( !stream ) ) return;
  fd_grpc_client_deadline_set(
      stream,
      FD_GRPC_DEADLINE_HEADER,
      fd_log_wallclock() + FD_BUNDLE_CLIENT_REQUEST_TIMEOUT );

  conn->bam.stream         = stream;
  conn->bam.challenge[ 0 ] = '\0';
  conn->bam.heartbeat_next = now;
  conn->bam.heartbeat_rx   = now; /* the timeout runs from here until the first heartbeat */
}

/* fd_bundle_client_bam_send finishes the SchedulerMessage in enc and
   sends it on the scheduler stream.  Returns 1 on success, 0 if the
   send failed. */

static int
fd_bundle_client_bam_send( fd_bundle_conn_t * conn,
                           fd_pb_encoder_t *  enc ) {
  fd_bundle_client_bam_msg_close( enc );
  return fd_grpc_client_stream_send_msg( conn->grpc_client, conn->bam.stream, fd_pb_encoder_out( enc ), fd_pb_encoder_out_sz( enc ) );
}

/* fd_bundle_client_bam_txn_err returns the
   bam_types.TransactionErrorReason of FD_RUNTIME_TXN_ERR_* err.  Codes
   in [-37,-2] are Agave TransactionError indices negated and minus one,
   as BAM's are indices. */

static uint
fd_bundle_client_bam_txn_err( int err ) {
  if( FD_LIKELY( err>=FD_RUNTIME_TXN_ERR_UNBALANCED_TRANSACTION && err<=FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE ) ) return (uint)( -1-err );
  if( err>=FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE && err<=FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED ) return 7U; /* BLOCKHASH_NOT_FOUND */
  return 38U; /* COMMIT_CANCELLED */
}

/* fd_bundle_client_bam_report sends the result of a batch on the
   scheduler stream, if it can. */

static void
fd_bundle_client_bam_report( fd_bundle_conn_t *         conn,
                             fd_bundle_result_t const * res ) {
  if( FD_UNLIKELY( !conn->bam.stream || fd_grpc_client_stream_send_is_blocked( conn->grpc_client ) ) ) return;

  /* The transaction that kept the batch out of the block, rather than
     one that failed with it (BUNDLE_PEER) */
  ulong failed = ULONG_MAX;
  for( ulong j=0UL; j<res->txn_cnt; j++ ) {
    if( !(res->landed & (1U<<j)) && ( failed==ULONG_MAX || res->txn_err[ failed ]==FD_RUNTIME_TXN_ERR_BUNDLE_PEER ) ) failed = j;
  }

  uchar           msg[ 256 ];
  fd_pb_encoder_t enc[1];
  fd_bundle_client_bam_msg_open( enc, msg, sizeof(msg), 3U );       /* multiple_atomic_txn_batch_result */
  FD_TEST( fd_pb_submsg_open( enc, 1U ) );                         /* results */
  FD_TEST( fd_pb_push_uint32( enc, 1U, (uint)res->seq ) );         /* seq_id */
  if( failed==ULONG_MAX ) {
    FD_TEST( fd_pb_submsg_open( enc, 2U ) );                       /* committed */
    for( ulong j=0UL; j<res->txn_cnt; j++ ) {
      FD_TEST( fd_pb_submsg_open( enc, 1U ) );                     /* transaction_results */
      FD_TEST( fd_pb_push_uint32( enc, 1U, res->cus[ j ] ) );      /* cus_consumed */
      FD_TEST( fd_pb_push_bool  ( enc, 4U, !res->txn_err[ j ] ) ); /* execution_success */
      FD_TEST( fd_pb_submsg_close( enc ) );
    }
  } else {
    FD_TEST( fd_pb_submsg_open( enc, 3U ) );                       /* not_committed */
    FD_TEST( fd_pb_submsg_open( enc, 1U ) );                       /* transaction_error */
    FD_TEST( fd_pb_push_uint32( enc, 1U, (uint)failed ) );         /* index */
    FD_TEST( fd_pb_push_uint32( enc, 2U, fd_bundle_client_bam_txn_err( res->txn_err[ failed ] ) ) ); /* reason */
    FD_TEST( fd_pb_submsg_close( enc ) );
  }
  FD_TEST( fd_pb_submsg_close( enc ) );
  FD_TEST( fd_pb_submsg_close( enc ) );
  fd_bundle_client_bam_send( conn, enc );
  conn->ctx->next_step_deadline = 0L;
}

/* fd_bundle_conn_may_request returns 1 if conn can start a request now:
   its gRPC client is not blocked and it is not backing off. */

static inline int
fd_bundle_conn_may_request( fd_bundle_conn_t const * conn,
                            long                     now ) {
  return !fd_grpc_client_request_is_blocked( conn->grpc_client ) && !fd_bundle_conn_should_stall( conn, now );
}

/* fd_bundle_conn_ping_deadline returns when conn next sends a keepalive
   PING, LONG_MAX if none is due or HTTP/2 setup is pending.  Sessions
   only advertise it once they can send one. */

static long
fd_bundle_conn_ping_deadline( fd_bundle_conn_t const * conn ) {
  if( !conn->keepalive->interval || conn->keepalive->inflight || fd_grpc_client_h2_conn( conn->grpc_client )->flags ) return LONG_MAX;
  return conn->keepalive->ts_next_tx;
}

static long
fd_bundle_client_jito_deadline( fd_bundle_conn_t const * conn,
                                long                     now ) {
  if( !fd_bundle_conn_may_request( conn, now ) || conn->auther.needs_poll || conn->auther.state!=FD_BUNDLE_AUTH_STATE_DONE_WAIT ) return LONG_MAX;
  long deadline = fd_bundle_conn_ping_deadline( conn );
  if( conn->builder.avail & !conn->builder.wait ) deadline = fd_long_min( deadline, conn->builder.next );
  return deadline;
}

static long
fd_bundle_client_bam_deadline( fd_bundle_conn_t const * conn,
                               long                     now ) {
  long deadline = conn->bam.stream ? conn->bam.heartbeat_rx+FD_BUNDLE_BAM_HEARTBEAT_TIMEOUT : LONG_MAX;
  if( !fd_bundle_conn_may_request( conn, now ) ) return deadline;
  deadline = fd_long_min( deadline, fd_bundle_conn_ping_deadline( conn ) );
  if( conn->bam.stream && !fd_grpc_client_stream_send_is_blocked( conn->grpc_client ) )
    deadline = fd_long_min( deadline, conn->bam.heartbeat_next );
  if( conn->bam.stream_accepted & !conn->builder.wait )
    deadline = fd_long_min( deadline, conn->builder.next );
  return deadline;
}

long
fd_bundle_client_next_deadline( fd_bundle_tile_t const * ctx,
                                long                     now ) {
  long deadline = LONG_MAX;
  for( ulong i=0UL; i<ctx->conn_cnt; i++ ) deadline = fd_long_min( deadline, fd_bundle_conn_session_deadline( &ctx->conn[ i ], now ) );
  return deadline;
}

/* fd_bundle_client_bam_step drives the BAM session: log in with a
   signed challenge as the first message of the scheduler stream, then
   answer pings, send heartbeats, and poll the builder config once the
   node accepted the stream.  A node silent for too long is reset. */

static int
fd_bundle_client_bam_step( fd_bundle_conn_t * conn,
                           long               now ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  if( FD_UNLIKELY( conn->bam.stream && now-conn->bam.heartbeat_rx>=FD_BUNDLE_BAM_HEARTBEAT_TIMEOUT ) ) {
    FD_LOG_WARNING(( "BAM node sent no heartbeat for %.2f seconds. Reconnecting ...",
                     (double)( now-conn->bam.heartbeat_rx )/1e9 ));
    conn->defer_reset = 1;
    return 1;
  }
  if( FD_UNLIKELY( !fd_bundle_conn_may_request( conn, now ) ) ) return 0;

  if( FD_UNLIKELY( !conn->bam.stream ) ) {
    if( conn->bam.challenge[ 0 ] ) {
      fd_bundle_client_bam_open_stream( conn, now );
      return 1;
    }
    if( !conn->bam.challenge_wait ) {
      fd_bundle_client_bam_request_challenge( conn );
      return 1;
    }
  } else if( !fd_grpc_client_stream_send_is_blocked( conn->grpc_client ) ) {
    uchar           msg[ 128 ];
    fd_pb_encoder_t enc[1];
    if( FD_UNLIKELY( conn->bam.pong_pending ) ) {
      fd_bundle_client_bam_msg_open( enc, msg, sizeof(msg), 5U ); /* pong */
      FD_TEST( fd_pb_push_uint32( enc, 1U, conn->bam.pong_id ) );  /* id */
      if( fd_bundle_client_bam_send( conn, enc ) ) conn->bam.pong_pending = 0;
      return 1;
    }
    if( FD_UNLIKELY( conn->leader_pending ) ) {
      fd_pack_leader_state_t const * state = ctx->leader_state;
      fd_bundle_client_bam_msg_open( enc, msg, sizeof(msg), 2U );                                    /* leader_state */
      FD_TEST( fd_pb_push_uint64( enc, 1U, state->slot ) );                                          /* slot */
      FD_TEST( fd_pb_push_uint32( enc, 2U, (uint)state->tick ) );                                    /* tick */
      FD_TEST( fd_pb_push_uint32( enc, 3U, (uint)fd_ulong_min( state->cus_remaining, UINT_MAX ) ) ); /* slot_cu_budget_remaining */
      if( now>=state->slot_end_ns || fd_bundle_client_bam_send( conn, enc ) ) conn->leader_pending = 0;
      return 1;
    }
    if( FD_UNLIKELY( now>=conn->bam.heartbeat_next ) ) {
      fd_bundle_client_bam_msg_open( enc, msg, sizeof(msg), 1U );      /* heart_beat */
      FD_TEST( fd_pb_push_uint64( enc, 1U, (ulong)now/1000UL ) );      /* time_sent_microseconds */
      if( fd_bundle_client_bam_send( conn, enc ) ) conn->bam.heartbeat_next = now + FD_BUNDLE_BAM_HEARTBEAT_INTERVAL;
      return 1;
    }
  }

  if( FD_UNLIKELY( conn->bam.stream_accepted && fd_bundle_builder_due( &conn->builder, now ) ) ) {
    fd_bundle_client_request_builder_info( conn );
    conn->builder.next = now + FD_BUNDLE_BAM_CONFIG_INTERVAL;
    return 1;
  }

  /* Send a PING */
  if( FD_UNLIKELY( fd_keepalive_should_tx( conn->keepalive, now ) ) ) {
    fd_bundle_conn_send_ping( conn );
    return 1;
  }

  return 0;
}

int
fd_bundle_client_step_reconnect( fd_bundle_conn_t * conn,
                                 long               now ) {
  return fd_bundle_conn_protocol( conn )->step( conn, now );
}

static int
fd_bundle_client_jito_step( fd_bundle_conn_t * conn,
                            long               now ) {
  if( FD_UNLIKELY( !fd_bundle_conn_may_request( conn, now ) ) ) return 0;
  fd_bundle_tile_t *           ctx      = conn->ctx;
  fd_bundle_protocol_t const * protocol = fd_bundle_conn_protocol( conn );

  /* Drive auth */
  if( FD_UNLIKELY( conn->auther.needs_poll ) ) {
    fd_bundle_auther_poll( &conn->auther, conn->grpc_client, ctx->keyguard_client );
    return 1;
  }
  if( FD_UNLIKELY( conn->auther.state!=FD_BUNDLE_AUTH_STATE_DONE_WAIT ) ) return 0;

  /* The leader window notice is time critical, and is only useful while
     the block stream is live and the slot has not ended */
  if( FD_UNLIKELY( conn->leader_pending ) ) {
    if( FD_UNLIKELY( now>=ctx->leader_state->slot_end_ns ) ) {
      FD_LOG_WARNING(( "Leader window info for slot %lu was never sent (slot ended)", ctx->leader_state->slot ));
      conn->leader_pending = 0;
    } else if( conn->sub[ FD_BUNDLE_SUB_BLOCKS ].live && fd_bundle_client_submit_leader_window_info( conn ) ) {
      return 1;
    }
  }

  /* Request block builder info */
  if( FD_UNLIKELY( fd_bundle_builder_due( &conn->builder, now ) ) ) {
    fd_bundle_client_request_builder_info( conn );
    return 1;
  }

  /* Request the shred receiver to forward shreds to */
  if( FD_UNLIKELY( ctx->forward_shreds && protocol->endpoints.path && !conn->endpoints_sent ) ) {
    if( fd_bundle_client_request( conn, &protocol->endpoints ) ) conn->endpoints_sent = 1;
    return 1;
  }

  if( FD_UNLIKELY( protocol->set_strategy && !conn->strategy_set ) ) {
    /* Set the scheduling strategy before subscribing */
    if( !conn->strategy_wait ) {
      fd_bundle_client_set_strategy( conn );
      return 1;
    }
  } else {
    for( ulong sub=0UL; sub<FD_BUNDLE_SUB_CNT; sub++ ) {
      if( FD_UNLIKELY( protocol->subs[ sub ] && !conn->sub[ sub ].live && !conn->sub[ sub ].wait ) ) {
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

/* fd_bundle_client_step_conn drives conn's transport and session. */

static void
fd_bundle_client_step_conn( fd_bundle_conn_t * conn,
                            int *              charge_busy ) {
  int const may_dial = conn->tcp_sock>=0 || !fd_bundle_conn_login_refused( conn );
  if( FD_LIKELY( may_dial && fd_bundle_conn_step( conn, charge_busy ) ) ) {
    *charge_busy |= fd_bundle_client_step_reconnect( conn, fd_bundle_now( conn->ctx ) );
  }
  fd_bundle_conn_flush( conn, charge_busy );
}

void
fd_bundle_client_step( fd_bundle_tile_t * ctx,
                       int *              charge_busy ) {
  /* The block builder conn is read first, for the first claim on
     verify_out's credits */
  fd_bundle_conn_t * builder = fd_bundle_client_builder( ctx );
  if( builder ) fd_bundle_client_step_conn( builder, charge_busy );
  for( ulong i=0UL; i<ctx->conn_cnt; i++ ) {
    if( &ctx->conn[ i ]!=builder ) fd_bundle_client_step_conn( &ctx->conn[ i ], charge_busy );
  }

  /* Edge-trigger logging with rate limiting */
  fd_bundle_client_log_status( ctx );
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

/* fd_bundle_tile_cr_avail returns the credits the message being decoded
   may use to publish. */

static inline ulong
fd_bundle_tile_cr_avail( fd_bundle_tile_t const * ctx ) {
  return fd_ulong_sat_sub( ctx->stem->cr_avail[ ctx->verify_out.idx ], ctx->cr_reserve );
}

/* Publishes a transaction to the verify tiles.  Assumes the caller
   checked that a credit is available.  bundle_txn_cnt is zero for a
   standalone packet, else the transaction is of the bundle being
   closed. */

static void
fd_bundle_tile_publish_txn( fd_bundle_tile_t * ctx,
                            void const *       txn,
                            ulong              txn_sz,  /* <=FD_TXN_MTU */
                            uint               source_ipv4,
                            ulong              bundle_txn_cnt ) {
  int is_bundle = bundle_txn_cnt>0UL;
  fd_txn_m_t * txnm = fd_chunk_to_laddr( ctx->verify_out.mem, ctx->verify_out.chunk );
  *txnm = (fd_txn_m_t) {
    .reference_block_height = 0UL,
    .payload_sz             = (ushort)txn_sz,
    .txn_t_sz               = 0U,
    .source_ipv4            = source_ipv4,
    .source_tpu             = FD_TXN_M_TPU_SOURCE_BUNDLE,
    .first_seen_nanos       = fd_bundle_now( ctx ),
    .block_engine = {
      .bundle_id      = is_bundle ? ctx->bundle_seq : 0UL,
      .bundle_txn_cnt = is_bundle ? bundle_txn_cnt : 1UL,
      .slot           = is_bundle ? ctx->bundle.slot : 0UL,
      .seq            = is_bundle ? ctx->bundle.seq : 0UL,
      .commission     = is_bundle ? ctx->bundle.builder->commission : (uchar)0,
      .atomic         = is_bundle ? ctx->bundle.atomic : (uchar)0,
      .want_result    = is_bundle ? ctx->bundle.want_result : (uchar)0,
    },
  };
  if( is_bundle ) fd_memcpy( txnm->block_engine.commission_pubkey, ctx->bundle.builder->pubkey, 32UL );
  else            fd_memset( txnm->block_engine.commission_pubkey, 0, 32UL );
  fd_memcpy( fd_txn_m_payload( txnm ), txn, txn_sz );

  ulong sz    = fd_txn_m_realized_footprint( txnm, 0, 0 );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_bundle_now( ctx ) );
  fd_stem_publish( ctx->stem, ctx->verify_out.idx, (ulong)is_bundle, ctx->verify_out.chunk, sz, 0UL, 0UL, tspub );
  ctx->verify_out.chunk = fd_dcache_compact_next( ctx->verify_out.chunk, sz, ctx->verify_out.chunk0, ctx->verify_out.wmark );
  ctx->metrics.txn_received_cnt++;
}

/* Every bundle source (Jito and Harmonic bundles, Harmonic blocks and
   BAM batches) decodes a bundle with bundle_open, bundle_push for each
   transaction and bundle_close, which publishes it.  A bundle that is
   too large, has an invalid transaction or does not fit is dropped
   whole on close.  The transactions point into the message being
   decoded. */

static void
fd_bundle_client_bundle_open( fd_bundle_tile_t *          ctx,
                              fd_bundle_builder_t const * builder,
                              int                         atomic,
                              int                         want_result ) {
  ctx->bundle.builder     = builder;
  ctx->bundle.txn_cnt     = 0UL;
  ctx->bundle.atomic      = (uchar)atomic;
  ctx->bundle.want_result = (uchar)want_result;
  ctx->bundle.invalid     = 0;
}

static void
fd_bundle_client_bundle_push( fd_bundle_tile_t * ctx,
                              void const *       txn,
                              ulong              txn_sz,
                              uint               source_ipv4 ) {
  ulong idx = ctx->bundle.txn_cnt++;
  if( FD_UNLIKELY( !fd_bundle_txn_sz_valid( txn_sz ) ) ) ctx->bundle.invalid = 1;
  if( FD_UNLIKELY( idx>=FD_BUNDLE_CLIENT_MAX_TXN_PER_BUNDLE ) ) return;
  ctx->bundle.txn[ idx ].data        = txn;
  ctx->bundle.txn[ idx ].data_sz     = txn_sz;
  ctx->bundle.txn[ idx ].source_ipv4 = source_ipv4;
}

/* fd_bundle_client_result_add tracks the result of the bundle just
   published, if its block builder wants it. */

static void
fd_bundle_client_result_add( fd_bundle_tile_t * ctx,
                             ulong              txn_cnt ) {
  if( !ctx->bundle.want_result ) return;
  fd_bundle_result_t * res = &ctx->results[ ctx->result_cnt++ & (FD_BUNDLE_RESULT_MAX-1UL) ];
  *res = (fd_bundle_result_t){ .seq=ctx->bundle.seq, .txn_cnt=(uchar)txn_cnt };
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    /* The first signature follows its 1 byte count */
    uchar const * payload = ctx->bundle.txn[ i ].data;
    res->sig[ i ] = ctx->bundle.txn[ i ].data_sz>=9UL ? FD_LOAD( ulong, payload+1UL ) : 0UL;
  }
}

void
fd_bundle_client_txn_executed( fd_bundle_tile_t * ctx,
                               ulong              sig,
                               uint               flags,
                               uint               cus ) {
  for( ulong i=0UL; i<FD_BUNDLE_RESULT_MAX; i++ ) {
    fd_bundle_result_t * res = &ctx->results[ i ];
    for( ulong j=0UL; j<res->txn_cnt; j++ ) {
      if( res->sig[ j ]!=sig ) continue;
      res->txn_err[ j ] = -(int)( flags>>24 );
      res->cus    [ j ] = cus;
      res->executed    |= (uchar)( 1U<<j );
      res->landed      |= (uchar)( fd_uint_if( !!(flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS), 1U<<j, 0U ) );
      if( res->executed==(1U<<res->txn_cnt)-1U ) {
        fd_bundle_conn_t * builder = fd_bundle_client_builder( ctx );
        if( builder && fd_bundle_conn_protocol( builder )->report ) fd_bundle_conn_protocol( builder )->report( builder, res );
        res->txn_cnt = 0;
      }
      return;
    }
  }
}

/* bundle_close publishes the bundle with its slot and seq (see
   fd_txn_m_t). */

static void
fd_bundle_client_bundle_close( fd_bundle_tile_t * ctx,
                               ulong              slot,
                               ulong              seq ) {
  ulong const n = ctx->bundle.txn_cnt;
  ctx->bundle.txn_cnt = 0UL;
  if( FD_UNLIKELY( !n ) ) return;
  if( FD_UNLIKELY( ctx->bundle.invalid | (n>FD_BUNDLE_CLIENT_MAX_TXN_PER_BUNDLE) ) ) {
    FD_LOG_DEBUG(( "Dropping bundle %lu with %lu transactions", seq, n ));
    return;
  }
  if( FD_UNLIKELY( fd_bundle_tile_cr_avail( ctx )<n ) ) {
    ctx->metrics.backpressure_drop_cnt += n;
    return;
  }
  ctx->bundle_seq++;
  ctx->bundle.slot = slot;
  ctx->bundle.seq  = seq;
  for( ulong i=0UL; i<n; i++ ) {
    fd_bundle_tile_publish_txn( ctx, ctx->bundle.txn[ i ].data, ctx->bundle.txn[ i ].data_sz, ctx->bundle.txn[ i ].source_ipv4, n );
  }
  fd_bundle_client_result_add( ctx, n );
  ctx->metrics.bundle_received_cnt++;
}

/* fd_bundle_packet_t holds the fields of a packet.Packet message used
   by the bundle client. */

struct fd_bundle_packet {
  uchar const * data;
  ulong         data_sz;
  int           has_meta;
  char          addr[ 256 ]; /* packet.Meta.addr, NUL terminated */
};

typedef struct fd_bundle_packet fd_bundle_packet_t;

/* fd_bundle_client_decode_packet decodes a packet.Packet message.
   Returns packet on success and NULL on decode failure. */

static fd_bundle_packet_t *
fd_bundle_client_decode_packet( fd_pb_inbuf_t        in,
                                fd_bundle_packet_t * packet ) {
  packet->data     = NULL;
  packet->data_sz  = 0UL;
  packet->has_meta = 0;
  packet->addr[0]  = '\0';
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return NULL;
    switch( tlv->field_id ) {
    case 1: /* data */
      packet->data = fd_pb_tlv_bytes( &in, tlv );
      if( FD_UNLIKELY( !packet->data ) ) return NULL;
      packet->data_sz = tlv->len;
      break;
    case 2: { /* meta */
      fd_pb_inbuf_t meta[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, meta ) ) ) return NULL;
      packet->has_meta = 1;
      while( fd_pb_inbuf_sz( meta ) ) {
        fd_pb_tlv_t meta_tlv[1];
        if( FD_UNLIKELY( !fd_pb_tlv_read( meta, meta_tlv ) ) ) return NULL;
        if( meta_tlv->field_id==2U ) { /* addr */
          if( FD_UNLIKELY( !fd_pb_tlv_cstr( meta, meta_tlv, packet->addr, sizeof(packet->addr) ) ) ) return NULL;
        }
        if( FD_UNLIKELY( !fd_pb_tlv_skip( meta, meta_tlv ) ) ) return NULL;
      }
      break;
    }
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return NULL;
  }
  return packet;
}

/* fd_bundle_client_decode_header_ts decodes the timestamp of a
   shared.Header message.  Returns the timestamp in nanoseconds since
   the Unix epoch on success (0 if absent).  Returns -1 on decode
   failure. */

static long
fd_bundle_client_decode_header_ts( fd_pb_inbuf_t in ) {
  ulong seconds = 0UL;
  ulong nanos   = 0UL;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return -1L;
    if( tlv->field_id==1U ) { /* ts */
      fd_pb_inbuf_t ts[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, ts ) ) ) return -1L;
      while( fd_pb_inbuf_sz( ts ) ) {
        fd_pb_tlv_t ts_tlv[1];
        if( FD_UNLIKELY( !fd_pb_tlv_read( ts, ts_tlv ) ) ) return -1L;
        switch( ts_tlv->field_id ) {
        case 1: /* seconds */
          if( FD_UNLIKELY( ts_tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return -1L;
          seconds = ts_tlv->varint;
          break;
        case 2: /* nanos */
          if( FD_UNLIKELY( ts_tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return -1L;
          nanos = (ulong)(uint)ts_tlv->varint;
          break;
        default:
          break;
        }
        if( FD_UNLIKELY( !fd_pb_tlv_skip( ts, ts_tlv ) ) ) return -1L;
      }
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return -1L;
  }
  return (long)( seconds*(ulong)1e9 + nanos );
}

static void
fd_bundle_client_sample_rx_delay( fd_bundle_tile_t * ctx,
                                  long               ts ) {
  fd_histf_sample( ctx->metrics.msg_rx_delay, fd_ulong_sat_sub( (ulong)ctx->cached_ts, (ulong)ts ) );
}

static uint
fd_bundle_packet_ip4( fd_bundle_packet_t const * packet,
                      uint                       dflt ) {
  uint ip4;
  if( packet->has_meta && fd_cstr_to_ip4_addr( packet->addr, &ip4 ) ) return ip4;
  return dflt;
}

/* Handles a bundle.Bundle message.  Returns 1 on success and 0 on
   decode failure. */

static int
fd_bundle_client_handle_bundle( fd_bundle_conn_t * conn,
                                fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  fd_bundle_client_bundle_open( ctx, &conn->builder, 1, 0 );
  long ts = 0L;

  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    switch( tlv->field_id ) {
    case 2: { /* header */
      fd_pb_inbuf_t header[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, header ) ) ) return 0;
      ts = fd_bundle_client_decode_header_ts( *header );
      if( FD_UNLIKELY( ts<0L ) ) return 0;
      break;
    }
    case 3: { /* packets */
      fd_pb_inbuf_t sub[1];
      fd_bundle_packet_t packet[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, sub ) ) ) return 0;
      if( FD_UNLIKELY( !fd_bundle_client_decode_packet( *sub, packet ) ) ) return 0;
      fd_bundle_client_bundle_push( ctx, packet->data, packet->data_sz, fd_bundle_packet_ip4( packet, conn->server_ip4_addr ) );
      break;
    }
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }

  fd_bundle_client_bundle_close( ctx, 0UL, 0UL );
  fd_bundle_client_sample_rx_delay( ctx, ts );
  return 1;
}

/* Handle a SubscribeBundlesResponse from a SubscribeBundles gRPC call. */

static void
fd_bundle_client_handle_bundle_batch(
    fd_bundle_conn_t * conn,
    fd_pb_inbuf_t      in
) {
  fd_bundle_tile_t * ctx = conn->ctx;
  if( FD_UNLIKELY( !conn->builder.avail ) ) {
    ctx->metrics.missing_builder_info_fail_cnt++; /* unreachable */
    return;
  }

  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) goto fail;
    if( tlv->field_id==1U ) { /* bundles (BundleUuid) */
      fd_pb_inbuf_t uuid[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, uuid ) ) ) goto fail;
      fd_pb_inbuf_t bundle[1] = {{0}};
      while( fd_pb_inbuf_sz( uuid ) ) {
        fd_pb_tlv_t uuid_tlv[1];
        if( FD_UNLIKELY( !fd_pb_tlv_read( uuid, uuid_tlv ) ) ) goto fail;
        if( uuid_tlv->field_id==1U ) { /* bundle */
          if( FD_UNLIKELY( !fd_pb_tlv_submsg( uuid, uuid_tlv, bundle ) ) ) goto fail;
        }
        if( FD_UNLIKELY( !fd_pb_tlv_skip( uuid, uuid_tlv ) ) ) goto fail;
      }
      if( FD_UNLIKELY( !fd_bundle_client_handle_bundle( conn, *bundle ) ) ) goto fail;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) goto fail;
  }
  return;

fail:
  ctx->metrics.decode_fail_cnt++;
  FD_LOG_WARNING(( "Protobuf decode of (block_engine.SubscribeBundlesResponse) failed" ));
}

/* Called for each 'Packet' (a regular transaction) of a
   SubscribePacketsResponse. */

static void
fd_bundle_client_handle_packet( fd_bundle_tile_t *         ctx,
                                fd_bundle_packet_t const * packet ) {
  if( FD_UNLIKELY( !fd_bundle_txn_sz_valid( packet->data_sz ) ) ) {
    FD_LOG_WARNING(( "Bundle server delivered a %lu byte packet, ignoring", packet->data_sz ));
    return;
  }
  if( FD_UNLIKELY( !fd_bundle_tile_cr_avail( ctx ) ) ) {
    ctx->metrics.backpressure_drop_cnt++;
    return;
  }
  fd_bundle_tile_publish_txn( ctx, packet->data, packet->data_sz, fd_bundle_packet_ip4( packet, 0U ), 0UL );
  ctx->metrics.packet_received_cnt++;
}

/* Handle a SubscribePacketsResponse from a SubscribePackets gRPC call.
   Its PacketBatch is field batch_field: 2 from a block engine, 3 from
   the relayer, which also sends heartbeats (field 2) while idle. */

static void
fd_bundle_client_handle_packet_batch(
    fd_bundle_tile_t * ctx,
    fd_pb_inbuf_t      in,
    uint               batch_field
) {
  long ts = 0L;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) goto fail;
    if( tlv->field_id==1U ) { /* header */
      fd_pb_inbuf_t header[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, header ) ) ) goto fail;
      ts = fd_bundle_client_decode_header_ts( *header );
      if( FD_UNLIKELY( ts<0L ) ) goto fail;
    } else if( tlv->field_id==batch_field ) { /* batch (PacketBatch) */
      fd_pb_inbuf_t batch[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, batch ) ) ) goto fail;
      while( fd_pb_inbuf_sz( batch ) ) {
        fd_pb_tlv_t batch_tlv[1];
        if( FD_UNLIKELY( !fd_pb_tlv_read( batch, batch_tlv ) ) ) goto fail;
        if( batch_tlv->field_id==1U ) { /* packets */
          fd_pb_inbuf_t sub[1];
          fd_bundle_packet_t packet[1];
          if( FD_UNLIKELY( !fd_pb_tlv_submsg( batch, batch_tlv, sub ) ) ) goto fail;
          if( FD_UNLIKELY( !fd_bundle_client_decode_packet( *sub, packet ) ) ) goto fail;
          fd_bundle_client_handle_packet( ctx, packet );
        }
        if( FD_UNLIKELY( !fd_pb_tlv_skip( batch, batch_tlv ) ) ) goto fail;
      }
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) goto fail;
  }

  fd_bundle_client_sample_rx_delay( ctx, ts );
  return;

fail:
  ctx->metrics.decode_fail_cnt++;
  FD_LOG_WARNING(( "Protobuf decode of (block_engine.SubscribePacketsResponse) failed" ));
}

/* fd_bundle_client_pb_find finds the last field field_id of the
   Protobuf message in.  Returns 1 if found, with *tlv set and *val
   positioned at the field's value, 0 if absent, and -1 on decode
   failure.  fd_bundle_client_pb_{varint,submsg,cstr} read such a field
   as a varint, submessage or string, returning the same. */

static int
fd_bundle_client_pb_find( fd_pb_inbuf_t   in,
                          uint            field_id,
                          fd_pb_tlv_t *   tlv,
                          fd_pb_inbuf_t * val ) {
  int found = 0;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t cur[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, cur ) ) ) return -1;
    if( cur->field_id==field_id ) {
      *tlv  = *cur;
      *val  = in;
      found = 1;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, cur ) ) ) return -1;
  }
  return found;
}

static int
fd_bundle_client_pb_varint( fd_pb_inbuf_t in,
                            uint          field_id,
                            ulong *       out ) {
  fd_pb_tlv_t tlv[1] = {{0}}; fd_pb_inbuf_t val[1] = {{0}};
  int found = fd_bundle_client_pb_find( in, field_id, tlv, val );
  if( found<=0 ) return found;
  if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return -1;
  *out = tlv->varint;
  return 1;
}

static int
fd_bundle_client_pb_submsg( fd_pb_inbuf_t   in,
                            uint            field_id,
                            fd_pb_inbuf_t * out ) {
  fd_pb_tlv_t tlv[1] = {{0}}; fd_pb_inbuf_t val[1] = {{0}};
  int found = fd_bundle_client_pb_find( in, field_id, tlv, val );
  if( found<=0 ) return found;
  return fd_pb_tlv_submsg( val, tlv, out ) ? 1 : -1;
}

static int
fd_bundle_client_pb_cstr( fd_pb_inbuf_t in,
                          uint          field_id,
                          char *        out,
                          ulong         out_max ) {
  fd_pb_tlv_t tlv[1] = {{0}}; fd_pb_inbuf_t val[1] = {{0}};
  int found = fd_bundle_client_pb_find( in, field_id, tlv, val );
  if( found<=0 ) return found;
  return fd_pb_tlv_cstr( val, tlv, out, out_max ) ? 1 : -1;
}

/* fd_bundle_client_handle_block_txn handles a block.Transaction.
   Consecutive transactions with the same nonzero bundle_id form a
   bundle, every other transaction is a bundle of one.  A dropped bundle
   keeps its block_seq so the gap is visible downstream.  Returns 1 on
   success and 0 on decode failure. */

static int
fd_bundle_client_handle_block_txn( fd_bundle_conn_t * conn,
                                   fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  uchar const * data      = NULL;
  ulong         data_sz   = 0UL;
  ulong         bundle_id = 0UL;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    switch( tlv->field_id ) {
    case 1: /* transaction */
      data = fd_pb_tlv_bytes( &in, tlv );
      if( FD_UNLIKELY( !data ) ) return 0;
      data_sz = tlv->len;
      break;
    case 3: /* bundle_id */
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return 0;
      bundle_id = tlv->varint;
      break;
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }

  if( !bundle_id || bundle_id!=conn->harmonic.block_bundle_id ) {
    fd_bundle_client_bundle_close( ctx, ctx->leader_state->slot, conn->harmonic.block_seq );
    fd_bundle_client_bundle_open( ctx, &conn->builder, !!bundle_id, 0 );
    conn->harmonic.block_bundle_id = bundle_id;
    conn->harmonic.block_seq++;
  }
  fd_bundle_client_bundle_push( ctx, data, data_sz, conn->server_ip4_addr );
  return 1;
}

/* Handle a Block from a SubscribeBlocks2 stream.  A Block that is not
   for our current leader slot, or is for a slot a reset cut off, is
   dropped whole.  Its bundles are published as they are decoded, so a
   Block that fails to decode keeps the bundles before the failure. */

static void
fd_bundle_client_handle_block( fd_bundle_conn_t * conn,
                               fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;

  /* Find the slot before publishing anything */
  ulong slot = 0UL;
  if( FD_UNLIKELY( fd_bundle_client_pb_varint( in, 1U, &slot )<0 ) ) goto decode_fail; /* slot */
  if( FD_UNLIKELY( slot!=ctx->leader_state->slot ) ) {
    FD_LOG_INFO(( "Dropping block for slot %lu while leader for slot %lu", slot, ctx->leader_state->slot ));
    return;
  }
  if( FD_UNLIKELY( conn->harmonic.block_lost ) ) {
    FD_LOG_DEBUG(( "Dropping block for slot %lu, cut off by a reset", slot ));
    return;
  }

  conn->harmonic.block_bundle_id = 0UL;
  ctx->bundle.txn_cnt            = 0UL;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) goto decode_fail;
    if( tlv->field_id==15U ) { /* transactions */
      fd_pb_inbuf_t txn[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, txn ) ) ) goto decode_fail;
      if( FD_UNLIKELY( !fd_bundle_client_handle_block_txn( conn, *txn ) ) ) goto decode_fail;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) goto decode_fail;
  }
  fd_bundle_client_bundle_close( ctx, slot, conn->harmonic.block_seq );
  return;

decode_fail:
  ctx->metrics.decode_fail_cnt++;
  FD_LOG_WARNING(( "Protobuf decode of (block.Block) failed" ));
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
    fd_pb_inbuf_t      in
) {
  fd_bundle_tile_t * ctx = conn->ctx;
  char  pubkey[ FD_BASE58_ENCODED_32_SZ ] = {0};
  ulong commission = 0UL;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) goto decode_fail;
    switch( tlv->field_id ) {
    case 1: /* pubkey */
      if( FD_UNLIKELY( !fd_pb_tlv_cstr( &in, tlv, pubkey, sizeof(pubkey) ) ) ) goto decode_fail;
      break;
    case 2: /* commission */
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) goto decode_fail;
      commission = tlv->varint;
      break;
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) goto decode_fail;
  }
  if( FD_UNLIKELY( !fd_bundle_client_set_builder( ctx, &conn->builder, pubkey, commission ) ) ) return;

  long validity_duration_ns = (long)( 60e9 * 5. ); /* 5 minutes */
  conn->builder.next = fd_bundle_now( ctx ) + validity_duration_ns;
  return;

decode_fail:
  ctx->metrics.decode_fail_cnt++;
  FD_LOG_WARNING(( "Protobuf decode of (block_engine.BlockBuilderFeeInfoResponse) failed" ));
}

static void
fd_bundle_client_bam_handle_challenge( fd_bundle_conn_t * conn,
                                       fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  if( FD_UNLIKELY( fd_bundle_client_pb_cstr( in, 1U, conn->bam.challenge, sizeof(conn->bam.challenge) )<=0 || /* challenge_to_sign */
                   !conn->bam.challenge[ 0 ] ) ) {
    conn->bam.challenge[ 0 ] = '\0';
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Invalid BAM auth challenge" ));
    fd_bundle_conn_backoff( conn, fd_bundle_now( ctx ) );
  }
}

/* fd_bundle_client_bam_handle_packet handles a bam_types.Packet of an
   AtomicTxnBatch.  A batch reverts on error (is atomic) if all its
   packets do.  Returns 1 on success and 0 on decode failure. */

static int
fd_bundle_client_bam_handle_packet( fd_bundle_conn_t * conn,
                                    fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  uchar const * data    = NULL;
  ulong         data_sz = 0UL;
  ulong         revert  = 0UL;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    switch( tlv->field_id ) {
    case 1: /* data */
      data = fd_pb_tlv_bytes( &in, tlv );
      if( FD_UNLIKELY( !data ) ) return 0;
      data_sz = tlv->len;
      break;
    case 2: { /* meta */
      fd_pb_inbuf_t meta [1];
      fd_pb_inbuf_t flags[1] = {{0}};
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, meta ) ||
                       fd_bundle_client_pb_submsg( *meta,  2U, flags   )<0 ||       /* flags */
                       fd_bundle_client_pb_varint( *flags, 2U, &revert )<0 ) ) return 0; /* revert_on_error */
      break;
    }
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }

  int const atomic = !!revert;
  if( FD_UNLIKELY( ctx->bundle.txn_cnt && atomic!=ctx->bundle.atomic ) ) ctx->bundle.invalid = 1;
  ctx->bundle.atomic = (uchar)atomic;
  fd_bundle_client_bundle_push( ctx, data, data_sz, conn->server_ip4_addr );
  return 1;
}

/* fd_bundle_client_bam_handle_batch handles a bam_types.AtomicTxnBatch,
   which is one bundle.  Returns 1 on success and 0 on decode failure.

   TODO: Report dropped batches to BAM as not committed. */

static int
fd_bundle_client_bam_handle_batch( fd_bundle_conn_t * conn,
                                   fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  fd_bundle_client_bundle_open( ctx, &conn->builder, 0, 1 );
  ulong seq_id = 0UL;
  ulong slot   = 0UL;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    switch( tlv->field_id ) {
    case 1: /* seq_id */
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return 0;
      seq_id = (uint)tlv->varint;
      break;
    case 2: /* max_schedule_slot */
      if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return 0;
      slot = tlv->varint;
      break;
    case 3: { /* packets */
      fd_pb_inbuf_t packet[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, packet ) ) ) return 0;
      if( FD_UNLIKELY( !fd_bundle_client_bam_handle_packet( conn, *packet ) ) ) return 0;
      break;
    }
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }

  /* As in jito-solana, only a batch that reverts on error may hold
     more than one transaction */
  if( FD_UNLIKELY( !ctx->bundle.atomic && ctx->bundle.txn_cnt>1UL ) ) ctx->bundle.invalid = 1;
  fd_bundle_client_bundle_close( ctx, slot, seq_id );
  return 1;
}

/* fd_bundle_client_bam_handle_batches handles a
   bam_types.MultipleAtomicTxnBatch.  Returns 1 on success and 0 on
   decode failure. */

static int
fd_bundle_client_bam_handle_batches( fd_bundle_conn_t * conn,
                                     fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  if( FD_UNLIKELY( !conn->builder.avail ) ) {
    ctx->metrics.missing_builder_info_fail_cnt++;
    return 1;
  }
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) return 0;
    if( tlv->field_id==3U ) { /* batches */
      fd_pb_inbuf_t batch[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, batch ) ) ) return 0;
      if( FD_UNLIKELY( !fd_bundle_client_bam_handle_batch( conn, *batch ) ) ) return 0;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) return 0;
  }
  return 1;
}

/* Handle a SchedulerResponse from the scheduler stream.  The first one
   shows the node accepted the login. */

static void
fd_bundle_client_bam_handle_response( fd_bundle_conn_t * conn,
                                      fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  fd_pb_inbuf_t v0[1];
  if( FD_UNLIKELY( fd_bundle_client_pb_submsg( in, 1U, v0 )<=0 ) ) goto fail; /* v0 */

  int   ping      = 0;
  ulong ping_id   = 0UL;
  int   heartbeat = 0;
  while( fd_pb_inbuf_sz( v0 ) ) {
    fd_pb_tlv_t   tlv[1];
    fd_pb_inbuf_t sub[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( v0, tlv ) ) ) goto fail;
    switch( tlv->field_id ) {
    case 1: /* heart_beat */
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( v0, tlv, sub ) ) ) goto fail;
      heartbeat = 1;
      break;
    case 2: /* multiple_atomic_txn_batch */
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( v0, tlv, sub ) ) ) goto fail;
      if( FD_UNLIKELY( !fd_bundle_client_bam_handle_batches( conn, *sub ) ) ) goto fail;
      break;
    case 3: /* ping */
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( v0, tlv, sub ) ) ) goto fail;
      if( FD_UNLIKELY( fd_bundle_client_pb_varint( *sub, 1U, &ping_id )<0 ) ) goto fail; /* id */
      ping = 1;
      break;
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( v0, tlv ) ) ) goto fail;
  }

  conn->bam.stream_accepted = 1;
  if( ping ) {
    conn->bam.pong_pending = 1;
    conn->bam.pong_id      = (uint)ping_id;
  }
  if( heartbeat ) {
    conn->bam.heartbeat_seen = 1;
    conn->bam.heartbeat_rx   = fd_bundle_now( ctx );
  }
  return;

fail:
  ctx->metrics.decode_fail_cnt++;
  FD_LOG_WARNING(( "Invalid BAM scheduler response. Reconnecting ..." ));
  conn->defer_reset = 1;
}

/* fd_bundle_client_socket decodes a bam_types.Socket or shared.Socket.
   Returns 1 on success, 0 if it fails to decode or is not a nonzero
   IPv4 address with a port that leaves room for the QUIC port (6
   higher). */

static int
fd_bundle_client_socket( fd_pb_inbuf_t in,
                             uint *        ip4,
                             ushort *      port ) {
  char  ip[ 64 ] = {0};
  ulong port_    = 0UL;
  if( FD_UNLIKELY( fd_bundle_client_pb_cstr  ( in, 1U, ip, sizeof(ip) )<0 || /* ip */
                   fd_bundle_client_pb_varint( in, 2U, &port_         )<0 ) ) return 0; /* port */
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( ip, ip4 ) || !*ip4 || !port_ || port_>USHORT_MAX-6U ) ) return 0;
  *port = (ushort)port_;
  return 1;
}

static void
fd_bundle_client_bam_handle_config( fd_bundle_conn_t * conn,
                                    fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  fd_pb_inbuf_t builder_cfg[1] = {{0}};
  fd_pb_inbuf_t bam_cfg    [1] = {{0}};
  fd_pb_inbuf_t tpu_sock   [1] = {{0}};
  fd_pb_inbuf_t fwd_sock   [1] = {{0}};
  fd_pb_inbuf_t shred_sock [1] = {{0}};
  char          pubkey[ 64 ]   = {0};
  ulong         commission     = 0UL;
  int const has_builder = fd_bundle_client_pb_submsg( in, 1U, builder_cfg ); /* block_engine_config */
  if( FD_UNLIKELY( has_builder<0 ||
                   fd_bundle_client_pb_submsg( in,           2U, bam_cfg                )<0 || /* bam_config */
                   fd_bundle_client_pb_cstr  ( *builder_cfg, 1U, pubkey, sizeof(pubkey) )<0 || /* builder_pubkey */
                   fd_bundle_client_pb_varint( *builder_cfg, 2U, &commission            )<0 || /* builder_commission */
                   fd_bundle_client_pb_submsg( *bam_cfg,     3U, tpu_sock               )<0 || /* tpu_sock */
                   fd_bundle_client_pb_submsg( *bam_cfg,     4U, fwd_sock               )<0 ||   /* tpu_fwd_sock */
                   fd_bundle_client_pb_submsg( *bam_cfg,     5U, shred_sock             )<0 ) ) { /* shred_socks */
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (bam_api.ConfigResponse) failed" ));
    return;
  }
  if( has_builder && fd_bundle_client_set_builder( ctx, &conn->builder, pubkey, commission ) ) {
    conn->builder.next = fd_bundle_now( ctx ) + FD_BUNDLE_BAM_CONFIG_REFRESH;
  }

  /* As in FireBAM, only a valid pair replaces the TPU, which is kept
     across reconnects */
  fd_bundle_tpu_t tpu = {0};
  if( fd_bundle_client_socket( *tpu_sock, &tpu.ip4,     &tpu.port     ) &&
      fd_bundle_client_socket( *fwd_sock, &tpu.fwd_ip4, &tpu.fwd_port ) ) {
    conn->tpu = tpu;
  }

  /* As in jito-solana, a config without one clears the shred receiver.
     We forward to one of them (the last). */
  uint   shred_ip4  = 0U;
  ushort shred_port = 0;
  conn->shred = fd_bundle_client_socket( *shred_sock, &shred_ip4, &shred_port ) ? fd_bundle_shred_sig( shred_ip4, shred_port ) : 0UL;
}

/* Handle a GetBlockEngineEndpointResponse: the global endpoint's
   ShredStream receiver, a host:port, is the shred receiver. */

static void
fd_bundle_client_handle_endpoints( fd_bundle_conn_t * conn,
                                   fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  fd_pb_inbuf_t endpoint[1]  = {{0}};
  char          addr[ 256 ] = {0};
  if( FD_UNLIKELY( fd_bundle_client_pb_submsg( in,        1U, endpoint           )<0 ||   /* global_endpoint */
                   fd_bundle_client_pb_cstr  ( *endpoint, 2U, addr, sizeof(addr) )<0 ) ) { /* shredstream_receiver_address */
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (block_engine.GetBlockEngineEndpointResponse) failed" ));
    return;
  }
  char * colon = strrchr( addr, ':' );
  ulong  port  = colon ? fd_cstr_to_ulong( colon+1 ) : 0UL;
  if( FD_UNLIKELY( !port || port>USHORT_MAX ) ) {
    FD_LOG_WARNING(( "Invalid shred receiver `%s`", addr ));
    return;
  }
  *colon = '\0';

  fd_addrinfo_t hints = {0};
  hints.ai_family = AF_INET;
  fd_addrinfo_t * res = NULL;
  uchar scratch[ 4096 ];
  void * pscratch = scratch;
  int err = fd_getaddrinfo( addr, &hints, &res, &pscratch, sizeof(scratch) );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_getaddrinfo `%s` failed (%d-%s)", addr, err, fd_gai_strerror( err ) ));
    return;
  }
  conn->shred = fd_bundle_shred_sig( ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr, (ushort)port );
}

/* Handle a GetTpuConfigsResponse from the relayer.  Only a valid pair
   of sockets makes its TPU available. */

static void
fd_bundle_client_handle_tpu_configs( fd_bundle_conn_t * conn,
                                     fd_pb_inbuf_t      in ) {
  fd_bundle_tile_t * ctx = conn->ctx;
  fd_pb_inbuf_t tpu_sock[1] = {{0}};
  fd_pb_inbuf_t fwd_sock[1] = {{0}};
  if( FD_UNLIKELY( fd_bundle_client_pb_submsg( in, 1U, tpu_sock )<0 ||   /* tpu */
                   fd_bundle_client_pb_submsg( in, 2U, fwd_sock )<0 ) ) { /* tpu_forward */
    ctx->metrics.decode_fail_cnt++;
    FD_LOG_WARNING(( "Protobuf decode of (relayer.GetTpuConfigsResponse) failed" ));
    return;
  }
  fd_bundle_tpu_t tpu = {0};
  if( FD_UNLIKELY( !fd_bundle_client_socket( *tpu_sock, &tpu.ip4,     &tpu.port     ) ||
                   !fd_bundle_client_socket( *fwd_sock, &tpu.fwd_ip4, &tpu.fwd_port ) ) ) {
    FD_LOG_WARNING(( "Invalid relayer TPU" ));
    return;
  }
  conn->tpu           = tpu;
  conn->builder.avail = 1;
  conn->builder.next  = fd_bundle_now( ctx ) + (long)60e9;
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
  fd_pb_inbuf_t in[1]; fd_pb_inbuf_init( in, protobuf, protobuf_sz );

  fd_bundle_conn_t * builder = fd_bundle_client_builder( ctx );
  ctx->cr_reserve = ( builder && conn!=builder ) ? ctx->stem->depths[ ctx->verify_out.idx ]/2UL : 0UL;

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
    fd_bundle_client_handle_bundle_batch( conn, *in );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets:
    fd_bundle_client_handle_packet_batch( ctx, *in, 2U );
    break;
  case FD_BUNDLE_CLIENT_REQ_Relayer_SubscribePackets:
    fd_bundle_client_handle_packet_batch( ctx, *in, 3U );
    break;
  case FD_BUNDLE_CLIENT_REQ_Relayer_GetTpuConfigs:
    fd_bundle_client_handle_tpu_configs( conn, *in );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    fd_bundle_client_handle_builder_fee_info( conn, *in );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockEngineEndpoints:
    fd_bundle_client_handle_endpoints( conn, *in );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks:
    fd_bundle_client_handle_block( conn, *in );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy:
  case FD_BUNDLE_CLIENT_REQ_Bundle_SubmitLeaderWindowInfo:
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge:
    fd_bundle_client_bam_handle_challenge( conn, *in );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream:
    fd_bundle_client_bam_handle_response( conn, *in );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig:
    fd_bundle_client_bam_handle_config( conn, *in );
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
  ulong sub = fd_bundle_sub_idx( request_ctx );
  if( sub!=ULONG_MAX ) {
    conn->sub[ sub ].live = 0;
    conn->sub[ sub ].wait = 0;
  }
  if( request_ctx==fd_bundle_conn_protocol( conn )->poll.id ) conn->builder.wait = 0;
  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthChallenge:
  case FD_BUNDLE_CLIENT_REQ_Auth_GenerateAuthTokens:
    fd_bundle_auther_handle_request_fail( &conn->auther );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy:
    conn->strategy_wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge:
    conn->bam.challenge_wait = 0;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream:
    conn->bam.stream = NULL;
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

  ulong sub = fd_bundle_sub_idx( request_ctx );
  if( sub!=ULONG_MAX ) {
    conn->sub[ sub ].live = 0;
    conn->sub[ sub ].wait = 0;
    fd_bundle_conn_backoff( conn, fd_bundle_now( ctx ) );
    conn->defer_reset = 1;
    FD_LOG_INFO(( "%s stream failed (gRPC status %u-%s). Reconnecting ...",
                  fd_bundle_request_ctx_cstr( request_ctx ),
                  resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ) ));
    return;
  }
  if( request_ctx==fd_bundle_conn_protocol( conn )->poll.id ) conn->builder.wait = 0;

  switch( request_ctx ) {
  case FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy:
    conn->strategy_wait = 0;
    conn->strategy_set  = resp->grpc_status==FD_GRPC_STATUS_OK;
    break;
  case FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream:
    conn->bam.stream = NULL;
    fd_bundle_conn_backoff( conn, fd_bundle_now( ctx ) );
    conn->defer_reset = 1;
    FD_LOG_INFO(( "InitSchedulerStream stream failed (gRPC status %u-%s). Reconnecting ...",
                  resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ) ));
    return;
  case FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge:
    conn->bam.challenge_wait = 0;
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

/* fd_bundle_conn_transport_status returns the FD_BUNDLE_STATE_* of
   conn's transport, before any session on it. */

static int
fd_bundle_conn_transport_status( fd_bundle_conn_t const * conn ) {
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
fd_bundle_conn_status( fd_bundle_conn_t const * conn ) {
  int status = fd_bundle_conn_transport_status( conn );
  if( FD_UNLIKELY( status!=FD_BUNDLE_STATE_CONNECTED ) ) return status;
  return fd_bundle_conn_protocol( conn )->status( conn );
}

static int
fd_bundle_client_jito_status( fd_bundle_conn_t const * conn ) {
  if( FD_UNLIKELY( conn->auther.state != FD_BUNDLE_AUTH_STATE_DONE_WAIT ) ) {
    return FD_BUNDLE_STATE_CONNECTING; /* not authenticated */
  }

  if( FD_UNLIKELY( !conn->builder.avail ) ) return FD_BUNDLE_STATE_CONNECTING; /* no builder yet */
  fd_bundle_protocol_t const * protocol = fd_bundle_conn_protocol( conn );
  for( ulong sub=0UL; sub<FD_BUNDLE_SUB_CNT; sub++ ) {
    if( FD_UNLIKELY( protocol->subs[ sub ] && !conn->sub[ sub ].live ) ) {
      return FD_BUNDLE_STATE_CONNECTING; /* not fully subscribed */
    }
  }

  /* As far as we know, the bundle connection is alive and well. */
  return FD_BUNDLE_STATE_CONNECTED;
}

static int
fd_bundle_client_bam_status( fd_bundle_conn_t const * conn ) {
  if( FD_UNLIKELY( !conn->bam.stream || !conn->bam.heartbeat_seen || !conn->builder.avail ) ) {
    return FD_BUNDLE_STATE_CONNECTING; /* not logged in, no heartbeat or no builder yet */
  }
  return FD_BUNDLE_STATE_CONNECTED;
}

int
fd_bundle_client_status( fd_bundle_tile_t const * ctx ) {
  int status = ctx->conn_cnt ? FD_BUNDLE_STATE_CONNECTED : FD_BUNDLE_STATE_DISCONNECTED;
  for( ulong i=0UL; i<ctx->conn_cnt; i++ ) status = fd_int_min( status, fd_bundle_conn_status( &ctx->conn[ i ] ) );
  return status;
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
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockEngineEndpoints:
    return "GetBlockEngineEndpoints";
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
  case FD_BUNDLE_CLIENT_REQ_Relayer_SubscribePackets:
    return "relayer.SubscribePackets";
  case FD_BUNDLE_CLIENT_REQ_Relayer_GetTpuConfigs:
    return "GetTpuConfigs";
  default:
    return "unknown";
  }
}
