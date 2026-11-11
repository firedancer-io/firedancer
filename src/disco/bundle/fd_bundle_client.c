/* fd_bundle_client.c steps gRPC related tasks. */

#define _GNU_SOURCE /* SOL_TCP */
#include "fd_bundle_auth.h"
#include "fd_bundle_tile_private.h"
#include "fd_bundle_tile.h"
#include "../waker/fd_waker.h"
#include "../fd_txn_m.h"
#include "../../waltz/h2/fd_h2_conn.h"
#include "../../waltz/http/fd_url.h" /* fd_url_unescape */
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/ed25519/fd_x25519.h"
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

/* fd_bundle_protocols describes how the client talks to each kind of
   bundle server.  The session hooks drive the session on a connected
   conn: a Jito session (fd_bundle_client_jito_*) logs in and subscribes
   to streams.  step drives it and returns 1 if it did work, status
   returns its FD_BUNDLE_STATE_*, deadline when it next needs a step
   (absent any fd event), and reset clears it. */

struct fd_bundle_request {
  ulong        id; /* FD_BUNDLE_CLIENT_REQ_* */
  char const * path;
};

typedef struct fd_bundle_request fd_bundle_request_t;

struct fd_bundle_protocol {
  char const *        name;
  char const *        subs[ FD_BUNDLE_SUB_CNT ]; /* path of each FD_BUNDLE_SUB_* stream, NULL if none, all required for a healthy connection */
  fd_bundle_request_t poll;                      /* block builder info, polled while it is valid */

  int  (* step    )( fd_bundle_conn_t * conn, long now );
  int  (* status  )( fd_bundle_conn_t const * conn );
  long (* deadline)( fd_bundle_conn_t const * conn, long now );
  void (* reset   )( fd_bundle_conn_t * conn );
};

typedef struct fd_bundle_protocol fd_bundle_protocol_t;

static int  fd_bundle_client_jito_step    ( fd_bundle_conn_t *       conn, long now );
static int  fd_bundle_client_jito_status  ( fd_bundle_conn_t const * conn );
static long fd_bundle_client_jito_deadline( fd_bundle_conn_t const * conn, long now );
static void fd_bundle_client_jito_reset   ( fd_bundle_conn_t *       conn );

#define BLOCK_ENGINE "/block_engine.BlockEngineValidator/"
#define SESSION( kind ) .step     = fd_bundle_client_##kind##_step,     \
                        .status   = fd_bundle_client_##kind##_status,   \
                        .deadline = fd_bundle_client_##kind##_deadline, \
                        .reset    = fd_bundle_client_##kind##_reset

static fd_bundle_protocol_t const fd_bundle_protocols[] = {
  [ FD_BUNDLE_PROTOCOL_JITO ] = {
    .name = "jito",
    .subs = { [ FD_BUNDLE_SUB_PACKETS ] = BLOCK_ENGINE "SubscribePackets",
              [ FD_BUNDLE_SUB_BUNDLES ] = BLOCK_ENGINE "SubscribeBundles" },
    .poll = { FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo, BLOCK_ENGINE "GetBlockBuilderFeeInfo" },
    SESSION( jito ),
  },
};

#undef SESSION
#undef BLOCK_ENGINE

/* fd_bundle_subs describes each FD_BUNDLE_SUB_* stream. */

static struct {
  ulong request_ctx;
} const fd_bundle_subs[ FD_BUNDLE_SUB_CNT ] = {
  [ FD_BUNDLE_SUB_PACKETS ] = { FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets },
  [ FD_BUNDLE_SUB_BUNDLES ] = { FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles },
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


__attribute__((weak)) long
fd_bundle_now( fd_bundle_tile_t const * ctx ) {
  return fd_clock_tile_now( ctx->clock );
}

static void
fd_bundle_client_jito_reset( fd_bundle_conn_t * conn ) {
  fd_bundle_auther_reset( &conn->auther );
  conn->builder       = (fd_bundle_builder_t){0};
  fd_memset( conn->sub, 0, sizeof(conn->sub) );
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

static void
fd_bundle_client_request_builder_info( fd_bundle_conn_t * conn ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( conn->grpc_client ) ) ) return;

  fd_bundle_request_t const * poll = &fd_bundle_conn_protocol( conn )->poll;
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      poll->path, strlen( poll->path ),
      poll->id,
      (uchar const *)"", 0UL, /* empty request message */
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

  char const * path = fd_bundle_conn_protocol( conn )->subs[ sub ];
  fd_grpc_h2_stream_t * request = fd_grpc_client_request_start(
      conn->grpc_client,
      path, strlen( path ),
      fd_bundle_subs[ sub ].request_ctx,
      (uchar const *)"", 0UL, /* empty request message */
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
  long deadline = fd_bundle_conn_next_deadline( conn, now );
  if( FD_UNLIKELY( !conn->tcp_sock_connected ) ) return deadline;
  return fd_long_min( deadline, fd_bundle_conn_protocol( conn )->deadline( conn, now ) );
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

long
fd_bundle_client_next_deadline( fd_bundle_tile_t const * ctx,
                                long                     now ) {
  long deadline = LONG_MAX;
  for( ulong i=0UL; i<ctx->conn_cnt; i++ ) deadline = fd_long_min( deadline, fd_bundle_conn_session_deadline( &ctx->conn[ i ], now ) );
  return deadline;
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

  /* Request block builder info */
  if( FD_UNLIKELY( fd_bundle_builder_due( &conn->builder, now ) ) ) {
    fd_bundle_client_request_builder_info( conn );
    return 1;
  }

  for( ulong sub=0UL; sub<FD_BUNDLE_SUB_CNT; sub++ ) {
    if( FD_UNLIKELY( protocol->subs[ sub ] && !conn->sub[ sub ].live && !conn->sub[ sub ].wait ) ) {
      fd_bundle_client_subscribe( conn, sub );
      return 1;
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
  if( FD_LIKELY( fd_bundle_conn_step( conn, charge_busy ) ) ) {
    *charge_busy |= fd_bundle_client_step_reconnect( conn, fd_bundle_now( conn->ctx ) );
  }
  fd_bundle_conn_flush( conn, charge_busy );
}

void
fd_bundle_client_step( fd_bundle_tile_t * ctx,
                       int *              charge_busy ) {
  for( ulong i=0UL; i<ctx->conn_cnt; i++ ) fd_bundle_client_step_conn( &ctx->conn[ i ], charge_busy );

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

static inline ulong
fd_bundle_tile_cr_avail( fd_bundle_tile_t const * ctx ) {
  return ctx->stem->cr_avail[ ctx->verify_out.idx ];
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
      .commission     = is_bundle ? ctx->bundle.builder->commission : (uchar)0,
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

/* Every bundle source decodes a bundle with bundle_open, bundle_push
   for each transaction and bundle_close, which publishes it.  A bundle
   that is too large, has an invalid transaction or does not fit is
   dropped whole on close.  The transactions point into the message
   being decoded. */

static void
fd_bundle_client_bundle_open( fd_bundle_tile_t *          ctx,
                              fd_bundle_builder_t const * builder ) {
  ctx->bundle.builder = builder;
  ctx->bundle.txn_cnt = 0UL;
  ctx->bundle.invalid = 0;
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

static void
fd_bundle_client_bundle_close( fd_bundle_tile_t * ctx ) {
  ulong const n = ctx->bundle.txn_cnt;
  ctx->bundle.txn_cnt = 0UL;
  if( FD_UNLIKELY( !n ) ) return;
  if( FD_UNLIKELY( ctx->bundle.invalid | (n>FD_BUNDLE_CLIENT_MAX_TXN_PER_BUNDLE) ) ) {
    FD_LOG_DEBUG(( "Dropping a bundle with %lu transactions", n ));
    return;
  }
  if( FD_UNLIKELY( fd_bundle_tile_cr_avail( ctx )<n ) ) {
    ctx->metrics.backpressure_drop_cnt += n;
    return;
  }
  ctx->bundle_seq++;
  for( ulong i=0UL; i<n; i++ ) {
    fd_bundle_tile_publish_txn( ctx, ctx->bundle.txn[ i ].data, ctx->bundle.txn[ i ].data_sz, ctx->bundle.txn[ i ].source_ipv4, n );
  }
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
  fd_bundle_client_bundle_open( ctx, &conn->builder );
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

  fd_bundle_client_bundle_close( ctx );
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

/* Handle a SubscribePacketsResponse from a SubscribePackets gRPC call. */

static void
fd_bundle_client_handle_packet_batch(
    fd_bundle_tile_t * ctx,
    fd_pb_inbuf_t      in
) {
  long ts = 0L;
  while( fd_pb_inbuf_sz( &in ) ) {
    fd_pb_tlv_t tlv[1];
    if( FD_UNLIKELY( !fd_pb_tlv_read( &in, tlv ) ) ) goto fail;
    switch( tlv->field_id ) {
    case 1: { /* header */
      fd_pb_inbuf_t header[1];
      if( FD_UNLIKELY( !fd_pb_tlv_submsg( &in, tlv, header ) ) ) goto fail;
      ts = fd_bundle_client_decode_header_ts( *header );
      if( FD_UNLIKELY( ts<0L ) ) goto fail;
      break;
    }
    case 2: { /* batch (PacketBatch) */
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
      break;
    }
    default:
      break;
    }
    if( FD_UNLIKELY( !fd_pb_tlv_skip( &in, tlv ) ) ) goto fail;
  }

  fd_bundle_client_sample_rx_delay( ctx, ts );
  return;

fail:
  ctx->metrics.decode_fail_cnt++;
  FD_LOG_WARNING(( "Protobuf decode of (block_engine.SubscribePacketsResponse) failed" ));
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
    fd_bundle_client_handle_packet_batch( ctx, *in );
    break;
  case FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo:
    fd_bundle_client_handle_builder_fee_info( conn, *in );
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
  default:
    return "unknown";
  }
}
