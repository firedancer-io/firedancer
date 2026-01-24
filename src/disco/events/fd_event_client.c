#define _GNU_SOURCE
#include "fd_event_client.h"

#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/http/fd_url.h"
#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../waltz/grpc/fd_grpc_client_private.h"
#include "../../ballet/pb/fd_pb_tokenize.h"
#include "../../ballet/pb/fd_pb_encode.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/log/fd_log.h"
#include "../keyguard/fd_keyguard.h"

#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DISCONNECT_REASON_IDENTITY_CHANGED   (0)
#define DISCONNECT_REASON_CONNECT_FAILED     (1)
#define DISCONNECT_REASON_DNS_RESOLVE_FAILED (2)
#define DISCONNECT_REASON_TIMEOUT            (3)
#define DISCONNECT_REASON_TRANSPORT_FAILED   (4)
#define DISCONNECT_REASON_PEER_CLOSED        (5)
#define DISCONNECT_REASON_INVALID_CURSOR     (6)
#define DISCONNECT_REASON_AUTH_FAILED        (7)

#define FD_EVENT_CLIENT_REQ_CTX_AUTHENTICATE  (1UL)
#define FD_EVENT_CLIENT_REQ_CTX_CONFIRM_AUTH  (2UL)
#define FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS (3UL)

struct fd_event_client {
  fd_grpc_client_t * grpc_client;
  fd_grpc_client_metrics_t grpc_metrics[1];
  fd_grpc_h2_stream_t * event_stream;

  char client_version[ 10UL ];
  uchar identity_pubkey[ 32UL ];

  int has_genesis_hash;
  uchar genesis_hash[ 32UL ];

  ushort has_shred_version;
  ushort shred_version;

  ulong event_id;

  ulong instance_id;
  ulong boot_id;
  ulong machine_id;

  int defer_disconnect;
  ulong consecutive_failure_count;

  ulong state;
  union {
    struct {
      long reconnect_deadline;
    } disconnected;

    struct {
      long connect_deadline;
    } connecting;

    struct {
      long connected_timestamp;
    } connected;
  };

  int so_sndbuf;
  int sockfd;

  char   server_fqdn[ 256 ]; /* cstr */
  ulong  server_fqdn_len;
  uint   server_ip4_addr;
  ushort server_tcp_port;

  fd_rng_t * rng;
  fd_circq_t * circq;
  fd_keyguard_client_t * keyguard_client;

  fd_event_client_metrics_t metrics;
};

FD_FN_CONST ulong
fd_event_client_align( void ) {
  return alignof( fd_event_client_t );
}

FD_FN_CONST ulong
fd_event_client_footprint( ulong buf_max ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_event_client_t), sizeof(fd_event_client_t)           );
  l = FD_LAYOUT_APPEND( l, fd_grpc_client_align(),     fd_grpc_client_footprint( buf_max ) );
  return FD_LAYOUT_FINI( l, alignof(fd_event_client_t) );
}

static void
parse_url( fd_url_t *   url_,
           char const * url_str,
           ulong        url_str_len,
           ushort *     tcp_port ) {

  /* Parse URL */

  int url_err[1];
  fd_url_t * url = fd_url_parse_cstr( url_, url_str, url_str_len, url_err );
  if( FD_UNLIKELY( !url ) ) {
    switch( *url_err ) {
    scheme_err:
    case FD_URL_ERR_SCHEME:
      FD_LOG_ERR(( "Invalid [tiles.event.url] `%.*s`: must start with `http://`", (int)url_str_len, url_str ));
      break;
    case FD_URL_ERR_HOST_OVERSZ:
      FD_LOG_ERR(( "Invalid [tiles.event.url] `%.*s`: domain name is too long", (int)url_str_len, url_str ));
      break;
    default:
      FD_LOG_ERR(( "Invalid [tiles.event.url] `%.*s`", (int)url_str_len, url_str ));
      break;
    }
  }

  /* FIXME the URL scheme path technically shouldn't contain slashes */
  if( url->scheme_len==7UL && fd_memeq( url->scheme, "http://", 7UL ) ) {
  } else {
    goto scheme_err;
  }

  /* Parse port number */

  *tcp_port = 7878;
  if( url->port_len ) {
    if( FD_UNLIKELY( url->port_len > 5 ) ) {
    invalid_port:
      FD_LOG_ERR(( "Invalid [tiles.event.url] `%.*s`: invalid port number", (int)url_str_len, url_str ));
    }

    char port_cstr[6];
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( port_cstr ), url->port, url->port_len ) );
    ulong port_no = fd_cstr_to_ulong( port_cstr );
    if( FD_UNLIKELY( !port_no || port_no>USHORT_MAX ) ) goto invalid_port;

    *tcp_port = (ushort)port_no;
  }

  /* Resolve domain */

  if( FD_UNLIKELY( url->host_len > 255 ) ) {
    FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  }
  char host_cstr[ 256 ];
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( host_cstr ), url->host, url->host_len ) );
}

void *
fd_event_client_new( void *                 shmem,
                     fd_keyguard_client_t * keyguard_client,
                     fd_rng_t *             rng,
                     fd_circq_t *           circq,
                     int                    so_sndbuf,
                     char const *           _url,
                     uchar const *          identity_pubkey,
                     char const *           client_version,
                     ulong                  instance_id,
                     ulong                  boot_id,
                     ulong                  machine_id,
                     ulong                  buf_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_event_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_event_client_t * client = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_event_client_t), sizeof(fd_event_client_t)          );
  void * grpc_client_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_client_align(),     fd_grpc_client_footprint( buf_max ) );

  fd_url_t url[1];
  parse_url(
      url,
      _url,
      strlen( _url ),
      &client->server_tcp_port );
  if( FD_UNLIKELY( url->host_len > 255 ) ) {
    FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  }
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( client->server_fqdn ), url->host, url->host_len ) );
  client->server_fqdn_len = url->host_len;

  fd_memcpy( client->identity_pubkey, identity_pubkey, 32UL );
  strncpy( client->client_version, client_version, sizeof( client->client_version ) );
  client->client_version[ sizeof( client->client_version ) - 1UL ] = '\0';

  client->event_id = 0UL;

  client->instance_id = instance_id;
  client->boot_id     = boot_id;
  client->machine_id  = machine_id;

  client->has_genesis_hash = 0;
  client->has_shred_version = 0;

  client->so_sndbuf = so_sndbuf;
  client->sockfd = -1;
  client->state = FD_EVENT_CLIENT_STATE_DISCONNECTED;
  client->disconnected.reconnect_deadline = 0L;

  client->defer_disconnect = INT_MAX;
  client->consecutive_failure_count = 7UL; /* Start high, so if server is down we don't keep retrying on boot */

  client->circq = circq;
  client->rng = rng;
  client->keyguard_client = keyguard_client;

  extern fd_grpc_client_callbacks_t fd_event_client_grpc_callbacks;
  client->grpc_client = fd_grpc_client_new( grpc_client_mem, &fd_event_client_grpc_callbacks, client->grpc_metrics, client, buf_max, fd_rng_ulong( rng ) );
  FD_TEST( client->grpc_client );

  memset( &client->metrics, 0, sizeof( client->metrics ) );

  fd_grpc_client_set_version( client->grpc_client, client->client_version, strlen( client->client_version ) );
  fd_grpc_client_set_authority( client->grpc_client, client->server_fqdn, client->server_fqdn_len, client->server_tcp_port );

  return (void *)client;
}

fd_event_client_t *
fd_event_client_join( void * shec ) {
  if( FD_UNLIKELY( !shec ) ) {
    FD_LOG_WARNING(( "NULL shec" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shec, fd_event_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shec" ));
    return NULL;
  }

  fd_event_client_t * client = (fd_event_client_t *)shec;

  return client;
}

fd_event_client_metrics_t const *
fd_event_client_metrics( fd_event_client_t const * client ) {
  /* Update bytes from grpc metrics */
  ((fd_event_client_t *)client)->metrics.bytes_written = client->grpc_metrics->stream_chunks_tx_bytes;
  ((fd_event_client_t *)client)->metrics.bytes_read = client->grpc_metrics->stream_chunks_rx_bytes;
  return &client->metrics;
}

ulong
fd_event_client_state( fd_event_client_t const * client ) {
  return client->state;
}

ulong
fd_event_client_id_reserve( fd_event_client_t * client ) {
  return client->event_id++;
}

void
fd_event_client_init_genesis_hash( fd_event_client_t * client,
                                   uchar const *       genesis_hash ) {
  fd_memcpy( client->genesis_hash, genesis_hash, 32UL );
  client->has_genesis_hash = 1;
}

void
fd_event_client_init_shred_version( fd_event_client_t * client,
                                    ushort              shred_version ) {
  client->shred_version = shred_version;
  client->has_shred_version = 1;
}

static void
backoff( fd_event_client_t * client ) {
  long now = fd_log_wallclock();
  ulong backoff_base = 1UL << fd_ulong_min( client->consecutive_failure_count, 7UL ); /* max 4 mins */
  ulong backoff_jitter = fd_rng_ulong_roll( client->rng, backoff_base );
  client->disconnected.reconnect_deadline = now + (long)( backoff_base + backoff_jitter )*(long)1e9;
  client->consecutive_failure_count++;
}

static void
disconnect( fd_event_client_t * client,
            int                 reason,
            int                 err,
            int                 _backoff ) {
  if( FD_LIKELY( -1!=client->sockfd ) ) {
    if( FD_UNLIKELY( -1==close( client->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    client->sockfd = -1;
    client->state = FD_EVENT_CLIENT_STATE_DISCONNECTED;
    fd_circq_reset_cursor( client->circq );
  }

  switch( reason ) {
    case DISCONNECT_REASON_IDENTITY_CHANGED:
      FD_LOG_INFO(( "disconnected: identity changed" ));
      break;
    case DISCONNECT_REASON_CONNECT_FAILED:
      FD_LOG_WARNING(( "connecting to " FD_IP4_ADDR_FMT ":%u failed (%i-%s)", FD_IP4_ADDR_FMT_ARGS( client->server_ip4_addr ), client->server_tcp_port, errno, fd_io_strerror( errno ) ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_DNS_RESOLVE_FAILED:
      FD_LOG_WARNING(( "failed to resolve host `%.*s` (%d-%s)", (int)client->server_fqdn_len, client->server_fqdn, err, fd_gai_strerror( err ) ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_TIMEOUT:
      FD_LOG_WARNING(( "disconnected: timeout" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_TRANSPORT_FAILED:
      FD_LOG_WARNING(( "disconnected: transport failed (%d-%s)", err, fd_io_strerror( err ) ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_PEER_CLOSED:
      FD_LOG_WARNING(( "disconnected: peer closed connection" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_INVALID_CURSOR:
      FD_LOG_WARNING(( "disconnected: invalid cursor" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_AUTH_FAILED:
      FD_LOG_WARNING(( "disconnected: authentication failed" ));
      client->metrics.transport_fail_cnt++;
      break;
    default:
      FD_LOG_WARNING(( "disconnected: unknown reason %d", reason ));
      client->metrics.transport_fail_cnt++;
      break;
  }

  if( FD_LIKELY( _backoff ) ) backoff( client );
}

void
fd_event_client_set_identity( fd_event_client_t * client,
                              uchar const *       identity_pubkey ) {
  fd_memcpy( client->identity_pubkey, identity_pubkey, 32UL );
  disconnect( client, DISCONNECT_REASON_IDENTITY_CHANGED, 0, 0 );
}

static void
reconnect( fd_event_client_t * client,
           int *               charge_busy ) {
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_DISCONNECTED );

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now<client->disconnected.reconnect_deadline ) ) return;

  *charge_busy = 1;

  FD_LOG_INFO(( "connecting to event server http://%.*s:%u", (int)client->server_fqdn_len, client->server_fqdn, client->server_tcp_port ));

  /* FIXME IPv6 support */
  fd_addrinfo_t hints = {0};
  hints.ai_family = AF_INET;
  fd_addrinfo_t * res = NULL;
  uchar scratch[ 4096 ];
  void * pscratch = scratch;
  int err = fd_getaddrinfo( client->server_fqdn, &hints, &res, &pscratch, sizeof(scratch) );
  if( FD_UNLIKELY( err ) ) {
    disconnect( client, DISCONNECT_REASON_DNS_RESOLVE_FAILED, err, 1 );
    return;
  }

  uint const ip4_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  client->server_ip4_addr = ip4_addr;

  client->sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==client->sockfd ) ) FD_LOG_ERR(( "socket() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr;
  fd_memset( &addr, 0, sizeof( addr ) );
  addr.sin_family = AF_INET;
  addr.sin_port   = fd_ushort_bswap( client->server_tcp_port );
  addr.sin_addr.s_addr = ip4_addr;

  int tcp_nodelay = 1;
  if( FD_UNLIKELY( -1==setsockopt( client->sockfd, SOL_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(int) ) ) ) FD_LOG_ERR(( "setsockopt failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==setsockopt( client->sockfd, SOL_SOCKET, SO_SNDBUF, &client->so_sndbuf, sizeof(int) ) ) ) FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_SNDBUF,%i) failed (%i-%s)", client->so_sndbuf, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( -1==connect( client->sockfd, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) ) && errno!=EINPROGRESS ) ) {
    disconnect( client, DISCONNECT_REASON_CONNECT_FAILED, errno, 1 );
    return;
  }

  fd_grpc_client_reset( client->grpc_client );

  client->state = FD_EVENT_CLIENT_STATE_CONNECTING;
  client->connecting.connect_deadline = now+(long)1L*(long)1e9; /* 1 second to connect */
}

static void
fd_event_client_grpc_conn_established( void * app_ctx ) {
  fd_event_client_t * client = app_ctx;

  fd_pb_encoder_t auth_req[1];
  uchar buffer[ 256UL ];
  fd_pb_encoder_init( auth_req, buffer, sizeof(buffer) );

  fd_pb_push_bytes( auth_req, 1U, client->identity_pubkey, 32UL );
  fd_pb_push_string( auth_req, 2U, client->client_version, strlen( client->client_version ) );
  fd_pb_push_bytes( auth_req, 3U, client->genesis_hash, 32UL );
  fd_pb_push_uint64( auth_req, 4U, client->shred_version );
  fd_pb_push_uint64( auth_req, 5U, client->instance_id );
  fd_pb_push_uint64( auth_req, 6U, client->machine_id );
  fd_pb_push_uint64( auth_req, 7U, client->boot_id );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start1(
      client->grpc_client,
      "/events.v1.EventService/Authenticate", strlen("/events.v1.EventService/Authenticate"),
      FD_EVENT_CLIENT_REQ_CTX_AUTHENTICATE,
      buffer, fd_pb_encoder_out_sz( auth_req ),
      NULL, 0UL,
      0 /* not streaming */ );

  if( FD_UNLIKELY( !stream ) ) {
    FD_LOG_WARNING(( "Failed to start Authenticate request" ));
    return;
  }

  client->state = FD_EVENT_CLIENT_STATE_AUTHENTICATING;
  FD_LOG_INFO(( "Requesting auth challenge from event server " FD_IP4_ADDR_FMT ":%u (%.*s)",
                FD_IP4_ADDR_FMT_ARGS( client->server_ip4_addr ), client->server_tcp_port,
                (int)client->server_fqdn_len, client->server_fqdn ));
}

static void
fd_event_client_handle_auth_challenge_resp( fd_event_client_t * client,
                                            void const *        protobuf,
                                            ulong               protobuf_sz ) {
  fd_pb_inbuf_t inbuf[1];
  fd_pb_inbuf_init( inbuf, protobuf, protobuf_sz );

  if( FD_UNLIKELY( protobuf_sz==0UL ) ) {
    FD_LOG_WARNING(( "Empty auth challenge response" ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  fd_pb_tlv_t challenge_tlv;
  if( FD_UNLIKELY( !fd_pb_read_tlv( inbuf, &challenge_tlv ) ) ) {
    FD_LOG_WARNING(( "Failed to parse auth challenge response" ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  if( FD_UNLIKELY( challenge_tlv.field_id!=1U || challenge_tlv.wire_type!=FD_PB_WIRE_TYPE_LEN ) ) {
    FD_LOG_WARNING(( "Unexpected field in auth challenge response" ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  ulong challenge_len = challenge_tlv.len;
  if( FD_UNLIKELY( challenge_len!=32UL ) ) {
    FD_LOG_WARNING(( "Invalid challenge size: %lu bytes", challenge_len ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  if( FD_UNLIKELY( fd_pb_inbuf_sz( inbuf )<challenge_len ) ) {
    FD_LOG_WARNING(( "Truncated auth challenge response" ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  uchar signed_challenge[ 64UL ];
  fd_keyguard_client_sign( client->keyguard_client,
                           signed_challenge,
                           inbuf->cur,
                           32UL,
                           FD_KEYGUARD_SIGN_TYPE_FD_EVENTS_AUTH_CONCAT_ED25519 );

  fd_pb_encoder_t confirm_req[1];
  uchar buffer[ 128UL ];
  fd_pb_encoder_init( confirm_req, buffer, sizeof(buffer) );
  fd_pb_push_bytes( confirm_req, 1U, signed_challenge, 64UL );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start1(
      client->grpc_client,
      "/events.v1.EventService/ConfirmAuthChallenge", strlen("/events.v1.EventService/ConfirmAuthChallenge"),
      FD_EVENT_CLIENT_REQ_CTX_CONFIRM_AUTH,
      buffer, fd_pb_encoder_out_sz( confirm_req ),
      NULL, 0UL,
      0 /* not streaming */ );

  if( FD_UNLIKELY( !stream ) ) {
    FD_LOG_WARNING(( "Failed to start ConfirmAuthChallenge request" ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  client->state = FD_EVENT_CLIENT_STATE_CONFIRMING_AUTH;
  FD_LOG_DEBUG(( "Sent signed auth challenge" ));
}

static void
fd_event_client_handle_confirm_auth_resp( fd_event_client_t * client,
                                          void const *        protobuf,
                                          ulong               protobuf_sz ) {
  (void)protobuf;
  (void)protobuf_sz;

  client->event_stream = NULL;
  client->metrics.transport_success_cnt++;
  client->state = FD_EVENT_CLIENT_STATE_CONNECTED;
  client->connected.connected_timestamp = fd_log_wallclock();
  FD_LOG_NOTICE(( "connected to event server " FD_IP4_ADDR_FMT ":%u (%.*s)",
                  FD_IP4_ADDR_FMT_ARGS( client->server_ip4_addr ), client->server_tcp_port,
                  (int)client->server_fqdn_len, client->server_fqdn ));
}

static void
fd_event_client_grpc_conn_dead( void * app_ctx,
                                uint   h2_err,
                                int    closed_by ) {
  fd_event_client_t * client = app_ctx;
  FD_LOG_WARNING(( "Event gRPC connection closed %s (%u-%s)",
                   closed_by ? "by peer" : "due to error",
                   h2_err, fd_h2_strerror( h2_err ) ));
  disconnect( client, DISCONNECT_REASON_PEER_CLOSED, 0, 1 );
}

static void
fd_event_client_grpc_tx_complete( void * app_ctx,
                                  ulong  request_ctx ) {
  (void)app_ctx; (void)request_ctx;
}

void
fd_event_client_grpc_rx_start( void * app_ctx,
                               ulong  request_ctx ) {
  (void)app_ctx; (void)request_ctx;
}

static void
fd_event_client_handle_stream_events_resp( fd_event_client_t * client,
                                           void const *        protobuf,
                                           ulong               protobuf_sz ) {
  fd_pb_inbuf_t inbuf[1];
  fd_pb_inbuf_init( inbuf, protobuf, protobuf_sz );

  ulong nonce_ack;
  if( FD_UNLIKELY( protobuf_sz==0UL ) ) {
    nonce_ack = 0UL;
  } else {
    fd_pb_tlv_t event_id;
    FD_TEST( fd_pb_read_tlv( inbuf, &event_id ) );
    FD_TEST( event_id.field_id==1U ); /* event_id */
    FD_TEST( event_id.wire_type==FD_PB_WIRE_TYPE_VARINT );
    nonce_ack = event_id.varint;
  }

  client->metrics.events_acked++;
  if( FD_UNLIKELY( nonce_ack==ULONG_MAX ) ) return;

  int err = fd_circq_pop_until( client->circq, nonce_ack );
  if( FD_UNLIKELY( -1==err ) ) {
    FD_LOG_WARNING(( "Event gRPC rx msg: invalid cursor ack %lu", nonce_ack ));
    client->defer_disconnect = DISCONNECT_REASON_INVALID_CURSOR;
  }
}

void
fd_event_client_grpc_rx_msg( void *       app_ctx,
                             void const * protobuf,
                             ulong        protobuf_sz,
                             ulong        request_ctx ) {
  fd_event_client_t * client = app_ctx;

  switch( request_ctx ) {
    case FD_EVENT_CLIENT_REQ_CTX_AUTHENTICATE:
      fd_event_client_handle_auth_challenge_resp( client, protobuf, protobuf_sz );
      break;
    case FD_EVENT_CLIENT_REQ_CTX_CONFIRM_AUTH:
      fd_event_client_handle_confirm_auth_resp( client, protobuf, protobuf_sz );
      break;
    case FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS:
      fd_event_client_handle_stream_events_resp( client, protobuf, protobuf_sz );
      break;
    default:
      FD_LOG_WARNING(( "Unknown request_ctx: %lu", request_ctx ));
      break;
  }
}

void
fd_event_client_grpc_rx_end( void *                app_ctx,
                             ulong                 request_ctx,
                             fd_grpc_resp_hdrs_t * resp ) {
  fd_event_client_t * client = app_ctx;

  if( FD_UNLIKELY( resp->h2_status!=200 ) ) {
    FD_LOG_WARNING(( "Event gRPC request failed (HTTP status %u)", resp->h2_status ));
    client->defer_disconnect = DISCONNECT_REASON_TRANSPORT_FAILED;
    return;
  }

  resp->grpc_msg_len = (uint)fd_url_unescape( resp->grpc_msg, resp->grpc_msg_len );
  if( !resp->grpc_msg_len ) {
    fd_memcpy( resp->grpc_msg, "unknown error", 13 );
    resp->grpc_msg_len = 13;
  }

  if( FD_UNLIKELY( resp->grpc_status!=FD_GRPC_STATUS_OK ) ) {
    switch( request_ctx ) {
    case FD_EVENT_CLIENT_REQ_CTX_AUTHENTICATE:
    case FD_EVENT_CLIENT_REQ_CTX_CONFIRM_AUTH:
      FD_LOG_WARNING(( "Event authentication failed (gRPC status %u-%s): %.*s",
                       resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ),
                       (int)resp->grpc_msg_len, resp->grpc_msg ));
      client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
      return;
    case FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS:
      FD_LOG_WARNING(( "Event stream failed (gRPC status %u-%s): %.*s",
                       resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ),
                       (int)resp->grpc_msg_len, resp->grpc_msg ));
      client->defer_disconnect = DISCONNECT_REASON_PEER_CLOSED;
      return;
    default:
      FD_LOG_WARNING(( "Event gRPC request failed (gRPC status %u-%s): %.*s",
                       resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ),
                       (int)resp->grpc_msg_len, resp->grpc_msg ));
      client->defer_disconnect = DISCONNECT_REASON_TRANSPORT_FAILED;
      return;
    }
  }

  if( request_ctx==FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS ) {
    FD_LOG_INFO(( "Event gRPC stream ended gracefully" ));
    client->defer_disconnect = DISCONNECT_REASON_PEER_CLOSED;
  }
}

void
fd_event_client_grpc_rx_timeout( void * app_ctx,
                                 ulong  request_ctx,
                                 int    deadline_kind ) {
  (void)app_ctx; (void)request_ctx; (void)deadline_kind;
  FD_LOG_WARNING(( "Event gRPC rx timeout" ));
}

static void
fd_event_client_grpc_ping_ack( void * app_ctx ) {
  (void)app_ctx;
  FD_LOG_WARNING(( "Event gRPC ping ack" ));
}

static void
tx( fd_event_client_t * client,
    int *               charge_busy ) {
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_CONNECTED );

  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client->grpc_client ) ) ) return;
  if( FD_UNLIKELY( client->event_stream && client->grpc_client->request_stream != NULL && client->grpc_client->request_stream!=client->event_stream ) ) return;

  ulong msg_sz;
  uchar const * msg = fd_circq_cursor_advance( client->circq, &msg_sz );
  if( FD_LIKELY( !msg ) ) return;

  if( FD_UNLIKELY( !client->event_stream ) ) {
    client->event_stream = fd_grpc_client_request_start1(
        client->grpc_client,
        "/events.v1.EventService/StreamEvents", strlen("/events.v1.EventService/StreamEvents"),
        FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS,
        msg, msg_sz,
        NULL, 0UL,
        1 /* streaming */ );
    if( FD_UNLIKELY( !client->event_stream ) ) return; /* Only reason for failure is too big message, so just skip it */
  } else {
    int result = fd_grpc_client_stream_send_msg1( client->grpc_client, client->event_stream, msg, msg_sz );
    if( FD_UNLIKELY( !result ) ) return; /* Only reason for failure is too big message, so just skip it */
  }

  client->metrics.events_sent++;
  *charge_busy = 1;
}

void
fd_event_client_poll( fd_event_client_t * client,
                      int *               charge_busy ) {
  if( FD_UNLIKELY( !client->has_genesis_hash || !client->has_shred_version ) ) return;

  long now = fd_log_wallclock();

  if( FD_UNLIKELY( client->state==FD_EVENT_CLIENT_STATE_DISCONNECTED ) ) reconnect( client, charge_busy );
  if( FD_UNLIKELY( client->state==FD_EVENT_CLIENT_STATE_CONNECTING ) ) {
    if( FD_UNLIKELY( now>client->connecting.connect_deadline ) ) {
      disconnect( client, DISCONNECT_REASON_TIMEOUT, 0, 1 );
      return;
    }
  }
  if( FD_LIKELY( client->state!=FD_EVENT_CLIENT_STATE_DISCONNECTED ) ) {
    if( FD_UNLIKELY( -1==fd_grpc_client_rxtx_socket( client->grpc_client, client->sockfd, charge_busy ) ) ) {
      disconnect( client, DISCONNECT_REASON_TRANSPORT_FAILED, errno, 1 );
      return;
    }
  }

  if( FD_UNLIKELY( client->defer_disconnect!=INT_MAX ) ) {
    int reason = client->defer_disconnect;
    client->defer_disconnect = INT_MAX;
    disconnect( client, reason, 0, 1 );
    return;
  }

  if( FD_LIKELY( client->state==FD_EVENT_CLIENT_STATE_CONNECTED ) ) {
    if( FD_UNLIKELY( client->consecutive_failure_count && (now-client->connected.connected_timestamp>10L*(long)1e9 ) ) ) client->consecutive_failure_count = 0UL;
    tx( client, charge_busy );
  }
}

fd_grpc_client_callbacks_t fd_event_client_grpc_callbacks = {
  .conn_established = fd_event_client_grpc_conn_established,
  .conn_dead        = fd_event_client_grpc_conn_dead,
  .tx_complete      = fd_event_client_grpc_tx_complete,
  .rx_start         = fd_event_client_grpc_rx_start,
  .rx_msg           = fd_event_client_grpc_rx_msg,
  .rx_end           = fd_event_client_grpc_rx_end,
  .rx_timeout       = fd_event_client_grpc_rx_timeout,
  .ping_ack         = fd_event_client_grpc_ping_ack,
};
