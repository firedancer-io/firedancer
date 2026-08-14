#define _GNU_SOURCE
#include "fd_event_client.h"

#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/http/fd_url.h"
#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../waltz/grpc/fd_grpc_client_private.h"
#include "../../ballet/pb/fd_pb_tokenize.h"
#include "../../ballet/pb/fd_pb_encode.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../tango/tempo/fd_tempo.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/log/fd_log.h"
#include "../keyguard/fd_keyguard.h"

#if FD_HAS_OPENSSL
#include "../../waltz/openssl/fd_openssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

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
#define DISCONNECT_REASON_INVALID_PROTOBUF   (8)

#define FD_EVENT_CLIENT_REQ_CTX_AUTHENTICATE  (1UL)
#define FD_EVENT_CLIENT_REQ_CTX_CONFIRM_AUTH  (2UL)
#define FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS (3UL)

#define FD_EVENT_CLIENT_HEARTBEAT_NANOS (15L*(long)1e9)

#define FD_EVENT_CLIENT_TOKEN_SZ (217UL)

struct fd_event_client {
  fd_grpc_client_t * grpc_client;
  fd_grpc_client_metrics_t grpc_metrics[1];
  fd_grpc_h2_stream_t * event_stream;

  char client_version[ 10UL ];
  char commit_hash[ 41UL ];
  char action[ 16UL ];
  uchar identity_pubkey[ 32UL ];

  int       has_genesis_hash;
  fd_hash_t genesis_hash[1];

  int connect_fail_logged;

  ushort has_shred_version;
  ushort shred_version;

  ulong event_id;

  ulong instance_id;
  ulong boot_id;
  ulong machine_id;

  int defer_disconnect;
  ulong consecutive_failure_count;

  long last_stream_send_ticks;
  long heartbeat_ticks;

  int auth_send_pending;

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

  int    use_tls;
#if FD_HAS_OPENSSL
  SSL_CTX * ssl_ctx;
  SSL     * ssl;
#endif

  /* wallclock deadline for auth handshake, LONG_MAX if not
     authenticating. */
  long auth_deadline;

  char   server_fqdn[ 256 ]; /* cstr */
  ulong  server_fqdn_len;
  uint   server_ip4_addr;
  ushort server_tcp_port;

  fd_rng_t * rng;
  fd_circq_t * circq;
  fd_keyguard_client_t * keyguard_client;

  /* Stateless-auth bearer value: "hex(challenge_token).hex(signature)",
     built from the challenge token returned by Authenticate and our
     ed25519 signature over it.  Presented as the `authorization: Bearer
     <...>` header on the StreamEvents request. */
  char  auth_bearer[ 2UL*FD_EVENT_CLIENT_TOKEN_SZ + 1UL + 2UL*64UL + 1UL ];
  ulong auth_bearer_len;

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

void *
fd_event_client_new( void *                 shmem,
                     fd_keyguard_client_t * keyguard_client,
                     fd_rng_t *             rng,
                     fd_circq_t *           circq,
                     int                    so_sndbuf,
                     char const *           _url,
                     uchar const *          identity_pubkey,
                     char const *           client_version,
                     char const *           commit_hash,
                     char const *           action,
                     ulong                  instance_id,
                     ulong                  boot_id,
                     ulong                  machine_id,
                     ulong                  buf_max,
                     int                    use_tls,
                     void *                 ssl_ctx ) {
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
  _Bool _is_ssl = 0;
  if( FD_UNLIKELY( fd_url_parse_endpoint( url,
                                          _url,
                                          strlen( _url ),
                                          &client->server_tcp_port,
                                          &_is_ssl,
                                          "[tiles.event.url]" ) ) ) {
    FD_LOG_ERR(( "Could not parse [tiles.event.url]" ));
  }
  if( FD_UNLIKELY( url->host_len > 255 ) ) {
    FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  }
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( client->server_fqdn ), url->host, url->host_len ) );
  client->server_fqdn_len = url->host_len;

  fd_memcpy( client->identity_pubkey, identity_pubkey, 32UL );
  fd_cstr_ncpy( client->client_version, client_version, sizeof( client->client_version ) );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( client->commit_hash ), commit_hash, fd_ulong_min( strlen( commit_hash ), sizeof( client->commit_hash )-1UL ) ) );
  fd_cstr_ncpy( client->action, action, sizeof( client->action ) );

  client->event_id = 0UL;

  client->instance_id = instance_id;
  client->boot_id     = boot_id;
  client->machine_id  = machine_id;

  client->has_genesis_hash = 0;
  client->has_shred_version = 0;
  client->connect_fail_logged = 0;

  client->so_sndbuf = so_sndbuf;
  client->sockfd = -1;
  client->use_tls = use_tls;
#if FD_HAS_OPENSSL
  client->ssl_ctx = (SSL_CTX *)ssl_ctx;
  client->ssl = NULL;
#else
  (void)ssl_ctx;
  if( FD_UNLIKELY( use_tls ) ) {
    FD_LOG_ERR(( "TLS requested for event service but this build does not include OpenSSL. "
                 "To install OpenSSL, re-run ./deps.sh and do a clean rebuild." ));
  }
#endif
  client->auth_deadline = LONG_MAX;
  client->auth_send_pending = 0;
  client->state = FD_EVENT_CLIENT_STATE_DISCONNECTED;
  client->disconnected.reconnect_deadline = 0L;

  client->defer_disconnect = INT_MAX;
  client->consecutive_failure_count = 7UL; /* Start high, so if server is down we don't keep retrying on boot */
  client->last_stream_send_ticks = 0L;
  client->heartbeat_ticks = (long)(fd_tempo_tick_per_ns( NULL )*(double)FD_EVENT_CLIENT_HEARTBEAT_NANOS);

  client->circq = circq;
  client->rng = rng;
  client->keyguard_client = keyguard_client;

  extern fd_grpc_client_callbacks_t fd_event_client_grpc_callbacks;
  client->grpc_client = fd_grpc_client_new( grpc_client_mem, &fd_event_client_grpc_callbacks, client->grpc_metrics, client, buf_max, fd_rng_ulong( rng ) );
  FD_TEST( client->grpc_client );

  memset( &client->metrics, 0, sizeof(client->metrics) );
  memset( client->grpc_metrics, 0, sizeof(fd_grpc_client_metrics_t) );

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
fd_event_client_init_genesis( fd_event_client_t *       client,
                              fd_genesis_meta_t const * meta ) {
  *client->genesis_hash = meta->genesis_hash;
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
  if( FD_UNLIKELY( client->consecutive_failure_count < 8UL ) ) client->consecutive_failure_count++;
}

static void
disconnect( fd_event_client_t * client,
            int                 reason,
            int                 err,
            int                 _backoff ) {
#if FD_HAS_OPENSSL
  if( FD_UNLIKELY( client->ssl ) ) {
    SSL_free( client->ssl );
    client->ssl = NULL;
  }
#endif
  if( FD_LIKELY( -1!=client->sockfd ) ) {
    if( FD_UNLIKELY( -1==close( client->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    client->sockfd = -1;
    client->state = FD_EVENT_CLIENT_STATE_DISCONNECTED;
    fd_circq_reset_cursor( client->circq );
  }

  client->event_stream = NULL;
  client->auth_deadline = LONG_MAX;
  client->auth_send_pending = 0;

  client->auth_bearer[ 0 ] = '\0';
  client->auth_bearer_len  = 0UL;

  switch( reason ) {
    case DISCONNECT_REASON_IDENTITY_CHANGED:
      FD_LOG_INFO(( "disconnected: identity changed" ));
      break;
    case DISCONNECT_REASON_CONNECT_FAILED:
      if( FD_UNLIKELY( !client->connect_fail_logged ) ) FD_LOG_WARNING(( "connecting to telemetry server " FD_IP4_ADDR_FMT ":%u failed %s(%i-%s)%s", FD_IP4_ADDR_FMT_ARGS( client->server_ip4_addr ), client->server_tcp_port, fd_log_style_dim(), errno, fd_io_strerror( errno ), fd_log_style_normal() ));
      else                                              FD_LOG_INFO((    "connecting to telemetry server " FD_IP4_ADDR_FMT ":%u failed (%i-%s)", FD_IP4_ADDR_FMT_ARGS( client->server_ip4_addr ), client->server_tcp_port, errno, fd_io_strerror( errno ) ));
      client->connect_fail_logged = 1;
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_DNS_RESOLVE_FAILED:
      if( FD_UNLIKELY( !client->connect_fail_logged ) ) FD_LOG_WARNING(( "failed to resolve telemetry server host %.*s %s(%d-%s)%s", (int)client->server_fqdn_len, client->server_fqdn, fd_log_style_dim(), err, fd_gai_strerror( err ), fd_log_style_normal() ));
      else                                              FD_LOG_INFO((    "failed to resolve telemetry server host %.*s (%d-%s)", (int)client->server_fqdn_len, client->server_fqdn, err, fd_gai_strerror( err ) ));
      client->connect_fail_logged = 1;
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_TIMEOUT:
      FD_LOG_INFO(( "connection failed: timeout" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_TRANSPORT_FAILED:
      FD_LOG_WARNING(( "disconnected from telemetry server: transport failed %s(%d-%s)%s", fd_log_style_dim(), err, fd_io_strerror( err ), fd_log_style_normal() ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_PEER_CLOSED:
      FD_LOG_WARNING(( "disconnected from telemetry server: peer closed connection" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_INVALID_CURSOR:
      FD_LOG_WARNING(( "disconnected from telemetry server: invalid cursor" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_AUTH_FAILED:
      FD_LOG_WARNING(( "disconnected from telemetry server: authentication failed" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_INVALID_PROTOBUF:
      FD_LOG_WARNING(( "disconnected from telemetry server: invalid protobuf message received" ));
      client->metrics.transport_fail_cnt++;
      break;
    default:
      FD_LOG_WARNING(( "disconnected from telemetry server: unknown reason %d", reason ));
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
  client->metrics.connect_attempt_cnt++;

  FD_LOG_INFO(( "connecting to event server %s://%.*s:%u", client->use_tls ? "https" : "http", (int)client->server_fqdn_len, client->server_fqdn, client->server_tcp_port ));

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

  if( FD_UNLIKELY( !res || !res->ai_addr ) ) {
    disconnect( client, DISCONNECT_REASON_DNS_RESOLVE_FAILED, 0, 1 );
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

# if FD_HAS_OPENSSL
  if( client->use_tls ) {
    BIO * bio = fd_openssl_bio_new_socket( client->sockfd, BIO_NOCLOSE );
    if( FD_UNLIKELY( !bio ) ) {
      FD_LOG_WARNING(( "fd_openssl_bio_new_socket failed" ));
      disconnect( client, DISCONNECT_REASON_CONNECT_FAILED, 0, 1 );
      return;
    }

    SSL * ssl = SSL_new( client->ssl_ctx );
    if( FD_UNLIKELY( !ssl ) ) {
      FD_LOG_WARNING(( "SSL_new failed" ));
      BIO_free( bio );
      disconnect( client, DISCONNECT_REASON_CONNECT_FAILED, 0, 1 );
      return;
    }

    SSL_set_bio( ssl, bio, bio ); /* moves ownership of bio */
    SSL_set_connect_state( ssl );

    /* SNI and hostname verification */
    if( FD_UNLIKELY( !SSL_set_tlsext_host_name( ssl, client->server_fqdn ) ) ) {
      FD_LOG_WARNING(( "SSL_set_tlsext_host_name failed" ));
      SSL_free( ssl );
      disconnect( client, DISCONNECT_REASON_CONNECT_FAILED, 0, 1 );
      return;
    }
    if( FD_UNLIKELY( !SSL_set1_host( ssl, client->server_fqdn ) ) ) {
      FD_LOG_WARNING(( "SSL_set1_host failed" ));
      SSL_free( ssl );
      disconnect( client, DISCONNECT_REASON_CONNECT_FAILED, 0, 1 );
      return;
    }

    client->ssl = ssl;
  }
# endif /* FD_HAS_OPENSSL */

  fd_grpc_client_reset( client->grpc_client );

  client->state = FD_EVENT_CLIENT_STATE_CONNECTING;
  client->connecting.connect_deadline = now+(long)1L*(long)1e9; /* 1 second to connect */
}

static int
fd_event_client_try_send_authenticate( fd_event_client_t * client ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client->grpc_client ) ) ) return 0;
  if( FD_UNLIKELY( fd_grpc_client_request_stream_busy( client->grpc_client ) ) ) return 0;

  fd_pb_encoder_t auth_req[1];
  uchar buffer[ 256UL ];
  fd_pb_encoder_init( auth_req, buffer, sizeof(buffer) );

  fd_pb_push_bytes( auth_req, 1U, client->identity_pubkey, 32UL );
  fd_pb_push_string( auth_req, 2U, client->client_version, strlen( client->client_version ) );
  fd_pb_push_string( auth_req, 3U, client->commit_hash, strlen( client->commit_hash ) );
  fd_pb_push_bytes( auth_req, 4U, client->genesis_hash, 32UL );
  fd_pb_push_uint64( auth_req, 5U, client->shred_version );
  fd_pb_push_uint64( auth_req, 6U, client->instance_id );
  fd_pb_push_uint64( auth_req, 7U, client->machine_id );
  fd_pb_push_uint64( auth_req, 8U, client->boot_id );
  fd_pb_push_string( auth_req, 9U, client->action, strlen( client->action ) );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start1(
      client->grpc_client,
      "/events.v1.EventService/Authenticate", strlen("/events.v1.EventService/Authenticate"),
      FD_EVENT_CLIENT_REQ_CTX_AUTHENTICATE,
      buffer, fd_pb_encoder_out_sz( auth_req ),
      NULL, 0UL,
      0 /* not streaming */ );

  if( FD_UNLIKELY( !stream ) ) return 0;

  long now = fd_log_wallclock();
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_HEADER, now+(long)2e9 );
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_RX_END, now+(long)2e9 );

  client->auth_send_pending = 0;
  FD_LOG_INFO(( "Requesting auth challenge from event server " FD_IP4_ADDR_FMT ":%u (%.*s)",
                FD_IP4_ADDR_FMT_ARGS( client->server_ip4_addr ), client->server_tcp_port,
                (int)client->server_fqdn_len, client->server_fqdn ));
  return 1;
}

static void
fd_event_client_grpc_conn_established( void * app_ctx ) {
  fd_event_client_t * client = app_ctx;

  long now = fd_log_wallclock();
  client->state             = FD_EVENT_CLIENT_STATE_AUTHENTICATING;
  client->auth_deadline     = now + (long)2e9;
  client->auth_send_pending = 1;

  fd_event_client_try_send_authenticate( client );
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
  if( FD_UNLIKELY( challenge_len!=FD_EVENT_CLIENT_TOKEN_SZ ) ) {
    FD_LOG_WARNING(( "Invalid challenge token size: %lu bytes (expected %lu)", challenge_len, FD_EVENT_CLIENT_TOKEN_SZ ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  if( FD_UNLIKELY( fd_pb_inbuf_sz( inbuf )<challenge_len ) ) {
    FD_LOG_WARNING(( "Truncated auth challenge response" ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  uchar challenge_token[ FD_EVENT_CLIENT_TOKEN_SZ ];
  memcpy( challenge_token, inbuf->cur, challenge_len );
  inbuf->cur += challenge_len;

  if( FD_UNLIKELY( fd_pb_inbuf_sz( inbuf ) ) ) {
    FD_LOG_WARNING(( "Trailing data in auth challenge response" ));
    client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
    return;
  }

  uchar sign_request[ 100UL + FD_EVENT_CLIENT_TOKEN_SZ ];
  static char const sign_prefix[ 100 ] =
    "                                "  /* 32 spaces */
    "                                "  /* 32 spaces */
    "Firedancer event challenge-response";
  memcpy( sign_request,     sign_prefix,     sizeof(sign_prefix) );
  memcpy( sign_request+100, challenge_token, challenge_len       );

  uchar signature[ 64UL ];
  fd_keyguard_client_sign( client->keyguard_client,
                           signature,
                           sign_request, 100UL+challenge_len,
                           FD_KEYGUARD_SIGN_TYPE_ED25519 );

  /* Build "hex(challenge_token).hex(signature)" for the bearer token. */
  fd_hex_encode( client->auth_bearer, challenge_token, FD_EVENT_CLIENT_TOKEN_SZ );
  client->auth_bearer[ 2UL*FD_EVENT_CLIENT_TOKEN_SZ ] = '.';
  fd_hex_encode( client->auth_bearer + 2UL*FD_EVENT_CLIENT_TOKEN_SZ+1UL, signature, 64UL );
  client->auth_bearer_len = 2UL*FD_EVENT_CLIENT_TOKEN_SZ + 1UL + 2UL*64UL;
  client->auth_bearer[ client->auth_bearer_len ] = '\0';

  client->event_stream = NULL;
  client->metrics.transport_success_cnt++;
  client->state = FD_EVENT_CLIENT_STATE_CONNECTED;
  client->connected.connected_timestamp = fd_log_wallclock();
  client->connect_fail_logged = 0;
  FD_LOG_NOTICE(( "connected to telemetry server %s%s://%.*s:%u%s",
                  fd_log_style_bold(), client->use_tls ? "https" : "http",
                  (int)client->server_fqdn_len, client->server_fqdn, client->server_tcp_port,
                  fd_log_style_normal() ));
}

static void
fd_event_client_grpc_conn_dead( void * app_ctx,
                                uint   h2_err,
                                int    closed_by ) {
  fd_event_client_t * client = app_ctx;
  FD_LOG_WARNING(( "Event gRPC connection closed %s (%u-%s)",
                   closed_by ? "by peer" : "due to error",
                   h2_err, fd_h2_strerror( h2_err ) ));
  client->defer_disconnect = DISCONNECT_REASON_PEER_CLOSED;
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

  ulong nonce_ack = 0UL;
  if( FD_LIKELY( protobuf_sz ) ) {
    fd_pb_tlv_t event_id;
    if( FD_UNLIKELY( !fd_pb_read_tlv( inbuf, &event_id ) ||
                     event_id.field_id!=1U /* event_id */ ||
                     event_id.wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) {
      FD_LOG_WARNING(( "Event gRPC rx msg: invalid Protobuf" ));
      client->defer_disconnect = DISCONNECT_REASON_INVALID_PROTOBUF;
      return;
    }
    nonce_ack = event_id.varint;

    if( FD_UNLIKELY( fd_pb_inbuf_sz( inbuf ) ) ) {
      FD_LOG_WARNING(( "Event gRPC rx msg: trailing data in StreamEventsResponse" ));
      client->defer_disconnect = DISCONNECT_REASON_INVALID_PROTOBUF;
      return;
    }
  }

  client->metrics.events_acked++;
  if( FD_UNLIKELY( nonce_ack==ULONG_MAX ) ) return;

  client->metrics.last_acked_id = nonce_ack;

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
    case FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS:
      fd_event_client_handle_stream_events_resp( client, protobuf, protobuf_sz );
      break;
    default:
      FD_LOG_WARNING(( "Unknown request_ctx: %lu, disconnecting", request_ctx ));
      client->defer_disconnect = DISCONNECT_REASON_INVALID_PROTOBUF;
      break;
  }
}

void
fd_event_client_grpc_rx_end( void *                app_ctx,
                             ulong                 request_ctx,
                             fd_grpc_resp_hdrs_t * resp ) {
  fd_event_client_t * client = app_ctx;

  if( FD_UNLIKELY( resp->h2_status!=200 ) ) {
    FD_LOG_WARNING(( "telemetry server request failed %s(HTTP status %u)%s", fd_log_style_dim(), resp->h2_status, fd_log_style_normal() ));
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
      FD_LOG_WARNING(( "telemetry server authentication failed: %.*s %s(%u-%s)%s",
                       (int)resp->grpc_msg_len, resp->grpc_msg,
                       fd_log_style_dim(), resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ), fd_log_style_normal() ));
      client->defer_disconnect = DISCONNECT_REASON_AUTH_FAILED;
      return;
    case FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS:
      FD_LOG_WARNING(( "telemetry server event stream failed: %.*s %s(%u-%s)%s",
                       (int)resp->grpc_msg_len, resp->grpc_msg,
                       fd_log_style_dim(), resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ), fd_log_style_normal() ));
      client->defer_disconnect = DISCONNECT_REASON_PEER_CLOSED;
      return;
    default:
      FD_LOG_WARNING(( "telemetry server request failed: %.*s %s(%u-%s)%s",
                       (int)resp->grpc_msg_len, resp->grpc_msg,
                       fd_log_style_dim(), resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ), fd_log_style_normal() ));
      client->defer_disconnect = DISCONNECT_REASON_TRANSPORT_FAILED;
      return;
    }
  }

  if( request_ctx==FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS ) {
    FD_LOG_INFO(( "telemetry server event stream ended gracefully" ));
    client->defer_disconnect = DISCONNECT_REASON_PEER_CLOSED;
  }
}

void
fd_event_client_grpc_rx_timeout( void * app_ctx,
                                 ulong  request_ctx FD_PARAM_UNUSED,
                                 int    deadline_kind FD_PARAM_UNUSED ) {
  FD_LOG_WARNING(( "Event gRPC rx timeout" ));
  fd_event_client_t * client = (fd_event_client_t *)app_ctx;
  client->defer_disconnect = DISCONNECT_REASON_TRANSPORT_FAILED;
  client->event_stream     = NULL;
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

  if( FD_UNLIKELY( !client->event_stream ) ) {
    client->event_stream = fd_grpc_client_request_start1(
        client->grpc_client,
        "/events.v1.EventService/StreamEvents", strlen("/events.v1.EventService/StreamEvents"),
        FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS,
        NULL, 0UL, /* headers only; first message sent later */
        client->auth_bearer, client->auth_bearer_len,
        1 /* streaming */ );
    if( FD_UNLIKELY( !client->event_stream ) ) return; /* transient; retry next poll */
    fd_grpc_client_deadline_set( client->event_stream, FD_GRPC_DEADLINE_HEADER, fd_log_wallclock()+(long)10e9 /* 10s */ );
    client->last_stream_send_ticks = fd_tickcount();
    *charge_busy = 1;
    return;
  }

  ulong msg_sz;
  uchar const * msg = fd_circq_cursor_advance( client->circq, &msg_sz );
  if( FD_LIKELY( !msg ) ) {
    /* Nothing to send.  If the stream has been quiet long enough that an
       intermediary proxy might kill it, send a zero-length
       StreamEventsRequest to heartbeat. */
    long now_ticks = fd_tickcount();
    if( FD_UNLIKELY( now_ticks-client->last_stream_send_ticks>client->heartbeat_ticks ) ) {
      if( FD_LIKELY( fd_grpc_client_stream_send_msg1( client->grpc_client, client->event_stream, (uchar const *)"", 0UL ) ) ) {
        client->last_stream_send_ticks = now_ticks;
        *charge_busy = 1;
      }
    }
    return;
  }

  int result = fd_grpc_client_stream_send_msg1( client->grpc_client, client->event_stream, msg, msg_sz );
  if( FD_UNLIKELY( !result ) ) return; /* Only reason for failure is too big message, so just skip it */

  client->metrics.events_sent++;
  client->last_stream_send_ticks = fd_tickcount();
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
  /* Check auth handshake timeout */
  if( FD_UNLIKELY( client->state==FD_EVENT_CLIENT_STATE_AUTHENTICATING && now>client->auth_deadline ) ) {
    FD_LOG_WARNING(( "auth handshake timed out" ));
    client->metrics.handshake_timeout_cnt++;
    disconnect( client, DISCONNECT_REASON_TIMEOUT, 0, 1 );
    return;
  }
  if( FD_LIKELY( client->state!=FD_EVENT_CLIENT_STATE_DISCONNECTED ) ) {
    int rxtx_err;
#   if FD_HAS_OPENSSL
    if( client->use_tls )
      rxtx_err = fd_grpc_client_rxtx_ossl( client->grpc_client, client->ssl, charge_busy );
    else
#   endif
      rxtx_err = fd_grpc_client_rxtx_socket( client->grpc_client, client->sockfd, charge_busy );
    if( FD_UNLIKELY( -1==rxtx_err ) ) {
      disconnect( client, DISCONNECT_REASON_TRANSPORT_FAILED, errno, 1 );
      return;
    }
  }

  if( FD_UNLIKELY( client->defer_disconnect!=INT_MAX ) ) {
    int reason = client->defer_disconnect;
    client->defer_disconnect = INT_MAX;
    if( reason==DISCONNECT_REASON_AUTH_FAILED ) client->metrics.auth_fail_cnt++;
    if( reason==DISCONNECT_REASON_INVALID_PROTOBUF ) client->metrics.invalid_msg_cnt++;
    disconnect( client, reason, 0, 1 );
    return;
  }

  if( FD_UNLIKELY( client->state==FD_EVENT_CLIENT_STATE_AUTHENTICATING && client->auth_send_pending ) ) {
    fd_event_client_try_send_authenticate( client );
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
