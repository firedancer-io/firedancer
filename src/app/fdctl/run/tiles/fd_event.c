#define _DEFAULT_SOURCE
#include "../../../../disco/tiles.h"

#include <sys/socket.h> /* SOCK_CLOEXEC, SOCK_NONBLOCK needed for seccomp filter */
#include "generated/event_seccomp.h"

#include "../../../../disco/keyguard/fd_keyguard.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/keyguard/fd_keyguard_client.h"
#include "../../../../disco/events/fd_circq.h"

#include "../../../../disco/metrics/generated/fd_event.h"
#include "../../../../disco/metrics/generated/fd_event_metrics.h"
#include "../../../../disco/metrics/generated/fd_metric_event_snap.h"

#include "../../../../ballet/base64/fd_base64.h"
#include "../../../../ballet/http/picohttpparser.h"

#include "../../version.h"

#include "../../../../flamenco/leaders/fd_leaders.h"

#include <sys/types.h>
#include <sys/random.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <poll.h>

#define FD_EVENT_CLIENT_STATE_DISCONNECTED (0UL)
#define FD_EVENT_CLIENT_STATE_CONNECTING   (1UL)
#define FD_EVENT_CLIENT_STATE_CONNECTED    (2UL)
#define FD_EVENT_CLIENT_STATE_WRITING      (3UL)
#define FD_EVENT_CLIENT_STATE_READING      (4UL)

typedef struct {
  char          version_string[ 16UL ];
  uchar const * identity_key;
  char          identity_key_base58[ FD_BASE58_ENCODED_32_SZ+1 ];

  ulong boot_id;
  ulong machine_id;
  ulong instance_id;

  char const * version;
  uchar cluster;
  uchar client;
  uchar os;
  
  char host[ 512 ];
  uint   endpoint_ip;
  ushort endpoint_port;

  long   metrics_snap_deadline_ns;

  ulong  metrics_snap_footprint;

  fd_circq_t * circq;

  fd_rng_t rng[1];
  fd_keyguard_client_t keyguard_client[1];

  int socket_fd;
  ulong state;
  long reconnect_deadline_ns;

  int has_request_body;
  ulong request_body_len;
  char request_body[ 1UL<<24UL ];
  ulong request_bytes_written;

  uchar response_data[ 8192UL ];
  ulong response_bytes_read;

  fd_topo_t * topo;

  struct {
    ulong sent_cnt;
    ulong sent_bytes;
    ulong recv_bytes;
    ulong ok_status;
    ulong client_err_status;
    ulong server_err_status;
  } metrics;
} fd_event_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_ctx_t ), sizeof( fd_event_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_circq_t ), fd_circq_footprint( 1UL<<30UL ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

struct fd_event_snap {
  long timestamp;
  ulong event_type;
  fd_event_t event;
};

typedef struct fd_event_snap fd_event_snap_t;

static void
snap_metrics( fd_event_ctx_t * ctx ) {
  uchar * buffer = fd_circq_push_back( ctx->circq, alignof( fd_event_snap_t ), ctx->metrics_snap_footprint );
  if( FD_UNLIKELY( !buffer ) ) return;

  fd_event_snap_t * event = (fd_event_snap_t *)buffer;
  event->timestamp      = fd_log_wallclock();
  event->event_type     = FD_EVENT_METRICS_SAMPLE;
  event->event.metrics_sample.slot   = 0UL;
  event->event.metrics_sample.reason = FD_EVENT_METRICS_SAMPLE_REASON_PERIODIC;

  fd_event_metrics_layout( ctx->topo, (uchar*)&event->event.metrics_sample );
  fd_metric_event_snap( ctx->topo, &event->event.metrics_sample );
}

/* These are the expected network errors which just mean the connection
   should be closed.  Any errors from a connect(2), read(2), or send(2)
   that are not expected here will be considered fatal and terminate the
   server. */

static inline int
is_expected_network_error( int err ) {
  return
    err==ENETDOWN ||
    err==EPROTO ||
    err==ENOPROTOOPT ||
    err==EHOSTDOWN ||
    err==ENONET ||
    err==EHOSTUNREACH ||
    err==EOPNOTSUPP ||
    err==ECONNREFUSED ||
    err==EADDRNOTAVAIL ||
    err==ENETUNREACH ||
    err==ETIMEDOUT ||
    err==ENETRESET ||
    err==ECONNABORTED ||
    err==ECONNRESET ||
    err==EPIPE;
}

#define FD_EVENT_DISCONNECT_REASON_CONNECT_NETWORK (0UL)
#define FD_EVENT_DISCONNECT_REASON_CONNECT_POLL    (1UL)
#define FD_EVENT_DISCONNECT_REASON_POLL            (2UL)
#define FD_EVENT_DISCONNECT_REASON_SEND_NETWORK    (3UL)
#define FD_EVENT_DISCONNECT_REASON_RECV_NETWORK    (4UL)
#define FD_EVENT_DISCONNECT_REASON_TOO_LARGE       (5UL)
#define FD_EVENT_DISCONNECT_REASON_CORRUPT         (6UL)
#define FD_EVENT_DISCONNECT_REASON_SERVER_5XX      (7UL)

static inline char const *
disconnect_reason_str( ulong reason ) {
  switch( reason ) {
    case FD_EVENT_DISCONNECT_REASON_CONNECT_NETWORK: return "CONNECT_FAILED";
    case FD_EVENT_DISCONNECT_REASON_CONNECT_POLL:    return "CONNECT_POLL_FAILED";
    case FD_EVENT_DISCONNECT_REASON_POLL:            return "POLL_FAILED";
    case FD_EVENT_DISCONNECT_REASON_SEND_NETWORK:    return "SEND_FAILED";
    case FD_EVENT_DISCONNECT_REASON_RECV_NETWORK:    return "RECV_FAILED";
    case FD_EVENT_DISCONNECT_REASON_TOO_LARGE:       return "RESPONSE_TOO_LARGE";
    case FD_EVENT_DISCONNECT_REASON_CORRUPT:         return "RESPONSE_CORRUPT";
    case FD_EVENT_DISCONNECT_REASON_SERVER_5XX:      return "SERVER_5XX";
    default: return "UNKNOWN";
  }
}

#define FD_EVENT_DISCONNECT_STAGE_CONNECT (0UL)

static inline void
disconnect( fd_event_ctx_t * ctx,
            ulong            reason,
            int              err_no ) {
  if( FD_LIKELY( ctx->socket_fd>=0 ) ) {
    if( FD_UNLIKELY( close( ctx->socket_fd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    ctx->socket_fd = -1;
  }
  ctx->state = FD_EVENT_CLIENT_STATE_DISCONNECTED;
  ctx->reconnect_deadline_ns = fd_log_wallclock() + 60L*1000L*1000L*1000L + (long)fd_rng_ulong_roll( ctx->rng, 60L*1000L*1000L*1000L );
  if( FD_LIKELY( err_no ) ) {
    FD_LOG_WARNING(( "Disconnected from %s:%u (%s %d-%s). Retrying in %lds", ctx->host, ctx->endpoint_port, disconnect_reason_str( reason ), err_no, fd_io_strerror( err_no ), (ctx->reconnect_deadline_ns-fd_log_wallclock())/1000000000L ));
  } else {
    FD_LOG_WARNING(( "Disconnected from %s:%u (%s). Retrying in %lds", ctx->host, ctx->endpoint_port, disconnect_reason_str( reason ), (ctx->reconnect_deadline_ns-fd_log_wallclock())/1000000000L ));
  }
}

static inline void
check_connection( fd_event_ctx_t * ctx,
                  int *            charge_busy ) {
  if( FD_UNLIKELY( ctx->state==FD_EVENT_CLIENT_STATE_DISCONNECTED ) ) {
    long now = fd_log_wallclock();
    if( FD_LIKELY( now<ctx->reconnect_deadline_ns ) ) return;

    *charge_busy = 1;

    ctx->socket_fd = socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );
    if( FD_UNLIKELY( ctx->socket_fd<0 ) ) FD_LOG_ERR(( "socket() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

    struct sockaddr_in addr;
    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;

    addr.sin_port = fd_ushort_bswap( ctx->endpoint_port );
    addr.sin_addr.s_addr = ctx->endpoint_ip;

    if( FD_UNLIKELY( -1==connect( ctx->socket_fd, fd_type_pun( &addr ), sizeof( addr ) ) ) ) {
      if( FD_UNLIKELY( is_expected_network_error( errno ) ) ) {
        disconnect( ctx, FD_EVENT_DISCONNECT_REASON_CONNECT_NETWORK, errno );
        return;
      }
      else if( FD_LIKELY( errno==EINPROGRESS ) ) {
        ctx->state = FD_EVENT_CLIENT_STATE_CONNECTING;
        return;
      }
      else FD_LOG_ERR(( "connect() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    } else {
      if( FD_UNLIKELY( ctx->has_request_body ) ) {
        ctx->request_bytes_written = 0UL;
        ctx->response_bytes_read = 0UL;
        ctx->state = FD_EVENT_CLIENT_STATE_WRITING;
      } else {
        ctx->state = FD_EVENT_CLIENT_STATE_CONNECTED;
        ctx->response_bytes_read = 0UL;
      }
    }
  }

  if( FD_UNLIKELY( ctx->state==FD_EVENT_CLIENT_STATE_CONNECTING ) ) {
    *charge_busy = 1;

    struct pollfd pfd = { .fd = ctx->socket_fd, .events = POLLOUT };
    if( FD_UNLIKELY( -1==poll( &pfd, 1, 0 ) ) ) FD_LOG_ERR(( "poll() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

    if( FD_UNLIKELY( pfd.revents & (POLLERR | POLLHUP) ) ) {
      disconnect( ctx, FD_EVENT_DISCONNECT_REASON_CONNECT_POLL, 0 );
      return;
    } else if( FD_UNLIKELY( pfd.revents & POLLOUT ) ) {
      int connect_errno;
      uint connect_errno_len = (uint)sizeof(connect_errno);
      if( FD_UNLIKELY( -1==getsockopt( ctx->socket_fd, SOL_SOCKET, SO_ERROR, &connect_errno, &connect_errno_len ) ) ) FD_LOG_ERR(( "getsockopt() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

      if( FD_UNLIKELY( is_expected_network_error( connect_errno ) ) ) {
        disconnect( ctx, FD_EVENT_DISCONNECT_REASON_CONNECT_POLL, connect_errno );
        return;
      }
      else if( FD_UNLIKELY( connect_errno ) ) FD_LOG_ERR(( "connect() failed (%d-%s)", connect_errno, fd_io_strerror( connect_errno ) ));

      if( FD_UNLIKELY( ctx->has_request_body ) ) {
        ctx->request_bytes_written = 0UL;
        ctx->state = FD_EVENT_CLIENT_STATE_WRITING;
      } else {
        ctx->state = FD_EVENT_CLIENT_STATE_CONNECTED;
        ctx->response_bytes_read = 0UL;
      }
    }
  }
}

static inline void
check_message( fd_event_ctx_t * ctx,
               int *            charge_busy ) {
  if( FD_UNLIKELY( ctx->state!=FD_EVENT_CLIENT_STATE_CONNECTED ) ) return;

  uchar const * event = fd_circq_pop_front( ctx->circq );
  if( FD_UNLIKELY( !event ) ) return;

  *charge_busy = 1;

  fd_event_snap_t * snap = (fd_event_snap_t *)event;

  fd_event_common_t common = {
    .timestamp   = snap->timestamp,
    .cluster     = ctx->cluster,
    .client      = ctx->client,
    .os          = ctx->os,
    .instance_id = ctx->instance_id,
    .machine_id  = ctx->machine_id,
    .boot_id     = ctx->boot_id,
  };

  strncpy( common.identity, ctx->identity_key_base58, 45UL );
  strncpy( common.version, ctx->version_string, 12UL );

  ulong off = 0UL;
  ulong printed;
  int success = fd_cstr_printf_check( ctx->request_body+off, sizeof( ctx->request_body )-off, &printed,
    "POST /insert HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Use-Agent: Firedancer\r\n"
    "Keep-Alive: timeout=60\r\n"
    "Content-Type: application/json\r\n"
    "Authorization: Bearer ", ctx->host );
  if( FD_UNLIKELY( !success ) ) return;
  off += (ulong)printed;

  ulong bearer_off = off;
  success = fd_cstr_printf_check( ctx->request_body+off, sizeof( ctx->request_body )-off, &printed,
    "                                                                                         \r\n"
    "Content-Length: " );
  if( FD_UNLIKELY( !success ) ) return;
  off += (ulong)printed;

  ulong content_length_off = off;
  success = fd_cstr_printf_check( ctx->request_body+off, sizeof( ctx->request_body )-off, &printed, "     \r\n\r\n" );
  if( FD_UNLIKELY( !success ) ) return;
  off += (ulong)printed;

  long post_data_len = fd_event_format( &common, snap->event_type, &snap->event, ctx->metrics_snap_footprint, ctx->request_body+off, sizeof( ctx->request_body )-off );
  if( FD_UNLIKELY( post_data_len<0L ) ) return;

  uchar post_data_hash[ 32 ];
  fd_sha256_hash( ctx->request_body+off, (ulong)post_data_len, post_data_hash );

  uchar post_data_signature[ 64 ];
  fd_keyguard_client_sign( ctx->keyguard_client, post_data_signature, post_data_hash, 32UL, FD_KEYGUARD_SIGN_TYPE_FD_METRICS_REPORT_CONCAT_ED25519 );
  fd_base64_encode( ctx->request_body+bearer_off, post_data_signature, 64UL );

  off += (ulong)post_data_len;

  char len[ 10 ];
  FD_TEST( fd_cstr_printf_check( len, 10UL, &printed, "%lu", (ulong)post_data_len ) );
  memcpy( ctx->request_body+content_length_off, len, printed );

  ctx->request_body_len = off;
  ctx->request_bytes_written = 0UL;
  /* We don't zero response bytes read, because the keep-alive
     connection will want to reuse bytes leftover from the
     previous recv(). */
  /* ctx->response_bytes_read   = 0UL; */
  ctx->state = FD_EVENT_CLIENT_STATE_WRITING;
  ctx->has_request_body = 1;
}

static void
write_request( fd_event_ctx_t * ctx,
               int *            charge_busy ) {
  if( FD_UNLIKELY( ctx->state!=FD_EVENT_CLIENT_STATE_WRITING ) ) return;

  long sent = send( ctx->socket_fd, ctx->request_body+ctx->request_bytes_written, ctx->request_body_len-ctx->request_bytes_written, 0 );
  if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return;
  else if( FD_UNLIKELY( -1==sent ) ) {
    *charge_busy = 1;

    if( FD_UNLIKELY( is_expected_network_error( errno ) ) ) {
      disconnect( ctx, FD_EVENT_DISCONNECT_REASON_SEND_NETWORK, errno );
      return;
    }
    else FD_LOG_ERR(( "send failed (%i-%s)", errno, strerror( errno ) ));
  }

  *charge_busy = 1;
  ctx->request_bytes_written += (ulong)sent;
  ctx->metrics.sent_bytes += (ulong)sent;
  if( FD_UNLIKELY( ctx->request_bytes_written==ctx->request_body_len ) ) {
    ctx->state = FD_EVENT_CLIENT_STATE_READING;
    ctx->metrics.sent_cnt++;
  }
}

static void
read_response( fd_event_ctx_t * ctx,
               int *            charge_busy ) {
  long read = recv( ctx->socket_fd, ctx->response_data+ctx->response_bytes_read, sizeof( ctx->response_data )-ctx->response_bytes_read, 0 );
  if( FD_UNLIKELY( -1==read && errno==EAGAIN ) ) return;
  else if( FD_UNLIKELY( -1==read ) ) {
    *charge_busy = 1;

    if( FD_UNLIKELY( is_expected_network_error( errno ) ) ) {
      disconnect( ctx, FD_EVENT_DISCONNECT_REASON_RECV_NETWORK, errno );
      return;
    }
    else FD_LOG_ERR(( "recv failed (%i-%s)", errno, strerror( errno ) ));
  }

  *charge_busy = 1;

  ctx->metrics.recv_bytes += (ulong)read;
  ctx->response_bytes_read += (ulong)read;
  if( FD_UNLIKELY( ctx->response_bytes_read==sizeof( ctx->response_data ) ) ) {
    disconnect( ctx, FD_EVENT_DISCONNECT_REASON_TOO_LARGE, 0 );
    return;
  }

  int minor_version;
  int status;
  const char * msg;
  ulong msg_len = 0UL;

  struct phr_header headers[ 16 ];
  ulong num_headers = sizeof( headers )/sizeof( headers[0] );
  int result = phr_parse_response( (char*)ctx->response_data, ctx->response_bytes_read, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0UL );
  if( FD_UNLIKELY( -1==result ) ) {
    ctx->has_request_body = 0; /* Discard this metric in case it's causing some issue ... */
    disconnect( ctx, FD_EVENT_DISCONNECT_REASON_CORRUPT, 0 );
    return;
  } else if( FD_LIKELY( -2==result ) ) {
    return;
  }

  memmove( ctx->response_data, ctx->response_data+result, ctx->response_bytes_read-(ulong)result );
  ctx->response_bytes_read -= (ulong)result;

  if( FD_UNLIKELY( status==408 || status==429 || (status/100)==5 ) ) {
    /* Retry the same event again if server had an error, or it
       indicated we should retry by returning TOO_MANY_REQUESTS,
       or it was REQUEST_TIMEOUT. */
    ctx->metrics.server_err_status++;
    disconnect( ctx, FD_EVENT_DISCONNECT_REASON_SERVER_5XX, 0 );
    return;
  }

  /* Otherwise, purge the event. Sometimes 2xx for success, but also can
     be 4xx meaning there */

  ctx->has_request_body = 0;
  ctx->state = FD_EVENT_CLIENT_STATE_CONNECTED;

  /* Don't retry the event for 4xx codes, likely we produced bad JSON
     or something that is not recoverable. */
  if( FD_UNLIKELY( (status/100)==2 ) ) ctx->metrics.ok_status++;
  else                                 ctx->metrics.client_err_status++;
}

static inline void
client_poll( fd_event_ctx_t * ctx,
             int *            charge_busy ) {
  check_connection( ctx, charge_busy );
  check_message( ctx, charge_busy );

  if( FD_UNLIKELY( ctx->state==FD_EVENT_CLIENT_STATE_DISCONNECTED ||
                   ctx->state==FD_EVENT_CLIENT_STATE_CONNECTING ||
                   ctx->state==FD_EVENT_CLIENT_STATE_CONNECTED ) ) return;

  struct pollfd pfd = { .fd = ctx->socket_fd, .events = POLLIN | POLLOUT };
  int nfds = poll( &pfd, 1, 0 );
  if( FD_UNLIKELY( 0==nfds ) ) return;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, strerror( errno ) ));

  if( FD_UNLIKELY( pfd.revents & (POLLERR | POLLHUP) ) ) {
    disconnect( ctx, FD_EVENT_DISCONNECT_REASON_POLL, 0 );
    return;
  }
  if( FD_LIKELY( pfd.revents & POLLOUT ) ) write_request( ctx, charge_busy );
  if( FD_UNLIKELY( ctx->state==FD_EVENT_CLIENT_STATE_DISCONNECTED ) ) return;
  if( FD_LIKELY( pfd.revents & POLLIN ) ) read_response( ctx, charge_busy );
}

static inline void
before_credit( fd_event_ctx_t *    ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  long now = fd_log_wallclock();
  if( FD_LIKELY( now>=ctx->metrics_snap_deadline_ns ) ) {
    *charge_busy = 1;
    ctx->metrics_snap_deadline_ns = now + 5L*1000L*1000L*1000L;

    snap_metrics( ctx );
  }

  client_poll( ctx, charge_busy );
}

static void
domain_to_static_ip( char const * url,
                     uint *       ip_addr,
                     ushort *     port,
                     char *       domain ) {
  const char * protocol_end = strstr( url, "://" );
  if( FD_UNLIKELY( !protocol_end ) ) FD_LOG_ERR(( "invalid [tiles.event.endpoint] `%s`. Must start with `http://`", url ));

  char const * domain_start = protocol_end+3UL;
  char const * domain_end = strchr( domain_start, ':' );
  if( FD_UNLIKELY( !domain_end ) ) {
    domain_end = url + strlen( url );
    *port = 7878;
  } else {
    *port = (ushort)strtoul( domain_end+1, NULL, 10 );
  }

  ulong domain_len = (ulong)(domain_end-domain_start);
  strncpy( domain, domain_start, domain_len );
  domain[ domain_len ] = '\0';

  struct addrinfo hints, *res;
  memset( &hints, 0, sizeof(hints) );
  hints.ai_family = AF_INET;

  int err = getaddrinfo( domain, NULL, &hints, &res );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "getaddrinfo `%s` failed (%d-%s)", domain, err, gai_strerror( err ) ));

  *ip_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  freeaddrinfo(res);
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_event_ctx_t ), sizeof( fd_event_ctx_t ) );

  if( FD_UNLIKELY( strlen( tile->event.endpoint)<7UL || strncmp( "http://", tile->event.endpoint, 7UL ) )) FD_LOG_ERR(( "invalid [tiles.event.endpoint] `%s`. Must start with `http://`", tile->event.endpoint ));

  /* DNS resolution loads files, `resolv.conf` and all kind of rubbish
     like that, don't want to allow in the sandbox. */
  domain_to_static_ip( tile->event.endpoint, &ctx->endpoint_ip, &ctx->endpoint_port, ctx->host );
  FD_LOG_WARNING(( "Connecting to " FD_IP4_ADDR_FMT " %s:%u", FD_IP4_ADDR_FMT_ARGS( ctx->endpoint_ip ), ctx->host, ctx->endpoint_port ));

  if( FD_UNLIKELY( 8UL!=getrandom( &ctx->instance_id, 8UL, 0 ) ) ) FD_LOG_ERR(( "getrandom failed" ));

  fd_rng_join( fd_rng_new( ctx->rng, 0, (ulong)fd_log_wallclock() ) );

  char boot_id[ 36 ];
  int boot_id_fd = open( "/proc/sys/kernel/random/boot_id", O_RDONLY );
  if( FD_UNLIKELY( boot_id_fd<0 ) ) FD_LOG_ERR(( "open(/proc/sys/kernel/random/boot_id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( 36UL!=read( boot_id_fd, boot_id, 36UL ) ) ) FD_LOG_ERR(( "read(/proc/sys/kernel/random/boot_id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( boot_id_fd ) ) ) FD_LOG_ERR(( "close(/proc/sys/kernel/random/boot_id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  ctx->boot_id = fd_hash( 0UL, boot_id, 36UL );

  char machine_id[ 32 ];
  int machine_id_fd = open( "/var/lib/dbus/machine-id", O_RDONLY );
  if( FD_UNLIKELY( machine_id_fd<0 ) ) FD_LOG_ERR(( "open(/var/lib/dbus/machine-id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( 32UL!=read( machine_id_fd, machine_id, 32UL ) ) ) FD_LOG_ERR(( "read(/var/lib/dbus/machine-id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( machine_id_fd ) ) ) FD_LOG_ERR(( "close(/var/lib/dbus/machine-id) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  ctx->machine_id = fd_hash( 0UL, machine_id, 32UL );

  if( FD_UNLIKELY( !strcmp( tile->event.identity_key_path, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));
  ctx->identity_key = fd_keyload_load( tile->event.identity_key_path, /* pubkey only: */ 1 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_event_ctx_t ), sizeof( fd_event_ctx_t ) );
  void * circq = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_circq_t ), fd_circq_footprint( 1UL<<30UL ) );

  ctx->circq = fd_circq_new( circq, 1UL<<30UL );
  ctx->topo = topo;

  ctx->socket_fd = -1;
  ctx->has_request_body = 0;
  ctx->state = FD_EVENT_CLIENT_STATE_DISCONNECTED;
  ctx->reconnect_deadline_ns = fd_log_wallclock();

  ulong sign_in_idx = fd_topo_find_tile_in_link( topo, tile, "sign_event", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ 0UL ] ];
  FD_TEST( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) ) );

  FD_TEST( fd_cstr_printf_check( ctx->version_string, sizeof( ctx->version_string ), NULL, "%lu.%lu.%lu", FDCTL_MAJOR_VERSION, FDCTL_MINOR_VERSION, FDCTL_PATCH_VERSION ) );
  fd_base58_encode_32( ctx->identity_key, NULL, ctx->identity_key_base58 );
  ctx->identity_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  if( FD_LIKELY( !strcmp( tile->event.cluster, "mainnet-beta" ) ) ) ctx->cluster = FD_EVENT_COMMON_CLUSTER_MAINNET;
  else if( FD_LIKELY( !strcmp( tile->event.cluster, "testnet" ) ) ) ctx->cluster = FD_EVENT_COMMON_CLUSTER_TESTNET;
  else if( FD_LIKELY( !strcmp( tile->event.cluster, "devnet" ) ) ) ctx->cluster = FD_EVENT_COMMON_CLUSTER_DEVNET;
  else if( FD_LIKELY( !strcmp( tile->event.cluster, "development" ) ) ) ctx->cluster = FD_EVENT_COMMON_CLUSTER_DEVELOPMENT;
  else if( FD_LIKELY( !strcmp( tile->event.cluster, "pythnet" ) ) ) ctx->cluster = FD_EVENT_COMMON_CLUSTER_PYTHNET;
  else if( FD_LIKELY( !strcmp( tile->event.cluster, "pythtest" ) ) ) ctx->cluster = FD_EVENT_COMMON_CLUSTER_PYTHTEST;
  else FD_LOG_ERR(( "invalid [tiles.event.cluster] `%s`", tile->event.cluster ));

  ctx->client = tile->event.is_frankendancer ? FD_EVENT_COMMON_CLIENT_FRANKENDANCER : FD_EVENT_COMMON_CLIENT_FIREDANCER;
  ctx->os = FD_EVENT_COMMON_OS_LINUX;

  ctx->metrics_snap_footprint = fd_ulong_align_up( sizeof( fd_event_snap_t ), alignof( fd_event_metrics_sample_t ) ) + fd_event_metrics_footprint( topo );
  ctx->metrics_snap_deadline_ns = fd_log_wallclock();

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_LOG_NOTICE(( "JSON event stream being reported to %s", tile->event.endpoint ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_event_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_event_ctx_t ), sizeof( fd_event_ctx_t ) );

  (void)ctx;

  populate_sock_filter_policy_event( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_event_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_event_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_event_ctx_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_event = {
  .name                     = "event",
  .rlimit_file_cnt          = 4UL, /* pipefd, socket, stderr, logfile */
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
