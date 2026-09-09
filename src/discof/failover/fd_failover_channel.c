#define _GNU_SOURCE
#include "fd_failover_channel.h"

#include "../../util/fd_util.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct fd_failover_channel {
  ulong magic;

  int    dial_peer;
  ulong  state;
  uint   peer_addr;
  ushort peer_port;

  int listen_fd;
  int conn_fd;

  uchar               secret[ 32 ];
  fd_failover_hello_t self_hello;
  fd_failover_hello_t peer_hello;

  fd_failover_wire_session_t wire;

  uchar rx_buf[ FD_FAILOVER_FRAME_MAX ];
  ulong rx_used;
  uchar tx_buf[ FD_FAILOVER_FRAME_MAX ];
  ulong tx_used;
  ulong tx_sent;

  long hello_deadline;
  long hello_timeout;
  long silence_timeout;
  long last_rx;
  long retry_at;
  long backoff;
  long backoff_min;
  long backoff_max;

  fd_failover_channel_metrics_t metrics;
};

FD_FN_CONST ulong
fd_failover_channel_align( void ) {
  return alignof(fd_failover_channel_t);
}

FD_FN_CONST ulong
fd_failover_channel_footprint( void ) {
  return sizeof(fd_failover_channel_t);
}

void *
fd_failover_channel_new( void * shmem ) {
  fd_failover_channel_t * channel = (fd_failover_channel_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_failover_channel_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  memset( channel, 0, sizeof(fd_failover_channel_t) );
  channel->listen_fd = -1;
  channel->conn_fd   = -1;
  channel->hello_timeout   = FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS;
  channel->silence_timeout = 5L*FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS;
  channel->backoff_min     = FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS;
  channel->backoff_max     = FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS;
  channel->backoff         = channel->backoff_min;

  channel->magic = FD_FAILOVER_CHANNEL_MAGIC;
  return shmem;
}

fd_failover_channel_t *
fd_failover_channel_join( void * shch ) {
  fd_failover_channel_t * channel = (fd_failover_channel_t *)shch;

  if( FD_UNLIKELY( !shch ) ) {
    FD_LOG_WARNING(( "NULL shch" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shch, fd_failover_channel_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shch" ));
    return NULL;
  }

  if( FD_UNLIKELY( channel->magic!=FD_FAILOVER_CHANNEL_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return channel;
}

static void
reset_session( fd_failover_channel_t * channel ) {
  if( FD_LIKELY( channel->conn_fd!=-1 ) ) {
    if( FD_UNLIKELY( close( channel->conn_fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    channel->conn_fd = -1;
  }
  fd_failover_wire_session_wipe( &channel->wire );
  channel->rx_used = 0UL;
  channel->tx_used = 0UL;
  channel->tx_sent = 0UL;
  channel->last_rx = 0L;
  channel->backoff = channel->backoff_min;
}

void
fd_failover_channel_init_listener( fd_failover_channel_t * channel,
                                   uint                    address,
                                   ushort                  port ) {
  reset_session( channel );
  channel->dial_peer = 0;
  channel->state     = FD_FAILOVER_SESSION_LISTENING;

  if( FD_LIKELY( channel->listen_fd!=-1 ) ) return;

  channel->listen_fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( -1==channel->listen_fd ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( channel->listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval) ) ) ) {
    FD_LOG_ERR(( "setsockopt() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( port ),
    .sin_addr.s_addr = address,
  };
  if( FD_UNLIKELY( -1==bind( channel->listen_fd, fd_type_pun( &addr ), sizeof(addr) ) ) ) {
    FD_LOG_ERR(( "bind() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==listen( channel->listen_fd, 1 ) ) ) {
    FD_LOG_ERR(( "listen() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

void
fd_failover_channel_init_dialer( fd_failover_channel_t * channel,
                                 uint                    address,
                                 ushort                  port ) {
  reset_session( channel );
  if( FD_UNLIKELY( channel->listen_fd!=-1 ) ) {
    if( FD_UNLIKELY( close( channel->listen_fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    channel->listen_fd = -1;
  }
  channel->dial_peer = 1;
  channel->state     = FD_FAILOVER_SESSION_BACKOFF;
  channel->peer_addr = address;
  channel->peer_port = port;
  channel->retry_at  = 0L;
}

void
fd_failover_channel_set_identity( fd_failover_channel_t *     channel,
                                  uchar const *               pair_secret,
                                  fd_failover_hello_t const * hello ) {
  memcpy( channel->secret, pair_secret, 32UL );
  channel->self_hello = *hello;
}

void
fd_failover_channel_set_timing( fd_failover_channel_t * channel,
                                long                    hello_timeout_nanos,
                                long                    silence_nanos,
                                long                    backoff_min_nanos,
                                long                    backoff_max_nanos ) {
  FD_TEST( hello_timeout_nanos>0L );
  FD_TEST( silence_nanos>0L );
  FD_TEST( backoff_min_nanos>0L && backoff_min_nanos<=backoff_max_nanos );
  channel->hello_timeout   = hello_timeout_nanos;
  channel->silence_timeout = silence_nanos;
  channel->backoff_min     = backoff_min_nanos;
  channel->backoff_max     = backoff_max_nanos;
  channel->backoff         = backoff_min_nanos;
}

FD_FN_PURE ulong fd_failover_channel_state    ( fd_failover_channel_t const * channel ) { return channel->state;        }
FD_FN_PURE int   fd_failover_channel_listen_fd( fd_failover_channel_t const * channel ) { return channel->listen_fd;    }
FD_FN_PURE ulong fd_failover_channel_ack_seq  ( fd_failover_channel_t const * channel ) { return channel->wire.rx_seq ? channel->wire.rx_seq-1UL : ULONG_MAX; }
FD_FN_PURE ulong fd_failover_channel_tx_seq   ( fd_failover_channel_t const * channel ) { return channel->wire.tx_seq;  }
FD_FN_PURE int   fd_failover_channel_tx_pending( fd_failover_channel_t const * channel ) { return !!channel->tx_used; }

FD_FN_PURE fd_failover_hello_t const *
fd_failover_channel_peer_hello( fd_failover_channel_t const * channel ) {
  return &channel->peer_hello;
}

FD_FN_PURE fd_failover_channel_metrics_t const *
fd_failover_channel_metrics( fd_failover_channel_t const * channel ) {
  return &channel->metrics;
}

ushort
fd_failover_channel_listen_port( fd_failover_channel_t const * channel ) {
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  if( FD_UNLIKELY( -1==getsockname( channel->listen_fd, fd_type_pun( &addr ), &addr_len ) ) ) {
    FD_LOG_ERR(( "getsockname() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return fd_ushort_bswap( addr.sin_port );
}

static int
is_expected_network_error( int err ) {
  return err==EACCES       || err==EADDRINUSE   || err==EADDRNOTAVAIL ||
         err==EAGAIN       || err==EINTR        || err==EMFILE        ||
         err==ENFILE       || err==ENETDOWN     || err==EPROTO        ||
         err==ENOPROTOOPT  || err==EHOSTDOWN    || err==ENONET        ||
         err==EHOSTUNREACH || err==EOPNOTSUPP   || err==ENETUNREACH   ||
         err==ETIMEDOUT    || err==ENETRESET    || err==ECONNABORTED  ||
         err==ECONNRESET   || err==ECONNREFUSED || err==ENOTCONN      ||
         err==ESHUTDOWN    || err==EPIPE        || err==EPERM         ||
         err==ENOBUFS      || err==ENOMEM;
}

static int
is_retryable_socket_error( int err ) {
  return err==EMFILE || err==ENFILE || err==ENOBUFS || err==ENOMEM;
}

/* drop closes the live connection and rests the channel.  A listener
   resumes accepting immediately.  A dialer waits out the backoff,
   which doubles on failures before pairing and resets after pairing. */

static void
drop( fd_failover_channel_t * channel,
      long                    now,
      int                     had_paired ) {
  if( FD_LIKELY( -1!=channel->conn_fd ) ) {
    if( FD_UNLIKELY( -1==close( channel->conn_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    channel->conn_fd = -1;
  }
  fd_failover_wire_session_wipe( &channel->wire );
  channel->rx_used = 0UL;
  channel->tx_used = 0UL;
  channel->tx_sent = 0UL;
  channel->last_rx = 0L;

  long retry_delay = had_paired ? 0L : channel->backoff;
  if( FD_LIKELY( had_paired ) ) channel->backoff = channel->backoff_min;
  else                          channel->backoff = fd_long_min( fd_long_sat_add( channel->backoff, channel->backoff ),
                                                               channel->backoff_max );

  channel->retry_at = fd_long_sat_add( now, retry_delay );
  channel->state = fd_failover_session_step( channel->state, channel->dial_peer, FD_FAILOVER_EV_LINK_LOST );
  if( FD_LIKELY( channel->state==FD_FAILOVER_SESSION_BACKOFF && !channel->dial_peer ) ) {
    channel->state = fd_failover_session_step( channel->state, channel->dial_peer, FD_FAILOVER_EV_RETRY );
  }
}

void
fd_failover_channel_hangup( fd_failover_channel_t * channel,
                            long                    now ) {
  if( FD_UNLIKELY( channel->state==FD_FAILOVER_SESSION_REJECTED ) ) return;
  if( FD_UNLIKELY( -1==channel->conn_fd ) ) return;
  drop( channel, now, 1 );
}

static int
flush_tx( fd_failover_channel_t * channel,
          long                    now,
          int *                   charge_busy ) {
  if( FD_LIKELY( channel->tx_sent==channel->tx_used ) ) return 0;

  long sent = send( channel->conn_fd, channel->tx_buf+channel->tx_sent,
                    channel->tx_used-channel->tx_sent, MSG_NOSIGNAL );
  if( FD_UNLIKELY( sent<0L ) ) {
    if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) return 1;
    if( FD_UNLIKELY( !is_expected_network_error( errno ) ) ) {
      FD_LOG_ERR(( "send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    drop( channel, now, channel->state==FD_FAILOVER_SESSION_PAIRED );
    return -1;
  }
  if( FD_UNLIKELY( !sent ) ) {
    drop( channel, now, channel->state==FD_FAILOVER_SESSION_PAIRED );
    return -1;
  }

  channel->tx_sent += (ulong)sent;
  *charge_busy = 1;
  if( FD_LIKELY( channel->tx_sent==channel->tx_used ) ) {
    channel->tx_used = 0UL;
    channel->tx_sent = 0UL;
    channel->metrics.frames_sent++;
    return 0;
  }
  return 1;
}

static int
send_frame( fd_failover_channel_t * channel,
            long                    now,
            ushort                  type,
            uchar const *           payload,
            ulong                   payload_sz ) {
  if( FD_UNLIKELY( channel->tx_used ) ) return -1;
  ulong frame_sz = fd_failover_wire_encode( &channel->wire, channel->tx_buf, type, payload, payload_sz );
  if( FD_UNLIKELY( !frame_sz ) ) {
    drop( channel, now, channel->state==FD_FAILOVER_SESSION_PAIRED );
    return -1;
  }
  channel->tx_used = frame_sz;
  channel->tx_sent = 0UL;
  int charge_busy = 0;
  return flush_tx( channel, now, &charge_busy )<0 ? -1 : 0;
}

/* start_hello begins the handshake on a fresh connection: derive the
   HELLO phase key, mint this connection's nonce, and send our HELLO. */

static void
start_hello( fd_failover_channel_t * channel,
             long                    now ) {
  fd_failover_wire_session_init( &channel->wire, channel->secret, 32UL, channel->dial_peer );
  FD_TEST( fd_rng_secure( channel->self_hello.session_nonce, 16UL ) );

  channel->rx_used        = 0UL;
  channel->hello_deadline = fd_long_sat_add( now, channel->hello_timeout );
  channel->last_rx        = now;
  channel->state          = fd_failover_session_step( channel->state, channel->dial_peer,
                                                      channel->dial_peer ?
                                                      FD_FAILOVER_EV_CONNECTED : FD_FAILOVER_EV_PEER_CONNECTED );
  channel->metrics.connect_cnt++;

  send_frame( channel, now, (ushort)FD_FAILOVER_MSG_HELLO, (uchar const *)&channel->self_hello, sizeof(fd_failover_hello_t) );
}

/* handle_hello runs the fatal checks on the peer's first frame and
   either derives the direction keys or parks the channel. */

static void
handle_hello( fd_failover_channel_t * channel,
              long                    now,
              uchar const *           payload,
              ulong                   payload_sz ) {
  if( FD_UNLIKELY( payload_sz!=sizeof(fd_failover_hello_t) ) ) {
    channel->metrics.wire_fatal_cnt++;
    drop( channel, now, 0 );
    return;
  }

  memcpy( &channel->peer_hello, payload, sizeof(fd_failover_hello_t) );

  int verdict = fd_failover_hello_check( &channel->self_hello, &channel->peer_hello );
  if( FD_UNLIKELY( verdict!=FD_FAILOVER_HELLO_OK ) ) {
    FD_LOG_WARNING(( "failover pairing failed a fatal HELLO check (verdict %d), operator attention required", verdict ));
    channel->metrics.hello_reject_cnt++;
    if( FD_LIKELY( -1!=channel->conn_fd ) ) {
      if( FD_UNLIKELY( -1==close( channel->conn_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      channel->conn_fd = -1;
    }
    fd_failover_wire_session_wipe( &channel->wire );
    channel->rx_used = 0UL;
    channel->tx_used = 0UL;
    channel->tx_sent = 0UL;
    channel->last_rx = 0L;
    channel->state = fd_failover_session_step( channel->state, channel->dial_peer, FD_FAILOVER_EV_HELLO_FATAL );
    return;
  }

  fd_failover_wire_session_keys( &channel->wire, channel->secret, 32UL,
                                 channel->self_hello.session_nonce,
                                 channel->peer_hello.session_nonce );
  channel->backoff = channel->backoff_min;
  channel->state   = fd_failover_session_step( channel->state, channel->dial_peer, FD_FAILOVER_EV_HELLO_OK );
}

/* decode_frame delivers the first complete buffered frame. */

static int
decode_frame( fd_failover_channel_t * channel,
              long                    now,
              int *                   charge_busy,
              ushort *                out_type,
              uchar *                 out_payload,
              ulong *                 out_payload_sz ) {
  if( FD_UNLIKELY( !channel->rx_used ) ) return 0;

  uchar const * payload;
  ulong         frame_sz;
  int err = fd_failover_wire_decode( &channel->wire, channel->rx_buf, channel->rx_used,
                                     out_type, &payload, out_payload_sz, &frame_sz );
  if( FD_LIKELY( err==FD_FAILOVER_WIRE_ERR_AGAIN ) ) return 0;
  if( FD_UNLIKELY( err!=FD_FAILOVER_WIRE_SUCCESS ) ) {
    if( err==FD_FAILOVER_WIRE_ERR_MAC ) channel->metrics.mac_fail_cnt++;
    else                                channel->metrics.wire_fatal_cnt++;
    drop( channel, now, channel->state==FD_FAILOVER_SESSION_PAIRED );
    return -1;
  }

  memcpy( out_payload, payload, *out_payload_sz );
  memmove( channel->rx_buf, channel->rx_buf+frame_sz, channel->rx_used-frame_sz );
  channel->rx_used -= frame_sz;
  channel->last_rx = now;
  channel->metrics.frames_received++;
  *charge_busy = 1;
  return 1;
}

/* read_frame decodes buffered data before reading more from the socket.
   This preserves complete frames that precede EOF. */

static int
read_frame( fd_failover_channel_t * channel,
            long                    now,
            int *                   charge_busy,
            ushort *                out_type,
            uchar *                 out_payload,
            ulong *                 out_payload_sz ) {
  int decoded = decode_frame( channel, now, charge_busy, out_type, out_payload, out_payload_sz );
  if( FD_UNLIKELY( decoded ) ) return decoded;

  long rd = read( channel->conn_fd, channel->rx_buf+channel->rx_used, sizeof(channel->rx_buf)-channel->rx_used );
  if( FD_UNLIKELY( !rd ) ) { drop( channel, now, channel->state==FD_FAILOVER_SESSION_PAIRED ); return -1; }
  if( FD_UNLIKELY( rd==-1L ) ) {
    if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) rd = 0L;
    else if( FD_LIKELY( is_expected_network_error( errno ) ) ) { drop( channel, now, channel->state==FD_FAILOVER_SESSION_PAIRED ); return -1; }
    else FD_LOG_ERR(( "read() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_LIKELY( rd>0L ) ) { channel->rx_used += (ulong)rd; *charge_busy = 1; }
  return decode_frame( channel, now, charge_busy, out_type, out_payload, out_payload_sz );
}

int
fd_failover_channel_poll( fd_failover_channel_t * channel,
                          long                    now,
                          int *                   charge_busy,
                          ushort *                out_type,
                          uchar *                 out_payload,
                          ulong *                 out_payload_sz ) {
  if( FD_UNLIKELY( channel->tx_used ) ) {
    int err = flush_tx( channel, now, charge_busy );
    if( FD_UNLIKELY( err<0 ) ) return 0;
  }

  switch( channel->state ) {

  case FD_FAILOVER_SESSION_REJECTED:
    return 0;

  case FD_FAILOVER_SESSION_BACKOFF: {
    if( FD_LIKELY( now<channel->retry_at ) ) return 0;
    channel->state = fd_failover_session_step( channel->state, channel->dial_peer, FD_FAILOVER_EV_RETRY );

    channel->conn_fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
    if( FD_UNLIKELY( -1==channel->conn_fd ) ) {
      int err = errno;
      if( FD_UNLIKELY( !is_retryable_socket_error( err ) ) ) {
        FD_LOG_ERR(( "socket() failed (%i-%s)", err, fd_io_strerror( err ) ));
      }
      drop( channel, now, 0 );
      *charge_busy = 1;
      return 0;
    }
    channel->hello_deadline = fd_long_sat_add( now, channel->hello_timeout );
    *charge_busy = 1;
    __attribute__((fallthrough));
  }

  case FD_FAILOVER_SESSION_DIALING: {
    if( FD_UNLIKELY( channel->state!=FD_FAILOVER_SESSION_DIALING ) ) return 0;
    if( FD_UNLIKELY( now>channel->hello_deadline ) ) { drop( channel, now, 0 ); return 0; }

    struct sockaddr_in addr = {
      .sin_family      = AF_INET,
      .sin_port        = fd_ushort_bswap( channel->peer_port ),
      .sin_addr.s_addr = channel->peer_addr,
    };
    if( FD_UNLIKELY( -1==connect( channel->conn_fd, fd_type_pun( &addr ), sizeof(addr) ) ) ) {
      if( FD_LIKELY( errno==EINPROGRESS || errno==EALREADY ) ) return 0;
      if( FD_UNLIKELY( errno!=EISCONN ) ) {
        if( FD_UNLIKELY( !is_expected_network_error( errno ) ) ) FD_LOG_ERR(( "connect() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        drop( channel, now, 0 );
        return 0;
      }
    }
    start_hello( channel, now );
    return 0;
  }

  case FD_FAILOVER_SESSION_LISTENING: {
    int fd = accept4( channel->listen_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC );
    if( FD_UNLIKELY( -1==fd ) ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) return 0;
      if( FD_LIKELY( is_expected_network_error( errno ) ) ) return 0;
      FD_LOG_ERR(( "accept4() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    channel->conn_fd = fd;
    start_hello( channel, now );
    *charge_busy = 1;
    return 0;
  }

  case FD_FAILOVER_SESSION_HELLO: {
    if( FD_UNLIKELY( now>channel->hello_deadline ) ) { drop( channel, now, 0 ); return 0; }

    ushort type;
    ulong  payload_sz;
    if( FD_LIKELY( read_frame( channel, now, charge_busy, &type, out_payload, &payload_sz )<=0 ) ) return 0;
    if( FD_UNLIKELY( type!=(ushort)FD_FAILOVER_MSG_HELLO ) ) {
      channel->metrics.wire_fatal_cnt++;
      drop( channel, now, 0 );
      return 0;
    }
    handle_hello( channel, now, out_payload, payload_sz );
    return 0;
  }

  case FD_FAILOVER_SESSION_PAIRED: {
    ushort type;
    ulong  payload_sz;
    int read_result = read_frame( channel, now, charge_busy, &type, out_payload, &payload_sz );
    if( FD_LIKELY( read_result<=0 ) ) {
      if( FD_UNLIKELY( read_result<0 ) ) return 0;
      if( FD_UNLIKELY( now>=channel->last_rx &&
                       now-channel->last_rx>channel->silence_timeout ) ) drop( channel, now, 1 );
      return 0;
    }
    if( FD_UNLIKELY( type==(ushort)FD_FAILOVER_MSG_HELLO ) ) {
      channel->metrics.wire_fatal_cnt++;
      drop( channel, now, 1 );
      return 0;
    }
    *out_type       = type;
    *out_payload_sz = payload_sz;
    return 1;
  }

  }

  return 0;
}

int
fd_failover_channel_send( fd_failover_channel_t * channel,
                          long                    now,
                          ushort                  type,
                          uchar const *           payload,
                          ulong                   payload_sz ) {
  if( FD_UNLIKELY( channel->state!=FD_FAILOVER_SESSION_PAIRED ) ) return -1;
  return send_frame( channel, now, type, payload, payload_sz );
}
