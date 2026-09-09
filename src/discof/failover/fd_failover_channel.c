#define _GNU_SOURCE
#include "fd_failover_channel.h"
#include "fd_failover_tls.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOURCE_CNT (256UL)
#define PHASE_CONNECT (0)
#define PHASE_TLS     (1)
#define PHASE_HELLO   (2)
#define PHASE_READY   (3)

struct candidate {
  int fd;
  int phase;
  uint address;
  long deadline;
  fd_failover_tls_t tls;
  fd_failover_wire_session_t wire;
  fd_failover_hello_t hello;
  uchar rx[ FD_FAILOVER_FRAME_MAX ];
  uchar tx[ FD_FAILOVER_FRAME_MAX ];
  ulong rx_used;
  ulong tx_used;
  ulong tx_sent;
};

struct source {
  uint address;
  int used;
  long updated;
  ulong credit;
};

struct fd_failover_channel {
  ulong magic;
  int dial_peer;
  ulong state;
  uint peer_addr;
  ushort peer_port;
  int listen_fd;
  int active;
  ulong cursor;
  fd_failover_tls_ctx_t tls_ctx;
  fd_failover_hello_t self_hello;
  fd_failover_hello_t peer_hello;
  struct candidate candidates[ FD_FAILOVER_CHANNEL_CANDIDATE_MAX ];
  struct source sources[ SOURCE_CNT ];
  long rate_updated;
  ulong rate_credit;
  long hello_timeout;
  long silence_timeout;
  long last_rx;
  long retry_at;
  long paired_at;
  long backoff;
  long backoff_min;
  long backoff_max;
  fd_failover_channel_metrics_t metrics;
};

FD_FN_CONST ulong fd_failover_channel_align( void ) { return alignof(fd_failover_channel_t); }
FD_FN_CONST ulong fd_failover_channel_footprint( void ) { return sizeof(fd_failover_channel_t); }

void *
fd_failover_channel_new( void * shmem ) {
  if( !shmem || !fd_ulong_is_aligned( (ulong)shmem, fd_failover_channel_align() ) ) return NULL;
  fd_failover_channel_t * ch = shmem;
  memset( ch, 0, sizeof(*ch) );
  ch->listen_fd = -1;
  ch->active = -1;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) ch->candidates[i].fd = -1;
  ch->hello_timeout   = FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS;
  ch->silence_timeout = 5L*FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS;
  ch->backoff_min     = FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS;
  ch->backoff_max     = FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS;
  ch->backoff         = ch->backoff_min;
  ch->rate_credit     = 16UL*1000000000UL;
  ch->magic           = FD_FAILOVER_CHANNEL_MAGIC;
  return shmem;
}

fd_failover_channel_t *
fd_failover_channel_join( void * shmem ) {
  if( !shmem || !fd_ulong_is_aligned( (ulong)shmem, fd_failover_channel_align() ) ) return NULL;
  fd_failover_channel_t * ch = shmem;
  return ch->magic==FD_FAILOVER_CHANNEL_MAGIC ? ch : NULL;
}

static void
close_candidate( struct candidate * c ) {
  fd_failover_tls_fini( &c->tls );
  if( c->fd!=-1 ) close( c->fd );
  c->fd = -1;
  c->rx_used = c->tx_used = c->tx_sent = 0UL;
  fd_failover_wire_session_wipe( &c->wire );
}

static void
reset( fd_failover_channel_t * ch ) {
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) close_candidate( &ch->candidates[i] );
  ch->active = -1;
  ch->last_rx = 0L;
  memset( &ch->peer_hello, 0, sizeof(ch->peer_hello) );
}

void
fd_failover_channel_init_listener( fd_failover_channel_t * ch, uint address, ushort port ) {
  reset( ch );
  ch->dial_peer = 0;
  ch->state = fd_failover_session_init( ch->dial_peer );
  if( ch->listen_fd!=-1 ) return;
  ch->listen_fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( ch->listen_fd==-1 ) FD_LOG_ERR(( "failover socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int yes = 1;
  if( setsockopt( ch->listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes) ) ) FD_LOG_ERR(( "failover setsockopt failed" ));
  struct sockaddr_in addr = { .sin_family=AF_INET, .sin_port=fd_ushort_bswap( port ), .sin_addr.s_addr=address };
  if( bind( ch->listen_fd, fd_type_pun( &addr ), sizeof(addr) ) || listen( ch->listen_fd, 64 ) )
    FD_LOG_ERR(( "failover listen failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
fd_failover_channel_init_dialer( fd_failover_channel_t * ch, uint address, ushort port ) {
  reset( ch );
  if( ch->listen_fd!=-1 ) close( ch->listen_fd );
  ch->listen_fd = -1;
  ch->dial_peer = 1;
  ch->state = fd_failover_session_init( ch->dial_peer );
  ch->peer_addr = address;
  ch->peer_port = port;
  ch->retry_at = 0L;
}

int
fd_failover_channel_set_identity( fd_failover_channel_t * ch, uchar const * keypair,
                                  uchar const * peer_pubkey, fd_failover_hello_t const * hello ) {
  if( memcmp( keypair+32, hello->junk_pubkey, 32UL ) ||
      !memcmp( hello->junk_pubkey, hello->staked_pubkey, 32UL ) ||
      !memcmp( peer_pubkey, hello->staked_pubkey, 32UL ) ) return -1;
  reset( ch );
  ch->state = fd_failover_session_init( ch->dial_peer );
  fd_failover_tls_ctx_fini( &ch->tls_ctx );
  ch->self_hello = *hello;
  return fd_failover_tls_ctx_init( &ch->tls_ctx, keypair, peer_pubkey );
}

void
fd_failover_channel_fini( fd_failover_channel_t * ch ) {
  reset( ch );
  if( ch->listen_fd!=-1 ) close( ch->listen_fd );
  ch->listen_fd = -1;
  fd_failover_tls_ctx_fini( &ch->tls_ctx );
}

void
fd_failover_channel_set_timing( fd_failover_channel_t * ch, long hello, long silence, long min, long max ) {
  FD_TEST( hello>0L && hello<=FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS );
  FD_TEST( silence>0L && min>0L && min<=max );
  ch->hello_timeout = hello; ch->silence_timeout = silence;
  ch->backoff_min = min; ch->backoff_max = max; ch->backoff = min;
}

void
fd_failover_channel_set_silence( fd_failover_channel_t * ch, long silence ) {
  FD_TEST( silence>0L );
  ch->silence_timeout = silence;
}

FD_FN_PURE ulong fd_failover_channel_state( fd_failover_channel_t const * ch ) { return ch->state; }
FD_FN_PURE int fd_failover_channel_listen_fd( fd_failover_channel_t const * ch ) { return ch->listen_fd; }
FD_FN_PURE ulong fd_failover_channel_ack_seq( fd_failover_channel_t const * ch ) {
  return ch->active>=0 && ch->candidates[ch->active].wire.rx_seq ? ch->candidates[ch->active].wire.rx_seq-1UL : ULONG_MAX;
}
FD_FN_PURE ulong fd_failover_channel_tx_seq( fd_failover_channel_t const * ch ) {
  return ch->active>=0 ? ch->candidates[ch->active].wire.tx_seq : 0UL;
}
FD_FN_PURE int fd_failover_channel_tx_pending( fd_failover_channel_t const * ch ) {
  return ch->active>=0 && !!ch->candidates[ch->active].tx_used;
}
FD_FN_PURE ulong fd_failover_channel_pending( fd_failover_channel_t const * ch ) {
  ulong n = 0UL;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) n += ch->candidates[i].fd!=-1 && (int)i!=ch->active;
  return n;
}
FD_FN_PURE fd_failover_hello_t const * fd_failover_channel_peer_hello( fd_failover_channel_t const * ch ) { return &ch->peer_hello; }
FD_FN_PURE fd_failover_channel_metrics_t const * fd_failover_channel_metrics( fd_failover_channel_t const * ch ) { return &ch->metrics; }

ushort
fd_failover_channel_listen_port( fd_failover_channel_t const * ch ) {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  if( getsockname( ch->listen_fd, fd_type_pun( &addr ), &len ) ) FD_LOG_ERR(( "failover getsockname failed" ));
  return fd_ushort_bswap( addr.sin_port );
}

/* Every state change goes through the session machine in
   fd_failover_proto.c, so that table is the one description of the
   channel's behavior. */
static void
drop( fd_failover_channel_t * ch, ulong idx, long now, int event ) {
  int paired = ch->active==(int)idx;
  close_candidate( &ch->candidates[idx] );
  if( paired ) {
    ch->active = -1;
    ch->last_rx = 0L;
    memset( &ch->peer_hello, 0, sizeof(ch->peer_hello) );
  }
  if( ch->dial_peer ) {
    /* Only a session that outlived the handshake window counts as
       established.  Losing one redials at once and resets the backoff,
       anything shorter keeps doubling it, so a peer that rejects right
       after HELLO cannot drive a redial storm. */
    int established = paired && now>=ch->paired_at && now-ch->paired_at>=ch->hello_timeout;
    ch->retry_at = fd_long_sat_add( now, established ? 0L : ch->backoff );
    ch->backoff  = established ? ch->backoff_min : fd_long_min( fd_long_sat_add( ch->backoff, ch->backoff ), ch->backoff_max );
  }
  ch->state = fd_failover_session_step( ch->state, ch->dial_peer, event );
}

void
fd_failover_channel_hangup( fd_failover_channel_t * ch, long now ) {
  if( ch->active>=0 ) drop( ch, (ulong)ch->active, now, FD_FAILOVER_EV_LINK_LOST );
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( ch->candidates[i].fd!=-1 ) drop( ch, i, now, FD_FAILOVER_EV_LINK_LOST );
}

static ulong
refill( ulong credit, long * updated, long now, ulong rate, ulong burst ) {
  if( now>*updated ) {
    /* Bound elapsed time before multiplying the scaled token count. */
    ulong elapsed = fd_ulong_min( (ulong)now-(ulong)*updated, 1000000000UL );
    credit = fd_ulong_min( credit+elapsed*rate, burst*1000000000UL );
    *updated = now;
  }
  return credit;
}

static int
admit( fd_failover_channel_t * ch, uint address, long now ) {
  ch->rate_credit = refill( ch->rate_credit, &ch->rate_updated, now, 32UL, 16UL );
  if( ch->rate_credit<1000000000UL ) return 0;
  ulong same = 0UL;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ )
    same += ch->candidates[i].fd!=-1 && ch->candidates[i].address==address;
  if( same>=2UL ) return 0;
  struct source * source = NULL;
  struct source * reusable = NULL;
  for( ulong i=0; i<SOURCE_CNT; i++ ) {
    struct source * s = &ch->sources[i];
    if( s->used ) s->credit = refill( s->credit, &s->updated, now, 4UL, 2UL );
    if( s->used && s->address==address ) { source = s; break; }
    if( !s->used || s->credit==2000000000UL ) reusable = s;
  }
  if( !source ) {
    if( !reusable ) return 0;
    source = reusable;
    *source = (struct source){ .address=address, .used=1, .updated=now, .credit=2000000000UL };
  }
  if( source->credit<1000000000UL ) return 0;
  source->credit -= 1000000000UL;
  ch->rate_credit -= 1000000000UL;
  return 1;
}

static int
start( fd_failover_channel_t * ch, ulong idx, int fd, uint address, long now, int phase ) {
  struct candidate * c = &ch->candidates[idx];
  c->fd = fd; c->address = address; c->phase = phase;
  c->deadline = fd_long_sat_add( now, ch->hello_timeout );
  fd_failover_wire_session_init( &c->wire );
  ch->metrics.connection_attempt_cnt++;
  if( fd_failover_tls_new( &c->tls, &ch->tls_ctx, fd, ch->dial_peer ) ) {
    ch->metrics.tls_fail_cnt++;
    drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
    return -1;
  }
  return 0;
}

static void
accept_candidates( fd_failover_channel_t * ch, long now, int * busy ) {
  for( ulong n=0; n<8UL; n++ ) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = accept4( ch->listen_fd, fd_type_pun( &addr ), &len, SOCK_NONBLOCK|SOCK_CLOEXEC );
    if( fd==-1 ) return;
    *busy = 1;
    ulong idx = 0UL;
    while( idx<FD_FAILOVER_CHANNEL_CANDIDATE_MAX && ch->candidates[idx].fd!=-1 ) idx++;
    if( ch->active>=0 || idx==FD_FAILOVER_CHANNEL_CANDIDATE_MAX || len!=sizeof(addr) ||
        addr.sin_family!=AF_INET || !admit( ch, addr.sin_addr.s_addr, now ) ) {
      ch->metrics.admission_drop_cnt++;
      close( fd );
      continue;
    }
    if( !start( ch, idx, fd, addr.sin_addr.s_addr, now, PHASE_TLS ) )
      ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_PEER_CONNECTED );
  }
}

static int
flush( fd_failover_channel_t * ch, ulong idx, long now, int * busy ) {
  struct candidate * c = &ch->candidates[idx];
  if( !c->tx_used ) return 0;
  long n = fd_failover_tls_write( &c->tls, c->tx+c->tx_sent, c->tx_used-c->tx_sent );
  if( n<0L ) { drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return -1; }
  if( !n ) return 1;
  *busy = 1;
  c->tx_sent += (ulong)n;
  if( c->tx_sent<c->tx_used ) return 1;
  c->tx_used = c->tx_sent = 0UL;
  ch->metrics.frames_sent++;
  return 0;
}

static int
decode( fd_failover_channel_t * ch, ulong idx, long now, int * busy,
        ushort * type, uchar * payload, ulong * payload_sz ) {
  struct candidate * c = &ch->candidates[idx];
  uchar const * data;
  ulong frame_sz;
  int err = fd_failover_wire_decode( &c->wire, c->rx, c->rx_used, type, &data, payload_sz, &frame_sz );
  if( err==FD_FAILOVER_WIRE_ERR_AGAIN ) return 0;
  if( err ) { ch->metrics.wire_fatal_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return -1; }
  memcpy( payload, data, *payload_sz );
  memmove( c->rx, c->rx+frame_sz, c->rx_used-frame_sz );
  c->rx_used -= frame_sz;
  ch->metrics.frames_received++;
  *busy = 1;
  return 1;
}

static int
read_frame( fd_failover_channel_t * ch, ulong idx, long now, int * busy,
            ushort * type, uchar * payload, ulong * payload_sz ) {
  struct candidate * c = &ch->candidates[idx];
  int rc = decode( ch, idx, now, busy, type, payload, payload_sz );
  if( rc ) return rc;
  ulong max = ch->active==(int)idx ? sizeof(c->rx) : FD_FAILOVER_FRAME_HDR_SZ+sizeof(fd_failover_hello_t);
  if( c->rx_used>=max ) { ch->metrics.wire_fatal_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return -1; }
  long n = fd_failover_tls_read( &c->tls, c->rx+c->rx_used, max-c->rx_used );
  if( n<0L ) { drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return -1; }
  if( n>0L ) { c->rx_used += (ulong)n; *busy = 1; }
  return decode( ch, idx, now, busy, type, payload, payload_sz );
}

static void
service_candidate( fd_failover_channel_t * ch, ulong idx, long now, int * busy, uchar * payload ) {
  struct candidate * c = &ch->candidates[idx];
  fd_failover_tls_budget( &c->tls );
  if( c->phase==PHASE_CONNECT ) {
    struct sockaddr_in addr = { .sin_family=AF_INET, .sin_port=fd_ushort_bswap( ch->peer_port ), .sin_addr.s_addr=ch->peer_addr };
    if( connect( c->fd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EISCONN ) {
      if( errno==EINPROGRESS || errno==EALREADY || errno==EINTR ) return;
      drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return;
    }
    c->phase = PHASE_TLS;
    ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_CONNECTED );
  }
  if( c->phase==PHASE_TLS ) {
    int rc = fd_failover_tls_handshake( &c->tls );
    if( rc<0 ) { ch->metrics.tls_fail_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return; }
    if( !rc ) return;
    *busy = 1;
    c->phase = PHASE_HELLO;
    c->tx_used = fd_failover_wire_encode( &c->wire, c->tx, FD_FAILOVER_MSG_HELLO,
                                         (uchar const *)&ch->self_hello, sizeof(ch->self_hello) );
  }
  if( flush( ch, idx, now, busy )!=0 ) return;
  if( c->phase==PHASE_HELLO ) {
    ushort type;
    ulong sz;
    if( read_frame( ch, idx, now, busy, &type, payload, &sz )<=0 ) return;
    if( type!=FD_FAILOVER_MSG_HELLO || sz!=sizeof(c->hello) ) {
      ch->metrics.wire_fatal_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_HELLO_FATAL ); return;
    }
    memcpy( &c->hello, payload, sizeof(c->hello) );
    if( memcmp( c->hello.junk_pubkey, ch->tls_ctx.peer_pubkey, 32UL ) ||
        fd_failover_hello_check( &ch->self_hello, &c->hello )!=FD_FAILOVER_HELLO_OK ) {
      ch->metrics.hello_reject_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_HELLO_FATAL ); return;
    }
    c->phase = PHASE_READY;
  }
  if( c->phase==PHASE_READY && !c->tx_used ) {
    ch->active = (int)idx;
    c->tls.paired = 1;
    ch->peer_hello = c->hello;
    ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_HELLO_OK );
    ch->metrics.paired_cnt++;
    ch->last_rx   = now;
    ch->paired_at = now;
    for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( i!=idx ) close_candidate( &ch->candidates[i] );
    *busy = 1;
  }
}

int
fd_failover_channel_poll( fd_failover_channel_t * ch, long now, int * busy,
                          ushort * type, uchar * payload, ulong * payload_sz ) {
  int delivered = 0;
  /* Established traffic gets service before the bounded accept drain. */
  if( ch->active>=0 ) {
    ulong idx = (ulong)ch->active;
    fd_failover_tls_budget( &ch->candidates[idx].tls );
    int flushed = flush( ch, idx, now, busy );
    if( !flushed ) {
      int rc = read_frame( ch, idx, now, busy, type, payload, payload_sz );
      if( rc>0 ) {
        if( *type==FD_FAILOVER_MSG_HELLO ) { ch->metrics.wire_fatal_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); }
        else { ch->last_rx = now; delivered = 1; }
      } else if( !rc && now>=ch->last_rx && now-ch->last_rx>ch->silence_timeout ) drop( ch, idx, now, FD_FAILOVER_EV_TIMEOUT );
    }
    if( flushed>0 && now>=ch->last_rx && now-ch->last_rx>ch->silence_timeout ) drop( ch, idx, now, FD_FAILOVER_EV_TIMEOUT );
  }
  /* Expire every slot each poll, independently of round-robin service. */
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    struct candidate * c = &ch->candidates[i];
    if( c->fd!=-1 && (int)i!=ch->active && now>=c->deadline ) {
      ch->metrics.handshake_timeout_cnt++; drop( ch, i, now, FD_FAILOVER_EV_TIMEOUT ); *busy = 1;
    }
  }
  if( !ch->dial_peer ) accept_candidates( ch, now, busy );
  else if( ch->state==FD_FAILOVER_SESSION_BACKOFF && now>=ch->retry_at && ch->tls_ctx.ready ) {
    int fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
    *busy = 1;
    if( fd==-1 ) { drop( ch, 0UL, now, FD_FAILOVER_EV_LINK_LOST ); return delivered; }
    ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_RETRY );
    start( ch, 0UL, fd, ch->peer_addr, now, PHASE_CONNECT );
  }
  if( ch->active>=0 ) return delivered;
  ulong serviced = 0UL;
  for( ulong n=0; n<FD_FAILOVER_CHANNEL_CANDIDATE_MAX && serviced<4UL; n++ ) {
    ulong idx = ch->cursor;
    ch->cursor = (ch->cursor+1UL)%FD_FAILOVER_CHANNEL_CANDIDATE_MAX;
    if( ch->candidates[idx].fd==-1 ) continue;
    service_candidate( ch, idx, now, busy, payload );
    serviced++;
    if( ch->active>=0 ) break;
  }
  return delivered;
}

int
fd_failover_channel_send( fd_failover_channel_t * ch, long now, ushort type, uchar const * payload, ulong sz ) {
  if( ch->active<0 ) return -1;
  ulong idx = (ulong)ch->active;
  struct candidate * c = &ch->candidates[idx];
  if( c->tx_used ) return -1;
  c->tx_used = fd_failover_wire_encode( &c->wire, c->tx, type, payload, sz );
  if( !c->tx_used ) { drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return -1; }
  int busy = 0;
  return flush( ch, idx, now, &busy )<0 ? -1 : 0;
}
