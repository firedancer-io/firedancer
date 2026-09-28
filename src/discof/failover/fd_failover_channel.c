#define _GNU_SOURCE
#include "fd_failover_channel.h"
#include "fd_failover_tls.h"
#include "fd_failover_log.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOURCE_CNT    (256UL)
#define PHASE_CONNECT (0)
#define PHASE_TLS     (1)
#define PHASE_HELLO   (2)
#define PHASE_READY   (3)

/* A HELLO whose junk key is not the key TLS authenticated */
#define HELLO_ERR_TLS_KEY (-1)

struct candidate {
  int                        fd;
  int                        phase;
  int                        dialed;  /* we dialed it, else it came in on the listener */
  uint                       address;
  long                       deadline;
  fd_failover_tls_t          tls;
  fd_failover_wire_session_t wire;
  fd_failover_hello_t        hello;
  uchar                      rx[ FD_FAILOVER_FRAME_MAX ];
  uchar                      tx[ FD_FAILOVER_FRAME_MAX ];
  ulong                      rx_used;
  ulong                      tx_used;
  ulong                      tx_sent;
};

struct source {
  uint  address;
  int   used;
  long  updated;
  ulong credit;
};

struct fd_failover_channel {
  ulong                         magic;
  int                           dial_peer;     /* the session machine runs as the dialer */
  ulong                         state;
  uint                          peer_addr;     /* the address we dial, zero if not known */
  ushort                        peer_port;
  uint                          expect_addr;   /* the configured peer's address, reserved on the listener, zero for none */
  int                           listen_fd;
  int                           active;
  ulong                         cursor;
  fd_failover_tls_ctx_t         tls_ctx;
  fd_failover_hello_t           self_hello;
  fd_failover_hello_t           peer_hello;
  int                           member_cert_set;
  fd_sha512_t                   sha[ 1 ];
  struct candidate              candidates[ FD_FAILOVER_CHANNEL_CANDIDATE_MAX ];
  struct source                 sources[ SOURCE_CNT ];
  long                          rate_updated;
  ulong                         rate_credit;
  long                          hello_timeout;
  long                          silence_timeout;
  long                          last_rx;
  long                          retry_at;
  long                          paired_at;
  long                          backoff;
  long                          backoff_min;
  long                          backoff_max;
  fd_failover_log_t             dial_log[3];  /* connect, early close, handshake timeout */
  fd_failover_log_t             tls_log[4];   /* transport, profile, authentication, malformed */
  fd_failover_log_t             hello_log[14]; /* one bounded bucket per HELLO refusal */
  fd_failover_log_t             loss_log[6];  /* transport, silence, TLS, protocol, framing, local encode */
  fd_failover_log_t             pair_log;
  int                           expected_close; /* RESULT was sent; peer may close normally */
  fd_failover_channel_metrics_t metrics;
};

FD_FN_CONST ulong fd_failover_channel_align    ( void ) { return alignof(fd_failover_channel_t); }
FD_FN_CONST ulong fd_failover_channel_footprint( void ) { return sizeof (fd_failover_channel_t); }

void *
fd_failover_channel_new( void * shmem ) {
  if( !shmem || !fd_ulong_is_aligned( (ulong)shmem, fd_failover_channel_align() ) ) return NULL;
  fd_failover_channel_t * ch = shmem;
  fd_memset( ch, 0, sizeof(*ch) );
  ch->listen_fd = -1;
  ch->active = -1;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) ch->candidates[i].fd = -1;
  ch->hello_timeout   = FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS;
  ch->silence_timeout = FD_FAILOVER_CHANNEL_IDLE_NANOS;
  ch->backoff_min     = FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS;
  ch->backoff_max     = FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS;
  ch->backoff         = ch->backoff_min;
  ch->rate_credit     = 16UL*1000000000UL;
  FD_TEST( fd_sha512_join( fd_sha512_new( ch->sha ) ) );
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
  c->dialed = 0;
  c->rx_used = c->tx_used = c->tx_sent = 0UL;
  fd_failover_wire_session_wipe( &c->wire );
}

static void
reset( fd_failover_channel_t * ch ) {
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) close_candidate( &ch->candidates[i] );
  ch->active = -1;
  ch->last_rx = 0L;
  fd_memset( &ch->peer_hello, 0, sizeof(ch->peer_hello) );
}

/* The controller sets a dial address only for an open handoff. */
static int
want_dial( fd_failover_channel_t const * ch ) {
  return !!ch->peer_addr;
}

/* Returns an unpaired channel to the resting state that fits our role
   and the active's address.  A dial in flight is dropped, and a standby
   that knows the active's address dials again right away.  A paired
   session is left alone, it outlives role and address changes. */
static void
rest( fd_failover_channel_t * ch ) {
  if( ch->active>=0 ) return;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( ch->candidates[i].dialed ) close_candidate( &ch->candidates[i] );
  ch->dial_peer = want_dial( ch );
  ch->state     = fd_failover_session_init( ch->dial_peer );
  ch->retry_at  = 0L;
}

void
fd_failover_channel_init_listener( fd_failover_channel_t * ch,
                                   uint                    address,
                                   ushort                  port ) {
  reset( ch );
  rest( ch );
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
fd_failover_channel_init_dialer( fd_failover_channel_t * ch,
                                 uint                    address,
                                 ushort                  port ) {
  if( address==ch->peer_addr && port==ch->peer_port ) return;
  ch->peer_addr = address;
  ch->peer_port = port;
  if( address ) fd_memset( ch->dial_log, 0, sizeof(ch->dial_log) );
  rest( ch );
}

void
fd_failover_channel_expect_peer( fd_failover_channel_t * ch,
                                 uint                    address ) {
  ch->expect_addr = address;
}

int
fd_failover_channel_set_identity( fd_failover_channel_t *     ch,
                                  uchar const *               keypair,
                                  fd_failover_hello_t const * hello ) {
  if( !fd_memeq( keypair+32, hello->junk_pubkey, 32UL ) ||
      fd_memeq( hello->junk_pubkey, hello->staked_pubkey, 32UL ) ) return -1;
  reset( ch );
  ch->state = fd_failover_session_init( ch->dial_peer );
  fd_failover_tls_ctx_fini( &ch->tls_ctx );
  ch->self_hello      = *hello;
  ch->member_cert_set = 0;
  return fd_failover_tls_ctx_init( &ch->tls_ctx, keypair );
}

int
fd_failover_channel_set_member_cert( fd_failover_channel_t * ch,
                                     uchar const *           member_cert ) {
  fd_failover_hello_t hello = ch->self_hello;
  fd_memcpy( hello.member_cert, member_cert, 64UL );
  if( FD_UNLIKELY( fd_failover_member_cert_check( &hello, ch->sha )!=FD_FAILOVER_HELLO_OK ) ) return -1;
  ch->self_hello      = hello;
  ch->member_cert_set = 1;
  return 0;
}

void
fd_failover_channel_fini( fd_failover_channel_t * ch ) {
  reset( ch );
  if( ch->listen_fd!=-1 ) close( ch->listen_fd );
  ch->listen_fd = -1;
  fd_failover_tls_ctx_fini( &ch->tls_ctx );
}

void
fd_failover_channel_set_role( fd_failover_channel_t * ch,
                              ulong                   role ) {
  ch->self_hello.role = (uchar)role;
}

FD_FN_PURE ulong fd_failover_channel_state    ( fd_failover_channel_t const * ch ) { return ch->state;     }
FD_FN_PURE int   fd_failover_channel_listen_fd( fd_failover_channel_t const * ch ) { return ch->listen_fd; }

FD_FN_PURE int
fd_failover_channel_tx_pending( fd_failover_channel_t const * ch ) {
  if( ch->active<0 ) return 0;
  struct candidate const * c = &ch->candidates[ch->active];
  return !!c->tx_used || fd_tlsrec_sock_tx_pending( &c->tls.sock );
}

FD_FN_PURE ulong
fd_failover_channel_pending( fd_failover_channel_t const * ch ) {
  ulong n = 0UL;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) n += ch->candidates[i].fd!=-1 && (int)i!=ch->active;
  return n;
}

FD_FN_PURE fd_failover_hello_t const *           fd_failover_channel_peer_hello( fd_failover_channel_t const * ch ) { return &ch->peer_hello; }
FD_FN_PURE fd_failover_channel_metrics_t const * fd_failover_channel_metrics   ( fd_failover_channel_t const * ch ) { return &ch->metrics;    }

ushort
fd_failover_channel_listen_port( fd_failover_channel_t const * ch ) {
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  if( getsockname( ch->listen_fd, fd_type_pun( &addr ), &len ) ) FD_LOG_ERR(( "failover getsockname failed" ));
  return fd_ushort_bswap( addr.sin_port );
}

/* Spreads a redial over up to one minimum backoff, so two standbys that
   dial each other do not keep colliding in step. */
static long
jitter( fd_failover_channel_t const * ch ) {
  ulong r = 0UL;
  if( FD_UNLIKELY( ch->backoff_min<=0L || !fd_rng_secure( &r, sizeof(r) ) ) ) return 0L;
  return (long)( r%(ulong)ch->backoff_min );
}

/* Distinct profile and authentication failures remain visible even when
   another TLS error is already being suppressed.  The number of buckets
   is fixed, so unknown peers cannot allocate log state or flood it. */
static ulong
tls_log_kind( uint reason ) {
  if( !reason ) return 0UL;
  if( reason==FD_TLS_REASON_ALPN_PARSE || reason==FD_TLS_REASON_ALPN_NEG || reason==FD_TLS_REASON_NO_ALPN ) return 1UL;
  if( reason==FD_TLS_REASON_WRONG_PUBKEY || reason==FD_TLS_REASON_ED25519_FAIL || reason==FD_TLS_REASON_CERT_VERIFY ) return 2UL;
  return 3UL;
}

/* Every state change goes through the session machine in
   fd_failover_proto.c, so that table is the one description of the
   channel's behavior. */
static void
drop( fd_failover_channel_t * ch,
      ulong                   idx,
      long                    now,
      int                     event ) {
  struct candidate * c = &ch->candidates[idx];
  int paired   = ch->active==(int)idx;
  int accepted = c->fd!=-1 && !c->dialed;
  close_candidate( c );
  if( paired ) {
    ch->active = -1;
    ch->last_rx = 0L;
    fd_memset( &ch->peer_hello, 0, sizeof(ch->peer_hello) );
  }
  /* A candidate from the listener does not move the session until it
     pairs. */
  if( !paired && accepted ) return;
  ch->state = fd_failover_session_step( ch->state, ch->dial_peer, event );
  if( paired && want_dial( ch )!=ch->dial_peer ) rest( ch );
  if( ch->dial_peer ) {
    /* Only a session that outlived the handshake window counts as
       established, also one that paired from the listener.  Losing one
       redials at once and resets the backoff, anything shorter keeps
       doubling it, so a peer that rejects right after HELLO cannot drive
       a redial storm.  The jitter breaks the step of two standbys that
       each pair the other's dial and close their own. */
    int established = paired && now>=ch->paired_at && now-ch->paired_at>=ch->hello_timeout;
    ch->retry_at = fd_long_sat_add( now, fd_long_sat_add( established ? 0L : ch->backoff, jitter( ch ) ) );
    ch->backoff  = established ? ch->backoff_min : fd_long_min( fd_long_sat_add( ch->backoff, ch->backoff ), ch->backoff_max );
  }
}

enum {
  LOSS_TRANSPORT,
  LOSS_SILENCE,
  LOSS_TLS,
  LOSS_PROTOCOL,
  LOSS_FRAME,
  LOSS_LOCAL_ENCODE
};

/* Same as drop, and if idx is the paired session we log why it ended. */
static void
lose( fd_failover_channel_t * ch,
      ulong                   idx,
      long                    now,
      int                     event,
      ulong                   cause,
      char const *            why ) {
  ulong suppressed;
  if( ch->active==(int)idx && fd_failover_log_take( &ch->loss_log[cause], now, &suppressed ) ) {
    FD_LOG_WARNING(( "lost the failover session with `" FD_IP4_ADDR_FMT "`, %s, repeated failures limited to one line per minute (%lu suppressed)",
                     FD_IP4_ADDR_FMT_ARGS( ch->candidates[idx].address ), why, suppressed ));
  }
  drop( ch, idx, now, event );
}

void
fd_failover_channel_hangup( fd_failover_channel_t * ch,
                            long                    now ) {
  if( ch->active>=0 ) drop( ch, (ulong)ch->active, now, FD_FAILOVER_EV_LINK_LOST );
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( ch->candidates[i].fd!=-1 ) drop( ch, i, now, FD_FAILOVER_EV_LINK_LOST );
}

void
fd_failover_channel_protocol_error( fd_failover_channel_t * ch,
                                    long                    now ) {
  ch->metrics.wire_fatal_cnt++;
  if( FD_LIKELY( ch->active>=0 ) ) {
    lose( ch, (ulong)ch->active, now, FD_FAILOVER_EV_LINK_LOST, LOSS_PROTOCOL, "it sent a message that breaks the protocol, check that both machines run the same Firedancer version" );
  }
  fd_failover_channel_hangup( ch, now );
}

static ulong
refill( ulong  credit,
        long * updated,
        long   now,
        ulong  rate,
        ulong  burst ) {
  if( now>*updated ) {
    /* Bound elapsed time before multiplying the scaled token count. */
    ulong elapsed = fd_ulong_min( (ulong)now-(ulong)*updated, 1000000000UL );
    credit = fd_ulong_min( credit+elapsed*rate, burst*1000000000UL );
    *updated = now;
  }
  return credit;
}

static int
admit( fd_failover_channel_t * ch,
       uint                    address,
       long                    now ) {
  int peer = ch->expect_addr && address==ch->expect_addr;
  ch->rate_credit = refill( ch->rate_credit, &ch->rate_updated, now, 32UL, 16UL );
  if( !peer && ch->rate_credit<1000000000UL ) return 0;
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
  if( !peer ) ch->rate_credit -= 1000000000UL;
  return 1;
}

/* A full table does not keep the expected peer out.  The oldest
   candidate from another address makes room, so holding every slot from
   other addresses only ever costs the holder a slot. */
static ulong
evict_for_peer( fd_failover_channel_t * ch,
                uint                    address,
                long                    now ) {
  if( !ch->expect_addr || address!=ch->expect_addr ) return FD_FAILOVER_CHANNEL_CANDIDATE_MAX;
  ulong victim = FD_FAILOVER_CHANNEL_CANDIDATE_MAX;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    struct candidate * c = &ch->candidates[i];
    if( c->fd==-1 || (int)i==ch->active || c->address==ch->expect_addr ) continue;
    if( victim==FD_FAILOVER_CHANNEL_CANDIDATE_MAX || c->deadline<ch->candidates[victim].deadline ) victim = i;
  }
  if( victim==FD_FAILOVER_CHANNEL_CANDIDATE_MAX ) return victim;
  ch->metrics.evicted_cnt++;
  drop( ch, victim, now, FD_FAILOVER_EV_TIMEOUT );
  return victim;
}

/* A full table does not keep our dial out.  The oldest candidate from
   the listener makes room, so holding every slot only ever costs the
   holder a slot. */
static ulong
dial_slot( fd_failover_channel_t * ch,
           long                    now ) {
  ulong victim = FD_FAILOVER_CHANNEL_CANDIDATE_MAX;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    struct candidate * c = &ch->candidates[i];
    if( c->fd==-1 ) return i;
    if( (int)i==ch->active || c->dialed ) continue;
    if( victim==FD_FAILOVER_CHANNEL_CANDIDATE_MAX || c->deadline<ch->candidates[victim].deadline ) victim = i;
  }
  if( victim==FD_FAILOVER_CHANNEL_CANDIDATE_MAX ) return victim;
  ch->metrics.evicted_cnt++;
  drop( ch, victim, now, FD_FAILOVER_EV_TIMEOUT );
  return victim;
}

static int
start( fd_failover_channel_t * ch,
       ulong                   idx,
       int                     fd,
       uint                    address,
       long                    now,
       int                     phase ) {
  struct candidate * c = &ch->candidates[idx];
  c->fd = fd; c->address = address; c->phase = phase; c->dialed = phase==PHASE_CONNECT;
  c->deadline = fd_long_sat_add( now, ch->hello_timeout );
  fd_failover_wire_session_init( &c->wire );
  ch->metrics.connection_attempt_cnt++;
  if( fd_failover_tls_new( &c->tls, &ch->tls_ctx, fd, c->dialed ) ) {
    ch->metrics.tls_fail_cnt++;
    drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
    return -1;
  }
  return 0;
}

static void
accept_candidates( fd_failover_channel_t * ch,
                   long                    now,
                   int *                   busy ) {
  for( ulong n=0; n<8UL; n++ ) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = accept4( ch->listen_fd, fd_type_pun( &addr ), &len, SOCK_NONBLOCK|SOCK_CLOEXEC );
    if( fd==-1 ) return;
    *busy = 1;
    ulong idx = 0UL;
    while( idx<FD_FAILOVER_CHANNEL_CANDIDATE_MAX && ch->candidates[idx].fd!=-1 ) idx++;
    if( idx==FD_FAILOVER_CHANNEL_CANDIDATE_MAX && ch->active<0 && len==sizeof(addr) && addr.sin_family==AF_INET )
      idx = evict_for_peer( ch, addr.sin_addr.s_addr, now );
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
flush( fd_failover_channel_t * ch,
       ulong                   idx,
       long                    now,
       int *                   busy ) {
  struct candidate * c = &ch->candidates[idx];
  if( !c->tx_used ) {
    int rc = fd_tlsrec_sock_flush( &c->tls.sock, c->fd );
    if( rc<0 ) { lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_TRANSPORT, "flushing TLS output failed" ); return -1; }
    return rc;
  }
  long n = fd_failover_tls_write( &c->tls, c->tx+c->tx_sent, c->tx_used-c->tx_sent );
  if( n<0L ) { lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_TRANSPORT, "writing to it failed, check that the peer runs and that the machines can reach each other" ); return -1; }
  if( !n ) return 1;
  *busy = 1;
  c->tx_sent += (ulong)n;
  if( c->tx_sent<c->tx_used ) return 1;
  c->tx_used = c->tx_sent = 0UL;
  ch->metrics.frames_sent++;
  return fd_tlsrec_sock_tx_pending( &c->tls.sock ) ? 1 : 0;
}

static int
decode( fd_failover_channel_t * ch,
        ulong                   idx,
        long                    now,
        int *                   busy,
        ushort *                type,
        uchar *                 payload,
        ulong *                 payload_sz ) {
  struct candidate * c = &ch->candidates[idx];
  uchar const * data;
  ulong frame_sz;
  int err = fd_failover_wire_decode( &c->wire, c->rx, c->rx_used, type, &data, payload_sz, &frame_sz );
  if( err==FD_FAILOVER_WIRE_ERR_AGAIN ) return 0;
  if( err ) { ch->metrics.wire_fatal_cnt++; lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_FRAME, "it sent a malformed frame, check that both machines run the same Firedancer version" ); return -1; }
  fd_memcpy( payload, data, *payload_sz );
  memmove( c->rx, c->rx+frame_sz, c->rx_used-frame_sz );
  c->rx_used -= frame_sz;
  ch->metrics.frames_received++;
  *busy = 1;
  return 1;
}

/* Names for the log, never numbers, and what the operator should check. */
static char const *
hello_err_name( int err ) {
  switch( err ) {
  case HELLO_ERR_TLS_KEY:                return "its junk key is not the key TLS authenticated, check who can reach the failover port";
  case FD_FAILOVER_HELLO_ERR_VERSION:    return "the protocol version differs, run the same Firedancer version on both machines";
  case FD_FAILOVER_HELLO_ERR_STAKED:     return "the staked identity differs, check that [paths.identity_key] is the same keypair on both machines";
  case FD_FAILOVER_HELLO_ERR_VOTE_ACCT:  return "the vote account differs, check that [paths.vote_account] is the same on both machines";
  case FD_FAILOVER_HELLO_ERR_JUNK_EQ:    return "its junk key is ours, give each machine its own [failover.junk_identity_key] and check that [failover.peer_address] is the other machine";
  case FD_FAILOVER_HELLO_ERR_JUNK_STAKE: return "a junk key is the staked key, [failover.junk_identity_key] must not be the staked [paths.identity_key]";
  case FD_FAILOVER_HELLO_ERR_BOTH_ACT:   return "both members are active, only one machine may run the staked identity, run `failover demote` on the other";
  case FD_FAILOVER_HELLO_ERR_ROLE:       return "the role is unknown, run the same Firedancer version on both machines";
  case FD_FAILOVER_HELLO_ERR_BOOT_ID:    return "the boot id is zero, run the same Firedancer version on both machines";
  case FD_FAILOVER_HELLO_ERR_CFG:        return "the config hash differs, run the same Firedancer version on both machines";
  case FD_FAILOVER_HELLO_ERR_MODE:       return "the consensus mode differs, run both machines in the same consensus mode";
  case FD_FAILOVER_HELLO_ERR_CERT:       return "its member certificate is not signed by our staked key, check that [paths.identity_key] is the same keypair on both machines";
  default:                               return "unknown";
  }
}

static int
read_frame( fd_failover_channel_t * ch,
            ulong                   idx,
            long                    now,
            int *                   busy,
            ushort *                type,
            uchar *                 payload,
            ulong *                 payload_sz ) {
  struct candidate * c = &ch->candidates[idx];
  int rc = decode( ch, idx, now, busy, type, payload, payload_sz );
  if( rc ) return rc;
  ulong max = ch->active==(int)idx ? sizeof(c->rx) : FD_FAILOVER_FRAME_HDR_SZ+sizeof(fd_failover_hello_t);
  if( c->rx_used>=max ) { ch->metrics.wire_fatal_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return -1; }
  long n = fd_failover_tls_read( &c->tls, c->rx+c->rx_used, max-c->rx_used );
  if( n<0L ) {
    /* The listener answers only a HELLO it accepts, so a close here
       usually means it refused ours. */
    ulong suppressed;
    if( FD_UNLIKELY( c->dialed && c->phase==PHASE_HELLO && fd_failover_log_take( &ch->dial_log[1], now, &suppressed ) ) ) {
      FD_LOG_WARNING(( "the failover peer at `" FD_IP4_ADDR_FMT "` closed the connection before answering our HELLO, its log says why it refused us (%lu repeats suppressed)",
                       FD_IP4_ADDR_FMT_ARGS( c->address ), suppressed ));
    }
    if( ch->active==(int)idx && ch->expected_close && c->tls.peer_closed && !fd_failover_channel_tx_pending( ch ) ) {
      drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
      return -1;
    }
    if( fd_tlsrec_conn_is_failed( &c->tls.conn ) ) {
      char why[192];
      fd_cstr_printf( why, sizeof(why), NULL, "TLS record rejected (%s), check the peer log and matching protocol versions",
                      fd_tls_reason_cstr( c->tls.conn.hs.base.reason ) );
      lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_TLS, why );
    } else {
      lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_TRANSPORT, "the connection closed, check that the peer runs and that the machines can reach each other" );
    }
    return -1;
  }
  if( n>0L ) { c->rx_used += (ulong)n; *busy = 1; }
  return decode( ch, idx, now, busy, type, payload, payload_sz );
}

static void
service_candidate( fd_failover_channel_t * ch,
                   ulong                   idx,
                   long                    now,
                   int *                   busy,
                   uchar *                 payload ) {
  struct candidate * c = &ch->candidates[idx];
  fd_failover_tls_budget( &c->tls );
  if( c->phase==PHASE_CONNECT ) {
    struct sockaddr_in addr = { .sin_family=AF_INET, .sin_port=fd_ushort_bswap( ch->peer_port ), .sin_addr.s_addr=ch->peer_addr };
    if( connect( c->fd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EISCONN ) {
      if( errno==EINPROGRESS || errno==EALREADY || errno==EINTR ) return;
      ulong suppressed;
      if( fd_failover_log_take( &ch->dial_log[0], now, &suppressed ) ) {
        FD_LOG_WARNING(( "could not connect to the failover peer at `" FD_IP4_ADDR_FMT ":%hu` (%i-%s), check that it runs and that the machines can reach each other on [failover.port] (%lu repeats suppressed)",
                         FD_IP4_ADDR_FMT_ARGS( ch->peer_addr ), ch->peer_port, errno, fd_io_strerror( errno ), suppressed ));
      }
      drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return;
    }
    c->phase = PHASE_TLS;
    ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_CONNECTED );
  }
  if( c->phase==PHASE_TLS ) {
    int rc = fd_failover_tls_handshake( &c->tls );
    if( rc<0 ) {
      ch->metrics.tls_fail_cnt++;
      ulong suppressed;
      uint reason = c->tls.conn.hs.base.reason;
      if( fd_failover_log_take( &ch->tls_log[tls_log_kind( reason )], now, &suppressed ) )
        FD_LOG_WARNING(( "TLS handshake with `" FD_IP4_ADDR_FMT "` failed (%s), check peer reachability, junk keys and matching connection modes on both machines (%lu repeats suppressed)",
                         FD_IP4_ADDR_FMT_ARGS( c->address ), reason ? fd_tls_reason_cstr( reason ) : "connection closed or socket error", suppressed ));
      drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
      return;
    }
    if( !rc ) return;
    *busy = 1;
    c->phase = PHASE_HELLO;
    /* The dialer sends first.  On the listener we answer only a HELLO
       that passed the checks below. */
    if( c->dialed ) c->tx_used = fd_failover_wire_encode( &c->wire, c->tx, FD_FAILOVER_MSG_HELLO,
                                                          (uchar const *)&ch->self_hello, sizeof(ch->self_hello) );
  }
  if( flush( ch, idx, now, busy )!=0 ) return;
  if( c->phase==PHASE_HELLO ) {
    ushort type;
    ulong sz;
    if( read_frame( ch, idx, now, busy, &type, payload, &sz )<=0 ) return;
    if( type!=FD_FAILOVER_MSG_HELLO || sz!=sizeof(c->hello) ) {
      ulong suppressed;
      if( fd_failover_log_take( &ch->hello_log[0], now, &suppressed ) ) FD_LOG_WARNING(( "rejected the failover HELLO from `" FD_IP4_ADDR_FMT "`, its first frame is not a HELLO, check who can reach the failover port (%lu repeats suppressed)", FD_IP4_ADDR_FMT_ARGS( c->address ), suppressed ));
      ch->metrics.wire_fatal_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_HELLO_FATAL ); return;
    }
    fd_memcpy( &c->hello, payload, sizeof(c->hello) );
    /* HELLO has to name the key TLS authenticated, and the member
       certificate proves the peer holds the staked key. */
    int err = fd_memeq( c->hello.junk_pubkey, c->tls.peer_pubkey, 32UL ) ? fd_failover_hello_check( &ch->self_hello, &c->hello ) : HELLO_ERR_TLS_KEY;
    if( err==FD_FAILOVER_HELLO_OK ) err = fd_failover_member_cert_check( &c->hello, ch->sha );
    if( err!=FD_FAILOVER_HELLO_OK ) {
      ulong suppressed;
      ulong bucket = err==HELLO_ERR_TLS_KEY ? 12UL : ( err>0 && err<=FD_FAILOVER_HELLO_ERR_CERT ? (ulong)err : 13UL );
      if( fd_failover_log_take( &ch->hello_log[bucket], now, &suppressed ) ) FD_LOG_WARNING(( "rejected the failover HELLO from `" FD_IP4_ADDR_FMT "`, %s (%lu repeats suppressed)", FD_IP4_ADDR_FMT_ARGS( c->address ), hello_err_name( err ), suppressed ));
      ch->metrics.hello_reject_cnt++; drop( ch, idx, now, FD_FAILOVER_EV_HELLO_FATAL ); return;
    }
    c->phase = PHASE_READY;
    if( !c->dialed ) {
      c->tx_used = fd_failover_wire_encode( &c->wire, c->tx, FD_FAILOVER_MSG_HELLO,
                                            (uchar const *)&ch->self_hello, sizeof(ch->self_hello) );
      if( flush( ch, idx, now, busy )!=0 ) return;
    }
  }
  if( c->phase==PHASE_READY && !c->tx_used ) {
    /* The first session that authenticates wins.  One that came in on the
       listener while we were dialing pairs as the listener. */
    for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( i!=idx ) close_candidate( &ch->candidates[i] );
    if( !c->dialed && ch->dial_peer ) {
      ch->dial_peer = 0;
      ch->state     = fd_failover_session_init( ch->dial_peer );
    }
    ch->active = (int)idx;
    c->tls.paired = 1;
    ch->peer_hello = c->hello;
    ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_HELLO_OK );
    ch->metrics.paired_cnt++;
    ch->last_rx   = now;
    ch->paired_at = now;
    ch->expected_close = 0;
    *busy = 1;
    ulong suppressed;
    if( fd_failover_log_take( &ch->pair_log, now, &suppressed ) ) {
      char member[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( c->hello.junk_pubkey, NULL, member );
      FD_LOG_NOTICE(( "paired with the failover peer at `" FD_IP4_ADDR_FMT "` via %s, authenticated member %s, role %s, boot id %016lx (%lu repeat pairings suppressed)",
                      FD_IP4_ADDR_FMT_ARGS( c->address ), c->dialed ? "outbound dial" : "listener", member,
                      c->hello.role==FD_FAILOVER_ROLE_ACTIVE ? "active" : "standby", c->hello.boot_id, suppressed ));
    }
  }
}

int
fd_failover_channel_poll( fd_failover_channel_t * ch,
                          long                    now,
                          int *                   busy,
                          ushort *                type,
                          uchar *                 payload,
                          ulong *                 payload_sz ) {
  int delivered = 0;
  /* Established traffic gets service before the bounded accept drain. */
  if( ch->active>=0 ) {
    ulong idx = (ulong)ch->active;
    fd_failover_tls_budget( &ch->candidates[idx].tls );
    int flushed = flush( ch, idx, now, busy );
    if( !flushed ) {
      int rc = read_frame( ch, idx, now, busy, type, payload, payload_sz );
      if( rc>0 ) {
        if( *type==FD_FAILOVER_MSG_HELLO ) { ch->metrics.wire_fatal_cnt++; lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_PROTOCOL, "it sent a second HELLO, check that both machines run the same Firedancer version" ); }
        else { ch->last_rx = now; delivered = 1; }
      } else if( !rc && now>=ch->last_rx && now-ch->last_rx>ch->silence_timeout ) {
        lose( ch, idx, now, FD_FAILOVER_EV_TIMEOUT, LOSS_SILENCE, "the handoff connection was idle past its deadline, check the peer log" );
      }
    }
    if( flushed>0 && now>=ch->last_rx && now-ch->last_rx>ch->silence_timeout ) {
      lose( ch, idx, now, FD_FAILOVER_EV_TIMEOUT, LOSS_SILENCE, "the handoff connection stopped making progress, check the peer log" );
    }
  }
  /* Expire every slot each poll, independently of round-robin service. */
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    struct candidate * c = &ch->candidates[i];
    if( c->fd!=-1 && (int)i!=ch->active && now>=c->deadline ) {
      ulong suppressed;
      if( c->dialed && fd_failover_log_take( &ch->dial_log[2], now, &suppressed ) ) {
        FD_LOG_WARNING(( "the failover peer at `" FD_IP4_ADDR_FMT "` did not finish the handshake in time, check that it runs and that the machines can reach each other on [failover.port] (%lu repeats suppressed)",
                         FD_IP4_ADDR_FMT_ARGS( c->address ), suppressed ));
      }
      ch->metrics.handshake_timeout_cnt++; drop( ch, i, now, FD_FAILOVER_EV_TIMEOUT ); *busy = 1;
    }
  }
  /* Nothing starts before we have our member certificate.  Every member
     drains accepts, and a standby that knows the active's address also
     starts a connection once the backoff ends. */
  if( FD_UNLIKELY( !ch->member_cert_set ) ) return delivered;
  if( ch->listen_fd!=-1 ) accept_candidates( ch, now, busy );
  if( ch->dial_peer && ch->state==FD_FAILOVER_SESSION_BACKOFF && now>=ch->retry_at && ch->tls_ctx.ready && ch->peer_addr ) {
    ulong idx = dial_slot( ch, now );
    if( FD_UNLIKELY( idx==FD_FAILOVER_CHANNEL_CANDIDATE_MAX ) ) return delivered;
    int fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
    *busy = 1;
    if( fd==-1 ) { drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return delivered; }
    ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_RETRY );
    start( ch, idx, fd, ch->peer_addr, now, PHASE_CONNECT );
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
fd_failover_channel_send( fd_failover_channel_t * ch,
                          long                    now,
                          ushort                  type,
                          uchar const *           payload,
                          ulong                   sz ) {
  if( ch->active<0 ) return -1;
  ulong idx = (ulong)ch->active;
  struct candidate * c = &ch->candidates[idx];
  if( c->tx_used ) return -1;
  c->tx_used = fd_failover_wire_encode( &c->wire, c->tx, type, payload, sz );
  if( !c->tx_used ) { lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_LOCAL_ENCODE, "we could not encode a frame for it" ); return -1; }
  int busy = 0;
  int rc = flush( ch, idx, now, &busy )<0 ? -1 : 0;
  if( !rc && FD_FAILOVER_ON_DEMAND && type==FD_FAILOVER_MSG_HANDOFF_RESULT ) ch->expected_close = 1;
  return rc;
}
