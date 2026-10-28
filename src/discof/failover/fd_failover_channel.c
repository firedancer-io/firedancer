#define _GNU_SOURCE
#include "fd_failover_channel.h"
#include "fd_failover_tls.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../waltz/tls/fd_tls_proto.h"
#include "../../waltz/fd_token_bucket.h"
#include "../../disco/bundle/fd_keepalive.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* Candidate slots. */
#define OUTBOUND_IDX         (0UL)
#define ADMITTED_IDX         (1UL)
#define UNAUTHENTICATED_IDX  (2UL)

/* TLS admission phase FSM states. */
#define PHASE_CONNECT        (0)
#define PHASE_START_SEND     (1)
#define PHASE_START_RECV     (2)
#define PHASE_CHALLENGE_SEND (3)
#define PHASE_CHALLENGE_RECV (4)
#define PHASE_REQUEST_SIGN   (5)
#define PHASE_REQUEST_SEND   (6)
#define PHASE_REQUEST_RECV   (7)
#define PHASE_RESPONSE_SIGN  (8)
#define PHASE_RESPONSE_SEND  (9)
#define PHASE_RESPONSE_RECV  (10)
#define PHASE_TLS_START      (11)
#define PHASE_TLS            (12)
#define PHASE_HELLO          (13)
#define PHASE_READY          (14)

/* Bounds. */
FD_STATIC_ASSERT( FD_FAILOVER_CHANNEL_CANDIDATE_MAX>UNAUTHENTICATED_IDX, admission_pool_capacity );
FD_STATIC_ASSERT( FD_FAILOVER_CHANNEL_KEEPALIVE_NANOS>=2L && FD_FAILOVER_CHANNEL_IDLE_NANOS>0L, keepalive_params );

FD_STATIC_ASSERT( FD_KEYGUARD_FAILOVER_PROOF_SZ<=FD_TLS_CV_SIGN_SZ, admission_sign_mtu );
FD_STATIC_ASSERT( FD_FAILOVER_CLIENT_HELLO_MAX+sizeof(fd_tlsrec_hdr_t)+sizeof(fd_failover_admission_start_t)<=FD_FAILOVER_ADMISSION_MAX, admission_buffer );

/* A HELLO whose junk key does not match the key that was TLS authenticated */
#define HELLO_ERR_TLS_KEY (-1)

struct candidate {
  int                               fd;          /* -1 for an unused candidate. */
  int                               phase;       /* PHASE_* */
  int                               dialed;      /* we dialed it, else the listener accepted it */
  uint                              address;
  long                              deadline;
  long                              admission_until;
  int                               tls_started; /* tls is initialized, close_candidate must fini it */
  fd_failover_hello_t               local_hello;
  fd_failover_admission_start_t     start;
  fd_failover_admission_challenge_t challenge;
  uchar                             client_hello[ FD_FAILOVER_CLIENT_HELLO_MAX+sizeof(fd_tlsrec_hdr_t) ];
  uchar                             transcript[ 32 ];
  uchar                             client_proof[ 64 ];
  fd_failover_tls_t                 tls;
  fd_failover_hello_t               hello;
  uchar                             rx[ FD_FAILOVER_FRAME_MAX ];
  uchar                             tx[ FD_FAILOVER_FRAME_MAX ];
  ulong                             rx_used;
  ulong                             tx_used;
  ulong                             tx_sent;
};

struct fd_failover_channel {
  /* Session */
  ulong                          magic;              /* FD_FAILOVER_CHANNEL_MAGIC once initialized */
  int                            dial_peer;          /* the session machine runs as the dialer */
  uint                           peer_addr;          /* the dial destination, zero when we do not dial */
  ushort                         peer_port;          /* the dial destination port */
  int                            listen_fd;          /* listening socket, -1 until it is open */
  int                            paired_idx;         /* the paired candidate, -1 while none is paired */
  ulong                          cursor;             /* the next unauthenticated candidate idx to service */

  /* Credentials */
  fd_failover_tls_ctx_t          tls_ctx;            /* TLS template every connection starts from */
  fd_failover_hello_t            self_hello;         /* the HELLO we send */
  fd_failover_hello_t            peer_hello;         /* the paired peer's HELLO, zero while unpaired */
  fd_failover_proof_signer_t     proof_signer;       /* signs our admission proofs in the sign tile */
  fd_sha512_t                    sha[ 1 ];           /* scratch hash for checking admission proofs */

  /* Connections */
  struct candidate               candidates[ FD_FAILOVER_CHANNEL_CANDIDATE_MAX ]; /* connections that are handshaking or paired */
  uint                           known_addr;         /* the last address that authenticated, gets the ADMITTED slot ahead of admission */
  long                           known_until;        /* until when */

  /* Rate limits */
  fd_token_bucket_t              accept_bucket;      /* accept syscalls */
  fd_token_bucket_t              admit_bucket;       /* candidates started */
  fd_token_bucket_t              verify_bucket;      /* Ed25519 proof checks and signs, at most one per poll */
  int                            verify_budget;      /* proof checks left this poll */

  /* Timers */
  fd_keepalive_t                 keepalive[ 1 ];     /* when the paired session last heard from the peer / pings it next */
  fd_rng_t                       rng[ 1 ];           /* spreads redials and KEEPALIVEs, not for secure RNG */
  long                           retry_at;           /* when the dialer dials again */
  long                           paired_at;          /* when the current session paired */
  long                           backoff;            /* the current dial backoff, doubles up to BACKOFF_MAX */

  /* The paired session */
  int                            expected_close;     /* RESULT was sent, peer may close normally */
  ulong                          generation;         /* identifies the current authenticated session */
};

FD_FN_CONST ulong fd_failover_channel_align    ( void ) { return alignof(fd_failover_channel_t); }
FD_FN_CONST ulong fd_failover_channel_footprint( void ) { return sizeof (fd_failover_channel_t); }

/* A bucket of burst tokens refilling at `rate` per second. */
static fd_token_bucket_t
token_bucket_new( ulong rate,
                  ulong burst ) {
  return (fd_token_bucket_t){ .rate=(float)rate/(float)FD_FAILOVER_NANOS_PER_SECOND, .burst=(float)burst, .balance=(float)burst };
}

void *
fd_failover_channel_new( void * shmem ) {
  if( !shmem || !fd_ulong_is_aligned( (ulong)shmem, fd_failover_channel_align() ) ) return NULL;
  fd_failover_channel_t * ch = shmem;

  /* Initialize the listening state. */
  fd_memset( ch, 0, sizeof(*ch) );
  ch->listen_fd  = -1;
  ch->paired_idx = -1;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) ch->candidates[i].fd = -1;
  ch->backoff = FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS;

  /* Rate limiting */
  ch->accept_bucket = token_bucket_new( FD_FAILOVER_ACCEPT_RATE, FD_FAILOVER_ACCEPT_BURST );
  ch->admit_bucket  = token_bucket_new( FD_FAILOVER_ADMIT_RATE,  FD_FAILOVER_ADMIT_BURST  );
  ch->verify_bucket = token_bucket_new( FD_FAILOVER_VERIFY_RATE, FD_FAILOVER_VERIFY_BURST );

  /* Set up secure randomness */
  uint seed;
  FD_TEST( fd_rng_secure( &seed, sizeof(seed) ) );
  FD_TEST( fd_rng_join( fd_rng_new( ch->rng, seed, 0UL ) ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ch->sha ) ) );

  ch->magic = FD_FAILOVER_CHANNEL_MAGIC;
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
  if( c->tls_started ) fd_failover_tls_fini( &c->tls );
  c->tls_started = 0;
  if( c->fd!=-1 ) close( c->fd );
  /* Closing a candidate frees its slot. */
  c->fd      = -1;
  c->dialed  = 0;
  c->rx_used = c->tx_used = c->tx_sent = 0UL;
}

/* Discards every candidate and the pairing. */
static void
discard( fd_failover_channel_t * ch ) {
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) close_candidate( &ch->candidates[i] );
  ch->paired_idx = -1;
  fd_memset( &ch->peer_hello, 0, sizeof(ch->peer_hello) );
}

static int
want_dial( fd_failover_channel_t const * ch ) {
  return !!ch->peer_addr;
}

/* Resets an unpaired channel: drops any dial in flight and goes back
   to listening, or to an immediate redial when a dial address is set. */
static void
reset( fd_failover_channel_t * ch ) {
  if( ch->paired_idx>=0 ) return;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    if( ch->candidates[i].dialed ) {
      close_candidate( &ch->candidates[i] );
    }
  }
  ch->dial_peer = want_dial( ch );
  ch->retry_at  = 0L;
}

void
fd_failover_channel_init_listener( fd_failover_channel_t * ch,
                                   uint                    address,
                                   ushort                  port ) {
  discard( ch );
  reset( ch );
  if( ch->listen_fd!=-1 ) return;
  ch->listen_fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( ch->listen_fd==-1 ) {
    FD_LOG_ERR(( "failover socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  int yes = 1;
  if( setsockopt( ch->listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes) ) ) {
    FD_LOG_ERR(( "failover setsockopt failed" ));
  }
  if( setsockopt( ch->listen_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes) ) ) {
    FD_LOG_ERR(( "failover setsockopt(TCP_NODELAY) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  struct sockaddr_in addr = { .sin_family=AF_INET, .sin_port=fd_ushort_bswap( port ), .sin_addr.s_addr=address };
  if( bind( ch->listen_fd, fd_type_pun( &addr ), sizeof(addr) ) || listen( ch->listen_fd, FD_FAILOVER_LISTEN_BACKLOG ) ) {
    FD_LOG_ERR(( "could not listen on `" FD_IP4_ADDR_FMT ":%hu` (%i-%s)",
                 FD_IP4_ADDR_FMT_ARGS( address ), port, errno, fd_io_strerror( errno ) ));
  }
}

void
fd_failover_channel_init_dialer( fd_failover_channel_t * ch,
                                 uint                    address,
                                 ushort                  port ) {
  if( address==ch->peer_addr && port==ch->peer_port ) return;
  if( address && ch->paired_idx>=0 ) discard( ch );
  ch->peer_addr = address;
  ch->peer_port = port;
  if( address ) {
    ch->backoff = FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS;
  }
  reset( ch );
}

int
fd_failover_channel_set_identity( fd_failover_channel_t *     ch,
                                  uchar const                 junk_pubkey[ 32 ],
                                  fd_tls_sign_t               signer,
                                  fd_failover_proof_signer_t  proof_signer,
                                  fd_failover_hello_t const * hello ) {
  if( !proof_signer.sign_fn || !signer.sign_fn ||
      !fd_memeq( junk_pubkey, hello->junk_pubkey, 32UL ) ||
      fd_memeq( hello->junk_pubkey, hello->staked_pubkey, 32UL ) ) return -1;
  discard( ch );
  /* An identity change requires a fresh session. */
  ch->known_addr   = 0U;
  ch->known_until  = 0L;
  ch->self_hello   = *hello;
  ch->proof_signer = proof_signer;
  return fd_failover_tls_ctx_init( &ch->tls_ctx, junk_pubkey, signer );
}

void
fd_failover_channel_fini( fd_failover_channel_t * ch ) {
  discard( ch );
  if( ch->listen_fd!=-1 ) close( ch->listen_fd );
  ch->listen_fd = -1;
  fd_failover_tls_ctx_fini( &ch->tls_ctx );
}

void
fd_failover_channel_set_holds( fd_failover_channel_t * ch,
                               int                     holds ) {
  if( ch->self_hello.holds==(uchar)!!holds ) return;
  ch->self_hello.holds = (uchar)!!holds;
  for( ulong i=0UL; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ )
    if( (int)i!=ch->paired_idx ) close_candidate( &ch->candidates[i] );
  if( ch->paired_idx<0 ) reset( ch );
}

/* Derive the session state from the socket state. */
FD_FN_PURE ulong
fd_failover_channel_state( fd_failover_channel_t const * ch ) {
  if( ch->paired_idx>=0 ) return FD_FAILOVER_SESSION_PAIRED;
  if( !ch->dial_peer    ) return FD_FAILOVER_SESSION_LISTENING;
  struct candidate const * c = &ch->candidates[OUTBOUND_IDX];
  if( c->fd==-1                 ) return FD_FAILOVER_SESSION_BACKOFF;
  if( c->phase==PHASE_CONNECT   ) return FD_FAILOVER_SESSION_DIALING;
  return FD_FAILOVER_SESSION_HELLO;
}

FD_FN_PURE int fd_failover_channel_listen_fd( fd_failover_channel_t const * ch ) { return ch->listen_fd; }

FD_FN_PURE int
fd_failover_channel_tx_pending( fd_failover_channel_t const * ch ) {
  if( ch->paired_idx<0 ) return 0;
  struct candidate const * c = &ch->candidates[ch->paired_idx];
  return !!c->tx_used || fd_tlsrec_sock_tx_pending( &c->tls.sock );
}

FD_FN_PURE fd_failover_hello_t const *           fd_failover_channel_peer_hello( fd_failover_channel_t const * ch ) { return &ch->peer_hello; }
FD_FN_PURE ulong fd_failover_channel_generation( fd_failover_channel_t const * ch ) { return ch->generation; }

ushort
fd_failover_channel_listen_port( fd_failover_channel_t const * ch ) {
  struct sockaddr_in addr;
  socklen_t          len = sizeof(addr);
  if( getsockname( ch->listen_fd, fd_type_pun( &addr ), &len ) ) FD_LOG_ERR(( "failover getsockname failed" ));
  return fd_ushort_bswap( addr.sin_port );
}

static void
drop( fd_failover_channel_t * ch,
      ulong                   idx,
      long                    now ) {
  struct candidate * c        = &ch->candidates[idx];
  int                paired   = ch->paired_idx==(int)idx;
  int                accepted = c->fd!=-1 && !c->dialed;
  close_candidate( c );
  if( paired ) {
    ch->paired_idx = -1;
    fd_memset( &ch->peer_hello, 0, sizeof(ch->peer_hello) );
  }
  /* A candidate from the listener does not get a session until it pairs. */
  if( !paired && accepted ) return;
  /* After loss, use the current handoff address to choose listener or dialer. */
  if( paired && want_dial( ch )!=ch->dial_peer ) reset( ch );
  if( ch->dial_peer ) {
    /* Recompute backoff parameters */
    int  established = paired && now>=ch->paired_at && now-ch->paired_at>=FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS;
    long jitter      = (long)fd_rng_ulong_roll( ch->rng, (ulong)FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS );
    ch->retry_at = fd_long_sat_add( now, fd_long_sat_add( established ? 0L : ch->backoff, jitter ) );
    ch->backoff  = established ? FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS
                               : fd_long_min( fd_long_sat_add( ch->backoff, ch->backoff ), FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS );
  }
}

/* Same as drop, and if idx is the paired session we log why it ended. */
static void
lose( fd_failover_channel_t * ch,
      ulong                   idx,
      long                    now,
      char const *            why ) {
  if( ch->paired_idx==(int)idx ) {
    FD_LOG_WARNING(( "lost the failover session with `" FD_IP4_ADDR_FMT "`, %s",
                     FD_IP4_ADDR_FMT_ARGS( ch->candidates[idx].address ), why ));
  }
  drop( ch, idx, now );
}

void
fd_failover_channel_hangup( fd_failover_channel_t * ch,
                            long                    now ) {
  if( ch->paired_idx>=0 ) drop( ch, (ulong)ch->paired_idx, now );
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( ch->candidates[i].fd!=-1 ) drop( ch, i, now );
}

void
fd_failover_channel_protocol_error( fd_failover_channel_t * ch,
                                    long                    now ) {
  if( FD_LIKELY( ch->paired_idx>=0 ) ) {
    lose( ch, (ulong)ch->paired_idx, now, "it sent a message that breaks the protocol" );
  }
  fd_failover_channel_hangup( ch, now );
}

/* Admit at most one live inbound candidate per source address. */
static int
admit( fd_failover_channel_t const * ch,
       uint                          address ) {
  for( ulong i=ADMITTED_IDX; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ )
    if( ch->candidates[i].fd!=-1 && ch->candidates[i].address==address ) return 0;
  return 1;
}

static int
has_proof( struct candidate const * c ) {
  return c->phase==PHASE_REQUEST_RECV && c->rx_used==sizeof(c->client_proof);
}

static int
known_source( fd_failover_channel_t const * ch, uint address, long now ) {
  return address==ch->known_addr && now<ch->known_until;
}

static void
remember_source( fd_failover_channel_t * ch, uint address, long now ) {
  ch->known_addr  = address;
  ch->known_until = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_IDLE_NANOS );
}

static ulong
listen_slot( fd_failover_channel_t const * ch,
             uint                          address,
             long                          now ) {
  if( known_source( ch, address, now ) ) {
    return ch->candidates[ADMITTED_IDX].fd==-1 ? ADMITTED_IDX : FD_FAILOVER_CHANNEL_CANDIDATE_MAX;
  }
  for( ulong i=UNAUTHENTICATED_IDX; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    if( ch->candidates[i].fd==-1 ) return i;
  }
  return FD_FAILOVER_CHANNEL_CANDIDATE_MAX;
}

static void
start( fd_failover_channel_t * ch,
       ulong                   idx,
       int                     fd,
       uint                    address,
       long                    now,
       int                     phase ) {
  struct candidate * c = &ch->candidates[idx];
  /* Inbound sockets do not initialize TLS until admission succeeds. */
  c->fd       = fd;
  c->address  = address;
  c->phase    = phase;
  c->dialed   = phase==PHASE_CONNECT;
  c->deadline = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS );
  c->admission_until = c->dialed ? c->deadline : fd_long_min( c->deadline, fd_long_sat_add( now, FD_FAILOVER_ADMISSION_START_NANOS ) );
  c->local_hello = ch->self_hello;
  c->rx_used     = c->tx_used = c->tx_sent = 0UL;
  c->tls_started = 0;
}

static void
accept_candidates( fd_failover_channel_t * ch,
                   long                    now,
                   int *                   busy ) {
  for( ulong n=0; n<FD_FAILOVER_ACCEPT_PER_POLL; n++ ) {
    if( !fd_token_bucket_consume( &ch->accept_bucket, 1.0f, now ) ) return;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int       fd  = accept4( ch->listen_fd, fd_type_pun( &addr ), &len, SOCK_NONBLOCK|SOCK_CLOEXEC );
    if( fd==-1 ) return;
    *busy = 1;
    uint  address = addr.sin_addr.s_addr;
    ulong idx     = listen_slot( ch, address, now );
    if( ch->paired_idx>=0 || len!=sizeof(addr) || addr.sin_family!=AF_INET ||
        idx==FD_FAILOVER_CHANNEL_CANDIDATE_MAX || !admit( ch, address ) ||
        !fd_token_bucket_consume( &ch->admit_bucket, 1.0f, now ) ) {
      close( fd );
      continue;
    }
    start( ch, idx, fd, address, now, PHASE_START_RECV );
  }
}

static int
flush( fd_failover_channel_t * ch,
       ulong                   idx,
       long                    now,
       int *                   busy ) {
  struct candidate * c = &ch->candidates[idx];
  if( !c->tx_used ) {
    int rc = fd_tlsrec_sock_flush( &c->tls.sock, c->tls.fd );
    if( rc<0 ) { lose( ch, idx, now, "flushing TLS output failed" ); return -1; }
    return rc;
  }
  long n = fd_failover_tls_write( &c->tls, c->tx+c->tx_sent, c->tx_used-c->tx_sent );
  if( n<0L ) { lose( ch, idx, now, "writing to it failed" ); return -1; }
  if( !n ) return 1;
  *busy = 1;
  c->tx_sent += (ulong)n;
  if( c->tx_sent<c->tx_used ) return 1;
  c->tx_used = c->tx_sent = 0UL;
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
  struct candidate * c   = &ch->candidates[idx];
  uchar const *      data;
  ulong              frame_sz;
  int                err = fd_failover_wire_decode( c->rx, c->rx_used, type, &data, payload_sz, &frame_sz );
  if( err==FD_FAILOVER_WIRE_ERR_AGAIN ) return 0;
  if( err ) { lose( ch, idx, now, "it sent a malformed frame" ); return -1; }
  fd_memcpy( payload, data, *payload_sz );
  memmove( c->rx, c->rx+frame_sz, c->rx_used-frame_sz );
  c->rx_used -= frame_sz;
  *busy = 1;
  return 1;
}

static char const *
hello_err_cstr( int err ) {
  switch( err ) {
  case HELLO_ERR_TLS_KEY:                return "its junk key is not the key TLS authenticated";
  case FD_FAILOVER_HELLO_ERR_VERSION:    return "the protocol version differs";
  case FD_FAILOVER_HELLO_ERR_STAKED:     return "the failover identity differs";
  case FD_FAILOVER_HELLO_ERR_VOTE_ACCT:  return "the vote account differs";
  case FD_FAILOVER_HELLO_ERR_JUNK_EQ:    return "its junk key is ours";
  case FD_FAILOVER_HELLO_ERR_JUNK_STAKE: return "a junk key is the identity being handed off";
  case FD_FAILOVER_HELLO_ERR_BOTH_HOLD:  return "both machines run the identity";
  case FD_FAILOVER_HELLO_ERR_HOLDS:      return "it sent an unknown value";
  case FD_FAILOVER_HELLO_ERR_BOOT_ID:    return "the boot id is zero";
  case FD_FAILOVER_HELLO_ERR_MODE:       return "the consensus mode differs";
  case FD_FAILOVER_HELLO_ERR_PROOF:      return "its admission proof is not signed by the failover identity";
  default:                               return "unknown";
  }
}

static void
refuse_hello( uint address, int err ) {
  FD_LOG_WARNING(( "rejected the failover peer at `" FD_IP4_ADDR_FMT "`, %s",
                   FD_IP4_ADDR_FMT_ARGS( address ), hello_err_cstr( err ) ));
}

static int
read_frame( fd_failover_channel_t * ch,
            ulong                   idx,
            long                    now,
            int *                   busy,
            ushort *                type,
            uchar *                 payload,
            ulong *                 payload_sz ) {
  struct candidate * c  = &ch->candidates[idx];
  int                rc = decode( ch, idx, now, busy, type, payload, payload_sz );
  if( rc ) return rc;
  ulong max = ch->paired_idx==(int)idx ? sizeof(c->rx) : FD_FAILOVER_FRAME_HDR_SZ+sizeof(fd_failover_hello_t);
  if( c->rx_used>=max ) { drop( ch, idx, now ); return -1; }
  long n = fd_failover_tls_read( &c->tls, c->rx+c->rx_used, max-c->rx_used );
  if( n<0L ) {
    if( FD_UNLIKELY( c->dialed && c->phase==PHASE_HELLO ) ) {
      FD_LOG_WARNING(( "the failover peer at `" FD_IP4_ADDR_FMT "` closed the connection before answering our HELLO",
                       FD_IP4_ADDR_FMT_ARGS( c->address ) ));
    }
    if( ch->paired_idx==(int)idx && ch->expected_close && c->tls.peer_closed && !fd_failover_channel_tx_pending( ch ) ) {
      drop( ch, idx, now );
      return -1;
    }
    if( fd_tlsrec_conn_is_failed( &c->tls.conn ) ) {
      char why[ 192 ];
      fd_cstr_printf( why, sizeof(why), NULL, "TLS record rejected (%s)",
                      fd_tls_reason_cstr( c->tls.conn.hs.base.reason ) );
      lose( ch, idx, now, why );
    } else {
      lose( ch, idx, now, "the connection closed" );
    }
    return -1;
  }
  if( n>0L ) { c->rx_used += (ulong)n; *busy = 1; }
  return decode( ch, idx, now, busy, type, payload, payload_sz );
}

/* Return one to continue this poll, zero to stop after a wait or failure. */
static int
connect_candidate( fd_failover_channel_t * ch,
                   ulong                   idx,
                   long                    now ) {
  struct candidate * c = &ch->candidates[idx];
  struct sockaddr_in addr = {
    .sin_family=AF_INET,
    .sin_port=fd_ushort_bswap( ch->peer_port ),
    .sin_addr.s_addr=ch->peer_addr
  };
  if( connect( c->fd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EISCONN ) {
    if( errno==EINPROGRESS || errno==EALREADY || errno==EINTR ) return 0; /* TCP is still connecting. */
    FD_LOG_WARNING(( "could not connect to the failover peer at `" FD_IP4_ADDR_FMT ":%hu` (%i-%s)",
                     FD_IP4_ADDR_FMT_ARGS( ch->peer_addr ), ch->peer_port, errno, fd_io_strerror( errno ) ));
    drop( ch, idx, now );
    return 0;
  }

  /* Only operator-initiated outbound work prepares a TLS key share here. */
  ulong hello_sz = sizeof(c->client_hello);
  if( fd_failover_tls_new( &c->tls, &ch->tls_ctx, c->fd, 1 ) ) {
    drop( ch, idx, now );
    return 0;
  }
  c->tls_started = 1;

  if( fd_failover_tls_client_hello( &c->tls, c->client_hello, &hello_sz ) ||
      hello_sz>sizeof(c->client_hello) ) {
    drop( ch, idx, now );
    return 0;
  }

  c->start = (fd_failover_admission_start_t){
    .magic=FD_FAILOVER_ADMISSION_MAGIC,
    .hello=c->local_hello,
    .client_hello_sz=(ushort)hello_sz
  };
  if( !fd_rng_secure( c->start.nonce, sizeof(c->start.nonce) ) ) {
    drop( ch, idx, now );
    return 0;
  }
  fd_memcpy( c->tx, &c->start, sizeof(c->start) );
  fd_memcpy( c->tx+sizeof(c->start), c->client_hello, hello_sz );
  c->tx_used = sizeof(c->start)+hello_sz;
  c->phase = PHASE_START_SEND;
  return 1;
}

static int
handshake_candidate( fd_failover_channel_t * ch,
                     ulong                   idx,
                     long                    now,
                     int *                   busy ) {
  struct candidate * c = &ch->candidates[idx];
  int rc = fd_failover_tls_handshake( &c->tls );
  if( rc<0 ) {
    uint reason = c->tls.conn.hs.base.reason;
    FD_LOG_WARNING(( "TLS handshake with `" FD_IP4_ADDR_FMT "` failed (%s)",
                     FD_IP4_ADDR_FMT_ARGS( c->address ), reason ? fd_tls_reason_cstr( reason ) : "connection closed or socket error" ));
    drop( ch, idx, now );
    return 0;
  }
  if( !rc ) return 0; /* Keep waiting for TLS. */
  *busy = 1;

  /* TLS authenticated a key, send the HELLO! */
  c->phase = PHASE_HELLO;
  if( c->dialed ) {
    c->tx_used = fd_failover_wire_encode( c->tx, FD_FAILOVER_MSG_HELLO,
                                          (uchar const *)&c->local_hello, sizeof(c->local_hello) );
  }
  return 1;
}

static int
read_candidate_hello( fd_failover_channel_t * ch,
                      ulong                   idx,
                      long                    now,
                      int *                   busy,
                      uchar *                 payload ) {
  struct candidate * c = &ch->candidates[idx];
  ushort type;
  ulong  sz;
  if( read_frame( ch, idx, now, busy, &type, payload, &sz )<=0 ) return 0;
  if( type!=FD_FAILOVER_MSG_HELLO || sz!=sizeof(c->hello) ) {
    FD_LOG_WARNING(( "rejected failover HELLO from `" FD_IP4_ADDR_FMT "`", FD_IP4_ADDR_FMT_ARGS( c->address ) ));
    drop( ch, idx, now );
    return 0;
  }

  /* HELLO and TLS must match admission. */
  int err = fd_memeq( payload, &c->hello, sizeof(c->hello) ) &&
            fd_memeq( c->hello.junk_pubkey, c->tls.peer_pubkey, 32UL )
          ? fd_failover_hello_check( &c->local_hello, &c->hello ) : HELLO_ERR_TLS_KEY;
  if( err!=FD_FAILOVER_HELLO_OK ) {
    refuse_hello( c->address, err );
    drop( ch, idx, now );
    return 0;
  }

  /* The peer is authenticated. */
  c->phase = PHASE_READY;
  if( !c->dialed ) {
    c->tx_used = fd_failover_wire_encode( c->tx, FD_FAILOVER_MSG_HELLO,
                                          (uchar const *)&c->local_hello, sizeof(c->local_hello) );
    if( flush( ch, idx, now, busy )!=0 ) return 0; /* Remain READY until output drains, unless the write fails. */
  }
  return 1;
}

static void
pair_candidate( fd_failover_channel_t * ch,
                ulong                   idx,
                long                    now,
                int *                   busy ) {
  struct candidate * c = &ch->candidates[idx];
  /* The first session that authenticates wins. */
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( i!=idx ) close_candidate( &ch->candidates[i] );

  if( !c->dialed ) ch->dial_peer = 0;

  ch->paired_idx = (int)idx;
  c->tls.paired  = 1;
  ch->peer_hello = c->hello;
  ch->generation++;
  remember_source( ch, c->address, now );

  fd_keepalive_init( ch->keepalive, ch->rng, FD_FAILOVER_CHANNEL_KEEPALIVE_NANOS, FD_FAILOVER_CHANNEL_IDLE_NANOS, now );
  fd_keepalive_rx(   ch->keepalive, now );
  ch->paired_at      = now;
  ch->expected_close = 0;
  *busy = 1;

  char member[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( c->hello.junk_pubkey, NULL, member );
  FD_LOG_NOTICE(( "paired with the failover peer at `" FD_IP4_ADDR_FMT "` via %s, authenticated member %s, %s, boot id %016lx",
                  FD_IP4_ADDR_FMT_ARGS( c->address ), c->dialed ? "outbound dial" : "listener", member,
                  c->hello.holds ? "it runs the identity" : "it does not run the identity", c->hello.boot_id ));
}

static int
read_admission( struct candidate * c, ulong goal, int * busy ) {
  if( FD_UNLIKELY( goal>FD_FAILOVER_ADMISSION_MAX || c->rx_used>goal ) ) return -1;
  if( c->rx_used==goal ) return 1;
  long n = recv( c->fd, c->rx+c->rx_used, goal-c->rx_used, MSG_DONTWAIT|MSG_NOSIGNAL );
  if( n<0L ) return ( errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ) ? 0 : -1;
  if( !n )   return -1;

  c->rx_used += (ulong)n;
  *busy = 1;
  return c->rx_used==goal;
}

static int
write_admission( struct candidate * c, int * busy ) {
  long n = send( c->fd, c->tx+c->tx_sent, c->tx_used-c->tx_sent, MSG_DONTWAIT|MSG_NOSIGNAL );
  if( n<0L ) return ( errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ) ? 0 : -1;
  if( !n )   return -1;
  c->tx_sent += (ulong)n;
  *busy = 1;
  if( c->tx_sent<c->tx_used ) return 0;
  c->tx_sent = c->tx_used = 0UL;
  return 1;
}

static int
verify_admission_proof( fd_failover_channel_t * ch, struct candidate * c, int server, uchar const sig[ 64 ] ) {
  uchar msg[ FD_KEYGUARD_FAILOVER_PROOF_SZ ];
  fd_failover_proof_msg( msg, server, c->hello.junk_pubkey, c->transcript );
  return fd_ed25519_verify( msg, sizeof(msg), sig, c->local_hello.staked_pubkey, ch->sha )==FD_ED25519_SUCCESS;
}

static int
sign_admission_proof( fd_failover_channel_t * ch, struct candidate * c, int server ) {
  uchar msg[ FD_KEYGUARD_FAILOVER_PROOF_SZ ];
  fd_failover_proof_msg( msg, server, c->local_hello.junk_pubkey, c->transcript );
  ch->proof_signer.sign_fn( ch->proof_signer.ctx, c->tx, msg );
  if( fd_ed25519_verify( msg, sizeof(msg), c->tx, c->local_hello.staked_pubkey, ch->sha )!=FD_ED25519_SUCCESS ) return 0;
  c->tx_used = 64UL;
  c->tx_sent = 0UL;
  return 1;
}

/* One Ed25519 operation per poll, within the global rate. */
static int
verify_credit( fd_failover_channel_t * ch, long now ) {
  if( !ch->verify_budget || !fd_token_bucket_consume( &ch->verify_bucket, 1.0f, now ) ) return 0;
  ch->verify_budget--;
  return 1;
}

/* Service the candidate admission state machine. */
static void
service_admission( fd_failover_channel_t * ch, ulong idx, long now, int * busy ) {
  struct candidate * c = &ch->candidates[idx];
  int rc;
  switch( c->phase ) {
  case PHASE_START_SEND:
  case PHASE_CHALLENGE_SEND:
  case PHASE_REQUEST_SEND:
  case PHASE_RESPONSE_SEND:
    rc = write_admission( c, busy );
    if( rc<0 ) break;
    if( !rc ) return;
    c->rx_used = 0UL;
    if( c->phase==PHASE_START_SEND ) {
      c->phase = PHASE_CHALLENGE_RECV;
    }
    else if( c->phase==PHASE_CHALLENGE_SEND ) {
      c->admission_until = fd_long_min( c->deadline, fd_long_sat_add( now, FD_FAILOVER_ADMISSION_PROOF_NANOS ) );
      c->phase = PHASE_REQUEST_RECV;
    }
    else if( c->phase==PHASE_REQUEST_SEND ) {
      c->phase = PHASE_RESPONSE_RECV;
    }
    else {
      c->phase = PHASE_TLS;
    }
    return;
  case PHASE_START_RECV: {
    /* Read only the fixed header until its length is checked. */
    ulong goal = c->rx_used<sizeof(c->start) ? sizeof(c->start) : sizeof(c->start)+c->start.client_hello_sz;
    rc = read_admission( c, goal, busy );
    if( rc<0 ) break;
    if( !rc ) return;
    if( goal==sizeof(c->start) ) {
      fd_memcpy( &c->start, c->rx, sizeof(c->start) );
      if( c->start.magic!=FD_FAILOVER_ADMISSION_MAGIC ||
          c->start.client_hello_sz<=sizeof(fd_tlsrec_hdr_t) ||
          c->start.client_hello_sz>sizeof(c->client_hello) ) break;
      int err = fd_failover_hello_check( &c->local_hello, &c->start.hello );
      if( err ) { refuse_hello( c->address, err ); break; }
      return;
    }
    fd_memcpy( c->client_hello, c->rx+sizeof(c->start), c->start.client_hello_sz );
    fd_tlsrec_hdr_t hdr;
    fd_memcpy( &hdr, c->client_hello, sizeof(hdr) );
    if( hdr.content_type!=FD_TLS_REC_HANDSHAKE ||
        (ulong)fd_ushort_bswap( hdr.length )+sizeof(hdr)!=c->start.client_hello_sz ||
        c->client_hello[ sizeof(hdr) ]!=FD_TLS_MSG_CLIENT_HELLO ) break;
    c->hello = c->start.hello;
    c->challenge = (fd_failover_admission_challenge_t){ .magic=FD_FAILOVER_ADMISSION_MAGIC, .hello=c->local_hello };
    if( !fd_rng_secure( c->challenge.nonce, sizeof(c->challenge.nonce) ) ) break;
    fd_failover_admission_hash( &c->start, c->client_hello, &c->challenge, c->transcript );
    fd_memcpy( c->tx, &c->challenge, sizeof(c->challenge) );
    c->tx_used = sizeof(c->challenge);
    c->rx_used = 0UL;
    c->admission_until = fd_long_min( c->deadline, fd_long_sat_add( now, FD_FAILOVER_ADMISSION_START_NANOS ) );
    c->phase = PHASE_CHALLENGE_SEND;
    return;
  }
  case PHASE_CHALLENGE_RECV:
    rc = read_admission( c, sizeof(c->challenge), busy );
    if( rc<0 ) break;
    if( !rc ) return;
    fd_memcpy( &c->challenge, c->rx, sizeof(c->challenge) );
    if( c->challenge.magic!=FD_FAILOVER_ADMISSION_MAGIC ) break;
    int err = fd_failover_hello_check( &c->local_hello, &c->challenge.hello );
    if( err ) { refuse_hello( c->address, err ); break; }
    c->hello = c->challenge.hello;
    fd_failover_admission_hash( &c->start, c->client_hello, &c->challenge, c->transcript );
    c->rx_used = 0UL;
    c->phase = PHASE_REQUEST_SIGN;
    *busy = 1;
    return;
  case PHASE_REQUEST_SIGN:
    if( !verify_credit( ch, now ) ) return;
    if( !sign_admission_proof( ch, c, 0 ) ) break;
    fd_memcpy( c->client_proof, c->tx, sizeof(c->client_proof) );
    c->phase = PHASE_REQUEST_SEND;
    *busy = 1;
    return;
  case PHASE_RESPONSE_RECV: {
    fd_failover_admission_response_t response;
    if( c->rx_used<sizeof(response) ) {
      rc = read_admission( c, sizeof(response), busy );
      if( rc<0 ) break;
      if( !rc ) return;
      fd_memcpy( &response, c->rx, sizeof(response) );
      if( !response.server_flight_sz || response.server_flight_sz>FD_FAILOVER_SERVER_FLIGHT_MAX ) break;
      return;
    }
    fd_memcpy( &response, c->rx, sizeof(response) );
    rc = read_admission( c, sizeof(response)+response.server_flight_sz, busy );
    if( rc<0 ) break;
    if( !rc || !verify_credit( ch, now ) ) return;
    fd_failover_response_hash( c->transcript, c->client_proof, c->rx+sizeof(response),
                               response.server_flight_sz, c->transcript );
    if( !verify_admission_proof( ch, c, 1, response.proof ) ) {
      refuse_hello( c->address, FD_FAILOVER_HELLO_ERR_PROOF );
      break;
    }
    if( fd_failover_tls_accept_flight( &c->tls, c->rx+sizeof(response), response.server_flight_sz ) ) break;
    c->phase = PHASE_TLS;
    c->rx_used = 0UL;
    *busy = 1;
    return;
  }
  case PHASE_REQUEST_RECV:
    rc = read_admission( c, 64UL, busy );
    if( rc<0 ) break;
    if( !rc || !verify_credit( ch, now ) ) return;
    if( !verify_admission_proof( ch, c, 0, c->rx ) ) {
      refuse_hello( c->address, FD_FAILOVER_HELLO_ERR_PROOF );
      break;
    }
    fd_memcpy( c->client_proof, c->rx, sizeof(c->client_proof) );
    c->rx_used         = 0UL;
    c->admission_until = c->deadline;
    c->phase           = PHASE_TLS_START;
    /* Only a verified proof can claim a protected slot. */
    if( idx!=ADMITTED_IDX ) {
      if( ch->candidates[ ADMITTED_IDX ].fd!=-1 ) break;
      ch->candidates[ ADMITTED_IDX ] = *c;
      c->fd = -1;
      c->tls_started = 0;
    }
    *busy = 1;
    return;
  case PHASE_RESPONSE_SIGN: {
    if( !verify_credit( ch, now ) ) return;
    fd_failover_admission_response_t response = { .server_flight_sz=(ushort)(c->tx_used-sizeof(fd_failover_admission_response_t)) };
    if( !sign_admission_proof( ch, c, 1 ) ) break;
    fd_memcpy( response.proof, c->tx, sizeof(response.proof) );
    fd_memcpy( c->tx, &response, sizeof(response) );
    c->tx_used = sizeof(response)+response.server_flight_sz;
    c->phase = PHASE_RESPONSE_SEND;
    *busy = 1;
    return;
  }
  case PHASE_TLS_START:
    if( fd_failover_tls_new( &c->tls, &ch->tls_ctx, c->fd, 0 ) ) break;
    c->tls_started = 1;
    if( fd_failover_tls_accept_flight( &c->tls, c->client_hello, c->start.client_hello_sz ) ) break;
    if( !c->tls.sock.tx_sz || c->tls.sock.tx_sz>FD_FAILOVER_SERVER_FLIGHT_MAX ) break;
    fd_failover_response_hash( c->transcript, c->client_proof, c->tls.sock.tx_buf,
                               (ushort)c->tls.sock.tx_sz, c->transcript );
    fd_memcpy( c->tx+sizeof(fd_failover_admission_response_t), c->tls.sock.tx_buf, c->tls.sock.tx_sz );
    c->tx_used = sizeof(fd_failover_admission_response_t)+c->tls.sock.tx_sz;
    c->tls.sock.tx_off = c->tls.sock.tx_sz = 0UL;
    c->phase = PHASE_RESPONSE_SIGN;
    *busy = 1;
    return;
  default:
    break;
  }
  if( c->dialed ) {
    FD_LOG_WARNING(( "the failover peer at `" FD_IP4_ADDR_FMT "` did not complete admission",
                     FD_IP4_ADDR_FMT_ARGS( c->address ) ));
  }
  drop( ch, idx, now );
}

/* Drive the candidate lifecycle state machine. */
static void
service_candidate( fd_failover_channel_t * ch,
                   ulong                   idx,
                   long                    now,
                   int *                   busy,
                   uchar *                 payload ) {
  struct candidate * c = &ch->candidates[idx];
  if( c->phase==PHASE_CONNECT ) {
    if( connect_candidate( ch, idx, now ) ) *busy = 1;
    return;
  }
  if( c->phase<PHASE_TLS ) {
    service_admission( ch, idx, now, busy );
    return;
  }
  if( c->phase==PHASE_TLS ) {
    if( !handshake_candidate( ch, idx, now, busy ) ) {
      return;
    }
  }
  if( flush( ch, idx, now, busy )!=0 ) return;
  if( c->phase==PHASE_HELLO ) {
    if( !read_candidate_hello( ch, idx, now, busy, payload ) ) {
      return;
    }
  }
  if( c->phase==PHASE_READY && !c->tx_used ) {
    pair_candidate( ch, idx, now, busy );
  }
}

/* The paired session went silent. */
static int
silent( fd_failover_channel_t const * ch, long now ) {
  long last_rx = ch->keepalive->ts_last_rx;
  return now>=last_rx && now-last_rx>FD_FAILOVER_CHANNEL_IDLE_NANOS;
}

/* Services the paired session.  Returns 1 when a post-HELLO frame was delivered. */
static int
service_paired( fd_failover_channel_t * ch,
                long                    now,
                int *                   busy,
                ushort *                type,
                uchar *                 payload,
                ulong *                 payload_sz ) {
  ulong idx = (ulong)ch->paired_idx;
  int delivered = 0;
  int flushed   = flush( ch, idx, now, busy );
  if( !flushed ) {
    int rc = read_frame( ch, idx, now, busy, type, payload, payload_sz );
    if( rc>0 ) {
      if( *type==FD_FAILOVER_MSG_HELLO ) {
        lose( ch, idx, now, "it sent a second HELLO" );
      }
      else {
        fd_keepalive_rx( ch->keepalive, now );
        remember_source( ch, ch->candidates[idx].address, now );
        delivered = *type!=FD_FAILOVER_MSG_KEEPALIVE;
      }
    } else if( !rc && silent( ch, now ) ) {
      lose( ch, idx, now, "it was idle past its deadline" );
    }
  }
  if( flushed>0 && silent( ch, now ) ) {
    lose( ch, idx, now, "it stopped making progress" );
  }
  if( ch->paired_idx>=0 &&
      !fd_failover_channel_tx_pending( ch ) &&
       fd_keepalive_should_tx( ch->keepalive, now ) )
  {
    if( !fd_failover_channel_send( ch, now, FD_FAILOVER_MSG_KEEPALIVE, NULL, 0UL ) ) {
      fd_keepalive_tx( ch->keepalive, ch->rng, now );
      *busy = 1;
    }
  }
  return delivered;
}

static void
dial( fd_failover_channel_t * ch,
      long                    now,
      int *                   busy ) {
  if( !ch->dial_peer || !ch->peer_addr || ch->candidates[OUTBOUND_IDX].fd!=-1 || now<ch->retry_at ) {
    return;
  }

  *busy = 1;
  int fd  = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( fd==-1 ) {
    drop( ch, OUTBOUND_IDX, now );
    return;
  }

  int yes = 1;
  if( setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes) ) ) {
    close( fd );
    drop( ch, OUTBOUND_IDX, now );
    return;
  }

  start( ch, OUTBOUND_IDX, fd, ch->peer_addr, now, PHASE_CONNECT );
}

int
fd_failover_channel_poll( fd_failover_channel_t * ch,
                          long                    now,
                          int *                   busy,
                          ushort *                type,
                          uchar *                 payload,
                          ulong *                 payload_sz ) {
  int delivered = 0;
  ch->verify_budget = 1;
  if( ch->paired_idx>=0 ) {
    delivered = service_paired( ch, now, busy, type, payload, payload_sz );
  }

  /* Expire every slot each poll, independently of round-robin service. */
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    struct candidate * c = &ch->candidates[i];
    if( c->fd!=-1 && (int)i!=ch->paired_idx && ( now>=c->deadline || now>=c->admission_until ) ) {
      if( c->dialed ) {
        FD_LOG_WARNING(( "the failover peer at `" FD_IP4_ADDR_FMT "` did not finish the handshake in time",
                         FD_IP4_ADDR_FMT_ARGS( c->address ) ));
      }
      drop( ch, i, now );
      *busy = 1;
    }
  }

  if( FD_UNLIKELY( !ch->tls_ctx.ready ) || ch->paired_idx>=0 ) {
    return delivered;
  }
  dial( ch, now, busy );

  ulong serviced = 0UL;
  for( ulong idx=0UL; idx<UNAUTHENTICATED_IDX; idx++ ) {
    if( ch->candidates[idx].fd==-1 ) continue;
    service_candidate( ch, idx, now, busy, payload );
    serviced++;
    if( ch->paired_idx>=0 ) return delivered;
  }

  for( ulong n=0UL; n<FD_FAILOVER_CHANNEL_CANDIDATE_MAX-UNAUTHENTICATED_IDX && serviced<4UL; n++ ) {
    ulong idx = UNAUTHENTICATED_IDX+ch->cursor;
    ch->cursor = (ch->cursor+1UL)%(FD_FAILOVER_CHANNEL_CANDIDATE_MAX-UNAUTHENTICATED_IDX);
    if( ch->candidates[idx].fd==-1 ) continue;
    if( has_proof( &ch->candidates[idx] ) && !ch->verify_budget ) continue;

    service_candidate( ch, idx, now, busy, payload );
    serviced++;
    if( ch->paired_idx>=0 ) {
      return delivered;
    }
  }
  if( ch->listen_fd!=-1 ) {
    accept_candidates( ch, now, busy );
  }
  return delivered;
}

int
fd_failover_channel_send( fd_failover_channel_t * ch,
                          long                    now,
                          ushort                  type,
                          uchar const *           payload,
                          ulong                   sz ) {
  if( ch->paired_idx<0 ) return -1;

  ulong              idx = (ulong)ch->paired_idx;
  struct candidate * c   = &ch->candidates[idx];

  if( c->tx_used ) return -1;
  c->tx_used = fd_failover_wire_encode( c->tx, type, payload, sz );
  if( !c->tx_used ) {
    lose( ch, idx, now, "we could not encode a frame for it" );
    return -1;
  }

  int busy = 0;
  int rc   = flush( ch, idx, now, &busy )<0 ? -1 : 0;
  if( !rc && type==FD_FAILOVER_MSG_HANDOFF_RESULT ) {
    ch->expected_close = 1;
  }
  return rc;
}
