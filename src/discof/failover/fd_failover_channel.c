#define _GNU_SOURCE
#include "fd_failover_channel.h"
#include "fd_failover_tls.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../waltz/tls/fd_tls_proto.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOURCE_CNT           (4096UL)
#define OUTBOUND_IDX         (0UL)
#define ADMITTED_IDX         (1UL)
#define RECONNECT_IDX        (2UL)
#define UNAUTHENTICATED_IDX  (3UL)
#define KNOWN_SOURCE_CNT     (4UL)
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

FD_STATIC_ASSERT( FD_FAILOVER_CHANNEL_CANDIDATE_MAX<=8UL*sizeof(ulong), candidate_service_mask );
FD_STATIC_ASSERT( FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS<=FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS, source_initial_quota );
FD_STATIC_ASSERT( SOURCE_CNT>=FD_FAILOVER_ADMIT_BURST+
                 FD_FAILOVER_RECONNECT_BURST+
                 ((FD_FAILOVER_ADMIT_RATE+FD_FAILOVER_RECONNECT_RATE)*2UL*(ulong)FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS+FD_FAILOVER_NANOS_PER_SECOND-1UL)/FD_FAILOVER_NANOS_PER_SECOND,
                 source_quota_capacity );
FD_STATIC_ASSERT( FD_FAILOVER_CHANNEL_CANDIDATE_MAX>UNAUTHENTICATED_IDX, admission_pool_capacity );

FD_STATIC_ASSERT( FD_KEYGUARD_FAILOVER_PROOF_SZ<=FD_TLS_CV_SIGN_SZ, admission_sign_mtu );
FD_STATIC_ASSERT( FD_FAILOVER_CLIENT_HELLO_MAX+sizeof(fd_tlsrec_hdr_t)+sizeof(fd_failover_admission_start_t)<=FD_FAILOVER_ADMISSION_MAX, admission_buffer );

/* A HELLO whose junk key does not match the key TLS authenticated */
#define HELLO_ERR_TLS_KEY (-1)

struct candidate {
  int                               fd;          /* -1 marks an unused candidate. */
  int                               phase;       /* PHASE_* */
  int                               dialed;      /* we dialed it, else the listener accepted it */
  int                               priority; /* Reserved crypto budget, never an authentication bypass. */
  uint                              address;
  long                              deadline;
  long                              admission_until;
  long                              accepted_at;
  int                               tls_started; /* tls is initialized, close_candidate must fini it */
  fd_failover_hello_t               local_hello;
  fd_failover_admission_start_t     start;
  fd_failover_admission_challenge_t challenge;
  uchar                             client_hello[ FD_FAILOVER_CLIENT_HELLO_MAX+sizeof(fd_tlsrec_hdr_t) ];
  uchar                             transcript[ 32 ];
  uchar                             client_proof[ 64 ];
  fd_failover_tls_t                 tls;
  fd_failover_wire_session_t        wire;
  fd_failover_hello_t               hello;
  uchar                             rx[ FD_FAILOVER_FRAME_MAX ];
  uchar                             tx[ FD_FAILOVER_FRAME_MAX ];
  ulong                             rx_used;
  ulong                             tx_used;
  ulong                             tx_sent;
};

struct source {
  uint  address;
  int   used;
  long  last_admit;
  long  next_admit;
  long  backoff;
};

struct known_source {
  uint address;
  long until;
};

struct fd_failover_channel {
  ulong                          magic;              /* FD_FAILOVER_CHANNEL_MAGIC once initialized */
  int                            dial_peer;          /* the session machine runs as the dialer */
  ulong                          state;              /* session state, stepped by fd_failover_session_step */
  uint                           peer_addr;          /* the dial destination, zero when we do not dial */
  ushort                         peer_port;          /* the dial destination port */
  int                            listen_fd;          /* listening socket, -1 until it is open */
  int                            paired_idx;         /* the paired candidate, -1 while none is paired */
  ulong                          cursor;             /* the next candidate to service, round robin */
  ulong                          proof_cursor;       /* the next complete proof to verify, round robin */
  fd_failover_tls_ctx_t          tls_ctx;            /* TLS template every connection starts from */
  fd_failover_hello_t            self_hello;         /* the HELLO we send */
  fd_failover_hello_t            peer_hello;         /* the paired peer's HELLO, zero while unpaired */
  fd_failover_proof_signer_t     proof_signer;
  long                           verify_updated;
  ulong                          verify_credit;
  long                           priority_verify_updated;
  ulong                          priority_verify_credit;
  int                            verify_budget;
  fd_sha512_t                    sha[ 1 ];           /* scratch for checking admission proofs */
  struct candidate               candidates[ FD_FAILOVER_CHANNEL_CANDIDATE_MAX ]; /* connections that are handshaking or paired */
  struct source                  sources[ SOURCE_CNT ]; /* accept rate limit per source address */
  struct known_source            known_sources[ KNOWN_SOURCE_CNT ]; /* authenticated addresses, expiring */
  fd_failover_channel_metrics_t  metrics;
  long                           rate_updated;       /* when rate_credit was last refilled */
  ulong                          rate_credit;        /* accept syscall limit across all addresses */
  long                           admit_updated;      /* when admit_credit was last refilled */
  ulong                          admit_credit;       /* new candidate limit across all addresses */
  long                           reconnect_updated;
  ulong                          reconnect_credit;
  long                           hello_timeout;      /* how long a candidate has to pair */
  long                           silence_timeout;    /* a paired session silent for this long is dropped */
  long                           last_rx;            /* when the paired session last received a frame */
  long                           keepalive_at;
  long                           retry_at;           /* when the dialer dials again */
  long                           paired_at;          /* when the current session paired */
  long                           backoff;            /* the current dial backoff, doubles up to backoff_max */
  long                           backoff_min;        /* the shortest dial backoff, also the jitter range */
  long                           backoff_max;        /* the longest dial backoff */
  long                           dial_log_at[ 3 ];   /* connect, early close, handshake timeout */
  long                           tls_log_at[ 4 ];    /* transport, ALPN, authentication, other */
  long                           hello_log_at[ 14 ]; /* one bounded bucket per HELLO refusal */
  long                           loss_log_at[ 6 ];   /* transport, silence, TLS, protocol, framing, local encode */
  long                           pair_log_at;        /* when a pairing may be logged again */
  int                            expected_close;     /* RESULT was sent, peer may close normally */
  ulong                          generation;         /* identifies the current authenticated session */
};

FD_FN_CONST ulong fd_failover_channel_align    ( void ) { return alignof(fd_failover_channel_t); }
FD_FN_CONST ulong fd_failover_channel_footprint( void ) { return sizeof (fd_failover_channel_t); }

void *
fd_failover_channel_new( void * shmem ) {
  if( !shmem || !fd_ulong_is_aligned( (ulong)shmem, fd_failover_channel_align() ) ) return NULL;
  fd_failover_channel_t * ch = shmem;
  /* Initialize the listening state with no sockets open. */
  fd_memset( ch, 0, sizeof(*ch) );
  ch->listen_fd  = -1;
  ch->paired_idx = -1;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) ch->candidates[i].fd = -1;
  ch->hello_timeout   = FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS;
  ch->silence_timeout = FD_FAILOVER_CHANNEL_IDLE_NANOS;
  ch->backoff_min     = FD_FAILOVER_CHANNEL_BACKOFF_MIN_NANOS;
  ch->backoff_max     = FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS;
  ch->backoff         = ch->backoff_min;
  ch->rate_credit     = FD_FAILOVER_ACCEPT_BURST*FD_FAILOVER_NANOS_PER_SECOND;
  ch->admit_credit    = FD_FAILOVER_ADMIT_BURST*FD_FAILOVER_NANOS_PER_SECOND;
  ch->verify_credit   = FD_FAILOVER_VERIFY_BURST*FD_FAILOVER_NANOS_PER_SECOND;
  ch->priority_verify_credit = FD_FAILOVER_PRIORITY_VERIFY_BURST*FD_FAILOVER_NANOS_PER_SECOND;
  ch->reconnect_credit       = FD_FAILOVER_RECONNECT_BURST*FD_FAILOVER_NANOS_PER_SECOND;
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
  if( c->tls_started ) fd_failover_tls_fini( &c->tls );
  c->tls_started = 0;
  if( c->fd!=-1 ) close( c->fd );
  /* Closing a candidate frees its slot. */
  c->fd      = -1;
  c->dialed  = 0;
  c->rx_used = c->tx_used = c->tx_sent = 0UL;
  fd_memzero_explicit( &c->wire, sizeof(c->wire) );
}

static void
reset( fd_failover_channel_t * ch ) {
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) close_candidate( &ch->candidates[i] );
  /* Discard the paired session. */
  ch->paired_idx = -1;
  ch->last_rx    = 0L;
  fd_memset( &ch->peer_hello, 0, sizeof(ch->peer_hello) );
}

/* A standby may authenticate before its operator requests a handoff. */
static int
want_dial( fd_failover_channel_t const * ch ) {
  return !!ch->peer_addr;
}

/* Resets an unpaired channel, to LISTENING without a dial address or to
   BACKOFF with an immediate retry with one. */
static void
rest( fd_failover_channel_t * ch ) {
  if( ch->paired_idx>=0 ) return; /* Keep a paired session through address changes. */
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( ch->candidates[i].dialed ) close_candidate( &ch->candidates[i] );
  ch->dial_peer = want_dial( ch );
  /* An unpaired channel listens or becomes ready to dial. */
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
  if( bind( ch->listen_fd, fd_type_pun( &addr ), sizeof(addr) ) || listen( ch->listen_fd, FD_FAILOVER_LISTEN_BACKLOG ) )
    FD_LOG_ERR(( "could not listen on `" FD_IP4_ADDR_FMT ":%hu` from [failover.listen_address] and [failover.listen_port] (%i-%s)",
                 FD_IP4_ADDR_FMT_ARGS( address ), port, errno, fd_io_strerror( errno ) ));
}

void
fd_failover_channel_init_dialer( fd_failover_channel_t * ch,
                                 uint                    address,
                                 ushort                  port ) {
  if( address==ch->peer_addr && port==ch->peer_port ) return;
  if( address && ch->paired_idx>=0 ) reset( ch );
  ch->peer_addr = address;
  ch->peer_port = port;
  if( address ) {
    fd_memset( ch->dial_log_at, 0, sizeof(ch->dial_log_at) );
    /* A new dial target starts from the shortest backoff. */
    ch->backoff = ch->backoff_min;
  }
  rest( ch );
}

int
fd_failover_channel_set_identity( fd_failover_channel_t *     ch,
                                  uchar const                 junk_pubkey[ 32 ],
                                  fd_tls_sign_t               signer,
                                  fd_failover_proof_signer_t   proof_signer,
                                  fd_failover_hello_t const *  hello ) {
  if( !proof_signer.sign_fn || !signer.sign_fn ||
      !fd_memeq( junk_pubkey, hello->junk_pubkey, 32UL ) ||
      fd_memeq( hello->junk_pubkey, hello->staked_pubkey, 32UL ) ) return -1;
  reset( ch );
  /* An identity change requires a fresh session. */
  fd_memset( ch->known_sources, 0, sizeof(ch->known_sources) );
  ch->state = fd_failover_session_init( ch->dial_peer );
  ch->self_hello   = *hello;
  ch->proof_signer = proof_signer;
  return fd_failover_tls_ctx_init( &ch->tls_ctx, junk_pubkey, signer );
}

void
fd_failover_channel_fini( fd_failover_channel_t * ch ) {
  reset( ch );
  if( ch->listen_fd!=-1 ) close( ch->listen_fd );
  ch->listen_fd = -1;
  fd_failover_tls_ctx_fini( &ch->tls_ctx );
}

fd_failover_channel_metrics_t const *
fd_failover_channel_metrics( fd_failover_channel_t const * ch ) { return &ch->metrics; }

void
fd_failover_channel_set_role( fd_failover_channel_t * ch,
                              ulong                   role ) {
  if( ch->self_hello.role==(uchar)role ) return;
  ch->self_hello.role = (uchar)role;
  for( ulong i=0UL; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ )
    if( (int)i!=ch->paired_idx ) close_candidate( &ch->candidates[i] );
  if( ch->paired_idx<0 ) rest( ch );
}

FD_FN_PURE ulong fd_failover_channel_state    ( fd_failover_channel_t const * ch ) { return ch->state;     }
FD_FN_PURE int   fd_failover_channel_listen_fd( fd_failover_channel_t const * ch ) { return ch->listen_fd; }

FD_FN_PURE int
fd_failover_channel_tx_pending( fd_failover_channel_t const * ch ) {
  if( ch->paired_idx<0 ) return 0;
  struct candidate const * c = &ch->candidates[ch->paired_idx];
  return !!c->tx_used || fd_tlsrec_sock_tx_pending( &c->tls.sock );
}

FD_FN_PURE ulong
fd_failover_channel_pending( fd_failover_channel_t const * ch ) {
  ulong n = 0UL;
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) n += ch->candidates[i].fd!=-1 && (int)i!=ch->paired_idx;
  return n;
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

/* Spreads a redial over up to one minimum backoff, so standbys that
   dial each other do not keep colliding in step. */
static long
jitter( fd_failover_channel_t const * ch ) {
  ulong r = 0UL;
  if( FD_UNLIKELY( ch->backoff_min<=0L || !fd_rng_secure( &r, sizeof(r) ) ) ) return 0L;
  return (long)( r%(ulong)ch->backoff_min );
}

/* An ALPN or authentication failure still gets logged while another
   kind of TLS error is being suppressed.  The number of buckets is
   fixed, so unknown peers cannot allocate log state or flood it. */
static ulong
tls_log_kind( uint reason ) {
  if( !reason ) return 0UL;
  if( reason==FD_TLS_REASON_ALPN_PARSE || reason==FD_TLS_REASON_ALPN_NEG || reason==FD_TLS_REASON_NO_ALPN ) return 1UL;
  if( reason==FD_TLS_REASON_WRONG_PUBKEY || reason==FD_TLS_REASON_ED25519_FAIL || reason==FD_TLS_REASON_CERT_VERIFY ) return 2UL;
  return 3UL;
}

/* Every session state change goes through fd_failover_session_init or
   fd_failover_session_step in fd_failover_proto.c. */
static void
drop( fd_failover_channel_t * ch,
      ulong                   idx,
      long                    now,
      int                     event ) {
  struct candidate * c        = &ch->candidates[idx];
  int                paired   = ch->paired_idx==(int)idx;
  int                accepted = c->fd!=-1 && !c->dialed;
  close_candidate( c );
  if( paired ) {
    ch->paired_idx = -1;
    ch->last_rx    = 0L;
    fd_memset( &ch->peer_hello, 0, sizeof(ch->peer_hello) );
  }
  /* A candidate from the listener does not move the session until it
     pairs. */
  if( !paired && accepted ) return;
  /* Loss returns the session to listening or backoff. */
  ch->state = fd_failover_session_step( ch->state, ch->dial_peer, event );
  /* After loss, use the current handoff address to choose listener or dialer. */
  if( paired && want_dial( ch )!=ch->dial_peer ) rest( ch );
  if( ch->dial_peer ) {
    /* A session counts as established once it outlives the handshake
       window, whichever side dialed it.  Losing an established session
       redials at once and resets the backoff, losing any other doubles
       it, so a peer that rejects us right after HELLO cannot drive a
       redial storm. */
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
  if( ch->paired_idx==(int)idx && now>=ch->loss_log_at[cause] ) {
    ch->loss_log_at[cause] = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
    FD_LOG_WARNING(( "lost the failover session with `" FD_IP4_ADDR_FMT "`, %s, repeated failures limited to one line per minute",
                     FD_IP4_ADDR_FMT_ARGS( ch->candidates[idx].address ), why ));
  }
  drop( ch, idx, now, event );
}

void
fd_failover_channel_hangup( fd_failover_channel_t * ch,
                            long                    now ) {
  if( ch->paired_idx>=0 ) drop( ch, (ulong)ch->paired_idx, now, FD_FAILOVER_EV_LINK_LOST );
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( ch->candidates[i].fd!=-1 ) drop( ch, i, now, FD_FAILOVER_EV_LINK_LOST );
}

void
fd_failover_channel_protocol_error( fd_failover_channel_t * ch,
                                    long                    now ) {
  ch->metrics.wire_fatal_cnt++;
  if( FD_LIKELY( ch->paired_idx>=0 ) ) {
    lose( ch, (ulong)ch->paired_idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_PROTOCOL, "it sent a message that breaks the protocol, check that both machines run the same Firedancer version" );
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
    ulong elapsed = fd_ulong_min( (ulong)now-(ulong)*updated, FD_FAILOVER_NANOS_PER_SECOND );
    credit   = fd_ulong_min( credit+elapsed*rate, burst*FD_FAILOVER_NANOS_PER_SECOND );
    *updated = now;
  }
  return credit;
}

/* Records are created only for allocated candidates.  The admission
   budget bounds their count through the longest quota and quiet period. */
static struct source *
source_get( fd_failover_channel_t * ch,
            uint                    address,
            long                    now,
            int                     create ) {
  struct source * source   = NULL;
  struct source * reusable = NULL;
  for( ulong i=0; i<SOURCE_CNT; i++ ) {
    struct source * s = &ch->sources[i];
    if( s->used && s->address==address ) { source = s; break; }
    if( !reusable || ( reusable->used && ( !s->used || s->last_admit<reusable->last_admit ) ) ) reusable = s;
  }
  if( !source ) {
    if( !create ) return NULL;
    source  = reusable;
    *source = (struct source){ .address=address, .used=1, .last_admit=now };
  }
  return source;
}

static int
admit( fd_failover_channel_t * ch,
       uint                    address,
       long                    now ) {
  for( ulong i=RECONNECT_IDX; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ )
    if( ch->candidates[i].fd!=-1 && ch->candidates[i].address==address ) return 0;
  struct source const * source = source_get( ch, address, now, 0 );
  return !source || now>=source->next_admit;
}

static void
source_admitted( fd_failover_channel_t * ch,
                 uint                    address,
                 long                    now ) {
  struct source * source = source_get( ch, address, now, 1 );
  if( !source->backoff || now>=fd_long_sat_add( source->next_admit, FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS ) )
    source->backoff = ch->hello_timeout;
  else
    source->backoff = fd_long_min( fd_long_sat_add( source->backoff, source->backoff ), FD_FAILOVER_CHANNEL_BACKOFF_MAX_NANOS );
  source->last_admit = now;
  source->next_admit = fd_long_sat_add( now, source->backoff );
}

static int
proof_ready( struct candidate const * c ) {
  return c->phase==PHASE_REQUEST_RECV && c->rx_used==sizeof(c->client_proof);
}

/* Admission never displaces an existing handshake.  Its phase and
   absolute deadlines bound retention even when it stops progressing. */
static ulong
listen_slot( fd_failover_channel_t * ch,
             long                    now FD_PARAM_UNUSED ) {
  for( ulong i=UNAUTHENTICATED_IDX; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    if( ch->candidates[i].fd==-1 ) return i;
  }
  return FD_FAILOVER_CHANNEL_CANDIDATE_MAX;
}

static int
known_source( fd_failover_channel_t const * ch, uint address, long now ) {
  for( ulong i=0UL; i<KNOWN_SOURCE_CNT; i++ )
    if( ch->known_sources[i].address==address && now<ch->known_sources[i].until ) return 1;
  return 0;
}

/* Only a completed mutual authentication or a frame on that session
   refreshes this cache.  An IP grants scheduling priority, not trust. */
static void
remember_source( fd_failover_channel_t * ch, uint address, long now ) {
  ulong idx = 0UL;
  for( ulong i=0UL; i<KNOWN_SOURCE_CNT; i++ ) {
    if( ch->known_sources[i].address==address ) { idx = i; break; }
    if( ch->known_sources[i].until<ch->known_sources[idx].until ) idx = i;
  }
  ch->known_sources[idx] = (struct known_source){ .address=address, .until=fd_long_sat_add( now, ch->silence_timeout ) };
}

static int
start( fd_failover_channel_t * ch,
       ulong                   idx,
       int                     fd,
       uint                    address,
       long                    now,
       int                     phase ) {
  struct candidate * c = &ch->candidates[idx];
  /* Inbound sockets do not initialize TLS until admission succeeds. */
  c->fd = fd; c->address = address; c->phase = phase; c->dialed = phase==PHASE_CONNECT;
  c->priority = c->dialed || idx==RECONNECT_IDX;
  c->deadline        = fd_long_sat_add( now, ch->hello_timeout );
  c->admission_until = c->dialed ? c->deadline : fd_long_min( c->deadline, fd_long_sat_add( now, FD_FAILOVER_ADMISSION_START_NANOS ) );
  c->accepted_at     = now;
  c->local_hello = ch->self_hello;
  c->rx_used = c->tx_used = c->tx_sent = 0UL;
  c->tls_started = 0;
  fd_failover_wire_session_init( &c->wire );
  return 0;
}

static void
accept_candidates( fd_failover_channel_t * ch,
                   long                    now,
                   int *                   busy ) {
  for( ulong n=0; n<FD_FAILOVER_ACCEPT_PER_POLL; n++ ) {
    ch->rate_credit = refill( ch->rate_credit, &ch->rate_updated, now, FD_FAILOVER_ACCEPT_RATE, FD_FAILOVER_ACCEPT_BURST );
    if( ch->rate_credit<FD_FAILOVER_NANOS_PER_SECOND ) { ch->metrics.accept_limited_cnt++; return; }
    ch->rate_credit -= FD_FAILOVER_NANOS_PER_SECOND;
    struct sockaddr_in addr;
    socklen_t          len = sizeof(addr);
    int                fd  = accept4( ch->listen_fd, fd_type_pun( &addr ), &len, SOCK_NONBLOCK|SOCK_CLOEXEC );
    if( fd==-1 ) return;
    ch->metrics.accept_cnt++;
    *busy = 1;
    ch->admit_credit = refill( ch->admit_credit, &ch->admit_updated, now, FD_FAILOVER_ADMIT_RATE, FD_FAILOVER_ADMIT_BURST );
    ch->reconnect_credit = refill( ch->reconnect_credit, &ch->reconnect_updated, now, FD_FAILOVER_RECONNECT_RATE, FD_FAILOVER_RECONNECT_BURST );
    if( ch->paired_idx>=0 || len!=sizeof(addr) || addr.sin_family!=AF_INET ) {
      close( fd );
      continue;
    }
    int priority = known_source( ch, addr.sin_addr.s_addr, now );
    ulong * credit = priority ? &ch->reconnect_credit : &ch->admit_credit;
    if( *credit<FD_FAILOVER_NANOS_PER_SECOND ) {
      ch->metrics.budget_reject_cnt++;
      close( fd );
      continue;
    }
    ulong idx = priority ? RECONNECT_IDX : listen_slot( ch, now );
    if( priority && ch->candidates[idx].fd!=-1 ) idx = FD_FAILOVER_CHANNEL_CANDIDATE_MAX;
    if( FD_UNLIKELY( idx==FD_FAILOVER_CHANNEL_CANDIDATE_MAX ) ) {
      ch->metrics.capacity_reject_cnt++;
      close( fd );
      continue;
    }
    if( !admit( ch, addr.sin_addr.s_addr, now ) ) {
      ch->metrics.source_reject_cnt++;
      close( fd );
      continue;
    }
    /* An accepted candidate leaves the session unpaired until authentication. */
    if( !start( ch, idx, fd, addr.sin_addr.s_addr, now, PHASE_START_RECV ) ) {
      *credit -= FD_FAILOVER_NANOS_PER_SECOND;
      ch->metrics.reconnect_cnt += (ulong)priority;
      source_admitted( ch, addr.sin_addr.s_addr, now );
      ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_PEER_CONNECTED );
    }
  }
}

static int
flush( fd_failover_channel_t * ch,
       ulong                   idx,
       long                    now,
       int *                   busy ) {
  struct candidate * c = &ch->candidates[idx];
  if( !c->tx_used ) {
    int rc = fd_failover_tls_flush( &c->tls );
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
  int                err = fd_failover_wire_decode( &c->wire, c->rx, c->rx_used, type, &data, payload_sz, &frame_sz );
  if( err==FD_FAILOVER_WIRE_ERR_AGAIN ) return 0;
  if( err ) { lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_FRAME, "it sent a malformed frame, check that both machines run the same Firedancer version" ); return -1; }
  fd_memcpy( payload, data, *payload_sz );
  memmove( c->rx, c->rx+frame_sz, c->rx_used-frame_sz );
  c->rx_used -= frame_sz;
  *busy = 1;
  return 1;
}

/* We log a HELLO refusal by name, with what the operator should check. */
static char const *
hello_err_name( int err ) {
  switch( err ) {
  case HELLO_ERR_TLS_KEY:                return "its junk key is not the key TLS authenticated, check who can reach the failover port";
  case FD_FAILOVER_HELLO_ERR_VERSION:    return "the protocol version differs, run the same Firedancer version on both machines";
  case FD_FAILOVER_HELLO_ERR_STAKED:     return "the failover identity differs, check that both machines run [paths.identity_key] with the same keypair, or the same key from their last `set-identity`";
  case FD_FAILOVER_HELLO_ERR_VOTE_ACCT:  return "the vote account differs, check that [paths.vote_account] is the same on both machines";
  case FD_FAILOVER_HELLO_ERR_JUNK_EQ:    return "its junk key is ours, check that the address is the other validator";
  case FD_FAILOVER_HELLO_ERR_JUNK_STAKE: return "a boot identity is the staked key, the standby must use a different identity";
  case FD_FAILOVER_HELLO_ERR_BOTH_ACT:   return "both members are active, only one machine may run the staked identity, stop the validator that should not vote, a failover-enabled validator restarts as standby";
  case FD_FAILOVER_HELLO_ERR_ROLE:       return "the role is unknown, run the same Firedancer version on both machines";
  case FD_FAILOVER_HELLO_ERR_BOOT_ID:    return "the boot id is zero, run the same Firedancer version on both machines";
  case FD_FAILOVER_HELLO_ERR_MODE:       return "the consensus mode differs, run both machines in the same consensus mode";
  case FD_FAILOVER_HELLO_ERR_PROOF:      return "its admission proof is not signed by the failover identity, check that both machines hold the same keypair for it";
  default:                              return "unknown";
  }
}

static void
hello_refused( fd_failover_channel_t * ch, uint address, int err, long now ) {
  ch->metrics.hello_reject_cnt++;
  ch->metrics.proof_reject_cnt += (ulong)( err==FD_FAILOVER_HELLO_ERR_PROOF );
  ulong bucket = err==HELLO_ERR_TLS_KEY ? 12UL : ( err>0 && err<=FD_FAILOVER_HELLO_ERR_PROOF ? (ulong)err : 13UL );
  if( now<ch->hello_log_at[bucket] ) return;
  ch->hello_log_at[bucket] = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
  FD_LOG_WARNING(( "rejected the failover peer at `" FD_IP4_ADDR_FMT "`, %s",
                   FD_IP4_ADDR_FMT_ARGS( address ), hello_err_name( err ) ));
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
  if( c->rx_used>=max ) { drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return -1; }
  long n = fd_failover_tls_read( &c->tls, c->rx+c->rx_used, max-c->rx_used );
  if( n<0L ) {
    /* The listener responds only to a HELLO it accepts, so a close here
       usually means it refused ours. */
    if( FD_UNLIKELY( c->dialed && c->phase==PHASE_HELLO && now>=ch->dial_log_at[1] ) ) {
      ch->dial_log_at[1] = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
      FD_LOG_WARNING(( "the failover peer at `" FD_IP4_ADDR_FMT "` closed the connection before answering our HELLO, its log says why it refused us",
                       FD_IP4_ADDR_FMT_ARGS( c->address ) ));
    }
    if( ch->paired_idx==(int)idx && ch->expected_close && c->tls.peer_closed && !fd_failover_channel_tx_pending( ch ) ) {
      drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
      return -1;
    }
    if( fd_tlsrec_conn_is_failed( &c->tls.conn ) ) {
      char why[ 192 ];
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

/* Return one to continue this poll, zero to stop after a wait or failure. */
static int
connect_candidate( fd_failover_channel_t * ch,
                   ulong                   idx,
                   long                    now ) {
  struct candidate * c = &ch->candidates[idx];
  struct sockaddr_in addr = { .sin_family=AF_INET, .sin_port=fd_ushort_bswap( ch->peer_port ), .sin_addr.s_addr=ch->peer_addr };
  if( connect( c->fd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EISCONN ) {
    if( errno==EINPROGRESS || errno==EALREADY || errno==EINTR ) return 0; /* TCP is still connecting. */
    if( now>=ch->dial_log_at[0] ) {
      ch->dial_log_at[0] = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
      FD_LOG_WARNING(( "could not connect to the failover peer at `" FD_IP4_ADDR_FMT ":%hu` (%i-%s), check that it runs and that the machines can reach each other on [failover.listen_port]",
                       FD_IP4_ADDR_FMT_ARGS( ch->peer_addr ), ch->peer_port, errno, fd_io_strerror( errno ) ));
    }
    /* A failed connect returns the dialer to backoff. */
    drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
    return 0;
  }
  /* Only operator-initiated outbound work prepares a TLS key share here. */
  if( fd_failover_tls_new( &c->tls, &ch->tls_ctx, c->fd, 1 ) ) {
    drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
    return 0;
  }
  c->tls_started = 1;
  ulong hello_sz = sizeof(c->client_hello);
  if( fd_failover_tls_client_hello( &c->tls, c->client_hello, &hello_sz ) ||
      hello_sz>sizeof(c->client_hello) ) {
    drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
    return 0;
  }
  c->start = (fd_failover_admission_start_t){ .magic=FD_FAILOVER_ADMISSION_MAGIC,
                                            .hello=c->local_hello, .client_hello_sz=(ushort)hello_sz };
  if( !fd_rng_secure( c->start.nonce, sizeof(c->start.nonce) ) ) {
    drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
    return 0;
  }
  fd_memcpy( c->tx, &c->start, sizeof(c->start) );
  fd_memcpy( c->tx+sizeof(c->start), c->client_hello, hello_sz );
  c->tx_used = sizeof(c->start)+hello_sz;
  c->phase = PHASE_START_SEND;
  ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_CONNECTED );
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
    ch->metrics.tls_fail_cnt++;
    uint  reason = c->tls.conn.hs.base.reason;
    ulong kind   = tls_log_kind( reason );
    if( now>=ch->tls_log_at[kind] ) {
      ch->tls_log_at[kind] = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
      FD_LOG_WARNING(( "TLS handshake with `" FD_IP4_ADDR_FMT "` failed (%s), not necessarily the other failover machine, check peer reachability and junk keys on both machines",
                       FD_IP4_ADDR_FMT_ARGS( c->address ), reason ? fd_tls_reason_cstr( reason ) : "connection closed or socket error" ));
    }
    /* TLS failure closes the candidate and returns an outbound dial to backoff. */
    drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST );
    return 0;
  }
  if( !rc ) return 0; /* Keep waiting for TLS. */
  *busy = 1;
  /* TLS authenticated a key, now check the peer HELLO. */
  c->phase = PHASE_HELLO;
  /* The dialer sends first.  On the listener we respond only to a HELLO
     that passed the checks below. */
  if( c->dialed ) c->tx_used = fd_failover_wire_encode( &c->wire, c->tx, FD_FAILOVER_MSG_HELLO,
                                                        (uchar const *)&c->local_hello, sizeof(c->local_hello) );
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
  if( read_frame( ch, idx, now, busy, &type, payload, &sz )<=0 ) return 0; /* Wait for HELLO, or stop after a read failure. */
  if( type!=FD_FAILOVER_MSG_HELLO || sz!=sizeof(c->hello) ) {
    if( now>=ch->hello_log_at[0] ) {
      ch->hello_log_at[0] = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
      FD_LOG_WARNING(( "rejected the failover HELLO from `" FD_IP4_ADDR_FMT "`, its first frame is not a HELLO, check who can reach the failover port", FD_IP4_ADDR_FMT_ARGS( c->address ) ));
    }
    /* A malformed HELLO closes this candidate without pairing. */
    drop( ch, idx, now, FD_FAILOVER_EV_HELLO_FATAL );
    return 0;
  }
  /* HELLO and TLS must match the admission transcript exactly. */
  int err = fd_memeq( payload, &c->hello, sizeof(c->hello) ) &&
            fd_memeq( c->hello.junk_pubkey, c->tls.peer_pubkey, 32UL )
          ? fd_failover_hello_check( &c->local_hello, &c->hello ) : HELLO_ERR_TLS_KEY;
  if( err!=FD_FAILOVER_HELLO_OK ) {
    hello_refused( ch, c->address, err, now );
    /* A refused HELLO closes this candidate without pairing. */
    drop( ch, idx, now, FD_FAILOVER_EV_HELLO_FATAL );
    return 0;
  }
  /* The peer is authenticated, finish any HELLO output before pairing. */
  c->phase = PHASE_READY;
  if( !c->dialed ) {
    c->tx_used = fd_failover_wire_encode( &c->wire, c->tx, FD_FAILOVER_MSG_HELLO,
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
  /* The first session that authenticates wins.  One that came in on the
     listener while we were dialing pairs as the listener. */
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) if( i!=idx ) close_candidate( &ch->candidates[i] );
  if( !c->dialed && ch->dial_peer ) {
    /* An inbound candidate won, pair as the listener. */
    ch->dial_peer = 0;
    ch->state     = fd_failover_session_init( ch->dial_peer );
  }
  ch->paired_idx = (int)idx;
  c->tls.paired = 1;
  ch->peer_hello = c->hello;
  /* HELLO is complete, this candidate becomes the paired session. */
  ch->state      = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_HELLO_OK );
  ch->generation++;
  remember_source( ch, c->address, now );
  ch->metrics.paired_cnt++;
  ch->metrics.handshake_latest_nanos = (ulong)fd_long_max( now-c->accepted_at, 0L );
  ch->metrics.handshake_duration_nanos += ch->metrics.handshake_latest_nanos;
  ch->keepalive_at   = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_KEEPALIVE_NANOS );
  ch->last_rx        = now;
  ch->paired_at      = now;
  ch->expected_close = 0;
  *busy = 1;
  if( now>=ch->pair_log_at ) {
    ch->pair_log_at = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
    char member[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( c->hello.junk_pubkey, NULL, member );
    FD_LOG_NOTICE(( "paired with the failover peer at `" FD_IP4_ADDR_FMT "` via %s, authenticated member %s, role %s, boot id %016lx",
                    FD_IP4_ADDR_FMT_ARGS( c->address ), c->dialed ? "outbound dial" : "listener", member,
                    c->hello.role==FD_FAILOVER_ROLE_ACTIVE ? "active" : "standby", c->hello.boot_id ));
  }
}

/* Each admission service turn performs at most one socket operation.
   No input can extend the absolute candidate deadline. */
static int
admission_read( struct candidate * c, ulong goal, int * busy ) {
  if( FD_UNLIKELY( goal>FD_FAILOVER_ADMISSION_MAX || c->rx_used>goal ) ) return -1;
  if( c->rx_used==goal ) return 1;
  long n = recv( c->fd, c->rx+c->rx_used, goal-c->rx_used, MSG_DONTWAIT|MSG_NOSIGNAL );
  if( n<0L ) return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ? 0 : -1;
  if( !n ) return -1;
  c->rx_used += (ulong)n;
  *busy = 1;
  return c->rx_used==goal;
}

static int
admission_write( struct candidate * c, int * busy ) {
  long n = send( c->fd, c->tx+c->tx_sent, c->tx_used-c->tx_sent, MSG_DONTWAIT|MSG_NOSIGNAL );
  if( n<0L ) return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ? 0 : -1;
  if( !n ) return -1;
  c->tx_sent += (ulong)n;
  *busy = 1;
  if( c->tx_sent<c->tx_used ) return 0;
  c->tx_sent = c->tx_used = 0UL;
  return 1;
}

static int
proof_verify( fd_failover_channel_t * ch, struct candidate * c, int server, uchar const sig[ 64 ] ) {
  uchar msg[ FD_KEYGUARD_FAILOVER_PROOF_SZ ];
  fd_failover_proof_msg( msg, server, c->hello.junk_pubkey, c->transcript );
  return fd_ed25519_verify( msg, sizeof(msg), sig, c->local_hello.staked_pubkey, ch->sha )==FD_ED25519_SUCCESS;
}

static int
proof_sign( fd_failover_channel_t * ch, struct candidate * c, int server ) {
  uchar msg[ FD_KEYGUARD_FAILOVER_PROOF_SZ ];
  fd_failover_proof_msg( msg, server, c->local_hello.junk_pubkey, c->transcript );
  ch->proof_signer.sign_fn( ch->proof_signer.ctx, c->tx, msg );
  /* An operator identity change may have reached Sign first. */
  if( fd_ed25519_verify( msg, sizeof(msg), c->tx, c->local_hello.staked_pubkey, ch->sha )!=FD_ED25519_SUCCESS ) return 0;
  c->tx_used = 64UL;
  c->tx_sent = 0UL;
  return 1;
}

static int
verify_credit( fd_failover_channel_t * ch, struct candidate const * c, long now ) {
  ch->verify_credit = refill( ch->verify_credit, &ch->verify_updated, now, FD_FAILOVER_VERIFY_RATE, FD_FAILOVER_VERIFY_BURST );
  ch->priority_verify_credit = refill( ch->priority_verify_credit, &ch->priority_verify_updated, now,
                                       FD_FAILOVER_PRIORITY_VERIFY_RATE, FD_FAILOVER_PRIORITY_VERIFY_BURST );
  ulong * credit = c->priority ? &ch->priority_verify_credit : &ch->verify_credit;
  if( !ch->verify_budget || *credit<FD_FAILOVER_NANOS_PER_SECOND ) return 0;
  ch->verify_budget--;
  *credit -= FD_FAILOVER_NANOS_PER_SECOND;
  return 1;
}

static void
admission_service( fd_failover_channel_t * ch, ulong idx, long now, int * busy ) {
  struct candidate * c = &ch->candidates[idx];
  int rc;
  switch( c->phase ) {
  case PHASE_START_SEND:
  case PHASE_CHALLENGE_SEND:
  case PHASE_REQUEST_SEND:
  case PHASE_RESPONSE_SEND:
    rc = admission_write( c, busy );
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
    rc = admission_read( c, goal, busy );
    if( rc<0 ) break;
    if( !rc ) return;
    if( goal==sizeof(c->start) ) {
      fd_memcpy( &c->start, c->rx, sizeof(c->start) );
      if( c->start.magic!=FD_FAILOVER_ADMISSION_MAGIC ||
          c->start.client_hello_sz<=sizeof(fd_tlsrec_hdr_t) ||
          c->start.client_hello_sz>sizeof(c->client_hello) ) break;
      int err = fd_failover_hello_check( &c->local_hello, &c->start.hello );
      if( err ) { hello_refused( ch, c->address, err, now ); break; }
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
    rc = admission_read( c, sizeof(c->challenge), busy );
    if( rc<0 ) break;
    if( !rc ) return;
    fd_memcpy( &c->challenge, c->rx, sizeof(c->challenge) );
    if( c->challenge.magic!=FD_FAILOVER_ADMISSION_MAGIC ) break;
    int err = fd_failover_hello_check( &c->local_hello, &c->challenge.hello );
    if( err ) { hello_refused( ch, c->address, err, now ); break; }
    c->hello = c->challenge.hello;
    fd_failover_admission_hash( &c->start, c->client_hello, &c->challenge, c->transcript );
    c->rx_used = 0UL;
    c->phase = PHASE_REQUEST_SIGN;
    *busy = 1;
    return;
  case PHASE_REQUEST_SIGN:
    if( !verify_credit( ch, c, now ) ) return;
    if( !proof_sign( ch, c, 0 ) ) break;
    fd_memcpy( c->client_proof, c->tx, sizeof(c->client_proof) );
    c->phase = PHASE_REQUEST_SEND;
    *busy = 1;
    return;
  case PHASE_RESPONSE_RECV: {
    fd_failover_admission_response_t response;
    if( c->rx_used<sizeof(response) ) {
      rc = admission_read( c, sizeof(response), busy );
      if( rc<0 ) break;
      if( !rc ) return;
      fd_memcpy( &response, c->rx, sizeof(response) );
      if( !response.server_flight_sz || response.server_flight_sz>FD_FAILOVER_SERVER_FLIGHT_MAX ) break;
      return;
    }
    fd_memcpy( &response, c->rx, sizeof(response) );
    rc = admission_read( c, sizeof(response)+response.server_flight_sz, busy );
    if( rc<0 ) break;
    if( !rc || !verify_credit( ch, c, now ) ) return;
    fd_failover_response_hash( c->transcript, c->client_proof, c->rx+sizeof(response),
                               response.server_flight_sz, c->transcript );
    if( !proof_verify( ch, c, 1, response.proof ) ) {
      hello_refused( ch, c->address, FD_FAILOVER_HELLO_ERR_PROOF, now );
      break;
    }
    if( fd_failover_tls_accept_flight( &c->tls, c->rx+sizeof(response), response.server_flight_sz ) ) break;
    c->phase = PHASE_TLS;
    c->rx_used = 0UL;
    *busy = 1;
    return;
  }
  case PHASE_REQUEST_RECV:
    rc = admission_read( c, 64UL, busy );
    if( rc<0 ) break;
    if( !rc || !verify_credit( ch, c, now ) ) return;
    if( !proof_verify( ch, c, 0, c->rx ) ) {
      hello_refused( ch, c->address, FD_FAILOVER_HELLO_ERR_PROOF, now );
      break;
    }
    struct source * source = source_get( ch, c->address, now, 0 );
    if( source ) {
      source->backoff    = 0L;
      source->next_admit = 0L;
    }
    if( ch->candidates[ ADMITTED_IDX ].fd!=-1 ) break;
    fd_memcpy( c->client_proof, c->rx, sizeof(c->client_proof) );
    c->rx_used         = 0UL;
    c->admission_until = c->deadline;
    c->phase           = PHASE_TLS_START;
    c->priority        = 1;
    /* Only a verified proof can claim this protected slot. */
    ch->candidates[ ADMITTED_IDX ] = *c;
    c->fd = -1;
    c->tls_started = 0;
    *busy = 1;
    return;
  case PHASE_RESPONSE_SIGN: {
    if( !verify_credit( ch, c, now ) ) return;
    fd_failover_admission_response_t response = { .server_flight_sz=(ushort)(c->tx_used-sizeof(fd_failover_admission_response_t)) };
    if( !proof_sign( ch, c, 1 ) ) break;
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
  if( c->dialed && now>=ch->dial_log_at[1] ) {
    ch->dial_log_at[1] = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
    FD_LOG_WARNING(( "the failover peer at `" FD_IP4_ADDR_FMT "` did not complete admission, check its log for an identity or vote account mismatch and that both machines run the same version",
                     FD_IP4_ADDR_FMT_ARGS( c->address ) ));
  }
  drop( ch, idx, now, FD_FAILOVER_EV_HELLO_FATAL );
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
    if( connect_candidate( ch, idx, now ) ) *busy = 1;
    return;
  }
  if( c->phase<PHASE_TLS ) {
    admission_service( ch, idx, now, busy );
    return;
  }
  if( c->phase==PHASE_TLS ) {
    if( !handshake_candidate( ch, idx, now, busy ) ) return;
  }
  if( flush( ch, idx, now, busy )!=0 ) return; /* Wait for output, or stop after a write failure. */
  if( c->phase==PHASE_HELLO ) {
    if( !read_candidate_hello( ch, idx, now, busy, payload ) ) return;
  }
  if( c->phase==PHASE_READY && !c->tx_used ) {
    pair_candidate( ch, idx, now, busy );
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
  ch->verify_budget = 1;
  ch->verify_credit = refill( ch->verify_credit, &ch->verify_updated, now, FD_FAILOVER_VERIFY_RATE, FD_FAILOVER_VERIFY_BURST );
  /* Established traffic gets service before the bounded accept drain. */
  if( ch->paired_idx>=0 ) {
    ulong idx = (ulong)ch->paired_idx;
    fd_failover_tls_budget( &ch->candidates[idx].tls );
    int flushed = flush( ch, idx, now, busy );
    if( !flushed ) {
      int rc = read_frame( ch, idx, now, busy, type, payload, payload_sz );
      if( rc>0 ) {
        if( *type==FD_FAILOVER_MSG_HELLO ) { lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_PROTOCOL, "it sent a second HELLO, check that both machines run the same Firedancer version" ); }
        else {
          ch->last_rx = now;
          remember_source( ch, ch->candidates[idx].address, now );
          delivered = *type!=FD_FAILOVER_MSG_KEEPALIVE;
        }
      } else if( !rc && now>=ch->last_rx && now-ch->last_rx>ch->silence_timeout ) {
        lose( ch, idx, now, FD_FAILOVER_EV_TIMEOUT, LOSS_SILENCE, "the handoff connection was idle past its deadline, check the peer log" );
      }
    }
    if( flushed>0 && now>=ch->last_rx && now-ch->last_rx>ch->silence_timeout ) {
      lose( ch, idx, now, FD_FAILOVER_EV_TIMEOUT, LOSS_SILENCE, "the handoff connection stopped making progress, check the peer log" );
    }
    if( ch->paired_idx>=0 && !fd_failover_channel_tx_pending( ch ) && now>=ch->keepalive_at ) {
      if( !fd_failover_channel_send( ch, now, FD_FAILOVER_MSG_KEEPALIVE, NULL, 0UL ) ) {
        ch->keepalive_at = fd_long_sat_add( now, FD_FAILOVER_CHANNEL_KEEPALIVE_NANOS );
        *busy = 1;
      }
    }
  }
  /* Expire every slot each poll, independently of round-robin service. */
  for( ulong i=0; i<FD_FAILOVER_CHANNEL_CANDIDATE_MAX; i++ ) {
    struct candidate * c = &ch->candidates[i];
    if( c->fd!=-1 && (int)i!=ch->paired_idx && ( now>=c->deadline || now>=c->admission_until ) ) {
      if( c->dialed && now>=ch->dial_log_at[2] ) {
        ch->dial_log_at[2] = fd_long_sat_add( now, FD_FAILOVER_LOG_INTERVAL_NANOS );
        FD_LOG_WARNING(( "the failover peer at `" FD_IP4_ADDR_FMT "` did not finish the handshake in time, check that it runs and that the machines can reach each other on [failover.listen_port]",
                         FD_IP4_ADDR_FMT_ARGS( c->address ) ));
      }
      ch->metrics.handshake_timeout_cnt++;
      /* An expired candidate closes, an outbound dial returns to backoff. */
      drop( ch, i, now, FD_FAILOVER_EV_TIMEOUT ); *busy = 1;
    }
  }
  if( FD_UNLIKELY( !ch->tls_ctx.ready ) || ch->paired_idx>=0 ) return delivered;
  if( ch->dial_peer && ch->state==FD_FAILOVER_SESSION_BACKOFF && now>=ch->retry_at && ch->peer_addr ) {
    ulong idx = OUTBOUND_IDX;
    if( ch->candidates[idx].fd==-1 ) {
      int fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
      *busy = 1;
      if( fd==-1 ) { drop( ch, idx, now, FD_FAILOVER_EV_LINK_LOST ); return delivered; }
      ch->state = fd_failover_session_step( ch->state, ch->dial_peer, FD_FAILOVER_EV_RETRY );
      start( ch, idx, fd, ch->peer_addr, now, PHASE_CONNECT );
    }
  }
  ulong serviced = 0UL;
  /* Reserved connections cannot be displaced or wait behind newcomers. */
  for( ulong idx=0UL; idx<UNAUTHENTICATED_IDX; idx++ ) {
    if( ch->candidates[idx].fd==-1 ) continue;
    service_candidate( ch, idx, now, busy, payload );
    serviced++;
    if( ch->paired_idx>=0 ) return delivered;
  }
  /* Give a buffered proof its verification turn before servicing more
     input.  An unchecked proof stays in the unauthenticated pool. */
  ulong serviced_mask = 0UL;
  if( ch->verify_budget && ch->verify_credit>=FD_FAILOVER_NANOS_PER_SECOND ) {
    for( ulong n=0UL; n<FD_FAILOVER_CHANNEL_CANDIDATE_MAX-UNAUTHENTICATED_IDX; n++ ) {
      ulong cursor = (ch->proof_cursor+n)%(FD_FAILOVER_CHANNEL_CANDIDATE_MAX-UNAUTHENTICATED_IDX);
      ulong idx    = UNAUTHENTICATED_IDX+cursor;
      if( ch->candidates[idx].fd==-1 || !proof_ready( &ch->candidates[idx] ) ) continue;
      ch->proof_cursor = (cursor+1UL)%(FD_FAILOVER_CHANNEL_CANDIDATE_MAX-UNAUTHENTICATED_IDX);
      service_candidate( ch, idx, now, busy, payload );
      serviced_mask = 1UL<<idx;
      serviced++;
      if( ch->paired_idx>=0 ) return delivered;
      break;
    }
  }
  for( ulong n=0UL; n<FD_FAILOVER_CHANNEL_CANDIDATE_MAX-UNAUTHENTICATED_IDX && serviced<4UL; n++ ) {
    ulong idx = UNAUTHENTICATED_IDX+ch->cursor;
    ch->cursor = (ch->cursor+1UL)%(FD_FAILOVER_CHANNEL_CANDIDATE_MAX-UNAUTHENTICATED_IDX);
    if( ch->candidates[idx].fd==-1 || ( serviced_mask & (1UL<<idx) ) ) continue;
    if( proof_ready( &ch->candidates[idx] ) &&
        ( !ch->verify_budget || ch->verify_credit<FD_FAILOVER_NANOS_PER_SECOND ) ) continue;
    service_candidate( ch, idx, now, busy, payload );
    serviced++;
    if( ch->paired_idx>=0 ) return delivered;
  }
  if( ch->listen_fd!=-1 ) accept_candidates( ch, now, busy );
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
  c->tx_used = fd_failover_wire_encode( &c->wire, c->tx, type, payload, sz );
  if( !c->tx_used ) { lose( ch, idx, now, FD_FAILOVER_EV_LINK_LOST, LOSS_LOCAL_ENCODE, "we could not encode a frame for it" ); return -1; }
  int busy = 0;
  int rc   = flush( ch, idx, now, &busy )<0 ? -1 : 0;
  if( !rc && type==FD_FAILOVER_MSG_HANDOFF_RESULT ) ch->expected_close = 1;
  return rc;
}
