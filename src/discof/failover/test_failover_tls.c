/* test_failover_tls drives the failover TLS transport end to end over a
   socketpair, the way the channel drives it but without the sockets and
   the handshake table.  We stand up two contexts with their own junk
   keypairs, run a real fd_tls 1.3 handshake between a dialer and a
   listener, move an application frame each way, and close one side to
   see the other read an orderly close_notify.

   The in-tree channel test reaches the transport only in passing, so
   these cases pin the parts it leaves loose: a CertificateVerify signed
   by a key other than the certificate's fails the handshake, tls_new
   refuses a context
   that never initialized, both ends learn the key the peer signed the
   handshake with, and fini sends close_notify on a ready connection so
   the peer reads a clean end rather than a reset. */

#include "fd_failover_tls.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include <sys/socket.h>
#include <unistd.h>

static uchar key_a[ 64 ] = { 1 };
static uchar key_b[ 64 ] = { 2 };
static fd_sha512_t sha[ 1 ];

/* Stands in for the sign tile, signs with the key in ctx. */
static void
sign_fn( void *      ctx,
         uchar       sig[ static FD_ED25519_SIG_SZ ],
         uchar const payload[ static FD_TLS_CV_SIGN_SZ ] ) {
  uchar const * key = ctx;
  fd_ed25519_sign( sig, payload, FD_TLS_CV_SIGN_SZ, key+32, key, sha );
}

static fd_tls_sign_t
signer( uchar const * key ) {
  return (fd_tls_sign_t){ .ctx=(void *)key, .sign_fn=sign_fn };
}

/* One service turn on each side: refill the per turn budget and step the
   handshake.  Returns 0 once both ends verified, -1 on any failure. */
static int
handshake( fd_failover_tls_t * x,
           fd_failover_tls_t * y ) {
  for( int i=0; i<64; i++ ) {
    fd_failover_tls_budget( x );
    fd_failover_tls_budget( y );
    int rx = fd_failover_tls_handshake( x );
    int ry = fd_failover_tls_handshake( y );
    if( rx<0 || ry<0 ) return -1;
    if( rx==1 && ry==1 ) return 0;
  }
  return -1;
}

/* from writes one frame, to reads it back, within a single turn each. */
static void
transfer( fd_failover_tls_t * from,
          fd_failover_tls_t * to ) {
  uchar msg[ 70 ], got[ 128 ];
  for( ulong i=0UL; i<sizeof(msg); i++ ) msg[i] = (uchar)(i*7U+1U);
  fd_failover_tls_budget( from );
  FD_TEST( fd_failover_tls_write( from, msg, sizeof(msg) )==(long)sizeof(msg) );
  fd_failover_tls_budget( to );
  long r = fd_failover_tls_read( to, got, sizeof(got) );
  FD_TEST( r==(long)sizeof(msg) && fd_memeq( msg, got, sizeof(msg) ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_sha512_join( fd_sha512_new( sha ) );
  fd_ed25519_public_from_private( key_a+32, key_a, sha );
  fd_ed25519_public_from_private( key_b+32, key_b, sha );

  fd_failover_tls_ctx_t ca, cb;
  fd_memset( &ca, 0, sizeof(ca) );
  fd_memset( &cb, 0, sizeof(cb) );
  FD_TEST( !fd_failover_tls_ctx_init( &ca, key_a+32, signer( key_a ) ) );
  FD_TEST( !fd_failover_tls_ctx_init( &cb, key_b+32, signer( key_b ) ) );

  /* A dialer whose signer uses another key than its certificate fails
     the handshake. */
  {
    fd_failover_tls_ctx_t bad_ctx; fd_memset( &bad_ctx, 0, sizeof(bad_ctx) );
    FD_TEST( !fd_failover_tls_ctx_init( &bad_ctx, key_a+32, signer( key_b ) ) );
    int bad_fds[ 2 ];
    FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, bad_fds ) );
    fd_failover_tls_t x, y;
    FD_TEST( !fd_failover_tls_new( &x, &bad_ctx, bad_fds[0], 1 ) );
    FD_TEST( !fd_failover_tls_new( &y, &cb,      bad_fds[1], 0 ) );
    FD_TEST( handshake( &x, &y )==-1 );
    FD_TEST( !y.verified );
    fd_failover_tls_fini( &x );
    fd_failover_tls_fini( &y );
    fd_failover_tls_ctx_fini( &bad_ctx );
    close( bad_fds[0] );
    close( bad_fds[1] );
  }

  /* tls_new refuses a context that never initialized. */
  {
    fd_failover_tls_ctx_t raw; fd_memset( &raw, 0, sizeof(raw) );
    fd_failover_tls_t probe;
    FD_TEST( fd_failover_tls_new( &probe, &raw, -1, 1 )==-1 );
  }

  int fds[ 2 ];
  FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, fds ) );

  fd_failover_tls_t a, b;
  FD_TEST( !fd_failover_tls_new( &a, &ca, fds[0], 1 ) ); /* dialer, client */
  FD_TEST( !fd_failover_tls_new( &b, &cb, fds[1], 0 ) ); /* listener, server */

  FD_TEST( !handshake( &a, &b ) );
  FD_TEST( a.verified && b.verified );

  /* Each end kept the junk key the peer signed the handshake with. */
  FD_TEST( fd_memeq( a.peer_pubkey, key_b+32, 32UL ) );
  FD_TEST( fd_memeq( b.peer_pubkey, key_a+32, 32UL ) );

  /* A handshake call after both verified stays 1 and moves nothing. */
  fd_failover_tls_budget( &a );
  FD_TEST( fd_failover_tls_handshake( &a )==1 );

  transfer( &a, &b );
  transfer( &b, &a );

  /* a finishes.  fini sends close_notify over its still open socket, so b
     reads a clean end, not a reset: its read fails with peer_closed set. */
  fd_failover_tls_fini( &a );
  FD_TEST( a.fd==-1 && !a.verified );
  fd_failover_tls_budget( &b );
  uchar got[ 16 ];
  FD_TEST( fd_failover_tls_read( &b, got, sizeof(got) )==-1L && b.peer_closed==1 );

  /* A second fini on the closed side is a no-op. */
  fd_failover_tls_fini( &a );

  fd_failover_tls_fini( &b );
  fd_failover_tls_ctx_fini( &ca );
  fd_failover_tls_ctx_fini( &cb );
  close( fds[0] );
  close( fds[1] );

  FD_LOG_NOTICE(( "pass: signer binding, mutual handshake authentication, framed transfer and an orderly close" ));
  fd_halt();
  return 0;
}
