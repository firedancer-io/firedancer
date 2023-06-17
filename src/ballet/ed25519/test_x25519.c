#include "fd_x25519.h"

struct fd_x25519_test_vector {
  uchar self  [ 32 ];
  uchar peer  [ 32 ];
  uchar secret[ 32 ];
};

typedef struct fd_x25519_test_vector fd_x25519_test_vector_t;

static const fd_x25519_test_vector_t test_x25519_vector[] = {
  /* RFC 7748, Section 6.1. */
  {
    .self = {
      0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
      0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    },
    .peer = {
      0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
      0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    },
    .secret = {
      0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
      0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    }
  }
};

static void
simulate_ecdh( fd_rng_t * rng ) {

  uchar secret0[ 32 ];
  uchar secret1[ 32 ];
  for( ulong b=0; b<32UL; b++ ) secret0[b] = fd_rng_uchar( rng );
  for( ulong b=0; b<32UL; b++ ) secret1[b] = fd_rng_uchar( rng );

  uchar pubkey0[ 32 ];
  uchar pubkey1[ 32 ];
  fd_x25519_public( pubkey0, secret0 );
  fd_x25519_public( pubkey1, secret1 );

  uchar _shared0[ 32 ];
  uchar _shared1[ 32 ];
  void * shared0 = fd_x25519_exchange( _shared0, secret0, pubkey1 );
  void * shared1 = fd_x25519_exchange( _shared1, secret1, pubkey0 );

  if( FD_UNLIKELY( (!shared0) | (!shared1) ) ) {
    FD_LOG_ERR(( "FAIL"
              "\n\tGiven secrets"
              "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
              "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
              "\n\tGot"
              "\n\t\tshared0=%s"
              "\n\t\tshared1=%s",
              FD_LOG_HEX16_FMT_ARGS( secret0 ), FD_LOG_HEX16_FMT_ARGS( secret0+16 ),
              FD_LOG_HEX16_FMT_ARGS( secret1 ), FD_LOG_HEX16_FMT_ARGS( secret1+16 ),
              shared0 ? "OK" : "NULL",
              shared1 ? "OK" : "NULL" ));
  }
  if( FD_UNLIKELY( memcmp( shared0, shared1, 32UL ) ) )
    FD_LOG_ERR(( "FAIL"
                 "\n\tGiven secrets"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                 FD_LOG_HEX16_FMT_ARGS(  secret0 ), FD_LOG_HEX16_FMT_ARGS(  secret0+16 ),
                 FD_LOG_HEX16_FMT_ARGS(  secret1 ), FD_LOG_HEX16_FMT_ARGS(  secret1+16 ),
                 FD_LOG_HEX16_FMT_ARGS( _shared0 ), FD_LOG_HEX16_FMT_ARGS( _shared0+16 ),
                 FD_LOG_HEX16_FMT_ARGS( _shared1 ), FD_LOG_HEX16_FMT_ARGS( _shared1+16 ) ));
}

static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( fd_x25519_test_vector_t const * test = test_x25519_vector;
       (ulong)test < ((ulong)test_x25519_vector + sizeof(test_x25519_vector));
       test++ ) {

    uchar secret[ 32 ]={0};
    fd_x25519_exchange( secret, test->self, test->peer );

    if( FD_UNLIKELY( memcmp( secret, test->secret, 32UL ) ) )
      FD_LOG_ERR(( "FAIL"
                   "\n\tGot"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\tExpected"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS( secret       ), FD_LOG_HEX16_FMT_ARGS( secret      +16 ),
                   FD_LOG_HEX16_FMT_ARGS( test->secret ), FD_LOG_HEX16_FMT_ARGS( test->secret+16 ) ));
  }

  /* Simulate real key exchange */

  {
    ulong iter = 10000UL;
    for( ulong rem=iter; rem; rem-- ) simulate_ecdh( rng );
    FD_LOG_NOTICE(( "OK: %lu ECDH simulations", iter ));
  }

  /* Prepare benchmark inputs */

  uchar _secret0[ 32 ]; uchar * secret0 = _secret0;
  uchar _secret1[ 32 ]; uchar * secret1 = _secret1;
  for( ulong b=0; b<32UL; b++ ) secret0[b] = fd_rng_uchar( rng );
  for( ulong b=0; b<32UL; b++ ) secret1[b] = fd_rng_uchar( rng );
  ulong iter = 10000UL;

  uchar _pubkey0[ 32 ]; uchar * pubkey0 = _pubkey0;
  uchar _pubkey1[ 32 ]; uchar * pubkey1 = _pubkey1;
  fd_x25519_public( pubkey0, secret0 );
  fd_x25519_public( pubkey1, secret1 );

  uchar _shared[ 32 ]; uchar * shared = _shared;

  /* Bench key exchange */

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( secret0 ); FD_COMPILER_FORGET( pubkey0 );
      FD_COMPILER_FORGET( shared  );
      fd_x25519_exchange( shared, secret0, pubkey1 );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_x25519_exchange" ), iter, dt );
  }

  /* Bench public key derivation */

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( secret0 ); FD_COMPILER_FORGET( pubkey0 );
      ulong idx  = (ulong)fd_rng_uchar( rng );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      secret0[ byte ] = (uchar)(((ulong)secret0[ byte ]) ^ (1UL<<bit));
      fd_x25519_public( pubkey0, secret0 );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_x25519_public" ), iter, dt );
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

