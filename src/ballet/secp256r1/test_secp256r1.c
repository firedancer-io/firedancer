#include "../fd_ballet.h"
#include "fd_secp256r1_private.h"
#include "../hex/fd_hex.h"

FD_FN_UNUSED static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

static void
test_secp256r1_scalar_frombytes( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar _sig[ 64 ] = { 0 }; uchar * sig = _sig;
  fd_hex_decode( sig, "a940d67c9560a47c5dafb45ab1f39eb68c8fac9b51fc8c4e30b1f0e63e4967d3586569a56364c3b03eefd421aa7fc750f6fa187210c3206c55602f96e0ecaa4d", 64 );
  fd_secp256r1_scalar_t _r[1]; fd_secp256r1_scalar_t * r = _r;

  FD_TEST( fd_secp256r1_scalar_frombytes( r, sig )==r );
  FD_TEST( fd_secp256r1_scalar_frombytes_positive( r, sig+32 )==r );
  FD_TEST( fd_secp256r1_scalar_frombytes_positive( r, sig )==NULL );

  // bench
  {
    ulong iter = 1000000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( r );
      fd_secp256r1_scalar_frombytes( r, sig );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_scalar_frombytes", iter, dt );
  }
  {
    ulong iter = 1000000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( r );
      fd_secp256r1_scalar_frombytes_positive( r, sig+32 );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_scalar_frombytes_positive", iter, dt );
  }
}

static void
test_secp256r1_scalar_mul( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar _buf[ 32 ] = { 0 }; uchar * buf = _buf;
  fd_secp256r1_scalar_t _r[1]; fd_secp256r1_scalar_t * r = _r;
  fd_secp256r1_scalar_t a[1], b[1], e[1];

  fd_hex_decode( buf, "a940d67c9560a47c5dafb45ab1f39eb68c8fac9b51fc8c4e30b1f0e63e4967d3", 32 );
  fd_secp256r1_scalar_frombytes( a, buf );
  fd_hex_decode( buf, "8f5f345242acd89f49a0c4b1c86d707247d234e29a35033f32d736829412f32f", 32 );
  fd_secp256r1_scalar_frombytes( b, buf );
  fd_hex_decode( buf, "3c781eb29540c997f49ba878d101dc89abef36491baf3b54c4a364e1245c74a8", 32 );
  fd_secp256r1_scalar_frombytes( e, buf );

  fd_secp256r1_scalar_mul( r, a, b );
  FD_TEST( fd_memeq( r, e, 32 ) );

  // bench
  {
    ulong iter = 100000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( r );
      fd_secp256r1_scalar_mul( r, a, b );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_scalar_mul", iter, dt );
  }
}

static void
test_secp256r1_scalar_inv( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar _buf[ 32 ] = { 0 }; uchar * buf = _buf;
  fd_secp256r1_scalar_t _r[1]; fd_secp256r1_scalar_t * r = _r;
  fd_secp256r1_scalar_t a[1], e[1];

  fd_hex_decode( buf, "586569a56364c3b03eefd421aa7fc750f6fa187210c3206c55602f96e0ecaa4d", 32 );
  fd_secp256r1_scalar_frombytes( a, buf );
  fd_hex_decode( buf, "8f5f345242acd89f49a0c4b1c86d707247d234e29a35033f32d736829412f32f", 32 );
  fd_secp256r1_scalar_frombytes( e, buf );

  fd_secp256r1_scalar_inv( r, a );
  FD_TEST( fd_memeq( r, e, 32 ) );

  // bench
  {
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( r );
      fd_secp256r1_scalar_inv( r, a );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_scalar_inv", iter, dt );
  }
}

static void
test_secp256r1_fp_frombytes( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar _buf[ 32 ] = { 0 }; uchar * buf = _buf;
  fd_hex_decode( buf, "d8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 32 );
  fd_secp256r1_fp_t _r[1]; fd_secp256r1_fp_t * r = _r;

  FD_TEST( fd_secp256r1_fp_frombytes( r, buf )==r );

  // bench
  {
    ulong iter = 1000000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( r );
      fd_secp256r1_fp_frombytes( r, buf );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_fp_frombytes", iter, dt );
  }
}

static void
test_secp256r1_fp_sqrt( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar _sqrt0[ 32 ] = { 0 }; uchar * sqrt0 = _sqrt0;
  uchar _sqrt1[ 32 ] = { 0 }; uchar * sqrt1 = _sqrt1;
  fd_hex_decode( sqrt0, "d942f2008adaab3a98ad4af432f97b2cc45170a9051574304e12c6b461c012e8", 32 );
  fd_hex_decode( sqrt1, "f942f2008adaab3a98ad4af432f97b2cc45170a9051574304e12c6b461c012e8", 32 );
  fd_secp256r1_fp_t _r[1]; fd_secp256r1_fp_t * r = _r;
  fd_secp256r1_fp_t a[1];

  FD_TEST( fd_secp256r1_fp_frombytes( a, sqrt1 )==a );
  FD_TEST( fd_secp256r1_fp_sqrt( r, a )==NULL );

  FD_TEST( fd_secp256r1_fp_frombytes( a, sqrt0 )==a );
  FD_TEST( fd_secp256r1_fp_sqrt( r, a )==r );

  // bench
  {
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( r );
      fd_secp256r1_fp_sqrt( r, a );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_fp_sqrt", iter, dt );
  }
}

static void
test_secp256r1_point_frombytes( FD_FN_UNUSED fd_rng_t * rng ) {

  uchar _pub[ 33 ] = { 0 }; uchar * pub = _pub;
  fd_secp256r1_point_t _r[1]; fd_secp256r1_point_t * r = _r;

  fd_hex_decode( pub, "04d8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 33 );
  FD_TEST( fd_secp256r1_point_frombytes( r, pub )==NULL );

  fd_hex_decode( pub, "02ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 33 );
  FD_TEST( fd_secp256r1_point_frombytes( r, pub )==NULL );

  fd_hex_decode( pub, "02b8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 33 );
  FD_TEST( fd_secp256r1_point_frombytes( r, pub )==NULL );

  fd_hex_decode( pub, "03d8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 33 );
  FD_TEST( fd_secp256r1_point_frombytes( r, pub )==r );

  fd_hex_decode( pub, "02d8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 33 );
  FD_TEST( fd_secp256r1_point_frombytes( r, pub )==r );

  // bench
  {
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( r );
      fd_secp256r1_point_frombytes( r, pub );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_point_frombytes", iter, dt );
  }
}

static void
test_secp256r1_point_eq_x( FD_FN_UNUSED fd_rng_t * rng ) {

  uchar _pub[ 33 ] = { 0 }; uchar * pub = _pub;
  fd_secp256r1_point_t _r[1]; fd_secp256r1_point_t * r = _r;
  fd_secp256r1_fp_t x[1];

  fd_hex_decode( pub, "d8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 32 );
  fd_secp256r1_fp_frombytes( x, pub );

  fd_hex_decode( pub, "02d8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 33 );

  // failure: Z=0
  fd_secp256r1_point_frombytes( r, pub );
  fd_secp256r1_fp_set( r->z, fd_secp256r1_const_zero );
  FD_TEST( fd_secp256r1_point_eq_x( r, x )==FD_SECP256R1_FAILURE );

  // failure: invalid x
  fd_secp256r1_point_frombytes( r, pub );
  r->x->limbs[0] = 123UL;
  FD_TEST( fd_secp256r1_point_eq_x( r, x )==FD_SECP256R1_FAILURE );

  // success
  fd_secp256r1_point_frombytes( r, pub );
  FD_TEST( fd_secp256r1_point_eq_x( r, x )==FD_SECP256R1_SUCCESS );

  // bench
  {
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( r );
      fd_secp256r1_point_eq_x( r, x );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_point_eq_x", iter, dt );
  }
}

static void
test_secp256r1_verify( FD_FN_UNUSED fd_rng_t * rng ) {

  uchar _msg[ 10 ] = { 0 }; uchar * msg = _msg;
  ulong msg_sz;
  uchar _sig[ 64 ] = { 0 }; uchar * sig = _sig;
  uchar _pub[ 33 ] = { 0 }; uchar * pub = _pub;
  fd_sha256_t sha[1];

  // test correctness (r,s)
  {
    msg_sz = 6;
    fd_hex_decode( msg, "deadbeef0000", msg_sz );
    fd_hex_decode( sig, "65f479af7700ea826cdf4a2d30bbbfd5be5a8abb4dd6e8ef0bb0d5018b5f08160856e32671be561383d7eb408c6d24c28fd05141fd247dd8e67fc511d4f2ace9", 64 );
    fd_hex_decode( pub, "030f5183ccd84510385acc742f2d9d83771190c83cd0a36c42b0877c1666598a31", 33 );
    FD_TEST( fd_secp256r1_verify( msg, msg_sz, sig, pub, sha )==FD_SECP256R1_SUCCESS );
  }
  {
    msg_sz = 6;
    fd_hex_decode( msg, "deadbeef0001", msg_sz );
    fd_hex_decode( sig, "dde6de58059a2edc745f3757a45b527c6a838e2f9944e7985cdbce18a9831444662257cde953020a5ba3dbd77dabc0e7ecf35dadf35754dd5c014e3197173ca7", 64 );
    fd_hex_decode( pub, "032a18f703b754f728b4faa2cd9e81d82647b86fb4e22bce7348ddf2a977a4e9d9", 33 );
    FD_TEST( fd_secp256r1_verify( msg, msg_sz, sig, pub, sha )==FD_SECP256R1_SUCCESS );
  }
  {
    msg_sz = 6;
    fd_hex_decode( msg, "deadbeef0002", msg_sz );
    fd_hex_decode( sig, "d852239f6cdd19f530636fed1736f6c1fff499e988ffc14faf9098b6c359f53f24d8918494d158e562643da21939e3d8f4f733b2e135c63f205281c3cbae7cc1", 64 );
    fd_hex_decode( pub, "025241d2133264e7d4b0f91c0d2b08d7b8e4c015cc84d68eafe8c5dfe4b8bf6753", 33 );
    FD_TEST( fd_secp256r1_verify( msg, msg_sz, sig, pub, sha )==FD_SECP256R1_SUCCESS );
  }

  // test malleability (r,-s)
  msg = (uchar *)"hello";
  msg_sz = 5;
  {
    fd_hex_decode( sig, "a940d67c9560a47c5dafb45ab1f39eb68c8fac9b51fc8c4e30b1f0e63e4967d3a79a96599c9b3c50c1102bde558038aec5ece23b96547e189e599b2c1b767b04", 64 );
    FD_TEST( fd_secp256r1_verify( msg, msg_sz, sig, pub, sha )==FD_SECP256R1_FAILURE );
  }

  fd_hex_decode( sig, "a940d67c9560a47c5dafb45ab1f39eb68c8fac9b51fc8c4e30b1f0e63e4967d3586569a56364c3b03eefd421aa7fc750f6fa187210c3206c55602f96e0ecaa4d", 64 );
  fd_hex_decode( pub, "02d8c82b3791c8b51cfe44aa50226217159596ca26e6075aaf8bf8be2d351b96ae", 33 );
  FD_TEST( fd_secp256r1_verify( msg, msg_sz, sig, pub, sha )==FD_SECP256R1_SUCCESS );

  // bench
  {
    ulong iter = 1000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig );
      fd_secp256r1_verify( msg, 5, sig, pub, sha );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_secp256r1_verify", iter, dt );
  }
}

/**********************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_secp256r1_scalar_frombytes( rng );
  test_secp256r1_scalar_mul      ( rng );
  test_secp256r1_scalar_inv      ( rng );

  test_secp256r1_fp_frombytes    ( rng );
  test_secp256r1_fp_sqrt         ( rng );

  test_secp256r1_point_frombytes ( rng );
  test_secp256r1_point_eq_x      ( rng );

  test_secp256r1_verify          ( rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
