#include "../fd_ballet.h"
#include "fd_ed25519.h"
#include "fd_curve25519.h"
#include "../hex/fd_hex.h"
#include "test_ed25519_wycheproof.c"
#include "test_ed25519_cctv.c"

#define FD_ED25519_UNIT_TESTS
#include "fd_curve25519_secure.c"
#undef FD_ED25519_UNIT_TESTS

static uchar *
fd_rng_b256( fd_rng_t * rng,
             uchar      r[ 32 ] ) {
  ulong * u = (ulong *)r;
  u[0] = fd_rng_ulong( rng ); u[1] = fd_rng_ulong( rng ); u[2] = fd_rng_ulong( rng ); u[3] = fd_rng_ulong( rng );
  return r;
}

static uchar *
fd_rng_b512( fd_rng_t * rng,
             uchar      r[ 64 ] ) {
  ulong * u = (ulong *)r;
  u[0] = fd_rng_ulong( rng ); u[1] = fd_rng_ulong( rng ); u[2] = fd_rng_ulong( rng ); u[3] = fd_rng_ulong( rng );
  u[4] = fd_rng_ulong( rng ); u[5] = fd_rng_ulong( rng ); u[6] = fd_rng_ulong( rng ); u[7] = fd_rng_ulong( rng );
  return r;
}

static int g_bench = 0;

void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  if( !iter ) return;
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

void
test_fe_frombytes( fd_rng_t * rng ) {
  uchar           _s[32]; uchar *       s = _s;
  fd_f25519_t     _h[1];  fd_f25519_t * h = _h;

  /* zero */

  fd_hex_decode( s, "0000000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_f25519_frombytes( h, s );
  FD_TEST( fd_f25519_is_zero( h ) );

  fd_hex_decode( s, "0000000000000000000000000000000000000000000000000000000000000080", 32 );
  fd_f25519_frombytes( h, s );
  FD_TEST( fd_f25519_is_zero( h ) );

  fd_hex_decode( s, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  fd_f25519_frombytes( h, s );
  FD_TEST( fd_f25519_is_zero( h ) );

  fd_hex_decode( s, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  fd_f25519_frombytes( h, s );
  FD_TEST( fd_f25519_is_zero( h ) );

  /* two */

  fd_hex_decode( s, "0200000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_f25519_frombytes( h, s );
  FD_TEST( fd_f25519_eq( h, fd_f25519_two ) );

  fd_hex_decode( s, "0200000000000000000000000000000000000000000000000000000000000080", 32 );
  fd_f25519_frombytes( h, s );
  FD_TEST( fd_f25519_eq( h, fd_f25519_two ) );

  fd_hex_decode( s, "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  fd_f25519_frombytes( h, s );
  FD_TEST( fd_f25519_eq( h, fd_f25519_two ) );

  fd_hex_decode( s, "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  fd_f25519_frombytes( h, s );
  FD_TEST( fd_f25519_eq( h, fd_f25519_two ) );

  /* bench */

  fd_rng_b256( rng, s );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( s ); FD_COMPILER_FORGET( h ); fd_f25519_frombytes( h, s ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_frombytes", iter, dt );
}

void
test_fe_tobytes( fd_rng_t * rng ) {
  uchar           _s[32]; uchar *       s = _s;
  uchar           _e[32]; uchar *       e = _e;
  fd_f25519_t     _h[1];  fd_f25519_t * h = _h;

  fd_hex_decode( e, "0000000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_f25519_tobytes( s, fd_f25519_zero );
  FD_TEST( fd_memeq( e, s, 32 ) );

  fd_hex_decode( e, "0100000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_f25519_tobytes( s, fd_f25519_one );
  FD_TEST( fd_memeq( e, s, 32 ) );

  fd_hex_decode( e, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  fd_f25519_tobytes( s, fd_f25519_minus_one );
  FD_TEST( fd_memeq( e, s, 32 ) );

  fd_hex_decode( e, "59f1b226949bd6eb56b183829a14e00030d1f3eef2808e19e7fcdf56dcd90624", 32 );
  fd_f25519_tobytes( s, fd_f25519_k );
  FD_TEST( fd_memeq( e, s, 32 ) );

  /* fd_f25519_tobytes should reduce mod p, i.e. only produce canonical results */

  fd_hex_decode( e, "0000000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_f25519_add_nr( h, fd_f25519_minus_one, fd_f25519_one );
  fd_f25519_tobytes( s, h );
  FD_TEST( fd_memeq( e, s, 32 ) );

  fd_hex_decode( e, "0100000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_f25519_add_nr( h, fd_f25519_minus_one, fd_f25519_two );
  fd_f25519_tobytes( s, h );
  FD_TEST( fd_memeq( e, s, 32 ) );

  /* frombytes > tobytes success */

  fd_hex_decode( e, "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", 32 );
  fd_f25519_frombytes( h, e );
  fd_f25519_tobytes( s, h );
  FD_TEST( fd_memeq( e, s, 32 ) );

  fd_hex_decode( e, "0000000000000000000000000000000000000000000000000000000000000002", 32 );
  fd_f25519_frombytes( h, e );
  fd_f25519_tobytes( s, h );
  FD_TEST( fd_memeq( e, s, 32 ) );

  fd_hex_decode( e, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  fd_f25519_frombytes( h, e );
  fd_f25519_tobytes( s, h );
  FD_TEST( fd_memeq( e, s, 32 ) );

  /* frombytes > tobytes expected failure */

  fd_hex_decode( e, "0000000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_hex_decode( s, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  fd_f25519_frombytes( h, s );
  fd_f25519_tobytes( s, h );
  FD_TEST( fd_memeq( e, s, 32 ) );

  /* bench */

  fd_f25519_rng_unsafe( h, rng );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( h ); FD_COMPILER_FORGET( h ); fd_f25519_tobytes( s, h ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_tobytes", iter, dt );
}

void
test_fe_is_zero( FD_PARAM_UNUSED fd_rng_t * rng ) {
  uchar           _s[32]; uchar *       s = _s;
  fd_f25519_t     _h[1];  fd_f25519_t * h = _h;

  FD_TEST( fd_f25519_is_zero( fd_f25519_zero ) );

  fd_hex_decode( s, "0000000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( fd_f25519_is_zero( h ), "fd_f25519_is_zero( 00..00 )" );

  fd_hex_decode( s, "0000000000000000000000000000000000000000000000000000000000000080", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( fd_f25519_is_zero( h ), "fd_f25519_is_zero( 00..80 )" );

  fd_hex_decode( s, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( fd_f25519_is_zero( h ), "fd_f25519_is_zero( edff..7f )" );

  fd_hex_decode( s, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( fd_f25519_is_zero( h ), "fd_f25519_is_zero( edff..ff )" );

  /* negative */

  FD_TEST( !fd_f25519_is_zero( fd_f25519_one ) );
  FD_TEST( !fd_f25519_is_zero( fd_f25519_minus_one ) );

  fd_hex_decode( s, "0100000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( !fd_f25519_is_zero( h ), "!fd_f25519_is_zero( 01..00 )" );

  fd_hex_decode( s, "0100000000000000000000000000000000000000000000000000000000000080", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( !fd_f25519_is_zero( h ), "!fd_f25519_is_zero( 01..80 )" );

  fd_hex_decode( s, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( !fd_f25519_is_zero( h ), "!fd_f25519_is_zero( eeff..7f )" );

  fd_hex_decode( s, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( !fd_f25519_is_zero( h ), "!fd_f25519_is_zero( eeff..ff )" );

  fd_hex_decode( s, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( !fd_f25519_is_zero( h ), "!fd_f25519_is_zero( ecff..7f )" );

  fd_hex_decode( s, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  fd_f25519_frombytes( h, s );
  FD_CHECK_ERR( !fd_f25519_is_zero( h ), "!fd_f25519_is_zero( ecff..ff )" );
}

void
test_fe_copy( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_set( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_set", iter, dt );
}

void
test_fe_add( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _g[1]; fd_f25519_t * g = _g;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;

  fd_f25519_rng_unsafe( f, rng );
  fd_f25519_rng_unsafe( g, rng );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( g ); FD_COMPILER_FORGET( h ); fd_f25519_add( h, f, g );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_add", iter, dt );
}

void
test_fe_sub( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _g[1]; fd_f25519_t * g = _g;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;

  fd_f25519_rng_unsafe( f, rng );
  fd_f25519_rng_unsafe( g, rng );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( g ); FD_COMPILER_FORGET( h ); fd_f25519_sub( h, f, g );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_sub", iter, dt );
}

void
test_fe_mul( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _g[1]; fd_f25519_t * g = _g;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;
  fd_f25519_t _e[1]; fd_f25519_t * e = _e;

  uchar buf[32], ebuf[32];
  fd_hex_decode( buf, "67ccf547e004ba7acda6c72bf9d7d6c5ea20ff33bd887ef92764243c83488700", 32 );
  fd_f25519_frombytes( f, buf );
  fd_hex_decode( buf, "58ad456df8e6593162f595ee41b26590052a98a75a243db7f26b3c5f2aba1430", 32 );
  fd_f25519_frombytes( g, buf );
  fd_hex_decode( ebuf, "0000000000000000000000000000000000000000000000000000000000000002", 32 );
  fd_f25519_frombytes( e, ebuf );
  fd_f25519_mul( h, f, g );
  FD_TEST( fd_f25519_eq( e, h ) );
  fd_f25519_tobytes( buf, h );
  FD_TEST( fd_memeq( buf, ebuf, 32 ) );

  fd_f25519_rng_unsafe( f, rng );
  fd_f25519_rng_unsafe( g, rng );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( g ); FD_COMPILER_FORGET( h ); fd_f25519_mul( h, f, g );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_mul", iter, dt );
}

void
test_fe_sq( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_sqr( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_sqr", iter, dt );
}

void
test_fe_invert( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = g_bench ? 10000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_inv( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_inv", iter, dt );
}

void
test_fe_neg( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = g_bench ? 100000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_neg( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_neg", iter, dt );
}

void
test_fe_if( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _g[1]; fd_f25519_t * g = _g;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;
  uchar c;

  fd_f25519_rng_unsafe( f, rng );
  fd_f25519_rng_unsafe( g, rng );
  FD_TEST( !fd_memeq( f, g, 32 ) );

  FD_TEST( fd_memeq( fd_f25519_if( h, 1, f, g ), f, 32 ) );
  FD_TEST( fd_memeq( fd_f25519_if( h, 0, f, g ), g, 32 ) );

  ulong iter = g_bench ? 100000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    c = (uchar)(rem & 1UL);
    FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( c ); FD_COMPILER_FORGET( h );
    fd_f25519_if( h, c, f, g );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_if", iter, dt );
}

void
test_fe_isnonzero( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  int c;

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = g_bench ? 100000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f );
    c = fd_f25519_is_nonzero( f );
    FD_COMPILER_FORGET( c );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_is_nonzero", iter, dt );
}

void
test_fe_pow22523( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = g_bench ? 100000UL : 0UL;

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_pow22523( h, f ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_f25519_pow22523", iter, dt );
  }
}

void
test_affine_frombytes( FD_PARAM_UNUSED fd_rng_t * rng ) {
  uchar x[32], y[32];
  fd_ed25519_point_t fd_ed25519_base_point[1];
  fd_hex_decode( x, "1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921", 32 );
  fd_hex_decode( y, "5866666666666666666666666666666666666666666666666666666666666666", 32 );
  fd_curve25519_affine_frombytes( fd_ed25519_base_point, x, y );
  FD_LOG_NOTICE(( "test_affine_frombytes: ok" ));
}

void
test_affine_is_small_order( FD_PARAM_UNUSED fd_rng_t * rng ) {
  uchar                 _s[32]; uchar *              s = _s;
  fd_ed25519_point_t    _r[1];  fd_ed25519_point_t * r = _r;

  // Passing condition
  fd_hex_decode(s, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( ! fd_ed25519_affine_is_small_order( r ) );

  fd_hex_decode(s, "5866666666666666666666666666666666666666666666666666666666666666", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( ! fd_ed25519_affine_is_small_order( r ) );

  // Small order points
  fd_hex_decode(s, "0100000000000000000000000000000000000000000000000000000000000000", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  fd_hex_decode(s, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  fd_hex_decode(s, "0000000000000000000000000000000000000000000000000000000000000000", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  fd_hex_decode(s, "0000000000000000000000000000000000000000000000000000000000000080", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  fd_hex_decode(s, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  fd_hex_decode(s, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  fd_hex_decode(s, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  fd_hex_decode(s, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  /* x=0 with sign bit set: accepted to match Dalek behavior (neg(0)==0). */
  fd_hex_decode(s, "0100000000000000000000000000000000000000000000000000000000000080", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );
  fd_hex_decode(s, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  FD_TEST( fd_ed25519_point_frombytes( r, s ) );
  FD_TEST( fd_ed25519_affine_is_small_order( r ) );

  FD_LOG_NOTICE(( "test_affine_is_small_order: ok" ));
}

static void
test_frombytes_2x( FD_PARAM_UNUSED fd_rng_t * rng ) {
  uchar _s1[32]; uchar * s1 = _s1;
  uchar _s2[32]; uchar * s2 = _s2;
  fd_ed25519_point_t _r1[1]; fd_ed25519_point_t * r1 = _r1;
  fd_ed25519_point_t _r2[1]; fd_ed25519_point_t * r2 = _r2;

  /* Two valid points */
  fd_hex_decode(s1, "5866666666666666666666666666666666666666666666666666666666666666", 32 ); /* base point */
  fd_hex_decode(s2, "0100000000000000000000000000000000000000000000000000000000000000", 32 ); /* identity */
  FD_TEST( fd_ed25519_point_frombytes_2x( r1, s1, r2, s2 )==0 );

  /* First invalid => -1 */
  fd_hex_decode(s1, "0200000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_hex_decode(s2, "0100000000000000000000000000000000000000000000000000000000000000", 32 );
  FD_TEST( fd_ed25519_point_frombytes_2x( r1, s1, r2, s2 )==-1 );

  /* Second invalid => -2 */
  fd_hex_decode(s1, "0100000000000000000000000000000000000000000000000000000000000000", 32 );
  fd_hex_decode(s2, "0200000000000000000000000000000000000000000000000000000000000000", 32 );
  FD_TEST( fd_ed25519_point_frombytes_2x( r1, s1, r2, s2 )==-2 );

  /* x=0, sign=1 in slot 1: should succeed (match Dalek) */
  fd_hex_decode(s1, "0100000000000000000000000000000000000000000000000000000000000080", 32 );
  fd_hex_decode(s2, "5866666666666666666666666666666666666666666666666666666666666666", 32 );
  FD_TEST( fd_ed25519_point_frombytes_2x( r1, s1, r2, s2 )==0 );
  FD_TEST( fd_ed25519_affine_is_small_order( r1 ) );

  /* x=0, sign=1 in slot 2: should succeed (match Dalek) */
  fd_hex_decode(s1, "5866666666666666666666666666666666666666666666666666666666666666", 32 );
  fd_hex_decode(s2, "0100000000000000000000000000000000000000000000000000000000000080", 32 );
  FD_TEST( fd_ed25519_point_frombytes_2x( r1, s1, r2, s2 )==0 );
  FD_TEST( fd_ed25519_affine_is_small_order( r2 ) );

  /* non-canonical y=1, sign=1 in slot 1: should succeed (match Dalek) */
  fd_hex_decode(s1, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  fd_hex_decode(s2, "5866666666666666666666666666666666666666666666666666666666666666", 32 );
  FD_TEST( fd_ed25519_point_frombytes_2x( r1, s1, r2, s2 )==0 );
  FD_TEST( fd_ed25519_affine_is_small_order( r1 ) );

  /* non-canonical y=1, sign=1 in slot 2: should succeed (match Dalek) */
  fd_hex_decode(s1, "5866666666666666666666666666666666666666666666666666666666666666", 32 );
  fd_hex_decode(s2, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  FD_TEST( fd_ed25519_point_frombytes_2x( r1, s1, r2, s2 )==0 );
  FD_TEST( fd_ed25519_affine_is_small_order( r2 ) );

  FD_LOG_NOTICE(( "test_frombytes_2x: ok" ));
}

/* FIXME: ADD VMUL, VSQ, VSQN TESTS HERE */

/**********************************************************************/

/* FIXME: ADD GE TESTS HERE */

static void
test_point_validate( FD_PARAM_UNUSED fd_rng_t * rng ) {
  uchar _buf[32]; uchar * buf = _buf;

  fd_ed25519_point_tobytes( buf, fd_ed25519_base_point );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(fd_ed25519_base_point)" );

  fd_hex_decode( buf, "0000000000000000000000000000000000000000000000000000000000000000", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(00..00)" );

  fd_hex_decode( buf, "0100000000000000000000000000000000000000000000000000000000000000", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(01..00)" );

  fd_hex_decode( buf, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(01..00)" );

  fd_hex_decode( buf, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(01..00)" );

  fd_hex_decode( buf, "0100000000000000000000000000000000000000000000000000000000000080", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(01..80)" );

  fd_hex_decode( buf, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(ee..ff)" );

  fd_hex_decode( buf, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(01..00)" );

  fd_hex_decode( buf, "0300000000000000000000000000000000000000000000000000000000000000", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(01..00)" );

  fd_hex_decode( buf, "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(01..00)" );

  // non-canonical points are accepted
  fd_hex_decode( buf, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
  FD_CHECK_ERR( fd_ed25519_point_validate( buf ), "fd_ed25519_point_validate(ff..ff)" );

  /* negative tests */

  fd_hex_decode( buf, "0200000000000000000000000000000000000000000000000000000000000000", 32 );
  FD_CHECK_ERR( !fd_ed25519_point_validate( buf ), "!fd_ed25519_point_validate(02..00)" );

  fd_hex_decode( buf, "b898e00f6f6df758b3f9a05cbf73b15fd392a008a9a417d471c178c1b28c7447", 32 );
  FD_CHECK_ERR( !fd_ed25519_point_validate( buf ), "!fd_ed25519_point_validate(02..00)" );
}

/* Reference implementations: a^((p-1)/2) = pow22523(a)^4 * a^2 and
   full decompression. */

static int
ref_is_square( fd_f25519_t const * a ) {
  fd_f25519_t e[1], a2[1];
  fd_f25519_pow22523( e, a );
  fd_f25519_sqr( e, e );
  fd_f25519_sqr( e, e );
  fd_f25519_sqr( a2, a );
  fd_f25519_mul( e, e, a2 );
  int ref = fd_f25519_is_zero( a ) || fd_f25519_eq( e, fd_f25519_one );
  /* is_square_var falls back to sqrt_ratio if the Jacobi symbol does
     not converge, check that too */
  FD_TEST( fd_f25519_sqrt_ratio( e, a, fd_f25519_one )==ref );
  return ref;
}

static int
ref_point_validate( uchar const buf[ 32 ] ) {
  fd_ed25519_point_t t[1];
  return !!fd_ed25519_point_frombytes( t, buf );
}

/* check_validate checks fd_ed25519_point_validate against decompression
   on buf with both sign bits.  Returns the number of valid inputs. */

static ulong
check_validate( uchar const buf[ 32 ] ) {
  uchar b[32]; memcpy( b, buf, 32UL );
  ulong valid_cnt = 0UL;
  for( int sign=0; sign<2; sign++ ) {
    b[31] = (uchar)( (b[31] & 0x7f) | (sign<<7) );
    int ref = ref_point_validate( b );
    int got = fd_ed25519_point_validate( b );
    if( FD_UNLIKELY( ref!=got ) ) {
      FD_LOG_HEXDUMP_WARNING(( "input", b, 32UL ));
      FD_LOG_ERR(( "fd_ed25519_point_validate mismatch (got %d, expected %d)", got, ref ));
    }
    valid_cnt += (ulong)got;
  }
  return valid_cnt;
}

/* le_add_small sets r = a + k (mod 2^256) for 32-byte little endian a. */

static void
le_add_small( uchar       r[ 32 ],
              uchar const a[ 32 ],
              long        k ) {
  ulong w[4]; memcpy( w, a, 32UL );
  ulong c = (ulong)k;
  ulong ext = k<0L ? ULONG_MAX : 0UL;
  for( int i=0; i<4; i++ ) {
    ulong s  = w[i] + c;
    ulong c0 = (ulong)(s<w[i]);
    w[i] = s;
    c = ext + c0;
  }
  memcpy( r, w, 32UL );
}

static void
test_point_validate_diff( fd_rng_t * rng,
                          ulong      iter ) {
  static char const * p_hex = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
  uchar p[32];  fd_hex_decode( p, p_hex, 32 );
  uchar b[32];
  fd_f25519_t a[1];

  /* is_square_var vs Euler's criterion: small values, values near p,
     powers of two and random elements. */

  for( long k=-2000L; k<=2000L; k++ ) {
    if( k>=0L ) { memset( b, 0, 32UL ); b[0] = (uchar)(k & 0xff); b[1] = (uchar)(k>>8); }
    else        le_add_small( b, p, k );
    fd_f25519_frombytes( a, b );
    FD_TEST( fd_f25519_is_square_var( a )==ref_is_square( a ) );
  }
  for( int i=0; i<255; i++ ) {
    memset( b, 0, 32UL ); b[i/8] = (uchar)(1<<(i%8));
    fd_f25519_frombytes( a, b );
    FD_TEST( fd_f25519_is_square_var( a )==ref_is_square( a ) );
    le_add_small( b, b, -1L );
    fd_f25519_frombytes( a, b );
    FD_TEST( fd_f25519_is_square_var( a )==ref_is_square( a ) );
  }
  ulong sq_cnt = 0UL;
  for( ulong i=0UL; i<iter/8UL; i++ ) {
    fd_f25519_rng_unsafe( a, rng );
    int got = fd_f25519_is_square_var( a );
    FD_TEST( got==ref_is_square( a ) );
    sq_cnt += (ulong)got;
  }
  FD_LOG_NOTICE(( "fd_f25519_is_square_var: %lu/%lu random elements are squares", sq_cnt, iter/8UL ));

  /* Structured y: 0..4096 and p-4096..2^255-1 (the latter covers all
     non-canonical y in [p,2^255)), both sign bits. */

  ulong edge_cnt = 0UL;
  for( long k=0L; k<=4096L; k++ ) {
    memset( b, 0, 32UL ); b[0] = (uchar)(k & 0xff); b[1] = (uchar)(k>>8);
    check_validate( b ); edge_cnt += 2UL;
  }
  for( long k=-4096L; k<=18L; k++ ) {
    le_add_small( b, p, k );
    check_validate( b ); edge_cnt += 2UL;
  }

  /* Torsion points (y=1, y=-1, y=0 and the two order 8 y's) and
     non-canonical encodings of y=0, y=1 and y=2^255-1. */

  static char const * torsion_hex[] = {
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* y=p   (0) */
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* y=p+1 (1) */
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", /* y=2^255-1 */
    NULL
  };
  for( ulong i=0UL; torsion_hex[i]; i++ ) {
    fd_hex_decode( b, torsion_hex[i], 32 );
    FD_TEST( check_validate( b )==2UL );
    edge_cnt += 2UL;
  }

  /* Points from keys, multiples of the base point, their negations and
     the same points shifted by each torsion point.  Every encoding must
     validate; y+-small must match decompression. */

  fd_ed25519_point_t tors[8];
  fd_hex_decode( b, torsion_hex[3], 32 ); FD_TEST( fd_ed25519_point_frombytes( &tors[0], b ) );
  for( ulong i=1UL; i<8UL; i++ ) fd_ed25519_point_add( &tors[i], &tors[i-1], &tors[0] );

  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  ulong key_cnt = fd_ulong_max( iter/1000UL, 64UL );
  for( ulong i=0UL; i<key_cnt; i++ ) {
    uchar prv[32], pub[32];
    fd_rng_b256( rng, prv );
    fd_ed25519_public_from_private( pub, prv, sha );
    FD_TEST( check_validate( pub )==2UL );
    fd_ed25519_point_t pt[1], q[1];
    FD_TEST( fd_ed25519_point_frombytes( pt, pub ) );
    for( ulong j=0UL; j<8UL; j++ ) {
      fd_ed25519_point_add( q, pt, &tors[j] );
      fd_ed25519_point_tobytes( b, q );
      FD_TEST( check_validate( b )==2UL );
      edge_cnt += 2UL;
    }
    for( long k=-2L; k<=2L; k++ ) { le_add_small( b, pub, k ); check_validate( b ); edge_cnt += 2UL; }
    edge_cnt += 2UL;
  }
  fd_sha512_delete( fd_sha512_leave( sha ) );

  /* Random 32 byte inputs (as PDAs are sha256 outputs), plus low
     Hamming weight and near-p/near-2^255 variants. */

  ulong valid_cnt = 0UL;
  for( ulong i=0UL; i<iter; i++ ) {
    fd_rng_b256( rng, b );
    switch( i & 7UL ) {
    case 5UL: /* sparse */
      for( ulong j=0UL; j<32UL; j++ ) b[j] &= fd_rng_uchar( rng ) & fd_rng_uchar( rng );
      break;
    case 6UL: /* top bits set */
      for( ulong j=8UL; j<32UL; j++ ) b[j] = 0xff;
      break;
    case 7UL: /* y close to 0 */
      for( ulong j=8UL; j<32UL; j++ ) b[j] = 0x00;
      break;
    default:
      break;
    }
    b[31] &= 0x7f;
    valid_cnt += check_validate( b );
  }
  FD_LOG_NOTICE(( "fd_ed25519_point_validate: %lu edge inputs, %lu/%lu random inputs valid: ok",
                  edge_cnt, valid_cnt, 2UL*iter ));

  /* bench (random inputs, ~50% valid) */

  if( g_bench ) {
    ulong const n = 1024UL;
    static uchar in[ 1024 ][ 32 ];
    for( ulong i=0UL; i<n; i++ ) fd_rng_b256( rng, in[i] );
    ulong bench_iter = 200000UL;
    int acc = 0;
    long dt = fd_log_wallclock();
    for( ulong i=0UL; i<bench_iter; i++ ) { acc += ref_point_validate( in[i&(n-1UL)] ); FD_COMPILER_FORGET( acc ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ed25519_point_frombytes(1)", bench_iter, dt );
    dt = fd_log_wallclock();
    for( ulong i=0UL; i<bench_iter; i++ ) { acc += fd_ed25519_point_validate( in[i&(n-1UL)] ); FD_COMPILER_FORGET( acc ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ed25519_point_validate", bench_iter, dt );
    fd_f25519_t fe[ 64 ];
    for( ulong i=0UL; i<64UL; i++ ) fd_f25519_rng_unsafe( &fe[i], rng );
    dt = fd_log_wallclock();
    for( ulong i=0UL; i<bench_iter; i++ ) { acc += fd_f25519_is_square_var( &fe[i&63UL] ); FD_COMPILER_FORGET( acc ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_f25519_is_square_var", bench_iter, dt );
  }
}

static void
test_point_frombytes( FD_PARAM_UNUSED fd_rng_t * rng ) {
  uchar _bufa[32]; uchar * bufa = _bufa;
  uchar _bufr[32]; uchar * bufr = _bufr;
  uchar _bufx[32]; uchar * bufx = _bufx;
  uchar _bufy[32]; uchar * bufy = _bufy;

  fd_f25519_t x[1], y[1], z[1], t[1];
  fd_ed25519_point_t a[1];

  {
    fd_hex_decode( bufa, "ffffffffffff0100fffffffffffffffffffffffffffdffffffffffffffffffff", 32 );
    fd_hex_decode( bufx, "3d0f773c2d26e69aa19258013f0bb4eb72a8db858498e6c802089ca8972b101b", 32 );
    fd_hex_decode( bufy, "ffffffffffff0100fffffffffffffffffffffffffffdffffffffffffffffff7f", 32 );

    FD_TEST( fd_ed25519_point_frombytes( a, bufa ) );

    fd_ed25519_point_tobytes( bufr, a );
    FD_TEST( fd_memeq( bufr, bufa, 32UL ) );

    fd_ed25519_point_to( x, y, z, t, a );
    fd_f25519_tobytes( bufr, x );
    FD_TEST( fd_memeq( bufr, bufx, 32UL ) );
    fd_f25519_tobytes( bufr, y );
    FD_TEST( fd_memeq( bufr, bufy, 32UL ) );
  }
  {
    fd_hex_decode( bufa, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
    fd_hex_decode( bufx, "c50fe3127abac974ddd36f74e8988d7fe71cfc79d15fce531b42ccafd973d348", 32 );
    fd_hex_decode( bufy, "1200000000000000000000000000000000000000000000000000000000000000", 32 );

    FD_TEST( fd_ed25519_point_frombytes( a, bufa ) );

    fd_ed25519_point_tobytes( bufr, a );
    FD_TEST( !fd_memeq( bufr, bufa, 32UL ) ); // non-canonical

    fd_ed25519_point_to( x, y, z, t, a );
    fd_f25519_tobytes( bufr, x );
    FD_TEST( fd_memeq( bufr, bufx, 32UL ) );
    fd_f25519_tobytes( bufr, y );
    FD_TEST( fd_memeq( bufr, bufy, 32UL ) );
  }
}

static void
test_point_add_secure( fd_rng_t * rng FD_PARAM_UNUSED ) {
  uchar _bufa[32]; uchar * bufa = _bufa;
  uchar _bufb[32]; uchar * bufb = _bufb;
  uchar _bufr[32]; uchar * bufr = _bufr;
  uchar _bufe[32]; uchar * bufe = _bufe;

  fd_ed25519_point_t a[1];
  fd_ed25519_point_t b[1];
  fd_ed25519_point_t r[1];
  fd_ed25519_point_t e[1];
  fd_ed25519_point_t tmp0[1];
  fd_ed25519_point_t tmp1[1];

  {
    // this failed the point_add_secure
    fd_hex_decode( bufa, "0100000000000000000000000000000000b90000000000000000000000000080", 32 );
    fd_hex_decode( bufb, "0000000000000000000000000000000000fb0000000000000000000000000080", 32 );
    fd_hex_decode( bufe, "1e7eb8ea9e26b4e89d6ae958797cee2d0a64ecf2f3a50eb4d4fff0492abf0658", 32 );

    FD_TEST( fd_ed25519_point_frombytes( a, bufa ) );
    FD_TEST( fd_ed25519_point_frombytes( b, bufb ) );

    FD_TEST( fd_ed25519_point_frombytes( e, bufe ) );
    {
      fd_ed25519_point_tobytes( bufr, a );
      FD_TEST( fd_memeq( bufr, bufa, 32UL ) );
      fd_ed25519_point_tobytes( bufr, b );
      FD_TEST( fd_memeq( bufr, bufb, 32UL ) );
    }

    fd_curve25519_into_precomputed( b );
    fd_ed25519_point_add_secure( r, a, b, tmp0, tmp1 );
    fd_ed25519_point_tobytes( bufr, r );

    FD_TEST( fd_memeq( bufr, bufe, 32UL ) );
  }
}

static void
test_point_neg_if( fd_rng_t * rng FD_PARAM_UNUSED ) {
  uchar _bufr[32]; uchar * bufr = _bufr;
  uchar _bufe[32]; uchar * bufe = _bufe;

  fd_ed25519_point_t b[1];
  fd_ed25519_point_t r[1];
  fd_ed25519_point_t zero[1];
  fd_ed25519_point_set_zero( zero );
  fd_ed25519_point_set_zero_precomputed( b );

  fd_ed25519_point_t tmp0[1], tmp1[1];

  for( ulong j=0; j<32; j++ ) {
    for( ulong k=0; k<8; k++ ) {
      fd_ed25519_point_t * a = (fd_ed25519_point_t *)( &fd_ed25519_base_point_const_time_table[j][k] );

      // neg_if( 0 ) == copy
      fd_ed25519_point_add_secure( r, zero, a, tmp0, tmp1 );
      fd_ed25519_point_tobytes( bufe, r );

      fd_ed25519_point_neg_if( b, a, 0 );
      fd_ed25519_point_add_secure( r, zero, b, tmp0, tmp1 );
      fd_ed25519_point_tobytes( bufr, r );

      FD_TEST( fd_memeq( bufr, bufe, 32UL ) );

      // neg_if( 1 ) == neg
      bufe[ 31 ] ^= 0x80;

      fd_ed25519_point_neg_if( b, a, 1 );
      fd_ed25519_point_add_secure( r, zero, b, tmp0, tmp1 );
      fd_ed25519_point_tobytes( bufr, r );

      FD_TEST( fd_memeq( bufr, bufe, 32UL ) );
    }
  }
}

static void
test_point_sub( fd_rng_t * rng FD_PARAM_UNUSED ) {
  uchar _bufa[32]; uchar * bufa = _bufa;
  uchar _bufb[32]; uchar * bufb = _bufb;
  uchar _bufr[32]; uchar * bufr = _bufr;
  uchar _bufe[32]; uchar * bufe = _bufe;

  fd_ed25519_point_t a[1];
  fd_ed25519_point_t b[1];
  fd_ed25519_point_t r[1];
  fd_ed25519_point_t e[1];

  {
    // this failed the point_sub
    fd_hex_decode( bufa, "01d5a4fc9af1e0cceec08818a6eba5b6068ac2a7b7862af0b3ba085fe942bb28", 32 );
    fd_hex_decode( bufb, "287e68afe7a4b3d01165472d2dc4a2ae8bccfeab6835852017916d0c2718c51e", 32 );
    fd_hex_decode( bufe, "a0beff37e6888bb25cfa14255247ea71d8276b8cd830d989e860aef22619fde2", 32 );

    FD_TEST( fd_ed25519_point_frombytes( a, bufa ) );
    FD_TEST( fd_ed25519_point_frombytes( b, bufb ) );

    FD_TEST( fd_ed25519_point_frombytes( e, bufe ) );
    {
      fd_ed25519_point_tobytes( bufr, a );
      FD_TEST( fd_memeq( bufr, bufa, 32UL ) );
      fd_ed25519_point_tobytes( bufr, b );
      FD_TEST( fd_memeq( bufr, bufb, 32UL ) );
    }

    fd_ed25519_point_sub( r, a, b );
    fd_ed25519_point_tobytes( bufr, r );

    FD_TEST( fd_memeq( bufr, bufe, 32UL ) );
  }
  {
    // this failed the field sub, causing failure in point_sub
    fd_hex_decode( bufa, "09090909090909090909090909090909090906090909099c0909090909090909", 32 );
    fd_hex_decode( bufb, "0909090909097e09090909090909090909090909090909090909090909090909", 32 );
    fd_hex_decode( bufe, "fa390a04c279c64396b818038dada0ba3d42aabcc5afe095440a8eff270e82f9", 32 );

    FD_TEST( fd_ed25519_point_frombytes( a, bufa ) );
    FD_TEST( fd_ed25519_point_frombytes( b, bufb ) );

    FD_TEST( fd_ed25519_point_frombytes( e, bufe ) );
    {
      fd_ed25519_point_tobytes( bufr, a );
      FD_TEST( fd_memeq( bufr, bufa, 32UL ) );
      fd_ed25519_point_tobytes( bufr, b );
      FD_TEST( fd_memeq( bufr, bufb, 32UL ) );
    }

    fd_ed25519_point_sub( r, a, b );
    fd_ed25519_point_tobytes( bufr, r );

    FD_TEST( fd_memeq( bufr, bufe, 32UL ) );
  }
  {
    // this failed sub, non-canonical point
    fd_hex_decode( bufa, "0100000000000000000000000000000000b90000000000000000000000000080", 32 );
    fd_hex_decode( bufb, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
    fd_hex_decode( bufe, "39b4ef21660663d8955e024b1a7d921cf76b6300dbd94827d47ec62829a7dddc", 32 );

    FD_TEST( fd_ed25519_point_frombytes( a, bufa ) );
    FD_TEST( fd_ed25519_point_frombytes( b, bufb ) );

    FD_TEST( fd_ed25519_point_frombytes( e, bufe ) );
    {
      fd_ed25519_point_tobytes( bufr, a );
      FD_TEST( fd_memeq( bufr, bufa, 32UL ) );
      fd_ed25519_point_tobytes( bufr, b );
      FD_TEST( !fd_memeq( bufr, bufb, 32UL ) ); // non-canonical
    }

    fd_ed25519_point_sub( r, a, b );
    fd_ed25519_point_tobytes( bufr, r );

    // FD_LOG_HEXDUMP_WARNING(( "bufr", bufr, 32 ));
    // FD_LOG_HEXDUMP_WARNING(( "bufe", bufe, 32 ));

    FD_TEST( fd_memeq( bufr, bufe, 32UL ) );
  }
}

static void
test_point_mul( fd_rng_t * rng FD_PARAM_UNUSED ) {
  uchar _bufa[32]; uchar * bufa = _bufa;
  uchar _bufn[32]; uchar * bufn = _bufn;
  uchar _bufr[32]; uchar * bufr = _bufr;
  uchar _bufe[32]; uchar * bufe = _bufe;

  fd_ed25519_point_t a[1];
  fd_ed25519_point_t r[1];
  fd_ed25519_point_t e[1];

  {
    fd_hex_decode( bufa, "0000000000000000003b0000e8e8e8000000000000000000000000000000ffff", 32 );
    fd_hex_decode( bufn, "005d0000000000000000000000000000000000000000000015b6b6b6b6000000", 32 );
    fd_hex_decode( bufe, "7b1e1037cbe6e84f922a9b0651ed50570530d6157853debba755d5904021740e", 32 );

    FD_TEST( fd_ed25519_scalar_validate( bufn ) );
    FD_TEST( fd_ed25519_point_frombytes( a, bufa ) );

    FD_TEST( fd_ed25519_point_frombytes( e, bufe ) );
    {
      fd_ed25519_point_tobytes( bufr, a );
      FD_TEST( fd_memeq( bufr, bufa, 32UL ) );
    }

    fd_ed25519_scalar_mul( r, bufn, a );
    fd_ed25519_point_tobytes( bufr, r );

    // FD_LOG_HEXDUMP_WARNING(( "bufr", bufr, 32 ));
    // FD_LOG_HEXDUMP_WARNING(( "bufe", bufe, 32 ));

    FD_TEST( fd_memeq( bufr, bufe, 32UL ) );
  }
}

/**********************************************************************/

void
test_sc_validate( fd_rng_t * rng ) {
  uchar _in [64]; uchar * in  = _in;
  uchar _out[32]; uchar * out = _out;

  FD_TEST( fd_curve25519_scalar_validate( fd_curve25519_scalar_zero ) );
  FD_TEST( fd_curve25519_scalar_validate( fd_curve25519_scalar_one ) );
  FD_TEST( fd_curve25519_scalar_validate( fd_curve25519_scalar_minus_one ) );

  /* negative test */
  fd_memcpy( out, fd_curve25519_scalar_minus_one, 32 ); out[0] = 0xed;
  FD_TEST( !fd_curve25519_scalar_validate( out ) );
  fd_rng_b256( rng, out ); out[31] |= 0x20;
  FD_TEST( !fd_curve25519_scalar_validate( out ) );

  /* random success */
  fd_rng_b512( rng, in );
  fd_curve25519_scalar_reduce( out, in );
  FD_TEST( fd_curve25519_scalar_validate( out ) );

  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( out ); fd_curve25519_scalar_validate( out ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_curve25519_scalar_validate", iter, dt );
}

void
test_sc_reduce( fd_rng_t * rng ) {
  uchar _in [64]; uchar * in  = _in;
  uchar _out[64]; uchar * out = _out;

  fd_rng_b512( rng, in );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( in ); FD_COMPILER_FORGET( out ); fd_curve25519_scalar_reduce( out, in ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_curve25519_scalar_reduce", iter, dt );
}

void
test_sc_muladd( fd_rng_t * rng ) {
  uchar _a[32]; uchar * a = _a;
  uchar _b[32]; uchar * b = _b;
  uchar _c[32]; uchar * c = _c;
  uchar _s[32]; uchar * s = _s;

  fd_rng_b256( rng, a );
  fd_rng_b256( rng, b );
  fd_rng_b256( rng, c );
  ulong iter = g_bench ? 1000000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( a ); FD_COMPILER_FORGET( b ); FD_COMPILER_FORGET( c );
    fd_curve25519_scalar_muladd( s, a, b, c );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_curve25519_scalar_muladd", iter, dt );
}

void
test_sc_unaligned_output( fd_rng_t * rng ) {
  uchar in[64];
  uchar a[32];
  uchar b[32];
  uchar c[32];
  uchar expected[32];
  uchar _actual[33] __attribute__((aligned(8)));
  uchar * actual = _actual+1;

  fd_rng_b512( rng, in );
  fd_curve25519_scalar_reduce( expected, in );
  FD_TEST( fd_curve25519_scalar_reduce( actual, in )==actual );
  FD_TEST( fd_memeq( actual, expected, 32UL ) );

  fd_rng_b256( rng, a );
  fd_rng_b256( rng, b );
  fd_rng_b256( rng, c );
  fd_curve25519_scalar_muladd( expected, a, b, c );
  FD_TEST( fd_curve25519_scalar_muladd( actual, a, b, c )==actual );
  FD_TEST( fd_memeq( actual, expected, 32UL ) );

  FD_TEST( fd_curve25519_scalar_from_u64( actual, 1UL )==actual );
  FD_TEST( fd_memeq( actual, fd_curve25519_scalar_one, 32UL ) );
}

void
test_public_from_private( fd_rng_t *    rng,
                          fd_sha512_t * sha ) {
  uchar _prv[32]; uchar * prv = _prv;
  uchar _pub[32]; uchar * pub = _pub;
  uchar _exp[32]; uchar * exp = _exp;

  fd_hex_decode( prv, "aac11373b6f936a0d22759e6a54e0a11947cd183cf34df9dec10e234b5d133eb", 32 );
  fd_hex_decode( exp, "1ddd2c92234f97eda0c91d0191491392a70fbe42fedc0df99d871583d9ad351f", 32 );
  fd_ed25519_public_from_private( pub, prv, sha );
  // FD_TEST( fd_memeq( pub, exp, 32UL ) );

  fd_rng_b256( rng, prv );
  fd_ed25519_public_from_private( pub, prv, sha );
  // FD_LOG_HEXDUMP_WARNING(( "prv", prv, 32 ));
  // FD_LOG_HEXDUMP_WARNING(( "pub", pub, 32 ));

  ulong iter = g_bench ? 10000UL : 0UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( prv ); FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sha );
    fd_ed25519_public_from_private( pub, prv, sha );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_public_from_private", iter, dt );
}

void
test_sign( fd_rng_t *    rng,
           fd_sha512_t * sha ) {
  uchar _msg[ 1024 ]; uchar * msg = _msg;
  uchar _pub[   32 ]; uchar * pub = _pub;
  uchar _prv[   32 ]; uchar * prv = _prv;
  uchar _sig[   64 ]; uchar * sig = _sig;
  uchar _exp[   64 ]; uchar * exp = _exp;

  fd_hex_decode( prv, "57835dc6a20e4efd70e90882dbd832b577dbc469960284e0ee718fb526d2ec84", 32 );
  fd_hex_decode( exp, "d65759870ce42b34fd955871f0371ce1c9a976edbe98417b84541bb4c68b65a0673799895c61d530624ffbf92c047d47d4eb4cd1bac2ecee1365faebb53a6303", 64 );
  fd_ed25519_public_from_private( pub, prv, sha );
  fd_ed25519_sign( sig, (uchar *)"", 0, pub, prv, sha );
  FD_TEST( fd_memeq( sig, exp, 64UL ) );

  for( ulong b=0; b<1024UL; b++ ) msg[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( pub, fd_rng_b256( rng, prv ), sha );

  ulong iter = g_bench ? 10000UL : 0UL;
  for( ulong sz=128UL; sz<=1024UL; sz+=128UL ) {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg ); FD_COMPILER_FORGET( sz  );
      FD_COMPILER_FORGET( prv ); FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sha );
      fd_ed25519_sign( sig, msg, sz, pub, prv, sha );
    }
    dt = fd_log_wallclock() - dt;

    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_sign(%lu)", sz ), iter, dt );
  }
}

void
test_sign_batch( fd_rng_t *    rng,
                 fd_sha512_t * sha ) {
  ulong const msg_row = 1024UL;
  uchar msg_mem[ 8UL*1024UL ];
  uchar prv [ 8UL*32UL ];
  uchar pub [ 8UL*32UL ];
  uchar sig1[ 8UL*64UL ];
  uchar sign[ 8UL*64UL ];

  uchar const * msg   [ 8UL ];
  ulong         msg_sz[ 8UL ];

  for( ulong b=0UL; b<8UL*msg_row; b++ ) msg_mem[b] = fd_rng_uchar( rng );
  for( ulong i=0UL; i<8UL; i++ ) {
    msg[i] = msg_mem + msg_row*i;
    fd_ed25519_public_from_private( pub+32UL*i, fd_rng_b256( rng, prv+32UL*i ), sha );
  }

  /* correctness: mixed sizes (empty and oversize included), all n in
     [1,8], vs sequential sign */

  for( ulong trial=0UL; trial<16UL; trial++ ) {
    ulong n = 1UL+(trial%8UL);
    for( ulong i=0UL; i<n; i++ ) {
      msg_sz[i] = fd_rng_ulong_roll( rng, 1025UL );
      if( FD_UNLIKELY( (trial==0UL) | (i==0UL) ) ) msg_sz[i] = 0UL;
      fd_ed25519_sign( sig1+64UL*i, msg[i], msg_sz[i], pub, prv, sha );
    }
    fd_ed25519_sign_batch8( sign, msg, msg_sz, pub, prv, n );
    FD_TEST( fd_memeq( sig1, sign, n*64UL ) );
  }
  FD_LOG_NOTICE(( "fd_ed25519_sign_batch8: ok" ));

  /* bench: per-signature rate, sequential vs batched at each n */

  if( !g_bench ) return;
  ulong iter = 10000UL;
  char cstr[128];

  for( ulong sz=128UL; sz<=1024UL; sz*=8UL ) {
    for( ulong i=0UL; i<8UL; i++ ) msg_sz[i] = sz;
    for( ulong n=1UL; n<=8UL; n++ ) {
      long dt = fd_log_wallclock();
      for( ulong rem=iter; rem; rem-- ) {
        for( ulong i=0UL; i<n; i++ ) fd_ed25519_sign( sign+64UL*i, msg[i], msg_sz[i], pub, prv, sha );
      }
      dt = fd_log_wallclock() - dt;
      log_bench( fd_cstr_printf( cstr, 128UL, NULL, "seq fd_ed25519_sign(%lu) x%lu/sig", sz, n ), iter*n, dt );

      dt = fd_log_wallclock();
      for( ulong rem=iter; rem; rem-- ) {
        fd_ed25519_sign_batch8( sign, msg, msg_sz, pub, prv, n );
      }
      dt = fd_log_wallclock() - dt;
      log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_sign_batch8(%lu) n=%lu", sz, n ), iter*n, dt );
    }
  }
}

void
test_verify( fd_rng_t *    rng,
             fd_sha512_t * sha ) {
  uchar _msg[ 1024 ]; uchar * msg = _msg;
  uchar _pub[   32 ]; uchar * pub = _pub;
  uchar _sig[   64 ]; uchar * sig = _sig;
  uchar _prv[   32 ]; uchar * prv = _prv;

  {
    // "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" // valid point
    // "b898e00f6f6df758b3f9a05cbf73b15fd392a008a9a417d471c178c1b28c7447" // invalid point
    // "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05" // small order point
    // "0000000000000000000000000000000000000000000000000000000000000000" // valid scalar
    // "2222222222222222222222222222222222222222222222222222222222222222" // invalid scalar

    // invalid scalar s
    fd_hex_decode( sig, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2222222222222222222222222222222222222222222222222222222222222222", 64 );
    fd_hex_decode( pub, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
    FD_TEST( fd_ed25519_verify( msg, 0, sig, pub, sha )==FD_ED25519_ERR_SIG );
    FD_TEST( fd_ed25519_verify_batch_single_msg( msg, 0, sig, pub, &sha, 1 )==FD_ED25519_ERR_SIG );

    // invalid point r
    fd_hex_decode( sig, "b898e00f6f6df758b3f9a05cbf73b15fd392a008a9a417d471c178c1b28c74470000000000000000000000000000000000000000000000000000000000000000", 64 );
    fd_hex_decode( pub, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
    FD_TEST( fd_ed25519_verify( msg, 0, sig, pub, sha )==FD_ED25519_ERR_SIG );
    FD_TEST( fd_ed25519_verify_batch_single_msg( msg, 0, sig, pub, &sha, 1 )==FD_ED25519_ERR_SIG );

    // small order r
    fd_hex_decode( sig, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000", 64 );
    fd_hex_decode( pub, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
    FD_TEST( fd_ed25519_verify( msg, 0, sig, pub, sha )==FD_ED25519_ERR_SIG );
    FD_TEST( fd_ed25519_verify_batch_single_msg( msg, 0, sig, pub, &sha, 1 )==FD_ED25519_ERR_SIG );

    // invalid point a
    fd_hex_decode( sig, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000", 64 );
    fd_hex_decode( pub, "b898e00f6f6df758b3f9a05cbf73b15fd392a008a9a417d471c178c1b28c7447", 32 );
    FD_TEST( fd_ed25519_verify( msg, 0, sig, pub, sha )==FD_ED25519_ERR_PUBKEY );
    FD_TEST( fd_ed25519_verify_batch_single_msg( msg, 0, sig, pub, &sha, 1 )==FD_ED25519_ERR_PUBKEY );

    // small order a
    fd_hex_decode( sig, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000", 64 );
    fd_hex_decode( pub, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 32 );
    FD_TEST( fd_ed25519_verify( msg, 0, sig, pub, sha )==FD_ED25519_ERR_PUBKEY );
    FD_TEST( fd_ed25519_verify_batch_single_msg( msg, 0, sig, pub, &sha, 1 )==FD_ED25519_ERR_PUBKEY );

    // all good, but (clearly) invalid sig
    fd_hex_decode( sig, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000", 64 );
    fd_hex_decode( pub, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32 );
    FD_TEST( fd_ed25519_verify( msg, 0, sig, pub, sha )==FD_ED25519_ERR_MSG );
    FD_TEST( fd_ed25519_verify_batch_single_msg( msg, 0, sig, pub, &sha, 1 )==FD_ED25519_ERR_MSG );
  }

  for( ulong b=0; b<1024UL; b++ ) msg[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( pub, fd_rng_b256( rng, prv ), sha );
  ulong iter = g_bench ? 10000UL : 0UL;

  for( ulong sz=128UL; sz<=1024UL; sz+=128UL ) {
    char cstr[128];
    fd_ed25519_sign( sig, msg, sz, pub, prv, sha );

    FD_CHECK_ERR( fd_ed25519_verify( msg, sz, sig, pub, sha )==FD_ED25519_SUCCESS, fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify(good %lu)", sz ) );

    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg ); FD_COMPILER_FORGET( sz  );
      FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sha );
      fd_ed25519_verify( msg, sz, sig, pub, sha );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify(good %lu)", sz ), iter, dt );
  }

  for( ulong sz=1024UL; sz<=1024UL; sz+=128UL ) {
    uchar _pubs[   32*16 ]; uchar * pubs = _pubs;
    uchar _sigs[   64*16 ]; uchar * sigs = _sigs;
    uchar _prv2[   32 ]; uchar * prv2 = _prv2;
    fd_sha512_t * _shas[ 16 ]; fd_sha512_t ** shas = _shas;
    for( ulong j=0; j<16; j++ ) {
      _shas[j] = sha;
      fd_rng_b256( rng, prv2 );
      fd_ed25519_public_from_private( &pubs[32*j], prv2, sha );
      fd_ed25519_sign( &sigs[64*j], msg, sz, &pubs[32*j], prv2, sha );
    }
    for( uchar batch=1; batch<=12; batch=(uchar)(batch*2) ) {

      // FD_TEST( fd_ed25519_verify( msg, sz, sigs, pubs, sha )==FD_ED25519_SUCCESS );
      FD_TEST( fd_ed25519_verify_batch_single_msg( msg, sz, sigs, pubs, shas, batch )==FD_ED25519_SUCCESS );

      long dt = fd_log_wallclock();
      for( ulong rem=iter/batch; rem; rem-- ) {
        FD_COMPILER_FORGET( sigs ); FD_COMPILER_FORGET( msg ); FD_COMPILER_FORGET( sz  );
        FD_COMPILER_FORGET( pubs ); FD_COMPILER_FORGET( shas ); FD_COMPILER_FORGET( batch );
        fd_ed25519_verify_batch_single_msg( msg, sz, sigs, pubs, shas, batch );
      }
      dt = fd_log_wallclock() - dt;
      char cstr[128];
      log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_..._verify_batch(%lu / %u)", sz, batch ), iter/batch, dt );

      /* trick to test 1, 2, 4, 8, 12 => 12 is the max we support */
      if( batch == 8 ) { batch = 6; }
    }
  }

  for( ulong sz=128UL; sz<=1024UL; sz+=128UL ) {
    fd_ed25519_sign( sig, msg, sz, pub, prv, sha );
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg ); FD_COMPILER_FORGET( sz  );
      FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sha );

      ulong idx  = (ulong)fd_rng_uint_roll( rng, 512UL );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      sig[ byte ] = (uchar)(((ulong)sig[ byte ]) ^ (1UL<<bit));
      fd_ed25519_verify( msg, sz, sig, pub, sha );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify(bad sig %lu)", sz ), iter, dt );
  }

  for( ulong sz=128UL; sz<=1024UL; sz+=128UL ) {
    fd_ed25519_sign( sig, msg, sz, pub, prv, sha );
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg ); FD_COMPILER_FORGET( sz  );
      FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sha );
      ulong idx  = (ulong)fd_rng_uint_roll( rng, 8U*(uint)sz );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      msg[ byte ] = (uchar)(((ulong)msg[ byte ]) ^ (1UL<<bit));

      fd_ed25519_verify( msg, sz, sig, pub, sha );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify(bad msg %lu)", sz ), iter, dt );
  }

  for( ulong sz=128UL; sz<=1024UL; sz+=128UL ) {
    fd_ed25519_sign( sig, msg, sz, pub, prv, sha );
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg ); FD_COMPILER_FORGET( sz  );
      FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sha );
      ulong idx  = (ulong)fd_rng_uint_roll( rng, 256UL );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      pub[ byte ] = (uchar)(((ulong)pub[ byte ]) ^ (1UL<<bit));

      fd_ed25519_verify( msg, sz, sig, pub, sha );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify(bad pub %lu)", sz ), iter, dt );
  }
}

void
test_wycheproofs( fd_sha512_t * sha ) {
  char cstr[128];

  for( fd_ed25519_verify_wycheproof_t const * proof = ed25519_verify_wycheproofs;
       proof->msg;
       proof++ ) {

    int actual = ( fd_ed25519_verify( proof->msg, proof->msg_sz, proof->sig, proof->pub, sha )
                     == FD_ED25519_SUCCESS );
    FD_CHECK_ERR( actual == proof->ok, fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify_wycheproof id=%u", proof->tc_id ) );

  }
  FD_LOG_NOTICE(( "fd_ed25519_verify_wycheproof: ok" ));
}

void
test_cctv( fd_sha512_t * sha ) {
  char cstr[128];
  for( fd_ed25519_verify_cctv_t const * proof = ed25519_verify_cctvs;
       proof->msg;
       proof++ ) {
    int actual = ( fd_ed25519_verify( proof->msg, proof->msg_sz, proof->sig, proof->pub, sha )
                     == FD_ED25519_SUCCESS );
    FD_CHECK_ERR( actual == proof->ok, fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify_cctv id=%u", proof->tc_id ) );
  }
  FD_LOG_NOTICE(( "fd_ed25519_verify_cctv: ok" ));
}

void
test_cctv_batch( fd_rng_t * rng, fd_sha512_t * sha ) {
  char cstr[128];

  uchar const * msg = ed25519_verify_cctvs[7].msg;
  ulong msg_sz = ed25519_verify_cctvs[7].msg_sz;

  uchar _pubs[   32*16 ]; uchar * pubs = _pubs;
  uchar _sigs[   64*16 ]; uchar * sigs = _sigs;
  uchar _prv2[   32 ]; uchar * prv2 = _prv2;
  fd_sha512_t * _shas[ 16 ]; fd_sha512_t ** shas = _shas;

  /* generate 16 valid signatures */
  for( ulong j=0; j<16; j++ ) {
    _shas[j] = sha;
    fd_rng_b256( rng, prv2 );
    fd_ed25519_public_from_private( &pubs[32*j], prv2, sha );
    fd_ed25519_sign( &sigs[64*j], msg, msg_sz, &pubs[32*j], prv2, sha );
  }
  FD_TEST( fd_ed25519_verify_batch_single_msg( msg, msg_sz, sigs, pubs, shas, 16 )==FD_ED25519_SUCCESS );

  for( fd_ed25519_verify_cctv_t const * proof = ed25519_verify_cctvs;
       proof->msg;
       proof++ ) {
    // only keep tests with the same msg
    if (proof->msg_sz != msg_sz || !fd_memeq( proof->msg, msg, msg_sz )) {
      continue;
    }

    fd_memcpy( &sigs[64], proof->sig, 64 );
    fd_memcpy( &pubs[32], proof->pub, 32 );

    int actual = ( fd_ed25519_verify_batch_single_msg( msg, msg_sz, sigs, pubs, shas, 2 )
                     == FD_ED25519_SUCCESS );
    FD_CHECK_ERR( actual == proof->ok, fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify_cctv_batch(2) id=%u", proof->tc_id ) );

    actual = ( fd_ed25519_verify_batch_single_msg( msg, msg_sz, sigs, pubs, shas, 4 )
                     == FD_ED25519_SUCCESS );
    FD_CHECK_ERR( actual == proof->ok, fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify_cctv_batch(4) id=%u", proof->tc_id ) );
  }
  FD_LOG_NOTICE(( "fd_ed25519_verify_cctv_batch: ok" ));
}

/**********************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  g_bench = fd_env_strip_cmdline_contains( &argc, &argv, "--bench" );
  /* Random inputs for the point_validate differential test, raise with
     --validate-iter or FD_ED25519_VALIDATE_ITER (and vary --seed) */
  ulong validate_iter = fd_env_strip_cmdline_ulong( &argc, &argv, "--validate-iter", "FD_ED25519_VALIDATE_ITER", g_bench ? 10000000UL : 100000UL );
  uint  seed          = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",          NULL,                       0U );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  test_fe_frombytes ( rng );
  test_fe_tobytes   ( rng );
  test_fe_is_zero   ( rng );
  test_fe_copy      ( rng );
  test_fe_add       ( rng );
  test_fe_sub       ( rng );
  test_fe_mul       ( rng );
  test_fe_sq        ( rng );
  test_fe_invert    ( rng );
  test_fe_neg       ( rng );
  test_fe_if        ( rng );
  test_fe_isnonzero ( rng );
  test_fe_pow22523  ( rng );

  test_affine_frombytes      ( rng );
  test_affine_is_small_order ( rng );
  test_frombytes_2x          ( rng );

  test_point_validate( rng );
  test_point_validate_diff( rng, validate_iter );
  test_point_frombytes( rng );
  test_point_neg_if( rng );
  test_point_sub( rng );
  test_point_add_secure( rng );
  test_point_mul( rng );

  test_sc_validate  ( rng );
  test_sc_reduce    ( rng );
  test_sc_muladd    ( rng );
  test_sc_unaligned_output( rng );

  test_public_from_private( rng, sha );
  test_sign               ( rng, sha );
  test_sign_batch         ( rng, sha );
  test_verify             ( rng, sha );

  test_wycheproofs( sha );
  test_cctv       ( sha );
  test_cctv_batch ( rng, sha );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
