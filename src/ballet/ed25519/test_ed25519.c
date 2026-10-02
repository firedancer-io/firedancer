#include "../fd_ballet.h"
#include "fd_ed25519.h"
#include "fd_curve25519.h"
#include "../hex/fd_hex.h"
#include <stdlib.h>
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

/* ref_inv is the inversion as an exponentiation, a^(p-2) with
   p-2 = 2^255-21 = 8*(2^252-3)+3, through the pow22523 addition chain
   (the old fd_f25519_inv was another addition chain for the same
   exponent).  0 maps to 0. */

static fd_f25519_t *
ref_inv( fd_f25519_t *       r,
         fd_f25519_t const * a ) {
  fd_f25519_t e[1], a3[1];
  fd_f25519_pow22523( e, a );
  fd_f25519_sqr( e, e );
  fd_f25519_sqr( e, e );
  fd_f25519_sqr( e, e );
  fd_f25519_sqr( a3, a );
  fd_f25519_mul( a3, a3, a );
  return fd_f25519_mul( r, e, a3 );
}

/* fe_bytes_p_plus writes the 32 little endian bytes of p+d, |d|<2^62 */

static void
fe_bytes_p_plus( uchar buf[ 32 ],
                 long  d ) {
  long  e = d-19L; /* p+d = 2^255+e */
  ulong w[ 4 ];
  if( e>=0L ) { w[0] = (ulong)e; w[1] = 0UL;       w[2] = 0UL;       w[3] = 1UL<<63;      }
  else        { w[0] = (ulong)e; w[1] = ULONG_MAX; w[2] = ULONG_MAX; w[3] = ULONG_MAX>>1; } /* 2^256+e-2^255 */
  memcpy( buf, w, 32UL );
}

static void
check_inv( uchar const buf[ 32 ] ) {
  fd_f25519_t a[1], h[1], e[1];
  uchar hb[ 32 ], eb[ 32 ];
  fd_f25519_frombytes( a, buf );
  fd_f25519_inv( h, a );
  ref_inv( e, a );
  fd_f25519_tobytes( hb, h );
  fd_f25519_tobytes( eb, e );
  if( FD_UNLIKELY( memcmp( hb, eb, 32UL ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "input",    buf, 32UL ));
    FD_LOG_HEXDUMP_WARNING(( "inv",      hb,  32UL ));
    FD_LOG_HEXDUMP_WARNING(( "expected", eb,  32UL ));
    FD_LOG_ERR(( "fd_f25519_inv mismatch" ));
  }
  /* a*inv(a)==1 unless a==0, in which case inv(a)==0 */
  fd_f25519_mul( e, a, h );
  FD_TEST( fd_f25519_is_zero( a ) ? fd_f25519_is_zero( h ) : fd_f25519_eq( e, fd_f25519_one ) );
  /* in place */
  fd_f25519_inv( a, a );
  FD_TEST( fd_f25519_eq( a, h ) );
}

void
test_fe_invert( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;

  /* Differential against the exponentiation: edge cases (0, 1, small
     values, p-1, p and other non-canonical encodings, the top bit
     that frombytes ignores) then random elements. */
  uchar buf[ 32 ];
  for( ulong k=0UL; k<300UL; k++ ) { memset( buf, 0, 32UL ); buf[0] = (uchar)k; buf[1] = (uchar)(k>>8); check_inv( buf ); } /* 0 .. 299 */
  for( long d=-300L; d<300L; d++ ) { fe_bytes_p_plus( buf, d ); check_inv( buf ); } /* p-300 .. p+299 (p+d, d>=0, is non-canonical) */
  memset( buf, 0, 32UL ); buf[31] = 0x80; check_inv( buf ); /* bit 255 set: read as 0 */
  memset( buf, 0xff, 32UL ); check_inv( buf );              /* read as 2^255-1 = p+18 */
  for( ulong k=0UL; k<(g_bench ? 1000000UL : 20000UL); k++ ) {
    for( ulong i=0UL; i<32UL; i++ ) buf[ i ] = fd_rng_uchar( rng );
    check_inv( buf );
  }

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

/* ref_wnaf is the previous bit-at-a-time implementation of
   fd_curve25519_scalar_wnaf, kept as the reference for the
   differential test below. */

static void FD_FN_NO_ASAN
ref_wnaf( short       _t[ 256 ],
          uchar const _s[ 32 ],
          int         bits ) {
  short max = (short)((1 << bits) - 1);

  for( int i=0; i<255; i++ ) _t[i] = ((short)_s[i>>3] >> (i&7)) & 1;
  _t[255] = 0;

  int i;
  for( i=0; i<256; i++ ) if( _t[i] ) break;

  while( i<256 ) {
    short ti = 1;
    int j;
    for( j=i+1; j<256; j++ ) {
      short tj = _t[j];
      if( !tj ) continue;
      short delta = (short)(1 << fd_int_min( j-i, 14 ));
      if( delta>(2*max) ) break;
      short tip = (short)(ti + delta);
      if( tip<=max ) { ti = tip; _t[j] = 0; continue; }
      short tim = (short)(ti - delta);
      if( tim>=-max ) {
        ti = tim; _t[j] = 0;
        for(;;) {
          j++;
          if( !_t[j] ) { _t[j] = 1; break; }
          _t[j] = 0;
        }
        break;
      }
      break;
    }
    _t[i] = ti;
    i = j;
  }
}

/* wnaf_scalar fills s with the case-th test scalar: random, all ones,
   sparse, dense, single bit (top bit set), zero low limbs, and the all
   ones top limb.  Bit 255 is randomly set to check it is ignored. */

static void
wnaf_scalar( fd_rng_t * rng,
             uchar      s[ 32 ],
             ulong      kase ) {
  ulong * u = (ulong *)s;
  switch( kase%7UL ) {
  case 0: fd_rng_b256( rng, s ); break;
  case 1: memset( s, 0xff, 32UL ); break;
  case 2: fd_rng_b256( rng, s ); for( ulong i=0UL; i<4UL; i++ ) u[i] &= fd_rng_ulong( rng ) & fd_rng_ulong( rng ); break;
  case 3: fd_rng_b256( rng, s ); for( ulong i=0UL; i<4UL; i++ ) u[i] |= fd_rng_ulong( rng ) | fd_rng_ulong( rng ); break;
  case 4: memset( s, 0, 32UL ); u[ fd_rng_ulong_roll( rng, 4UL ) ] |= 1UL<<fd_rng_ulong_roll( rng, 64UL ); u[3] |= 1UL<<62; break;
  case 5: fd_rng_b256( rng, s ); for( ulong i=0UL; i<fd_rng_ulong_roll( rng, 4UL ); i++ ) u[i] = 0UL; break;
  default: fd_rng_b256( rng, s ); u[3] = ULONG_MAX; break;
  }
  u[3] = (u[3] & ~(1UL<<63)) | (fd_rng_ulong( rng ) & (1UL<<63));
}

void
test_sc_wnaf( fd_rng_t * rng ) {
  ulong iter = g_bench ? 3000000UL : 100000UL;
  for( ulong i=0UL; i<iter; i++ ) {
    uchar s[32]; wnaf_scalar( rng, s, i );
    int bits = 1 + (int)fd_rng_uint_roll( rng, 12U );
    short t0[256], t1[256];
    ref_wnaf( t0, s, bits );
    fd_curve25519_scalar_wnaf( t1, s, bits );
    if( FD_UNLIKELY( !fd_memeq( t0, t1, sizeof(t0) ) ) ) {
      FD_LOG_ERR(( "fd_curve25519_scalar_wnaf mismatch: scalar " FD_LOG_HEX16_FMT " " FD_LOG_HEX16_FMT " bits %i",
                   FD_LOG_HEX16_FMT_ARGS( s ), FD_LOG_HEX16_FMT_ARGS( s+16 ), bits ));
    }
  }
  FD_LOG_NOTICE(( "fd_curve25519_scalar_wnaf: ok (%lu cases)", iter ));

  /* bench over random reduced scalars (branch behaviour matters) */

  static uchar s[ 1024 ][ 32 ];
  for( ulong i=0UL; i<1024UL; i++ ) { uchar h[64]; fd_curve25519_scalar_reduce( s[i], fd_rng_b512( rng, h ) ); }
  iter = g_bench ? 1000000UL : 0UL;
  for( int bits=4; bits<=8; bits+=4 ) {
    short _t[256]; short * t = _t;
    char cstr[128];
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( t );
      ref_wnaf( t, s[ rem&1023UL ], bits );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "ref_wnaf(%i)", bits ), iter, dt );
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( t );
      fd_curve25519_scalar_wnaf( t, s[ rem&1023UL ], bits );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_curve25519_scalar_wnaf(%i)", bits ), iter, dt );
  }
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

/* Cached verify tests.  Every cached result is compared against the
   uncached one on the same inputs. */

static fd_ed25519_cache_t *
cache_create( ulong ent_cnt,
              ulong seed ) {
  void * mem = aligned_alloc( fd_ed25519_cache_align(), fd_ed25519_cache_footprint( ent_cnt ) );
  FD_TEST( mem );
  fd_ed25519_cache_t * cache = fd_ed25519_cache_join( fd_ed25519_cache_new( mem, ent_cnt, seed ) );
  FD_TEST( cache );
  return cache;
}

static void
cache_destroy( fd_ed25519_cache_t * cache ) {
  free( fd_ed25519_cache_delete( fd_ed25519_cache_leave( cache ) ) );
}

/* check_cached verifies (msg,sig,pub) cold, then several times so the
   key gets cached, and checks every result matches uncached verify. */

static int
check_cached( uchar const *        msg,
              ulong                msg_sz,
              uchar const *        sig,
              uchar const *        pub,
              fd_sha512_t *        sha,
              fd_ed25519_cache_t * cache,
              ulong                rep ) {
  int expected = fd_ed25519_verify( msg, msg_sz, sig, pub, sha );
  for( ulong i=0UL; i<rep; i++ ) FD_TEST( fd_ed25519_verify_cached( msg, msg_sz, sig, pub, sha, cache )==expected );
  return expected;
}

/* mutate applies a random corruption to a signature / key / msg */

static void
mutate( fd_rng_t * rng,
        uchar *    msg,
        ulong      msg_sz,
        uchar *    sig,
        uchar *    pub ) {
  switch( fd_rng_uint_roll( rng, 9U ) ) {
  case 0: break;                                                                              /* good */
  case 1: if( msg_sz ) msg[ fd_rng_ulong_roll( rng, msg_sz ) ] ^= (uchar)(1U<<fd_rng_uint_roll( rng, 8U )); break; /* bad msg */
  case 2: sig[ fd_rng_uint_roll( rng, 32U ) ] ^= (uchar)(1U<<fd_rng_uint_roll( rng, 8U )); break; /* bad R */
  case 3: sig[ 32U+fd_rng_uint_roll( rng, 32U ) ] ^= (uchar)(1U<<fd_rng_uint_roll( rng, 8U )); break; /* bad S (maybe non-canonical) */
  case 4: pub[ fd_rng_uint_roll( rng, 32U ) ] ^= (uchar)(1U<<fd_rng_uint_roll( rng, 8U )); break; /* bad A */
  case 5: fd_rng_b256( rng, sig ); break;                                                    /* random R */
  case 6: fd_rng_b256( rng, pub ); break;                                                    /* random A */
  case 7: { /* S+L (malleable, rejected) */
    static uchar const L[32] = { 0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
                                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10 };
    uint c = 0U;
    for( ulong i=0UL; i<32UL; i++ ) { c += (uint)sig[32UL+i] + (uint)L[i]; sig[32UL+i] = (uchar)c; c >>= 8; }
    break;
  }
  case 8: pub[31] ^= 0x80; break;                                                            /* flip x sign of A */
  }
}

/* Small order points and non-canonical encodings of them */

static char const * const small_order_hex[] = {
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  NULL
};

static void
test_verify_cached( fd_rng_t *    rng,
                    fd_sha512_t * sha ) {

  /* Split double scalar mul matches the regular one for random points
     (including mixed order points A+T) and scalars. */

  static fd_ed25519_point_t b_tbl[ FD_ED25519_SPLIT_B_TBL_CNT ];
  fd_ed25519_split_table_b( b_tbl );
  for( ulong iter=0UL; iter<2000UL; iter++ ) {
    uchar buf[32]; uchar h[64]; uchar n1[32]; uchar n2[32];
    fd_ed25519_point_t A[1];
    do { fd_rng_b256( rng, buf ); } while( fd_ed25519_point_frombytes_1x( A, buf ) );
    if( iter&1UL ) { /* add a torsion component */
      fd_ed25519_point_t T[1];
      fd_hex_decode( h, small_order_hex[ fd_rng_uint_roll( rng, 8U ) ], 32 );
      FD_TEST( !fd_ed25519_point_frombytes_1x( T, h ) );
      fd_ed25519_point_add( A, A, T );
    }
    fd_curve25519_into_affine( A );
    fd_curve25519_scalar_reduce( n1, fd_rng_b512( rng, h ) );
    fd_curve25519_scalar_reduce( n2, fd_rng_b512( rng, h ) );
    if( iter%7UL==0UL ) memset( n1, 0, 32 );
    if( iter%11UL==0UL ) memset( n2, 0, 32 );
    static fd_ed25519_point_t a_tbl[ FD_ED25519_SPLIT_A_TBL_CNT ];
    fd_ed25519_split_table_a( a_tbl, A );
    fd_ed25519_point_t r0[1], r1[1];
    fd_ed25519_double_scalar_mul_base      ( r0, n1, A, n2 );
    fd_ed25519_double_scalar_mul_base_split( r1, n1, a_tbl, n2, b_tbl );
    FD_TEST( fd_ed25519_point_eq( r0, r1 ) );
  }

  /* frombytes_1x is bit identical to either slot of frombytes_2x */

  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    uchar a[32], b[32];
    fd_ed25519_point_t p1[1], p2a[1], p2b[1];
    fd_rng_b256( rng, a );
    if( iter<14UL ) fd_hex_decode( a, small_order_hex[ iter ], 32 );
    do { fd_rng_b256( rng, b ); } while( fd_ed25519_point_frombytes_1x( p1, b ) ); /* b valid */
    int e1 = fd_ed25519_point_frombytes_1x( p1, a );
    int e2 = fd_ed25519_point_frombytes_2x( p2a, a, p2b, b );
    FD_TEST( e2==(e1 ? -1 : 0) );
    if( !e1 ) FD_TEST( fd_memeq( p1, p2a, sizeof(fd_ed25519_point_t) ) );
    e2 = fd_ed25519_point_frombytes_2x( p2a, b, p2b, a );
    FD_TEST( e2==(e1 ? -2 : 0) );
    if( !e1 ) FD_TEST( fd_memeq( p1, p2b, sizeof(fd_ed25519_point_t) ) );
  }

  /* Staged decode matches frombytes_1x for any step schedule */

  ulong decode_iter = g_bench ? 1000000UL : 50000UL;
  for( ulong iter=0UL; iter<decode_iter; iter++ ) {
    uchar a[32];
    fd_ed25519_point_t p1[1], p2[1];
    switch( iter%4UL ) {
    case 0: fd_rng_b256( rng, a ); break;
    case 1: fd_hex_decode( a, small_order_hex[ fd_rng_uint_roll( rng, 14U ) ], 32 ); break;
    case 2: do { fd_rng_b256( rng, a ); } while( fd_ed25519_point_frombytes_1x( p1, a ) ); a[ fd_rng_uint_roll( rng, 32U ) ] ^= (uchar)(1U<<fd_rng_uint_roll( rng, 8U )); break;
    default: do { fd_rng_b256( rng, a ); } while( fd_ed25519_point_frombytes_1x( p1, a ) ); a[31] ^= 0x80; break;
    }
    memset( p1, 0xa5, sizeof(fd_ed25519_point_t) ); memset( p2, 0x5a, sizeof(fd_ed25519_point_t) );
    int e1 = fd_ed25519_point_frombytes_1x( p1, a );
    fd_ed25519_point_decode_t dec[1];
    fd_ed25519_point_decode_init( dec, a );
    memset( a, 0, 32 ); /* buf is only read by init */
    if( iter%5UL==0UL ) fd_ed25519_point_decode_step( dec, ULONG_MAX ); /* all at once */
    else if( iter%3UL ) {                                                 /* random schedule (none when iter%3==0) */
      ulong budget = fd_rng_ulong_roll( rng, 400UL );
      while( budget ) { ulong n = fd_ulong_min( budget, 1UL+fd_rng_ulong_roll( rng, 7UL ) ); fd_ed25519_point_decode_step( dec, n ); budget -= n; }
    }
    int e2 = fd_ed25519_point_decode_fini( p2, dec );
    FD_TEST( e1==e2 );
    if( !e1 ) FD_TEST( fd_memeq( p1, p2, sizeof(fd_ed25519_point_t) ) );
  }
  if( g_bench ) {
    uchar _a[32]; uchar * a = _a; fd_ed25519_point_t p[1];
    do { fd_rng_b256( rng, a ); } while( fd_ed25519_point_frombytes_1x( p, a ) );
    ulong iter = 100000UL;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( a ); fd_ed25519_point_frombytes_1x( p, a ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ed25519_point_frombytes_1x", iter, dt );
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { fd_ed25519_point_decode_t dec[1]; FD_COMPILER_FORGET( a ); fd_ed25519_point_decode_init( dec, a ); fd_ed25519_point_decode_fini( p, dec ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ed25519_point_decode (staged)", iter, dt );
  }

  /* Fused split scalar mul matches the plain one */

  for( ulong iter=0UL; iter<500UL; iter++ ) {
    uchar buf[32]; uchar h[64]; uchar n1[32]; uchar n2[32]; uchar enc[32];
    fd_ed25519_point_t A[1], p1[1], p2[1];
    do { fd_rng_b256( rng, buf ); } while( fd_ed25519_point_frombytes_1x( A, buf ) );
    fd_curve25519_into_affine( A );
    fd_curve25519_scalar_reduce( n1, fd_rng_b512( rng, h ) );
    fd_curve25519_scalar_reduce( n2, fd_rng_b512( rng, h ) );
    if( iter%7UL==0UL ) memset( n1, 0, 32 );
    if( iter%11UL==0UL ) memset( n2, 0, 32 );
    if( iter%13UL==0UL ) { memset( n1, 0, 32 ); memset( n2, 0, 32 ); }
    fd_rng_b256( rng, enc );
    static fd_ed25519_point_t a_tbl[ FD_ED25519_SPLIT_A_TBL_CNT ];
    fd_ed25519_split_table_a( a_tbl, A );
    fd_ed25519_point_t r0[1], r1[1];
    fd_ed25519_point_decode_t dec[1];
    fd_ed25519_point_decode_init( dec, enc );
    fd_ed25519_double_scalar_mul_base_split       ( r0, n1, a_tbl, n2, b_tbl );
    fd_ed25519_double_scalar_mul_base_split_decode( r1, n1, a_tbl, n2, b_tbl, dec );
    FD_TEST( fd_memeq( r0, r1, sizeof(fd_ed25519_point_t) ) );
    int e1 = fd_ed25519_point_frombytes_1x( p1, enc );
    int e2 = fd_ed25519_point_decode_fini( p2, dec );
    FD_TEST( e1==e2 );
    if( !e1 ) FD_TEST( fd_memeq( p1, p2, sizeof(fd_ed25519_point_t) ) );
  }

  /* Differential: random keys with repeats, random corruptions,
     small caches to exercise eviction. */

  ulong const ent_cnts[3] = { 4UL, 16UL, 1024UL };
  for( ulong ci=0UL; ci<3UL; ci++ ) {
    fd_ed25519_cache_t * cache = cache_create( ent_cnts[ci], fd_rng_ulong( rng ) );
#   define KEY_CNT 64UL
    uchar prv[ KEY_CNT ][ 32 ], pubk[ KEY_CNT ][ 32 ];
    for( ulong i=0UL; i<KEY_CNT; i++ ) fd_ed25519_public_from_private( pubk[i], fd_rng_b256( rng, prv[i] ), sha );
    ulong good = 0UL, bad[4] = {0};
    for( ulong iter=0UL; iter<6000UL; iter++ ) {
      ulong  i = fd_rng_ulong_roll( rng, iter<3000UL ? 8UL : KEY_CNT ); /* hot keys first, then more keys than fit */
      uchar  msg[ 256 ]; ulong msg_sz = fd_rng_ulong_roll( rng, 257UL );
      for( ulong b=0UL; b<msg_sz; b++ ) msg[b] = fd_rng_uchar( rng );
      uchar  sig[ 64 ], pub[ 32 ];
      memcpy( pub, pubk[i], 32 );
      fd_ed25519_sign( sig, msg, msg_sz, pub, prv[i], sha );
      mutate( rng, msg, msg_sz, sig, pub );
      int res = check_cached( msg, msg_sz, sig, pub, sha, cache, 1UL+fd_rng_ulong_roll( rng, 3UL ) );
      if( !res ) good++; else bad[ -res ]++;
    }
    FD_LOG_NOTICE(( "cached differential ent_cnt=%lu: good %lu err_sig %lu err_pubkey %lu err_msg %lu; hit %lu miss %lu insert %lu",
                    ent_cnts[ci], good, bad[1], bad[2], bad[3],
                    fd_ed25519_cache_hit_cnt( cache ), fd_ed25519_cache_miss_cnt( cache ), fd_ed25519_cache_insert_cnt( cache ) ));
    FD_TEST( good && bad[1] && bad[2] && bad[3] );
    FD_TEST( fd_ed25519_cache_hit_cnt( cache ) && fd_ed25519_cache_insert_cnt( cache ) );

    /* Batch: mixes of cached and uncached keys, errors at any index */

    for( ulong iter=0UL; iter<1500UL; iter++ ) {
      uchar msg[ 128 ]; ulong msg_sz = fd_rng_ulong_roll( rng, 129UL );
      for( ulong b=0UL; b<msg_sz; b++ ) msg[b] = fd_rng_uchar( rng );
      uchar batch = (uchar)(1UL+fd_rng_ulong_roll( rng, 12UL ));
      if( iter%100UL==0UL ) batch = (uchar)( iter%200UL ? 0 : 17 );
      uchar sigs[ 64*17 ], pubs[ 32*17 ];
      fd_sha512_t * shas[ 17 ];
      for( ulong j=0UL; j<17UL; j++ ) shas[j] = sha;
      for( ulong j=0UL; j<batch; j++ ) {
        ulong i = fd_rng_ulong_roll( rng, 16UL );
        memcpy( pubs+32*j, pubk[i], 32 );
        fd_ed25519_sign( sigs+64*j, msg, msg_sz, pubs+32*j, prv[i], sha );
      }
      for( ulong j=0UL; j<batch; j++ ) if( !fd_rng_uint_roll( rng, 6U ) ) {
        uchar m2[1];
        mutate( rng, m2, 0UL, sigs+64*j, pubs+32*j );
      }
      int expected = fd_ed25519_verify_batch_single_msg( msg, msg_sz, sigs, pubs, shas, batch );
      for( ulong r=0UL; r<3UL; r++ ) {
        FD_TEST( fd_ed25519_verify_batch_single_msg_cached( msg, msg_sz, sigs, pubs, shas, batch, cache )==expected );
      }
    }
    cache_destroy( cache );
  }

  /* Small order / non-canonical keys and R's are never cached and give
     the same results.  Use a valid signature for R and S so that the
     key checks are what fails. */

  {
    fd_ed25519_cache_t * cache = cache_create( 16UL, 1UL );
    uchar prv[32], pub[32], sig[64], msg[32];
    fd_ed25519_point_t R0[1];
    fd_ed25519_public_from_private( pub, fd_rng_b256( rng, prv ), sha );
    fd_rng_b256( rng, msg );
    fd_ed25519_sign( sig, msg, 32UL, pub, prv, sha );
    for( ulong i=0UL; small_order_hex[i]; i++ ) {
      uchar bad[32]; fd_hex_decode( bad, small_order_hex[i], 32 );
      FD_TEST( check_cached( msg, 32UL, sig, bad, sha, cache, 4UL )==FD_ED25519_ERR_PUBKEY );
      uchar sig2[64]; memcpy( sig2, bad, 32 ); memcpy( sig2+32, sig+32, 32 );
      FD_TEST( check_cached( msg, 32UL, sig2, pub, sha, cache, 4UL )==FD_ED25519_ERR_SIG );
    }
    FD_TEST( check_cached( msg, 32UL, sig, pub, sha, cache, 4UL )==FD_ED25519_SUCCESS );
    /* Now that pub is cached, bad R must still be rejected identically */
    FD_TEST( fd_ed25519_cache_insert_cnt( cache )==1UL );
    for( ulong i=0UL; small_order_hex[i]; i++ ) {
      uchar sig2[64]; fd_hex_decode( sig2, small_order_hex[i], 32 ); memcpy( sig2+32, sig+32, 32 );
      FD_TEST( check_cached( msg, 32UL, sig2, pub, sha, cache, 2UL )==FD_ED25519_ERR_SIG );
    }
    FD_TEST( fd_ed25519_cache_insert_cnt( cache )==1UL );

    /* Bad R or S gives the same error cached or not, and a cached
       failure earns no credit */

    for( ulong iter=0UL; iter<2000UL; iter++ ) {
      uchar sig2[64]; memcpy( sig2, sig, 64 );
      int expect_sig = 1;
      switch( iter%4UL ) {
      case 0: do { fd_rng_b256( rng, sig2 ); } while( !fd_ed25519_point_frombytes_1x( &R0[0], sig2 ) ); break; /* not on curve */
      case 1: fd_hex_decode( sig2, small_order_hex[ fd_rng_uint_roll( rng, 14U ) ], 32 ); break;              /* small order */
      case 2: sig2[ fd_rng_uint_roll( rng, 32U ) ] ^= (uchar)(1U<<fd_rng_uint_roll( rng, 8U )); expect_sig = 0; break; /* bit flip in R */
      default: do { fd_rng_b256( rng, sig2 ); } while( fd_ed25519_point_frombytes_1x( &R0[0], sig2 ) ); expect_sig = 0; break; /* random point */
      }
      ulong hit0 = fd_ed25519_cache_hit_cnt( cache );
      int res = check_cached( msg, 32UL, sig2, pub, sha, cache, 2UL );
      FD_TEST( fd_ed25519_cache_hit_cnt( cache )==hit0+2UL ); /* took the cached path */
      if( expect_sig ) FD_TEST( res==FD_ED25519_ERR_SIG );
      else             FD_TEST( res==FD_ED25519_ERR_SIG || res==FD_ED25519_ERR_MSG );
      /* and with a key that is not cached */
      uchar prv2[32], pub2[32], sig3[64];
      fd_ed25519_public_from_private( pub2, fd_rng_b256( rng, prv2 ), sha );
      fd_ed25519_sign( sig3, msg, 32UL, pub2, prv2, sha );
      memcpy( sig3, sig2, 32 );
      FD_TEST( check_cached( msg, 32UL, sig3, pub2, sha, cache, 1UL )==( expect_sig ? FD_ED25519_ERR_SIG : (res==FD_ED25519_ERR_SIG ? FD_ED25519_ERR_SIG : FD_ED25519_ERR_MSG) ) );
    }
    FD_TEST( fd_ed25519_cache_insert_cnt( cache )==1UL );
    /* batch: invalid R after an earlier failure still gives ERR_SIG */
    {
      uchar sigs[128], pubs[64]; fd_sha512_t * shas[2] = { sha, sha };
      memcpy( sigs, sig, 64 ); sigs[40] ^= 1; /* S off by 2^64: still canonical, group equation fails */
      memcpy( pubs, pub, 32 );
      memcpy( sigs+64, sig, 64 ); fd_hex_decode( sigs+64, small_order_hex[4], 32 );
      memcpy( pubs+32, pub, 32 );
      int expected = fd_ed25519_verify_batch_single_msg( msg, 32UL, sigs, pubs, shas, 2 );
      FD_TEST( expected==FD_ED25519_ERR_SIG );
      FD_TEST( fd_ed25519_verify_batch_single_msg_cached( msg, 32UL, sigs, pubs, shas, 2, cache )==expected );
      do { fd_rng_b256( rng, sigs+64 ); } while( !fd_ed25519_point_frombytes_1x( &R0[0], sigs+64 ) );
      expected = fd_ed25519_verify_batch_single_msg( msg, 32UL, sigs, pubs, shas, 2 );
      FD_TEST( expected==FD_ED25519_ERR_SIG );
      FD_TEST( fd_ed25519_verify_batch_single_msg_cached( msg, 32UL, sigs, pubs, shas, 2, cache )==expected );
    }
    cache_destroy( cache );
  }

  /* Table builds are rate limited: with every key new, at most ~1 in 8
     verifies builds a table (plus the initial burst). */

  {
    fd_ed25519_cache_t * cache = cache_create( 1024UL, 4UL );
    ulong n = 1000UL;
    for( ulong i=0UL; i<n; i++ ) {
      uchar prv[32], pub[32], sig[64], msg[8];
      fd_ed25519_public_from_private( pub, fd_rng_b256( rng, prv ), sha );
      for( ulong r=0UL; r<2UL; r++ ) {
        memcpy( msg, &r, 8 );
        fd_ed25519_sign( sig, msg, 8UL, pub, prv, sha );
        FD_TEST( check_cached( msg, 8UL, sig, pub, sha, cache, 1UL )==FD_ED25519_SUCCESS );
      }
    }
    ulong ins = fd_ed25519_cache_insert_cnt( cache );
    FD_LOG_NOTICE(( "rate limit: %lu inserts for %lu new keys", ins, n ));
    FD_TEST( ins>=64UL && ins<=64UL+2UL*n/8UL+1UL );
    cache_destroy( cache );
  }

  /* Vector suites through the cached path: each vector repeated so its
     key gets cached where possible, then again with a warm cache. */

  {
    fd_ed25519_cache_t * cache = cache_create( 4096UL, 2UL );
    for( ulong pass=0UL; pass<2UL; pass++ ) {
      for( fd_ed25519_verify_wycheproof_t const * proof = ed25519_verify_wycheproofs; proof->msg; proof++ ) {
        int res = check_cached( proof->msg, proof->msg_sz, proof->sig, proof->pub, sha, cache, 3UL );
        FD_TEST( (res==FD_ED25519_SUCCESS)==proof->ok );
      }
      for( fd_ed25519_verify_cctv_t const * proof = ed25519_verify_cctvs; proof->msg; proof++ ) {
        int res = check_cached( proof->msg, proof->msg_sz, proof->sig, proof->pub, sha, cache, 3UL );
        FD_TEST( (res==FD_ED25519_SUCCESS)==proof->ok );
      }
    }
    FD_LOG_NOTICE(( "cached vectors: hit %lu miss %lu insert %lu",
                    fd_ed25519_cache_hit_cnt( cache ), fd_ed25519_cache_miss_cnt( cache ), fd_ed25519_cache_insert_cnt( cache ) ));
    FD_TEST( fd_ed25519_cache_hit_cnt( cache ) );

    /* cctv vectors (mixed order / non-canonical A and R) against a
       cached key in slot 0 and 2 of a batch */

    uchar const * msg    = ed25519_verify_cctvs[7].msg;
    ulong         msg_sz = ed25519_verify_cctvs[7].msg_sz;
    uchar sigs[ 64*4 ], pubs[ 32*4 ];
    fd_sha512_t * shas[4] = { sha, sha, sha, sha };
    for( ulong j=0UL; j<4UL; j++ ) {
      uchar prv[32];
      fd_ed25519_public_from_private( pubs+32*j, fd_rng_b256( rng, prv ), sha );
      fd_ed25519_sign( sigs+64*j, msg, msg_sz, pubs+32*j, prv, sha );
    }
    for( fd_ed25519_verify_cctv_t const * proof = ed25519_verify_cctvs; proof->msg; proof++ ) {
      if( proof->msg_sz!=msg_sz || !fd_memeq( proof->msg, msg, msg_sz ) ) continue;
      memcpy( sigs+64, proof->sig, 64 ); memcpy( pubs+32, proof->pub, 32 );
      int expected = fd_ed25519_verify_batch_single_msg( msg, msg_sz, sigs, pubs, shas, 4 );
      FD_TEST( (expected==FD_ED25519_SUCCESS)==proof->ok );
      for( ulong r=0UL; r<3UL; r++ ) FD_TEST( fd_ed25519_verify_batch_single_msg_cached( msg, msg_sz, sigs, pubs, shas, 4, cache )==expected );
    }
    cache_destroy( cache );
  }

  FD_LOG_NOTICE(( "test_verify_cached: ok" ));

  if( !g_bench ) return;

  /* Bench: keys signing random messages, random key order */

  ulong const key_cnts[4] = { 1UL, 256UL, 2048UL, 4096UL };
  for( ulong ki=0UL; ki<4UL; ki++ ) {
    ulong key_cnt = key_cnts[ki];
    fd_ed25519_cache_t * cache = cache_create( 4096UL, 3UL );
    uchar (* pubs)[32]  = aligned_alloc( 64UL, key_cnt*32UL  );
    uchar (* sigs)[64]  = aligned_alloc( 64UL, key_cnt*64UL  );
    uchar (* msgs)[200] = aligned_alloc( 64UL, key_cnt*200UL );
    for( ulong i=0UL; i<key_cnt; i++ ) {
      uchar prv[32];
      fd_ed25519_public_from_private( pubs[i], fd_rng_b256( rng, prv ), sha );
      for( ulong b=0UL; b<200UL; b++ ) msgs[i][b] = fd_rng_uchar( rng );
      fd_ed25519_sign( sigs[i], msgs[i], 200UL, pubs[i], prv, sha );
    }
    ulong iter = 20000UL;
    char cstr[128];

    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      ulong i = fd_rng_ulong_roll( rng, key_cnt );
      FD_TEST( !fd_ed25519_verify( msgs[i], 200UL, sigs[i], pubs[i], sha ) );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "verify uncached keys=%lu", key_cnt ), iter, dt );

    /* cold: a key's first verify (miss, same work as uncached) */
    dt = fd_log_wallclock();
    for( ulong i=0UL; i<key_cnt; i++ ) FD_TEST( !fd_ed25519_verify_cached( msgs[i], 200UL, sigs[i], pubs[i], sha, cache ) );
    dt = fd_log_wallclock() - dt;
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "verify cached miss keys=%lu", key_cnt ), key_cnt, dt );

    /* warm up until every key that fits is cached */
    for( ulong pass=0UL; pass<64UL; pass++ ) {
      for( ulong i=0UL; i<key_cnt; i++ ) FD_TEST( !fd_ed25519_verify_cached( msgs[i], 200UL, sigs[i], pubs[i], sha, cache ) );
    }

    ulong hit0 = fd_ed25519_cache_hit_cnt( cache ), miss0 = fd_ed25519_cache_miss_cnt( cache );
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      ulong i = fd_rng_ulong_roll( rng, key_cnt );
      FD_TEST( !fd_ed25519_verify_cached( msgs[i], 200UL, sigs[i], pubs[i], sha, cache ) );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "verify cached warm keys=%lu", key_cnt ), iter, dt );
    ulong hit = fd_ed25519_cache_hit_cnt( cache )-hit0, miss = fd_ed25519_cache_miss_cnt( cache )-miss0;
    FD_LOG_NOTICE(( "  warm hit rate %.1f%% (inserted %lu)", 100.*(double)hit/(double)(hit+miss), fd_ed25519_cache_insert_cnt( cache ) ));

    /* table build cost */
    static fd_ed25519_point_t a_tbl[ FD_ED25519_SPLIT_A_TBL_CNT ];
    fd_ed25519_point_t A[1];
    FD_TEST( !fd_ed25519_point_frombytes_1x( A, pubs[0] ) );
    dt = fd_log_wallclock();
    for( ulong rem=1000UL; rem; rem-- ) { FD_COMPILER_MFENCE(); fd_ed25519_split_table_a( a_tbl, A ); }
    dt = fd_log_wallclock() - dt;
    if( !ki ) log_bench( "fd_ed25519_split_table_a", 1000UL, dt );

    free( pubs ); free( sigs ); free( msgs );
    cache_destroy( cache );
  }
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
  test_sc_wnaf      ( rng );
  test_sc_unaligned_output( rng );

  test_public_from_private( rng, sha );
  test_sign               ( rng, sha );
  test_sign_batch         ( rng, sha );
  test_verify             ( rng, sha );

  test_wycheproofs( sha );
  test_cctv       ( sha );
  test_cctv_batch ( rng, sha );

  test_verify_cached( rng, sha );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
