#include "../fd_ballet.h"
#include "fd_ed25519_private.h"

static uchar *
fd_rng_b256( fd_rng_t * rng,
             uchar *    r ) {
  ulong * u = (ulong *)r;
  u[0] = fd_rng_ulong( rng ); u[1] = fd_rng_ulong( rng ); u[2] = fd_rng_ulong( rng ); u[3] = fd_rng_ulong( rng );
  return r;
}

static uchar *
fd_rng_b512( fd_rng_t * rng,
             uchar *    r ) {
  ulong * u = (ulong *)r;
  u[0] = fd_rng_ulong( rng ); u[1] = fd_rng_ulong( rng ); u[2] = fd_rng_ulong( rng ); u[3] = fd_rng_ulong( rng );
  u[4] = fd_rng_ulong( rng ); u[5] = fd_rng_ulong( rng ); u[6] = fd_rng_ulong( rng ); u[7] = fd_rng_ulong( rng );
  return r;
}

static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

#define OPENSSL_COMPARE 0
#if OPENSSL_COMPARE
#include <stdint.h>
#include "ATTIC/curve25519.c"

static int *
fe_rng( int *      h,
        fd_rng_t * rng ) {
  uint m26 = (uint)FD_ULONG_MASK_LSB(26); uint m25 = (uint)FD_ULONG_MASK_LSB(25);
  h[0] = (int)(fd_rng_uint( rng ) & m26); h[1] = (int)(fd_rng_uint( rng ) & m25);
  h[2] = (int)(fd_rng_uint( rng ) & m26); h[3] = (int)(fd_rng_uint( rng ) & m25);
  h[4] = (int)(fd_rng_uint( rng ) & m26); h[5] = (int)(fd_rng_uint( rng ) & m25);
  h[6] = (int)(fd_rng_uint( rng ) & m26); h[7] = (int)(fd_rng_uint( rng ) & m25);
  h[8] = (int)(fd_rng_uint( rng ) & m26); h[9] = (int)(fd_rng_uint( rng ) & m25);
  return h;
}
#endif

static void
test_fe_frombytes( fd_rng_t * rng ) {
  uchar           _s[32]; uchar *           s = _s;
  fd_ed25519_fe_t _h[1];  fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    uchar ref_s[32]; fe ref_h; fe_frombytes( ref_h, fd_rng_b256( rng, ref_s ) );
    fd_memcpy( s, ref_s, 32UL );
    FD_TEST( fd_ed25519_fe_frombytes( h, s )==h );
    FD_TEST( !memcmp( s, ref_s, 32UL ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );
  }
# endif

  fd_rng_b256( rng, s );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( s ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_frombytes( h, s ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_frombytes", iter, dt );
}

static void
test_fe_tobytes( fd_rng_t * rng ) {
  fd_ed25519_fe_t _h[1];  fd_ed25519_fe_t * h = _h;
  uchar           _s[32]; uchar *           s = _s;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_h; uchar ref_s[32]; fe_tobytes( ref_s, fe_rng( ref_h, rng ) );
    fd_memcpy( h, ref_h, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_tobytes( s, h )==s );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );
    FD_TEST( !memcmp( s, ref_s, 32UL ) );
  }
# endif

  fd_ed25519_fe_rng( h, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( h ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_tobytes( s, h ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_tobytes", iter, dt );
}

static void
test_fe_copy( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_copy( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_copy( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_copy( f, f )==f );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_copy( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_copy", iter, dt );
}

static void
test_fe_0( fd_rng_t * rng ) {
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_h; fe_rng( ref_h, rng ); fd_memcpy( h, ref_h, sizeof(fe) ); fe_0( ref_h );
    FD_TEST( fd_ed25519_fe_0( h )==h );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );
  }
# endif

  fd_ed25519_fe_rng( h, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( h ); fd_ed25519_fe_0( h ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_0", iter, dt );
}

static void
test_fe_1( fd_rng_t * rng ) {
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_h; fe_rng( ref_h, rng ); fd_memcpy( h, ref_h, sizeof(fe) ); fe_1( ref_h );
    FD_TEST( fd_ed25519_fe_1( h )==h );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );
  }
# endif

  fd_ed25519_fe_rng( h, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( h ); fd_ed25519_fe_1( h ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_1", iter, dt );
}

static void
test_fe_add( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _g[1]; fd_ed25519_fe_t * g = _g;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_g; fe ref_h; fe_add( ref_h, fe_rng( ref_f, rng ), fe_rng( ref_g, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    fd_memcpy( g, ref_g, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_add( h, f, g )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_add( f, f, g )==f );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
    fd_memcpy( f, ref_f, sizeof(fe) );

    FD_TEST( fd_ed25519_fe_add( g, f, g )==g );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_h, sizeof(fe) ) );
  //fd_memcpy( g, ref_g, sizeof(fe) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  fd_ed25519_fe_rng( g, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( g ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_add( h, f, g );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_add", iter, dt );
}

static void
test_fe_sub( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _g[1]; fd_ed25519_fe_t * g = _g;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_g; fe ref_h; fe_sub( ref_h, fe_rng( ref_f, rng ), fe_rng( ref_g, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    fd_memcpy( g, ref_g, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_sub( h, f, g )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_sub( f, f, g )==f );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
    fd_memcpy( f, ref_f, sizeof(fe) );

    FD_TEST( fd_ed25519_fe_sub( g, f, g )==g );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_h, sizeof(fe) ) );
  //fd_memcpy( g, ref_g, sizeof(fe) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  fd_ed25519_fe_rng( g, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( g ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_sub( h, f, g );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_sub", iter, dt );
}

static void
test_fe_mul( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _g[1]; fd_ed25519_fe_t * g = _g;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_g; fe ref_h; fe_mul( ref_h, fe_rng( ref_f, rng ), fe_rng( ref_g, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    fd_memcpy( g, ref_g, sizeof(fe) );
    fd_ed25519_fe_t z[1]; fd_ed25519_fe_0( z );
    FD_TEST( fd_ed25519_fe_mul( h, f, g )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_mul( f, f, g )==f );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
    fd_memcpy( f, ref_f, sizeof(fe) );

    FD_TEST( fd_ed25519_fe_mul( g, f, g )==g );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  fd_ed25519_fe_rng( g, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( g ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_mul( h, f, g );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_mul", iter, dt );
}

static void
test_fe_sq( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_sq( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_sq( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_sq( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_sq( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_sq", iter, dt );
}

static void
test_fe_invert( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=10000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_invert( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_invert( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_invert( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_invert( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_invert", iter, dt );
}

static void
test_fe_neg( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_neg( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_neg( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_neg( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 100000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_neg( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_neg", iter, dt );
}

static void
test_fe_if( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _g[1]; fd_ed25519_fe_t * g = _g;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
  int c;
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; fe ref_g; fe ref_h;
    c = (int)(fd_rng_uint( rng ) & 1U);
    fe_rng( ref_f, rng );
    fe_rng( ref_g, rng );
    fd_memcpy( ref_h, ref_g, sizeof(fe) ); fe_cmov( ref_h, ref_f, (uint)c );
    fd_memcpy( f, ref_f, sizeof(fe) );
    fd_memcpy( g, ref_g, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_if( h, c, f, g )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_if( f, c, f, g )==f );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
    fd_memcpy( f, ref_f, sizeof(fe) );

    FD_TEST( fd_ed25519_fe_if( g, c, f, g )==g );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_h, sizeof(fe) ) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  fd_ed25519_fe_rng( g, rng );
  ulong iter = 100000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    c = (int)(rem & 1UL);
    FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( c ); FD_COMPILER_FORGET( h );
    fd_ed25519_fe_if( h, c, f, g );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_if", iter, dt );
}

static void
test_fe_isnonzero( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  int c;
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; c = fe_isnonzero( fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_isnonzero( f )==c );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 100000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f );
    c = fd_ed25519_fe_isnonzero( f );
    FD_COMPILER_FORGET( c );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_isnonzero", iter, dt );
}

static void
test_fe_isnegative( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  int c;
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; c = fe_isnegative( fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_isnegative( f )==c );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 100000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( f );
    c = fd_ed25519_fe_isnegative( f );
    FD_COMPILER_FORGET( c );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_isnegative", iter, dt );
}

static void
test_fe_sq2( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_sq2( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_sq2( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_sq2( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_sq2( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_sq2", iter, dt );
}

static void
test_fe_pow22523( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_pow22523( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_ed25519_fe_pow22523( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_ed25519_fe_pow22523( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 100000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_pow22523( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_pow22523", iter, dt );
}

/* FIXME: ADD VMUL, VSQ, VSQN TESTS HERE */

static void
test_fe_sqrt_ratio( fd_rng_t * rng ) {
  /* u and v zero */
  do {
    fd_ed25519_fe_t r[1];
    fd_ed25519_fe_t u[1]; fd_ed25519_fe_0( u );
    fd_ed25519_fe_t v[1]; fd_ed25519_fe_0( v );
    int is_sq = fd_ed25519_fe_sqrt_ratio( r, u, v );
    FD_TEST( is_sq==1 );
    FD_TEST( !fd_ed25519_fe_isnonzero( r ) );  /* r==0 */
  } while(0);

  /* u zero, v non-zero */
  do {
    fd_ed25519_fe_t r[1];
    fd_ed25519_fe_t u[1]; fd_ed25519_fe_0( u );
    fd_ed25519_fe_t v[1]; fd_ed25519_fe_1( v );
    int is_sq = fd_ed25519_fe_sqrt_ratio( r, u, v );
    FD_TEST( is_sq==1 );
    FD_TEST( !fd_ed25519_fe_isnonzero( r ) );  /* r==0 */
  } while(0);

  /* u non-zero, v zero */
  do {
    fd_ed25519_fe_t r[1];
    fd_ed25519_fe_t u[1]; fd_ed25519_fe_1( u );
    fd_ed25519_fe_t v[1]; fd_ed25519_fe_0( v );
    int is_sq = fd_ed25519_fe_sqrt_ratio( r, u, v );
    FD_TEST( is_sq==0 );
    FD_TEST( !fd_ed25519_fe_isnonzero( r ) );  /* r==0 */
  } while(0);

  /* u/v is square */
  ulong iter = 100000UL;
  for( ulong rem=iter; rem; rem-- ) {
    fd_ed25519_fe_t v[1]; fd_ed25519_fe_t u[1];
    fd_ed25519_fe_rng( v, rng  );  /* v = rand() */
    fd_ed25519_fe_sq ( u, v    );
    fd_ed25519_fe_mul( u, u, v );  /* u = v^3 */
    /* r = sqrt(u/v) */
    fd_ed25519_fe_t r[1];
    int is_sq = fd_ed25519_fe_sqrt_ratio( r, u, v );
    FD_TEST( is_sq==1 );
    FD_TEST(  fd_ed25519_fe_isnonzero ( r ) );
    FD_TEST( !fd_ed25519_fe_isnegative( r ) );
    /* u2 = r^2 * v */
    fd_ed25519_fe_t u2[1];
    fd_ed25519_fe_sq ( u2, r     );
    fd_ed25519_fe_mul( u2, u2, v );
    /* u2 = (sqrt(u/v))^2 * v = u/v * v = u */
    uchar uc[ 32 ];                 uchar u2c[ 32 ];
    fd_ed25519_fe_tobytes( uc, u ); fd_ed25519_fe_tobytes( u2c, u2 );
    FD_TEST( 0==memcmp( uc, u2c, 32 ) );
  }
}

static void
test_fe_inv_sqrt( fd_rng_t * rng ) {
  fd_ed25519_fe_t _f[1]; fd_ed25519_fe_t * f = _f;
  fd_ed25519_fe_t _h[1]; fd_ed25519_fe_t * h = _h;

  fd_ed25519_fe_rng( f, rng );
  ulong iter = 100000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_ed25519_fe_inv_sqrt( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_fe_inv_sqrt", iter, dt );
}

/**********************************************************************/

/* FIXME: ADD GE TESTS HERE */

/**********************************************************************/

static void
test_sc_reduce( fd_rng_t * rng ) {
  uchar _in [64]; uchar * in  = _in;
  uchar _out[64]; uchar * out = _out;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    uchar ref_in[64]; uchar ref_out[64]; x25519_sc_reduce( fd_memcpy( ref_out, fd_rng_b512( rng, ref_in ), 64UL ) );
    fd_memcpy( in, ref_in, 64UL );
    FD_TEST( fd_ed25519_sc_reduce( out, in )==out );
    FD_TEST( !memcmp( in,  ref_in,  64UL ) );
    FD_TEST( !memcmp( out, ref_out, 32UL ) ); /* yes 32 */

    FD_TEST( fd_ed25519_sc_reduce( in, in )==in );
    FD_TEST( !memcmp( in, ref_out, 64UL ) );
  }
# endif

  fd_rng_b512( rng, in );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( in ); FD_COMPILER_FORGET( out ); fd_ed25519_sc_reduce( out, in ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_sc_reduce", iter, dt );
}

static void
test_sc_muladd( fd_rng_t * rng ) {
  uchar _a[32]; uchar * a = _a;
  uchar _b[32]; uchar * b = _b;
  uchar _c[32]; uchar * c = _c;
  uchar _s[32]; uchar * s = _s;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    uchar ref_a[32]; uchar ref_b[32]; uchar ref_c[32]; uchar ref_s[32];
    sc_muladd( ref_s, fd_rng_b256( rng, ref_a ), fd_rng_b256( rng, ref_b ), fd_rng_b256( rng, ref_c ) );
    fd_memcpy( a, ref_a, 32UL );
    fd_memcpy( b, ref_b, 32UL );
    fd_memcpy( c, ref_c, 32UL );
    FD_TEST( fd_ed25519_sc_muladd( s, a, b, c )==s );
    FD_TEST( !memcmp( a, ref_a, 32UL ) );
    FD_TEST( !memcmp( b, ref_b, 32UL ) );
    FD_TEST( !memcmp( c, ref_c, 32UL ) );
    FD_TEST( !memcmp( s, ref_s, 32UL ) );

    FD_TEST( fd_ed25519_sc_muladd( a, a, b, c )==a );
    FD_TEST( !memcmp( b, ref_b, 32UL ) );
    FD_TEST( !memcmp( c, ref_c, 32UL ) );
    FD_TEST( !memcmp( a, ref_s, 32UL ) );
    fd_memcpy( a, ref_a, 32UL );

    FD_TEST( fd_ed25519_sc_muladd( b, a, b, c )==b );
    FD_TEST( !memcmp( a, ref_a, 32UL ) );
    FD_TEST( !memcmp( c, ref_c, 32UL ) );
    FD_TEST( !memcmp( b, ref_s, 32UL ) );
    fd_memcpy( b, ref_b, 32UL );

    FD_TEST( fd_ed25519_sc_muladd( c, a, b, c )==c );
    FD_TEST( !memcmp( a, ref_a, 32UL ) );
    FD_TEST( !memcmp( b, ref_b, 32UL ) );
    FD_TEST( !memcmp( c, ref_s, 32UL ) );
  //fd_memcpy( c, ref_c, 32UL );
  }
# endif

  fd_rng_b256( rng, a );
  fd_rng_b256( rng, b );
  fd_rng_b256( rng, c );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( a ); FD_COMPILER_FORGET( b ); FD_COMPILER_FORGET( c );
    fd_ed25519_sc_muladd( s, a, b, c );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_sc_muladd", iter, dt );
}

static void
test_public_from_private( fd_rng_t *    rng,
                          fd_sha512_t * sha ) {
  uchar _prv[32]; uchar * prv = _prv;
  uchar _pub[32]; uchar * pub = _pub;
# if OPENSSL_COMPARE
  for( ulong rem=10000UL; rem; rem-- ) {
    uchar ref_prv[32]; uchar ref_pub[32]; ED25519_public_from_private( ref_pub, fd_rng_b256( rng, ref_prv ) );
    fd_memcpy( prv, ref_prv, 32UL );
    FD_TEST( fd_ed25519_public_from_private( pub, prv, sha )==pub );
    FD_TEST( !memcmp( prv, ref_prv, 32UL ) );
    FD_TEST( !memcmp( pub, ref_pub, 32UL ) );
  }
# endif

  fd_rng_b256( rng, prv );
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( prv ); FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sha );
    fd_ed25519_public_from_private( pub, prv, sha );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_public_from_private", iter, dt );
}

static void
test_sign( fd_rng_t *    rng,
           fd_sha512_t * sha ) {
  uchar _msg[ 1024 ]; uchar * msg = _msg;
  uchar _pub[   32 ]; uchar * pub = _pub;
  uchar _prv[   32 ]; uchar * prv = _prv;
  uchar _sig[   64 ]; uchar * sig = _sig;
# if OPENSSL_COMPARE
  for( ulong rem=10000UL; rem; rem-- ) {
    uchar ref_msg[ 1024 ]; uchar ref_pub[32]; uchar ref_prv[32]; uchar ref_sig[64];
    ulong sz = (ulong)fd_rng_uint_roll( rng, 1025U );
    for( ulong b=0; b<sz; b++ ) ref_msg[b] = fd_rng_uchar( rng );
    ED25519_public_from_private( ref_pub, fd_rng_b256( rng, ref_prv ) );
    ED25519_sign( ref_sig, ref_msg, sz, ref_pub, ref_prv );
    fd_memcpy( msg, ref_msg, sz   );
    fd_memcpy( pub, ref_pub, 32UL );
    fd_memcpy( prv, ref_prv, 32UL );
    FD_TEST( fd_ed25519_sign( sig, msg, sz, pub, prv, sha )==sig );
    FD_TEST( !memcmp( msg, ref_msg, sz   ) );
    FD_TEST( !memcmp( pub, ref_pub, 32UL ) );
    FD_TEST( !memcmp( prv, ref_prv, 32UL ) );
    FD_TEST( !memcmp( sig, ref_sig, 32UL ) );
  }
# endif

  for( ulong b=0; b<1024UL; b++ ) msg[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( pub, fd_rng_b256( rng, prv ), sha );
  ulong iter = 10000UL;

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

static void
test_verify( fd_rng_t *    rng,
             fd_sha512_t * sha ) {
  uchar _msg[ 1024 ]; uchar * msg = _msg;
  uchar _pub[   32 ]; uchar * pub = _pub;
  uchar _sig[   64 ]; uchar * sig = _sig;
  uchar _prv[   32 ]; uchar * prv = _prv;
# if OPENSSL_COMPARE
  for( ulong rem=10000UL; rem; rem-- ) {
    uchar ref_msg[ 1024 ]; uchar ref_pub[ 32 ]; uchar ref_sig[ 64 ]; uchar ref_prv[ 32 ];
    ulong sz = (ulong)fd_rng_uint_roll( rng, 1025U );
    for( ulong b=0; b<sz; b++ ) ref_msg[b] = fd_rng_uchar( rng );
    ED25519_public_from_private( ref_pub, fd_rng_b256( rng, ref_prv ) );
    ED25519_sign( ref_sig, ref_msg, sz, ref_pub, ref_prv );

    uint r = fd_rng_uint( rng );
    int corrupt_sig = !(r & 31U); r >>= 5;
    int corrupt_msg = !(r & 31U); r >>= 5;
    int corrupt_sz  = !(r & 31U); r >>= 5;
    int corrupt_pub = !(r & 31U); r >>= 5;

    if( corrupt_sig ) {
      ulong idx  = (ulong)fd_rng_uint_roll( rng, 512UL );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      ref_sig[ byte ] = (uchar)(((ulong)ref_sig[ byte ]) ^ (1UL<<bit));
    }

    if( corrupt_msg && sz ) {
      ulong idx = (ulong)fd_rng_uint_roll( rng, 8U*(uint)sz );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      ref_msg[ byte ] = (uchar)(((ulong)ref_msg[ byte ]) ^ (1UL<<bit));
    }

    if( corrupt_sz ) {
      ulong old_sz = sz;
      sz = (ulong)fd_rng_uint_roll( rng, 1025U );
      for( ulong b=old_sz; b<sz; b++ ) ref_msg[b] = fd_rng_uchar( rng );
    }

    if( corrupt_pub ) {
      ulong idx  = (ulong)fd_rng_uint_roll( rng, 256UL );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      ref_pub[ byte ] = (uchar)(((ulong)ref_pub[ byte ]) ^ (1UL<<bit));
    }

    int ref_good = ED25519_verify( ref_msg, sz, ref_sig, ref_pub );

    fd_memcpy( msg, ref_msg, sz   );
    fd_memcpy( sig, ref_sig, 64UL );
    fd_memcpy( pub, ref_pub, 32UL );
    int err = fd_ed25519_verify( msg, sz, sig, pub, sha );
    FD_TEST( !memcmp( msg, ref_msg, sz   ) );
    FD_TEST( !memcmp( sig, ref_sig, 64UL ) );
    FD_TEST( !memcmp( pub, ref_pub, 32UL ) );
    FD_TEST( ref_good ? !err : !!err );
  }
# endif

  for( ulong b=0; b<1024UL; b++ ) msg[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( pub, fd_rng_b256( rng, prv ), sha );
  ulong iter = 10000UL;

  for( ulong sz=128UL; sz<=1024UL; sz+=128UL ) {
    fd_ed25519_sign( sig, msg, sz, pub, prv, sha );
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg ); FD_COMPILER_FORGET( sz  );
      FD_COMPILER_FORGET( pub ); FD_COMPILER_FORGET( sha );
      fd_ed25519_verify( msg, sz, sig, pub, sha );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_ed25519_verify(good %lu)", sz ), iter, dt );
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

static void
test_validate_public_key( fd_rng_t * rng ) {
  /* Randomly generated bytes */

  static struct { char key[32]; int valid; } const test_vector[32] = {
    { "\xbe\x21\x94\x3b\xa4\x5e\x17\x46\xe1\x18\xf9\xc3\x18\x05\xaa\x85\x83\x42\x3a\xc0\xcd\xe8\xce\x76\x16\xb5\xa3\x63\x20\xa5\xe9\x36", 1 },
    { "\x4b\xc4\x04\xb9\x5c\x55\x4b\x5a\x2c\xe8\x4e\x04\x5f\x22\x34\x37\x59\x85\x45\x99\x2c\x14\x96\x9d\x2e\xb6\xae\xbd\x71\xa9\xb7\xf0", 0 },
    { "\xbd\xf3\x7e\x36\xd8\x75\x6c\xcb\x8a\xbb\xa1\x0d\x3e\x5a\xa5\x4e\x97\xc5\xb7\x66\x41\xbe\x7b\xcf\x94\x66\xe4\x36\x97\x7e\xee\x55", 0 },
    { "\x5c\xca\x42\x2b\x70\x06\x2f\xd2\xe0\x5c\x6d\xa6\x8b\xbc\x03\xd0\x51\x10\x1f\x4a\xbe\xcf\x74\xfa\x33\xb6\xc5\xba\xdd\xc7\x47\x5d", 0 },
    { "\x48\xd9\xd7\x73\xe5\x2a\x0b\x97\x80\xed\x85\xa1\x16\x37\x7f\x8c\x80\x42\x3e\x7b\x3e\xcc\x39\x9d\x98\x3d\x11\x07\xca\x60\x42\xbb", 0 },
    { "\xe6\xdd\x3e\xa7\xca\x7a\x90\xc0\x32\x1e\x1e\x9b\x67\x39\x43\x67\x52\x49\x85\x8b\xea\x54\x2f\x6d\x12\x5c\x53\x8d\x79\x20\xa1\xdb", 1 },
    { "\x6d\xc5\xeb\x09\x8c\xe6\xf5\x97\xa6\xba\xec\xc2\xd0\xfe\x6a\x97\x9d\xb4\xaa\xdf\xca\x5a\x52\x2d\xe4\x0e\xb0\x79\xd2\x4d\xff\x25", 1 },
    { "\x94\x43\xb4\x88\x20\xe2\x8c\xeb\x53\xba\x77\x2a\x0b\x80\x8e\x2c\x32\xb2\xef\x0d\x47\x91\x10\x6d\x66\xc3\xc8\x2b\x5d\xc8\x71\x6f", 0 },
    { "\x1e\x84\xbc\xa4\x6f\xb5\x7b\xc3\x09\x65\xae\xf6\x69\x26\xd9\x55\x86\xa5\xbf\x64\x3a\xdb\x24\xc9\xe7\x9b\x00\xe8\x88\x20\xcf\x57", 0 },
    { "\x40\x20\x7d\x9d\x1e\x47\xa9\x8b\x65\x8c\x55\x09\xbb\x3b\x22\x63\x0f\xdd\x67\xf6\x1c\xe1\x25\xaf\xf2\x49\x85\x9a\x18\xc3\xa1\x25", 0 },
    { "\x8e\x7e\xef\x7f\xac\x4c\x1e\xdd\xaf\x32\x7b\x3d\x4b\x58\xee\x5b\xe6\x36\xdf\x99\x81\x42\xa8\x33\x3f\xd4\xdb\x47\x34\x90\x2a\x37", 1 },
    { "\x38\x7a\x48\x9f\xa4\x9e\xce\x87\x5e\x36\x09\xdb\x83\x1f\x1e\xae\x0f\x5c\x18\x64\x50\x29\xd8\x20\xa3\x6b\xed\xd4\xb2\x54\xe8\xa6", 1 },
    { "\xde\x68\x39\xad\x14\xd2\xea\x57\x86\x53\x23\xbe\x7f\xd8\xb3\x80\x50\xf0\x7c\xa5\x4d\xf3\xbd\xb4\x09\xff\x00\xb9\xe9\x9b\x29\x65", 1 },
    { "\x3d\x3e\x2f\x26\x11\xe8\xf3\x1d\x73\xb3\x0a\x43\x75\x21\x0a\x91\x47\x97\x74\x9a\x66\x55\x57\xb4\xb5\xe6\x95\xbd\xa6\x4a\xcb\xef", 0 },
    { "\x7e\x41\x79\x5a\xbc\xe7\x70\x5c\xb6\xd4\x4c\xed\xbe\x62\x03\xcd\x68\x72\x08\xda\x6c\x15\x53\xf7\xc3\x8f\x92\x33\x9f\x5c\x36\x88", 0 },
    { "\x84\xfc\x02\x5b\x90\xb2\x16\xee\x1e\x23\x05\x14\xca\xf5\x5a\x79\xfd\xd9\x5d\xf5\x46\x30\x52\x4e\xd2\x42\x53\x79\x45\xc1\xce\xdb", 0 },
    { "\x75\xd9\xab\x3d\xc9\xad\x6e\xf2\xf9\x06\xf0\xea\xd3\x19\xec\x0e\x8e\x93\x08\xd1\x94\x09\x57\xec\xc0\xe0\x6b\x29\xb4\x95\x5b\xad", 0 },
    { "\x13\x84\x09\xd4\x47\x0a\x77\x12\x23\x1d\x97\x9d\xdc\x88\x6a\xb9\x73\xb4\x86\x8e\x1b\x16\x7d\x42\x44\x3e\x81\xdf\xf3\xf1\x89\x2c", 0 },
    { "\xb8\x80\x0a\x67\x01\xd5\x0f\xbb\x00\x7e\x04\x0a\x1e\x8a\xf8\x83\xd3\xee\x5e\xce\x91\xe6\x03\x0f\xfc\xa1\x73\x9a\x7a\x18\x4e\x1a", 1 },
    { "\xc4\x77\x76\x4c\x65\xec\x92\x01\xc3\x37\xad\x0c\x0e\x3f\xfd\x85\x12\xa4\xbe\x3d\xaa\x80\x91\x38\x00\xea\x2f\x51\xd1\x89\xab\x00", 0 },
    { "\x3a\xc1\x78\x2c\x6b\xf6\x1d\x3a\x32\xd8\x06\x22\x92\xd0\x31\x3f\xe6\xf4\xe4\xb8\xd1\x42\xde\xa4\xe0\xeb\xdf\x3c\x20\xd9\x13\x70", 0 },
    { "\x7c\x33\xc4\x0d\xfe\xc3\x05\x15\xfa\xaa\xa1\xfe\xe2\xeb\x8e\x05\xa0\xe6\x25\xd5\x03\xa8\x86\x57\x5b\x5a\xa3\xff\xcb\x26\x98\x51", 0 },
    { "\x75\x8c\x43\xbc\x2d\x20\x8a\x4d\x6d\xf0\xf1\x3b\xa4\xed\x7a\x36\x0f\x54\x9f\xc7\x9b\x77\xde\x70\x8d\xe7\xa2\x21\x74\x2a\x35\x96", 1 },
    { "\x64\x34\xdf\x69\xe4\xc2\xf5\xc1\xf9\x52\x1e\xf6\x0a\x6e\x5b\x8d\xd0\x5b\x9b\x4f\x2d\x3c\x7f\x55\xf2\x35\xc8\x1d\x6c\xdc\xae\x6e", 0 },
    { "\x05\xaa\x59\xa7\x1a\x36\x51\x06\x1d\xe9\xdb\x59\x92\x33\x61\x20\xb0\x25\x2d\xcd\xfa\x71\x8f\x16\x2a\xdf\x0d\xb2\xf6\xe2\x15\x58", 0 },
    { "\x55\xb7\x1e\x57\x81\xa4\x2a\x5d\x43\x7d\xb8\xb7\x6e\x9e\x0e\xa8\x60\xfa\x86\x28\x8e\x90\xb8\x03\x10\x7f\x93\xb8\x7d\xbc\x0d\x80", 1 },
    { "\x7a\x84\x33\x2a\x9a\xa1\x28\x52\x76\x3b\x9e\xbf\x85\xf7\xe8\x10\xcc\x98\x40\x4c\x2e\x3a\x91\x27\x60\x55\xaf\x13\x74\x3e\x27\xee", 0 },
    { "\x3b\x6d\x5d\xf7\xaf\x46\xb4\xff\x29\x57\x72\x09\x6f\x3e\xae\xab\x14\xb8\xc5\xdc\xea\x19\x46\x7b\xdc\x70\xbc\xf5\x7b\x17\x77\x58", 1 },
    { "\x80\xfa\xfb\xe6\x1b\xba\x92\xa0\xa4\x79\x37\xea\xe1\xdd\xfd\x52\x2f\xb1\x6b\x40\xa7\x02\x0d\xa0\x28\x31\x24\x64\x5a\x59\x0b\x7c", 1 },
    { "\x4d\xd7\xb9\xaf\x2b\xe4\x79\x5b\x9d\x7c\x7a\x09\x74\xe6\x85\xe5\x27\xb6\xc0\xac\x60\x52\x79\x56\x5e\x84\xce\x09\xea\x2c\x5f\x08", 0 },
    { "\xe3\x6b\xb2\xcc\xc1\x51\x10\xe0\x13\x5a\x4c\x48\xef\xa9\xa1\xe6\x79\x77\x0b\x28\x76\x10\x2a\x40\xbf\xdc\x4c\xcf\x1c\x96\xcb\x01", 1 },
    { "\xb9\x45\xb8\xea\x32\xde\xda\x8e\xfe\x30\x6e\xf1\xd8\x54\xb0\x42\x55\xb9\xba\x93\x16\xa7\x30\x2d\x5b\x67\x90\x93\x0d\x18\xc8\xc2", 0 },
  };

  for( ulong i=0UL; i<32UL; i++ ) {
    int valid = !!fd_ed25519_validate_public_key( test_vector[i].key );
    FD_TEST( valid==test_vector[i].valid );
  }

  /* Benchmark */

  uchar _s[32]; uchar * s = _s;
  fd_rng_b256( rng, s );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( s );
    int h = !!fd_ed25519_validate_public_key( s );
    FD_COMPILER_UNPREDICTABLE( h );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ed25519_validate_public_key", iter, dt );
}

/**********************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  test_fe_frombytes ( rng );
  test_fe_tobytes   ( rng );
  test_fe_copy      ( rng );
  test_fe_0         ( rng );
  test_fe_1         ( rng );
  test_fe_add       ( rng );
  test_fe_sub       ( rng );
  test_fe_mul       ( rng );
  test_fe_sq        ( rng );
  test_fe_invert    ( rng );
  test_fe_neg       ( rng );
  test_fe_if        ( rng );
  test_fe_isnonzero ( rng );
  test_fe_isnegative( rng );
  test_fe_sq2       ( rng );
  test_fe_pow22523  ( rng );
  test_fe_sqrt_ratio( rng );
  test_fe_inv_sqrt  ( rng );

  test_sc_reduce    ( rng );
  test_sc_muladd    ( rng );

  test_public_from_private( rng, sha );
  test_sign               ( rng, sha );
  test_verify             ( rng, sha );
  test_validate_public_key( rng );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
