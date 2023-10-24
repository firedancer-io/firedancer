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
  
  test_sc_reduce    ( rng );
  test_sc_muladd    ( rng );

  test_public_from_private( rng, sha );
  test_sign               ( rng, sha );
  test_verify             ( rng, sha );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
