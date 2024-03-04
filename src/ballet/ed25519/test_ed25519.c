#include "../fd_ballet.h"
#include "fd_ed25519.h"
#include "fd_curve25519.h"
#include "../hex/fd_hex.h"
#include "test_ed25519_wycheproof.c"

static uchar *
fd_rng_b256( fd_rng_t * rng,
             uchar      r[ static 32 ] ) {
  ulong * u = (ulong *)r;
  u[0] = fd_rng_ulong( rng ); u[1] = fd_rng_ulong( rng ); u[2] = fd_rng_ulong( rng ); u[3] = fd_rng_ulong( rng );
  return r;
}

static uchar *
fd_rng_b512( fd_rng_t * rng,
             uchar      r[ static 64 ] ) {
  ulong * u = (ulong *)r;
  u[0] = fd_rng_ulong( rng ); u[1] = fd_rng_ulong( rng ); u[2] = fd_rng_ulong( rng ); u[3] = fd_rng_ulong( rng );
  u[4] = fd_rng_ulong( rng ); u[5] = fd_rng_ulong( rng ); u[6] = fd_rng_ulong( rng ); u[7] = fd_rng_ulong( rng );
  return r;
}

void
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

void
test_fe_frombytes( fd_rng_t * rng ) {
  uchar           _s[32]; uchar *           s = _s;
  fd_f25519_t _h[1];  fd_f25519_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    uchar ref_s[32]; fe ref_h; fe_frombytes( ref_h, fd_rng_b256( rng, ref_s ) );
    fd_memcpy( s, ref_s, 32UL );
    FD_TEST( fd_f25519_frombytes( h, s )==h );
    FD_TEST( !memcmp( s, ref_s, 32UL ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );
  }
# endif

  fd_rng_b256( rng, s );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( s ); FD_COMPILER_FORGET( h ); fd_f25519_frombytes( h, s ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_frombytes", iter, dt );
}

void
test_fe_tobytes( fd_rng_t * rng ) {
  fd_f25519_t _h[1];  fd_f25519_t * h = _h;
  uchar           _s[32]; uchar *           s = _s;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_h; uchar ref_s[32]; fe_tobytes( ref_s, fe_rng( ref_h, rng ) );
    fd_memcpy( h, ref_h, sizeof(fe) );
    FD_TEST( fd_f25519_tobytes( s, h )==s );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );
    FD_TEST( !memcmp( s, ref_s, 32UL ) );
  }
# endif

  fd_f25519_rng_unsafe( h, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( h ); FD_COMPILER_FORGET( h ); fd_f25519_tobytes( s, h ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_tobytes", iter, dt );
}

void
test_fe_copy( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_copy( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_f25519_set( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_set( f, f )==f );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = 1000000UL;
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
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_g; fe ref_h; fe_add( ref_h, fe_rng( ref_f, rng ), fe_rng( ref_g, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    fd_memcpy( g, ref_g, sizeof(fe) );
    FD_TEST( fd_f25519_add( h, f, g )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_add( f, f, g )==f );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
    fd_memcpy( f, ref_f, sizeof(fe) );

    FD_TEST( fd_f25519_add( g, f, g )==g );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_h, sizeof(fe) ) );
  //fd_memcpy( g, ref_g, sizeof(fe) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  fd_f25519_rng_unsafe( g, rng );
  ulong iter = 1000000UL;
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
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_g; fe ref_h; fe_sub( ref_h, fe_rng( ref_f, rng ), fe_rng( ref_g, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    fd_memcpy( g, ref_g, sizeof(fe) );
    FD_TEST( fd_f25519_sub( h, f, g )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_sub( f, f, g )==f );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
    fd_memcpy( f, ref_f, sizeof(fe) );

    FD_TEST( fd_f25519_sub( g, f, g )==g );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_h, sizeof(fe) ) );
  //fd_memcpy( g, ref_g, sizeof(fe) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  fd_f25519_rng_unsafe( g, rng );
  ulong iter = 1000000UL;
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
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_g; fe ref_h; fe_mul( ref_h, fe_rng( ref_f, rng ), fe_rng( ref_g, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    fd_memcpy( g, ref_g, sizeof(fe) );
    fd_f25519_t z[1]; fd_f25519_0( z );
    FD_TEST( fd_f25519_mul( h, f, g )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_mul( f, f, g )==f );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
    fd_memcpy( f, ref_f, sizeof(fe) );

    FD_TEST( fd_f25519_mul( g, f, g )==g );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  fd_f25519_rng_unsafe( g, rng );
  ulong iter = 1000000UL;
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
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_sq( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_f25519_sqr( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_sqr( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_sqr( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_sqr", iter, dt );
}

void
test_fe_invert( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=10000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_invert( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_f25519_inv( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_inv( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_inv( h, f ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_f25519_inv", iter, dt );
}

void
test_fe_neg( fd_rng_t * rng ) {
  fd_f25519_t _f[1]; fd_f25519_t * f = _f;
  fd_f25519_t _h[1]; fd_f25519_t * h = _h;
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_neg( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_f25519_neg( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_neg( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = 100000UL;
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
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; fe ref_g; fe ref_h;
    c = (int)(fd_rng_uint( rng ) & 1U);
    fe_rng( ref_f, rng );
    fe_rng( ref_g, rng );
    fd_memcpy( ref_h, ref_g, sizeof(fe) ); fe_cmov( ref_h, ref_f, (uint)c );
    fd_memcpy( f, ref_f, sizeof(fe) );
    fd_memcpy( g, ref_g, sizeof(fe) );
    FD_TEST( fd_f25519_if( h, c, f, g )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_if( f, c, f, g )==f );
    FD_TEST( !memcmp( g, ref_g, sizeof(fe) ) );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
    fd_memcpy( f, ref_f, sizeof(fe) );

    FD_TEST( fd_f25519_if( g, c, f, g )==g );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( g, ref_h, sizeof(fe) ) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  fd_f25519_rng_unsafe( g, rng );
  FD_TEST( !fd_memeq( f, g, 32 ) );

  FD_TEST( fd_memeq( fd_f25519_if( h, 1, f, g ), f, 32 ) );
  FD_TEST( fd_memeq( fd_f25519_if( h, 0, f, g ), g, 32 ) );

  ulong iter = 100000UL;
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
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; c = fe_isnonzero( fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_f25519_is_nonzero( f )==c );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = 100000UL;
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
# if OPENSSL_COMPARE
  for( ulong rem=100000UL; rem; rem-- ) {
    fe ref_f; fe ref_h; fe_pow22523( ref_h, fe_rng( ref_f, rng ) );
    fd_memcpy( f, ref_f, sizeof(fe) );
    FD_TEST( fd_f25519_pow22523( h, f )==h );
    FD_TEST( !memcmp( f, ref_f, sizeof(fe) ) );
    FD_TEST( !memcmp( h, ref_h, sizeof(fe) ) );

    FD_TEST( fd_f25519_pow22523( f, f )==f );
    FD_TEST( !memcmp( f, ref_h, sizeof(fe) ) );
  //fd_memcpy( f, ref_f, sizeof(fe) );
  }
# endif

  fd_f25519_rng_unsafe( f, rng );
  ulong iter = 100000UL;

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_pow22523( h, f ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_f25519_pow22523", iter, dt );
  }

  /* during refactor, fd_f25519_pow22523_2 & fd_f25519_pow22523_4
     were not implemented. leaving the tests in case we add them. */
#if 0
  fd_f25519_t _fb[1]; fd_f25519_t * fb = _fb;
  fd_f25519_t _hb[1]; fd_f25519_t * hb = _hb;
  fd_f25519_t _fc[1]; fd_f25519_t * fc = _fc;
  fd_f25519_t _hc[1]; fd_f25519_t * hc = _hc;
  fd_f25519_t _fd[1]; fd_f25519_t * fd = _fd;
  fd_f25519_t _hd[1]; fd_f25519_t * hd = _hd;
  fd_f25519_t _ref_h[1]; fd_f25519_t * ref_h = _ref_h;
  memset(ref_h, 0, sizeof(fd_f25519_t));
  memset(h, 0, sizeof(fd_f25519_t));
  memset(hb, 0, sizeof(fd_f25519_t));
  memset(hc, 0, sizeof(fd_f25519_t));
  memset(hd, 0, sizeof(fd_f25519_t));
  fd_f25519_rng_unsafe( fb, rng );
  fd_f25519_rng_unsafe( fc, rng );
  fd_f25519_rng_unsafe( fd, rng );

  fd_f25519_pow22523( ref_h, f );
  fd_f25519_pow22523_2( h,f, hb,f );
  FD_TEST( !memcmp( h,  ref_h, sizeof(fd_f25519_t) ) );
  FD_TEST( !memcmp( hb, ref_h, sizeof(fd_f25519_t) ) );

  fd_f25519_pow22523_4( h,f, hb,f, hc,f, hd,f );
  FD_TEST( !memcmp( h,  ref_h, sizeof(fd_f25519_t) ) );
  FD_TEST( !memcmp( hb, ref_h, sizeof(fd_f25519_t) ) );
  FD_TEST( !memcmp( hc, ref_h, sizeof(fd_f25519_t) ) );
  FD_TEST( !memcmp( hd, ref_h, sizeof(fd_f25519_t) ) );

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_pow22523_2( h,f, hb,fb ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_f25519_pow22523_2", iter, dt );
  }

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( h ); fd_f25519_pow22523_4( h,f, hb,fb, hc,fc, hd,fd ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_f25519_pow22523_4", iter, dt );
  }
#endif
}

/* FIXME: ADD VMUL, VSQ, VSQN TESTS HERE */

/**********************************************************************/

/* FIXME: ADD GE TESTS HERE */

/**********************************************************************/

void
test_sc_validate( FD_PARAM_UNUSED fd_rng_t * rng ) {
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

  ulong iter = 1000000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( out ); fd_curve25519_scalar_validate( out ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_curve25519_scalar_validate", iter, dt );
}

void
test_sc_reduce( fd_rng_t * rng ) {
  uchar _in [64]; uchar * in  = _in;
  uchar _out[64]; uchar * out = _out;
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    uchar ref_in[64]; uchar ref_out[64]; x25519_sc_reduce( fd_memcpy( ref_out, fd_rng_b512( rng, ref_in ), 64UL ) );
    fd_memcpy( in, ref_in, 64UL );
    FD_TEST( fd_curve25519_scalar_reduce( out, in )==out );
    FD_TEST( !memcmp( in,  ref_in,  64UL ) );
    FD_TEST( !memcmp( out, ref_out, 32UL ) ); /* yes 32 */

    FD_TEST( fd_curve25519_scalar_reduce( in, in )==in );
    FD_TEST( !memcmp( in, ref_out, 64UL ) );
  }
# endif

  fd_rng_b512( rng, in );
  ulong iter = 1000000UL;
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
# if OPENSSL_COMPARE
  for( ulong rem=1000000UL; rem; rem-- ) {
    uchar ref_a[32]; uchar ref_b[32]; uchar ref_c[32]; uchar ref_s[32];
    sc_muladd( ref_s, fd_rng_b256( rng, ref_a ), fd_rng_b256( rng, ref_b ), fd_rng_b256( rng, ref_c ) );
    fd_memcpy( a, ref_a, 32UL );
    fd_memcpy( b, ref_b, 32UL );
    fd_memcpy( c, ref_c, 32UL );
    FD_TEST( fd_curve25519_scalar_muladd( s, a, b, c )==s );
    FD_TEST( !memcmp( a, ref_a, 32UL ) );
    FD_TEST( !memcmp( b, ref_b, 32UL ) );
    FD_TEST( !memcmp( c, ref_c, 32UL ) );
    FD_TEST( !memcmp( s, ref_s, 32UL ) );

    FD_TEST( fd_curve25519_scalar_muladd( a, a, b, c )==a );
    FD_TEST( !memcmp( b, ref_b, 32UL ) );
    FD_TEST( !memcmp( c, ref_c, 32UL ) );
    FD_TEST( !memcmp( a, ref_s, 32UL ) );
    fd_memcpy( a, ref_a, 32UL );

    FD_TEST( fd_curve25519_scalar_muladd( b, a, b, c )==b );
    FD_TEST( !memcmp( a, ref_a, 32UL ) );
    FD_TEST( !memcmp( c, ref_c, 32UL ) );
    FD_TEST( !memcmp( b, ref_s, 32UL ) );
    fd_memcpy( b, ref_b, 32UL );

    FD_TEST( fd_curve25519_scalar_muladd( c, a, b, c )==c );
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
    fd_curve25519_scalar_muladd( s, a, b, c );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_curve25519_scalar_muladd", iter, dt );
}

void
test_public_from_private( fd_rng_t *    rng,
                          fd_sha512_t * sha ) {
  uchar _prv[32]; uchar * prv = _prv;
  uchar _pub[32]; uchar * pub = _pub;
  uchar _exp[32]; uchar * exp = _exp;
# if OPENSSL_COMPARE
  for( ulong rem=10000UL; rem; rem-- ) {
    uchar ref_prv[32]; uchar ref_pub[32]; ED25519_public_from_private( ref_pub, fd_rng_b256( rng, ref_prv ) );
    fd_memcpy( prv, ref_prv, 32UL );
    FD_TEST( fd_ed25519_public_from_private( pub, prv, sha )==pub );
    FD_TEST( !memcmp( prv, ref_prv, 32UL ) );
    FD_TEST( !memcmp( pub, ref_pub, 32UL ) );
  }
# endif
  fd_hex_decode( prv, "aac11373b6f936a0d22759e6a54e0a11947cd183cf34df9dec10e234b5d133eb", 32 );
  fd_hex_decode( exp, "1ddd2c92234f97eda0c91d0191491392a70fbe42fedc0df99d871583d9ad351f", 32 );
  fd_ed25519_public_from_private( pub, prv, sha );
  // FD_TEST( fd_memeq( pub, exp, 32UL ) );

  fd_rng_b256( rng, prv );
  fd_ed25519_public_from_private( pub, prv, sha );
  // FD_LOG_HEXDUMP_WARNING(( "prv", prv, 32 ));
  // FD_LOG_HEXDUMP_WARNING(( "pub", pub, 32 ));

  ulong iter = 10000UL;
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

  fd_hex_decode( prv, "57835dc6a20e4efd70e90882dbd832b577dbc469960284e0ee718fb526d2ec84", 32 );
  fd_hex_decode( exp, "d65759870ce42b34fd955871f0371ce1c9a976edbe98417b84541bb4c68b65a0673799895c61d530624ffbf92c047d47d4eb4cd1bac2ecee1365faebb53a6303", 64 );
  fd_ed25519_public_from_private( pub, prv, sha );
  fd_ed25519_sign( sig, (uchar *)"", 0, pub, prv, sha );
  FD_TEST( fd_memeq( sig, exp, 64UL ) );

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

void
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

    FD_TEST( fd_ed25519_verify( msg, sz, sig, pub, sha )==FD_ED25519_SUCCESS );

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
      log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_..._verify_batch(%lu / %lu)", sz, batch ), iter/batch, dt );

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

static void
test_wycheproofs( fd_sha512_t * sha ) {

  for( fd_ed25519_verify_wycheproof_t const * proof = ed25519_verify_wycheproofs;
       proof->msg;
       proof++ ) {

    int actual = ( fd_ed25519_verify( proof->msg, proof->msg_sz, proof->sig, proof->pub, sha )
                     == FD_ED25519_SUCCESS );
    FD_TEST( actual == proof->ok );

  }
  FD_LOG_NOTICE(( "fd_ed25519_verify_wycheproof: ok" ));

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
  test_fe_add       ( rng );
  test_fe_sub       ( rng );
  test_fe_mul       ( rng );
  test_fe_sq        ( rng );
  test_fe_invert    ( rng );
  test_fe_neg       ( rng );
  test_fe_if        ( rng );
  test_fe_isnonzero ( rng );
  test_fe_pow22523  ( rng );

  test_sc_validate  ( rng );
  test_sc_reduce    ( rng );
  test_sc_muladd    ( rng );

  test_public_from_private( rng, sha );
  test_sign               ( rng, sha );
  test_verify             ( rng, sha );

  test_wycheproofs( sha );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
