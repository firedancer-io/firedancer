#include "../fd_ballet.h"
#include "fd_secp256k1.h"

static uchar *
fd_rng_b256( fd_rng_t * rng,
             uchar *    r ) {
  ulong * u = (ulong *)r;
  u[0] = fd_rng_ulong( rng ); u[1] = fd_rng_ulong( rng ); u[2] = fd_rng_ulong( rng ); u[3] = fd_rng_ulong( rng );
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


static void
test_public_from_private( fd_rng_t * rng ) {
  uchar _prv[32]; uchar * prv = _prv;
  uchar _pub[64]; uchar * pub = _pub;
  
  fd_rng_b256( rng, prv );
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( prv ); FD_COMPILER_FORGET( pub );
    FD_TEST( fd_secp256k1_public_from_private( pub, prv ) != NULL );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_secp256k1_public_from_private", iter, dt );
}

static void
test_sign( fd_rng_t * rng ) {
  uchar _msg_hash[ 32 ]; uchar * msg_hash = _msg_hash;
  uchar _pub[ 64 ]; uchar * pub = _pub;
  uchar _prv[ 32 ]; uchar * prv = _prv;
  uchar _sig[ 64 ]; uchar * sig = _sig;
  
  for( ulong b=0; b<32UL; b++ ) msg_hash[b] = fd_rng_uchar( rng );
  fd_secp256k1_public_from_private( pub, fd_rng_b256( rng, prv ) );
  ulong iter = 10000UL;

  ulong sz = 32;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg_hash ); FD_COMPILER_FORGET( prv ); 
    FD_COMPILER_FORGET( pub );
    fd_secp256k1_sign( sig, msg_hash, prv );
  }
  dt = fd_log_wallclock() - dt;

  char cstr[128];
  log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_secp256k1_sign(%lu)", sz ), iter, dt );
}

static void
test_verify( fd_rng_t * rng ) {
  uchar _msg_hash[ 32 ]; uchar * msg_hash = _msg_hash;
  uchar _pub[ 64 ]; uchar * pub = _pub;
  uchar _sig[ 64 ]; uchar * sig = _sig;
  uchar _prv[ 32 ]; uchar * prv = _prv;
  
  for( ulong b=0; b<32UL; b++ ) msg_hash[b] = fd_rng_uchar( rng );
  FD_TEST( fd_secp256k1_public_from_private( pub, fd_rng_b256( rng, prv ) )!=NULL );
  ulong iter = 10000UL;
  
  ulong sz = 32;
  {
    fd_secp256k1_sign( sig, msg_hash, prv );
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg_hash ); FD_COMPILER_FORGET( pub );
      fd_secp256k1_verify( msg_hash, sig, pub );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_secp256k1_verify(good %lu)", sz ), iter, dt );
  }

  {
    fd_secp256k1_sign( sig, msg_hash, prv );
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg_hash ); FD_COMPILER_FORGET( pub );
      ulong idx  = (ulong)fd_rng_uint_roll( rng, 512UL );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      sig[ byte ] = (uchar)(((ulong)sig[ byte ]) ^ (1UL<<bit));
      fd_secp256k1_verify( msg_hash, sig, pub );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_secp256k1_verify(bad sig %lu)", sz ), iter, dt );
  }

  {
    fd_secp256k1_sign( sig, msg_hash, prv );
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg_hash ); FD_COMPILER_FORGET( pub );
      ulong idx  = (ulong)fd_rng_uint_roll( rng, 8U*(uint)sz );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      msg_hash[ byte ] = (uchar)(((ulong)msg_hash[ byte ]) ^ (1UL<<bit));

      fd_secp256k1_verify( msg_hash, sig, pub );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_secp256k1_verify(bad msg %lu)", sz ), iter, dt );
  }

  {
    fd_secp256k1_sign( sig, msg_hash, prv );
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( sig ); FD_COMPILER_FORGET( msg_hash ); FD_COMPILER_FORGET( pub );
      ulong idx  = (ulong)fd_rng_uint_roll( rng, 256UL );
      ulong byte = idx>>3;
      ulong bit  = idx & 7UL;
      pub[ byte ] = (uchar)(((ulong)pub[ byte ]) ^ (1UL<<bit));

      fd_secp256k1_verify( msg_hash, sig, pub );
    }
    dt = fd_log_wallclock() - dt;
    char cstr[128];
    log_bench( fd_cstr_printf( cstr, 128UL, NULL, "fd_secp256k1_verify(bad pub %lu)", sz ), iter, dt );
  }
}

/**********************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_public_from_private( rng );
  test_sign               ( rng );
  test_verify             ( rng );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
