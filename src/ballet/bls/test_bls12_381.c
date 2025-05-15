#include "../fd_ballet.h"
#include "fd_bls12_381.h"
#include "../hex/fd_hex.h"

void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

static void
test_add( FD_FN_UNUSED fd_rng_t * rng ) {
  // test correctness
  //
  uchar re[48] = { 0 };
  uchar r[48] = { 0 };
  uchar p[48] = { 0 };
  uchar q[48] = { 0 };

  fd_hex_decode( p, "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", 48 );
  fd_hex_decode( q, "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", 48 );
  fd_hex_decode( re, "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e", 48 );

  FD_TEST( fd_bls12_381_g1_add_syscall( r, p, q )==0 );
  FD_TEST( fd_memeq( r, re, 48 ) );
}

/**********************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_add ( rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
