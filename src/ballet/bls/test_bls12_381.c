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

static void
test_public_from_private( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar priv[32] = { 0 };
  uchar pub[96] = { 0 };
  uchar expected_pub[96] = { 0 };

  // Known test vector - private key
  fd_hex_decode( priv,
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 32 );

  // Known test vector - corresponding public key
  fd_hex_decode( expected_pub,
    "0050f8806754799da16d96b0e47f172ef4e1dda1d7ccdfa141fb162fb0618fe662c07639c84d9da2100ffb4a57430259"
    "10c20b974c6e6e80b434809f7d291257d79db7ac98205c90db07151556fe81eaf53a1f1c4ae931cfd4a5d4e526d33121", 96 );

  // Test public key generation
  FD_TEST( fd_bls12_381_public_from_private( pub, priv )==pub );
  FD_TEST( fd_memeq( pub, expected_pub, 96 ) );
}


static void
test_sign( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar priv[32] = { 0 };
  uchar msg[32] = { 0 };
  uchar sig[192] = { 0 };
  uchar expected_sig[192] = { 0 };

  // Known test vector - private key
  fd_hex_decode( priv,
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 32 );

  // Known test vector - message
  fd_hex_decode( msg,
    "0000000000000000000000000000000000000000000000000000000000000000", 32 );

  // Known test vector - expected signature
  fd_hex_decode( expected_sig,
    "0e9c8d21fcb9ee9e9e80b056dce8e6701d418581f675315594dad16ac2eb6a254f1cf705c0438c4c0c6f04a210ca54f8"
    "164a32b0f97fbd518d984f3ff58f00ab729b90741b614342849f0e3ff6cc46b60ae30549e2a416fb2f98786d03304ce1"
    "039b3f5553218edb404ec36654556ce4ad2c7fc6e214c4356d5f2f32c7a0e571bfdc060b9a4917cb2dd9bf013c85ef6b"
    "04d5d8007d2c0ae8745de432717d7f6f93417ea4b63211bd8e34cd0772813c9a197e36eff82a86bf3c688e7fd43d097e", 192 );

  // Test signature generation
  FD_TEST( fd_bls12_381_sign( sig, msg, 32, priv )==sig );
  FD_TEST( fd_memeq( sig, expected_sig, 192 ) );
}

static void
test_verify( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar pub[96] = { 0 };
  uchar msg[32] = { 0 };
  uchar sig[192] = { 0 };

  // Known test vector - public key
  fd_hex_decode( pub,
    "0050f8806754799da16d96b0e47f172ef4e1dda1d7ccdfa141fb162fb0618fe662c07639c84d9da2100ffb4a57430259"
    "10c20b974c6e6e80b434809f7d291257d79db7ac98205c90db07151556fe81eaf53a1f1c4ae931cfd4a5d4e526d33121", 96 );

  // Known test vector - message
  fd_hex_decode( msg,
    "0000000000000000000000000000000000000000000000000000000000000000", 32 );

  // Known test vector - valid signature
  fd_hex_decode( sig,
    "0e9c8d21fcb9ee9e9e80b056dce8e6701d418581f675315594dad16ac2eb6a254f1cf705c0438c4c0c6f04a210ca54f8"
    "164a32b0f97fbd518d984f3ff58f00ab729b90741b614342849f0e3ff6cc46b60ae30549e2a416fb2f98786d03304ce1"
    "039b3f5553218edb404ec36654556ce4ad2c7fc6e214c4356d5f2f32c7a0e571bfdc060b9a4917cb2dd9bf013c85ef6b"
    "04d5d8007d2c0ae8745de432717d7f6f93417ea4b63211bd8e34cd0772813c9a197e36eff82a86bf3c688e7fd43d097e", 192 );

  // Test valid signature verification
  FD_TEST( fd_bls12_381_verify(msg, 32, sig, pub) == 0 );

  // Test verification fails with wrong message
  uchar wrong_msg[32] = { 1 };  // Different message
  FD_TEST( fd_bls12_381_verify(wrong_msg, 32, sig, pub) != 0 );

  // Test verification fails with wrong signature
  uchar wrong_sig[192];
  memcpy(wrong_sig, sig, 192);
  wrong_sig[0] ^= 1;  // Flip a bit in the signature
  FD_TEST( fd_bls12_381_verify(msg, 32, wrong_sig, pub) != 0 );
}

/**********************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_add( rng );
  test_public_from_private( rng );
  test_sign( rng );
  test_verify( rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
