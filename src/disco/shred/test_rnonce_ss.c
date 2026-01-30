#include "fd_rnonce_ss.h"


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1U, 0UL ) );

  fd_rnonce_ss_t ss[1];
  for( ulong i=0UL; i<64UL; i++ ) ss->bytes[i] = fd_rng_uchar( rng );

  /* Test success, normal repair */
  for( ulong i=0UL; i<1000000UL; i++ ) {
    ulong slot      = fd_rng_ulong( rng );
    uint  shred_idx = fd_rng_uint ( rng );
    long  rq_time   = (long)fd_rng_ulong( rng );

    uint nonce = fd_rnonce_ss_compute( ss, 1, slot, shred_idx, rq_time );

    long rs_time = rq_time + (long)fd_rng_ulong_roll( rng, 1000000000UL );
    FD_TEST( fd_rnonce_ss_verify( ss, nonce, slot, shred_idx, rs_time ) );
  }

  /* Test success, not normal repair */
  for( ulong i=0UL; i<1000000UL; i++ ) {
    ulong slot      = fd_rng_ulong( rng );
    uint  shred_idx = fd_rng_uint ( rng );
    long  rq_time   = (long)fd_rng_ulong( rng );

    uint nonce = fd_rnonce_ss_compute( ss, 0, slot, shred_idx, rq_time );

    slot        -= fd_rng_ulong_roll( rng, 128UL );
    shred_idx    = fd_rng_uint( rng );
    long rs_time = rq_time + (long)fd_rng_ulong_roll( rng, 1000000000UL );
    FD_TEST( fd_rnonce_ss_verify( ss, nonce, slot, shred_idx, rs_time ) );
  }

  ulong failure_cnt = 0UL;
  /* These should not match, but with only effectively 25 bits, we
     expect some random successes */
  for( ulong i=0UL; i<10000000UL; i++ ) {
    for( ulong j=0UL; j<64UL; j++ ) ss->bytes[j] = fd_rng_uchar( rng );
    ulong slot      = fd_rng_ulong( rng );
    uint  shred_idx = fd_rng_uint ( rng );
    long  rq_time   = (long)fd_rng_ulong( rng );

    uint nonce = fd_rnonce_ss_compute( ss, 1, slot, shred_idx, rq_time );

    long rs_time = rq_time + (long)fd_rng_ulong_roll( rng, 1000000000UL );
    switch( i%8UL ) {
      case 0UL: slot++;                                       break;
      case 1UL: slot      = fd_rng_ulong( rng );              break;
      case 2UL: shred_idx++;                                  break;
      case 3UL: shred_idx = fd_rng_uint( rng );               break; /* this could return shred_idx, but very unlikely */
      case 4UL: rs_time  += 1024000000L;                      break;
      case 5UL: rs_time  += 1L<<32;                           break;
      case 6UL: rs_time   = (long)fd_rng_ulong( rng );        break;
      case 7UL: ss->private.ss0[ 1 ]--;                       break;
    }
    failure_cnt += (ulong)fd_rnonce_ss_verify( ss, nonce, slot, shred_idx, rs_time );
    if( FD_UNLIKELY( fd_rnonce_ss_verify( ss, nonce, slot, shred_idx, rs_time ) ) ) FD_LOG_NOTICE(( "normal - %lu", i ));
  }
  FD_LOG_NOTICE(( "%lu false positives out of %lu", failure_cnt, 10000000UL ));
  /* failure_cnt should be a binomially distributed random variable with
     N=10,000,000 and p approx 2^-25.  With 99.99% probability,
     failure_cnt<=4 (mean is about 0.3). */
  FD_TEST( failure_cnt<=4UL );

  failure_cnt = 0UL;
  for( ulong i=0UL; i<10000000UL; i++ ) {
    ulong slot      = fd_rng_ulong( rng );
    uint  shred_idx = fd_rng_uint ( rng );
    long  rq_time   = (long)fd_rng_ulong( rng );

    uint nonce = fd_rnonce_ss_compute( ss, 0, slot, shred_idx, rq_time );

    long rs_time = rq_time + (long)fd_rng_ulong_roll( rng, 1000000000UL );
    switch( i%6UL ) {
      case 0UL: slot     += 256UL;                                  break;
      case 1UL: slot      = fd_rng_ulong( rng );                    break; /* returns a valid slot with p=2^-56 */
      case 2UL: rs_time  += 1024000000L;                            break;
      case 3UL: rs_time  += 1L<<32;                                 break;
      case 4UL: rs_time   = (long)fd_rng_ulong( rng );              break;
      case 5UL: ss->private.ss0[ 1 ]--;                             break;
    }
    failure_cnt += (ulong)fd_rnonce_ss_verify( ss, nonce, slot, shred_idx, rs_time );
  }
  FD_LOG_NOTICE(( "%lu false positives out of %lu", failure_cnt, 10000000UL ));
  FD_TEST( failure_cnt<=4UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

