#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_ed25519.h"

/* Differential fuzzer: the batch APIs against the single-item ones.
   Each input gives one signing identity and eight lanes.  The eight
   signatures of fd_ed25519_sign_batch8 must equal the eight of
   fd_ed25519_sign; after a per-lane mutation of the fuzzer's choosing,
   the eight results of fd_ed25519_verify_batch_multi_msg (cached and
   uncached) must equal the eight of fd_ed25519_verify, and
   fd_ed25519_verify_batch_single_msg must succeed exactly when every
   lane does. */

#define LANE_CNT (8UL)

static fd_sha512_t          sha_mem[ LANE_CNT ];
static fd_sha512_t *        shas[ LANE_CNT ];
static fd_ed25519_cache_t * cache;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */

  for( ulong i=0UL; i<LANE_CNT; i++ ) shas[i] = fd_sha512_join( fd_sha512_new( sha_mem+i ) );
  ulong ent_cnt = 4UL;
  void * mem = aligned_alloc( fd_ed25519_cache_align(), fd_ed25519_cache_footprint( ent_cnt ) );
  cache = fd_ed25519_cache_join( fd_ed25519_cache_new( mem, ent_cnt, 0UL ) );
  assert( cache );
  return 0;
}

/* mode bit 0: every lane signs the whole message (the single-message
   batch applies); otherwise lane i signs the message from offset i.
   flip[i]==0 leaves lane i intact; bit 7 selects the public key over
   the signature as the byte to corrupt, the low bits its position. */

struct batch_test {
  uchar prv [ 32 ];
  uchar mode;
  uchar flip[ LANE_CNT ];
  uchar msg [ ];
};
typedef struct batch_test batch_test_t;

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size<sizeof(batch_test_t) ) ) return -1;

  batch_test_t const * test = (batch_test_t const *)data;
  ulong sz = fd_ulong_min( size-sizeof(batch_test_t), FD_ED25519_SIGN_BATCH_MSG_MAX );

  uchar pub[ 32 ];
  fd_ed25519_public_from_private( pub, test->prv, shas[0] );

  uchar const * msg   [ LANE_CNT ];
  ulong         msg_sz[ LANE_CNT ];
  for( ulong i=0UL; i<LANE_CNT; i++ ) {
    ulong off = (test->mode & 1) ? 0UL : fd_ulong_min( i, sz );
    msg   [i] = test->msg+off;
    msg_sz[i] = sz-off;
  }

  /* sign: eight singles against one batch, then a shorter batch */
  uchar sig  [ LANE_CNT ][ 64 ];
  uchar sig_b[ LANE_CNT ][ 64 ];
  for( ulong i=0UL; i<LANE_CNT; i++ ) fd_ed25519_sign( sig[i], msg[i], msg_sz[i], pub, test->prv, shas[i] );
  fd_ed25519_sign_batch8( sig_b[0], msg, msg_sz, pub, test->prv, LANE_CNT );
  assert( fd_memeq( sig, sig_b, sizeof(sig) ) );
  ulong n = 1UL + (test->mode>>1)%LANE_CNT;
  memset( sig_b, 0, sizeof(sig_b) );
  fd_ed25519_sign_batch8( sig_b[0], msg, msg_sz, pub, test->prv, n );
  assert( fd_memeq( sig, sig_b, 64UL*n ) );

  /* corrupt the lanes the input selects */
  uchar pk[ LANE_CNT ][ 32 ];
  for( ulong i=0UL; i<LANE_CNT; i++ ) {
    memcpy( pk[i], pub, 32UL );
    uchar f = test->flip[i];
    if( !f ) continue;
    if( f & 0x80 ) pk [i][ f & 31 ] ^= f;
    else           sig[i][ f & 63 ] ^= f;
  }

  /* verify: eight singles, cached and uncached */
  uchar const * sigs[ LANE_CNT ];
  uchar const * pks [ LANE_CNT ];
  int expected[ LANE_CNT ];
  int all_ok = 1;
  for( ulong i=0UL; i<LANE_CNT; i++ ) {
    sigs[i] = sig[i];
    pks [i] = pk [i];
    expected[i] = fd_ed25519_verify( msg[i], msg_sz[i], sig[i], pk[i], shas[i] );
    assert( fd_ed25519_verify_cached( msg[i], msg_sz[i], sig[i], pk[i], shas[i], cache )==expected[i] );
    all_ok &= (expected[i]==FD_ED25519_SUCCESS);
  }

  /* the multi-message batches, lane by lane */
  int results[ LANE_CNT ];
  fd_ed25519_verify_batch_multi_msg( msg, msg_sz, sigs, pks, shas, results, LANE_CNT );
  for( ulong i=0UL; i<LANE_CNT; i++ ) assert( results[i]==expected[i] );
  memset( results, 0x7f, sizeof(results) );
  fd_ed25519_verify_batch_multi_msg_cached( msg, msg_sz, sigs, pks, shas, results, LANE_CNT, cache );
  for( ulong i=0UL; i<LANE_CNT; i++ ) assert( results[i]==expected[i] );

  /* the single-message batches, when every lane has the same message */
  if( test->mode & 1 ) {
    int res = fd_ed25519_verify_batch_single_msg( msg[0], msg_sz[0], sig[0], pk[0], shas, (uchar)LANE_CNT );
    assert( (res==FD_ED25519_SUCCESS)==all_ok );
    res = fd_ed25519_verify_batch_single_msg_cached( msg[0], msg_sz[0], sig[0], pk[0], shas, (uchar)LANE_CNT, cache );
    assert( (res==FD_ED25519_SUCCESS)==all_ok );
  }

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
