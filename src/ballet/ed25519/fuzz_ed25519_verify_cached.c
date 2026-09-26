#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_ed25519.h"

/* Differential fuzzer: cached vs uncached verify.  Each input is a
   sequence of verify ops over a small set of keys so the cache sees
   repeats, evictions and signatures that are valid except for a
   mutation of the fuzzer's choosing. */

#define KEY_CNT (8UL)

static fd_sha512_t          sha_mem[1];
static fd_sha512_t *        sha;
static uchar                prv[ KEY_CNT ][ 32 ];
static uchar                pub[ KEY_CNT ][ 32 ];
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

  sha = fd_sha512_join( fd_sha512_new( sha_mem ) );
  for( ulong i=0UL; i<KEY_CNT; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) prv[i][j] = (uchar)(i*32UL+j);
    fd_ed25519_public_from_private( pub[i], prv[i], sha );
  }
  ulong ent_cnt = 4UL; /* smaller than KEY_CNT to force evictions */
  void * mem = aligned_alloc( fd_ed25519_cache_align(), fd_ed25519_cache_footprint( ent_cnt ) );
  cache = fd_ed25519_cache_join( fd_ed25519_cache_new( mem, ent_cnt, 0UL ) );
  assert( cache );
  return 0;
}

/* op layout: key idx (1) | mode (1) | pos (1) | val (1) | sig/pub bytes (32) | msg_sz (1) | msg */

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  while( size>=37UL ) {
    ulong         k      = data[0] % KEY_CNT;
    uint          mode   = data[1];
    uchar         pos    = data[2];
    uchar         val    = data[3];
    uchar const * bytes  = data+4;
    ulong         msg_sz = fd_ulong_min( data[36], size-37UL );
    uchar const * msg    = data+37;
    data += 37UL+msg_sz; size -= 37UL+msg_sz;

    uchar sig[ 64 ]; uchar pk[ 32 ];
    memcpy( pk, pub[k], 32UL );
    fd_ed25519_sign( sig, msg, msg_sz, pk, prv[k], sha );

    switch( mode % 8U ) {
    case 0: break;
    case 1: sig[ pos & 63 ] ^= val;           break; /* corrupt R or S */
    case 2: pk [ pos & 31 ] ^= val;           break; /* corrupt A */
    case 3: memcpy( sig,    bytes, 32UL );   break; /* arbitrary R */
    case 4: memcpy( sig+32, bytes, 32UL );   break; /* arbitrary S */
    case 5: memcpy( pk,     bytes, 32UL );   break; /* arbitrary A */
    case 6: memcpy( pk,     bytes, 32UL ); memcpy( sig, bytes, 32UL ); break; /* R==A */
    case 7: { uchar m2[1] = { val }; if( msg_sz ) { fd_ed25519_sign( sig, m2, 1UL, pk, prv[k], sha ); } break; } /* wrong msg */
    }

    int expected = fd_ed25519_verify( msg, msg_sz, sig, pk, sha );
    for( ulong r=0UL; r<3UL; r++ ) assert( fd_ed25519_verify_cached( msg, msg_sz, sig, pk, sha, cache )==expected );

    /* batch: this signature in the middle of two good ones */
    uchar sigs[ 3*64 ]; uchar pks[ 3*32 ];
    ulong k2 = (k+1UL) % KEY_CNT;
    memcpy( pks, pub[k2], 32UL ); fd_ed25519_sign( sigs, msg, msg_sz, pks, prv[k2], sha );
    memcpy( pks+32, pk, 32UL );   memcpy( sigs+64, sig, 64UL );
    memcpy( pks+64, pub[k], 32UL ); fd_ed25519_sign( sigs+128, msg, msg_sz, pks+64, prv[k], sha );
    fd_sha512_t * shas[3] = { sha, sha, sha };
    int eb = fd_ed25519_verify_batch_single_msg( msg, msg_sz, sigs, pks, shas, 3 );
    assert( fd_ed25519_verify_batch_single_msg_cached( msg, msg_sz, sigs, pks, shas, 3, cache )==eb );
    FD_FUZZ_MUST_BE_COVERED;
  }
  return 0;
}
