#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_ed25519.h"

/* Differential fuzzer: multi-message batch verify (plain and cached)
   vs fd_ed25519_verify, lane by lane.  Each input is a sequence of
   lanes over a small set of keys so a batch mixes valid signatures,
   cache repeats, evictions and mutations of the fuzzer's choosing. */

#define KEY_CNT  (8UL)
#define LANE_MAX (12UL)

static fd_sha512_t          sha_mem[ LANE_MAX ];
static fd_sha512_t *        shas   [ LANE_MAX ];
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

  for( ulong j=0UL; j<LANE_MAX; j++ ) shas[j] = fd_sha512_join( fd_sha512_new( sha_mem+j ) );
  for( ulong i=0UL; i<KEY_CNT; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) prv[i][j] = (uchar)(i*32UL+j);
    fd_ed25519_public_from_private( pub[i], prv[i], shas[0] );
  }
  ulong ent_cnt = 4UL; /* smaller than KEY_CNT to force evictions */
  void * mem = aligned_alloc( fd_ed25519_cache_align(), fd_ed25519_cache_footprint( ent_cnt ) );
  cache = fd_ed25519_cache_join( fd_ed25519_cache_new( mem, ent_cnt, 0UL ) );
  assert( cache );
  return 0;
}

/* lane layout: key idx (1) | mode (1) | pos (1) | val (1) | sig/pub bytes (32) | msg_sz (1) | msg */

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  uchar         sig[ LANE_MAX ][ 64 ];
  uchar         pk [ LANE_MAX ][ 32 ];
  uchar const * msgs   [ LANE_MAX ] = {0};
  ulong         msg_szs[ LANE_MAX ] = {0};
  uchar const * sigs   [ LANE_MAX ] = {0};
  uchar const * pks    [ LANE_MAX ] = {0};
  int           expected[ LANE_MAX ] = {0};
  int           results [ LANE_MAX+1UL ];
  int           cached  [ LANE_MAX+1UL ];

  ulong cnt = 0UL;
  while( size>=37UL && cnt<LANE_MAX ) {
    ulong         k      = data[0] % KEY_CNT;
    uint          mode   = data[1];
    uchar         pos    = data[2];
    uchar         val    = data[3];
    uchar const * bytes  = data+4;
    ulong         msg_sz = fd_ulong_min( data[36], size-37UL );
    uchar const * msg    = data+37;
    data += 37UL+msg_sz; size -= 37UL+msg_sz;

    uchar * s = sig[ cnt ];
    uchar * p = pk [ cnt ];
    memcpy( p, pub[k], 32UL );
    fd_ed25519_sign( s, msg, msg_sz, p, prv[k], shas[ cnt ] );

    switch( mode % 8U ) {
    case 0: break;
    case 1: s[ pos & 63 ] ^= val;           break; /* corrupt R or S */
    case 2: p[ pos & 31 ] ^= val;           break; /* corrupt A */
    case 3: memcpy( s,    bytes, 32UL );   break; /* arbitrary R */
    case 4: memcpy( s+32, bytes, 32UL );   break; /* arbitrary S */
    case 5: memcpy( p,    bytes, 32UL );   break; /* arbitrary A */
    case 6: memcpy( p,    bytes, 32UL ); memcpy( s, bytes, 32UL ); break; /* R==A */
    case 7: { uchar m2[1] = { val }; if( msg_sz ) { fd_ed25519_sign( s, m2, 1UL, p, prv[k], shas[ cnt ] ); } break; } /* wrong msg */
    }

    msgs   [ cnt ] = msg_sz ? msg : NULL;
    msg_szs[ cnt ] = msg_sz;
    sigs   [ cnt ] = s;
    pks    [ cnt ] = p;
    expected[ cnt ] = fd_ed25519_verify( msg, msg_sz, s, p, shas[ cnt ] );
    cnt++;
  }

  results[ cnt ] = 12345; cached[ cnt ] = 12345;
  fd_ed25519_verify_batch_multi_msg       ( msgs, msg_szs, sigs, pks, shas, results, cnt );
  fd_ed25519_verify_batch_multi_msg_cached( msgs, msg_szs, sigs, pks, shas, cached,  cnt, cache );
  for( ulong j=0UL; j<cnt; j++ ) {
    assert( results[j]==expected[j] );
    assert( cached [j]==expected[j] );
  }
  assert( results[ cnt ]==12345 && cached[ cnt ]==12345 );

  /* Repeat the cached call so the lanes admitted above now hit. */
  fd_ed25519_verify_batch_multi_msg_cached( msgs, msg_szs, sigs, pks, shas, cached, cnt, cache );
  for( ulong j=0UL; j<cnt; j++ ) assert( cached[j]==expected[j] );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
