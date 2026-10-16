#include "../fd_ballet.h"
#include "fd_ed25519.h"
#include "fd_curve25519.h"
#include "../hex/fd_hex.h"
#include <stdlib.h>
#include "test_ed25519_cctv.c"
#include "test_ed25519_wycheproof.c"

#define TEST_MAX (33UL)

/* The cached variant shares one signer cache across the whole test so
   repeated keys get admitted and later batches mix warm, cold and
   invalid keys at any tail position. */

static fd_ed25519_cache_t * test_cache;

static void
check_batch( uchar const * const msgs[],
             ulong const         sizes[],
             uchar const * const sigs[],
             uchar const * const pubs[],
             fd_sha512_t *       shas[],
             ulong               cnt ) {
  int results[TEST_MAX+2];
  int cached [TEST_MAX+2];
  for( ulong j=0; j<TEST_MAX+2; j++ ) results[j] = cached[j] = 12345;
  fd_ed25519_verify_batch_multi_msg( msgs, sizes, sigs, pubs, shas, results+1, cnt );
  fd_ed25519_verify_batch_multi_msg_cached( msgs, sizes, sigs, pubs, shas, cached+1, cnt, test_cache );
  FD_TEST( results[0]==12345 && cached[0]==12345 );
  for( ulong j=0; j<cnt; j++ ) {
    int expected = fd_ed25519_verify( msgs[j], sizes[j], sigs[j], pubs[j], shas[j] );
    if( results[j+1]!=expected ) FD_LOG_ERR(( "count %lu lane %lu: got %d expected %d", cnt, j, results[j+1], expected ));
    if( cached [j+1]!=expected ) FD_LOG_ERR(( "count %lu lane %lu: cached got %d expected %d", cnt, j, cached[j+1], expected ));
  }
  for( ulong j=cnt+1; j<TEST_MAX+2; j++ ) FD_TEST( results[j]==12345 && cached[j]==12345 );
}

static void
test_corpora( fd_sha512_t * shas[] ) {
  uchar const * msgs[8], * sigs[8], * pubs[8];
  ulong sizes[8];
  /* Every fixture in every lane, with distinct neighboring fixtures.
     Existing scalar verify, not another library's policy, is the oracle. */
#define TEST_CORPUS(corpus) do {                                                           \
    ulong n = sizeof(corpus)/sizeof((corpus)[0])-1UL;                                       \
    for( ulong start=0; start<n; start+=8UL ) {                                             \
      ulong cnt = fd_ulong_min( 8UL, n-start );                                            \
      for( ulong rotation=0; rotation<8UL; rotation++ ) {                                   \
        for( ulong j=0; j<8UL; j++ ) {                                                     \
          ulong idx = (start+(j+rotation)%8UL)%n;                                          \
          msgs[j] = (corpus)[idx].msg; sizes[j] = (corpus)[idx].msg_sz;                      \
          sigs[j] = (corpus)[idx].sig; pubs[j] = (corpus)[idx].pub;                         \
        }                                                                                 \
        check_batch( msgs, sizes, sigs, pubs, shas, 8UL );                                  \
        check_batch( msgs, sizes, sigs, pubs, shas, cnt );                                  \
      }                                                                                   \
    }                                                                                     \
    FD_LOG_NOTICE(( #corpus ": %lu fixtures, all lane rotations pass", n ));                \
  } while(0)
  TEST_CORPUS( ed25519_verify_cctvs );
  TEST_CORPUS( ed25519_verify_wycheproofs );
#undef TEST_CORPUS
}

static void
test_messages( fd_rng_t *    rng,
               fd_sha512_t * shas[],
               ulong         iters ) {
  uchar msg[TEST_MAX][4097], sig[TEST_MAX][65], pub[TEST_MAX][33], priv[TEST_MAX][32];
  uchar const * msgs[TEST_MAX], * sigs[TEST_MAX], * pubs[TEST_MAX];
  ulong sizes[TEST_MAX];
  ulong lengths[] = { 0UL, 1UL, 47UL, 48UL, 49UL, 63UL, 64UL, 65UL, 111UL, 112UL, 113UL, 127UL, 128UL, 129UL,
                      175UL, 176UL, 177UL, 255UL, 256UL, 511UL, 512UL, 1024UL, 1231UL, 1232UL, 1233UL, 4096UL };
  for( ulong j=0; j<TEST_MAX; j++ ) {
    for( ulong b=0; b<32UL; b++ ) priv[j][b] = fd_rng_uchar( rng );
    for( ulong b=0; b<4097UL; b++ ) msg[j][b] = fd_rng_uchar( rng );
    sizes[j] = lengths[j%(sizeof(lengths)/sizeof(lengths[0]))];
    msgs[j] = sizes[j] ? msg[j]+1 : NULL;
    sigs[j] = sig[j]+1; pubs[j] = pub[j]+1; /* unaligned inputs */
    fd_ed25519_public_from_private( pub[j]+1, priv[j], shas[j] );
    fd_ed25519_sign( sig[j]+1, msgs[j], sizes[j], pubs[j], priv[j], shas[j] );
    FD_TEST( fd_ed25519_verify( msgs[j], sizes[j], sigs[j], pubs[j], shas[j] )==FD_ED25519_SUCCESS );
  }
  for( ulong cnt=0; cnt<=TEST_MAX; cnt++ ) check_batch( msgs, sizes, sigs, pubs, shas, cnt );

  /* Scalar/encoding boundaries and conflicting errors.  Every edge is
     tested in each lane among valid neighbors, then restored.  The
     encodings are: y=0 (order 4), the identity, y=2 (no square root),
     y=p (noncanonical zero), y=p-1 (order 2), y=p+1 (noncanonical
     identity), an order 8 point, all ones, then every small-order
     point [n]T8 with both sign bits, x=0 encodings with sign=1, and
     further noncanonical y with each sign bit. */
#define EDGE_CNT (32UL)
  uchar enc[EDGE_CNT][32] = {{0}};
  enc[1][0] = 1; enc[2][0] = 2;
  fd_hex_decode( enc[3], "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32UL );
  fd_hex_decode( enc[4], "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32UL );
  fd_hex_decode( enc[5], "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32UL );
  fd_hex_decode( enc[6], "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 32UL );
  fd_memset( enc[7], 255, 32UL );
  {
    fd_ed25519_point_t t8[1], m[1];
    FD_TEST( fd_ed25519_point_frombytes( t8, enc[6] ) );
    fd_ed25519_point_set_zero( m );
    for( ulong n=0; n<8UL; n++ ) {
      fd_ed25519_point_tobytes( enc[8+2*n], m );
      fd_memcpy( enc[9+2*n], enc[8+2*n], 32UL );
      enc[9+2*n][31] ^= 0x80;
      fd_ed25519_point_add( m, m, t8 );
    }
  }
  enc[24][0] = 1;    enc[24][31] = 0x80;                         /* y=1, sign=1: x=0 accepted */
  fd_memcpy( enc[25], enc[4], 32UL ); enc[25][31] |= 0x80;       /* y=p-1, sign=1 */
  fd_memcpy( enc[26], enc[5], 32UL ); enc[26][31] |= 0x80;       /* y=p+1, sign=1 */
  fd_memcpy( enc[27], enc[3], 32UL ); enc[27][31] |= 0x80;       /* y=p, sign=1: x=0 */
  fd_memcpy( enc[28], enc[7], 32UL ); enc[28][31] = 0x7f;        /* y=2^255-1 */
  fd_memcpy( enc[29], enc[5], 32UL ); enc[29][0] = 0xef;         /* y=p+2: noncanonical, no square root */
  fd_hex_decode( enc[30], "0000000000000000000000000000000000000000000000000000000000000080", 32UL );
  fd_hex_decode( enc[31], "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32UL ); /* y=p+3, sign=1 */
  for( ulong lane=0; lane<TEST_MAX; lane++ ) {
    uchar saved_sig[64], saved_pub[32];
    fd_memcpy( saved_sig, sigs[lane], 64UL ); fd_memcpy( saved_pub, pubs[lane], 32UL );
    for( ulong edge=0; edge<EDGE_CNT; edge++ ) {
      for( ulong kind=0; kind<6UL; kind++ ) {
        fd_memcpy( sig[lane]+1, saved_sig, 64UL ); fd_memcpy( pub[lane]+1, saved_pub, 32UL );
        if( kind==0 || kind>=3 ) fd_memcpy( pub[lane]+1, enc[edge], 32UL );
        if( kind==1 || kind==3 || kind==5 ) fd_memcpy( sig[lane]+1, enc[(edge+1)%EDGE_CNT], 32UL );
        if( kind==2 || kind>=4 ) {
          fd_hex_decode( sig[lane]+33, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 32UL );
          if( edge==0 ) sig[lane][33]--; /* L-1 */
          if( edge==1 ) sig[lane][33]++; /* L+1 */
          if( edge==2 ) fd_memset( sig[lane]+33, 0, 32UL );
          if( edge>=3 && edge<8UL ) sig[lane][64] = (uchar)(1U<<(uint)edge);
          if( edge>=8 ) sig[lane][33+(edge%32UL)] ^= (uchar)(1U<<(edge%8UL));
        }
        check_batch( msgs, sizes, sigs, pubs, shas, TEST_MAX );
      }
    }
    fd_memcpy( sig[lane]+1, saved_sig, 64UL ); fd_memcpy( pub[lane]+1, saved_pub, 32UL );
  }
  /* Small-order points as both A and R in the same lane, and R equal
     to A, with valid neighbors. */
  for( ulong lane=0; lane<TEST_MAX; lane+=5UL ) {
    uchar saved_sig[64], saved_pub[32];
    fd_memcpy( saved_sig, sigs[lane], 64UL ); fd_memcpy( saved_pub, pubs[lane], 32UL );
    for( ulong ea=8UL; ea<24UL; ea++ ) for( ulong er=8UL; er<24UL; er++ ) {
      fd_memcpy( pub[lane]+1, enc[ea], 32UL ); fd_memcpy( sig[lane]+1, enc[er], 32UL );
      check_batch( msgs, sizes, sigs, pubs, shas, TEST_MAX );
    }
    fd_memcpy( sig[lane]+1, saved_sig, 64UL ); fd_memcpy( pub[lane]+1, saved_pub, 32UL );
  }
#undef EDGE_CNT
  /* Deterministic mixed random changes, many simultaneous invalid lanes,
     with full/tail/multiple groups and lane permutations.  Flips hit
     signatures, public keys and messages. */
  for( ulong trial=0; trial<200UL*iters; trial++ ) {
    for( ulong j=0; j<TEST_MAX; j++ ) {
      fd_ed25519_sign( sig[j]+1, msgs[j], sizes[j], pubs[j], priv[j], shas[j] );
      uint r = fd_rng_uint( rng );
      if( r&1U ) sig[j][1UL+fd_rng_ulong_roll( rng, 64UL )] ^= (uchar)(1U<<(fd_rng_uint( rng )&7U));
      if( (r&6U)==2U ) pub[j][1UL+fd_rng_ulong_roll( rng, 32UL )] ^= (uchar)(1U<<(fd_rng_uint( rng )&7U));
      if( (r&24U)==8U && sizes[j] ) msg[j][1UL+fd_rng_ulong_roll( rng, sizes[j] )] ^= (uchar)(1U<<(fd_rng_uint( rng )&7U));
    }
    check_batch( msgs, sizes, sigs, pubs, shas, trial%(TEST_MAX+1UL) );
    for( ulong j=0; j<TEST_MAX/2UL; j++ ) {
      ulong k = TEST_MAX-1UL-j;
      uchar const * p;
      p=msgs[j]; msgs[j]=msgs[k]; msgs[k]=p;
      p=sigs[j]; sigs[j]=sigs[k]; sigs[k]=p;
      p=pubs[j]; pubs[j]=pubs[k]; pubs[k]=p;
      ulong z=sizes[j]; sizes[j]=sizes[k]; sizes[k]=z;
    }
    check_batch( msgs, sizes, sigs, pubs, shas, TEST_MAX );
    /* Restore pointer order and keys for the next signing round. */
    for( ulong j=0; j<TEST_MAX/2UL; j++ ) {
      ulong k = TEST_MAX-1UL-j;
      uchar const * p;
      p=msgs[j]; msgs[j]=msgs[k]; msgs[k]=p;
      p=sigs[j]; sigs[j]=sigs[k]; sigs[k]=p;
      p=pubs[j]; pubs[j]=pubs[k]; pubs[k]=p;
      ulong z=sizes[j]; sizes[j]=sizes[k]; sizes[k]=z;
    }
    for( ulong j=0; j<TEST_MAX; j++ ) fd_ed25519_public_from_private( pub[j]+1, priv[j], shas[j] );
  }
  FD_LOG_NOTICE(( "counts 0..33, SHA boundaries, encoding/scalar precedence, small order pairs, %lu mixed random rounds: pass", 200UL*iters ));
}

static void
bench_messages( fd_sha512_t * shas[],
                ulong         iters ) {
  uchar msg[TEST_MAX][1232], sig[TEST_MAX][64], pub[TEST_MAX][32], priv[32];
  uchar const * msgs[TEST_MAX], * sigs[TEST_MAX], * pubs[TEST_MAX];
  ulong sizes[TEST_MAX];
  int results[TEST_MAX];
  ulong lengths[] = { 0UL, 64UL, 256UL, 1232UL };
  ulong counts[] = { 1UL, 2UL, 3UL, 4UL, 5UL, 6UL, 7UL, 8UL, 9UL, 16UL, 33UL };
  FD_LOG_NOTICE(( "multi-message benchmark, iterations=%lu (ns per signature through the public API)", iters ));
  for( ulong l=0; l<sizeof(lengths)/sizeof(lengths[0]); l++ ) {
    for( ulong j=0; j<TEST_MAX; j++ ) {
      fd_memset( priv, (int)j+1, 32UL ); fd_memset( msg[j], (int)j+2, 1232UL );
      msgs[j]=msg[j]; sizes[j]=lengths[l]; sigs[j]=sig[j]; pubs[j]=pub[j];
      fd_ed25519_public_from_private( pub[j], priv, shas[j] );
      fd_ed25519_sign( sig[j], msgs[j], sizes[j], pubs[j], priv, shas[j] );
    }
    for( ulong c=0; c<sizeof(counts)/sizeof(counts[0]); c++ ) {
      ulong cnt = counts[c];
      check_batch( msgs, sizes, sigs, pubs, shas, cnt );
      long elapsed[2] = {0,0};
      /* Alternate order over four rounds, include hashing, preparation,
         table construction and tails.  No cache/prepared-key shortcut. */
      for( ulong round=0; round<4UL; round++ ) {
        for( ulong which=0; which<2UL; which++ ) {
          ulong mode = which^(round&1UL);
          long start = fd_log_wallclock();
          for( ulong i=0; i<iters; i++ ) {
            if( mode ) fd_ed25519_verify_batch_multi_msg( msgs, sizes, sigs, pubs, shas, results, cnt );
            else for( ulong j=0; j<cnt; j++ ) results[j] = fd_ed25519_verify( msgs[j], sizes[j], sigs[j], pubs[j], shas[j] );
            FD_COMPILER_MFENCE();
          }
          elapsed[mode] += fd_log_wallclock()-start;
          for( ulong j=0; j<cnt; j++ ) FD_TEST( results[j]==FD_ED25519_SUCCESS );
        }
      }
      double denom = (double)(4UL*iters*cnt);
      FD_LOG_NOTICE(( "bytes=%4lu count=%2lu baseline=%9.1f multi=%9.1f speedup=%.3fx", lengths[l], cnt,
                       (double)elapsed[0]/denom, (double)elapsed[1]/denom, (double)elapsed[0]/(double)elapsed[1] ));
    }
  }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  ulong bench = fd_env_strip_cmdline_ulong( &argc, &argv, "--bench", NULL, 0UL );
  ulong iters = fd_env_strip_cmdline_ulong( &argc, &argv, "--iters", NULL, 1UL );
  fd_rng_t rng_mem[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 0UL ) );
  fd_sha512_t sha_mem[TEST_MAX]; fd_sha512_t * shas[TEST_MAX];
  for( ulong j=0; j<TEST_MAX; j++ ) shas[j] = fd_sha512_join( fd_sha512_new( &sha_mem[j] ) );
  fd_ed25519_verify_batch_multi_msg( NULL, NULL, NULL, NULL, NULL, NULL, 0UL );
  test_cache = fd_ed25519_cache_join( fd_ed25519_cache_new( aligned_alloc( fd_ed25519_cache_align(), fd_ed25519_cache_footprint( 64UL ) ), 64UL, 1UL ) );
  FD_TEST( test_cache );
  fd_ed25519_verify_batch_multi_msg_cached( NULL, NULL, NULL, NULL, NULL, NULL, 0UL, test_cache );
  test_messages( rng, shas, iters );
  test_corpora( shas );
  FD_LOG_NOTICE(( "cached variant: hit %lu miss %lu insert %lu", fd_ed25519_cache_hit_cnt( test_cache ), fd_ed25519_cache_miss_cnt( test_cache ), fd_ed25519_cache_insert_cnt( test_cache ) ));
  FD_TEST( fd_ed25519_cache_hit_cnt( test_cache ) && fd_ed25519_cache_insert_cnt( test_cache ) );
  if( bench ) bench_messages( shas, bench );
  free( fd_ed25519_cache_delete( fd_ed25519_cache_leave( test_cache ) ) );
  for( ulong j=0; j<TEST_MAX; j++ ) fd_sha512_delete( fd_sha512_leave( shas[j] ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
