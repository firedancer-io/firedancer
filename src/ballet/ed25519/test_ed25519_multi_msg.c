#include "fd_ed25519.h"
#include "fd_curve25519.h"
#include "../hex/fd_hex.h"
#include "test_ed25519_cctv.c"
#include "test_ed25519_wycheproof.c"

#if FD_HAS_AVX512
#include "avx512/fd_ed25519_lane.h"

/* Independent field oracle: evaluate arbitrary u52 limbs by Horner's
   rule using Firedancer's existing field implementation. */
static void
lane_to_scalar( fd_f25519_t *                  out,
                fd_ed25519_lane_fe_t const * a,
                int                           lane ) {
  uchar buf[32] = {0};
  buf[6] = 8; /* 2^51 */
  fd_f25519_t radix[1], limb[1];
  fd_f25519_frombytes( radix, buf );
  fd_f25519_set( out, fd_f25519_zero );
  for( int i=4; i>=0; i-- ) {
    ulong v[8];
    wwv_stu( v, a->limb[i] );
    fd_memset( buf, 0, 32UL );
    fd_memcpy( buf, &v[lane], 8UL );
    fd_f25519_frombytes( limb, buf );
    fd_f25519_mul( out, out, radix );
    fd_f25519_add( out, out, limb );
  }
}

static void
test_lane_field( fd_rng_t * rng ) {
  for( ulong trial=0; trial<1000UL; trial++ ) {
    fd_ed25519_lane_fe_t a, b, r, alias;
    for( int i=0; i<5; i++ ) {
      ulong x[8], y[8];
      for( int j=0; j<8; j++ ) {
        x[j] = fd_rng_ulong( rng ) & ((1UL<<52)-1UL);
        y[j] = fd_rng_ulong( rng ) & ((1UL<<52)-1UL);
        if( trial<8UL ) {
          ulong edges[] = { 0UL, 1UL, 18UL, 19UL, (1UL<<51)-19UL, (1UL<<51)-1UL, 1UL<<51, (1UL<<52)-1UL };
          x[j] = edges[(trial+(ulong)j)%8UL];
          y[j] = edges[(trial+(ulong)i)%8UL];
        }
        if( trial==8UL ) x[j] = y[j] = (1UL<<52)-1UL;
      }
      a.limb[i] = wwv_ldu( x ); b.limb[i] = wwv_ldu( y );
    }
    for( int op=0; op<4; op++ ) {
      if( op==0 ) fd_ed25519_lane_add( &r, &a, &b );
      if( op==1 ) fd_ed25519_lane_sub( &r, &a, &b );
      if( op==2 ) fd_ed25519_lane_mul( &r, &a, &b );
      if( op==3 ) {
        fd_ed25519_lane_sqr( &r, &a );
        fd_ed25519_lane_mul( &alias, &a, &a );
        FD_TEST( fd_memeq( &r, &alias, sizeof(r) ) );
      }
      alias = a;
      if( op==0 ) fd_ed25519_lane_add( &alias, &alias, &b );
      if( op==1 ) fd_ed25519_lane_sub( &alias, &alias, &b );
      if( op==2 ) fd_ed25519_lane_mul( &alias, &alias, &b );
      if( op==3 ) fd_ed25519_lane_sqr( &alias, &alias );
      FD_TEST( fd_memeq( &r, &alias, sizeof(r) ) );
      if( op<3 ) {
        alias = b;
        if( op==0 ) fd_ed25519_lane_add( &alias, &a, &alias );
        if( op==1 ) fd_ed25519_lane_sub( &alias, &a, &alias );
        if( op==2 ) fd_ed25519_lane_mul( &alias, &a, &alias );
        FD_TEST( fd_memeq( &r, &alias, sizeof(r) ) );
      }
      for( int i=0; i<5; i++ ) FD_TEST( wwv_lt( r.limb[i], wwv_bcast( 1UL<<52 ) )==255 );
      int zero_mask = fd_ed25519_lane_is_zero( r );
      for( int j=0; j<8; j++ ) {
        fd_f25519_t x[1], y[1], z[1], expected[1];
        lane_to_scalar( x, &a, j ); lane_to_scalar( y, &b, j ); lane_to_scalar( z, &r, j );
        if( op==0 ) fd_f25519_add( expected, x, y );
        if( op==1 ) fd_f25519_sub( expected, x, y );
        if( op==2 ) fd_f25519_mul( expected, x, y );
        if( op==3 ) fd_f25519_sqr( expected, x );
        FD_TEST( fd_f25519_eq( z, expected ) );
        FD_TEST( !!(zero_mask & (1<<j)) == fd_f25519_is_zero( expected ) );
      }
    }
  }
  /* All nineteen noncanonical u51 encodings, including p == zero. */
  for( ulong n=0UL; n<19UL; n++ ) {
    fd_ed25519_lane_fe_t a;
    for( int i=0; i<5; i++ ) a.limb[i] = wwv_bcast( FD_ED25519_LANE_MASK-(i==0 ? 18UL-n : 0UL) );
    FD_TEST( fd_ed25519_lane_is_zero( a ) == (n ? 0 : 255) );
  }
  for( ulong multiple=0UL; multiple<=2UL; multiple++ ) {
    fd_ed25519_lane_fe_t a;
    for( int i=0; i<5; i++ ) a.limb[i] = wwv_bcast( multiple*(FD_ED25519_LANE_MASK-(i==0 ? 18UL : 0UL)) );
    FD_TEST( fd_ed25519_lane_is_zero( a )==255 );
  }
  FD_LOG_NOTICE(( "lane field differential, u52 bounds and aliases: pass" ));
}

static void
test_lane_decode( fd_rng_t * rng ) {
  for( ulong trial=0; trial<1000UL; trial++ ) {
    uchar bytes[8][33]; uchar const * inputs[8];
    fd_ed25519_point_t points[8];
    int expected_valid = 0, expected_small = 0;
    for( int j=0; j<8; j++ ) {
      inputs[j] = bytes[j]+1;
      for( int b=1; b<33; b++ ) bytes[j][b] = fd_rng_uchar( rng );
      if( trial<38UL ) {
        fd_memset( bytes[j]+1, 255, 32UL );
        bytes[j][1] = (uchar)(237UL+trial%19UL);
        bytes[j][32] = (uchar)(127U | ((uint)(trial/19UL)<<7));
      }
      if( fd_ed25519_point_frombytes( &points[j], inputs[j] ) ) expected_valid |= 1<<j;
      else fd_ed25519_point_set_zero( &points[j] );
      if( fd_ed25519_affine_is_small_order( &points[j] ) ) expected_small |= 1<<j;
    }
    fd_ed25519_lane_point_t got, expected;
    FD_TEST( fd_ed25519_lane_decode( &got, inputs )==expected_valid );
    FD_TEST( fd_ed25519_lane_small_order( &got )==expected_small );
    fd_ed25519_lane_pack( &expected, points );
    fd_ed25519_lane_sub( &got.x, &got.x, &expected.x );
    fd_ed25519_lane_sub( &got.y, &got.y, &expected.y );
    fd_ed25519_lane_sub( &got.z, &got.z, &expected.z );
    fd_ed25519_lane_sub( &got.t, &got.t, &expected.t );
    FD_TEST( fd_ed25519_lane_is_zero( got.x )==255 );
    FD_TEST( fd_ed25519_lane_is_zero( got.y )==255 );
    FD_TEST( fd_ed25519_lane_is_zero( got.z )==255 );
    FD_TEST( fd_ed25519_lane_is_zero( got.t )==255 );
  }
  FD_LOG_NOTICE(( "lane decode differential: 8000 encodings, canonical parity and small order pass" ));
}

static void
test_lane_group( fd_rng_t * rng ) {
  fd_ed25519_point_t torsion[1];
  uchar buf[64];
  fd_hex_decode( buf, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 32UL );
  FD_TEST( fd_ed25519_point_frombytes( torsion, buf ) );
  for( ulong trial=0; trial<100UL; trial++ ) {
    fd_ed25519_point_t a[8], r[8], tmp[1];
    uchar k[8][32], s[8][32];
    for( int j=0; j<8; j++ ) {
      for( int b=0; b<64; b++ ) buf[b] = fd_rng_uchar( rng );
      fd_curve25519_scalar_reduce( k[j], buf );
      for( int b=0; b<64; b++ ) buf[b] = fd_rng_uchar( rng );
      fd_curve25519_scalar_reduce( s[j], buf );
      fd_ed25519_scalar_mul_base_const_time( &a[j], k[j] );
      /* Mixed-order points: do not assume the public key is in the
         prime-order subgroup.  Include pure torsion and the identity. */
      for( int n=0; n<j; n++ ) fd_ed25519_point_add( &a[j], &a[j], torsion );
      if( trial==0UL ) {
        fd_ed25519_point_set( &a[j], torsion );
        fd_memset( k[j], 0, 32UL ); fd_memset( s[j], 0, 32UL );
        k[j][0] = (uchar)j;
      }
      if( trial==1UL ) {
        fd_hex_decode( k[j], "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 32UL );
        fd_memcpy( s[j], k[j], 32UL );
      }
      fd_ed25519_point_tobytes( buf, &a[j] );
      FD_TEST( fd_ed25519_point_frombytes( &a[j], buf ) );
      fd_ed25519_double_scalar_mul_base( tmp, k[j], &a[j], s[j] );
      fd_ed25519_point_tobytes( buf, tmp );
      FD_TEST( fd_ed25519_point_frombytes( &r[j], buf ) );
    }
    fd_ed25519_lane_point_t av, rv;
    fd_ed25519_lane_pack( &av, a ); fd_ed25519_lane_pack( &rv, r );
    FD_TEST( fd_ed25519_lane_verify( &av, &rv, (uchar const (*)[32])k, (uchar const (*)[32])s )==255 );
    int lane = (int)(trial%8UL);
    fd_ed25519_point_add( tmp, &r[lane], fd_ed25519_base_point );
    fd_ed25519_point_tobytes( buf, tmp );
    FD_TEST( fd_ed25519_point_frombytes( &r[lane], buf ) );
    fd_ed25519_lane_pack( &rv, r );
    FD_TEST( fd_ed25519_lane_verify( &av, &rv, (uchar const (*)[32])k, (uchar const (*)[32])s )==(255^(1<<lane)) );
  }
  FD_LOG_NOTICE(( "lane group differential, mixed-order points and independent verdicts: pass" ));
}
#endif

#define TEST_MAX 33UL

static void
check_batch( uchar const * const msgs[],
             ulong const           sizes[],
             uchar const * const sigs[],
             uchar const * const pubs[],
             fd_sha512_t *         shas[],
             ulong                 cnt ) {
  int results[TEST_MAX+2];
  for( ulong j=0; j<TEST_MAX+2; j++ ) results[j] = 12345;
  fd_ed25519_verify_batch_multi_msg( msgs, sizes, sigs, pubs, shas, results+1, cnt );
  FD_TEST( results[0]==12345 );
  for( ulong j=0; j<cnt; j++ ) {
    int expected = fd_ed25519_verify( msgs[j], sizes[j], sigs[j], pubs[j], shas[j] );
    if( results[j+1]!=expected ) FD_LOG_ERR(( "count %lu lane %lu: got %d expected %d", cnt, j, results[j+1], expected ));
  }
  for( ulong j=cnt+1; j<TEST_MAX+2; j++ ) FD_TEST( results[j]==12345 );
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
test_messages( fd_rng_t * rng,
               fd_sha512_t * shas[] ) {
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
     tested in each lane among valid neighbors, then restored. */
  uchar enc[8][32] = {{0}};
  enc[1][0] = 1; enc[2][0] = 2;
  fd_hex_decode( enc[3], "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32UL );
  fd_hex_decode( enc[4], "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32UL );
  fd_hex_decode( enc[5], "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 32UL );
  fd_hex_decode( enc[6], "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 32UL );
  fd_memset( enc[7], 255, 32UL );
  for( ulong lane=0; lane<TEST_MAX; lane++ ) {
    uchar saved_sig[64], saved_pub[32];
    fd_memcpy( saved_sig, sigs[lane], 64UL ); fd_memcpy( saved_pub, pubs[lane], 32UL );
    for( ulong edge=0; edge<8UL; edge++ ) {
      for( ulong kind=0; kind<6UL; kind++ ) {
        fd_memcpy( sig[lane]+1, saved_sig, 64UL ); fd_memcpy( pub[lane]+1, saved_pub, 32UL );
        if( kind==0 || kind>=3 ) fd_memcpy( pub[lane]+1, enc[edge], 32UL );
        if( kind==1 || kind==3 || kind==5 ) fd_memcpy( sig[lane]+1, enc[(edge+1)%8UL], 32UL );
        if( kind==2 || kind>=4 ) {
          fd_hex_decode( sig[lane]+33, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 32UL );
          if( edge==0 ) sig[lane][33]--; /* L-1 */
          if( edge==1 ) sig[lane][33]++; /* L+1 */
          if( edge==2 ) fd_memset( sig[lane]+33, 0, 32UL );
          if( edge>=3 ) sig[lane][64] = (uchar)(1U<<(uint)edge);
        }
        check_batch( msgs, sizes, sigs, pubs, shas, TEST_MAX );
      }
    }
    fd_memcpy( sig[lane]+1, saved_sig, 64UL ); fd_memcpy( pub[lane]+1, saved_pub, 32UL );
  }
  /* Deterministic mixed random changes, many simultaneous invalid lanes,
     with full/tail/multiple groups and lane permutations. */
  for( ulong trial=0; trial<200UL; trial++ ) {
    for( ulong j=0; j<TEST_MAX; j++ ) {
      fd_ed25519_sign( sig[j]+1, msgs[j], sizes[j], pubs[j], priv[j], shas[j] );
      if( fd_rng_uint( rng )&1U ) sig[j][1UL+fd_rng_ulong_roll( rng, 64UL )] ^= 1;
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
    /* Restore pointer order for the next signing round. */
    for( ulong j=0; j<TEST_MAX/2UL; j++ ) {
      ulong k = TEST_MAX-1UL-j;
      uchar const * p;
      p=msgs[j]; msgs[j]=msgs[k]; msgs[k]=p;
      p=sigs[j]; sigs[j]=sigs[k]; sigs[k]=p;
      p=pubs[j]; pubs[j]=pubs[k]; pubs[k]=p;
      ulong z=sizes[j]; sizes[j]=sizes[k]; sizes[k]=z;
    }
  }
  FD_LOG_NOTICE(( "counts 0..33, SHA boundaries, encoding/scalar precedence, mixed permutations: pass" ));
}

#if FD_HAS_AVX512
/* Phase microbenchmarks diagnose the gap to the throughput target.
   The end-to-end numbers below remain the complete public API, not
   these prepared-core numbers. */
static void
bench_phases( uchar const * const msgs[],
              ulong const           sizes[],
              uchar const * const sigs[],
              uchar const * const pubs[],
              fd_sha512_t *         shas[],
              ulong                 iters ) {
  fd_ed25519_lane_point_t a, r;
  uchar k[8][32], s[8][32], hash_input[8][64+1232], hashes[8][64];
  long start = fd_log_wallclock();
  for( ulong i=0; i<iters; i++ ) {
    FD_TEST( fd_ed25519_lane_decode( &a, pubs )==255 );
    FD_TEST( fd_ed25519_lane_decode( &r, sigs )==255 );
    FD_TEST( !fd_ed25519_lane_small_order( &a ) );
    FD_TEST( !fd_ed25519_lane_small_order( &r ) );
    fd_sha512_batch_t batch[1];
    fd_sha512_batch_init( batch );
    for( int j=0; j<8; j++ ) {
      FD_TEST( fd_curve25519_scalar_validate( sigs[j]+32 ) );
      if( sizes[j]<=1232UL ) {
        fd_memcpy( hash_input[j], sigs[j], 32UL );
        fd_memcpy( hash_input[j]+32, pubs[j], 32UL );
        if( sizes[j] ) fd_memcpy( hash_input[j]+64, msgs[j], sizes[j] );
        fd_sha512_batch_add( batch, hash_input[j], 64UL+sizes[j], hashes[j] );
      } else {
        fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( shas[j] ),
                        sigs[j], 32UL ), pubs[j], 32UL ), msgs[j], sizes[j] ), hashes[j] );
      }
    }
    fd_sha512_batch_fini( batch );
    for( int j=0; j<8; j++ ) {
      fd_curve25519_scalar_reduce( k[j], hashes[j] );
      fd_memcpy( s[j], sigs[j]+32, 32UL );
    }
    fd_ed25519_lane_fe_t zero;
    for( int j=0; j<5; j++ ) zero.limb[j] = wwv_zero();
    fd_ed25519_lane_sub( &a.x, &zero, &a.x );
    fd_ed25519_lane_sub( &a.t, &zero, &a.t );
    FD_COMPILER_MFENCE();
  }
  long prepare = fd_log_wallclock()-start;
  start = fd_log_wallclock();
  for( ulong i=0; i<iters; i++ ) {
    FD_TEST( fd_ed25519_lane_verify( &a, &r, (uchar const (*)[32])k, (uchar const (*)[32])s )==255 );
    FD_COMPILER_MFENCE();
  }
  long core = fd_log_wallclock()-start;
  FD_LOG_NOTICE(( "phase bytes=%4lu count=8 prepare=%9.1f core=%9.1f ns/signature (diagnostic, not end-to-end)",
                   sizes[0], (double)prepare/(double)(iters*8UL), (double)core/(double)(iters*8UL) ));
}
#endif

static void
bench_messages( fd_sha512_t * shas[],
                ulong         iters ) {
  uchar msg[TEST_MAX][1232], sig[TEST_MAX][64], pub[TEST_MAX][32], priv[32];
  uchar const * msgs[TEST_MAX], * sigs[TEST_MAX], * pubs[TEST_MAX];
  ulong sizes[TEST_MAX];
  int results[TEST_MAX];
  ulong lengths[] = { 0UL, 64UL, 256UL, 1232UL };
  ulong counts[] = { 1UL, 2UL, 3UL, 4UL, 5UL, 6UL, 7UL, 8UL, 9UL, 16UL, 33UL };
  FD_LOG_NOTICE(( "multi-message benchmark FD_HAS_AVX512=%d, iterations=%lu (ns/signature = ns/one-signature transaction, crypto API only)", FD_HAS_AVX512, iters ));
  for( ulong l=0; l<sizeof(lengths)/sizeof(lengths[0]); l++ ) {
    for( ulong j=0; j<TEST_MAX; j++ ) {
      fd_memset( priv, (int)j+1, 32UL ); fd_memset( msg[j], (int)j+2, 1232UL );
      msgs[j]=msg[j]; sizes[j]=lengths[l]; sigs[j]=sig[j]; pubs[j]=pub[j];
      fd_ed25519_public_from_private( pub[j], priv, shas[j] );
      fd_ed25519_sign( sig[j], msgs[j], sizes[j], pubs[j], priv, shas[j] );
    }
#if FD_HAS_AVX512
    bench_phases( msgs, sizes, sigs, pubs, shas, iters*4UL );
#endif
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
  fd_rng_t rng_mem[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 0UL ) );
  fd_sha512_t sha_mem[TEST_MAX]; fd_sha512_t * shas[TEST_MAX];
  for( ulong j=0; j<TEST_MAX; j++ ) shas[j] = fd_sha512_join( fd_sha512_new( &sha_mem[j] ) );
  fd_ed25519_verify_batch_multi_msg( NULL, NULL, NULL, NULL, NULL, NULL, 0UL );
#if FD_HAS_AVX512
  test_lane_field( rng );
  test_lane_decode( rng );
  test_lane_group( rng );
#endif
  test_messages( rng, shas );
  test_corpora( shas );
  if( bench ) bench_messages( shas, bench );
  for( ulong j=0; j<TEST_MAX; j++ ) fd_sha512_delete( fd_sha512_leave( shas[j] ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
