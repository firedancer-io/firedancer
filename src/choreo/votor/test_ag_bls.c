#include "ag_bls_serde.h"

#include "../../third_party/blst/bindings/blst.h"

/* Compressed public keys are only needed to exercise the compressed arm
   of fd_bls_pub_de; ag_bls has no compressor of its own. */

static void
pub_compress( uchar                out[ FD_BLS_PUB_COMPRESSED_SZ ],
              fd_bls_pub_t const * pub ) {
  blst_p1_affine a[1];
  blst_p1_to_affine( a, pub );
  blst_p1_affine_compress( out, a );
}

/* Golden bitmap vectors.

   ag_bls_agg_ser and ag_bls_agg_de speak the solana_signer_store bitmap
   that an agave certificate and block footer carry, so the bytes
   themselves are the contract: a ser -> de round trip through our own
   codec agrees with itself even when both halves have drifted off the
   format together, and would not notice.  Every case below states the
   expected bytes outright. */

static void
check_base2( fd_bls_agg_t const * agg,
             uchar const *        exp,
             ulong                exp_sz ) {
  uchar buf[ AG_BLS_AGG_SER_MAX ];
  ulong sz = ag_bls_agg_ser( agg, buf );

  FD_TEST( sz==exp_sz );
  FD_TEST( sz==ag_bls_agg_ser_sz( agg ) );
  FD_TEST( !memcmp( buf, exp, sz ) );

  fd_bls_agg_t back[1];
  fd_memset( &back->sig, 0xAA, sizeof(back->sig) );
  ulong bit_cnt;
  FD_TEST( ag_bls_agg_de( back, &bit_cnt, buf, sz )==AG_BLS_DE_SUCCESS );
  FD_TEST( bit_cnt==fd_ulong_min( FD_BLS_SET_MAX, fd_bls_set_last( agg->set )+1UL ) );
  for( ulong i=0UL; i<FD_BLS_SET_MAX; i++ ) FD_TEST( fd_bls_set_test( back->set, i )==fd_bls_set_test( agg->set, i ) );

  /* a bitmap carries no signature, so decoding clears the one that was there */
  fd_bls_agg_t zero[1]; memset( zero, 0, sizeof(fd_bls_agg_t) );
  FD_TEST( !memcmp( &back->sig, &zero->sig, sizeof(back->sig) ) );

  /* base2 is legal wherever a fallback partition could be: it says the
     fallback set is empty */
  fd_bls_agg_t b[1], f[1];
  FD_TEST( ag_bls_agg_pair_de( b, f, &bit_cnt, buf, sz )==AG_BLS_DE_SUCCESS );
  FD_TEST( !fd_bls_set_cnt( f->set ) );
  for( ulong i=0UL; i<FD_BLS_SET_MAX; i++ ) FD_TEST( fd_bls_set_test( b->set, i )==fd_bls_set_test( agg->set, i ) );
}

static void
check_base3( fd_bls_agg_t const * base,
             fd_bls_agg_t const * fb,
             uchar const *        exp,
             ulong                exp_sz ) {
  uchar buf[ AG_BLS_AGG_PAIR_SER_MAX ];
  ulong sz = ag_bls_agg_pair_ser( base, fb, buf );

  FD_TEST( sz==exp_sz );
  FD_TEST( sz==ag_bls_agg_pair_ser_sz( base, fb ) );
  FD_TEST( !memcmp( buf, exp, sz ) );

  fd_bls_agg_t b[1], f[1];
  ulong bit_cnt;
  FD_TEST( ag_bls_agg_pair_de( b, f, &bit_cnt, buf, sz )==AG_BLS_DE_SUCCESS );
  for( ulong i=0UL; i<FD_BLS_SET_MAX; i++ ) {
    FD_TEST( fd_bls_set_test( b->set, i )==fd_bls_set_test( base->set, i ) );
    FD_TEST( fd_bls_set_test( f->set, i )==fd_bls_set_test( fb->set,   i ) );
  }

  /* only the pair decoder takes base3: a message with a single partition
     has no second signer set to decode into */
  fd_bls_agg_t one[1];
  FD_TEST( ag_bls_agg_de( one, &bit_cnt, buf, sz )==AG_BLS_DE_ERR_INVAL );
}

static void
test_agg_bitmap( void ) {
  fd_bls_agg_t agg[1], fb[1];

  /* nobody signed, so the bitmap is its framing and nothing else */

  memset( agg, 0, sizeof(fd_bls_agg_t) );
  memset( fb,  0, sizeof(fd_bls_agg_t) );
  uchar const empty2[3] = { 0, 0, 0 };
  uchar const empty3[3] = { 1, 0, 0 };
  check_base2( agg, empty2, sizeof(empty2) );
  check_base3( agg, fb, empty3, sizeof(empty3) );

  /* ranks 0..4, one bit to a rank, least significant bit first */

  for( ulong i=0UL; i<5UL; i++ ) fd_bls_set_insert( agg->set, i );
  uchar const five[4] = { 0, 5, 0, 0x1f };
  check_base2( agg, five, sizeof(five) );

  /* the same five in the base partition and ranks 5..8 in the fallback,
     five ranks to a byte: 1+3+9+27+81 == 121, then 2+6+18+54 == 80 */

  for( ulong i=5UL; i<9UL; i++ ) fd_bls_set_insert( fb->set, i );
  uchar const mixed[5] = { 1, 9, 0, 121, 80 };
  check_base3( agg, fb, mixed, sizeof(mixed) );

  /* only ranks 0 and 63, so the count is 64 and the payload is the eight
     bytes that span it -- a bitmap is trimmed, not sparse */

  memset( agg, 0, sizeof(fd_bls_agg_t) );
  fd_bls_set_insert( agg->set, 0UL  );
  fd_bls_set_insert( agg->set, 63UL );
  uchar const sparse[11] = { 0, 64, 0, 0x01, 0, 0, 0, 0, 0, 0, 0x80 };
  check_base2( agg, sparse, sizeof(sparse) );

  /* every rank */

  memset( agg, 0, sizeof(fd_bls_agg_t) );
  fd_bls_set_full( agg->set );
  uchar full2[ AG_BLS_AGG_SER_MAX ];
  full2[ 0 ] = 0; FD_STORE( ushort, full2+1UL, (ushort)FD_BLS_SET_MAX );
  fd_memset( full2+AG_BLS_AGG_HDR_SZ, 0xff, AG_BLS_AGG_SER_MAX-AG_BLS_AGG_HDR_SZ );
  check_base2( agg, full2, AG_BLS_AGG_SER_MAX );

  /* every rank in the base partition: a full byte is 1+3+9+27+81 == 121,
     and 2000 ranks fill 400 of them exactly */

  memset( fb, 0, sizeof(fd_bls_agg_t) );
  ulong const chunks = AG_BLS_AGG_PAIR_SER_MAX-AG_BLS_AGG_HDR_SZ;
  uchar full3[ AG_BLS_AGG_PAIR_SER_MAX ];
  full3[ 0 ] = 1; FD_STORE( ushort, full3+1UL, (ushort)FD_BLS_SET_MAX );
  fd_memset( full3+AG_BLS_AGG_HDR_SZ, 121, chunks );
  check_base3( agg, fb, full3, AG_BLS_AGG_PAIR_SER_MAX );

  /* the partitions interleaved, base on the even ranks and fallback on
     the odd: a byte that starts on an even rank is 1+6+9+54+81 == 151 and
     one that starts on an odd rank is 2+3+18+27+162 == 212 */

  memset( agg, 0, sizeof(fd_bls_agg_t) );
  memset( fb,  0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<FD_BLS_SET_MAX; i++ ) fd_bls_set_insert( (i&1UL) ? fb->set : agg->set, i );
  uchar split3[ AG_BLS_AGG_PAIR_SER_MAX ];
  split3[ 0 ] = 1; FD_STORE( ushort, split3+1UL, (ushort)FD_BLS_SET_MAX );
  for( ulong c=0UL; c<chunks; c++ ) split3[ AG_BLS_AGG_HDR_SZ+c ] = (c&1UL) ? 212 : 151;
  check_base3( agg, fb, split3, AG_BLS_AGG_PAIR_SER_MAX );

  FD_LOG_NOTICE(( "signer set bitmap golden vectors pass" ));
}

static void
test_agg_bitmap_errors( void ) {
  fd_bls_agg_t agg[1], dst[1], b[1], f[1];
  memset( agg, 0, sizeof(fd_bls_agg_t) );
  memset( f,   0, sizeof(fd_bls_agg_t) );
  for( ulong i=0UL; i<5UL; i++ ) fd_bls_set_insert( agg->set, i );

  uchar buf[ AG_BLS_AGG_PAIR_SER_MAX ];
  ulong sz = ag_bls_agg_ser( agg, buf );
  ulong bit_cnt;

  /* short of the framing */

  for( ulong n=0UL; n<AG_BLS_AGG_HDR_SZ; n++ ) {
    FD_TEST( ag_bls_agg_de     ( dst,  &bit_cnt, buf, n )==AG_BLS_DE_ERR_SZ );
    FD_TEST( ag_bls_agg_pair_de( b, f, &bit_cnt, buf, n )==AG_BLS_DE_ERR_SZ );
  }

  /* a payload the bit count does not call for */

  FD_TEST( ag_bls_agg_de( dst, &bit_cnt, buf, sz-1UL )==AG_BLS_DE_ERR_INVAL ); /* too few  */
  FD_TEST( ag_bls_agg_de( dst, &bit_cnt, buf, sz+1UL )==AG_BLS_DE_ERR_INVAL ); /* trailing */

  /* a version tag that is neither base2 nor base3 */

  uchar bad[ AG_BLS_AGG_PAIR_SER_MAX ];
  fd_memcpy( bad, buf, sz );
  bad[ 0 ] = 2;
  FD_TEST( ag_bls_agg_de     ( dst,  &bit_cnt, bad, sz )==AG_BLS_DE_ERR_INVAL );
  FD_TEST( ag_bls_agg_pair_de( b, f, &bit_cnt, bad, sz )==AG_BLS_DE_ERR_INVAL );

  /* a bit count past the signer bound */

  fd_memcpy( bad, buf, sz );
  FD_STORE( ushort, bad+1UL, (ushort)(FD_BLS_SET_MAX+1UL) );
  FD_TEST( ag_bls_agg_de( dst, &bit_cnt, bad, sz )==AG_BLS_DE_ERR_SZ );

  ulong sz3 = ag_bls_agg_pair_ser( agg, f, bad );
  FD_STORE( ushort, bad+1UL, (ushort)(FD_BLS_SET_MAX+1UL) );
  FD_TEST( ag_bls_agg_pair_de( b, f, &bit_cnt, bad, sz3 )==AG_BLS_DE_ERR_SZ );

  FD_LOG_NOTICE(( "signer set bitmap error paths pass" ));
}

/* src/crypto/aggsig.rs::basic, ::aggregate */

static void
test_roundtrip( void ) {
  uchar const msg[]  = "alpenglow round trip";
  ulong       msg_sz = sizeof(msg)-1UL;

  ulong const  N = 5UL;
  fd_bls_sec_t sk [5];
  fd_bls_pub_t pk [5];
  fd_bls_sig_t sig[5];
  for( ulong i=0UL; i<N; i++ ) {
    fd_memset( &sk[i], 0, FD_BLS_SEC_SZ );
    sk[i].b[0] = (uchar)( i+1UL );
    fd_bls_sec_to_pub( &sk[i], pk+i );
    fd_bls_sec_sign ( &sk[i], msg, msg_sz, sig+i );
    blst_p2 one; blst_p2_from_affine( &one, sig+i );

    FD_TEST(  fd_bls_agg_verify( msg,                msg_sz, pk+i,         &one ) );
    FD_TEST( !fd_bls_agg_verify( msg,                msg_sz, pk+(i+1UL)%N, &one ) );
    FD_TEST( !fd_bls_agg_verify( (uchar const *)"x", 1UL,    pk+i,         &one ) );
  }

  FD_LOG_NOTICE(( "blst sig round trip pass" ));
}

static void
test_derive( void ) {
  uchar ikm_a[64]; for( ulong i=0UL; i<64UL; i++ ) ikm_a[i] = (uchar)(i*7u+1u);
  uchar ikm_b[64]; for( ulong i=0UL; i<64UL; i++ ) ikm_b[i] = (uchar)(i*7u+2u);

  fd_bls_sec_t sk_a, sk_a2, sk_b;
  fd_bls_sec_derive( &sk_a,  ikm_a, sizeof(ikm_a) );
  fd_bls_sec_derive( &sk_a2, ikm_a, sizeof(ikm_a) );
  fd_bls_sec_derive( &sk_b,  ikm_b, sizeof(ikm_b) );

  FD_TEST(  !memcmp( &sk_a, &sk_a2, sizeof(fd_bls_sec_t) ) );
  FD_TEST(   memcmp( &sk_a, &sk_b,  sizeof(fd_bls_sec_t) ) );

  fd_bls_pub_t  pk; fd_bls_sec_to_pub( &sk_a, &pk );
  uchar const * msg = (uchar const *)"derived key vote";
  ulong         msg_sz = 16UL;
  fd_bls_sig_t  sig; fd_bls_sec_sign( &sk_a, msg, msg_sz, &sig );
  blst_p2       one; blst_p2_from_affine( &one, &sig );
  FD_TEST( fd_bls_agg_verify( msg, msg_sz, &pk, &one ) );

  FD_LOG_NOTICE(( "bls sk derive round trip pass" ));
}

/* src/crypto/aggsig.rs::verify_without_bitmask, ::signers, PublicKey::try_from_bytes */

static void
test_ref_api( void ) {
  uchar const * msg    = (uchar const *)"reference api";
  ulong         msg_sz = 13UL;
  ulong const   N      = 5UL;

  fd_bls_sec_t sk [5];
  fd_bls_pub_t pk [5];
  fd_bls_sig_t sig[5];
  for( ulong i=0UL; i<N; i++ ) {
    fd_memset( &sk[i], 0, FD_BLS_SEC_SZ );
    sk[i].b[0] = (uchar)( i+1UL );
    fd_bls_sec_to_pub( &sk[i], pk+i );
    fd_bls_sec_sign( &sk[i], msg, msg_sz, &sig[i] );
  }

  /* PublicKey::try_from_bytes -- compressed and affine both round trip */
  uchar comp[ FD_BLS_PUB_COMPRESSED_SZ ];
  pub_compress( comp, pk );
  fd_bls_pub_t from_comp, from_aff;
  FD_TEST( !fd_bls_pub_de( &from_comp, comp,        sizeof(comp)     ) );
  uchar aff[ FD_BLS_PUB_SZ ]; { blst_p1_affine a[1]; blst_p1_to_affine( a, pk ); blst_p1_affine_serialize( aff, a ); }
  FD_TEST( !fd_bls_pub_de( &from_aff,  aff,         FD_BLS_PUB_SZ    ) );
  FD_TEST( !memcmp( &from_comp, pk, sizeof(fd_bls_pub_t) ) );
  FD_TEST( !memcmp( &from_aff,  pk, sizeof(fd_bls_pub_t) ) );
  FD_TEST(  fd_bls_pub_de( &from_aff, comp, 47UL ) ); /* bad length */
  uchar junk[ FD_BLS_PUB_COMPRESSED_SZ ]; fd_memset( junk, 0xEE, sizeof(junk) );
  FD_TEST(  fd_bls_pub_de( &from_aff, junk, sizeof(junk) ) ); /* not on curve */

  FD_LOG_NOTICE(( "reference api pass" ));
}

static void
test_pub_sum( void ) {
  ulong const    N = 64UL;
  blst_p1_affine key[ 64 ];
  fd_bls_sec_t   sk;
  for( ulong i=0UL; i<N; i++ ) {
    fd_memset( &sk, 0, FD_BLS_SEC_SZ );
    sk.b[0] = (uchar)( i+1UL ); sk.b[1] = (uchar)( i*7UL );
    fd_bls_pub_t pk; fd_bls_sec_to_pub( &sk, &pk );
    blst_p1_to_affine( key+i, &pk );
  }
  fd_bls_set_t set[ fd_bls_set_word_cnt ];
  fd_bls_pub_t full[1], bad[1];
  fd_bls_pub_sum( full, key, N, fd_bls_set_range( set, 0UL, N ), NULL );
  fd_bls_pub_sum( bad,  key, N, fd_bls_set_range( set, 1UL, N ), NULL );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 1234U, 0UL ) );
  for( ulong cnt=0UL; cnt<=N; cnt++ ) {
    fd_bls_set_null( set );
    while( fd_bls_set_cnt( set )<cnt ) fd_bls_set_insert( set, fd_rng_ulong_roll( rng, N ) );
    fd_bls_pub_t exp[1], got[1], neg[1];
    fd_memset( exp, 0, sizeof(fd_bls_pub_t) );
    for( ulong i=0UL; i<N; i++ ) if( fd_bls_set_test( set, i ) ) blst_p1_add_or_double_affine( exp, exp, key+i );
    fd_bls_pub_sum( got, key, N, set, full );
    FD_TEST( blst_p1_is_equal( got, exp ) );
    FD_TEST( !!blst_p1_is_inf( got )==!cnt );
    fd_bls_pub_sum( neg, key, N, set, bad );
    FD_TEST( blst_p1_is_equal( neg, exp )==( 2UL*cnt<=N ) ); /* only the subtract path reads full */
  }
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pub sum pass" ));
}

/* fd_bls_agg_verify_bisect must agree with the linear scan for any
   pattern of bad signers: none, one, several straddling the splits,
   the whole set, and a set whose signatures cancel to infinity. */

static void
test_bisect( void ) {
  uchar const * msg    = (uchar const *)"bisect";
  ulong         msg_sz = 6UL;
  ulong const   N      = 100UL;

  fd_bls_sec_t sk  [ 100 ];
  fd_bls_pub_t pk  [ 100 ];
  fd_bls_sig_t good[ 100 ];
  fd_bls_sig_t sig [ 100 ];
  for( ulong i=0UL; i<N; i++ ) {
    fd_memset( &sk[i], 0, FD_BLS_SEC_SZ );
    sk[i].b[0] = (uchar)( i+1UL ); sk[i].b[1] = (uchar)( i*3UL );
    fd_bls_sec_to_pub( &sk[i], pk+i );
    fd_bls_sec_sign( &sk[i], msg, msg_sz, good+i );
  }

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 42U, 0UL ) );
  fd_bls_set_t set[ fd_bls_set_word_cnt ], poison[ fd_bls_set_word_cnt ], exp[ fd_bls_set_word_cnt ], got[ fd_bls_set_word_cnt ];
  for( ulong trial=0UL; trial<40UL; trial++ ) {
    ulong set_cnt = 1UL+fd_rng_ulong_roll( rng, N );
    fd_bls_set_null( set );
    while( fd_bls_set_cnt( set )<set_cnt ) fd_bls_set_insert( set, fd_rng_ulong_roll( rng, N ) );

    /* trial 0: nothing bad, trial 1: everything bad, else a random subset */
    ulong bad_cnt = trial==0UL ? 0UL : trial==1UL ? set_cnt : fd_rng_ulong_roll( rng, set_cnt+1UL );
    fd_bls_set_null( poison );
    while( fd_bls_set_cnt( poison )<bad_cnt ) {
      ulong rank = fd_rng_ulong_roll( rng, N );
      if( fd_bls_set_test( set, rank ) ) fd_bls_set_insert( poison, rank );
    }
    for( ulong i=0UL; i<N; i++ ) sig[i] = fd_bls_set_test( poison, i ) ? good[ (i+1UL)%N ] : good[i];

    fd_bls_agg_t agg[1]; fd_bls_agg_null( agg );
    fd_bls_agg_construct( agg, pk, sig, set );

    fd_bls_agg_verify_linear( agg, msg, msg_sz, pk, sig, exp );
    FD_TEST( fd_bls_set_eq( exp, poison ) );
    fd_bls_agg_verify_bisect( agg, msg, msg_sz, pk, sig, got );
    FD_TEST( fd_bls_set_eq( got, poison ) );

    fd_bls_agg_t sub[1] = { *agg };
    int err = fd_bls_agg_verify_subtract( sub, msg, msg_sz, pk, sig, got );
    FD_TEST( fd_bls_set_eq( got, poison ) );
    FD_TEST( ( err!=0 )==( bad_cnt==set_cnt ) );
    fd_bls_set_subtract( exp, set, poison );
    FD_TEST( fd_bls_set_eq( sub->set, exp ) );
    if( FD_LIKELY( !err ) ) FD_TEST( fd_bls_agg_verify( msg, msg_sz, &sub->pub, &sub->sig ) );
  }

  /* two signers whose bogus signatures cancel: the aggregate sig is the
     point at infinity, so the top level fails without implicating a
     half, and both signers must still be found */
  sig[0] = good[1];
  sig[1] = good[1]; blst_fp2_cneg( &sig[1].y, &sig[1].y, 1 );
  fd_bls_agg_t agg[1]; fd_bls_agg_null( agg );
  fd_bls_agg_construct( agg, pk, sig, fd_bls_set_range( set, 0UL, 2UL ) );
  FD_TEST( blst_p2_is_inf( &agg->sig ) );
  fd_bls_agg_verify_bisect( agg, msg, msg_sz, pk, sig, got );
  FD_TEST( fd_bls_set_eq( got, set ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "bisect pass" ));
}

/* Benchmark the bad-signer search.  N signers of which bad_cnt are
   poisoned; reports the mean cost of one fd_bls_agg_verify_bisect
   call and the linear scan for comparison. */

static void
bench_bisect( ulong N,
              ulong bad_cnt,
              int   scattered,
              fd_bls_pub_t const * pk,
              fd_bls_sig_t const * good,
              fd_bls_sig_t *       sig ) {
  fd_bls_set_t set[ fd_bls_set_word_cnt ], bad[ fd_bls_set_word_cnt ];
  fd_bls_set_range( set, 0UL, N );
  for( ulong i=0UL; i<N; i++ ) sig[i] = good[i];
  /* scattered: bad signers spread evenly across the rank order (worst
     case for the bisect); otherwise clustered at the lowest-stake end
     (the case the stake-sorted descent is tuned for) */
  for( ulong j=0UL; j<bad_cnt; j++ ) {
    ulong i = scattered ? ( j*N )/bad_cnt + N/( 2UL*bad_cnt ) : N-1UL-j;
    sig[i] = good[ (i+1UL)%N ];
  }
  fd_bls_agg_t agg[1]; fd_bls_agg_null( agg );
  fd_bls_agg_construct( agg, pk, sig, set );

  uchar const * msg = (uchar const *)"bisect"; ulong msg_sz = 6UL;
  ulong iter = 5UL;
  long dt_b = fd_log_wallclock();
  for( ulong it=0UL; it<iter; it++ ) fd_bls_agg_verify_bisect( agg, msg, msg_sz, pk, sig, bad );
  dt_b = fd_log_wallclock()-dt_b;
  FD_TEST( fd_bls_set_cnt( bad )==bad_cnt );
  long dt_l = fd_log_wallclock();
  for( ulong it=0UL; it<iter; it++ ) fd_bls_agg_verify_linear( agg, msg, msg_sz, pk, sig, bad );
  dt_l = fd_log_wallclock()-dt_l;
  FD_LOG_NOTICE(( "N=%4lu bad=%3lu %-9s bisect %9.3f ms  linear %9.3f ms", N, bad_cnt, scattered ? "scattered" : "clustered",
                  (double)dt_b/(double)iter*1e-6, (double)dt_l/(double)iter*1e-6 ));
}

static void
test_bench( void ) {
  ulong const N = 1000UL;
  static fd_bls_pub_t pk  [ 1000 ];
  static fd_bls_sig_t good[ 1000 ];
  static fd_bls_sig_t sig [ 1000 ];
  uchar const * msg = (uchar const *)"bisect"; ulong msg_sz = 6UL;
  for( ulong i=0UL; i<N; i++ ) {
    fd_bls_sec_t sk; fd_memset( &sk, 0, FD_BLS_SEC_SZ );
    sk.b[0] = (uchar)( i+1UL ); sk.b[1] = (uchar)( i>>8 ); sk.b[2] = 7;
    fd_bls_sec_to_pub( &sk, pk+i );
    fd_bls_sec_sign( &sk, msg, msg_sz, good+i );
  }
  ulong const bad_cnts[] = { 1UL, 2UL, 8UL, 32UL };
  for( ulong k=0UL; k<sizeof(bad_cnts)/sizeof(bad_cnts[0]); k++ ) {
    bench_bisect( N, bad_cnts[k], 0, pk, good, sig );
    bench_bisect( N, bad_cnts[k], 1, pk, good, sig );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_agg_bitmap();
  test_agg_bitmap_errors();
  test_roundtrip();
  test_derive();
  test_ref_api();
  test_pub_sum();
  test_bisect();
  if( FD_UNLIKELY( fd_env_strip_cmdline_contains( &argc, &argv, "--bench" ) ) ) test_bench();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
