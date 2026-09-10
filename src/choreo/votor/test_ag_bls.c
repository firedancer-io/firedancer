#include "ag_bls_serde.h"

#include "../../third_party/blst/bindings/blst.h"

/* Compressed public keys are only needed to exercise the compressed arm
   of fd_bls_pub_try_from_bytes; ag_bls has no compressor of its own. */

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
  fd_memset( &back->sig, 0xAA, sizeof(fd_bls_sig_t) );
  FD_TEST( ag_bls_agg_de( back, buf, sz )==AG_BLS_DE_SUCCESS );
  for( ulong i=0UL; i<FD_BLS_SET_MAX; i++ ) FD_TEST( fd_bls_set_test( back->set, i )==fd_bls_set_test( agg->set, i ) );

  /* a bitmap carries no signature, so decoding clears the one that was there */
  fd_bls_agg_t zero[1]; memset( zero, 0, sizeof(fd_bls_agg_t) );
  FD_TEST( !memcmp( &back->sig, &zero->sig, sizeof(fd_bls_sig_t) ) );

  /* base2 is legal wherever a fallback partition could be: it says the
     fallback set is empty */
  fd_bls_agg_t b[1], f[1];
  FD_TEST( ag_bls_agg_pair_de( b, f, buf, sz )==AG_BLS_DE_SUCCESS );
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
  FD_TEST( ag_bls_agg_pair_de( b, f, buf, sz )==AG_BLS_DE_SUCCESS );
  for( ulong i=0UL; i<FD_BLS_SET_MAX; i++ ) {
    FD_TEST( fd_bls_set_test( b->set, i )==fd_bls_set_test( base->set, i ) );
    FD_TEST( fd_bls_set_test( f->set, i )==fd_bls_set_test( fb->set,   i ) );
  }

  /* only the pair decoder takes base3: a message with a single partition
     has no second signer set to decode into */
  fd_bls_agg_t one[1];
  FD_TEST( ag_bls_agg_de( one, buf, sz )==AG_BLS_DE_ERR_INVAL );
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

  /* short of the framing */

  for( ulong n=0UL; n<AG_BLS_AGG_HDR_SZ; n++ ) {
    FD_TEST( ag_bls_agg_de     ( dst,  buf, n )==AG_BLS_DE_ERR_SZ );
    FD_TEST( ag_bls_agg_pair_de( b, f, buf, n )==AG_BLS_DE_ERR_SZ );
  }

  /* a payload the bit count does not call for */

  FD_TEST( ag_bls_agg_de( dst, buf, sz-1UL )==AG_BLS_DE_ERR_INVAL ); /* too few  */
  FD_TEST( ag_bls_agg_de( dst, buf, sz+1UL )==AG_BLS_DE_ERR_INVAL ); /* trailing */

  /* a version tag that is neither base2 nor base3 */

  uchar bad[ AG_BLS_AGG_PAIR_SER_MAX ];
  fd_memcpy( bad, buf, sz );
  bad[ 0 ] = 2;
  FD_TEST( ag_bls_agg_de     ( dst,  bad, sz )==AG_BLS_DE_ERR_INVAL );
  FD_TEST( ag_bls_agg_pair_de( b, f, bad, sz )==AG_BLS_DE_ERR_INVAL );

  /* a bit count past the signer bound */

  fd_memcpy( bad, buf, sz );
  FD_STORE( ushort, bad+1UL, (ushort)(FD_BLS_SET_MAX+1UL) );
  FD_TEST( ag_bls_agg_de( dst, bad, sz )==AG_BLS_DE_ERR_SZ );

  ulong sz3 = ag_bls_agg_pair_ser( agg, f, bad );
  FD_STORE( ushort, bad+1UL, (ushort)(FD_BLS_SET_MAX+1UL) );
  FD_TEST( ag_bls_agg_pair_de( b, f, bad, sz3 )==AG_BLS_DE_ERR_SZ );

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

    FD_TEST(  fd_bls_agg_verify( pk+i,         &sig[i], msg,  msg_sz ) );
    FD_TEST( !fd_bls_agg_verify( pk+(i+1UL)%N, &sig[i], msg,  msg_sz ) );
    FD_TEST( !fd_bls_agg_verify( pk+i, &sig[i], (uchar const *)"x", 1UL ) );
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
  FD_TEST( fd_bls_agg_verify( &pk, &sig, msg, msg_sz ) );

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
  FD_TEST( !fd_bls_pub_try_from_bytes( &from_comp, comp,        sizeof(comp)     ) );
  uchar aff[ FD_BLS_PUB_SZ ]; { blst_p1_affine a[1]; blst_p1_to_affine( a, pk ); blst_p1_affine_serialize( aff, a ); }
  FD_TEST( !fd_bls_pub_try_from_bytes( &from_aff,  aff,         FD_BLS_PUB_SZ    ) );
  FD_TEST( !memcmp( &from_comp, pk, sizeof(fd_bls_pub_t) ) );
  FD_TEST( !memcmp( &from_aff,  pk, sizeof(fd_bls_pub_t) ) );
  FD_TEST(  fd_bls_pub_try_from_bytes( &from_aff, comp, 47UL ) ); /* bad length */
  uchar junk[ FD_BLS_PUB_COMPRESSED_SZ ]; fd_memset( junk, 0xEE, sizeof(junk) );
  FD_TEST(  fd_bls_pub_try_from_bytes( &from_aff, junk, sizeof(junk) ) ); /* not on curve */

  FD_LOG_NOTICE(( "reference api pass" ));
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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
