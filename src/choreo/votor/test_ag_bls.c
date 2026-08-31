#include "ag_bls_serde.h"

#include "../../third_party/blst/bindings/blst.h"

/* Compressed public keys are only needed to exercise the compressed arm
   of ag_bls_pub_try_from_bytes; ag_bls has no compressor of its own. */

static void
pub_compress( uchar              out[ AG_BLS_PUB_COMPRESSED_SZ ],
              ag_bls_pub_t const pub ) {
  blst_p1_affine a[1];
  FD_TEST( blst_p1_deserialize( a, pub )==BLST_SUCCESS );
  blst_p1_affine_compress( out, a );
}

/* ag_bls_pub_t / ag_bls_sig_t are array typedefs, so they have no value
   semantics -- gather them explicitly rather than by brace initialiser. */

static void
pick_pub( ag_bls_pub_t * dst,
          ag_bls_pub_t * src,
          ulong const *  sel,
          ulong          cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) memcpy( dst[i], src[ sel[i] ], AG_BLS_PUB_SZ );
}

static void
pick_sig( ag_bls_sig_t * dst,
          ag_bls_sig_t * src,
          ulong const *  sel,
          ulong          cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) memcpy( dst[i], src[ sel[i] ], AG_BLS_SIG_SZ );
}

/* src/crypto/aggsig.rs::signers */

FD_FN_UNUSED static void
test_signers( void ) {
  uchar const * msg = (uchar const *)"blst is such a blast";
  ulong         msg_sz = 20UL;

  ag_bls_sec_t sk[3];
  ag_bls_pub_t pk[3];
  ag_bls_sig_t sig[3];
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( sk[i], (int)(i+1UL), AG_BLS_SEC_SZ );
    ag_bls_sec_to_pub( sk[i], pk[i] );
    ag_bls_sec_sign( sk[i], sig[i], msg, msg_sz );
    FD_TEST( ag_bls_sig_verify( sig[i], pk[i], msg, msg_sz ) );
  }

  ag_bls_sig_t sigs[2];
  { ulong _sel[2] = { 0UL, 2UL }; pick_sig( sigs, sig, _sel, 2UL ); }
  ulong        idx [2] = { 0UL, 2UL };
  ag_bls_agg_t agg[1];
  ag_bls_agg_zero( agg );
  for( ulong i=0UL; i<2UL; i++ ) ag_bls_agg_add( agg, idx[i], sigs[i] );

  FD_TEST( ag_bls_agg_signer_cnt( agg )==2UL );
  FD_TEST(  ag_bls_agg_is_signer( agg, 0UL ) );
  FD_TEST( !ag_bls_agg_is_signer( agg, 1UL ) );
  FD_TEST(  ag_bls_agg_is_signer( agg, 2UL ) );
  FD_TEST( !ag_bls_agg_is_signer( agg, 3UL ) );

  ulong seen = 0UL, cnt = 0UL;
  for( ulong i=signer_set_const_iter_init( agg->bitmask );
       !signer_set_const_iter_done( i );
       i=signer_set_const_iter_next( agg->bitmask, i ) ) {
    seen |= (1UL<<i); cnt++;
  }
  FD_TEST( cnt==2UL );
  FD_TEST( seen==((1UL<<0)|(1UL<<2)) );

  ag_bls_pub_t pks[3];
  { ulong _sel[3] = { 0UL, 1UL, 2UL }; pick_pub( pks, pk, _sel, 3UL ); }
  FD_TEST(  ag_bls_agg_verify( agg, msg, msg_sz, pks[0], sizeof(ag_bls_pub_t), 3UL ) );
  FD_TEST( !ag_bls_agg_verify( agg, msg, msg_sz, pks[0], sizeof(ag_bls_pub_t), 2UL ) );
}

FD_FN_UNUSED static void
test_incremental( void ) {
  uchar const * msg = (uchar const *)"incremental";
  ag_bls_sec_t  sk; fd_memset( sk, 7, AG_BLS_SEC_SZ );
  ag_bls_sig_t  s; ag_bls_sec_sign( sk, s, msg, 11UL );

  ag_bls_agg_t agg[1];
  ag_bls_agg_zero( agg );
  FD_TEST( ag_bls_agg_signer_cnt( agg )==0UL );
  ag_bls_agg_add( agg, 5UL, s );
  ag_bls_agg_add( agg, 1UL, s );
  FD_TEST( ag_bls_agg_signer_cnt( agg )==2UL );
  FD_TEST( ag_bls_agg_is_signer( agg, 5UL ) );
  FD_TEST( ag_bls_agg_is_signer( agg, 1UL ) );
}

FD_FN_UNUSED static void
test_serde( void ) {
  ulong        bits  = 200UL;
  ag_bls_sec_t sk; fd_memset( sk, 3, AG_BLS_SEC_SZ );
  ag_bls_sig_t s; ag_bls_sec_sign( sk, s, (uchar const *)"x", 1UL );

  ag_bls_agg_t agg[1];
  ag_bls_agg_zero( agg );
  ulong want[5] = { 0UL, 63UL, 64UL, 130UL, 199UL };
  for( ulong i=0UL; i<5UL; i++ ) ag_bls_agg_add( agg, want[i], s );

  uchar buf[ AG_BLS_SER_MAX ];
  ulong sz;
  sz = ag_bls_ser( agg, buf );
  FD_TEST( sz==AG_BLS_SER_SZ( bits ) );

  ag_bls_agg_t back[1];
  FD_TEST( ag_bls_de( back, buf, sz )==AG_BLS_DE_SUCCESS );
  FD_TEST( !memcmp( back->sig, agg->sig, AG_BLS_SIG_SZ ) );
  for( ulong i=0UL; i<bits; i++ ) FD_TEST( ag_bls_agg_is_signer( back, i )==ag_bls_agg_is_signer( agg, i ) );
  FD_TEST( ag_bls_agg_signer_cnt( back )==5UL );

  FD_TEST( ag_bls_de( back, buf, sz-1UL )==AG_BLS_DE_ERR_SZ ); /* too few  */
    FD_TEST( ag_bls_de( back, buf, sz+1UL )==AG_BLS_DE_ERR_SZ ); /* trailing */

  uchar bad[ AG_BLS_SER_MAX ];
  fd_memcpy( bad, buf, sz );
  FD_STORE( ulong, bad+AG_BLS_SIG_SZ+8UL, 1000UL );
  FD_TEST( ag_bls_de( back, bad, sz )==AG_BLS_DE_ERR_SZ );
}

/* src/crypto/aggsig.rs::basic, ::aggregate */

static void
test_roundtrip( void ) {
  uchar const msg[]  = "alpenglow round trip";
  ulong       msg_sz = sizeof(msg)-1UL;

  ulong const  N = 5UL;
  ag_bls_sec_t sk [5];
  ag_bls_pub_t pk [5];
  ag_bls_sig_t sig[5];
  for( ulong i=0UL; i<N; i++ ) {
    fd_memset( sk[i], 0, AG_BLS_SEC_SZ );
    sk[i][0] = (uchar)( i+1UL );
    ag_bls_sec_to_pub( sk[i], pk[i] );
    ag_bls_sec_sign ( sk[i], sig[i], msg, msg_sz );

    FD_TEST(  ag_bls_sig_verify( sig[i], pk[i],          msg,  msg_sz ) );
    FD_TEST( !ag_bls_sig_verify( sig[i], pk[(i+1UL)%N],  msg,  msg_sz ) );
    FD_TEST( !ag_bls_sig_verify( sig[i], pk[i], (uchar const *)"x", 1UL ) );
  }

  ag_bls_pub_t pks[5];
  { ulong _sel[5] = { 0UL, 1UL, 2UL, 3UL, 4UL }; pick_pub( pks, pk, _sel, 5UL ); }

  ag_bls_sig_t sigs[3];
  { ulong _sel[3] = { 0UL, 2UL, 4UL }; pick_sig( sigs, sig, _sel, 3UL ); }
  ulong        idx [3] = { 0UL, 2UL, 4UL };
  ag_bls_agg_t agg[1];
  ag_bls_agg_zero( agg );
  for( ulong i=0UL; i<3UL; i++ ) ag_bls_agg_add( agg, idx[i], sigs[i] );

  FD_TEST( ag_bls_agg_verify( agg, msg, msg_sz, pks[0], sizeof(ag_bls_pub_t), N ) );

  FD_TEST( !ag_bls_agg_verify( agg, (uchar const *)"different message", 17UL, pks[0], sizeof(ag_bls_pub_t), N ) );

  ag_bls_agg_t tampered = *agg;
  tampered.sig[0] = (uchar)( tampered.sig[0] ^ 0xFFu );
  FD_TEST( !ag_bls_agg_verify( &tampered, msg, msg_sz, pks[0], sizeof(ag_bls_pub_t), N ) );

  ag_bls_pub_t pks_wrong[5];
  { ulong _sel[5] = { 1UL, 1UL, 2UL, 3UL, 4UL }; pick_pub( pks_wrong, pk, _sel, 5UL ); }
  FD_TEST( !ag_bls_agg_verify( agg, msg, msg_sz, pks_wrong[0], sizeof(ag_bls_pub_t), N ) );

  ag_bls_agg_t mismatch = *agg;
  signer_set_remove( mismatch.bitmask, 4UL );
  FD_TEST( ag_bls_agg_signer_cnt( &mismatch )==2UL );
  FD_TEST( !ag_bls_agg_verify( &mismatch, msg, msg_sz, pks[0], sizeof(ag_bls_pub_t), N ) );

  FD_TEST( !ag_bls_agg_verify( agg, msg, msg_sz, pks[0], sizeof(ag_bls_pub_t), N-1UL ) );

  ag_bls_agg_t agg_all[1];
  ulong        idx_all[5] = { 0UL, 1UL, 2UL, 3UL, 4UL };
  ag_bls_agg_zero( agg_all );
  for( ulong i=0UL; i<N; i++ ) ag_bls_agg_add( agg_all, idx_all[i], sig[i] );
  FD_TEST( ag_bls_agg_verify( agg_all, msg, msg_sz, pks[0], sizeof(ag_bls_pub_t), N ) );

  FD_LOG_NOTICE(( "blst agg sig round trip pass" ));
}

static void
test_derive( void ) {
  uchar ikm_a[64]; for( ulong i=0UL; i<64UL; i++ ) ikm_a[i] = (uchar)(i*7u+1u);
  uchar ikm_b[64]; for( ulong i=0UL; i<64UL; i++ ) ikm_b[i] = (uchar)(i*7u+2u);

  ag_bls_sec_t sk_a, sk_a2, sk_b;
  ag_bls_sec_derive( sk_a,  ikm_a, sizeof(ikm_a) );
  ag_bls_sec_derive( sk_a2, ikm_a, sizeof(ikm_a) );
  ag_bls_sec_derive( sk_b,  ikm_b, sizeof(ikm_b) );

  FD_TEST(  !memcmp( sk_a, sk_a2, AG_BLS_SEC_SZ ) );
  FD_TEST(   memcmp( sk_a, sk_b,  AG_BLS_SEC_SZ ) );

  ag_bls_pub_t  pk; ag_bls_sec_to_pub( sk_a, pk );
  uchar const * msg = (uchar const *)"derived key vote";
  ulong         msg_sz = 16UL;
  ag_bls_sig_t  sig; ag_bls_sec_sign( sk_a, sig, msg, msg_sz );
  FD_TEST( ag_bls_sig_verify( sig, pk, msg, msg_sz ) );

  FD_LOG_NOTICE(( "bls sk derive round trip pass" ));
}

/* src/crypto/aggsig.rs::verify_without_bitmask, ::signers, PublicKey::try_from_bytes */

static void
test_ref_api( void ) {
  uchar const * msg    = (uchar const *)"reference api";
  ulong         msg_sz = 13UL;
  ulong const   N      = 5UL;

  ag_bls_sec_t sk [5];
  ag_bls_pub_t pk [5];
  ag_bls_sig_t sig[5];
  for( ulong i=0UL; i<N; i++ ) {
    fd_memset( sk[i], 0, AG_BLS_SEC_SZ );
    sk[i][0] = (uchar)( i+1UL );
    ag_bls_sec_to_pub   ( sk[i], pk[i] );
    ag_bls_sec_sign( sk[i], sig[i], msg, msg_sz );
  }

  /* PublicKey::try_from_bytes -- compressed and affine both round trip */
  uchar comp[ AG_BLS_PUB_COMPRESSED_SZ ];
  pub_compress( comp, pk[0] );
  ag_bls_pub_t from_comp, from_aff;
  FD_TEST( !ag_bls_pub_try_from_bytes( from_comp, comp,    sizeof(comp)        ) );
  FD_TEST( !ag_bls_pub_try_from_bytes( from_aff,  pk[0], AG_BLS_PUB_SZ    ) );
  FD_TEST( !memcmp( from_comp, pk[0], AG_BLS_PUB_SZ ) );
  FD_TEST( !memcmp( from_aff,  pk[0], AG_BLS_PUB_SZ ) );
  FD_TEST(  ag_bls_pub_try_from_bytes( from_aff, comp, 47UL ) ); /* bad length */
  uchar junk[ AG_BLS_PUB_COMPRESSED_SZ ]; fd_memset( junk, 0xEE, sizeof(junk) );
  FD_TEST(  ag_bls_pub_try_from_bytes( from_aff, junk, sizeof(junk) ) ); /* not on curve */

  /* aggregate over signers {0,2,4} */
  ag_bls_sig_t sigs[3];
  { ulong _sel[3] = { 0UL, 2UL, 4UL }; pick_sig( sigs, sig, _sel, 3UL ); }
  ulong        idx [3] = { 0UL, 2UL, 4UL };
  ag_bls_agg_t agg[1];
  ag_bls_agg_zero( agg );
  for( ulong i=0UL; i<3UL; i++ ) ag_bls_agg_add( agg, idx[i], sigs[i] );

  /* signers() iteration agrees with is_signer */
  ulong seen = 0UL, cnt = 0UL;
  for( ulong i=ag_bls_agg_signers_iter_init( agg );
       !ag_bls_agg_signers_iter_done( i );
       i=ag_bls_agg_signers_iter_next( agg, i ) ) { seen |= 1UL<<i; cnt++; }
  FD_TEST( cnt==3UL );
  FD_TEST( seen==((1UL<<0)|(1UL<<2)|(1UL<<4)) );
  FD_TEST( cnt==ag_bls_agg_signer_cnt( agg ) );
  for( ulong i=0UL; i<N; i++ ) FD_TEST( ag_bls_agg_is_signer( agg, i )==(int)!!(seen&(1UL<<i)) );

  /* verify_without_bitmask: caller supplies exactly the signers' keys */
  ag_bls_pub_t signer_pk[3];
  { ulong _sel[3] = { 0UL, 2UL, 4UL }; pick_pub( signer_pk, pk, _sel, 3UL ); }
  FD_TEST( ag_bls_agg_verify_without_bitmask( agg, msg, msg_sz, signer_pk[0], sizeof(ag_bls_pub_t), 3UL ) );
  /* wrong count -> reject */
  FD_TEST( !ag_bls_agg_verify_without_bitmask( agg, msg, msg_sz, signer_pk[0], sizeof(ag_bls_pub_t), 2UL ) );
  /* wrong keys -> reject */
  ag_bls_pub_t wrong_pk[3];
  { ulong _sel[3] = { 1UL, 2UL, 4UL }; pick_pub( wrong_pk, pk, _sel, 3UL ); }
  FD_TEST( !ag_bls_agg_verify_without_bitmask( agg, msg, msg_sz, wrong_pk[0], sizeof(ag_bls_pub_t), 3UL ) );

  ag_bls_pub_t all_pk[5];
  { ulong _sel[5] = { 0UL, 1UL, 2UL, 3UL, 4UL }; pick_pub( all_pk, pk, _sel, 5UL ); }
  FD_TEST(  ag_bls_agg_verify( agg, msg, msg_sz, all_pk[0], sizeof(ag_bls_pub_t), N     ) );
  /* a bitmask wider than the key set is still a hard reject */
  FD_TEST( !ag_bls_agg_verify( agg, msg, msg_sz, all_pk[0], sizeof(ag_bls_pub_t), N-1UL ) );

  /* Regression: wire certs carry a TRIMMED bit count (ag_signer_store
     trimmed width = highest rank rank + 1), so it is routinely below the
     epoch validator count.  Rejecting that -- as aggsig.rs' strict
     bitmask.len()==pks.len() would -- discards almost every real cert. */
  ag_bls_sig_t tsigs[2];
  { ulong _sel[2] = { 0UL, 1UL }; pick_sig( tsigs, sig, _sel, 2UL ); }
  ulong        tidx [2] = { 0UL, 1UL };
  ag_bls_agg_t trimmed[1];
  ag_bls_agg_zero( trimmed );
  for( ulong i=0UL; i<2UL; i++ ) ag_bls_agg_add( trimmed, tidx[i], tsigs[i] );
  FD_TEST( ag_bls_agg_verify( trimmed, msg, msg_sz, all_pk[0], sizeof(ag_bls_pub_t), N ) );

  FD_LOG_NOTICE(( "reference api pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_signers();
  test_incremental();
  test_serde();
  test_roundtrip();
  test_derive();
  test_ref_api();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
