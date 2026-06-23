#include "fd_aggsig.h"

/* Mirrors the structural parts of alpenglow/src/crypto/aggsig.rs mod tests
   that do not depend on real BLS crypto (the stub accepts all valid-shaped
   verifications).  Covers: aggregate construction, is_signer, signer
   enumeration, the bitmask-length check in verify, and wincode round-trip. */

FD_FN_UNUSED static void
test_signers( void ) {
  uchar const * msg = (uchar const *)"blst is such a blast";
  ulong         msg_sz = 20UL;

  fd_aggsig_sk_t sk[3];
  fd_aggsig_pk_t pk[3];
  fd_aggsig_sig_t sig[3];
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( sk[i].v, (int)(i+1UL), FD_AGGSIG_SECKEY_SZ );
    fd_aggsig_sk_to_pk( &pk[i], &sk[i] );
    fd_aggsig_sign_bytes( &sig[i], &sk[i], msg, msg_sz );
    FD_TEST( fd_aggsig_individual_verify_bytes( &sig[i], &pk[i], msg, msg_sz ) );
  }

  /* aggregate over 2/3 signatures: indices {0,2}, nbits 3 */
  fd_aggsig_sig_t sigs[2] = { sig[0], sig[2] };
  ulong           idx [2] = { 0UL, 2UL };
  fd_aggsig_t     agg[1];
  fd_aggsig_new( agg, sigs, idx, 2UL, 3UL );

  FD_TEST( fd_aggsig_signer_cnt( agg )==2UL );
  FD_TEST(  fd_aggsig_is_signer( agg, 0UL ) );
  FD_TEST( !fd_aggsig_is_signer( agg, 1UL ) );
  FD_TEST(  fd_aggsig_is_signer( agg, 2UL ) );
  FD_TEST( !fd_aggsig_is_signer( agg, 3UL ) ); /* out of range */

  /* enumerate signers via the underlying set iterator */
  ulong seen = 0UL, cnt = 0UL;
  for( ulong i=signer_set_const_iter_init( agg->bitmask );
       !signer_set_const_iter_done( i );
       i=signer_set_const_iter_next( agg->bitmask, i ) ) {
    seen |= (1UL<<i); cnt++;
  }
  FD_TEST( cnt==2UL );
  FD_TEST( seen==((1UL<<0)|(1UL<<2)) );

  /* verify: bitmask length (nbits) must equal pk_cnt */
  fd_aggsig_pk_t pks[3] = { pk[0], pk[1], pk[2] };
  FD_TEST(  fd_aggsig_verify_bytes( agg, msg, msg_sz, pks, 3UL ) ); /* nbits==3 */
  FD_TEST( !fd_aggsig_verify_bytes( agg, msg, msg_sz, pks, 2UL ) ); /* length mismatch */
}

FD_FN_UNUSED static void
test_incremental( void ) {
  uchar const * msg = (uchar const *)"incremental";
  fd_aggsig_sk_t sk; fd_memset( sk.v, 7, FD_AGGSIG_SECKEY_SZ );
  fd_aggsig_sig_t s; fd_aggsig_sign_bytes( &s, &sk, msg, 11UL );

  fd_aggsig_t agg[1];
  fd_aggsig_init( agg, 8UL );
  FD_TEST( fd_aggsig_signer_cnt( agg )==0UL );
  fd_aggsig_add( agg, 5UL, &s );
  fd_aggsig_add( agg, 1UL, &s );
  FD_TEST( fd_aggsig_signer_cnt( agg )==2UL );
  FD_TEST( fd_aggsig_is_signer( agg, 5UL ) );
  FD_TEST( fd_aggsig_is_signer( agg, 1UL ) );
}

FD_FN_UNUSED static void
test_serde( void ) {
  /* build an aggregate with assorted signers across word boundaries */
  ulong nbits = 200UL;
  fd_aggsig_sk_t sk; fd_memset( sk.v, 3, FD_AGGSIG_SECKEY_SZ );
  fd_aggsig_sig_t s; fd_aggsig_sign_bytes( &s, &sk, (uchar const *)"x", 1UL );

  fd_aggsig_t agg[1];
  fd_aggsig_init( agg, nbits );
  ulong want[5] = { 0UL, 63UL, 64UL, 130UL, 199UL };
  for( ulong i=0UL; i<5UL; i++ ) fd_aggsig_add( agg, want[i], &s );

  uchar buf[ FD_AGGSIG_SERIALIZED_MAX ];
  ulong sz = fd_aggsig_serialize( agg, buf, sizeof(buf) );
  FD_TEST( sz==FD_AGGSIG_SERIALIZED_SZ( nbits ) );

  fd_aggsig_t back[1];
  ulong consumed = fd_aggsig_deserialize( back, buf, sz );
  FD_TEST( consumed==sz );
  FD_TEST( back->nbits==nbits );
  FD_TEST( !memcmp( back->sig, agg->sig, FD_AGGSIG_SIG_SZ ) );
  for( ulong i=0UL; i<nbits; i++ ) FD_TEST( fd_aggsig_is_signer( back, i )==fd_aggsig_is_signer( agg, i ) );
  FD_TEST( fd_aggsig_signer_cnt( back )==5UL );

  /* truncated input fails */
  FD_TEST( fd_aggsig_deserialize( back, buf, sz-1UL )==0UL );
  /* declared num_words too large fails */
  uchar bad[ FD_AGGSIG_SERIALIZED_MAX ];
  fd_memcpy( bad, buf, sz );
  FD_STORE( ulong, bad+FD_AGGSIG_SIG_SZ+8UL, 1000UL ); /* num_words huge */
  FD_TEST( fd_aggsig_deserialize( back, bad, sz )==0UL );
}


/* test_roundtrip exercises the real BLS path end-to-end: derive keys, sign a
   common message, aggregate a subset, and assert fd_aggsig_verify_bytes
   accepts the honest aggregate and rejects every corruption.  Only valid with
   real crypto (the stub accepts everything, so the negative cases would
   fail). */

static void
test_roundtrip( void ) {
  uchar const msg[]  = "alpenglow round trip";
  ulong       msg_sz = sizeof(msg)-1UL;

  ulong const      N = 5UL; /* validator set size == bitmask nbits */
  fd_aggsig_sk_t   sk [5];
  fd_aggsig_pk_t   pk [5];
  fd_aggsig_sig_t  sig[5];
  for( ulong i=0UL; i<N; i++ ) {
    fd_memset( sk[i].v, 0, FD_AGGSIG_SECKEY_SZ );
    sk[i].v[0] = (uchar)( i+1UL ); /* distinct small (valid) scalars */
    fd_aggsig_sk_to_pk  ( &pk[i], &sk[i] );
    fd_aggsig_sign_bytes( &sig[i], &sk[i], msg, msg_sz );

    /* individual verify: right key+msg accepts; wrong key or wrong msg rejects */
    FD_TEST(  fd_aggsig_individual_verify_bytes( &sig[i], &pk[i],          msg,  msg_sz ) );
    FD_TEST( !fd_aggsig_individual_verify_bytes( &sig[i], &pk[(i+1UL)%N],  msg,  msg_sz ) );
    FD_TEST( !fd_aggsig_individual_verify_bytes( &sig[i], &pk[i], (uchar const *)"x", 1UL ) );
  }

  fd_aggsig_pk_t pks[5] = { pk[0], pk[1], pk[2], pk[3], pk[4] };

  /* aggregate the subset {0,2,4} and verify against the full pubkey array */
  fd_aggsig_sig_t sigs[3] = { sig[0], sig[2], sig[4] };
  ulong           idx [3] = { 0UL, 2UL, 4UL };
  fd_aggsig_t     agg[1];
  fd_aggsig_new( agg, sigs, idx, 3UL, N );

  /* positive: honest aggregate verifies */
  FD_TEST( fd_aggsig_verify_bytes( agg, msg, msg_sz, pks, N ) );

  /* negative: wrong message */
  FD_TEST( !fd_aggsig_verify_bytes( agg, (uchar const *)"different message", 17UL, pks, N ) );

  /* negative: tampered aggregate signature point */
  fd_aggsig_t tampered = *agg;
  tampered.sig[0] = (uchar)( tampered.sig[0] ^ 0xFFu );
  FD_TEST( !fd_aggsig_verify_bytes( &tampered, msg, msg_sz, pks, N ) );

  /* negative: a signer's pubkey is wrong (pk[0] replaced) */
  fd_aggsig_pk_t pks_wrong[5] = { pk[1], pk[1], pk[2], pk[3], pk[4] };
  FD_TEST( !fd_aggsig_verify_bytes( agg, msg, msg_sz, pks_wrong, N ) );

  /* negative: bitmask disagrees with the aggregated signatures.  Drop signer 4
     from the mask (sig still covers {0,2,4}); aggregating pk{0,2} no longer
     matches the signature. */
  fd_aggsig_t mismatch = *agg;
  signer_set_remove( mismatch.bitmask, 4UL );
  FD_TEST( fd_aggsig_signer_cnt( &mismatch )==2UL );
  FD_TEST( !fd_aggsig_verify_bytes( &mismatch, msg, msg_sz, pks, N ) );

  /* negative: bitmask length must equal pk_cnt */
  FD_TEST( !fd_aggsig_verify_bytes( agg, msg, msg_sz, pks, N-1UL ) );

  /* full-set aggregate also verifies */
  fd_aggsig_t     agg_all[1];
  ulong           idx_all[5] = { 0UL, 1UL, 2UL, 3UL, 4UL };
  fd_aggsig_new( agg_all, sig, idx_all, N, N );
  FD_TEST( fd_aggsig_verify_bytes( agg_all, msg, msg_sz, pks, N ) );

  FD_LOG_NOTICE(( "blst aggsig round trip pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  (void) test_signers;
  (void) test_incremental;
  (void) test_serde;
  //test_signers();
  //test_incremental();
  //test_serde();
  test_roundtrip();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
