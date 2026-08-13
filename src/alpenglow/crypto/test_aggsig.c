#include "ag_aggsig.h"

FD_FN_UNUSED static void
test_signers( void ) {
  uchar const * msg = (uchar const *)"blst is such a blast";
  ulong         msg_sz = 20UL;

  ag_aggsig_sk_t sk[3];
  ag_aggsig_pk_t pk[3];
  ag_aggsig_sig_t sig[3];
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( sk[i].v, (int)(i+1UL), AG_AGGSIG_SECKEY_SZ );
    ag_aggsig_sk_to_pk( &pk[i], &sk[i] );
    ag_aggsig_sign_bytes( &sig[i], &sk[i], msg, msg_sz );
    FD_TEST( ag_aggsig_individual_verify_bytes( &sig[i], &pk[i], msg, msg_sz ) );
  }

  ag_aggsig_sig_t sigs[2] = { sig[0], sig[2] };
  ulong           idx [2] = { 0UL, 2UL };
  ag_aggsig_t     agg[1];
  ag_aggsig_new( agg, sigs, idx, 2UL, 3UL );

  FD_TEST( ag_aggsig_signer_cnt( agg )==2UL );
  FD_TEST(  ag_aggsig_is_signer( agg, 0UL ) );
  FD_TEST( !ag_aggsig_is_signer( agg, 1UL ) );
  FD_TEST(  ag_aggsig_is_signer( agg, 2UL ) );
  FD_TEST( !ag_aggsig_is_signer( agg, 3UL ) );

  ulong seen = 0UL, cnt = 0UL;
  for( ulong i=voter_set_const_iter_init( agg->bitmask );
       !voter_set_const_iter_done( i );
       i=voter_set_const_iter_next( agg->bitmask, i ) ) {
    seen |= (1UL<<i); cnt++;
  }
  FD_TEST( cnt==2UL );
  FD_TEST( seen==((1UL<<0)|(1UL<<2)) );

  ag_aggsig_pk_t pks[3] = { pk[0], pk[1], pk[2] };
  FD_TEST(  ag_aggsig_verify_bytes( agg, msg, msg_sz, pks->v, sizeof(ag_aggsig_pk_t), 3UL ) );
  FD_TEST( !ag_aggsig_verify_bytes( agg, msg, msg_sz, pks->v, sizeof(ag_aggsig_pk_t), 2UL ) );
}

FD_FN_UNUSED static void
test_incremental( void ) {
  uchar const * msg = (uchar const *)"incremental";
  ag_aggsig_sk_t sk; fd_memset( sk.v, 7, AG_AGGSIG_SECKEY_SZ );
  ag_aggsig_sig_t s; ag_aggsig_sign_bytes( &s, &sk, msg, 11UL );

  ag_aggsig_t agg[1];
  ag_aggsig_init( agg, 8UL );
  FD_TEST( ag_aggsig_signer_cnt( agg )==0UL );
  ag_aggsig_add( agg, 5UL, &s );
  ag_aggsig_add( agg, 1UL, &s );
  FD_TEST( ag_aggsig_signer_cnt( agg )==2UL );
  FD_TEST( ag_aggsig_is_signer( agg, 5UL ) );
  FD_TEST( ag_aggsig_is_signer( agg, 1UL ) );
}

FD_FN_UNUSED static void
test_serde( void ) {

  ulong nbits = 200UL;
  ag_aggsig_sk_t sk; fd_memset( sk.v, 3, AG_AGGSIG_SECKEY_SZ );
  ag_aggsig_sig_t s; ag_aggsig_sign_bytes( &s, &sk, (uchar const *)"x", 1UL );

  ag_aggsig_t agg[1];
  ag_aggsig_init( agg, nbits );
  ulong want[5] = { 0UL, 63UL, 64UL, 130UL, 199UL };
  for( ulong i=0UL; i<5UL; i++ ) ag_aggsig_add( agg, want[i], &s );

  uchar buf[ AG_AGGSIG_SERIALIZED_MAX ];
  ulong sz = ag_aggsig_serialize( agg, buf, sizeof(buf) );
  FD_TEST( sz==AG_AGGSIG_SERIALIZED_SZ( nbits ) );

  ag_aggsig_t back[1];
  ulong consumed = ag_aggsig_deserialize( back, buf, sz );
  FD_TEST( consumed==sz );
  FD_TEST( back->nbits==nbits );
  FD_TEST( !memcmp( back->sig, agg->sig, AG_AGGSIG_SIG_SZ ) );
  for( ulong i=0UL; i<nbits; i++ ) FD_TEST( ag_aggsig_is_signer( back, i )==ag_aggsig_is_signer( agg, i ) );
  FD_TEST( ag_aggsig_signer_cnt( back )==5UL );

  FD_TEST( ag_aggsig_deserialize( back, buf, sz-1UL )==0UL );

  uchar bad[ AG_AGGSIG_SERIALIZED_MAX ];
  fd_memcpy( bad, buf, sz );
  FD_STORE( ulong, bad+AG_AGGSIG_SIG_SZ+8UL, 1000UL );
  FD_TEST( ag_aggsig_deserialize( back, bad, sz )==0UL );
}

static void
test_roundtrip( void ) {
  uchar const msg[]  = "alpenglow round trip";
  ulong       msg_sz = sizeof(msg)-1UL;

  ulong const      N = 5UL;
  ag_aggsig_sk_t   sk [5];
  ag_aggsig_pk_t   pk [5];
  ag_aggsig_sig_t  sig[5];
  for( ulong i=0UL; i<N; i++ ) {
    fd_memset( sk[i].v, 0, AG_AGGSIG_SECKEY_SZ );
    sk[i].v[0] = (uchar)( i+1UL );
    ag_aggsig_sk_to_pk  ( &pk[i], &sk[i] );
    ag_aggsig_sign_bytes( &sig[i], &sk[i], msg, msg_sz );

    FD_TEST(  ag_aggsig_individual_verify_bytes( &sig[i], &pk[i],          msg,  msg_sz ) );
    FD_TEST( !ag_aggsig_individual_verify_bytes( &sig[i], &pk[(i+1UL)%N],  msg,  msg_sz ) );
    FD_TEST( !ag_aggsig_individual_verify_bytes( &sig[i], &pk[i], (uchar const *)"x", 1UL ) );
  }

  ag_aggsig_pk_t pks[5] = { pk[0], pk[1], pk[2], pk[3], pk[4] };

  ag_aggsig_sig_t sigs[3] = { sig[0], sig[2], sig[4] };
  ulong           idx [3] = { 0UL, 2UL, 4UL };
  ag_aggsig_t     agg[1];
  ag_aggsig_new( agg, sigs, idx, 3UL, N );

  FD_TEST( ag_aggsig_verify_bytes( agg, msg, msg_sz, pks->v, sizeof(ag_aggsig_pk_t), N ) );

  FD_TEST( !ag_aggsig_verify_bytes( agg, (uchar const *)"different message", 17UL, pks->v, sizeof(ag_aggsig_pk_t), N ) );

  ag_aggsig_t tampered = *agg;
  tampered.sig[0] = (uchar)( tampered.sig[0] ^ 0xFFu );
  FD_TEST( !ag_aggsig_verify_bytes( &tampered, msg, msg_sz, pks->v, sizeof(ag_aggsig_pk_t), N ) );

  ag_aggsig_pk_t pks_wrong[5] = { pk[1], pk[1], pk[2], pk[3], pk[4] };
  FD_TEST( !ag_aggsig_verify_bytes( agg, msg, msg_sz, pks_wrong->v, sizeof(ag_aggsig_pk_t), N ) );

  ag_aggsig_t mismatch = *agg;
  voter_set_remove( mismatch.bitmask, 4UL );
  FD_TEST( ag_aggsig_signer_cnt( &mismatch )==2UL );
  FD_TEST( !ag_aggsig_verify_bytes( &mismatch, msg, msg_sz, pks->v, sizeof(ag_aggsig_pk_t), N ) );

  FD_TEST( !ag_aggsig_verify_bytes( agg, msg, msg_sz, pks->v, sizeof(ag_aggsig_pk_t), N-1UL ) );

  ag_aggsig_t     agg_all[1];
  ulong           idx_all[5] = { 0UL, 1UL, 2UL, 3UL, 4UL };
  ag_aggsig_new( agg_all, sig, idx_all, N, N );
  FD_TEST( ag_aggsig_verify_bytes( agg_all, msg, msg_sz, pks->v, sizeof(ag_aggsig_pk_t), N ) );

  FD_LOG_NOTICE(( "blst aggsig round trip pass" ));
}

static void
test_derive( void ) {
  uchar ikm_a[64]; for( ulong i=0UL; i<64UL; i++ ) ikm_a[i] = (uchar)(i*7u+1u);
  uchar ikm_b[64]; for( ulong i=0UL; i<64UL; i++ ) ikm_b[i] = (uchar)(i*7u+2u);

  ag_aggsig_sk_t sk_a[1], sk_a2[1], sk_b[1];
  ag_aggsig_sk_derive( sk_a,  ikm_a, sizeof(ikm_a) );
  ag_aggsig_sk_derive( sk_a2, ikm_a, sizeof(ikm_a) );
  ag_aggsig_sk_derive( sk_b,  ikm_b, sizeof(ikm_b) );

  FD_TEST(  !memcmp( sk_a->v, sk_a2->v, AG_AGGSIG_SECKEY_SZ ) );
  FD_TEST(   memcmp( sk_a->v, sk_b->v,  AG_AGGSIG_SECKEY_SZ ) );

  ag_aggsig_pk_t  pk[1]; ag_aggsig_sk_to_pk( pk, sk_a );
  uchar const *   msg = (uchar const *)"derived key vote";
  ulong           msg_sz = 16UL;
  ag_aggsig_sig_t sig[1]; ag_aggsig_sign_bytes( sig, sk_a, msg, msg_sz );
  FD_TEST( ag_aggsig_individual_verify_bytes( sig, pk, msg, msg_sz ) );

  FD_LOG_NOTICE(( "aggsig derive round trip pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  (void) test_signers;
  (void) test_incremental;
  (void) test_serde;

  test_roundtrip();
  test_derive();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
