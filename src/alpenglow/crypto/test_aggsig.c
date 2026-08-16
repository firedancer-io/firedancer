#include "ag_aggsig.h"
#include "../../ballet/bls/fd_bls12_381_kdf.h"
#include "../../ballet/ed25519/fd_ed25519.h"

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
  for( ulong i=signer_set_const_iter_init( agg->bitmask );
       !signer_set_const_iter_done( i );
       i=signer_set_const_iter_next( agg->bitmask, i ) ) {
    seen |= (1UL<<i); cnt++;
  }
  FD_TEST( cnt==2UL );
  FD_TEST( seen==((1UL<<0)|(1UL<<2)) );

  ag_aggsig_pk_t pks[3] = { pk[0], pk[1], pk[2] };
  FD_TEST(  ag_aggsig_verify_bytes( agg, msg, msg_sz, pks, 3UL ) );
  FD_TEST( !ag_aggsig_verify_bytes( agg, msg, msg_sz, pks, 2UL ) );
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

  FD_TEST( ag_aggsig_verify_bytes( agg, msg, msg_sz, pks, N ) );

  FD_TEST( !ag_aggsig_verify_bytes( agg, (uchar const *)"different message", 17UL, pks, N ) );

  ag_aggsig_t tampered = *agg;
  tampered.sig[0] = (uchar)( tampered.sig[0] ^ 0xFFu );
  FD_TEST( !ag_aggsig_verify_bytes( &tampered, msg, msg_sz, pks, N ) );

  ag_aggsig_pk_t pks_wrong[5] = { pk[1], pk[1], pk[2], pk[3], pk[4] };
  FD_TEST( !ag_aggsig_verify_bytes( agg, msg, msg_sz, pks_wrong, N ) );

  ag_aggsig_t mismatch = *agg;
  signer_set_remove( mismatch.bitmask, 4UL );
  FD_TEST( ag_aggsig_signer_cnt( &mismatch )==2UL );
  FD_TEST( !ag_aggsig_verify_bytes( &mismatch, msg, msg_sz, pks, N ) );

  FD_TEST( !ag_aggsig_verify_bytes( agg, msg, msg_sz, pks, N-1UL ) );

  ag_aggsig_t     agg_all[1];
  ulong           idx_all[5] = { 0UL, 1UL, 2UL, 3UL, 4UL };
  ag_aggsig_new( agg_all, sig, idx_all, N, N );
  FD_TEST( ag_aggsig_verify_bytes( agg_all, msg, msg_sz, pks, N ) );

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

/* The BLS voting key has to be derived identically in two places that
   never meet: fd_bls12_381_kdf, which genesis creation uses to write
   the compressed pubkey into the vote account, and the sign tile's
   derive_fields, which does the ed25519 sign itself and hands the IKM
   to ag_aggsig_sk_derive.  If they ever diverge the validator signs
   alpenglow votes with a key nobody has registered for it, so it is
   given no stake weight and silently cannot vote.  Pin them together.

   The prefix is BLSKeypair::derive_from_signer's "bls-key-derive-"
   concatenated with BLS_KEYPAIR_DERIVE_SEED. */

static void
test_derive_matches_kdf( void ) {
  uchar sk[ 32 ]; for( ulong i=0UL; i<32UL; i++ ) sk[ i ] = (uchar)(i*3u+5u);

  fd_sha512_t sha[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );

  uchar pk[ 32 ];
  fd_ed25519_public_from_private( pk, sk, sha );

  /* Genesis side. */
  uchar kdf_pk[ 48 ], kdf_sk[ 32 ];
  FD_TEST( !fd_bls12_381_kdf( kdf_pk, kdf_sk, pk, sk, sha ) );

  /* Sign tile side. */
  static char const derive_msg[] = "bls-key-derive-alpenglow";
  uchar ikm[ 64 ];
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL, pk, sk, sha );

  ag_aggsig_sk_t bls_sk[1];
  ag_aggsig_sk_derive( bls_sk, ikm, sizeof(ikm) );
  FD_TEST( !memcmp( bls_sk->v, kdf_sk, AG_AGGSIG_SECKEY_SZ ) );

  uchar tile_pk[ AG_AGGSIG_PUBKEY_COMPRESSED_SZ ];
  ag_aggsig_sk_to_pk_compressed( tile_pk, bls_sk );
  FD_TEST( !memcmp( tile_pk, kdf_pk, AG_AGGSIG_PUBKEY_COMPRESSED_SZ ) );

  FD_LOG_NOTICE(( "genesis and sign tile derive the same BLS voting key" ));
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
  test_derive_matches_kdf();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
