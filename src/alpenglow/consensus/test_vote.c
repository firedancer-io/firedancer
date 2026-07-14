#include "ag_vote.h"

#define TEST_SHRED_VERSION ((ushort)514)

static void
test_basic( void ) {
  ag_aggsig_sk_t sk; fd_memset( sk.v, 9, AG_AGGSIG_SECKEY_SZ );
  ag_aggsig_pk_t pk; ag_aggsig_sk_to_pk( &pk, &sk );
  fd_hash_t h; memset( h.uc, 0, sizeof(fd_hash_t) );

  ag_vote_t v;

  ag_vote_new_notar( &v, 0UL, &h, &sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_NOTAR );
  FD_TEST( ag_vote_slot( &v )==0UL );
  FD_TEST( ag_vote_signer( &v )==0UL );
  FD_TEST( ag_vote_block_hash( &v ) && !memcmp( ag_vote_block_hash(&v)->uc, h.uc, 32 ) );
  FD_TEST( ag_vote_check_sig( &v, &pk, TEST_SHRED_VERSION ) );
#if FD_HAS_BLST
  FD_TEST( !ag_vote_check_sig( &v, &pk, (ushort)(TEST_SHRED_VERSION+1) ) ); /* payload binds shred_version */
#endif

  ag_vote_new_notar_fallback( &v, 1UL, &h, &sk, 2UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_NOTAR_FALLBACK );
  FD_TEST( ag_vote_block_hash( &v )!=NULL );
  FD_TEST( ag_vote_check_sig( &v, &pk, TEST_SHRED_VERSION ) );

  ag_vote_new_skip( &v, 3UL, &sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_SKIP );
  FD_TEST( ag_vote_block_hash( &v )==NULL );
  FD_TEST( ag_vote_check_sig( &v, &pk, TEST_SHRED_VERSION ) );

  ag_vote_new_skip_fallback( &v, 3UL, &sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_SKIP_FALLBACK );
  FD_TEST( ag_vote_block_hash( &v )==NULL );

  ag_vote_new_final( &v, 4UL, &sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_FINAL );
  FD_TEST( ag_vote_block_hash( &v )==NULL );
  FD_TEST( ag_vote_slot( &v )==4UL );
}

static void
test_payload_distinct( void ) {
  fd_hash_t h; memset( h.uc, 0x11, sizeof(fd_hash_t) );
  uchar a[ AG_VOTE_PAYLOAD_MAX ], b[ AG_VOTE_PAYLOAD_MAX ];

  ulong sa = ag_vote_payload_bytes_to_sign( a, AG_VOTE_TYPE_NOTAR,          7UL, &h, TEST_SHRED_VERSION );
  ulong sb = ag_vote_payload_bytes_to_sign( b, AG_VOTE_TYPE_NOTAR_FALLBACK, 7UL, &h, TEST_SHRED_VERSION );
  FD_TEST( sa==sb );
  FD_TEST( memcmp( a, b, sa )!=0 );

  /* VotePayloadToSign: u8 tag (kind+1) + slot [+ block_id] + u16 shred_version */
  ulong sn = ag_vote_payload_bytes_to_sign( a, AG_VOTE_TYPE_NOTAR, 7UL, &h, TEST_SHRED_VERSION );
  ulong sk = ag_vote_payload_bytes_to_sign( b, AG_VOTE_TYPE_SKIP,  7UL, NULL, TEST_SHRED_VERSION );
  FD_TEST( sn==1UL+8UL+32UL+2UL );
  FD_TEST( sk==1UL+8UL+2UL );
  FD_TEST( a[0]==(uchar)(AG_VOTE_TYPE_NOTAR+1U) );
  FD_TEST( b[0]==(uchar)(AG_VOTE_TYPE_SKIP+1U)  );
  FD_TEST( FD_LOAD( ushort, a+sn-2UL )==TEST_SHRED_VERSION );

  ulong s0 = ag_vote_payload_bytes_to_sign( a, AG_VOTE_TYPE_SKIP, 7UL, NULL, TEST_SHRED_VERSION );
  ulong s1 = ag_vote_payload_bytes_to_sign( b, AG_VOTE_TYPE_SKIP, 8UL, NULL, TEST_SHRED_VERSION );
  FD_TEST( s0==s1 );
  FD_TEST( memcmp( a, b, s0 )!=0 );
}

/* check_wire serializes v, parses the ConsensusMessage::Vote wire layout field
   by field (there is no deserializer yet), and verifies the embedded signature
   validates against pk over the signed payload -- i.e. the vote was signed
   correctly and the signature survives serialization intact. */

static void
check_wire( ag_vote_t const * v, ag_aggsig_pk_t const * pk ) {
  uchar out[ AG_VOTE_SERIALIZED_MAX ];
  ulong n = ag_vote_serialize( v, out, sizeof(out), TEST_SHRED_VERSION );
  FD_TEST( n>0UL );

  fd_hash_t const * h       = ag_vote_block_hash( v );
  ulong             vote_sz = 1UL + 8UL + ( h ? 32UL : 0UL ) + 2UL; /* VotePayloadToSign */
  FD_TEST( n == 4UL + vote_sz + AG_AGGSIG_SIG_SZ + 2UL );

  ulong off = 0UL;
  FD_TEST( FD_LOAD( uint,  out+off )==0U              ); off += 4UL; /* ConsensusMessage::Vote */
  FD_TEST( out[off]==(uchar)(v->kind+1U)              ); off += 1UL; /* VotePayloadToSign tag  */
  FD_TEST( FD_LOAD( ulong, out+off )==ag_vote_slot( v )); off += 8UL; /* slot                   */
  if( h ) { FD_TEST( !memcmp( out+off, h->uc, 32UL ) ); off += 32UL; } /* block_id (Block kinds) */
  FD_TEST( FD_LOAD( ushort, out+off )==TEST_SHRED_VERSION ); off += 2UL; /* shred_version      */
  FD_TEST( off==4UL+vote_sz );

  uchar const * wire_sig = out+off; off += AG_AGGSIG_SIG_SZ;        /* 192B BLSSignature       */
  FD_TEST( FD_LOAD( ushort, out+off )==ag_vote_signer( v ) ); off += 2UL; /* u16 rank          */
  FD_TEST( off==n );

  /* the in-struct vote is signed correctly ... */
  FD_TEST( ag_vote_check_sig( v, pk, TEST_SHRED_VERSION ) );
  /* ... and the signature carried on the wire verifies over the serialized
     payload (out[4, 4+vote_sz) == the bytes that were signed). */
  ag_aggsig_sig_t sig; fd_memcpy( sig.v, wire_sig, AG_AGGSIG_SIG_SZ );
  FD_TEST( ag_aggsig_individual_verify_bytes( &sig, pk, out+4UL, vote_sz ) );

#if FD_HAS_BLST
  /* negative: tamper the slot in the payload -> the signature must reject. */
  uchar bad[ AG_VOTE_SERIALIZED_MAX ]; fd_memcpy( bad, out, n );
  bad[ 5 ] ^= 0xFFu;
  FD_TEST( !ag_aggsig_individual_verify_bytes( &sig, pk, bad+4UL, vote_sz ) );
#endif
}

static void
test_serialize( void ) {
  uchar ikm[ 64 ]; for( ulong i=0UL; i<64UL; i++ ) ikm[i] = (uchar)(i+1u);
  ag_aggsig_sk_t sk; ag_aggsig_sk_derive( &sk, ikm, sizeof(ikm) );
  ag_aggsig_pk_t pk; ag_aggsig_sk_to_pk( &pk, &sk );
  fd_hash_t h; for( ulong i=0UL; i<32UL; i++ ) h.uc[i] = (uchar)(0xA0u+i);

  ag_vote_t v;
  ag_vote_new_notar         ( &v, 12345UL, &h, &sk, 7UL,     TEST_SHRED_VERSION ); check_wire( &v, &pk );
  ag_vote_new_notar_fallback( &v, 99UL,    &h, &sk, 65535UL, TEST_SHRED_VERSION ); check_wire( &v, &pk ); /* max u16 rank */
  ag_vote_new_skip          ( &v, 42UL,        &sk, 3UL,     TEST_SHRED_VERSION ); check_wire( &v, &pk );
  ag_vote_new_skip_fallback ( &v, 42UL,        &sk, 3UL,     TEST_SHRED_VERSION ); check_wire( &v, &pk );
  ag_vote_new_final         ( &v, 7UL,         &sk, 1UL,     TEST_SHRED_VERSION ); check_wire( &v, &pk );

  /* buffer too small -> 0 */
  uchar small[ 8 ];
  FD_TEST( ag_vote_serialize( &v, small, sizeof(small), TEST_SHRED_VERSION )==0UL );

  FD_LOG_NOTICE(( "vote serialize round trip pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_basic();
  test_payload_distinct();
  test_serialize();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
