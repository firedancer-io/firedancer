#include "ag_vote.h"
#include "ag_votor.h"

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

  /* signed payload: u8 tag (kind+1) + slot [+ block_id] + u16 shred_version */
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

/* check_wire serializes v, parses the V1 wire consensus message vote
   layout field by field, verifies the wire signature validates
   against pk over the (rebuilt) signed payload, and round-trips the
   bytes through ag_consensus_message_de. */

static void
check_wire( ag_vote_t const * v, ag_aggsig_pk_t const * pk ) {
  uchar out[ AG_VOTE_SERIALIZED_MAX ];
  ulong n = ag_vote_serialize( v, out, sizeof(out), TEST_SHRED_VERSION );
  FD_TEST( n>0UL );

  fd_hash_t const * h       = ag_vote_block_hash( v );
  ulong             body_sz = 8UL + ( h ? 32UL : 0UL ) + AG_AGGSIG_SIG_SZ + 2UL;
  FD_TEST( n == 2UL + body_sz + 2UL );

  ulong off = 0UL;
  FD_TEST( out[off]==(uchar)1                          ); off += 1UL; /* version tag (V1)                  */
  FD_TEST( out[off]==(uchar)(v->kind+1U)               ); off += 1UL; /* kind tag                          */
  FD_TEST( FD_LOAD( ulong, out+off )==ag_vote_slot( v )); off += 8UL; /* slot                              */
  if( h ) { FD_TEST( !memcmp( out+off, h->uc, 32UL ) ); off += 32UL; } /* block_id (notar kinds)           */
  uchar const * wire_sig = out+off; off += AG_AGGSIG_SIG_SZ;           /* 192B BLS signature                */
  FD_TEST( FD_LOAD( ushort, out+off )==ag_vote_signer( v ) ); off += 2UL; /* u16 rank                       */
  FD_TEST( FD_LOAD( ushort, out+off )==TEST_SHRED_VERSION  ); off += 2UL; /* u16 shred_version              */
  FD_TEST( off==n );

  /* the in-struct vote is signed correctly ... */
  FD_TEST( ag_vote_check_sig( v, pk, TEST_SHRED_VERSION ) );
  /* ... and the wire signature verifies over the signed payload (rebuilt
     from the vote, not the wire bytes). */
  uchar payload[ AG_VOTE_PAYLOAD_MAX ];
  ulong payload_sz = ag_vote_payload_bytes_to_sign( payload, v->kind, ag_vote_slot( v ), h, TEST_SHRED_VERSION );
  ag_aggsig_sig_t sig; fd_memcpy( sig.v, wire_sig, AG_AGGSIG_SIG_SZ );
  FD_TEST( ag_aggsig_individual_verify_bytes( &sig, pk, payload, payload_sz ) );

#if FD_HAS_BLST
  /* negative: tamper the payload slot -> the signature must reject. */
  payload[ 1 ] ^= 0xFFu;
  FD_TEST( !ag_aggsig_individual_verify_bytes( &sig, pk, payload, payload_sz ) );
#endif

  /* round trip through the consensus-message deserializer */
  ag_consensus_message_t msg[1];
  FD_TEST( ag_consensus_message_de( msg, out, n, TEST_SHRED_VERSION )==AG_CONSENSUS_MESSAGE_DE_SUCCESS );
  FD_TEST( msg->kind==AG_CONSENSUS_MESSAGE_VOTE );
  FD_TEST( msg->inner.vote.kind==v->kind );
  FD_TEST( ag_vote_slot  ( &msg->inner.vote )==ag_vote_slot  ( v ) );
  FD_TEST( ag_vote_signer( &msg->inner.vote )==ag_vote_signer( v ) );
  if( h ) FD_TEST( !memcmp( ag_vote_block_hash( &msg->inner.vote )->uc, h->uc, 32UL ) );
  FD_TEST( ag_vote_check_sig( &msg->inner.vote, pk, TEST_SHRED_VERSION ) );

  /* shred_version mismatch / malformed envelope are rejected */
  FD_TEST( ag_consensus_message_de( msg, out, n, (ushort)(TEST_SHRED_VERSION+1) )==AG_CONSENSUS_MESSAGE_DE_ERR_SHRED_VERSION );
  FD_TEST( ag_consensus_message_de( msg, out, n-1UL, TEST_SHRED_VERSION )==AG_CONSENSUS_MESSAGE_DE_ERR_MALFORMED );
  uchar bad_version[ AG_VOTE_SERIALIZED_MAX ]; fd_memcpy( bad_version, out, n ); bad_version[0] = 2;
  FD_TEST( ag_consensus_message_de( msg, bad_version, n, TEST_SHRED_VERSION )==AG_CONSENSUS_MESSAGE_DE_ERR_UNSUPPORTED );
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
