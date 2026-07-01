#include "fd_vote.h"

/* Mirrors alpenglow/src/consensus/vote.rs mod tests::basic plus payload
   distinctness checks. */

static void
test_basic( void ) {
  fd_aggsig_sk_t sk; fd_memset( sk.v, 9, FD_AGGSIG_SECKEY_SZ );
  fd_aggsig_pk_t pk; fd_aggsig_sk_to_pk( &pk, &sk );
  fd_hash_t h; memset( h.uc, 0, sizeof(fd_hash_t) ); /* genesis block hash */

  fd_ag_vote_t v;

  fd_vote_new_notar( &v, 0UL, &h, &sk, 0UL );
  FD_TEST( v.discriminant==FD_VOTE_TYPE_NOTAR );
  FD_TEST( fd_vote_slot( &v )==0UL );
  FD_TEST( fd_vote_signer( &v )==0UL );
  FD_TEST( fd_vote_block_hash( &v ) && !memcmp( fd_vote_block_hash(&v)->uc, h.uc, 32 ) );
  FD_TEST( fd_vote_check_sig( &v, &pk ) );

  fd_vote_new_notar_fallback( &v, 1UL, &h, &sk, 2UL );
  FD_TEST( v.discriminant==FD_VOTE_TYPE_NOTAR_FALLBACK );
  FD_TEST( fd_vote_block_hash( &v )!=NULL );
  FD_TEST( fd_vote_check_sig( &v, &pk ) );

  fd_vote_new_skip( &v, 3UL, &sk, 0UL );
  FD_TEST( v.discriminant==FD_VOTE_TYPE_SKIP );
  FD_TEST( fd_vote_block_hash( &v )==NULL );
  FD_TEST( fd_vote_check_sig( &v, &pk ) );

  fd_vote_new_skip_fallback( &v, 3UL, &sk, 0UL );
  FD_TEST( v.discriminant==FD_VOTE_TYPE_SKIP_FALLBACK );
  FD_TEST( fd_vote_block_hash( &v )==NULL );

  fd_vote_new_final( &v, 4UL, &sk, 0UL );
  FD_TEST( v.discriminant==FD_VOTE_TYPE_FINAL );
  FD_TEST( fd_vote_block_hash( &v )==NULL );
  FD_TEST( fd_vote_slot( &v )==4UL );
}

static void
test_payload_distinct( void ) {
  fd_hash_t h; memset( h.uc, 0x11, sizeof(fd_hash_t) );
  uchar a[ FD_VOTE_PAYLOAD_MAX ], b[ FD_VOTE_PAYLOAD_MAX ];

  /* notar vs notar-fallback for same (slot,hash) sign different bytes */
  ulong sa = fd_vote_payload_bytes_to_sign( a, FD_VOTE_TYPE_NOTAR,          7UL, &h );
  ulong sb = fd_vote_payload_bytes_to_sign( b, FD_VOTE_TYPE_NOTAR_FALLBACK, 7UL, &h );
  FD_TEST( sa==sb );
  FD_TEST( memcmp( a, b, sa )!=0 );

  /* notar carries the hash (longer), skip does not */
  ulong sn = fd_vote_payload_bytes_to_sign( a, FD_VOTE_TYPE_NOTAR, 7UL, &h );
  ulong sk = fd_vote_payload_bytes_to_sign( b, FD_VOTE_TYPE_SKIP,  7UL, NULL );
  FD_TEST( sn==4UL+8UL+32UL );
  FD_TEST( sk==4UL+8UL );

  /* different slots differ */
  ulong s0 = fd_vote_payload_bytes_to_sign( a, FD_VOTE_TYPE_SKIP, 7UL, NULL );
  ulong s1 = fd_vote_payload_bytes_to_sign( b, FD_VOTE_TYPE_SKIP, 8UL, NULL );
  FD_TEST( s0==s1 );
  FD_TEST( memcmp( a, b, s0 )!=0 );
}

/* check_wire serializes v, parses the ConsensusMessage::Vote wire layout field
   by field (there is no deserializer yet), and verifies the embedded signature
   validates against pk over the signed payload -- i.e. the vote was signed
   correctly and the signature survives serialization intact. */

static void
check_wire( fd_ag_vote_t const * v, fd_aggsig_pk_t const * pk ) {
  uchar out[ FD_VOTE_SERIALIZED_MAX ];
  ulong n = fd_vote_serialize( v, out, sizeof(out) );
  FD_TEST( n>0UL );

  fd_hash_t const * h       = fd_vote_block_hash( v );
  ulong             vote_sz = 4UL + 8UL + ( h ? 32UL : 0UL ); /* Vote tag + slot [+ block_id] */
  FD_TEST( n == 4UL + vote_sz + FD_AGGSIG_SIG_SZ + 2UL );

  ulong off = 0UL;
  FD_TEST( FD_LOAD( uint,  out+off )==0U             ); off += 4UL; /* ConsensusMessage::Vote */
  FD_TEST( FD_LOAD( uint,  out+off )==v->discriminant ); off += 4UL; /* Vote variant tag       */
  FD_TEST( FD_LOAD( ulong, out+off )==fd_vote_slot( v )); off += 8UL; /* slot                   */
  if( h ) { FD_TEST( !memcmp( out+off, h->uc, 32UL ) ); off += 32UL; } /* block_id (Block kinds) */
  FD_TEST( off==4UL+vote_sz );

  uchar const * wire_sig = out+off; off += FD_AGGSIG_SIG_SZ;        /* 192B BLSSignature       */
  FD_TEST( FD_LOAD( ushort, out+off )==fd_vote_signer( v ) ); off += 2UL; /* u16 rank          */
  FD_TEST( off==n );

  /* the in-struct vote is signed correctly ... */
  FD_TEST( fd_vote_check_sig( v, pk ) );
  /* ... and the signature carried on the wire verifies over the serialized
     payload (out[4, 4+vote_sz) == the bytes that were signed). */
  fd_aggsig_sig_t sig; fd_memcpy( sig.v, wire_sig, FD_AGGSIG_SIG_SZ );
  FD_TEST( fd_aggsig_individual_verify_bytes( &sig, pk, out+4UL, vote_sz ) );

#if FD_HAS_BLST
  /* negative: tamper the slot in the payload -> the signature must reject. */
  uchar bad[ FD_VOTE_SERIALIZED_MAX ]; fd_memcpy( bad, out, n );
  bad[ 8 ] ^= 0xFFu;
  FD_TEST( !fd_aggsig_individual_verify_bytes( &sig, pk, bad+4UL, vote_sz ) );
#endif
}

static void
test_serialize( void ) {
  uchar ikm[ 64 ]; for( ulong i=0UL; i<64UL; i++ ) ikm[i] = (uchar)(i+1u);
  fd_aggsig_sk_t sk; fd_aggsig_sk_derive( &sk, ikm, sizeof(ikm) );
  fd_aggsig_pk_t pk; fd_aggsig_sk_to_pk( &pk, &sk );
  fd_hash_t h; for( ulong i=0UL; i<32UL; i++ ) h.uc[i] = (uchar)(0xA0u+i);

  fd_ag_vote_t v;
  fd_vote_new_notar         ( &v, 12345UL, &h, &sk, 7UL     ); check_wire( &v, &pk );
  fd_vote_new_notar_fallback( &v, 99UL,    &h, &sk, 65535UL ); check_wire( &v, &pk ); /* max u16 rank */
  fd_vote_new_skip          ( &v, 42UL,        &sk, 3UL     ); check_wire( &v, &pk );
  fd_vote_new_skip_fallback ( &v, 42UL,        &sk, 3UL     ); check_wire( &v, &pk );
  fd_vote_new_final         ( &v, 7UL,         &sk, 1UL     ); check_wire( &v, &pk );

  /* buffer too small -> 0 */
  uchar small[ 8 ];
  FD_TEST( fd_vote_serialize( &v, small, sizeof(small) )==0UL );

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
