#include "ag_vote_serde.h"

#define TEST_SHRED_VERSION ((ushort)514)

/* src/consensus/vote.rs::basic */

static void
test_basic( void ) {
  ag_bls_sec_t sk; fd_memset( sk, 9, AG_BLS_SEC_SZ );
  ag_bls_pub_t pk; ag_bls_sec_to_pub( pk, sk );
  ag_block_hash_t h; memset( h, 0, sizeof(ag_block_hash_t) );

  ag_vote_t v;

  ag_vote_new_notar( &v, 0UL, h, sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_NOTAR );
  FD_TEST( ag_vote_slot( &v )==0UL );
  FD_TEST( ag_vote_signer( &v )==0UL );
  FD_TEST( ag_vote_block_hash( &v ) && !memcmp( ag_vote_block_hash(&v), h, sizeof(ag_block_hash_t) ) );
  FD_TEST( ag_vote_check_sig( &v, pk, TEST_SHRED_VERSION ) );
  FD_TEST( !ag_vote_check_sig( &v, pk, (ushort)(TEST_SHRED_VERSION+1) ) );

  ag_vote_new_notar_fallback( &v, 1UL, h, sk, 2UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_NOTAR_FALLBACK );
  FD_TEST( ag_vote_block_hash( &v )!=NULL );
  FD_TEST( ag_vote_check_sig( &v, pk, TEST_SHRED_VERSION ) );

  ag_vote_new_skip( &v, 3UL, sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_SKIP );
  FD_TEST( ag_vote_block_hash( &v )==NULL );
  FD_TEST( ag_vote_check_sig( &v, pk, TEST_SHRED_VERSION ) );

  ag_vote_new_skip_fallback( &v, 3UL, sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_SKIP_FALLBACK );
  FD_TEST( ag_vote_block_hash( &v )==NULL );

  ag_vote_new_final( &v, 4UL, sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_TYPE_FINAL );
  FD_TEST( ag_vote_block_hash( &v )==NULL );
  FD_TEST( ag_vote_slot( &v )==4UL );
}

static void
test_payload_distinct( void ) {
  ag_block_hash_t h; memset( h, 0x11, sizeof(ag_block_hash_t) );
  uchar a[ AG_VOTE_PAYLOAD_MAX ], b[ AG_VOTE_PAYLOAD_MAX ];

  ulong sa = ag_vote_payload_bytes_to_sign( a, AG_VOTE_TYPE_NOTAR,          7UL, h, TEST_SHRED_VERSION );
  ulong sb = ag_vote_payload_bytes_to_sign( b, AG_VOTE_TYPE_NOTAR_FALLBACK, 7UL, h, TEST_SHRED_VERSION );
  FD_TEST( sa==sb );
  FD_TEST( memcmp( a, b, sa )!=0 );

  ulong sn = ag_vote_payload_bytes_to_sign( a, AG_VOTE_TYPE_NOTAR, 7UL, h, TEST_SHRED_VERSION );
  ulong sk = ag_vote_payload_bytes_to_sign( b, AG_VOTE_TYPE_SKIP,  7UL, NULL, TEST_SHRED_VERSION );
  FD_TEST( sn==1UL+8UL+sizeof(ag_block_hash_t)+2UL );
  FD_TEST( sk==1UL+8UL+2UL );
  FD_TEST( a[0]==(uchar)(AG_VOTE_TYPE_NOTAR+1U) );
  FD_TEST( b[0]==(uchar)(AG_VOTE_TYPE_SKIP+1U)  );
  FD_TEST( FD_LOAD( ushort, a+sn-2UL )==TEST_SHRED_VERSION );

  ulong s0 = ag_vote_payload_bytes_to_sign( a, AG_VOTE_TYPE_SKIP, 7UL, NULL, TEST_SHRED_VERSION );
  ulong s1 = ag_vote_payload_bytes_to_sign( b, AG_VOTE_TYPE_SKIP, 8UL, NULL, TEST_SHRED_VERSION );
  FD_TEST( s0==s1 );
  FD_TEST( memcmp( a, b, s0 )!=0 );
}

static void
check_wire( ag_vote_t const * v, ag_bls_pub_t const pk ) {
  uchar out[ AG_VOTE_SERIALIZED_MAX ];
  ulong n;
  FD_TEST( ag_vote_ser( v, TEST_SHRED_VERSION, out, sizeof(out), &n )==0 );
  FD_TEST( n>0UL );

  uchar const * h       = ag_vote_block_hash( v );
  ulong         body_sz = 8UL + ( h ? sizeof(ag_block_hash_t) : 0UL ) + AG_BLS_SIG_SZ;
  FD_TEST( n == 2UL + body_sz + 2UL );

  ulong off = 0UL;
  FD_TEST( out[off]==(uchar)1                          ); off += 1UL;
  FD_TEST( out[off]==(uchar)(v->kind+1U)               ); off += 1UL;
  FD_TEST( FD_LOAD( ulong, out+off )==ag_vote_slot( v )); off += 8UL;
  if( h ) { FD_TEST( !memcmp( out+off, h, sizeof(ag_block_hash_t) ) ); off += sizeof(ag_block_hash_t); }
  uchar const * wire_sig = out+off; off += AG_BLS_SIG_SZ;
  FD_TEST( FD_LOAD( ushort, out+off )==TEST_SHRED_VERSION  ); off += 2UL;
  FD_TEST( off==n );

  ag_vote_t rt; ulong consumed;
  FD_TEST( ag_vote_de( &rt, TEST_SHRED_VERSION, out, n, &consumed )==AG_VOTE_DE_SUCCESS );
  FD_TEST( consumed==n );
  FD_TEST( rt.kind==v->kind );
  FD_TEST( ag_vote_slot  ( &rt )==ag_vote_slot  ( v ) );
  FD_TEST( ag_vote_signer( &rt )==USHORT_MAX ); /* rank is not on the wire */
  uchar const * rt_h = ag_vote_block_hash( &rt );
  FD_TEST( !rt_h==!h );
  if( h ) FD_TEST( !memcmp( rt_h, h, sizeof(ag_block_hash_t) ) );
  FD_TEST( ag_vote_check_sig( &rt, pk, TEST_SHRED_VERSION ) );
  FD_TEST( ag_vote_de( &rt, (ushort)(TEST_SHRED_VERSION+1), out, n, NULL )==AG_VOTE_DE_ERR_SHRED_VERSION );
  FD_TEST( ag_vote_de( &rt, TEST_SHRED_VERSION, out, n-1UL, NULL )==AG_VOTE_DE_ERR_TRUNCATED );

  FD_TEST( ag_vote_check_sig( v, pk, TEST_SHRED_VERSION ) );

  uchar        payload[ AG_VOTE_PAYLOAD_MAX ];
  ulong        payload_sz = ag_vote_payload_bytes_to_sign( payload, v->kind, ag_vote_slot( v ), h, TEST_SHRED_VERSION );
  ag_bls_sig_t sig; fd_memcpy( sig, wire_sig, AG_BLS_SIG_SZ );
  FD_TEST( ag_bls_sig_verify_bytes( sig, pk, payload, payload_sz ) );

  payload[ 1 ] ^= 0xFFu;
  FD_TEST( !ag_bls_sig_verify_bytes( sig, pk, payload, payload_sz ) );
}

static void
test_serialize( void ) {
  uchar        ikm[ 64 ]; for( ulong i=0UL; i<64UL; i++ ) ikm[i] = (uchar)(i+1u);
  ag_bls_sec_t sk; ag_bls_sec_derive( sk, ikm, sizeof(ikm) );
  ag_bls_pub_t pk; ag_bls_sec_to_pub( pk, sk );
  ag_block_hash_t h; for( ulong i=0UL; i<32UL; i++ ) h[i] = (uchar)(0xA0u+i);

  ag_vote_t v;
  ag_vote_new_notar         ( &v, 12345UL, h, sk, 7UL,     TEST_SHRED_VERSION ); check_wire( &v, pk );
  ag_vote_new_notar_fallback( &v, 99UL,    h, sk, 65535UL, TEST_SHRED_VERSION ); check_wire( &v, pk );
  ag_vote_new_skip          ( &v, 42UL,       sk, 3UL,     TEST_SHRED_VERSION ); check_wire( &v, pk );
  ag_vote_new_skip_fallback ( &v, 42UL,       sk, 3UL,     TEST_SHRED_VERSION ); check_wire( &v, pk );
  ag_vote_new_final         ( &v, 7UL,        sk, 1UL,     TEST_SHRED_VERSION ); check_wire( &v, pk );

  uchar small[ 8 ];
  FD_TEST( ag_vote_ser( &v, TEST_SHRED_VERSION, small, sizeof(small), NULL )==-1 );

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
