#include "ag_vote_serde.h"

#define TEST_SHRED_VERSION ((ushort)514)

/* check_wire drives its expectations off the kinds that carry a block
   hash, so it needs the dispatch the typed accessors do not do */

static uchar const *
block_hash( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return ag_vote_notar_block_hash( &self->notar );
  case AG_VOTE_KIND_NOTAR_FALLBACK: return ag_vote_notar_fallback_block_hash( &self->notar_fallback );
  default:                          return NULL;
  }
}

/* src/consensus/vote.rs::basic */

static void
test_basic( void ) {
  ag_bls_sec_t sk; fd_memset( sk, 9, AG_BLS_SEC_SZ );
  ag_bls_pub_t pk; ag_bls_sec_to_pub( sk, pk );
  ag_block_hash_t h; memset( h, 0, sizeof(ag_block_hash_t) );

  ag_vote_t v;

  v = ag_vote_construct_notar( 0UL, h, sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_KIND_NOTAR );
  FD_TEST( ag_vote_slot( &v )==0UL );
  FD_TEST( ag_vote_rank( &v )==0UL );
  FD_TEST( !memcmp( ag_vote_notar_block_hash( &v.notar ), h, sizeof(ag_block_hash_t) ) );
  FD_TEST( ag_vote_verify( &v, pk, TEST_SHRED_VERSION ) );
  FD_TEST( !ag_vote_verify( &v, pk, (ushort)(TEST_SHRED_VERSION+1) ) );

  v = ag_vote_construct_notar_fallback( 1UL, h, sk, 2UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_KIND_NOTAR_FALLBACK );
  FD_TEST( !memcmp( ag_vote_notar_fallback_block_hash( &v.notar_fallback ), h, sizeof(ag_block_hash_t) ) );
  FD_TEST( ag_vote_verify( &v, pk, TEST_SHRED_VERSION ) );

  v = ag_vote_construct_skip( 3UL, sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_KIND_SKIP );
  FD_TEST( block_hash( &v )==NULL );
  FD_TEST( ag_vote_verify( &v, pk, TEST_SHRED_VERSION ) );

  v = ag_vote_construct_skip_fallback( 3UL, sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_KIND_SKIP_FALLBACK );
  FD_TEST( block_hash( &v )==NULL );

  v = ag_vote_construct_final( 4UL, sk, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==AG_VOTE_KIND_FINAL );
  FD_TEST( block_hash( &v )==NULL );
  FD_TEST( ag_vote_slot( &v )==4UL );
}

/* the bytes a voter of the given kind over slot, and hash for the
   notarizing kinds, would have signed.  A cert aggregates the voters'
   signatures, so checking one means rebuilding their payload rather
   than serializing a vote we hold. */

static ulong
voter_signing_ser( uint          kind,
                   ulong         slot,
                   uchar const * hash,
                   ushort        shred_version,
                   uchar         buf[ static AG_VOTE_SIGNING_SER_MAX ] ) {
  ag_vote_t vote[1]; fd_memset( vote, 0, sizeof(ag_vote_t) );
  vote->kind = kind;
  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:          vote->notar.slot          = slot; memcpy( vote->notar.block_hash,          hash, sizeof(ag_block_hash_t) ); break;
  case AG_VOTE_KIND_FINAL:          vote->final.slot          = slot;                                                                           break;
  case AG_VOTE_KIND_SKIP:           vote->skip.slot           = slot;                                                                           break;
  case AG_VOTE_KIND_NOTAR_FALLBACK: vote->notar_fallback.slot = slot; memcpy( vote->notar_fallback.block_hash, hash, sizeof(ag_block_hash_t) ); break;
  case AG_VOTE_KIND_SKIP_FALLBACK:  vote->skip_fallback.slot  = slot;                                                                           break;
  default:                          __builtin_unreachable();
  }
  return ag_vote_signing_ser( vote, shred_version, buf );
}

static void
test_payload_distinct( void ) {
  ag_block_hash_t h; memset( h, 0x11, sizeof(ag_block_hash_t) );
  uchar a[ AG_VOTE_SIGNING_SER_MAX ], b[ AG_VOTE_SIGNING_SER_MAX ];

  ulong sa = voter_signing_ser( AG_VOTE_KIND_NOTAR,          7UL, h, TEST_SHRED_VERSION, a );
  ulong sb = voter_signing_ser( AG_VOTE_KIND_NOTAR_FALLBACK, 7UL, h, TEST_SHRED_VERSION, b );
  FD_TEST( sa==sb );
  FD_TEST( memcmp( a, b, sa )!=0 );

  ulong sn = voter_signing_ser( AG_VOTE_KIND_NOTAR, 7UL, h, TEST_SHRED_VERSION, a );
  ulong sk = voter_signing_ser( AG_VOTE_KIND_SKIP,  7UL, NULL, TEST_SHRED_VERSION, b );
  FD_TEST( sn==1UL+8UL+sizeof(ag_block_hash_t)+2UL );
  FD_TEST( sk==1UL+8UL+2UL );
  FD_TEST( a[0]==(uchar)(AG_VOTE_KIND_NOTAR+1U) );
  FD_TEST( b[0]==(uchar)(AG_VOTE_KIND_SKIP+1U)  );
  FD_TEST( FD_LOAD( ushort, a+sn-2UL )==TEST_SHRED_VERSION );

  ulong s0 = voter_signing_ser( AG_VOTE_KIND_SKIP, 7UL, NULL, TEST_SHRED_VERSION, a );
  ulong s1 = voter_signing_ser( AG_VOTE_KIND_SKIP, 8UL, NULL, TEST_SHRED_VERSION, b );
  FD_TEST( s0==s1 );
  FD_TEST( memcmp( a, b, s0 )!=0 );
}

static void
check_wire( ag_vote_t const * v, ag_bls_pub_t const pk ) {
  uchar out[ AG_VOTE_SER_SZ( 1 ) ];
  ulong n;
  n = ag_vote_ser( v, TEST_SHRED_VERSION, out );
  FD_TEST( n>0UL );

  uchar const * h       = block_hash( v );
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

  ag_vote_t rt;
  FD_TEST( ag_vote_de( &rt, TEST_SHRED_VERSION, out, n )==AG_VOTE_DE_SUCCESS );
  FD_TEST( rt.kind==v->kind );
  FD_TEST( ag_vote_slot  ( &rt )==ag_vote_slot  ( v ) );
  FD_TEST( ag_vote_rank( &rt )==USHORT_MAX ); /* rank is not on the wire */
  uchar const * rt_h = block_hash( &rt );
  FD_TEST( !rt_h==!h );
  if( h ) FD_TEST( !memcmp( rt_h, h, sizeof(ag_block_hash_t) ) );
  FD_TEST( ag_vote_verify( &rt, pk, TEST_SHRED_VERSION ) );
  FD_TEST( ag_vote_de( &rt, (ushort)(TEST_SHRED_VERSION+1), out, n )==AG_VOTE_DE_ERR_SHRED_VERSION );
  FD_TEST( ag_vote_de( &rt, TEST_SHRED_VERSION, out, n-1UL )==AG_VOTE_DE_ERR_SZ ); /* too few  */
  FD_TEST( ag_vote_de( &rt, TEST_SHRED_VERSION, out, n+1UL )==AG_VOTE_DE_ERR_SZ ); /* trailing */

  FD_TEST( ag_vote_verify( v, pk, TEST_SHRED_VERSION ) );

  uchar        payload[ AG_VOTE_SIGNING_SER_MAX ];
  ulong        payload_sz = ag_vote_signing_ser( v, TEST_SHRED_VERSION, payload );
  ag_bls_sig_t sig; memcpy( sig, wire_sig, AG_BLS_SIG_SZ );
  FD_TEST( ag_bls_sig_verify( sig, pk, payload, payload_sz ) );

  payload[ 1 ] ^= 0xFFu;
  FD_TEST( !ag_bls_sig_verify( sig, pk, payload, payload_sz ) );
}

static void
test_serialize( void ) {
  uchar        ikm[ 64 ]; for( ulong i=0UL; i<64UL; i++ ) ikm[i] = (uchar)(i+1u);
  ag_bls_sec_t sk; ag_bls_sec_derive( sk, ikm, sizeof(ikm) );
  ag_bls_pub_t pk; ag_bls_sec_to_pub( sk, pk );
  ag_block_hash_t h; for( ulong i=0UL; i<32UL; i++ ) h[i] = (uchar)(0xA0u+i);

  ag_vote_t v;
  v = ag_vote_construct_notar( 12345UL, h, sk, 7UL, TEST_SHRED_VERSION ); check_wire( &v, pk );
  v = ag_vote_construct_final( 7UL, sk, 1UL, TEST_SHRED_VERSION ); check_wire( &v, pk );
  v = ag_vote_construct_skip( 42UL, sk, 3UL, TEST_SHRED_VERSION ); check_wire( &v, pk );
  v = ag_vote_construct_notar_fallback( 99UL, h, sk, 65535UL, TEST_SHRED_VERSION ); check_wire( &v, pk );
  v = ag_vote_construct_skip_fallback( 42UL, sk, 3UL, TEST_SHRED_VERSION ); check_wire( &v, pk );

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
