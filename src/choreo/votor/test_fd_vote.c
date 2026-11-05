#include "fd_vote_serde.h"

#define TEST_SHRED_VERSION ((ushort)514)

/* sec_sign_fn is the fd_bls_sign_fn of a test that holds the secret
   key in memory; ctx points to the fd_bls_sec_t. */

static void
sec_sign_fn( void *         ctx,
             fd_bls_sig_t * sig,
             uchar const *  public_key,
             uchar const *  msg,
             ulong          msg_sz ) {
  (void)public_key;
  fd_bls_sec_sign( (fd_bls_sec_t const *)ctx, msg, msg_sz, sig );
}

/* check_wire drives its expectations off the kinds that carry a block
   hash, so it needs the dispatch the typed accessors do not do */

static fd_block_hash_t const *
block_hash( fd_vote_t const * self ) {
  switch( self->kind ) {
  case FD_VOTE_KIND_NOTAR:          return &self->notar.block_hash;
  case FD_VOTE_KIND_NOTAR_FALLBACK: return &self->notar_fallback.block_hash;
  default:                          return NULL;
  }
}

/* src/consensus/vote.rs::basic */

static void
test_basic( void ) {
  fd_bls_sec_t sk; fd_memset( &sk, 9, FD_BLS_SEC_SZ );
  fd_bls_pub_t pk; fd_bls_sec_to_pub( &sk, &pk );
  uchar selector[ FD_BLS_PUB_COMPRESSED_SZ ]; fd_bls_pub_compress( &pk, selector );
  fd_block_hash_t h; memset( &h, 0, sizeof(fd_block_hash_t) );

  fd_vote_t v;

  v = fd_vote_construct_notar( sec_sign_fn, &sk, selector, 0UL, &h, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==FD_VOTE_KIND_NOTAR );
  FD_TEST( fd_vote_slot( &v )==0UL );
  FD_TEST( fd_vote_rank( &v )==0UL );
  FD_TEST( !memcmp( &v.notar.block_hash, &h, sizeof(fd_block_hash_t) ) );

  v = fd_vote_construct_notar_fallback( sec_sign_fn, &sk, selector, 1UL, &h, 2UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==FD_VOTE_KIND_NOTAR_FALLBACK );
  FD_TEST( !memcmp( &v.notar_fallback.block_hash, &h, sizeof(fd_block_hash_t) ) );

  v = fd_vote_construct_skip( sec_sign_fn, &sk, selector, 3UL, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==FD_VOTE_KIND_SKIP );
  FD_TEST( block_hash( &v )==NULL );

  v = fd_vote_construct_skip_fallback( sec_sign_fn, &sk, selector, 3UL, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==FD_VOTE_KIND_SKIP_FALLBACK );
  FD_TEST( block_hash( &v )==NULL );

  v = fd_vote_construct_final( sec_sign_fn, &sk, selector, 4UL, 0UL, TEST_SHRED_VERSION );
  FD_TEST( v.kind==FD_VOTE_KIND_FINAL );
  FD_TEST( block_hash( &v )==NULL );
  FD_TEST( fd_vote_slot( &v )==4UL );
}

static void
test_payload_distinct( void ) {
  fd_block_hash_t h; memset( &h, 0x11, sizeof(fd_block_hash_t) );
  uchar a[ FD_VOTE_SIGNING_SER_MAX ], b[ FD_VOTE_SIGNING_SER_MAX ];

  ulong sa = fd_vote_signing_ser( FD_VOTE_KIND_NOTAR,          7UL, &h, TEST_SHRED_VERSION, a );
  ulong sb = fd_vote_signing_ser( FD_VOTE_KIND_NOTAR_FALLBACK, 7UL, &h, TEST_SHRED_VERSION, b );
  FD_TEST( sa==sb );
  FD_TEST( memcmp( a, b, sa )!=0 );

  ulong sn = fd_vote_signing_ser( FD_VOTE_KIND_NOTAR, 7UL, &h, TEST_SHRED_VERSION, a );
  ulong sk = fd_vote_signing_ser( FD_VOTE_KIND_SKIP,  7UL, NULL, TEST_SHRED_VERSION, b );
  FD_TEST( sn==1UL+8UL+sizeof(fd_block_hash_t)+2UL );
  FD_TEST( sk==1UL+8UL+2UL );
  FD_TEST( a[0]==(uchar)(FD_VOTE_KIND_NOTAR+1U) );
  FD_TEST( b[0]==(uchar)(FD_VOTE_KIND_SKIP+1U)  );
  FD_TEST( FD_LOAD( ushort, a+sn-2UL )==TEST_SHRED_VERSION );

  ulong s0 = fd_vote_signing_ser( FD_VOTE_KIND_SKIP, 7UL, NULL, TEST_SHRED_VERSION, a );
  ulong s1 = fd_vote_signing_ser( FD_VOTE_KIND_SKIP, 8UL, NULL, TEST_SHRED_VERSION, b );
  FD_TEST( s0==s1 );
  FD_TEST( memcmp( a, b, s0 )!=0 );
}

static void
check_wire( fd_vote_t const *    v,
            fd_bls_pub_t const * pk ) {
  uchar out[ FD_VOTE_SER_MAX ];
  ulong n;
  n = fd_vote_ser( v, out );
  FD_TEST( n>0UL );

  fd_block_hash_t const * h       = block_hash( v );
  ulong                   body_sz = 8UL + ( h ? sizeof(fd_block_hash_t) : 0UL ) + FD_BLS_SIG_SZ;
  FD_TEST( n == 2UL + body_sz + 2UL );

  ulong off = 0UL;
  FD_TEST( out[off]==(uchar)1                          ); off += 1UL;
  FD_TEST( out[off]==(uchar)(v->kind+1U)               ); off += 1UL;
  FD_TEST( FD_LOAD( ulong, out+off )==fd_vote_slot( v )); off += 8UL;
  if( h ) { FD_TEST( !memcmp( out+off, h, sizeof(fd_block_hash_t) ) ); off += sizeof(fd_block_hash_t); }
  uchar const * wire_sig = out+off; off += FD_BLS_SIG_SZ;
  FD_TEST( FD_LOAD( ushort, out+off )==TEST_SHRED_VERSION  ); off += 2UL;
  FD_TEST( off==n );

  fd_vote_t rt;
  FD_TEST( fd_vote_de( &rt, out, n )==FD_VOTE_DE_SUCCESS );
  FD_TEST( rt.kind==v->kind );
  FD_TEST( fd_vote_shred_version( &rt )==TEST_SHRED_VERSION );
  FD_TEST( fd_vote_slot  ( &rt )==fd_vote_slot  ( v ) );
  fd_block_hash_t const * rt_h = block_hash( &rt );
  FD_TEST( !rt_h==!h );
  if( h ) FD_TEST( !memcmp( rt_h, h, sizeof(fd_block_hash_t) ) );
  FD_TEST( fd_vote_de( &rt, out, n-1UL )==FD_VOTE_DE_ERR_SZ ); /* too few  */
  FD_TEST( fd_vote_de( &rt, out, n+1UL )==FD_VOTE_DE_SUCCESS ); /* trailing */

  uchar wire_comp[ FD_VOTE_SER_MAX ]; memcpy( wire_comp, out, n );
  uchar * comp_sig = wire_comp + ( wire_sig-out );
  fd_bls_sig_compress( fd_vote_sig( v ), comp_sig );
  fd_memset( comp_sig+FD_BLS_SIG_COMPRESSED_SZ, 0xEE, FD_BLS_SIG_SZ-FD_BLS_SIG_COMPRESSED_SZ );
  FD_TEST( comp_sig[0]&0x80U );
  FD_TEST( fd_vote_de( &rt, wire_comp, n )==FD_VOTE_DE_SUCCESS );
  FD_TEST( fd_bls_sig_eq( fd_vote_sig( &rt ), fd_vote_sig( v ) ) );

  fd_memset( comp_sig, 0, FD_BLS_SIG_SZ );
  comp_sig[0] = 0x40; FD_TEST( fd_vote_de( &rt, wire_comp, n )==FD_VOTE_DE_ERR_SIG ); /* uncompressed identity */
  comp_sig[0] = 0xC0; FD_TEST( fd_vote_de( &rt, wire_comp, n )==FD_VOTE_DE_ERR_SIG ); /* compressed identity   */

  uchar          payload[ FD_VOTE_SIGNING_SER_MAX ];
  ulong          payload_sz = fd_vote_signing_ser( v->kind, fd_vote_slot( v ), h, TEST_SHRED_VERSION, payload );
  fd_bls_sig_t sig[1];
  FD_TEST( !fd_bls_sig_de_unchecked( sig, wire_sig ) );
  FD_TEST( fd_bls_agg_verify( payload, payload_sz, pk, sig ) );

  payload[ 1 ] ^= 0xFFu;
  FD_TEST( !fd_bls_agg_verify( payload, payload_sz, pk, sig ) );
}

static void
test_serialize( void ) {
  uchar        ikm[ 64 ]; for( ulong i=0UL; i<64UL; i++ ) ikm[i] = (uchar)(i+1u);
  fd_bls_sec_t sk; fd_bls_sec_derive( &sk, ikm, sizeof(ikm) );
  fd_bls_pub_t pk; fd_bls_sec_to_pub( &sk, &pk );
  uchar selector[ FD_BLS_PUB_COMPRESSED_SZ ]; fd_bls_pub_compress( &pk, selector );
  fd_block_hash_t h; for( ulong i=0UL; i<32UL; i++ ) h.uc[i] = (uchar)(0xA0u+i);

  fd_vote_t v;
  v = fd_vote_construct_notar( sec_sign_fn, &sk, selector, 12345UL, &h, 7UL, TEST_SHRED_VERSION ); check_wire( &v, &pk );
  v = fd_vote_construct_final( sec_sign_fn, &sk, selector, 7UL, 1UL, TEST_SHRED_VERSION ); check_wire( &v, &pk );
  v = fd_vote_construct_skip( sec_sign_fn, &sk, selector, 42UL, 3UL, TEST_SHRED_VERSION ); check_wire( &v, &pk );
  v = fd_vote_construct_notar_fallback( sec_sign_fn, &sk, selector, 99UL, &h, 65535UL, TEST_SHRED_VERSION ); check_wire( &v, &pk );
  v = fd_vote_construct_skip_fallback( sec_sign_fn, &sk, selector, 42UL, 3UL, TEST_SHRED_VERSION ); check_wire( &v, &pk );

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
