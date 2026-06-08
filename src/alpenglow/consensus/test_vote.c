#include "fd_vote.h"

/* Mirrors alpenglow/src/consensus/vote.rs mod tests::basic plus payload
   distinctness checks. */

static void
test_basic( void ) {
  fd_aggsig_sk_t sk; fd_memset( sk.v, 9, FD_AGGSIG_SECKEY_SZ );
  fd_aggsig_pk_t pk; fd_aggsig_sk_to_pk( &pk, &sk );
  fd_hash_t h; memset( h.uc, 0, sizeof(fd_hash_t) ); /* genesis block hash */

  fd_vote_t v;

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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_basic();
  test_payload_distinct();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
