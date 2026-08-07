#include "ag_epoch_info.h"
#include <stdlib.h>

static ag_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  ag_validator_info_t * v = (ag_validator_info_t *)malloc( n*sizeof(ag_validator_info_t) );
  FD_TEST( v );
  for( ulong i=0UL; i<n; i++ ) {
    memset( &v[i], 0, sizeof(ag_validator_info_t) );
    v[i].id    = i;
    v[i].stake = 1UL;
    ag_aggsig_sk_t sk; fd_memset( sk.v, (int)(i+1UL), AG_AGGSIG_SECKEY_SZ );
    ag_aggsig_sk_to_pk( &v[i].voting_pubkey, &sk );
  }
  void * mem = aligned_alloc( ag_epoch_info_align(), ag_epoch_info_footprint( n ) );
  FD_TEST( mem );
  ag_epoch_info_t * ei = ag_epoch_info_join( ag_epoch_info_new( mem, v, n ) );
  free( v );
  *out_mem = mem;
  return ei;
}

static void
test_quorums( void ) {
  void * m6; ag_epoch_info_t * e6 = make_epoch( 6UL, &m6 );
  FD_TEST( ag_epoch_info_total_stake( e6 )==6UL );
  FD_TEST(  ag_epoch_info_is_weak_quorum  ( e6, 3UL ) );
  FD_TEST( !ag_epoch_info_is_quorum       ( e6, 3UL ) );
  FD_TEST(  ag_epoch_info_is_quorum       ( e6, 4UL ) );
  FD_TEST( !ag_epoch_info_is_strong_quorum( e6, 4UL ) );
  FD_TEST(  ag_epoch_info_is_strong_quorum( e6, 5UL ) );
  free( m6 );

  void * m11; ag_epoch_info_t * e11 = make_epoch( 11UL, &m11 );
  FD_TEST(  ag_epoch_info_is_weak_quorum  ( e11, 5UL ) );
  FD_TEST( !ag_epoch_info_is_quorum       ( e11, 5UL ) );
  FD_TEST(  ag_epoch_info_is_quorum       ( e11, 7UL ) );
  FD_TEST( !ag_epoch_info_is_strong_quorum( e11, 7UL ) );
  FD_TEST(  ag_epoch_info_is_strong_quorum( e11, 9UL ) );
  free( m11 );

  void * m5; ag_epoch_info_t * e5 = make_epoch( 5UL, &m5 );
  FD_TEST( !ag_epoch_info_is_weakest_quorum( e5, 0UL ) );
  FD_TEST(  ag_epoch_info_is_weakest_quorum( e5, 1UL ) );
  free( m5 );

  void * m100; ag_epoch_info_t * e100 = make_epoch( 100UL, &m100 );
  FD_TEST(  ag_epoch_info_is_quorum       ( e100, 60UL ) );
  FD_TEST(  ag_epoch_info_is_strong_quorum( e100, 80UL ) );
  FD_TEST( !ag_epoch_info_is_strong_quorum( e100, 79UL ) );
  free( m100 );
}

static void
test_leader( void ) {
  void * m; ag_epoch_info_t * e = make_epoch( 3UL, &m );

  FD_TEST( ag_epoch_info_leader( e, 0UL  )->id==0UL );
  FD_TEST( ag_epoch_info_leader( e, 3UL  )->id==0UL );
  FD_TEST( ag_epoch_info_leader( e, 4UL  )->id==1UL );
  FD_TEST( ag_epoch_info_leader( e, 8UL  )->id==2UL );
  FD_TEST( ag_epoch_info_leader( e, 12UL )->id==0UL );
  FD_TEST( ag_epoch_info_validator( e, 2UL )->id==2UL );
  free( m );
}


static void
set_bls( uchar * bls_pubkeys, ulong i, uchar seed ) {
  ag_aggsig_sk_t sk; fd_memset( sk.v, (int)seed, AG_AGGSIG_SECKEY_SZ );
  ag_aggsig_sk_to_pk_compressed( bls_pubkeys + i*AG_AGGSIG_PUBKEY_COMPRESSED_SZ, &sk );
}

static void
test_rank( void ) {
# define N 8UL
  fd_vote_stake_weight_t stakes[ N ];
  uchar                  bls[ N*AG_AGGSIG_PUBKEY_COMPRESSED_SZ ];
  ag_validator_info_t    out[ N ];

  for( ulong i=0UL; i<N; i++ ) {
    memset( &stakes[i], 0, sizeof(fd_vote_stake_weight_t) );
    memset( stakes[i].id_key.uc,   (int)(0x10U+i), sizeof(fd_pubkey_t) ); /* distinct identity */
    memset( stakes[i].vote_key.uc, (int)(0x40U+i), sizeof(fd_pubkey_t) );
    set_bls( bls, i, (uchar)(i+1UL) );                                    /* distinct BLS key */
  }

  stakes[0].stake = 100UL;                                          /* survives -> rank 0 */
  stakes[1].stake =  90UL;                                          /* survives -> rank 1 */
  stakes[2].stake =   0UL;                                          /* dropped: no stake   */
  stakes[3].stake =  80UL;                                          /* survives -> rank 2 */
  stakes[4].stake =  70UL; set_bls( bls, 4UL, 0xAAU );              /* dropped: BLS dup    */
  stakes[5].stake =  60UL; set_bls( bls, 5UL, 0xAAU );              /* dropped: BLS dup    */
  stakes[6].stake =  50UL; memset( stakes[6].id_key.uc, 0xBB, 32 ); /* dropped: id dup     */
  stakes[7].stake =  40UL; memset( stakes[7].id_key.uc, 0xBB, 32 ); /* dropped: id dup     */

  ulong cnt = ag_epoch_info_rank( out, N, stakes, N, bls );

  /* Both copies of a duplicated key are dropped, not just the extras. */
  FD_TEST( cnt==3UL );
  FD_TEST( out[0].stake==100UL && out[0].id==0UL );
  FD_TEST( out[1].stake== 90UL && out[1].id==1UL );
  FD_TEST( out[2].stake== 80UL && out[2].id==2UL );

  /* Equal stake ties break on the compressed BLS pubkey ascending. */
  for( ulong i=0UL; i<N; i++ ) {
    memset( &stakes[i], 0, sizeof(fd_vote_stake_weight_t) );
    memset( stakes[i].id_key.uc, (int)(0x10U+i), sizeof(fd_pubkey_t) );
    set_bls( bls, i, (uchar)(i+1UL) );
    stakes[i].stake = 7UL;
  }
  cnt = ag_epoch_info_rank( out, N, stakes, N, bls );
  FD_TEST( cnt==N );
  for( ulong r=1UL; r<cnt; r++ ) {
    FD_TEST( memcmp( out[r-1UL].voting_pubkey.v, out[r].voting_pubkey.v, AG_AGGSIG_PUBKEY_SZ )!=0 );
    FD_TEST( out[r].id==r );
  }
# undef N
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_quorums();
  test_leader();
  test_rank();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
