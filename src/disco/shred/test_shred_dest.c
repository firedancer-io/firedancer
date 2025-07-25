#include "fd_shred_dest.h"

FD_IMPORT_BINARY( t1_pubkey,           "src/disco/shred/fixtures/cluster_info_pubkey.bin" );  /* fd_pubkey[] */
FD_IMPORT_BINARY( t1_dest_info,        "src/disco/shred/fixtures/cluster_info.bin"        );  /* fd_shred_dest_weighted_t[] */
FD_IMPORT_BINARY( t1_broadcast_peers,  "src/disco/shred/fixtures/broadcast_peers.bin"     );  /* fd_pubkey[] */
FD_IMPORT_BINARY( t1_retransmit_peers, "src/disco/shred/fixtures/retransmit_peers.bin"    );  /* ulong[] */
FD_IMPORT_BINARY( testnet_dest_info,   "src/disco/shred/fixtures/testnet.bin"             );  /* fd_shred_dest_weighted_t[] */

#define TEST_MAX_FOOTPRINT (4UL*1024UL*1024UL)
uchar _sd_footprint[ TEST_MAX_FOOTPRINT ] __attribute__((aligned(FD_SHRED_DEST_ALIGN)));
uchar _l_footprint[ TEST_MAX_FOOTPRINT ] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));

#define TEST_MAX_VALIDATORS 10240
fd_vote_stake_weight_t stakes[ TEST_MAX_VALIDATORS ];
FD_STATIC_ASSERT( FD_SHRED_DEST_ALIGN==alignof(fd_shred_dest_t), shred_dest_align );

FD_STATIC_ASSERT( sizeof(fd_shred_dest_weighted_t)==48UL, dest_info_construction );

const ulong vote_keyed_lsched = 0UL;

static void
test_compute_first_matches_agave( void ) {
  ulong cnt = t1_dest_info_sz / sizeof(fd_shred_dest_weighted_t);
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
  fd_pubkey_t const * src_key = (fd_pubkey_t const *)t1_pubkey;

  ulong staked = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
    stakes[i].id_key = info[i].pubkey;
    stakes[i].vote_key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }
  FD_TEST( fd_shred_dest_footprint   ( staked, staked-cnt ) <= TEST_MAX_FOOTPRINT );
  FD_TEST( fd_epoch_leaders_footprint( cnt, 10000UL       ) <= TEST_MAX_FOOTPRINT );

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 10000UL, staked, stakes, 0UL, vote_keyed_lsched ) );
  FD_TEST( lsched );

  fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, src_key, 0UL ) );
  FD_TEST( sdest );

  fd_shred_dest_idx_t result[1];
  fd_shred_t shred[1];
  fd_shred_t const * shred_ptr[ 1 ] = { shred };

  ulong j=0UL;
  for( ulong slot=0UL; slot<10000UL; slot++ ) {
    if( FD_LIKELY( memcmp( fd_epoch_leaders_get( lsched, slot ), src_key, 32UL ) ) ) continue;
    shred->slot = slot;
    for( int type=0; type<2; type++ ) {
      shred->variant = fd_shred_variant( type==0 ? FD_SHRED_TYPE_MERKLE_DATA : FD_SHRED_TYPE_MERKLE_CODE, 2 );
      for( ulong idx=(ulong)(type+1); idx<67UL; idx += 3UL ) {
        shred->idx = (uint)idx;
        FD_TEST( fd_shred_dest_compute_first( sdest, shred_ptr, 1UL, result ) );
        fd_shred_dest_weighted_t const * rresult = fd_shred_dest_idx_to_dest( sdest, *result );
        /* The test stores a 0 pubkey when we don't know the contact info
           even if we know the pubkey. */
        if( !rresult->ip4 ) rresult = fd_shred_dest_idx_to_dest( sdest, FD_SHRED_DEST_NO_DEST );

        FD_TEST( !memcmp( rresult->pubkey.uc, t1_broadcast_peers+32UL*j, 32UL ) );

        j++;
      }
    }
  }
  FD_TEST( j*32UL == t1_broadcast_peers_sz );

  fd_shred_dest_delete( fd_shred_dest_leave( sdest ) );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
}

static void
test_compute_children_matches_agave( void ) {
  ulong cnt = t1_dest_info_sz / sizeof(fd_shred_dest_weighted_t);
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
  fd_pubkey_t const * src_key = (fd_pubkey_t const *)t1_pubkey;

  ulong staked = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    stakes[i].id_key = info[i].pubkey;
    stakes[i].vote_key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }

  FD_TEST( fd_shred_dest_footprint   ( staked, cnt-staked ) <= TEST_MAX_FOOTPRINT );
  FD_TEST( fd_epoch_leaders_footprint( cnt,        2000UL ) <= TEST_MAX_FOOTPRINT );

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 4000UL, staked, stakes, 0UL, vote_keyed_lsched ) );

  fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, src_key, 0UL ) );

  ulong const * ans_ul = (ulong const *)t1_retransmit_peers;

  fd_shred_dest_idx_t result[200];
  fd_shred_t shred[1];
  fd_shred_t const * shred_ptr[ 1 ] = { shred };

  ulong j=0UL;
  for( ulong slot=1UL; slot<2000UL; slot += 97UL ) {
    shred->slot = slot;
    for( int type=0; type<2; type++ ) {
      shred->variant = fd_shred_variant( type==0 ? FD_SHRED_TYPE_MERKLE_DATA : FD_SHRED_TYPE_MERKLE_CODE, 2 );
      for( ulong idx=(ulong)(type+1); idx<67UL; idx += 3UL ) {
        shred->idx = (uint)idx;
        ulong max_dest_cnt[1] = { 0UL };
        FD_TEST( fd_shred_dest_compute_children( sdest, shred_ptr, 1UL, result, 1UL, 200UL, 200UL, max_dest_cnt ) );

        ulong answer_cnt = ans_ul[j++];
        FD_TEST( *max_dest_cnt == answer_cnt );
        for( ulong i=0UL; i<answer_cnt; i++ ) {
          fd_shred_dest_weighted_t const * rresult = fd_shred_dest_idx_to_dest( sdest, result[i] );
          FD_TEST( !memcmp( rresult->pubkey.uc, ans_ul+j, 32UL ) );

          j += 32/sizeof(ulong);
        }
        for( ulong i=answer_cnt; i<200UL; i++ ) FD_TEST( result[i]==FD_SHRED_DEST_NO_DEST );
      }
    }
  }

  fd_shred_dest_delete( fd_shred_dest_leave( sdest ) );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
}

static void
test_distribution_is_tree( fd_shred_dest_weighted_t const * info, ulong cnt, fd_epoch_leaders_t * lsched, ulong fanout, ulong slot, int is_data, ulong idx ) {
  uchar hit[2048] = { 0 };
  fd_shred_dest_idx_t out[1024];
  fd_shred_t shred[1];
  fd_shred_t const * shred_ptr[ 1 ] = { shred };

  /* If any of these fail, adjust test */
  FD_TEST(    cnt<2048UL );
  FD_TEST( fanout<1024UL );
  FD_TEST( cnt<=fanout*(fanout+1UL) );


  shred->slot = slot;
  shred->variant = fd_shred_variant( is_data ? FD_SHRED_TYPE_MERKLE_DATA : FD_SHRED_TYPE_MERKLE_CODE, 2 );
  shred->idx = (uint)idx;

  fd_pubkey_t const * leader = fd_epoch_leaders_get( lsched, slot );

  for( ulong src_idx=0UL; src_idx<cnt; src_idx++ ) {
    fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, &(info[src_idx].pubkey), 0UL ) );

    ulong dest_cnt = 0UL;
    if( !memcmp( &(info[src_idx].pubkey), leader, 32UL ) ) {
      //FD_LOG_NOTICE(( "%lu is leader", src_idx ));
      FD_TEST( out==fd_shred_dest_compute_first( sdest, shred_ptr, 1UL, out ) );
      FD_TEST( !hit[ src_idx ] );
      hit[ src_idx ] = 1;
      dest_cnt = 1UL;
    } else {
      //FD_LOG_NOTICE(( "%lu is not leader", src_idx ));
      FD_TEST( out==fd_shred_dest_compute_children( sdest, shred_ptr, 1UL, out, 1UL, fanout, fanout, &dest_cnt ) );
    }

    for( ulong i=0; i<dest_cnt; i++ ) {
      fd_shred_dest_idx_t child = out[i];
      if( FD_LIKELY( child != FD_SHRED_DEST_NO_DEST ) ) {
        FD_TEST( !hit[child] );
        hit[child] = 1;
        //FD_LOG_NOTICE(( " %lu -> %lu", src_idx, (ulong)child ));
      }
    }
    fd_shred_dest_delete( fd_shred_dest_leave( sdest ) );
  }

  for( ulong j=0UL; j<cnt; j++ ) FD_TEST( hit[j] );
}
static void
test_batching( void ) {
  fd_rng_t _rng[1]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cnt = 32UL;
  fd_shred_dest_weighted_t info[32];
  fd_memset( info, 0, sizeof(info) );
  for( ulong iter=0UL; iter<1000UL; iter++ ) {
    /* Random stakes for shred dest. All positive. */
    ulong prev = 1UL<<48;
    for( ulong i=0UL; i<cnt; i++ ) {
      info[i].pubkey.uc[0] = (uchar)(cnt-i);
      stakes[i].id_key.uc[0] = (uchar)(cnt-i);
      stakes[i].vote_key.uc[0] = (uchar)(cnt-i);
      info[i].stake_lamports = 1UL + fd_rng_ulong_roll( r, prev );
      stakes[i].stake = info[i].stake_lamports;
      prev = info[i].stake_lamports+1UL;
      info[i].ip4 = (uint)i;
    }
    fd_pubkey_t * src_key = &(info[0].pubkey);
    fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 100UL, cnt, stakes, 0UL, vote_keyed_lsched ) );
    fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, src_key, 0UL ) );

#define BATCH_CNT 5
    fd_shred_dest_idx_t result1[BATCH_CNT*BATCH_CNT];
    fd_shred_dest_idx_t result2[BATCH_CNT*BATCH_CNT];
    fd_shred_t shred[BATCH_CNT];
    fd_shred_t const * shred_ptr[ BATCH_CNT ];
    for( ulong j=0UL; j<BATCH_CNT; j++ ) shred_ptr[j] = shred+j;

    memset( result1, 0x11, sizeof(result1) );
    memset( result2, 0x22, sizeof(result2) );

    for( ulong slot=0UL; slot<100UL; slot+=4 ) {
      for( ulong j=0UL; j<BATCH_CNT; j++ ) {
        shred[j].slot = slot;
        shred[j].idx = fd_rng_uint_roll( r, 100UL );
        shred[j].variant = fd_shred_variant( fd_rng_int_roll( r, 2 ) ? FD_SHRED_TYPE_MERKLE_DATA : FD_SHRED_TYPE_MERKLE_CODE, 2 );
      }
      if( FD_LIKELY( memcmp( fd_epoch_leaders_get( lsched, slot ), src_key, 32UL ) ) ) {
        /* Not leader */
        FD_TEST( fd_shred_dest_compute_children( sdest, shred_ptr, 5UL, result1, 5UL, 5UL, 5UL, NULL ) );
        for( ulong j=0UL; j<BATCH_CNT; j++ ) {
          FD_TEST( fd_shred_dest_compute_children( sdest, shred_ptr+j, 1UL, result2+j, 5UL, 5UL, 5UL, NULL ) );
        }
        for( ulong j=0UL; j<BATCH_CNT*BATCH_CNT; j++ ) FD_TEST( result1[j]==result2[j] );
      } else {
        /* Leader */
        FD_TEST( fd_shred_dest_compute_first( sdest, shred_ptr, 5UL, result1 ) );
        for( ulong j=0UL; j<BATCH_CNT; j++ ) {
          FD_TEST( fd_shred_dest_compute_first( sdest, shred_ptr+j, 1UL, result2+j ) );
          FD_TEST( result1[j]==result2[j] );
        }
      }
    }
    fd_shred_dest_delete( fd_shred_dest_leave( sdest ) );
    fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
  }
}

static void
test_vary_stake( void ) {
  fd_rng_t _rng[1]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cnt = 32UL;
  fd_shred_dest_weighted_t info[32];
  fd_memset( info, 0, sizeof(info) );
  for( ulong iter=0UL; iter<1000UL; iter++ ) {
    /* Random stakes for shred dest. Non-increasing, some zeros. */
    ulong prev = 1UL<<48;
    ulong staked_cnt = fd_rng_ulong_roll( r, 33UL );
    if( iter%100UL==0UL ) FD_LOG_NOTICE(( "iter %lu, staked_cnt=%lu", iter, staked_cnt ));
    for( ulong i=0UL; i<cnt; i++ ) {
      info[i].pubkey.uc[0] = (uchar)(cnt-i);
      info[i].stake_lamports = i<staked_cnt ? fd_rng_ulong_roll( r, prev ) : 0UL;
      prev = info[i].stake_lamports+1UL;
      info[i].ip4 = (uint)i;
    }
    /* Totally different stakes for leader schedule. All positive */
    prev = 1UL<<48;
    ulong pubkey0 = 1UL+fd_rng_ulong_roll( r, 30UL );
    for( ulong i=0UL; i<30UL; i++ ) {
      memset( stakes[i].id_key.uc, 0, 32UL );
      memset( stakes[i].vote_key.uc, 0, 32UL );
      stakes[i].id_key.uc[0] = (uchar)pubkey0;
      stakes[i].vote_key.uc[0] = (uchar)pubkey0;
      pubkey0 = (pubkey0*3UL)%31; /* Hits [1, 30] */
      stakes[i].stake = 2UL + fd_rng_ulong_roll( r, prev );
      prev = stakes[i].stake;
    }
    stakes[30].id_key.uc[0] = 31;
    stakes[31].id_key.uc[0] = 0;
    stakes[30].vote_key.uc[0] = 31;
    stakes[31].vote_key.uc[0] = 0;
    stakes[30].stake = stakes[31].stake = prev-1UL;

    fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 100UL, cnt, stakes, 0UL, vote_keyed_lsched ) );
    test_distribution_is_tree( info, 32UL, lsched, 6+fd_rng_ulong_roll(r, 25UL ), fd_rng_ulong_roll( r, 100UL ), fd_rng_int_roll( r, 2 ), fd_rng_ulong_roll( r, 100UL ) );
    fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
  }
  fd_rng_delete( fd_rng_leave( r ) );
}

static void
test_t1_vary_radix( void ) {
  fd_rng_t _rng[1]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong staked = 0UL;
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
  ulong cnt = t1_dest_info_sz / sizeof(fd_shred_dest_weighted_t);
  for( ulong i=0UL; i<cnt; i++ ) {
    stakes[i].id_key = info[i].pubkey;
    stakes[i].vote_key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 4000UL, staked, stakes, 0UL, vote_keyed_lsched ) );
  for( ulong fanout=35UL; fanout<650UL; fanout+=11UL ) {
    FD_LOG_NOTICE(( "Fanout: %lu", fanout ));
    test_distribution_is_tree( info, cnt, lsched, fanout, fd_rng_ulong_roll( r, 4000UL ), fd_rng_int_roll( r, 2 ), fd_rng_ulong_roll( r, 100UL ) );
  }

  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
  fd_rng_delete( fd_rng_leave( r ) );
}
static void
test_change_contact( void ) {
  ulong cnt = t1_dest_info_sz / sizeof(fd_shred_dest_weighted_t);
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
  fd_pubkey_t const * src_key = (fd_pubkey_t const *)t1_pubkey;

  ulong staked = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    stakes[i].id_key = info[i].pubkey;
    stakes[i].vote_key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 10000UL, staked, stakes, 0UL, vote_keyed_lsched ) );

  fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, src_key, 0UL ) );
  fd_shred_dest_idx_to_dest( sdest, (ushort)0 )->ip4 = 12U;
  FD_TEST( fd_shred_dest_idx_to_dest( sdest, (ushort)0 )->ip4 == 12U );
  fd_shred_dest_idx_to_dest( sdest, (ushort)0 )->ip4 = 14U;
  FD_TEST( fd_shred_dest_idx_to_dest( sdest, (ushort)0 )->ip4 == 14U );

  fd_shred_dest_delete( fd_shred_dest_leave( sdest ) );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
}

static void
test_errors( void ) {
  FD_TEST( NULL==fd_shred_dest_new( NULL,      NULL, 0, NULL, NULL, 0UL ) );
  FD_TEST( NULL==fd_shred_dest_new( (void *)1, NULL, 0, NULL, NULL, 0UL ) );

  memset( &(stakes[0].id_key), 1, 32UL );
  memset( &(stakes[0].vote_key), 1, 32UL );
  stakes[0].stake = 100UL;
  fd_pubkey_t const * src_key = (fd_pubkey_t const *)t1_pubkey;
  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 10000UL, 1UL, stakes, 0UL, vote_keyed_lsched ) );

  fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, NULL, 0UL, lsched, src_key, 0UL ) );
  FD_TEST( sdest==NULL );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
}

static void
test_indeterminate( void ) {
  fd_rng_t _rng[1]; fd_rng_t * r = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong staked_cnt = 0UL;

  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
  ulong cnt = t1_dest_info_sz / sizeof(fd_shred_dest_weighted_t);
  for( ulong i=0UL; i<cnt; i++ ) {
    stakes[i].id_key = info[i].pubkey;
    stakes[i].vote_key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked_cnt += (info[i].stake_lamports>0UL);
  }

  ulong truncated_cnt  = 995UL*staked_cnt/1000UL;
  ulong excluded_stake = 0UL;
  for( ulong i=truncated_cnt; i<staked_cnt; i++ ) excluded_stake += stakes[i].stake;

  uchar * lf_full  = _l_footprint;
  uchar * lf_trunc = _l_footprint + fd_epoch_leaders_footprint( staked_cnt, 4000UL );
  FD_TEST( lf_trunc + fd_epoch_leaders_footprint( truncated_cnt, 4000UL ) < _l_footprint + TEST_MAX_FOOTPRINT );

  fd_epoch_leaders_t * lsched_full  = fd_epoch_leaders_join( fd_epoch_leaders_new( lf_full,  0UL, 0UL, 4000UL, staked_cnt,
                                                                                   stakes, 0UL,            vote_keyed_lsched ) );
  fd_epoch_leaders_t * lsched_trunc = fd_epoch_leaders_join( fd_epoch_leaders_new( lf_trunc, 0UL, 0UL, 4000UL, truncated_cnt,
                                                                                   stakes, excluded_stake, vote_keyed_lsched ) );

  uchar * sf_full  = _sd_footprint;
  uchar * sf_trunc = _sd_footprint + fd_shred_dest_footprint( staked_cnt, 0UL );
  FD_TEST( sf_trunc + fd_shred_dest_footprint( truncated_cnt, 0UL ) < _sd_footprint + TEST_MAX_FOOTPRINT );

  ulong match_cnt   = 0UL;
  ulong no_dest_cnt = 0UL;
  for( ulong iter=0UL; iter<5000UL; iter++ ) {
    fd_pubkey_t const * src = &(info[ fd_rng_ulong_roll( r, truncated_cnt + (staked_cnt-truncated_cnt)/4UL ) ].pubkey);
    fd_shred_dest_t * sdest_full  = fd_shred_dest_join( fd_shred_dest_new( sf_full,  info, staked_cnt,    lsched_full,  src, 0UL            ) );
    fd_shred_dest_t * sdest_trunc = fd_shred_dest_join( fd_shred_dest_new( sf_trunc, info, truncated_cnt, lsched_trunc, src, excluded_stake ) );

    ulong slot = fd_rng_ulong_roll( r, 4000UL );
    ulong fanout = fd_rng_ulong_roll( r, 200UL ) + 65UL;

    if( FD_UNLIKELY( sdest_trunc==NULL ) ) {
      no_dest_cnt += fanout;
      continue;
    }

    fd_pubkey_t const * leader = fd_epoch_leaders_get( lsched_full, slot );

    fd_shred_t shred[1];
    fd_shred_t const * shred_ptr[ 1 ] = { shred };
    shred->slot = slot;
    shred->variant = fd_shred_variant( fd_rng_int_roll( r, 2 ) ? FD_SHRED_TYPE_MERKLE_DATA : FD_SHRED_TYPE_MERKLE_CODE, 2 );
    shred->idx = fd_rng_uint_roll( r, 100UL );

    fd_shred_dest_idx_t out_full [1024];
    fd_shred_dest_idx_t out_trunc[1024];
    ulong dest_cnt = 0UL;
    if( !memcmp( src, leader, 32UL ) ) {
      FD_TEST( out_full==             fd_shred_dest_compute_first( sdest_full,  shred_ptr, 1UL, out_full  ) );
      fd_shred_dest_idx_t * o_trunc = fd_shred_dest_compute_first( sdest_trunc, shred_ptr, 1UL, out_trunc );
      if( FD_UNLIKELY( o_trunc==NULL ) ) {
        no_dest_cnt++;
      } else {
        FD_TEST( o_trunc==out_trunc );
        dest_cnt = 1UL;
      }
    } else {
      ulong dcnt_f = 0UL;
      ulong dcnt_t = 0UL;
      FD_TEST( out_full==             fd_shred_dest_compute_children( sdest_full,  shred_ptr, 1UL, out_full,  1UL, fanout, fanout, &dcnt_f ) );
      fd_shred_dest_idx_t * o_trunc = fd_shred_dest_compute_children( sdest_trunc, shred_ptr, 1UL, out_trunc, 1UL, fanout, fanout, &dcnt_t );
      FD_TEST( dcnt_f>=dcnt_t ); /* == in the good case */

      if( FD_UNLIKELY( o_trunc==NULL ) ) {
        no_dest_cnt+=fanout;
      } else {
        FD_TEST( o_trunc==out_trunc );
        dest_cnt     = dcnt_t;
        no_dest_cnt += dcnt_f - dcnt_t;
      }
    }

    for( ulong i=0UL; i<dest_cnt; i++ ) {
      if( FD_LIKELY( out_full[ i ]==out_trunc[ i ] ) ) match_cnt++;
      else {
        FD_TEST( out_trunc[ i ]==FD_SHRED_DEST_NO_DEST );
        no_dest_cnt++;
      }
    }

    fd_shred_dest_delete( fd_shred_dest_leave( sdest_trunc ) );
    fd_shred_dest_delete( fd_shred_dest_leave( sdest_full  ) );
  }

  FD_LOG_NOTICE(( "Matched on %lu destination.  %lu destinations were not known because of truncation", match_cnt, no_dest_cnt ));

  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched_trunc ) );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched_full  ) );
  fd_rng_delete( fd_rng_leave( r ) );
}

static void
test_performance( void ) {
  ulong cnt = testnet_dest_info_sz / sizeof(fd_shred_dest_weighted_t);
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)testnet_dest_info;

  fd_pubkey_t const * src_key = (fd_pubkey_t const *)(&info[18].pubkey);
  FD_TEST( cnt                                        <= TEST_MAX_VALIDATORS );

  ulong staked = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    stakes[i].id_key = info[i].pubkey;
    stakes[i].vote_key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }

  FD_TEST( fd_shred_dest_footprint   ( staked, cnt-staked ) <= TEST_MAX_FOOTPRINT  );
  FD_TEST( fd_epoch_leaders_footprint( cnt,       10000UL ) <= TEST_MAX_FOOTPRINT  );

  long dt = -fd_log_wallclock();
  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 10000UL, staked, stakes, 0UL, vote_keyed_lsched ) );
  fd_shred_dest_t    * sdest  = fd_shred_dest_join   ( fd_shred_dest_new   ( _sd_footprint, info, cnt, lsched, src_key, 0UL ) );
  dt += fd_log_wallclock();

  ulong max_dest_cnt[ 16 ] = { 0UL };
  fd_shred_t shred[ 16 ];
  fd_shred_t const * shred_ptr[ 16 ];
  fd_shred_dest_idx_t result[ 16*200 ];
  for( ulong j=0UL; j<16UL; j++ ) {
    shred_ptr[j] = shred+j;

    shred[j].slot = 1UL;
    shred[j].variant = j<8UL ? FD_SHRED_TYPE_MERKLE_DATA : FD_SHRED_TYPE_MERKLE_CODE;
  }

  dt = -fd_log_wallclock();
#define TEST_CNT 1000000
  for( ulong j=0UL; j<TEST_CNT; j++ ) {
    shred[0].idx = (uint)j;
    FD_TEST( fd_shred_dest_compute_children( sdest, shred_ptr, 1UL, result, 1UL, 200UL, 200UL, max_dest_cnt ) );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "Compute children (1 shred/batch): %.2f ns/shred", (double)dt / (double)TEST_CNT ));

  dt = -fd_log_wallclock();
#undef TEST_CNT
#define TEST_CNT 10000
  for( ulong j=0UL; j<TEST_CNT; j++ ) {
    for( ulong k=0UL; k<16UL; k++ ) shred[k].idx = (uint)(j*16UL+k);
    FD_TEST( fd_shred_dest_compute_children( sdest, shred_ptr, 16UL, result, 16UL, 200UL, 200UL, max_dest_cnt ) );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "Compute children (16 shred/batch): %.2f ns/shred", (double)dt / (double)(16UL*TEST_CNT) ));
#undef TEST_CNT
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_shred_dest_align() == FD_SHRED_DEST_ALIGN );

  test_errors();
  FD_LOG_NOTICE(( "Testing conformance with Agave code" ));
  test_compute_first_matches_agave();
  test_compute_children_matches_agave();
  FD_LOG_NOTICE(( "Varying stake" ));
  test_vary_stake();
  FD_LOG_NOTICE(( "Varying radix" ));
  test_t1_vary_radix();
  FD_LOG_NOTICE(( "Testing batching" ));
  test_batching();
  FD_LOG_NOTICE(( "Testing contact change" ));
  test_change_contact();
  FD_LOG_NOTICE(( "Testing indeterminate" ));
  test_indeterminate();
  FD_LOG_NOTICE(( "Testing performance" ));
  test_performance();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
