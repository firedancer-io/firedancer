#include "fd_shred_dest.h"

FD_IMPORT_BINARY( t1_pubkey,           "src/disco/shred/fixtures/cluster_info_pubkey.bin" );
FD_IMPORT_BINARY( t1_dest_info,        "src/disco/shred/fixtures/cluster_info.bin"        );
FD_IMPORT_BINARY( t1_broadcast_peers,  "src/disco/shred/fixtures/broadcast_peers.bin"     );
FD_IMPORT_BINARY( t1_retransmit_peers, "src/disco/shred/fixtures/retransmit_peers.bin"    );

#define TEST_MAX_FOOTPRINT (1024UL*1024UL)
uchar _sd_footprint[ TEST_MAX_FOOTPRINT ] __attribute__((aligned(FD_SHRED_DEST_ALIGN)));
uchar _l_footprint[ TEST_MAX_FOOTPRINT ] __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)));

fd_stake_weight_t stakes[2048];
FD_STATIC_ASSERT( FD_SHRED_DEST_ALIGN==alignof(fd_shred_dest_t), shred_dest_align );

FD_STATIC_ASSERT( sizeof(fd_shred_dest_weighted_t)==56UL, dest_info_construction );

static void
test_compute_first_matches_solana( void ) {
  ulong cnt = t1_dest_info_sz / sizeof(fd_shred_dest_weighted_t);
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
  fd_pubkey_t const * src_key = (fd_pubkey_t const *)t1_pubkey;
  FD_TEST( fd_shred_dest_footprint   ( cnt          ) <= TEST_MAX_FOOTPRINT );
  FD_TEST( fd_epoch_leaders_footprint( cnt, 10000UL ) <= TEST_MAX_FOOTPRINT );

  ulong staked = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
    stakes[i].key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 10000UL, staked, stakes ) );

  fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, src_key ) );

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
test_compute_children_matches_solana( void ) {
  ulong cnt = t1_dest_info_sz / sizeof(fd_shred_dest_weighted_t);
  fd_shred_dest_weighted_t const * info = (fd_shred_dest_weighted_t const *)t1_dest_info;
  fd_pubkey_t const * src_key = (fd_pubkey_t const *)t1_pubkey;
  FD_TEST( fd_shred_dest_footprint   ( cnt         ) <= TEST_MAX_FOOTPRINT );
  FD_TEST( fd_epoch_leaders_footprint( cnt, 2000UL ) <= TEST_MAX_FOOTPRINT );

  ulong staked = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    stakes[i].key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 4000UL, staked, stakes ) );

  fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, src_key ) );

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
    fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, &(info[src_idx].pubkey) ) );

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
      ushort child = out[i];
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
      stakes[i].key.uc[0] = (uchar)(cnt-i);
      info[i].stake_lamports = 1UL + fd_rng_ulong_roll( r, prev );
      stakes[i].stake = info[i].stake_lamports;
      prev = info[i].stake_lamports+1UL;
      info[i].ip4 = (uint)i;
    }
    fd_pubkey_t * src_key = &(info[0].pubkey);
    fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 100UL, cnt, stakes ) );
    fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, src_key ) );

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
      memset( stakes[i].key.uc, 0, 32UL );
      stakes[i].key.uc[0] = (uchar)pubkey0;
      pubkey0 = (pubkey0*3UL)%31; /* Hits [1, 30] */
      stakes[i].stake = 2UL + fd_rng_ulong_roll( r, prev );
      prev = stakes[i].stake;
    }
    stakes[30].key.uc[0] = 31;
    stakes[31].key.uc[0] = 0;
    stakes[30].stake = stakes[31].stake = prev-1UL;

    fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 100UL, cnt, stakes ) );
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
    stakes[i].key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 4000UL, staked, stakes ) );
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
    stakes[i].key = info[i].pubkey;
    stakes[i].stake = info[i].stake_lamports;
    staked += (info[i].stake_lamports>0UL);
  }

  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 10000UL, staked, stakes ) );

  fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, info, cnt, lsched, src_key ) );
  fd_shred_dest_idx_to_dest( sdest, (ushort)0 )->ip4 = 12U;
  FD_TEST( fd_shred_dest_idx_to_dest( sdest, (ushort)0 )->ip4 == 12U );
  fd_shred_dest_idx_to_dest( sdest, (ushort)0 )->ip4 = 14U;
  FD_TEST( fd_shred_dest_idx_to_dest( sdest, (ushort)0 )->ip4 == 14U );

  fd_shred_dest_delete( fd_shred_dest_leave( sdest ) );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
}

static void
test_errors( void ) {
  FD_TEST( NULL==fd_shred_dest_new( NULL,      NULL, 0, NULL, NULL ) );
  FD_TEST( NULL==fd_shred_dest_new( (void *)1, NULL, 0, NULL, NULL ) );

  memset( &(stakes[0].key), 1, 32UL );
  stakes[0].stake = 100UL;
  fd_pubkey_t const * src_key = (fd_pubkey_t const *)t1_pubkey;
  fd_epoch_leaders_t * lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( _l_footprint, 0UL, 0UL, 10000UL, 1UL, stakes ) );

  fd_shred_dest_t * sdest = fd_shred_dest_join( fd_shred_dest_new( _sd_footprint, NULL, 0UL, lsched, src_key ) );
  FD_TEST( sdest==NULL );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( lsched ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_shred_dest_align() == FD_SHRED_DEST_ALIGN );

  test_errors();
  FD_LOG_NOTICE(( "Testing conformance with Solana Labs code" ));
  test_compute_first_matches_solana();
  test_compute_children_matches_solana();
  FD_LOG_NOTICE(( "Varying stake" ));
  test_vary_stake();
  FD_LOG_NOTICE(( "Varying radix" ));
  test_t1_vary_radix();
  FD_LOG_NOTICE(( "Testing batching" ));
  test_batching();
  test_change_contact();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
