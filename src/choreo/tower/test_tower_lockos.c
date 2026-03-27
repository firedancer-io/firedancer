#include "fd_tower.c"

void
mock_vote_acc( fd_hash_t const * pubkey, ulong stake, ulong vote, uint conf, fd_tower_vtr_t * out, fd_tower_vote_t * votes_mem ) {
  fd_vote_acc_t voter = {
    .kind = FD_VOTE_ACC_V3,
    .v3 = {
      .node_pubkey = *pubkey,
      .votes_cnt = 1,
      .votes = {
        { .slot = vote, .conf = conf },
      },
    }
  };

  fd_tower_vote_remove_all( votes_mem );
  fd_tower_from_vote_acc( votes_mem, &out->root, (uchar const *)&voter );
  out->votes    = votes_mem;
  out->stake    = stake;
  out->vote_acc = *pubkey;
}

void
test_lockos( fd_wksp_t * wksp ) {
  ulong slot_max    = 64;
  ulong voter_max   = 16;

  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( slot_max, voter_max ), 1UL );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, slot_max, voter_max, 0UL ) );

  lockout_interval_map_t * lck_map  = tower->lck_map;
  lockout_interval_t *     lck_pool = tower->lck_pool;

  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_votes_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_votes = fd_tower_vote_join( fd_tower_vote_new( mock_votes_mem ) );

  fd_tower_vtr_t acct;
  ulong fork_slot = 1;
  ulong end_intervals[31];
  for( ulong i = 1; i < 32; i++ ) {
    ulong vote_slot = 50 - (i - 1);
    mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, vote_slot, (uint)i, &acct, mock_votes );
    fd_tower_lockos_insert( tower, fork_slot, &acct.vote_acc, acct.votes );
    end_intervals[i - 1] = vote_slot + (1UL << (uint)i);
  }

  for( ulong i = 0; i < 31; i++ ) {
    ulong key = lockout_interval_key( fork_slot, end_intervals[i] );
    FD_TEST( lockout_interval_map_ele_query( lck_map, &key, NULL, lck_pool ) );
  }

  /* Verify sentinels exist for fork_slot. */

  ulong sentinel_key = lockout_interval_key( fork_slot, 0 );
  FD_TEST( lockout_interval_map_ele_query( lck_map, &sentinel_key, NULL, lck_pool ) );

  ulong num_keys = 0;
  for( lockout_interval_t const * sentinel = lockout_interval_map_ele_query_const( lck_map, &sentinel_key, NULL, lck_pool );
                                              sentinel;
                                              sentinel = lockout_interval_map_ele_next_const( sentinel, NULL, lck_pool ) ) {
    ulong interval_end = sentinel->start;
    ulong key          = lockout_interval_key( fork_slot, interval_end );
    num_keys++;

    /* Intervals are keyed by the end of the interval. */

    ulong num_pubkeys = 0;
    for( lockout_interval_t const * interval = lockout_interval_map_ele_query_const( lck_map, &key, NULL, lck_pool );
                                                interval;
                                                interval = lockout_interval_map_ele_next_const( interval, NULL, lck_pool ) ) {
      FD_TEST( memcmp( &interval->addr, &acct.vote_acc, sizeof(fd_hash_t) ) == 0 );
      num_pubkeys++;
    }
    FD_TEST( num_pubkeys == 1 );
  }
  FD_TEST( num_keys == 31 );


  fd_tower_lockos_remove( tower, fork_slot );
  for( ulong i = 0; i < 31; i++ ) {
    ulong key = lockout_interval_key( fork_slot, end_intervals[i] );
    FD_TEST( !lockout_interval_map_ele_query( lck_map, &key, NULL, lck_pool ) );
  }
  FD_TEST( !lockout_interval_map_ele_query( lck_map, &sentinel_key, NULL, lck_pool ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1;
  char *      page_sz  = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_lockos( wksp );

  fd_halt();
  return 0;
}
