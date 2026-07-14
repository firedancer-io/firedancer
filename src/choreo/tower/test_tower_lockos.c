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
  fd_tower_from_vote_acc( votes_mem, &out->root, (uchar const *)&voter, sizeof(fd_vote_acc_t) );
  out->votes    = votes_mem;
  out->stake    = stake;
  out->vote_acc = *pubkey;
}

/* count_intervals walks fork_slot's per-blk list, returning the number
   of intervals and checking each against addr / expected ends. */

static ulong
count_intervals( fd_tower_t * tower, ulong fork_slot, fd_hash_t const * addr, ulong const * ends, ulong end_cnt ) {
  lockout_interval_t * lck_pool = tower->lck_pool;
  fd_tower_blk_t * blk = fd_tower_blocks_query( tower, fork_slot );
  FD_TEST( blk );
  ulong cnt  = 0;
  ulong null = lockout_interval_pool_idx_null( lck_pool );
  for( ulong idx = blk->lck_head; idx!=null; idx = lck_pool[ idx ].next ) {
    lockout_interval_t const * interval = &lck_pool[ idx ];
    FD_TEST( 0==memcmp( &interval->addr, addr, sizeof(fd_hash_t) ) );
    int found = 0;
    for( ulong i=0; i<end_cnt; i++ ) found |= ( ends[i]==(ulong)interval->end );
    FD_TEST( found );
    FD_TEST( (ulong)interval->start + ( (ulong)interval->end - (ulong)interval->start )==(ulong)interval->end ); /* sanity */
    cnt++;
  }
  return cnt;
}

void
test_lockos( fd_wksp_t * wksp ) {
  ulong slot_max    = 64;
  ulong voter_max   = 16;

  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( slot_max, voter_max ), 1UL );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, slot_max, voter_max, 0UL ) );

  lockout_interval_t * lck_pool = tower->lck_pool;

  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_votes_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_votes = fd_tower_vote_join( fd_tower_vote_new( mock_votes_mem ) );

  ulong free_at_start = lockout_interval_pool_free( lck_pool );

  fd_tower_vtr_t acct;
  ulong fork_slot = 1;
  fd_tower_blocks_insert( tower, fork_slot, ULONG_MAX );

  ulong end_intervals[31];
  for( ulong i = 1; i < 32; i++ ) {
    ulong vote_slot = 50 - (i - 1);
    mock_vote_acc( &(fd_hash_t){.ul = {1}}, 100, vote_slot, (uint)i, &acct, mock_votes );
    fd_tower_lockos_insert( tower, fork_slot, &acct.vote_acc, acct.votes );
    end_intervals[i - 1] = vote_slot + (1UL << (uint)i);
  }

  FD_TEST( 31UL==count_intervals( tower, fork_slot, &acct.vote_acc, end_intervals, 31UL ) );
  FD_TEST( lockout_interval_pool_free( lck_pool )==free_at_start-31UL );

  /* Remove releases every interval back to the pool and empties the
     blk list. */

  fd_tower_lockos_remove( tower, fork_slot );
  fd_tower_blk_t * blk = fd_tower_blocks_query( tower, fork_slot );
  FD_TEST( blk->lck_head==lockout_interval_pool_idx_null( lck_pool ) );
  FD_TEST( lockout_interval_pool_free( lck_pool )==free_at_start );

  /* Remove is idempotent and tolerates slots with no tower blk
     (skipped slots in the prune loops). */

  fd_tower_lockos_remove( tower, fork_slot );
  fd_tower_lockos_remove( tower, 999 );
  FD_TEST( lockout_interval_pool_free( lck_pool )==free_at_start );

  /* blocks_remove releases any remaining intervals with the blk. */

  mock_vote_acc( &(fd_hash_t){.ul = {2}}, 100, 40, 3, &acct, mock_votes );
  fd_tower_lockos_insert( tower, fork_slot, &acct.vote_acc, acct.votes );
  FD_TEST( lockout_interval_pool_free( lck_pool )==free_at_start-1UL );
  fd_tower_blocks_remove( tower, fork_slot );
  FD_TEST( lockout_interval_pool_free( lck_pool )==free_at_start );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_lockos( wksp );

  fd_halt();
  return 0;
}
