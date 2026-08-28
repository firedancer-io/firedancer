#include "fd_tower.c"

#include <stdlib.h>

FD_STATIC_ASSERT( sizeof(lockout_interval_t)==12UL, lockout_interval_compact );
FD_STATIC_ASSERT( alignof(lockout_interval_t)==4UL, lockout_interval_align );
FD_STATIC_ASSERT( sizeof(lockout_rec_t)==8UL, lockout_rec_compact );

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

static lockout_pubkey_ref_t *
pubkey_ref_query( fd_tower_t * tower, fd_pubkey_t const * addr ) {
  return lockout_pubkey_map_ele_query( tower->lck_pubkey_map, addr, NULL, tower->lck_pubkey_pool );
}

/* slot_interval_query walks fork_slot's interval list and returns the
   first interval with the given end, or NULL. */

static lockout_interval_t *
slot_interval_query( fd_tower_t * tower, ulong fork_slot, ulong end ) {
  lockout_slot_t * ls = lockout_slot_map_query( (lockout_slot_t *)tower->lck_slot_map, fork_slot, NULL );
  if( !ls ) return NULL;
  lockout_interval_t * lck_pool = tower->lck_pool;
  for( uint idx = ls->head; idx!=UINT_MAX; ) {
    lockout_interval_t * interval = lockout_interval_pool_ele( lck_pool, idx );
    if( (ulong)interval->start + (1UL<<(interval->packed & 63U))==end ) return interval;
    idx = interval->next;
  }
  return NULL;
}

void
test_lockos( fd_wksp_t * wksp ) {
  ulong slot_max    = 64;
  ulong voter_max   = 16;

  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( slot_max, voter_max ), 1UL );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, slot_max, voter_max, 0UL ) );

  lockout_slot_t *     lck_slot_map = tower->lck_slot_map;
  lockout_interval_t * lck_pool     = tower->lck_pool;

  ulong pool_max = lockout_interval_pool_max( lck_pool );
  FD_TEST( pool_max==FD_TOWER_LOCKOS_MAX*slot_max*voter_max );

  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_votes_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_votes = fd_tower_vote_join( fd_tower_vote_new( mock_votes_mem ) );

  fd_tower_vtr_t acct;
  ulong fork_slot = 1;
  ulong end_intervals[31];
  fd_hash_t vote_acc = { .ul = { 1 } };
  for( ulong i = 1; i < 32; i++ ) {
    ulong vote_slot = 50 - (i - 1);
    mock_vote_acc( &vote_acc, 100, vote_slot, (uint)i, &acct, mock_votes );
    fd_tower_lockos_insert( tower, fork_slot, &acct.vote_acc, acct.votes );
    end_intervals[i - 1] = vote_slot + (1UL << (uint)i);
  }

  /* Each insert threads one interval onto fork_slot's list. */

  for( ulong i = 0; i < 31; i++ ) {
    lockout_interval_t * interval = slot_interval_query( tower, fork_slot, end_intervals[i] );
    FD_TEST( interval );
    FD_TEST( interval->start==(uint)(50 - i) );
    lockout_pubkey_ref_t const * ref = lockout_pubkey_pool_ele_const( tower->lck_pubkey_pool, interval->packed>>6 );
    FD_TEST( memcmp( &ref->addr, &acct.vote_acc, sizeof(fd_hash_t) )==0 );
  }

  /* The list holds exactly 31 intervals and the pool released as many. */

  lockout_slot_t * ls = lockout_slot_map_query( lck_slot_map, fork_slot, NULL );
  FD_TEST( ls );
  ulong list_cnt = 0;
  for( uint idx = ls->head; idx!=UINT_MAX; idx = lockout_interval_pool_ele( lck_pool, idx )->next ) list_cnt++;
  FD_TEST( list_cnt==31UL );
  FD_TEST( lockout_interval_pool_free( lck_pool )==pool_max - 31UL );

  /* All 31 inserts used the same vote account with one vote each, so
     the pubkey pool should hold a single entry with ref_cnt==31. */

  lockout_pubkey_ref_t * ref = pubkey_ref_query( tower, &vote_acc );
  FD_TEST( ref );
  FD_TEST( ref->ref_cnt==31U );
  FD_TEST( lockout_pubkey_pool_free( tower->lck_pubkey_pool )==2UL*voter_max - 1UL );

  fd_tower_lockos_remove( tower, fork_slot );
  for( ulong i = 0; i < 31; i++ ) {
    FD_TEST( !slot_interval_query( tower, fork_slot, end_intervals[i] ) );
  }
  FD_TEST( !lockout_slot_map_query( lck_slot_map, fork_slot, NULL ) );
  FD_TEST( lockout_interval_pool_free( lck_pool )==pool_max );

  /* Zero-ref reclamation: pubkey entry is gone and free count restored. */
  FD_TEST( !pubkey_ref_query( tower, &vote_acc ) );
  FD_TEST( lockout_pubkey_pool_free( tower->lck_pubkey_pool )==2UL*voter_max );

  /* Removing a slot with no lockos is a no-op (skipped slots). */
  fd_tower_lockos_remove( tower, fork_slot );
  fd_tower_lockos_remove( tower, 42UL );
}

void
test_lockos_pubkey_pool( fd_wksp_t * wksp ) {
  ulong slot_max  = 64;
  ulong voter_max = 16;

  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( slot_max, voter_max ), 1UL );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, slot_max, voter_max, 0UL ) );

  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) votes_mem_a[ FD_TOWER_VOTE_FOOTPRINT ];
  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) votes_mem_b[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * votes_a = fd_tower_vote_join( fd_tower_vote_new( votes_mem_a ) );
  fd_tower_vote_t * votes_b = fd_tower_vote_join( fd_tower_vote_new( votes_mem_b ) );

  fd_tower_vtr_t acct_a;
  fd_tower_vtr_t acct_b;
  fd_hash_t pk_a = { .ul = { 11 } };
  fd_hash_t pk_b = { .ul = { 22 } };

  mock_vote_acc( &pk_a, 100, 10, 1, &acct_a, votes_a );
  mock_vote_acc( &pk_b, 100, 11, 1, &acct_b, votes_b );

  /* Same pubkey across two slots shares one pool entry; refs accumulate. */
  fd_tower_lockos_insert( tower, 1, &acct_a.vote_acc, acct_a.votes );
  fd_tower_lockos_insert( tower, 2, &acct_a.vote_acc, acct_a.votes );
  lockout_pubkey_ref_t * ref_a = pubkey_ref_query( tower, &pk_a );
  FD_TEST( ref_a );
  FD_TEST( ref_a->ref_cnt==2U );
  uint reused_idx = (uint)lockout_pubkey_pool_idx( tower->lck_pubkey_pool, ref_a );

  lockout_interval_t * iv1 = slot_interval_query( tower, 1, 10 + (1UL << 1) );
  lockout_interval_t * iv2 = slot_interval_query( tower, 2, 10 + (1UL << 1) );
  FD_TEST( iv1 && iv2 );
  FD_TEST( iv1->packed>>6==reused_idx );
  FD_TEST( iv2->packed>>6==reused_idx );

  /* Distinct pubkey gets a distinct pool entry. */
  fd_tower_lockos_insert( tower, 1, &acct_b.vote_acc, acct_b.votes );
  lockout_pubkey_ref_t * ref_b = pubkey_ref_query( tower, &pk_b );
  FD_TEST( ref_b );
  FD_TEST( ref_b->ref_cnt==1U );
  FD_TEST( lockout_pubkey_pool_idx( tower->lck_pubkey_pool, ref_b )!=reused_idx );

  /* Removing one slot drops shared refs by one but keeps the entry. */
  fd_tower_lockos_remove( tower, 2 );
  ref_a = pubkey_ref_query( tower, &pk_a );
  FD_TEST( ref_a );
  FD_TEST( ref_a->ref_cnt==1U );
  FD_TEST( pubkey_ref_query( tower, &pk_b ) );

  /* Removing the last references reclaims both entries. */
  fd_tower_lockos_remove( tower, 1 );
  FD_TEST( !pubkey_ref_query( tower, &pk_a ) );
  FD_TEST( !pubkey_ref_query( tower, &pk_b ) );
  FD_TEST( lockout_pubkey_pool_free( tower->lck_pubkey_pool )==2UL*voter_max );

  /* Index reuse must not leave a stale map entry. */
  mock_vote_acc( &pk_a, 100, 20, 1, &acct_a, votes_a );
  fd_tower_lockos_insert( tower, 3, &acct_a.vote_acc, acct_a.votes );
  ref_a = pubkey_ref_query( tower, &pk_a );
  FD_TEST( ref_a );
  FD_TEST( ref_a->ref_cnt==1U );
  FD_TEST( (uint)lockout_pubkey_pool_idx( tower->lck_pubkey_pool, ref_a )==reused_idx );
  FD_TEST( !memcmp( &ref_a->addr, &pk_a, sizeof(fd_pubkey_t) ) );

  fd_tower_lockos_remove( tower, 3 );
  FD_TEST( !pubkey_ref_query( tower, &pk_a ) );
}

/* test_lockos_spill exercises the disk tier: spill on window overflow,
   bit-exact record round-trip, cold append to a spilled slot, spilled
   remove (pubkey ref decrement + region reuse), and the equivocation
   remove+reinsert path. */

void
test_lockos_spill( fd_wksp_t * wksp ) {
  ulong blk_max   = 1024; /* > FD_TOWER_LOCKOS_WND so the window binds */
  ulong voter_max = 4;

  void *       tower_mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint( blk_max, voter_max ), 1UL );
  fd_tower_t * tower     = fd_tower_join( fd_tower_new( tower_mem, blk_max, voter_max, 0UL ) );
  FD_TEST( tower->lck_wnd==FD_TOWER_LOCKOS_WND );
  FD_TEST( lockout_interval_pool_max( (lockout_interval_t *)tower->lck_pool )==FD_TOWER_LOCKOS_MAX*FD_TOWER_LOCKOS_WND*voter_max );

  char tmpl[] = "/tmp/test_tower_lockos_XXXXXX";
  int  fd     = mkstemp( tmpl );
  FD_TEST( fd>=0 );
  FD_TEST( !unlink( tmpl ) );
  FD_TEST( !ftruncate( fd, (off_t)FD_TOWER_LOCKOS_SPILL_FOOTPRINT( blk_max, voter_max ) ) );
  tower->lck_fd = fd;

  uchar __attribute__((aligned(FD_TOWER_VOTE_ALIGN))) mock_votes_mem[ FD_TOWER_VOTE_FOOTPRINT ];
  fd_tower_vote_t * mock_votes = fd_tower_vote_join( fd_tower_vote_new( mock_votes_mem ) );

  fd_tower_vtr_t acct;
  fd_hash_t pk_a = { .ul = { 7 } };
  fd_hash_t pk_b = { .ul = { 8 } };

  /* Fill the window plus 100 slots: each overflow spills the oldest
     resident list whole. */

  ulong slot_cnt = FD_TOWER_LOCKOS_WND + 100UL;
  for( ulong s = 1; s <= slot_cnt; s++ ) {
    mock_vote_acc( &pk_a, 100, s + 100, 3, &acct, mock_votes );
    fd_tower_lockos_insert( tower, s, &acct.vote_acc, acct.votes );
  }
  FD_TEST( tower->lck_resident==FD_TOWER_LOCKOS_WND );
  FD_TEST( tower->lck_spill_cnt==100UL );
  FD_TEST( tower->lck_lru_head==101UL ); /* slots 1..100 spilled oldest-first */
  FD_TEST( tower->lck_lru_tail==slot_cnt );
  FD_TEST( tower->lck_region_free==blk_max-100UL );

  /* Spilled slots keep map entries; their pubkey refs stay pinned. */

  lockout_slot_t * ls = lockout_slot_map_query( (lockout_slot_t *)tower->lck_slot_map, 1UL, NULL );
  FD_TEST( ls && ls->region!=UINT_MAX && ls->head==UINT_MAX && ls->disk_cnt==1U );
  lockout_pubkey_ref_t * ref = pubkey_ref_query( tower, &pk_a );
  FD_TEST( ref && ref->ref_cnt==(uint)slot_cnt );
  uint pk_a_idx = (uint)lockout_pubkey_pool_idx( tower->lck_pubkey_pool, ref );

  /* Spilled records round-trip bit-exact. */

  FD_TEST( lockos_load( tower, ls )==1UL );
  lockout_rec_t const * rec = tower->lck_scratch;
  FD_TEST( rec[0].start ==101U );
  FD_TEST( rec[0].packed==(3U | (pk_a_idx<<6)) );

  /* Cold append to a spilled slot (new pubkey). */

  mock_vote_acc( &pk_b, 100, 55, 2, &acct, mock_votes );
  fd_tower_lockos_insert( tower, 1UL, &acct.vote_acc, acct.votes );
  FD_TEST( ls->disk_cnt==2U );
  FD_TEST( lockos_load( tower, ls )==2UL );
  FD_TEST( rec[0].start==101U );
  FD_TEST( rec[1].start==55U );
  FD_TEST( (rec[1].packed & 63U)==2U );
  lockout_pubkey_ref_t * ref_b = pubkey_ref_query( tower, &pk_b );
  FD_TEST( ref_b && ref_b->ref_cnt==1U );
  FD_TEST( rec[1].packed>>6==(uint)lockout_pubkey_pool_idx( tower->lck_pubkey_pool, ref_b ) );

  /* Removing a spilled slot decrements refs and frees its region. */

  fd_tower_lockos_remove( tower, 1UL );
  FD_TEST( !lockout_slot_map_query( (lockout_slot_t *)tower->lck_slot_map, 1UL, NULL ) );
  FD_TEST( !pubkey_ref_query( tower, &pk_b ) );
  ref = pubkey_ref_query( tower, &pk_a );
  FD_TEST( ref && ref->ref_cnt==(uint)slot_cnt-1U );
  FD_TEST( tower->lck_region_free==blk_max-99UL );
  FD_TEST( tower->lck_resident==FD_TOWER_LOCKOS_WND );

  /* Equivocation path: remove a spilled slot then reinsert it after
     arbitrary delay; it becomes the newest resident (spilling the
     oldest resident to make room). */

  fd_tower_lockos_remove( tower, 2UL );
  mock_vote_acc( &pk_a, 100, 700, 1, &acct, mock_votes );
  fd_tower_lockos_insert( tower, 2UL, &acct.vote_acc, acct.votes );
  FD_TEST( tower->lck_lru_tail==2UL );
  FD_TEST( tower->lck_lru_head==102UL ); /* 101 spilled to make room */
  FD_TEST( tower->lck_resident==FD_TOWER_LOCKOS_WND );
  FD_TEST( tower->lck_spill_cnt==101UL );

  /* Remove everything: pools, regions, and lru drain fully. */

  for( ulong s = 1; s <= slot_cnt; s++ ) fd_tower_lockos_remove( tower, s );
  FD_TEST( tower->lck_resident==0UL );
  FD_TEST( tower->lck_lru_head==ULONG_MAX && tower->lck_lru_tail==ULONG_MAX );
  FD_TEST( lockout_interval_pool_free( (lockout_interval_t *)tower->lck_pool )==lockout_interval_pool_max( (lockout_interval_t *)tower->lck_pool ) );
  FD_TEST( tower->lck_region_free==blk_max );
  FD_TEST( lockout_pubkey_pool_free( tower->lck_pubkey_pool )==2UL*voter_max );
  FD_TEST( !pubkey_ref_query( tower, &pk_a ) );

  FD_TEST( !close( fd ) );
  fd_wksp_free_laddr( fd_tower_delete( fd_tower_leave( tower ) ) );
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
  test_lockos_pubkey_pool( wksp );
  test_lockos_spill( wksp );

  fd_halt();
  return 0;
}
