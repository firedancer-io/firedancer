#include "fd_notar.h"

void
test_advance_epoch( fd_wksp_t * wksp ) {
  ulong  slot_max = 8;

  void * notar_mem = fd_wksp_alloc_laddr( wksp, fd_notar_align(), fd_notar_footprint( slot_max ), 1UL );
  fd_notar_t * notar = fd_notar_join( fd_notar_new( notar_mem, slot_max ) );
  FD_TEST( notar );

  void * tower_accts_mem = fd_wksp_alloc_laddr( wksp, fd_tower_accts_align(), fd_tower_accts_footprint( FD_VOTER_MAX ), 1UL );
  fd_tower_accts_t * tower_accts = fd_tower_accts_join( fd_tower_accts_new( tower_accts_mem, FD_VOTER_MAX ) );
  FD_TEST( tower_accts );

  fd_tower_accts_t acct = { .addr = (fd_pubkey_t){ .key = { 1 } }, .stake = 10 };
  fd_tower_accts_push_tail( tower_accts, acct );

  /* Voter should be accts. */

  fd_notar_advance_wmark( notar, 431998 );

  fd_notar_advance_epoch( notar, tower_accts, 1 );
  FD_TEST( fd_notar_vtr_query( notar->vtr_map, acct.addr, NULL ) ); /* populate vtr map */
  FD_TEST( fd_notar_count_vote( notar, 100, &acct.addr, 431999, &((fd_hash_t){ .ul = { 431999 } }) ) );

  /* Evict the voter from accts. */

  fd_tower_accts_pop_head( tower_accts );
  fd_notar_advance_epoch( notar, tower_accts, 2 );
  FD_TEST( !fd_notar_count_vote( notar, 100, &acct.addr, 432000, &((fd_hash_t){ .ul = { 432000 } }) ) );

  // fd_hash_t block_id  = { .ul = { slot } };
  // ulong     slot      = 368778153;
  // fd_hash_t bank_hash = { .ul = { slot } };

  // fd_notar_blk_t * blk = fd_notar_blk_insert( notar->blk, block_id );
  // blk->parent_slot     = slot - 1;
  // blk->bank_hash       = bank_hash;
  // blk->block_id        = block_id;
  // blk->stake           = 0;
  // blk->pro_conf        = 0;
  // blk->dup_conf        = 0;
  // blk->opt_conf        = 0;
  // blk->sup_conf        = 0;

  // fd_pubkey_t pubkeys[4] = { { .key = { 1 } },
  //                            { .key = { 2 } },
  //                            { .key = { 3 } },
  //                            { .key = { 4 } } };
  // for( ulong i = 0; i < sizeof(pubkeys) / sizeof(fd_pubkey_t); i++ ) {
  //   fd_notar_vtr_t * vtr = fd_notar_vtr_insert( notar->vtr, pubkeys[i] );
  //   vtr->bit = i;
  // }

  // ulong stakes[4] = { 1, 2, 3, 4 };

  // mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  // FD_TEST( mem );
  // fd_tower_t * tower = fd_tower_join( fd_tower_new( mem ) );
  // fd_tower_vote( tower, 368778153 );

  // fd_notar_vote( notar, &pubkeys[3], tower,  ); /* first valid vote */

  fd_wksp_free_laddr( fd_notar_delete( fd_notar_leave( notar ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_advance_epoch( wksp );

  // fd_tower_restore( NULL, pubkey,  );
  // test_tower_vote();
  // test_tower_from_vote_acc_data_v1_14_11();
  // test_tower_from_vote_acc_data_current();

  fd_halt();
  return 0;
}
