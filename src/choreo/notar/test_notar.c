#include "fd_notar.h"

void
test_notar_simple( fd_wksp_t * wksp ) {
  ulong  slot_max = 8;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_notar_align(), fd_notar_footprint( slot_max ), 1UL );
  fd_notar_t * notar = fd_notar_join( fd_notar_new( mem, slot_max ) );
  FD_TEST( notar );

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

  // fd_tower_restore( NULL, pubkey,  );
  // test_tower_vote();
  // test_tower_from_vote_acc_data_v1_14_11();
  // test_tower_from_vote_acc_data_current();

  fd_halt();
  return 0;
}
