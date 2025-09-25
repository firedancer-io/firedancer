#include "fd_notar.h"

void
test_notar_simple( fd_wksp_t * wksp ) {
  void * mem;
  ulong  blk_max = 8;

  mem = fd_wksp_alloc_laddr( wksp, fd_notar_align(), fd_notar_footprint( blk_max ), 1UL );
  FD_TEST( mem );
  fd_notar_t * notar = fd_notar_join( fd_notar_new( mem, blk_max ) );

  ulong slot = 368778153;

  fd_notar_blk_t * blk = fd_notar_blk_insert( notar->blks, slot );
  blk->parent_slot = slot - 1;
  memset( &blk->bank_hash, 0, sizeof(fd_hash_t) );
  blk->bank_hash.ul[0] = slot;
  blk->stake           = 0;

  fd_pubkey_t pubkeys[4] = { { .key = { 1 } },
                             { .key = { 2 } },
                             { .key = { 3 } },
                             { .key = { 4 } } };
  for( ulong i = 0; i < sizeof(pubkeys) / sizeof(fd_pubkey_t); i++ ) {
    fd_notar_vtr_t * vtr = fd_notar_vtr_insert( notar->vtrs, pubkeys[i] );
    vtr->bit = i;
  }

  ulong stakes[4] = { 1, 2, 3, 4 };

  mem = fd_wksp_alloc_laddr( wksp, fd_tower_align(), fd_tower_footprint(), 1UL );
  FD_TEST( mem );
  fd_tower_t * tower = fd_tower_join( fd_tower_new( mem ) );
  fd_tower_vote( tower, 368778153 );

  fd_notar_vote( notar, &pubkeys[3], stakes[3], tower, NULL ); /* first valid vote */

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
