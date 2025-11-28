#include "fd_hfork.h"
#include "fd_hfork_private.h"

void
test_hfork_simple( fd_wksp_t * wksp ) {
  ulong  max_live_slots    = 2;
  ulong  max_vote_accounts = 4;

  void *       mem   = fd_wksp_alloc_laddr( wksp, fd_hfork_align(), fd_hfork_footprint( max_live_slots, max_vote_accounts ), 1UL );
  fd_hfork_t * hfork = fd_hfork_join( fd_hfork_new( mem, max_live_slots, max_vote_accounts, 42, 0 ) );
  FD_TEST( hfork );

  ulong     slot      = 368778153;
  fd_hash_t block_id  = { .ul = { slot } };
  fd_hash_t bank_hash = { .ul = { slot } };

  ulong     slot1      = 368778154;
  fd_hash_t block_id1  = { .ul = { slot1 } };
  fd_hash_t bank_hash1 = { .ul = { slot1 } };

  ulong     slot2      = 368778155;
  fd_hash_t block_id2  = { .ul = { slot2 } };
  fd_hash_t bank_hash2 = { .ul = { slot2 } };

  ulong     slot3      = 368778156;
  // fd_hash_t block_id3  = { .ul = { slot3 } };
  fd_hash_t bank_hash3 = { .ul = { slot3 } };

  fd_hash_t voters[4] = {
    (fd_hash_t){ .ul = { 1 } },
    (fd_hash_t){ .ul = { 2 } },
    (fd_hash_t){ .ul = { 3 } },
    (fd_hash_t){ .ul = { 4 } },
  };

  fd_hfork_metrics_t metrics = { 0 };

  FD_TEST( 0!=memcmp( voters->key, pubkey_null.key, 32UL ) );
  for( ulong i = 0; i < vtr_map_slot_cnt( hfork->vtr_map ); i++ ) {
    FD_TEST( 0==memcmp( hfork->vtr_map[i].vote_acc.key, pubkey_null.key, 32UL ) );
  }

  fd_hfork_count_vote( hfork, &voters[0], &block_id, &bank_hash, slot, 1, 100, &metrics );
  candidate_key_t key       = { .block_id = block_id, .bank_hash = bank_hash };
  candidate_t *   candidate = candidate_map_query( hfork->candidate_map, key, NULL );
  FD_TEST( candidate->slot   ==slot );
  FD_TEST( candidate->stake  ==1    );
  FD_TEST( candidate->cnt    ==1    );
  FD_TEST( candidate->checked==0    );

  fd_hfork_count_vote( hfork, &voters[1], &block_id, &bank_hash, slot, 51, 100, &metrics );
  FD_TEST( candidate->stake  ==52   );
  FD_TEST( candidate->cnt    ==2    );
  FD_TEST( candidate->checked==0    );

  fd_hfork_record_our_bank_hash( hfork, &block_id, &bank_hash, 100 );
  FD_TEST( candidate->checked==1    );

  fd_hfork_count_vote( hfork, &voters[0], &block_id1, &bank_hash1, slot1, 1, 100, &metrics );
  fd_hfork_count_vote( hfork, &voters[0], &block_id2, &bank_hash2, slot2, 1, 100, &metrics );

  /* evicted */

  FD_TEST( candidate->stake==51 );
  FD_TEST( candidate->cnt  ==1 );

  /* max bank hashes for a given block_id */

  fd_hfork_count_vote( hfork, &voters[0], &block_id, &bank_hash,  slot3, 1,  100, &metrics );
  fd_hfork_count_vote( hfork, &voters[1], &block_id, &bank_hash1, slot3, 51, 100, &metrics );
  fd_hfork_count_vote( hfork, &voters[2], &block_id, &bank_hash2, slot3, 2,  100, &metrics );
  fd_hfork_count_vote( hfork, &voters[3], &block_id, &bank_hash3, slot3, 3,  100, &metrics );

  blk_t * blk = blk_map_query( hfork->blk_map, block_id, NULL );
  bank_hash_t * curr = blk->bank_hashes;
  ulong cnt = 0;
  while( FD_LIKELY( curr ) ) {
    curr = bank_hash_pool_ele( hfork->bank_hash_pool, curr->next );
    cnt++;
  }
  FD_TEST( cnt==4 );

  fd_wksp_free_laddr( fd_hfork_delete( fd_hfork_leave( hfork ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_hfork_simple( wksp );

  fd_halt();
  return 0;
}
