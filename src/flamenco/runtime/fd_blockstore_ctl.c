#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_rocksdb.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 10;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  // test_ghost_print( wksp );
  // test_ghost_simple( wksp );
  // test_ghost_publish_left( wksp );
  // test_ghost_publish_right( wksp );
  // test_ghost_gca( wksp );
  // test_ghost_vote_leaves( wksp );
  // test_ghost_head_full_tree( wksp );
  // test_ghost_head( wksp );
  // test_rooted_vote( wksp );
  ulong shred_max = 1 << 15;
  ulong idx_max = 1 << 15;
  ulong block_max = 1 << 15;
  ulong txn_max = 1 << 15;
  void * mem = fd_wksp_alloc_laddr( wksp,                                              
                                    fd_blockstore_align(),                             
                                    fd_blockstore_footprint( shred_max,                
                                                             block_max,                
                                                             idx_max,                  
                                                             txn_max ),                
                                    1UL );                                             
  FD_TEST( mem );                                                                      
  fd_blockstore_t * blockstore = fd_blockstore_join( fd_blockstore_new( mem,           
                                                                        1,             
                                                                        0,             
                                                                        shred_max,     
                                                                        block_max,     
                                                                        idx_max,       
                                                                        txn_max ) );   
  FD_TEST( blockstore );                                                               
  fd_slot_bank_t slot_bank = {                                                         
      .slot = 1,                                                                       
      .prev_slot = 0,                                                                  
      .banks_hash = {.hash = {0}},                                                     
      .block_height = 1,                                                               
  };                                                                                   
  fd_slot_bank_new( &slot_bank );                                                      
  fd_hash_t fake_hash = {.hash = {1}};                                                 
  slot_bank.block_hash_queue.last_hash = &fake_hash;                                   
  slot_bank.block_hash_queue.last_hash_index = 0;

  int fd = open("test.txt", O_RDWR | O_CREAT, 0666);
  FD_TEST( fd > 0 );

  FD_TEST(fd_blockstore_init(blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &slot_bank));



  fd_rocksdb_t           rocks_db         = {0};
  fd_rocksdb_root_iter_t iter             = {0};
  char * err = fd_rocksdb_init( &rocks_db, "/data/ledgers/mainnet-307987557/rocksdb" );
  FD_LOG_NOTICE(( "rocksdb init: %s", err ));
  //FD_TEST( err );
  fd_rocksdb_root_iter_new( &iter );

  void *       alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  fd_alloc_t * alloc     = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 1UL );
  fd_valloc_t  valloc    = fd_alloc_virtual( alloc );

  fd_slot_meta_t slot_meta = { 0 };
  uchar trash_hash_buf[32];

  ulong st = 308015637;
  ulong end = 308016637;

  memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );
  for (ulong slot = st; slot <= end; slot++) {
    //slot_meta.slot = slot;
    int err = fd_rocksdb_root_iter_seek( &iter, &rocks_db, slot, &slot_meta, valloc );
    //yet__asm__("int $3");

    FD_LOG_NOTICE(( "block found: %d", err ));
    //__asm__("int $3");
    err = fd_rocksdb_import_block_blockstore( &rocks_db, &slot_meta, blockstore, 1, trash_hash_buf );
    if( FD_UNLIKELY( err != 0) ) {
      FD_LOG_ERR(( "Failed to import block %lu", slot ));
    }
  }

  // iterate the blocks:
  for( ulong slot = st; slot <= end; slot++ ) {
    //FD_LOG_NOTICE(( "querying block %lu", slot ));  
    fd_block_t * block = fd_blockstore_block_query( blockstore, slot );
    FD_TEST( block );
    FD_LOG_NOTICE(( "shred cnt: %lu", block->shreds_cnt ));
    fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, block->shreds_gaddr );
    for ( ulong shred_idx = 0; shred_idx < block->shreds_cnt; shred_idx++ ) {

      fd_block_shred_t * shred = &shreds[shred_idx];
      if( shred->hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
        // batch ended
        FD_LOG_NOTICE(( "batch ended with shred idx: %lu", shred_idx ));
      }
      uchar ref_tick = (uchar)( (int)shred->hdr.data.flags &
                                               (int)FD_SHRED_DATA_REF_TICK_MASK );
      FD_LOG_NOTICE(( "shred idx: %lu, ref_tick: %u", shred_idx, ref_tick ));
      //fd_block_shred_payload_t * payload = fd_shred_data_payload( shred );
    }
  }

  fd_block_t * block = fd_blockstore_block_query( blockstore, 308015636);
  FD_TEST( !block );

  //fd_block_micro_t entry = {0};

  fd_halt();
  return 0;
}
