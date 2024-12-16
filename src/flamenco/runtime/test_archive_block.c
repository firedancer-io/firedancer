#include "../../util/fd_util.h"

#if FD_HAS_INT128

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include  "fd_blockstore.h"

ulong shred_max = 128;
ulong block_max = 128;
ulong txn_max = 128;

#define GENERATE_BLOCK_DATA( ser, block_map_entry, block, slot, data_sz )              \
  uchar data[data_sz];                                                                 \
  for( ulong i = 0; i < data_sz; i++ ) {                                               \
    data[i] = (uchar) rand();                                                          \
  }                                                                                    \
  fd_block_t block = { .data_gaddr = 0, .data_sz = data_sz, .rewards = { 0 }};         \
  block.rewards.collected_fees = slot; /* used for meaningful check test */            \
  fd_block_map_t block_map_entry = { 0 };                                              \
  block_map_entry.parent_slot = slot;  /* bc query_block needs an existing parent */   \
  block_map_entry.slot = slot;                                                         \
  block_map_entry.ts = (long) time(NULL); /* used for meaningful check test */         \
  fd_blockstore_ser_t ser = {                                                          \
    .block_map = &block_map_entry,                                                     \
    .block = &block,                                                                   \
    .data = data                                                                       \
  };

#define CREATE_BLOCKSTORE( blockstore, slot_bank, mem, fake_hash )                     \
  void * mem = fd_wksp_alloc_laddr( wksp,                                              \
                                    fd_blockstore_align(),                             \
                                    fd_blockstore_footprint( shred_max,                \
                                                             block_max,                \
                                                             idx_max,                  \
                                                             txn_max ),                \
                                    1UL );                                             \
  FD_TEST( mem );                                                                      \
  fd_blockstore_t * blockstore = fd_blockstore_join( fd_blockstore_new( mem,           \
                                                                        1,             \
                                                                        0,             \
                                                                        shred_max,     \
                                                                        block_max,     \
                                                                        idx_max,       \
                                                                        txn_max ) );   \
  FD_TEST( blockstore );                                                               \
  fd_slot_bank_t slot_bank = {                                                         \
      .slot = 1,                                                                       \
      .prev_slot = 0,                                                                  \
      .banks_hash = {.hash = {0}},                                                     \
      .block_height = 1,                                                               \
  };                                                                                   \
  fd_slot_bank_new( &slot_bank );                                                      \
  fd_hash_t fake_hash = {.hash = {1}};                                                 \
  slot_bank.block_hash_queue.last_hash = &fake_hash;                                   \
  slot_bank.block_hash_queue.last_hash_index = 0;

#define CLOSE_BLOCKSTORE  fd_wksp_free_laddr( mem );

bool
blocks_equal(fd_block_t* block1, fd_block_t* block2) {
  return block1->data_sz == block2->data_sz && block1->rewards.collected_fees == block2->rewards.collected_fees;
}

fd_block_map_t 
query_block(bool expect, fd_blockstore_t * blockstore, int fd, ulong slotn){
  ulong blk_sz;
  fd_block_map_t meta[1];
  fd_block_rewards_t rewards[1];
  fd_hash_t parent_hash;
  uchar * blk_data = NULL;
  fd_valloc_t valloc = fd_alloc_virtual( fd_blockstore_alloc(blockstore) ); 
  bool success = fd_blockstore_block_data_query_volatile( blockstore, fd, slotn, valloc, &parent_hash, meta, rewards, &blk_data, &blk_sz ) == 0;
  if ( blk_data ) {
    fd_alloc_free( fd_blockstore_alloc(blockstore), blk_data );
  }

  if ( success != expect ) {
    FD_LOG_ERR(("query_block does not match expected for slot %lu", slotn));
  }

  return meta[0];
}

void
test_archive_many_blocks( fd_wksp_t * wksp, int fd, ulong fd_size_max, ulong idx_max, ulong blocks ) {
  /**
    Tests archiving blocks that will exceed the blockstore's capacity
    and will require the file to be overwritten.
   */

  // ensure fd is cleared
  FD_TEST( ftruncate(fd, 0) == 0 );
  FD_LOG_NOTICE(("fd is %d", fd));

  CREATE_BLOCKSTORE(blockstore, slot_bank, mem, fake_hash);
  FD_TEST(fd_blockstore_init(blockstore, fd, fd_size_max,&slot_bank));

  /* Store blocks that have been written to compare them later */
  fd_block_map_t * block_map_record = fd_alloc_malloc( fd_blockstore_alloc(blockstore), 
                                                      fd_block_map_align(),
                                                        sizeof(fd_block_map_t) * (blocks + 1) );
  int max_data_sz_pow = 20;
  uchar buf_out[ (1 << max_data_sz_pow) ]; 

  fd_block_map_t block_map_entry;
  fd_block_t     block;

  for( ulong slot = 1; slot <= blocks; slot++ ){
    ulong data_sz = (ulong) (1 << (rand() % 18 + 2));
    ulong prev_lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &block_map_entry, &block );

    GENERATE_BLOCK_DATA( ser, block_map_entry, block, slot, data_sz );
    FD_LOG_NOTICE( ( "slot %lu, data_sz %lu", slot, data_sz ) );
    block_map_record[slot] = block_map_entry;

    /* Checkpoint the generated data */

    fd_blockstore_block_checkpt( blockstore, &ser, fd, slot );

    /* Read back the data from archive */

    fd_block_idx_t * block_idx_entry = fd_block_idx_query( fd_blockstore_block_idx(blockstore), slot, NULL );
    fd_block_map_t block_map_entry_out;
    fd_block_t block_out;
    //ulong read_off = block_idx_entry->off;
    fd_blockstore_block_meta_restore(&blockstore->archiver, fd, block_idx_entry, &block_map_entry_out, &block_out);
    //read_off = wrap_offset(&blockstore->archiver, read_off + sizeof(fd_block_map_t) + sizeof(fd_block_t));
    fd_blockstore_block_data_restore(&blockstore->archiver, fd, block_idx_entry, buf_out, block_out.data_sz, block_out.data_sz);

    /* Check data read back matches data written */

    FD_TEST( memcmp(buf_out, data, block_out.data_sz) == 0 );
    FD_TEST( blocks_equal(&block, &block_out) );
    FD_TEST( block_map_entry_out.slot == slot );

    /* Check that blocks are evicted or stay in file as expected */
    ulong lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &block_map_entry, &block );

    if( lrw_slot != prev_lrw_slot && slot != 1) {
      query_block(false, blockstore, fd, prev_lrw_slot);              // no longer in archive
    }
    query_block(true, blockstore, fd, lrw_slot); // should be in archive
    query_block(true, blockstore, fd, slot); // should be in archive

    if ( slot % 10 == 0 ) {
      // periodically check all blocks in the block_idx match the blocks in the archive
      // and blocks in archive match what we store in memory
      for( ulong s = lrw_slot; s != blockstore->mrw_slot; s++ ){
        fd_block_map_t blk_map = query_block(true, blockstore, fd, s);
        FD_TEST( memcmp( &blk_map, &block_map_record[s], sizeof(fd_block_map_t)) == 0 );
      }
    }
  }
  FD_LOG_NOTICE(("key count: %lu", fd_block_idx_key_cnt(fd_blockstore_block_idx(blockstore))));
  fd_alloc_free( fd_blockstore_alloc(blockstore), block_map_record );
  CLOSE_BLOCKSTORE
}

void test_blockstore_archive_big( fd_wksp_t * wksp, int fd, ulong first_idx_max, ulong replay_idx_max ){
  /*
    This test assumes that the limit on blocks in the blockstore file is the size, not idx max.
  */
  FD_TEST( ftruncate(fd, 0) == 0 );

  ulong idx_max = first_idx_max;
  CREATE_BLOCKSTORE(blockstore, slot_bank, mem, fake_hash);
  FD_TEST(fd_blockstore_init(blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &slot_bank));

  for( ulong slot = 1; slot <= first_idx_max; slot++ ){
    ulong data_sz = (ulong) (1 << (rand() % 18 + 2));

    GENERATE_BLOCK_DATA( ser, block_map_entry, block, slot, data_sz );
    FD_LOG_DEBUG( ( "slot %lu, data_sz %lu", slot, data_sz ) );

    /* Checkpoint the generated data */

    fd_blockstore_block_checkpt( blockstore, &ser, fd, slot );
  }
  fd_block_map_t lrw_block_map;
  fd_block_t     lrw_block;

  ulong lrw1 = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map, &lrw_block);

  idx_max = replay_idx_max;
  CREATE_BLOCKSTORE( blockstore2, slot_bank2, mem2, fake_hash2 );

  // initialize from fd that was created from the test_archive_many_blocks
  FD_TEST(fd_blockstore_init(blockstore2, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &slot_bank2));

  ulong lrw2 = fd_blockstore_archiver_lrw_slot( blockstore2, fd, &lrw_block_map, &lrw_block);
  FD_TEST( lrw2 >= lrw1 );

  for ( ulong slot = lrw2; slot != first_idx_max; slot++ ){
    query_block(true, blockstore2, fd, slot);
  }
  for ( ulong slot = lrw1; slot != lrw2; slot++ ){
    query_block(false, blockstore2, fd, slot);
  }
}

void test_blockstore_archive_small( fd_wksp_t * wksp, int fd, ulong first_idx_max, ulong replay_idx_max ){
  /**
    This test assumes that the blockstore can fit first_idx_max blocks in the archive file without evicting.
    Tests the blockstore's ability to read from archive files that have valid data.
    Will store the max_idx number of blocks in the archive file; read back that data,
    and then try to insert more.
   */
  FD_TEST( ftruncate(fd, 0) == 0 );

  // large fd - limit on blocks in archive should be idx_max
  test_archive_many_blocks( wksp, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, first_idx_max, first_idx_max );
  ulong last_archived = first_idx_max;

  ulong idx_max = replay_idx_max; 
  CREATE_BLOCKSTORE( blockstore, slot_bank, mem, fake_hash );

  // initialize from fd that was created from the test_archive_many_blocks
  FD_TEST(fd_blockstore_init(blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &slot_bank));
  fd_block_idx_t * block_idx = fd_blockstore_block_idx(blockstore);

  if( first_idx_max < replay_idx_max ){
    FD_LOG_WARNING(("The following tests are meaninful only when first_idx_max >= replay_idx_max, skipping."));
    return;
  }
  FD_TEST(fd_block_idx_key_cnt( block_idx) == fd_block_idx_key_max( block_idx ));

  /* LRW and MRW slot should be properly populated */

  fd_block_map_t lrw_block_map;
  fd_block_t     lrw_block;
  ulong lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map, &lrw_block );
  FD_LOG_NOTICE(("lrw_slot: %lu, mrw_slot: %lu", lrw_slot, blockstore->mrw_slot));
  FD_TEST( lrw_slot == last_archived - (idx_max - 1) + 1);
  FD_TEST( blockstore->mrw_slot == last_archived);

  /* Insert slot idx_max + 1 into the blockstore, should succeed */

  ulong slot = last_archived + 1;
  ulong data_sz = 1024;
  GENERATE_BLOCK_DATA( ser, block_map_entry, block, slot, data_sz );
  fd_blockstore_block_checkpt( blockstore, &ser, fd, slot);

  /* Check that LRW was evicted, and MRW is updated */
  
  lrw_slot = fd_blockstore_archiver_lrw_slot( blockstore, fd, &lrw_block_map, &lrw_block);
  FD_TEST( lrw_slot == slot - fd_block_idx_key_max( block_idx ) + 1);
  FD_TEST( blockstore->mrw_slot == slot);

  for(ulong i = lrw_slot; i != blockstore->mrw_slot; i++){
    // can be reasonably sure that the blocks are read from file properly, as
    // the slot key is derived from block_map_out read from the file.
    FD_TEST( fd_block_idx_query(block_idx, i, NULL) );
  }
  CLOSE_BLOCKSTORE
}

void
test_blockstore_metadata_invalid( int fd ){
  FD_TEST( ftruncate(fd, 0) == 0 );
  fd_blockstore_t blockstore;
  blockstore.archiver.fd_size_max = 0x6000;

  fd_blockstore_archiver_t metadata = { .magic = FD_BLOCKSTORE_MAGIC, 
                                        .fd_size_max = 0x6000, 
                                        .head = 2, 
                                        .tail = 3 };
  FD_TEST( fd_blockstore_archiver_verify(&blockstore, &metadata) );
  metadata.fd_size_max = 0x5000;
  FD_TEST( fd_blockstore_archiver_verify(&blockstore, &metadata) );
}

int 
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
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

  const char * file = fd_env_strip_cmdline_cstr( &argc, &argv, "--blockstore-file", NULL, NULL);
  int fd = open(file, O_RDWR | O_CREAT, 0666);
  FD_TEST( fd > 0 );

  test_blockstore_archive_big(wksp, fd, 1 << 12, 1 << 11);
  test_blockstore_archive_small(wksp, fd, 128, 128);
  test_blockstore_archive_small(wksp, fd, 128, 64);
  test_blockstore_metadata_invalid(fd);

  // tested archive with smaller fd size ( on order of 20KB ), by setting FD_BLOCKSTORE_ARCHIVE_MIN_SIZE 
  ulong small_fd_size_max = FD_BLOCKSTORE_ARCHIVE_MIN_SIZE;
  test_archive_many_blocks(wksp, fd, small_fd_size_max, 4, 128);         // small idx_mas
  test_archive_many_blocks(wksp, fd, small_fd_size_max, 256, 512);      
  test_archive_many_blocks(wksp, fd, small_fd_size_max, 1 << 12, 1025);  // idx_max > blocks
  test_archive_many_blocks(wksp, fd, small_fd_size_max, 1 << 13, 1<<15); // large blocks

  //test_archive_many_blocks(wksp, fd, small_fd_size_max, 1 << 13, 1<<20); // 1 million blocks

  fd_halt();
  return 0;
}

#else 

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_INT128 capability" ));
  fd_halt();
  return 0;
}

#endif // FD_HAS_INT128
