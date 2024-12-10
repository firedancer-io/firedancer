#include  "fd_blockstore.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define GENERATE_BLOCK_DATA( ser, block_map_entry, block, slot, data_sz )              \
  uchar data[data_sz];                                                                 \
  for( ulong i = 0; i < data_sz; i++ ) {                                               \
    data[i] = (uchar) rand();                                                          \
  }                                                                                    \
  fd_block_t block = { .data_gaddr = 0, .data_sz = data_sz, .rewards = {0}};           \
  block.rewards.collected_fees = (ulong) rand(); /* used for meaningful check test */  \
  fd_block_map_t block_map_entry = { 0 };                                              \
  block_map_entry.parent_slot = slot;  /* bc query_block needs an existing parent */   \
  block_map_entry.slot = slot;                                                         \
  fd_blockstore_ser_t ser = {                                                          \
    .block_map = &block_map_entry,                                                     \
    .block = &block,                                                                   \
    .data = data                                                                       \
  };

bool
blocks_equal(fd_block_t* block1, fd_block_t* block2) {
  return block1->data_sz == block2->data_sz && block1->rewards.collected_fees == block2->rewards.collected_fees;
}

bool 
query_block(fd_blockstore_t * blockstore, int fd, ulong slotn){
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
  return success;
}

void
test_archive_many_blocks( fd_wksp_t * wksp, int fd, ulong idx_max ) {
  /**
    Tests archiving blocks that will exceed the blockstore's capacity
    and will require the file to be overwritten.
   */
  // ensure fd is cleared
  FD_TEST( ftruncate(fd, 0) == 0 );
  FD_LOG_NOTICE(("fd is %d", fd));
  ulong shred_max = 128;
  ulong block_max = 128;
  ulong txn_max = 128;

  void * mem = fd_wksp_alloc_laddr( wksp, 
                                    fd_blockstore_align(), 
                                    fd_blockstore_footprint( shred_max, block_max, idx_max, txn_max ),
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

  fd_slot_bank_t slot_bank ={
      .slot = 1,
      .prev_slot = 0,
      .banks_hash = {.hash = {0}},
      .block_height = 1,
  };

  fd_slot_bank_new( &slot_bank);

  fd_hash_t fake = {.hash = {1}};
  slot_bank.block_hash_queue.last_hash = &fake;
  slot_bank.block_hash_queue.last_hash_index = 0;

  fd_blockstore_init(blockstore, fd, FD_ARCHIVE_MIN_SIZE,&slot_bank);

  ulong start_slot = 2;
  for( ulong slot = start_slot; slot < idx_max + 10; slot++ ){
    ulong data_sz = (ulong) (1 << (rand() % 12));
    ulong prev_lrw_slot = blockstore->lrw_slot;

    GENERATE_BLOCK_DATA( ser, block_map_entry, block, slot, data_sz );
    FD_LOG_NOTICE( ( "slot %lu, data_sz %lu", slot, data_sz ) );

    /* Checkpoint the generated data */
    ulong write_off = fd_blockstore_checkpt_write_offset( blockstore, fd, &ser );
    ulong wsz = fd_blockstore_block_checkpt( blockstore, &ser, fd, write_off, slot );
    fd_blockstore_checkpt_update(blockstore, &block_map_entry, slot, wsz, write_off);

    /* Read back the data from archive */
    fd_block_idx_t * block_idx_entry = fd_block_idx_query( fd_blockstore_block_idx(blockstore), slot, NULL );
    fd_block_map_t block_map_entry_out;
    fd_block_t block_out;
    fd_blockstore_block_meta_restore(blockstore, fd, block_idx_entry, &block_map_entry_out, &block_out);
    uchar buf_out[block_out.data_sz]; 
    fd_blockstore_block_data_restore(blockstore, fd, block_idx_entry, buf_out, block_out.data_sz, block_out.data_sz);

    /* Check data read back matches data written */  
    FD_TEST( memcmp(buf_out, data, block_out.data_sz) == 0 );
    FD_TEST( blocks_equal(&block, &block_out) );
    FD_TEST( block_map_entry_out.slot == slot );

    /* Check that blocks are evicted or stay in file as expected */
    if( blockstore->lrw_slot != prev_lrw_slot && slot != start_slot) {
      FD_TEST(!query_block(blockstore, fd, prev_lrw_slot)); // no longer in archive
    }
    FD_TEST(query_block(blockstore, fd, blockstore->lrw_slot)); // should be in archive
    FD_TEST(query_block(blockstore, fd, blockstore->mrw_slot)); // should be in archive
  }

  fd_wksp_free_laddr(mem);
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

  test_archive_many_blocks(wksp, fd, 4);
  test_archive_many_blocks(wksp, fd, 128);
  test_archive_many_blocks(wksp, fd, 256);
  test_archive_many_blocks(wksp, fd, 1 << 12);

  fd_halt();
  return 0;
}
