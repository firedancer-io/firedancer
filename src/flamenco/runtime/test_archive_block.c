#include  "fd_blockstore.h"
#include <stdbool.h>
#include <stdlib.h>


#define GENERATE_BLOCK_DATA( slot, data_sz )                                           \
  uchar data[data_sz];                                                                 \
  fd_block_t block = { .data_gaddr = 0, .data_sz = data_sz, .rewards = {0}};           \
  block.rewards.collected_fees = (ulong) rand(); /* used for meaningful check test */  \
  fd_block_map_t block_map_entry = { 0 };                                              \
  block_map_entry.slot = slot;                                                         \
  fd_blockstore_ser_t ser = {                                                          \
    .block_map = &block_map_entry,                                                     \
    .block = &block,                                                                   \
    .data = data                                                                       \
  };

bool
blocks_equal(fd_block_t* block1, fd_block_t* block2) {
  if (block1->data_sz != block2->data_sz) {
    return false;
  }
  return true;
}

void
test_archive_many_block( fd_wksp_t * wksp, int fd ) {
  /**
    Tests archiving blocks that will exceed the blockstore's capacity
    and will require the file to be overwritten.
   */
  ulong shred_max = 128;
  ulong block_max = 128;
  ulong idx_max = 128;
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

  fd_blockstore_init(blockstore, fd, &slot_bank);

    //fd_blockstore_publish(blockstore, fd, 1);

    //.block_hash = {.hash = {0}},
    //.bank_hash = {.hash = {0}},
  
  for( ulong slot = 2; slot < idx_max + 10; slot++) {
    ulong data_sz = (ulong) (1 << (rand() % 12));
    GENERATE_BLOCK_DATA( slot, data_sz );
    FD_LOG_NOTICE(("fd is %d", fd));

    // Not perfect, but fd_blockstore_publish has a couple of other things happening that are not accounted for here
    ulong write_off = fd_blockstore_checkpt_write_offset( blockstore, fd, &ser );
    ulong wsz = fd_blockstore_block_checkpt( blockstore, &ser, fd, write_off, slot );
    fd_blockstore_checkpt_update(blockstore, &block_map_entry, slot, wsz, write_off);

    fd_block_idx_t * block_idx_entry = fd_block_idx_query( fd_blockstore_block_idx(blockstore), slot, NULL );

    fd_block_map_t block_map_entry_out = {0};
    fd_block_t block_out = {0};
    fd_blockstore_block_meta_restore(blockstore, fd,  block_idx_entry, &block_map_entry_out,  &block_out);
    
    FD_TEST( blocks_equal(&block, &block_out) );
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
  test_archive_many_block(wksp, fd);

  fd_halt();
  return 0;
}
