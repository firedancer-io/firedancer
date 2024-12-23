#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_rocksdb.h"

#define INITIALIZE_BLOCKSTORE( blockstore )                                              \
    ulong shred_max = 1 << 15;                                                           \
    ulong idx_max = 1 << 15;                                                             \
    ulong block_max = 1 << 15;                                                           \
    ulong txn_max = 1 << 15;                                                             \
    void * mem = fd_wksp_alloc_laddr( wksp,                                              \
                                        fd_blockstore_align(),                           \
                                        fd_blockstore_footprint( shred_max,              \
                                                                 block_max,              \
                                                                 idx_max,                \
                                                                 txn_max ),              \
                                        1UL );                                           \
    FD_TEST( mem );                                                                      \
    fd_blockstore_t * blockstore = fd_blockstore_join( fd_blockstore_new( mem,           \
                                                                            1,           \
                                                                            0,           \
                                                                            shred_max,   \
                                                                            block_max,   \
                                                                            idx_max,     \
                                                                            txn_max ) ); \
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
    slot_bank.block_hash_queue.last_hash_index = 0;                                      \
    int fd = open("test.txt", O_RDWR | O_CREAT, 0666);                                   \
    FD_TEST( fd > 0 );

struct fd_batch_row {
  ulong slot;
  uchar ref_tick;
  ulong sz;        /* bytes */
  ulong shred_cnt;
};
typedef struct fd_batch_row fd_batch_row_t;

struct fd_entry_row {
  ulong slot;
  uchar ref_tick;
  ulong sz;        /* bytes */
  ulong txn_cnt;
};
typedef struct fd_entry_row fd_entry_row_t;

static ulong
get_next_batch_shred_off( fd_block_shred_t * shreds, ulong shreds_cnt, ulong * curr_shred_idx ) {
  for( ulong i = *curr_shred_idx + 1; i < shreds_cnt; i++ ) {
    if( shreds[i].hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
      *curr_shred_idx = i + 1;
      if (i + 1 < shreds_cnt) return shreds[i + 1].off;
      else return ULONG_MAX;
    }
  }
  return ULONG_MAX;
}

void append_csv(const char *filename, fd_entry_row_t *row) {
    // Open file in append mode
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Write the row data to the CSV file
    fprintf(file, "%lu,%u,%lu,%lu\n", 
            row->slot, row->ref_tick, row->sz, row->txn_cnt);

    // Close the file
    fclose(file);
}


static void
aggregate_entries( fd_wksp_t * wksp, const char * folder, const char * csv ){
    INITIALIZE_BLOCKSTORE( blockstore );

    FD_TEST(fd_blockstore_init(blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &slot_bank));

    fd_rocksdb_t           rocks_db         = {0};
    fd_rocksdb_root_iter_t iter             = {0};

    char * err = fd_rocksdb_init( &rocks_db, folder );
    FD_LOG_NOTICE(( "rocksdb init: %s", err ));

    fd_rocksdb_root_iter_new( &iter );
    void *       alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
    fd_alloc_t * alloc     = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 1UL );
    fd_valloc_t  valloc    = fd_alloc_virtual( alloc );

    fd_slot_meta_t slot_meta = { 0 };
    uchar trash_hash_buf[32];
    memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );

    ulong st  = 308015637;
    ulong end = 308015637;

    ulong populated_slots[end - st + 1];
    memset( populated_slots, -1, sizeof(populated_slots) );
    int slot_idx = 0;
    for (ulong slot = st; slot <= end; slot++) {
      int err = fd_rocksdb_root_iter_seek( &iter, &rocks_db, slot, &slot_meta, valloc );

      if( err < 0 ) continue;

      err = fd_rocksdb_import_block_blockstore( &rocks_db, &slot_meta, blockstore, 1, trash_hash_buf );
      if( FD_UNLIKELY( err != 0) ) {
        FD_LOG_ERR(( "Failed to import block %lu", slot ));
      }
      populated_slots[slot_idx++] = slot;
    }

    fd_entry_row_t row = {0};
    fd_block_t * block = NULL;
    // iterate the blocks:
    for( int i = 0; i < slot_idx; i++ ) {
      ulong slot = populated_slots[i];
      row.slot   = slot;

      block = fd_blockstore_block_query( blockstore, slot );
      FD_TEST( block );

      fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, block->shreds_gaddr );
      uchar * data              = fd_wksp_laddr_fast( wksp, block->data_gaddr );
      fd_block_micro_t * micros = fd_wksp_laddr_fast( wksp, block->micros_gaddr );

      FD_LOG_NOTICE(( " shreds->off, micros->off: %lu, %lu", shreds->off, micros->off ));

     /* iterate shreds, print offset */
      ulong curr_shred_idx = 0;
      int curr_batch_tick = shreds[curr_shred_idx].hdr.data.flags & FD_SHRED_DATA_REF_TICK_MASK;
      ulong next_batch_off = get_next_batch_shred_off( shreds, block->shreds_cnt, &curr_shred_idx );

      for( ulong micro_idx = 0; micro_idx < block->micros_cnt; micro_idx++ ) {
        fd_block_micro_t * micro = &micros[micro_idx];

        /* as we iterate along microblocks, advance shred ptr with us */
        /* we are looking for any shred that contains the microblock  */
        /*while( shreds[curr_shred_idx].off < micro->off - sizeof(ulong) ) {
          curr_shred_idx++;
          FD_LOG_NOTICE(( "\t Shred | off: %lu", shreds[curr_shred_idx].off )); 
        }*/
        if ( micro->off - sizeof(ulong) >= next_batch_off ) {
          FD_TEST( curr_shred_idx < block->shreds_cnt );
          curr_batch_tick = shreds[curr_shred_idx].hdr.data.flags & FD_SHRED_DATA_REF_TICK_MASK;
          next_batch_off = get_next_batch_shred_off( shreds, block->shreds_cnt, &curr_shred_idx );
        }

        //fd_block_shred_t * shred = &shreds[curr_shred_idx];

        row.ref_tick = (uchar) curr_batch_tick; //(uchar)( (int)shred->hdr.data.flags &
                                                //                     (int)FD_SHRED_DATA_REF_TICK_MASK );
        
        fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)( (uchar *)data + micro->off );
        
        row.txn_cnt = hdr->txn_cnt;

        if( micro_idx + 1 < block->micros_cnt ) {
          row.sz = (ulong) (micros[micro_idx + 1].off) - micro->off;
        } else {
          row.sz = block->data_sz - micro->off;
        }
        append_csv(csv, &row);
        FD_LOG_NOTICE(( "Entry | slot: %lu, payload_sz: %lu txn_cnt: %lu, ref_tick: %d",
                        row.slot, row.sz, row.txn_cnt, (int) row.ref_tick ));
      }
    }
}

static void
aggregate_batch_entries( fd_wksp_t * wksp ){
  return;
  INITIALIZE_BLOCKSTORE( blockstore );

  FD_TEST(fd_blockstore_init(blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &slot_bank));

  fd_rocksdb_t           rocks_db         = {0};
  fd_rocksdb_root_iter_t iter             = {0};

  char * err = fd_rocksdb_init( &rocks_db, "/data/ledgers/mainnet-307987557/rocksdb" );
  FD_LOG_NOTICE(( "rocksdb init: %s", err ));

  fd_rocksdb_root_iter_new( &iter );
  void *       alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  fd_alloc_t * alloc     = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 1UL );
  fd_valloc_t  valloc    = fd_alloc_virtual( alloc );

  fd_slot_meta_t slot_meta = { 0 };
  uchar trash_hash_buf[32];
  memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );

  ulong st  = 308015637;
  ulong end = 308016637;

  ulong populated_slots[end - st + 1];
  memset( populated_slots, -1, sizeof(populated_slots) );
  int slot_idx = 0;
  for (ulong slot = st; slot <= end; slot++) {
    int err = fd_rocksdb_root_iter_seek( &iter, &rocks_db, slot, &slot_meta, valloc );

    if( err < 0 ) continue;

    err = fd_rocksdb_import_block_blockstore( &rocks_db, &slot_meta, blockstore, 1, trash_hash_buf );
    if( FD_UNLIKELY( err != 0) ) {
      FD_LOG_ERR(( "Failed to import block %lu", slot ));
    }
    populated_slots[slot_idx++] = slot;
  }

  fd_batch_row_t row = {0};
  fd_block_t * block = NULL;
  // iterate the blocks:
  for( int i = 0; i < slot_idx; i++ ) {
    ulong slot = populated_slots[i];
    row.slot   = slot;

    block = fd_blockstore_block_query( blockstore, slot );
    FD_TEST( block );
    
    fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, block->shreds_gaddr );
    ulong batch_start         = 0;
    ulong batch_sz            = 0;
    for ( ulong shred_idx = 0; shred_idx < block->shreds_cnt; shred_idx++ ) {
      fd_block_shred_t * shred = &shreds[shred_idx];
      batch_sz += fd_shred_payload_sz( &shred->hdr );

      if( shred->hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
        row.shred_cnt = shred_idx - batch_start + 1;
        row.ref_tick  = (uchar)( (int)shred->hdr.data.flags &
                                      (int)FD_SHRED_DATA_REF_TICK_MASK );
        row.sz        = batch_sz;
        batch_start   = shred_idx + 1;

        FD_LOG_NOTICE(( "Batch | slot: %lu, ref_tick: %d, payload_sz: %lu, shred_cnt: %lu",
                row.slot, (int) row.ref_tick, row.sz, row.shred_cnt ));
      }
    }
  }
}

static void
investigate_shred( fd_wksp_t * wksp, const char * folder ){
  INITIALIZE_BLOCKSTORE( blockstore );

  FD_TEST(fd_blockstore_init(blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &slot_bank));

  fd_rocksdb_t           rocks_db         = {0};
  fd_rocksdb_root_iter_t iter             = {0};

  char * err = fd_rocksdb_init( &rocks_db, folder );
  FD_LOG_NOTICE(( "rocksdb init: %s", err ));

  fd_rocksdb_root_iter_new( &iter );
  void *       alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  fd_alloc_t * alloc     = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 1UL );
  fd_valloc_t  valloc    = fd_alloc_virtual( alloc );

  fd_slot_meta_t slot_meta = { 0 };
  uchar trash_hash_buf[32];
  memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );

  ulong st  = 308015637;
  ulong end = 308015637;

  ulong populated_slots[end - st + 1];
  memset( populated_slots, -1, sizeof(populated_slots) );
  int slot_idx = 0;
  for (ulong slot = st; slot <= end; slot++) {
    int err = fd_rocksdb_root_iter_seek( &iter, &rocks_db, slot, &slot_meta, valloc );

    if( err < 0 ) continue;

    err = fd_rocksdb_import_block_blockstore( &rocks_db, &slot_meta, blockstore, 1, trash_hash_buf );
    if( FD_UNLIKELY( err != 0) ) {
      FD_LOG_ERR(( "Failed to import block %lu", slot ));
    }
    populated_slots[slot_idx++] = slot;
  }

  fd_block_t * block = NULL;
  // iterate the blocks:
  for( int i = 0; i < slot_idx; i++ ) {
    ulong slot = populated_slots[i];

    block = fd_blockstore_block_query( blockstore, slot );
    FD_TEST( block );

    fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, block->shreds_gaddr );
    //uchar * data              = fd_wksp_laddr_fast( wksp, block->data_gaddr );
    fd_block_micro_t * micros = fd_wksp_laddr_fast( wksp, block->micros_gaddr );

    for ( ulong shred_idx = 0; shred_idx < block->shreds_cnt; shred_idx++ ) {
      fd_block_shred_t * shred = &shreds[shred_idx];
      FD_LOG_NOTICE(("Shred offset: %lu", shred->off));
      if( shred->hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
        FD_LOG_NOTICE(( " -- BATCH DONE -- " ));
      }

    }

    for ( ulong micro_idx = 0; micro_idx < block->micros_cnt; micro_idx++ ) {
      fd_block_micro_t * micro = &micros[micro_idx];
      FD_LOG_NOTICE(("Micro offset: %lu", micro->off));
    }
  }

  FD_LOG_NOTICE(( "size of ulong %lu", sizeof(ulong) ));
}


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

  const char * folder = fd_env_strip_cmdline_cstr( &argc, &argv, "--rocksdb-path", NULL, NULL);
  const char * csv    = fd_env_strip_cmdline_cstr( &argc, &argv, "--out", NULL, NULL);
  int fd = open(folder, O_RDONLY | O_DIRECTORY, 0666);
  FD_TEST( fd > 0 );

  int csv_fd = open(csv, O_RDWR | O_CREAT, 0666);
  FD_TEST( csv_fd > 0 );

  // investigate_shred( wksp, folder );
  aggregate_entries( wksp , folder, csv );
  // aggregate_batch_entries( wksp );
  
  fd_halt();
  return 0;

  investigate_shred( wksp, folder );
  aggregate_batch_entries( wksp );

}
