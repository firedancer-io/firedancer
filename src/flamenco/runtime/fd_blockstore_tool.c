#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include <unistd.h>
#include <stdio.h>

/*
Example:
./build/native/gcc/bin/fd_blockstore_tool batch --rocksdb-path /data/emwang/307987557/rocksdb/ --out out.csv st 308015636 en 308015650

helpful:
sudo /data/emwang/agave/release/agave-ledger-tool -l /data/emwang/rocksdb.tar.zst bounds
 - to look at slot bounds
*/

static int
usage( void ) {
  fprintf( stderr,
    "Usage: fd_blockstore_tool {microblock|batch|info} [options]\n"
    "\n"
    "Reads from a rocksdb path and tries to import all slots from st to en. \n"
    "Will continue if the slot does not exist in the rocksdb folder. \n"
    "It then aggregates the data into a csv file.\n"
    "\n"
    "If microblock is specified, it will aggregate the data into a csv file with the following columns:\n"
    "\tslot, batch_idx, ref_tick, hash_cnt_from_slot_start, sz, txn_cnt\n"
    "\n"
    "If batch is specified, it will aggregate the data into a csv file with the following columns:\n"
    "\tslot, ref_tick, sz, shred_cnt\n"
    "\n"
    "If info is specified, it will print the shred payload sizes and if the shred is the last in the batch to stdout\n"
    "\n"
    "Options:\n"
    "  {microblock|batch|info}                  Type of aggregation         Required\n"
    "  --rocksdb-path {path}                    Path of rocksdb/            Required\n"
    "  --out          {out.csv}                 Output csv path             Required for {microblock|batch}\n"
    "  st             {start_slot}              Target start slot           Required\n"
    "  en             {end_slot}                Target end slot             Required\n"
    "\n" );
  return 0;
}

#define INITIALIZE_BLOCKSTORE( blockstore )                                              \
    ulong shred_max = 1 << 17;                                                           \
    ulong idx_max = 1 << 12;                                                             \
    ulong block_max = 1 << 17;                                                           \
    void * mem = fd_wksp_alloc_laddr( wksp,                                              \
                                      fd_blockstore_align(),                             \
                                      fd_blockstore_footprint( shred_max,                \
                                                               block_max,                \
                                                               idx_max ),                \
                                      1UL );                                             \
    FD_TEST( mem );                                                                      \
    void * shblockstore = fd_blockstore_new( mem,                                        \
                                             1UL,                                        \
                                             0UL,                                        \
                                             shred_max,                                  \
                                             block_max,                                  \
                                             idx_max );                                  \
                                                                                         \
    FD_TEST( shblockstore );                                                             \
    fd_blockstore_t   blockstore_ljoin;                                                  \
    fd_blockstore_t * blockstore = fd_blockstore_join( &blockstore_ljoin, shblockstore ); \
    fd_buf_shred_pool_reset( blockstore->shred_pool, 0 );                                \
    FD_TEST( blockstore );                                                               \
    int fd = open( "dummy.archv", O_RDWR | O_CREAT, 0666 );                              \
    FD_TEST( fd > 0 );

struct fd_batch_row {
  ulong slot;
  int   ref_tick;
  ulong sz;        /* bytes */
  ulong shred_cnt;
};
typedef struct fd_batch_row fd_batch_row_t;

struct fd_entry_row {
  ulong slot;
  ulong batch_idx;
  int   ref_tick;
  ulong sz;        /* bytes */
  ulong txn_cnt;
  ulong hashcnt_from_slot_start;
};
typedef struct fd_entry_row fd_entry_row_t;

static void
entry_write_header( const char *filename ) {
    FILE *file = fopen( filename, "w" );
    if ( FD_UNLIKELY( file == NULL ) ) {
        perror( "Error opening file" );
        return;
    }
    fprintf(file, "slot,batch_idx,ref_tick,hash_count_from_start,sz,txn_cnt\n");
    fclose(file);
}

static void
batch_write_header( const char *filename ) {
    FILE *file = fopen(filename, "w");
    if ( FD_UNLIKELY( file == NULL ) ) {
        perror("Error opening file");
        return;
    }
    fprintf(file, "slot,ref_tick,sz,shred_cnt\n");
    fclose(file);
}

static void
batch_append_csv( const char * filename, fd_batch_row_t * row ) {
    FILE *file = fopen(filename, "a");
    if ( FD_UNLIKELY( file == NULL ) ) {
        perror("Error opening file");
        return;
    }

    // Write the row data to the CSV file
    fprintf(file, "%lu,%d,%lu,%lu\n",
            row->slot, row->ref_tick, row->sz, row->shred_cnt);

    fclose(file);
}

static void
entry_append_csv( const char * filename, fd_entry_row_t * row ) {
    FILE *file = fopen(filename, "a");
    if ( FD_UNLIKELY( file == NULL ) ) {
        perror("Error opening file");
        return;
    }

    // Write the row data to the CSV file
    fprintf(file, "%lu,%lu,%d,%lu,%lu,%lu\n",
            row->slot, row->batch_idx, row->ref_tick, row->hashcnt_from_slot_start,row->sz, row->txn_cnt);

    fclose(file);
}

static ulong
get_next_batch_shred_off( fd_block_shred_t * shreds, ulong shreds_cnt, ulong * curr_shred_idx ) {
  for( ulong i = *curr_shred_idx; i < shreds_cnt; i++ ) {
    if( shreds[i].hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
      *curr_shred_idx = i + 1;
      if ( i + 1 < shreds_cnt ) return shreds[i + 1].off;
      else return ULONG_MAX;
    }
  }
  return ULONG_MAX;
}

static int
initialize_rocksdb( fd_wksp_t * wksp,
                    fd_blockstore_t * blockstore,
                    const char * folder,
                    ulong st,
                    ulong end,
                    ulong * populated_slots_out ) {
  fd_rocksdb_t           rocks_db         = {0};
  fd_rocksdb_root_iter_t iter             = {0};

  char * err = fd_rocksdb_init( &rocks_db, folder );
  if( err ) {
    FD_LOG_ERR(( "Failed to initialize rocksdb: %s", err ));
    return -1;
  }

  fd_rocksdb_root_iter_new( &iter );
  void *       alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  fd_alloc_t * alloc     = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 1UL );
  fd_valloc_t  valloc    = fd_alloc_virtual( alloc );

  fd_slot_meta_t slot_meta = { 0 };
  uchar trash_hash_buf[32];
  memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );

  int slot_idx = 0;
  for (ulong slot = st; slot <= end; slot++) {
    int err = fd_rocksdb_root_iter_seek( &iter, &rocks_db, slot, &slot_meta, valloc );

    if( err < 0 ) continue;

    err = fd_rocksdb_import_block_blockstore( &rocks_db, &slot_meta, blockstore, trash_hash_buf, valloc );
    if( FD_UNLIKELY( err != 0) ) {
      FD_LOG_ERR(( "Failed to import block %lu", slot ));
    }
    populated_slots_out[slot_idx++] = slot;
  }
  return slot_idx;
}

static void
aggregate_entries( fd_wksp_t * wksp, const char * folder, const char * csv, ulong st, ulong end ){
    INITIALIZE_BLOCKSTORE( blockstore );
    FD_TEST( fd_blockstore_init( blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, 1UL ) );

    ulong populated_slots[end - st + 1];
    memset( populated_slots, -1, sizeof(populated_slots) );
    int slots_read = initialize_rocksdb( wksp, blockstore, folder, st, end, populated_slots );

    for( int i = 0; i < slots_read; i++ ) {
      fd_entry_row_t row = {0};
      ulong slot         = populated_slots[i];
      row.slot           = slot;
      fd_block_t * block = fd_blockstore_block_query( blockstore, slot );
      if (FD_UNLIKELY( !block ) ) {
        FD_LOG_WARNING(( "Block incomplete for slot %lu", slot ));
        continue;
      }

      fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, block->shreds_gaddr );
      fd_block_micro_t * micros = fd_wksp_laddr_fast( wksp, block->micros_gaddr );
      uchar * data              = fd_wksp_laddr_fast( wksp, block->data_gaddr );

      FD_LOG_DEBUG(( "SLOT: %lu", slot ));

     /* prepare batch boundaries */
      ulong curr_shred_idx       = 0;
      ulong next_batch_shred_idx = curr_shred_idx;  /* not necessary to maintain both, but could be useful */
      int   curr_batch_tick      = shreds[curr_shred_idx].hdr.data.flags & FD_SHRED_DATA_REF_TICK_MASK;
      ulong next_batch_off       = get_next_batch_shred_off( shreds, block->shreds_cnt, &next_batch_shred_idx );

      row.batch_idx                 = 0;
      ulong hashcnt_from_slot_start = 0;
      for( ulong micro_idx = 0; micro_idx < block->micros_cnt; micro_idx++ ) {
        fd_block_micro_t * micro = &micros[micro_idx];

        /* as we iterate along microblocks, advance shred ptr with us */
        /* if we have reached a new batch  */
        if ( FD_UNLIKELY( micro->off >= next_batch_off ) ) {
          row.batch_idx++;
          FD_TEST( next_batch_shred_idx < block->shreds_cnt );
          curr_batch_tick = shreds[next_batch_shred_idx].hdr.data.flags & FD_SHRED_DATA_REF_TICK_MASK;
          curr_shred_idx  = next_batch_shred_idx;
          next_batch_off  = get_next_batch_shred_off( shreds, block->shreds_cnt, &next_batch_shred_idx ); // advance shred idx to next batch
          FD_LOG_DEBUG(( "New Batch - shred idx start: %lu, end: %lu, ref_tick: %d, off : %lu", curr_shred_idx, next_batch_shred_idx, curr_batch_tick, shreds[curr_shred_idx].off ));

          if( FD_UNLIKELY(next_batch_off == ULONG_MAX ) ) {
            FD_LOG_DEBUG(( "New Batch is last batch in slot" ));
          }
        }

        row.ref_tick = curr_batch_tick;

        fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)( (uchar *)data + micro->off );
        ulong hashcnt             = hdr->hash_cnt;
        hashcnt_from_slot_start  += hashcnt;

        /**
         Iterate through the transactions in the microblock to calculate the total payload size
         to handle case where there's extra stuff between microblocks
         */

        ulong total_sz = sizeof(fd_microblock_hdr_t);
        ulong blockoff = micro->off + sizeof(fd_microblock_hdr_t);
        for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
          ulong raw_mblk = (ulong) data + blockoff;
          uchar txn_out[FD_TXN_MAX_SZ];
          ulong pay_sz = 0;
          fd_txn_parse_core( (uchar const *) raw_mblk,
                             fd_ulong_min( block->data_sz - blockoff, FD_TXN_MTU ),
                             txn_out,
                             NULL,
                             &pay_sz );
          blockoff += pay_sz;
          total_sz += pay_sz;
        }

        row.hashcnt_from_slot_start = hashcnt_from_slot_start;
        row.txn_cnt                 = hdr->txn_cnt;
        row.sz                      = total_sz;

        if ( row.txn_cnt == 0 ) { /* truncate payload sz to 48 at all times */
          /* this shouldn't be needed bc of iterating txn counts above, but here to be safe */
          row.sz = 48;
        }

        entry_append_csv( csv, &row );
        FD_LOG_DEBUG(( "Entry | slot: %lu, payload_sz: %lu txn_cnt: %lu, ref_tick: %d",
                        row.slot, row.sz, row.txn_cnt, row.ref_tick ));
      }
    }
}

static void
aggregate_batch_entries( fd_wksp_t * wksp, const char * folder, const char * csv, ulong st, ulong end ){
  INITIALIZE_BLOCKSTORE( blockstore );
  FD_TEST( fd_blockstore_init( blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, 1UL ) );

  ulong populated_slots[end - st + 1];
  memset( populated_slots, -1, sizeof(populated_slots) );
  int slots_read = initialize_rocksdb( wksp, blockstore, folder, st, end, populated_slots );

  fd_batch_row_t row = {0};
  fd_block_t * block = NULL;
  for( int i = 0; i < slots_read; i++ ) {
    ulong slot = populated_slots[i];
    row.slot   = slot;
    block      = fd_blockstore_block_query( blockstore, slot );
    if (FD_UNLIKELY( !block ) ) {
      FD_LOG_WARNING(( "Block incomplete for slot %lu", slot ));
      continue;
    }

    fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, block->shreds_gaddr );
    ulong batch_start         = 0;
    ulong batch_sz            = 0;
    for ( ulong shred_idx = 0; shred_idx < block->shreds_cnt; shred_idx++ ) {
      fd_block_shred_t * shred = &shreds[shred_idx];
      batch_sz += fd_shred_payload_sz( &shred->hdr );

      /* batch done */

      if( shred->hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
        row.shred_cnt = shred_idx - batch_start + 1;
        row.ref_tick  = ( (int)shred->hdr.data.flags &
                                      (int)FD_SHRED_DATA_REF_TICK_MASK );

        row.sz        = batch_sz;
        batch_sz      = 0;
        batch_start   = shred_idx + 1;

        batch_append_csv( csv, &row );

        FD_LOG_DEBUG(( "Batch | slot: %lu, ref_tick: %d, payload_sz: %lu, shred_cnt: %lu",
                            row.slot, row.ref_tick, row.sz, row.shred_cnt ));
      }
    }
  }
}

static void
investigate_shred( fd_wksp_t * wksp, const char * folder, ulong st, ulong end ){
  INITIALIZE_BLOCKSTORE( blockstore );
  FD_TEST( fd_blockstore_init( blockstore, fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, 1UL ) );

  ulong populated_slots[end - st + 1];
  memset( populated_slots, -1, sizeof(populated_slots) );
  int slots_read = initialize_rocksdb( wksp, blockstore, folder, st, end, populated_slots );

  fd_block_t * block = NULL;
  for( int i = 0; i < slots_read; i++ ) {
    ulong slot = populated_slots[i];
    block      = fd_blockstore_block_query( blockstore, slot );
    FD_TEST( block );

    fd_block_shred_t * shreds = fd_wksp_laddr_fast( wksp, block->shreds_gaddr );
    fd_block_micro_t * micros = fd_wksp_laddr_fast( wksp, block->micros_gaddr );

    for ( ulong shred_idx = 0; shred_idx < block->shreds_cnt; shred_idx++ ) {
      fd_block_shred_t * shred = &shreds[shred_idx];

      printf("Shred payload sz: %lu\n", fd_shred_payload_sz( &shred->hdr ));
      if( shred->hdr.data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) {
        printf(" -- BATCH DONE -- \n");
      }
    }
    for ( ulong micro_idx = 0; micro_idx < block->micros_cnt; micro_idx++ ) {
      fd_block_micro_t * micro = &micros[micro_idx];
      FD_LOG_NOTICE(("Micro offset: %lu", micro->off));
    }
    printf("Slot done %lu\n\n", slot);
  }
}

const char *
prepare_csv( int argc, char ** argv ) {
  const char * csv = fd_env_strip_cmdline_cstr( &argc, &argv, "--out", NULL, NULL );
  int csv_fd = open( csv, O_RDWR | O_CREAT, 0666 );
  FD_TEST( csv_fd > 0 );
  int err = ftruncate( csv_fd, 0);
  FD_TEST( err == 0 );
  return csv;
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

  if ( fd_env_strip_cmdline_contains( &argc, &argv, "--help" ) ) {
    return usage();
  }

  const char * folder = fd_env_strip_cmdline_cstr( &argc, &argv, "--rocksdb-path", NULL, NULL);
  int fd = open( folder, O_RDONLY | O_DIRECTORY, 0666 );
  FD_TEST( fd > 0 );

  ulong start = fd_env_strip_cmdline_ulong( &argc, &argv, "st", NULL, 0 );
  ulong end   = fd_env_strip_cmdline_ulong( &argc, &argv, "en", NULL, 0 );

  if ( fd_env_strip_cmdline_contains(&argc, &argv, "microblock") ){
    const char * csv = prepare_csv(argc, argv);
    entry_write_header(csv);
    aggregate_entries( wksp , folder, csv, start, end);
  } else if( fd_env_strip_cmdline_contains(&argc, &argv, "batch") ){
    const char * csv = prepare_csv(argc, argv);
    batch_write_header(csv);
    aggregate_batch_entries( wksp, folder, csv, start, end);
  } else if( fd_env_strip_cmdline_contains(&argc, &argv, "info") ){
    investigate_shred( wksp, folder, start, end );
  } else {
    FD_LOG_WARNING(("Please specify either microblock, batch, or info in the command line. Check --help for usage." ));
  }

  fd_halt();
  return 0;
}
