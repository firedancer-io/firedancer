#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include <unistd.h>
#include <sys/stat.h>

struct fd_ledger_args {
  fd_wksp_t *           wksp;                    /* wksp for blockstore */
  char const *          cmd;                     /* user passed command to fd_ledger */
  ulong                 start_slot;              /* start slot for offline replay */
  ulong                 end_slot;                /* end slot for offline replay */
  uint                  hashseed;                /* hashseed */
  char const *          restore;                 /* wksp restore */
  ulong                 shred_max;               /* maximum number of shreds*/
  ulong                 slot_history_max;        /* number of slots stored by blockstore*/
  char const *          mini_db_dir;             /* path to minifed rocksdb that's to be created */
  int                   copy_txn_status;         /* determine if txns should be copied to the blockstore during minify/replay */
  ulong                 trash_hash;              /* trash hash to be used for negative cases*/
  char const *          rocksdb_path;            /* path to rocksdb directory */
  fd_valloc_t           valloc; /* wksp valloc that should NOT be used for runtime allocations */
};
typedef struct fd_ledger_args fd_ledger_args_t;

/***************************** Helpers ****************************************/
static fd_valloc_t
allocator_setup( fd_wksp_t * wksp ) {

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_ERR(( "workspace is NULL" ));
  }

  void * alloc_shmem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); }
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { FD_LOG_ERR( ( "fd_alloc_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) { FD_LOG_ERR( ( "fd_alloc_join failed" ) ); }
  fd_valloc_t valloc = fd_alloc_virtual( alloc );
  return valloc;

  /* NOTE: Enable this if leak hunting */
  //return fd_backtracing_alloc_virtual( &valloc );

}

void
ingest_rocksdb( char const *      file,
                ulong             start_slot,
                ulong             end_slot,
                FD_PARAM_UNUSED ulong             trash_hash,
                fd_valloc_t       valloc ) {

  fd_rocksdb_t rocks_db;
  char * err = fd_rocksdb_init( &rocks_db, file );
  if( FD_UNLIKELY( err!=NULL ) ) {
    FD_LOG_ERR(( "fd_rocksdb_init returned %s", err ));
  }

  ulong last_slot = fd_rocksdb_last_slot( &rocks_db, &err );
  if( FD_UNLIKELY( err!=NULL ) ) {
    FD_LOG_ERR(( "fd_rocksdb_last_slot returned %s", err ));
  }

  if( last_slot < start_slot ) {
    FD_LOG_ERR(( "rocksdb blocks are older than snapshot. first=%lu last=%lu wanted=%lu",
                 fd_rocksdb_first_slot(&rocks_db, &err), last_slot, start_slot ));
  }

  FD_LOG_NOTICE(( "ingesting rocksdb from start=%lu to end=%lu", start_slot, end_slot ));

  fd_rocksdb_root_iter_t iter = {0};
  fd_rocksdb_root_iter_new( &iter );

  fd_slot_meta_t slot_meta = {0};
  fd_memset( &slot_meta, 0, sizeof(slot_meta) );

  int block_found = -1;
  while ( block_found!=0 && start_slot<=end_slot ) {
    block_found = fd_rocksdb_root_iter_seek( &iter, &rocks_db, start_slot, &slot_meta, valloc );
    if ( block_found!=0 ) {
      start_slot++;
    }
  }
  if( FD_UNLIKELY( block_found!=0 ) ) {
    FD_LOG_ERR(( "unable to seek to any slot" ));
  }

  uchar trash_hash_buf[32];
  memset( trash_hash_buf, 0xFE, sizeof(trash_hash_buf) );

  ulong blk_cnt = 0;
  do {
    ulong slot = slot_meta.slot;
    if( slot > end_slot ) {
      break;
    }

    /* Read and deshred block from RocksDB */
    if( blk_cnt % 100 == 0 ) {
      FD_LOG_WARNING(( "imported %lu blocks", blk_cnt ));
    }

    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_rocksdb_get_block failed" ));
    }

    ++blk_cnt;

    memset( &slot_meta, 0, sizeof(fd_slot_meta_t) );

    int ret = fd_rocksdb_root_iter_next( &iter, &slot_meta, valloc );
    if( ret < 0 ) {
      // FD_LOG_WARNING(("Failed for slot %lu", slot + 1));
      ret = fd_rocksdb_get_meta( &rocks_db, slot + 1, &slot_meta, valloc );
      if( ret < 0 ) {
        break;
      }
    }
      // FD_LOG_ERR(("fd_rocksdb_root_iter_seek returned %d", ret));
  } while (1);

  fd_rocksdb_root_iter_destroy( &iter );
  fd_rocksdb_destroy( &rocks_db );

  FD_LOG_NOTICE(( "ingested %lu blocks", blk_cnt ));
}

// void
// init_blockstore( fd_ledger_args_t * args ) {
//   fd_wksp_tag_query_info_t info;
//   ulong blockstore_tag = FD_BLOCKSTORE_MAGIC;
//   void * shmem;
//   if( fd_wksp_tag_query( args->wksp, &blockstore_tag, 1, &info, 1 ) > 0 ) {
//     shmem = fd_wksp_laddr_fast( args->wksp, info.gaddr_lo );
//     args->blockstore = fd_blockstore_join( &args->blockstore_ljoin, shmem );
//     if( args->blockstore->shmem->magic != FD_BLOCKSTORE_MAGIC ) {
//       FD_LOG_ERR(( "failed to join a blockstore" ));
//     }
//     FD_LOG_NOTICE(( "joined blockstore" ));
//   } else {
//     shmem = fd_wksp_alloc_laddr( args->wksp, fd_blockstore_align(), fd_blockstore_footprint( args->shred_max, args->slot_history_max, 16 ), blockstore_tag );
//     if( shmem == NULL ) {
//       FD_LOG_ERR(( "failed to allocate a blockstore" ));
//     }
//     args->blockstore = fd_blockstore_join( &args->blockstore_ljoin, fd_blockstore_new( shmem, 1, args->hashseed, args->shred_max, args->slot_history_max, 16 ) );
//     if( args->blockstore->shmem->magic != FD_BLOCKSTORE_MAGIC ) {
//       fd_wksp_free_laddr( shmem );
//       FD_LOG_ERR(( "failed to allocate a blockstore" ));
//     }
//     FD_LOG_NOTICE(( "allocating a new blockstore" ));
//   }
// }

void
wksp_restore( fd_ledger_args_t * args ) {
  if( args->restore != NULL ) {
    FD_LOG_NOTICE(( "restoring wksp %s", args->restore ));
    fd_wksp_restore( args->wksp, args->restore, args->hashseed );
  }
}

/********************* Main Command Functions and Setup ***********************/
void
minify( fd_ledger_args_t * args ) {
    /* Example commmand:
    fd_ledger --cmd minify --rocksdb <LARGE_ROCKSDB> --minified-rocksdb <MINI_ROCKSDB>
              --start-slot <START_SLOT> --end-slot <END_SLOT> --copy-txn-status 1
  */
  if( args->rocksdb_path == NULL ) {
    FD_LOG_ERR(( "rocksdb path is NULL" ));
  }
  if( args->mini_db_dir == NULL ) {
    FD_LOG_ERR(( "minified rocksdb path is NULL" ));
  }

  args->valloc = allocator_setup( args->wksp );

  fd_rocksdb_t big_rocksdb;
  char * err = fd_rocksdb_init( &big_rocksdb, args->rocksdb_path );
  if( FD_UNLIKELY( err!=NULL ) ) {
    FD_LOG_ERR(( "fd_rocksdb_init at path=%s returned error=%s", args->rocksdb_path, err ));
  }

  /* If the directory for the minified rocksdb already exists, error out */
  struct stat statbuf;
  if( stat( args->mini_db_dir, &statbuf ) == 0 ) {
    FD_LOG_ERR(( "path for mini_db_dir=%s already exists", args->mini_db_dir ));
  }

  /* Create a new smaller rocksdb */
  fd_rocksdb_t mini_rocksdb;
  fd_rocksdb_new( &mini_rocksdb, args->mini_db_dir );

  /* Correctly bound off start and end slot */
  ulong first_slot = fd_rocksdb_first_slot( &big_rocksdb, &err );
  ulong last_slot  = fd_rocksdb_last_slot( &big_rocksdb, &err );
  if( args->start_slot < first_slot ) { args->start_slot = first_slot; }
  if( args->end_slot > last_slot )    { args->end_slot = last_slot; }

  FD_LOG_NOTICE(( "copying over rocks db for range [%lu, %lu]", args->start_slot, args->end_slot ));

  /* Copy over all slot indexed columns */
  for( ulong cf_idx = 1; cf_idx < FD_ROCKSDB_CF_CNT; ++cf_idx ) {
    fd_rocksdb_copy_over_slot_indexed_range( &big_rocksdb, &mini_rocksdb, cf_idx,
                                              args->start_slot, args->end_slot );
  }
  FD_LOG_NOTICE(("copied over all slot indexed columns"));

  /* Copy over transactions. This is more complicated because first, a temporary
      blockstore will be populated. This will be used to look up transactions
      which can be quickly queried */
  if( args->copy_txn_status ) {
    // /* Ingest block range into blockstore */
    // ingest_rocksdb( args->rocksdb_path,
    //                 args->start_slot,
    //                 args->end_slot,
    //                 args->blockstore,
    //                 ULONG_MAX,
    //                 args->valloc );

  } else {
    FD_LOG_NOTICE(( "skipping copying of transaction statuses" ));
  }

  /* TODO: Currently, the address signatures column family isn't copied as it
           is indexed on the pubkey. */

  fd_rocksdb_destroy( &big_rocksdb );
  fd_rocksdb_destroy( &mini_rocksdb );
}

/* Parse user arguments and setup shared data structures used across commands */
int
initial_setup( int argc, char ** argv, fd_ledger_args_t * args ) {
  if( FD_UNLIKELY( argc==1 ) ) {
    return 1;
  }

  fd_boot( &argc, &argv );

  char const * wksp_name             = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--wksp-name",             NULL, NULL                                               );
  ulong        page_cnt              = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",              NULL, 5                                                  );
  int          reset                 = fd_env_strip_cmdline_int   ( &argc, &argv, "--reset",                 NULL, 0                                                  );
  char const * cmd                   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cmd",                   NULL, NULL                                               );
  int          copy_txn_status       = fd_env_strip_cmdline_int   ( &argc, &argv, "--copy-txn-status",       NULL, 0                                                  );
  ulong        slot_history_max      = fd_env_strip_cmdline_ulong ( &argc, &argv, "--slot-history",          NULL, 100UL                                              );
  ulong        shred_max             = fd_env_strip_cmdline_ulong ( &argc, &argv, "--shred-max",             NULL, 1UL << 17                                          );
  ulong        start_slot            = fd_env_strip_cmdline_ulong ( &argc, &argv, "--start-slot",            NULL, 0UL                                                );
  ulong        end_slot              = fd_env_strip_cmdline_ulong ( &argc, &argv, "--end-slot",              NULL, ULONG_MAX                                          );
  char const * restore               = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--restore",               NULL, NULL                                               );
  ulong        trash_hash            = fd_env_strip_cmdline_ulong ( &argc, &argv, "--trash-hash",            NULL, ULONG_MAX                                          );
  char const * mini_db_dir           = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--minified-rocksdb",      NULL, NULL                                               );
  char const * rocksdb_path          = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--rocksdb",               NULL, NULL                                               );

  // TODO: Add argument validation. Make sure that we aren't including any arguments that aren't parsed for

  char hostname[64];
  gethostname( hostname, sizeof(hostname) );
  ulong hashseed = fd_hash( 0, hostname, strnlen( hostname, sizeof(hostname) ) );
  args->hashseed = (uint)hashseed;

  /* Setup workspace */
  fd_wksp_t * wksp;
  if( wksp_name == NULL ) {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace" ));
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, page_cnt, 0, "wksp", 0UL );
  } else {
    fd_shmem_info_t shmem_info[1];
    if( FD_UNLIKELY( fd_shmem_info( wksp_name, 0UL, shmem_info ) ) )
      FD_LOG_ERR(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
  }

  if( wksp == NULL ) {
    FD_LOG_ERR(( "failed to attach to workspace %s", wksp_name ));
  }
  if( reset ) {
    fd_wksp_reset( wksp, args->hashseed );
  }
  args->wksp = wksp;

  /* Copy over arguments */
  args->cmd                     = cmd;
  args->start_slot              = start_slot;
  args->end_slot                = end_slot;
  args->shred_max               = shred_max;
  args->slot_history_max        = slot_history_max;
  args->restore                 = restore;
  args->mini_db_dir             = mini_db_dir;
  args->copy_txn_status         = copy_txn_status;
  args->trash_hash              = trash_hash;
  args->rocksdb_path            = rocksdb_path;

  if( args->rocksdb_path != NULL ) {
    FD_LOG_NOTICE(( "rocksdb=%s", args->rocksdb_path ));
  }

  return 0;
}

int main( int argc, char ** argv ) {
  /* Declaring this on the stack gets the alignment wrong when using asan */
  fd_ledger_args_t * args = fd_alloca( alignof(fd_ledger_args_t), sizeof(fd_ledger_args_t) );
  memset( args, 0, sizeof(fd_ledger_args_t) );
  initial_setup( argc, argv, args );

  if( args->cmd == NULL ) {
    FD_LOG_ERR(( "no command specified" ));
  } else if( strcmp( args->cmd, "minify" ) == 0 ) {
    minify( args );
  } else {
    FD_LOG_ERR(( "unknown command=%s", args->cmd ));
  }

  return 0;
}
