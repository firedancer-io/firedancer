#if !FD_HAS_ROCKSDB
#error "fd_ledger requires RocksDB"
#endif

#include "../../util/fd_util.h"
#include <rocksdb/c.h>
#include <sys/stat.h>

static char const * const fd_rocksdb_cf_names[] = {
  "default",
  "meta",
  "dead_slots",
  "duplicate_slots",
  "erasure_meta",
  "orphans",
  "bank_hashes",
  "root",
  "index",
  "data_shred",
  "code_shred",
  "transaction_status",
  "address_signatures",
  "transaction_memos",
  "rewards",
  "blocktime",
  "perf_samples",
  "block_height",
  "optimistic_slots",
  "merkle_root_meta",
};

#define FD_ROCKSDB_CF_CNT (sizeof(fd_rocksdb_cf_names)/sizeof(fd_rocksdb_cf_names[0]))

#define FD_ROCKSDB_CFIDX_ROOT                     (7UL)
#define FD_ROCKSDB_CFIDX_TRANSACTION_STATUS       (11UL)
#define FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES       (12UL)
#define FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS        (13UL)

struct fd_rocksdb {
  rocksdb_t *                      db;
  rocksdb_column_family_handle_t * cf_handles[ FD_ROCKSDB_CF_CNT ];
  rocksdb_options_t *              opts;
  rocksdb_readoptions_t *          ro;
  rocksdb_writeoptions_t *         wo;
};
typedef struct fd_rocksdb fd_rocksdb_t;

static char *
fd_rocksdb_init( fd_rocksdb_t * db,
                 char const *   db_name ) {
  fd_memset( db, 0, sizeof(fd_rocksdb_t) );

  db->opts = rocksdb_options_create();

  rocksdb_options_t const * cf_options[ FD_ROCKSDB_CF_CNT ];
  for( ulong i=0UL; i<FD_ROCKSDB_CF_CNT; i++ )
    cf_options[ i ] = db->opts;

  char * err = NULL;

  db->db = rocksdb_open_for_read_only_column_families(
      db->opts,
      db_name,
      FD_ROCKSDB_CF_CNT,
      fd_rocksdb_cf_names,
      (rocksdb_options_t const * const *)cf_options,
      db->cf_handles,
      0,
      &err );

  if( FD_UNLIKELY( err ) ) return err;

  db->ro = rocksdb_readoptions_create();

  return NULL;
}

static void
fd_rocksdb_new( fd_rocksdb_t * db,
                char const *   db_name ) {
  fd_memset( db, 0, sizeof(fd_rocksdb_t) );

  db->opts = rocksdb_options_create();
  rocksdb_options_set_create_if_missing( db->opts, 1 );
  rocksdb_options_set_compression( db->opts, rocksdb_lz4_compression );

  char * err = NULL;
  db->db = rocksdb_open( db->opts, db_name, &err );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "rocksdb creation failed: %s", err ));
  }

  db->wo = rocksdb_writeoptions_create();

  for( ulong i=1UL; i<FD_ROCKSDB_CF_CNT; i++ ) {
    db->cf_handles[i] = rocksdb_create_column_family( db->db, db->opts, fd_rocksdb_cf_names[i], &err );
  }
}

static void
fd_rocksdb_destroy( fd_rocksdb_t * db ) {

  for( ulong i=0UL; i<FD_ROCKSDB_CF_CNT; i++ ) {
    if( db->cf_handles[i] ) {
      rocksdb_column_family_handle_destroy( db->cf_handles[i] );
      db->cf_handles[i] = NULL;
    }
  }

  if( db->ro ) {
    rocksdb_readoptions_destroy( db->ro );
    db->ro = NULL;
  }

  if( db->opts ) {
    rocksdb_options_destroy( db->opts );
    db->opts = NULL;
  }

  if( db->db ) {
    rocksdb_close( db->db );
    db->db = NULL;
  }

  if( db->wo ) {
    rocksdb_writeoptions_destroy( db->wo );
  }
}

static ulong
fd_rocksdb_root_slot( fd_rocksdb_t * db,
                      int            last,
                      char **        err ) {
  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf( db->db, db->ro, db->cf_handles[FD_ROCKSDB_CFIDX_ROOT] );
  if( last ) rocksdb_iter_seek_to_last ( iter );
  else       rocksdb_iter_seek_to_first( iter );

  if( FD_UNLIKELY( !rocksdb_iter_valid( iter ) ) ) {
    rocksdb_iter_destroy( iter );
    *err = "db column for root is empty";
    return 0;
  }

  ulong klen = 0;
  char const * key = rocksdb_iter_key( iter, &klen );
  ulong slot = fd_ulong_bswap( FD_LOAD( ulong, key ) );
  rocksdb_iter_destroy( iter );
  return slot;
}

static void
fd_rocksdb_copy_over_slot_indexed_range( fd_rocksdb_t * src,
                                         fd_rocksdb_t * dst,
                                         ulong          cf_idx,
                                         ulong          start_slot,
                                         ulong          end_slot ) {
  FD_LOG_NOTICE(( "fd_rocksdb_copy_over_slot_indexed_range: %lu", cf_idx ));

  if( cf_idx==FD_ROCKSDB_CFIDX_TRANSACTION_MEMOS  ||
      cf_idx==FD_ROCKSDB_CFIDX_TRANSACTION_STATUS ||
      cf_idx==FD_ROCKSDB_CFIDX_ADDRESS_SIGNATURES ) {
    FD_LOG_NOTICE(( "fd_rocksdb_copy_over_range: skipping cf_idx=%lu because not slot indexed", cf_idx ));
    return;
  }

  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf( src->db, src->ro, src->cf_handles[cf_idx] );
  if( FD_UNLIKELY( !iter ) ) {
    FD_LOG_ERR(( "rocksdb_create_iterator_cf failed for cf_idx=%lu", cf_idx ));
  }

  ulong start_key = fd_ulong_bswap( start_slot );
  for( rocksdb_iter_seek( iter, (char const *)&start_key, sizeof(start_key) ); rocksdb_iter_valid( iter ); rocksdb_iter_next( iter ) ) {
    ulong klen = 0;
    char const * key = rocksdb_iter_key( iter, &klen );

    ulong slot = fd_ulong_bswap( FD_LOAD( ulong, key ) );
    if( slot<start_slot ) {
      continue;
    } else if( slot>end_slot ) {
      break;
    }

    ulong vlen = 0;
    char const * value = rocksdb_iter_value( iter, &vlen );

    char * err = NULL;
    rocksdb_put_cf( dst->db, dst->wo, dst->cf_handles[cf_idx], key, klen, value, vlen, &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "rocksdb_put_cf failed with error %s", err ));
      rocksdb_free( err );
    }
  }
  rocksdb_iter_destroy( iter );
}

/********************* Main Command Functions and Setup ***********************/
static void
minify( char const * rocksdb_path,
        char const * mini_db_dir,
        ulong        start_slot,
        ulong        end_slot ) {
  /* Example command:
     fd_ledger --cmd minify --rocksdb <LARGE_ROCKSDB> --minified-rocksdb <MINI_ROCKSDB>
               --start-slot <START_SLOT> --end-slot <END_SLOT> */
  if( FD_UNLIKELY( !rocksdb_path ) ) {
    FD_LOG_ERR(( "rocksdb path is NULL" ));
  }
  if( FD_UNLIKELY( !mini_db_dir ) ) {
    FD_LOG_ERR(( "minified rocksdb path is NULL" ));
  }

  fd_rocksdb_t big_rocksdb;
  char * err = fd_rocksdb_init( &big_rocksdb, rocksdb_path );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "fd_rocksdb_init at path=%s returned error=%s", rocksdb_path, err ));
  }

  /* If the directory for the minified rocksdb already exists, error out */
  struct stat statbuf;
  if( stat( mini_db_dir, &statbuf ) == 0 ) {
    FD_LOG_ERR(( "path for mini_db_dir=%s already exists", mini_db_dir ));
  }

  /* Create a new smaller rocksdb */
  fd_rocksdb_t mini_rocksdb;
  fd_rocksdb_new( &mini_rocksdb, mini_db_dir );

  /* Correctly bound off start and end slot */
  ulong first_slot = fd_rocksdb_root_slot( &big_rocksdb, 0, &err );
  ulong last_slot  = fd_rocksdb_root_slot( &big_rocksdb, 1, &err );
  if( start_slot < first_slot ) start_slot = first_slot;
  if( end_slot   > last_slot  ) end_slot   = last_slot;

  FD_LOG_NOTICE(( "copying over rocks db for range [%lu, %lu]", start_slot, end_slot ));

  /* Copy over all slot indexed columns */
  for( ulong cf_idx=1UL; cf_idx<FD_ROCKSDB_CF_CNT; cf_idx++ ) {
    fd_rocksdb_copy_over_slot_indexed_range( &big_rocksdb, &mini_rocksdb, cf_idx,
                                             start_slot, end_slot );
  }
  FD_LOG_NOTICE(( "copied over all slot indexed columns" ));

  /* TODO: Currently, the address signatures column family isn't copied as it
           is indexed on the pubkey. */

  rocksdb_flushoptions_t * flush_options = rocksdb_flushoptions_create();
  rocksdb_flushoptions_set_wait( flush_options, 1 );
  char * flush_err = NULL;
  rocksdb_flush_cfs( mini_rocksdb.db, flush_options,
                     &mini_rocksdb.cf_handles[ 1 ],
                     FD_ROCKSDB_CF_CNT - 1, &flush_err );
  if( FD_UNLIKELY( flush_err ) ) {
    FD_LOG_WARNING(( "minify: flushing minified rocksdb failed: %s", flush_err ));
    rocksdb_free( flush_err );
  }
  rocksdb_flushoptions_destroy( flush_options );

  fd_rocksdb_destroy( &big_rocksdb );
  fd_rocksdb_destroy( &mini_rocksdb );
}

int
main( int     argc,
      char ** argv ) {
  if( FD_UNLIKELY( argc==1 ) ) {
    FD_LOG_ERR(( "no command specified" ));
  }

  fd_boot( &argc, &argv );

  char const * cmd                   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cmd",                   NULL, NULL                                               );
  ulong        start_slot            = fd_env_strip_cmdline_ulong ( &argc, &argv, "--start-slot",            NULL, 0UL                                                );
  ulong        end_slot              = fd_env_strip_cmdline_ulong ( &argc, &argv, "--end-slot",              NULL, ULONG_MAX                                          );
  char const * mini_db_dir           = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--minified-rocksdb",      NULL, NULL                                               );
  char const * rocksdb_path          = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--rocksdb",               NULL, NULL                                               );

  if( rocksdb_path ) {
    FD_LOG_NOTICE(( "rocksdb=%s", rocksdb_path ));
  }

  if( FD_UNLIKELY( !cmd ) ) {
    FD_LOG_ERR(( "no command specified" ));
  } else if( strcmp( cmd, "minify" ) == 0 ) {
    minify( rocksdb_path, mini_db_dir, start_slot, end_slot );
  } else {
    FD_LOG_ERR(( "unknown command=%s", cmd ));
  }

  return 0;
}
