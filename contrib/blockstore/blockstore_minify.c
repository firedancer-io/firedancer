#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <rocksdb/c.h>

static char const * const non_slot_indexed_cf_names[] = {
  "transaction_status",
  "address_signatures",
  "transaction_memos",
};

#define NON_SLOT_INDEXED_CF_CNT (sizeof(non_slot_indexed_cf_names)/sizeof(non_slot_indexed_cf_names[0]))

struct blockstore_db {
  rocksdb_t * db;
  size_t cf_cnt;
  char ** cf_names;
  rocksdb_column_family_handle_t ** cf_handles;
  rocksdb_options_t * opts;
  rocksdb_readoptions_t * ro;
  rocksdb_writeoptions_t * wo;
};

static void
die( char const * msg ) {
  fprintf( stderr, "error: %s\n", msg );
  exit( 1 );
}

static int
usage( int rc ) {
  fputs(
    "\n"
    "Usage: blockstore_minify --rocksdb <path> --minified-rocksdb <path> [--start-slot <n>] [--end-slot <n>]\n"
    "\n"
    "Copies slot-indexed column-family rows from an Agave RocksDB blockstore into a new smaller RocksDB.\n"
    "The output path must not already exist.\n"
    "\n"
    "  --rocksdb           <path>  Source Agave RocksDB directory\n"
    "  --minified-rocksdb  <path>  Destination RocksDB directory to create\n"
    "  --start-slot        <n>     Start slot (inclusive, default: first root)\n"
    "  --end-slot          <n>     End slot (inclusive, default: last root)\n"
    "\n",
    stderr
  );
  return rc;
}

static uint64_t
bswap64( uint64_t x ) {
  return __builtin_bswap64( x );
}

static uint64_t
load_uint64( void const * p ) {
  uint64_t x;
  memcpy( &x, p, sizeof(x) );
  return x;
}

static void
make_slot_key( uint64_t slot,
               char  key[8] ) {
  uint64_t be = bswap64( slot );
  memcpy( key, &be, sizeof(be) );
}

static int
parse_uint64_arg( char const * name,
                 char const * val,
                 uint64_t *   out ) {
  if( !val || !val[0] ) {
    fprintf( stderr, "error: %s requires a value\n", name );
    return -1;
  }

  errno = 0;
  char * end = NULL;
  unsigned long long x = strtoull( val, &end, 0 );
  if( errno || !end || *end ) {
    fprintf( stderr, "error: invalid %s value: %s\n", name, val );
    return -1;
  }

  *out = (uint64_t)x;
  return 0;
}

static int
cf_is_slot_indexed( char const * name ) {
  for( size_t i=0UL; i<NON_SLOT_INDEXED_CF_CNT; i++ ) {
    if( strcmp( name, non_slot_indexed_cf_names[i] )==0 ) return 0;
  }
  return 1;
}

static size_t
cf_index_of( struct blockstore_db * db,
             char const *           name ) {
  for( size_t i=0UL; i<db->cf_cnt; i++ ) {
    if( strcmp( db->cf_names[i], name )==0 ) return i;
  }
  fprintf( stderr, "error: source RocksDB has no \"%s\" column family\n", name );
  exit( 1 );
}

static char *
blockstore_open_read_only( struct blockstore_db * db,
                           char const *           path ) {
  memset( db, 0, sizeof(*db) );

  db->opts = rocksdb_options_create();
  if( !db->opts ) die( "rocksdb_options_create failed" );

  char * err = NULL;
  db->cf_names = rocksdb_list_column_families( db->opts, path, &db->cf_cnt, &err );
  if( err ) return err;

  rocksdb_options_t const ** cf_options = calloc( db->cf_cnt, sizeof(*cf_options) );
  db->cf_handles = calloc( db->cf_cnt, sizeof(*db->cf_handles) );
  if( !cf_options || !db->cf_handles ) die( "out of memory" );
  for( size_t i=0UL; i<db->cf_cnt; i++ ) cf_options[i] = db->opts;

  db->db = rocksdb_open_for_read_only_column_families(
      db->opts,
      path,
      (int)db->cf_cnt,
      (char const * const *)db->cf_names,
      cf_options,
      db->cf_handles,
      0,
      &err );
  free( cf_options );
  if( err ) return err;

  db->ro = rocksdb_readoptions_create();
  if( !db->ro ) die( "rocksdb_readoptions_create failed" );
  return NULL;
}

static void
blockstore_create( struct blockstore_db * db,
                   char const *           path,
                   struct blockstore_db * src ) {
  memset( db, 0, sizeof(*db) );

  db->opts = rocksdb_options_create();
  if( !db->opts ) die( "rocksdb_options_create failed" );
  rocksdb_options_set_create_if_missing( db->opts, 1 );
  rocksdb_options_set_create_missing_column_families( db->opts, 1 );
  rocksdb_options_set_compression( db->opts, rocksdb_lz4_compression );

  db->cf_cnt = src->cf_cnt;
  db->cf_handles = calloc( db->cf_cnt, sizeof(*db->cf_handles) );
  rocksdb_options_t const ** cf_options = calloc( db->cf_cnt, sizeof(*cf_options) );
  if( !cf_options || !db->cf_handles ) die( "out of memory" );
  for( size_t i=0UL; i<db->cf_cnt; i++ ) cf_options[i] = db->opts;

  char * err = NULL;
  db->db = rocksdb_open_column_families(
      db->opts,
      path,
      (int)db->cf_cnt,
      (char const * const *)src->cf_names,
      cf_options,
      db->cf_handles,
      &err );
  free( cf_options );
  if( err ) {
    fprintf( stderr, "error: rocksdb creation failed: %s\n", err );
    rocksdb_free( err );
    exit( 1 );
  }

  db->wo = rocksdb_writeoptions_create();
  if( !db->wo ) die( "rocksdb_writeoptions_create failed" );
}

static void
blockstore_close( struct blockstore_db * db ) {
  for( size_t i=0UL; i<db->cf_cnt; i++ ) {
    if( db->cf_handles && db->cf_handles[i] ) {
      rocksdb_column_family_handle_destroy( db->cf_handles[i] );
      db->cf_handles[i] = NULL;
    }
  }
  free( db->cf_handles );
  db->cf_handles = NULL;

  if( db->cf_names ) {
    rocksdb_list_column_families_destroy( db->cf_names, db->cf_cnt );
    db->cf_names = NULL;
  }

  if( db->ro ) {
    rocksdb_readoptions_destroy( db->ro );
    db->ro = NULL;
  }
  if( db->wo ) {
    rocksdb_writeoptions_destroy( db->wo );
    db->wo = NULL;
  }
  if( db->db ) {
    rocksdb_close( db->db );
    db->db = NULL;
  }
  if( db->opts ) {
    rocksdb_options_destroy( db->opts );
    db->opts = NULL;
  }
}

static uint64_t
blockstore_root_slot( struct blockstore_db * db,
                      int                    last,
                      char **                err_out ) {
  size_t root_cf_idx = cf_index_of( db, "root" );
  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf( db->db, db->ro, db->cf_handles[root_cf_idx] );
  if( !iter ) {
    *err_out = "rocksdb_create_iterator_cf(root) failed";
    return 0UL;
  }

  if( last ) rocksdb_iter_seek_to_last( iter );
  else       rocksdb_iter_seek_to_first( iter );

  if( !rocksdb_iter_valid( iter ) ) {
    rocksdb_iter_destroy( iter );
    *err_out = "db column for root is empty";
    return 0UL;
  }

  size_t key_sz = 0UL;
  char const * key = rocksdb_iter_key( iter, &key_sz );
  if( !key || key_sz<sizeof(uint64_t) ) {
    rocksdb_iter_destroy( iter );
    *err_out = "db column for root has invalid key";
    return 0UL;
  }

  uint64_t slot = bswap64( load_uint64( key ) );
  rocksdb_iter_destroy( iter );
  return slot;
}

static void
copy_slot_indexed_range( struct blockstore_db * src,
                         struct blockstore_db * dst,
                         size_t                 cf_idx,
                         uint64_t               start_slot,
                         uint64_t               end_slot ) {
  char const * cf_name = src->cf_names[cf_idx];
  fprintf( stderr, "copy_slot_indexed_range: %s\n", cf_name );

  if( !cf_is_slot_indexed( cf_name ) ) {
    fprintf( stderr, "skipping %s because it is not slot indexed\n", cf_name );
    return;
  }

  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf( src->db, src->ro, src->cf_handles[cf_idx] );
  if( !iter ) {
    fprintf( stderr, "error: rocksdb_create_iterator_cf failed for %s\n", cf_name );
    exit( 1 );
  }

  char start_key[8];
  make_slot_key( start_slot, start_key );

  for( rocksdb_iter_seek( iter, start_key, sizeof(start_key) ); rocksdb_iter_valid( iter ); rocksdb_iter_next( iter ) ) {
    size_t key_sz = 0UL;
    char const * key = rocksdb_iter_key( iter, &key_sz );
    if( !key || key_sz<sizeof(uint64_t) ) {
      fprintf( stderr, "error: corrupt RocksDB: invalid key in %s\n", cf_name );
      exit( 1 );
    }

    uint64_t slot = bswap64( load_uint64( key ) );
    if( slot < start_slot ) continue;
    if( slot > end_slot ) break;

    size_t value_sz = 0UL;
    char const * value = rocksdb_iter_value( iter, &value_sz );

    char * err = NULL;
    rocksdb_put_cf( dst->db, dst->wo, dst->cf_handles[cf_idx], key, key_sz, value, value_sz, &err );
    if( err ) {
      fprintf( stderr, "error: rocksdb_put_cf(%s) failed: %s\n", cf_name, err );
      exit( 1 );
    }
  }

  /* An iterator also goes invalid on a read/checksum error, which is
     indistinguishable from clean exhaustion without asking. */
  char * iter_err = NULL;
  rocksdb_iter_get_error( iter, &iter_err );
  if( iter_err ) {
    fprintf( stderr, "error: iterating %s failed: %s\n", cf_name, iter_err );
    exit( 1 );
  }

  rocksdb_iter_destroy( iter );
}

static void
minify( char const * rocksdb_path,
        char const * mini_db_dir,
        uint64_t     start_slot,
        uint64_t     end_slot ) {
  if( !rocksdb_path ) die( "rocksdb path is NULL" );
  if( !mini_db_dir  ) die( "minified rocksdb path is NULL" );

  struct blockstore_db big_db;
  char * err = blockstore_open_read_only( &big_db, rocksdb_path );
  if( err ) {
    fprintf( stderr, "error: opening source RocksDB %s failed: %s\n", rocksdb_path, err );
    rocksdb_free( err );
    exit( 1 );
  }

  struct stat statbuf;
  if( stat( mini_db_dir, &statbuf )==0 ) {
    fprintf( stderr, "error: path for minified RocksDB already exists: %s\n", mini_db_dir );
    exit( 1 );
  }
  if( errno!=ENOENT ) {
    fprintf( stderr, "error: stat(%s) failed: %d-%s\n", mini_db_dir, errno, strerror( errno ) );
    exit( 1 );
  }

  char * root_err = NULL;
  uint64_t first_slot = blockstore_root_slot( &big_db, 0, &root_err );
  if( root_err ) die( root_err );
  uint64_t last_slot = blockstore_root_slot( &big_db, 1, &root_err );
  if( root_err ) die( root_err );

  if( start_slot < first_slot ) start_slot = first_slot;
  if( end_slot   > last_slot  ) end_slot   = last_slot;
  if( start_slot > end_slot ) {
    fprintf( stderr, "error: requested range does not overlap rooted range [%" PRIu64 ", %" PRIu64 "]\n", first_slot, last_slot );
    exit( 1 );
  }

  struct blockstore_db mini_db;
  blockstore_create( &mini_db, mini_db_dir, &big_db );

  fprintf( stderr, "copying RocksDB range [%" PRIu64 ", %" PRIu64 "]\n", start_slot, end_slot );
  for( size_t cf_idx=0UL; cf_idx<big_db.cf_cnt; cf_idx++ ) {
    if( strcmp( big_db.cf_names[cf_idx], "default" )==0 ) continue;
    copy_slot_indexed_range( &big_db, &mini_db, cf_idx, start_slot, end_slot );
  }
  fputs( "copied all slot-indexed column families\n", stderr );

  rocksdb_flushoptions_t * flush_options = rocksdb_flushoptions_create();
  if( !flush_options ) die( "rocksdb_flushoptions_create failed" );
  rocksdb_flushoptions_set_wait( flush_options, 1 );

  for( size_t i=0UL; i<mini_db.cf_cnt; i++ ) {
    if( strcmp( big_db.cf_names[i], "default" )==0 ) continue;
    char * flush_err = NULL;
    rocksdb_flush_cf( mini_db.db, flush_options, mini_db.cf_handles[i], &flush_err );
    if( flush_err ) {
      fprintf( stderr, "error: flushing minified RocksDB column family %s failed: %s\n", big_db.cf_names[i], flush_err );
      exit( 1 );
    }
  }
  rocksdb_flushoptions_destroy( flush_options );

  blockstore_close( &mini_db );
  blockstore_close( &big_db );
}

int
main( int     argc,
      char ** argv ) {
  char const * rocksdb_path = NULL;
  char const * mini_db_dir = NULL;
  uint64_t start_slot = 0UL;
  uint64_t end_slot = UINT64_MAX;

  static struct option const opts[] = {
    { "help",             no_argument,       NULL, 'h' },
    { "rocksdb",          required_argument, NULL, 'r' },
    { "minified-rocksdb", required_argument, NULL, 'm' },
    { "start-slot",       required_argument, NULL, 's' },
    { "end-slot",         required_argument, NULL, 'e' },
    { NULL,               0,                 NULL,  0  }
  };

  opterr = 0;
  for(;;) {
    int opt = getopt_long( argc, argv, "h", opts, NULL );
    if( opt==-1 ) break;
    switch( opt ) {
    case 'h': return usage( 0 );
    case 'r': rocksdb_path = optarg; break;
    case 'm': mini_db_dir = optarg; break;
    case 's':
      if( parse_uint64_arg( "--start-slot", optarg, &start_slot ) ) return usage( 1 );
      break;
    case 'e':
      if( parse_uint64_arg( "--end-slot", optarg, &end_slot ) ) return usage( 1 );
      break;
    default:
      fprintf( stderr, "error: unknown or malformed argument: %s\n", argv[optind-1] );
      return usage( 1 );
    }
  }
  if( optind<argc ) {
    fprintf( stderr, "error: unexpected positional argument: %s\n", argv[optind] );
    return usage( 1 );
  }

  minify( rocksdb_path, mini_db_dir, start_slot, end_slot );
  return 0;
}
