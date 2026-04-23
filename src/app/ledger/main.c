#include "../../flamenco/runtime/fd_rocksdb.h"
#include <unistd.h>
#include <sys/stat.h>

struct fd_ledger_args {
  fd_wksp_t *           wksp;                    /* wksp for blockstore */
  char const *          cmd;                     /* user passed command to fd_ledger */
  ulong                 start_slot;              /* start slot for offline replay */
  ulong                 end_slot;                /* end slot for offline replay */
  uint                  hashseed;                /* hashseed */
  ulong                 shred_max;               /* maximum number of shreds*/
  ulong                 slot_history_max;        /* number of slots stored by blockstore*/
  char const *          mini_db_dir;             /* path to minifed rocksdb that's to be created */
  char const *          rocksdb_path;            /* path to rocksdb directory */
};
typedef struct fd_ledger_args fd_ledger_args_t;

/********************* Main Command Functions and Setup ***********************/
void
minify( fd_ledger_args_t * args ) {
    /* Example commmand:
    fd_ledger --cmd minify --rocksdb <LARGE_ROCKSDB> --minified-rocksdb <MINI_ROCKSDB>
              --start-slot <START_SLOT> --end-slot <END_SLOT>
  */
  if( args->rocksdb_path == NULL ) {
    FD_LOG_ERR(( "rocksdb path is NULL" ));
  }
  if( args->mini_db_dir == NULL ) {
    FD_LOG_ERR(( "minified rocksdb path is NULL" ));
  }

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

/* Parse user arguments and setup shared data structures used across commands */
int
initial_setup( int argc, char ** argv, fd_ledger_args_t * args ) {
  if( FD_UNLIKELY( argc==1 ) ) {
    return 1;
  }

  fd_boot( &argc, &argv );

  char const * cmd                   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cmd",                   NULL, NULL                                               );
  ulong        slot_history_max      = fd_env_strip_cmdline_ulong ( &argc, &argv, "--slot-history",          NULL, 100UL                                              );
  ulong        shred_max             = fd_env_strip_cmdline_ulong ( &argc, &argv, "--shred-max",             NULL, 1UL << 17                                          );
  ulong        start_slot            = fd_env_strip_cmdline_ulong ( &argc, &argv, "--start-slot",            NULL, 0UL                                                );
  ulong        end_slot              = fd_env_strip_cmdline_ulong ( &argc, &argv, "--end-slot",              NULL, ULONG_MAX                                          );
  char const * mini_db_dir           = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--minified-rocksdb",      NULL, NULL                                               );
  char const * rocksdb_path          = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--rocksdb",               NULL, NULL                                               );

  // TODO: Add argument validation. Make sure that we aren't including any arguments that aren't parsed for

  char hostname[64];
  gethostname( hostname, sizeof(hostname) );
  ulong hashseed = fd_hash( 0, hostname, strnlen( hostname, sizeof(hostname) ) );
  args->hashseed = (uint)hashseed;

  /* Copy over arguments */
  args->cmd                     = cmd;
  args->start_slot              = start_slot;
  args->end_slot                = end_slot;
  args->shred_max               = shred_max;
  args->slot_history_max        = slot_history_max;
  args->mini_db_dir             = mini_db_dir;
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
