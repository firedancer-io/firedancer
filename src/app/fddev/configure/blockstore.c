#define _GNU_SOURCE
#include "../../fdctl/configure/configure.h"

#include "../../../ballet/shred/fd_shred.h"
#include "../../../disco/shred/fd_shredder.h"
#include "../../../ballet/poh/fd_poh.h"
#include "../../fdctl/run/tiles/tiles.h"
#include "../genesis_hash.h"

#include <sys/stat.h>
#include <dirent.h>

#define NAME "blockstore"

extern void
fd_ext_blockstore_create_block0( char const *  ledger_path,
                                 ulong         shred_cnt,
                                 uchar const * shred_bytes,
                                 ulong         shred_sz,
                                 ulong         stride );

static inline void zero_signer( void * _1, uchar * sig, uchar const * _2 ) { (void)_1; (void)_2; memset( sig, '\0', 64UL ); }

static void
init( config_t * const config ) {
  /* The Agave validator cannot boot without a block 0 existing in the
     blockstore in the ledger directory, so we have to create one.  This
     creates a directory "rocksdb" under which the blockstore with
     block0 is created.  The entire directory should be included in the
     genesis archive "genesis.tar.bz2". */

  /* TODO: Parse genesis.bin and use those values instead. */
  ulong ticks_per_slot  = config->development.genesis.ticks_per_slot;
  ulong hashes_per_tick = config->development.genesis.hashes_per_tick;

  char genesis_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->ledger.path ) );
  uchar genesis_hash[ 32 ] = { 0 };
  ushort shred_version = compute_shred_version( genesis_path, genesis_hash );

  /* This is not a fundamental limit.  It could be set as high as 663
     with no modifications to the rest of the code.  It's set to 128
     because that seems more than enough and we don't need to consume
     that much stack space.  It could be set even higher if you add
     multiple FEC sets. */
#define GENESIS_MAX_TICKS_PER_SLOT 128UL
  FD_TEST( ticks_per_slot<GENESIS_MAX_TICKS_PER_SLOT );
  struct {
    ulong                   ticks_in_batch;
    fd_entry_batch_header_t ticks[ GENESIS_MAX_TICKS_PER_SLOT ];
  } batch;

  batch.ticks_in_batch = ticks_per_slot;
  uchar poh_hash[ 32 ] = {0};
  memcpy( poh_hash, genesis_hash, 32UL );

  for( ulong i=0UL; i<ticks_per_slot; i++ ) {
    fd_poh_append( poh_hash, hashes_per_tick );

    batch.ticks[ i ].hashcnt_delta = hashes_per_tick;
    batch.ticks[ i ].txn_cnt       = 0UL;
    memcpy( batch.ticks[ i ].hash, poh_hash, 32UL );
  }

  ulong batch_sz = sizeof(ulong)+ticks_per_slot*sizeof(fd_entry_batch_header_t);

  FD_TEST( fd_shredder_count_data_shreds  ( batch_sz )<=34UL );
  FD_TEST( fd_shredder_count_parity_shreds( batch_sz )<=34UL );

  fd_shred34_t data, parity;
  fd_fec_set_t fec;
  for( ulong i=0UL; i<34UL; i++ ) {
    fec.data_shreds  [ i ] = data.pkts  [ i ].buffer;
    fec.parity_shreds[ i ] = parity.pkts[ i ].buffer;
  }
  for( ulong i=34UL; i<FD_REEDSOL_DATA_SHREDS_MAX;   i++ ) fec.data_shreds  [ i ] = NULL;
  for( ulong i=34UL; i<FD_REEDSOL_PARITY_SHREDS_MAX; i++ ) fec.parity_shreds[ i ] = NULL;

  fd_entry_batch_meta_t meta[ 1 ] = {{
    .parent_offset  = 0UL,
    .reference_tick = ticks_per_slot,
    .block_complete = 1
  }};

  fd_shredder_t _shredder[ 1 ];
  fd_shredder_t * shredder = fd_shredder_join( fd_shredder_new( _shredder, zero_signer, NULL, shred_version ) );

  fd_shredder_init_batch( shredder, &batch, batch_sz, 0UL, meta );
  fd_shredder_next_fec_set( shredder, &fec );

  /* Switch to target user in the configuration when creating the
     genesis.bin file so it is permissioned correctly. */
  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( gid == 0 && setegid( config->gid ) ) )
    FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( uid == 0 && seteuid( config->uid ) ) )
    FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  mode_t previous = umask( S_IRWXO | S_IRWXG );

  fd_ext_blockstore_create_block0( config->ledger.path, fec.data_shred_cnt, (uchar const *)data.pkts, FD_SHRED_MIN_SZ, FD_SHRED_MAX_SZ );

  umask( previous );

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
fini( config_t * const config,
      int              pre_init ) {
  (void)pre_init;

  DIR * dir = opendir( config->ledger.path );
  if( FD_UNLIKELY( !dir ) ) {
    if( errno == ENOENT ) return;
    FD_LOG_ERR(( "opendir `%s` failed (%i-%s)", config->ledger.path, errno, fd_io_strerror( errno ) ));
  }

  struct dirent * entry;
  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    /* genesis.bin managed by genesis stage*/
    if( FD_LIKELY( !strcmp( entry->d_name, "genesis.bin" ) ) ) continue;

    char path1[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( path1, PATH_MAX, NULL, "%s/%s", config->ledger.path, entry->d_name ) );

    struct stat st;
    if( FD_UNLIKELY( lstat( path1, &st ) ) ) {
      if( FD_LIKELY( errno == ENOENT ) ) continue;
      FD_LOG_ERR(( "stat `%s` failed (%i-%s)", path1, errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( S_ISDIR( st.st_mode ) ) ) {
      rmtree( path1, 1 );
    } else {
      if( FD_UNLIKELY( unlink( path1 ) && errno != ENOENT ) )
        FD_LOG_ERR(( "unlink `%s` failed (%i-%s)", path1, errno, fd_io_strerror( errno ) ));
    }
  }

  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir `%s` failed (%i-%s)", config->ledger.path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir `%s` failed (%i-%s)", config->ledger.path, errno, fd_io_strerror( errno ) ));
}

static configure_result_t
check( config_t * const config ) {
  int has_non_genesis = 0;

  DIR * dir = opendir( config->ledger.path );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_UNLIKELY( errno==ENOENT ) ) NOT_CONFIGURED( "ledger directory does not exist at `%s`", config->ledger.path );
    FD_LOG_ERR(( "opendir `%s` failed (%i-%s)", config->ledger.path, errno, fd_io_strerror( errno ) ));
  }

  struct dirent * entry;
  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    /* genesis.bin managed by genesis stage*/
    if( FD_LIKELY( !strcmp( entry->d_name, "genesis.bin" ) ) ) continue;
    if( FD_LIKELY( !strcmp( entry->d_name, "rocksdb" ) ) ) {
      char rocksdb_path[ PATH_MAX ];
      fd_cstr_printf_check( rocksdb_path, PATH_MAX, NULL, "%s/rocksdb", config->ledger.path );

      configure_result_t result = check_dir( rocksdb_path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR );
      if( FD_UNLIKELY( result.result != CONFIGURE_OK ) ) {
        if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir `%s` failed (%i-%s)", config->ledger.path, errno, fd_io_strerror( errno ) ));
        return result;
      }
    }

    has_non_genesis = 1;
    break;
  }

  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir `%s` failed (%i-%s)", config->ledger.path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir `%s` failed (%i-%s)", config->ledger.path, errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( has_non_genesis ) ) {
    PARTIALLY_CONFIGURED( "rocksdb directory exists at `%s`", config->ledger.path );
  } else {
    NOT_CONFIGURED( "rocksdb directory does not exist at `%s`", config->ledger.path );
  }
}

configure_stage_t blockstore = {
  .name            = NAME,
  .always_recreate = 1,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
