#define _GNU_SOURCE
#include "../../fdctl/configure/configure.h"

#include "../../../ballet/shred/fd_shred.h"
#include "../../../disco/shred/fd_shredder.h"
#include "../../../ballet/poh/fd_poh.h"
#include "../../fdctl/run/tiles/tiles.h"
#include "../genesis_hash.h"

#include <sys/stat.h>

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

  ulong ticks_per_slot  = 64UL;
  ulong hashes_per_tick = 12500UL;

  /* TODO: Read the genesis file in the ledger dir */
  /* TODO: Extract ticks_per_slot and hashes_per_tick from genesis file */

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
  fd_poh_state_t poh[ 1 ] = {{{ 0 }}};
  memcpy( poh->state, genesis_hash, 32UL );

  char base58[ FD_BASE58_ENCODED_32_SZ ];
  FD_LOG_WARNING(( "genesis hash: %s", fd_base58_encode_32( poh->state, NULL, base58 ) ));
  for( ulong i=0UL; i<ticks_per_slot; i++ ) {
    fd_poh_append( poh, hashes_per_tick );

    batch.ticks[ i ].hashcnt_delta = hashes_per_tick;
    batch.ticks[ i ].txn_cnt       = 0UL;
    memcpy( batch.ticks[ i ].hash, poh->state, 32UL );
    FD_LOG_WARNING(( "Tick %lu: %s", i, fd_base58_encode_32( poh->state, NULL, base58 ) ));
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
    .parent_offset = 0UL,
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

  /* TODO: Do we need to create the genesis archive genesis.tar.bz2 here? */

  umask( previous );

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
fini( config_t * const config ) {
  char rocksdb_path[ PATH_MAX ];
  fd_cstr_printf_check( rocksdb_path, PATH_MAX, NULL, "%s/rocksdb", config->ledger.path );
  rmtree( rocksdb_path, 1 );
}

static configure_result_t
check( config_t * const config ) {
  char rocksdb_path[ PATH_MAX ];
  fd_cstr_printf_check( rocksdb_path, PATH_MAX, NULL, "%s/rocksdb", config->ledger.path );

  struct stat st;
  if( FD_UNLIKELY( stat( rocksdb_path, &st ) && errno==ENOENT ) )
    NOT_CONFIGURED( "`%s` does not exist", rocksdb_path );

  CHECK( check_dir( rocksdb_path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  PARTIALLY_CONFIGURED( "rocksdb directory exists at `%s`", rocksdb_path );
}

configure_stage_t blockstore = {
  .name            = NAME,
  .always_recreate = 1,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
