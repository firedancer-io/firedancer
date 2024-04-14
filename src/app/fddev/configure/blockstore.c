#define _GNU_SOURCE
#include "../../fdctl/configure/configure.h"

#include "../../../disco/shred/fd_shredder.h"

#include <sys/stat.h>

#define NAME "blockstore"

extern void
fd_ext_blockstore_create_block0( char const *  ledger_path,
                                 ulong         shred_cnt,
                                 uchar const * shred_bytes,
                                 ulong         shred_sz,
                                 ulong         stride );

static void
init( config_t * const config ) {
  /* The Agave validator cannot boot without a block 0 existing in the
     blockstore in the ledger directory, so we have to create one.  This
     creates a directory "rocksdb" under which the blockstore with
     block0 is created.  The entire directory should be included in the
     genesis archive "genesis.tar.bz2". */

  ulong shred_cnt     = 0UL;
  uchar * shred_bytes = NULL;
  ulong shred_sz      = 0UL;
  ulong stride        = 0UL;

  /* TODO: Read the genesis file in the ledger dir */
  /* TODO: Extract ticks_per_slot and hashes_per_tick from genesis file */
  /* TODO: Create shreds for an empty block, with just ticks_per_slot tick entries of hashes_per_tick each, on
           top of the genesis hash */

  /* Switch to target user in the configuration when creating the
     genesis.bin file so it is permissioned correctly. */
  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( gid == 0 && setegid( config->gid ) ) )
    FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( uid == 0 && seteuid( config->uid ) ) )
    FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  mode_t previous = umask( S_IRWXO | S_IRWXG );

  fd_ext_blockstore_create_block0( config->ledger.path, shred_cnt, shred_bytes, shred_sz, stride );

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
