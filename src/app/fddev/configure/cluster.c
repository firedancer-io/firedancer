#define _GNU_SOURCE
#include "../../fdctl/configure/configure.h"

#include <unistd.h>
#include <sys/stat.h>

#define NAME "cluster"

static int
enabled( config_t * const config ) {
  /* always enabled by default, this only gets run directly from the `dev` command */
  (void)config;
  return 1;
}

/* todo ... port this out of solana code */
extern void solana_genesis_main( const char ** args );

static void
init( config_t * const config ) {
  mkdir_all( config->scratch_directory, config->uid, config->gid );
  mkdir_all( config->ledger.path, config->uid, config->gid );

  struct stat st;
  if( FD_UNLIKELY( stat( config->consensus.identity_path, &st ) && errno == ENOENT ) )
    generate_keypair( config->consensus.identity_path, config );

  char faucet[ PATH_MAX ];
  snprintf1( faucet, PATH_MAX, "%s/faucet.json", config->scratch_directory );
  generate_keypair( faucet, config );

  char stake[ PATH_MAX ];
  snprintf1( stake, PATH_MAX, "%s/stake-account.json", config->scratch_directory );
  generate_keypair( stake, config );

  char vote[ PATH_MAX ];
  snprintf1( vote, PATH_MAX, "%s/vote-account.json", config->scratch_directory );
  generate_keypair( vote, config );

  uint idx = 0;
  char * argv[ 128 ];
  uint bufidx = 0;
  char buffer[ 32 ][ 16 ];
#define ADD1( arg ) do { argv[ idx++ ] = arg; } while( 0 )
#define ADD( arg, val ) do { argv[ idx++ ] = arg; argv[ idx++ ] = val; } while( 0 )
#define ADDU( arg, val ) do { argv[ idx++ ] = arg; snprintf1( buffer[ bufidx ], 16, "%u", val ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )
#define ADDH( arg, val ) do { argv[ idx++ ] = arg; snprintf1( buffer[ bufidx ], 16, "%hu", val ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )

  ADD1( "fddev" );

  ADDU( "--max-genesis-archive-unpacked-size", 1073741824 );
  ADD1( "--enable-warmup-epochs" );
  ADD( "--bootstrap-validator", config->consensus.identity_path );
  ADD1( vote );
  ADD1( stake );
  ADD( "--bootstrap-stake-authorized-pubkey", config->consensus.identity_path );

  ADD( "--ledger", config->ledger.path );
  ADD( "--faucet-pubkey", faucet );
  ADDU( "--faucet-lamports", 500000000000000000 );
  ADD( "--hashes-per-tick", "auto" );
  ADD( "--cluster-type", "development" );

  /* these are copied out of the output of `solana/fetch-spl.sh` ... need to
     figure out what to do here long term. */
  // ADD( "--bpf-program", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" );
  // ADD1( "BPFLoader2111111111111111111111111111111111" );
  // ADD1( "spl_token-3.5.0.so" );
  //
  // ADD( "--upgradeable-program", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" );
  // ADD1( "BPFLoaderUpgradeab1e11111111111111111111111" );
  // ADD1( "spl_token-2022-0.6.0.so" );
  // ADD1( "none" );
  //
  // ADD( "--bpf-program", "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo" );
  // ADD1( "BPFLoader1111111111111111111111111111111111" );
  // ADD1( "spl_memo-1.0.0.so" );
  //
  // ADD( "--bpf-program", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" );
  // ADD1( "BPFLoader2111111111111111111111111111111111" );
  // ADD1( "spl_memo-3.0.0.so" );
  //
  // ADD( "--bpf-program", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" );
  // ADD1( "BPFLoader2111111111111111111111111111111111" );
  // ADD1( "spl_associated-token-account-1.1.2.so" );
  //
  // ADD( "--bpf-program", "Feat1YXHhH6t1juaWF74WLcfv4XoNocjXA6sPWHNgAse" );
  // ADD1( "BPFLoader2111111111111111111111111111111111" );
  // ADD1( "spl_feature-proposal-1.0.0.so" );

  argv[ idx ] = NULL;

  /* switch to non-root uid/gid for file creation. permissions checks still done as root. */
  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( gid == 0 && setegid( config->gid ) ) )
    FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( uid == 0 && seteuid( config->uid ) ) )
    FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  mode_t previous = umask( S_IRWXO | S_IRWXG );

  solana_genesis_main( (const char **)argv );

  umask( previous );

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
fini( config_t * const config ) {
  char path[ PATH_MAX ];
  snprintf1( path, PATH_MAX, "%s/faucet.json", config->scratch_directory );
  if( FD_UNLIKELY( unlink( path ) && errno != ENOENT ) )
    FD_LOG_ERR(( "could not remove cluster file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  snprintf1( path, PATH_MAX, "%s/stake-account.json", config->scratch_directory );
  if( FD_UNLIKELY( unlink( path ) && errno != ENOENT ) )
    FD_LOG_ERR(( "could not remove cluster file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  snprintf1( path, PATH_MAX, "%s/vote-account.json", config->scratch_directory );
  if( FD_UNLIKELY( unlink( path ) && errno != ENOENT ) )
    FD_LOG_ERR(( "could not remove cluster file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  snprintf1( path, PATH_MAX, "%s/genesis.bin", config->ledger.path );
  if( FD_UNLIKELY( unlink( path ) && errno != ENOENT ) )
    FD_LOG_ERR(( "could not remove cluster file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

static configure_result_t
check( config_t * const config ) {
  char faucet[ PATH_MAX ], stake[ PATH_MAX ], vote[ PATH_MAX ], genesis[ PATH_MAX ];

  snprintf1( faucet, PATH_MAX, "%s/faucet.json", config->scratch_directory );
  snprintf1( stake, PATH_MAX, "%s/stake-account.json", config->scratch_directory );
  snprintf1( vote, PATH_MAX, "%s/vote-account.json", config->scratch_directory );
  snprintf1( genesis, PATH_MAX, "%s/genesis.bin", config->ledger.path );

  struct stat st;
  if( FD_UNLIKELY( stat( faucet, &st ) && errno == ENOENT &&
                   stat( stake, &st ) && errno == ENOENT &&
                   stat( vote, &st ) && errno == ENOENT &&
                   stat( genesis, &st ) && errno == ENOENT ) )
    NOT_CONFIGURED( "faucet.json, stake-account.json, vote-account.json, and genesis.bin do not exist" );

  CHECK( check_dir( config->ledger.path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );
  CHECK( check_dir( config->scratch_directory, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  CHECK( check_file( faucet, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CHECK( check_file( stake, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CHECK( check_file( vote, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CHECK( check_file( genesis, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );

  CONFIGURE_OK();
}

configure_stage_t cluster = {
  .name            = NAME,
  .always_recreate = 1,
  .enabled         = enabled,
  .init_perm       = NULL,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
