#define _GNU_SOURCE
#include "../../fdctl/configure/configure.h"

#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define NAME "genesis"

static int
enabled( config_t * const config ) {
  /* always enabled by default, this only gets run directly from the `dev` command */
  (void)config;
  return 1;
}

extern void fd_ext_genesis_main( const char ** args );

static void
init( config_t * const config ) {
  mkdir_all( config->ledger.path, config->uid, config->gid );

  uint idx = 0;
  char * argv[ 128 ];
  uint bufidx = 0;
  char buffer[ 32 ][ 24 ];
#define ADD1( arg ) do { argv[ idx++ ] = arg; } while( 0 )
#define ADD( arg, val ) do { argv[ idx++ ] = arg; argv[ idx++ ] = val; } while( 0 )
#define ADDU( arg, val ) do { argv[ idx++ ] = arg; FD_TEST( fd_cstr_printf_check( buffer[ bufidx ], 24, NULL, "%lu", val ) ); argv[ idx++ ] = buffer[ bufidx++ ]; } while( 0 )

  char faucet[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( faucet, PATH_MAX, NULL, "%s/faucet.json", config->scratch_directory ) );

  char stake[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( stake, PATH_MAX, NULL, "%s/stake-account.json", config->scratch_directory ) );

  char vote[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( vote, PATH_MAX, NULL, "%s/vote-account.json", config->scratch_directory ) );

  ADD1( "fddev" );

  ADD( "--faucet-pubkey", faucet );
  ADD( "--hashes-per-tick", "sleep" );
  ADDU( "--faucet-lamports", 500000000000000000UL );
  ADD( "--bootstrap-validator", config->consensus.identity_path ); ADD1( vote ); ADD1( stake );
  ADD( "--ledger", config->ledger.path );
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

  /* fork off a new process for genesis creation.  Genesis creation happens
     multi-threaded (Solana Labs spawns hundreds of Rayon threads), so we
     would no longer be able to sandbox this process (you can't unshare the
     user namespace once multi-threaded). We also want all those threads
     gone once genesis creation completes, but Labs does not clean them up. */
  pid_t pid = fork();
  if( FD_UNLIKELY( pid == -1 ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( !pid ) ) {
    /* switch to non-root uid/gid for file creation. permissions checks still done as root. */
    gid_t gid = getgid();
    uid_t uid = getuid();
    if( FD_LIKELY( gid == 0 && setegid( config->gid ) ) )
      FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_LIKELY( uid == 0 && seteuid( config->uid ) ) )
      FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    umask( S_IRWXO | S_IRWXG );
    fd_ext_genesis_main( (const char **)argv );
    exit_group( 0 );
  } else {
    int wstatus;
    if( FD_UNLIKELY( waitpid( pid, &wstatus, 0 )==-1 ) ) FD_LOG_ERR(( "waitpid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( WIFSIGNALED( wstatus ) ) )
      FD_LOG_ERR(( "genesis creation process terminated by signal %i-%s", WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) )
      FD_LOG_ERR(( "genesis creation process exited with status %i", WEXITSTATUS( wstatus ) ));
  }
}

static void
rmtree( char * path ) {
    DIR * dir = opendir( path );
    if( FD_UNLIKELY( !dir ) ) {
      if( errno == ENOENT ) return;
      FD_LOG_ERR(( "opendir `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    }

    struct dirent * entry;
    errno = 0;
    while(( entry = readdir( dir ) )) {
      if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

      char path1[ PATH_MAX ];
      FD_TEST( fd_cstr_printf_check( path1, PATH_MAX, NULL, "%s/%s", path, entry->d_name ) );

      struct stat st;
      if( FD_UNLIKELY( lstat( path1, &st ) ) ) {
        if( FD_LIKELY( errno == ENOENT ) ) continue;
        FD_LOG_ERR(( "stat `%s` failed (%i-%s)", path1, errno, fd_io_strerror( errno ) ));
      }

      if( FD_UNLIKELY( S_ISDIR( st.st_mode ) ) ) {
        rmtree( path1 );
      } else {
        if( FD_UNLIKELY( unlink( path1 ) && errno != ENOENT ) )
          FD_LOG_ERR(( "unlink `%s` failed (%i-%s)", path1, errno, fd_io_strerror( errno ) ));
      }
    }

    if( FD_UNLIKELY( errno && errno != ENOENT ) ) FD_LOG_ERR(( "readdir `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

    if( FD_UNLIKELY( rmdir( path ) ) ) FD_LOG_ERR(( "rmdir `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

static void
fini( config_t * const config ) {
  rmtree( config->ledger.path );
}

static configure_result_t
check( config_t * const config ) {
  struct stat st;
  if( FD_UNLIKELY( stat( config->ledger.path, &st ) && errno == ENOENT ) )
    NOT_CONFIGURED( "`%s` does not exist", config->ledger.path );

  CHECK( check_dir( config->ledger.path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  PARTIALLY_CONFIGURED( "genesis directory exists at `%s`", config->ledger.path );
}

configure_stage_t genesis = {
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
