#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"
#include "../../util/wksp/fd_wksp_private.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/wait.h>

#include "../../util/tile/fd_tile_private.h"

void
dev_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args ) {
  args->dev.monitor = fd_env_strip_cmdline_contains( pargc, pargv, "--monitor" );
  args->dev.no_configure = fd_env_strip_cmdline_contains( pargc, pargv, "--no-configure" );
  args->dev.no_solana_labs = fd_env_strip_cmdline_contains( pargc, pargv, "--no-solana-labs" ) ||
                             fd_env_strip_cmdline_contains( pargc, pargv, "--no-solana" ) ||
                             fd_env_strip_cmdline_contains( pargc, pargv, "--no-labs" );
  const char * debug_tile = fd_env_strip_cmdline_cstr( pargc, pargv, "--debug-tile", NULL, NULL );
  if( FD_UNLIKELY( debug_tile ) )
    strncpy( args->dev.debug_tile, debug_tile, sizeof( args->dev.debug_tile ) - 1 );
}

void
dev_cmd_perm( args_t *         args,
              fd_caps_ctx_t *  caps,
              config_t * const config ) {
  if( FD_LIKELY( !args->dev.no_configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
      configure_args.configure.stages[ i ] = STAGES[ i ];
    configure_cmd_perm( &configure_args, caps, config );
  }

  run_cmd_perm( NULL, caps, config );
}

pid_t firedancer_pid, monitor_pid;
extern char fd_log_private_path[ 1024 ]; /* empty string on start */

#define FD_LOG_ERR_NOEXIT(a) do { long _fd_log_msg_now = fd_log_wallclock(); fd_log_private_1( 4, _fd_log_msg_now, __FILE__, __LINE__, __func__, fd_log_private_0 a ); } while(0)

extern int * fd_log_private_shared_lock;

static void
parent_signal( int sig ) {
  (void)sig;
  if( FD_LIKELY( firedancer_pid ) ) kill( firedancer_pid, SIGINT );
  if( FD_LIKELY( monitor_pid ) )    kill( monitor_pid, SIGKILL );

  /* Same hack as in run.c, see comments there. */
  int lock = 0;
  fd_log_private_shared_lock = &lock;

  if( -1!=fd_log_private_logfile_fd() ) FD_LOG_ERR_NOEXIT(( "Received signal %s\nLog at \"%s\"", fd_io_strsignal( sig ), fd_log_private_path ));
  else                                  FD_LOG_ERR_NOEXIT(( "Received signal %s",                fd_io_strsignal( sig ) ));

  if( FD_LIKELY( sig==SIGINT ) ) exit_group( 128+SIGINT  );
  else                           exit_group( 128+SIGTERM );
}

static void
install_parent_signals( void ) {
  struct sigaction sa = {
    .sa_handler = parent_signal,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static ushort
compute_shred_version( char const * genesis_path ) {
  /* Compute the shred version and the genesis hash */
  fd_sha256_t _sha[ 1 ];  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_sha256_init( sha );
  uchar buffer[ 4096 ];

  FILE * genesis_file = fopen( genesis_path, "r" );
  if( FD_UNLIKELY( !genesis_file ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return (ushort)0;

    FD_LOG_ERR(( "Opening genesis file (%s) failed (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));
  }

  while( !feof( genesis_file ) ) {
    ulong read = fread( buffer, 1UL, sizeof(buffer), genesis_file );
    if( FD_UNLIKELY( ferror( genesis_file ) ) )
      FD_LOG_ERR(( "fread failed `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

    fd_sha256_append( sha, buffer, read );
  }

  if( FD_UNLIKELY( fclose( genesis_file ) ) )
    FD_LOG_ERR(( "fclose failed `%s` (%i-%s)", genesis_path, errno, fd_io_strerror( errno ) ));

  union {
    uchar  c[ 32 ];
    ushort s[ 16 ];
  } hash;
  fd_sha256_fini( sha, hash.c );
  fd_sha256_delete( fd_sha256_leave( sha ) );

  ushort xor = 0;
  for( ulong i=0UL; i<16UL; i++ ) xor ^= hash.s[ i ];

  xor = fd_ushort_bswap( xor );
  return fd_ushort_if( xor<USHORT_MAX, (ushort)(xor + 1), USHORT_MAX );
}

void
update_config_for_dev( config_t * const config ) {
  /* when starting from a new genesis block, this needs to be off else the
     validator will get stuck forever. */
  config->consensus.wait_for_vote_to_start_leader = 0;

  /* We have to wait until we get a snapshot before we can join a second
     validator to this one, so make this smaller than the default.  */
  config->snapshots.full_snapshot_interval_slots = 200U;

  /* Automatically compute the shred version from genesis if it
     exists and we don't know it.  If it doesn't exist, we'll keep it
     set to zero and get from gossip. */
  ulong shred_id = fd_topo_find_tile( &config->topo, "shred", 0UL );
  if( FD_UNLIKELY( shred_id == ULONG_MAX ) ) FD_LOG_ERR(( "could not find shred tile" ));
  fd_topo_tile_t * shred = &config->topo.tiles[ shred_id ];
  if( FD_LIKELY( shred->shred.expected_shred_version==(ushort)0 ) ) {
    char genesis_path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( genesis_path, PATH_MAX, NULL, "%s/genesis.bin", config->ledger.path ) );
    shred->shred.expected_shred_version = compute_shred_version( genesis_path );
  }

  if( FD_LIKELY( !strcmp( config->consensus.vote_account_path, "" ) ) )
    FD_TEST( fd_cstr_printf_check( config->consensus.vote_account_path,
                                   sizeof( config->consensus.vote_account_path ),
                                   NULL,
                                   "%s/vote-account.json",
                                   config->scratch_directory ) );
}

static void *
solana_labs_main1( void * args ) {
  solana_labs_boot( args );
  return NULL;
}

/* Run Firedancer entirely in a single process for development and
   debugging convenience. */

static void
run_firedancer_threaded( config_t * config ) {
  install_parent_signals();

  fd_topo_print_log( 0, &config->topo );

  if( FD_UNLIKELY( config->development.debug_tile ) ) {
    fd_log_private_shared_lock[ 1 ] = 1;
  }

  /* This is kind of a hack, but we have to join all the workspaces as read-write
     if we are running things threaded.  The reason is that if one of the earlier
     tiles maps it in as read-only, later tiles will reuse the same cached shmem
     join (the key is only on shmem name, when it should be (name, mode)). */

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run, fdctl_tile_align, fdctl_tile_footprint );

  if( FD_LIKELY( !config->development.no_solana_labs ) ) {
    pthread_t pthread;
    if( FD_UNLIKELY( pthread_create( &pthread, NULL, solana_labs_main1, config ) ) ) FD_LOG_ERR(( "pthread_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( pthread_setname_np( pthread, "fdSolMain" ) ) ) FD_LOG_ERR(( "pthread_setname_np() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* None of the threads will ever exit, they just abort the process, so sleep forever. */
  for(;;) sleep( 60 );
}

void
dev_cmd_fn( args_t *         args,
            config_t * const config ) {
  if( FD_LIKELY( !args->dev.no_configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
      configure_args.configure.stages[ i ] = STAGES[ i ];
    configure_cmd_fn( &configure_args, config );
  }

  update_config_for_dev( config );
  if( FD_UNLIKELY( args->dev.no_solana_labs ) ) config->development.no_solana_labs = 1;

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    /* if we entered a network namespace during configuration, leave it
       so that `run_firedancer` starts from a clean namespace */
    leave_network_namespace();
  }

  if( FD_UNLIKELY( strcmp( "", args->dev.debug_tile ) ) ) {
    if( FD_LIKELY( config->development.sandbox ) ) {
      FD_LOG_WARNING(( "disabling sandbox to debug tile `%s`", args->dev.debug_tile ));
      config->development.sandbox = 0;
    }

    if( !strcmp( args->dev.debug_tile, "solana" ) ||
        !strcmp( args->dev.debug_tile, "labs" ) ||
        !strcmp( args->dev.debug_tile, "solana-labs" ) ) {
      config->development.debug_tile = UINT_MAX; /* Sentinel value representing Solana Labs */
    } else {
      ulong tile_id = fd_topo_find_tile( &config->topo, args->dev.debug_tile, 0UL );
      if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "--debug-tile `%s` not present in topology", args->dev.debug_tile ));
      config->development.debug_tile = 1U+(uint)tile_id;
    }
  }

  if( FD_LIKELY( !args->dev.monitor ) ) {
      if( FD_LIKELY( !config->development.no_clone ) ) run_firedancer( config );
      else                                             run_firedancer_threaded( config );
  } else {
    install_parent_signals();

    int pipefd[2];
    if( FD_UNLIKELY( pipe2( pipefd, O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    firedancer_pid = fork();
    if( !firedancer_pid ) {
      if( FD_UNLIKELY( close( pipefd[0] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( dup2( pipefd[1], STDERR_FILENO ) == -1 ) )
        FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( close( pipefd[1] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( setenv( "RUST_LOG_STYLE", "always", 1 ) ) ) /* otherwise RUST_LOG will not be colorized to the pipe */
        FD_LOG_ERR(( "setenv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_LIKELY( !config->development.no_clone ) ) run_firedancer( config );
      else                                             run_firedancer_threaded( config );
    } else {
      if( FD_UNLIKELY( close( pipefd[1] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    args_t monitor_args;
    int argc = 0;
    char * argv[] = { NULL };
    char ** pargv = (char**)argv;
    monitor_cmd_args( &argc, &pargv, &monitor_args );
    monitor_args.monitor.drain_output_fd = pipefd[0];

    monitor_pid = fork();
    if( !monitor_pid ) monitor_cmd_fn( &monitor_args, config );
    if( FD_UNLIKELY( close( pipefd[0] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    int wstatus;
    pid_t exited_pid = wait4( -1, &wstatus, (int)__WALL, NULL );
    if( FD_UNLIKELY( exited_pid == -1 ) ) FD_LOG_ERR(( "wait4() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    char * exited_child = exited_pid == firedancer_pid ? "firedancer" : exited_pid == monitor_pid ? "monitor" : "unknown";
    int exit_code = 0;
    if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
      FD_LOG_ERR(( "%s exited unexpectedly with signal %d (%s)", exited_child, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
      exit_code = WTERMSIG( wstatus );
    } else {
      FD_LOG_ERR(( "%s exited unexpectedly with code %d", exited_child, WEXITSTATUS( wstatus ) ));
      if( FD_UNLIKELY( exited_pid == monitor_pid && !WEXITSTATUS( wstatus ) ) ) exit_code = EXIT_FAILURE;
      else exit_code = WEXITSTATUS( wstatus );
    }

    if( FD_UNLIKELY( exited_pid == monitor_pid ) ) {
      if( FD_UNLIKELY( kill( firedancer_pid, SIGKILL ) ) )
        FD_LOG_ERR(( "failed to kill all processes (%i-%s)", errno, fd_io_strerror( errno ) ));
    } else {
      if( FD_UNLIKELY( kill( monitor_pid, SIGKILL ) ) )
        FD_LOG_ERR(( "failed to kill all processes (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    exit_group( exit_code );
  }
}
