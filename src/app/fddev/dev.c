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
#include <sys/wait.h>

void
dev_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args ) {
  args->dev.monitor = fd_env_strip_cmdline_contains( pargc, pargv, "--monitor" );
  args->dev.no_configure = fd_env_strip_cmdline_contains( pargc, pargv, "--no-configure" );
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

static void
parent_signal( int sig ) {
  (void)sig;
  int err = 0;
  if( FD_LIKELY( firedancer_pid ) )
    if( kill( firedancer_pid, SIGINT ) ) err = 1;
  if( FD_LIKELY( monitor_pid ) )
    if( kill( monitor_pid, SIGKILL ) ) err = 1;
  fd_log_private_fprintf_nolock_0( STDERR_FILENO, "Log at \"%s\"\n", fd_log_private_path );
  exit_group( err );
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
  if( FD_LIKELY( config->consensus.expected_shred_version==(ushort)0 ) ) {
    char genesis_path[ PATH_MAX ];
    snprintf1( genesis_path, PATH_MAX, "%s/genesis.bin", config->ledger.path );
    config->consensus.expected_shred_version = compute_shred_version( genesis_path );

    ulong i=0UL;
    for( ; i<config->shmem.workspaces_cnt; i++ ) {
      if( FD_UNLIKELY( config->shmem.workspaces[ i ].kind == wksp_shred ) ) break;
    }
    FD_TEST( i!=config->shmem.workspaces_cnt );

    char name[ PATH_MAX ];
    snprintf1( name, sizeof( name ), "%s_shred.wksp", config->name );

    fd_wksp_t * wksp = fd_wksp_attach( name );
    if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "could not attach to workspace `%s`", name ));

    void * laddr = fd_wksp_laddr( wksp, wksp->gaddr_lo );
    if( FD_UNLIKELY( !laddr ) ) FD_LOG_ERR(( "could not get gaddr_low from workspace `%s`", name ));

    uchar const * pod = fd_pod_join( laddr );
    if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "fd_pod_join to pod at gaddr_lo failed" ));

    ulong * shred_version = fd_wksp_pod_map( pod, "shred_version" );
    *shred_version = (ulong)config->consensus.expected_shred_version;
    fd_wksp_pod_unmap( shred_version );
    fd_wksp_detach( wksp );
  }

  if( FD_LIKELY( !strcmp( config->consensus.vote_account_path, "" ) ) )
    snprintf1( config->consensus.vote_account_path,
               sizeof( config->consensus.vote_account_path ),
               "%s/vote-account.json",
               config->scratch_directory );
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

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    /* if we entered a network namespace during configuration, leave it
       so that `run_firedancer` starts from a clean namespace */
    leave_network_namespace();
  }

  if( FD_LIKELY( !args->dev.monitor ) ) run_firedancer( config );
  else {
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
      run_firedancer( config );
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
    if( FD_UNLIKELY( exited_pid == -1 ) ) {
      fd_log_private_fprintf_nolock_0( STDERR_FILENO, "wait4() failed (%i-%s)", errno, fd_io_strerror( errno ) );
      exit_group( 1 );
    }

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
