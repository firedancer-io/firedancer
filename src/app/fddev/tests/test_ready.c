#define _GNU_SOURCE
#include "test_fddev.h"

static int
fddev_ready( config_t * config,
             int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "ready" );
  args_t args = {0};
  ready_cmd_fn( &args, config );
  return 0;
}

int
fddev_test_run( int     argc,
                char ** argv,
                int (* run)( config_t * config ) ) {
  int is_base_run = argc==1 ||
    (argc==5 && !strcmp( argv[ 1 ], "--log-path" ) && !strcmp( argv[ 3 ], "--log-level-stderr" ));

  if( FD_LIKELY( is_base_run ) ) {
    if( FD_UNLIKELY( -1==unshare( CLONE_NEWPID ) ) ) FD_LOG_ERR(( "unshare(CLONE_NEWPID) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    int pid = fork();
    if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( !pid ) {
      fd_boot( &argc, &argv );
      fd_log_thread_set( "supervisor" );

      static config_t config[1];
      fdctl_cfg_from_env( &argc, &argv, config );
      config->log.log_fd = fd_log_private_logfile_fd();
      config->log.lock_fd = init_log_memfd();
      config->tick_per_ns_mu = fd_tempo_tick_per_ns( &config->tick_per_ns_sigma );

      return run( config );
    } else {
      int wstatus;
      for(;;) {
        int exited_pid = waitpid( pid, &wstatus, __WALL );
        if( FD_UNLIKELY( -1==exited_pid && errno==EINTR ) ) continue;
        else if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "waitpid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        else if( FD_UNLIKELY( !exited_pid ) ) FD_LOG_ERR(( "supervisor did not exit" ));
        break;
      }

      if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) return 128 + WTERMSIG( wstatus );
      else if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) return WEXITSTATUS( wstatus );
    }
  } else {
    return fddev_main( argc, argv );
  }

  return 0;
}

static int
test_fddev_ready( config_t * config ) {
  struct child_info configure = fork_child( "fddev configure", config, fddev_configure );
  wait_children( &configure, 1UL, 15UL );
  struct child_info wksp = fork_child( "fddev wksp", config, fddev_wksp );
  wait_children( &wksp, 1UL, 15UL );

  struct child_info dev = fork_child( "fddev dev", config, fddev_dev );
  struct child_info ready = fork_child( "fddev ready", config, fddev_ready );

  struct child_info children[ 2 ] = { ready, dev };
  ulong exited = wait_children( children, 2UL, 15UL );
  if( FD_UNLIKELY( exited!=0UL ) ) FD_LOG_ERR(( "`%s` exited unexpectedly", children[ exited-1 ].name ));
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  return fddev_test_run( argc, argv, test_fddev_ready );
}
