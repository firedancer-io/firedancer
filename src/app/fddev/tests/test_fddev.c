#define _GNU_SOURCE
#include "../main.h"

#include "../../platform/fd_sys_util.h"
#include "../../shared/commands/ready.h"
#include "../../shared_dev/commands/wksp.h"
#include "../../shared_dev/commands/dev.h"

#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mman.h>

struct child_info {
  char const * name;
  int          pipefd;
  int          pid;
};

static int
fddev_configure( config_t * config,
                 int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "configure" );
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
    .configure.stages  = {0},
  };

  ulong stage_idx = 0UL;
  for( ulong i=0UL; STAGES[i]; i++ ) {
    /* We can't run the kill stage, else it would kill the currently running
       tests. */
    if( FD_UNLIKELY( !strcmp( "kill", STAGES[ i ]->name ) ) ) continue;
    args.configure.stages[ stage_idx++ ] = STAGES[ i ];
  }

  fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
  configure_cmd_perm( &args, chk, config );
  FD_TEST( !fd_cap_chk_err_cnt( chk ) );
  configure_cmd_fn( &args, config );
  return 0;
}

static int
fddev_wksp( config_t * config,
            int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "wksp" );
  args_t args = {0};
  fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
  wksp_cmd_perm( &args, chk, config );
  ulong err_cnt = fd_cap_chk_err_cnt( chk );
  if( FD_UNLIKELY( err_cnt ) ) {
    for( ulong i=0UL; i<err_cnt; i++ ) FD_LOG_WARNING(( "%s", fd_cap_chk_err( chk, i ) ));
    FD_LOG_ERR(( "insufficient permissions to create workspaces" ));
  }
  wksp_cmd_fn( &args, config );
  return 0;
}

static int
fddev_ready( config_t * config,
             int        pipefd ) {
  (void)pipefd;

  fd_log_thread_set( "ready" );
  args_t args = {0};
  ready_cmd_fn( &args, config );
  return 0;
}

void
spawn_agave( config_t const * config );

static int
fddev_dev( config_t * config,
           int        pipefd ) {
  fd_log_thread_set( "dev" );
  args_t args = {
    .dev.parent_pipefd      = pipefd,
    .dev.no_configure       = 1,
    .dev.no_init_workspaces = 1,
    .dev.no_agave           = 0,
    .dev.monitor            = 0,
  };
  args.dev.debug_tile[ 0 ] = '\0';
  fd_cap_chk_t * chk = fd_cap_chk_join( fd_cap_chk_new( __builtin_alloca_with_align( fd_cap_chk_footprint(), FD_CAP_CHK_ALIGN ) ) );
  dev_cmd_perm( &args, chk, config );
  FD_TEST( !fd_cap_chk_err_cnt( chk ) );
  FD_LOG_WARNING(( "waitpid %lu", fd_sandbox_getpid() ));
  // sleep(15);
  dev_cmd_fn( &args, config, spawn_agave );
  return 0;
}

static struct child_info
fork_child( char const * name,
            config_t * config,
            int (* child)( config_t * config, int pipefd ) ) {
  int pipefd[2] = {0};
  if( FD_UNLIKELY( -1==pipe( pipefd ) ) ) FD_LOG_ERR(( "pipe failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int pid = fork();
  if( FD_UNLIKELY( -1==pid ) ) FD_LOG_ERR(( "fork failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( !pid ) {
    if( FD_UNLIKELY( -1==close( pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    int result = child( config, pipefd[ 1 ] );
    fd_sys_util_exit_group( result );
  }
  if( FD_UNLIKELY( -1==close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return (struct child_info){ .name = name, .pipefd = pipefd[ 0 ], .pid = pid };
}

static ulong
wait_children( struct child_info * children,
               ulong               children_cnt,
               ulong               timeout_seconds ) {
  struct pollfd pfd[ 256 ];
  FD_TEST( children_cnt<=256 );
  for( ulong i=0; i<children_cnt; i++ ) {
    pfd[ i ] = (struct pollfd){
      .fd      = children[ i ].pipefd,
      .events  = 0,
    };
  }

  int exited_child_cnt = poll( pfd, children_cnt, (int)(timeout_seconds*1000UL) );
  if( FD_UNLIKELY( -1==exited_child_cnt ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !exited_child_cnt ) ) FD_LOG_ERR(( "`%s` timed out", children[ 0 ].name ));

  ulong exited_child;
  for( exited_child=0; exited_child<children_cnt; exited_child++ ) {
    if( FD_UNLIKELY( pfd[ exited_child ].revents & POLLHUP ) ) break;
  }
  FD_TEST( exited_child<children_cnt );

  int wstatus;
  int exited_pid = waitpid( children[ exited_child ].pid, &wstatus, __WALL );
  if( FD_UNLIKELY( -1==exited_pid ) ) FD_LOG_ERR(( "waitpid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  else if( FD_UNLIKELY( !exited_pid ) ) FD_LOG_ERR(( "`%s` did not exit", children[ exited_child ].name ));
  else if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) FD_LOG_ERR(( "`%s` failed with signal %d (%s)", children[ exited_child ].name, WTERMSIG( wstatus ), strsignal( WTERMSIG( wstatus ) ) ));
  else if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) FD_LOG_ERR(( "`%s` failed with status %d", children[ exited_child ].name, WEXITSTATUS( wstatus ) ));

  if( FD_UNLIKELY( -1==close( children[ exited_child ].pipefd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return exited_child;
}

static int
init_log_memfd( void ) {
  int memfd = memfd_create( "fd_log_lock_page", 0U );
  if( FD_UNLIKELY( -1==memfd) ) FD_LOG_ERR(( "memfd_create(\"fd_log_lock_page\",0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==ftruncate( memfd, 4096 ) ) ) FD_LOG_ERR(( "ftruncate(memfd,4096) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return memfd;
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
      fd_config_load( 0, 0, 1, (char const *)fdctl_default_config, fdctl_default_config_sz, NULL, NULL, 0UL, NULL, 0UL, NULL, config );
      fd_topo_initialize( config );
      config->log.log_fd = fd_log_private_logfile_fd();
      config->log.lock_fd = init_log_memfd();
      config->frankendancer.consensus.poh_speed_test = 0;

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
    fd_config_file_t _default = (fd_config_file_t){
      .name    = "default",
      .data    = fdctl_default_config,
      .data_sz = fdctl_default_config_sz,
    };

    fd_config_file_t * configs[] = {
      &_default,
      NULL
    };

    return fd_dev_main( argc, argv, 0, configs, fd_topo_initialize );
  }

  return 0;
}

static int
test_fddev( config_t * config ) {
  struct child_info configure = fork_child( "fddev configure", config, fddev_configure );
  wait_children( &configure, 1UL, 15UL );
  struct child_info wksp = fork_child( "fddev wksp", config, fddev_wksp );
  wait_children( &wksp, 1UL, 60UL );

  struct child_info dev = fork_child( "fddev dev", config, fddev_dev );
  struct child_info ready = fork_child( "fddev ready", config, fddev_ready );

  struct child_info children[ 2 ] = { ready, dev };
  ulong exited = wait_children( children, 2UL, 30UL );
  if( FD_UNLIKELY( exited!=0UL ) ) FD_LOG_ERR(( "`%s` exited unexpectedly", children[ exited ].name ));
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  return fddev_test_run( argc, argv, test_fddev );
}
