#define _GNU_SOURCE
#include "fddev.h"

#include <dirent.h>
#include <sched.h>
#include <stdio.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <linux/unistd.h>

#include "../fdctl/run/run.h"

#include "../../util/tile/fd_tile_private.h"

#define FD_LOG_ERR_NOEXIT(a) do { long _fd_log_msg_now = fd_log_wallclock(); fd_log_private_1( 4, _fd_log_msg_now, __FILE__, __LINE__, __func__, fd_log_private_0 a ); } while(0)

void
runhot_cmd_perm( args_t *         args,
                 fd_caps_ctx_t *  caps,
                 config_t * const config ) {
  (void)args;
  (void)config;

  run_cmd_perm( args, caps, config );
}

void
runhot_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {
  args->runhot.hot_reload_binary = fd_env_strip_cmdline_cstr( pargc, pargv, "--hot-reload-binary", NULL, NULL );
  if( FD_UNLIKELY( !args->runhot.hot_reload_binary ) ) FD_LOG_ERR(( "missing required argument --hot-reload-binary" ));
}

extern int * fd_log_private_shared_lock;

struct pidns_clone_args {
  config_t * config;
  int      * pipefd;
  int        closefd;
};

static void
reap_child( ulong        child_idx,
            pid_t        child_pid,
            const char * child_name ) {
  int wstatus;
  int exited_pid = wait4( child_pid, &wstatus, (int)__WALL, NULL );
  if( FD_UNLIKELY( -1==exited_pid ) ) {
    FD_LOG_ERR(( "pidns wait4() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else if( FD_UNLIKELY( child_pid!=exited_pid ) ) {
    FD_LOG_ERR(( "pidns wait4() returned unexpected pid %d %d", child_pid, exited_pid ));
  } else if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
    /* If the tile died with a signal like SIGSEGV or SIGSYS it might
        still be holding the lock, which would cause us to hang when
        writing out the error, so don't require the lock here. */
    int lock = 0;
    fd_log_private_shared_lock = &lock;

    FD_LOG_ERR_NOEXIT(( "tile %lu (%s) exited while booting with signal %d (%s)\n", child_idx, child_name, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
    exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
  }
  if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) {
    FD_LOG_ERR_NOEXIT(( "tile %lu (%s) exited while booting with code %d\n", child_idx, child_name, WEXITSTATUS( wstatus ) ));
    exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
  }
}

static const char * hot_reload_binary;

static int
main_pid_namespace( void * _args ) {
  struct pidns_clone_args * args = _args;
  if( FD_UNLIKELY( close( args->pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1!=args->closefd ) ) {
    if( FD_UNLIKELY( close( args->closefd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  config_t * const config = args->config;

  fd_log_thread_set( "pidns" );
  ulong pid = fd_sandbox_getpid(); /* Need to read /proc again.. we got a new PID from clone */
  fd_log_private_group_id_set( pid );
  fd_log_private_thread_id_set( pid );
  fd_log_private_stack_discover( FD_TILE_PRIVATE_STACK_SZ,
                                 &fd_tile_private_stack0, &fd_tile_private_stack1 );

  if( FD_UNLIKELY( !config->development.sandbox ) ) {
    /* If no sandbox, then there's no actual PID namespace so we can't
       wait() grandchildren for the exit code.  Do this as a workaround. */
    if( FD_UNLIKELY( -1==prctl( PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0 ) ) )
      FD_LOG_ERR(( "prctl(PR_SET_CHILD_SUBREAPER) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Save the current affinity, it will be restored after creating any child tiles */
  FD_CPUSET_DECL( floating_cpu_set );
  if( FD_UNLIKELY( fd_cpuset_getaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "fd_cpuset_getaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  pid_t child_pids[ FD_TOPO_MAX_TILES+1 ];
  char  child_names[ FD_TOPO_MAX_TILES+1 ][ 32 ];
  struct pollfd fds[ FD_TOPO_MAX_TILES+2 ];

  int config_memfd = fdctl_cfg_to_memfd( config );

  if( FD_UNLIKELY( config->development.debug_tile ) ) {
    fd_log_private_shared_lock[1] = 1;
  }

  ulong child_cnt = 0UL;
  if( FD_LIKELY( !config->development.no_agave ) ) {
    int pipefd[ 2 ];
    if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    fds[ child_cnt ] = (struct pollfd){ .fd = pipefd[ 0 ], .events = 0 };
    child_pids[ child_cnt ] = execve_agave( config_memfd, pipefd[ 1 ] );
    if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    strncpy( child_names[ child_cnt ], "agave", 32 );
    child_cnt++;
  }

  errno = 0;
  int save_priority = getpriority( PRIO_PROCESS, 0 );
  if( FD_UNLIKELY( -1==save_priority && errno ) ) FD_LOG_ERR(( "getpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_xdp_fds_t xdp_fds = fd_topo_install_xdp( &config->topo );

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles[ i ];
    if( FD_UNLIKELY( tile->is_agave ) ) continue;

    if( FD_UNLIKELY( strcmp( tile->name, "net" ) ) ) {
      if( FD_UNLIKELY( -1==fcntl( xdp_fds.xsk_map_fd,   F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( -1==fcntl( xdp_fds.prog_link_fd, F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    } else {
      if( FD_UNLIKELY( -1==fcntl( xdp_fds.xsk_map_fd,   F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( -1==fcntl( xdp_fds.prog_link_fd, F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    int pipefd[ 2 ];
    if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    fds[ child_cnt ] = (struct pollfd){ .fd = pipefd[ 0 ], .events = 0 };
    child_pids[ child_cnt ] = execve_tile( tile, floating_cpu_set, save_priority, config_memfd, pipefd[ 1 ], NULL );
    if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    strncpy( child_names[ child_cnt ], tile->name, 32 );
    child_cnt++;
  }

  if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, save_priority ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "fd_cpuset_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* No sandbox, since we need to be able to clone off sandboxed tiles
     and they would inherit the restrictions. */

  /* Reap child process PIDs so they don't show up in `ps` etc.  All of
     these children should have exited immediately after clone(2)'ing
     another child with a huge page based stack. */
  for( ulong i=0UL; i<child_cnt; i++ ) reap_child( i, child_pids[ i ], child_names[ i ] );

  fds[ child_cnt ] = (struct pollfd){ .fd = args->pipefd[ 1 ], .events = 0 };

  /* We are now the init process of the pid namespace.  If the init
     process dies, all children are terminated.  If any child dies, we
     terminate the init process, which will cause the kernel to
     terminate all other children bringing all of our processes down as
     a group.  The parent process will also die if this process dies,
     due to getting SIGHUP on the pipe. */
  while( 1 ) {
    if( FD_UNLIKELY( -1==poll( fds, 1+child_cnt, -1 ) ) ) FD_LOG_ERR(( "poll() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    for( ulong i=0UL; i<1UL+child_cnt; i++ ) {
      if( FD_UNLIKELY( fds[ i ].revents ) ) {
        /* Must have been POLLHUP, POLLERR and POLLNVAL are not possible. */
        if( FD_UNLIKELY( i==child_cnt ) ) {
          /* Parent process died, probably SIGINT, exit gracefully. */
          exit_group( 0 );
        }

        char * tile_name = child_names[ i ];
        ulong  tile_idx = 0UL;
        if( FD_LIKELY( i>0UL ) ) tile_idx = config->development.no_agave ? i : i-1UL;
        ulong  tile_id = config->topo.tiles[ tile_idx ].kind_id;

        /* Child process died, reap it to figure out exit code. */
        int wstatus;
        int exited_pid = wait4( -1, &wstatus, (int)__WALL | (int)WNOHANG, NULL );
        if( FD_UNLIKELY( -1==exited_pid ) ) {
          FD_LOG_ERR(( "pidns wait4() failed (%i-%s) %lu %hu", errno, fd_io_strerror( errno ), i, fds[ i ].revents ));
        } else if( FD_UNLIKELY( !exited_pid ) ) {
          /* Spurious wakeup, no child actually dead yet. */
          continue;
        }

        if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
          int is_reloadable_exit = WTERMSIG( wstatus )==SIGTERM || WTERMSIG( wstatus )==SIGKILL || WTERMSIG( wstatus )==SIGINT;
          int is_reloadable_tile = !strcmp( tile_name, "quic" ) ||
                                   !strcmp( tile_name, "verify" ) ||
                                   !strcmp( tile_name, "dedup" );
          if( FD_LIKELY( is_reloadable_tile && is_reloadable_exit ) ) {
            FD_LOG_NOTICE(( "tile %s:%lu exited with signal %d (%s), it will be hot reloaded", tile_name, tile_id, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));

            if( FD_UNLIKELY( close( fds[ i ].fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

            errno = 0;
            save_priority = getpriority( PRIO_PROCESS, 0 );
            if( FD_UNLIKELY( -1==save_priority && errno ) ) FD_LOG_ERR(( "getpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

            if( FD_UNLIKELY( strcmp( tile_name, "net" ) ) ) {
              if( FD_UNLIKELY( -1==fcntl( xdp_fds.xsk_map_fd,   F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
              if( FD_UNLIKELY( -1==fcntl( xdp_fds.prog_link_fd, F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
            } else {
              if( FD_UNLIKELY( -1==fcntl( xdp_fds.xsk_map_fd,   F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
              if( FD_UNLIKELY( -1==fcntl( xdp_fds.prog_link_fd, F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
            }

            int pipefd[ 2 ];
            if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
            fds[ i ] = (struct pollfd){ .fd = pipefd[ 0 ], .events = 0 };
            child_pids[ i ] = execve_tile( &config->topo.tiles[ tile_idx ], floating_cpu_set, save_priority, config_memfd, pipefd[ 1 ], hot_reload_binary );
            if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

            if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, save_priority ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
            if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, floating_cpu_set ) ) )
              FD_LOG_ERR(( "fd_cpuset_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

            reap_child( i, child_pids[ i ], tile_name );
          } else {
            FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with signal %d (%s)", tile_name, tile_id, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
            exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
          }
        } else {
          FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with code %d", tile_name, tile_id, WEXITSTATUS( wstatus ) ));
          exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
        }
      }
    }
  }
  return 0;
}

void
runhot_cmd_fn( args_t *         args,
               config_t * const config ) {
  hot_reload_binary = args->runhot.hot_reload_binary;

  if( FD_UNLIKELY( !config->gossip.entrypoints_cnt && !config->development.bootstrap ) )
    FD_LOG_ERR(( "No entrypoints specified in configuration file under [gossip.entrypoints], but "
                 "at least one is needed to determine how to connect to the Solana cluster. If "
                 "you want to start a new cluster in a development environment, use `fddev` instead "
                 "of `fdctl`. If you want to use an existing genesis, set [development.bootstrap] "
                 "to \"true\" in the configuration file." ));

  for( ulong i=0; i<config->gossip.entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( config->gossip.entrypoints[ i ], "" ) ) )
      FD_LOG_ERR(( "One of the entrypoints in your configuration file under [gossip.entrypoints] is "
                   "empty. Please remove the empty entrypoint or set it correctly. "));
  }

  run_firedancer( config, -1, 1, main_pid_namespace );
}
