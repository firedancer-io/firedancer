#define _GNU_SOURCE
#include "run.h"

#include <sys/wait.h>
#include "generated/main_seccomp.h"
#include "generated/pidns_seccomp.h"

#include "../../../disco/tiles.h"
#include "../configure/configure.h"

#include <sched.h>
#include <stdio.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <linux/capability.h>
#include <linux/unistd.h>

#include "../../../util/tile/fd_tile_private.h"

#define NAME "run"

void
run_cmd_perm( args_t *         args,
              fd_caps_ctx_t *  caps,
              config_t * const config ) {
  (void)args;

  ulong mlock_limit = fd_topo_mlock_max_tile( &config->topo );

  fd_caps_check_resource(     caps, NAME, RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );
  fd_caps_check_resource(     caps, NAME, RLIMIT_NICE,    40,          "call `setpriority(2)` to increase thread priorities" );
  fd_caps_check_resource(     caps, NAME, RLIMIT_NOFILE,  CONFIGURE_NR_OPEN_FILES,
                                                                       "call `rlimit(2)  to increase `RLIMIT_NOFILE` to allow more open files for Agave" );
  fd_caps_check_capability(   caps, NAME, CAP_NET_RAW,                 "call `socket(2)` to bind to a raw socket for use by XDP" );
  fd_caps_check_capability(   caps, NAME, CAP_SYS_ADMIN,               "call `bpf(2)` with the `BPF_OBJ_GET` command to initialize XDP" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_caps_check_capability( caps, NAME, CAP_SETUID,                  "call `setresuid(2)` to switch uid" );
  if( FD_LIKELY( getgid() != config->gid ) )
    fd_caps_check_capability( caps, NAME, CAP_SETGID,                  "call `setresgid(2)` to switch gid" );
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    fd_caps_check_capability( caps, NAME, CAP_SYS_ADMIN,               "call `setns(2)` to enter a network namespace" );
  if( FD_UNLIKELY( config->tiles.metric.prometheus_listen_port<1024 ) )
    fd_caps_check_capability( caps, NAME, CAP_NET_BIND_SERVICE,        "call `bind(2)` to bind to a privileged port for serving metrics" );
}

struct pidns_clone_args {
  config_t * config;
  int      * pipefd;
  int        closefd;
};

extern char fd_log_private_path[ 1024 ]; /* empty string on start */

static pid_t pid_namespace;

#define FD_LOG_ERR_NOEXIT(a) do { long _fd_log_msg_now = fd_log_wallclock(); fd_log_private_1( 4, _fd_log_msg_now, __FILE__, __LINE__, __func__, fd_log_private_0 a ); } while(0)

extern int * fd_log_private_shared_lock;

static void
parent_signal( int sig ) {
  if( FD_LIKELY( pid_namespace ) ) kill( pid_namespace, SIGKILL );

  /* A pretty gross hack.  For the local process, clear the lock so that
     we can always print the messages without waiting on another process,
     particularly if one of those processes might have just died.  The
     signal handler is re-entrant so this also avoids a deadlock since
     the log lock is not re-entrant. */
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

static int
execve_solana_labs( int config_memfd,
                    int pipefd ) {
  if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  pid_t child = fork();
  if( FD_UNLIKELY( -1==child ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !child ) ) {
    char _current_executable_path[ PATH_MAX ];
    current_executable_path( _current_executable_path );

    char config_fd[ 32 ];
    FD_TEST( fd_cstr_printf_check( config_fd, sizeof( config_fd ), NULL, "%d", config_memfd ) );
    char * args[ 5 ] = { _current_executable_path, "run-solana", "--config-fd", config_fd, NULL };

    char * envp[] = { NULL, NULL };
    char * google_creds = getenv( "GOOGLE_APPLICATION_CREDENTIALS" );
    char provide_creds[ PATH_MAX+30UL ];
    if( FD_UNLIKELY( google_creds ) ) {
      FD_TEST( fd_cstr_printf_check( provide_creds, sizeof( provide_creds ), NULL, "GOOGLE_APPLICATION_CREDENTIALS=%s", google_creds ) );
      envp[ 0 ] = provide_creds;
    }

    if( FD_UNLIKELY( -1==execve( _current_executable_path, args, envp ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return child;
  }
  return 0;
}

static pid_t
execve_tile( fd_topo_tile_t * tile,
             fd_cpuset_t *    floating_cpu_set,
             int              floating_priority,
             int              config_memfd,
             int              pipefd ) {
  FD_CPUSET_DECL( cpu_set );
  if( FD_LIKELY( tile->cpu_idx!=ULONG_MAX ) ) {
    /* set the thread affinity before we clone the new process to ensure
        kernel first touch happens on the desired thread. */
    fd_cpuset_insert( cpu_set, tile->cpu_idx );
    if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, -19 ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    fd_memcpy( cpu_set, floating_cpu_set, fd_cpuset_footprint() );
    if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, floating_priority ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, cpu_set ) ) ) {
    if( FD_LIKELY( errno==EINVAL ) ) {
      FD_LOG_ERR(( "Unable to set the thread affinity for tile %s:%lu on cpu %lu. It is likely that the affinity "
                   "you have specified for this tile in [layout.affinity] of your configuration file contains a "
                   "CPU (%lu) which does not exist on this machine.",
                   tile->name, tile->kind_id, tile->cpu_idx, tile->cpu_idx ));
    } else {
      FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  /* Clear CLOEXEC on the side of the pipe we want to pass to the tile. */
  if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  pid_t child = fork();
  if( FD_UNLIKELY( -1==child ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !child ) ) {
    char _current_executable_path[ PATH_MAX ];
    current_executable_path( _current_executable_path );

    char kind_id[ 32 ], config_fd[ 32 ], pipe_fd[ 32 ];
    FD_TEST( fd_cstr_printf_check( kind_id,   sizeof( kind_id ),   NULL, "%lu", tile->kind_id ) );
    FD_TEST( fd_cstr_printf_check( config_fd, sizeof( config_fd ), NULL, "%d",  config_memfd ) );
    FD_TEST( fd_cstr_printf_check( pipe_fd,   sizeof( pipe_fd ),   NULL, "%d",  pipefd ) );
    char * args[ 9 ] = { _current_executable_path, "run1", tile->name, kind_id, "--pipe-fd", pipe_fd, "--config-fd", config_fd, NULL };
    if( FD_UNLIKELY( -1==execve( _current_executable_path, args, NULL ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return child;
  }
  return 0;
}

extern int * fd_log_private_shared_lock;

int
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

  int config_memfd = config_write_memfd( config );

  if( FD_UNLIKELY( config->development.debug_tile ) ) {
    fd_log_private_shared_lock[1] = 1;
  }

  ulong child_cnt = 0UL;
  if( FD_LIKELY( !config->development.no_solana_labs ) ) {
    int pipefd[ 2 ];
    if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    fds[ child_cnt ] = (struct pollfd){ .fd = pipefd[ 0 ], .events = 0 };
    child_pids[ child_cnt ] = execve_solana_labs( config_memfd, pipefd[ 1 ] );
    if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    strncpy( child_names[ child_cnt ], "solana-labs", 32 );
    child_cnt++;
  }

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    enter_network_namespace( config->tiles.net.interface );
    close_network_namespace_original_fd();
  }

  errno = 0;
  int save_priority = getpriority( PRIO_PROCESS, 0 );
  if( FD_UNLIKELY( -1==save_priority && errno ) ) FD_LOG_ERR(( "getpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong i=0; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles[ i ];
    if( FD_UNLIKELY( tile->is_labs ) ) continue;

    int pipefd[ 2 ];
    if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    fds[ child_cnt ] = (struct pollfd){ .fd = pipefd[ 0 ], .events = 0 };
    child_pids[ child_cnt ] = execve_tile( tile, floating_cpu_set, save_priority, config_memfd, pipefd[ 1 ] );
    if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    strncpy( child_names[ child_cnt ], tile->name, 32 );
    child_cnt++;
  }

  if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, save_priority ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "fd_cpuset_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( close( config_memfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( config->log.lock_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int allow_fds[ 4+FD_TOPO_MAX_TILES ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  allow_fds[ allow_fds_cnt++ ] = args->pipefd[ 1 ]; /* write end of main pipe */
  for( ulong i=0; i<child_cnt; i++ )
    allow_fds[ allow_fds_cnt++ ] = fds[ i ].fd; /* read end of child pipes */

  struct sock_filter seccomp_filter[ 128UL ];
  populate_sock_filter_policy_pidns( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd() );

  if( FD_LIKELY( config->development.sandbox ) ) {
    fd_sandbox_enter( config->uid,
                      config->gid,
                      0,
                      1UL+child_cnt, /* RLIMIT_NOFILE needs to be set to the nfds argument of poll() */
                      allow_fds_cnt,
                      allow_fds,
                      sock_filter_policy_pidns_instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }

  /* Reap child process PIDs so they don't show up in `ps` etc.  All of
     these children should have exited immediately after clone(2)'ing
     another child with a huge page based stack. */
  for( ulong i=0; i<child_cnt; i++ ) {
    int wstatus;
    int exited_pid = wait4( child_pids[ i ], &wstatus, (int)__WALL, NULL );
    if( FD_UNLIKELY( -1==exited_pid ) ) {
      FD_LOG_ERR(( "pidns wait4() failed (%i-%s) %lu %hu", errno, fd_io_strerror( errno ), i, fds[i].revents ));
    } else if( FD_UNLIKELY( child_pids[ i ]!=exited_pid ) ) {
      FD_LOG_ERR(( "pidns wait4() returned unexpected pid %d %d", child_pids[ i ], exited_pid ));
    } else if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
      FD_LOG_ERR_NOEXIT(( "tile %lu (%s) exited while booting with signal %d (%s)\n", i, child_names[ i ], WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
      exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
    }
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) {
      FD_LOG_ERR_NOEXIT(( "tile %lu (%s) exited while booting with code %d\n", i, child_names[ i ], WEXITSTATUS( wstatus ) ));
      exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
    }
  }

  fds[ child_cnt ] = (struct pollfd){ .fd = args->pipefd[ 1 ], .events = 0 };

  /* We are now the init process of the pid namespace.  If the init
     process dies, all children are terminated.  If any child dies, we
     terminate the init process, which will cause the kernel to
     terminate all other children bringing all of our processes down as
     a group.  The parent process will also die if this process dies,
     due to getting SIGHUP on the pipe. */
  while( 1 ) {
    if( FD_UNLIKELY( -1==poll( fds, 1+child_cnt, -1 ) ) ) FD_LOG_ERR(( "poll() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    for( ulong i=0; i<1+child_cnt; i++ ) {
      if( FD_UNLIKELY( fds[ i ].revents ) ) {
        /* Must have been POLLHUP, POLLERR and POLLNVAL are not possible. */
        if( FD_UNLIKELY( i==child_cnt ) ) {
          /* Parent process died, probably SIGINT, exit gracefully. */
          exit_group( 0 );
        }

        char * tile_name = child_names[ i ];
        ulong  tile_id = config->topo.tiles[ i ].kind_id;

        /* Child process died, reap it to figure out exit code. */
        int wstatus;
        int exited_pid = wait4( -1, &wstatus, (int)__WALL | (int)WNOHANG, NULL );
        if( FD_UNLIKELY( -1==exited_pid ) ) {
          FD_LOG_ERR(( "pidns wait4() failed (%i-%s) %lu %hu", errno, fd_io_strerror( errno ), i, fds[i].revents ));
        } else if( FD_UNLIKELY( !exited_pid ) ) {
          /* Spurious wakeup, no child actually dead yet. */
          continue;
        }

        if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
          FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with signal %d (%s)", tile_name, tile_id, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
          exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
        } else {
          FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with code %d", tile_name, tile_id, WEXITSTATUS( wstatus ) ));
          exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
        }
      }
    }
  }
  return 0;
}

int
clone_firedancer( config_t * const config,
                  int              close_fd,
                  int *            out_pipe ) {
  /* This pipe is here just so that the child process knows when the
     parent has died (it will get a HUP). */
  int pipefd[2];
  if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC | O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* clone into a pid namespace */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  struct pidns_clone_args args = { .config = config, .closefd = close_fd, .pipefd = pipefd, };

  void * stack = fd_topo_tile_stack_new( 0, NULL, NULL, 0UL, 0UL );

  int pid_namespace = clone( main_pid_namespace, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, flags, &args );
  if( FD_UNLIKELY( pid_namespace<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  *out_pipe = pipefd[ 0 ];
  return pid_namespace;
}

/* The boot sequence is a little bit involved...

   A process tree is created that looks like,

   + main
   +-- pidns
       +-- solana-labs
       +-- tile 0
       +-- tile 1
       ...

   What we want is that if any process in the tree dies, all other
   processes will also die.  This is done as follows,

    (a) pidns is the init process of a PID namespace, so if it dies the
        kernel will terminate the child processes.

    (b) main is the parent of pidns, so it can issue a waitpid() on the
        child PID, and when it completes terminate itself.

    (c) pidns is the parent of solana-labs and the tiles, so it could
        issue a waitpid() of -1 to wait for any of them to terminate,
        but how would it know if main has died?

    (d) main creates a pipe, and passes the write end to pidns.  If main
        dies, the pipe will be closed, and pidns will get a HUP on the
        read end.  Then pidns creates a pipe per child and passes the
        write end to the child.  If any of the children die, the pipe
        will be closed, and pidns will get a HUP on the read end.

        Then pidns can call poll() on both the write end of the main
        pipe and the read end of all the child pipes.  If any of them
        raises SIGHUP, then pidns knows that the parent or a child has
        died, and it can terminate itself, which due to (a) and (b)
        will kill all other processes. */
void
run_firedancer( config_t * const config,
                int              parent_pipefd ) {
  /* dump the topology we are using to the output log */
  fd_topo_print_log( 0, &config->topo );

#if defined(__x86_64__)

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#endif
  long abi = syscall( SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION );
  if( -1L==abi && (errno==ENOSYS || errno==EOPNOTSUPP ) ) {
    FD_LOG_WARNING(( "The Landlock access control system is not supported by your Linux kernel. Firedancer uses landlock to "
                     "provide an additional layer of security to the sandbox, but it is not required." ));
  }

  if( FD_UNLIKELY( close( 0 ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fd_log_private_logfile_fd()!=1 && close( 1 ) ) ) FD_LOG_ERR(( "close(1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int pipefd;
  pid_namespace = clone_firedancer( config, parent_pipefd, &pipefd );

  /* Print the location of the logfile on SIGINT or SIGTERM, and also
     kill the child.  They are connected by a pipe which the child is
     polling so we don't strictly need to kill the child, but its helpful
     to do that before printing the log location line, else it might
     get interleaved due to timing windows in the shutdown. */
  install_parent_signals();

  if( FD_UNLIKELY( close( config->log.lock_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct sock_filter seccomp_filter[ 128UL ];
  populate_sock_filter_policy_main( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd(), (uint)pid_namespace );

  int allow_fds[ 4 ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile, or maybe stdout */
  allow_fds[ allow_fds_cnt++ ] = pipefd; /* read end of main pipe */
  if( FD_UNLIKELY( parent_pipefd!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = parent_pipefd; /* write end of parent pipe */

  if( FD_LIKELY( config->development.sandbox ) ) {
    fd_sandbox_enter( config->uid,
                      config->gid,
                      1, /* Keep controlling terminal for main so it can receive Ctrl+C */
                      0UL,
                      allow_fds_cnt,
                      allow_fds,
                      sock_filter_policy_main_instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }


  /* the only clean way to exit is SIGINT or SIGTERM on this parent process,
     so if wait4() completes, it must be an error */
  int wstatus;
  if( FD_UNLIKELY( -1==wait4( pid_namespace, &wstatus, (int)__WALL, NULL ) ) )
    FD_LOG_ERR(( "main wait4() failed (%i-%s)\nLog at \"%s\"", errno, fd_io_strerror( errno ), fd_log_private_path ));

  if( FD_UNLIKELY( WIFSIGNALED( wstatus ) ) ) exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
  else exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
}

void
run_cmd_fn( args_t *         args,
            config_t * const config ) {
  (void)args;

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

  run_firedancer( config, -1 );
}
