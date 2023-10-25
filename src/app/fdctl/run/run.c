#define _GNU_SOURCE
#include "run.h"

#include <sys/wait.h>
#include "generated/main_seccomp.h"
#include "generated/pidns_seccomp.h"

#include "tiles/tiles.h"
#include "../configure/configure.h"

#include <sched.h>
#include <stdio.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <linux/capability.h>
#include <linux/unistd.h>

#define NAME "run"

void
run_cmd_perm( args_t *         args,
              fd_caps_ctx_t *  caps,
              config_t * const config ) {
  (void)args;

  ulong mlock_limit = fd_topo_mlock_max_tile( &config->topo );

  fd_caps_check_resource(     caps, NAME, RLIMIT_MEMLOCK, mlock_limit, "increase `RLIMIT_MEMLOCK` to lock the workspace in memory with `mlock(2)`" );
  fd_caps_check_resource(     caps, NAME, RLIMIT_NICE,    40,          "call `setpriority(2)` to increase thread priorities" );
  fd_caps_check_resource(     caps, NAME, RLIMIT_NOFILE,  CONFIGURE_NR_OPEN_FILES,
                                                                       "increase `RLIMIT_NOFILE` to allow more open files for Solana Labs" );
  fd_caps_check_capability(   caps, NAME, CAP_NET_RAW,                 "call `bind(2)` to bind to a socket with `SOCK_RAW`" );
  fd_caps_check_capability(   caps, NAME, CAP_SYS_ADMIN,               "initialize XDP by calling `bpf_obj_get`" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_caps_check_capability( caps, NAME, CAP_SETUID,                  "switch uid by calling `setuid(2)`" );
  if( FD_LIKELY( getgid() != config->gid ) )
    fd_caps_check_capability( caps, NAME, CAP_SETGID,                  "switch gid by calling `setgid(2)`" );
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    fd_caps_check_capability( caps, NAME, CAP_SYS_ADMIN,               "enter a network namespace by calling `setns(2)`" );
}

struct pidns_clone_args {
  config_t * config;
  int      * pipefd;
};

extern int  fd_log_private_shared_memfd;
extern char fd_log_private_path[ 1024 ]; /* empty string on start */

static pid_t pid_namespace;

static void
parent_signal( int sig ) {
  (void)sig;
  if( FD_LIKELY( pid_namespace ) ) kill( pid_namespace, SIGKILL );
  fd_log_private_fprintf_nolock_0( STDERR_FILENO, "Received signal %s\n", fd_io_strsignal( sig ) );
  if( -1!=fd_log_private_logfile_fd() )
    fd_log_private_fprintf_nolock_0( STDERR_FILENO, "Log at \"%s\"\n", fd_log_private_path );
  exit_group( 0 );
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

extern int * fd_log_private_shared_lock;

static int write_config_memfd( config_t * config ) {
  int config_memfd = memfd_create( "config", 0 );
  if( FD_UNLIKELY( -1==config_memfd ) ) FD_LOG_ERR(( "memfd_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==ftruncate( config_memfd, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "ftruncate() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  uchar * bytes = mmap( NULL, sizeof( config_t ), PROT_READ | PROT_WRITE, MAP_SHARED, config_memfd, 0 );
  if( FD_UNLIKELY( bytes == MAP_FAILED ) ) FD_LOG_ERR(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_memcpy( bytes, config, sizeof( config_t ) );
  if( FD_UNLIKELY( munmap( bytes, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return config_memfd;
}

static int
execve_solana_labs( int        config_memfd,
                    int        pipefd ) {
  if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  pid_t child = fork();
  if( FD_UNLIKELY( -1==child ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !child ) ) {
    char self_exe_path[ PATH_MAX ];
    self_exe( self_exe_path );

    char * env;
    char * envp[ 3 ] = {0};
    int    idx = 0;
    if( FD_LIKELY(( env = getenv( "TERM" ) )) ) {
      if( FD_UNLIKELY( asprintf( &envp[ idx++ ], "TERM=%s", env ) == -1 ) )
        FD_LOG_ERR(( "asprintf() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    
    char config_fd[ 32 ];
    snprintf1( config_fd, sizeof( config_fd ), "%d", config_memfd );
    char * args[ 5 ] = { self_exe_path, "run-solana", "--boot-memfd", config_fd, NULL };
    if( FD_UNLIKELY( -1==execve( self_exe_path, args, envp ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return child;
  }
  return 0;
}

static pid_t
execve_tile( fd_topo_tile_t * tile,
             ushort           cpu_idx,
             cpu_set_t *      floating_cpu_set,
             int              config_memfd,
             int              pipefd ) {
  cpu_set_t cpu_set[1];
  if( FD_LIKELY( cpu_idx<65535UL ) ) {
      /* set the thread affinity before we clone the new process to ensure
         kernel first touch happens on the desired thread. */
      cpu_set_t cpu_set[1];
      CPU_ZERO( cpu_set );
      CPU_SET( cpu_idx, cpu_set );
  } else {
      fd_memcpy( cpu_set, floating_cpu_set, sizeof(cpu_set_t) );
  }

  if( FD_UNLIKELY( sched_setaffinity( 0, sizeof(cpu_set_t), cpu_set ) ) ) {
    FD_LOG_WARNING(( "unable to pin tile to cpu with sched_setaffinity (%i-%s). "
                     "Unable to set the thread affinity for tile %lu on cpu %hu. Attempting to "
                     "continue without explicitly specifying this cpu's thread affinity but it "
                     "is likely this thread group's performance and stability are compromised "
                     "(possibly catastrophically so). Update [layout.affinity] in the configuraton "
                     "to specify a set of allowed cpus that have been reserved for this thread "
                     "group on this host to eliminate this warning.",
                     errno, fd_io_strerror( errno ), tile->id, cpu_idx ));
  }

  if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  pid_t child = fork();
  if( FD_UNLIKELY( -1==child ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !child ) ) {
    char self_exe_path[ PATH_MAX ];
    self_exe( self_exe_path );

    char * env;
    char * envp[ 3 ] = {0};
    int    idx = 0;
    if( FD_LIKELY(( env = getenv( "TERM" ) )) ) {
      if( FD_UNLIKELY( asprintf( &envp[ idx++ ], "TERM=%s", env ) == -1 ) )
        FD_LOG_ERR(( "asprintf() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    
    char kind_id[ 32 ], config_fd[ 32 ], pipe_fd[ 32 ];
    snprintf1( kind_id, sizeof( kind_id ), "%lu", tile->kind_id );
    snprintf1( config_fd, sizeof( config_fd ), "%d", config_memfd );
    snprintf1( pipe_fd, sizeof( pipe_fd ), "%d", pipefd );
    char * args[ 9 ] = { self_exe_path, "run1", fd_topo_tile_kind_str( tile->kind ), kind_id, "--pipe-fd", pipe_fd, "--boot-memfd", config_fd, NULL };
    if( FD_UNLIKELY( -1==execve( self_exe_path, args, envp ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return child;
  }
  return 0;
}

extern int fd_log_private_fileno;

int
main_pid_namespace( void * _args ) {
  struct pidns_clone_args * args = _args;
  if( FD_UNLIKELY( close( args->pipefd[ 0 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fcntl( args->pipefd[ 1 ], F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  config_t * const config = args->config;

  fd_log_thread_set( "pidns" );
  fd_log_private_group_id_set( (ulong)getpid1() ); /* Need to read /proc since we are in a PID namespace now */

  /* Bank and store tiles are not real tiles yet. */
  ulong tile_cnt = config->topo.tile_cnt
    - fd_topo_tile_kind_cnt( &config->topo, FD_TOPO_TILE_KIND_BANK )
    - fd_topo_tile_kind_cnt( &config->topo, FD_TOPO_TILE_KIND_STORE );

  ushort tile_to_cpu[ FD_TILE_MAX ];
  ulong  affinity_tile_cnt = fd_tile_private_cpus_parse( config->layout.affinity, tile_to_cpu );
  if( FD_UNLIKELY( affinity_tile_cnt<tile_cnt ) ) FD_LOG_ERR(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] only provides for %lu cores. "
                                                               "You should either increase the number of cores dedicated to Firedancer in the affinity string, or decrease the number of cores needed by reducing "
                                                               "the total tile count. You can reduce the tile count by decreasing individual tile counts in the [layout] section of the configuration file.",
                                                               config->topo.tile_cnt, affinity_tile_cnt ));
  if( FD_UNLIKELY( affinity_tile_cnt>tile_cnt ) ) FD_LOG_WARNING(( "The topology you are using has %lu tiles, but the CPU affinity specified in the config tile as [layout.affinity] provides for %lu cores. "
                                                                   "Not all cores in the affinity will be used by Firedancer. You may wish to increase the number of tiles in the system by increasing "
                                                                   "individual tile counts in the [layout] section of the configuration file.",
                                                                    config->topo.tile_cnt, affinity_tile_cnt ));

  /* Save the current affinity, it will be restored after creating any child tiles */
  cpu_set_t floating_cpu_set[1];
  if( FD_UNLIKELY( sched_getaffinity( 0, sizeof(cpu_set_t), floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_getaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  pid_t child_pids[ FD_TOPO_MAX_TILES+1 ];
  char  child_names[ FD_TOPO_MAX_TILES+1 ][ 32 ];
  struct pollfd fds[ FD_TOPO_MAX_TILES+2 ];

  fds[ 0 ] = (struct pollfd){ .fd = args->pipefd[ 1 ], .events = 0 };

  int config_memfd = write_config_memfd( config );

  ulong child_cnt = 0UL;
  if( FD_LIKELY( !config->development.no_solana_labs ) ) {
    int pipefd[ 2 ];
    if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    fds[ 1+child_cnt ] = (struct pollfd){ .fd = pipefd[ 0 ], .events = 0 };
    child_pids[ child_cnt ] = execve_solana_labs( config_memfd, pipefd[ 1 ] );
    if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    strncpy( child_names[ child_cnt ], "solana-labs", 32 );
    child_cnt++;
  }

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    enter_network_namespace( config->tiles.net.interface );
    close_network_namespace_original_fd();
  }

  for( ulong i=0; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles[ i ];
    if( FD_UNLIKELY( tile->kind == FD_TOPO_TILE_KIND_BANK || tile->kind == FD_TOPO_TILE_KIND_STORE ) ) continue;

    int pipefd[ 2 ];
    if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    fds[ 1+child_cnt ] = (struct pollfd){ .fd = pipefd[ 0 ], .events = 0 };
    child_pids[ child_cnt ] = execve_tile( tile, tile_to_cpu[ i ], floating_cpu_set, config_memfd, pipefd[ 1 ] );
    if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    strncpy( child_names[ child_cnt ], fd_topo_tile_kind_str( tile->kind ), 32 );
    child_cnt++;
  }

  if( FD_UNLIKELY( close( config_memfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd_log_private_shared_memfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( sched_setaffinity( 0, sizeof(cpu_set_t), floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( args->pipefd[ 1 ]!=1 ) ) FD_LOG_ERR(( "unexpected fd %d for main pipe", fds[ 0 ].fd ));
  if( FD_UNLIKELY( fd_log_private_fileno!=4 ) ) FD_LOG_ERR(( "unexpected fd %d for logfile", fd_log_private_fileno ));

  int allow_fds[ 4+FD_TOPO_MAX_TILES ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  allow_fds[ allow_fds_cnt++ ] = 1; /* write end of main pipe */
  for( ulong i=0; i<child_cnt; i++ )
    allow_fds[ allow_fds_cnt++ ] = fds[ 1+i ].fd; /* read end of child pipes */

  struct sock_filter seccomp_filter[ 128UL ];
  populate_sock_filter_policy_pidns( 128UL, seccomp_filter );

  fd_sandbox( config->development.sandbox,
              config->uid,
              config->gid,
              1+child_cnt, /* RLIMIT_NOFILE needs to be set to the nfds argument of poll() */
              allow_fds_cnt,
              allow_fds,
              sock_filter_policy_pidns_instr_cnt,
              seccomp_filter );

  /* No more access to the log file, write log lines only to STDERR from
     here out. */

  for( ulong i=0; i<child_cnt; i++ ) {
    int wstatus;
    int exited_pid = wait4( child_pids[ i ], &wstatus, (int)__WALL | (int)WNOHANG, NULL );
    if( FD_UNLIKELY( -1==exited_pid ) ) {
      fd_log_private_fprintf_nolock_0( STDERR_FILENO, "pidns wait4() failed (%i-%s) %lu %hu", errno, fd_io_strerror( errno ), i, fds[i].revents );
      exit_group( 1 );
    } else if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
      fd_log_private_fprintf_nolock_0( STDERR_FILENO, "tile %lu (%s) exited while booting with signal %d (%s)\n", i, child_names[ i ], WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) );
      exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
    }
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) {
      fd_log_private_fprintf_nolock_0( STDERR_FILENO, "tile %lu (%s) exited while booting with code %d\n", i, child_names[ i ], WEXITSTATUS( wstatus ) );
      exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
    }
  }

  /* We are now the init process of the pid namespace. if the init
     process dies, all children are terminated.  If any child dies, we
     terminate the init process, which will cause the kernel to
     terminate all other children bringing all of our processes down as
     a group.  The parent process will also die if this process dies,
     due to getting SIGHUP on the pipe. */
  while( 1 ) {
    if( FD_UNLIKELY( -1==poll( fds, 1+child_cnt, -1 ) ) ) {
      fd_log_private_fprintf_nolock_0( STDERR_FILENO, "poll() failed (%i-%s)", errno, fd_io_strerror( errno ) );
      exit_group( 1 );
    }

    for( ulong i=0; i<1+child_cnt; i++ ) {
      if( FD_UNLIKELY( fds[ i ].revents ) ) {
        if( FD_UNLIKELY( !i ) ) {
          /* Parent process died, probably SIGINT, exit gracefully. */
          exit_group( 0 );
        }

        /* Child process died, reap it to figure out exit code. */
        int wstatus;
        int exited_pid = wait4( -1, &wstatus, (int)__WALL | (int)WNOHANG, NULL );
        if( FD_UNLIKELY( -1==exited_pid ) ) {
          fd_log_private_fprintf_nolock_0( STDERR_FILENO, "pidns wait4() failed (%i-%s) %lu %hu", errno, fd_io_strerror( errno ), i, fds[i].revents );
          exit_group( 1 );
        } else if( FD_UNLIKELY( !exited_pid ) ) {
          /* Spurious wakeup, no child actually dead yet. */
          continue;
        }

        char * tile_name = child_names[ i-1 ];
        ulong  tile_id = i-1 ? config->topo.tiles[ i-1 ].kind_id : 0;

        if( FD_UNLIKELY( !WIFEXITED( wstatus ) ) ) {
          fd_log_private_fprintf_nolock_0( STDERR_FILENO, "tile %s:%lu exited with signal %d (%s)\n", tile_name, tile_id, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) );
          exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
        }
        fd_log_private_fprintf_nolock_0( STDERR_FILENO, "tile %s:%lu exited with code %d\n", tile_name, tile_id, WEXITSTATUS( wstatus ) );
        exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
      }
    }
  }
  return 0;
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
        but how would it know if main has dies?

    (d) main creates a pipe, and passes the write end to pidns.  If main
        dies, the pipe will be closed, and pidns will get a HUP on the
        read end.  Then pidns creates a pipe per child and passes the
        write end to the child.  If any of the children die, the pipe
        will be closed, and pidns will get a HUP on the read end.

        Then pidns can call poll() on both the write end of the main
        pipe and the read end of all the child pipes.  If any of them
        raises SIGHUP, then pidns knows that the parent or a child has
        died, and it can terminate itself, which due to (a) and (b)
        will kill all other processes.
   */
void
run_firedancer( config_t * const config ) {
  /* dump the topology we are using to the output log */
  fd_topo_print_log( &config->topo );

  void * stack = fd_tile_private_stack_new( 0, 65535UL );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for boot process" ));

  if( FD_UNLIKELY( close( 0 ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( 1 ) ) ) FD_LOG_ERR(( "close(1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* This pipe is here just so that the child process knows when the
     parent has died (it will get a HUP). */
  int pipefd[2];
  if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC | O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* clone into a pid namespace */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  struct pidns_clone_args args = { .config = config, .pipefd = pipefd, };
  pid_namespace = clone( main_pid_namespace, (uchar *)stack + (8UL<<20), flags, &args );
  if( FD_UNLIKELY( pid_namespace<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Print the location of the logfile on SIGINT or SIGTERM, and also
     kill the child.  They are connected by a pipe which the child is
     polling so we don't strictly need to kill the child, but its helpful
     to do that before printing the log location line, else it might
     get interleaved due to timing windows in the shutdown. */
  install_parent_signals();

  if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd_log_private_shared_memfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct sock_filter seccomp_filter[ 128UL ];
  FD_TEST( pid_namespace >= 0 );
  populate_sock_filter_policy_main( 128UL, seccomp_filter, (unsigned int)pid_namespace );

  int allow_fds[3];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  allow_fds[ allow_fds_cnt++ ] = 0; /* read end of main pipe */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

  fd_sandbox( config->development.sandbox,
              config->uid,
              config->gid,
              0UL,
              allow_fds_cnt,
              allow_fds,
              sock_filter_policy_main_instr_cnt,
              seccomp_filter );

  /* the only clean way to exit is SIGINT or SIGTERM on this parent process,
     so if wait4() completes, it must be an error */
  int wstatus;
  if( FD_UNLIKELY( -1==wait4( pid_namespace, &wstatus, (int)__WALL, NULL ) ) ) {
    fd_log_private_fprintf_nolock_0( STDERR_FILENO, "main wait4() failed (%i-%s)\nLog at \"%s\"\n", errno, fd_io_strerror( errno ), fd_log_private_path );
    exit_group( 1 );
  }
  if( FD_UNLIKELY( WIFSIGNALED( wstatus ) ) ) exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
  else exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
}

void
run_cmd_fn( args_t *         args,
            config_t * const config ) {
  (void)args;

  if( FD_UNLIKELY( !config->gossip.entrypoints_cnt ) )
    FD_LOG_ERR(( "No entrypoints specified in configuration file under [gossip.entrypoints], but "
                 "at least one is needed to determine how to connect to the Solana cluster. If "
                 "you want to start a new cluster in a development environment, use `fddev` instead "
                 "of `fdctl`." ));

  for( ulong i=0; i<config->gossip.entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( config->gossip.entrypoints[ i ], "" ) ) )
      FD_LOG_ERR(( "One of the entrypoints in your configuration file under [gossip.entrypoints] is "
                   "empty. Please remove the empty entrypoint or set it correctly. "));
  }

  run_firedancer( config );
}
