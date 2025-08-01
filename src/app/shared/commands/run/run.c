#define _GNU_SOURCE
#include "run.h"

#include <sys/wait.h>
#include "generated/main_seccomp.h"
#if defined(__aarch64__)
#include "generated/pidns_arm64_seccomp.h"
#else
#include "generated/pidns_seccomp.h"
#endif

#include "../../../platform/fd_sys_util.h"
#include "../../../platform/fd_file_util.h"
#include "../../../platform/fd_net_util.h"

#include "../configure/configure.h"

#include <dirent.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h> /* getenv */
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/capability.h>
#include <linux/unistd.h>

#include "../../../../util/tile/fd_tile_private.h"

extern fd_topo_obj_callbacks_t * CALLBACKS[];

#define NAME "run"

void
run_cmd_perm( args_t *         args,
              fd_cap_chk_t *   chk,
              config_t const * config ) {
  (void)args;

  ulong mlock_limit = fd_topo_mlock_max_tile( &config->topo );

  fd_cap_chk_raise_rlimit( chk, NAME, RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );
  fd_cap_chk_raise_rlimit( chk, NAME, RLIMIT_NICE,    40,          "call `setpriority(2)` to increase thread priorities" );
  fd_cap_chk_raise_rlimit( chk, NAME, RLIMIT_NOFILE,  CONFIGURE_NR_OPEN_FILES,
                                                                       "call `rlimit(2)  to increase `RLIMIT_NOFILE` to allow more open files for Agave" );
  fd_cap_chk_cap(          chk, NAME, CAP_NET_RAW,                 "call `socket(2)` to bind to a raw socket for use by XDP" );
  fd_cap_chk_cap(          chk, NAME, CAP_SYS_ADMIN,               "call `bpf(2)` with the `BPF_OBJ_GET` command to initialize XDP" );
  if( fd_sandbox_requires_cap_sys_admin( config->uid, config->gid ) )
    fd_cap_chk_cap(        chk, NAME, CAP_SYS_ADMIN,               "call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_cap_chk_cap(        chk, NAME, CAP_SETUID,                  "call `setresuid(2)` to switch uid to the sandbox user" );
  if( FD_LIKELY( getgid()!=config->gid ) )
    fd_cap_chk_cap(        chk, NAME, CAP_SETGID,                  "call `setresgid(2)` to switch gid to the sandbox user" );
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    fd_cap_chk_cap(        chk, NAME, CAP_SYS_ADMIN,               "call `setns(2)` to enter a network namespace" );
  if( FD_UNLIKELY( config->tiles.metric.prometheus_listen_port<1024 ) )
    fd_cap_chk_cap(        chk, NAME, CAP_NET_BIND_SERVICE,        "call `bind(2)` to bind to a privileged port for serving metrics" );
  if( FD_UNLIKELY( config->tiles.gui.gui_listen_port<1024 ) )
    fd_cap_chk_cap(        chk, NAME, CAP_NET_BIND_SERVICE,        "call `bind(2)` to bind to a privileged port for serving the GUI" );
}

struct pidns_clone_args {
  config_t const * config;
  int *            pipefd;
  int              closefd;
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

  if( FD_LIKELY( sig==SIGINT ) ) fd_sys_util_exit_group( 128+SIGINT );
  else                           fd_sys_util_exit_group( 0          );
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

  sa.sa_handler = SIG_IGN;
  if( FD_UNLIKELY( sigaction( SIGUSR1, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGUSR1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGUSR2, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGUSR2) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void *
create_clone_stack( void ) {
  ulong mmap_sz = FD_TILE_PRIVATE_STACK_SZ + 2UL*FD_SHMEM_NORMAL_PAGE_SZ;
  uchar * stack = (uchar *)mmap( NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, (off_t)0 );
  if( FD_UNLIKELY( stack==MAP_FAILED ) )
    FD_LOG_ERR(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Make space for guard lo and guard hi */
  if( FD_UNLIKELY( munmap( stack, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
    FD_LOG_ERR(( "munmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  stack += FD_SHMEM_NORMAL_PAGE_SZ;
  if( FD_UNLIKELY( munmap( stack + FD_TILE_PRIVATE_STACK_SZ, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
    FD_LOG_ERR(( "munmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Create the guard regions in the extra space */
  void * guard_lo = (void *)(stack - FD_SHMEM_NORMAL_PAGE_SZ );
  if( FD_UNLIKELY( mmap( guard_lo, FD_SHMEM_NORMAL_PAGE_SZ, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, (off_t)0 )!=guard_lo ) )
    FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  void * guard_hi = (void *)(stack + FD_TILE_PRIVATE_STACK_SZ);
  if( FD_UNLIKELY( mmap( guard_hi, FD_SHMEM_NORMAL_PAGE_SZ, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, (off_t)0 )!=guard_hi ) )
    FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return stack;
}


static int
execve_agave( int config_memfd,
                    int pipefd ) {
  if( FD_UNLIKELY( -1==fcntl( pipefd, F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  pid_t child = fork();
  if( FD_UNLIKELY( -1==child ) ) FD_LOG_ERR(( "fork() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !child ) ) {
    char _current_executable_path[ PATH_MAX ];
    FD_TEST( -1!=fd_file_util_self_exe( _current_executable_path ) );

    char config_fd[ 32 ];
    FD_TEST( fd_cstr_printf_check( config_fd, sizeof( config_fd ), NULL, "%d", config_memfd ) );
    char * args[ 5 ] = { _current_executable_path, "run-agave", "--config-fd", config_fd, NULL };

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
execve_tile( fd_topo_tile_t const * tile,
             fd_cpuset_t const *    floating_cpu_set,
             int                    floating_priority,
             int                    config_memfd,
             int                    pipefd ) {
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
    FD_TEST( -1!=fd_file_util_self_exe( _current_executable_path ) );

    char kind_id[ 32 ], config_fd[ 32 ], pipe_fd[ 32 ];
    FD_TEST( fd_cstr_printf_check( kind_id,   sizeof( kind_id ),   NULL, "%lu", tile->kind_id ) );
    FD_TEST( fd_cstr_printf_check( config_fd, sizeof( config_fd ), NULL, "%d",  config_memfd ) );
    FD_TEST( fd_cstr_printf_check( pipe_fd,   sizeof( pipe_fd ),   NULL, "%d",  pipefd ) );
    char const * args[ 9 ] = { _current_executable_path, "run1", tile->name, kind_id, "--pipe-fd", pipe_fd, "--config-fd", config_fd, NULL };
    if( FD_UNLIKELY( -1==execve( _current_executable_path, (char **)args, NULL ) ) ) FD_LOG_ERR(( "execve() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
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

  config_t const * config = args->config;

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

  int config_memfd = fd_config_to_memfd( config );
  if( FD_UNLIKELY( -1==config_memfd ) ) FD_LOG_ERR(( "fd_config_to_memfd() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( config->development.debug_tile ) ) {
    fd_log_private_shared_lock[1] = 1;
  }

  ulong child_cnt = 0UL;
  if( FD_LIKELY( !config->is_firedancer && !config->development.no_agave ) ) {
    int pipefd[ 2 ];
    if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    fds[ child_cnt ] = (struct pollfd){ .fd = pipefd[ 0 ], .events = 0 };
    child_pids[ child_cnt ] = execve_agave( config_memfd, pipefd[ 1 ] );
    if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    strncpy( child_names[ child_cnt ], "agave", 32 );
    child_cnt++;
  }

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    if( FD_UNLIKELY( -1==fd_net_util_netns_enter( config->net.interface, NULL ) ) )
      FD_LOG_ERR(( "failed to enter network namespace `%s` (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));
  }

  errno = 0;
  int save_priority = getpriority( PRIO_PROCESS, 0 );
  if( FD_UNLIKELY( -1==save_priority && errno ) ) FD_LOG_ERR(( "getpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int need_xdp = 0==strcmp( config->net.provider, "xdp" );
  fd_xdp_fds_t xdp_fds = {0};
  if( need_xdp ) {
    xdp_fds = fd_topo_install_xdp( &config->topo, config->net.bind_address_parsed );
  }

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &config->topo.tiles[ i ];
    if( FD_UNLIKELY( tile->is_agave ) ) continue;

    if( need_xdp ) {
      if( FD_UNLIKELY( strcmp( tile->name, "net" ) ) ) {
        /* close XDP related file descriptors */
        if( FD_UNLIKELY( -1==fcntl( xdp_fds.xsk_map_fd,   F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        if( FD_UNLIKELY( -1==fcntl( xdp_fds.prog_link_fd, F_SETFD, FD_CLOEXEC ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,FD_CLOEXEC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      } else {
        if( FD_UNLIKELY( -1==fcntl( xdp_fds.xsk_map_fd,   F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        if( FD_UNLIKELY( -1==fcntl( xdp_fds.prog_link_fd, F_SETFD, 0 ) ) ) FD_LOG_ERR(( "fcntl(F_SETFD,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
    }

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
  if( need_xdp ) {
    if( FD_UNLIKELY( close( xdp_fds.xsk_map_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( close( xdp_fds.prog_link_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int allow_fds[ 4+FD_TOPO_MAX_TILES ];
  ulong allow_fds_cnt = 0;
  allow_fds[ allow_fds_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( fd_log_private_logfile_fd()!=-1 ) )
    allow_fds[ allow_fds_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  allow_fds[ allow_fds_cnt++ ] = args->pipefd[ 1 ]; /* write end of main pipe */
  for( ulong i=0; i<child_cnt; i++ )
    allow_fds[ allow_fds_cnt++ ] = fds[ i ].fd; /* read end of child pipes */

  struct sock_filter seccomp_filter[ 128UL ];
  unsigned int instr_cnt;
  #if defined(__aarch64__)
  populate_sock_filter_policy_pidns_arm64( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd() );
  instr_cnt = sock_filter_policy_pidns_arm64_instr_cnt;
  #else
  populate_sock_filter_policy_pidns( 128UL, seccomp_filter, (uint)fd_log_private_logfile_fd() );
  instr_cnt = sock_filter_policy_pidns_instr_cnt;
  #endif

  if( FD_LIKELY( config->development.sandbox ) ) {
    fd_sandbox_enter( config->uid,
                      config->gid,
                      0,
                      0,
                      0,
                      0,
                      1UL+child_cnt, /* RLIMIT_NOFILE needs to be set to the nfds argument of poll() */
                      0UL,
                      0UL,
                      allow_fds_cnt,
                      allow_fds,
                      instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }

  /* The supervsior process should not share the log lock, because a
     child process might die while holding it and we still need to
     reap and print errors. */
  int lock = 0;
  fd_log_private_shared_lock = &lock;

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
      fd_sys_util_exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
    }
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) {
      FD_LOG_ERR_NOEXIT(( "tile %lu (%s) exited while booting with code %d\n", i, child_names[ i ], WEXITSTATUS( wstatus ) ));
      fd_sys_util_exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
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

    for( ulong i=0UL; i<1UL+child_cnt; i++ ) {
      if( FD_UNLIKELY( fds[ i ].revents ) ) {
        /* Must have been POLLHUP, POLLERR and POLLNVAL are not possible. */
        if( FD_UNLIKELY( i==child_cnt ) ) {
          /* Parent process died, probably SIGINT, exit gracefully. */
          fd_sys_util_exit_group( 0 );
        }

        char * tile_name = child_names[ i ];
        ulong  tile_idx = 0UL;
        if( FD_LIKELY( i>0UL ) ) tile_idx = (!config->is_firedancer && config->development.no_agave) ? i : i-1UL;
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
          FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with signal %d (%s)", tile_name, tile_id, WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
          fd_sys_util_exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
        } else {
          int exit_code = WEXITSTATUS( wstatus );
          if( FD_LIKELY( !exit_code && config->topo.tiles[ tile_idx ].allow_shutdown ) ) {
            FD_LOG_INFO(( "tile %s:%lu exited gracefully with code %d", tile_name, tile_id, exit_code ));
          } else {
            FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with code %d", tile_name, tile_id, exit_code ));
            fd_sys_util_exit_group( exit_code ? exit_code : 1 );
          }
        }
      }
    }
  }
  return 0;
}

int
clone_firedancer( config_t const * config,
                  int              close_fd,
                  int *            out_pipe ) {
  /* This pipe is here just so that the child process knows when the
     parent has died (it will get a HUP). */
  int pipefd[2];
  if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC | O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* clone into a pid namespace */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  struct pidns_clone_args args = { .config = config, .closefd = close_fd, .pipefd = pipefd, };

  void * stack = create_clone_stack();

  int pid_namespace = clone( main_pid_namespace, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, flags, &args );
  if( FD_UNLIKELY( pid_namespace<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  *out_pipe = pipefd[ 0 ];
  return pid_namespace;
}

static void
workspace_path( config_t const *       config,
                fd_topo_wksp_t const * wksp,
                char                   out[ PATH_MAX ] ) {
  char const * mount_path;
  switch( wksp->page_sz ) {
    case FD_SHMEM_HUGE_PAGE_SZ:
      mount_path = config->hugetlbfs.huge_page_mount_path;
      break;
    case FD_SHMEM_GIGANTIC_PAGE_SZ:
      mount_path = config->hugetlbfs.gigantic_page_mount_path;
      break;
    case FD_SHMEM_NORMAL_PAGE_SZ:
      mount_path = config->hugetlbfs.normal_page_mount_path;
      break;
    default:
      FD_LOG_ERR(( "invalid page size %lu", wksp->page_sz ));
  }

  FD_TEST( fd_cstr_printf_check( out, PATH_MAX, NULL, "%s/%s_%s.wksp", mount_path, config->name, wksp->name ) );
}

static void
warn_unknown_files( config_t const * config,
                    ulong            mount_type ) {
  char const * mount_path;
  switch( mount_type ) {
    case 0UL:
      mount_path = config->hugetlbfs.huge_page_mount_path;
      break;
    case 1UL:
      mount_path = config->hugetlbfs.gigantic_page_mount_path;
      break;
    default:
      FD_LOG_ERR(( "invalid mount type %lu", mount_type ));
  }

  /* Check if there are any files in mount_path */
  DIR * dir = opendir( mount_path );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_UNLIKELY( errno!=ENOENT ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", mount_path, errno, fd_io_strerror( errno ) ));
    return;
  }

  struct dirent * entry;
  while(( FD_LIKELY( entry = readdir( dir ) ) )) {
    if( FD_UNLIKELY( !strcmp( entry->d_name, ".") || !strcmp( entry->d_name, ".." ) ) ) continue;

    char entry_path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( entry_path, PATH_MAX, NULL, "%s/%s", mount_path, entry->d_name ));

    int known_file = 0;
    for( ulong i=0UL; i<config->topo.wksp_cnt; i++ ) {
      fd_topo_wksp_t const * wksp = &config->topo.workspaces[ i ];
      if( !wksp->is_locked ) continue;

      char expected_path[ PATH_MAX ];
      workspace_path( config, wksp, expected_path );

      if( !strcmp( entry_path, expected_path ) ) {
        known_file = 1;
        break;
      }
    }

    if( mount_type==0UL ) {
      for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &config->topo.tiles [ i ];

        char expected_path[ PATH_MAX ];
        FD_TEST( fd_cstr_printf_check( expected_path, PATH_MAX, NULL, "%s/%s_stack_%s%lu", config->hugetlbfs.huge_page_mount_path, config->name, tile->name, tile->kind_id ) );

        if( !strcmp( entry_path, expected_path ) ) {
          known_file = 1;
          break;
        }
      }
    }

    if( FD_UNLIKELY( !known_file ) ) FD_LOG_WARNING(( "unknown file `%s` found in `%s`", entry->d_name, mount_path ));
  }

  if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "error closing `%s` (%i-%s)", mount_path, errno, fd_io_strerror( errno ) ));
}

void
initialize_workspaces( config_t * config ) {
  /* Switch to non-root uid/gid for workspace creation.  Permissions
     checks are still done as the current user. */
  uint gid = getgid();
  uint uid = getuid();
  if( FD_LIKELY( gid!=config->gid && -1==setegid( config->gid ) ) )
    FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( uid!=config->uid && -1==seteuid( config->uid ) ) )
    FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong i=0UL; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];

    char path[ PATH_MAX ];
    workspace_path( config, wksp, path );

    struct stat st;
    int result = stat( path, &st );

    int update_existing;
    if( FD_UNLIKELY( !result && config->is_live_cluster ) ) {
      if( FD_UNLIKELY( -1==unlink( path ) && errno!=ENOENT ) ) FD_LOG_ERR(( "unlink() failed when trying to create workspace `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
      update_existing = 0;
    } else if( FD_UNLIKELY( !result ) ) {
      /* Creating all of the workspaces is very expensive because the
         kernel has to zero out all of the pages.  There can be tens or
         hundreds of gigabytes of zeroing to do.

         What would be really nice is if the kernel let us create huge
         pages without zeroing them, but it's not possible.  The
         ftruncate and fallocate calls do not support this type of
         resize with the hugetlbfs filesystem.

         Instead.. to prevent repeatedly doing this zeroing every time
         we start the validator, we have a small hack here to re-use the
         workspace files if they exist. */
      update_existing = 1;
    } else if( FD_LIKELY( result && errno==ENOENT ) ) {
      update_existing = 0;
    } else {
      FD_LOG_ERR(( "stat failed when trying to create workspace `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( -1==fd_topo_create_workspace( &config->topo, wksp, update_existing ) ) ) {
      FD_TEST( errno==ENOMEM );

      warn_unknown_files( config, wksp->page_sz!=FD_SHMEM_HUGE_PAGE_SZ );

      char path[ PATH_MAX ];
      workspace_path( config, wksp, path );
      FD_LOG_ERR(( "ENOMEM-Out of memory when trying to create workspace `%s` at `%s` "
                   "with %lu %s pages. Firedancer reserves enough memory for all of its workspaces "
                   "during the `hugetlbfs` configure step, so it is likely you have unknown files "
                   "left over in this directory which are consuming memory, or another program on "
                   "the system is using pages from the same mount.",
                   wksp->name, path, wksp->page_cnt, fd_shmem_page_sz_to_cstr( wksp->page_sz ) ));
    }
    fd_topo_join_workspace( &config->topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topo_wksp_new( &config->topo, wksp, CALLBACKS );
    fd_topo_leave_workspace( &config->topo, wksp );
  }

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
initialize_stacks( config_t const * config ) {
# if FD_HAS_MSAN
  /* MSan calls an external symbolizer using fork() on crashes, which is
     incompatible with Firedancer's MAP_SHARED stacks. */
  (void)config;
  return;
# endif

  /* Switch to non-root uid/gid for workspace creation.  Permissions
     checks are still done as the current user. */
  uint gid = getgid();
  uint uid = getuid();
  if( FD_LIKELY( gid!=config->gid && -1==setegid( config->gid ) ) )
    FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( uid!=config->uid && -1==seteuid( config->uid ) ) )
    FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &config->topo.tiles[ i ];

    char path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "%s/%s_stack_%s%lu", config->hugetlbfs.huge_page_mount_path, config->name, tile->name, tile->kind_id ) );

    struct stat st;
    int result = stat( path, &st );

    int update_existing;
    if( FD_UNLIKELY( !result && config->is_live_cluster ) ) {
      if( FD_UNLIKELY( -1==unlink( path ) && errno!=ENOENT ) ) FD_LOG_ERR(( "unlink() failed when trying to create stack workspace `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
      update_existing = 0;
    } else if( FD_UNLIKELY( !result ) ) {
      /* See above note about zeroing out pages. */
      update_existing = 1;
    } else if( FD_LIKELY( result && errno==ENOENT ) ) {
      update_existing = 0;
    } else {
      FD_LOG_ERR(( "stat failed when trying to create workspace `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    }

    /* TODO: Use a better CPU idx for the stack if tile is floating */
    ulong stack_cpu_idx = 0UL;
    if( FD_LIKELY( tile->cpu_idx<65535UL ) ) stack_cpu_idx = tile->cpu_idx;

    char name[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_stack_%s%lu", config->name, tile->name, tile->kind_id ) );

    ulong sub_page_cnt[ 1 ] = { 6 };
    ulong sub_cpu_idx [ 1 ] = { stack_cpu_idx };
    int err;
    if( FD_UNLIKELY( update_existing ) ) {
      err = fd_shmem_update_multi( name, FD_SHMEM_HUGE_PAGE_SZ, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR ); /* logs details */
    } else {
      err = fd_shmem_create_multi( name, FD_SHMEM_HUGE_PAGE_SZ, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR ); /* logs details */
    }
    if( FD_UNLIKELY( err && errno==ENOMEM ) ) {
      warn_unknown_files( config, 0UL );

      char path[ PATH_MAX ];
      FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "%s/%s_stack_%s%lu", config->hugetlbfs.huge_page_mount_path, config->name, tile->name, tile->kind_id ) );
      FD_LOG_ERR(( "ENOMEM-Out of memory when trying to create huge page stack for tile `%s` at `%s`. "
                   "Firedancer reserves enough memory for all of its stacks during the `hugetlbfs` configure "
                   "step, so it is likely you have unknown files left over in this directory which are "
                   "consuming memory, or another program on the system is using pages from the same mount.",
                   tile->name, path ));
    } else if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_shmem_create_multi failed" ));
  }

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

extern configure_stage_t fd_cfg_stage_hugetlbfs;
extern configure_stage_t fd_cfg_stage_ethtool_channels;
extern configure_stage_t fd_cfg_stage_ethtool_gro;
extern configure_stage_t fd_cfg_stage_ethtool_loopback;
extern configure_stage_t fd_cfg_stage_sysctl;
extern configure_stage_t fd_cfg_stage_hyperthreads;

void
fdctl_check_configure( config_t const * config ) {
  configure_result_t check = fd_cfg_stage_hugetlbfs.check( config );
  if( FD_UNLIKELY( check.result!=CONFIGURE_OK ) )
    FD_LOG_ERR(( "Huge pages are not configured correctly: %s. You can run `fdctl configure init hugetlbfs` "
                 "to create the mounts correctly. This must be done after every system restart before running "
                 "Firedancer.", check.message ));

  if( FD_LIKELY( !config->development.netns.enabled && 0==strcmp( config->net.provider, "xdp" ) ) ) {
    check = fd_cfg_stage_ethtool_channels.check( config );
    if( FD_UNLIKELY( check.result!=CONFIGURE_OK ) )
      FD_LOG_ERR(( "Network %s. You can run `fdctl configure init ethtool-channels` to set the number of channels on the "
                  "network device correctly.", check.message ));

    check = fd_cfg_stage_ethtool_gro.check( config );
    if( FD_UNLIKELY( check.result!=CONFIGURE_OK ) )
      FD_LOG_ERR(( "Network %s. You can run `fdctl configure init ethtool-gro` to disable generic-receive-offload "
                  "as required.", check.message ));

    check = fd_cfg_stage_ethtool_loopback.check( config );
    if( FD_UNLIKELY( check.result!=CONFIGURE_OK ) )
      FD_LOG_ERR(( "Network %s. You can run `fdctl configure init ethtool-loopback` to disable tx-udp-segmentation "
                  "on the loopback device.", check.message ));
  }

  check = fd_cfg_stage_sysctl.check( config );
  if( FD_UNLIKELY( check.result!=CONFIGURE_OK ) )
    FD_LOG_ERR(( "Kernel parameters are not configured correctly: %s. You can run `fdctl configure init sysctl` "
                 "to set kernel parameters correctly.", check.message ));

  check = fd_cfg_stage_hyperthreads.check( config );
  if( FD_UNLIKELY( check.result!=CONFIGURE_OK ) )
    FD_LOG_ERR(( "Hyperthreading is not configured correctly: %s. You can run `fdctl configure init hyperthreads` "
                 "to configure hyperthreading correctly.", check.message ));
}

void
run_firedancer_init( config_t * config,
                     int        init_workspaces ) {
  struct stat st;
  int err = stat( config->paths.identity_key, &st );
  if( FD_UNLIKELY( -1==err && errno==ENOENT ) ) FD_LOG_ERR(( "[consensus.identity_path] key does not exist `%s`. You can generate an identity key at this path by running `fdctl keys new identity --config <toml>`", config->paths.identity_key ));
  else if( FD_UNLIKELY( -1==err ) )             FD_LOG_ERR(( "could not stat [consensus.identity_path] `%s` (%i-%s)", config->paths.identity_key, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( !config->is_firedancer ) ) {
    for( ulong i=0UL; i<config->frankendancer.paths.authorized_voter_paths_cnt; i++ ) {
      err = stat( config->frankendancer.paths.authorized_voter_paths[ i ], &st );
      if( FD_UNLIKELY( -1==err && errno==ENOENT ) ) FD_LOG_ERR(( "[consensus.authorized_voter_paths] key does not exist `%s`", config->frankendancer.paths.authorized_voter_paths[ i ] ));
      else if( FD_UNLIKELY( -1==err ) )             FD_LOG_ERR(( "could not stat [consensus.authorized_voter_paths] `%s` (%i-%s)", config->frankendancer.paths.authorized_voter_paths[ i ], errno, fd_io_strerror( errno ) ));
    }
  }

  fdctl_check_configure( config );
  if( FD_LIKELY( init_workspaces ) ) initialize_workspaces( config );
  initialize_stacks( config );
}

void
fdctl_setup_netns( config_t * config,
                   int        stay ) {
  if( !config->development.netns.enabled ) return;

  int original_netns_;
  int * original_netns = stay ? NULL : &original_netns_;
  if( FD_UNLIKELY( -1==fd_net_util_netns_enter( config->net.interface, original_netns ) ) )
    FD_LOG_ERR(( "failed to enter network namespace `%s` (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));

  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    fd_cfg_stage_ethtool_channels.init( config );
    fd_cfg_stage_ethtool_gro     .init( config );
    fd_cfg_stage_ethtool_loopback.init( config );
  }

  if( FD_UNLIKELY( original_netns && -1==fd_net_util_netns_restore( original_netns_ ) ) )
    FD_LOG_ERR(( "failed to restore network namespace (fd=%d) (%i-%s)", original_netns_, errno, fd_io_strerror( errno ) ));
}

/* The boot sequence is a little bit involved...

   A process tree is created that looks like,

   + main
   +-- pidns
       +-- agave
       +-- tile 0
       +-- tile 1
       ...

   What we want is that if any process in the tree dies, all other
   processes will also die.  This is done as follows,

    (a) pidns is the init process of a PID namespace, so if it dies the
        kernel will terminate the child processes.

    (b) main is the parent of pidns, so it can issue a waitpid() on the
        child PID, and when it completes terminate itself.

    (c) pidns is the parent of agave and the tiles, so it could
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
run_firedancer( config_t * config,
                int        parent_pipefd,
                int        init_workspaces ) {
  /* dump the topology we are using to the output log */
  fd_topo_print_log( 0, &config->topo );

  run_firedancer_init( config, init_workspaces );

#if defined(__x86_64__) || defined(__aarch64__)

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
                      0,
                      0,
                      1, /* Keep controlling terminal for main so it can receive Ctrl+C */
                      0,
                      0UL,
                      0UL,
                      0UL,
                      allow_fds_cnt,
                      allow_fds,
                      sock_filter_policy_main_instr_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( config->uid, config->gid );
  }

  /* The supervsior process should not share the log lock, because a
     child process might die while holding it and we still need to
     reap and print errors. */
  int lock = 0;
  fd_log_private_shared_lock = &lock;

  /* the only clean way to exit is SIGINT or SIGTERM on this parent process,
     so if wait4() completes, it must be an error */
  int wstatus;
  if( FD_UNLIKELY( -1==wait4( pid_namespace, &wstatus, (int)__WALL, NULL ) ) )
    FD_LOG_ERR(( "main wait4() failed (%i-%s)\nLog at \"%s\"", errno, fd_io_strerror( errno ), fd_log_private_path ));

  if( FD_UNLIKELY( WIFSIGNALED( wstatus ) ) ) fd_sys_util_exit_group( WTERMSIG( wstatus ) ? WTERMSIG( wstatus ) : 1 );
  else fd_sys_util_exit_group( WEXITSTATUS( wstatus ) ? WEXITSTATUS( wstatus ) : 1 );
}

void
run_cmd_fn( args_t *   args FD_PARAM_UNUSED,
            config_t * config ) {
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

  run_firedancer( config, -1, 1 );
}

action_t fd_action_run1 = {
  .name        = "run1",
  .args        = run1_cmd_args,
  .fn          = run1_cmd_fn,
  .perm        = NULL,
  .description = "Start up a single Firedancer tile"
};

action_t fd_action_run = {
  .name           = "run",
  .args           = NULL,
  .fn             = run_cmd_fn,
  .require_config = 1,
  .perm           = run_cmd_perm,
  .description    = "Start up a Firedancer validator",
  .permission_err = "insufficient permissions to execute command `%s`. It is recommended "
                    "to start Firedancer as the root user, but you can also start it "
                    "with the missing capabilities listed above. The program only needs "
                    "to start with elevated permissions to do privileged operations at "
                    "boot, and will immediately drop permissions and switch to the user "
                    "specified in your configuration file once they are complete. Firedancer "
                    "will not execute outside of the boot process as root, and will refuse "
                    "to start if it cannot drop privileges. Firedancer needs to be started "
                    "privileged to configure high performance networking with XDP.",
};
