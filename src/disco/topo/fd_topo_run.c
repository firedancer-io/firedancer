#define _GNU_SOURCE
#include "fd_topo.h"

#include "../metrics/fd_metrics.h"
#include "../../waltz/xdp/fd_xdp1.h"
#include "../../util/tile/fd_tile_private.h"
#include "../../util/shmem/fd_shmem_private.h"

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <net/if.h>

static void
initialize_logging( char const * tile_name,
                    ulong        tile_kind_id,
                    ulong        pid,
                    ulong        tid ) {
  fd_log_cpu_set( NULL );
  fd_log_private_tid_set( pid );
  char thread_name[ 20 ];
  FD_TEST( fd_cstr_printf_check( thread_name, sizeof( thread_name ), NULL, "%s:%lu", tile_name, tile_kind_id ) );
  fd_log_thread_set( thread_name );
  fd_log_private_stack_discover( FD_TILE_PRIVATE_STACK_SZ,
                                 &fd_tile_private_stack0, &fd_tile_private_stack1 );
  FD_LOG_NOTICE(( "booting tile %s pid:%lu tid:%lu", thread_name, fd_log_group_id(), tid ));
}

static void
check_wait_debugger( ulong          pid,
                     volatile int * wait,
                     volatile int * debugger ) {
  if( FD_UNLIKELY( debugger ) ) {
    FD_LOG_WARNING(( "waiting for debugger to attach to tile pid:%lu", pid ));
    if( FD_UNLIKELY( -1==kill( getpid(), SIGSTOP ) ) )
      FD_LOG_ERR(( "kill(SIGSTOP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    *FD_VOLATILE( debugger ) = 1;
  }

  if( FD_UNLIKELY( wait ) ) {
    while( FD_LIKELY( !*FD_VOLATILE( wait ) ) ) FD_SPIN_PAUSE();
  }
}

void
fd_topo_run_tile( fd_topo_t *          topo,
                  fd_topo_tile_t *     tile,
                  int                  sandbox,
                  int                  keep_controlling_terminal,
                  uint                 uid,
                  uint                 gid,
                  int                  allow_fd,
                  volatile int *       wait,
                  volatile int *       debugger,
                  fd_topo_run_tile_t * tile_run ) {
  char thread_name[ 20 ];
  FD_TEST( fd_cstr_printf_check( thread_name, sizeof( thread_name ), NULL, "%s:%lu", tile->name, tile->kind_id ) );
  if( FD_UNLIKELY( prctl( PR_SET_NAME, thread_name, 0, 0, 0 ) ) ) FD_LOG_ERR(( "prctl(PR_SET_NAME) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong pid = fd_sandbox_getpid(); /* Need to read /proc again.. we got a new PID from clone */
  ulong tid = fd_sandbox_gettid(); /* Need to read /proc again.. we got a new TID from clone */

  check_wait_debugger( pid, wait, debugger );
  initialize_logging( tile->name, tile->kind_id, pid, tid );

  /* preload shared memory before sandboxing, so it is already mapped */
  fd_topo_join_tile_workspaces( topo, tile );

  if( FD_UNLIKELY( tile_run->privileged_init ) )
    tile_run->privileged_init( topo, tile );

  ulong allow_fds_offset = 0UL;
  int allow_fds[ 256 ] = { 0 };
  if( FD_LIKELY( -1!=allow_fd ) ) {
    allow_fds_offset = 1UL;
    allow_fds[ 0 ] = allow_fd;
  }
  ulong allow_fds_cnt = 0UL;
  if( FD_LIKELY( tile_run->populate_allowed_fds ) ) {
    allow_fds_cnt = tile_run->populate_allowed_fds( topo,
                                                    tile,
                                                    (sizeof(allow_fds)/sizeof(allow_fds[ 0 ]))-allow_fds_offset,
                                                    allow_fds+allow_fds_offset );
  }


  struct sock_filter seccomp_filter[ 128UL ];
  ulong seccomp_filter_cnt = 0UL;
  if( FD_LIKELY( tile_run->populate_allowed_seccomp ) ) {
    seccomp_filter_cnt = tile_run->populate_allowed_seccomp( topo,
                                                             tile,
                                                             sizeof(seccomp_filter)/sizeof(seccomp_filter[ 0 ]),
                                                             seccomp_filter );
  }

  if( FD_LIKELY( sandbox ) ) {
    fd_sandbox_enter( uid,
                      gid,
                      tile_run->keep_host_networking,
                      keep_controlling_terminal,
                      tile_run->rlimit_file_cnt,
                      allow_fds_cnt+allow_fds_offset,
                      allow_fds,
                      seccomp_filter_cnt,
                      seccomp_filter );
  } else {
    fd_sandbox_switch_uid_gid( uid, gid );
  }

  /* Now we are sandboxed, join all the tango IPC objects in the workspaces */
  fd_topo_fill_tile( topo, tile );

  FD_TEST( tile->metrics );
  fd_metrics_register( tile->metrics );

  FD_MGAUGE_SET( TILE, PID, pid );
  FD_MGAUGE_SET( TILE, TID, tid );

  if( FD_UNLIKELY( tile_run->unprivileged_init ) )
    tile_run->unprivileged_init( topo, tile );

  tile_run->run( topo, tile );
  FD_LOG_ERR(( "tile run loop returned" ));
}

typedef struct {
  fd_topo_t *        topo;
  fd_topo_tile_t *   tile;
  fd_topo_run_tile_t tile_run;
  uint               uid;
  uint               gid;
  int *              done_futex;
  volatile int       copied;
} fd_topo_run_thread_args_t;

static void *
run_tile_thread_main( void * _args ) {
  fd_topo_run_thread_args_t args = *(fd_topo_run_thread_args_t *)_args;
  FD_COMPILER_MFENCE();
  ((fd_topo_run_thread_args_t *)_args)->copied = 1;

  fd_topo_run_tile( args.topo, args.tile, 0, 1, args.uid, args.gid, -1, NULL, NULL, &args.tile_run );
  if( FD_UNLIKELY( args.done_futex ) ) {
    for(;;) {
      if( FD_LIKELY( INT_MAX==FD_ATOMIC_CAS( args.done_futex, INT_MAX, (int)args.tile->id ) ) ) break;
      FD_SPIN_PAUSE();
    }
    if( FD_UNLIKELY( -1==syscall( SYS_futex, args.done_futex, FUTEX_WAKE, INT_MAX, NULL, NULL, 0 ) ) )
      FD_LOG_ERR(( "futex(FUTEX_WAKE) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    FD_LOG_ERR(( "fd_topo_run_tile() returned" ));
  }
  return NULL;
}

void *
fd_topo_tile_stack_join( char const * app_name,
                         char const * tile_name,
                         ulong        tile_kind_id ) {
  char name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_stack_%s%lu", app_name, tile_name, tile_kind_id ) );

  uchar * stack = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, NULL );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "fd_shmem_join failed" ));

  /* Make space for guard lo and guard hi */
  if( FD_UNLIKELY( fd_shmem_release( stack, FD_SHMEM_HUGE_PAGE_SZ, 1UL ) ) )
    FD_LOG_ERR(( "fd_shmem_release (%d-%s)", errno, fd_io_strerror( errno ) ));
  stack += FD_SHMEM_HUGE_PAGE_SZ;
  if( FD_UNLIKELY( fd_shmem_release( stack + FD_TILE_PRIVATE_STACK_SZ, FD_SHMEM_HUGE_PAGE_SZ, 1UL ) ) )
    FD_LOG_ERR(( "fd_shmem_release (%d-%s)", errno, fd_io_strerror( errno ) ));

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

fd_xdp_fds_t
fd_topo_install_xdp( fd_topo_t * topo ) {
  ulong net0_tile_idx = fd_topo_find_tile( topo, "net", 0UL );
  FD_TEST( net0_tile_idx!=ULONG_MAX );
  fd_topo_tile_t const * net0_tile = &topo->tiles[ net0_tile_idx ];

  ushort udp_port_candidates[] = { 
    (ushort)net0_tile->net.legacy_transaction_listen_port,
    (ushort)net0_tile->net.quic_transaction_listen_port,
    (ushort)net0_tile->net.shred_listen_port,
    (ushort)net0_tile->net.gossip_listen_port,
    (ushort)net0_tile->net.repair_intake_listen_port,
    (ushort)net0_tile->net.repair_serve_listen_port,
  };

  uint if_idx = if_nametoindex( net0_tile->net.interface );
  if( FD_UNLIKELY( !if_idx ) ) FD_LOG_ERR(( "if_nametoindex(%s) failed", net0_tile->net.interface ));

  fd_xdp_fds_t xdp_fds = fd_xdp_install( if_idx,
                                         net0_tile->net.src_ip_addr,
                                         sizeof(udp_port_candidates)/sizeof(udp_port_candidates[0]),
                                         udp_port_candidates,
                                         net0_tile->net.xdp_mode );
  if( FD_UNLIKELY( -1==dup2( xdp_fds.xsk_map_fd, 123462 ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( xdp_fds.xsk_map_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==dup2( xdp_fds.prog_link_fd, 123463 ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( xdp_fds.prog_link_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  xdp_fds.xsk_map_fd = 123462;
  xdp_fds.prog_link_fd = 123463;

  return xdp_fds;
}

static inline void
run_tile_thread( fd_topo_t *         topo,
                 fd_topo_tile_t *    tile,
                 fd_topo_run_tile_t  tile_run,
                 uint                uid,
                 uint                gid,
                 int *               done_futex,
                 fd_cpuset_t const * floating_cpu_set,
                 int                 floating_priority ) {
  /* tpool will assign a thread later */
  if( FD_UNLIKELY( tile_run.for_tpool ) ) return;
  void * stack = fd_topo_tile_stack_join( topo->app_name, tile->name, tile->kind_id );

  pthread_attr_t attr[ 1 ];
  if( FD_UNLIKELY( pthread_attr_init( attr ) ) ) FD_LOG_ERR(( "pthread_attr_init() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( pthread_attr_setstack( attr, stack, FD_TILE_PRIVATE_STACK_SZ ) ) ) FD_LOG_ERR(( "pthread_attr_setstacksize() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_CPUSET_DECL( cpu_set );
  if( FD_LIKELY( tile->cpu_idx<65535UL ) ) {
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

  fd_topo_run_thread_args_t args = {
    .topo       = topo,
    .tile       = tile,
    .tile_run   = tile_run,
    .uid        = uid,
    .gid        = gid,
    .done_futex = done_futex,
    .copied     = 0,
  };

  pthread_t pthread;
  if( FD_UNLIKELY( pthread_create( &pthread, attr, run_tile_thread_main, &args ) ) ) FD_LOG_ERR(( "pthread_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  while( !FD_VOLATILE( args.copied ) ) FD_SPIN_PAUSE();
}

void
fd_topo_run_single_process( fd_topo_t * topo,
                            int         agave,
                            uint        uid,
                            uint        gid,
                            fd_topo_run_tile_t (* tile_run )( fd_topo_tile_t * tile ),
                            int *       done_futex ) {
  /* Save the current affinity, it will be restored after creating any child tiles */
  FD_CPUSET_DECL( floating_cpu_set );
  if( FD_UNLIKELY( fd_cpuset_getaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_getaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  errno = 0;
  int save_priority = getpriority( PRIO_PROCESS, 0 );
  if( FD_UNLIKELY( -1==save_priority && errno ) ) FD_LOG_ERR(( "getpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( !agave && tile->is_agave ) continue;
    if( agave==1 && !tile->is_agave ) continue;

    fd_topo_run_tile_t run_tile = tile_run( tile );
    run_tile_thread( topo, tile, run_tile, uid, gid, done_futex, floating_cpu_set, save_priority );
  }

  fd_sandbox_switch_uid_gid( uid, gid );

  if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, save_priority ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
