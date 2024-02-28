#define _GNU_SOURCE

#include "fd_topo.h"
#include "fd_topo_pod_helper.h"

#include "../mux/fd_mux.h"
#include "../metrics/fd_metrics.h"
#include "../../util/tile/fd_tile_private.h"

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/resource.h>

static void
check_wait_debugger( fd_topo_tile_t const * tile,
                     int                    pid ) {
  (void)tile; (void)pid;
  /* fd_topo_edge_debug_t const * debug = (fd_topo_edge_debug_t const *)fd_topo_query_adj1( topo, &topo->app->base, FD_TOPO_EDGE_ID_DEBUG ).e;
  if( FD_UNLIKELY( debug ) ) {
    if( FD_UNLIKELY( debug->base.dst==run->base.dst ) ) {
      FD_LOG_WARNING(( "waiting for debugger to attach to runner %s pid:%d", run->thread_name, pid ));
      if( FD_UNLIKELY( -1==kill( getpid(), SIGSTOP ) ) )
        FD_LOG_ERR(( "kill(SIGSTOP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      *debug->wait = 0;
    } else {
      while( FD_LIKELY( *debug->wait ) ) FD_SPIN_PAUSE();
    }
  }*/
}

static void
initialize_logging( char const * thread_name, 
                    int          pid ) {
  fd_log_cpu_set( NULL );
  fd_log_private_tid_set( (ulong)pid );
  fd_log_thread_set( thread_name );
  fd_log_private_stack_discover( FD_TILE_PRIVATE_STACK_SZ,
                                 &fd_tile_private_stack0, &fd_tile_private_stack1 );
  FD_LOG_NOTICE(( "booting tile %s pid:%lu", thread_name, fd_log_group_id() ));
}

void
fd_topo_run_tile( fd_topo_tile_t *          tile,
                  int                       sandbox,
                  uint                      uid,
                  uint                      gid,
                  int                       allow_fd,
                  fd_topo_run_tile_args_t * args ) {
  int pid = fd_sandbox_getpid();
  check_wait_debugger( tile, pid );

  char thread_name[ 20 ];
  FD_TEST( fd_cstr_printf_check( thread_name, sizeof( thread_name ), NULL, "%s:%lu", tile->name, tile->tidx ) );
  initialize_logging( thread_name, pid );

  fd_topo_wksp_attach_tile( tile );
  ulong tile_mem_offset = fd_pod_queryf_ulong( tile->topo->pod, ULONG_MAX, "tile.%s.offset", tile->name );
  FD_TEST( tile_mem_offset!=ULONG_MAX );
  void * tile_mem = (void*)((ulong)tile->wksp->wksp + tile_mem_offset);

  char id[ 20UL ];
  FD_TEST( fd_cstr_printf_check( id, sizeof( id ), NULL, "tile.%lu", tile->idx ) );
  if( FD_UNLIKELY( args->join_privileged ) ) args->join_privileged( tile_mem, tile->topo->pod, id );

  ulong allow_fds_offset = 0UL;
  int allow_fds[ 32 ] = { 0 };
  if( FD_LIKELY( -1!=allow_fd ) ) {
    allow_fds_offset = 1UL;
    allow_fds[ 0 ] = allow_fd;
  }
  ulong allow_fds_cnt = 0UL;
  if( FD_LIKELY( args->allowed_fds ) ) {
    allow_fds_cnt = args->allowed_fds( tile_mem,
                                       allow_fds+allow_fds_offset,
                                       (sizeof(allow_fds)/sizeof(allow_fds[ 0 ]))-allow_fds_offset );
  }


  struct sock_filter seccomp_filter[ 128UL ];
  ulong seccomp_filter_cnt = 0UL;
  if( FD_LIKELY( args->seccomp_policy ) ) {
    seccomp_filter_cnt = args->seccomp_policy( tile_mem,
                                               seccomp_filter,
                                               sizeof(seccomp_filter)/sizeof(seccomp_filter[ 0 ]) );
  }

  fd_sandbox( sandbox,
              uid,
              gid,
              args->rlimit_file_cnt,
              allow_fds_cnt+allow_fds_offset,
              allow_fds,
              seccomp_filter_cnt,
              seccomp_filter );

  /* Now we are sandboxed, join all objects in the workspaces. */

  fd_topo_wksp_join( tile->topo );

  /* Register the metrics thread local for the tile. */

  fd_metrics_register( tile->metrics );

  FD_MGAUGE_SET( TILE, PID, (ulong)pid );

  if( FD_UNLIKELY( args->join ) ) args->join( tile_mem, tile->topo->pod, id );

  const fd_frag_meta_t * in_mcache[ FD_TOPO_TILE_IN_MAX ];
  ulong * in_fseq[ FD_TOPO_TILE_IN_MAX ];

  ulong polled_in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_in_t const * link_in = tile->in[ i ];
    if( FD_UNLIKELY( !link_in->polled ) ) continue;

    in_mcache[ polled_in_cnt ] = link_in->link->mcache;
    in_fseq[ polled_in_cnt ]   = link_in->fseq;

    polled_in_cnt += 1;
  }

  ulong out_cnt_reliable = 0;
  ulong * out_fseq[ FD_TOPO_LINK_OUT_MAX ];
  fd_topo_link_t const * link = tile->primary_output;
  if( FD_LIKELY( link ) ) {
    for( ulong i=0UL; i<link->link_in_cnt; i++ ) {
      fd_topo_link_in_t const * link_in = link->link_ins[ i ];
      if( FD_UNLIKELY( !link_in->reliable ) ) continue;

      out_fseq[ out_cnt_reliable ] = link_in->fseq;
      out_cnt_reliable++;
    }
  }

  args->run( tile_mem,
             tile->cnc,
             polled_in_cnt,
             in_mcache,
             in_fseq,
             tile->primary_output->mcache,
             out_cnt_reliable,
             out_fseq );

  FD_LOG_ERR(( "tile run loop returned" ));
}

static void *
run_tile_thread_main( void * _tile ) {
  fd_topo_tile_t * tile = (fd_topo_tile_t *)_tile;
  fd_topo_run_tile( tile, 0, 0, 0, -1, NULL );
  return NULL;
}

static inline pthread_t
run_tile_thread( fd_topo_tile_t *    tile,
                 fd_cpuset_t const * floating_cpu_set,
                 int                 floating_priority ) {
  void * stack = fd_tile_private_stack_new( 1, tile->cpu_idx );

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

  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, cpu_set ) ) ) FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  pthread_t pthread;
  if( FD_UNLIKELY( pthread_create( &pthread, attr, run_tile_thread_main, tile ) ) ) FD_LOG_ERR(( "pthread_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char thread_name[ 20 ];
  FD_TEST( fd_cstr_printf_check( thread_name, sizeof( thread_name ), NULL, "%s:%lu", tile->name, tile->tidx ) );
  if( FD_UNLIKELY( pthread_setname_np( pthread, thread_name ) ) ) FD_LOG_ERR(( "pthread_setname_np() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return pthread;
}

ulong
fd_topo_run_single_process( uchar *     pod,
                            int         solana_labs,
                            uint        uid,
                            uint        gid,
                            pthread_t   out_threads[ static FD_TOPO_TILE_MAX ] ) {
  fd_topo_print( pod, 0 );

  /* Save the current affinity, it will be restored after creating any child tiles */
  FD_CPUSET_DECL( floating_cpu_set );
  if( FD_UNLIKELY( fd_cpuset_getaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_getaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  errno = 0;
  int save_priority = getpriority( PRIO_PROCESS, 0 );
  if( FD_UNLIKELY( -1==save_priority && errno ) ) FD_LOG_ERR(( "getpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_topo_t topo[ 1 ];
  fd_topo_new( topo, pod );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = topo->tiles[ i ];
    if( !solana_labs && tile->solana_labs ) continue;
    if( solana_labs==1 && !tile->solana_labs ) continue;

    out_threads[ i ] = run_tile_thread( tile, floating_cpu_set, save_priority );
  }

  fd_sandbox( 0, uid, gid, 0, 0, NULL, 0, NULL );

  if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, save_priority ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return topo->tile_cnt;
}
