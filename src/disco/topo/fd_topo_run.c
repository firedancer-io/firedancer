#define _GNU_SOURCE
#include "fd_topo.h"

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

static void
initialize_logging( char const * tile_name,
                    ulong        tile_kind_id,
                    ulong        pid ) {
  fd_log_cpu_set( NULL );
  fd_log_private_tid_set( pid );
  char thread_name[ 20 ];
  FD_TEST( fd_cstr_printf_check( thread_name, sizeof( thread_name ), NULL, "%s:%lu", tile_name, tile_kind_id ) );
  fd_log_thread_set( thread_name );
  fd_log_private_stack_discover( FD_TILE_PRIVATE_STACK_SZ,
                                 &fd_tile_private_stack0, &fd_tile_private_stack1 );
  FD_LOG_NOTICE(( "booting tile %s pid:%lu", thread_name, fd_log_group_id() ));
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
                  uint                 uid,
                  uint                 gid,
                  int                  allow_fd,
                  volatile int *       wait,
                  volatile int *       debugger,
                  fd_topo_run_tile_t * tile_run ) {
  ulong pid = fd_sandbox_getpid(); /* Need to read /proc again.. we got a new PID from clone */
  ulong tid = fd_sandbox_gettid(); /* Need to read /proc again.. we got a new TID from clone */

  check_wait_debugger( pid, wait, debugger );
  initialize_logging( tile->name, tile->kind_id, pid );

  /* preload shared memory before sandboxing, so it is already mapped */
  fd_topo_join_tile_workspaces( topo, tile );

  void * tile_mem = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile_run->privileged_init ) )
    tile_run->privileged_init( topo, tile, tile_mem );

  ulong allow_fds_offset = 0UL;
  int allow_fds[ 32 ] = { 0 };
  if( FD_LIKELY( -1!=allow_fd ) ) {
    allow_fds_offset = 1UL;
    allow_fds[ 0 ] = allow_fd;
  }
  ulong allow_fds_cnt = 0UL;
  if( FD_LIKELY( tile_run->populate_allowed_fds ) ) {
    allow_fds_cnt = tile_run->populate_allowed_fds( tile_mem,
                                                    (sizeof(allow_fds)/sizeof(allow_fds[ 0 ]))-allow_fds_offset,
                                                    allow_fds+allow_fds_offset );
  }


  struct sock_filter seccomp_filter[ 128UL ];
  ulong seccomp_filter_cnt = 0UL;
  if( FD_LIKELY( tile_run->populate_allowed_seccomp ) ) {
    seccomp_filter_cnt = tile_run->populate_allowed_seccomp( tile_mem,
                                                             sizeof(seccomp_filter)/sizeof(seccomp_filter[ 0 ]),
                                                             seccomp_filter );
  }

  fd_sandbox( sandbox,
              uid,
              gid,
              tile_run->rlimit_file_cnt,
              allow_fds_cnt+allow_fds_offset,
              allow_fds,
              seccomp_filter_cnt,
              seccomp_filter );

  /* Now we are sandboxed, join all the tango IPC objects in the workspaces */
  fd_topo_fill_tile( topo, tile );

  FD_TEST( tile->cnc );
  FD_TEST( tile->metrics );
  fd_metrics_register( tile->metrics );

  FD_MGAUGE_SET( TILE, PID, pid );
  FD_MGAUGE_SET( TILE, TID, tid );

  if( FD_UNLIKELY( tile_run->unprivileged_init ) )
    tile_run->unprivileged_init( topo, tile, tile_mem );

  const fd_frag_meta_t * in_mcache[ FD_TOPO_MAX_LINKS ];
  ulong * in_fseq[ FD_TOPO_MAX_TILE_IN_LINKS ];

  ulong polled_in_cnt = 0UL;
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    in_mcache[ polled_in_cnt ] = topo->links[ tile->in_link_id[ i ] ].mcache;
    FD_TEST( in_mcache[ polled_in_cnt ] );
    in_fseq[ polled_in_cnt ]   = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ polled_in_cnt ] );
    polled_in_cnt += 1;
  }

  ulong out_cnt_reliable = 0;
  ulong * out_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0; j<consumer_tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id_primary && consumer_tile->in_link_reliable[ j ] ) ) {
        out_fseq[ out_cnt_reliable ] = consumer_tile->in_link_fseq[ j ];
        FD_TEST( out_fseq[ out_cnt_reliable ] );
        out_cnt_reliable++;
        /* Need to test this, since each link may connect to many outs,
           you could construct a topology which has more than this
           consumers of links. */
        FD_TEST( out_cnt_reliable<FD_TOPO_MAX_LINKS );
      }
    }
  }

  fd_mux_callbacks_t callbacks = {
    .during_housekeeping = tile_run->mux_during_housekeeping,
    .before_credit       = tile_run->mux_before_credit,
    .after_credit        = tile_run->mux_after_credit,
    .before_frag         = tile_run->mux_before_frag,
    .during_frag         = tile_run->mux_during_frag,
    .after_frag          = tile_run->mux_after_frag,
    .metrics_write       = tile_run->mux_metrics_write,
  };

  void * ctx = NULL;
  if( FD_LIKELY( tile_run->mux_ctx ) ) ctx = tile_run->mux_ctx( tile_mem );

  long lazy = 0L;
  if( FD_UNLIKELY( tile_run->lazy ) ) lazy = tile_run->lazy( tile_mem );

  fd_rng_t rng[1];
  fd_mux_tile( tile->cnc,
               tile_run->mux_flags,
               polled_in_cnt,
               in_mcache,
               in_fseq,
               tile->out_link_id_primary == ULONG_MAX ? NULL : topo->links[ tile->out_link_id_primary ].mcache,
               out_cnt_reliable,
               out_fseq,
               tile_run->burst,
               0,
               lazy,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( polled_in_cnt, out_cnt_reliable ) ),
               ctx,
               &callbacks );
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

  char thread_name[ 20 ];
  FD_TEST( fd_cstr_printf_check( thread_name, sizeof( thread_name ), NULL, "%s:%lu", args.tile->name, args.tile->kind_id ) );
  if( FD_UNLIKELY( prctl( PR_SET_NAME, thread_name, 0, 0, 0 ) ) ) FD_LOG_ERR(( "prctl(PR_SET_NAME) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_topo_run_tile( args.topo, args.tile, 0, args.uid, args.gid, -1, NULL, NULL, &args.tile_run );
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
fd_topo_tile_stack_new( int          optimize,
                        char const * app_name,
                        char const * tile_name,
                        ulong        tile_kind_id,
                        ulong        cpu_idx ) {
  uchar * stack = NULL;

  if( FD_LIKELY( optimize ) ) {
    char name[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_stack_%s%lu.wksp", app_name, tile_name, tile_kind_id ) );

    ulong sub_page_cnt[ 1 ] = { 6 };
    ulong sub_cpu_idx [ 1 ] = { cpu_idx };
    int err = fd_shmem_create_multi( name, FD_SHMEM_HUGE_PAGE_SZ, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR ); /* logs details */
    if( FD_UNLIKELY( err && errno==ENOMEM ) ) {
      char mount_path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
      FD_TEST( fd_cstr_printf_check( mount_path, FD_SHMEM_PRIVATE_PATH_BUF_MAX, NULL, "%s/.%s", fd_shmem_private_base, fd_shmem_page_sz_to_cstr( FD_SHMEM_HUGE_PAGE_SZ ) ));
      FD_LOG_ERR(( "ENOMEM-Out of memory when trying to create workspace `%s` at `%s` "
                   "with %lu %s pages. Firedancer has successfully reserved enough memory "
                   "for all of its workspaces during the `hugetlbfs` configure step, so it is "
                   "likely you have unused files left over in this directory which are consuming "
                   "memory.",
                   name, mount_path, sub_page_cnt[ 0 ], fd_shmem_page_sz_to_cstr( FD_SHMEM_HUGE_PAGE_SZ ) ));
    }
    else if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_shmem_create_multi failed" ));

    stack = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, NULL );
    if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "fd_shmem_join failed" ));

    /* Make space for guard lo and guard hi */
    if( FD_UNLIKELY( fd_shmem_release( stack, FD_SHMEM_HUGE_PAGE_SZ, 1UL ) ) )
      FD_LOG_ERR(( "fd_shmem_release (%d-%s)", errno, fd_io_strerror( errno ) ));
    stack += FD_SHMEM_HUGE_PAGE_SZ;
    if( FD_UNLIKELY( fd_shmem_release( stack + FD_TILE_PRIVATE_STACK_SZ, FD_SHMEM_HUGE_PAGE_SZ, 1UL ) ) )
      FD_LOG_ERR(( "fd_shmem_release (%d-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    ulong mmap_sz = FD_TILE_PRIVATE_STACK_SZ + 2UL*FD_SHMEM_NORMAL_PAGE_SZ;
    stack = (uchar *)mmap( NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, (off_t)0 );
    if( FD_UNLIKELY( stack==MAP_FAILED ) )
      FD_LOG_ERR(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    /* Make space for guard lo and guard hi */
    if( FD_UNLIKELY( munmap( stack, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
      FD_LOG_WARNING(( "munmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    stack += FD_SHMEM_NORMAL_PAGE_SZ;

    if( FD_UNLIKELY( munmap( stack + FD_TILE_PRIVATE_STACK_SZ, FD_SHMEM_NORMAL_PAGE_SZ ) ) )
      FD_LOG_WARNING(( "munmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

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

static inline pthread_t
run_tile_thread( fd_topo_t *         topo,
                 fd_topo_tile_t *    tile,
                 fd_topo_run_tile_t  tile_run,
                 uint                uid,
                 uint                gid,
                 int *               done_futex,
                 fd_cpuset_t const * floating_cpu_set,
                 int                 floating_priority ) {
  /* TODO: Use a better CPU idx for the stack if tile is floating */
  ulong stack_cpu_idx = 0UL;
  if( FD_LIKELY( tile->cpu_idx<65535UL ) ) stack_cpu_idx = tile->cpu_idx;
  void * stack = fd_topo_tile_stack_new( 1, topo->app_name, tile->name, tile->kind_id, stack_cpu_idx );

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
  return pthread;
}

void
fd_topo_run_single_process( fd_topo_t * topo,
                            int         solana_labs,
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
    if( !solana_labs && tile->is_labs ) continue;
    if( solana_labs==1 && !tile->is_labs ) continue;

    fd_topo_run_tile_t run_tile = tile_run( tile );
    run_tile_thread( topo, tile, run_tile, uid, gid, done_futex, floating_cpu_set, save_priority );
  }

  fd_sandbox( 0, uid, gid, 0, 0, NULL, 0, NULL );

  if( FD_UNLIKELY( -1==setpriority( PRIO_PROCESS, 0, save_priority ) ) ) FD_LOG_ERR(( "setpriority() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fd_cpuset_setaffinity( 0, floating_cpu_set ) ) )
    FD_LOG_ERR(( "sched_setaffinity failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
