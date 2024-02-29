#define _GNU_SOURCE
#include "run.h"

#include "../../../util/tile/fd_tile_private.h"
#include <sched.h>
#include <sys/wait.h>

#define NAME "run1"

void
run1_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args) {
  char * usage = "usage: run1 <tile-name> <kind-id>";
  if( FD_UNLIKELY( *pargc < 2 ) ) FD_LOG_ERR(( "%s", usage ));

  args->run1.pipe_fd  = fd_env_strip_cmdline_int( pargc, pargv, "--pipe-fd", NULL, -1 );

  ulong tile_kind = fd_topo_tile_kind_from_cstr( **pargv );
  if( FD_UNLIKELY( ULONG_MAX==tile_kind ) ) FD_LOG_ERR(( "unknown tile `%s`", **pargv ));
  args->run1.tile_kind = tile_kind;

  (*pargc)--;
  (*pargv)++;

  char * endptr;
  ulong kind_id = strtoul( **pargv, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!='\0' || kind_id==ULONG_MAX ) ) FD_LOG_ERR(( "invalid tile-id provided `%s`", **pargv ));
  args->run1.kind_id = kind_id;

  (*pargc)--;
  (*pargv)++;
}

extern int * fd_log_private_shared_lock;

int
tile_main( void * _args ) {
  tile_main_args_t * args = _args;
  fd_topo_tile_t * tile = args->tile;

  if( FD_UNLIKELY( args->config->development.debug_tile ) ) {
    if( FD_UNLIKELY( tile->id==args->config->development.debug_tile-1 ) ) {
      FD_LOG_WARNING(( "waiting for debugger to attach to tile %s:%lu pid:%d", fd_topo_tile_kind_str( tile->kind ), tile->kind_id, getpid1() ));
      if( FD_UNLIKELY( -1==kill( getpid(), SIGSTOP ) ) )
        FD_LOG_ERR(( "kill(SIGSTOP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      fd_log_private_shared_lock[1] = 0;
    } else {
      while( FD_LIKELY( fd_log_private_shared_lock[1] ) ) FD_SPIN_PAUSE();
    }
  }

  ulong pid = (ulong)getpid1(); /* Need to read /proc again.. we got a new PID from clone */
  fd_log_cpu_set( NULL );
  fd_log_private_tid_set( pid );
  char thread_name[ FD_LOG_NAME_MAX ] = {0};
  FD_TEST( fd_cstr_printf_check( thread_name, FD_LOG_NAME_MAX-1UL, NULL, "%s:%lu", fd_topo_tile_kind_str( tile->kind ), tile->kind_id ) );
  fd_log_thread_set( thread_name );
  fd_log_private_stack_discover( FD_TILE_PRIVATE_STACK_SZ,
                                 &fd_tile_private_stack0, &fd_tile_private_stack1 );
  FD_LOG_NOTICE(( "booting tile %s:%lu pid:%lu", fd_topo_tile_kind_str( tile->kind ), tile->kind_id, fd_log_group_id() ));

  /* preload shared memory before sandboxing, so it is already mapped */
  if( FD_LIKELY( !args->no_shmem ) ) {
    fd_topo_join_tile_workspaces( args->config->name,
                                  &args->config->topo,
                                  tile );
  }

  fd_tile_config_t * config = fd_topo_tile_to_config( tile );

  void * scratch_mem = NULL;
  if( FD_LIKELY( config->scratch_align ) ) {
    scratch_mem = (uchar*)args->config->topo.workspaces[ tile->wksp_id ].wksp + tile->user_mem_offset;
    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch_mem, config->scratch_align() ) ) )
      FD_LOG_ERR(( "scratch_mem is not aligned to %lu", config->scratch_align() ));
  }

  if( FD_UNLIKELY( config->privileged_init ) )
    config->privileged_init( &args->config->topo, tile, scratch_mem );

  ulong allow_fds_offset = 0UL;
  int allow_fds[ 32 ] = { 0 };
  if( FD_LIKELY( -1!=args->pipefd ) ) {
    allow_fds_offset = 1UL;
    allow_fds[ 0 ] = args->pipefd;
  }
  ulong allow_fds_cnt = 0UL;
  if( FD_LIKELY( config->populate_allowed_fds ) ) {
    allow_fds_cnt = config->populate_allowed_fds( scratch_mem,
                                                  (sizeof(allow_fds)/sizeof(allow_fds[ 0 ]))-allow_fds_offset,
                                                  allow_fds+allow_fds_offset );
  }


  struct sock_filter seccomp_filter[ 128UL ];
  ulong seccomp_filter_cnt = 0UL;
  if( FD_LIKELY( config->populate_allowed_seccomp ) ) {
    seccomp_filter_cnt = config->populate_allowed_seccomp( scratch_mem,
                                                           sizeof(seccomp_filter)/sizeof(seccomp_filter[ 0 ]),
                                                           seccomp_filter );
  }

  fd_sandbox( args->config->development.sandbox,
              args->config->uid,
              args->config->gid,
              config->rlimit_file_cnt,
              allow_fds_cnt+allow_fds_offset,
              allow_fds,
              seccomp_filter_cnt,
              seccomp_filter );

  /* Now we are sandboxed, join all the tango IPC objects in the workspaces */
  fd_topo_fill_tile( &args->config->topo, tile, FD_TOPO_FILL_MODE_JOIN, fdctl_tile_align, fdctl_tile_footprint );

  FD_TEST( tile->cnc );
  FD_TEST( tile->metrics );
  fd_metrics_register( tile->metrics );

  FD_MGAUGE_SET( TILE, PID, pid );

  if( FD_UNLIKELY( config->unprivileged_init ) )
    config->unprivileged_init( &args->config->topo, tile, scratch_mem );

  const fd_frag_meta_t * in_mcache[ FD_TOPO_MAX_LINKS ];
  ulong * in_fseq[ FD_TOPO_MAX_TILE_IN_LINKS ];

  ulong polled_in_cnt = 0UL;
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    in_mcache[ polled_in_cnt ] = args->config->topo.links[ tile->in_link_id[ i ] ].mcache;
    FD_TEST( in_mcache[ polled_in_cnt ] );
    in_fseq[ polled_in_cnt ]   = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ polled_in_cnt ] );
    polled_in_cnt += 1;
  }

  ulong out_cnt_reliable = 0;
  ulong * out_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0; i<args->config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &args->config->topo.tiles[ i ];
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
    .during_housekeeping = config->mux_during_housekeeping,
    .before_credit       = config->mux_before_credit,
    .after_credit        = config->mux_after_credit,
    .before_frag         = config->mux_before_frag,
    .during_frag         = config->mux_during_frag,
    .after_frag          = config->mux_after_frag,
    .metrics_write       = config->mux_metrics_write,
  };

  void * ctx = NULL;
  if( FD_LIKELY( config->mux_ctx ) ) ctx = config->mux_ctx( scratch_mem );

  long lazy = 0L;
  if( FD_UNLIKELY( config->lazy ) ) lazy = config->lazy( scratch_mem );

  fd_rng_t rng[1];
  fd_mux_tile( tile->cnc,
               config->mux_flags,
               polled_in_cnt,
               in_mcache,
               in_fseq,
               tile->out_link_id_primary == ULONG_MAX ? NULL : args->config->topo.links[ tile->out_link_id_primary ].mcache,
               out_cnt_reliable,
               out_fseq,
               config->burst,
               0,
               lazy,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( tile->in_cnt, out_cnt_reliable ) ),
               ctx,
               &callbacks );
  FD_LOG_ERR(( "tile run loop returned" ));
  return 0;
}

void
run1_cmd_fn( args_t *         args,
             config_t * const config ) {
  ulong pid = (ulong)getpid1(); /* Need to read /proc again.. we got a new PID from clone */
  fd_log_private_tid_set( pid );

  ulong tile_id = fd_topo_find_tile( &config->topo, args->run1.tile_kind, args->run1.kind_id );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu not found", fd_topo_tile_kind_str( args->run1.tile_kind ), args->run1.kind_id ));
  fd_topo_tile_t * tile = &config->topo.tiles[ tile_id ];

  char thread_name[ FD_LOG_NAME_MAX ] = {0};
  FD_TEST( fd_cstr_printf_check( thread_name, FD_LOG_NAME_MAX-1UL, NULL, "%s:%lu", fd_topo_tile_kind_str( tile->kind ), tile->kind_id ) );
  fd_log_thread_set( thread_name );

  if( FD_UNLIKELY( close( config->log.lock_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_CPUSET_DECL( affinity );
  if( FD_UNLIKELY( -1==fd_cpuset_getaffinity( 0, affinity ) ) )
    FD_LOG_ERR(( "fd_cpuset_getaffinity() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  ulong cpu_idx = fd_cpuset_first( affinity );
        cpu_idx = fd_ulong_if( cpu_idx<FD_TILE_MAX, cpu_idx, ULONG_MAX );

  if( FD_UNLIKELY( cpu_idx==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "unable to find a CPU to run on, using CPU 0" ));
    cpu_idx = 0UL;
  }

  void * stack = fd_tile_private_stack_new( 1, cpu_idx );
  if( FD_UNLIKELY( !stack ) ) FD_LOG_ERR(( "unable to create a stack for tile process" ));

  tile_main_args_t clone_args = {
    .config      = config,
    .tile        = tile,
    .pipefd      = args->run1.pipe_fd,
    .no_shmem    = 0,
  };

  /* Also clone tiles into PID namespaces so they cannot signal each
     other or the parent. */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t clone_pid = clone( tile_main, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, flags, &clone_args );
  if( FD_UNLIKELY( clone_pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
