#define _GNU_SOURCE
#include "run.h"

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

extern int fd_log_private_fileno;

int
tile_main( void * _args ) {
  tile_main_args_t * args = _args;
  fd_topo_tile_t * tile = args->tile;

  fd_log_private_group_id_set( (ulong)getpid1() ); /* Need to read /proc again.. we got a new PID from clone */
  FD_LOG_NOTICE(( "booting tile %s:%lu pid:%lu", fd_topo_tile_kind_str( tile->kind ), tile->kind_id, fd_log_group_id() ));

  /* calling fd_tempo_tick_per_ns requires nanosleep, it is cached with
     a FD_ONCE.  We do this for all tiles before sandboxing so that we
     don't need to allow the nanosleep syscall. */
  fd_tempo_tick_per_ns( NULL );

  /* preload shared memory before sandboxing, so it is already mapped */
  fd_topo_join_tile_workspaces( args->config->name,
                                &args->config->topo,
                                tile );

  fd_tile_config_t * config = fd_topo_tile_to_config( tile );

  void * scratch_mem   = NULL;
  if( FD_LIKELY( config->scratch_align ) ) {
    scratch_mem = (uchar*)args->config->topo.workspaces[ tile->wksp_id ].wksp + tile->user_mem_offset;
    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch_mem, config->scratch_align() ) ) )
      FD_LOG_ERR(( "scratch_mem is not aligned to %lu", config->scratch_align() ));
  }

  if( FD_UNLIKELY( config->privileged_init ) )
    config->privileged_init( &args->config->topo, tile, scratch_mem );

  if( FD_UNLIKELY( fd_log_private_fileno!=4 ) ) FD_LOG_ERR(( "unexpected fd %d for logfile", fd_log_private_fileno ));
  ulong allow_fds_offset = 0UL;
  int allow_fds[ 32 ] = { 0 };
  if( FD_LIKELY( -1!=args->pipefd ) ) {
    allow_fds_offset = 1UL;
    allow_fds[ 0 ] = args->pipefd;
  }
  ulong allow_fds_cnt = config->populate_allowed_fds( scratch_mem,
                                                      (sizeof(allow_fds)/sizeof(allow_fds[ 0 ]))-allow_fds_offset,
                                                      allow_fds+allow_fds_offset );

  struct sock_filter seccomp_filter[ 128UL ];
  ulong seccomp_filter_cnt = config->populate_allowed_seccomp( scratch_mem,
                                                               sizeof(seccomp_filter)/sizeof(seccomp_filter[ 0 ]),
                                                               seccomp_filter );

  fd_sandbox( args->config->development.sandbox,
              args->config->uid,
              args->config->gid,
              0UL,
              allow_fds_cnt+allow_fds_offset,
              allow_fds,
              seccomp_filter_cnt,
              seccomp_filter );

  /* Now we are sandboxed, join all the tango IPC objects in the workspaces */
  fd_topo_fill_tile( &args->config->topo, tile, FD_TOPO_FILL_MODE_JOIN );
  FD_TEST( tile->cnc );

  if( FD_UNLIKELY( config->unprivileged_init ) )
    config->unprivileged_init( &args->config->topo, tile, scratch_mem );

  const fd_frag_meta_t * in_mcache[ FD_TOPO_MAX_LINKS ];
  ulong * in_fseq[ FD_TOPO_MAX_TILE_IN_LINKS ];

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    in_mcache[ i ] = args->config->topo.links[ tile->in_link_id[ i ] ].mcache;
    FD_TEST( in_mcache[ i ] );
    in_fseq[ i ]   = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ i ] );
  }

  ulong out_cnt_reliable = 0;
  ulong * out_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0; i<args->config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &args->config->topo.tiles[ i ];
    for( ulong j=0; j<tile->in_cnt; j++ ) {
      if( FD_UNLIKELY( tile->in_link_id[ j ] == tile->out_link_id_primary && tile->in_link_reliable[ j ] ) ) {
        out_fseq[ out_cnt_reliable ] = tile->in_link_fseq[ j ];
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
    .cnc_diag_write      = config->mux_cnc_diag_write,
    .cnc_diag_clear      = config->mux_cnc_diag_clear,
  };

  void * ctx = NULL;
  if( FD_LIKELY( config->mux_ctx ) ) ctx = config->mux_ctx( scratch_mem );

  fd_rng_t rng[1];
  fd_mux_tile( tile->cnc,
               config->mux_flags,
               tile->in_cnt,
               in_mcache,
               in_fseq,
               tile->out_link_id_primary == ULONG_MAX ? NULL : args->config->topo.links[ tile->out_link_id_primary ].mcache,
               out_cnt_reliable,
               out_fseq,
               config->burst,
               0,
               0,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( tile->in_cnt, out_cnt_reliable ) ),
               ctx,
               &callbacks );

  return 0;
}

extern int fd_log_private_shared_memfd;

void
run1_cmd_fn( args_t *         args,
             config_t * const config ) {
  ulong tile_id = fd_topo_find_tile( &config->topo, args->run1.tile_kind, args->run1.kind_id );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu not found", fd_topo_tile_kind_str( args->run1.tile_kind ), args->run1.kind_id ));
  fd_topo_tile_t * tile = &config->topo.tiles[ tile_id ];

  if( FD_UNLIKELY( close( fd_log_private_shared_memfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_log_private_tid_set( tile->id );
  fd_log_thread_set( fd_topo_tile_kind_str( tile->kind ) );
  fd_log_private_group_id_set( (ulong)getpid1() ); /* Need to read /proc since we are in a PID namespace now */

  cpu_set_t affinity[1];
  if( FD_UNLIKELY( -1==sched_getaffinity( 0, sizeof( affinity ), affinity ) ) ) FD_LOG_ERR(( "sched_getaffinity() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  ulong cpu_idx = ULONG_MAX;
  for( ulong i=0; i<CPU_SETSIZE; i++ ) {
    if( FD_LIKELY( CPU_ISSET( i, affinity ) ) ) {
      cpu_idx = i;
      break;
    }
  }

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
  };

  /* Also clone tiles into PID namespaces so they cannot signal each
     other or the parent. */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t clone_pid = clone( tile_main, (uchar *)stack + (8UL<<20), flags, &clone_args );
  if( FD_UNLIKELY( clone_pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
