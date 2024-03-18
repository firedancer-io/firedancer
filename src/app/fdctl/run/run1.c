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
  strncpy( args->run1.tile_name, **pargv, sizeof( args->run1.tile_name ) - 1 );

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

typedef struct {
  config_t *       config;
  fd_topo_tile_t * tile;
  int              pipefd;
} tile_main_args_t;

static int
tile_main( void * _args ) {
  tile_main_args_t * args = (tile_main_args_t *)_args;

  volatile int * wait = NULL;
  volatile int * debug = NULL;
  if( FD_UNLIKELY( args->config->development.debug_tile ) ) {
    if( FD_UNLIKELY( args->tile->id==args->config->development.debug_tile-1 ) ) *debug = fd_log_private_shared_lock[1];
    else *wait = fd_log_private_shared_lock[1];
  }

  fd_topo_run_tile_t run_tile = fdctl_tile_run( args->tile );
  fd_topo_run_tile( &args->config->topo, args->tile, args->config->development.sandbox, args->config->uid, args->config->gid, args->pipefd, wait, debug, &run_tile );
  return 0;
}

void
run1_cmd_fn( args_t *         args,
             config_t * const config ) {
  ulong pid = fd_sandbox_getpid(); /* Need to read /proc again.. we got a new PID from clone */
  fd_log_private_tid_set( pid );

  ulong tile_id = fd_topo_find_tile( &config->topo, args->run1.tile_name, args->run1.kind_id );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu not found", args->run1.tile_name, args->run1.kind_id ));
  fd_topo_tile_t * tile = &config->topo.tiles[ tile_id ];

  char thread_name[ FD_LOG_NAME_MAX ] = {0};
  FD_TEST( fd_cstr_printf_check( thread_name, FD_LOG_NAME_MAX-1UL, NULL, "%s:%lu", tile->name, tile->kind_id ) );
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
  };

  /* Also clone tiles into PID namespaces so they cannot signal each
     other or the parent. */
  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t clone_pid = clone( tile_main, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, flags, &clone_args );
  if( FD_UNLIKELY( clone_pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
