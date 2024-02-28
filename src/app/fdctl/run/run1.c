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

  args->run1.tile_name = **pargv;

  (*pargc)--;
  (*pargv)++;

  char * endptr;
  ulong kind_id = strtoul( **pargv, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!='\0' || kind_id==ULONG_MAX ) ) FD_LOG_ERR(( "invalid tile-id provided `%s`", **pargv ));
  args->run1.tidx = kind_id;

  (*pargc)--;
  (*pargv)++;
}

typedef struct {
  fd_topo_tile_t * tile;
  int              pipefd;
  int              sandbox;
  uint             uid;
  uint             gid;
} clone_args_t;

static int
run1_main( void * _args ) {
  clone_args_t const * args = _args;
  fd_topo_run_tile( args->tile, args->sandbox, args->uid, args->gid, args->pipefd, NULL );
  return 0;
}

void
run1_cmd_fn( args_t *         args,
             config_t * const config ) {
  ulong pid = (ulong)fd_sandbox_getpid(); /* Need to read /proc again.. we got a new PID from clone */
  fd_log_private_tid_set( pid );

  fd_topo_t topo[ 1 ];
  fd_topo_new( topo, config->pod );

  fd_topo_tile_t * tile = NULL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * _tile = topo->tiles[ i ];
    if( FD_UNLIKELY( strcmp( _tile->name, args->run1.tile_name ) || _tile->tidx ) ) continue;
    tile = _tile;
    break;
  }

  if( FD_UNLIKELY( !tile ) ) FD_LOG_ERR(( "tile %s:%lu not found", args->run1.tile_name, args->run1.tidx ));

  char thread_name[ 20UL ];
  FD_TEST( fd_cstr_printf_check( thread_name, sizeof( thread_name ), NULL, "%s:%lu", tile->name, tile->tidx ) );
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

  clone_args_t clone_args = {
    .tile    = tile,
    .pipefd  = args->run1.pipe_fd,
    .sandbox = config->development.sandbox,
    .uid     = config->uid,
    .gid     = config->gid,
  };

  /* Also clone tiles into PID namespaces so they cannot signal each
     other or the parent. */

  int flags = config->development.sandbox ? CLONE_NEWPID : 0;
  pid_t clone_pid = clone( run1_main, (uchar *)stack + FD_TILE_PRIVATE_STACK_SZ, flags, &clone_args );
  if( FD_UNLIKELY( clone_pid<0 ) ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}
