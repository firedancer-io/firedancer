#include "fd_tile.h"

static ulong fd_tile_private_id0; /* 0 outside boot/halt, init on boot */
static ulong fd_tile_private_id1; /* " */
static ulong fd_tile_private_cnt; /* " */

ulong fd_tile_id0( void ) { return fd_tile_private_id0; }
ulong fd_tile_id1( void ) { return fd_tile_private_id1; }
ulong fd_tile_cnt( void ) { return fd_tile_private_cnt; }

static ulong fd_tile_private_id;     /* 0 outside boot/halt, init on boot */
static ulong fd_tile_private_idx;    /* " */
/**/   ulong fd_tile_private_stack0; /* " */
/**/   ulong fd_tile_private_stack1; /* " */

ulong fd_tile_id ( void ) { return fd_tile_private_id;  }
ulong fd_tile_idx( void ) { return fd_tile_private_idx; }

ulong fd_tile_cpu_id( ulong tile_idx ) { return tile_idx ? ULONG_MAX : fd_log_cpu_id(); }

/* Dispatch side APIs ************************************************/

struct fd_tile_exec_private {
  int            done;
  int            argc;
  char **        argv;
  fd_tile_task_t task;
  ulong          idx;
};

fd_tile_exec_t *
fd_tile_exec_new( ulong          idx,
                  fd_tile_task_t task,
                  int            argc,
                  char **        argv ) {
  (void)task; (void)argc; (void)argv;
  FD_VOLATILE_CONST( idx ); /* Suppress compiler warnings */
  return NULL;
}

fd_tile_exec_t * fd_tile_exec( ulong tile_idx ) { FD_VOLATILE_CONST( tile_idx ); /* Suppress compiler warnings */ return NULL; }

/* These should arguably FD_LOG_CRIT.  As it stands, they'll probably
   seg fault because they are probably passed NULL pointers (which is
   what the threaded implementation would do).  FD_LOG_CRIT would also
   behave like a seg fault but probably in a more informative way. */

char const *
fd_tile_exec_delete( fd_tile_exec_t * exec,
                     int *            opt_ret ) {
  while( !FD_VOLATILE_CONST( exec->done ) ) FD_YIELD();
  (void)opt_ret;
  return "fd_tile_exec_delete with no matching successful new";
}

ulong          fd_tile_exec_idx ( fd_tile_exec_t const * exec ) { return exec->idx;  }
fd_tile_task_t fd_tile_exec_task( fd_tile_exec_t const * exec ) { return exec->task; }
int            fd_tile_exec_argc( fd_tile_exec_t const * exec ) { return exec->argc; }
char **        fd_tile_exec_argv( fd_tile_exec_t const * exec ) { return exec->argv; }

int fd_tile_exec_done( fd_tile_exec_t const * exec ) { return FD_VOLATILE_CONST( exec->done ); }

/* Boot/halt APIs ****************************************************/

void
fd_tile_private_boot( int *    pargc,
                      char *** pargv ) {
  FD_LOG_INFO(( "fd_tile: booting" ));
  
  /* We strip the command line so there are no unexpected differences
     downstream but don't actually do anything with the results */

  if( fd_env_strip_cmdline_cstr( pargc, pargv, "--tile-cpus", "FD_TILE_CPUS", NULL ) )
    FD_LOG_INFO(( "fd_tile: ignoring --tile-cpus (group not threaded)" ));

  fd_tile_private_id0 = fd_log_thread_id();
  fd_tile_private_id1 = fd_tile_private_id0 + 1UL;
  fd_tile_private_cnt = 1UL;

  ulong app_id = fd_log_app_id();
  FD_LOG_INFO(( "fd_tile: booting thread group %lu:%lu/%lu", app_id, fd_tile_private_id0, fd_tile_private_cnt ));

  FD_LOG_INFO(( "fd tile: booting tile %lu on cpu %lu:%lu", 0UL, fd_log_host_id(), fd_log_cpu_id() ));

  fd_tile_private_id  = fd_tile_private_id0;
  fd_tile_private_idx = 0UL;

  fd_log_private_stack_discover( fd_log_private_main_stack_sz(),
                                 &fd_tile_private_stack0, &fd_tile_private_stack1 ); /* logs details */
  if( FD_UNLIKELY( !fd_tile_private_stack0 ) )
    FD_LOG_WARNING(( "stack diagnostics not available on this tile; attempting to continue" ));

  FD_LOG_INFO(( "fd_tile: boot tile %lu success (thread %lu:%lu in thread group %lu:%lu/%lu)",
                fd_tile_private_idx, app_id, fd_tile_private_id, app_id, fd_tile_private_id0, fd_tile_private_cnt ));

  FD_LOG_INFO(( "fd_tile: boot success" ));
}

void
fd_tile_private_halt( void ) {
  FD_LOG_INFO(( "fd_tile: halting" ));

  FD_LOG_INFO(( "fd_tile: halting tile 0" ));

  fd_tile_private_stack1 = 0UL;
  fd_tile_private_stack0 = 0UL;
  fd_tile_private_idx    = 0UL;
  fd_tile_private_id     = 0UL;

  FD_LOG_INFO(( "fd tile: halt tile 0 success" ));

  fd_tile_private_cnt = 0UL;
  fd_tile_private_id1 = 0UL;
  fd_tile_private_id0 = 0UL;

  FD_LOG_INFO(( "fd_tile: halt success" ));
}

