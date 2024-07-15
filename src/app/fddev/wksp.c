#define _GNU_SOURCE
#include "fddev.h"

void
initialize_workspaces( config_t * const config );

void
wksp_cmd_perm( args_t *         args,
               fd_caps_ctx_t *  caps,
               config_t * const config ) {
  (void)args;

  ulong mlock_limit = 0UL;
  for( ulong i=0UL; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];
    mlock_limit = fd_ulong_max( mlock_limit, wksp->page_cnt * wksp->page_sz );
  }
  /* One 4K page is used by the logging lock */
  fd_caps_check_resource( caps, "wksp", RLIMIT_MEMLOCK, mlock_limit+4096UL, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );
}

void
wksp_cmd_fn( args_t *         args,
             config_t * const config ) {
  (void)args;

  initialize_workspaces( config );
  exit_group( 0 );
}
