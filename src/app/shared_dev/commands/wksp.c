#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../platform/fd_sys_util.h"

#include <sys/resource.h>

void
initialize_workspaces( config_t const * config );

void
wksp_cmd_perm( args_t *         args FD_PARAM_UNUSED,
               fd_cap_chk_t *   chk,
               config_t const * config ) {
  ulong mlock_limit = 0UL;
  for( ulong i=0UL; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t const * wksp = &config->topo.workspaces[ i ];
    mlock_limit = fd_ulong_max( mlock_limit, wksp->page_cnt * wksp->page_sz );
  }
  /* One 4K page is used by the logging lock */
  fd_cap_chk_raise_rlimit( chk, "wksp", RLIMIT_MEMLOCK, mlock_limit+4096UL, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );
}

void
wksp_cmd_fn( args_t *   args FD_PARAM_UNUSED,
             config_t * config ) {
  initialize_workspaces( config );
  fd_sys_util_exit_group( 0 );
}

action_t fd_action_wksp = {
  .name = "wksp",
  .args = NULL,
  .fn   = wksp_cmd_fn,
  .perm = wksp_cmd_perm,
  .description = "Initialize workspaces"
};
