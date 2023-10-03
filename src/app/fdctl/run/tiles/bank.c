#include "tiles.h"
#include "../run.h"

/* dummy bank definition for use by some config macros */

static workspace_kind_t allow_workspaces[] = {
  wksp_pack_bank,  /* receive path */
  wksp_bank_shred, /* send path */
};

fd_tile_config_t bank = {
  .name                 = "bank",
  .allow_workspaces_cnt = sizeof(allow_workspaces)/sizeof(allow_workspaces[ 0 ]),
  .allow_workspaces     = allow_workspaces,
  .allow_syscalls_cnt   = 0,
  .allow_syscalls       = NULL,
  .allow_fds            = NULL,
  .init                 = NULL,
  .run                  = NULL,
};
