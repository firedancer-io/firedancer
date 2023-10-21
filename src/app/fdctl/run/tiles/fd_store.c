#include "tiles.h"

/* This is a stub definition that's needed so the tile can be used in
   the topology system to set up links and count tiles and things, but
   it's not invoked by the runner to start a bank tile.  Instead, the
   store tile is managed by the Solana Labs process. */

fd_tile_config_t fd_tile_store = {
  .mux_flags           = FD_MUX_FLAG_DEFAULT,
  .burst               = 1UL,
  .mux_ctx             = NULL,
  .allow_syscalls_cnt  = 0,
  .allow_syscalls      = NULL,
  .allow_fds           = NULL,
  .scratch_align       = NULL,
  .scratch_footprint   = NULL,
  .privileged_init     = NULL,
  .unprivileged_init   = NULL,
};
