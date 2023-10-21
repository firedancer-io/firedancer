#include "tiles.h"

fd_tile_config_t fd_tile_bank = {
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
