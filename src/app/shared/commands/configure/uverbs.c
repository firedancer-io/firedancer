#include "configure.h"
#include "../../../../disco/net/mlx5/fd_mlx5.h"

#include <linux/capability.h>

static int
enabled( config_t const * config ) {
  return !strcmp( config->net.provider, "mlx5" );
}

static void
init_perm( fd_cap_chk_t   * chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "uverbs",                 "run modprobe to load the ib_uverbs kernel module" );
  fd_cap_chk_cap(  chk, "uverbs", CAP_SYS_MODULE, "run modprobe to load the ib_uverbs kernel module" );
}

static void
init( config_t const * config FD_PARAM_UNUSED ) {
  FD_LOG_NOTICE(( "%sRUN: `modprobe ib_uverbs`%s", fd_log_style_dim(), fd_log_style_normal() ));
  if( FD_UNLIKELY( fd_mlx5_uverbs_modprobe( 0 ) ) ) {
    FD_LOG_ERR(( "failed to load ib_uverbs kernel module. "
                 "Run `sudo modprobe ib_uverbs` and retry" ));
  }
  if( FD_UNLIKELY( !fd_mlx5_uverbs_avail() ) ) {
    FD_LOG_ERR(( "failed to run mlx5 tile: uverbs interface still unavailable after trying to load ib_uverbs kernel module. "
                 "Please set [net.provider] to `xdp`" ));
  }
}

static configure_result_t
check( config_t const * config     FD_PARAM_UNUSED,
       int              check_type FD_PARAM_UNUSED ) {
  if( !fd_mlx5_uverbs_avail() ) NOT_CONFIGURED( "uverbs interface unavailable" );
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_uverbs = {
  .name      = "uverbs",
  .enabled   = enabled,
  .init_perm = init_perm,
  .init      = init,
  .check     = check,
};
