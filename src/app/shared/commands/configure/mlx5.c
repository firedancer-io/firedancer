#include "configure.h"
#include "fd_ethtool_ioctl.h"
#include "../../../../disco/net/mlx5/fd_mlx5.h"

#include <linux/capability.h>

static int
enabled( config_t const * config ) {
  return !strcmp( config->net.provider, "mlx5" );
}

static void
init_perm( fd_cap_chk_t   * chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "mlx5", "configure mlx5 network devices and load the ib_uverbs kernel module" );
  if( !fd_mlx5_uverbs_avail() ) {
    fd_cap_chk_cap( chk, "mlx5", CAP_SYS_MODULE, "run modprobe to load the ib_uverbs kernel module" );
  }
}

static void
init( config_t const * config ) {
  if( !fd_mlx5_uverbs_avail() ) {
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

  fd_ethtool_ioctl_reset( config->net.interface );
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  if( !fd_mlx5_uverbs_avail() ) NOT_CONFIGURED( "uverbs interface unavailable" );

  int is_modified = fd_ethtool_ioctl_is_modified( config->net.interface );
  if( FD_UNLIKELY( is_modified ) ) {
    if( check_type!=FD_CONFIGURE_CHECK_TYPE_RUN ) {
      NOT_CONFIGURED( "device `%s` has ethtool configuration left by the xdp provider", config->net.interface );
    }
    FD_LOG_WARNING(( "Network device `%s` has ethtool configuration left by the xdp provider. "
                     "Run `%s configure init mlx5` to restore the device defaults.", config->net.interface, FD_BINARY_NAME ));
  }
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_mlx5 = {
  .name      = "mlx5",
  .enabled   = enabled,
  .init_perm = init_perm,
  .init      = init,
  .check     = check,
};
