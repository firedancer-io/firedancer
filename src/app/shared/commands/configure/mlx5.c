#include "configure.h"
#include "fd_ethtool_ioctl.h"
#include "../../../platform/fd_sys_util.h"
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
fini_perm( fd_cap_chk_t   * chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "mlx5", "modify network device configuration with ethtool" );
}

static void
init( config_t const * config FD_PARAM_UNUSED ) {
  if( !fd_mlx5_uverbs_avail() ) {
    FD_LOG_NOTICE(( "%sRUN: `modprobe ib_uverbs`%s", fd_log_style_dim(), fd_log_style_normal() ));
    if( FD_UNLIKELY( -1==fd_sys_util_modprobe( "ib_uverbs", 0 ) ) ) {
      FD_LOG_ERR(( "failed to load ib_uverbs kernel module. "
                   "Run `sudo modprobe ib_uverbs` and retry" ));
    }
    if( FD_UNLIKELY( !fd_mlx5_uverbs_avail() ) ) {
      FD_LOG_ERR(( "failed to run mlx5 tile: uverbs interface still unavailable after trying to load ib_uverbs kernel module. "
                   "Please set [net.provider] to `xdp`" ));
    }
  }
}

static int
fini( config_t const * config,
      int              pre_init FD_PARAM_UNUSED ) {
  return fd_ethtool_ioctl_reset( config->net.interface );
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  int is_modified = fd_ethtool_ioctl_is_modified( config->net.interface );
  if( FD_UNLIKELY( is_modified ) ) {
    PARTIALLY_CONFIGURED( "device `%s` has ethtool configuration left by the xdp provider", config->net.interface );
  }

  if( check_type==FD_CONFIGURE_CHECK_TYPE_FINI_PERM ||
      check_type==FD_CONFIGURE_CHECK_TYPE_PRE_FINI  ||
      check_type==FD_CONFIGURE_CHECK_TYPE_POST_FINI ) {
    NOT_CONFIGURED( "device `%s` has no ethtool configuration to clear", config->net.interface );
  }

  if( !fd_mlx5_uverbs_avail() ) NOT_CONFIGURED( "uverbs interface unavailable" );
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_mlx5 = {
  .name      = "mlx5",
  .enabled   = enabled,
  .init_perm = init_perm,
  .fini_perm = fini_perm,
  .init      = init,
  .fini      = fini,
  .check     = check,
};
