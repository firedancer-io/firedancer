#include "configure.h"
#include "../../../platform/fd_sys_util.h"

#include <linux/capability.h>
#include <sys/stat.h>

static int
enabled( config_t const * config ) {
  return !strcmp( config->net.provider, "iavf" );
}

static int
vfio_avail( void ) {
  struct stat st;
  return !stat( "/sys/bus/pci/drivers/vfio-pci", &st ) && S_ISDIR( st.st_mode );
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, "vfio",                 "run modprobe to load the vfio-pci kernel module" );
  fd_cap_chk_cap(  chk, "vfio", CAP_SYS_MODULE, "run modprobe to load the vfio-pci kernel module" );
}

static void
init( config_t const * config FD_PARAM_UNUSED ) {
  FD_LOG_NOTICE(( "%sRUN: `modprobe vfio-pci`%s", fd_log_style_dim(), fd_log_style_normal() ));
  if( FD_UNLIKELY( fd_sys_util_modprobe( "vfio-pci", 0 ) ) ) {
    FD_LOG_ERR(( "failed to load vfio-pci kernel module. Run `sudo modprobe vfio-pci` and retry" ));
  }
  if( FD_UNLIKELY( !vfio_avail() ) ) {
    FD_LOG_ERR(( "vfio-pci driver still unavailable after trying to load its kernel module" ));
  }
}

static configure_result_t
check( config_t const * config     FD_PARAM_UNUSED,
       int              check_type FD_PARAM_UNUSED ) {
  if( !vfio_avail() ) NOT_CONFIGURED( "vfio-pci driver unavailable" );
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_vfio = {
  .name      = "vfio",
  .enabled   = enabled,
  .init_perm = init_perm,
  .init      = init,
  .check     = check,
};
