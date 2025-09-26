/* This stage disables the "tx-udp-segmentation" offload on the loopback
   interface.  If left enabled, AF_XDP will drop loopback UDP packets sent
   by processes that enable TX segmentation via SOL_UDP/UDP_SEGMENT sockopt
   or cmsg.

   TLDR tx-udp-segmentation and AF_XDP are incompatible. */

#include "configure.h"

#include "fd_ethtool_ioctl.h"

#define NAME "ethtool-loopback"

static int
enabled( fd_config_t const * config ) {

  /* if we're running in a network namespace, we configure ethtool on
     the virtual device as part of netns setup, not here */
  if( config->development.netns.enabled ) return 0;

  /* only enable if network stack is XDP */
  if( 0!=strcmp( config->net.provider, "xdp" ) ) return 0;

  return 1;
}

static void
init_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "disable loopback " FD_ETHTOOL_FEATURE_TXUDPSEG " with `ethtool --offload lo " FD_ETHTOOL_FEATURE_TXUDPSEG " off`" );
}

static void
init( fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_ethtool_ioctl_t ioc;
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, "lo" ) ) )
    FD_LOG_ERR(( "error configuring network device (lo), unable to init ethtool ioctl" ));

  FD_TEST( 0==fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_TXUDPSEG, 0 ) );

  fd_ethtool_ioctl_fini( &ioc );
}

static configure_result_t
check( fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_ethtool_ioctl_t ioc;
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, "lo" ) ) )
    FD_LOG_ERR(( "error configuring network device (lo), unable to init ethtool ioctl" ));

  int udpseg_active;
  FD_TEST( 0==fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_TXUDPSEG, &udpseg_active ) );

  fd_ethtool_ioctl_fini( &ioc );

  if( udpseg_active ) {
    NOT_CONFIGURED( "device `lo` has " FD_ETHTOOL_FEATURE_TXUDPSEG " enabled. Should be disabled" );
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_ethtool_loopback = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
