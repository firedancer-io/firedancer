/* This stage checks and modifies various ethtool features on the main
   and loopback interfaces.

     - "Generic Receive Offload": If enabled, may greatly increase
     throughput for sockets-based TCP flows, such as HTTP snapshot
     downloads.  This stage will log a warning if GRO is disabled, but
     does not modify the flag.

     - "RX UDP GRO Forwarding": If left enabled, may aggregate multiple
     UDP packets into a single large superpacket.  This would normally
     be split later for socket recv() calls, but AF_XDP delivers the
     full superpacket which confuses the application layer.  Disabled
     by this stage.

     - "GRE Segmentation Offload": This feature has been known to cause
     corruption of packets sent via normal sockets while XDP is in use
     on the same system.  Disabled by this stage. */

#include "configure.h"

#include "fd_ethtool_ioctl.h"
#include "../../../../disco/net/fd_linux_bond.h"

#define NAME "ethtool-offloads"

static int
enabled( fd_config_t const * config ) {

  /* if we're running in a network namespace, we configure ethtool on
     the virtual device as part of netns setup, not here */
  if( config->development.netns.enabled ) return 0;

  return 1;
}

static void
init_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "disable network device features with `ethtool --offload INTF FEATURE off`" );
}


static void
init_device( char const * device,
             int          xdp ) {
  if( !xdp ) return;

  fd_ethtool_ioctl_t ioc __attribute__((cleanup(fd_ethtool_ioctl_fini)));
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to init ethtool ioctl", device ));

  /* turn off rx-udp-gro-forwarding, which is entirely incompatible with
   * AF_XDP and QUIC
   * It results in multiple UDP payloads being merged into a single UDP packet,
   * with IP and UDP headers rewritten, combining the lengths and updating the
   * checksums. QUIC short packets cannot be processed reliably in this case. */
  FD_TEST( 0==fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_RXUDPGROFWD,  0 ) );

  /* turn off tx-gre-segmentation and tx-gre-csum-segmentation.  When
     enabled, some packets sent via normal sockets can be corrupted
     while XDP is in use on the same system. */
  FD_TEST( 0==fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_TXGRESEG,     0 ) );
  FD_TEST( 0==fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_TXGRECSUMSEG, 0 ) );
}

static void
init( fd_config_t const * config ) {
  int const xdp = 0==strcmp( config->net.provider, "xdp" );
  if( FD_UNLIKELY( fd_bonding_is_master( config->net.interface ) ) ) {
    fd_bonding_slave_iter_t iter_[1];
    fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
    for( ; !fd_bonding_slave_iter_done( iter );
         fd_bonding_slave_iter_next( iter ) ) {
      init_device( fd_bonding_slave_iter_ele( iter ), xdp );
    }
  } else {
    init_device( config->net.interface, xdp );
  }
  init_device( "lo", xdp );
}

static configure_result_t
check_device( char const * device,
              int          xdp,
              int          warn_gro ) {
  fd_ethtool_ioctl_t ioc __attribute__((cleanup(fd_ethtool_ioctl_fini)));
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to init ethtool ioctl", device ));

  if( warn_gro ) {
    int gro_active, gro_supported;
    if( FD_LIKELY( 0==fd_ethtool_ioctl_feature_gro_test( &ioc, &gro_active, &gro_supported ) ) ) {
      if( FD_UNLIKELY( !gro_active && gro_supported ) ) {
        FD_LOG_WARNING(( "network device `%s` has generic-receive-offload disabled.  "
                         "Consider enabling with `ethtool --offload %s generic-receive-offload on`.  "
                         "Proceeding but performance may be reduced.", device, device ));
      }
    }
  }

  if( xdp ) {
    int udpgrofwd_active;
    int greseg_active;
    int grecsumseg_active;
    FD_TEST( 0==fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_RXUDPGROFWD,  &udpgrofwd_active  ) );
    FD_TEST( 0==fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_TXGRESEG,     &greseg_active     ) );
    FD_TEST( 0==fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_TXGRECSUMSEG, &grecsumseg_active ) );

    if( FD_UNLIKELY( udpgrofwd_active ) )
      NOT_CONFIGURED( "device `%s` has rx-udp-gro-forwarding enabled. Should be disabled", device );
    if( FD_UNLIKELY( greseg_active ) )
      NOT_CONFIGURED( "device `%s` has tx-gre-segmentation enabled. Should be disabled", device );
    if( FD_UNLIKELY( grecsumseg_active ) )
      NOT_CONFIGURED( "device `%s` has tx-gre-csum-segmentation enabled. Should be disabled", device );
  }

  CONFIGURE_OK();
}

static configure_result_t
check( fd_config_t const * config,
       int                 check_type ) {
  int warn_gro = check_type==FD_CONFIGURE_CHECK_TYPE_PRE_INIT ||
                 check_type==FD_CONFIGURE_CHECK_TYPE_CHECK ||
                 check_type==FD_CONFIGURE_CHECK_TYPE_RUN;
  int const xdp = 0==strcmp( config->net.provider, "xdp" );
  if( FD_UNLIKELY( fd_bonding_is_master( config->net.interface ) ) ) {
    fd_bonding_slave_iter_t iter_[1];
    fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
    for( ; !fd_bonding_slave_iter_done( iter );
         fd_bonding_slave_iter_next( iter ) ) {
      CHECK( check_device( fd_bonding_slave_iter_ele( iter ), xdp, warn_gro ) );
    }
  } else {
    CHECK( check_device( config->net.interface, xdp, warn_gro ) );
  }
  CHECK( check_device( "lo", xdp, 0 ) );

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_ethtool_offloads = {
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
