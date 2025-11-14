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

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "fd_ethtool_ioctl.h"

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

static int
device_is_bonded( char const * device ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/bonding", device ) );
  struct stat st;
  int err = stat( path, &st );
  if( FD_UNLIKELY( err && errno != ENOENT ) )
    FD_LOG_ERR(( "error checking if device `%s` is bonded, stat(%s) failed (%i-%s)",
                 device, path, errno, fd_io_strerror( errno ) ));
  return !err;
}

static void
device_read_slaves( char const * device,
                    char         output[ 4096 ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/class/net/%s/bonding/slaves", device ) );

  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) )
    FD_LOG_ERR(( "error configuring network device, fopen(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !fgets( output, 4096, fp ) ) )
    FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( feof( fp ) ) ) FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (EOF)", path ));
  if( FD_UNLIKELY( ferror( fp ) ) ) FD_LOG_ERR(( "error configuring network device, fgets(%s) failed (error)", path ));
  if( FD_UNLIKELY( strlen( output ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
  if( FD_UNLIKELY( strlen( output ) == 0 ) ) FD_LOG_ERR(( "line empty in `%s`", path ));
  if( FD_UNLIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error configuring network device, fclose(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  output[ strlen( output ) - 1 ] = '\0';
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
  if( FD_UNLIKELY( device_is_bonded( config->net.interface ) ) ) {
    char line[ 4096 ];
    device_read_slaves( config->net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line , " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      init_device( token, xdp );
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
  if( FD_UNLIKELY( device_is_bonded( config->net.interface ) ) ) {
    char line[ 4096 ];
    device_read_slaves( config->net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line, " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      CHECK( check_device( token, xdp, warn_gro ) );
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
