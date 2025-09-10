#include "configure.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "fd_ethtool_ioctl.h"

#define NAME "ethtool-channels"

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
  fd_cap_chk_root( chk, NAME, "modify network device configuration with ethtool" );
}

static void
fini_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "modify network device configuration with ethtool" );
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
init_device( char const *        device,
             fd_config_t const * config ) {
  fd_ethtool_ioctl_t ioc;
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device, unable to init ethtool ioctl" ));

  uint num_channels;
  if( 0==strcmp( config->net.xdp.rss_queue_mode, "simple" ) ) {
    num_channels = config->layout.net_tile_count;
  } else {
    num_channels = 0; /* maximum allowed */
  }
  int ret = fd_ethtool_ioctl_channels_set_num( &ioc, num_channels );
  if( FD_UNLIKELY( ret != 0 ) ) {
    if( FD_LIKELY( ret == EBUSY ) )
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SCHANNELS) failed (%i-%s). "
                   "This is most commonly caused by an issue with the Intel ice driver on certain versions "
                   "of Ubuntu.  If you are using the ice driver, `sudo dmesg | grep %s` contains "
                   "messages about RDMA, and you do not need RDMA, try running `rmmod irdma` and/or "
                   "blacklisting the irdma kernel module.",
                   ret, fd_io_strerror( ret ), device ));
    else
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SCHANNELS) failed (%i-%s)",
                   ret, fd_io_strerror( ret ) ));
  }

  if( 0==strcmp( config->net.xdp.rss_queue_mode, "dedicated" ) ) {
    if( FD_UNLIKELY( config->layout.net_tile_count != 1 ) )
      FD_LOG_ERR(( "`layout.net_tile_count` must be 1 when `net.xdp.rss_queue_mode` is \"dedicated\"" ));

    /* Remove queue 0 from the rxfh table.  This queue is dedicated for xdp. */
    FD_TEST( 0==fd_ethtool_ioctl_rxfh_set_suffix( &ioc, 1 ) );

    /* FIXME Centrally define listen port list to avoid this configure
       stage from going out of sync with port mappings. */
    uint rule_idx = 0;
    FD_TEST( 0==fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, 1 ) );
    FD_TEST( 0==fd_ethtool_ioctl_ntuple_clear( &ioc ) );
    FD_TEST( 0==fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.shred.shred_listen_port, 0 ) );
    FD_TEST( 0==fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.quic.quic_transaction_listen_port, 0 ) );
    FD_TEST( 0==fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.quic.regular_transaction_listen_port, 0 ) );
    if( config->is_firedancer ) {
      FD_TEST( 0==fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->gossip.port, 0 ) );
      FD_TEST( 0==fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.repair.repair_intake_listen_port, 0 ) );
      FD_TEST( 0==fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.repair.repair_serve_listen_port, 0 ) );
      FD_TEST( 0==fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.send.send_src_port, 0 ) );
    }
  }

  fd_ethtool_ioctl_fini( &ioc );
}

static void
init( fd_config_t const * config ) {
  /* we need one channel for both TX and RX on the NIC for each net
     tile, but the interface probably defaults to one channel total */
  if( FD_UNLIKELY( device_is_bonded( config->net.interface ) ) ) {
    /* if using a bonded device, we need to set channels on the
       underlying devices. */
    char line[ 4096 ];
    device_read_slaves( config->net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line , " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      init_device( token, config );
    }
  } else {
    init_device( config->net.interface, config );
  }
}

static configure_result_t
check_device( char const * device,
              fd_config_t const * config ) {
  fd_ethtool_ioctl_t ioc;
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device, unable to init ethtool ioctl" ));

  fd_ethtool_ioctl_channels_t channels;
  FD_TEST( 0==fd_ethtool_ioctl_channels_get_num( &ioc, &channels ) );

  if( 0==strcmp( config->net.xdp.rss_queue_mode, "simple" ) ) {
    fd_ethtool_ioctl_fini( &ioc );
    if( FD_UNLIKELY( channels.current != config->layout.net_tile_count ) ) {
      if( FD_UNLIKELY( !channels.supported ) ) {
        FD_LOG_ERR(( "Network device `%s` does not support setting number of channels, "
                     "but you are running with more than one net tile (expected {%u}), "
                     "and there must be one channel per tile. You can either use a NIC "
                     "that supports multiple channels, or run Firedancer with only one "
                     "net tile. You can configure Firedancer to run with only one net "
                     "tile by setting `layout.net_tile_count` to 1 in your "
                     "configuration file.",
                     device, config->layout.net_tile_count ));
      } else {
        NOT_CONFIGURED( "device `%s` does not have right number of channels (got %u but "
                        "expected %u)",
                        device, channels.current, config->layout.net_tile_count );
      }
    }
    CONFIGURE_OK();
  } else {
    int error = 0;    /* is anything not fully configured */
    int modified = 0; /* is anything changed from the default (fini'd) state */

    if( FD_UNLIKELY( channels.current != channels.max ) ) {
      error = 1;
      modified = 1;
      FD_LOG_WARNING(( "device `%s` does not have right number of channels (got %u but "
                       "expected %u)",
                       device, channels.current, channels.max ));
    }

    uint rxfh_table[ FD_ETHTOOL_MAX_RXFH_TABLE_SIZE ] = { 0 };
    uint rxfh_table_size;
    FD_TEST( 0==fd_ethtool_ioctl_rxfh_get_table( &ioc, rxfh_table, &rxfh_table_size ) );
    int rxfh_error = 0;
    uint default_queue = 0;
    uint configured_queue = 1; /* If properly configured the 0th queue is excluded */
    for( uint j=0u; j<rxfh_table_size; j++) {
      modified   |= (rxfh_table[ j ] != default_queue++);
      rxfh_error |= (rxfh_table[ j ] != configured_queue++);
      if( default_queue >= channels.current )
        default_queue = 0;
      if( configured_queue >= channels.current )
        configured_queue = 1;
    }
    if( FD_UNLIKELY( rxfh_error ) ) {
      error = 1;
      FD_LOG_WARNING(( "device `%s` does not have the correct rxfh table installed", device ));
    }

    int ntuple_feature_active;
    FD_TEST( 0==fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, &ntuple_feature_active ) );
    if( !ntuple_feature_active ) {
      error = 1;
      FD_LOG_WARNING(( "device `%s` has incorrect ntuple feature flag, should be enabled", device ));
    }

    int ntuple_rules_empty;
    FD_TEST( 0==fd_ethtool_ioctl_ntuple_validate_udp_dport( &ioc, NULL, 0, 0, &ntuple_rules_empty ) );
    if( ntuple_rules_empty ) {
      error = 1;
      FD_LOG_WARNING(( "device `%s` is missing ntuple rules", device ));
    } else {
      modified = 1;

      /* FIXME Centrally define listen port list to avoid this configure
         stage from going out of sync with port mappings. */
      uint num_ports = 0;
      ushort ports[ 32 ];
      ports[ num_ports++ ] = config->tiles.shred.shred_listen_port;
      ports[ num_ports++ ] = config->tiles.quic.quic_transaction_listen_port;
      ports[ num_ports++ ] = config->tiles.quic.regular_transaction_listen_port;
      if( config->is_firedancer ) {
        ports[ num_ports++ ] = config->gossip.port;
        ports[ num_ports++ ] = config->tiles.repair.repair_intake_listen_port;
        ports[ num_ports++ ] = config->tiles.repair.repair_serve_listen_port;
        ports[ num_ports++ ] = config->tiles.send.send_src_port;
      }
      int ports_valid;
      FD_TEST( 0==fd_ethtool_ioctl_ntuple_validate_udp_dport( &ioc, ports, num_ports, 0, &ports_valid ));
      if( FD_UNLIKELY( !ports_valid ) ) {
        error = 1;
        FD_LOG_WARNING(( "device `%s` has incorrect ntuple rules", device ));
      }
    }

    fd_ethtool_ioctl_fini( &ioc );

    if( !error )
      CONFIGURE_OK();
    if( modified )
      PARTIALLY_CONFIGURED( "device `%s` has partial ethtool-channels network configuration", device );
    NOT_CONFIGURED( "device `%s` missing ethtool-channels network configuration", device );
  }
}

static configure_result_t
check( fd_config_t const * config ) {
  if( FD_UNLIKELY( device_is_bonded( config->net.interface ) ) ) {
    char line[ 4096 ];
    device_read_slaves( config->net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line, " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      CHECK( check_device( token, config ) );
    }
  } else {
    CHECK( check_device( config->net.interface, config ) );
  }

  CONFIGURE_OK();
}

static int
fini_device( char const *        device,
             fd_config_t const * config ) {
  if( 0==strcmp( config->net.xdp.rss_queue_mode, "simple" ) )
    return 0;

  fd_ethtool_ioctl_t ioc;
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device, unable to init ethtool ioctl" ));

  /* This should happen first, otherwise changing the number of channels may fail */
  fd_ethtool_ioctl_rxfh_set_default( &ioc );

  fd_ethtool_ioctl_channels_set_num( &ioc, 0 /* max */ );

  /* Some drivers (i40e) do not always evenly redistribute the RXFH table
     when increasing the channel count, so we run this again just in case. */
  fd_ethtool_ioctl_rxfh_set_default( &ioc );

  /* Note: We leave the ntuple feature flag as-is in fini */
  fd_ethtool_ioctl_ntuple_clear( &ioc );

  fd_ethtool_ioctl_fini( &ioc );
  return 1;
}

static int
fini( fd_config_t const * config,
      int                 pre_init FD_PARAM_UNUSED ) {
  int done = 0;
  if( FD_UNLIKELY( device_is_bonded( config->net.interface ) ) ) {
    char line[ 4096 ];
    device_read_slaves( config->net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line , " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      done |= fini_device( token, config );
    }
  } else {
    done |= fini_device( config->net.interface, config );
  }
  return done;
}

configure_stage_t fd_cfg_stage_ethtool_channels = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
