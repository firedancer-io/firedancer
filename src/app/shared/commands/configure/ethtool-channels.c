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
  int const simple_mode    = (0==strcmp( config->net.xdp.rss_queue_mode, "simple" ));
  int const dedicated_mode = (0==strcmp( config->net.xdp.rss_queue_mode, "dedicated" ));

  fd_ethtool_ioctl_t ioc;
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to init ethtool ioctl", device ));

  /* This should happen first, otherwise changing the number of channels may fail */
  FD_TEST( 0==fd_ethtool_ioctl_rxfh_set_default( &ioc ) );

  uint const num_channels = simple_mode ? config->layout.net_tile_count : 0 /* maximum allowed */;
  int ret = fd_ethtool_ioctl_channels_set_num( &ioc, num_channels );
  if( FD_UNLIKELY( ret != 0 ) ) {
    if( FD_LIKELY( ret == EBUSY ) )
      FD_LOG_ERR(( "error configuring network device (%s), failed to set number of channels. "
                   "This is most commonly caused by an issue with the Intel ice driver on certain versions "
                   "of Ubuntu.  If you are using the ice driver, `sudo dmesg | grep %s` contains "
                   "messages about RDMA, and you do not need RDMA, try running `rmmod irdma` and/or "
                   "blacklisting the irdma kernel module.", device, device ));
    else
      FD_LOG_ERR(( "error configuring network device (%s), failed to set number of channels", device ));
  }

  FD_TEST( 0==fd_ethtool_ioctl_ntuple_clear( &ioc ) );

  if( dedicated_mode ) {
    if( FD_UNLIKELY( config->layout.net_tile_count != 1 ) )
      FD_LOG_ERR(( "`layout.net_tile_count` must be 1 when `net.xdp.rss_queue_mode` is \"dedicated\"" ));

    /* Remove queue 0 from the rxfh table.  This queue is dedicated for xdp. */
    if( FD_UNLIKELY( 0!=fd_ethtool_ioctl_rxfh_set_suffix( &ioc, 1 ) ) )
      FD_LOG_ERR(( "error configuring network device (%s), failed to isolate queue zero. Try `net.xdp.rss_queue_mode=\"simple\"`", device ));

    if( FD_UNLIKELY( 0!=fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, 1 ) ) )
      FD_LOG_ERR(( "error configuring network device (%s), failed to enable ntuple feature. Try `net.xdp.rss_queue_mode=\"simple\"`", device ));

    /* FIXME Centrally define listen port list to avoid this configure
       stage from going out of sync with port mappings. */
    int error = 0;
    uint rule_idx = 0;
    error |= ( 0!=fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.shred.shred_listen_port, 0 ) );
    error |= ( 0!=fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.quic.quic_transaction_listen_port, 0 ) );
    error |= ( 0!=fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.quic.regular_transaction_listen_port, 0 ) );
    if( config->is_firedancer ) {
      error |= ( 0!=fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->gossip.port, 0 ) );
      error |= ( 0!=fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.repair.repair_intake_listen_port, 0 ) );
      error |= ( 0!=fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.repair.repair_serve_listen_port, 0 ) );
      error |= ( 0!=fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, config->tiles.send.send_src_port, 0 ) );
    }
    if( FD_UNLIKELY( error ) )
      FD_LOG_ERR(( "error configuring network device (%s), failed to install ntuple rules. Try `net.xdp.rss_queue_mode=\"simple\"`", device ));
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
  int const simple_mode    = (0==strcmp( config->net.xdp.rss_queue_mode, "simple" ));
  int const dedicated_mode = (0==strcmp( config->net.xdp.rss_queue_mode, "dedicated" ));

  fd_ethtool_ioctl_t ioc;
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to init ethtool ioctl", device ));

  int error = 0;    /* is anything not fully configured according to the current mode */
  int modified = 0; /* is anything changed from the default (fini'd) state */

  fd_ethtool_ioctl_channels_t channels;
  FD_TEST( 0==fd_ethtool_ioctl_channels_get_num( &ioc, &channels ) );
  if( channels.current != channels.max ) {
    modified = 1;
    if( dedicated_mode ) {
      error = 1;
      FD_LOG_WARNING(( "device `%s` does not have right number of channels (got %u but "
                       "expected %u)",
                       device, channels.current, channels.max ));
    }
  }
  if( simple_mode ) {
    if( FD_UNLIKELY( channels.current != config->layout.net_tile_count ) ) {
      error = 1;
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
        FD_LOG_WARNING(( "device `%s` does not have right number of channels (got %u but "
                         "expected %u)",
                         device, channels.current, config->layout.net_tile_count ));
      }
    }
  }

  uint rxfh_table[ FD_ETHTOOL_MAX_RXFH_TABLE_CNT ] = { 0 };
  uint rxfh_table_ele_cnt;
  FD_TEST( 0==fd_ethtool_ioctl_rxfh_get_table( &ioc, rxfh_table, &rxfh_table_ele_cnt ) );
  if( rxfh_table_ele_cnt==0 ) {
    if( dedicated_mode ) {
      error = 1;
      FD_LOG_WARNING(( "device `%s` does not have any rxfh table installed", device ));
    }
  } else {
    int rxfh_error = 0;
    uint default_queue = 0;
    uint configured_queue = dedicated_mode ? 1 : 0;
    for( uint j=0u; j<rxfh_table_ele_cnt; j++) {
      modified   |= (rxfh_table[ j ] != default_queue++);
      rxfh_error |= (rxfh_table[ j ] != configured_queue++);
      if( default_queue >= channels.current )
        default_queue = 0;
      if( configured_queue >= channels.current )
        configured_queue = dedicated_mode ? 1 : 0;
    }
    if( FD_UNLIKELY( rxfh_error ) ) {
      error = 1;
      FD_LOG_WARNING(( "device `%s` does not have the correct rxfh table installed", device ));
    }
  }

  if( dedicated_mode ) {
    int ntuple_feature_active;
    FD_TEST( 0==fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, &ntuple_feature_active ) );
    if( !ntuple_feature_active ) {
      error = 1;
      FD_LOG_WARNING(( "device `%s` has incorrect ntuple feature flag, should be enabled", device ));
    }
  }

  int ntuple_rules_empty;
  FD_TEST( 0==fd_ethtool_ioctl_ntuple_validate_udp_dport( &ioc, NULL, 0, 0, &ntuple_rules_empty ) );
  if( !ntuple_rules_empty ) {
    modified = 1;
    if( simple_mode ) {
      error = 1;
      FD_LOG_WARNING(( "device `%s` should not have ntuple rules", device ));
    }
  }
  if( dedicated_mode ) {
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
fini_device( char const * device ) {
  int error = 0;

  fd_ethtool_ioctl_t ioc;
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to init ethtool ioctl", device ));

  /* It may be the case for certain devices that the default state is
     the same as the init'd state (in simple mode).  In this case the
     following fini commands will all be noops, which is fine.  But we
     need to return 0 so that the configure stage logic does not
     consider this to be an error.  We compare the state before and
     after to see if anything was changed by fini. */
  fd_ethtool_ioctl_channels_t channels_orig;
  error |= (0!=fd_ethtool_ioctl_channels_get_num( &ioc, &channels_orig ));
  uint rxfh_table_orig[ FD_ETHTOOL_MAX_RXFH_TABLE_CNT ] = { 0 };
  uint rxfh_table_orig_ele_cnt;
  error |= (0!=fd_ethtool_ioctl_rxfh_get_table( &ioc, rxfh_table_orig, &rxfh_table_orig_ele_cnt ));
  int ntuple_rules_empty_orig;
  error |= (0!=fd_ethtool_ioctl_ntuple_validate_udp_dport( &ioc, NULL, 0, 0, &ntuple_rules_empty_orig ));
  if( FD_UNLIKELY( error ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to determine initial state", device ));

  /* This should happen first, otherwise changing the number of channels may fail */
  error |= (0!=fd_ethtool_ioctl_rxfh_set_default( &ioc ));

  error |= (0!=fd_ethtool_ioctl_channels_set_num( &ioc, 0 /* max */ ));

  /* Some drivers (i40e) do not always evenly redistribute the RXFH table
     when increasing the channel count, so we run this again just in case. */
  error |= (0!=fd_ethtool_ioctl_rxfh_set_default( &ioc ));

  /* Note: We leave the ntuple feature flag as-is in fini */
  error |= (0!=fd_ethtool_ioctl_ntuple_clear( &ioc ));

  if( FD_UNLIKELY( error ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to set to default state", device ));

  fd_ethtool_ioctl_channels_t channels_new;
  error |= (0!=fd_ethtool_ioctl_channels_get_num( &ioc, &channels_new ));
  uint rxfh_table_new[ FD_ETHTOOL_MAX_RXFH_TABLE_CNT ] = { 0 };
  uint rxfh_table_new_ele_cnt;
  error |= (0!=fd_ethtool_ioctl_rxfh_get_table( &ioc, rxfh_table_new, &rxfh_table_new_ele_cnt ));
  int ntuple_rules_empty_new;
  error |= (0!=fd_ethtool_ioctl_ntuple_validate_udp_dport( &ioc, NULL, 0, 0, &ntuple_rules_empty_new ));
  if( FD_UNLIKELY( error ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to determine final state", device ));

  fd_ethtool_ioctl_fini( &ioc );

  int modified = (0!=memcmp( &channels_orig, &channels_new, sizeof(fd_ethtool_ioctl_channels_t) )) ||
                 (rxfh_table_orig_ele_cnt != rxfh_table_new_ele_cnt) ||
                 (0!=memcmp( rxfh_table_orig, rxfh_table_new, rxfh_table_orig_ele_cnt * sizeof(uint) )) ||
                 (ntuple_rules_empty_orig!=ntuple_rules_empty_new);
  return modified;
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
      done |= fini_device( token );
    }
  } else {
    done |= fini_device( config->net.interface );
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
