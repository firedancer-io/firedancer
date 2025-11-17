#include "configure.h"

#include <errno.h>
#include <unistd.h>

#include "fd_ethtool_ioctl.h"
#include "../../../../disco/net/fd_linux_bond.h"

#define NAME "ethtool-channels"

static int fini_device( char const * device );

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

/* FIXME: Centrally define listen port list to avoid this configure
   stage from going out of sync with port mappings. */
static uint
get_ports( fd_config_t const * config,
           ushort *            ports ) {
  uint port_cnt = 0U;

#define ADD_PORT( p ) do { \
  ushort __port = ( p ); \
  if( FD_UNLIKELY( __port==0U ) ) break; \
  int __dupe = 0; \
  for( uint __p=0U; !__dupe && __p<port_cnt; ++__p ) __dupe = (ports[ __p ]==__port); \
  if( FD_UNLIKELY( __dupe ) ) break; \
  ports[ port_cnt ] = __port; \
  port_cnt++; \
} while(0)

  ADD_PORT( config->tiles.shred.shred_listen_port              );
  ADD_PORT( config->tiles.quic.quic_transaction_listen_port    );
  ADD_PORT( config->tiles.quic.regular_transaction_listen_port );
  if( config->is_firedancer ) {
    ADD_PORT( config->gossip.port                              );
    ADD_PORT( config->tiles.repair.repair_intake_listen_port   );
    ADD_PORT( config->tiles.repair.repair_serve_listen_port    );
    ADD_PORT( config->tiles.send.send_src_port                 );
  }
#undef ADD_PORT

  return port_cnt;
}

/* Attempts to initialize the device in simple or dedicated mode.  If
   strict is true, FD_LOG_ERR's on failure.  Otherwise, returns 1 on
   failure. Returns 0 on success. */
static int
init_device( char const *        device,
             fd_config_t const * config,
             int                 dedicated_mode,
             int                 strict,
             uint                device_cnt ) {
  FD_TEST( dedicated_mode || strict );

  uint const net_tile_cnt = config->layout.net_tile_count;
  if( FD_UNLIKELY( net_tile_cnt%device_cnt!=0 ) ) {
    FD_LOG_ERR(( "net tile count %u must be a multiple of the number of slave devices %u (incompatible settings [layout.net_tile_count] and [net.xdp.native_bond])", net_tile_cnt, device_cnt ));
  }
  uint const queue_cnt = net_tile_cnt / device_cnt;

  fd_ethtool_ioctl_t ioc __attribute__((cleanup(fd_ethtool_ioctl_fini)));
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to init ethtool ioctl", device ));

  /* This should happen first, otherwise changing the number of channels may fail */
  FD_TEST( 0==fd_ethtool_ioctl_rxfh_set_default( &ioc ) );

  uint const num_channels = !dedicated_mode ? queue_cnt : 0 /* maximum allowed */;
  int ret = fd_ethtool_ioctl_channels_set_num( &ioc, num_channels );
  if( FD_UNLIKELY( 0!=ret ) ) {
    if( strict ) {
      if( FD_LIKELY( ret == EBUSY ) )
        FD_LOG_ERR(( "error configuring network device (%s), failed to set number of channels. "
                     "This is most commonly caused by an issue with the Intel ice driver on certain versions "
                     "of Ubuntu.  If you are using the ice driver, `sudo dmesg | grep %s` contains "
                     "messages about RDMA, and you do not need RDMA, try running `rmmod irdma` and/or "
                     "blacklisting the irdma kernel module.", device, device ));
      else
        FD_LOG_ERR(( "error configuring network device (%s), failed to set number of channels", device ));
    }
    return 1;
  }

  /* Some drivers (e.g. igb) put the RXFH table into an incorrect state
     after changing the channel count.  So in simple mode we reset it
     to the default again. */
  if( !dedicated_mode ) {
    FD_TEST( 0==fd_ethtool_ioctl_rxfh_set_default( &ioc ) );
  }

  FD_TEST( 0==fd_ethtool_ioctl_ntuple_clear( &ioc ) );

  if( dedicated_mode ) {
    /* Some drivers (e.g. ixgbe) reset the RXFH table upon activation
       of the ntuple feature, so we do this first. */
    if( FD_UNLIKELY( 0!=fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, 1 ) ) ) {
      if( strict ) FD_LOG_ERR(( "error configuring network device (%s), failed to enable ntuple feature. Try `net.xdp.rss_queue_mode=\"simple\"`", device ));
      else         return 1;
    }

    /* Remove a queue from the rxfh table for each net tile. */
    uint rxfh_queue_cnt;
    FD_TEST( 0==fd_ethtool_ioctl_rxfh_get_queue_cnt( &ioc, &rxfh_queue_cnt ) );
    if( FD_UNLIKELY( queue_cnt>=rxfh_queue_cnt ) ) {
      if( strict ) FD_LOG_ERR(( "error configuring network device (%s), too many net tiles %u for queue count %u.  "
                                "Try `net.xdp.rss_queue_mode=\"simple\"` or reduce net tile count",
                                device, net_tile_cnt, rxfh_queue_cnt ));
      else         return 1;
    }
    if( FD_UNLIKELY( 0!=fd_ethtool_ioctl_rxfh_set_suffix( &ioc, queue_cnt ) ) ) {
      if( strict ) FD_LOG_ERR(( "error configuring network device (%s), failed to isolate queues. Try `net.xdp.rss_queue_mode=\"simple\"`", device ));
      else         return 1;
    }

    /* Add a ntuple rule for each listening destination port.  If there
       are multiple net tiles, create a group of rules for each tile. */
    int ntuple_error = 0;
    ushort ports[ 32 ];
    uint port_cnt = get_ports( config, ports );
    uint rule_idx = 0;
    uint const rule_group_cnt = fd_uint_pow2_up( queue_cnt );
    for( uint r=0U; !ntuple_error && r<rule_group_cnt; r++ ) {
      for( uint p=0U; !ntuple_error && p<port_cnt; p++ ) {
        ntuple_error = 0!=fd_ethtool_ioctl_ntuple_set_udp_dport( &ioc, rule_idx++, ports[ p ], r, rule_group_cnt, r%queue_cnt );
      }
    }
    if( FD_UNLIKELY( ntuple_error ) ) {
      if( strict ) FD_LOG_ERR(( "error configuring network device (%s), failed to install ntuple rules.  "
                                "Try `net.xdp.rss_queue_mode=\"simple\"` or `layout.net_tile_count=1`", device ));
      else         return 1;
    }
  }

  return 0;
}

static void
init( fd_config_t const * config ) {
  int only_dedicated =
    (0==strcmp( config->net.xdp.rss_queue_mode, "dedicated" ));
  int try_dedicated = only_dedicated ||
    (0==strcmp( config->net.xdp.rss_queue_mode, "auto" ) );

  /* if using a bonded device, we need to set channels on the
     underlying devices. */
  int  is_bonded  = fd_bonding_is_master( config->net.interface );
  uint device_cnt = 1U;
  if( is_bonded && config->net.xdp.native_bond ) {
    device_cnt = fd_bonding_slave_cnt( config->net.interface );
  }

  /* If the mode was auto, we will try to init in dedicated mode but will
     not fail the stage if this is not successful.  If the mode was
     dedicated, we will require success. */
  if( try_dedicated ) {
    int failed = 0;
    if( is_bonded ) {
      fd_bonding_slave_iter_t iter_[1];
      fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
      for( ; !failed && !fd_bonding_slave_iter_done( iter );
          fd_bonding_slave_iter_next( iter ) ) {
        failed = init_device( fd_bonding_slave_iter_ele( iter ), config, 1, only_dedicated, device_cnt );
      }
    } else {
      failed = init_device( config->net.interface, config, 1, only_dedicated, device_cnt );
    }
    if( !failed ) return;
    FD_TEST( !only_dedicated );
    FD_LOG_WARNING(( "error configuring network device (%s), rss_queue_mode \"auto\" attempted"
                     " \"dedicated\" configuration but falling back to \"simple\".", config->net.interface ));
    /* Wipe partial dedicated configuration before simple init */
    if( is_bonded ) {
      fd_bonding_slave_iter_t iter_[1];
      fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
      for( ; !fd_bonding_slave_iter_done( iter );
          fd_bonding_slave_iter_next( iter ) ) {
        fini_device( fd_bonding_slave_iter_ele( iter ) );
      }
    }
    else {
      fini_device( config->net.interface );
    }
  }

  /* Require success for simple mode, either configured or as fallback */
  if( is_bonded ) {
    fd_bonding_slave_iter_t iter_[1];
    fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
    for( ; !fd_bonding_slave_iter_done( iter );
        fd_bonding_slave_iter_next( iter ) ) {
      init_device( fd_bonding_slave_iter_ele( iter ), config, 0, 1, device_cnt );
    }
  } else {
    init_device( config->net.interface, config, 0, 1, device_cnt );
  }
}

/* Returns whether anything is changed from the default (fini'd) state */
static int
check_device_is_modified( char const * device ) {
  fd_ethtool_ioctl_t ioc __attribute__((cleanup(fd_ethtool_ioctl_fini)));
  if( FD_UNLIKELY( &ioc!=fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to init ethtool ioctl", device ));

  fd_ethtool_ioctl_channels_t channels;
  FD_TEST( 0==fd_ethtool_ioctl_channels_get_num( &ioc, &channels ) );
  if( channels.current!=channels.max ) return 1;

  uint rxfh_queue_cnt;
  FD_TEST( 0==fd_ethtool_ioctl_rxfh_get_queue_cnt( &ioc, &rxfh_queue_cnt ) );

  uint rxfh_table[ FD_ETHTOOL_MAX_RXFH_TABLE_CNT ] = { 0 };
  uint rxfh_table_ele_cnt;
  FD_TEST( 0==fd_ethtool_ioctl_rxfh_get_table( &ioc, rxfh_table, &rxfh_table_ele_cnt ) );
  for( uint j=0U, q=0U; j<rxfh_table_ele_cnt; j++) {
    if( rxfh_table[ j ]!=q++ ) return 1;
    if( q>=rxfh_queue_cnt ) q = 0;
  }

  int ntuple_rules_empty;
  FD_TEST( 0==fd_ethtool_ioctl_ntuple_validate_udp_dport( &ioc, NULL, 0, 0, &ntuple_rules_empty ) );
  if( !ntuple_rules_empty ) return 1;

  return 0;
}

static int
check_device_is_configured( char const *        device,
                            fd_config_t const * config,
                            int                 dedicated_mode,
                            uint                device_cnt ) {
  uint const net_tile_cnt = config->layout.net_tile_count;
  if( FD_UNLIKELY( net_tile_cnt%device_cnt!=0 ) ) {
    FD_LOG_ERR(( "net tile count %u must be a multiple of the number of slave devices %u (incompatible settings [layout.net_tile_count] and [net.xdp.native_bond])", net_tile_cnt, device_cnt ));
  }
  uint const queue_cnt = net_tile_cnt / device_cnt;

  fd_ethtool_ioctl_t ioc __attribute__((cleanup(fd_ethtool_ioctl_fini)));
  if( FD_UNLIKELY( &ioc != fd_ethtool_ioctl_init( &ioc, device ) ) )
    FD_LOG_ERR(( "error configuring network device (%s), unable to init ethtool ioctl", device ));

  fd_ethtool_ioctl_channels_t channels;
  FD_TEST( 0==fd_ethtool_ioctl_channels_get_num( &ioc, &channels ) );
  if( channels.current!=(dedicated_mode ? channels.max : queue_cnt) ) return 0;

  uint rxfh_queue_cnt;
  FD_TEST( 0==fd_ethtool_ioctl_rxfh_get_queue_cnt( &ioc, &rxfh_queue_cnt ) );
  rxfh_queue_cnt = fd_uint_min( rxfh_queue_cnt, channels.current );

  uint rxfh_table[ FD_ETHTOOL_MAX_RXFH_TABLE_CNT ] = { 0 };
  uint rxfh_table_ele_cnt;
  FD_TEST( 0==fd_ethtool_ioctl_rxfh_get_table( &ioc, rxfh_table, &rxfh_table_ele_cnt ) );
  int rxfh_error = (dedicated_mode && 0U==rxfh_table_ele_cnt);
  uint const start_queue = dedicated_mode ? queue_cnt : 0U;
  for( uint j=0U, q=start_queue; !rxfh_error && j<rxfh_table_ele_cnt; j++) {
    rxfh_error = (rxfh_table[ j ]!=q++);
    if( FD_UNLIKELY( q>=rxfh_queue_cnt ) ) q = start_queue;
  }
  if( rxfh_error ) return 0;

  if( dedicated_mode ) {
    int ntuple_feature_active;
    FD_TEST( 0==fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, &ntuple_feature_active ) );
    if( !ntuple_feature_active ) return 0;
  }

  if( !dedicated_mode ) {
    int ntuple_rules_empty;
    FD_TEST( 0==fd_ethtool_ioctl_ntuple_validate_udp_dport( &ioc, NULL, 0, 0, &ntuple_rules_empty ) );
    if( !ntuple_rules_empty ) return 0;
  } else {
    int ports_valid;
    ushort ports[ 32 ];
    uint port_cnt = get_ports( config, ports );
    FD_TEST( 0==fd_ethtool_ioctl_ntuple_validate_udp_dport( &ioc, ports, port_cnt, queue_cnt, &ports_valid ));
    if( !ports_valid ) return 0;
  }

  return 1;
}

static configure_result_t
check( fd_config_t const * config,
       int                 check_type FD_PARAM_UNUSED ) {
  int only_dedicated =
    (0==strcmp( config->net.xdp.rss_queue_mode, "dedicated" ));
  int check_dedicated = only_dedicated ||
    (0==strcmp( config->net.xdp.rss_queue_mode, "auto" ));

  int  is_bonded  = fd_bonding_is_master( config->net.interface );
  uint device_cnt = 1U;
  if( is_bonded && config->net.xdp.native_bond ) {
    device_cnt = fd_bonding_slave_cnt( config->net.interface );
  }

  if( check_dedicated ) {
    int is_configured = 1;
    if( is_bonded ) {
      fd_bonding_slave_iter_t iter_[1];
      fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
      for( ; is_configured && !fd_bonding_slave_iter_done( iter );
          fd_bonding_slave_iter_next( iter ) ) {
        is_configured = check_device_is_configured( fd_bonding_slave_iter_ele( iter ), config, 1, device_cnt );
      }
    } else {
      is_configured = check_device_is_configured( config->net.interface, config, 1, device_cnt );
    }
    if( is_configured ) CONFIGURE_OK();
  }

  if( !only_dedicated ) {
    int is_configured = 1;
    if( is_bonded ) {
      fd_bonding_slave_iter_t iter_[1];
      fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
      for( ; is_configured && !fd_bonding_slave_iter_done( iter );
          fd_bonding_slave_iter_next( iter ) ) {
        is_configured = check_device_is_configured( fd_bonding_slave_iter_ele( iter ), config, 0, device_cnt );
      }
    } else {
      is_configured = check_device_is_configured( config->net.interface, config, 0, device_cnt );
    }
    if( is_configured ) CONFIGURE_OK();
  }

  int is_modified = 0;
  if( is_bonded ) {
    fd_bonding_slave_iter_t iter_[1];
    fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
    for( ; !is_modified && !fd_bonding_slave_iter_done( iter );
        fd_bonding_slave_iter_next( iter ) ) {
      is_modified = check_device_is_modified( fd_bonding_slave_iter_ele( iter ) );
    }
  } else {
    is_modified = check_device_is_modified( config->net.interface );
  }
  if( is_modified )
    PARTIALLY_CONFIGURED( "device `%s` has partial ethtool-channels network configuration", config->net.interface );

  NOT_CONFIGURED( "device `%s` missing ethtool-channels network configuration", config->net.interface );
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

  /* We leave the ntuple feature flag as-is in fini */
  error |= (0!=fd_ethtool_ioctl_ntuple_clear( &ioc ));

  /* This should happen first, otherwise changing the number of channels may fail */
  error |= (0!=fd_ethtool_ioctl_rxfh_set_default( &ioc ));

  error |= (0!=fd_ethtool_ioctl_channels_set_num( &ioc, 0 /* max */ ));

  /* Some drivers (i40e) do not always evenly redistribute the RXFH table
     when increasing the channel count, so we run this again just in case. */
  error |= (0!=fd_ethtool_ioctl_rxfh_set_default( &ioc ));

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
  if( FD_UNLIKELY( fd_bonding_is_master( config->net.interface ) ) ) {
    fd_bonding_slave_iter_t iter_[1];
    fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_, config->net.interface );
    for( ; !fd_bonding_slave_iter_done( iter );
         fd_bonding_slave_iter_next( iter ) ) {
      done |= fini_device( fd_bonding_slave_iter_ele( iter ) );
    }
  } else {
    done = fini_device( config->net.interface );
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
