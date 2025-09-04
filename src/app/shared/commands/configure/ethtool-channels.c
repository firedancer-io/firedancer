#include "configure.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

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
  fd_cap_chk_root( chk, NAME, "increase network device channels with `ethtool --set-channels`" );
}

static void
fini_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "TODO" );
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

static int
set_device_rxfh_default( char const * device ) {
  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = { 0 };
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( ifr.ifr_name ), device, IF_NAMESIZE-1 ));

  struct ethtool_rxfh_indir rxfh = {
    .cmd = ETHTOOL_SRXFHINDIR,
    .size = 0, /* default indirection table */
  };
  ifr.ifr_data = &rxfh;

  FD_LOG_NOTICE(( "RUN: `ethtool --set-rxfh-indir %s default`", device ));

  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    FD_LOG_WARNING(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SRXFHINDIR) failed (%i-%s)",
                      errno, fd_io_strerror( errno ) ));
    return -errno;
  }

  close( sock );
  return 0;
}

static void
set_device_num_channels( char const * device,
                         uint num_channels /* 0 for max */ ) {
  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = { 0 };
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( ifr.ifr_name ), device, IF_NAMESIZE-1 ));

  struct ethtool_channels ech = { 0 };
  ech.cmd = ETHTOOL_GCHANNELS;
  ifr.ifr_data = &ech;

  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  if( num_channels == 0 ) {
    uint max_queue_count = fd_uint_max( ech.max_combined, ech.max_rx );
    num_channels = fd_uint_min( max_queue_count, (uint)fd_shmem_cpu_cnt() );
  }

  ech.cmd = ETHTOOL_SCHANNELS;
  if( ech.max_combined ) {
    ech.combined_count = num_channels;
    ech.rx_count       = 0;
    ech.tx_count       = 0;
    FD_LOG_NOTICE(( "RUN: `ethtool --set-channels %s combined %u`", device, num_channels ));
  } else {
    ech.combined_count = 0;
    ech.rx_count       = num_channels;
    ech.tx_count       = num_channels;
    FD_LOG_NOTICE(( "RUN: `ethtool --set-channels %s rx %u tx %u`", device, num_channels, num_channels ));
  }

  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    if( FD_LIKELY( errno == EBUSY ) )
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SCHANNELS) failed (%i-%s). "
                   "This is most commonly caused by an issue with the Intel ice driver on certain versions "
                   "of Ubuntu.  If you are using the ice driver, `sudo dmesg | grep %s` contains "
                   "messages about RDMA, and you do not need RDMA, try running `rmmod irdma` and/or "
                   "blacklisting the irdma kernel module.",
                   errno, fd_io_strerror( errno ), device ));
    else
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SCHANNELS) failed (%i-%s)",
                   errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
init_device( char const * device,
             uint         rss_queue_mode,
             uint         net_tile_count ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) FD_LOG_ERR(( "device name `%s` is empty", device ));

  /* First reset the RXFH indirection table to the default behavior, which
     is to evenly distribute hashes amongst channels regardless of the
     number of channels. This allows us to freely change the number of
     channels. */
  set_device_rxfh_default( device );

  uint num_channels;
  if( rss_queue_mode == FD_CONFIG_NET_XDP_RSS_QUEUE_MODE_SIMPLE ) {
    num_channels = net_tile_count;
  } else {
    num_channels = 0; /* maximum allowed */
  }
  set_device_num_channels( device, num_channels );

  if( rss_queue_mode == FD_CONFIG_NET_XDP_RSS_QUEUE_MODE_DEDICATED ) {
    //TODO-AM: Check net_tile_count == 1

    /* Remove the very first queue from the table and then evenly distribute */
    //RUN( "ethtool --set-rxfh-indir %s start 1 equal %u", device, channel_count - 1 );

    //RUN( "ethtool --features %s ntuple-filters on", device );
    //RUN( "ethtool --show-ntuple %s | awk '/^Filter: /{print $2}' | xargs -r -n1 ethtool --config-ntuple %s delete",
    //     device, device );
    //RUN( "ethtool --config-ntuple %s flow-type udp4 dst-port %hu queue 0",
    //     device, fd_ushort_bswap( 9001 ) );
  }
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
      init_device( token, config->net.xdp.rss_queue_mode_, config->layout.net_tile_count );
    }
  } else {
    init_device( config->net.interface, config->net.xdp.rss_queue_mode_, config->layout.net_tile_count );
  }
}

static configure_result_t
check_device( const char * device,
              uint         rss_queue_mode,
              uint         net_tile_count ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) FD_LOG_ERR(( "device name `%s` is empty", device ));

  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ethtool_channels channels = {0};
  channels.cmd = ETHTOOL_GCHANNELS;

  struct ifreq ifr = {0};
  strncpy( ifr.ifr_name, device, IF_NAMESIZE );
  ifr.ifr_name[ IF_NAMESIZE - 1 ] = '\0'; // silence linter, not needed for correctness
  ifr.ifr_data = (void *)&channels;

  int  supports_channels = 1;
  uint current_channels  = 0;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    if( FD_LIKELY( errno == EOPNOTSUPP ) ) {
      /* network device doesn't support setting number of channels, so
         it must always be 1 */
      supports_channels = 0;
      current_channels  = 1;
    } else {
      FD_LOG_ERR(( "error configuring network device `%s`, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                   device, errno, fd_io_strerror( errno ) ));
    }
  }

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error configuring network device, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( channels.combined_count ) {
    current_channels = channels.combined_count;
  } else if( channels.rx_count || channels.tx_count ) {
    if( FD_UNLIKELY( channels.rx_count != channels.tx_count ) ) {
      NOT_CONFIGURED( "device `%s` has unbalanced channel count: (got %u rx, %u tx)",
                      device, channels.rx_count, channels.tx_count );
    }
    current_channels = channels.rx_count;
  }

  if( rss_queue_mode == FD_CONFIG_NET_XDP_RSS_QUEUE_MODE_SIMPLE ) {
    if( FD_UNLIKELY( current_channels != net_tile_count ) ) {
      if( FD_UNLIKELY( !supports_channels ) ) {
        FD_LOG_ERR(( "Network device `%s` does not support setting number of channels, "
                     "but you are running with more than one net tile (expected {%u}), "
                     "and there must be one channel per tile. You can either use a NIC "
                     "that supports multiple channels, or run Firedancer with only one "
                     "net tile. You can configure Firedancer to run with only one net "
                     "tile by setting `layout.net_tile_count` to 1 in your "
                     "configuration file.",
                     device, net_tile_count ));
      } else {
        NOT_CONFIGURED( "device `%s` does not have right number of channels (got %u but "
                        "expected %u)",
                        device, current_channels, net_tile_count );
      }
    }
  } else if( rss_queue_mode == FD_CONFIG_NET_XDP_RSS_QUEUE_MODE_DEDICATED ) {
    //TODO-AM: Check net_tile_count == 1 ?
    // check expected_queue_count = min(num_phys_cpus, max_queue_count)
    // check ntuple rule for queue0 in place
    //FD_LOG_ERR(( "TODO" ));
  } else {
    FD_LOG_ERR(( "error configuring network device, invalid rss_queue_mode (%u)", rss_queue_mode )); //TODO-AM?
  }

  // check rxfh table sharding across [0,N) or [1,N)
  //TODO-AM check irq affinities?

  CONFIGURE_OK();
}

static configure_result_t
check( config_t const * config ) {
  if( FD_UNLIKELY( device_is_bonded( config->net.interface ) ) ) {
    char line[ 4096 ];
    device_read_slaves( config->net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line, " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      CHECK( check_device( token, config->net.xdp.rss_queue_mode_, config->layout.net_tile_count ) );
    }
  } else {
    CHECK( check_device( config->net.interface, config->net.xdp.rss_queue_mode_, config->layout.net_tile_count ) );
  }

  CONFIGURE_OK();
}

static void
fini_device( char const * device ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) FD_LOG_ERR(( "device name `%s` is empty", device ));

  /* This should happen first, otherwise changing the number of channels may fail */
  set_device_rxfh_default( device );

  set_device_num_channels( device, 0 /* max */ );

  //TODO-AM: Delete all ntuple rules
  /* Note: We leave the ntuple feature enabled */
}

static void
fini( fd_config_t const * config,
      int                 pre_init FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( device_is_bonded( config->net.interface ) ) ) {
    char line[ 4096 ];
    device_read_slaves( config->net.interface, line );
    char * saveptr;
    for( char * token=strtok_r( line , " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      fini_device( token );
    }
  } else {
    fini_device( config->net.interface );
  }
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
