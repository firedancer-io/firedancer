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

#define MAX_FEATURES (1024)
#define MAX_NTUPLE_RULES (1024)
#define MAX_RXFH_TABLE_SIZE (2048)

#define ETHTOOL_CMD_SZ( base_t, data_t, data_len ) ( sizeof(base_t) + (sizeof(data_t)*(data_len)) )

//TODO-AM: Extract much of this into a fd_ethtool_ioctl header

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

static void
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
    if( FD_UNLIKELY( errno != EOPNOTSUPP ) ) {
      FD_LOG_WARNING(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SRXFHINDIR) failed (%i-%s)",
                        errno, fd_io_strerror( errno ) ));
    }
  }

  close( sock );
}

static void
set_device_rxfh_from_idx( char const * device,
                          uint         start_idx ) {
  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = { 0 };
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( ifr.ifr_name ), device, IF_NAMESIZE-1 ));

  /* Get current channel count */
  struct ethtool_channels ech = { 0 };
  ech.cmd = ETHTOOL_GCHANNELS;
  ifr.ifr_data = &ech;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device `%s`, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                 device, errno, fd_io_strerror( errno ) ));
  uint const num_channels = ech.combined_count + ech.rx_count;
  if( FD_UNLIKELY( start_idx >= num_channels ))
    FD_LOG_ERR(( "error configuring network device `%s`, rxfh start index %u"
                 " is too large for current chanenl count %u", device, start_idx, num_channels ));

  union {
    struct ethtool_rxfh_indir m;
    uchar _[ ETHTOOL_CMD_SZ( struct ethtool_rxfh_indir, uint, MAX_RXFH_TABLE_SIZE ) ];
  } rxfh = { 0 };
  ifr.ifr_data = &rxfh;

  /* Get size of rx indirection table */
  rxfh.m.cmd = ETHTOOL_GRXFHINDIR;
  rxfh.m.size = 0;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXFHINDIR) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  uint const table_size = rxfh.m.size;
  if( FD_UNLIKELY( table_size == 0 || table_size > MAX_RXFH_TABLE_SIZE ) )
    FD_LOG_ERR(( "error configuring network device, rxfh table size invalid" ));

  /* Set table to round robin over all channels from [start_idx, num_channels) */
  rxfh.m.cmd = ETHTOOL_SRXFHINDIR;
  rxfh.m.size = table_size;
  uint i = start_idx;
  for(uint j=0u; j<table_size; ++j) {
    rxfh.m.ring_index[ j ] = i++;
    if( i >= num_channels )
      i = start_idx;
  }
  FD_LOG_NOTICE(( "RUN: `ethtool --set-rxfh-indir %s start %u equal %u`",
                  device, start_idx, num_channels - start_idx ));
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SRXFHINDIR) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  close( sock );
}

static void
device_enable_feature_ntuple( char const * device ) {
  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = { 0 };
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( ifr.ifr_name ), device, IF_NAMESIZE-1 ));

  /* Check size of features string set is not too large (prevent overflow) */
  union {
    struct ethtool_sset_info m;
    uchar _[ ETHTOOL_CMD_SZ( struct ethtool_sset_info, uint, 1 ) ];
  } esi = { .m = {
    .cmd = ETHTOOL_GSSET_INFO,
    .sset_mask = fd_ulong_mask_bit( ETH_SS_FEATURES )
  } };
  ifr.ifr_data = &esi;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GSSET_INFO) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( esi.m.data[0] == 0 || esi.m.data[0] > MAX_FEATURES ) )
    FD_LOG_ERR(( "error configuring network device, feature string set size invalid" ));

  /* Get strings from features string set */
  union {
    struct ethtool_gstrings m;
    uchar _[ sizeof(struct ethtool_gstrings) + (MAX_FEATURES * ETH_GSTRING_LEN) ];
  } egs = { 0 };
  egs.m.cmd = ETHTOOL_GSTRINGS;
  egs.m.string_set = ETH_SS_FEATURES;
  ifr.ifr_data = &egs;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GSTRINGS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  int feature_idx = -1;
  for( uint j=0U; j<egs.m.len; ++j) {
    uchar const * gstring = egs.m.data + (j * ETH_GSTRING_LEN);
    if( 0==strncmp( (char const *)gstring, "rx-ntuple-filter", ETH_GSTRING_LEN ) ) {
      feature_idx = (int)j;
      break;
    }
  }
  if( FD_UNLIKELY( feature_idx < 0 ) )
    FD_LOG_ERR(( "error configuring network device, ntuple feature string not found" ));

  /* Now that we know the feature index, enable the ntuple feature */
  FD_LOG_NOTICE(( "RUN: `ethtool --features %s ntuple-filters on`", device ));
  uint feature_block = (uint)feature_idx / 32u;
  uint feature_offset = (uint)feature_idx % 32u;
  union {
    struct ethtool_sfeatures m;
    uchar _[ ETHTOOL_CMD_SZ( struct ethtool_sfeatures, struct ethtool_set_features_block, MAX_FEATURES / 32u ) ];
  } esf = { 0 };
  esf.m.cmd = ETHTOOL_SFEATURES;
  esf.m.size = feature_block + 1;
  esf.m.features[ feature_block ].valid     = 1u<<feature_offset;
  esf.m.features[ feature_block ].requested = 1u<<feature_offset;
  ifr.ifr_data = &esf;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SFEATURES) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  close( sock );
}

static void
device_ntuple_clear( char const * device ) {
  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = { 0 };
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( ifr.ifr_name ), device, IF_NAMESIZE-1 ));

  union {
    struct ethtool_rxnfc m;
    uchar _[ ETHTOOL_CMD_SZ( struct ethtool_rxnfc, uint, MAX_NTUPLE_RULES ) ];
  } efc = { 0 };
  ifr.ifr_data = &efc;

  /* Get count of currently defined rules, return if none exist */
  efc.m.cmd = ETHTOOL_GRXCLSRLCNT;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRLCNT) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));
  uint const rule_cnt = efc.m.rule_cnt;
  if( FD_UNLIKELY( rule_cnt > MAX_NTUPLE_RULES ) )
    FD_LOG_ERR(( "error configuring network device, ntuple rules count invalid" ));
  if( rule_cnt == 0 ) {
    close( sock );
    return;
  }

  /* Get location indexes of all rules */
  efc.m.cmd = ETHTOOL_GRXCLSRLALL;
  efc.m.rule_cnt = rule_cnt;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRLALL) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  /* Delete all rules */
  for( uint i=0u; i<efc.m.rule_cnt; i++) {
    FD_LOG_NOTICE(( "RUN: `ethtool --config-ntuple %s delete %u`", device, efc.m.rule_locs[ i ] ));
    struct ethtool_rxnfc del = { 0 };
    del.cmd = ETHTOOL_SRXCLSRLDEL;
    del.fs.location = efc.m.rule_locs[ i ];
    ifr.ifr_data = &del;
    if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
      FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_SRXCLSRLDEL) failed (%i-%s)",
                   errno, fd_io_strerror( errno ) ));
  }

  close( sock );
}

struct device_channels {
  int  supported;
  uint current;
  uint max;
};
typedef struct device_channels device_channels_t;

static void
get_device_num_channels( char const * device,
                         device_channels_t* channels ) {
  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ethtool_channels ech = { 0 };
  ech.cmd = ETHTOOL_GCHANNELS;

  struct ifreq ifr = { 0 };
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( ifr.ifr_name ), device, IF_NAMESIZE-1 ));
  ifr.ifr_data = &ech;

  channels->supported = 1;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    if( FD_LIKELY( errno == EOPNOTSUPP ) ) {
      /* network device doesn't support getting number of channels, so
         it must always be 1 */
      channels->supported = 0;
      channels->current = 1;
      channels->max = 1;
    } else {
      FD_LOG_ERR(( "error configuring network device `%s`, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                   device, errno, fd_io_strerror( errno ) ));
    }
    close( sock );
    return;
  }

  if( ech.combined_count ) {
    channels->current = ech.combined_count;
    channels->max = ech.max_combined;
  } else if( ech.rx_count || ech.tx_count ) {
    if( FD_UNLIKELY( ech.rx_count != ech.tx_count ) ) {
      FD_LOG_WARNING(( "device `%s` has unbalanced channel count: (got %u rx, %u tx)",
                       device, ech.rx_count, ech.tx_count ));
    }
    channels->current = ech.rx_count;
    channels->max = ech.max_rx;
  } else {
    FD_LOG_ERR(( "error configuring network device `%s`, ETHTOOL_GCHANNELS returned invalid results", device ));
  }

  channels->max = fd_uint_min( channels->max, (uint)fd_shmem_cpu_cnt() );
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
    if( FD_UNLIKELY( net_tile_count != 1 ) )
      FD_LOG_ERR(( "`layout.net_tile_count` must be 1 when `net.xdp.rss_queue_mode` is \"dedicated\"" ));

    set_device_rxfh_from_idx( device, 1 );

    device_enable_feature_ntuple( device );

    device_ntuple_clear( device );
    //TODO-AM
    // for port in udp_ports_from_config:
    //   ethtool --config-ntuple %s flow-type udp4 dst-port %hu queue 0",
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
check_device( char const * device,
              uint         rss_queue_mode,
              uint         net_tile_count ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) FD_LOG_ERR(( "device name `%s` is empty", device ));

  int error = 0;    /* is anything not fully configured */
  int modified = 0; /* is anything changed from the default (fini'd) state */

  /* Set modified bit if num_channels is not the maximum, and set the
   * error bit if it is not correct as per the current rss_queue_mode */
  device_channels_t channels;
  get_device_num_channels( device, &channels );
  if( channels.current != channels.max )
    modified = 1;
  if( rss_queue_mode == FD_CONFIG_NET_XDP_RSS_QUEUE_MODE_SIMPLE ) {
    if( FD_UNLIKELY( channels.current != net_tile_count ) ) {
      error = 1;
      if( FD_UNLIKELY( !channels.supported ) ) {
        FD_LOG_ERR(( "Network device `%s` does not support setting number of channels, "
                     "but you are running with more than one net tile (expected {%u}), "
                     "and there must be one channel per tile. You can either use a NIC "
                     "that supports multiple channels, or run Firedancer with only one "
                     "net tile. You can configure Firedancer to run with only one net "
                     "tile by setting `layout.net_tile_count` to 1 in your "
                     "configuration file.",
                     device, net_tile_count ));
      } else {
        /*TODO shouldn't log in all checks?
        FD_LOG_WARNING(( "device `%s` does not have right number of channels (got %u but "
                         "expected %u)",
                         device, channels.current, net_tile_count ));
                         */
      }
    }
  } else if( rss_queue_mode == FD_CONFIG_NET_XDP_RSS_QUEUE_MODE_DEDICATED ) {
    if( FD_UNLIKELY( channels.current != channels.max ) ) {
      error = 1;
      /*TODO shouldn't log in all checks?
      FD_LOG_WARNING(( "device `%s` does not have right number of channels (got %u but "
                       "expected %u)",
                       device, channels.current, channels.max )); */
    }
  }

  //TODO: Set modified bit if rxfh table is not default
  //TODO: Set error bit if rxfh table is not [0,N) or [1,N] as required by mode

  //TODO: Set error bit if ntuple-filters feature does not exist

  //TODO: Set error bit if ntuple filters do not exactly match desired rules
  //TODO: Set modified bit if any ntuple rules exist

  if( !error )
    CONFIGURE_OK();
  if( modified )
    PARTIALLY_CONFIGURED("TODO");
  NOT_CONFIGURED("TODO");
}

static configure_result_t
check( fd_config_t const * config ) {
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

  /* Note: We leave the ntuple feature enabled */
  device_ntuple_clear( device );
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
