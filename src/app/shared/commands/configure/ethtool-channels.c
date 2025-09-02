/* This configure stage does all ethtool(8) configuration.

   High level steps:

     if( user selected 'ntuple' flow steering ) {
       Set channel count (ETHTOOL_SCHANNELS) to CPU count
         (Such that socket traffic is load-balanced across CPUs)
       Steer Firedancer flows (ETHTOOL_SRXCLSRLINS) to queue 0
         (ntuple flow steering)
       Re-route all other packets (ETHTOOL_SRXFHINDIR) away from queue 0
         (RSS indirection table)
     } else {
       Set channel count (ETHTOOL_SCHANNELS) to 1
     }

   Q: What's "ntuple"?
   A: Linux term for 'flow steering rule', e.g. "send all incoming
      packets with destination UDP port 1234 to queue 3".

   Q: What's an "RSS indirection table"?
   A: 'RSS (receive side scaling)' hashes incoming packets by a flow
      identifier (e.g. 5-tuple) and truncates the hash to a small power
      of 2, e.g. in [0,2048).  The RSS indirection table maps each hash
      value to an RX queue.

   Q: So, what does Firedancer "ntuple" mode do?
   A: It isolates RX queue 0 entirely for Firedancer XDP traffic, such
      that Firedancer's XDP stack and regular socket applications get
      along better (instead of being noisy neighbors on the same CPU).
      This is done by ensuring the RSS indirection table does not
      contain queue 0 for any hash slot.

   Q: Why RX queue 0?
   A: Locality.  The net tile is typically the first tile on CPU 0.  And
      RX queue 0 is typically also served by MSI-X/NAPI softirq
      interrupts on CPU 0.

   Known pitfalls:

   - Specific RXFH indirection table states can cause ethtool channel
     count changes to fail.  This may be painful for operators to
     understand and debug due to lack of upstream documentation.
     Fixed by `ethtool -X <dev> default`.

   Known errata:

   - Firedancer "ntuple" mode does not support Intel E810-like NICs.
     As of Linux 6.12, the ice driver has a bugged implementation of the
     ETHTOOL_GRXFHINDIR ioctl operation, which prevents this code from
     setting up RXFH config.  ice_get_rss_key does not accept a NULL RSS
     context key, which is the default context. */

#include "configure.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h> /* close(2) */
#include <sys/ioctl.h> /* ioctl(2) */
#include <sys/stat.h>
#include <linux/if.h> /* struct ifreq */
#include <linux/ethtool.h> /* ETHTOOL_* */
#include <linux/sockios.h> /* SIOCETHTOOL */
#include <netinet/ip.h> /* IPPROTO_IP */

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

static int
ntuple_is_enabled( fd_config_t const * config ) {
  /* if we're running in a network namespace, we configure ethtool on
     the virtual device as part of netns setup, not here */
  if( config->development.netns.enabled ) return 0;

  /* only enable if network stack is XDP */
  if( 0!=strcmp( config->net.provider, "xdp" ) ) return 0;

  /* only enable if rx_flow_steering mode requires ntuple */
  if( config->net.xdp.rx_flow_steering_ != FD_CONFIG_RX_FLOW_STEERING_NTUPLE ) return 0;

  return 1;
}

/* iter_udp4_rules requests ethtool ntuple rules for the given device.
   Calls cb for every udp4 rule found.  If cb returns non-zero, stops
   iterating and returns cb's return value.  Otherwise, iterates until
   the end and returns zero. */

static int
iter_udp4_rules( int          socket,
                 char const * device,
                 int (* cb)( void * ctx, struct ethtool_rx_flow_spec const * ),
                 void * cb_ctx ) {
  struct ifreq ifr = {0};
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_init( ifr.ifr_name ), device ) );

  /* Get number of RX flow steering rules */
  ulong rule_cnt = 0UL;
  struct ethtool_rxnfc cnt_cmd = {
    .cmd  = ETHTOOL_GRXCLSRLCNT,
    .data = 0
  };
  ifr.ifr_data = (void *)&cnt_cmd;
  if( FD_UNLIKELY( ioctl( socket, SIOCETHTOOL, &ifr ) ) ) {
    FD_LOG_ERR(( "error configuring network device `%s`: ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRLCNT) failed (%i-%s)",
                 device, errno, fd_io_strerror( errno ) ));
  }
  rule_cnt = cnt_cmd.rule_cnt;
  if( !rule_cnt ) return 0;

  /* Get "locations" of RX flow steering rules */
  struct ethtool_rxnfc * idx_cmd = calloc( 1UL, sizeof(struct ethtool_rxnfc)+rule_cnt*sizeof(uint) );
  if( FD_UNLIKELY( !idx_cmd ) ) FD_LOG_ERR(( "out of memory" ));
  idx_cmd->cmd      = ETHTOOL_GRXCLSRLALL;
  idx_cmd->rule_cnt = (uint)rule_cnt;
  ifr.ifr_data = (void *)&idx_cmd;
  if( FD_UNLIKELY( ioctl( socket, SIOCETHTOOL, &ifr ) ) ) {
    if( errno==ENOTSUP ) {
      FD_LOG_ERR(( "error configuring network device `%s`: ethtool ntuple not supported by device.\n"
                   "Consider changing [net.xdp.rx_flow_steering] to \"fewer-queues\".",
                   device ));
    }
    FD_LOG_ERR(( "error configuring network device `%s`: ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRLALL) failed (%i-%s)",
                 device, errno, fd_io_strerror( errno ) ));
  }

  /* Request each flow steering rule */
  int retval = 0;
  for( ulong i=0UL; i<rule_cnt; i++ ) {
    uint loc = idx_cmd->rule_locs[ i ];
    struct ethtool_rxnfc get_cmd = {
      .cmd = ETHTOOL_GRXCLSRULE,
      .fs  = { .location = loc }
    };
    ifr.ifr_data = (void *)&get_cmd;
    if( FD_UNLIKELY( ioctl( socket, SIOCETHTOOL, &ifr ) ) ) {
      FD_LOG_ERR(( "error configuring network device `%s`: ioctl(SIOCETHTOOL,ETHTOOL_GRXCLSRULE(%u)) failed (%i-%s)",
                   device, loc, errno, fd_io_strerror( errno ) ));
    }
    retval = cb( cb_ctx, &get_cmd.fs );
    if( FD_UNLIKELY( retval ) ) break;
  }

  free( idx_cmd );
  return retval;
}

static void
init_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "increase network device channels with `ethtool --set-channels`" );
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
init_device_channels( fd_config_t const * config,
                      char const *        device ) {
  if( FD_UNLIKELY( strlen( device ) >= IF_NAMESIZE ) ) FD_LOG_ERR(( "device name `%s` is too long", device ));
  if( FD_UNLIKELY( strlen( device ) == 0 ) ) FD_LOG_ERR(( "device name `%s` is empty", device ));

  /* Check max channel count */

  int sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error configuring network device, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  struct ethtool_channels channels = {0};
  channels.cmd = ETHTOOL_GCHANNELS;

  struct ifreq ifr = {0};
  strncpy( ifr.ifr_name, device, IF_NAMESIZE-1 );
  ifr.ifr_data = (void *)&channels;

  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) )
    FD_LOG_ERR(( "error configuring network device, ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                 errno, fd_io_strerror( errno ) ));

  /* Derive target channel count */

  uint combined_channel_count;
  if( ntuple_is_enabled( config ) ) {
    combined_channel_count = (uint)fd_shmem_cpu_cnt();
    ulong combined_limit   = fd_ulong_max( channels.combined_count, channels.rx_count );
    combined_channel_count = fd_uint_min( combined_channel_count, (uint)combined_limit );
  } else {
    combined_channel_count = config->layout.net_tile_count;
  }

  channels.cmd = ETHTOOL_SCHANNELS;
  if( channels.max_combined ) {
    channels.combined_count = combined_channel_count;
    channels.rx_count       = 0;
    channels.tx_count       = 0;
    FD_LOG_NOTICE(( "RUN: `ethtool --set-channels %s combined %u`", device, combined_channel_count ));
  } else {
    channels.combined_count = 0;
    channels.rx_count       = combined_channel_count;
    channels.tx_count       = combined_channel_count;
    FD_LOG_NOTICE(( "RUN: `ethtool --set-channels %s rx %u tx %u`", device, combined_channel_count, combined_channel_count ));
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

/* FIXME centrally define this, to avoid this configure stage from
         becoming incompatible in the future */
#define MAX_UDP_PORTS 16u

struct udp_rules {
  ushort rules[ MAX_UDP_PORTS ];
  uint   rule_cnt;
  uint   mask;
};
typedef struct udp_rules udp_rules_t;

static void
udp_rules_push( udp_rules_t * rules,
                ushort        port ) {
  if( FD_UNLIKELY( rules->rule_cnt >= MAX_UDP_PORTS ) ) {
    FD_LOG_ERR(( "too many UDP ports in ntuple rules, max is %u", MAX_UDP_PORTS ));
  }
  /* Skip if rule already exists */
  for( uint i=0U; i<rules->rule_cnt; i++ ) {
    if( rules->rules[ i ]==port ) return;
  }
  /* Add rule */
  rules->rules[ rules->rule_cnt ] = port;
  rules->rule_cnt++;
}

static void
udp_rules_from_config( udp_rules_t *       rules,
                       fd_config_t const * config ) {
  memset( rules, 0, sizeof(udp_rules_t) );
  /* FIXME centrally define listen port list to avoid this configure
           stage from going out of sync with port mappings */
  udp_rules_push( rules, config->tiles.shred.shred_listen_port );
  udp_rules_push( rules, config->tiles.quic.quic_transaction_listen_port );
  udp_rules_push( rules, config->tiles.quic.regular_transaction_listen_port );
  if( config->is_firedancer ) {
    udp_rules_push( rules, config->gossip.port );
    udp_rules_push( rules, config->tiles.repair.repair_intake_listen_port );
    udp_rules_push( rules, config->tiles.repair.repair_serve_listen_port );
    udp_rules_push( rules, config->tiles.send.send_src_port );
  }
}

struct ntuple_rule_install {
  char const * if_name;
  int          sock;
};
typedef struct ntuple_rule_install ntuple_rule_install_t;

static int
ntuple_rule_delete( void * ctx,
                    struct ethtool_rx_flow_spec const * fs ) {
  ntuple_rule_install_t const * rule = ctx;

  struct ethtool_rxnfc cmd = {
    .cmd = ETHTOOL_SRXCLSRLDEL,
    .fs  = { .location = fs->location }
  };
  struct ifreq ifr = {0};
  strncpy( ifr.ifr_name, rule->if_name, IF_NAMESIZE-1 );
  ifr.ifr_data = (void *)&cmd;
  if( FD_UNLIKELY( ioctl( rule->sock, SIOCETHTOOL, (void *)&ifr ) ) ) {
    FD_LOG_ERR(( "failed to install RX flow steering entry to `%s`: ioctl(SIOCETHTOOL,ETHTOOL_SRXCLSRLDEL) failed (%i-%s)",
                 rule->if_name, errno, fd_io_strerror( errno ) ));
  }
  return 0;
}

static void
ntuple_rule_add( ntuple_rule_install_t const * ctx,
                 ushort                 port ) {
  struct ethtool_rxnfc cmd = {
    .cmd = ETHTOOL_SRXCLSRLINS,
    .fs  = {
      .flow_type = UDP_V4_FLOW,
      .h_u = { .udp_ip4_spec = {
        .pdst = fd_ushort_bswap( port ),
      }},
      .m_u = { .udp_ip4_spec = {
        .pdst = 0xFFFF,
      }},
      .ring_cookie = 0, /* steer to queue 0 */
      .location    = RX_CLS_LOC_ANY
    }
  };
  struct ifreq ifr = {0};
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_init( ifr.ifr_name ), ctx->if_name ) );
  ifr.ifr_data = (void *)&cmd;
  if( FD_UNLIKELY( ioctl( ctx->sock, SIOCETHTOOL, (void *)&ifr ) ) ) {
    FD_LOG_ERR(( "failed to install RX flow steering entry to `%s`: ioctl(SIOCETHTOOL,ETHTOOL_SRXCLSRULE) failed (%i-%s)",
                  ctx->if_name, errno, fd_io_strerror( errno ) ));
  }
}

/* Define a set of UDP4 rules that should be applied */

#define NTUPLE_OK           0
#define NTUPLE_UNKNOWN_PORT 1
#define NTUPLE_MISSING_PORT 2

static int
ntuple_rule_check( void * ctx,
                   struct ethtool_rx_flow_spec const * fs ) {
  udp_rules_t * rules = ctx;
  if( fs->flow_type!=UDP_V4_FLOW ) return 0;
  struct ethtool_tcpip4_spec const * udp_spec = &fs->h_u.udp_ip4_spec;
  /* FIXME check masks and dst port rule ... in the unlikely case a user
     created a conflicting flow rule with a mask */
  uint rule_idx;
  for( rule_idx=0U; rule_idx<MAX_UDP_PORTS; rule_idx++ ) {
    if( rule_idx>=rules->rule_cnt ) continue;
    if( rules->rules[ rule_idx ]==fd_ushort_bswap( udp_spec->pdst ) ) break;
  }
  if( rule_idx==MAX_UDP_PORTS ) return NTUPLE_UNKNOWN_PORT;
  /* Mark element as found */
  fd_uint_set_bit( rules->mask, (int)rule_idx );
  return NTUPLE_OK;
}

static void
init_device_ntuple( fd_config_t const * config,
                    char const *        device ) {
  int sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
  if( FD_UNLIKELY( sock<0 ) ) FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_IP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  iter_udp4_rules( sock, device, ntuple_rule_delete, (void *)(ulong)sock );

  ntuple_rule_install_t install = {
    .if_name = device,
    .sock    = sock
  };
  udp_rules_t rules;
  udp_rules_from_config( &rules, config );
  for( uint i=0U; i<rules.rule_cnt; i++ ) {
    ntuple_rule_add( &install, rules.rules[i] );
  }

  if( FD_UNLIKELY( close( sock ) ) ) {
    FD_LOG_ERR(( "close(socket) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static void
init_device_rxfh( char const * device,
                  uint         start ) {
  int sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
  if( FD_UNLIKELY( sock<0 ) ) FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_IP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = {0};
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_init( ifr.ifr_name ), device ) );

  /* Get number of ethtool channels */
  struct ethtool_channels channels = {
    .cmd = ETHTOOL_GCHANNELS
  };
  ifr.ifr_data = (void *)&channels;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    FD_LOG_ERR(( "error configuring network device `%s`: ioctl(SIOCETHTOOL,ETHTOOL_GCHANNELS) failed (%i-%s)",
                 device, errno, fd_io_strerror( errno ) ));
  }
  uint rx_cnt = channels.rx_count + channels.combined_count;
  if( FD_UNLIKELY( !rx_cnt ) ) {
    FD_LOG_ERR(( "error configuring network device `%s`: ethtool reports device has no RX or combined channels", device ));
  }

  /* Get size of RXFH indirection table */
  struct ethtool_rxfh_indir rxfh_peek = {
    .cmd  = ETHTOOL_GRXFHINDIR,
    .size = 0
  };
  ifr.ifr_data = (void *)&rxfh_peek;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    if( errno==ENOTSUP ) {
      FD_LOG_ERR(( "error configuring network device `%s`: ethtool rxfh not supported by device.\n"
                   "Consider changing [net.xdp.rx_flow_steering] to \"fewer-queues\".",
                   device ));
    }
    FD_LOG_ERR(( "error configuring network device `%s`: ioctl(SIOCETHTOOL,ETHTOOL_GRXFHINDIR) failed (%i-%s)",
                 device, errno, fd_io_strerror( errno ) ));
  }
  ulong const rxfh_max = rxfh_peek.size;
  if( FD_UNLIKELY( !rxfh_max ) ) {
    FD_LOG_ERR(( "error configuring network device `%s`: ethtool RXFH indirection table has no entries",
                 device ));
  }

  /* Generate RXFH indirection table */
  struct ethtool_rxfh_indir * rxfh_get = calloc( 1UL, sizeof(struct ethtool_rxfh_indir) + rxfh_max*sizeof(uint) );
  if( FD_UNLIKELY( !rxfh_get ) ) FD_LOG_ERR(( "out of memory" ));
  rxfh_get->cmd   = ETHTOOL_SRXFHINDIR;
  rxfh_get->size  = (uint)rxfh_max;
  ifr.ifr_data    = (void *)rxfh_get;
  uint next_queue = start;
  for( ulong j=0UL; j<rxfh_max; j++ ) {
    rxfh_get->ring_index[ j ] = next_queue;
    next_queue++;
    if( next_queue>=rx_cnt ) next_queue = start;
  }
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    free( rxfh_get );
    FD_LOG_ERR(( "error configuring network device `%s`: ioctl(SIOCETHTOOL,ETHTOOL_GRXFHINDIR,.size=%lu) failed (%i-%s)",
                 device, rxfh_max, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( close( sock ) ) ) {
    FD_LOG_ERR(( "close(socket) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}


static void
init( fd_config_t const * config ) {
  /* we need one channel for both TX and RX on the NIC for each QUIC
     tile, but the interface probably defaults to one channel total */
  char const * device = config->net.interface;
  if( FD_UNLIKELY( device_is_bonded( device ) ) ) {
    /* if using a bonded device, we need to set channels on the
       underlying devices. */
    char line[ 4096 ];
    device_read_slaves( device, line );
    char * saveptr;
    for( char * token=strtok_r( line , " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      /* FIXME slave device channels counts should probably lower */
      init_device_channels( config, token );
    }
  } else {
    init_device_channels( config, device );
    if( ntuple_is_enabled( config ) ) {
      init_device_ntuple( config, device );
      init_device_rxfh( device, 1 );
    }
  }
}

static configure_result_t
check_device_channels( fd_config_t const * config,
                       char const *        device ) {
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

  /* Derive target channel count */

  uint expected_channel_count;
  if( ntuple_is_enabled( config ) ) {
    expected_channel_count = (uint)fd_shmem_cpu_cnt();
    ulong combined_limit   = fd_ulong_max( channels.combined_count, channels.rx_count );
    expected_channel_count = fd_uint_min( expected_channel_count, (uint)combined_limit );
  } else {
    expected_channel_count = config->layout.net_tile_count;
  }

  if( channels.combined_count ) {
    current_channels = channels.combined_count;
  } else if( channels.rx_count || channels.tx_count ) {
    if( FD_UNLIKELY( channels.rx_count != channels.tx_count ) ) {
      NOT_CONFIGURED( "device `%s` has unbalanced channel count: (got %u rx, %u tx, expected %u)",
                      device, channels.rx_count, channels.tx_count, expected_channel_count );
    }
    current_channels = channels.rx_count;
  }

  if( FD_UNLIKELY( current_channels != expected_channel_count ) ) {
    if( FD_UNLIKELY( !supports_channels ) ) {
      FD_LOG_ERR(( "Network device `%s` does not support setting number of channels, "
                   "but you are running with more than one net tile (expected {%u}), "
                   "and there must be one channel per tile. You can either use a NIC "
                   "that supports multiple channels, or run Firedancer with only one "
                   "net tile. You can configure Firedancer to run with only one QUIC "
                   "tile by setting `layout.net_tile_count` to 1 in your "
                   "configuration file. It is not recommended to do this in production "
                   "as it will limit network performance.",
                   device, expected_channel_count ));
    } else {
      NOT_CONFIGURED( "device `%s` does not have right number of channels (got %u but "
                      "expected %u)",
                      device, current_channels, expected_channel_count );
    }
  }

  CONFIGURE_OK();
}

struct fd_ethtool_nl {
  int fd;
};

typedef struct fd_ethtool_nl fd_ethtool_nl_t;

extern fd_ethtool_nl_t *
fd_ethtool_nl_init( void ) ;

static configure_result_t
check_device_ntuple( fd_config_t const * config,
                     char const *        device ) {
  if( FD_UNLIKELY( device_is_bonded( device ) ) ) {
    FD_LOG_ERR(( "device `%s` does not support [net.xdp.rx_flow_steering] mode \"ntuple\": device is bonded",
                 device ));
  }

  int sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
  if( FD_UNLIKELY( sock<0 ) ) FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_IP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  udp_rules_t rules;
  udp_rules_from_config( &rules, config );

  int err = iter_udp4_rules( sock, device, ntuple_rule_check, &rules );
  if( err==NTUPLE_UNKNOWN_PORT ) {
    (void)close( sock );
    NOT_CONFIGURED( "device `%s` has incorrect RX UDP flow steering rules", device );
  } else if( err ) {
    FD_LOG_ERR(( "unknown error code %d", err ));
  }

  if( (uint)fd_uint_popcnt( rules.mask )!=rules.rule_cnt ) {
    (void)close( sock );
    NOT_CONFIGURED( "device `%s` is missing some RX UDP flow steering rules", device );
  }

  if( FD_UNLIKELY( close( sock ) ) ) {
    FD_LOG_ERR(( "close(socket) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  CONFIGURE_OK();
}


static configure_result_t
check_device_rxfh( char const * device ) {
  int sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
  if( FD_UNLIKELY( sock<0 ) ) FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_IP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct ifreq ifr = {0};
  fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_init( ifr.ifr_name ), device ) );

  /* Get size of RXFH indirection table */
  struct ethtool_rxfh_indir rxfh_peek = {
    .cmd  = ETHTOOL_GRXFHINDIR,
    .size = 0
  };
  ifr.ifr_data = (void *)&rxfh_peek;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    if( errno==ENOTSUP ) {
      FD_LOG_ERR(( "error configuring network device `%s`: ethtool rxfh not supported by device.\n"
                   "Consider changing [net.xdp.rx_flow_steering] to \"fewer-queues\".",
                   device ));
    }
    FD_LOG_ERR(( "error configuring network device `%s`: ioctl(SIOCETHTOOL,ETHTOOL_GRXFHINDIR) failed (%i-%s)",
                 device, errno, fd_io_strerror( errno ) ));
  }

  /* Actually download RXFH indirection table */
  ulong const rxfh_max = rxfh_peek.size;
  if( FD_UNLIKELY( !rxfh_max ) ) {
    FD_LOG_ERR(( "error configuring network device `%s`: ethtool RXFH indirection table has no entries",
                 device ));
  }
  struct ethtool_rxfh_indir * rxfh_get = calloc( 1UL, sizeof(struct ethtool_rxfh_indir) + rxfh_max*sizeof(uint) );
  if( FD_UNLIKELY( !rxfh_get ) ) FD_LOG_ERR(( "out of memory" ));
  rxfh_get->cmd  = ETHTOOL_GRXFHINDIR;
  rxfh_get->size = (uint)rxfh_max;
  ifr.ifr_data   = (void *)rxfh_get;
  if( FD_UNLIKELY( ioctl( sock, SIOCETHTOOL, &ifr ) ) ) {
    free( rxfh_get );
    FD_LOG_ERR(( "error configuring network device `%s`: ioctl(SIOCETHTOOL,ETHTOOL_GRXFHINDIR,.size=%lu) failed (%i-%s)",
                 device, rxfh_max, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( close( sock ) ) ) {
    FD_LOG_ERR(( "close(socket) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Ensure that default RXFH indir table doesn't steer to queue zero */
  int ok = 1;
  ulong const rxfh_cnt = fd_ulong_min( rxfh_get->size, rxfh_max );
  for( ulong i=0UL; i<rxfh_cnt; i++ ) {
    if( rxfh_get->ring_index[ i ]==0U ) ok = 0;
  }
  free( rxfh_get );

  /* FIXME verify that RXFH indir table load balances uniformly across
     all channels */

  if( !ok ) NOT_CONFIGURED( "device `%s` rxfh-indir table is not set up (queue 0 is not isolated from default flow steering rules)", device );
  else      CONFIGURE_OK();
}

static configure_result_t
check( fd_config_t const * config ) {
  int const ntuple_enabled = ntuple_is_enabled( config );

  fd_ethtool_nl_init();

  char const * device = config->net.interface;
  if( FD_UNLIKELY( device_is_bonded( device ) ) ) {
    char line[ 4096 ];
    device_read_slaves( device, line );
    char * saveptr;
    for( char * token=strtok_r( line, " \t", &saveptr ); token!=NULL; token=strtok_r( NULL, " \t", &saveptr ) ) {
      CHECK( check_device_channels( config, token ) );
    }
    if( FD_UNLIKELY( ntuple_enabled ) ) {
      NOT_CONFIGURED( "device `%s` does not support [net.xdp.rx_flow_steering] mode \"ntuple\": device is bonded", device );
    }
  } else {
    CHECK( check_device_channels( config, device ) );
    if( ntuple_enabled ) {
      check_device_ntuple( config, device );
      check_device_rxfh( device );
    }
  }

  CONFIGURE_OK();
}

static void
fini( fd_config_t const * config,
      int                 pre_init ) {
  (void)pre_init;
  char const * const device = config->net.interface;
  init_device_rxfh( device, 0U ); /* reset RXFH to default config */
}

configure_stage_t fd_cfg_stage_ethtool_channels = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
