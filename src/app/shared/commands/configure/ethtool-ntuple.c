#include "configure.h"
#include "fd_ethtool.h"

#include <errno.h>
#include <sys/ioctl.h> /* ioctl(2) */
#include <linux/if.h> /* struct ifreq */
#include <netinet/ip.h> /* IPPROTO_IP */
#include <linux/ethtool.h> /* ETHTOOL_* */
#include <linux/sockios.h> /* SIOCETHTOOL */
#include <unistd.h> /* close(2) */

#define NAME "ethtool-ntuple"

static int
enabled( config_t const * config ) {

  /* if we're running in a network namespace, we configure ethtool on
     the virtual device as part of netns setup, not here */
  if( config->development.netns.enabled ) return 0;

  /* only enable if network stack is XDP */
  if( 0!=strcmp( config->net.provider, "xdp" ) ) return 0;

  /* only enable if rx_flow_steering mode requires ntuple */
  if( config->net.xdp.rx_flow_steering_ != FD_CONFIG_RX_FLOW_STEERING_NTUPLE ) return 0;

  return 1;
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "set up flow steering with `ethtool --set-channels`" );
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

/* Define a set of UDP4 rules that should be applied */

#define NTUPLE_OK           0
#define NTUPLE_UNKNOWN_PORT 1
#define NTUPLE_MISSING_PORT 2

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
udp_rules_from_config( udp_rules_t *    rules,
                       config_t const * config ) {
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

static int
rule_check( void * ctx,
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

static configure_result_t
check( config_t const * config ) {
  if( FD_UNLIKELY( fd_ethtool_device_is_bonded( config->net.interface ) ) ) {
    FD_LOG_ERR(( "device `%s` does not support [net.xdp.rx_flow_steering] mode \"ntuple\": device is bonded",
                 config->net.interface ));
  }

  int sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
  if( FD_UNLIKELY( sock<0 ) ) FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_IP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  udp_rules_t rules;
  udp_rules_from_config( &rules, config );

  int err = iter_udp4_rules( sock, config->net.interface, rule_check, &rules );
  if( err==NTUPLE_UNKNOWN_PORT ) {
    (void)close( sock );
    NOT_CONFIGURED( "device `%s` has incorrect RX UDP flow steering rules", config->net.interface );
  } else if( err ) {
    FD_LOG_ERR(( "unknown error code %d", err ));
  }

  if( (uint)fd_uint_popcnt( rules.mask )!=rules.rule_cnt ) {
    (void)close( sock );
    NOT_CONFIGURED( "device `%s` is missing some RX UDP flow steering rules", config->net.interface );
  }

  if( FD_UNLIKELY( close( sock ) ) ) {
    FD_LOG_ERR(( "close(socket) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  CONFIGURE_OK();
}

struct rule_install {
  char const * if_name;
  int          sock;
};
typedef struct rule_install rule_install_t;

static int
rule_delete( void * ctx,
             struct ethtool_rx_flow_spec const * fs ) {
  rule_install_t const * rule = ctx;

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
rule_add( rule_install_t const * ctx,
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

static void
init( config_t const * config ) {
  int sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
  if( FD_UNLIKELY( sock<0 ) ) FD_LOG_ERR(( "socket(AF_INET,SOCK_DGRAM,IPPROTO_IP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  iter_udp4_rules( sock, config->net.interface, rule_delete, (void *)(ulong)sock );

  rule_install_t install = {
    .if_name = config->net.interface,
    .sock    = sock
  };
  udp_rules_t rules;
  udp_rules_from_config( &rules, config );
  for( uint i=0U; i<rules.rule_cnt; i++ ) {
    rule_add( &install, rules.rules[i] );
  }

  if( FD_UNLIKELY( close( sock ) ) ) {
    FD_LOG_ERR(( "close(socket) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

configure_stage_t fd_cfg_stage_ethtool_ntuple = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check
};

#undef NAME
