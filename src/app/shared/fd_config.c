#define _GNU_SOURCE
#include "fd_config.h"
#include "fd_config_auto.h"
#include "fd_config_private.h"

#include "../platform/fd_net_util.h"
#include "../platform/fd_sys_util.h"
#include "../../ballet/toml/fd_toml.h"
#include "../../disco/genesis/fd_genesis_cluster.h"
#include "../../discof/genesis/fd_genesi_tile.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../disco/pack/fd_microblock.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../discof/restore/utils/fd_ssarchive.h"

#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h> /* strtoul */
#include <sys/utsname.h>
#include <sys/mman.h>

int
fd_config_str_set( fd_config_t *   config,
                   fd_topo_str_t * s,
                   char const *    str,
                   ulong           len ) {
  if( FD_UNLIKELY( len>=sizeof(config->strs)-config->strs_len ) ) return 0;
  char * dst = config->strs + config->strs_len;
  memmove( dst, str, len );
  dst[ len ] = '\0';
  config->strs_len += len+1UL;
  s->rel = (int)( dst - (char *)s );
  return 1;
}

int
fd_config_str_printf( fd_config_t *   config,
                      fd_topo_str_t * s,
                      char const *    fmt, ... ) {
  ulong cap = sizeof(config->strs)-config->strs_len;
  if( FD_UNLIKELY( !cap ) ) return 0;
  char * dst = config->strs + config->strs_len;
  va_list ap;
  va_start( ap, fmt );
  int n = vsnprintf( dst, cap, fmt, ap );
  va_end( ap );
  if( FD_UNLIKELY( n<0 || (ulong)n>=cap ) ) return 0;
  config->strs_len += (ulong)n+1UL;
  s->rel = (int)( dst - (char *)s );
  return 1;
}

/* replace substitutes the first occurrence of pat in *s with sub. */

static void
replace( fd_config_t *   config,
         fd_topo_str_t * s,
         const char *    pat,
         const char *    sub ) {
  char const * in  = fd_topo_str( s );
  char const * hit = strstr( in, pat );
  if( FD_LIKELY( hit ) ) {
    ulong pre_len = (ulong)( hit - in );
    ulong pat_len = strlen( pat );
    ulong sub_len = strlen( sub );
    ulong in_len  = strlen( in );

    ulong total_len = in_len - pat_len + sub_len;
    if( FD_UNLIKELY( total_len>=sizeof(config->strs)-config->strs_len ) )
      FD_LOG_ERR(( "configuration string storage exhausted while expanding `%s`", in ));

    char * out = config->strs + config->strs_len;
    fd_memcpy( out,                 in,          pre_len );
    fd_memcpy( out+pre_len,         sub,         sub_len );
    fd_memcpy( out+pre_len+sub_len, hit+pat_len, in_len-pre_len-pat_len );
    FD_TEST( fd_config_str_set( config, s, out, total_len ) );
  }
}


FD_FN_CONST static inline int
parse_log_level( char const * level ) {
  if( FD_UNLIKELY( !strcmp( level, "DEBUG" ) ) )    return 0;
  if( FD_UNLIKELY( !strcmp( level, "INFO"  ) ) )    return 1;
  if( FD_UNLIKELY( !strcmp( level, "NOTICE"  ) ) )  return 2;
  if( FD_UNLIKELY( !strcmp( level, "WARNING"  ) ) ) return 3;
  if( FD_UNLIKELY( !strcmp( level, "ERR" ) ) )      return 4;
  if( FD_UNLIKELY( !strcmp( level, "CRIT" ) ) )     return 5;
  if( FD_UNLIKELY( !strcmp( level, "ALERT" ) ) )    return 6;
  if( FD_UNLIKELY( !strcmp( level, "EMERG" ) ) )    return 7;
  return -1;
}

FD_FN_CONST static inline int
parse_core_dump_level( char const * level ) {
  if( FD_UNLIKELY( !strcmp( level, "disabled" ) ) )       return FD_TOPO_CORE_DUMP_LEVEL_DISABLED;
  if( FD_UNLIKELY( !strcmp( level, "minimal"  ) ) )       return FD_TOPO_CORE_DUMP_LEVEL_MINIMAL;
  if( FD_UNLIKELY( !strcmp( level, "regular"  ) ) )       return FD_TOPO_CORE_DUMP_LEVEL_REGULAR;
  if( FD_UNLIKELY( !strcmp( level, "full"     ) ) )       return FD_TOPO_CORE_DUMP_LEVEL_FULL;
  return -1;
}

#define FD_CONFIG_TOML_BUF_SZ   (1UL<<18)
#define FD_CONFIG_TOML_NODE_MAX (8192UL)

int
fd_config_toml_parse( fd_toml_doc_t *      doc,
                      char const *         buf,
                      ulong                sz,
                      fd_toml_err_info_t * opt_err ) {
  static char           toml_buf  [ FD_CONFIG_TOML_BUF_SZ   ];
  static fd_toml_node_t toml_nodes[ FD_CONFIG_TOML_NODE_MAX ];
  if( FD_UNLIKELY( sz>sizeof(toml_buf) ) ) FD_LOG_ERR(( "config file too large (%lu bytes, max %lu)", sz, sizeof(toml_buf) ));
  fd_memcpy( toml_buf, buf, sz );
  return fd_toml_parse( doc, toml_buf, sz, toml_nodes, FD_CONFIG_TOML_NODE_MAX, opt_err );
}

void
fd_config_load_buf( fd_config_t * out,
                    char const *  buf,
                    ulong         sz,
                    char const *  path ) {
  fd_toml_doc_t      doc[1];
  fd_toml_err_info_t toml_err[1];
  int toml_errc = fd_config_toml_parse( doc, buf, sz, toml_err );
  if( FD_UNLIKELY( toml_errc!=FD_TOML_SUCCESS ) ) {
    switch( toml_errc ) {
    case FD_TOML_ERR_NODE:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: too many keys", path, toml_err->line ));
      break;
    case FD_TOML_ERR_DUP:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: duplicate key", path, toml_err->line ));
      break;
    case FD_TOML_ERR_RANGE:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: invalid value for key", path, toml_err->line ));
      break;
    case FD_TOML_ERR_PARSE:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu", path, toml_err->line ));
      break;
    default:
      FD_LOG_ERR(( "Failed to parse config file (%s): %s", path, fd_toml_strerror( toml_errc ) ));
      break;
    }
  }

  if( FD_UNLIKELY( !fd_config_extract_toml( doc, out ) ) ) FD_LOG_ERR(( "Failed to parse config file (%s): there are unrecognized keys logged above", path ));
}

static void
fd_config_fillf( fd_config_t * config ) {
  char const * user = FD_TOPO_STR( config->user );
  char const * name = FD_TOPO_STR( config->name );
  char const * base = FD_TOPO_STR( config->paths.base );

  if( FD_UNLIKELY( FD_TOPO_STR( config->paths.accounts )[0] ) ) {
    replace( config, &config->paths.accounts, "{user}", user );
    replace( config, &config->paths.accounts, "{name}", name );
  } else {
    FD_TEST( fd_config_str_printf( config, &config->paths.accounts, "%s/accounts.db", base ) );
  }

  if( FD_UNLIKELY( FD_TOPO_STR( config->paths.shredb )[0] ) ) {
    replace( config, &config->paths.shredb, "{user}", user );
    replace( config, &config->paths.shredb, "{name}", name );
  } else {
    FD_TEST( fd_config_str_printf( config, &config->paths.shredb, "%s/shreds.db", base ) );
  }

  if( FD_UNLIKELY( FD_TOPO_STR( config->paths.guidb )[0] ) ) {
    replace( config, &config->paths.guidb, "{user}", user );
    replace( config, &config->paths.guidb, "{name}", name );
  } else {
    FD_TEST( fd_config_str_printf( config, &config->paths.guidb, "%s/gui.db", base ) );
  }

  for( ulong i=0UL; i<config->firedancer.paths.authorized_voter_paths_cnt; i++ ) {
    replace( config, &config->firedancer.paths.authorized_voter_paths[ i ], "{user}", user );
    replace( config, &config->firedancer.paths.authorized_voter_paths[ i ], "{name}", name );
  }
}

static void
fd_config_fillh( fd_config_t * config ) {
  char const * user = FD_TOPO_STR( config->user );
  char const * name = FD_TOPO_STR( config->name );
  char const * base = FD_TOPO_STR( config->paths.base );

  if( FD_UNLIKELY( FD_TOPO_STR( config->frankendancer.paths.accounts_path )[0] ) ) {
    replace( config, &config->frankendancer.paths.accounts_path, "{user}", user );
    replace( config, &config->frankendancer.paths.accounts_path, "{name}", name );
  }

  if( FD_UNLIKELY( FD_TOPO_STR( config->frankendancer.paths.ledger )[0] ) ) {
    replace( config, &config->frankendancer.paths.ledger, "{user}", user );
    replace( config, &config->frankendancer.paths.ledger, "{name}", name );
  } else {
    FD_TEST( fd_config_str_printf( config, &config->frankendancer.paths.ledger, "%s/ledger", base ) );
  }

  if( FD_UNLIKELY( FD_TOPO_STR( config->frankendancer.snapshots.path )[0] ) ) {
    replace( config, &config->frankendancer.snapshots.path, "{user}", user );
    replace( config, &config->frankendancer.snapshots.path, "{name}", name );
  } else {
    char const * ledger = FD_TOPO_STR( config->frankendancer.paths.ledger );
    FD_TEST( fd_config_str_set( config, &config->frankendancer.snapshots.path, ledger, strlen( ledger ) ) );
  }

  for( ulong i=0UL; i<config->frankendancer.paths.authorized_voter_paths_cnt; i++ ) {
    replace( config, &config->frankendancer.paths.authorized_voter_paths[ i ], "{user}", user );
    replace( config, &config->frankendancer.paths.authorized_voter_paths[ i ], "{name}", name );
  }

  if( FD_UNLIKELY( config->tiles.quic.quic_transaction_listen_port!=config->tiles.quic.regular_transaction_listen_port+6 ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be 6 more than [tiles.quic.regular_transaction_listen_port] `%hu`",
                 config->tiles.quic.quic_transaction_listen_port,
                 config->tiles.quic.regular_transaction_listen_port ));

  char dynamic_port_range[ 32 ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( dynamic_port_range, sizeof(dynamic_port_range), NULL, "%s", FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ) ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ));

  char * dash = strstr( dynamic_port_range, "-" );
  if( FD_UNLIKELY( !dash ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ));

  *dash = '\0';
  char * endptr;
  ulong agave_port_min = strtoul( dynamic_port_range, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || agave_port_min > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ));
  ulong agave_port_max = strtoul( dash + 1, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || agave_port_max > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ));
  if( FD_UNLIKELY( agave_port_min > agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "The minimum port must be less than or equal to the maximum port",
                 FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ));

  if( FD_UNLIKELY( config->tiles.quic.regular_transaction_listen_port >= agave_port_min &&
                   config->tiles.quic.regular_transaction_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 config->tiles.quic.regular_transaction_listen_port,
                 FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ));

  if( FD_UNLIKELY( config->tiles.quic.quic_transaction_listen_port >= agave_port_min &&
                   config->tiles.quic.quic_transaction_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 config->tiles.quic.quic_transaction_listen_port,
                 FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ));

  if( FD_UNLIKELY( config->tiles.shred.shred_listen_port >= agave_port_min &&
                   config->tiles.shred.shred_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.shred.shred_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 config->tiles.shred.shred_listen_port,
                 FD_TOPO_STR( config->frankendancer.dynamic_port_range ) ));
}

static void
fd_config_fill_net( fd_config_t * config ) {
  if( FD_UNLIKELY( !FD_TOPO_STR( config->net.interface )[0] ) ) {
    uint ifindex;
    int result = fd_net_util_internet_ifindex( &ifindex );
    if( FD_UNLIKELY( -1==result && errno!=ENODEV ) ) FD_LOG_ERR(( "could not get network device index (%i-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( -1==result ) )
      FD_LOG_ERR(( "no network device found which routes to 8.8.8.8. If no network "
                   "interface is specified in the configuration file, Firedancer "
                   "tries to use the first network interface found which routes to "
                   "8.8.8.8. You can see what this is by running `ip route get 8.8.8.8` "
                   "You can fix this error by specifying a network interface to bind to in "
                   "your configuration file under [net.interface]" ));

    char interface[ IF_NAMESIZE ];
    if( FD_UNLIKELY( !if_indextoname( ifindex, interface ) ) )
      FD_LOG_ERR(( "could not get name of interface with index %u", ifindex ));
    FD_TEST( fd_config_str_set( config, &config->net.interface, interface, strlen( interface ) ) );
  }

  if( FD_UNLIKELY( !if_nametoindex( FD_TOPO_STR( config->net.interface ) ) ) )
    FD_LOG_ERR(( "configuration specifies network interface `%s` which does not exist", FD_TOPO_STR( config->net.interface ) ));
  uint iface_ip;
  if( FD_UNLIKELY( -1==fd_net_util_if_addr( FD_TOPO_STR( config->net.interface ), &iface_ip ) ) )
    FD_LOG_ERR(( "could not get IP address for interface `%s`", FD_TOPO_STR( config->net.interface ) ));

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    if( FD_UNLIKELY( strcmp( FD_TOPO_STR( config->firedancer.gossip.host ), "" ) ) ) {
      uint gossip_ip_addr = iface_ip;
      int  has_gossip_ip4 = 0;
      if( FD_UNLIKELY( strlen( FD_TOPO_STR( config->firedancer.gossip.host ) )<=15UL ) ) {
        /* Only sets gossip_ip_addr if it's a valid IPv4 address, otherwise assume it's a DNS name */
        has_gossip_ip4 = fd_cstr_to_ip4_addr( FD_TOPO_STR( config->firedancer.gossip.host ), &gossip_ip_addr );
      }
      if( FD_UNLIKELY( !fd_ip4_addr_is_public( gossip_ip_addr ) && config->is_live_cluster && has_gossip_ip4 ) )
        FD_LOG_ERR(( "Trying to use [gossip.host] " FD_IP4_ADDR_FMT " for listening to incoming "
                     "transactions, but it is part of a private network and will not be routable "
                     "for other Solana network nodes.", FD_IP4_ADDR_FMT_ARGS( gossip_ip_addr ) ));
    } else if( FD_UNLIKELY( !fd_ip4_addr_is_public( iface_ip ) && config->is_live_cluster ) ) {
      FD_LOG_ERR(( "Trying to use network interface `%s` for listening to incoming transactions, "
                   "but it has IPv4 address " FD_IP4_ADDR_FMT " which is part of a private network "
                   "and will not be routable for other Solana network nodes. If you are running "
                   "behind a NAT and this interface is publicly reachable, you can continue by "
                   "manually specifying the IP address to advertise in your configuration under "
                   "[gossip.host].", FD_TOPO_STR( config->net.interface ), FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
    }
  }

  config->net.ip_addr = iface_ip;
}

void
fd_config_fill( fd_config_t * config,
                int           is_local_cluster,
                int           dev ) {
  struct utsname utsname;
  if( FD_UNLIKELY( -1==uname( &utsname ) ) )
    FD_LOG_ERR(( "could not get uname (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_cstr_ncpy( config->hostname, utsname.nodename, sizeof(config->hostname) ); /* Just truncate the name if it's too long to fit */

  ulong cluster;
  if( FD_UNLIKELY( !config->is_firedancer ) ) cluster = fd_genesis_cluster_identify( FD_TOPO_STR( config->frankendancer.consensus.expected_genesis_hash ) );
  else                                        cluster = fd_genesis_cluster_identify( FD_TOPO_STR( config->consensus.expected_genesis_hash ) );
  config->is_live_cluster = cluster!=FD_CLUSTER_UNKNOWN;
  strcpy( config->cluster, fd_genesis_cluster_name( cluster ) );

  if( FD_UNLIKELY( !FD_TOPO_STR( config->user )[0] ) ) {
    const char * user = fd_sys_util_login_user();
    if( FD_UNLIKELY( !user ) )                                                                 FD_LOG_ERR(( "could not automatically determine a user to run Firedancer as. You must specify a [user] in your configuration TOML file." ));
    if( FD_UNLIKELY( strlen( user )>=256UL ) )                                                 FD_LOG_ERR(( "user name `%s` is too long", user ));
    FD_TEST( fd_config_str_set( config, &config->user, user, strlen( user ) ) );
  }

  if( FD_UNLIKELY( -1==fd_sys_util_user_to_uid( FD_TOPO_STR( config->user ), &config->uid, &config->gid ) ) ) FD_LOG_ERR(( "configuration file wants firedancer to run as user `%s` but it does not exist", FD_TOPO_STR( config->user ) ));
  if( FD_UNLIKELY( !config->uid || !config->gid ) )                                            FD_LOG_ERR(( "firedancer cannot run as root. please specify a non-root user in the configuration file" ));
  if( FD_UNLIKELY( getuid()!=0U && config->uid!=getuid() ) )                                   FD_LOG_ERR(( "running as uid %u, but config specifies uid %u", getuid(), config->uid ));
  if( FD_UNLIKELY( getgid()!=0U && config->gid!=getgid() ) )                                   FD_LOG_ERR(( "running as gid %u, but config specifies gid %u", getgid(), config->gid ));

  FD_TEST( fd_config_str_printf( config, &config->hugetlbfs.gigantic_page_mount_path, "%s/.gigantic", FD_TOPO_STR( config->hugetlbfs.mount_path ) ) );
  FD_TEST( fd_config_str_printf( config, &config->hugetlbfs.huge_page_mount_path,      "%s/.huge",     FD_TOPO_STR( config->hugetlbfs.mount_path ) ) );

  ulong max_page_sz = fd_cstr_to_shmem_page_sz( FD_TOPO_STR( config->hugetlbfs.max_page_size ) );
  if( FD_UNLIKELY( max_page_sz!=FD_SHMEM_HUGE_PAGE_SZ && max_page_sz!=FD_SHMEM_GIGANTIC_PAGE_SZ ) ) FD_LOG_ERR(( "[hugetlbfs.max_page_size] must be \"huge\" or \"gigantic\"" ));

  char const * user = FD_TOPO_STR( config->user );
  char const * name = FD_TOPO_STR( config->name );

  replace( config, &config->log.path, "{user}", user );
  replace( config, &config->log.path, "{name}", name );

  if( FD_LIKELY( !strcmp( "auto", FD_TOPO_STR( config->log.colorize ) ) ) )       config->log.colorize1 = 2;
  else if( FD_LIKELY( !strcmp( "true", FD_TOPO_STR( config->log.colorize ) ) ) )  config->log.colorize1 = 1;
  else if( FD_LIKELY( !strcmp( "false", FD_TOPO_STR( config->log.colorize ) ) ) ) config->log.colorize1 = 0;
  else  FD_LOG_ERR(( "[log.colorize] must be one of \"auto\", \"true\", or \"false\"" ));

  if( FD_LIKELY( 2==config->log.colorize1 ) ) {
    config->log.colorize1 = fd_log_should_colorize();
  }

  config->log.level_logfile1 = parse_log_level( FD_TOPO_STR( config->log.level_logfile ) );
  config->log.level_stderr1  = parse_log_level( FD_TOPO_STR( config->log.level_stderr ) );
  if( FD_UNLIKELY( !strcmp( FD_TOPO_STR( config->log.level_flush ), "NONE" ) ) ) config->log.level_flush1 = 8;
  else                                                            config->log.level_flush1 = parse_log_level( FD_TOPO_STR( config->log.level_flush ) );
  if( FD_UNLIKELY( -1==config->log.level_logfile1 ) ) FD_LOG_ERR(( "unrecognized [log.level_logfile] `%s`", FD_TOPO_STR( config->log.level_logfile ) ));
  if( FD_UNLIKELY( -1==config->log.level_stderr1 ) )  FD_LOG_ERR(( "unrecognized [log.level_stderr] `%s`", FD_TOPO_STR( config->log.level_stderr ) ));
  if( FD_UNLIKELY( -1==config->log.level_flush1 ) )   FD_LOG_ERR(( "unrecognized [log.level_flush] `%s`", FD_TOPO_STR( config->log.level_flush ) ));

  config->development.core_dump_level = parse_core_dump_level( FD_TOPO_STR( config->development.core_dump ) );
  if( FD_UNLIKELY( -1==config->development.core_dump_level ) ) FD_LOG_ERR(( "unrecognized [development.core_dump] `%s`", FD_TOPO_STR( config->development.core_dump ) ));

  replace( config, &config->paths.base, "{user}", user );
  replace( config, &config->paths.base, "{name}", name );
  char const * base = FD_TOPO_STR( config->paths.base );

  if( FD_UNLIKELY( !FD_TOPO_STR( config->paths.identity_key )[0] ) ) {
    /* Development binaries generate an identity key on boot. */
    if( FD_UNLIKELY( config->is_live_cluster && !dev ) ) FD_LOG_ERR(( "configuration file must specify [consensus.identity_path] when joining a live cluster" ));

    FD_TEST( fd_config_str_printf( config, &config->paths.identity_key, "%s/identity.json", base ) );
  } else {
    replace( config, &config->paths.identity_key, "{user}", user );
    replace( config, &config->paths.identity_key, "{name}", name );
  }

  replace( config, &config->paths.vote_account, "{user}", user );
  replace( config, &config->paths.vote_account, "{name}", name );

  if( FD_UNLIKELY( FD_TOPO_STR( config->paths.snapshots )[0] ) ) {
    replace( config, &config->paths.snapshots, "{user}", user );
    replace( config, &config->paths.snapshots, "{name}", name );
  } else {
    FD_TEST( fd_config_str_printf( config, &config->paths.snapshots, "%s/snapshots", base ) );
  }

  if( FD_UNLIKELY( FD_TOPO_STR( config->paths.genesis )[0] ) ) {
    replace( config, &config->paths.genesis, "{user}", user );
    replace( config, &config->paths.genesis, "{name}", name );
  } else {
    FD_TEST( fd_config_str_printf( config, &config->paths.genesis, "%s/genesis.bin", base ) );
  }

  long ts = -fd_log_wallclock();
  config->is_dev = dev;

  config->tick_per_ns_mu = dev ? fd_tempo_tick_per_ns_dev( &config->tick_per_ns_sigma )
                               : fd_tempo_tick_per_ns    ( &config->tick_per_ns_sigma );
  FD_LOG_INFO(( "calibrating fd_tempo tick_per_ns took %ld ms", (fd_log_wallclock()+ts)/(1000L*1000L) ));

  if( 0!=strcmp( FD_TOPO_STR( config->net.bind_address ), "" ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( FD_TOPO_STR( config->net.bind_address ), &config->net.bind_address_parsed ) ) ) {
      FD_LOG_ERR(( "`net.bind_address` is not a valid IPv4 address" ));
    }
  }

  if(      FD_LIKELY( !strcmp( FD_TOPO_STR( config->tiles.pack.schedule_strategy ), "perf"     ) ) ) config->tiles.pack.schedule_strategy_enum = 0;
  else if( FD_LIKELY( !strcmp( FD_TOPO_STR( config->tiles.pack.schedule_strategy ), "balanced" ) ) ) config->tiles.pack.schedule_strategy_enum = 1;
  else if( FD_LIKELY( !strcmp( FD_TOPO_STR( config->tiles.pack.schedule_strategy ), "revenue"  ) ) ) {
    FD_LOG_ERR(( "the revenue scheduler has been removed.  Please update [tiles.pack.schedule_strategy]" ));
  }
  else FD_LOG_ERR(( "[tiles.pack.schedule_strategy] %s not recognized", FD_TOPO_STR( config->tiles.pack.schedule_strategy ) ));

  fd_config_fill_net( config );

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    fd_config_fillf( config );
  } else {
    fd_config_fillh( config );
  }

  fd_config_auto( config );
  if( FD_UNLIKELY( !strcmp( FD_TOPO_STR( config->net.provider ), "auto" ) ) ) {
    FD_LOG_ERR(( "failed to resolve automatic network provider" ));
  }
  fd_config_validate( config );

  config->limits.max_cost_per_block   = fd_ulong_if( !!config->development.bench.max_cost_per_block,   config->development.bench.max_cost_per_block,   FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND );
  config->limits.max_shreds_per_block = fd_ulong_if( !!config->development.bench.max_shreds_per_block, config->development.bench.max_shreds_per_block, FD_SHRED_BLK_MAX );
  config->limits.max_txn_per_slot     = fd_ulong_min( config->limits.max_cost_per_block/FD_PACK_MIN_TXN_COST,
                                                      (config->limits.max_shreds_per_block*FD_SHRED_DATA_PAYLOAD_MAX - 65UL*sizeof(fd_entry_batch_header_t))/FD_TXN_MIN_SERIALIZED_SZ ); /* 64 ticks + one giant microblock */
  if( FD_LIKELY( !config->development.bench.max_cost_per_block && !config->development.bench.max_shreds_per_block ) ) FD_TEST( config->limits.max_txn_per_slot==FD_MAX_TXN_PER_SLOT );

  if( FD_LIKELY( config->is_live_cluster) ) {
    if( FD_UNLIKELY( !config->development.sandbox ) )                            FD_LOG_ERR(( "trying to join a live cluster, but configuration disables the sandbox which is a development only feature" ));
    if( FD_UNLIKELY( config->development.no_clone ) )                            FD_LOG_ERR(( "trying to join a live cluster, but configuration disables multiprocess which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.max_cost_per_block ) )            FD_LOG_ERR(( "trying to join a live cluster, but configuration sets [development.bench.max_cost_per_block] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.max_shreds_per_block ) )          FD_LOG_ERR(( "trying to join a live cluster, but configuration sets [development.bench.max_shreds_per_block] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.disable_blockstore_from_slot ) )  FD_LOG_ERR(( "trying to join a live cluster, but configuration has a non-zero value for [development.bench.disable_blockstore_from_slot] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.disable_status_cache ) )          FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.disable_status_cache] which is a development only feature" ));
  }

  /* When running a local cluster, some options are overridden by default
     to make starting and running in development environments a little
     easier and less strict. */
  if( FD_UNLIKELY( is_local_cluster ) ) {
    if( FD_LIKELY( !FD_TOPO_STR( config->paths.vote_account )[0] ) ) {
      FD_TEST( fd_config_str_printf( config, &config->paths.vote_account, "%s/vote-account.json", base ) );
    }

    strncpy( config->cluster, "development", sizeof(config->cluster) );

    if( FD_UNLIKELY( !config->is_firedancer ) ) {
      /* By default only_known is true for validators to ensure secure
        snapshot download, but in development it doesn't matter and
        often the developer does not provide known peers. */
      config->frankendancer.rpc.only_known = 0;

      /* When starting from a new genesis block, this needs to be off else
        the validator will get stuck forever. */
      config->frankendancer.consensus.wait_for_vote_to_start_leader = 0;

      /* We have to wait until we get a snapshot before we can join a
        second validator to this one, so make this smaller than the
        default.  */
      config->frankendancer.snapshots.full_snapshot_interval_slots = fd_uint_min( config->frankendancer.snapshots.full_snapshot_interval_slots, 200U );
    }
  }

  if( FD_UNLIKELY( config->is_firedancer && strcmp( FD_TOPO_STR( config->firedancer.consensus.wait_for_supermajority_with_bank_hash ), "" ) && (!config->consensus.expected_shred_version || config->consensus.wait_for_vote_to_start_leader) ) ) {
    FD_LOG_ERR(( "Config option [consensus.wait_for_supermajority_with_bank_hash] requires consensus.expected_shred_version!=0 and consensus.wait_for_vote_to_start_leader==false." ));
  }

}

#define CFG_HAS_NON_EMPTY( key ) do {                  \
  if( !FD_TOPO_STR( config->key )[0] ) {                \
    FD_LOG_ERR(( "missing `%s`", #key ));              \
  }                                                    \
} while(0)

#define CFG_HAS_NON_ZERO( key ) do {                           \
  if( !config->key ) { FD_LOG_ERR(( "missing `%s`", #key )); } \
} while(0)

#define CFG_HAS_POW2( key ) do {                       \
  ulong value = (ulong)( config -> key );              \
  if( !value || !fd_ulong_is_pow2( value ) ) {         \
    FD_LOG_ERR(( "`%s` must be a power of 2", #key )); \
  }                                                    \
} while(0)

static void
fd_config_validatef( fd_configf_t const * config ) {
  CFG_HAS_NON_ZERO( layout.sign_tile_count );
  CFG_HAS_NON_ZERO( layout.resolv_tile_count );
  CFG_HAS_NON_ZERO( layout.execle_tile_count );
  CFG_HAS_NON_ZERO( layout.snapzp_tile_count );
  CFG_HAS_NON_ZERO( layout.snapsv_tile_count );
  CFG_HAS_NON_ZERO( layout.snapsv_io_worker_count );
  CFG_HAS_NON_ZERO( layout.snapdc_tile_count );
  if( FD_UNLIKELY( config->layout.sign_tile_count < 2 ) ) {
    FD_LOG_ERR(( "layout.sign_tile_count must be >= 2" ));
  }

  if( FD_UNLIKELY( config->snapshots.sources.gossip.allow_any && config->snapshots.sources.gossip.allow_list_cnt>0UL ) ) {
    FD_LOG_ERR(( "`snapshots.sources.gossip` has an explicit list of %lu allowed peer(s) in `allow_list` "
                 "but also allows any peer with `allow_any=true`. `allow_list` has no effect and may "
                 "give a false sense of security. Please modify one of the two options and restart.",
                 config->snapshots.sources.gossip.allow_list_cnt ));
  }
  for( ulong i=0UL; i<config->snapshots.sources.gossip.allow_list_cnt; i++ ) {
    for( ulong j=0UL; j<config->snapshots.sources.gossip.block_list_cnt; j++ ) {
      if( FD_UNLIKELY( 0==strcmp( FD_TOPO_STR( config->snapshots.sources.gossip.allow_list[ i ] ), FD_TOPO_STR( config->snapshots.sources.gossip.block_list[ j ] ) ) ) ) {
        FD_LOG_ERR(( "`snapshots.sources.gossip` has repeated public key `%s` in both allow[%lu] and block[%lu] lists.  "
                     "Please modify one of the two options and restart.", FD_TOPO_STR( config->snapshots.sources.gossip.allow_list[ i ] ), i, j ));

      }
    }
  }

  if( FD_UNLIKELY( config->snapshots.server.enabled && !config->layout.enable_snapshot_production ) ) {
    FD_LOG_ERR(( "[snapshots.server].enabled=true requires [layout].enable_snapshot_production=true" ));
  }

  CFG_HAS_NON_ZERO( snapshots.wait_for_peers_timeout_seconds );
  if( FD_UNLIKELY( config->snapshots.server.idle_timeout_millis<100UL ||
                   config->snapshots.server.idle_timeout_millis>=60000UL ) ) {
    FD_LOG_ERR(( "`snapshots.server.idle_timeout_millis` must be in [100,60000)" ));
  }
  if( FD_UNLIKELY( config->snapshots.server.send_timeout_millis<100UL ||
                   config->snapshots.server.send_timeout_millis>=60000UL ) ) {
    FD_LOG_ERR(( "`snapshots.server.send_timeout_millis` must be in [100,60000)" ));
  }

  if( FD_UNLIKELY( config->snapshots.max_full_snapshots_to_keep>FD_SSARCHIVE_MAX_ENTRIES ) ) {
    FD_LOG_ERR(( "`snapshots.max_full_snapshots_to_keep` is %u but must be at most %lu",
                 config->snapshots.max_full_snapshots_to_keep, FD_SSARCHIVE_MAX_ENTRIES ));
  }
  if( FD_UNLIKELY( config->snapshots.max_incremental_snapshots_to_keep>FD_SSARCHIVE_MAX_ENTRIES ) ) {
    FD_LOG_ERR(( "`snapshots.max_incremental_snapshots_to_keep` is %u but must be at most %lu",
                 config->snapshots.max_incremental_snapshots_to_keep, FD_SSARCHIVE_MAX_ENTRIES ));
  }

  CFG_HAS_NON_ZERO( accounts.max_accounts   );
  CFG_HAS_NON_ZERO( accounts.cache_size_gib );

  CFG_HAS_NON_ZERO( development.genesis.max_file_size_mib );
  if( FD_UNLIKELY( config->development.genesis.max_file_size_mib>FD_GENESIS_MAX_FILE_SIZE_MIB ) ) {
    FD_LOG_ERR(( "`development.genesis.max_file_size_mib` must be at most %lu", FD_GENESIS_MAX_FILE_SIZE_MIB ));
  }

  CFG_HAS_NON_ZERO( runtime.program_cache.mean_cache_entry_size );
  CFG_HAS_NON_ZERO( runtime.program_cache.heap_size_mib );
  if( config->runtime.program_cache.mean_cache_entry_size < 4096 ) { FD_LOG_ERR(( "`%s` must be >= 4096", "runtime.program_cache.mean_cache_entry_size" )); }
  if( config->runtime.program_cache.heap_size_mib < 32 ) { FD_LOG_ERR(( "`%s` must be >= 32", "runtime.program_cache.heap_size_mib" )); }
}

static void
fd_config_validateh( fd_configh_t const * config ) {
  CFG_HAS_NON_EMPTY( dynamic_port_range );

  CFG_HAS_NON_EMPTY( ledger.snapshot_archive_format );

  CFG_HAS_NON_ZERO( snapshots.full_snapshot_interval_slots );
  CFG_HAS_NON_ZERO( snapshots.incremental_snapshot_interval_slots );
  CFG_HAS_NON_ZERO( snapshots.minimum_snapshot_download_speed );
  CFG_HAS_NON_ZERO( snapshots.maximum_snapshot_download_abort );

  CFG_HAS_NON_EMPTY( layout.agave_affinity );
  CFG_HAS_NON_ZERO ( layout.resolh_tile_count );
  CFG_HAS_NON_ZERO ( layout.bank_tile_count );
}

void
fd_config_validate( fd_config_t const * config ) {
  if( FD_LIKELY( config->is_firedancer ) ) {
    fd_config_validatef( &config->firedancer );
  } else {
    fd_config_validateh( &config->frankendancer );
  }

  CFG_HAS_NON_EMPTY( name );
  CFG_HAS_NON_EMPTY( paths.base );

  CFG_HAS_NON_EMPTY( log.colorize );
  CFG_HAS_NON_EMPTY( log.level_logfile );
  CFG_HAS_NON_EMPTY( log.level_stderr );
  CFG_HAS_NON_EMPTY( log.level_flush );

  CFG_HAS_NON_EMPTY( layout.affinity );
  CFG_HAS_NON_EMPTY( layout.blocklist_cores );
  CFG_HAS_NON_ZERO ( layout.net_tile_count );
  CFG_HAS_NON_ZERO ( layout.quic_tile_count );
  CFG_HAS_NON_ZERO ( layout.verify_tile_count );
  CFG_HAS_NON_ZERO ( layout.shred_tile_count );

  CFG_HAS_NON_EMPTY( hugetlbfs.mount_path );
  CFG_HAS_NON_EMPTY( hugetlbfs.max_page_size );

  CFG_HAS_NON_ZERO( net.ingress_buffer_size );

  ulong bench_cost   = config->development.bench.max_cost_per_block;
  ulong bench_shreds = config->development.bench.max_shreds_per_block;
  if( FD_UNLIKELY( bench_cost && (bench_cost<FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND || bench_cost>=UINT_MAX) ) ) /* fd_pack_limits_t: [0,UINT_MAX) */
    FD_LOG_ERR(( "invalid [development.bench.max_cost_per_block]: must be 0 or in [%lu,%u)", FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND, UINT_MAX ));
  if( FD_UNLIKELY( bench_shreds && (bench_shreds%FD_SHRED_BLK_MAX || bench_shreds>FD_SHRED_BLK_MAX_RAISED) ) )
    FD_LOG_ERR(( "invalid [development.bench.max_shreds_per_block]: must be 0 or a multiple of %lu up to %lu", (ulong)FD_SHRED_BLK_MAX, FD_SHRED_BLK_MAX_RAISED ));
  /* Frankendancer's Agave side only knows the booleans behind these
     (18x block cost, 32x shreds), so it accepts exactly the values that
     match what the Firedancer side used to hardcode for them. */
  if( FD_UNLIKELY( !config->is_firedancer && bench_cost && bench_cost!=18UL*FD_PACK_MAX_COST_PER_BLOCK_LOWER_BOUND ) )
    FD_LOG_ERR(( "invalid [development.bench.max_cost_per_block]: Frankendancer supports 0 or %lu", 18UL*FD_PACK_MAX_COST_PER_BLOCK_LOWER_BOUND ));
  if( FD_UNLIKELY( !config->is_firedancer && bench_shreds && bench_shreds!=32UL*FD_SHRED_BLK_MAX ) )
    FD_LOG_ERR(( "invalid [development.bench.max_shreds_per_block]: Frankendancer supports 0 or %lu", 32UL*FD_SHRED_BLK_MAX ));

  if( 0==strcmp( FD_TOPO_STR( config->net.provider ), "xdp" ) ) {
    if( 0!=strcmp( FD_TOPO_STR( config->net.xdp.xdp_mode ), "skb"     ) &&
        0!=strcmp( FD_TOPO_STR( config->net.xdp.xdp_mode ), "drv"     ) &&
        0!=strcmp( FD_TOPO_STR( config->net.xdp.xdp_mode ), "auto"    ) &&
        0!=strcmp( FD_TOPO_STR( config->net.xdp.xdp_mode ), "default" ) ) {
      FD_LOG_ERR(( "invalid `net.xdp.xdp_mode`: \"%s\"; must be \"skb\", \"drv\", \"auto\" or \"default\"",
                   FD_TOPO_STR( config->net.xdp.xdp_mode ) ));
    }

    if( 0!=strcmp( FD_TOPO_STR( config->net.xdp.poll_mode ), "prefbusy" ) &&
        0!=strcmp( FD_TOPO_STR( config->net.xdp.poll_mode ), "softirq"  ) &&
        0!=strcmp( FD_TOPO_STR( config->net.xdp.poll_mode ), "auto"     ) ) {
      FD_LOG_ERR(( "invalid `net.xdp.poll_mode`: \"%s\"; must be \"prefbusy\", \"softirq\" or \"auto\"",
                   FD_TOPO_STR( config->net.xdp.poll_mode ) ));
    }

    CFG_HAS_POW2     ( net.xdp.xdp_rx_queue_size );
    CFG_HAS_POW2     ( net.xdp.xdp_tx_queue_size );
    if( 0!=strcmp( FD_TOPO_STR( config->net.xdp.rss_queue_mode ), "dedicated" ) &&
        0!=strcmp( FD_TOPO_STR( config->net.xdp.rss_queue_mode ), "simple"    ) &&
        0!=strcmp( FD_TOPO_STR( config->net.xdp.rss_queue_mode ), "auto"      ) ) {
      FD_LOG_ERR(( "invalid `net.xdp.rss_queue_mode`: \"%s\"; must be \"simple\", \"dedicated\" or \"auto\"",
                   FD_TOPO_STR( config->net.xdp.rss_queue_mode ) ));
    }
  } else if( 0==strcmp( FD_TOPO_STR( config->net.provider ), "mlx5" ) ) {
    CFG_HAS_POW2( net.mlx5.rx_queue_size );
    CFG_HAS_POW2( net.mlx5.tx_queue_size );
    if( FD_UNLIKELY( config->net.mlx5.rx_queue_size<=FD_MLX5_BATCH_SIZE ||
                     config->net.mlx5.tx_queue_size< FD_MLX5_BATCH_SIZE ) ) {
      FD_LOG_ERR(( "invalid mlx5 queue depth: RX must exceed %u and TX must be at least %u",
                   FD_MLX5_BATCH_SIZE, FD_MLX5_BATCH_SIZE ));
    }
    if( FD_UNLIKELY( config->net.mlx5.rx_queue_size>FD_MLX5_QUEUE_DEPTH_MAX ||
                     config->net.mlx5.tx_queue_size>FD_MLX5_QUEUE_DEPTH_MAX ) ) {
      FD_LOG_ERR(( "invalid mlx5 queue depth: RX and TX must not exceed %u", FD_MLX5_QUEUE_DEPTH_MAX ));
    }
  } else if( 0==strcmp( FD_TOPO_STR( config->net.provider ), "socket" ) ) {
    CFG_HAS_NON_ZERO( net.socket.receive_buffer_size );
    CFG_HAS_NON_ZERO( net.socket.send_buffer_size );
  } else if( 0==strcmp( FD_TOPO_STR( config->net.provider ), "auto" ) ) {
    /* "auto" is resolved after interface discovery in fd_config_fill(). */
  } else {
    FD_LOG_ERR(( "invalid `net.provider`: \"%s\"; must be \"auto\", \"xdp\", \"socket\" or \"mlx5\"",
                 FD_TOPO_STR( config->net.provider ) ));
  }

  CFG_HAS_NON_ZERO( tiles.netlink.max_routes           );
  CFG_HAS_NON_ZERO( tiles.netlink.max_peer_routes      );
  CFG_HAS_NON_ZERO( tiles.netlink.max_neighbors        );

  CFG_HAS_NON_ZERO( tiles.quic.max_concurrent_connections );
  CFG_HAS_NON_ZERO( tiles.quic.txn_reassembly_count );
  CFG_HAS_NON_ZERO( tiles.quic.max_concurrent_handshakes );
  CFG_HAS_NON_ZERO( tiles.quic.idle_timeout_millis );

  CFG_HAS_NON_ZERO( tiles.verify.signature_cache_size );
  CFG_HAS_NON_ZERO( tiles.verify.receive_buffer_size );

  CFG_HAS_NON_ZERO( tiles.dedup.signature_cache_size );

  CFG_HAS_NON_ZERO( tiles.pack.max_pending_transactions );

  CFG_HAS_NON_ZERO( tiles.shred.max_pending_shred_sets );

  if( config->is_firedancer ) {
    CFG_HAS_POW2( tiles.repair.slot_max );
    CFG_HAS_NON_ZERO( tiles.rotor.slot_max );
  }

  if( FD_UNLIKELY( config->tiles.bundle.keepalive_interval_millis <    3000 ||
                   config->tiles.bundle.keepalive_interval_millis > 3600000 ) ) {
    FD_LOG_ERR(( "`tiles.bundle.keepalive_interval_millis` must be in range [3000, 3,600,000]" ));
  }

  CFG_HAS_NON_EMPTY( development.core_dump );

  CFG_HAS_NON_ZERO( development.genesis.target_tick_duration_micros );
  CFG_HAS_NON_ZERO( development.genesis.ticks_per_slot );
  CFG_HAS_NON_ZERO( development.genesis.fund_initial_accounts );
  CFG_HAS_NON_ZERO( development.genesis.fund_initial_amount_lamports );

  CFG_HAS_NON_ZERO ( development.bench.benchg_tile_count );
  CFG_HAS_NON_ZERO ( development.bench.benchs_tile_count );
  CFG_HAS_NON_EMPTY( development.bench.affinity );
}

#undef CFG_HAS_NON_EMPTY
#undef CFG_HAS_NON_ZERO
#undef CFG_HAS_POW2

void
fd_config_load( int           is_firedancer,
                int           is_local_cluster,
                char const *  default_config,
                ulong         default_config_sz,
                char const *  override_config,
                char const *  override_config_path,
                ulong         override_config_sz,
                char const *  user_config,
                ulong         user_config_sz,
                char const *  user_config_path,
                fd_config_t * config,
                int           dev ) {
  memset( config, 0, sizeof(config_t) );
  config->is_firedancer = is_firedancer;
  config->boot_timestamp_nanos = fd_log_wallclock();

  fd_config_load_buf( config, default_config, default_config_sz, "default.toml" );
  fd_config_validate( config );
  if( FD_UNLIKELY( override_config ) ) {
    fd_config_load_buf( config, override_config, override_config_sz, override_config_path );
    fd_config_validate( config );
  }
  if( FD_LIKELY( user_config ) ) {
    fd_config_load_buf( config, user_config, user_config_sz, user_config_path );
    fd_config_validate( config );
    if( FD_UNLIKELY( user_config_sz>sizeof(config->user_config)-1UL ) ) {
      if( FD_UNLIKELY( config->telemetry && FD_TOPO_STR( config->tiles.event.url )[ 0 ] ) ) {
        FD_LOG_ERR(( "config file (%s) is too large (%lu bytes, max %lu) to report in telemetry", user_config_path, user_config_sz, sizeof(config->user_config)-1UL ));
      }
    } else {
      fd_memcpy( config->user_config, user_config, user_config_sz );
      config->user_config[ user_config_sz ] = '\0';
      config->user_config_len = user_config_sz;
    }
  }

  fd_config_fill( config, is_local_cluster, dev );
}

int
fd_config_to_memfd( fd_config_t const * config ) {
  int config_memfd = memfd_create( "fd_config", 0 );
  if( FD_UNLIKELY( -1==config_memfd ) ) return -1;
  if( FD_UNLIKELY( -1==ftruncate( config_memfd, sizeof( config_t ) ) ) ) {
    if( FD_UNLIKELY( close( config_memfd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  uchar * bytes = mmap( NULL, sizeof( config_t ), PROT_READ|PROT_WRITE, MAP_SHARED, config_memfd, 0 );
  if( FD_UNLIKELY( bytes==MAP_FAILED ) ) {
    if( FD_UNLIKELY( close( config_memfd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  fd_memcpy( bytes, config, sizeof( config_t ) );
  if( FD_UNLIKELY( munmap( bytes, sizeof( config_t ) ) ) ) {
    FD_LOG_WARNING(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  return config_memfd;
}
