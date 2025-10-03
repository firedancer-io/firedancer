#define _GNU_SOURCE
#include "fd_config.h"
#include "fd_config_private.h"

#include "../platform/fd_net_util.h"
#include "../platform/fd_sys_util.h"
#include "../../ballet/toml/fd_toml.h"
#include "../../disco/genesis/fd_genesis_cluster.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h> /* strtoul */
#include <sys/utsname.h>
#include <sys/mman.h>

/* TODO: Rewrite this ... */

static inline void
replace( char *       in,
         const char * pat,
         const char * sub ) {
  char * replace = strstr( in, pat );
  if( FD_LIKELY( replace ) ) {
    ulong pat_len = strlen( pat );
    ulong sub_len = strlen( sub );
    ulong in_len  = strlen( in );
    if( FD_UNLIKELY( pat_len > in_len ) ) return;

    ulong total_len = in_len - pat_len + sub_len;
    if( FD_UNLIKELY( total_len >= PATH_MAX ) )
      FD_LOG_ERR(( "configuration scratch directory path too long: `%s`", in ));

    uchar after[PATH_MAX] = {0};
    fd_memcpy( after, replace + pat_len, strlen( replace + pat_len ) );
    fd_memcpy( replace, sub, sub_len );
    ulong after_len = strlen( ( const char * ) after );
    fd_memcpy( replace + sub_len, after, after_len );
    in[ total_len ] = '\0';
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

void
fd_config_load_buf( fd_config_t * out,
                    char const *  buf,
                    ulong         sz,
                    char const *  path ) {
  static uchar pod_mem[ 1UL<<26 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  fd_toml_err_info_t toml_err[1];
  uchar scratch[ 4096 ];
  int toml_errc = fd_toml_parse( buf, sz, pod, scratch, sizeof(scratch), toml_err );
  if( FD_UNLIKELY( toml_errc!=FD_TOML_SUCCESS ) ) {
    switch( toml_errc ) {
    case FD_TOML_ERR_POD:
      FD_LOG_ERR(( "Failed to parse config file (%s): ran out of buffer space while parsing", path ));
      break;
    case FD_TOML_ERR_SCRATCH:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: ran out of scratch space while parsing", path, toml_err->line ));
      break;
    case FD_TOML_ERR_KEY:
      FD_LOG_ERR(( "Failed to parse config file (%s) at line %lu: oversize key", path, toml_err->line ));
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

  fd_config_extract_pod( pod, out );

  fd_pod_delete( fd_pod_leave( pod ) );
}

static void
fd_config_fillf( fd_config_t * config ) {
  (void)config;
}

static void
fd_config_fillh( fd_config_t * config ) {
  if( FD_UNLIKELY( strcmp( config->frankendancer.paths.accounts_path, "" ) ) ) {
    replace( config->frankendancer.paths.accounts_path, "{user}", config->user );
    replace( config->frankendancer.paths.accounts_path, "{name}", config->name );
  }

  if( FD_UNLIKELY( strcmp( config->frankendancer.snapshots.path, "" ) ) ) {
    replace( config->frankendancer.snapshots.path, "{user}", config->user );
    replace( config->frankendancer.snapshots.path, "{name}", config->name );
  } else {
    strncpy( config->frankendancer.snapshots.path, config->paths.ledger, sizeof(config->frankendancer.snapshots.path) );
  }

  for( ulong i=0UL; i<config->frankendancer.paths.authorized_voter_paths_cnt; i++ ) {
    replace( config->frankendancer.paths.authorized_voter_paths[ i ], "{user}", config->user );
    replace( config->frankendancer.paths.authorized_voter_paths[ i ], "{name}", config->name );
  }

  if( FD_UNLIKELY( config->tiles.quic.quic_transaction_listen_port!=config->tiles.quic.regular_transaction_listen_port+6 ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be 6 more than [tiles.quic.regular_transaction_listen_port] `%hu`",
                 config->tiles.quic.quic_transaction_listen_port,
                 config->tiles.quic.regular_transaction_listen_port ));

  char dynamic_port_range[ 32 ];
  fd_memcpy( dynamic_port_range, config->frankendancer.dynamic_port_range, sizeof(dynamic_port_range) );

  char * dash = strstr( dynamic_port_range, "-" );
  if( FD_UNLIKELY( !dash ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 config->frankendancer.dynamic_port_range ));

  *dash = '\0';
  char * endptr;
  ulong agave_port_min = strtoul( dynamic_port_range, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || agave_port_min > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 config->frankendancer.dynamic_port_range ));
  ulong agave_port_max = strtoul( dash + 1, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || agave_port_max > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 config->frankendancer.dynamic_port_range ));
  if( FD_UNLIKELY( agave_port_min > agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "The minimum port must be less than or equal to the maximum port",
                 config->frankendancer.dynamic_port_range ));

  if( FD_UNLIKELY( config->tiles.quic.regular_transaction_listen_port >= agave_port_min &&
                   config->tiles.quic.regular_transaction_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 config->tiles.quic.regular_transaction_listen_port,
                 config->frankendancer.dynamic_port_range ));

  if( FD_UNLIKELY( config->tiles.quic.quic_transaction_listen_port >= agave_port_min &&
                   config->tiles.quic.quic_transaction_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 config->tiles.quic.quic_transaction_listen_port,
                 config->frankendancer.dynamic_port_range ));

  if( FD_UNLIKELY( config->tiles.shred.shred_listen_port >= agave_port_min &&
                   config->tiles.shred.shred_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.shred.shred_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 config->tiles.shred.shred_listen_port,
                 config->frankendancer.dynamic_port_range ));
}

static void
fd_config_fill_net( fd_config_t * config ) {
  if( FD_UNLIKELY( !strcmp( config->net.interface, "" ) && !config->development.netns.enabled ) ) {
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

    if( FD_UNLIKELY( !if_indextoname( ifindex, config->net.interface ) ) )
      FD_LOG_ERR(( "could not get name of interface with index %u", ifindex ));
  }

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {
    if( !strcmp( config->net.interface, "" ) ) {
      memcpy( config->net.interface, config->development.netns.interface0, sizeof(config->net.interface) );
    }

    if( !strcmp( config->development.pktgen.fake_dst_ip, "" ) ) {
      memcpy( config->development.pktgen.fake_dst_ip, config->development.netns.interface1_addr, sizeof(config->development.netns.interface1_addr) );
    }

    if( FD_UNLIKELY( strcmp( config->development.netns.interface0, config->net.interface ) ) ) {
      FD_LOG_ERR(( "netns interface and firedancer interface are different. If you are using the "
                   "[development.netns] functionality to run Firedancer in a network namespace "
                   "for development, the configuration file must specify that "
                   "[development.netns.interface0] is the same as [net.interface]" ));
    }

    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->development.netns.interface0_addr, &config->net.ip_addr ) ) )
      FD_LOG_ERR(( "configuration specifies invalid netns IP address `%s`", config->development.netns.interface0_addr ));
  } else { /* !config->development.netns.enabled */
    if( FD_UNLIKELY( !if_nametoindex( config->net.interface ) ) )
      FD_LOG_ERR(( "configuration specifies network interface `%s` which does not exist", config->net.interface ));
    uint iface_ip;
    if( FD_UNLIKELY( -1==fd_net_util_if_addr( config->net.interface, &iface_ip ) ) )
      FD_LOG_ERR(( "could not get IP address for interface `%s`", config->net.interface ));

    if( FD_UNLIKELY( config->is_firedancer ) ) {
      if( FD_UNLIKELY( strcmp( config->firedancer.gossip.host, "" ) ) ) {
        uint gossip_ip_addr = iface_ip;
        int  has_gossip_ip4 = 0;
        if( FD_UNLIKELY( strlen( config->firedancer.gossip.host )<=15UL ) ) {
          /* Only sets gossip_ip_addr if it's a valid IPv4 address, otherwise assume it's a DNS name */
          has_gossip_ip4 = fd_cstr_to_ip4_addr( config->firedancer.gossip.host, &gossip_ip_addr );
        }
        if( FD_UNLIKELY( !fd_ip4_addr_is_public( gossip_ip_addr ) && config->is_live_cluster && has_gossip_ip4 ) )
          FD_LOG_ERR(( "Trying to use [gossip.host] " FD_IP4_ADDR_FMT " for listening to incoming "
                      "transactions, but it is part of a private network and will not be routable "
                      "for other Solana network nodes.", FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
      } else if( FD_UNLIKELY( !fd_ip4_addr_is_public( iface_ip ) && config->is_live_cluster ) ) {
        FD_LOG_ERR(( "Trying to use network interface `%s` for listening to incoming transactions, "
                    "but it has IPv4 address " FD_IP4_ADDR_FMT " which is part of a private network "
                    "and will not be routable for other Solana network nodes. If you are running "
                    "behind a NAT and this interface is publicly reachable, you can continue by "
                    "manually specifying the IP address to advertise in your configuration under "
                    "[gossip.host].", config->net.interface, FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
      }
    }

    config->net.ip_addr = iface_ip;
  }
}

void
fd_config_fill( fd_config_t * config,
                int           netns,
                int           is_local_cluster ) {
  if( FD_UNLIKELY( netns ) ) {
    config->development.netns.enabled = 1;
    strncpy( config->net.interface,
             config->development.netns.interface0,
             sizeof(config->net.interface) );
    config->net.interface[ sizeof(config->net.interface) - 1 ] = '\0';
  }

  struct utsname utsname;
  if( FD_UNLIKELY( -1==uname( &utsname ) ) )
    FD_LOG_ERR(( "could not get uname (%i-%s)", errno, fd_io_strerror( errno ) ));
  strncpy( config->hostname, utsname.nodename, sizeof(config->hostname) );
  config->hostname[ sizeof(config->hostname)-1UL ] = '\0'; /* Just truncate the name if it's too long to fit */

  ulong cluster = FD_CLUSTER_UNKNOWN;
  if( FD_UNLIKELY( !config->is_firedancer ) ) {
    cluster = fd_genesis_cluster_identify( config->frankendancer.consensus.expected_genesis_hash );
  }
  config->is_live_cluster = cluster!=FD_CLUSTER_UNKNOWN;
  strcpy( config->cluster, fd_genesis_cluster_name( cluster ) );

  if( FD_UNLIKELY( !strcmp( config->user, "" ) ) ) {
    const char * user = fd_sys_util_login_user();
    if( FD_UNLIKELY( !user ) )                                                                 FD_LOG_ERR(( "could not automatically determine a user to run Firedancer as. You must specify a [user] in your configuration TOML file." ));
    if( FD_UNLIKELY( strlen( user )>=sizeof( config->user ) ) )                                FD_LOG_ERR(( "user name `%s` is too long", user ));
    strncpy( config->user, user, sizeof(config->user) );
  }

  if( FD_UNLIKELY( -1==fd_sys_util_user_to_uid( config->user, &config->uid, &config->gid ) ) ) FD_LOG_ERR(( "configuration file wants firedancer to run as user `%s` but it does not exist", config->user ));
  if( FD_UNLIKELY( !config->uid || !config->gid ) )                                            FD_LOG_ERR(( "firedancer cannot run as root. please specify a non-root user in the configuration file" ));
  if( FD_UNLIKELY( getuid()!=0U && config->uid!=getuid() ) )                                   FD_LOG_ERR(( "running as uid %u, but config specifies uid %u", getuid(), config->uid ));
  if( FD_UNLIKELY( getgid()!=0U && config->gid!=getgid() ) )                                   FD_LOG_ERR(( "running as gid %u, but config specifies gid %u", getgid(), config->gid ));

  FD_TEST( fd_cstr_printf_check( config->hugetlbfs.gigantic_page_mount_path,
    sizeof(config->hugetlbfs.gigantic_page_mount_path),
    NULL,
    "%s/.gigantic",
    config->hugetlbfs.mount_path ) );
  FD_TEST( fd_cstr_printf_check( config->hugetlbfs.huge_page_mount_path,
    sizeof(config->hugetlbfs.huge_page_mount_path),
    NULL,
    "%s/.huge",
    config->hugetlbfs.mount_path ) );
  FD_TEST( fd_cstr_printf_check( config->hugetlbfs.normal_page_mount_path,
    sizeof(config->hugetlbfs.normal_page_mount_path),
    NULL,
    "%s/.normal",
    config->hugetlbfs.mount_path ) );

  ulong max_page_sz = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  if( FD_UNLIKELY( max_page_sz!=FD_SHMEM_HUGE_PAGE_SZ && max_page_sz!=FD_SHMEM_GIGANTIC_PAGE_SZ ) ) FD_LOG_ERR(( "[hugetlbfs.max_page_size] must be \"huge\" or \"gigantic\"" ));

  replace( config->log.path, "{user}", config->user );
  replace( config->log.path, "{name}", config->name );

  if( FD_LIKELY( !strcmp( "auto", config->log.colorize ) ) )       config->log.colorize1 = 2;
  else if( FD_LIKELY( !strcmp( "true", config->log.colorize ) ) )  config->log.colorize1 = 1;
  else if( FD_LIKELY( !strcmp( "false", config->log.colorize ) ) ) config->log.colorize1 = 0;
  else  FD_LOG_ERR(( "[log.colorize] must be one of \"auto\", \"true\", or \"false\"" ));

  if( FD_LIKELY( 2==config->log.colorize1 ) ) {
    char const * cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "COLORTERM", NULL );
    int truecolor = cstr && !strcmp( cstr, "truecolor" );

    cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "TERM", NULL );
    int color256 = cstr && strstr( cstr, "256color" );

    config->log.colorize1 = truecolor || color256;
  }

  config->log.level_logfile1 = parse_log_level( config->log.level_logfile );
  config->log.level_stderr1  = parse_log_level( config->log.level_stderr );
  config->log.level_flush1   = parse_log_level( config->log.level_flush );
  if( FD_UNLIKELY( -1==config->log.level_logfile1 ) ) FD_LOG_ERR(( "unrecognized [log.level_logfile] `%s`", config->log.level_logfile ));
  if( FD_UNLIKELY( -1==config->log.level_stderr1 ) )  FD_LOG_ERR(( "unrecognized [log.level_stderr] `%s`", config->log.level_logfile ));
  if( FD_UNLIKELY( -1==config->log.level_flush1 ) )   FD_LOG_ERR(( "unrecognized [log.level_flush] `%s`", config->log.level_logfile ));

  replace( config->paths.base, "{user}", config->user );
  replace( config->paths.base, "{name}", config->name );

  if( FD_UNLIKELY( strcmp( config->paths.ledger, "" ) ) ) {
    replace( config->paths.ledger, "{user}", config->user );
    replace( config->paths.ledger, "{name}", config->name );
  } else {
    FD_TEST( fd_cstr_printf_check( config->paths.ledger, sizeof(config->paths.ledger), NULL, "%s/ledger", config->paths.base ) );
  }

  if( FD_UNLIKELY( !strcmp( config->paths.identity_key, "" ) ) ) {
    if( FD_UNLIKELY( config->is_live_cluster ) ) FD_LOG_ERR(( "configuration file must specify [consensus.identity_path] when joining a live cluster" ));

    FD_TEST( fd_cstr_printf_check( config->paths.identity_key,
                                   sizeof(config->paths.identity_key),
                                   NULL,
                                   "%s/identity.json",
                                   config->paths.base ) );
  } else {
    replace( config->paths.identity_key, "{user}", config->user );
    replace( config->paths.identity_key, "{name}", config->name );
  }

  replace( config->paths.vote_account, "{user}", config->user );
  replace( config->paths.vote_account, "{name}", config->name );

  if( FD_UNLIKELY( strcmp( config->paths.snapshots, "" ) ) ) {
    replace( config->paths.snapshots, "{user}", config->user );
    replace( config->paths.snapshots, "{name}", config->name );
  } else {
    FD_TEST( fd_cstr_printf_check( config->paths.snapshots, sizeof(config->paths.snapshots), NULL, "%s/snapshots", config->paths.base ) );
  }

  if( FD_UNLIKELY( strcmp( config->paths.genesis, "" ) ) ) {
    replace( config->paths.genesis, "{user}", config->user );
    replace( config->paths.genesis, "{name}", config->name );
  } else {
    FD_TEST( fd_cstr_printf_check( config->paths.genesis, sizeof(config->paths.genesis), NULL, "%s/genesis.bin", config->paths.base ) );
  }

  long ts = -fd_log_wallclock();
  config->tick_per_ns_mu = fd_tempo_tick_per_ns( &config->tick_per_ns_sigma );
  FD_LOG_INFO(( "calibrating fd_tempo tick_per_ns took %ld ms", (fd_log_wallclock()+ts)/(1000L*1000L) ));

  if( 0!=strcmp( config->net.bind_address, "" ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->net.bind_address, &config->net.bind_address_parsed ) ) ) {
      FD_LOG_ERR(( "`net.bind_address` is not a valid IPv4 address" ));
    }
  }

  if(      FD_LIKELY( !strcmp( config->tiles.pack.schedule_strategy, "perf"     ) ) ) config->tiles.pack.schedule_strategy_enum = 0;
  else if( FD_LIKELY( !strcmp( config->tiles.pack.schedule_strategy, "balanced" ) ) ) config->tiles.pack.schedule_strategy_enum = 1;
  else if( FD_LIKELY( !strcmp( config->tiles.pack.schedule_strategy, "revenue"  ) ) ) config->tiles.pack.schedule_strategy_enum = 2;
  else FD_LOG_ERR(( "[tiles.pack.schedule_strategy] %s not recognized", config->tiles.pack.schedule_strategy ));

  fd_config_fill_net( config );

  if( FD_UNLIKELY( config->is_firedancer ) ) {
    fd_config_fillf( config );
  } else {
    fd_config_fillh( config );
  }


  if(      FD_LIKELY( !strcmp( config->development.gui.frontend_release_channel, "stable" ) ) ) config->development.gui.frontend_release_channel_enum = 0;
  else if( FD_LIKELY( !strcmp( config->development.gui.frontend_release_channel, "alpha"  ) ) ) config->development.gui.frontend_release_channel_enum = 1;
  else FD_LOG_ERR(( "[development.gui.release_channel] %s not recognized", config->development.gui.frontend_release_channel ));

  if( FD_LIKELY( config->is_live_cluster) ) {
    if( FD_UNLIKELY( !config->development.sandbox ) )                            FD_LOG_ERR(( "trying to join a live cluster, but configuration disables the sandbox which is a a development only feature" ));
    if( FD_UNLIKELY( config->development.no_clone ) )                            FD_LOG_ERR(( "trying to join a live cluster, but configuration disables multiprocess which is a development only feature" ));
    if( FD_UNLIKELY( config->development.netns.enabled ) )                       FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.netns] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.larger_max_cost_per_block ) )     FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.larger_max_cost_per_block] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.larger_shred_limits_per_block ) ) FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.larger_shred_limits_per_block] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.disable_blockstore_from_slot ) )  FD_LOG_ERR(( "trying to join a live cluster, but configuration has a non-zero value for [development.bench.disable_blockstore_from_slot] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.disable_status_cache ) )          FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.disable_status_cache] which is a development only feature" ));
  }

  /* When running a local cluster, some options are overriden by default
     to make starting and running in development environments a little
     easier and less strict. */
  if( FD_UNLIKELY( is_local_cluster ) ) {
    if( FD_LIKELY( !strcmp( config->paths.vote_account, "" ) ) ) {
      FD_TEST( fd_cstr_printf_check( config->paths.vote_account,
                                     sizeof( config->paths.vote_account ),
                                     NULL,
                                     "%s/vote-account.json",
                                     config->paths.base ) );
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

  if( FD_UNLIKELY( config->is_firedancer && config->is_live_cluster && cluster!=FD_CLUSTER_TESTNET ) )
    FD_LOG_ERR(( "Attempted to start against live cluster `%s`. Firedancer is not "
                 "ready for production deployment, has not been tested, and is "
                 "missing consensus critical functionality. Joining a live Solana "
                 "cluster may destabilize the network. Please do not attempt. You "
                 "can start against the testnet cluster by specifying the testnet "
                 "entrypoints from https://docs.solana.com/clusters under "
                 "[gossip.entrypoints] in your configuration file.", fd_genesis_cluster_name( cluster ) ));
}

#define CFG_HAS_NON_EMPTY( key ) do {                  \
  if( !strnlen( config->key, sizeof(config->key) ) ) { \
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
  CFG_HAS_NON_ZERO( layout.snaplta_tile_count );
  if( FD_UNLIKELY( config->layout.sign_tile_count < 2 ) ) {
    FD_LOG_ERR(( "layout.sign_tile_count must be >= 2" ));
  }
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
  CFG_HAS_NON_ZERO ( layout.net_tile_count );
  CFG_HAS_NON_ZERO ( layout.quic_tile_count );
  CFG_HAS_NON_ZERO ( layout.resolv_tile_count );
  CFG_HAS_NON_ZERO ( layout.verify_tile_count );
  CFG_HAS_NON_ZERO ( layout.bank_tile_count  );
  CFG_HAS_NON_ZERO ( layout.shred_tile_count );

  CFG_HAS_NON_EMPTY( hugetlbfs.mount_path );
  CFG_HAS_NON_EMPTY( hugetlbfs.max_page_size );

  CFG_HAS_NON_ZERO( net.ingress_buffer_size );
  if( 0==strcmp( config->net.provider, "xdp" ) ) {
    CFG_HAS_NON_EMPTY( net.xdp.xdp_mode );
    CFG_HAS_POW2     ( net.xdp.xdp_rx_queue_size );
    CFG_HAS_POW2     ( net.xdp.xdp_tx_queue_size );
    if( 0==strcmp( config->net.xdp.rss_queue_mode, "dedicated" ) ) {
      if( FD_UNLIKELY( config->layout.net_tile_count != 1 ) )
        FD_LOG_ERR(( "`layout.net_tile_count` must be 1 when `net.xdp.rss_queue_mode` is \"dedicated\"" ));
    } else if( 0!=strcmp( config->net.xdp.rss_queue_mode, "simple" ) ) {
      FD_LOG_ERR(( "invalid `net.xdp.rss_queue_mode`: \"%s\"; must be \"simple\" or \"dedicated\"",
                   config->net.xdp.rss_queue_mode  ));
    }
  } else if( 0==strcmp( config->net.provider, "socket" ) ) {
    CFG_HAS_NON_ZERO( net.socket.receive_buffer_size );
    CFG_HAS_NON_ZERO( net.socket.send_buffer_size );
  } else {
    FD_LOG_ERR(( "invalid `net.provider`: must be \"xdp\" or \"socket\"" ));
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
  }

  if( FD_UNLIKELY( config->tiles.bundle.keepalive_interval_millis <    3000 &&
                   config->tiles.bundle.keepalive_interval_millis > 3600000 ) ) {
    FD_LOG_ERR(( "`tiles.bundle.keepalive_interval_millis` must be in range [3000, 3,600,000]" ));
  }

  CFG_HAS_NON_EMPTY( development.netns.interface0 );
  CFG_HAS_NON_EMPTY( development.netns.interface0_mac );
  CFG_HAS_NON_EMPTY( development.netns.interface0_addr );
  CFG_HAS_NON_EMPTY( development.netns.interface1 );
  CFG_HAS_NON_EMPTY( development.netns.interface1_mac );
  CFG_HAS_NON_EMPTY( development.netns.interface1_addr );

  CFG_HAS_NON_ZERO( development.genesis.target_tick_duration_micros );
  CFG_HAS_NON_ZERO( development.genesis.ticks_per_slot );
  CFG_HAS_NON_ZERO( development.genesis.fund_initial_accounts );
  CFG_HAS_NON_ZERO( development.genesis.fund_initial_amount_lamports );

  CFG_HAS_NON_ZERO ( development.bench.benchg_tile_count );
  CFG_HAS_NON_ZERO ( development.bench.benchs_tile_count );
  CFG_HAS_NON_EMPTY( development.bench.affinity );

  CFG_HAS_NON_ZERO( development.bundle.ssl_heap_size_mib );
}

#undef CFG_HAS_NON_EMPTY
#undef CFG_HAS_NON_ZERO
#undef CFG_HAS_POW2

void
fd_config_load( int           is_firedancer,
                int           netns,
                int           is_local_cluster,
                char const *  default_config,
                ulong         default_config_sz,
                char const *  override_config,
                char const *  override_config_path,
                ulong         override_config_sz,
                char const *  user_config,
                ulong         user_config_sz,
                char const *  user_config_path,
                fd_config_t * config ) {
  memset( config, 0, sizeof(config_t) );
  config->is_firedancer = is_firedancer;
  config->boot_timestamp_nanos = fd_log_wallclock();

  if( FD_UNLIKELY( is_firedancer ) ) {
    fd_cstr_printf_check( config->development.gui.frontend_release_channel, sizeof(config->development.gui.frontend_release_channel), NULL, "alpha" );
  } else {
    fd_cstr_printf_check( config->development.gui.frontend_release_channel, sizeof(config->development.gui.frontend_release_channel), NULL, "stable" );
  }

  fd_config_load_buf( config, default_config, default_config_sz, "default.toml" );
  fd_config_validate( config );
  if( FD_UNLIKELY( override_config ) ) {
    fd_config_load_buf( config, override_config, override_config_sz, override_config_path );
    fd_config_validate( config );
  }
  if( FD_LIKELY( user_config ) ) {
    fd_config_load_buf( config, user_config, user_config_sz, user_config_path );
    fd_config_validate( config );
  }

  fd_config_fill( config, netns, is_local_cluster);
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
  if( FD_UNLIKELY( munmap( bytes, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return config_memfd;
}
