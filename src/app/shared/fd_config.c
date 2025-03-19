#define _GNU_SOURCE
#include "fd_config.h"

#include "fd_config_parse.h"
#include "fd_net_util.h"
#include "fd_sys_util.h"
#include "../../ballet/toml/fd_toml.h"
#include "../../flamenco/genesis/fd_genesis_cluster.h"

#include <errno.h>
#include <stdlib.h> /* strtoul */
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>

extern uchar const fdctl_default_config[];
extern ulong const fdctl_default_config_sz;

extern uchar const fdctl_default_firedancer_config[];
extern ulong const fdctl_default_firedancer_config_sz;

/* FD_TOML_POD_SZ sets the buffer size of the fd_pod that will hold the
   parsed config file content.

   This should be large enough to hold a Firedancer TOML file with all
   config options set. */

#define FD_TOML_POD_SZ (1UL<<20)

FD_FN_CONST static int
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

/* TODO: Rewrite this ... */

void
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

static void
validate_ports( config_t * result ) {
  char dynamic_port_range[ 32 ];
  fd_memcpy( dynamic_port_range, result->dynamic_port_range, sizeof(dynamic_port_range) );

  char * dash = strstr( dynamic_port_range, "-" );
  if( FD_UNLIKELY( !dash ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));

  *dash = '\0';
  char * endptr;
  ulong agave_port_min = strtoul( dynamic_port_range, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || agave_port_min > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));
  ulong agave_port_max = strtoul( dash + 1, &endptr, 10 );
  if( FD_UNLIKELY( *endptr != '\0' || agave_port_max > USHORT_MAX ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "This must be formatted like `<min>-<max>`",
                 result->dynamic_port_range ));
  if( FD_UNLIKELY( agave_port_min > agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [dynamic_port_range] `%s`. "
                 "The minimum port must be less than or equal to the maximum port",
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.quic.regular_transaction_listen_port >= agave_port_min &&
                   result->tiles.quic.regular_transaction_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.quic.regular_transaction_listen_port,
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.quic.quic_transaction_listen_port >= agave_port_min &&
                   result->tiles.quic.quic_transaction_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.quic.quic_transaction_listen_port,
                 result->dynamic_port_range ));

  if( FD_UNLIKELY( result->tiles.shred.shred_listen_port >= agave_port_min &&
                   result->tiles.shred.shred_listen_port < agave_port_max ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.shred.shred_listen_port] `%hu`. "
                 "This must be outside the dynamic port range `%s`",
                 result->tiles.shred.shred_listen_port,
                 result->dynamic_port_range ));
}

static void
fdctl_cfg_load_buf( config_t *   out,
                    char const * buf,
                    ulong        sz,
                    char const * path ) {

  static uchar pod_mem[ 1UL<<30 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  fd_toml_err_info_t toml_err[1];
  uchar scratch[ 4096 ];
  int toml_errc = fd_toml_parse( buf, sz, pod, scratch, sizeof(scratch), toml_err );
  if( FD_UNLIKELY( toml_errc!=FD_TOML_SUCCESS ) ) {
    /* Override the default error messages of fd_toml for a better user
       experience */
    switch( toml_errc ) {
    case FD_TOML_ERR_POD:
      FD_LOG_ERR(( "Failed to parse config file (%s): ran out of buffer space while parsing (Increase FD_TOML_POD_SZ?)", path ));
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

  if( FD_UNLIKELY( !fdctl_pod_to_cfg( out, pod ) ) ) {
    FD_LOG_ERR(( "Invalid config (%s)", path ));
  }

  fd_pod_delete( fd_pod_leave( pod ) );
}

static void
fdctl_cfg_load_file( config_t *   out,
                     char const * path ) {

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  struct stat st;
  if( FD_UNLIKELY( fstat( fd, &st ) ) ) {
    FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  ulong toml_sz = (ulong)st.st_size;

  if( FD_UNLIKELY( toml_sz==0UL ) ) {
    if( FD_UNLIKELY( 0!=close( fd ) ) ) {
      FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    return;
  }

  void * mem = mmap( NULL, toml_sz, PROT_READ, MAP_PRIVATE, fd, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=close( fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fdctl_cfg_load_buf( out, mem, toml_sz, path );

  if( FD_UNLIKELY( 0!=munmap( mem, toml_sz ) ) ) {
    FD_LOG_ERR(( "munmap(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
}

void
fdctl_cfg_from_env( int *      pargc,
                    char ***   pargv,
                    config_t * config ) {

  memset( config, 0, sizeof(config_t) );
  fdctl_cfg_load_buf( config, (char const *)fdctl_default_config, fdctl_default_config_sz, "default" );
#if FD_HAS_NO_AGAVE
  fdctl_cfg_load_buf( config, (char const *)fdctl_default_firedancer_config, fdctl_default_firedancer_config_sz, "default_firedancer" );
#endif

  const char * user_config = fd_env_strip_cmdline_cstr(
      pargc,
      pargv,
      "--config",
      "FIREDANCER_CONFIG_TOML",
      NULL );

  if( FD_LIKELY( user_config ) ) {
    fdctl_cfg_load_file( config, user_config );
  }

  int netns = fd_env_strip_cmdline_contains( pargc, pargv, "--netns" );
  if( FD_UNLIKELY( netns ) ) {
    config->development.netns.enabled = 1;
    strncpy( config->tiles.net.interface,
             config->development.netns.interface0,
             sizeof(config->tiles.net.interface) );
    config->tiles.net.interface[ sizeof(config->tiles.net.interface) - 1 ] = '\0';
  }

  if( FD_UNLIKELY( !strcmp( config->user, "" ) ) ) {
    const char * user = fd_sys_util_login_user();
    if( FD_UNLIKELY( !user ) ) FD_LOG_ERR(( "could not automatically determine a user to run Firedancer as. You must specify a [user] in your configuration TOML file." ));
    if( FD_UNLIKELY( strlen( user ) >= sizeof( config->user ) ) )
                              FD_LOG_ERR(( "user name `%s` is too long", user ));
    strncpy( config->user, user, 256 );
  }

  struct utsname utsname;
  if( FD_UNLIKELY( -1==uname( &utsname ) ) )
    FD_LOG_ERR(( "could not get uname (%i-%s)", errno, fd_io_strerror( errno ) ));
  strncpy( config->hostname, utsname.nodename, sizeof(config->hostname) );
  config->hostname[ sizeof(config->hostname)-1UL ] = '\0'; /* Just truncate the name if it's too long to fit */

  ulong cluster = fd_genesis_cluster_identify( config->consensus.expected_genesis_hash );
  config->is_live_cluster = cluster != FD_CLUSTER_UNKNOWN;

  fdctl_cfg_net_auto( config );

  if( FD_UNLIKELY( -1==fd_sys_util_user_to_uid( config->user, &config->uid, &config->gid ) ) )
    FD_LOG_ERR(( "configuration file wants firedancer to run as user `%s` but it does not exist", config->user ));

  if( FD_UNLIKELY( !config->uid || !config->gid ) )
    FD_LOG_ERR(( "firedancer cannot run as root. please specify a non-root user in the configuration file" ));

  if( FD_UNLIKELY( getuid() != 0 && config->uid != getuid() ) )
    FD_LOG_ERR(( "running as uid %u, but config specifies uid %u", getuid(), config->uid ));
  if( FD_UNLIKELY( getgid() != 0 && config->gid != getgid() ) )
    FD_LOG_ERR(( "running as gid %u, but config specifies gid %u", getgid(), config->gid ));

  ulong len = strlen( config->hugetlbfs.mount_path );
  if( FD_UNLIKELY( !len ) ) FD_LOG_ERR(( "[hugetlbfs.mount_path] must be non-empty in your configuration file" ));
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

  ulong max_page_sz = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  if( FD_UNLIKELY( max_page_sz!=FD_SHMEM_HUGE_PAGE_SZ && max_page_sz!=FD_SHMEM_GIGANTIC_PAGE_SZ ) ) {
    FD_LOG_ERR(( "[hugetlbfs.max_page_size] must be \"huge\" or \"gigantic\"" ));
  }

  replace( config->log.path, "{user}", config->user );
  replace( config->log.path, "{name}", config->name );
  if( FD_LIKELY( !strcmp( "auto", config->log.colorize ) ) )       config->log.colorize1 = 2;
  else if( FD_LIKELY( !strcmp( "true", config->log.colorize ) ) )  config->log.colorize1 = 1;
  else if( FD_LIKELY( !strcmp( "false", config->log.colorize ) ) ) config->log.colorize1 = 0;
  else FD_LOG_ERR(( "[log.colorize] must be one of \"auto\", \"true\", or \"false\"" ));

  if( FD_LIKELY( 2==config->log.colorize1 ) ) {
    char const * cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "COLORTERM", NULL );
    int truecolor = cstr && !strcmp( cstr, "truecolor" );

    cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "TERM", NULL );
    int xterm256color = cstr && !strcmp( cstr, "xterm-256color" );

    config->log.colorize1 = truecolor || xterm256color;
  }

  config->log.level_logfile1 = parse_log_level( config->log.level_logfile );
  config->log.level_stderr1  = parse_log_level( config->log.level_stderr );
  config->log.level_flush1   = parse_log_level( config->log.level_flush );
  if( FD_UNLIKELY( -1==config->log.level_logfile1 ) ) FD_LOG_ERR(( "unrecognized [log.level_logfile] `%s`", config->log.level_logfile ));
  if( FD_UNLIKELY( -1==config->log.level_stderr1 ) )  FD_LOG_ERR(( "unrecognized [log.level_stderr] `%s`", config->log.level_logfile ));
  if( FD_UNLIKELY( -1==config->log.level_flush1 ) )   FD_LOG_ERR(( "unrecognized [log.level_flush] `%s`", config->log.level_logfile ));

  replace( config->scratch_directory, "{user}", config->user );
  replace( config->scratch_directory, "{name}", config->name );

  if( FD_UNLIKELY( strcmp( config->ledger.path, "" ) ) ) {
    replace( config->ledger.path, "{user}", config->user );
    replace( config->ledger.path, "{name}", config->name );
  } else {
    FD_TEST( fd_cstr_printf_check( config->ledger.path, sizeof(config->ledger.path), NULL, "%s/ledger", config->scratch_directory ) );
  }

  if( FD_UNLIKELY( strcmp( config->snapshots.path, "" ) ) ) {
    replace( config->snapshots.path, "{user}", config->user );
    replace( config->snapshots.path, "{name}", config->name );
  } else {
    strncpy( config->snapshots.path, config->ledger.path, sizeof(config->snapshots.path) );
  }

  if( FD_UNLIKELY( !strcmp( config->consensus.identity_path, "" ) ) ) {
    FD_TEST( fd_cstr_printf_check( config->consensus.identity_path,
                                   sizeof(config->consensus.identity_path),
                                   NULL,
                                   "%s/identity.json",
                                   config->scratch_directory ) );
  } else {
    replace( config->consensus.identity_path, "{user}", config->user );
    replace( config->consensus.identity_path, "{name}", config->name );
  }

#if FD_HAS_NO_AGAVE
  if( FD_UNLIKELY( !strcmp( config->consensus.vote_account_path, "" ) ) ) {
    FD_TEST( fd_cstr_printf_check( config->consensus.vote_account_path,
                                   sizeof(config->consensus.vote_account_path),
                                   NULL,
                                   "%s/vote-account.json",
                                   config->scratch_directory ) );
  }
#endif
  replace( config->consensus.vote_account_path, "{user}", config->user );
  replace( config->consensus.vote_account_path, "{name}", config->name );

  for( ulong i=0UL; i<config->consensus.authorized_voter_paths_cnt; i++ ) {
    replace( config->consensus.authorized_voter_paths[ i ], "{user}", config->user );
    replace( config->consensus.authorized_voter_paths[ i ], "{name}", config->name );
  }

  strcpy( config->cluster, fd_genesis_cluster_name( cluster ) );

#if FD_HAS_NO_AGAVE
  if( FD_UNLIKELY( config->is_live_cluster && cluster!=FD_CLUSTER_TESTNET ) )
    FD_LOG_ERR(( "Attempted to start against live cluster `%s`. Firedancer is not "
                 "ready for production deployment, has not been tested, and is "
                 "missing consensus critical functionality. Joining a live Solana "
                 "cluster may destabilize the network. Please do not attempt. You "
                 "can start against the testnet cluster by specifying the testnet "
                 "entrypoints from https://docs.solana.com/clusters under "
                 "[gossip.entrypoints] in your configuration file.", fd_genesis_cluster_name( cluster ) ));
#endif /* FD_HAS_NO_AGAVE */

  if( FD_LIKELY( config->is_live_cluster) ) {
    if( FD_UNLIKELY( !config->development.sandbox ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration disables the sandbox which is a a development only feature" ));
    if( FD_UNLIKELY( config->development.no_clone ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration disables multiprocess which is a development only feature" ));
    if( FD_UNLIKELY( config->development.netns.enabled ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.netns] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.larger_max_cost_per_block ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.larger_max_cost_per_block] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.larger_shred_limits_per_block ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.larger_shred_limits_per_block] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.disable_blockstore_from_slot ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration has a non-zero value for [development.bench.disable_blockstore_from_slot] which is a development only feature" ));
    if( FD_UNLIKELY( config->development.bench.disable_status_cache ) )
      FD_LOG_ERR(( "trying to join a live cluster, but configuration enables [development.bench.disable_status_cache] which is a development only feature" ));
  }

  if( FD_UNLIKELY( config->tiles.quic.quic_transaction_listen_port != config->tiles.quic.regular_transaction_listen_port + 6 ) )
    FD_LOG_ERR(( "configuration specifies invalid [tiles.quic.quic_transaction_listen_port] `%hu`. "
                 "This must be 6 more than [tiles.quic.regular_transaction_listen_port] `%hu`",
                 config->tiles.quic.quic_transaction_listen_port,
                 config->tiles.quic.regular_transaction_listen_port ));

  if( FD_LIKELY( !strcmp( config->consensus.identity_path, "" ) ) ) {
    if( FD_UNLIKELY( config->is_live_cluster ) )
      FD_LOG_ERR(( "configuration file must specify [consensus.identity_path] when joining a live cluster" ));

    FD_TEST( fd_cstr_printf_check( config->consensus.identity_path,
                                   sizeof(config->consensus.identity_path),
                                   NULL,
                                   "%s/identity.json",
                                   config->scratch_directory ) );
  }

  fdctl_cfg_validate( config );
  validate_ports( config );
}

void
fdctl_cfg_net_auto( config_t * config ) {

  if( FD_UNLIKELY( !strcmp( config->tiles.net.interface, "" ) && !config->development.netns.enabled ) ) {
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

    if( FD_UNLIKELY( !if_indextoname( ifindex, config->tiles.net.interface ) ) )
      FD_LOG_ERR(( "could not get name of interface with index %u", ifindex ));
  }

  if( FD_UNLIKELY( config->development.netns.enabled ) ) {

    if( !strcmp( config->tiles.net.interface, "" ) ) {
      memcpy( config->tiles.net.interface, config->development.netns.interface0, sizeof(config->tiles.net.interface) );
    }

    if( !strcmp( config->development.pktgen.fake_dst_ip, "" ) ) {
      memcpy( config->development.pktgen.fake_dst_ip, config->development.netns.interface1_addr, sizeof(config->development.netns.interface1_addr) );
    }

    if( FD_UNLIKELY( strcmp( config->development.netns.interface0, config->tiles.net.interface ) ) ) {
      FD_LOG_ERR(( "netns interface and firedancer interface are different. If you are using the "
                   "[development.netns] functionality to run Firedancer in a network namespace "
                   "for development, the configuration file must specify that "
                   "[development.netns.interface0] is the same as [tiles.net.interface]" ));
    }

    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->development.netns.interface0_addr, &config->tiles.net.ip_addr ) ) )
      FD_LOG_ERR(( "configuration specifies invalid netns IP address `%s`", config->development.netns.interface0_addr ));

  } else { /* !config->development.netns.enabled */

    if( FD_UNLIKELY( !if_nametoindex( config->tiles.net.interface ) ) )
      FD_LOG_ERR(( "configuration specifies network interface `%s` which does not exist", config->tiles.net.interface ));
    uint iface_ip;
    if( FD_UNLIKELY( -1==fd_net_util_if_addr( config->tiles.net.interface, &iface_ip ) ) )
      FD_LOG_ERR(( "could not get IP address for interface `%s`", config->tiles.net.interface ));

    if( FD_UNLIKELY( strcmp( config->gossip.host, "" ) ) ) {
      uint gossip_ip_addr = iface_ip;
      int  has_gossip_ip4 = 0;
      if( FD_UNLIKELY( strlen( config->gossip.host )<=15UL ) ) {
        /* Only sets gossip_ip_addr if it's a valid IPv4 address, otherwise assume it's a DNS name */
        has_gossip_ip4 = fd_cstr_to_ip4_addr( config->gossip.host, &gossip_ip_addr );
      }
      if( FD_UNLIKELY( !fd_ip4_addr_is_public( gossip_ip_addr ) && config->is_live_cluster && has_gossip_ip4 ) )
        FD_LOG_ERR(( "Trying to use [gossip.host] " FD_IP4_ADDR_FMT " for listening to incoming "
                     "transactions, but it is part of a private network and will not be routable "
                     "for other Solana network nodes.",
                     FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
    } else if( FD_UNLIKELY( !fd_ip4_addr_is_public( iface_ip ) && config->is_live_cluster ) ) {
      FD_LOG_ERR(( "Trying to use network interface `%s` for listening to incoming transactions, "
                   "but it has IPv4 address " FD_IP4_ADDR_FMT " which is part of a private network "
                   "and will not be routable for other Solana network nodes. If you are running "
                   "behind a NAT and this interface is publicly reachable, you can continue by "
                   "manually specifying the IP address to advertise in your configuration under "
                   "[gossip.host].",
                   config->tiles.net.interface, FD_IP4_ADDR_FMT_ARGS( iface_ip ) ));
    }

    config->tiles.net.ip_addr = iface_ip;

  }

}

int
fdctl_cfg_to_memfd( config_t const * config ) {
  int config_memfd = memfd_create( "fd_config", 0 );
  if( FD_UNLIKELY( -1==config_memfd ) ) FD_LOG_ERR(( "memfd_create() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==ftruncate( config_memfd, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "ftruncate() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  uchar * bytes = mmap( NULL, sizeof( config_t ), PROT_READ | PROT_WRITE, MAP_SHARED, config_memfd, 0 );
  if( FD_UNLIKELY( bytes == MAP_FAILED ) ) FD_LOG_ERR(( "mmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_memcpy( bytes, config, sizeof( config_t ) );
  if( FD_UNLIKELY( munmap( bytes, sizeof( config_t ) ) ) ) FD_LOG_ERR(( "munmap() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return config_memfd;
}
