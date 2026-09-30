#include "fd_config_private.h"
#include "../../ballet/toml/fd_toml.h"

#include <sys/wait.h>
#include <unistd.h>

static char const cfg_str_1[] =
  "[gossip]\n"
  "  entrypoints = [\"208.91.106.45:8080\"]";

static char const cfg_str_oversized_array[] =
  "[ledger]\n"
  "  account_indexes = [\"01234567890123456789012345678901\"]";

static char const cfg_str_invalid_aliased_array[] =
  "[consensus]\n"
  "  authorized_voter_paths = [1]";

static char const cfg_str_2[] =
  "wumbo = \"mini\"";

/* Auto config specific */
static char const cfg_str_3[] =
  "[net.xdp]\n  xdp_zero_copy = \"auto\"\n  native_bond = \"auto\"";
static char const cfg_str_4[] =
  "[net.xdp]\n  xdp_zero_copy = \"something wrong\"";
static char const cfg_str_5[] =
  "[development.genesis]\n"
  "  max_file_size_mib = 33";
static char const cfg_str_vote_history[] =
  "[paths]\n"
  "  vote_history = \"/data/{name}/vote_history\"\n"
  "[tiles.tower]\n"
  "  write_vote_history_file = false\n"
  "[tiles.votor]\n"
  "  write_vote_history_file = true";
static char const cfg_str_failover[] =
  "[failover]\n"
  "  enabled = true\n"
  "  listen_address = \"10.0.0.1\"\n"
  "  listen_port = 9010";

extern uchar const fdctl_default_config[];
extern ulong const fdctl_default_config_sz;

static int
genesis_max_file_size_is_valid( config_t * config,
                                ulong      max_file_size_mib ) {
  int pid = fork();
  FD_TEST( pid>=0 );
  if( FD_UNLIKELY( !pid ) ) {
    config->firedancer.development.genesis.max_file_size_mib = max_file_size_mib;
    fd_config_validate( config );
    _exit( 0 );
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  return WIFEXITED( status ) && !WEXITSTATUS( status );
}

static int
vote_history_path_is_valid( char const * path ) {
  int pid = fork();
  FD_TEST( pid>=0 );
  if( FD_UNLIKELY( !pid ) ) {
    char toml[ 256 ];
    FD_TEST( fd_cstr_printf_check( toml, sizeof(toml), NULL, "[paths]\n  vote_history = \"%s\"", path ) );
    static uchar pod_mem[ 1UL<<16 ];
    static uchar scratch[ 4096 ];
    static config_t config[1];
    config->is_firedancer = 1;
    uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
    FD_TEST( fd_toml_parse( toml, strlen( toml ), pod, scratch, sizeof(scratch), NULL )==FD_TOML_SUCCESS );
    _exit( fd_config_extract_pod( pod, config )!=config ); /* exits 1 on an invalid path */
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  return WIFEXITED( status ) && !WEXITSTATUS( status );
}

/* Validates the config with the given failover knobs in a child, so the
   FD_LOG_ERR paths can be checked. */

static int
failover_is_valid( config_t *   config,
                   int          enabled,
                   char const * listen_address,
                   ushort       listen_port,
                   char const * vote_account,
                   int          alpenglow ) {
  int pid = fork();
  FD_TEST( pid>=0 );
  if( FD_UNLIKELY( !pid ) ) {
    config->firedancer.development.genesis.max_file_size_mib = 4055UL;
    config->firedancer.consensus.alpenglow                   = alpenglow;
    config->firedancer.failover.enabled                      = enabled;
    config->firedancer.failover.listen_port                  = listen_port;
    fd_cstr_ncpy( config->firedancer.failover.listen_address, listen_address, sizeof(config->firedancer.failover.listen_address) );
    fd_cstr_ncpy( config->paths.vote_account, vote_account, sizeof(config->paths.vote_account) );
    fd_config_validate( config );
    _exit( 0 );
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  return WIFEXITED( status ) && !WEXITSTATUS( status );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Parse a basic config string */

  static uchar pod_mem[ 1UL<<16 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  static uchar scratch[ 4096 ];
  FD_TEST( fd_toml_parse( cfg_str_1, sizeof(cfg_str_1)-1, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );

  static config_t config[1];
  FD_TEST( fd_config_extract_pod( pod, config ) == config );

  FD_TEST( config->gossip.entrypoints_cnt == 1 );
  FD_TEST( 0==strcmp( config->gossip.entrypoints[0], "208.91.106.45:8080" ) );

  /* Maximum-sized URLs and shred destinations survive config extraction. */

  char endpoint[ FD_URL_MAX ];
  fd_memcpy( endpoint, "https://", 8UL );
  fd_memset( endpoint+8UL, 'a', FD_FQDN_BUF_MAX-1UL );
  fd_memcpy( endpoint+8UL+FD_FQDN_BUF_MAX-1UL, ":65535", 6UL );
  endpoint[ FD_URL_MAX-1UL ] = '\0';

  char  cfg_str_limits[ 4096 ];
  ulong cfg_str_limits_sz;
  FD_TEST( fd_cstr_printf_check( cfg_str_limits, sizeof(cfg_str_limits), &cfg_str_limits_sz,
                                "[snapshots.sources]\n"
                                "servers = [\"%s\"]\n"
                                "[tiles.bundle]\n"
                                "url = \"%s\"\n"
                                "[tiles.shred]\n"
                                "additional_shred_destinations_retransmit = [\"%s\"]\n"
                                "additional_shred_destinations_leader = [\"%s\"]\n",
                                endpoint, endpoint, endpoint+8UL, endpoint+8UL ) );

  memset( config, 0, sizeof(config_t) );
  config->is_firedancer = 1;
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_limits, cfg_str_limits_sz, pod, scratch, sizeof(scratch), NULL )==FD_TOML_SUCCESS );
  FD_TEST( fd_config_extract_pod( pod, config )==config );
  FD_TEST( config->firedancer.snapshots.sources.servers_cnt==1UL );
  FD_TEST( !strcmp( config->firedancer.snapshots.sources.servers[0], endpoint ) );
  FD_TEST( !strcmp( config->tiles.bundle.url, endpoint ) );
  FD_TEST( config->tiles.shred.additional_shred_destinations_retransmit_cnt==1UL &&
           !strcmp( config->tiles.shred.additional_shred_destinations_retransmit[ 0 ], endpoint+8UL ) );
  FD_TEST( config->tiles.shred.additional_shred_destinations_leader_cnt==1UL &&
           !strcmp( config->tiles.shred.additional_shred_destinations_leader[ 0 ], endpoint+8UL ) );

  /* Reject invalid direct and aliased array elements. */

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_oversized_array, sizeof(cfg_str_oversized_array)-1UL, pod, scratch, sizeof(scratch), NULL )==FD_TOML_SUCCESS );
  FD_TEST( !fd_config_extract_pod( pod, config ) );

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_invalid_aliased_array, sizeof(cfg_str_invalid_aliased_array)-1UL, pod, scratch, sizeof(scratch), NULL )==FD_TOML_SUCCESS );
  FD_TEST( !fd_config_extract_pod( pod, config ) );

  /* Reject unrecognized config keys */

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_2, sizeof(cfg_str_2)-1, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );
  FD_TEST( !fd_config_extract_pod( pod, config ) );

  /* The default config must parse fine */

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( fdctl_default_config, fdctl_default_config_sz, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );
  FD_TEST( fd_config_extract_pod( pod, config ) == config );
  fd_config_validate( config );  /* exits process with code 1 on failure */

  strcpy( config->net.provider, "auto" );
  fd_config_validate( config );
  strcpy( config->net.provider, "xdp" );

  /* bzip2's avail_in and avail_out fields are uint. */

  config->is_firedancer = 1;
  memset( &config->firedancer, 0, sizeof(config->firedancer) );
  config->firedancer.layout.sign_tile_count          = 2U;
  config->firedancer.layout.resolv_tile_count        = 1U;
  config->firedancer.layout.execle_tile_count        = 1U;
  config->firedancer.layout.snapdc_tile_count        = 1U;
  config->firedancer.layout.snapin_tile_count        = 4U;
  config->firedancer.layout.snapzp_tile_count        = 1U;
  config->firedancer.layout.snapsv_tile_count        = 1U;
  config->firedancer.layout.snapsv_io_worker_count   = 1U;
  config->firedancer.snapshots.wait_for_peers_timeout_seconds = 1UL;
  config->firedancer.snapshots.server.idle_timeout_millis      = 100UL;
  config->firedancer.snapshots.server.send_timeout_millis      = 100UL;
  config->firedancer.accounts.max_accounts                     = 1UL;
  config->firedancer.accounts.cache_size_gib                   = 1UL;
  config->firedancer.runtime.program_cache_size_mib            = 32UL;
  config->tiles.repair.slot_max                                   = 1UL;
  strcpy( config->firedancer.layout.mode, "performance" );

  FD_TEST(  genesis_max_file_size_is_valid( config, 4055UL ) );
  FD_TEST( !genesis_max_file_size_is_valid( config, 4056UL ) );

  FD_TEST(  failover_is_valid( config, 0, "0.0.0.0",   8010, "vote.json", 0 ) );
  FD_TEST(  failover_is_valid( config, 1, "0.0.0.0",   8010, "vote.json", 0 ) );
  FD_TEST(  failover_is_valid( config, 1, "10.0.0.1",  8010, "vote.json", 0 ) );
  FD_TEST( !failover_is_valid( config, 1, "0.0.0.0",   0,    "vote.json", 0 ) );
  FD_TEST( !failover_is_valid( config, 1, "localhost", 8010, "vote.json", 0 ) );
  FD_TEST( !failover_is_valid( config, 1, "0.0.0.0",   8010, "",          0 ) );
  FD_TEST( !failover_is_valid( config, 1, "0.0.0.0",   8010, "vote.json", 1 ) );
  FD_TEST(  failover_is_valid( config, 0, "",          0,    "",          1 ) );

  /* Ensure we can selectively override a field */

  config->gossip.port = 9191;
  config->gossip.entrypoints_cnt = 2;
  strcpy( config->gossip.entrypoints[0], "foo" );
  strcpy( config->gossip.entrypoints[1], "bar" );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_1, sizeof(cfg_str_1)-1, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );
  FD_TEST( fd_config_extract_pod( pod, config ) == config );
  FD_TEST( config->gossip.entrypoints_cnt == 1 );
  FD_TEST( 0==strcmp( config->gossip.entrypoints[0], "208.91.106.45:8080" ) );
  FD_TEST( config->gossip.port == 9191 );  /* unchanged */

  /* Test passing "auto" leads to 2 for auto configure fields */

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_3, sizeof(cfg_str_3)-1, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );
  FD_TEST( fd_config_extract_pod( pod, config ) == config );
  FD_TEST( config->net.xdp.xdp_zero_copy == 2 );
  FD_TEST( config->net.xdp.native_bond   == 2 );

  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_4, sizeof(cfg_str_4)-1, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );
  FD_TEST( !fd_config_extract_pod( pod, config ) );

  /* Parse runtime genesis limits */

  memset( config, 0, sizeof(config_t) );
  config->is_firedancer = 1;
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_5, sizeof(cfg_str_5)-1, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );
  FD_TEST( fd_config_extract_pod( pod, config ) == config );
  FD_TEST( config->firedancer.development.genesis.max_file_size_mib == 33UL );

  /* Parse the vote history file options */

  memset( config, 0, sizeof(config_t) );
  config->is_firedancer = 1;
  config->tiles.tower.write_vote_history_file = 1;
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_vote_history, sizeof(cfg_str_vote_history)-1, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );
  FD_TEST( fd_config_extract_pod( pod, config ) == config );
  FD_TEST( !strcmp( config->paths.vote_history, "/data/{name}/vote_history" ) );
  FD_TEST( !config->tiles.tower.write_vote_history_file );
  FD_TEST(  config->tiles.votor.write_vote_history_file );

  FD_TEST(  vote_history_path_is_valid( ""                   ) ); /* default */
  FD_TEST(  vote_history_path_is_valid( "/data/vote_history" ) );
  FD_TEST(  vote_history_path_is_valid( "/data/"             ) );
  FD_TEST( !vote_history_path_is_valid( "data/vote_history"  ) ); /* relative */

  /* Parse the failover knobs */

  fd_memset( config, 0, sizeof(config_t) );
  config->is_firedancer = 1;
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_failover, sizeof(cfg_str_failover)-1, pod, scratch, sizeof(scratch), NULL ) == FD_TOML_SUCCESS );
  FD_TEST( fd_config_extract_pod( pod, config ) == config );
  FD_TEST( config->firedancer.failover.enabled );
  FD_TEST( !strcmp( config->firedancer.failover.listen_address, "10.0.0.1" ) );
  FD_TEST( config->firedancer.failover.listen_port==9010 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
