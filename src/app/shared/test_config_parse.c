#include "fd_config_private.h"
#include "../../ballet/toml/fd_toml.h"

#include <sys/wait.h>
#include <unistd.h>

static char const cfg_str_1[] =
  "[gossip]\n"
  "  entrypoints = [\"208.91.106.45:8080\"]";

static char const cfg_str_oversized_array[] =
  "[ledger]\n"
  "  account_indexes = [\"a\", \"b\", \"c\", \"d\", \"e\"]";

static char const cfg_str_invalid_aliased_array[] =
  "[consensus]\n"
  "  authorized_voter_paths = [1]";

static char const cfg_str_2[] =
  "wumbo = \"mini\"";

static char const cfg_str_empty_unknown_array[] =
  "wumbo = []";

static char const cfg_str_escaped[] =
  "[tiles.bundle]\n"
  "  tls_domain_name = \"a\\u0062c.example\"";

/* Auto config specific */
static char const cfg_str_3[] =
  "[net.xdp]\n  xdp_zero_copy = \"auto\"\n  native_bond = \"auto\"";
static char const cfg_str_4[] =
  "[net.xdp]\n  xdp_zero_copy = \"something wrong\"";
static char const cfg_str_5[] =
  "[development.genesis]\n"
  "  max_file_size_mib = 33";

extern uchar const fdctl_default_config[];
extern ulong const fdctl_default_config_sz;

/* load parses toml and extracts it into config.  Returns 1 if both
   succeeded. */

static int
load( config_t *   config,
      char const * toml,
      ulong        toml_sz ) {
  fd_toml_doc_t doc[1];
  FD_TEST( fd_config_toml_parse( doc, toml, toml_sz, NULL )==FD_TOML_SUCCESS );
  return fd_config_extract_toml( doc, config )==config;
}

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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Parse a basic config string */

  static config_t config[1];
  FD_TEST( load( config, cfg_str_1, sizeof(cfg_str_1)-1 ) );

  FD_TEST( config->gossip.entrypoints_cnt == 1 );
  FD_TEST( 0==strcmp( FD_TOPO_STR( config->gossip.entrypoints[0] ), "208.91.106.45:8080" ) );

  /* String values are only bounded by the config string arena, so a
     URL far beyond any fixed buffer size loads fine. */

  static char endpoint[ 65536UL ];
  fd_memcpy( endpoint, "https://", 8UL );
  fd_memset( endpoint+8UL, 'a', sizeof(endpoint)-8UL-7UL );
  fd_memcpy( endpoint+sizeof(endpoint)-7UL, ":65535", 7UL );

  static char cfg_str_long[ 2UL*sizeof(endpoint)+128UL ];
  ulong cfg_str_long_sz;
  FD_TEST( fd_cstr_printf_check( cfg_str_long, sizeof(cfg_str_long), &cfg_str_long_sz,
                                "[snapshots.sources]\n"
                                "servers = [\"%s\"]\n"
                                "[tiles.bundle]\n"
                                "url = \"%s\"\n",
                                endpoint, endpoint ) );

  memset( config, 0, sizeof(config_t) );
  config->is_firedancer = 1;
  FD_TEST( load( config, cfg_str_long, cfg_str_long_sz ) );
  FD_TEST( config->firedancer.snapshots.sources.servers_cnt==1UL );
  FD_TEST( !strcmp( FD_TOPO_STR( config->firedancer.snapshots.sources.servers[0] ), endpoint ) );
  FD_TEST( !strcmp( FD_TOPO_STR( config->tiles.bundle.url ), endpoint ) );

  /* Exhausting the arena is a clean rejection.  A single document is
     capped below the arena size, so load a large value twice into the
     same config (as a default followed by a user override would). */

  static char cfg_str_over[ 3UL*FD_CONFIG_STRS_SZ/4UL ];
  ulong cfg_str_over_sz = 0UL;
  fd_memcpy( cfg_str_over, "[tiles.bundle]\nurl = \"", 22UL ); cfg_str_over_sz += 22UL;
  fd_memset( cfg_str_over+cfg_str_over_sz, 'a', sizeof(cfg_str_over)-32UL ); cfg_str_over_sz += sizeof(cfg_str_over)-32UL;
  fd_memcpy( cfg_str_over+cfg_str_over_sz, "\"\n", 2UL ); cfg_str_over_sz += 2UL;
  memset( config, 0, sizeof(config_t) );
  config->is_firedancer = 1;
  FD_TEST(  load( config, cfg_str_over, cfg_str_over_sz ) );
  FD_TEST( !load( config, cfg_str_over, cfg_str_over_sz ) );

  /* Escape sequences are decoded. */

  memset( config, 0, sizeof(config_t) );
  FD_TEST( load( config, cfg_str_escaped, sizeof(cfg_str_escaped)-1UL ) );
  FD_TEST( !strcmp( FD_TOPO_STR( config->tiles.bundle.tls_domain_name ), "abc.example" ) );

  /* Reject invalid direct and aliased array elements. */

  memset( config, 0, sizeof(config_t) );
  FD_TEST( !load( config, cfg_str_oversized_array, sizeof(cfg_str_oversized_array)-1UL ) );

  memset( config, 0, sizeof(config_t) );
  FD_TEST( !load( config, cfg_str_invalid_aliased_array, sizeof(cfg_str_invalid_aliased_array)-1UL ) );

  /* Reject unrecognized config keys */

  memset( config, 0, sizeof(config_t) );
  FD_TEST( !load( config, cfg_str_2, sizeof(cfg_str_2)-1 ) );

  memset( config, 0, sizeof(config_t) );
  FD_TEST( !load( config, cfg_str_empty_unknown_array, sizeof(cfg_str_empty_unknown_array)-1 ) );

  /* The default config must parse fine */

  memset( config, 0, sizeof(config_t) );
  FD_TEST( load( config, (char const *)fdctl_default_config, fdctl_default_config_sz ) );
  fd_config_validate( config );  /* exits process with code 1 on failure */

  /* Loading again only appends the new strings to the arena */

  ulong strs_len = config->strs_len;
  FD_TEST( load( config, cfg_str_1, sizeof(cfg_str_1)-1 ) );
  FD_TEST( config->strs_len==strs_len+sizeof("208.91.106.45:8080") );
  FD_TEST( 0==strcmp( FD_TOPO_STR( config->gossip.entrypoints[0] ), "208.91.106.45:8080" ) );
  FD_TEST( 0==strcmp( FD_TOPO_STR( config->net.provider ), "xdp" ) );

  FD_TEST( fd_config_str_set( config, &config->net.provider, "auto", 4UL ) );
  fd_config_validate( config );
  FD_TEST( fd_config_str_set( config, &config->net.provider, "xdp", 3UL ) );

  /* bzip2's avail_in and avail_out fields are uint. */

  config->is_firedancer = 1;
  memset( &config->firedancer, 0, sizeof(config->firedancer) );
  config->firedancer.layout.sign_tile_count          = 2U;
  config->firedancer.layout.resolv_tile_count        = 1U;
  config->firedancer.layout.execle_tile_count        = 1U;
  config->firedancer.layout.snapdc_tile_count        = 1U;
  config->firedancer.layout.snapzp_tile_count        = 1U;
  config->firedancer.layout.snapsv_tile_count        = 1U;
  config->firedancer.layout.snapsv_io_worker_count   = 1U;
  config->firedancer.snapshots.wait_for_peers_timeout_seconds = 1UL;
  config->firedancer.snapshots.server.idle_timeout_millis      = 100UL;
  config->firedancer.snapshots.server.send_timeout_millis      = 100UL;
  config->firedancer.accounts.max_accounts                     = 1UL;
  config->firedancer.accounts.cache_size_gib                   = 1UL;
  config->firedancer.runtime.program_cache.mean_cache_entry_size = 4096UL;
  config->firedancer.runtime.program_cache.heap_size_mib         = 32UL;
  config->tiles.repair.slot_max                                   = 1UL;
  config->tiles.rotor.slot_max                                    = 1UL;

  FD_TEST(  genesis_max_file_size_is_valid( config, 4055UL ) );
  FD_TEST( !genesis_max_file_size_is_valid( config, 4056UL ) );

  /* Ensure we can selectively override a field */

  config->gossip.port = 9191;
  config->gossip.entrypoints_cnt = 2;
  FD_TEST( fd_config_str_set( config, &config->gossip.entrypoints[0], "foo", 3UL ) );
  FD_TEST( fd_config_str_set( config, &config->gossip.entrypoints[1], "bar", 3UL ) );
  FD_TEST( load( config, cfg_str_1, sizeof(cfg_str_1)-1 ) );
  FD_TEST( config->gossip.entrypoints_cnt == 1 );
  FD_TEST( 0==strcmp( FD_TOPO_STR( config->gossip.entrypoints[0] ), "208.91.106.45:8080" ) );
  FD_TEST( config->gossip.port == 9191 );  /* unchanged */

  /* Test passing "auto" leads to 2 for auto configure fields */

  memset( config, 0, sizeof(config_t) );
  FD_TEST( load( config, cfg_str_3, sizeof(cfg_str_3)-1 ) );
  FD_TEST( config->net.xdp.xdp_zero_copy == 2 );
  FD_TEST( config->net.xdp.native_bond   == 2 );

  FD_TEST( !load( config, cfg_str_4, sizeof(cfg_str_4)-1 ) );

  /* Parse runtime genesis limits */

  memset( config, 0, sizeof(config_t) );
  config->is_firedancer = 1;
  FD_TEST( load( config, cfg_str_5, sizeof(cfg_str_5)-1 ) );
  FD_TEST( config->firedancer.development.genesis.max_file_size_mib == 33UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
