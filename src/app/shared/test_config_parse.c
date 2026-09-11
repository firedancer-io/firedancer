#include "fd_config_private.h"
#include "../../ballet/toml/fd_toml.h"

#include <netdb.h>
#include <sys/wait.h>
#include <unistd.h>

static struct sockaddr_in test_resolver_addr[ 2 ] = {
  { .sin_family = AF_INET, .sin_addr.s_addr = FD_IP4_ADDR( 192, 0, 2, 10 ) },
  { .sin_family = AF_INET, .sin_addr.s_addr = FD_IP4_ADDR( 192, 0, 2, 11 ) },
};
static struct addrinfo test_resolver_result[ 2 ] = {
  { .ai_family = AF_INET, .ai_addrlen = sizeof(struct sockaddr_in), .ai_addr = (struct sockaddr *)&test_resolver_addr[ 0 ], .ai_next = &test_resolver_result[ 1 ] },
  { .ai_family = AF_INET, .ai_addrlen = sizeof(struct sockaddr_in), .ai_addr = (struct sockaddr *)&test_resolver_addr[ 1 ] },
};
static ulong test_resolver_call_cnt;
static ulong test_resolver_free_cnt;

int
getaddrinfo( char const * restrict            node,
             char const * restrict            service,
             struct addrinfo const * restrict hints,
             struct addrinfo ** restrict      result ) {
  FD_TEST( !service );
  FD_TEST( hints && hints->ai_family==AF_INET );
  test_resolver_call_cnt++;
  if( !strcmp( node, "missing.test" ) ) return EAI_NONAME;
  FD_TEST( !strcmp( node, "123.123.123.123.example" ) );
  *result = test_resolver_result;
  return 0;
}

void
freeaddrinfo( struct addrinfo * result ) {
  FD_TEST( result==test_resolver_result );
  test_resolver_free_cnt++;
}

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
  FD_TEST( config->tiles.shred.additional_shred_destinations_retransmit_cnt==1UL );
  FD_TEST( config->tiles.shred.additional_shred_destinations_leader_cnt==1UL );
  FD_TEST( !strcmp( config->tiles.shred.additional_shred_destinations_retransmit[ 0 ], endpoint+8UL ) );
  FD_TEST( !strcmp( config->tiles.shred.additional_shred_destinations_leader[ 0 ], endpoint+8UL ) );

  /* Reject invalid direct and aliased array elements. */

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_oversized_array, sizeof(cfg_str_oversized_array)-1UL, pod, scratch, sizeof(scratch), NULL )==FD_TOML_SUCCESS );
  FD_TEST( !fd_config_extract_pod( pod, config ) );

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_invalid_aliased_array, sizeof(cfg_str_invalid_aliased_array)-1UL, pod, scratch, sizeof(scratch), NULL )==FD_TOML_SUCCESS );
  FD_TEST( !fd_config_extract_pod( pod, config ) );

  /* Endpoint parsing is strict.  The test resolver returns two IPv4
     records.  The hostname's IPv4 prefix must not bypass the resolver. */

  fd_topo_ip_port_t resolved_endpoint;
  FD_TEST( fd_config_resolve_ip4_endpoint( "198.51.100.42:1", &resolved_endpoint ) );
  FD_TEST( resolved_endpoint.ip==FD_IP4_ADDR( 198, 51, 100, 42 ) );
  FD_TEST( resolved_endpoint.port==1U );
  FD_TEST( !test_resolver_call_cnt );

  config->tiles.shred.additional_shred_destinations_retransmit_cnt = 1UL;
  config->tiles.shred.additional_shred_destinations_leader_cnt     = 1UL;
  strcpy( config->tiles.shred.additional_shred_destinations_retransmit[ 0 ], "123.123.123.123.example:65535" );
  strcpy( config->tiles.shred.additional_shred_destinations_leader[ 0 ],     "198.51.100.42:12000" );
  fd_memset( &config->topo, 0, sizeof(config->topo) );
  config->topo.tile_cnt = 3UL;
  strcpy( config->topo.tiles[ 0 ].name, "metric" );
  for( ulong i=1UL; i<3UL; i++ ) strcpy( config->topo.tiles[ i ].name, "shred" );
  fd_config_apply_shred_destinations( config );

  FD_TEST( test_resolver_call_cnt==1UL );
  FD_TEST( test_resolver_free_cnt==1UL );
  for( ulong i=1UL; i<3UL; i++ ) {
    FD_TEST( config->topo.tiles[ i ].shred.adtl_dests_retransmit_cnt==1UL );
    FD_TEST( config->topo.tiles[ i ].shred.adtl_dests_retransmit[ 0 ].ip==FD_IP4_ADDR( 192, 0, 2, 10 ) );
    FD_TEST( config->topo.tiles[ i ].shred.adtl_dests_retransmit[ 0 ].port==65535U );
    FD_TEST( config->topo.tiles[ i ].shred.adtl_dests_leader_cnt==1UL );
    FD_TEST( config->topo.tiles[ i ].shred.adtl_dests_leader[ 0 ].ip==FD_IP4_ADDR( 198, 51, 100, 42 ) );
    FD_TEST( config->topo.tiles[ i ].shred.adtl_dests_leader[ 0 ].port==12000U );
  }

  char const * invalid_endpoints[] = {
    "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:12x", ":1234", "127.0.0.1:", "127.0.0.1",
    "127.0.0.1:+1", "127.0.0.1:-18446744073709551615", "127.0.0.1: 1", "127.0.0.1:18446744073709551616",
    "::ffff:127.0.0.1:12000", "[::1]:12000", "host:extra:12000"
  };
  for( ulong i=0UL; i<sizeof(invalid_endpoints)/sizeof(*invalid_endpoints); i++ ) {
    FD_TEST( !fd_config_resolve_ip4_endpoint( invalid_endpoints[ i ], &resolved_endpoint ) );
  }
  char oversized_hostname[ 259UL ];
  memset( oversized_hostname, 'a', 256UL );
  fd_memcpy( oversized_hostname+256UL, ":1", 3UL );
  FD_TEST( !fd_config_resolve_ip4_endpoint( oversized_hostname, &resolved_endpoint ) );
  FD_TEST( test_resolver_call_cnt==1UL );
  FD_TEST( !fd_config_resolve_ip4_endpoint( "missing.test:1234", &resolved_endpoint ) );
  FD_TEST( test_resolver_call_cnt==2UL && test_resolver_free_cnt==1UL );

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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
