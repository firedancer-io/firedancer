#include "config_parse.h"
#include "../../ballet/toml/fd_toml.h"

static char const cfg_str_1[] =
  "[tiles.gossip]\n"
  "  entrypoints = [\"208.91.106.45\"]";

static char const cfg_str_2[] =
  "wumbo = \"mini\"";

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Parse a basic config string */

  static uchar pod_mem[ 1UL<<16 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  static uchar scratch[ 4096 ];
  FD_TEST( fd_toml_parse( cfg_str_1, sizeof(cfg_str_1)-1, pod, scratch, sizeof(scratch) ) == FD_TOML_SUCCESS );

  static config_t config[1];
  FD_TEST( fdctl_pod_to_cfg( config, pod ) == config );

  FD_TEST( config->tiles.gossip.entrypoints_cnt == 1 );
  FD_TEST( 0==strcmp( config->tiles.gossip.entrypoints[0], "208.91.106.45" ) );

  /* Reject unrecognized config keys */

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_2, sizeof(cfg_str_2)-1, pod, scratch, sizeof(scratch) ) == FD_TOML_SUCCESS );
  FD_TEST( !fdctl_pod_to_cfg( config, pod ) );

  /* The default config must parse fine */

  memset( config, 0, sizeof(config_t) );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( fdctl_default_config, fdctl_default_config_sz, pod, scratch, sizeof(scratch) ) == FD_TOML_SUCCESS );
  FD_TEST( fdctl_pod_to_cfg( config, pod ) == config );
  fdctl_cfg_validate( config );  /* exits process with code 1 on failure */

  /* Ensure we can selectively override a field */

  config->tiles.gossip.gossip_listen_port = 9191;
  config->tiles.gossip.entrypoints_cnt = 2;
  strcpy( config->tiles.gossip.entrypoints[0], "foo" );
  strcpy( config->tiles.gossip.entrypoints[1], "bar" );
  pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
  FD_TEST( fd_toml_parse( cfg_str_1, sizeof(cfg_str_1)-1, pod, scratch, sizeof(scratch) ) == FD_TOML_SUCCESS );
  FD_TEST( fdctl_pod_to_cfg( config, pod ) == config );
  FD_TEST( config->tiles.gossip.entrypoints_cnt == 1 );
  FD_TEST( 0==strcmp( config->tiles.gossip.entrypoints[0], "208.91.106.45" ) );
  FD_TEST( config->tiles.gossip.gossip_listen_port == 9191 );  /* unchanged */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
