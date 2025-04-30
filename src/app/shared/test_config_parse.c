#include "fd_config_private.h"
#include "../../ballet/toml/fd_toml.h"

static char const cfg_str_1[] =
  "[gossip]\n"
  "  entrypoints = [\"208.91.106.45:8080\"]";

static char const cfg_str_2[] =
  "wumbo = \"mini\"";

extern uchar const fdctl_default_config[];
extern ulong const fdctl_default_config_sz;

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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
