#include "config_parse.h"
#include "../../ballet/toml/fd_toml.h"

static char const cfg_str[] =
  "[tiles.gossip]\n"
  "  entrypoints = [\"208.91.106.45\"]";

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar pod_mem[ 1UL<<16 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  static uchar scratch[ 4096 ];
  FD_TEST( fd_toml_parse( cfg_str, sizeof(cfg_str)-1, pod, scratch, sizeof(scratch) ) == FD_TOML_SUCCESS );

  static config_t config[1];
  fdctl_pod_to_cfg( config, pod );

  FD_TEST( config->tiles.gossip.entrypoints_cnt == 1 );
  FD_TEST( 0==strcmp( config->tiles.gossip.entrypoints[0], "208.91.106.45" ) );

  fd_halt();
}
