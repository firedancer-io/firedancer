#include "main.h"

int
main( int     argc,
      char ** argv ) {
  return fd_dev_main( argc, argv, (char const *)fdctl_default_config, fdctl_default_config_sz, NULL, 0UL, fd_topo_initialize );
}
