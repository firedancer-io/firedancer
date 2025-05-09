#include "main.h"

int
main( int     argc,
      char ** argv ) {
  return fd_dev_main( argc, argv, 0, (char const *)fdctl_default_config, fdctl_default_config_sz, fd_topo_initialize );
}
