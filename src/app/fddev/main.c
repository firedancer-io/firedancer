#include "main.h"

#include "../shared_dev/boot/fd_dev_boot.h"
#include "../fdctl/topology.h"
#include "../fdctl/config.h"

int
main( int     argc,
      char ** argv ) {
  return fd_dev_main( argc, argv, 0, (char const *)fdctl_default_config, fdctl_default_config_sz, fd_topo_initialize );
}
