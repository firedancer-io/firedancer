#include "../fdctl/config.h"
#include "../shared_dev/boot/fd_dev_boot.h"

int
main( int     argc,
      char ** argv ) {
  return fd_dev_main( argc, argv, (char const *)fdctl_default_config, fdctl_default_config_sz, NULL, 0UL, fd_topo_initialize );
}
