#include "main.h"

int
main( int     argc,
      char ** argv ) {
  fd_config_file_t _default = (fd_config_file_t){
    .name    = "default",
    .data    = fdctl_default_config,
    .data_sz = fdctl_default_config_sz,
  };

  fd_config_file_t * configs[] = {
    &_default,
    NULL
  };

  return fd_dev_main( argc, argv, 0, configs, fd_topo_initialize );
}
