#ifndef HEADER_fd_src_app_shared_dev_boot_fd_dev_boot_h
#define HEADER_fd_src_app_shared_dev_boot_fd_dev_boot_h

#include "../../shared/fd_config.h"
#include "../../../util/fd_util.h"

FD_PROTOTYPES_BEGIN

int
fd_dev_main( int     argc,
             char ** _argv,
             char const * default_config1,
             ulong        default_config1_sz,
             char const * default_config2,
             ulong        default_config2_sz,
             void (* topo_init )( config_t * config ) );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_dev_boot_fd_dev_boot_h */
