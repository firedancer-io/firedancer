#ifndef HEADER_fd_src_app_shared_dev_boot_fd_dev_boot_h
#define HEADER_fd_src_app_shared_dev_boot_fd_dev_boot_h

#include "../../shared/fd_config.h"
#include "../../shared/fd_config_file.h"

FD_PROTOTYPES_BEGIN

int
fd_dev_main( int                        argc,
             char **                    _argv,
             int                        is_firedancer,
             fd_config_file_t * const * configs );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_dev_boot_fd_dev_boot_h */
