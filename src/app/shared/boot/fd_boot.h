#ifndef HEADER_fd_src_app_shared_boot_fd_boot_h
#define HEADER_fd_src_app_shared_boot_fd_boot_h

#include "../fd_config.h"
#include "../../../util/fd_util.h"

FD_PROTOTYPES_BEGIN

int
fd_main( int          argc,
         char **      _argv,
         int          is_firedancer,
         char const * default_config,
         ulong        default_config_sz,
         void (* topo_init )( config_t * config ) );

void
fd_main_init( int *        pargc,
              char ***     pargv,
              config_t   * config,
              const char * opt_user_config_path,
              int          is_firedancer,
              int          is_local_cluster,
              char const * log_path,
              char const * default_config,
              ulong        default_config_sz,
              void (* topo_init )( config_t * config ) );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_boot_fd_boot_h */
