#ifndef HEADER_fd_src_app_shared_boot_fd_boot_h
#define HEADER_fd_src_app_shared_boot_fd_boot_h

#include "../fd_config.h"
#include "../fd_config_file.h"

FD_PROTOTYPES_BEGIN

/* Parse the one-time new-voter authorization before building the
   topology.  The inherited child config is left intact when this option
   is absent.  Only Firedancer run/dev may accept the explicit option. */
void
fd_boot_failover_first_use( int *        argc,
                            char ***     argv,
                            config_t   * config,
                            char const * action );

int
fd_main( int                        argc,
         char **                    _argv,
         int                        is_firedancer,
         fd_config_file_t * const * configs,
         void (* topo_init )( config_t * config ) );

int
fd_main_init( int *                      pargc,
              char ***                   pargv,
              config_t   *               config,
              const char *               opt_user_config_path,
              int                        is_firedancer,
              int                        is_local_cluster,
              char const *               log_path,
              fd_config_file_t * const * configs,
              int                        dev );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_boot_fd_boot_h */
