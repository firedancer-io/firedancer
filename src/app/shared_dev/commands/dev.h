#ifndef HEADER_fd_src_app_shared_dev_commands_dev_h
#define HEADER_fd_src_app_shared_dev_commands_dev_h

#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

FD_PROTOTYPES_BEGIN

void
dev_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args );

void
dev_cmd_perm( args_t *         args,
              fd_cap_chk_t *   chk,
              config_t const * config );

/* run_firedancer_dev runs the topology in config, as tile processes or
   as tile threads if [development.no_clone] is set.  If watch, the
   output is shown by the watch command.  Does not return. */

void
run_firedancer_dev( config_t * config,
                    int        parent_pipefd,
                    int        init_workspaces,
                    int        check_configure,
                    int        watch,
                    int        full_watch,
                    void ( * agave_main )( config_t const * ) );

void
dev_cmd_fn( args_t *   args,
            config_t * config,
            void ( * agave_main )( config_t const * ) );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_dev_commands_dev_h */
