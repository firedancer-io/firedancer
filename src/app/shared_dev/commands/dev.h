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

/* run_firedancer_watched runs Firedancer in a child process with its
   output shown by watch in another child process.  Exits with the exit
   code of the first child to stop. */

void
run_firedancer_watched( config_t * config,
                        int        check_configure,
                        int        full_watch );

void
dev_cmd_fn( args_t *   args,
            config_t * config,
            void ( * agave_main )( config_t const * ) );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_dev_commands_dev_h */
