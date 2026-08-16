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

/* monitor_main, if non-NULL and --votor-monitor was given, is forked in
   place of the log watcher and draws for as long as the validator runs.
   Only firedancer-dev supplies one; it is the binary-specific hook the
   same way agave_main is. */

void
dev_cmd_fn( args_t *   args,
            config_t * config,
            void ( * agave_main )( config_t const * ),
            void ( * monitor_main )( args_t *, config_t * ) );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_dev_commands_dev_h */
