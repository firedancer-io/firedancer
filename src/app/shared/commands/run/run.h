#ifndef HEADER_fd_src_app_shared_commands_run_run_h
#define HEADER_fd_src_app_shared_commands_run_run_h

#include "../../fd_config.h"

FD_PROTOTYPES_BEGIN

void *
create_clone_stack( void );

#if !FD_HAS_NO_AGAVE

void
agave_boot( config_t const * config );

int
agave_main( void * args );

#endif /* !FD_HAS_NO_AGAVE */

int
clone_firedancer( config_t const * config,
                  int              close_fd,
                  int *            out_pipe );

void
fdctl_check_configure( config_t const * config );

void
initialize_workspaces( config_t * config );

void
initialize_stacks( config_t const * config );

void
run_firedancer_init( config_t * config,
                     int        init_workspaces );

void
fdctl_setup_netns( config_t * config,
                   int        stay );

void
run_firedancer( config_t * config,
                int        parent_pipefd,
                int        init_workspaces );

void run_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void run_cmd_fn  ( args_t * args, config_t * config );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_run_run_h */
