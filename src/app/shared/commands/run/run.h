#ifndef HEADER_fd_src_app_shared_commands_run_run_h
#define HEADER_fd_src_app_shared_commands_run_run_h

#include "../../fd_config.h"
#include "../../fd_action.h"

FD_PROTOTYPES_BEGIN

void *
create_clone_stack( void );

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
initialize_accdb_fd( config_t const * config );

/* initialize_snapshots_pool reconciles the snapshots directory into
   the snapshot producer's managed file pool and opens the pool fds at
   the well known FD_BACKUP_POOL_FD/FD_BACKUP_POOL_DIO_FD numbers (see
   discof/backup/fd_backup_pool.h).  No-op unless the topology
   contains a snapmk tile.  Returns the pool slot count. */

ulong
initialize_snapshots_pool( config_t const * config );

void
run_firedancer_init( config_t * config,
                     int        init_workspaces,
                     int        check_configure );

void
run_firedancer( config_t * config,
                int        parent_pipefd,
                int        init_workspaces );

void run_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void run_cmd_fn  ( args_t * args, config_t * config );


void run1_cmd_args( int * pargc, char *** pargv, args_t * args );
void run1_cmd_fn  ( args_t * args, config_t * config );

FD_PROTOTYPES_END

extern action_t fd_action_run1;
extern action_t fd_action_run;

#endif /* HEADER_fd_src_app_shared_commands_run_run_h */
