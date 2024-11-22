#ifndef HEADER_fd_src_app_fdctl_run_h
#define HEADER_fd_src_app_fdctl_run_h

#include "../fdctl.h"

#include "../../../util/tile/fd_tile_private.h"

void *
create_clone_stack( void );

void
agave_boot( config_t * config );

int
agave_main( void * args );

int
execve_agave( int config_memfd,
              int pipefd );

pid_t
execve_tile( fd_topo_tile_t * tile,
             fd_cpuset_t *    floating_cpu_set,
             int              floating_priority,
             int              config_memfd,
             int              pipefd,
             char const *     execve_binary );

void
initialize_workspaces( config_t * const config );

void
run_firedancer_init( config_t * const config,
                     int              init_workspaces );

void
run_firedancer( config_t * const config,
                int              parent_pipefd,
                int              init_workspaces,
                int            (*main_pid_namespace_fn)( void * args ) );

#endif /* HEADER_fd_src_app_fdctl_run_h */
