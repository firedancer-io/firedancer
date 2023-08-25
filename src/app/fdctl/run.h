#ifndef HEADER_fd_src_app_fdctl_run_h
#define HEADER_fd_src_app_fdctl_run_h

#include "fdctl.h"
#include "../frank/fd_frank.h"

typedef struct {
  fd_frank_task_t * tile;
  ulong tile_idx;
  ulong idx;
  int sandbox;
  uid_t uid;
  gid_t gid;
  char * app_name;
  double tick_per_ns;
} tile_main_args_t;

const uchar *
workspace_pod_join( char * app_name,
                    char * tile_name,
                    ulong tile_idx );

int
solana_labs_main( void * args );

int
tile_main( void * _args );

void
run_firedancer( config_t * const config );

#endif /* HEADER_fd_src_app_fdctl_run_h */
