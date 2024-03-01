#ifndef HEADER_fd_src_app_fdctl_run_h
#define HEADER_fd_src_app_fdctl_run_h

#include "../fdctl.h"
#include "tiles/tiles.h"

#include "../../../waltz/xdp/fd_xsk.h"

void
solana_labs_boot( config_t * config );

int
solana_labs_main( void * args );

int
clone_firedancer( config_t * const config,
                  int              close_fd,
                  int *            out_pipe );

void
run_firedancer( config_t * const config );

#endif /* HEADER_fd_src_app_fdctl_run_h */
