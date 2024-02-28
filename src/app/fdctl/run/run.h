#ifndef HEADER_fd_src_app_fdctl_run_h
#define HEADER_fd_src_app_fdctl_run_h

#include "../fdctl.h"

int
solana_labs_main( void * args );

int
clone_firedancer( config_t * const config,
                  int              close_fd,
                  int *            out_pipe );

void
run_firedancer( config_t * const config );

#endif /* HEADER_fd_src_app_fdctl_run_h */
