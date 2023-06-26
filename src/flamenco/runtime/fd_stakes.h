#ifndef HEADER_fd_src_flamenco_runtime_fd_stakes_h
#define HEADER_fd_src_flamenco_runtime_fd_stakes_h

#include "fd_executor.h"

void fd_stakes_init( fd_global_ctx_t* global, fd_stakes_t* stakes );

void activate_epoch( fd_global_ctx_t* global, ulong next_epoch );

#endif /* HEADER_fd_src_flamenco_runtime_fd_stakes_h */
