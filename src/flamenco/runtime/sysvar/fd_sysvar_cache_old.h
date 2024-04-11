#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_old_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_old_h

#include "../../types/fd_types.h"

struct fd_sysvar_cache_old {
  fd_sol_sysvar_clock_t clock[1];
  fd_slot_hashes_t slot_hashes[1];
  fd_rent_t rent[1];
};
typedef struct fd_sysvar_cache_old fd_sysvar_cache_old_t;

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_old_h */
