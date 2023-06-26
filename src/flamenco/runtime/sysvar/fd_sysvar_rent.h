#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

/* The rent sysvar contains the rent of rate. */

/* Initialize the rent sysvar account. */
void fd_sysvar_rent_init( fd_global_ctx_t* global );

/* Reads the current value of the rent sysvar */
void fd_sysvar_rent_read( fd_global_ctx_t* global, fd_rent_t* result );

/* Returns the minimum balance needed for an account with the given data_len to be rent exempt */
ulong fd_rent_exempt_minimum_balance( fd_global_ctx_t* global, ulong data_len );

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h */

