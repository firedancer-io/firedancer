#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_slot_ctx.h"

/* The rent sysvar contains the rent of rate. */

/* fd_sysvar_rent_init copies the cached rent sysvar stored from
   fd_exec_slot_ctx_t to the corresponding account in the database.
   Note that it does NOT initialize global->bank.rent */
void
fd_sysvar_rent_init( fd_exec_slot_ctx_t * slot_ctx );

/* Reads the current value of the rent sysvar */
int fd_sysvar_rent_read( fd_exec_slot_ctx_t * slot_ctx, fd_rent_t* result );

/* Returns the minimum balance needed for an account with the given data_len to be rent exempt */
ulong fd_rent_exempt_minimum_balance( fd_exec_slot_ctx_t * slot_ctx, ulong data_len );

ulong
fd_rent_exempt_minimum_balance2( fd_rent_t const * rent,
                                 ulong             data_len );

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h */

