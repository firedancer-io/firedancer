#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_rent_init copies the cached rent sysvar stored from
   fd_exec_slot_ctx_t to the corresponding account in the database.
   Note that it does NOT initialize global->bank.rent */

void
fd_sysvar_rent_init( fd_exec_slot_ctx_t * slot_ctx );

/* fd_rent_exempt_minimum_balance returns the minimum balance needed
   for an account with the given data_len to be rent exempt.  rent
   points to the current rent parameters. */

ulong
fd_rent_exempt_minimum_balance( fd_rent_t const * rent,
                                ulong             data_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h */

