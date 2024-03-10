#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../types/fd_types.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_rent_read queries the rent sysvar from the given slot
   context.  Rent sysvar is written into *result (may be uninitialized).
   Returns result on success, NULL otherwise. */

fd_rent_t *
fd_sysvar_rent_read( fd_rent_t *          result,
                     fd_exec_slot_ctx_t * slot_ctx );

/* fd_rent_exempt_minimum_balance looks up the minimum balance needed
   for an account with the given data_len to be rent exempt.  slot_ctx
   is a slot execution context that has a rent sysvar.  Returns 0 and
   sets *min_balance on success.  On failure, returns an error code in
   FD_EXECUTOR_INSTR_ERR_{...} and leaves *min_balance undefined. */

int
fd_rent_exempt_minimum_balance( fd_exec_slot_ctx_t * slot_ctx,
                                ulong                data_len,
                                ulong *              min_balance );

/* fd_rent_exempt_minimum_balance2 returns the minimum balance needed
   for an account with the given data_len to be rent exempt.  rent
   points to the current rent parameters. */

ulong
fd_rent_exempt_minimum_balance2( fd_rent_t const * rent,
                                 ulong             data_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h */

