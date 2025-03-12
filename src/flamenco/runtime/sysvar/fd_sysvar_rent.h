#ifndef HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h
#define HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../types/fd_types.h"

FD_PROTOTYPES_BEGIN

/* fd_sysvar_rent_init copies the cached rent sysvar stored from
   fd_exec_slot_ctx_t to the corresponding account in the database.
   Note that it does NOT initialize global->bank.rent */

void
fd_sysvar_rent_init( fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_rent_read queries the rent sysvar from the given slot
   context.  Rent sysvar is written into *result (may be uninitialized).
   Returns result on success, NULL otherwise. */

fd_rent_t *
fd_sysvar_rent_read( fd_sysvar_cache_t const * sysvar_cache,
                     fd_acc_mgr_t *            acc_mgr,
                     fd_funk_txn_t *           funk_txn,
                     fd_spad_t *               spad );

/* fd_rent_exempt_minimum_balance returns the minimum balance needed
   for an account with the given data_len to be rent exempt.  rent
   points to the current rent parameters. */

ulong
fd_rent_exempt_minimum_balance( fd_rent_t const * rent,
                                ulong             data_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_sysvar_rent_h */

