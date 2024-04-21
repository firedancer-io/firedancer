#ifndef HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h

/* The stake program (native program) allows users to stake their coins
   on a validator (registered with the vote program).  The user
   receives inflation rewards for doing so.  The slot boundary will read
   and write accounts owned by the stake program (e.g. to determine
   validator stake weights and pay out staking rewards).

   Address: Stake11111111111111111111111111111111111111 */

#include "../context/fd_exec_instr_ctx.h"

#define FD_STAKE_STATE_V2_SZ (200UL)

FD_PROTOTYPES_BEGIN

/* fd_stake_program_execute is the instruction processing entrypoint
   for the stake program.  On return, ctx.txn_ctx->dirty_stake_acc==1 if
   a stake account may have been modified. */

int
fd_stake_program_execute( fd_exec_instr_ctx_t ctx );

int
fd_stake_get_state( fd_borrowed_account_t const * self,
                    fd_valloc_t const *           valloc,
                    fd_stake_state_v2_t *         out );

fd_stake_history_entry_t
fd_stake_activating_and_deactivating( fd_delegation_t const *    self,
                                      ulong                      target_epoch,
                                      fd_stake_history_t const * stake_history,
                                      ulong *                    new_rate_activation_epoch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h */
