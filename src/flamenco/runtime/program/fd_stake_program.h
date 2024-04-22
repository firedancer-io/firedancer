#ifndef HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h

/* The stake program (native program) allows users to stake their coins
   on a validator (registered with the vote program).  The user
   receives inflation rewards for doing so.  The slot boundary will read
   and write accounts owned by the stake program (e.g. to determine
   validator stake weights and pay out staking rewards).

   Address: Stake11111111111111111111111111111111111111 */


#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../program/fd_vote_program.h"

#define FD_STAKE_STATE_V2_SZ (200UL)

FD_PROTOTYPES_BEGIN

/* Initializes an account which holds configuration used by the stake program.
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/config.rs
 */
void
fd_stake_program_config_init( fd_exec_slot_ctx_t * global );

int
fd_stake_get_state( fd_borrowed_account_t const * self,
                    fd_valloc_t const *           valloc,
                    fd_stake_state_v2_t *         out );

fd_stake_history_entry_t
fd_stake_activating_and_deactivating( fd_delegation_t const *    self,
                                      ulong                      target_epoch,
                                      fd_stake_history_t const * stake_history,
                                      ulong *                    new_rate_activation_epoch );

/* Entry-point for the Solana Stake Program */
int
fd_stake_program_execute( fd_exec_instr_ctx_t ctx );

void fd_store_stake_delegation( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * stake_account );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h */
