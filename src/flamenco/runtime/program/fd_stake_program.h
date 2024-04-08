#ifndef HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h

/* The stake program (native program) allows users to stake their coins
   on a validator (registered with the vote program).  The user
   receives inflation rewards for doing so.  The slot boundary will read
   and write accounts owned by the stake program (e.g. to determine
   validator stake weights and pay out staking rewards).

   Address: Stake11111111111111111111111111111111111111 */

#include "../context/fd_exec_instr_ctx.h"

FD_PROTOTYPES_BEGIN

/* fd_stake_program_execute is the instruction processing entrypoint
   for the stake program.  On return, ctx.txn_ctx->dirty_stake_acc==1 if
   a stake account may have been modified. */

int
fd_stake_program_execute( fd_exec_instr_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h */
