#ifndef HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h

/* The vote program (native program) allows node operators to register
   their nodes and participate in consensus.  The vote program
   implements various Tower BFT logic like voting and lockouts.  The set
   of vote accounts is the 'source of truth' for Solana's consensus
   algorithm.

   Address: Vote111111111111111111111111111111111111111 */

#include "../context/fd_exec_instr_ctx.h"
#include "../fd_bank.h"

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L35
#define MAX_LOCKOUT_HISTORY 31UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L36
#define MAX_EPOCH_CREDITS_HISTORY 64UL

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L48
#define VOTE_CREDITS_MAXIMUM_PER_SLOT 16

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L45
#define VOTE_CREDITS_GRACE_SLOTS 2

/* https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L597-L598 */
#define DEFAULT_BLOCK_REVENUE_COMMISSION_BPS (10000UL)

/* Vote program custom error codes */

#define FD_VOTE_ERR_VOTE_TOO_OLD                    ( 0)
#define FD_VOTE_ERR_SLOTS_MISMATCH                  ( 1)
#define FD_VOTE_ERR_SLOTS_HASH_MISMATCH             ( 2)
#define FD_VOTE_ERR_EMPTY_SLOTS                     ( 3)
#define FD_VOTE_ERR_TIMESTAMP_TOO_OLD               ( 4)
#define FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE         ( 5)
#define FD_VOTE_ERR_LOCKOUT_CONFLICT                ( 6)
#define FD_VOTE_ERR_NEW_VOTE_STATE_LOCKOUT_MISMATCH ( 7)
#define FD_VOTE_ERR_SLOTS_NOT_ORDERED               ( 8)
#define FD_VOTE_ERR_CONFIRMATIONS_NOT_ORDERED       ( 9)
#define FD_VOTE_ERR_ZERO_CONFIRMATIONS              (10)
#define FD_VOTE_ERR_CONFIRMATION_TOO_LARGE          (11)
#define FD_VOTE_ERR_ROOT_ROLL_BACK                  (12)
#define FD_VOTE_ERR_CONFIRMATION_ROLL_BACK          (13)
#define FD_VOTE_ERR_SLOT_SMALLER_THAN_ROOT          (14)
#define FD_VOTE_ERR_TOO_MANY_VOTES                  (15)
#define FD_VOTE_ERR_VOTES_TOO_OLD_ALL_FILTERED      (16)
#define FD_VOTE_ERR_ROOT_ON_DIFFERENT_FORK          (17)
#define FD_VOTE_ERR_ACTIVE_VOTE_ACCOUNT_CLOSE       (18)
#define FD_VOTE_ERR_COMMISSION_UPDATE_TOO_LATE      (19)

#define FD_VOTE_STATE_V2_SZ (3731UL)
#define FD_VOTE_STATE_V3_SZ (3762UL)
#define FD_VOTE_STATE_V4_SZ (3762UL)

/* Target vote state versions
   https://github.com/anza-xyz/agave/blob/v3.1.1/programs/vote/src/vote_state/handler.rs#L639-L645 */
#define VOTE_STATE_TARGET_VERSION_V3 (0)
#define VOTE_STATE_TARGET_VERSION_V4 (1)

FD_PROTOTYPES_BEGIN

/* fd_vote_program_execute is the instruction processing entrypoint
   for the vote program. */
int
fd_vote_program_execute( fd_exec_instr_ctx_t * ctx );

/* An implementation of solana_sdk::transaction_context::BorrowedAccount::get_state
   for setting the vote state.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L965 */
fd_vote_state_versioned_t *
fd_vote_get_state( fd_account_meta_t const * meta,
                   uchar *                   mem );

void
fd_vote_convert_to_current( fd_vote_state_versioned_t * self,
                            uchar *                     authorized_voters_mem,
                            uchar *                     landed_votes_mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h */
