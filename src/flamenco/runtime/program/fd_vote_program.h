#ifndef HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

/* Vote error codes */
/* TODO: serialize these in the correct */
#define FD_VOTE_VOTE_TOO_OLD                    ( 0  )
#define FD_VOTE_SLOTS_MISMATCH                  ( 1  )
#define FD_VOTE_SLOT_HASH_MISMATCH              ( 2  )
#define FD_VOTE_EMPTY_SLOTS                     ( 3  )
#define FD_VOTE_TIMESTAMP_TOO_OLD               ( 4  )
#define FD_VOTE_TOO_SOON_TO_REAUTHORIZE         ( 5  )
#define FD_VOTE_LOCKOUT_CONFLICT                ( 6  )
#define FD_VOTE_NEW_VOTE_STATE_LOCKOUT_MISMATCH ( 7  )
#define FD_VOTE_SLOTS_NOT_ORDERED               ( 8  )
#define FD_VOTE_CONFIRMATIONS_NOT_ORDERED       ( 9  )
#define FD_VOTE_ZERO_CONFIRMATIONS              ( 10 )
#define FD_VOTE_CONFIRMATION_TOO_LARGE          ( 11 )
#define FD_VOTE_ROOT_ROLL_BACK                  ( 12 )
#define FD_VOTE_CONFIRMATION_ROLL_BACK          ( 13 )
#define FD_VOTE_SLOT_SMALLER_THAN_ROOT          ( 14 )
#define FD_VOTE_TOO_MANY_VOTES                  ( 15 )
#define FD_VOTE_VOTES_TOO_OLD_ALL_FILTERED      ( 16 )
#define FD_VOTE_ROOT_ON_DIFFERENT_FORK          ( 17 )
#define FD_VOTE_ACTIVE_VOTE_ACCOUNT_CLOSE       ( 18 )


void record_timestamp_vote( fd_global_ctx_t *   global,
                            fd_pubkey_t const * vote_acc,
                            ulong               timestamp );


void record_timestamp_vote_with_slot( fd_global_ctx_t *   global,
                                      fd_pubkey_t const * vote_acc,
                                      ulong               timestamp,
                                      ulong               slot );

/* Entry-point for the Solana Vote Program */
int fd_executor_vote_program_execute_instruction( instruction_ctx_t ctx ) ;

/* Number of credits owned to the given vote account from the mining pool. */
int
fd_vote_acc_credits( fd_global_ctx_t * global,
                     fd_pubkey_t *     vote_acc,
                     ulong *           result );

int
fd_vote_load_account( fd_vote_state_versioned_t * account,
                      fd_account_meta_t *         meta,
                      fd_global_ctx_t *           global,
                      fd_pubkey_t const *         address );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h */
