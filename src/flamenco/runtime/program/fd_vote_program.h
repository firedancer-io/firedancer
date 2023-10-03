#ifndef HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h

#include <stdbool.h>

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"

FD_PROTOTYPES_BEGIN

/**********************************************************************/
/* Vote Program                                                       */
/**********************************************************************/

#define OK FD_EXECUTOR_INSTR_SUCCESS /* Corresponds to Result::Ok in Rust */

/* Vote error codes */
/* TODO: serialize these in the correct */
#define VOTE_TOO_OLD                    ( 0 )
#define SLOTS_MISMATCH                  ( 1 )
#define SLOT_HASH_MISMATCH              ( 2 )
#define EMPTY_SLOTS                     ( 3 )
#define TIMESTAMP_TOO_OLD               ( 4 )
#define TOO_SOON_TO_REAUTHORIZE         ( 5 )
#define LOCKOUT_CONFLICT                ( 6 )
#define NEW_VOTE_STATE_LOCKOUT_MISMATCH ( 7 )
#define SLOTS_NOT_ORDERED               ( 8 )
#define CONFIRMATIONS_NOT_ORDERED       ( 9 )
#define ZERO_CONFIRMATIONS              ( 10 )
#define CONFIRMATION_TOO_LARGE          ( 11 )
#define ROOT_ROLL_BACK                  ( 12 )
#define CONFIRMATION_ROLL_BACK          ( 13 )
#define SLOT_SMALLER_THAN_ROOT          ( 14 )
#define TOO_MANY_VOTES                  ( 15 )
#define VOTES_TOO_OLD_ALL_FILTERED      ( 16 )
#define ROOT_ON_DIFFERENT_FORK          ( 17 )
#define ACTIVE_VOTE_ACCOUNT_CLOSE       ( 18 )
#define COMMISSION_UPDATE_TOO_LATE      ( 19 )

/**********************************************************************/
/* Entry point for the Vote Program                                   */
/**********************************************************************/

int
fd_executor_vote_program_execute_instruction( instruction_ctx_t ctx );

void
fd_vote_record_timestamp_vote( fd_global_ctx_t *   global,
                               fd_pubkey_t const * vote_acc,
                               ulong               timestamp );

void
fd_vote_record_timestamp_vote_with_slot( fd_global_ctx_t *   global,
                                         fd_pubkey_t const * vote_acc,
                                         ulong               timestamp,
                                         ulong               slot );

int
fd_executor_vote_program_execute_instruction( instruction_ctx_t ctx );

int
fd_vote_acc_credits( instruction_ctx_t         ctx,
                     fd_account_meta_t const * vote_acc_meta,
                     uchar const *             vote_acc_data,
                     ulong *                   result );

struct fd_commission_split {
  ulong voter_portion;
  ulong staker_portion;
  uint  is_split;
};
typedef struct fd_commission_split fd_commission_split_t;

void
fd_vote_commission_split( fd_vote_state_versioned_t * vote_state_versioned,
                          ulong                       on,
                          fd_commission_split_t *     result );

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

int
fd_vote_get_state( fd_borrowed_account_t const *            self,
                   instruction_ctx_t                        ctx,
                   /* return */ fd_vote_state_versioned_t * versioned );

void
fd_vote_convert_to_current( fd_vote_state_versioned_t * self, instruction_ctx_t ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h */
