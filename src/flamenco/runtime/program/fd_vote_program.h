#ifndef HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_executor.h"


/**********************************************************************/
/* Vote Program                                                       */
/**********************************************************************/

/* Vote error codes */
/* TODO: serialize these in the correct */
#define FD_VOTE_ERROR_VOTE_TOO_OLD                  ( 0 )
#define FD_VOTE_ERR_SLOTS_MISMATCH                  ( 1 )
#define FD_VOTE_ERR_SLOTS_HASH_MISMATCH             ( 2 )
#define FD_VOTE_ERR_EMPTY_SLOTS                     ( 3 )
#define FD_VOTE_ERR_TIMESTAMP_TOO_OLD               ( 4 )
#define FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE         ( 5 )
#define FD_VOTE_ERR_LOCKOUT_CONFLICT                ( 6 )
#define FD_VOTE_ERR_NEW_VOTE_STATE_LOCKOUT_MISMATCH ( 7 )
#define FD_VOTE_ERR_SLOTS_NOT_ORDERED               ( 8 )
#define FD_VOTE_ERR_CONFIRMATIONS_NOT_ORDERED       ( 9 )
#define FD_VOTE_ERR_ZERO_CONFIRMATIONS              ( 10 )
#define FD_VOTE_ERR_CONFIRMATION_TOO_LARGE          ( 11 )
#define FD_VOTE_ERR_ROOT_ROLL_BACK                  ( 12 )
#define FD_VOTE_ERR_CONFIRMATION_ROLL_BACK          ( 13 )
#define FD_VOTE_ERR_SLOT_SMALLER_THAN_ROOT          ( 14 )
#define FD_VOTE_ERR_TOO_MANY_VOTES                  ( 15 )
#define FD_VOTE_ERR_VOTES_TOO_OLD_ALL_FILTERED      ( 16 )
#define FD_VOTE_ERR_ROOT_ON_DIFFERENT_FORK          ( 17 )
#define FD_VOTE_ERR_ACTIVE_VOTE_ACCOUNT_CLOSE       ( 18 )
#define FD_VOTE_ERR_COMMISSION_UPDATE_TOO_LATE      ( 19 )

/**********************************************************************/
/* Entry point for the Vote Program                                   */
/**********************************************************************/

FD_PROTOTYPES_BEGIN

int
fd_executor_vote_program_execute_instruction( fd_exec_instr_ctx_t ctx );

void
fd_vote_record_timestamp_vote( fd_exec_slot_ctx_t * slot_ctx,
                               fd_pubkey_t const *  vote_acc,
                               ulong                timestamp );

void
fd_vote_record_timestamp_vote_with_slot( fd_exec_slot_ctx_t * slot_ctx,
                                         fd_pubkey_t const *  vote_acc,
                                         ulong                timestamp,
                                         ulong                slot );

int
fd_executor_vote_program_execute_instruction( fd_exec_instr_ctx_t ctx );

int
fd_vote_acc_credits( fd_exec_instr_ctx_t       ctx,
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
fd_vote_get_state( fd_borrowed_account_t const * self,
                   fd_valloc_t                   valloc,
                   fd_vote_state_versioned_t *   versioned /* out */ );

void
fd_vote_convert_to_current( fd_vote_state_versioned_t * self, fd_valloc_t valloc );

int
fd_vote_decode_compact_update( fd_exec_instr_ctx_t              ctx,
                               fd_compact_vote_state_update_t * compact_update,
                               fd_vote_state_update_t *         vote_update );

ulong
fd_vote_transcoding_state_versioned_size( fd_vote_state_versioned_t const * self );

int
fd_vote_transcoding_state_versioned_encode( fd_vote_state_versioned_t const * self,
                                            fd_bincode_encode_ctx_t *         ctx );

fd_vote_instruction_t *
fd_vote_flamenco_txn_decode( fd_flamenco_txn_t * txn, fd_valloc_t valloc );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_vote_program_h */
