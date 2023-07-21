#ifndef HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h

#include "../fd_flamenco_base.h"
#include "../runtime/fd_executor.h"
#include "../runtime/fd_runtime.h"
#include "fd_stakes.h"
#include "../runtime/program/fd_vote_program.h"

FD_PROTOTYPES_BEGIN

struct merge_kind {
  uint discriminant;
  uint is_active_stake;
};
typedef struct merge_kind fd_merge_kind_t;

enum MERGE_KIND_STATE {
    MERGE_KIND_INACTIVE,
    MERGE_KIND_ACTIVE_EPOCH,
    MERGE_KIND_FULLY_ACTIVE
};

/* Entry-point for the Solana Stake Program */
int fd_executor_stake_program_execute_instruction( instruction_ctx_t ctx ) ;

/* Initializes an account which holds configuration used by the stake program.
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/config.rs
 */
void fd_stake_program_config_init( fd_global_ctx_t* global );
int read_stake_state( fd_global_ctx_t* global, fd_pubkey_t* stake_acc, fd_stake_state_t* result );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_stake_program_h */
