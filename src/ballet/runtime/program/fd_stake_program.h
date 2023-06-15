#ifndef HEADER_fd_src_ballet_runtime_program_fd_stake_program_h
#define HEADER_fd_src_ballet_runtime_program_fd_stake_program_h

#include "../../fd_ballet_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

FD_PROTOTYPES_BEGIN

struct merge_kind {
  uint discriminant;
  fd_stake_state_meta_t* meta;
  union merge_stake {
    fd_acc_lamports_t stake_lamports;
    fd_stake_t* stake;
  } merge_stake;
};
typedef struct merge_kind fd_merge_kind_t;

/* Entry-point for the Solana Stake Program */
int fd_executor_stake_program_execute_instruction( instruction_ctx_t ctx ) ;

/* Initializes an account which holds configuration used by the stake program.
   https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/config.rs
 */
void fd_stake_program_config_init( fd_global_ctx_t* global );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_program_fd_stake_program_h */
