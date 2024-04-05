#include "fd_executor.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "fd_system_ids.h"

#include "program/fd_address_lookup_table_program.h"
#include "program/fd_bpf_loader_v1_program.h"
#include "program/fd_bpf_loader_v2_program.h"
#include "program/fd_bpf_loader_v3_program.h"
#include "program/fd_bpf_loader_v4_program.h"
#include "program/fd_config_program.h"
#include "program/fd_ed25519_program.h"
#include "program/fd_stake_program.h"
#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"

#include <assert.h>

fd_exec_instr_fn_t
fd_executor_lookup_native_program( fd_pubkey_t const * program_id ) {

  /* TODO: Move this to fd_system_ids and use fd_map_perfect */

  if( 0==memcmp( program_id, &fd_solana_address_lookup_table_program_id, sizeof(fd_pubkey_t) ) )
    return fd_address_lookup_table_program_execute;
  if( 0==memcmp( program_id, &fd_solana_bpf_loader_deprecated_program_id, sizeof(fd_pubkey_t) ) )
    return fd_bpf_loader_v1_program_execute;
  if( 0==memcmp( program_id, &fd_solana_bpf_loader_program_id, sizeof(fd_pubkey_t) ) )
    return fd_bpf_loader_v2_program_execute;
  if( 0==memcmp( program_id, &fd_solana_bpf_loader_upgradeable_program_id, sizeof(fd_pubkey_t) ) )
    return fd_bpf_loader_v3_program_execute;
  if( 0==memcmp( program_id, &fd_solana_bpf_loader_v4_program_id, sizeof(fd_pubkey_t) ) )
    return fd_bpf_loader_v4_program_execute;
  if( 0==memcmp( program_id, &fd_solana_ed25519_sig_verify_program_id, sizeof(fd_pubkey_t) ) )
    return fd_ed25519_program_execute;
  if( 0==memcmp( program_id, &fd_solana_config_program_id, sizeof(fd_pubkey_t) ) )
    return fd_config_program_execute;
  if( 0==memcmp( program_id, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) )
    return fd_stake_program_execute;
  if( 0==memcmp( program_id, &fd_solana_system_program_id, sizeof(fd_pubkey_t) ) )
    return fd_system_program_execute;
  if( 0==memcmp( program_id, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) )
    return fd_vote_program_execute;

  return NULL;

}

int
fd_execute_instr( fd_exec_txn_ctx_t * txn_ctx,
                  fd_instr_info_t *   instr ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_pubkey_t const * txn_accs = txn_ctx->accounts;

    fd_exec_instr_ctx_t * ctx = &txn_ctx->instr_stack[ txn_ctx->instr_stack_sz++ ];
    *ctx = (fd_exec_instr_ctx_t) {
      .instr     = instr,
      .txn_ctx   = txn_ctx,
      .epoch_ctx = txn_ctx->epoch_ctx,
      .slot_ctx  = txn_ctx->slot_ctx,
      .valloc    = fd_scratch_virtual(),
      .acc_mgr   = txn_ctx->acc_mgr,
      .funk_txn  = txn_ctx->funk_txn,
    };

    assert( instr->program_id < txn_ctx->txn_descriptor->acct_addr_cnt + txn_ctx->txn_descriptor->addr_table_adtl_cnt );

    fd_pubkey_t const * program_id = &txn_accs[ instr->program_id ];
    fd_exec_instr_fn_t  native_prog_fn = fd_executor_lookup_native_program( program_id );

    int exec_result = FD_EXECUTOR_INSTR_SUCCESS;
    if( native_prog_fn != NULL ) {
      exec_result = native_prog_fn( *ctx );
    } else {
      FD_LOG_WARNING(( "TODO: support user deployed programs" ));
      exec_result = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
    }

    txn_ctx->instr_stack_sz--;

    /* TODO: sanity before/after checks: total lamports unchanged etc */
    return exec_result;
  } FD_SCRATCH_SCOPE_END;
}

FD_FN_CONST char const *
fd_executor_instr_strerror( int err ) {

  switch( err ) {
  case FD_EXECUTOR_INSTR_SUCCESS                                : return "success";
  case FD_EXECUTOR_INSTR_ERR_FATAL                              : return "FATAL";
  case FD_EXECUTOR_INSTR_ERR_GENERIC_ERR                        : return "GENERIC_ERR";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ARG                        : return "INVALID_ARG";
  case FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA                 : return "INVALID_INSTR_DATA";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA                   : return "INVALID_ACC_DATA";
  case FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL                 : return "ACC_DATA_TOO_SMALL";
  case FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS                 : return "INSUFFICIENT_FUNDS";
  case FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID               : return "INCORRECT_PROGRAM_ID";
  case FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE         : return "MISSING_REQUIRED_SIGNATURE";
  case FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED            : return "ACC_ALREADY_INITIALIZED";
  case FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT              : return "UNINITIALIZED_ACCOUNT";
  case FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR                   : return "UNBALANCED_INSTR";
  case FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID                : return "MODIFIED_PROGRAM_ID";
  case FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND     : return "EXTERNAL_ACCOUNT_LAMPORT_SPEND";
  case FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED             : return "EXTERNAL_DATA_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE            : return "READONLY_LAMPORT_CHANGE";
  case FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED             : return "READONLY_DATA_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_IDX              : return "DUPLICATE_ACCOUNT_IDX";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED                : return "EXECUTABLE_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_RENT_EPOCH_MODIFIED                : return "RENT_EPOCH_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS                : return "NOT_ENOUGH_ACC_KEYS";
  case FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED              : return "ACC_DATA_SIZE_CHANGED";
  case FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE                 : return "ACC_NOT_EXECUTABLE";
  case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED                  : return "ACC_BORROW_FAILED";
  case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING             : return "ACC_BORROW_OUTSTANDING";
  case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC      : return "DUPLICATE_ACCOUNT_OUT_OF_SYNC";
  case FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR                         : return "CUSTOM_ERR";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ERR                        : return "INVALID_ERR";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED           : return "EXECUTABLE_DATA_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE          : return "EXECUTABLE_LAMPORT_CHANGE";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT : return "EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT";
  case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID             : return "UNSUPPORTED_PROGRAM_ID";
  case FD_EXECUTOR_INSTR_ERR_CALL_DEPTH                         : return "CALL_DEPTH";
  case FD_EXECUTOR_INSTR_ERR_MISSING_ACC                        : return "MISSING_ACC";
  case FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED             : return "REENTRANCY_NOT_ALLOWED";
  case FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED           : return "MAX_SEED_LENGTH_EXCEEDED";
  case FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS                      : return "INVALID_SEEDS";
  case FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC                    : return "INVALID_REALLOC";
  case FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED            : return "COMPUTE_BUDGET_EXCEEDED";
  case FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION               : return "PRIVILEGE_ESCALATION";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE  : return "PROGRAM_ENVIRONMENT_SETUP_FAILURE";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE         : return "PROGRAM_FAILED_TO_COMPLETE";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPILE          : return "PROGRAM_FAILED_TO_COMPILE";
  case FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE                      : return "ACC_IMMUTABLE";
  case FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY                : return "INCORRECT_AUTHORITY";
  case FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR                     : return "BORSH_IO_ERROR";
  case FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT                : return "ACC_NOT_RENT_EXEMPT";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER                  : return "INVALID_ACC_OWNER";
  case FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW                : return "ARITHMETIC_OVERFLOW";
  case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR                 : return "UNSUPPORTED_SYSVAR";
  case FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER                      : return "ILLEGAL_OWNER";
  case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_SIZE_EXCEEDED        : return "MAX_ACCS_DATA_SIZE_EXCEEDED";
  case FD_EXECUTOR_INSTR_ERR_ACTIVE_VOTE_ACC_CLOSE              : return "ACTIVE_VOTE_ACC_CLOSE";
  default: break;
  }

  return "unknown";
}
