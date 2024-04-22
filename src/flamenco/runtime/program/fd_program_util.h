#ifndef HEADER_fd_src_flamenco_runtime_native_program_util_h
#define HEADER_fd_src_flamenco_runtime_native_program_util_h

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"

#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_stake_history.h"

#include <stdbool.h>

#define FD_DEBUG_MODE 0

#ifndef FD_DEBUG_MODE
#define FD_DEBUG( ... ) __VA_ARGS__
#else
#define FD_DEBUG( ... )
#endif

#define FD_PROGRAM_OK FD_EXECUTOR_INSTR_SUCCESS

FD_PROTOTYPES_BEGIN

/**********************************************************************/
/* impl BorrowedAccount                                               */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L841
static inline int
fd_borrowed_account_checked_add_lamports( fd_borrowed_account_t * self, ulong lamports ) {
  // FIXME suppress warning
  ulong temp;
  int   rc = fd_int_if( __builtin_uaddl_overflow( self->meta->info.lamports, lamports, &temp ),
                      FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW,
                      FD_PROGRAM_OK );
  self->meta->info.lamports = temp;
  return rc;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L851
static inline int
fd_borrowed_account_checked_sub_lamports( fd_borrowed_account_t * self, ulong lamports ) {
  // FIXME suppress warning
  ulong temp;
  int   rc = fd_int_if( __builtin_usubl_overflow( self->meta->info.lamports, lamports, &temp ),
                      FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW,
                      FD_PROGRAM_OK );
  self->meta->info.lamports = temp;
  return rc;
}

/**********************************************************************/
/* impl TransactionContext                                            */
/**********************************************************************/

static FD_FN_UNUSED int
fd_txn_ctx_get_key_of_account_at_index( fd_exec_txn_ctx_t const * self,
                                        uchar                     index_in_transaction,
                                        /* out */ fd_pubkey_t *   pubkey ) {
  if( FD_UNLIKELY( index_in_transaction >= self->accounts_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }
  *pubkey = self->accounts[index_in_transaction];
  return FD_PROGRAM_OK;
}

/**********************************************************************/
/* impl InstructionContext                                            */
/**********************************************************************/

static FD_FN_UNUSED int
fd_instr_ctx_get_index_of_instruction_account_in_transaction(
    fd_instr_info_t const * self,
    uchar                   instruction_account_index,
    /* out */ uchar *       index_in_transaction ) {
  if( FD_UNLIKELY( instruction_account_index >= self->acct_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }
  *index_in_transaction = self->acct_txn_idxs[instruction_account_index];
  return FD_PROGRAM_OK;
}

static int
fd_instr_ctx_try_borrow_account( fd_exec_instr_ctx_t *     self,
                                 fd_exec_txn_ctx_t const * transaction_context,
                                 uchar                     index_in_transaction,
                                 uchar                     index_in_instruction,
                                 fd_borrowed_account_t **  out ) {
  int rc;
  if( FD_UNLIKELY( index_in_transaction >= transaction_context->accounts_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
  // FIXME implement `const` versions for instructions that don't need write
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L685-L690
  rc = fd_instr_borrowed_account_modify_idx( self,
                                             index_in_instruction,
                                             0, // FIXME
                                             out );
    if( rc != FD_ACC_MGR_SUCCESS ) {
    rc = fd_instr_borrowed_account_view_idx( self,
                                             index_in_instruction,
                                             out );
  }
  switch ( rc ) {
  case FD_ACC_MGR_SUCCESS:
    return FD_PROGRAM_OK;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L637
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L639
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
}

static FD_FN_UNUSED int
fd_instr_ctx_try_borrow_instruction_account( fd_exec_instr_ctx_t *     self,
                                             fd_exec_txn_ctx_t const * transaction_context,
                                             uchar                     instruction_account_index,
                                             fd_borrowed_account_t **  out ) {
  int rc;

  uchar index_in_transaction = FD_TXN_ACCT_ADDR_MAX;
  rc                         = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
      self->instr, instruction_account_index, &index_in_transaction );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = fd_instr_ctx_try_borrow_account( self,
                                        transaction_context,
                                        index_in_transaction,
                                        instruction_account_index, // FIXME add to program accounts?
                                        out );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/src/transaction_context.rs#L718
static FD_FN_UNUSED int
fd_instr_ctx_is_instruction_account_signer( fd_instr_info_t const * self,
                                            uchar                   instruction_account_index,
                                            bool *                  out ) {
  if( FD_UNLIKELY( instruction_account_index >= self->acct_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }
  *out = fd_instr_acc_is_signer_idx( self, instruction_account_index );
  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/src/transaction_context.rs#L718
static FD_FN_UNUSED int
fd_instr_ctx_get_signers( fd_instr_info_t const *   self,
                          fd_exec_txn_ctx_t const * transaction_context,
                          fd_pubkey_t const *       signers[static FD_TXN_SIG_MAX] ) {
  // int   rc;
  uchar j = 0;
  for( uchar i = 0; i < self->acct_cnt && j < FD_TXN_SIG_MAX; i++ ) {
    if( FD_UNLIKELY( fd_instr_acc_is_signer_idx( self, i ) ) ) {
      signers[j++] = &transaction_context->accounts[self->acct_txn_idxs[i]];
      // FIXME
      // rc =
      //     get_key_of_account_at_index( transaction_context, self->acct_txn_idxs[i], &signers[j++]
      //     );
      // if ( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    }
  }
  return FD_PROGRAM_OK;
}

static inline bool
fd_instr_ctx_signers_contains( fd_pubkey_t const * signers[FD_TXN_SIG_MAX],
                               fd_pubkey_t const * pubkey ) {
  for( ulong i = 0; i < FD_TXN_SIG_MAX && signers[i]; i++ ) {
    if( FD_UNLIKELY( 0 == memcmp( signers[i], pubkey, sizeof( fd_pubkey_t ) ) ) ) return true;
  }
  return false;
}

/**********************************************************************/
/* mod get_sysvar_with_account_check                                  */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/v1.17/program-runtime/src/sysvar_cache.rs#L223
#define FD_SYSVAR_CHECK_SYSVAR_ACCOUNT(                                                                  \
    transaction_context, instruction_context, instruction_account_index, fd_sysvar_id )                  \
  do {                                                                                                   \
    int   rc;                                                                                            \
    uchar index_in_transaction = FD_TXN_ACCT_ADDR_MAX;                                                   \
    rc                         = fd_instr_ctx_get_index_of_instruction_account_in_transaction(           \
        instruction_context, instruction_account_index, &index_in_transaction ); \
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;                                                  \
    if( FD_UNLIKELY( 0 != memcmp( &transaction_context->accounts[index_in_transaction],                  \
                                  fd_sysvar_id.key,                                                      \
                                  sizeof( fd_pubkey_t ) ) ) ) {                                          \
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;                                                          \
    }                                                                                                    \
  } while( 0 )

#define FD_SYSVAR_CHECKED_READ( invoke_context,                                                    \
                                instruction_context,                                               \
                                instruction_account_index,                                         \
                                fd_sysvar_id,                                                      \
                                fd_sysvar_read,                                                    \
                                out )                                                              \
  do {                                                                                             \
    FD_SYSVAR_CHECK_SYSVAR_ACCOUNT(                                                                \
        invoke_context->txn_ctx, instruction_context, instruction_account_index, fd_sysvar_id );   \
    if( FD_UNLIKELY( !fd_sysvar_read( out, invoke_context->slot_ctx ) ) )                          \
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;                                             \
    return FD_PROGRAM_OK;                                                                          \
  } while( 0 )

#define FD_SYSVAR_CHECKED_READ_2(invoke_context,                                                   \
                                instruction_context,                                               \
                                instruction_account_index,                                         \
                                fd_sysvar_id,                                                      \
                                fd_sysvar_read,                                                    \
                                valloc,                                                            \
                                out )                                                              \
  do {                                                                                             \
    FD_SYSVAR_CHECK_SYSVAR_ACCOUNT(                                                                \
        invoke_context->txn_ctx, instruction_context, instruction_account_index, fd_sysvar_id );   \
    if( FD_UNLIKELY( !fd_sysvar_read( out, invoke_context->slot_ctx, valloc ) ) )                  \
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;                                             \
    return FD_PROGRAM_OK;                                                                          \
  } while( 0 )

// https://github.com/firedancer-io/solana/blob/debug-master/program-runtime/src/sysvar_cache.rs#L236
static FD_FN_UNUSED int
fd_sysvar_clock_checked_read( fd_exec_instr_ctx_t const *       invoke_context,
                              fd_instr_info_t const *           instruction_context,
                              uchar                             instruction_account_index,
                              /* out */ fd_sol_sysvar_clock_t * clock ) {
  FD_SYSVAR_CHECKED_READ( invoke_context,
                          instruction_context,
                          instruction_account_index,
                          fd_sysvar_clock_id,
                          fd_sysvar_clock_read,
                          clock );
}

// https://github.com/firedancer-io/solana/blob/debug-master/program-runtime/src/sysvar_cache.rs#L249
static FD_FN_UNUSED int
fd_sysvar_rent_checked_read( fd_exec_instr_ctx_t const * invoke_context,
                             fd_instr_info_t const *     instruction_context,
                             uchar                       instruction_account_index,
                             /* out */ fd_rent_t *       rent ) {
  FD_SYSVAR_CHECKED_READ( invoke_context,
                          instruction_context,
                          instruction_account_index,
                          fd_sysvar_rent_id,
                          fd_sysvar_rent_read,
                          rent );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_native_program_util_h */
