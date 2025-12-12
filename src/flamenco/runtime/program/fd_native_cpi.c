#include "fd_native_cpi.h"
#include "../fd_borrowed_account.h"
#include "../fd_executor.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../../../util/bits/fd_uwide.h"

int
fd_native_cpi_native_invoke( fd_exec_instr_ctx_t *             ctx,
                             fd_pubkey_t const *               native_program_id,
                             uchar *                           instr_data,
                             ulong                             instr_data_len,
                             fd_vm_rust_account_meta_t const * acct_metas,
                             ulong                             acct_metas_len,
                             fd_pubkey_t const *               signers,
                             ulong                             signers_cnt ) {
  /* Set up the instr info */
  fd_instr_info_t *        instr_info = &ctx->runtime->instr.trace[ ctx->runtime->instr.trace_length++ ];
  fd_instruction_account_t instruction_accounts[ FD_INSTR_ACCT_MAX ];
  ulong                    instruction_accounts_cnt;

  /* Set the stack size */
  instr_info->stack_height = ctx->runtime->instr.stack_sz+1;

  /* fd_vm_prepare_instruction will handle missing/invalid account case */
  instr_info->program_id = UCHAR_MAX;
  int program_id = fd_runtime_find_index_of_account( ctx->txn_out, native_program_id );
  if( FD_LIKELY( program_id!=-1 ) ) {
    instr_info->program_id = (uchar)program_id;
  }

  fd_pubkey_t instr_acct_keys[ FD_INSTR_ACCT_MAX ];
  uchar       acc_idx_seen[ FD_INSTR_ACCT_MAX ];
  memset( acc_idx_seen, 0, FD_INSTR_ACCT_MAX );

  instr_info->acct_cnt = (ushort)acct_metas_len;
  for( ushort j=0U; j<acct_metas_len; j++ ) {
    fd_vm_rust_account_meta_t const * acct_meta     = &acct_metas[j];
    fd_pubkey_t const *               acct_key      = fd_type_pun_const( acct_meta->pubkey );
    instr_acct_keys[j] = *acct_key;

    int idx_in_txn    = fd_runtime_find_index_of_account( ctx->txn_out, acct_key );
    int idx_in_caller = fd_exec_instr_ctx_find_idx_of_instr_account( ctx, acct_key );

    fd_instr_info_setup_instr_account( instr_info,
                                       acc_idx_seen,
                                       idx_in_txn!=-1 ? (ushort)idx_in_txn : USHORT_MAX,
                                       idx_in_caller!=-1 ? (ushort)idx_in_caller : USHORT_MAX,
                                       j,
                                       acct_meta->is_writable,
                                       acct_meta->is_signer );
  }

  fd_memcpy( instr_info->data, instr_data, instr_data_len );
  instr_info->data_sz = (ushort)instr_data_len;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/program-runtime/src/invoke_context.rs#L312-L313 */
  int exec_err = fd_vm_prepare_instruction( instr_info,
                                            ctx,
                                            native_program_id,
                                            instr_acct_keys,
                                            instruction_accounts,
                                            &instruction_accounts_cnt,
                                            signers,
                                            signers_cnt );
  if( FD_UNLIKELY( exec_err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return exec_err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/program-runtime/src/invoke_context.rs#L315-L321 */
  return fd_execute_instr( ctx->runtime, ctx->bank, ctx->txn_in, ctx->txn_out, instr_info );
}

void
fd_native_cpi_create_account_meta( fd_pubkey_t const * key, uchar is_signer,
                                   uchar is_writable, fd_vm_rust_account_meta_t * meta ) {
  meta->is_signer = is_signer;
  meta->is_writable = is_writable;
  fd_memcpy( meta->pubkey, key->key, sizeof(fd_pubkey_t) );
}
