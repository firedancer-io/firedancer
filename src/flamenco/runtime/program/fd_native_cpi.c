#include "fd_native_cpi.h"
#include "../fd_borrowed_account.h"
#include "../fd_executor.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../../../util/bits/fd_uwide.h"

int
fd_native_cpi_execute_system_program_instruction( fd_exec_instr_ctx_t * ctx,
                                                  fd_system_program_instruction_t const * instr,
                                                  fd_vm_rust_account_meta_t const * acct_metas,
                                                  ulong acct_metas_len,
                                                  fd_pubkey_t const * signers,
                                                  ulong signers_cnt ) {
  fd_instr_info_t instr_info[ 1 ];
  fd_instruction_account_t instruction_accounts[ FD_INSTR_ACCT_MAX ];
  ulong instruction_accounts_cnt;

  /* fd_vm_prepare_instruction will handle missing/invalid account case */
  instr_info->program_id = UCHAR_MAX;
  int program_id = fd_exec_txn_ctx_find_index_of_account( ctx->txn_ctx, &fd_solana_system_program_id );
  if( FD_LIKELY( program_id!=-1 ) ) {
    instr_info->program_id = (uchar)program_id;
  }

  uchar acc_idx_seen[256];
  memset( acc_idx_seen, 0, FD_INSTR_ACCT_MAX );

  instr_info->acct_cnt = (ushort)acct_metas_len;
  for ( ushort j=0; j<acct_metas_len; j++ ) {
    fd_vm_rust_account_meta_t const * acct_meta     = &acct_metas[j];
    fd_pubkey_t const *               acct_key      = fd_type_pun_const( acct_meta->pubkey );

    int idx_in_caller = fd_exec_instr_ctx_find_idx_of_instr_account( ctx, acct_key );

    if( FD_LIKELY( idx_in_caller!=-1 ) ) {
      fd_instr_info_setup_instr_account( instr_info,
                                         acc_idx_seen,
                                         ctx->instr->accounts[ idx_in_caller ].index_in_transaction,
                                         (ushort)idx_in_caller,
                                         j,
                                         acct_meta->is_writable,
                                         acct_meta->is_signer );
    }
  }

  fd_bincode_encode_ctx_t ctx2;
  uchar buf[4096UL]; // Size that is large enough for the instruction
  ctx2.data = buf;
  ctx2.dataend = (uchar*)ctx2.data + sizeof(buf);
  int err = fd_system_program_instruction_encode( instr, &ctx2 );
  if( err ) {
    return FD_EXECUTOR_INSTR_ERR_FATAL;
  }

  instr_info->data = buf;
  instr_info->data_sz = sizeof(buf);
  int exec_err = fd_vm_prepare_instruction( instr_info, ctx, instruction_accounts,
                                            &instruction_accounts_cnt, signers, signers_cnt );
  if( exec_err != FD_EXECUTOR_INSTR_SUCCESS ) {
    return exec_err;
  }

  return fd_execute_instr( ctx->txn_ctx, instr_info );
}

void
fd_native_cpi_create_account_meta( fd_pubkey_t const * key, uchar is_signer,
                                   uchar is_writable, fd_vm_rust_account_meta_t * meta ) {
  meta->is_signer = is_signer;
  meta->is_writable = is_writable;
  fd_memcpy( meta->pubkey, key->key, sizeof(fd_pubkey_t) );
}
