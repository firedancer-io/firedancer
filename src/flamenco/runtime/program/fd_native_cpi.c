#include "fd_native_cpi.h"
#include "../fd_borrowed_account.h"
#include "../fd_executor.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../../../util/bits/fd_uwide.h"

int
fd_native_cpi_execute_system_program_instruction( fd_exec_instr_ctx_t * ctx,
                                                  fd_system_program_instruction_t const * instr,
                                                  fd_vm_account_meta_t const * acct_metas,
                                                  ulong acct_metas_len,
                                                  fd_pubkey_t const * signers,
                                                  ulong signers_cnt ) {
  fd_instr_info_t instr_info[ 1 ];
  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;

  /* fd_vm_prepare_instruction will handle missing/invalid account case */
  instr_info->program_id_pubkey = fd_solana_system_program_id;
  instr_info->program_id = UCHAR_MAX;

  for( ulong i = 0UL; i < ctx->txn_ctx->accounts_cnt; i++ ) {
    if( !memcmp( fd_solana_system_program_id.key, ctx->txn_ctx->account_keys[i].key, sizeof(fd_pubkey_t) ) ) {
      instr_info->program_id = (uchar)i;
      break;
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
  int exec_err = fd_vm_prepare_instruction( ctx->instr, instr_info, ctx,
                                            acct_metas, acct_metas_len,
                                            instruction_accounts, &instruction_accounts_cnt,
                                            signers, signers_cnt );
  if( exec_err != FD_EXECUTOR_INSTR_SUCCESS ) {
    return exec_err;
  }

  return fd_execute_instr( ctx->txn_ctx, instr_info );
}

void
fd_native_cpi_create_account_meta( fd_pubkey_t const * key, uchar is_signer,
                                   uchar is_writable, fd_vm_account_meta_t * meta ) {
  meta->is_signer = is_signer;
  meta->is_writable = is_writable;
  fd_memcpy( meta->pubkey, key->key, sizeof(fd_pubkey_t) );
}
