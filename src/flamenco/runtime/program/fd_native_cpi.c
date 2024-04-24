#include "../fd_account.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "../../vm/fd_vm_interp.h"

int 
fd_native_cpi_execute_system_program_instruction( fd_exec_instr_ctx_t * ctx,
                                                  fd_system_program_instruction_t const * instr,
                                                  fd_vm_rust_account_meta_t const * acct_metas,
                                                  ulong acct_metas_len,
                                                  fd_pubkey_t const * signers,
                                                  ulong signers_cnt ) {
  fd_instr_info_t instr_info[1];
  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;

  for ( ulong i = 0; i < ctx->txn_ctx->accounts_cnt; i++ ) {
    if ( memcmp( fd_solana_system_program_id.key, ctx->txn_ctx->accounts[i].key, sizeof(fd_pubkey_t) ) == 0 ) {
      instr_info->program_id = (uchar)i;
      break;
    }
  }

  ulong starting_lamports = 0;
  uchar acc_idx_seen[256];
  memset( acc_idx_seen, 0, 256 );

  instr_info->program_id_pubkey = fd_solana_system_program_id;
  instr_info->acct_cnt = (ushort)acct_metas_len;
  for ( ulong j = 0; j < acct_metas_len; j++ ) {
    fd_vm_rust_account_meta_t const * acct_meta = &acct_metas[j];

    for ( ulong k = 0; k < ctx->txn_ctx->accounts_cnt; k++ ) {
      if ( memcmp( acct_meta->pubkey, ctx->txn_ctx->accounts[k].uc, sizeof(fd_pubkey_t) ) == 0 ) {
        instr_info->acct_pubkeys[j] = ctx->txn_ctx->accounts[k];
        instr_info->acct_txn_idxs[j] = (uchar)k;
        instr_info->acct_flags[j] = 0;
        instr_info->borrowed_accounts[j] = &ctx->txn_ctx->borrowed_accounts[k];

        instr_info->is_duplicate[j] = acc_idx_seen[k];
        if( FD_LIKELY( !acc_idx_seen[k] ) ) {
          /* This is the first time seeing this account */
          acc_idx_seen[k] = 1;
          if( instr_info->borrowed_accounts[j]->const_meta != NULL ) {
            starting_lamports += instr_info->borrowed_accounts[j]->const_meta->info.lamports;
          }
        }

        if( acct_meta->is_writable ) {
          instr_info->acct_flags[j] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
        }
        // TODO: should check the parent has signer flag set
        if( acct_meta->is_signer ) {
          instr_info->acct_flags[j] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
        } else {
          for( ulong k = 0; k < signers_cnt; k++ ) {
            if( memcmp( &signers[k], &acct_meta->pubkey, sizeof( fd_pubkey_t ) ) == 0 ) {
              instr_info->acct_flags[j] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
              break;
            }
          }
        }
        break;
      }
    }

    instr_info->starting_lamports = starting_lamports;
  }

  fd_bincode_encode_ctx_t ctx2;
  uchar buf[4096UL]; // Size that is large enough for the instruction
  ctx2.data = buf;
  ctx2.dataend = (uchar*)ctx2.data + sizeof(buf);
  int err = fd_system_program_instruction_encode( instr, &ctx2 );
  if( err ) {
    FD_LOG_WARNING(( "Encode failed" ));
    return FD_EXECUTOR_INSTR_ERR_FATAL;
  }

  instr_info->data = buf;
  instr_info->data_sz = sizeof(buf);
  int exec_err = fd_vm_prepare_instruction( ctx->instr, instr_info, ctx, instruction_accounts,
                                              &instruction_accounts_cnt, signers, signers_cnt );
  if( exec_err != FD_EXECUTOR_INSTR_SUCCESS ) {
    FD_LOG_WARNING(("Preparing instruction failed"));
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
