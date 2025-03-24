#include "fd_exec_txn_ctx.h"
#include "../fd_acc_mgr.h"
#include "../fd_executor.h"
#include "../../vm/fd_vm.h"
#include "../fd_system_ids.h"
#include "fd_exec_epoch_ctx.h"

void *
fd_exec_txn_ctx_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_TXN_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_txn_ctx_t * self = (fd_exec_txn_ctx_t *) mem;

  FD_COMPILER_MFENCE();
  self->magic = FD_EXEC_TXN_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_exec_txn_ctx_t *
fd_exec_txn_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_exec_txn_ctx_t * ctx = (fd_exec_txn_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_exec_txn_ctx_leave( fd_exec_txn_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_exec_txn_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_TXN_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_txn_ctx_t * hdr = (fd_exec_txn_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

int
fd_exec_txn_ctx_get_account_view_idx( fd_exec_txn_ctx_t * ctx,
                                      uchar               idx,
                                      fd_txn_account_t * * account ) {
  if( FD_UNLIKELY( idx>=ctx->accounts_cnt ) ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  fd_txn_account_t * txn_account = &ctx->accounts[idx];
  *account = txn_account;

  if( FD_UNLIKELY( !fd_acc_exists( txn_account->const_meta ) ) ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  return FD_ACC_MGR_SUCCESS;
}

int
fd_exec_txn_ctx_get_account_view( fd_exec_txn_ctx_t *  ctx,
                                  fd_pubkey_t const *  pubkey,
                                  fd_txn_account_t * * account ) {
  for( ulong i = 0; i < ctx->accounts_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->account_keys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if readable???
      fd_txn_account_t * txn_account = &ctx->accounts[i];
      *account = txn_account;

      if( FD_UNLIKELY( !fd_acc_exists( txn_account->const_meta ) ) ) {
        return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
      }

      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

int
fd_exec_txn_ctx_get_account_executable_view( fd_exec_txn_ctx_t *  ctx,
                                             fd_pubkey_t const *  pubkey,
                                             fd_txn_account_t * * account ) {
  /* First try to fetch the executable account from the existing borrowed accounts.
     If the pubkey is in the account keys, then we want to re-use that
     borrowed account since it reflects changes from prior instructions. Referencing the
     read-only executable accounts list is incorrect behavior when the program
     data account is written to in a prior instruction (e.g. program upgrade + invoke within the same txn) */
  int err = fd_exec_txn_ctx_get_account_view( ctx, pubkey, account );
  if( FD_UNLIKELY( err==FD_ACC_MGR_SUCCESS ) ) {
    return FD_ACC_MGR_SUCCESS;
  }

  for( ulong i = 0; i < ctx->executable_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->executable_accounts[i].pubkey->uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if readable???
      fd_txn_account_t * txn_account = &ctx->executable_accounts[i];
      *account = txn_account;

      if( FD_UNLIKELY( !fd_acc_exists( txn_account->const_meta ) ) )
        return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;

      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

int
fd_exec_txn_ctx_get_account_modify_fee_payer( fd_exec_txn_ctx_t *  ctx,
                                              fd_txn_account_t * * account ) {

  *account = &ctx->accounts[ FD_FEE_PAYER_TXN_IDX ];

  if( FD_UNLIKELY( !fd_txn_is_writable( ctx->txn_descriptor, FD_FEE_PAYER_TXN_IDX ) ) ) {
    return FD_ACC_MGR_ERR_WRITE_FAILED;
  }
  return FD_ACC_MGR_SUCCESS;
}

int
fd_exec_txn_ctx_get_account_modify_idx( fd_exec_txn_ctx_t *   ctx,
                                        uchar                 idx,
                                        ulong                 min_data_sz,
                                        fd_txn_account_t * *  account ) {
  if( idx >= ctx->accounts_cnt ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  fd_txn_account_t * txn_account = &ctx->accounts[idx];
  if( FD_UNLIKELY( !fd_txn_account_is_writable_idx( ctx, (int)idx ) ) ) {
    return FD_ACC_MGR_ERR_WRITE_FAILED;
  }

  if( min_data_sz > txn_account->const_meta->dlen ) {
    fd_txn_account_resize( txn_account, min_data_sz );
  }

  *account = txn_account;
  return FD_ACC_MGR_SUCCESS;
}

int
fd_exec_txn_ctx_get_account_modify( fd_exec_txn_ctx_t *  ctx,
                                    fd_pubkey_t const *  pubkey,
                                    ulong                min_data_sz,
                                    fd_txn_account_t * * account ) {
  for( ulong i = 0; i < ctx->accounts_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->account_keys[i].uc, sizeof(fd_pubkey_t) )==0 ) {
      // TODO: check if writable???
      fd_txn_account_t * txn_account = &ctx->accounts[i];
      if( min_data_sz > txn_account->const_meta->dlen ) {
        fd_txn_account_resize( txn_account, min_data_sz );
      }
      *account = txn_account;
      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

void
fd_exec_txn_ctx_setup_basic( fd_exec_txn_ctx_t * txn_ctx ) {
  txn_ctx->compute_unit_limit = 200000;
  txn_ctx->compute_unit_price = 0;
  txn_ctx->compute_meter      = 200000;
  txn_ctx->prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED;
  txn_ctx->custom_err         = UINT_MAX;

  txn_ctx->instr_stack_sz                  = 0;
  txn_ctx->accounts_cnt                    = 0UL;
  txn_ctx->executable_cnt                  = 0UL;
  txn_ctx->paid_fees                       = 0UL;
  txn_ctx->heap_size                       = FD_VM_HEAP_DEFAULT;
  txn_ctx->loaded_accounts_data_size_limit = FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;
  txn_ctx->loaded_accounts_data_size       = 0UL;
  txn_ctx->accounts_resize_delta           = 0UL;
  txn_ctx->collected_rent                  = 0UL;

  txn_ctx->num_instructions = 0;
  memset( txn_ctx->return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  txn_ctx->return_data.len = 0;

  txn_ctx->dirty_vote_acc  = 0;
  txn_ctx->dirty_stake_acc = 0;
  txn_ctx->failed_instr    = NULL;
  txn_ctx->instr_err_idx   = INT_MAX;
  txn_ctx->capture_ctx     = NULL;

  txn_ctx->instr_info_cnt     = 0;
  txn_ctx->instr_trace_length = 0;

  txn_ctx->exec_err      = 0;
  txn_ctx->exec_err_kind = FD_EXECUTOR_ERR_KIND_NONE;
}

void
fd_exec_txn_ctx_setup( fd_exec_txn_ctx_t   * txn_ctx,
                       fd_txn_t      const * txn_descriptor,
                       fd_rawtxn_b_t const * txn_raw ) {
  fd_exec_txn_ctx_setup_basic( txn_ctx );
  txn_ctx->txn_descriptor   = txn_descriptor;
  txn_ctx->_txn_raw->raw    = txn_raw->raw;
  txn_ctx->_txn_raw->txn_sz = txn_raw->txn_sz;
}

void
fd_exec_txn_ctx_teardown( fd_exec_txn_ctx_t * txn_ctx ) {
  (void)txn_ctx;
}

void
fd_exec_txn_ctx_from_exec_slot_ctx( fd_exec_slot_ctx_t const * slot_ctx,
                                    fd_exec_txn_ctx_t *        txn_ctx,
                                    fd_wksp_t const *          funk_wksp,
                                    fd_wksp_t const *          runtime_pub_wksp,
                                    ulong                      funk_txn_gaddr,
                                    ulong                      acc_mgr_gaddr,
                                    ulong                      sysvar_cache_gaddr,
                                    ulong                      funk_gaddr ) {

  txn_ctx->runtime_pub_wksp = (fd_wksp_t *)runtime_pub_wksp;

  txn_ctx->funk_txn = fd_wksp_laddr( funk_wksp, funk_txn_gaddr );
  if( FD_UNLIKELY( !txn_ctx->funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction" ));
  }

  txn_ctx->acc_mgr = fd_wksp_laddr( runtime_pub_wksp, acc_mgr_gaddr );
  if( FD_UNLIKELY( !txn_ctx->acc_mgr ) ) {
    FD_LOG_ERR(( "Could not find valid account manager" ));
  }
  txn_ctx->acc_mgr->funk = fd_wksp_laddr( funk_wksp, funk_gaddr );

  txn_ctx->sysvar_cache = fd_wksp_laddr( runtime_pub_wksp, sysvar_cache_gaddr );

  txn_ctx->features     = slot_ctx->epoch_ctx->features;
  txn_ctx->status_cache = slot_ctx->status_cache;

  txn_ctx->bank_hash_cmp = slot_ctx->epoch_ctx->bank_hash_cmp;

  txn_ctx->prev_lamports_per_signature = slot_ctx->prev_lamports_per_signature;
  txn_ctx->enable_exec_recording       = slot_ctx->enable_exec_recording;
  txn_ctx->total_epoch_stake           = slot_ctx->epoch_ctx->total_epoch_stake;

  txn_ctx->slot                        = slot_ctx->slot_bank.slot;
  txn_ctx->fee_rate_governor           = slot_ctx->slot_bank.fee_rate_governor;
  txn_ctx->block_hash_queue            = slot_ctx->slot_bank.block_hash_queue; /* MAKE GLOBAL */

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank_const( slot_ctx->epoch_ctx );
  txn_ctx->schedule                    = epoch_bank->epoch_schedule;
  txn_ctx->rent                        = epoch_bank->rent;
  txn_ctx->slots_per_year              = epoch_bank->slots_per_year;
  txn_ctx->stakes                      = epoch_bank->stakes;

}

void
fd_exec_txn_ctx_reset_return_data( fd_exec_txn_ctx_t * txn_ctx ) {
  txn_ctx->return_data.len = 0;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.1/sdk/program/src/message/versions/v0/loaded.rs#L162 */
int
fd_txn_account_is_demotion( fd_exec_txn_ctx_t const * txn_ctx, int idx )
{
  uint is_program = 0U;
  for( ulong j=0UL; j<txn_ctx->txn_descriptor->instr_cnt; j++ ) {
    if( txn_ctx->txn_descriptor->instr[j].program_id == idx ) {
      is_program = 1U;
      break;
    }
  }

  uint bpf_upgradeable_in_txn = 0U;
  for( ulong j = 0; j < txn_ctx->accounts_cnt; j++ ) {
    const fd_pubkey_t * acc = &txn_ctx->account_keys[j];
    if ( memcmp( acc->uc, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) {
      bpf_upgradeable_in_txn = 1U;
      break;
    }
  }
  return (is_program && !bpf_upgradeable_in_txn);
}

/* This function aims to mimic the writable accounts check to populate the writable accounts cache, used
   to determine if accounts are writable or not.

   https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L38-L47 */
int
fd_txn_account_is_writable_idx( fd_exec_txn_ctx_t const * txn_ctx, int idx ) {

  /* https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L43 */
  if( !fd_txn_is_writable( txn_ctx->txn_descriptor, idx ) ) {
    return 0;
  }

  /* See comments in fd_system_ids.h.
     https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L44 */
  if( fd_pubkey_is_active_reserved_key(&txn_ctx->account_keys[idx] ) ||
      ( FD_FEATURE_ACTIVE( txn_ctx->slot, txn_ctx->features, add_new_reserved_account_keys ) &&
                           fd_pubkey_is_pending_reserved_key( &txn_ctx->account_keys[idx] ) ) ||
      ( FD_FEATURE_ACTIVE( txn_ctx->slot, txn_ctx->features, enable_secp256r1_precompile ) &&
                           fd_pubkey_is_secp256r1_key( &txn_ctx->account_keys[idx] ) ) ) {
    return 0;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L45 */
  if( fd_txn_account_is_demotion( txn_ctx, idx ) ) {
    return 0;
  }

  return 1;
}
