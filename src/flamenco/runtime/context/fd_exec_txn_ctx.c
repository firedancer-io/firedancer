#include "fd_exec_txn_ctx.h"
#include "../fd_acc_mgr.h"
#include "../fd_executor.h"
#include "../../vm/fd_vm.h"
#include "../fd_system_ids.h"

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
fd_exec_txn_ctx_join( void *      mem,
                      fd_spad_t * spad,
                      fd_wksp_t * spad_wksp ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_exec_txn_ctx_t * ctx = (fd_exec_txn_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  /* Rejoin the wksp */
  ctx->spad      = spad;
  ctx->spad_wksp = spad_wksp;

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
fd_exec_txn_ctx_get_account_at_index( fd_exec_txn_ctx_t *             ctx,
                                      ushort                          idx,
                                      fd_txn_account_t * *            account,
                                      fd_txn_account_condition_fn_t * condition ) {
  if( FD_UNLIKELY( idx>=ctx->accounts_cnt ) ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  fd_txn_account_t * txn_account = &ctx->accounts[idx];
  *account = txn_account;

  if( FD_LIKELY( condition != NULL ) ) {
    if( FD_UNLIKELY( !condition( *account, ctx, idx ) ) ) {
      return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
    }
  }

  return FD_ACC_MGR_SUCCESS;
}

int
fd_exec_txn_ctx_get_account_with_key( fd_exec_txn_ctx_t *             ctx,
                                      fd_pubkey_t const *             pubkey,
                                      fd_txn_account_t * *            account,
                                      fd_txn_account_condition_fn_t * condition ) {
  int index = fd_exec_txn_ctx_find_index_of_account( ctx, pubkey );
  if( FD_UNLIKELY( index==-1 ) ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  return fd_exec_txn_ctx_get_account_at_index( ctx,
                                               (uchar)index,
                                               account,
                                               condition );
}

int
fd_exec_txn_ctx_get_executable_account( fd_exec_txn_ctx_t *             ctx,
                                        fd_pubkey_t const *             pubkey,
                                        fd_txn_account_t * *            account,
                                        fd_txn_account_condition_fn_t * condition ) {
  /* First try to fetch the executable account from the existing borrowed accounts.
     If the pubkey is in the account keys, then we want to re-use that
     borrowed account since it reflects changes from prior instructions. Referencing the
     read-only executable accounts list is incorrect behavior when the program
     data account is written to in a prior instruction (e.g. program upgrade + invoke within the same txn) */
  int err = fd_exec_txn_ctx_get_account_with_key( ctx, pubkey, account, condition );
  if( FD_UNLIKELY( err==FD_ACC_MGR_SUCCESS ) ) {
    return FD_ACC_MGR_SUCCESS;
  }

  for( ushort i=0; i<ctx->executable_cnt; i++ ) {
    if( memcmp( pubkey->uc, ctx->executable_accounts[i].pubkey->uc, sizeof(fd_pubkey_t) )==0 ) {
      fd_txn_account_t * txn_account = &ctx->executable_accounts[i];
      *account = txn_account;

      if( FD_LIKELY( condition != NULL ) ) {
        if( FD_UNLIKELY( !condition( *account, ctx, i ) ) ) {
          return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
        }
      }

      return FD_ACC_MGR_SUCCESS;
    }
  }

  return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
}

int
fd_exec_txn_ctx_get_key_of_account_at_index( fd_exec_txn_ctx_t *  ctx,
                                             ushort               idx,
                                             fd_pubkey_t const * * key ) {
  /* Return a NotEnoughAccountKeys error if idx is out of bounds.
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L218 */
  if( FD_UNLIKELY( idx>=ctx->accounts_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  *key = &ctx->account_keys[ idx ];
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_exec_txn_ctx_setup_basic( fd_exec_txn_ctx_t * ctx ) {
  ctx->compute_unit_limit = 200000;
  ctx->compute_unit_price = 0;
  ctx->compute_meter      = 200000;
  ctx->prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED;
  ctx->custom_err         = UINT_MAX;

  ctx->instr_stack_sz                  = 0;
  ctx->accounts_cnt                    = 0UL;
  ctx->executable_cnt                  = 0UL;
  ctx->paid_fees                       = 0UL;
  ctx->heap_size                       = FD_VM_HEAP_DEFAULT;
  ctx->loaded_accounts_data_size_limit = FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;
  ctx->loaded_accounts_data_size       = 0UL;
  ctx->accounts_resize_delta           = 0UL;
  ctx->collected_rent                  = 0UL;

  ctx->num_instructions = 0;
  memset( ctx->return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  ctx->return_data.len = 0;

  ctx->dirty_vote_acc  = 0;
  ctx->dirty_stake_acc = 0;
  ctx->failed_instr    = NULL;
  ctx->instr_err_idx   = INT_MAX;
  ctx->capture_ctx     = NULL;

  ctx->instr_info_cnt     = 0UL;
  ctx->cpi_instr_info_cnt = 0UL;
  ctx->instr_trace_length = 0UL;

  ctx->exec_err      = 0;
  ctx->exec_err_kind = FD_EXECUTOR_ERR_KIND_NONE;
}

void
fd_exec_txn_ctx_setup( fd_exec_txn_ctx_t   * ctx,
                       fd_txn_t      const * txn_descriptor,
                       fd_rawtxn_b_t const * txn_raw ) {
  fd_exec_txn_ctx_setup_basic( ctx );
  ctx->txn_descriptor   = txn_descriptor;
  ctx->_txn_raw->raw    = txn_raw->raw;
  ctx->_txn_raw->txn_sz = txn_raw->txn_sz;
}

void
fd_exec_txn_ctx_teardown( fd_exec_txn_ctx_t * ctx ) {
  (void)ctx;
}

void
fd_exec_txn_ctx_reset_return_data( fd_exec_txn_ctx_t * txn_ctx ) {
  txn_ctx->return_data.len = 0;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.1/sdk/program/src/message/versions/v0/loaded.rs#L162 */
int
fd_txn_account_is_demotion( const int        idx,
                            const fd_txn_t * txn_descriptor,
                            const uint       bpf_upgradeable_in_txn ) {
  uint is_program = 0U;
  for( ulong j=0UL; j<txn_descriptor->instr_cnt; j++ ) {
    if( txn_descriptor->instr[j].program_id == idx ) {
      is_program = 1U;
      break;
    }
  }

  return (is_program && !bpf_upgradeable_in_txn);
}

uint
fd_txn_account_has_bpf_loader_upgradeable( const fd_pubkey_t * account_keys,
                                           const ulong         accounts_cnt ) {
  for( ulong j=0; j<accounts_cnt; j++ ) {
    const fd_pubkey_t * acc = &account_keys[j];
    if ( memcmp( acc->uc, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) {
      return 1U;
    }
  }
  return 0U;
}

/* This function aims to mimic the writable accounts check to populate the writable accounts cache, used
   to determine if accounts are writable or not.

   https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L38-L47 */
int
fd_exec_txn_ctx_account_is_writable_idx( fd_exec_txn_ctx_t const * txn_ctx, ushort idx ) {
  uint bpf_upgradeable = fd_txn_account_has_bpf_loader_upgradeable( txn_ctx->account_keys, txn_ctx->accounts_cnt );
  return fd_exec_txn_account_is_writable_idx_flat( txn_ctx->slot,
                                                   idx,
                                                   &txn_ctx->account_keys[idx],
                                                   txn_ctx->txn_descriptor,
                                                   &txn_ctx->features,
                                                   bpf_upgradeable );
}

int
fd_exec_txn_account_is_writable_idx_flat( const ulong           slot,
                                          const ushort          idx,
                                          const fd_pubkey_t *   addr_at_idx,
                                          const fd_txn_t *      txn_descriptor,
                                          const fd_features_t * features,
                                          const uint            bpf_upgradeable_in_txn ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L43 */
  if( !fd_txn_is_writable( txn_descriptor, idx ) ) {
    return 0;
  }

  /* See comments in fd_system_ids.h.
     https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L44 */
  if( fd_pubkey_is_active_reserved_key( addr_at_idx ) ||
      ( FD_FEATURE_ACTIVE( slot, features, add_new_reserved_account_keys ) &&
                           fd_pubkey_is_pending_reserved_key( addr_at_idx ) ) ||
      ( FD_FEATURE_ACTIVE( slot, features, enable_secp256r1_precompile ) &&
                           fd_pubkey_is_secp256r1_key( addr_at_idx ) ) ) {

    return 0;
  }

  if( fd_txn_account_is_demotion( idx, txn_descriptor, bpf_upgradeable_in_txn ) ) {
    return 0;
  }

  return 1;
}

/* Account pre-condition filtering functions */

int
fd_txn_account_check_exists( fd_txn_account_t *        acc,
                             fd_exec_txn_ctx_t const * ctx,
                             ushort                    idx ) {
  (void) ctx;
  (void) idx;
  return fd_account_meta_exists( acc->vt->get_meta( acc ) );
}

int
fd_txn_account_check_is_writable( fd_txn_account_t *        acc,
                                  fd_exec_txn_ctx_t const * ctx,
                                  ushort                    idx ) {
  (void) acc;
  return fd_exec_txn_ctx_account_is_writable_idx( ctx, idx );
}

int
fd_txn_account_check_fee_payer_writable( fd_txn_account_t *        acc,
                                         fd_exec_txn_ctx_t const * ctx,
                                         ushort                    idx ) {
  (void) acc;
  return fd_txn_is_writable( ctx->txn_descriptor, idx );
}

int
fd_txn_account_check_borrow_mut( fd_txn_account_t *        acc,
                                 fd_exec_txn_ctx_t const * ctx,
                                 ushort                    idx ) {
  (void) ctx;
  (void) idx;
  return acc->vt->is_mutable( acc ) && acc->vt->try_borrow_mut( acc );
}
