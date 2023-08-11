#include "fd_executor.h"
#include "fd_acc_mgr.h"
#include "fd_hashes.h"
#include "fd_runtime.h"

#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include "../stakes/fd_stake_program.h"
#include "program/fd_config_program.h"
#include "program/fd_ed25519_program.h"
#include "program/fd_secp256k1_program.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_bpf_upgradeable_loader_program.h"
#include "program/fd_bpf_deprecated_loader_program.h"
#include "program/fd_compute_budget_program.h"

#include "../../ballet/base58/fd_base58.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

void* fd_executor_new(void*            mem,
                      fd_global_ctx_t* global,
                      ulong            footprint) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  fd_executor_t *executor = (fd_executor_t*)mem;
  executor->global = global;

  return mem;
}

fd_executor_t *fd_executor_join(void* mem) {
  return (fd_executor_t*)mem;
}

void *fd_executor_leave(fd_executor_t* executor) {
  return (void*)executor;
}

void* fd_executor_delete(void* mem) {
  return mem;
}

/* Look up a native program given it's pubkey key */
execute_instruction_func_t
fd_executor_lookup_native_program( fd_global_ctx_t* global,  fd_pubkey_t* pubkey ) {
  /* TODO: replace with proper lookup table */
  if ( !memcmp( pubkey, global->solana_vote_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_vote_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_system_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_system_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_config_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_config_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_stake_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_stake_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_ed25519_sig_verify_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_ed25519_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_keccak_secp_256k_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_secp256k1_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_bpf_loader_upgradeable_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_bpf_upgradeable_loader_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_bpf_loader_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_bpf_loader_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_bpf_loader_deprecated_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_bpf_deprecated_loader_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_compute_budget_program, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_compute_budget_program_execute_instruction_nop;
  } else {
    return NULL; /* FIXME */
  }
}

int
fd_executor_lookup_program( fd_global_ctx_t * global, fd_pubkey_t * pubkey ) {
  if( fd_executor_bpf_upgradeable_loader_program_is_executable_program_account(global, pubkey)==0 ) {
    return 0;
  }

  return -1;
}

/* todo rent exempt check */
static void
fd_set_exempt_rent_epoch_max( fd_global_ctx_t * global,
                              void const *      addr ) {

  fd_funk_rec_t const * rrec = NULL;
  int err = 0;
  uchar const * raw_data = fd_acc_mgr_view_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)addr, &rrec, &err );
  FD_LOG_NOTICE(( "fd_acc_mgr_view_data %32J returned %d", addr, err ));
  if ( FD_UNLIKELY( !raw_data && err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) )
    return;
  FD_TEST( raw_data && err==FD_ACC_MGR_SUCCESS );

  fd_account_meta_t const * meta_r = (fd_account_meta_t const *)raw_data;
  if( meta_r->info.lamports < fd_rent_exempt_minimum_balance( global, meta_r->dlen ) ) return;
  if( meta_r->info.rent_epoch == ULONG_MAX ) return;

  uchar * raw_data_w = fd_acc_mgr_modify_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)addr, 0, NULL, rrec, NULL, &err );
  FD_LOG_NOTICE(( "fd_acc_mgr_modify %32J returned %d", addr, err ));
  FD_TEST( raw_data_w );

  fd_account_meta_t * meta_w = (fd_account_meta_t *)raw_data_w;
  meta_w->info.rent_epoch = ULONG_MAX;
}

static int
fd_executor_collect_fee( fd_global_ctx_t *   global,
                         fd_pubkey_t const * account,
                         ulong               fee ) {

  int          err = 0;
  ulong        sz;
  void const * raw_data = fd_acc_mgr_modify_data( global->acc_mgr, global->funk_txn, account, 0, &sz, NULL, NULL, &err );
  if( !raw_data ) {
    FD_LOG_WARNING(( "fd_acc_mgr_view_data failed" ));
    // TODO: The fee payer does not seem to exist?!  what now?
    return -1;
  }
  fd_account_meta_t * meta = (fd_account_meta_t *)raw_data;

  if (fee > meta->info.lamports) {
    // TODO: Not enough lamports to pay for this txn...
    //
    // (Should this be lamps + whatever is required to keep the payer rent exempt?)
    FD_LOG_WARNING(( "Not enough lamps" ));
    return -1;
  }

  if (FD_UNLIKELY(global->log_level > 2)) {
    FD_LOG_WARNING(( "fd_execute_txn: global->collected: %ld->%ld (%ld)", global->bank.collected, global->bank.collected + fee, fee));
    FD_LOG_DEBUG(( "calling set_lamports to charge the fee %lu", fee));
  }

  // TODO: I BELIEVE we charge for the fee BEFORE we create the funk_txn fork
  // since we collect reguardless of the success of the txn execution...
  meta->info.lamports -= fee;
  global->bank.collected += fee;

  /* todo rent exempt check */
  meta->info.rent_epoch = ULONG_MAX;
  return 0;
}

int
fd_execute_txn( fd_executor_t* executor, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
  fd_pubkey_t *tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);

  fd_global_ctx_t *global = executor->global;

  transaction_ctx_t txn_ctx = {
    .global             = executor->global,
    .compute_unit_limit = 200000,
    .compute_unit_price = 0,
    .prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED,
    .txn_descriptor     = txn_descriptor,
    .txn_raw            = txn_raw,
  };

  int compute_budget_status = fd_executor_compute_budget_program_execute_instructions( &txn_ctx );
  (void)compute_budget_status;

  ulong fee = fd_runtime_calculate_fee ( global, &txn_ctx, txn_descriptor, txn_raw );
  if( fd_executor_collect_fee( global, &tx_accs[0], fee ) ) {
    return -1;
  }

  // TODO: we are just assuming the fee payer is account 0... FIX this..

  /// Returns true if the account at the specified index is not invoked as a
  /// program or, if invoked, is passed to a program.
  //    pub fn is_non_loader_key(&self, key_index: usize) -> bool {
  //      !self.is_invoked(key_index) || self.is_key_passed_to_program(key_index)
  //    }

  //    let fee_payer = (0..message.account_keys().len()).find_map(|i| {
  //            if let Some((k, a)) = &accounts.get(i) {
  //                if message.is_non_loader_key(i) {
  //                    return Some((k, a));
  //                }
  //            }
  //      }



  /* TODO: track compute budget used within execution */
  /* TODO: store stack of instructions to detect reentrancy */

  /* TODO: execute within a transaction context, which can be reverted */

  fd_funk_txn_t* parent_txn = global->funk_txn;
  fd_funk_txn_xid_t xid;
  xid.ul[0] = fd_rng_ulong( global->rng );
  xid.ul[1] = fd_rng_ulong( global->rng );
  xid.ul[2] = fd_rng_ulong( global->rng );
  xid.ul[3] = fd_rng_ulong( global->rng );
  fd_funk_txn_t * txn = fd_funk_txn_prepare( global->funk, parent_txn, &xid, 1 );
  global->funk_txn = txn;

  /* Update rent exempt on writable accounts if feature activated
     TODO this should probably not run on executable accounts
          Also iterate over LUT accounts */
  if( global->features.set_exempt_rent_epoch_max ) {
    fd_txn_acct_iter_t ctrl;
    for( ulong i=fd_txn_acct_iter_init( txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE, &ctrl );
          i<fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i, &ctrl ) ) {
      if( i==0 ) continue;
      fd_set_exempt_rent_epoch_max( global, &tx_accs[i] );
    }
  }

  for ( ushort i = 0; i < txn_descriptor->instr_cnt; ++i ) {
    fd_txn_instr_t *  instr = &txn_descriptor->instr[i];
    instruction_ctx_t ctx = {
      .global                 = executor->global,
      .instr                  = instr,
      .txn_ctx                = &txn_ctx,
    };

    // defense in depth
    if (instr->program_id >= txn_ctx.txn_descriptor->acct_addr_cnt) {
      int exec_result = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d", exec_result ));
      continue;
    }

    /* TODO: allow instructions to be failed, and the transaction to be reverted */
    execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( executor->global, &tx_accs[instr->program_id] );

    if (exec_instr_func != NULL) {
      int exec_result = exec_instr_func( ctx );
      if ( FD_UNLIKELY( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
        exec_result = exec_instr_func( ctx );
        FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d, program id: %32J", exec_result, &tx_accs[instr->program_id] ));
        fd_funk_txn_cancel(global->funk, txn, 0);
        global->funk_txn = parent_txn;
        return -1;
        /* TODO: revert transaction context */
      }
    } else {
      char program_id_str[FD_BASE58_ENCODED_32_SZ];
      fd_base58_encode_32((uchar *)&tx_accs[instr->program_id], NULL, program_id_str);
      if (fd_executor_lookup_program(executor->global, &tx_accs[instr->program_id]) == 0 ) {
        FD_LOG_NOTICE(( "found BPF upgradeable executable program account - program id: %s", program_id_str ));

        int exec_result = fd_executor_bpf_upgradeable_loader_program_execute_program_instruction(ctx);
        if (exec_result != FD_EXECUTOR_INSTR_SUCCESS) {
          fd_funk_txn_cancel(global->funk, txn, 0);
          global->funk_txn = parent_txn;
          return -1;
        }
      } else if ( fd_executor_bpf_loader_program_is_executable_program_account(executor->global, &tx_accs[instr->program_id]) == 0 ) {
        FD_LOG_NOTICE(( "found BPF v2 executable program account - program id: %s", program_id_str ));

        int exec_result = fd_executor_bpf_loader_program_execute_program_instruction(ctx);
        if (exec_result != FD_EXECUTOR_INSTR_SUCCESS) {
          fd_funk_txn_cancel(global->funk, txn, 0);
          global->funk_txn = parent_txn;
          return -1;
        }
      } else {
        FD_LOG_WARNING(( "did not find native or BPF executable program account - program id: %s", program_id_str ));
        fd_funk_txn_cancel(global->funk, txn, 0);
        global->funk_txn = parent_txn;
        return -1;
      }
    }

    /* TODO: sanity before/after checks: total lamports unchanged etc */
  }

  fd_funk_txn_merge(global->funk, txn, 0);
  global->funk_txn = parent_txn;
  return 0;
}
