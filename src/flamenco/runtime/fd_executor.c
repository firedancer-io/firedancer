#include "fd_executor.h"
#include "fd_runtime.h"

#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include "program/fd_stake_program.h"
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
  } else if ( !memcmp( pubkey, global->solana_bpf_loader_upgradeable_program_with_jit, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_bpf_upgradeable_loader_program_execute_instruction;
  } else if ( !memcmp( pubkey, global->solana_bpf_loader_program_with_jit, sizeof( fd_pubkey_t ) ) ) {
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

void
fd_execute_txn( fd_executor_t* executor, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
  fd_pubkey_t *tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);

  fd_global_ctx_t *global = executor->global;

  ulong fee = fd_runtime_calculate_fee ( global, txn_descriptor, txn_raw );

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


  fd_acc_lamports_t lamps;
  int               ret = fd_acc_mgr_get_lamports ( global->acc_mgr, global->funk_txn, &tx_accs[0], &lamps);
  if (ret != FD_ACC_MGR_SUCCESS) {
    // TODO: The fee payer does not seem to exist?!  what now?
    return;
  }

  if (fee > lamps) {
    // TODO: Not enough lamports to pay for this txn...
    //
    // (Should this be lamps + whatever is required to keep the payer rent exempt?)
    FD_LOG_WARNING(( "Not enough lamps" ));
    return;
  }

  // TODO:  HORRIBLE hack until we implement the schedule leader stuff...
  //
  // The VERY first txn (at slot 2) happens to be a vote made by the very first schedule leader..
  if (!global->collector_set) {
    fd_memcpy(global->bank.collector_id.key, tx_accs[0].key, sizeof(fd_pubkey_t));
    global->collector_set = 1;
  }

  if (FD_UNLIKELY(global->log_level > 2)) {
    FD_LOG_WARNING(( "fd_execute_txn: global->collected: %ld->%ld (%ld)", global->bank.collected, global->bank.collected + fee, fee));
    FD_LOG_WARNING(( "calling set_lamports to charge the fee %lu", fee));
  }

  // TODO: I BELIEVE we charge for the fee BEFORE we create the funk_txn fork
  // since we collect reguardless of the success of the txn execution...
  ret = fd_acc_mgr_set_lamports ( global->acc_mgr, global->funk_txn, global->bank.slot, &tx_accs[0], lamps - fee);
  if (ret != FD_ACC_MGR_SUCCESS) {
    // TODO: Wait! wait! what?!
    FD_LOG_ERR(( "lamport update failed" ));
    return;
  }
  global->bank.collected += fee;

  /* TODO: track compute budget used within execution */
  /* TODO: store stack of instructions to detect reentrancy */

  /* TODO: execute within a transaction context, which can be reverted */

//
//  fd_funk_xactionid_t* ptxn = global->funk_txn;
//  fd_funk_xactionid_t local_funk_txn;
//  global->funk_txn = &local_funk_txn;
//
//  ulong *p = (ulong *) &global->funk_txn->id[0];
//  p[0] = fd_rng_ulong( global->rng );
//  p[1] = fd_rng_ulong( global->rng );
//  p[2] = fd_rng_ulong( global->rng );
//  p[3] = fd_rng_ulong( global->rng );
//
//  if (fd_funk_fork(global->funk, ptxn, global->funk_txn) == 0)
//    FD_LOG_ERR(("fd_funk_fork failed"));
  transaction_ctx_t txn_ctx = {
    .global             = executor->global,
    .compute_unit_limit = 200000,
    .compute_unit_price = 1,
    .txn_descriptor     = txn_descriptor,
    .txn_raw            = txn_raw,
  };

  int compute_budget_status = fd_executor_compute_budget_program_execute_instructions( &txn_ctx );
  (void)compute_budget_status;

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
        char program_id_str[FD_BASE58_ENCODED_32_SZ];
        fd_base58_encode_32((uchar *)&tx_accs[instr->program_id], NULL, program_id_str);
        FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d, program id: %s", exec_result, program_id_str ));
        FD_LOG_HEXDUMP_ERR(( "instruction content", (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off, instr->data_sz ));

        /* TODO: revert transaction context */
      }
    } else {
      char program_id_str[FD_BASE58_ENCODED_32_SZ];
      fd_base58_encode_32((uchar *)&tx_accs[instr->program_id], NULL, program_id_str);
      if (fd_executor_lookup_program(executor->global, &tx_accs[instr->program_id]) == 0 ) {
        FD_LOG_NOTICE(( "found BPF executable program account - program id: %s", program_id_str ));

        fd_executor_bpf_upgradeable_loader_program_execute_program_instruction(ctx);
      } else {
        FD_LOG_WARNING(( "did not find native or BPF executable program account - program id: %s", program_id_str ));
      }
    }


    /* TODO: sanity before/after checks: total lamports unchanged etc */
  }

  // if err
  //             fd_funk_cancel(global->funk, global->funk_txn);
  // else
//  fd_funk_commit(global->funk, global->funk_txn);
//  global->funk_txn = ptxn;
}
