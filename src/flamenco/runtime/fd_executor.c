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
#include "program/fd_bpf_loader_v4_program.h"
#include "program/fd_compute_budget_program.h"

#include "../../ballet/base58/fd_base58.h"

void * fd_executor_new(void*           mem,
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

fd_executor_t * fd_executor_join(void* mem) {
  return (fd_executor_t*)mem;
}

void * fd_executor_leave(fd_executor_t* executor) {
  return (void*)executor;
}

void * fd_executor_delete(void* mem) {
  return mem;
}

void
fd_convert_txn_instr_to_instr( fd_txn_t const * txn_descriptor,
                               fd_rawtxn_b_t const * txn_raw,
                               fd_txn_instr_t const * txn_instr,
                               fd_pubkey_t const * accounts,
                               fd_instr_t * instr ) {
  instr->program_id = txn_instr->program_id;
  instr->program_id_pubkey = accounts[txn_instr->program_id];
  instr->acct_cnt = txn_instr->acct_cnt;
  instr->data_sz = txn_instr->data_sz;
  instr->data =  (uchar *)txn_raw->raw + txn_instr->data_off;

  uchar * instr_acc_idxs = (uchar *)txn_raw->raw + txn_instr->acct_off;
  for( ulong i = 0; i < instr->acct_cnt; i++ ) {
    instr->acct_txn_idxs[i] = instr_acc_idxs[i];
    instr->acct_pubkeys[i] = accounts[instr_acc_idxs[i]];

    instr->acct_flags[i] = 0;
    if( fd_account_is_writable_idx( txn_descriptor, txn_instr->program_id, instr_acc_idxs[i] ) ) {
      instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
    }
    if( fd_txn_is_signer ( txn_descriptor, instr_acc_idxs[i] ) ) {
      instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
    }
  }
}

/* Look up a native program given it's pubkey key */
execute_instruction_func_t
fd_executor_lookup_native_program( fd_global_ctx_t * global,  fd_pubkey_t const * pubkey ) {
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
  } else if( !memcmp( pubkey, global->solana_bpf_loader_v4_program->key, sizeof(fd_pubkey_t) ) ) {
    return fd_executor_bpf_loader_v4_program_execute_instruction;
  } else {
    return NULL; /* FIXME */
  }
}

int
fd_executor_lookup_program( fd_global_ctx_t * global, fd_pubkey_t const * pubkey ) {
  if( fd_executor_bpf_upgradeable_loader_program_is_executable_program_account( global, pubkey )==0 ) {
    return 0;
  }

  return -1;
}

// TODO: handle error codes
void
fd_executor_setup_accessed_accounts_for_txn( transaction_ctx_t * txn_ctx, fd_rawtxn_b_t const * txn_raw ) {
  fd_global_ctx_t * global = txn_ctx->global;

  fd_pubkey_t *tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  for( ulong i = 0; i < txn_ctx->txn_descriptor->acct_addr_cnt; i++ ) {
    txn_ctx->accounts[i] = tx_accs[i];
  }
  txn_ctx->accounts_cnt += (uchar) txn_ctx->txn_descriptor->acct_addr_cnt;

  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    fd_txn_acct_addr_lut_t * addr_luts = fd_txn_get_address_tables( txn_ctx->txn_descriptor );
    for (ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++) {
      fd_txn_acct_addr_lut_t * addr_lut = &addr_luts[i];
      fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_raw->raw + addr_lut->addr_off);

      char * raw_acc_data = (char*) fd_acc_mgr_view_raw(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) addr_lut_acc, NULL, NULL);
      if (!raw_acc_data) {
        // TODO: return txn err code
        FD_LOG_ERR(( "addr lut not found" ));
      }

      fd_account_meta_t * meta = (fd_account_meta_t *)raw_acc_data;
      uchar * acct_data = fd_account_get_data(meta);

      FD_LOG_WARNING(( "LUT ACC: idx: %lu, acc: %32J, meta.dlen; %lu", i, addr_lut_acc, meta->dlen ));

      fd_address_lookup_table_state_t addr_lookup_table_state;
      fd_address_lookup_table_state_new( &addr_lookup_table_state );
      fd_bincode_decode_ctx_t decode_ctx = {
        .data = acct_data,
        .dataend = &acct_data[56], // TODO macro const.
        .valloc  = global->valloc,
      };
      if (fd_address_lookup_table_state_decode( &addr_lookup_table_state, &decode_ctx )) {
        FD_LOG_ERR(("fd_address_lookup_table_state_decode failed"));
      }
      if (addr_lookup_table_state.discriminant != fd_address_lookup_table_state_enum_lookup_table) {
        FD_LOG_ERR(("addr lut is uninit"));
      }

      fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&acct_data[56];
      uchar * writable_lut_idxs = (uchar *)txn_raw->raw + addr_lut->writable_off;
      for (ulong j = 0; j < addr_lut->writable_cnt; j++) {
        FD_LOG_WARNING(( "LUT ACC WRITABLE: idx: %3lu, acc: %32J, lut_idx: %3lu, acct_idx: %3lu, %32J", i, addr_lut_acc, j, writable_lut_idxs[j], &lookup_addrs[writable_lut_idxs[j]] ));
        txn_ctx->accounts[txn_ctx->accounts_cnt++] = lookup_addrs[writable_lut_idxs[j]];
      }
    }

    for (ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++) {
      fd_txn_acct_addr_lut_t * addr_lut = &addr_luts[i];
      fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_raw->raw + addr_lut->addr_off);

      char * raw_acc_data = (char*) fd_acc_mgr_view_raw(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) addr_lut_acc, NULL, NULL);
      if (!raw_acc_data) {
        // TODO: return txn err code
        FD_LOG_ERR(( "addr lut not found" ));
      }

      fd_account_meta_t * meta = (fd_account_meta_t *)raw_acc_data;
      uchar * acct_data = fd_account_get_data(meta);

      fd_address_lookup_table_state_t addr_lookup_table_state;
      fd_address_lookup_table_state_new( &addr_lookup_table_state );
      fd_bincode_decode_ctx_t decode_ctx = {
        .data = acct_data,
        .dataend = &acct_data[56], // TODO macro const.
        .valloc  = global->valloc,
      };
      if (fd_address_lookup_table_state_decode( &addr_lookup_table_state, &decode_ctx )) {
        FD_LOG_ERR(("fd_address_lookup_table_state_decode failed"));
      }
      if (addr_lookup_table_state.discriminant != fd_address_lookup_table_state_enum_lookup_table) {
        FD_LOG_ERR(("addr lut is uninit"));
      }

      fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&acct_data[56];
      uchar * readonly_lut_idxs = (uchar *)txn_raw->raw + addr_lut->readonly_off;
      for (ulong j = 0; j < addr_lut->readonly_cnt; j++) {
        FD_LOG_WARNING(( "LUT ACC READONLY: idx: %3lu, acc: %32J, lut_idx: %3lu, acct_idx: %3lu, %32J", i, addr_lut_acc, j, readonly_lut_idxs[j], &lookup_addrs[readonly_lut_idxs[j]] ));
        txn_ctx->accounts[txn_ctx->accounts_cnt++] = lookup_addrs[readonly_lut_idxs[j]];
      }
    }
  }
}

/* todo rent exempt check */
static void
fd_set_exempt_rent_epoch_max( fd_global_ctx_t * global,
                              void const *      addr ) {

  fd_funk_rec_t const *     rec_ro  = NULL;
  fd_account_meta_t const * meta_ro = NULL;
  int err = fd_acc_mgr_view( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)addr, &rec_ro, &meta_ro, NULL );
  if( FD_UNLIKELY( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) )
    return;
  FD_TEST( err==FD_ACC_MGR_SUCCESS );

  if( meta_ro->info.lamports < fd_rent_exempt_minimum_balance( global, meta_ro->dlen ) ) return;
  if( meta_ro->info.rent_epoch == ULONG_MAX ) return;

  fd_account_meta_t * meta_rw = NULL;
  err = fd_acc_mgr_modify( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)addr, 0, 0UL, rec_ro, NULL, &meta_rw, NULL );
  FD_TEST( err==FD_ACC_MGR_SUCCESS );

  meta_rw->info.rent_epoch = ULONG_MAX;
}

static int
fd_executor_collect_fee( fd_global_ctx_t *   global,
                         fd_pubkey_t const * account,
                         ulong               fee ) {

  fd_account_meta_t * meta = NULL;
  int err = fd_acc_mgr_modify( global->acc_mgr, global->funk_txn, account, 0, 0UL, NULL, NULL, &meta, NULL );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_acc_mgr_modify_raw failed (%d)", err ));
    // TODO: The fee payer does not seem to exist?!  what now?
    return -1;
  }

  if (fee > meta->info.lamports) {
    // TODO: Not enough lamports to pay for this txn...
    //
    // (Should this be lamps + whatever is required to keep the payer rent exempt?)
    FD_LOG_WARNING(( "Not enough lamps" ));
    return -1;
  }

  if (FD_UNLIKELY(global->log_level > 2)) {
    FD_LOG_WARNING(( "fd_execute_txn: global->collected: %ld->%ld (%ld)", global->bank.collected_fees, global->bank.collected_fees + fee, fee));
    FD_LOG_DEBUG(( "calling set_lamports to charge the fee %lu", fee));
  }

  // TODO: I BELIEVE we charge for the fee BEFORE we create the funk_txn fork
  // since we collect reguardless of the success of the txn execution...
  meta->info.lamports -= fee;
  global->bank.collected_fees += fee;
  global->bank.capitalization -= fee;

  /* todo rent exempt check */
  if( FD_FEATURE_ACTIVE( global, set_exempt_rent_epoch_max ) )
    meta->info.rent_epoch = ULONG_MAX;
  return 0;
}

int
fd_execute_instr( fd_executor_t * executor, fd_instr_t * instr, transaction_ctx_t * txn_ctx ) {
  fd_pubkey_t const * txn_accs = txn_ctx->accounts;

  instruction_ctx_t * ctx = &txn_ctx->instr_stack[txn_ctx->instr_stack_sz++];
  ctx->global = executor->global;
  ctx->instr = instr;
  ctx->txn_ctx = txn_ctx;

  // defense in depth
  if (instr->program_id >= txn_ctx->txn_descriptor->acct_addr_cnt + txn_ctx->txn_descriptor->addr_table_adtl_cnt) {
    int exec_result = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    txn_ctx->instr_stack_sz--;

    FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d", exec_result ));
    return exec_result;
  }

  /* TODO: allow instructions to be failed, and the transaction to be reverted */
  fd_pubkey_t const * program_id_acc = &txn_accs[instr->program_id];

  execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( executor->global, program_id_acc );

  int exec_result = FD_EXECUTOR_INSTR_SUCCESS;
  if (exec_instr_func != NULL) {
    exec_result = exec_instr_func( *ctx );

  } else {
    if (fd_executor_lookup_program(executor->global, program_id_acc) == 0 ) {
      FD_LOG_NOTICE(( "found BPF upgradeable executable program account - program id: %32J", program_id_acc ));

      exec_result = fd_executor_bpf_upgradeable_loader_program_execute_program_instruction(*ctx);

    } else if ( fd_executor_bpf_loader_program_is_executable_program_account(executor->global, program_id_acc) == 0 ) {
      FD_LOG_NOTICE(( "found BPF v2 executable program account - program id: %32J", program_id_acc ));

      exec_result = fd_executor_bpf_loader_program_execute_program_instruction(*ctx);

    } else {
      FD_LOG_WARNING(( "did not find native or BPF executable program account - program id: %32J", program_id_acc ));

      exec_result = FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
  }

  if ( FD_UNLIKELY( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d, custom err: %d, program id: %32J", exec_result, txn_ctx->custom_err, program_id_acc ));
  }

  txn_ctx->instr_stack_sz--;

  /* TODO: sanity before/after checks: total lamports unchanged etc */
  return exec_result;
}

int
fd_execute_txn( fd_executor_t * executor, fd_txn_t * txn_descriptor, fd_rawtxn_b_t const * txn_raw ) {
  fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);

  fd_global_ctx_t * global = executor->global;

  transaction_ctx_t txn_ctx = {
    .global             = executor->global,
    .compute_unit_limit = 200000,
    .compute_unit_price = 0,
    .prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED,
    .txn_descriptor     = txn_descriptor,
    ._txn_raw           = txn_raw,
    .custom_err         = UINT_MAX,
    .instr_stack_sz     = 0,
    .accounts_cnt       = 0,
  };

  fd_executor_setup_accessed_accounts_for_txn( &txn_ctx, txn_raw );
  int compute_budget_status = fd_executor_compute_budget_program_execute_instructions( &txn_ctx, txn_raw );
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
  if( FD_FEATURE_ACTIVE( global, set_exempt_rent_epoch_max ) ) {
    fd_txn_acct_iter_t ctrl;
    for( ulong i=fd_txn_acct_iter_init( txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE, &ctrl );
          i<fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i, &ctrl ) ) {
      if( i==0 ) continue;
      fd_set_exempt_rent_epoch_max( global, &tx_accs[i] );
    }
  }

  fd_instr_t instrs[txn_descriptor->instr_cnt];
  for ( ushort i = 0; i < txn_descriptor->instr_cnt; ++i ) {
    fd_txn_instr_t *  txn_instr = &txn_descriptor->instr[i];
    fd_convert_txn_instr_to_instr( txn_descriptor, txn_raw, txn_instr, txn_ctx.accounts, &instrs[i] );
  }

  int ret = fd_sysvar_instructions_serialize_account( global, instrs, txn_descriptor->instr_cnt );
  if( ret != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_WARNING(( "SYSVAR INSTRS FAILED TO SERIALIZE!" ));
    fd_funk_txn_cancel(global->funk, txn, 0);
    global->funk_txn = parent_txn;
    return -1;
  }

  for ( ushort i = 0; i < txn_descriptor->instr_cnt; ++i ) {
    ret = fd_sysvar_instructions_update_current_instr_idx( global, i );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "SYSVAR INSTRS FAILED TO UPDATE CURRENT INSTR IDX!" ));
      fd_funk_txn_cancel(global->funk, txn, 0);
      global->funk_txn = parent_txn;
      return -1;
    }

    int exec_result = fd_execute_instr( executor, &instrs[i], &txn_ctx );
    if( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) {
      fd_funk_txn_cancel(global->funk, txn, 0);
      global->funk_txn = parent_txn;
      return -1;
    }

    /* TODO: sanity before/after checks: total lamports unchanged etc */
  }

  ret = fd_sysvar_instructions_cleanup_account( global );
  if( ret != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_WARNING(( "SYSVAR INSTRS FAILED TO CLEANUP!" ));
    return -1;
  }

  fd_funk_txn_merge(global->funk, txn, 0);
  global->funk_txn = parent_txn;
  return 0;
}
