#include "fd_executor.h"
#include "fd_acc_mgr.h"
#include "fd_hashes.h"
#include "fd_runtime.h"

#include "../../util/rng/fd_rng.h"
#include "../nanopb/pb_encode.h"
#include "../trace/fd_txntrace.h"
#include "fd_system_ids.h"
#include "program/fd_address_lookup_table_program.h"
#include "program/fd_bpf_deprecated_loader_program.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_bpf_loader_v4_program.h"
#include "program/fd_bpf_upgradeable_loader_program.h"
#include "program/fd_compute_budget_program.h"
#include "program/fd_config_program.h"
#include "program/fd_ed25519_program.h"
#include "program/fd_secp256k1_program.h"
#include "program/fd_stake_program.h"
#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include "program/fd_bpf_upgradeable_loader_program.h"

#include "../../ballet/base58/fd_base58.h"

#include <errno.h>
#include <stdio.h>   /* snprintf(3) */
#include <fcntl.h>   /* openat(2) */
#include <unistd.h>  /* write(3) */
#include <time.h>

/* Look up a native program given it's pubkey key */
execute_instruction_func_t
fd_executor_lookup_native_program( fd_pubkey_t const * pubkey ) {
  /* TODO: replace with proper lookup table */
  if ( !memcmp( pubkey, fd_solana_vote_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_vote_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_system_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_config_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_config_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_stake_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_stake_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_ed25519_sig_verify_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_ed25519_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_keccak_secp_256k_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_secp256k1_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_bpf_upgradeable_loader_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_bpf_loader_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_bpf_loader_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_bpf_loader_deprecated_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_bpf_deprecated_loader_program_execute_instruction;
  } else if ( !memcmp( pubkey, fd_solana_compute_budget_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_executor_compute_budget_program_execute_instruction_nop;
  } else if( !memcmp( pubkey, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_executor_bpf_loader_v4_program_execute_instruction;
  } else if( !memcmp( pubkey, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_executor_address_lookup_table_program_execute_instruction;
  } else {
    return NULL; /* FIXME */
  }
}

int
fd_executor_lookup_program( fd_exec_slot_ctx_t * slot_ctx,
                            fd_pubkey_t const * pubkey ) {
  if( fd_executor_bpf_upgradeable_loader_program_is_executable_program_account( slot_ctx, pubkey )==0 ) {
    return 0;
  }

  return -1;
}

// TODO: handle error codes
void
fd_executor_setup_accessed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx, fd_rawtxn_b_t const * txn_raw, uint * use_sysvar_instructions ) {
  fd_pubkey_t *tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  for( ulong i = 0; i < txn_ctx->txn_descriptor->acct_addr_cnt; i++ ) {
    txn_ctx->accounts[i] = tx_accs[i];
    if ( FD_UNLIKELY(
        *use_sysvar_instructions
        || memcmp(&txn_ctx->accounts[i], fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t))==0
      ) ) {
      *use_sysvar_instructions = 1;
    }
  }
  txn_ctx->accounts_cnt += (uchar) txn_ctx->txn_descriptor->acct_addr_cnt;

  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    fd_txn_acct_addr_lut_t * addr_luts = fd_txn_get_address_tables( txn_ctx->txn_descriptor );
    for (ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++) {
      fd_txn_acct_addr_lut_t * addr_lut = &addr_luts[i];
      fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_raw->raw + addr_lut->addr_off);

      FD_BORROWED_ACCOUNT_DECL(addr_lut_rec);
      int err = fd_acc_mgr_view(txn_ctx->acc_mgr, txn_ctx->funk_txn, (fd_pubkey_t *) addr_lut_acc, addr_lut_rec);
      if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
        // TODO: return txn err code
        FD_LOG_ERR(( "addr lut not found" ));
      }
      FD_LOG_WARNING(( "LUT ACC: idx: %lu, acc: %32J, meta.dlen; %lu", i, addr_lut_acc, addr_lut_rec->const_meta->dlen ));

      fd_address_lookup_table_state_t addr_lookup_table_state;
      fd_bincode_decode_ctx_t decode_ctx = {
        .data = addr_lut_rec->const_data,
        .dataend = &addr_lut_rec->const_data[56], // TODO macro const.
        .valloc  = txn_ctx->valloc,
      };
      if (fd_address_lookup_table_state_decode( &addr_lookup_table_state, &decode_ctx )) {
        FD_LOG_ERR(("fd_address_lookup_table_state_decode failed"));
      }
      if (addr_lookup_table_state.discriminant != fd_address_lookup_table_state_enum_lookup_table) {
        FD_LOG_ERR(("addr lut is uninit"));
      }

      fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&addr_lut_rec->const_data[56];
      uchar * writable_lut_idxs = (uchar *)txn_raw->raw + addr_lut->writable_off;
      for (ulong j = 0; j < addr_lut->writable_cnt; j++) {
        FD_LOG_WARNING(( "LUT ACC WRITABLE: idx: %3lu, acc: %32J, lut_idx: %3lu, acct_idx: %3lu, %32J", i, addr_lut_acc, j, writable_lut_idxs[j], &lookup_addrs[writable_lut_idxs[j]] ));
        txn_ctx->accounts[txn_ctx->accounts_cnt++] = lookup_addrs[writable_lut_idxs[j]];
        if ( FD_UNLIKELY(
            *use_sysvar_instructions
            || memcmp( &lookup_addrs[writable_lut_idxs[j]], fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t))==0
          ) ) {
          *use_sysvar_instructions = 1;
        }
      }
    }

    for (ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++) {
      fd_txn_acct_addr_lut_t * addr_lut = &addr_luts[i];
      fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_raw->raw + addr_lut->addr_off);

      FD_BORROWED_ACCOUNT_DECL(addr_lut_rec);
      int err = fd_acc_mgr_view(txn_ctx->acc_mgr, txn_ctx->funk_txn, (fd_pubkey_t *) addr_lut_acc, addr_lut_rec);
      if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
        // TODO: return txn err code
        FD_LOG_ERR(( "addr lut not found" ));
      }

      fd_address_lookup_table_state_t addr_lookup_table_state;
      fd_bincode_decode_ctx_t decode_ctx = {
        .data = addr_lut_rec->const_data,
        .dataend = &addr_lut_rec->const_data[56], // TODO macro const.
        .valloc  = txn_ctx->valloc,
      };
      if (fd_address_lookup_table_state_decode( &addr_lookup_table_state, &decode_ctx )) {
        FD_LOG_ERR(("fd_address_lookup_table_state_decode failed"));
      }
      if (addr_lookup_table_state.discriminant != fd_address_lookup_table_state_enum_lookup_table) {
        FD_LOG_ERR(("addr lut is uninit"));
      }

      fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&addr_lut_rec->const_data[56];
      uchar * readonly_lut_idxs = (uchar *)txn_raw->raw + addr_lut->readonly_off;
      for (ulong j = 0; j < addr_lut->readonly_cnt; j++) {
        FD_LOG_WARNING(( "LUT ACC READONLY: idx: %3lu, acc: %32J, lut_idx: %3lu, acct_idx: %3lu, %32J", i, addr_lut_acc, j, readonly_lut_idxs[j], &lookup_addrs[readonly_lut_idxs[j]] ));
        txn_ctx->accounts[txn_ctx->accounts_cnt++] = lookup_addrs[readonly_lut_idxs[j]];
        if ( FD_UNLIKELY(
            *use_sysvar_instructions
            || memcmp( &lookup_addrs[readonly_lut_idxs[j]], fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t))==0
          ) ) {
          *use_sysvar_instructions = 1;
        }
      }
    }
  }
}

/* todo rent exempt check */
static void
fd_set_exempt_rent_epoch_max( fd_exec_slot_ctx_t * slot_ctx,
                              void const *         addr ) {

  FD_BORROWED_ACCOUNT_DECL(rec);

  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t const *)addr, rec);
  if( FD_UNLIKELY( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) )
    return;
  FD_TEST( err==FD_ACC_MGR_SUCCESS );

  if( rec->const_meta->info.lamports < fd_rent_exempt_minimum_balance( slot_ctx, rec->const_meta->dlen ) ) return;
  if( rec->const_meta->info.rent_epoch == ULONG_MAX ) return;

  err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t const *)addr, 0, 0, rec);
  FD_TEST( err==FD_ACC_MGR_SUCCESS );

  rec->meta->info.rent_epoch = ULONG_MAX;
}

// loaded account data size defined consists of data encapsulated within accounts pointed to by these pubkeys:
// 1. static and dynamic account keys that are loaded for the message
// 2. owner program which inteprets the opaque data for each instruction
static int 
fd_cap_transaction_accounts_data_size( fd_exec_txn_ctx_t * txn_ctx,
                                       fd_instr_info_t const *  instrs,
                                       ushort              instrs_cnt ) {
  ulong total_accounts_data_size = 0UL;
  for (ulong idx = 0; idx < txn_ctx->accounts_cnt; idx++) {
    fd_borrowed_account_t *b = &txn_ctx->borrowed_accounts[idx];
    ulong program_data_len = (NULL != b->meta) ? b->meta->dlen : (NULL != b->const_meta) ? b->const_meta->dlen : 0UL;
    total_accounts_data_size = fd_ulong_sat_add(total_accounts_data_size, program_data_len);
  }
  for( ushort i = 0; i < instrs_cnt; ++i ) {
    fd_instr_info_t const * instr = &instrs[i];
    
    fd_borrowed_account_t * p = NULL;
    int err = fd_txn_borrowed_account_view( txn_ctx, (fd_pubkey_t const *) &instr->program_id_pubkey, &p );    
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Error in ix borrowed acc view %d", err));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    fd_account_meta_t const * p_meta = p->const_meta ? p->const_meta : p->meta;

    fd_borrowed_account_t * o = NULL;
    err = fd_txn_borrowed_account_view( txn_ctx, (fd_pubkey_t const *) &p_meta->info.owner, &o );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Error in ix borrowed acc view %d", err));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    ulong o_dlen = (NULL != o->meta) ? o->meta->dlen : (NULL != o->const_meta) ? o->const_meta->dlen : 0UL;
    total_accounts_data_size = fd_ulong_sat_add(total_accounts_data_size, o_dlen);
  }

  if ( total_accounts_data_size > txn_ctx->loaded_accounts_data_size_limit ) {
    FD_LOG_WARNING(( "Total loaded accounts data size %lu has exceeded its set limit %lu", total_accounts_data_size, txn_ctx->loaded_accounts_data_size_limit ));
    return FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_SIZE_EXCEEDED;
  };
  
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
fd_executor_collect_fee( fd_exec_slot_ctx_t * slot_ctx,
                         fd_pubkey_t const *  account,
                         ulong                fee ) {

  FD_BORROWED_ACCOUNT_DECL(rec);

  int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, account, 0, 0UL, rec);
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_acc_mgr_modify(%32J) failed (%d-%s)", account->uc, err, fd_acc_mgr_strerror( err ) ));
    // TODO: The fee payer does not seem to exist?!  what now?
    return -1;
  }

  if (fee > rec->meta->info.lamports) {
    // TODO: Not enough lamports to pay for this txn...
    //
    // (Should this be lamps + whatever is required to keep the payer rent exempt?)
    FD_LOG_WARNING(( "Not enough lamps" ));
    return -1;
  }

  FD_LOG_DEBUG(( "fd_execute_txn: global->collected: %ld->%ld (%ld)", slot_ctx->slot_bank.collected_fees, slot_ctx->slot_bank.collected_fees + fee, fee));
  FD_LOG_DEBUG(( "calling set_lamports to charge the fee %lu", fee));

  // TODO: I BELIEVE we charge for the fee BEFORE we create the funk_txn fork
  // since we collect reguardless of the success of the txn execution...
  rec->meta->info.lamports -= fee;
  slot_ctx->slot_bank.collected_fees += fee;

  /* todo rent exempt check */
  if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) )
    rec->meta->info.rent_epoch = ULONG_MAX;
  return 0;
}

int
fd_execute_instr( fd_instr_info_t * instr, fd_exec_txn_ctx_t * txn_ctx ) {
  fd_pubkey_t const * txn_accs = txn_ctx->accounts;

  fd_exec_instr_ctx_t * ctx = &txn_ctx->instr_stack[txn_ctx->instr_stack_sz++];
  ctx->instr = instr;
  ctx->txn_ctx = txn_ctx;
  ctx->epoch_ctx = txn_ctx->epoch_ctx;
  ctx->slot_ctx = txn_ctx->slot_ctx;
  ctx->valloc = txn_ctx->valloc;
  ctx->acc_mgr = txn_ctx->acc_mgr;
  ctx->funk_txn = txn_ctx->funk_txn;

  // defense in depth
  if (instr->program_id >= txn_ctx->txn_descriptor->acct_addr_cnt + txn_ctx->txn_descriptor->addr_table_adtl_cnt) {
    FD_LOG_WARNING(( "INVALID PROGRAM ID, RUNTIME BUG!!!" ));
    int exec_result = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    txn_ctx->instr_stack_sz--;

    //FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d", exec_result ));
    return exec_result;
  }

  /* TODO: allow instructions to be failed, and the transaction to be reverted */
  fd_pubkey_t const * program_id_acc = &txn_accs[instr->program_id];

  execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( program_id_acc );

  int exec_result = FD_EXECUTOR_INSTR_SUCCESS;
  if (exec_instr_func != NULL) {
    exec_result = exec_instr_func( *ctx );

  } else {
    if (fd_executor_lookup_program( ctx->slot_ctx, program_id_acc ) == 0 ) {
      FD_LOG_NOTICE(( "found BPF upgradeable executable program account - program id: %32J", program_id_acc ));

      exec_result = fd_executor_bpf_upgradeable_loader_program_execute_program_instruction(*ctx);

    } else if ( fd_executor_bpf_loader_program_is_executable_program_account( ctx->slot_ctx, program_id_acc ) == 0 ) {
      FD_LOG_NOTICE(( "found BPF v2 executable program account - program id: %32J", program_id_acc ));

      exec_result = fd_executor_bpf_loader_program_execute_program_instruction(*ctx);

    } else {
      FD_LOG_WARNING(( "did not find native or BPF executable program account - program id: %32J", program_id_acc ));

      exec_result = FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }
  }

//  if ( FD_UNLIKELY( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
//    FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d, custom err: %d, program id: %32J", exec_result, txn_ctx->custom_err, program_id_acc ));
//  }

  txn_ctx->instr_stack_sz--;

  /* TODO: sanity before/after checks: total lamports unchanged etc */
  return exec_result;
}

/* fd_executor_dump_txntrace creates a new file in the trace dir
   containing the given binary blob. */

static void
fd_executor_dump_txntrace( fd_exec_slot_ctx_t *         slot_ctx,
                           fd_ed25519_sig_t const *     sig,
                           fd_soltrace_TxnTrace const * trace ) {

  if( FD_UNLIKELY( !fd_scratch_push_is_safe() ) ) return;
  FD_SCRATCH_SCOPED_FRAME;
  if( FD_UNLIKELY( !fd_scratch_prepare_is_safe( 1UL ) ) ) return;

  /* Serialize to open-ended scratch frame */
  ulong   data_bufsz = fd_scratch_free();
  uchar * data       = fd_scratch_prepare( 1UL );
  pb_ostream_t ostream = pb_ostream_from_buffer( data, data_bufsz );
  if( FD_UNLIKELY( !pb_encode( &ostream, fd_soltrace_TxnTrace_fields, trace ) ) ) {
    FD_LOG_ERR(( "pb_encode of trace %p failed (%lu bufsz, %lu written): %s",
                     (void *)trace, data_bufsz, ostream.bytes_written, PB_GET_ERROR( &ostream ) ));
    fd_scratch_cancel();
    return;
  }
  ulong data_sz = ostream.bytes_written;
  fd_scratch_publish( data+data_sz );

  /* Formulate file name */
  char filename[ 128UL ];
  /* 118 (20+1+88+9) chars + null terminator */
  snprintf( filename, sizeof(filename), "%lu-%64J.txntrace",
            slot_ctx->slot_bank.slot, sig );

  /* Create file */
  int dump_fd = openat( slot_ctx->trace_dirfd, filename, O_WRONLY|O_CREAT|O_TRUNC, 0666 );
  if( FD_UNLIKELY( dump_fd<0 ) ) {
    FD_LOG_WARNING(( "openat(%d, %s) failed (%d-%s)",
                     slot_ctx->trace_dirfd, filename, errno, fd_io_strerror( errno ) ));
    return;
  }

  /* Write file */
  long nbytes = write( dump_fd, data, data_sz );
  if( FD_UNLIKELY( nbytes!=(long)data_sz ) ) {
    FD_LOG_WARNING(( "write to %s failed (%d-%s)",
                     filename, errno, fd_io_strerror( errno ) ));
    close( dump_fd );
    unlinkat( slot_ctx->trace_dirfd, filename, 0 );
    return;
  }
  close( dump_fd );
}

void
fd_executor_setup_borrowed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  ulong j = 0;
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    fd_pubkey_t * acc = &txn_ctx->accounts[i];
    fd_borrowed_account_t * borrowed_account = fd_borrowed_account_init( &txn_ctx->borrowed_accounts[i] );
    if( fd_txn_account_is_writable_idx( txn_ctx->txn_descriptor, (int)i ) ) {
      int err = fd_acc_mgr_modify( txn_ctx->acc_mgr, txn_ctx->funk_txn, acc, 1, 0UL, borrowed_account);

      if( FD_UNLIKELY( err ) ) {
      //   FD_LOG_WARNING(( "fd_acc_mgr_modify(%32J) failed (%d-%s)", acc->uc, err, fd_acc_mgr_strerror( err ) ));
      }
    } else {
      int err = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, acc, borrowed_account );

      if( FD_UNLIKELY( err ) ) {
      //   FD_LOG_WARNING(( "fd_acc_mgr_view(%32J) failed (%d-%s)", acc->uc, err, fd_acc_mgr_strerror( err ) ));
      }
    }
    fd_account_meta_t const * meta = borrowed_account->const_meta ? borrowed_account->const_meta : borrowed_account->meta;
    if (meta == NULL) {
      continue;
    }
    if (memcmp(meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t)) == 0) {
      fd_bpf_upgradeable_loader_state_t program_loader_state;
      int err = 0;
      if (FD_UNLIKELY(!read_bpf_upgradeable_loader_state_for_program( txn_ctx, (uchar) i, &program_loader_state, &err )))
        continue;

      fd_bincode_destroy_ctx_t ctx_d = { .valloc = txn_ctx->valloc };

      if( !fd_bpf_upgradeable_loader_state_is_program( &program_loader_state ) ) {
        fd_bpf_upgradeable_loader_state_destroy( &program_loader_state, &ctx_d );
        continue;
      }

      fd_pubkey_t * programdata_acc = &program_loader_state.inner.program.programdata_address;
      fd_borrowed_account_t * executable_account = fd_borrowed_account_init( &txn_ctx->executable_accounts[j] );
      fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, programdata_acc, executable_account);
      j++;
    }
  }
  txn_ctx->executable_cnt = j;
}

static void
fd_executor_retrace( fd_exec_slot_ctx_t *          slot_ctx FD_PARAM_UNUSED,
                     fd_soltrace_TxnInput const * trace_pre,
                     fd_soltrace_TxnDiff  const * trace_post0,
                     fd_wksp_t *                  local_wksp ) {

  FD_SCRATCH_SCOPED_FRAME;

  fd_soltrace_TxnDiff  _trace_post1[1];
  fd_soltrace_TxnDiff * trace_post1 =
      fd_txntrace_replay( _trace_post1, trace_pre, local_wksp );

  if( FD_UNLIKELY( !trace_post1 ) )
    FD_LOG_ERR(( "fd_txntrace_replay failed" ));

  if( FD_UNLIKELY( !fd_txntrace_diff( trace_post0, trace_post1 ) ) )
    FD_LOG_ERR(( "fd_txntrace_replay returned incorrect trace:\n%s",
                 fd_txntrace_diff_cstr() ));
}


int
fd_execute_txn( fd_exec_slot_ctx_t *  slot_ctx,
                fd_txn_t const *      txn_descriptor,
                fd_rawtxn_b_t const * txn_raw ) {
  FD_SCRATCH_SCOPED_FRAME;

  fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);

  /* Trace transaction input */
  fd_soltrace_TxnInput  _trace_pre[1];
  fd_soltrace_TxnInput * trace_pre = NULL;
  if( FD_UNLIKELY( slot_ctx->trace_mode ) ) {
    trace_pre = fd_txntrace_capture_pre( _trace_pre, slot_ctx, txn_descriptor, txn_raw->raw );
    if( FD_UNLIKELY( !trace_pre ) )
      FD_LOG_WARNING(( "fd_txntrace_capture_pre failed (out of scratch memory?)" ));
  }

  fd_transaction_return_data_t return_data = {0};
  return_data.data = (uchar*)fd_valloc_malloc(slot_ctx->valloc, 1, 1024);

  fd_exec_txn_ctx_t txn_ctx = {
    .epoch_ctx          = slot_ctx->epoch_ctx,
    .slot_ctx           = slot_ctx,
    .funk_txn           = slot_ctx->funk_txn,
    .acc_mgr            = slot_ctx->acc_mgr,
    .valloc             = slot_ctx->valloc,
    .compute_unit_limit = 200000,
    .compute_unit_price = 0,
    .compute_meter      = 200000,
    .prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED,
    .txn_descriptor     = txn_descriptor,
    ._txn_raw           = txn_raw,
    .custom_err         = UINT_MAX,
    .instr_stack_sz     = 0,
    .accounts_cnt       = 0,
    .executable_cnt     = 0,
    .return_data        = return_data,
  };

  uint use_sysvar_instructions = 0;
  fd_executor_setup_accessed_accounts_for_txn( &txn_ctx, txn_raw, &use_sysvar_instructions );
  int compute_budget_status = fd_executor_compute_budget_program_execute_instructions( &txn_ctx, txn_raw );
  (void)compute_budget_status;

  ulong fee = fd_runtime_calculate_fee( &txn_ctx, txn_descriptor, txn_raw );
  if( fd_executor_collect_fee( slot_ctx, &tx_accs[0], fee ) ) {
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

  fd_funk_txn_t* parent_txn = slot_ctx->funk_txn;
  fd_funk_txn_xid_t xid;
  xid.ul[0] = fd_rng_ulong( slot_ctx->rng );
  xid.ul[1] = fd_rng_ulong( slot_ctx->rng );
  xid.ul[2] = fd_rng_ulong( slot_ctx->rng );
  xid.ul[3] = fd_rng_ulong( slot_ctx->rng );
  fd_funk_txn_t * txn = fd_funk_txn_prepare( slot_ctx->acc_mgr->funk, parent_txn, &xid, 1 );
  // TODO: bad for multi-threading...
  txn_ctx.funk_txn = txn;

  fd_executor_setup_borrowed_accounts_for_txn( &txn_ctx );
  /* Update rent exempt on writable accounts if feature activated
    TODO this should probably not run on executable accounts
        Also iterate over LUT accounts */
  if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
    fd_txn_acct_iter_t ctrl;
    for( ulong i=fd_txn_acct_iter_init( txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE, &ctrl );
          i<fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i, &ctrl ) ) {
      if( i==0 ) continue;
      fd_set_exempt_rent_epoch_max( slot_ctx, &tx_accs[i] );
    }
  }

  fd_instr_info_t instrs[txn_descriptor->instr_cnt];
  for ( ushort i = 0; i < txn_descriptor->instr_cnt; ++i ) {
    fd_txn_instr_t const * txn_instr = &txn_descriptor->instr[i];
    fd_convert_txn_instr_to_instr( txn_descriptor, txn_raw, txn_instr, txn_ctx.accounts, txn_ctx.borrowed_accounts, &instrs[i] );
  }

  int ret = 0L;
  if ( FD_FEATURE_ACTIVE( slot_ctx, cap_transaction_accounts_data_size ) ) {    
    int ret = fd_cap_transaction_accounts_data_size( &txn_ctx, instrs, txn_descriptor->instr_cnt );  
    if ( ret != FD_EXECUTOR_INSTR_SUCCESS ) {
      return -1;
    }    
  }  
  if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
    fd_sysvar_instructions_serialize_account( &txn_ctx, instrs, txn_descriptor->instr_cnt );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "SYSVAR INSTRS FAILED TO SERIALIZE!" ));
      fd_funk_txn_cancel(txn_ctx.acc_mgr->funk, txn, 0);
      txn_ctx.funk_txn = parent_txn;
      return -1;
    }
  }
  uint unknown_accounts[128];
  for( ulong i = 0; i < txn_ctx.accounts_cnt; i++ ) {
    unknown_accounts[i] = 0;
    if (fd_txn_is_writable(txn_ctx.txn_descriptor, (int)i)) {
      FD_BORROWED_ACCOUNT_DECL(writable_new);
      int err = fd_acc_mgr_view(txn_ctx.acc_mgr, txn_ctx.funk_txn, &txn_ctx.accounts[i], writable_new);
      if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
        unknown_accounts[i] = 1;
      }
    }
  }
  for ( ushort i = 0; i < txn_descriptor->instr_cnt; ++i ) {
    if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
      ret = fd_sysvar_instructions_update_current_instr_idx( &txn_ctx, i );
      if( ret != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_WARNING(( "SYSVAR INSTRS FAILED TO UPDATE CURRENT INSTR IDX!" ));
        fd_funk_txn_cancel(txn_ctx.acc_mgr->funk, txn, 0);
        txn_ctx.funk_txn = parent_txn;
        return -1;
      }
    }

    int exec_result = fd_execute_instr( &instrs[i], &txn_ctx );

    if( exec_result == FD_EXECUTOR_INSTR_SUCCESS )
      exec_result = fd_executor_txn_check( slot_ctx, &txn_ctx );

    if( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) {
      FD_LOG_DEBUG(( "fd_execute_instr failed (%d)", exec_result ));
      fd_funk_txn_cancel(txn_ctx.acc_mgr->funk, txn, 0);
      txn_ctx.funk_txn = parent_txn;
      return -1;
    }
  }

  for( ulong i = 0; i < txn_ctx.accounts_cnt; i++ ) {
    if (unknown_accounts[i]) {
      FD_BORROWED_ACCOUNT_DECL(writable_new);
      int err = fd_acc_mgr_modify(txn_ctx.acc_mgr, txn_ctx.funk_txn, &txn_ctx.accounts[i], 1, 0, writable_new);
      if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_ERR(( "account mgr modify failed for %32J", txn_ctx.accounts[i].uc ));
      }
      writable_new->meta->slot = txn_ctx.slot_ctx->slot_bank.slot;
      memset(writable_new->meta->hash, 0xFF, sizeof(fd_hash_t));
    }
  }

  fd_valloc_free(txn_ctx.valloc, txn_ctx.return_data.data);

  if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
    ret = fd_sysvar_instructions_cleanup_account( &txn_ctx );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "SYSVAR INSTRS FAILED TO CLEANUP!" ));
      return -1;
    }
  }

  /* Export trace to Protobuf file */
  if( FD_UNLIKELY( trace_pre ) ) {
    fd_soltrace_TxnDiff  _trace_post[1];
    fd_soltrace_TxnDiff * trace_post = fd_txntrace_capture_post( _trace_post, slot_ctx, trace_pre );
    if( trace_post ) {
      if( slot_ctx->trace_mode & FD_RUNTIME_TRACE_SAVE ) {
        fd_soltrace_TxnTrace trace = {
          .input = trace_pre,
          .diff  = trace_post
        };
        fd_ed25519_sig_t const * sig0 = &fd_txn_get_signatures( txn_descriptor, txn_raw->raw )[0];
        fd_executor_dump_txntrace( slot_ctx, sig0, &trace );
      }
      if( slot_ctx->trace_mode & FD_RUNTIME_TRACE_REPLAY ) {
        fd_executor_retrace( slot_ctx, trace_pre, trace_post, NULL /* FIXME: set this to a reasonable local_wksp */);
      }
    }
  }

  fd_funk_txn_merge(slot_ctx->acc_mgr->funk, txn, 0);
  slot_ctx->funk_txn = parent_txn;
  return 0;
}

int fd_executor_txn_check( fd_exec_slot_ctx_t * slot_ctx,  fd_exec_txn_ctx_t *txn ) {
  // We really need to cache this...
  fd_rent_t rent;
  fd_rent_new( &rent );
  fd_sysvar_rent_read( slot_ctx, &rent );

  ulong ending_lamports = 0;
  ulong ending_dlen = 0;
  ulong starting_lamports = 0;
  ulong starting_dlen = 0;

  for (ulong idx = 0; idx < txn->accounts_cnt; idx++) {
    fd_borrowed_account_t *b = &txn->borrowed_accounts[idx];
    if (NULL != b->meta) {
      ending_lamports += b->meta->info.lamports;
      ending_dlen += b->meta->dlen;

      // Lets prevent creating non-rent-exempt accounts...
      uchar after_exempt = fd_rent_exempt_minimum_balance2( &rent, b->meta->dlen) <= b->meta->info.lamports;

      if (!after_exempt) {
        uchar before_exempt = (b->starting_dlen != ULONG_MAX) ?
          (fd_rent_exempt_minimum_balance2( &rent, b->starting_dlen) <= b->starting_lamports) : 1;
        if (before_exempt && (b->meta->dlen != b->starting_dlen) && b->meta->dlen != 0) {
          FD_LOG_WARNING(("Rent exempt error for %32J Curr len %lu Starting len %lu Curr lamports %lu Starting lamports %lu Curr exempt %lu Starting exempt %lu", b->pubkey->uc, b->meta->dlen, b->starting_dlen, b->meta->info.lamports, b->starting_lamports, fd_rent_exempt_minimum_balance2( &rent, b->meta->dlen), fd_rent_exempt_minimum_balance2( &rent, b->starting_dlen)));
          return FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT;
        }
      }

      if (b->starting_lamports != ULONG_MAX)
        starting_lamports += b->starting_lamports;
      if (b->starting_dlen != ULONG_MAX)
        starting_dlen += b->starting_dlen;
    } else if (NULL != b->const_meta) {
      // Should these just kill the client?  They are impossible...
      if (b->starting_lamports != b->const_meta->info.lamports)
        return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
      if (b->starting_dlen != b->const_meta->dlen)
        return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
    }
  }

  // Should these just kill the client?  They are impossible yet solana just throws an error
  if (ending_lamports != starting_lamports)
    return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;

#if 0
  // cap_accounts_data_allocations_per_transaction
  //    TODO: I am unsure if this is the correct check...
  if (((long)ending_dlen - (long)starting_dlen) > MAX_PERMITTED_DATA_INCREASE)
    return FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_SIZE_EXCEEDED;
#endif

  /* TODO unused variables */
  (void)ending_dlen; (void)starting_dlen;

  return FD_EXECUTOR_INSTR_SUCCESS;
}
