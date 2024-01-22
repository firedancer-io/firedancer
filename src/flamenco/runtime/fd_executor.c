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
#include "program/fd_zk_token_proof_program.h"

#include "../vm/fd_vm_context.h"

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
  } else if( !memcmp( pubkey, fd_solana_zk_token_proof_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_executor_zk_token_proof_program_execute_instruction;
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

/* Returns 1 if the sysvar instruction is used, 0 otherwise */
uint
fd_executor_txn_uses_sysvar_instructions( fd_exec_txn_ctx_t const * txn_ctx ) {
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    if( FD_UNLIKELY( memcmp( txn_ctx->accounts[i].key, fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      return 1;
    }
  }

  return 0;
}

// TODO: handle error codes
void
fd_executor_setup_accessed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  // Set up accounts in the transaction body
  for( ulong i = 0; i < txn_ctx->txn_descriptor->acct_addr_cnt; i++ ) {
    txn_ctx->accounts[i] = tx_accs[i];
  }
  txn_ctx->accounts_cnt += (uchar) txn_ctx->txn_descriptor->acct_addr_cnt;

  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    fd_pubkey_t readonly_lut_accs[128];
    ulong readonly_lut_accs_cnt = 0;

    // Set up accounts in the account look up tables.
    fd_txn_acct_addr_lut_t * addr_luts = fd_txn_get_address_tables( txn_ctx->txn_descriptor );
    for( ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++ ) {
      fd_txn_acct_addr_lut_t * addr_lut = &addr_luts[i];
      fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + addr_lut->addr_off);

      FD_BORROWED_ACCOUNT_DECL(addr_lut_rec);
      int err = fd_acc_mgr_view(txn_ctx->slot_ctx->acc_mgr, txn_ctx->slot_ctx->funk_txn, (fd_pubkey_t *) addr_lut_acc, addr_lut_rec);
      if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_ERR(( "addr lut not found" )); // TODO: return txn err code
      }

      fd_address_lookup_table_state_t addr_lookup_table_state;
      fd_bincode_decode_ctx_t decode_ctx = {
        .data = addr_lut_rec->const_data,
        .dataend = &addr_lut_rec->const_data[56], // TODO macro const.
        .valloc  = txn_ctx->valloc,
      };
      if( fd_address_lookup_table_state_decode( &addr_lookup_table_state, &decode_ctx ) ) {
        FD_LOG_ERR(("fd_address_lookup_table_state_decode failed"));
      }
      if( addr_lookup_table_state.discriminant != fd_address_lookup_table_state_enum_lookup_table ) {
        FD_LOG_ERR(("addr lut is uninit"));
      }

      fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&addr_lut_rec->const_data[56];

      uchar * writable_lut_idxs = (uchar *)txn_ctx->_txn_raw->raw + addr_lut->writable_off;
      for( ulong j = 0; j < addr_lut->writable_cnt; j++ ) {
        txn_ctx->accounts[txn_ctx->accounts_cnt++] = lookup_addrs[writable_lut_idxs[j]];
      }

      uchar * readonly_lut_idxs = (uchar *)txn_ctx->_txn_raw->raw + addr_lut->readonly_off;
      for( ulong j = 0; j < addr_lut->readonly_cnt; j++ ) {
        readonly_lut_accs[readonly_lut_accs_cnt++] = lookup_addrs[readonly_lut_idxs[j]];
      }
    }

    fd_memcpy( &txn_ctx->accounts[txn_ctx->accounts_cnt], readonly_lut_accs, readonly_lut_accs_cnt * sizeof(fd_pubkey_t) );
    txn_ctx->accounts_cnt += readonly_lut_accs_cnt;
  }
}

void
fd_set_exempt_rent_epoch_max( fd_exec_txn_ctx_t * txn_ctx,
                              void const *        addr ) {
  fd_borrowed_account_t * rec = NULL;
  int err = fd_txn_borrowed_account_view( txn_ctx, (fd_pubkey_t const *)addr, &rec);
  if( FD_UNLIKELY( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) )
    return;
  FD_TEST( err==FD_ACC_MGR_SUCCESS );

  if( fd_pubkey_is_sysvar_id( rec->pubkey ) ) {
    return;
  }

  if( rec->const_meta->info.lamports < fd_rent_exempt_minimum_balance2( &txn_ctx->slot_ctx->epoch_ctx->epoch_bank.rent,rec->const_meta->dlen ) )
    return;
  if( rec->const_meta->info.rent_epoch == ULONG_MAX )
    return;

  err = fd_txn_borrowed_account_modify( txn_ctx, (fd_pubkey_t const *)addr, 0, &rec);
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
  for( ulong idx = 0; idx < txn_ctx->accounts_cnt; idx++ ) {
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

    total_accounts_data_size = fd_ulong_sat_add(total_accounts_data_size, p->starting_owner_dlen);
  }

  if (0 == txn_ctx->loaded_accounts_data_size_limit) {
    txn_ctx->custom_err = 33;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if ( total_accounts_data_size > txn_ctx->loaded_accounts_data_size_limit ) {
    FD_LOG_WARNING(( "Total loaded accounts data size %lu has exceeded its set limit %lu", total_accounts_data_size, txn_ctx->loaded_accounts_data_size_limit ));
    return FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_SIZE_EXCEEDED;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_executor_collect_fee( fd_exec_slot_ctx_t * slot_ctx,
                         fd_borrowed_account_t const * rec,
                         ulong                fee ) {

  if (fee > rec->meta->info.lamports) {
    // TODO: Not enough lamports to pay for this txn...
    //
    // (Should this be lamps + whatever is required to keep the payer rent exempt?)
    FD_LOG_WARNING(( "Not enough lamps" ));
    return -1;
  }

  // FD_LOG_DEBUG(( "fd_execute_txn: global->collected: %ld->%ld (%ld)", slot_ctx->slot_bank.collected_fees, slot_ctx->slot_bank.collected_fees + fee, fee));
  // FD_LOG_DEBUG(( "calling set_lamports to charge the fee %lu", fee));

  if( FD_FEATURE_ACTIVE( slot_ctx, checked_arithmetic_in_fee_validation ) ) {
    ulong x;
    bool cf = __builtin_usubl_overflow( rec->meta->info.lamports, fee, &x );
    if (cf) {
      // Sature_sub failure
      FD_LOG_WARNING(( "Not enough lamps" ));
      return -1;
    }
    rec->meta->info.lamports = x;
  } else {
    rec->meta->info.lamports -= fee;
  }

  if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
    if( FD_LIKELY( rec->const_meta->info.lamports >= fd_rent_exempt_minimum_balance2( &slot_ctx->epoch_ctx->epoch_bank.rent,rec->const_meta->dlen ) ) ) {
      if( !fd_pubkey_is_sysvar_id( rec->pubkey ) ) {
        rec->meta->info.rent_epoch = ULONG_MAX;
      }
    }
  }

  return 0;
}

int
fd_execute_instr( fd_instr_info_t * instr, fd_exec_txn_ctx_t * txn_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    ulong max_num_instructions = FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, limit_max_instruction_trace_length ) ? 64 : ULONG_MAX;
    if (txn_ctx->num_instructions >= max_num_instructions ) {
      return -1;
    }
    txn_ctx->num_instructions++;
    fd_pubkey_t const * txn_accs = txn_ctx->accounts;
    ulong starting_lamports = fd_instr_info_sum_account_lamports( instr );
    instr->starting_lamports = starting_lamports;

    fd_exec_instr_ctx_t * ctx = &txn_ctx->instr_stack[txn_ctx->instr_stack_sz++];
    ctx->instr = instr;
    ctx->txn_ctx = txn_ctx;
    ctx->epoch_ctx = txn_ctx->epoch_ctx;
    ctx->slot_ctx = txn_ctx->slot_ctx;
    ctx->valloc = fd_scratch_virtual();
    ctx->acc_mgr = txn_ctx->acc_mgr;
    ctx->funk_txn = txn_ctx->funk_txn;

    // defense in depth
    if (instr->program_id >= txn_ctx->txn_descriptor->acct_addr_cnt + txn_ctx->txn_descriptor->addr_table_adtl_cnt) {
      FD_LOG_WARNING(( "INVALID PROGRAM ID, RUNTIME BUG!!!" ));
      int exec_result = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      txn_ctx->instr_stack_sz--;

      FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d", exec_result ));
      return exec_result;
    }

    /* TODO: allow instructions to be failed, and the transaction to be reverted */
    fd_pubkey_t const * program_id_acc = &txn_accs[instr->program_id];
    execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( program_id_acc );

    fd_exec_txn_ctx_reset_return_data( txn_ctx );
    int exec_result = FD_EXECUTOR_INSTR_SUCCESS;
    if (exec_instr_func != NULL) {
      exec_result = exec_instr_func( *ctx );

    } else {
      if (fd_executor_lookup_program( ctx->slot_ctx, program_id_acc ) == 0 ) {
        // FD_LOG_WARNING(( "found BPF upgradeable executable program account - program id: %32J", program_id_acc ));

        exec_result = fd_executor_bpf_upgradeable_loader_program_execute_program_instruction(*ctx);

      } else if ( fd_executor_bpf_loader_program_is_executable_program_account( ctx->slot_ctx, program_id_acc ) == 0 ) {
        // FD_LOG_WARNING(( "found BPF v2 executable program account - program id: %32J", program_id_acc ));

        exec_result = fd_executor_bpf_loader_program_execute_program_instruction(*ctx);

      } else {
        // FD_LOG_DEBUG(( "did not find native or BPF executable program account - program id: %32J", program_id_acc ));

        exec_result = FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
      }
    }

    ulong ending_lamports = fd_instr_info_sum_account_lamports( instr );
    // FD_LOG_WARNING(("check lamports %lu %lu %lu", starting_lamports, instr->starting_lamports, ending_lamports ));

    if( starting_lamports != ending_lamports ) {
      // FD_LOG_WARNING(("starting lamports mismatched %lu %lu %lu", starting_lamports, instr->starting_lamports, ending_lamports ));
      exec_result = FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
    }

  //  if ( FD_UNLIKELY( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
  //    FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d, custom err: %d, program id: %32J", exec_result, txn_ctx->custom_err, program_id_acc ));
  //  } else {
  //    FD_LOG_WARNING(( "instruction executed successfully: error code %d, custom err: %d, program id: %32J", exec_result, txn_ctx->custom_err, program_id_acc ));
  //  }

    txn_ctx->instr_stack_sz--;

    /* TODO: sanity before/after checks: total lamports unchanged etc */
    return exec_result;
  } FD_SCRATCH_SCOPE_END;
}

/* fd_executor_dump_txntrace creates a new file in the trace dir
   containing the given binary blob. */

static void FD_FN_UNUSED
fd_executor_dump_txntrace( fd_exec_slot_ctx_t *         slot_ctx,
                           fd_capture_ctx_t *           capture_ctx,
                           fd_ed25519_sig_t const *     sig,
                           fd_soltrace_TxnTrace const * trace ) {

  if( FD_UNLIKELY( !fd_scratch_push_is_safe() ) ) return;
  FD_SCRATCH_SCOPE_BEGIN {
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
    int dump_fd = openat( capture_ctx->trace_dirfd, filename, O_WRONLY|O_CREAT|O_TRUNC, 0666 );
    if( FD_UNLIKELY( dump_fd<0 ) ) {
      FD_LOG_WARNING(( "openat(%d, %s) failed (%d-%s)",
                      capture_ctx->trace_dirfd, filename, errno, fd_io_strerror( errno ) ));
      return;
    }

    /* Write file */
    long nbytes = write( dump_fd, data, data_sz );
    if( FD_UNLIKELY( nbytes!=(long)data_sz ) ) {
      FD_LOG_WARNING(( "write to %s failed (%d-%s)",
          filename, errno, fd_io_strerror( errno ) ));
      close( dump_fd );
      unlinkat( capture_ctx->trace_dirfd, filename, 0 );
      return;
    }
    close( dump_fd );
  } FD_SCRATCH_SCOPE_END;
}

void
fd_executor_setup_borrowed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  uint bpf_upgradeable_in_txn = 0;
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    fd_pubkey_t * acc = &txn_ctx->accounts[i];
    if ( memcmp( acc->uc, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) {
      bpf_upgradeable_in_txn = 1;
      break;
    }
  }

  ulong j = 0;
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    fd_pubkey_t * acc = &txn_ctx->accounts[i];
    fd_borrowed_account_t * borrowed_account = fd_borrowed_account_init( &txn_ctx->borrowed_accounts[i] );
    int err = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, acc, borrowed_account );

    if( FD_UNLIKELY( err ) ) {
      // FD_LOG_WARNING(( "fd_acc_mgr_view(%32J) failed (%d-%s)", acc->uc, err, fd_acc_mgr_strerror( err ) ));
    }

    uint is_executable = borrowed_account->const_meta != NULL && borrowed_account->const_meta->info.executable;
    if( fd_txn_account_is_writable_idx( txn_ctx->txn_descriptor, txn_ctx->accounts, (int)i ) ) {
      if ( is_executable ) {
        if ( bpf_upgradeable_in_txn && memcmp( borrowed_account->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t)) == 0 ) {
          void * borrowed_account_data = fd_valloc_malloc( txn_ctx->valloc, 8UL, fd_borrowed_account_raw_size( borrowed_account ) );
          fd_borrowed_account_make_modifiable( borrowed_account, borrowed_account_data );
        }
      } else {
        void * borrowed_account_data = fd_valloc_malloc( txn_ctx->valloc, 8UL, fd_borrowed_account_raw_size( borrowed_account ) );
        fd_borrowed_account_make_modifiable( borrowed_account, borrowed_account_data );
      }
    }

    fd_account_meta_t const * meta = borrowed_account->const_meta ? borrowed_account->const_meta : borrowed_account->meta;
    if (meta == NULL) {
      continue;
    }

    if( meta->info.executable ) {
      FD_BORROWED_ACCOUNT_DECL(owner_borrowed_account);
      int err = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, (fd_pubkey_t *)meta->info.owner, owner_borrowed_account );
      if( FD_UNLIKELY( err ) ) {
        borrowed_account->starting_owner_dlen = 0;
      } else {
        borrowed_account->starting_owner_dlen = owner_borrowed_account->const_meta->dlen;
      }
    }

    if( FD_UNLIKELY( memcmp( meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      fd_bpf_upgradeable_loader_state_t program_loader_state;
      int err = 0;
      if( FD_UNLIKELY( !read_bpf_upgradeable_loader_state_for_program( txn_ctx, (uchar) i, &program_loader_state, &err ) ) ) {
        continue;
      }
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

static void FD_FN_UNUSED
fd_executor_retrace( fd_exec_slot_ctx_t *         slot_ctx FD_PARAM_UNUSED,
                     fd_soltrace_TxnInput const * trace_pre,
                     fd_soltrace_TxnDiff  const * trace_post0,
                     fd_wksp_t *                  local_wksp ) {

  FD_SCRATCH_SCOPE_BEGIN {
    fd_soltrace_TxnDiff  _trace_post1[1];
    fd_soltrace_TxnDiff * trace_post1 =
      fd_txntrace_replay( _trace_post1, trace_pre, local_wksp );

    if( FD_UNLIKELY( !trace_post1 ) )
      FD_LOG_ERR(( "fd_txntrace_replay failed" ));

    if( FD_UNLIKELY( !fd_txntrace_diff( trace_post0, trace_post1 ) ) )
      FD_LOG_ERR(( "fd_txntrace_replay returned incorrect trace:\n%s",
          fd_txntrace_diff_cstr() ));
  } FD_SCRATCH_SCOPE_END;
}

/* Stuff to be done before multithreading can begin */
int
fd_execute_txn_prepare_phase1( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx, 
                               fd_txn_t const * txn_descriptor,
                               fd_rawtxn_b_t const * txn_raw ) {
  fd_exec_txn_ctx_new( txn_ctx );
  fd_exec_txn_ctx_from_exec_slot_ctx( slot_ctx, txn_ctx );
  fd_exec_txn_ctx_setup( txn_ctx, txn_descriptor, txn_raw );

  fd_executor_setup_accessed_accounts_for_txn( txn_ctx );

  int compute_budget_status = fd_executor_compute_budget_program_execute_instructions( txn_ctx, txn_ctx->_txn_raw );
  if( compute_budget_status != 0 ) {
    return -1;
  }

  return 0;
}

int
fd_execute_txn_prepare_phase2( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx ) {

  fd_pubkey_t * tx_accs = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  fd_pubkey_t const * fee_payer_acc = &tx_accs[0];
  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, fee_payer_acc, rec );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_acc_mgr_view(%32J) failed (%d-%s)", fee_payer_acc->uc, err, fd_acc_mgr_strerror( err ) ));
    // TODO: The fee payer does not seem to exist?!  what now?
    return -1;
  }
  void * rec_data = fd_valloc_malloc( slot_ctx->valloc, 8UL, fd_borrowed_account_raw_size( rec ) );
  fd_borrowed_account_make_modifiable( rec, rec_data );

  ulong fee = fd_runtime_calculate_fee( txn_ctx, txn_ctx->txn_descriptor, txn_ctx->_txn_raw );
  if( fd_executor_collect_fee( slot_ctx, rec, fee ) ) {
    return -1;
  }
  slot_ctx->slot_bank.collected_fees += fee;

  err = fd_acc_mgr_save( slot_ctx->acc_mgr, slot_ctx->funk_txn, slot_ctx->valloc, rec );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_acc_mgr_save(%32J) failed (%d-%s)", fee_payer_acc->uc, err, fd_acc_mgr_strerror( err ) ));
    // TODO: The fee payer does not seem to exist?!  what now?
    return -1;
  }

  return 0;
}

int
fd_execute_txn_prepare_phase3( fd_exec_slot_ctx_t * slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx ) {
  fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
  // fd_funk_txn_xid_t xid;
  // fd_ed25519_sig_t const * sig0 = &fd_txn_get_signatures( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw )[0];

  // fd_memcpy( xid.uc, sig0, sizeof( fd_funk_txn_xid_t ) );
  // fd_funk_txn_t * txn = fd_funk_txn_prepare( slot_ctx->acc_mgr->funk, parent_txn, &xid, 1 );
  // txn_ctx->funk_txn = txn;
  txn_ctx->funk_txn = parent_txn;

  return 0;
}

int
fd_execute_txn_prepare_phase4( fd_exec_slot_ctx_t * slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx ) {
  fd_executor_setup_borrowed_accounts_for_txn( txn_ctx );
  /* Update rent exempt on writable accounts if feature activated
    TODO this should probably not run on executable accounts
        Also iterate over LUT accounts */
  if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
    fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);
    fd_txn_acct_iter_t ctrl;
    for( ulong i = fd_txn_acct_iter_init( txn_ctx->txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE, &ctrl );
          i < fd_txn_acct_iter_end(); i=fd_txn_acct_iter_next( i, &ctrl ) ) {
      if( (i == 0) || fd_pubkey_is_sysvar_id( &tx_accs[i] ) )
        continue;
      fd_set_exempt_rent_epoch_max( txn_ctx, &tx_accs[i] );
    }
  }

  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    txn_ctx->unknown_accounts[i] = 0;
    txn_ctx->nonce_accounts[i] = 0;
    if (fd_txn_is_writable(txn_ctx->txn_descriptor, (int)i)) {
      FD_BORROWED_ACCOUNT_DECL(writable_new);
      int err = fd_acc_mgr_view(txn_ctx->acc_mgr, txn_ctx->funk_txn, &txn_ctx->accounts[i], writable_new);
      if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
        txn_ctx->unknown_accounts[i] = 1;
      }
    }
  }

  return 0;
}

/* Stuff to be done after multithreading ends */
int
fd_execute_txn_finalize( fd_exec_slot_ctx_t * slot_ctx,
                         fd_exec_txn_ctx_t * txn_ctx,
                         int exec_txn_err ) {
  if( exec_txn_err != 0 ) {
    for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
      fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];
      void * acc_rec_data = fd_borrowed_account_destroy( acc_rec );
      if( acc_rec_data != NULL ) {
        fd_valloc_free( txn_ctx->valloc, acc_rec_data );
      }
    }

    // fd_funk_txn_cancel( slot_ctx->acc_mgr->funk, txn_ctx->funk_txn, 0 );
    return 0;
  }

  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    if( !fd_txn_account_is_writable_idx(txn_ctx->txn_descriptor, txn_ctx->accounts, (int)i) ) {
      continue;
    }

    fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

    if( txn_ctx->unknown_accounts[i] ) {
      memset( acc_rec->meta->hash, 0xFF, sizeof(fd_hash_t) );
      if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
        fd_set_exempt_rent_epoch_max( txn_ctx, &txn_ctx->accounts[i] );
      }
    }

    int ret = fd_acc_mgr_save( txn_ctx->acc_mgr, txn_ctx->funk_txn, txn_ctx->valloc, acc_rec );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_ERR(( "failed to save edits to accounts" ));
      return -1;
    }

    void * borrow_account_data = fd_borrowed_account_destroy( acc_rec );
    if( borrow_account_data != NULL ) {
      fd_valloc_free( txn_ctx->valloc, borrow_account_data );
    }
  }

  return 0;
}

int
fd_execute_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    uint use_sysvar_instructions = fd_executor_txn_uses_sysvar_instructions( txn_ctx );

    fd_instr_info_t instrs[txn_ctx->txn_descriptor->instr_cnt];
    for ( ushort i = 0; i < txn_ctx->txn_descriptor->instr_cnt; i++ ) {
      fd_txn_instr_t const * txn_instr = &txn_ctx->txn_descriptor->instr[i];
      fd_convert_txn_instr_to_instr( txn_ctx->txn_descriptor, txn_ctx->_txn_raw, txn_instr, txn_ctx->accounts, txn_ctx->borrowed_accounts, &instrs[i] );
    }

    int ret = 0;
    if ( FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, cap_transaction_accounts_data_size ) ) {
      int ret = fd_cap_transaction_accounts_data_size( txn_ctx, instrs, txn_ctx->txn_descriptor->instr_cnt );
      if ( ret != FD_EXECUTOR_INSTR_SUCCESS ) {
        fd_funk_txn_cancel(txn_ctx->acc_mgr->funk, txn_ctx->funk_txn, 0);
        return -1;
      }
    }

    if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
      ret = fd_sysvar_instructions_serialize_account( txn_ctx, instrs, txn_ctx->txn_descriptor->instr_cnt );
      if( ret != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_ERR(( "sysvar instrutions failed to serialize" ));
        return -1;
      }
    }

    // fd_txn_t const *txn = txn_ctx->txn_descriptor;
    // fd_rawtxn_b_t const *raw_txn = txn_ctx->_txn_raw;
    // uchar * sig = (uchar *)raw_txn->raw + txn->signature_off;

    for ( ushort i = 0; i < txn_ctx->txn_descriptor->instr_cnt; i++ ) {
      if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
        ret = fd_sysvar_instructions_update_current_instr_idx( txn_ctx, i );
        if( ret != FD_ACC_MGR_SUCCESS ) {
          FD_LOG_ERR(( "sysvar instructions failed to update instruction index" ));
          return -1;
        }
      }
      // ulong pre_cus = txn_ctx->compute_meter;
      int exec_result = fd_execute_instr( &instrs[i], txn_ctx );
      // FD_LOG_WARNING(("CUs used in instr index %u - %lu", i, pre_cus - txn_ctx->compute_meter));
      if( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) {
        if (exec_result == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR) {
          // FD_LOG_WARNING(( "fd_execute_instr failed (%d:%d) for %64J", exec_result, txn_ctx->custom_err, sig ));
        } else {
          // FD_LOG_WARNING(( "fd_execute_instr failed (%d) index %u for %64J", exec_result, i, sig ));
        }
        if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
          ret = fd_sysvar_instructions_cleanup_account( txn_ctx );
          if( ret != FD_ACC_MGR_SUCCESS ) {
            FD_LOG_WARNING(( "sysvar instructions failed to cleanup" ));
            return -1;
          }
        }
        return -1;
      }
    }
    int err = fd_executor_txn_check( txn_ctx->slot_ctx, txn_ctx );
    if ( err != FD_EXECUTOR_INSTR_SUCCESS) {
      FD_LOG_DEBUG(( "fd_executor_txn_check failed (%d)", err ));
      if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
        ret = fd_sysvar_instructions_cleanup_account( txn_ctx );
        if( ret != FD_ACC_MGR_SUCCESS ) {
          FD_LOG_WARNING(( "sysvar instructions failed to cleanup" ));
          return -1;
        }
      }
      return -1;
    }

    if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
      ret = fd_sysvar_instructions_cleanup_account( txn_ctx );
      if( ret != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_WARNING(( "sysvar instructions failed to cleanup" ));
        return -1;
      }
    }

    for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
      fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

      if( !fd_txn_account_is_writable_idx(txn_ctx->txn_descriptor, txn_ctx->accounts, (int)i) || acc_rec->const_meta->info.executable ) {
        continue;
      }

      if( acc_rec->meta->info.lamports == 0 ) {
        acc_rec->meta->dlen = 0;
        memset( acc_rec->meta->info.owner, 0, sizeof(fd_pubkey_t) );
      }
    }



    return 0;
  } FD_SCRATCH_SCOPE_END;
}

int fd_executor_txn_check( fd_exec_slot_ctx_t * slot_ctx,  fd_exec_txn_ctx_t *txn ) {
  fd_rent_t const * rent = slot_ctx->sysvar_cache.rent;

  ulong ending_lamports = 0;
  ulong ending_dlen = 0;
  ulong starting_lamports = 0;
  ulong starting_dlen = 0;

  for( ulong idx = 0; idx < txn->accounts_cnt; idx++ ) {
    fd_borrowed_account_t * b = &txn->borrowed_accounts[idx];

    // Was this account written to?
    if( NULL != b->meta ) {
      ending_lamports += b->meta->info.lamports;
      ending_dlen += b->meta->dlen;

      // Lets prevent creating non-rent-exempt accounts...
      uchar after_exempt = fd_rent_exempt_minimum_balance2( rent, b->meta->dlen) <= b->meta->info.lamports;

      if( memcmp( b->pubkey->key, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) )!=0) {
        if (after_exempt || b->meta->info.lamports == 0) {
          // no-op
        } else {
          uchar before_exempt = (b->starting_dlen != ULONG_MAX) ?
            (fd_rent_exempt_minimum_balance2( rent, b->starting_dlen) <= b->starting_lamports) : 1;
          if (before_exempt || b->starting_lamports == 0) {
            FD_LOG_DEBUG(("Rent exempt error for %32J Curr len %lu Starting len %lu Curr lamports %lu Starting lamports %lu Curr exempt %lu Starting exempt %lu", b->pubkey->uc, b->meta->dlen, b->starting_dlen, b->meta->info.lamports, b->starting_lamports, fd_rent_exempt_minimum_balance2( rent, b->meta->dlen), fd_rent_exempt_minimum_balance2( rent, b->starting_dlen)));
            return FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT;
          } else if (!before_exempt && (b->meta->dlen == b->starting_dlen) && b->meta->info.lamports <= b->starting_lamports) {
            // no-op
          } else {
            FD_LOG_DEBUG(("Rent exempt error for %32J Curr len %lu Starting len %lu Curr lamports %lu Starting lamports %lu Curr exempt %lu Starting exempt %lu", b->pubkey->uc, b->meta->dlen, b->starting_dlen, b->meta->info.lamports, b->starting_lamports, fd_rent_exempt_minimum_balance2( rent, b->meta->dlen), fd_rent_exempt_minimum_balance2( rent, b->starting_dlen)));
            return FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT;
          }
        }
      }

      if (b->starting_lamports != ULONG_MAX)
        starting_lamports += b->starting_lamports;
      if (b->starting_dlen != ULONG_MAX)
        starting_dlen += b->starting_dlen;
    } else if (NULL != b->const_meta) {
      // FD_LOG_DEBUG(("Const rec mismatch %32J starting %lu %lu ending %lu %lu", b->pubkey->uc, b->starting_dlen, b->starting_lamports, b->const_meta->dlen, b->const_meta->info.lamports));
      // Should these just kill the client?  They are impossible...
      if (b->starting_lamports != b->const_meta->info.lamports) {
        FD_LOG_DEBUG(("Const rec mismatch %32J starting %lu %lu ending %lu %lu", b->pubkey->uc, b->starting_dlen, b->starting_lamports, b->const_meta->dlen, b->const_meta->info.lamports));
        return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
      }
      if (b->starting_dlen != b->const_meta->dlen) {
        FD_LOG_DEBUG(("Const rec mismatch %32J starting %lu %lu ending %lu %lu", b->pubkey->uc, b->starting_dlen, b->starting_lamports, b->const_meta->dlen, b->const_meta->info.lamports));
        return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
      }
    }
  }

  // Should these just kill the client?  They are impossible yet solana just throws an error
  if (ending_lamports != starting_lamports) {
    // FD_LOG_DEBUG(("Lamport sum mismatch: starting %lu ending %lu", starting_lamports, ending_lamports));
    return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
  }
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
