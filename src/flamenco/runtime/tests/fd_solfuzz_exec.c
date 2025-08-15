/* fd_solfuzz_exec.c contains internal executors */

#include "fd_solfuzz_private.h"
#include "generated/block.pb.h"
#include "generated/invoke.pb.h"
#include "generated/txn.pb.h"
#include "generated/vm.pb.h"
#include "generated/elf.pb.h"
#include "../fd_executor_err.h"
#include <assert.h>

/*
 * fixtures
 */

static int
sol_compat_cmp_binary_strict( void const * effects,
                              void const * expected,
                              pb_msgdesc_t const * encode_type,
                              fd_spad_t * spad ) {
#define MAX_SZ 32*1024*1024
FD_SPAD_FRAME_BEGIN( spad ) {
  if( effects==NULL ) {
    FD_LOG_WARNING(( "No output effects" ));
    return 0;
  }

  /* Note: Most likely this spad allocation won't fail. If it does, you may need to bump
     the allocated spad memory amount in fd_exec_sol_compat.c. */
  ulong out_sz = MAX_SZ;
  uchar * out = fd_spad_alloc( spad, 1UL, out_sz );
  if( !sol_compat_encode( out, &out_sz, effects, encode_type ) ) {
    FD_LOG_WARNING(( "Error encoding effects" ));
    return 0;
  }

  ulong exp_sz = MAX_SZ;
  uchar * exp = fd_spad_alloc( spad, 1UL, exp_sz );
  if( !sol_compat_encode( exp, &exp_sz, expected, encode_type ) ) {
    FD_LOG_WARNING(( "Error encoding expected" ));
    return 0;
  }

  if( out_sz!=exp_sz ) {
    FD_LOG_WARNING(( "Binary cmp failed: different size. out_sz=%lu exp_sz=%lu", out_sz, exp_sz  ));
    return 0;
  }
  if( !fd_memeq( out, exp, out_sz ) ) {
    FD_LOG_WARNING(( "Binary cmp failed: different values." ));
    return 0;
  }

  return 1;
} FD_SPAD_FRAME_END;
#undef MAX_SIZE
}

static int
_diff_txn_acct( fd_exec_test_acct_state_t * expected,
                fd_exec_test_acct_state_t * actual ) {
  /* AcctState -> address (This must hold true when calling this function!) */
  assert( fd_memeq( expected->address, actual->address, sizeof(fd_pubkey_t) ) );

  /* AcctState -> lamports */
  if( expected->lamports != actual->lamports ) {
    FD_LOG_WARNING(( "Lamports mismatch: expected=%lu actual=%lu", expected->lamports, actual->lamports ));
    return 0;
  }

  /* AcctState -> data */
  if( expected->data != NULL || actual->data != NULL ) {
    if( expected->data == NULL ) {
      FD_LOG_WARNING(( "Expected account data is NULL, actual is non-NULL" ));
      return 0;
    }

    if( actual->data == NULL ) {
      FD_LOG_WARNING(( "Expected account data is NULL, actual is non-NULL" ));
      return 0;
    }

    if( expected->data->size != actual->data->size ) {
      FD_LOG_WARNING(( "Account data size mismatch: expected=%u actual=%u", expected->data->size, actual->data->size ));
      return 0;
    }

    if( !fd_memeq( expected->data->bytes, actual->data->bytes, expected->data->size ) ) {
      FD_LOG_WARNING(( "Account data mismatch" ));
      return 0;
    }
  }

  /* AcctState -> executable */
  if( expected->executable != actual->executable ) {
    FD_LOG_WARNING(( "Executable mismatch: expected=%d actual=%d", expected->executable, actual->executable ));
    return 0;
  }

  /* AcctState -> rent_epoch */
  if( expected->rent_epoch != actual->rent_epoch ) {
    FD_LOG_WARNING(( "Rent epoch mismatch: expected=%lu actual=%lu", expected->rent_epoch, actual->rent_epoch ));
    return 0;
  }

  /* AcctState -> owner */
  if( !fd_memeq( expected->owner, actual->owner, sizeof(fd_pubkey_t) ) ) {
    char a[ FD_BASE58_ENCODED_32_SZ ];
    char b[ FD_BASE58_ENCODED_32_SZ ];
    FD_LOG_WARNING(( "Owner mismatch: expected=%s, actual=%s", fd_acct_addr_cstr( a, expected->owner ), fd_acct_addr_cstr( b, actual->owner ) ));
    return 0;
  }

  return 1;
}


static int
_diff_resulting_states( fd_exec_test_resulting_state_t *  expected,
                        fd_exec_test_resulting_state_t *  actual ) {
  // Verify that the number of accounts are the same
  if( expected->acct_states_count != actual->acct_states_count ) {
    FD_LOG_WARNING(( "Account states count mismatch: expected=%u actual=%u", expected->acct_states_count, actual->acct_states_count ));
    return 0;
  }

  // Verify that the account states are the same
  for( ulong i = 0; i < expected->acct_states_count; ++i ) {
    for( ulong j = 0; j < actual->acct_states_count; ++j ) {
      if( fd_memeq( expected->acct_states[i].address, actual->acct_states[j].address, sizeof(fd_pubkey_t) ) ) {
        if( !_diff_txn_acct( &expected->acct_states[i], &actual->acct_states[j] ) ) {
          return 0;
        }
      }
    }
  }

  // TODO: resulting_state -> rent_debits, resulting_state->transaction_rent
  return 1;
}

static int
sol_compat_cmp_txn( fd_exec_test_txn_result_t *  expected,
                    fd_exec_test_txn_result_t *  actual ) {
  /* TxnResult -> executed */
  if( expected->executed != actual->executed ) {
    FD_LOG_WARNING(( "Executed mismatch: expected=%d actual=%d", expected->executed, actual->executed ));
    return 0;
  }

  /* TxnResult -> sanitization_error */
  if( expected->sanitization_error != actual->sanitization_error ) {
    FD_LOG_WARNING(( "Sanitization error mismatch: expected=%d actual=%d", expected->sanitization_error, actual->sanitization_error ));
    return 0;
  }

  /* TxnResult -> resulting_state */
  if( !_diff_resulting_states( &expected->resulting_state, &actual->resulting_state ) ) {
    return 0;
  }

  /* TxnResult -> rent */
  if( expected->rent != actual->rent ) {
    FD_LOG_WARNING(( "Rent mismatch: expected=%lu actual=%lu", expected->rent, actual->rent ));
    return 0;
  }

  /* TxnResult -> is_ok */
  if( expected->is_ok != actual->is_ok ) {
    FD_LOG_WARNING(( "Is ok mismatch: expected=%d actual=%d", expected->is_ok, actual->is_ok ));
    return 0;
  }

  /* TxnResult -> status */
  if( expected->status != actual->status ) {
    FD_LOG_WARNING(( "Status mismatch: expected=%u actual=%u", expected->status, actual->status ));
    return 0;
  }

  /* TxnResult -> instruction_error */
  if( expected->instruction_error != actual->instruction_error ) {
    FD_LOG_WARNING(( "Instruction error mismatch: expected=%u actual=%u", expected->instruction_error, actual->instruction_error ));
    return 0;
  }

  if( expected->instruction_error ) {
    /* TxnResult -> instruction_error_index */
    if( expected->instruction_error_index != actual->instruction_error_index ) {
      FD_LOG_WARNING(( "Instruction error index mismatch: expected=%u actual=%u", expected->instruction_error_index, actual->instruction_error_index ));
      return 0;
    }

    /* TxnResult -> custom_error */
    if( expected->instruction_error == (ulong) -FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR && expected->custom_error != actual->custom_error ) {
      FD_LOG_WARNING(( "Custom error mismatch: expected=%u actual=%u", expected->custom_error, actual->custom_error ));
      return 0;
    }
  }

  /* TxnResult -> return_data */
  if( expected->return_data != NULL || actual->return_data != NULL ) {
    if( expected->return_data == NULL ) {
      FD_LOG_WARNING(( "Expected return data is NULL, actual is non-NULL" ));
      return 0;
    }

    if( actual->return_data == NULL ) {
      FD_LOG_WARNING(( "Expected return data is NULL, actual is non-NULL" ));
      return 0;
    }

    if( expected->return_data->size != actual->return_data->size ) {
      FD_LOG_WARNING(( "Return data size mismatch: expected=%u actual=%u", expected->return_data->size, actual->return_data->size ));
      return 0;
    }

    if( !fd_memeq( expected->return_data->bytes, actual->return_data->bytes, expected->return_data->size ) ) {
      FD_LOG_WARNING(( "Return data mismatch" ));
      return 0;
    }
  }

  /* TxnResult -> executed_units */
  if( expected->executed_units != actual->executed_units ) {
    FD_LOG_WARNING(( "Executed units mismatch: expected=%lu actual=%lu", expected->executed_units, actual->executed_units ));
    return 0;
  }

  /* TxnResult -> fee_details */
  if( expected->has_fee_details != actual->has_fee_details ) {
    FD_LOG_WARNING(( "Has fee details mismatch: expected=%d actual=%d", expected->has_fee_details, actual->has_fee_details ));
    return 0;
  }

  if( expected->has_fee_details ) {
    if( expected->fee_details.transaction_fee != actual->fee_details.transaction_fee ) {
      FD_LOG_WARNING(( "Transaction fee mismatch: expected=%lu actual=%lu", expected->fee_details.transaction_fee, actual->fee_details.transaction_fee ));
      return 0;
    }

    if( expected->fee_details.prioritization_fee != actual->fee_details.prioritization_fee ) {
      FD_LOG_WARNING(( "Priority fee mismatch: expected=%lu actual=%lu", expected->fee_details.prioritization_fee, actual->fee_details.prioritization_fee ));
      return 0;
    }
  }

  /* TxnResult -> loaded_accounts_data_size */
  if( expected->loaded_accounts_data_size != actual->loaded_accounts_data_size ) {
    FD_LOG_WARNING(( "Loaded accounts data size mismatch: expected=%lu actual=%lu", expected->loaded_accounts_data_size, actual->loaded_accounts_data_size ));
    return 0;
  }

  return 1;
}

int
fd_solfuzz_instr_fixture( fd_solfuzz_runner_t * runner,
                          uchar const *         in,
                          ulong                 in_sz ) {
  // Decode fixture
  fd_exec_test_instr_fixture_t fixture[1] = {0};
  void * res = sol_compat_decode( &fixture, in, in_sz, &fd_exec_test_instr_fixture_t_msg );
  if( !res ) {
    FD_LOG_WARNING(( "Invalid instr fixture." ));
    return 0;
  }

  int ok = 0;
  // Execute
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, &fixture->input, &output, fd_solfuzz_instr_run );

  // Compare effects
  ok = sol_compat_cmp_binary_strict( output, &fixture->output, &fd_exec_test_instr_effects_t_msg, runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_instr_fixture_t_msg, fixture );
  return ok;
}

int
fd_solfuzz_txn_fixture( fd_solfuzz_runner_t * runner,
                        uchar const *         in,
                        ulong                 in_sz ) {
  // Decode fixture
  fd_exec_test_txn_fixture_t fixture[1] = {0};
  void * res = sol_compat_decode( &fixture, in, in_sz, &fd_exec_test_txn_fixture_t_msg );
  if( !res ) {
    FD_LOG_WARNING(( "Invalid txn fixture." ));
    return 0;
  }

  fd_spad_push( runner->spad );
  int ok = 0;
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, &fixture->input, &output, fd_solfuzz_txn_run );
  if( FD_LIKELY( output ) ) {
    // Compare effects
    fd_exec_test_txn_result_t * effects = output;
    ok = sol_compat_cmp_txn( &fixture->output, effects );
  }
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_txn_fixture_t_msg, fixture );
  return ok;
}

int
fd_solfuzz_block_fixture( fd_solfuzz_runner_t * runner,
                          uchar const *         in,
                          ulong                 in_sz ) {
  // Decode fixture
  fd_exec_test_block_fixture_t fixture[1] = {0};
  void * res = sol_compat_decode( &fixture, in, in_sz, &fd_exec_test_block_fixture_t_msg );
  if( !res ) {
    FD_LOG_WARNING(( "Invalid block fixture" ));
    return 0;
  }

  fd_spad_push( runner->spad );
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, &fixture->input, &output, fd_solfuzz_block_run );
  int ok = sol_compat_cmp_binary_strict( output, &fixture->output, &fd_exec_test_block_effects_t_msg, runner->spad );
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_block_fixture_t_msg, fixture );
  return ok;
}

int
fd_solfuzz_elf_loader_fixture( fd_solfuzz_runner_t * runner,
                               uchar const *         in,
                               ulong                 in_sz ) {
  // Decode fixture
  fd_exec_test_elf_loader_fixture_t fixture[1] = {0};
  void * res = sol_compat_decode( &fixture, in, in_sz, &fd_exec_test_elf_loader_fixture_t_msg );
  if( !res ) {
    FD_LOG_WARNING(( "Invalid elf_loader fixture." ));
    return 0;
  }

  fd_spad_push( runner->spad );
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, &fixture->input, &output, fd_solfuzz_elf_loader_run );
  int ok = sol_compat_cmp_binary_strict( output, &fixture->output, &fd_exec_test_elf_loader_effects_t_msg, runner->spad );
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_elf_loader_fixture_t_msg, fixture );
  return ok;
}

int
fd_solfuzz_syscall_fixture( fd_solfuzz_runner_t * runner,
                            uchar const *         in,
                            ulong                 in_sz ) {
  // Decode fixture
  fd_exec_test_syscall_fixture_t fixture[1] = {0};
  if( !sol_compat_decode( &fixture, in, in_sz, &fd_exec_test_syscall_fixture_t_msg ) ) {
    FD_LOG_WARNING(( "Invalid syscall fixture." ));
    return 0;
  }

  fd_spad_push( runner->spad );
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, &fixture->input, &output, fd_solfuzz_syscall_run );
  int ok = sol_compat_cmp_binary_strict( output, &fixture->output, &fd_exec_test_syscall_effects_t_msg, runner->spad );
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_syscall_fixture_t_msg, fixture );
  return ok;
}

int
fd_solfuzz_vm_interp_fixture( fd_solfuzz_runner_t * runner,
                              uchar const *         in,
                              ulong                 in_sz ) {
  // Decode fixture
  fd_exec_test_syscall_fixture_t fixture[1] = {0};
  if( !sol_compat_decode( &fixture, in, in_sz, &fd_exec_test_syscall_fixture_t_msg ) ) {
    FD_LOG_WARNING(( "Invalid syscall fixture." ));
    return 0;
  }

  fd_spad_push( runner->spad );
  void * output = NULL;
  fd_solfuzz_execute_wrapper( runner, &fixture->input, &output, fd_solfuzz_vm_interp_run );
  int ok = sol_compat_cmp_binary_strict( output, &fixture->output, &fd_exec_test_syscall_effects_t_msg, runner->spad );
  fd_spad_pop( runner->spad );

  // Cleanup
  pb_release( &fd_exec_test_syscall_fixture_t_msg, fixture );
  return ok;
}
