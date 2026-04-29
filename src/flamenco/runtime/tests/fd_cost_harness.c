#include "fd_cost_harness.h"
#include "fd_solfuzz_private.h"
#include "fd_txn_harness.h"

#include "../fd_cost_tracker.h"
#include "../program/fd_compute_budget_program.h"

int
fd_solfuzz_pb_cost_run( fd_solfuzz_runner_t *               runner,
                        fd_exec_test_cost_context_t const * input,
                        fd_exec_test_cost_result_t *        output ) {
  if( FD_UNLIKELY( !input->has_tx || !input->has_features ) ) return 0;

  int ok = 0;

  fd_banks_clear_bank( runner->banks, runner->bank, 64UL );
  runner->bank->f.slot = 1UL;
  FD_TEST( fd_solfuzz_pb_restore_features( &runner->bank->f.features, &input->features ) );

  fd_txn_p_t * txn_p = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), sizeof(fd_txn_p_t) );
  ulong txn_sz = fd_solfuzz_pb_txn_serialize( txn_p->payload, &input->tx );
  if( FD_UNLIKELY( txn_sz==ULONG_MAX ) ) return 0;

  txn_p->payload_sz = txn_sz;
  if( FD_UNLIKELY( !fd_txn_parse( txn_p->payload, txn_p->payload_sz, TXN( txn_p ), NULL ) ) ) {
    return 0;
  }

  fd_txn_in_t txn_in = {0};
  txn_in.txn = txn_p;

  fd_txn_out_t txn_out = {0};
  fd_compute_budget_details_new( &txn_out.details.compute_budget );
  txn_out.details.loaded_accounts_data_size = txn_out.details.compute_budget.loaded_accounts_data_size_limit;
  txn_out.details.is_simple_vote = fd_txn_is_simple_vote_transaction( TXN( txn_p ), txn_p->payload );

  int err = fd_executor_compute_budget_program_execute_instructions( runner->bank, &txn_in, &txn_out );
  if( FD_LIKELY( !err ) ) err = fd_sanitize_compute_unit_limits( &txn_out );
  if( FD_UNLIKELY( err ) ) return 0;

  if( input->mode==FD_EXEC_TEST_TXN_COST_MODE_ACTUAL ) {
    ulong actual_cost = input->actual_programs_execution_cost;
    ulong limit = txn_out.details.compute_budget.compute_unit_limit;
    txn_out.details.compute_budget.compute_meter = fd_ulong_sat_sub( limit, fd_ulong_min( actual_cost, limit ) );
    txn_out.details.loaded_accounts_data_size = (ulong)input->actual_loaded_accounts_data_size_bytes;
  } else {
    /* In ESTIMATE mode, programs_execution_cost = compute_unit_limit (see
       agave cost_model.rs:get_estimated_execution_cost). fd_cost_tracker
       computes programs_execution_cost as (limit - compute_meter), so zero
       the meter here to yield the full limit. */
    txn_out.details.compute_budget.compute_meter = 0UL;
    txn_out.details.loaded_accounts_data_size = txn_out.details.compute_budget.loaded_accounts_data_size_limit;
  }

  fd_cost_tracker_calculate_cost( runner->bank, &txn_in, &txn_out );

  /* In ACTUAL mode agave passes actual_programs_execution_cost through
     without clamping to compute_unit_limit (see agave cost_model.rs:
     calculate_cost_for_executed_transaction). The (limit - meter)
     formula in fd_cost_tracker inherently clamps, so overwrite with the
     raw actual value here for parity. */
  if( input->mode==FD_EXEC_TEST_TXN_COST_MODE_ACTUAL &&
      txn_out.details.txn_cost.type==FD_TXN_COST_TYPE_TRANSACTION ) {
    txn_out.details.txn_cost.transaction.programs_execution_cost = input->actual_programs_execution_cost;
  }

  *output = (fd_exec_test_cost_result_t)FD_EXEC_TEST_COST_RESULT_INIT_ZERO;
  output->has_cost = 1;
  if( txn_out.details.txn_cost.type==FD_TXN_COST_TYPE_TRANSACTION ) {
    output->signature_cost = txn_out.details.txn_cost.transaction.signature_cost;
    output->write_lock_cost = txn_out.details.txn_cost.transaction.write_lock_cost;
    output->data_bytes_cost = txn_out.details.txn_cost.transaction.data_bytes_cost;
    output->programs_execution_cost = txn_out.details.txn_cost.transaction.programs_execution_cost;
    output->loaded_accounts_data_size_cost = txn_out.details.txn_cost.transaction.loaded_accounts_data_size_cost;
    output->allocated_accounts_data_size = txn_out.details.txn_cost.transaction.allocated_accounts_data_size;
  } else {
    /* Simple-vote branch: proto CostResult fields have to match agave's
       TransactionCost::SimpleVote component-wise (cost-model/src/
       transaction_cost.rs:48-51 and :86-93). The 2100 here is
       solana_vote_program::vote_processor::DEFAULT_COMPUTE_UNITS --
       the vote program's per-invocation cost. Components sum to
       FD_SIMPLE_VOTE_USAGE_COST (3428). */
    output->signature_cost = FD_PACK_COST_PER_SIGNATURE;
    output->write_lock_cost = FD_WRITE_LOCK_UNITS * 2UL;
    output->data_bytes_cost = 0UL;
    output->programs_execution_cost = 2100UL;
    output->loaded_accounts_data_size_cost = 8UL;
    output->allocated_accounts_data_size = 0UL;
  }
  /* Saturating add to match agave's UsageCostDetails::sum (transaction_cost.rs:
     saturating_add chain). Plain + wraps on u64::MAX inputs (e.g. adversarial
     actual_programs_execution_cost = u64::MAX). */
  output->total_cost = fd_ulong_sat_add( output->signature_cost, output->write_lock_cost );
  output->total_cost = fd_ulong_sat_add( output->total_cost, output->data_bytes_cost );
  output->total_cost = fd_ulong_sat_add( output->total_cost, output->programs_execution_cost );
  output->total_cost = fd_ulong_sat_add( output->total_cost, output->loaded_accounts_data_size_cost );
  ok = 1;

  return ok;
}
