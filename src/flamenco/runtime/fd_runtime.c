#include "fd_runtime.h"
#include "fd_system_ids.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "context/fd_exec_epoch_ctx.h"
#include "../../ballet/pack/fd_compute_budget_program.h"
#include "program/fd_compute_budget_program.h"
#include "program/fd_system_program.h"
#include "../vm/fd_vm_context.h"

static ulong
fd_runtime_txn_lamports_per_signature( fd_exec_txn_ctx_t * txn_ctx ) {

  FD_SCRATCH_SCOPE_BEGIN {
    fd_nonce_state_versions_t state = {0};
    int err = 0;
    if( txn_ctx->txn_descriptor &&
        fd_load_nonce_account( txn_ctx, &state, fd_scratch_virtual(), &err ) ) {
      if( state.inner.current.discriminant == fd_nonce_state_enum_initialized )
        return state.inner.current.inner.initialized.fee_calculator.lamports_per_signature;
    }
  }
  FD_SCRATCH_SCOPE_END;

  //   lamports_per_signature = (transaction has a DurableNonce, use the lamports_per_signature from that nonce instead of looking up the recent_block_hash and using the lamports_per_signature associated with that hash
  //                        let TransactionExecutionDetails {
  //                            status,
  //                            log_messages,
  //                            inner_instructions,
  //                            durable_nonce_fee,
  //                            ..
  //                        } = details;
  //                        let lamports_per_signature = match durable_nonce_fee {
  //                            Some(DurableNonceFee::Valid(lamports_per_signature)) => {
  //                                Some(lamports_per_signature)
  //                            }
  //                            Some(DurableNonceFee::Invalid) => None,
  //                            None => bank.get_lamports_per_signature_for_blockhash(
  //                                transaction.message().recent_blockhash(),
  //                            ),
  //                        }

  fd_txn_t const *      txn_descriptor = txn_ctx->txn_descriptor;
  fd_rawtxn_b_t const * txn_raw        = txn_ctx->_txn_raw;
  return (txn_raw == NULL) ? fd_runtime_lamports_per_signature_for_blockhash(txn_ctx->slot_ctx, NULL) : fd_runtime_lamports_per_signature_for_blockhash(txn_ctx->slot_ctx, (fd_hash_t *)((uchar *)txn_raw->raw + txn_descriptor->recent_blockhash_off));
}

static void
compute_priority_fee( fd_exec_txn_ctx_t const * txn_ctx,
                      ulong *                   fee,
                      ulong *                   priority ) {

  switch( txn_ctx->prioritization_fee_type ) {
  case FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED:
  {
    if (txn_ctx->compute_unit_limit == 0)
    {
      *priority = 0;
    }
    else
    {
      uint128 micro_lamport_fee = (uint128)txn_ctx->compute_unit_price * (uint128)FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT;
      uint128 _priority = micro_lamport_fee / (uint128)txn_ctx->compute_unit_limit;
      *priority = _priority > (uint128)ULONG_MAX ? ULONG_MAX : (ulong)_priority;
    }

    *fee = txn_ctx->compute_unit_price;
    return;
  }
  case FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE:
  {

    uint128 micro_lamport_fee = (uint128)txn_ctx->compute_unit_price * (uint128)txn_ctx->compute_unit_limit;

    *priority = txn_ctx->compute_unit_price;
    uint128 _fee = (micro_lamport_fee + (uint128)(FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT - 1)) / (uint128)(FD_COMPUTE_BUDGET_MICRO_LAMPORTS_PER_LAMPORT);
    *fee = _fee > (uint128)ULONG_MAX ? ULONG_MAX : (ulong)_fee;
    return;
  }
  default:
    __builtin_unreachable();
  }
}

#define ACCOUNT_DATA_COST_PAGE_SIZE ((double)32 * 1024)

ulong
fd_runtime_calculate_fee( fd_exec_txn_ctx_t *   txn_ctx,
                          fd_txn_t const *      txn_descriptor,
                          fd_rawtxn_b_t const * txn_raw ) {

  // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L4443
  // TODO: implement fee distribution to the collector ... and then charge us the correct amount
  ulong priority = 0;
  ulong priority_fee = 0;
  compute_priority_fee(txn_ctx, &priority_fee, &priority);
  ulong lamports_per_signature = fd_runtime_txn_lamports_per_signature( txn_ctx );

  double BASE_CONGESTION = 5000.0;
  double current_congestion = (BASE_CONGESTION > (double)lamports_per_signature) ? BASE_CONGESTION : (double)lamports_per_signature;
  double congestion_multiplier = (lamports_per_signature == 0)                                                             ? 0.0
                                 : FD_FEATURE_ACTIVE(txn_ctx->slot_ctx, remove_congestion_multiplier_from_fee_calculation) ? 1.0
                                                                                                                           : (BASE_CONGESTION / current_congestion);

  //  bool support_set_compute_unit_price_ix = false;
  //  bool use_default_units_per_instruction = false;
  //  bool enable_request_heap_frame_ix = true;

  //        let mut compute_budget = ComputeBudget::default();
  //        let prioritization_fee_details = compute_budget
  //            .process_instructions(
  //                message.program_instructions_iter(),
  //                use_default_units_per_instruction,
  //                support_set_compute_unit_price_ix,
  //                enable_request_heap_frame_ix,
  //            )
  //            .unwrap_or_default();
  //        let prioritization_fee = prioritization_fee_details.get_fee();
  double prioritization_fee = (double)priority_fee;

  // let signature_fee = Self::get_num_signatures_in_message(message) .saturating_mul(fee_structure.lamports_per_signature);
  ulong num_signatures = txn_descriptor->signature_cnt;
  for (ushort i = 0; i < txn_descriptor->instr_cnt; ++i)
  {
    fd_txn_instr_t const *txn_instr = &txn_descriptor->instr[i];
    fd_pubkey_t *program_id = &txn_ctx->accounts[txn_instr->program_id];
    if (memcmp(program_id->uc, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t)) == 0 ||
        memcmp(program_id->uc, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t)) == 0)
    {
      if (txn_instr->data_sz == 0)
      {
        continue;
      }
      uchar *data = (uchar *)txn_raw->raw + txn_instr->data_off;
      num_signatures = fd_ulong_sat_add(num_signatures, (ulong)(data[0]));
    }
  }
  double signature_fee = (double)fd_runtime_lamports_per_signature(&txn_ctx->slot_ctx->slot_bank) * (double)num_signatures;

  // TODO: as far as I can tell, this is always 0
  //
  //            let write_lock_fee = Self::get_num_write_locks_in_message(message)
  //                .saturating_mul(fee_structure.lamports_per_write_lock);
  ulong lamports_per_write_lock = 0;
  double write_lock_fee = (double)fd_ulong_sat_mul(fd_txn_account_cnt(txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE), lamports_per_write_lock);

  // TODO: the fee_structure bin is static and default..
  //        let loaded_accounts_data_size_cost = if include_loaded_account_data_size_in_fee {
  //            FeeStructure::calculate_memory_usage_cost(
  //                budget_limits.loaded_accounts_data_size_limit,
  //                budget_limits.heap_cost,
  //            )
  //        } else {
  //            0_u64
  //        };
  //        let total_compute_units =
  //            loaded_accounts_data_size_cost.saturating_add(budget_limits.compute_unit_limit);
  //        let compute_fee = self
  //            .compute_fee_bins
  //            .iter()
  //            .find(|bin| total_compute_units <= bin.limit)
  //            .map(|bin| bin.fee)
  //            .unwrap_or_else(|| {
  //                self.compute_fee_bins
  //                    .last()
  //                    .map(|bin| bin.fee)
  //                    .unwrap_or_default()
  //            });

  double MEMORY_USAGE_COST = ((((double)txn_ctx->loaded_accounts_data_size_limit + (ACCOUNT_DATA_COST_PAGE_SIZE - 1)) / ACCOUNT_DATA_COST_PAGE_SIZE) * (double)vm_compute_budget.heap_cost);
  double loaded_accounts_data_size_cost = FD_FEATURE_ACTIVE(txn_ctx->slot_ctx, include_loaded_accounts_data_size_in_fee_calculation) ? MEMORY_USAGE_COST : 0.0;
  double total_compute_units = loaded_accounts_data_size_cost + (double)txn_ctx->compute_unit_limit;
  /* unused */
  (void)total_compute_units;
  double compute_fee = 0;

  double fee = (prioritization_fee + signature_fee + write_lock_fee + compute_fee) * congestion_multiplier;

  // FD_LOG_DEBUG(("fd_runtime_calculate_fee_compare: slot=%ld fee(%lf) = (prioritization_fee(%f) + signature_fee(%f) + write_lock_fee(%f) + compute_fee(%f)) * congestion_multiplier(%f)", txn_ctx->slot_ctx->slot_bank.slot, fee, prioritization_fee, signature_fee, write_lock_fee, compute_fee, congestion_multiplier));

  if (fee >= (double)ULONG_MAX)
    return ULONG_MAX;
  else
    return (ulong)fee;
}
