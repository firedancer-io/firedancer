#include "fd_compute_budget_program.h"

#include "../fd_runtime_err.h"
#include "../fd_system_ids.h"
#include "../fd_executor.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../vm/fd_vm.h"
#include "fd_builtin_programs.h"

#define DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT    (200000UL)
#define DEFAULT_COMPUTE_UNITS                     (150UL)

/* https://github.com/anza-xyz/agave/blob/v2.1.13/compute-budget/src/compute_budget_limits.rs#L11-L13 */
#define MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT (3000UL)

FD_FN_PURE static inline uchar
get_program_kind( fd_exec_txn_ctx_t const * txn_ctx,
                  fd_txn_instr_t const *    instr ) {
  fd_acct_addr_t const * txn_accs       = fd_txn_get_acct_addrs( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw );
  fd_pubkey_t const *    program_pubkey = fd_type_pun_const( &txn_accs[ instr->program_id ] );

  /* The program is a standard, non-migrating builtin (e.g. system program) */
  if( fd_is_non_migrating_builtin_program( program_pubkey ) ) {
    return FD_PROGRAM_KIND_BUILTIN;
  }

  uchar migrated_yet;
  uchar is_migrating_program = fd_is_migrating_builtin_program( txn_ctx, program_pubkey, &migrated_yet );

  /* The program has a BPF migration config but has not been migrated yet, so it's still a builtin program */
  if( is_migrating_program && !migrated_yet ) {
    return FD_PROGRAM_KIND_BUILTIN;
  }

  /* The program has a BPF migration config AND has been migrated */
  if( is_migrating_program && migrated_yet ) {
    return FD_PROGRAM_KIND_MIGRATING_BUILTIN;
  }

  /* The program is some other program kind, i.e. not a builtin */
  return FD_PROGRAM_KIND_NOT_BUILTIN;
}

FD_FN_PURE static inline int
is_compute_budget_instruction( fd_txn_t const *       txn,
                               fd_rawtxn_b_t const *  txn_raw,
                               fd_txn_instr_t const * instr ) {
  fd_acct_addr_t const * txn_accs       = fd_txn_get_acct_addrs( txn, txn_raw->raw );
  fd_acct_addr_t const * program_pubkey = &txn_accs[ instr->program_id ];
  return !memcmp(program_pubkey, fd_solana_compute_budget_program_id.key, sizeof(fd_pubkey_t));
}

/* In our implementation of this function, our parameters map to Agave's as follows:
  - `num_builtin_instrs` -> `num_non_migratable_builtin_instructions` + `num_not_migrated`
  - `num_non_builtin_instrs` -> `num_non_builtin_instructions` + `num_migrated`

   https://github.com/anza-xyz/agave/blob/v2.1.13/runtime-transaction/src/compute_budget_instruction_details.rs#L211-L239 */
FD_FN_PURE static inline ulong
calculate_default_compute_unit_limit( fd_exec_txn_ctx_t const * ctx,
                                      ulong                     num_builtin_instrs,
                                      ulong                     num_non_builtin_instrs,
                                      ulong                     num_non_compute_budget_instrs ) {
  if( FD_FEATURE_ACTIVE_BANK( ctx->bank, reserve_minimal_cus_for_builtin_instructions ) ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.13/runtime-transaction/src/compute_budget_instruction_details.rs#L227-L234 */
    return fd_ulong_sat_add( fd_ulong_sat_mul( num_builtin_instrs, MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT ),
                             fd_ulong_sat_mul( num_non_builtin_instrs, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT ) );
  } else {
    /* https://github.com/anza-xyz/agave/blob/v2.1.13/runtime-transaction/src/compute_budget_instruction_details.rs#L236-L237 */
    return fd_ulong_sat_mul( num_non_compute_budget_instrs, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT );
  }
}

/* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/compute-budget/src/compute_budget_processor.rs#L150-L153 */
FD_FN_PURE static inline int
sanitize_requested_heap_size( ulong bytes ) {
  return !(bytes>FD_MAX_HEAP_FRAME_BYTES || bytes<FD_MIN_HEAP_FRAME_BYTES || bytes%FD_HEAP_FRAME_BYTES_GRANULARITY);
}

/* NOTE: At this point, the transaction context has NOT been fully initialized (namely, the accounts). The accounts are NOT safe to access.

   https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/compute-budget/src/compute_budget_processor.rs#L69-L148 */
int
fd_executor_compute_budget_program_execute_instructions( fd_exec_txn_ctx_t * ctx ) {
  uint   has_compute_units_limit_update              = 0UL;
  uint   has_compute_units_price_update              = 0UL;
  uint   has_requested_heap_size                     = 0UL;
  uint   has_loaded_accounts_data_size_limit_update  = 0UL;

  ushort requested_heap_size_instr_index             = 0;

  /* SIMD-170 introduces a conservative CU limit of 3,000 CUs per non-migrated native program,
     and 200,000 CUs for all other programs (including migrated builtins). */
  ulong  num_non_compute_budget_instrs               = 0UL;
  ulong  num_builtin_instrs                          = 0UL;
  ulong  num_non_builtin_instrs                      = 0UL;

  uint   updated_compute_unit_limit                  = 0U;
  uint   updated_requested_heap_size                 = 0U;
  uint   updated_loaded_accounts_data_size_limit     = 0U;
  ulong  updated_compute_unit_price                  = 0UL;

  uint prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE;

  for( ushort i=0; i<ctx->txn_descriptor->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &ctx->txn_descriptor->instr[i];

    /* Track builtin vs non-builtin metrics only if SIMD-170 is active */
    if( FD_FEATURE_ACTIVE_BANK( ctx->bank, reserve_minimal_cus_for_builtin_instructions ) ) {
      /* Only `FD_PROGRAM_KIND_BUILTIN` gets charged as a builtin instruction */
      uchar program_kind = get_program_kind( ctx, instr );
      if( program_kind==FD_PROGRAM_KIND_BUILTIN ) {
        num_builtin_instrs++;
      } else {
        num_non_builtin_instrs++;
      }
    }

    if( !is_compute_budget_instruction( ctx->txn_descriptor, ctx->_txn_raw, instr ) ) {
      num_non_compute_budget_instrs++;
      continue;
    }

    /* Deserialize the ComputeBudgetInstruction enum */
    uchar * data = (uchar *)ctx->_txn_raw->raw + instr->data_off;

    int ret;
    fd_compute_budget_program_instruction_t * instruction =
      fd_bincode_decode_spad(
        compute_budget_program_instruction, ctx->spad,
        data, instr->data_sz, &ret );
    if( FD_UNLIKELY( ret ) ) {
      FD_TXN_ERR_FOR_LOG_INSTR( ctx, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA, i );
      return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
    }

    switch( instruction->discriminant ) {
      case fd_compute_budget_program_instruction_enum_request_heap_frame: {
        if( FD_UNLIKELY( has_requested_heap_size ) ) {
          return FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION;
        }

        has_requested_heap_size     = 1U;
        updated_requested_heap_size = instruction->inner.request_heap_frame;
        requested_heap_size_instr_index = i;

        break;
      }
      case fd_compute_budget_program_instruction_enum_set_compute_unit_limit: {
        if( FD_UNLIKELY( has_compute_units_limit_update ) ) {
          return FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION;
        }

        has_compute_units_limit_update  = 1U;
        updated_compute_unit_limit      = instruction->inner.set_compute_unit_limit;

        break;
      }
      case fd_compute_budget_program_instruction_enum_set_compute_unit_price: {
        if( FD_UNLIKELY( has_compute_units_price_update ) ) {
          return FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION;
        }

        has_compute_units_price_update = 1U;
        prioritization_fee_type        = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE;
        updated_compute_unit_price     = instruction->inner.set_compute_unit_price;

        break;
      }
      case fd_compute_budget_program_instruction_enum_set_loaded_accounts_data_size_limit: {
          if( FD_UNLIKELY( has_loaded_accounts_data_size_limit_update ) ) {
            return FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION;
          }

          has_loaded_accounts_data_size_limit_update = 1U;
          updated_loaded_accounts_data_size_limit    = instruction->inner.set_loaded_accounts_data_size_limit;

          break;
      }
      default: {
        FD_TXN_ERR_FOR_LOG_INSTR( ctx, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA, i );
        return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
      }
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1/runtime-transaction/src/compute_budget_instruction_details.rs#L51-L64 */
  if( has_requested_heap_size ) {
    if( FD_UNLIKELY( !sanitize_requested_heap_size( updated_requested_heap_size ) ) ) {
      FD_TXN_ERR_FOR_LOG_INSTR( ctx, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA, requested_heap_size_instr_index );
      return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
    }
    ctx->heap_size = updated_requested_heap_size;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.13/runtime-transaction/src/compute_budget_instruction_details.rs#L137-L143 */
  if( has_compute_units_limit_update ) {
    ctx->compute_unit_limit = fd_ulong_min( FD_MAX_COMPUTE_UNIT_LIMIT, updated_compute_unit_limit );
  } else {
    ctx->compute_unit_limit = fd_ulong_min( calculate_default_compute_unit_limit(ctx,
                                                                                    num_builtin_instrs,
                                                                                    num_non_builtin_instrs,
                                                                                    num_non_compute_budget_instrs),
                                            FD_MAX_COMPUTE_UNIT_LIMIT );
  }
  ctx->compute_meter = ctx->compute_unit_limit;

  if( has_compute_units_price_update ) {
    ctx->prioritization_fee_type = prioritization_fee_type;
    ctx->compute_unit_price      = updated_compute_unit_price;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1/runtime-transaction/src/compute_budget_instruction_details.rs#L84-L93 */
  if( has_loaded_accounts_data_size_limit_update ) {
    if( FD_UNLIKELY( updated_loaded_accounts_data_size_limit==0UL ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;
    }
    ctx->loaded_accounts_data_size_limit =
      fd_ulong_min( FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT, updated_loaded_accounts_data_size_limit );
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}


int fd_compute_budget_program_execute( fd_exec_instr_ctx_t * ctx ) {
  FD_EXEC_CU_UPDATE( ctx, DEFAULT_COMPUTE_UNITS );
  return FD_EXECUTOR_INSTR_SUCCESS;
}
