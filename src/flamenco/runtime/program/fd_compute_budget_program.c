#include "fd_compute_budget_program.h"

#include "../fd_runtime_err.h"
#include "../fd_system_ids.h"
#include "../fd_executor.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../../vm/fd_vm.h"

#define DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT  (200000)
#define DEFAULT_COMPUTE_UNITS                   (150UL)

FD_FN_PURE static inline int
is_compute_budget_instruction( fd_exec_txn_ctx_t const * ctx,
                               fd_txn_instr_t    const * instr ) {
  fd_pubkey_t const * txn_accs       = ctx->accounts;
  fd_pubkey_t const * program_pubkey = &txn_accs[ instr->program_id ];
  return !memcmp(program_pubkey, fd_solana_compute_budget_program_id.key, sizeof(fd_pubkey_t));
}

/* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/compute-budget/src/compute_budget_processor.rs#L150-L153 */
FD_FN_PURE static inline int
sanitize_requested_heap_size( ulong bytes ) {
  return !(bytes>FD_MAX_HEAP_FRAME_BYTES || bytes<FD_MIN_HEAP_FRAME_BYTES || bytes%FD_HEAP_FRAME_BYTES_GRANULARITY);
}

/* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/compute-budget/src/compute_budget_processor.rs#L69-L148 */
int fd_executor_compute_budget_program_execute_instructions( fd_exec_txn_ctx_t * ctx, fd_rawtxn_b_t const * txn_raw ) {
  uint has_compute_units_limit_update             = 0UL;
  uint has_compute_units_price_update             = 0UL;
  uint has_requested_heap_size                    = 0UL;
  uint has_loaded_accounts_data_size_limit_update = 0UL;

  uint num_non_compute_budget_instrs = 0U;

  uint  updated_compute_unit_limit              = 0U;
  uint  updated_requested_heap_size             = 0U;
  uint  updated_loaded_accounts_data_size_limit = 0U;
  ulong updated_compute_unit_price              = 0UL;

  uint prioritization_fee_type = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE;

  for( ushort i=0; i<ctx->txn_descriptor->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &ctx->txn_descriptor->instr[i];

    if( !is_compute_budget_instruction( ctx, instr ) ) {
      num_non_compute_budget_instrs++;
      continue;
    }
    /* Deserialize the ComputeBudgetInstruction enum */
    uchar * data = (uchar *)txn_raw->raw + instr->data_off;

    fd_compute_budget_program_instruction_t instruction;
    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = data,
      .dataend = &data[ instr->data_sz ],
      .valloc  = ctx->valloc,
    };

    int ret = fd_compute_budget_program_instruction_decode( &instruction, &decode_ctx );
    if ( ret ) {
      FD_LOG_WARNING(("fd_compute_budget_program_instruction_decode failed"));
      FD_LOG_HEXDUMP_WARNING(("cbi data", data, instr->data_sz));
      FD_TXN_ERR_FOR_LOG_INSTR( ctx, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA, i );
      return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
    }

    switch( instruction.discriminant ) {
      case fd_compute_budget_program_instruction_enum_request_heap_frame: {
        if( FD_UNLIKELY( has_requested_heap_size ) ) {
          return FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION;
        }

        has_requested_heap_size     = 1U;
        updated_requested_heap_size = instruction.inner.request_heap_frame;

        if( FD_UNLIKELY( !sanitize_requested_heap_size( updated_requested_heap_size ) ) ) {
          FD_TXN_ERR_FOR_LOG_INSTR( ctx, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA, i );
          return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
        } 
        break;
      }
      case fd_compute_budget_program_instruction_enum_set_compute_unit_limit: {
        if( FD_UNLIKELY( has_compute_units_limit_update ) ) {
          return FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION;
        }

        has_compute_units_limit_update = 1U;
        updated_compute_unit_limit     = instruction.inner.set_compute_unit_limit;

        break;
      }
      case fd_compute_budget_program_instruction_enum_set_compute_unit_price: {
        if( FD_UNLIKELY( has_compute_units_price_update ) ) {
          return FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION;
        }

        has_compute_units_price_update = 1U;
        prioritization_fee_type        = FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE;
        updated_compute_unit_price     = instruction.inner.set_compute_unit_price;

        break;
      }
      case fd_compute_budget_program_instruction_enum_set_loaded_accounts_data_size_limit: {
          if( FD_UNLIKELY( has_loaded_accounts_data_size_limit_update ) ) {
            return FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION;
          }

          has_loaded_accounts_data_size_limit_update = 1U;
          updated_loaded_accounts_data_size_limit    = instruction.inner.set_loaded_accounts_data_size_limit;

          break;
      }
      default: {
        FD_TXN_ERR_FOR_LOG_INSTR( ctx, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA, i );
        return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
      }
    }
  }

  if( has_requested_heap_size ) {
    ctx->heap_size = updated_requested_heap_size;
  }

  if( has_compute_units_limit_update ) {
    ctx->compute_unit_limit = fd_ulong_min( FD_MAX_COMPUTE_UNIT_LIMIT, updated_compute_unit_limit );
  } else {
    ctx->compute_unit_limit = fd_ulong_min( FD_MAX_COMPUTE_UNIT_LIMIT, 
                                            (ulong)fd_uint_sat_mul( num_non_compute_budget_instrs, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT ) );
  }

  if( has_compute_units_price_update ) {
    ctx->prioritization_fee_type = prioritization_fee_type;
    ctx->compute_unit_price      = updated_compute_unit_price;
  }

  if( has_loaded_accounts_data_size_limit_update ) {
    ctx->loaded_accounts_data_size_limit = 
      fd_ulong_min( FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT, updated_loaded_accounts_data_size_limit );
  }

  ctx->compute_meter = ctx->compute_unit_limit;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}


int fd_compute_budget_program_execute( fd_exec_instr_ctx_t * ctx ) {
  FD_EXEC_CU_UPDATE( ctx, DEFAULT_COMPUTE_UNITS );
  return FD_EXECUTOR_INSTR_SUCCESS;
}
