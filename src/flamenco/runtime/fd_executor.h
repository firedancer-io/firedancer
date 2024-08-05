#ifndef HEADER_fd_src_flamenco_runtime_fd_executor_h
#define HEADER_fd_src_flamenco_runtime_fd_executor_h

#include "fd_executor_err.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/pack/fd_microblock.h"
#include "../../ballet/poh/fd_poh.h"
#include "../types/fd_types_yaml.h"
#include "tests/generated/invoke.pb.h"
#include "tests/generated/txn.pb.h"

FD_PROTOTYPES_BEGIN

/* fd_exec_instr_fn_t processes an instruction.  Returns an error code
   in FD_EXECUTOR_INSTR_{ERR_{...},SUCCESS}. */

typedef int (* fd_exec_instr_fn_t)( fd_exec_instr_ctx_t ctx );

/* fd_executor_lookup_native_program returns the appropriate instruction
   processor for the given native program ID.  Returns NULL if given ID
   is not a recognized native program. */

fd_exec_instr_fn_t
fd_executor_lookup_native_program(  fd_pubkey_t const * program_id );

/* fd_execute_instr creates a new fd_exec_instr_ctx_t and performs
   instruction processing.  Does fd_scratch allocations.  Returns an
   error code in FD_EXECUTOR_INSTR_{ERR_{...},SUCCESS}.

   IMPORTANT: instr_info must have the same lifetime as txn_ctx. This can
   be achieved by using fd_executor_acquire_instr_info_elem( txn_ctx ) to
   acquire an fd_instr_info_t element with the same lifetime as the txn_ctx */
int
fd_executor_txn_verify( fd_exec_txn_ctx_t * txn_ctx );

int
fd_execute_instr( fd_exec_txn_ctx_t * txn_ctx,
                  fd_instr_info_t *   instr_info );

int
fd_execute_txn_prepare_phase1( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx,
                               fd_txn_t const * txn_descriptor,
                               fd_rawtxn_b_t const * txn_raw );

int
fd_execute_txn_prepare_phase2( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx );
int
fd_execute_txn_prepare_phase3( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx,
                               fd_txn_p_t * txn );

int
fd_execute_txn_prepare_phase4( fd_exec_txn_ctx_t * txn_ctx );

int
fd_execute_txn_finalize( fd_exec_txn_ctx_t * txn_ctx,
                         int exec_txn_err );

/*
  Execute the given transaction.

  Makes changes to the Funk accounts DB. */
int
fd_execute_txn( fd_exec_txn_ctx_t * txn_ctx );

/* Returns a new fd_instr_info_t element, which will have the same lifetime as the given txn_ctx.

   Returns NULL if we failed to acquire a new fd_instr_info_t element from the pool, which has
   FD_MAX_INSTRUCTION_TRACE_LENGTH capacity. The appropiate response to this is usually
   failing with FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED.
 */
fd_instr_info_t *
fd_executor_acquire_instr_info_elem( fd_exec_txn_ctx_t * txn_ctx );

uint
fd_executor_txn_uses_sysvar_instructions( fd_exec_txn_ctx_t const * txn_ctx );

void
fd_executor_setup_accessed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx );

void
fd_executor_setup_borrowed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx );

/*
  Validate the txn after execution for violations of various lamport balance and size rules
 */

int
fd_executor_txn_check( fd_exec_slot_ctx_t * slot_ctx,  fd_exec_txn_ctx_t *txn );

int
fd_should_set_exempt_rent_epoch_max( fd_rent_t const *       rent,
                                     fd_borrowed_account_t * rec );

void
fd_txn_set_exempt_rent_epoch_max( fd_exec_txn_ctx_t * txn_ctx,
                                  void const *        addr );

int
fd_executor_collect_fee( fd_exec_slot_ctx_t * slot_ctx,
                         fd_borrowed_account_t const * rec,
                         ulong                fee );

void
fd_txn_reclaim_accounts( fd_exec_txn_ctx_t * txn_ctx );

/* fd_io_strerror converts an FD_EXECUTOR_INSTR_ERR_{...} code into a
   human readable cstr.  The lifetime of the returned pointer is
   infinite and the call itself is thread safe.  The returned pointer is
   always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_executor_instr_strerror( int err );

int
fd_executor_check_txn_accounts( fd_exec_txn_ctx_t * txn_ctx );

static inline int
fd_exec_consume_cus( fd_exec_txn_ctx_t * txn_ctx,
                     ulong               cus ) {
  ulong new_cus   =  txn_ctx->compute_meter - cus;
  int   underflow = (txn_ctx->compute_meter < cus);
  if( FD_UNLIKELY( underflow ) ) {
    txn_ctx->compute_meter = 0UL;
    return FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED;
  }
  txn_ctx->compute_meter = new_cus;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
dump_txn_to_protobuf( fd_exec_txn_ctx_t *txn_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_executor_h */
