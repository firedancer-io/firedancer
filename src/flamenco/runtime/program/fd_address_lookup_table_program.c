#include "fd_zk_token_proof_program.h"
#include "../fd_executor.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../fd_acc_mgr.h"
#include <string.h>

static int
create_lookup_table( fd_exec_instr_ctx_t         ctx,
                     fd_addrlut_create_t const * create ) {
  FD_LOG_WARNING(( "TODO" ));
  (void)ctx; (void)create;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

static int
freeze_lookup_table( fd_exec_instr_ctx_t ctx ) {
  FD_LOG_WARNING(( "TODO" ));
  (void)ctx;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

static int
extend_lookup_table( fd_exec_instr_ctx_t         ctx,
                     fd_addrlut_extend_t const * extend ) {
  FD_LOG_WARNING(( "TODO" ));
  (void)ctx; (void)extend;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

static int
deactivate_lookup_table( fd_exec_instr_ctx_t ctx ) {
  FD_LOG_WARNING(( "TODO" ));
  (void)ctx;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

static int
close_lookup_table( fd_exec_instr_ctx_t ctx ) {
  FD_LOG_WARNING(( "TODO" ));
  (void)ctx;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

int
fd_executor_address_lookup_table_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {

  uchar const * instr_data    = ctx.instr->data;
  ulong         instr_data_sz = ctx.instr->data_sz;

  FD_SCRATCH_SCOPED_FRAME;

  fd_bincode_decode_ctx_t decode = {
    .valloc  = fd_scratch_virtual(),
    .data    = instr_data,
    .dataend = instr_data + instr_data_sz
  };
  fd_addrlut_instruction_t instr[1];
  /* https://github.com/solana-labs/solana/blob/fb80288f885a62bcd923f4c9579fd0edeafaff9b/programs/address-lookup-table/src/processor.rs#L31 */
  if( FD_UNLIKELY( fd_addrlut_instruction_decode( instr, &decode ) != FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  switch( instr->discriminant ) {
  case fd_addrlut_instruction_enum_create_lut:
    return create_lookup_table( ctx, &instr->inner.create_lut );
  case fd_addrlut_instruction_enum_freeze_lut:
    return freeze_lookup_table( ctx );
  case fd_addrlut_instruction_enum_extend_lut:
    return extend_lookup_table( ctx, &instr->inner.extend_lut );
  case fd_addrlut_instruction_enum_deactivate_lut:
    return deactivate_lookup_table( ctx );
  case fd_addrlut_instruction_enum_close_lut:
    return close_lookup_table( ctx );
  default:
    break;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
