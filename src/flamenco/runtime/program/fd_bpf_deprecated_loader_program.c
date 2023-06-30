#include "fd_bpf_deprecated_loader_program.h"

int fd_executor_bpf_deprecated_loader_program_execute_instruction( instruction_ctx_t ctx ) {
  /* Deserialize the Stake instruction */
  uchar * data            = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off; 

  fd_bpf_loader_program_instruction_t instruction;
  fd_bpf_loader_program_instruction_new( &instruction );
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.allocf = ctx.global->allocf;
  decode_ctx.allocf_arg = ctx.global->allocf_arg;

  if ( fd_bpf_loader_program_instruction_decode( &instruction, &decode_ctx ) ) {
    FD_LOG_WARNING(("fd_bpf_loader_program_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}