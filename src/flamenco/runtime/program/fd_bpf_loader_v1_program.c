#include "fd_bpf_loader_v1_program.h"

int
fd_bpf_loader_v1_program_execute( fd_exec_instr_ctx_t ctx ) {
  uchar const * data = ctx.instr->data;

  fd_bpf_loader_program_instruction_t instruction;
  fd_bincode_decode_ctx_t decode =
    { .data    = data,
      .dataend = data + ctx.instr->data_sz,
      .valloc  = ctx.valloc };

  if( fd_bpf_loader_program_instruction_decode( &instruction, &decode ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
}
