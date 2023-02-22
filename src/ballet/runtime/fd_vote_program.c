#include "fd_vote_program.h"

void fd_executor_vote_program_execute_instruction(
    instruction_ctx_t ctx
) {
    /* TODO: template out bincode decoding of enums */

    /* Deserialize the VoteInstruction enum */
    /* solana/sdk/program/src/vote/instruction.rs::VoteInstruction */
    uchar *data            = (uchar *)ctx.txn_raw->raw + ctx.instr->data_off;
    void* input            = (void *)data;
    const void** input_ptr = (const void **)&input;
    void* dataend          = (void*)&data[ctx.instr->data_sz];

    uint discrimant  = 0;
    fd_bincode_uint32_decode( &discrimant, input_ptr, dataend );

    FD_LOG_INFO(( "decoded vote program discriminant: %d", discrimant ));

    /* TODO */
}
