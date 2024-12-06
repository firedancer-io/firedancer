#include "fd_loader_v4_program.h"

/* `process_instruction_write`, this code path is taken when 

   https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L86-L121 */
static int
fd_bpf_loader_v4_program_instruction_write( fd_exec_instr_ctx_t * instr_ctx,
                                            fd_bpf_loader_v4_program_instruction_write_t const * instr ) {
}

/* `process_instruction_inner`, the entrypoint for all loader v4 instruction invocations +
   any loader v4-owned programs.
   
   https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L463-L526 */
int
fd_loader_v4_program_execute( fd_exec_instr_ctx_t * instr_ctx ) {
  /* TODO: feature active check */
  FD_SCRATCH_SCOPE_BEGIN {
    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L470 */
    fd_pubkey_t const * program_id = &instr_ctx->instr->program_id_pubkey;

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L471-L488 */
    int rc = FD_EXECUTOR_INSTR_SUCCESS;
    if( !memcmp( program_id, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L472 */
      FD_EXEC_CU_UPDATE( instr_ctx, LOADER_V4_DEFAULT_COMPUTE_UNITS );

      /* Note the dataend is capped at a 1232 bytes offset to mirror the semantics of `limited_deserialize`.
         https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L473 */
      uchar const * data = instr_ctx->instr->data;

      fd_bpf_loader_v4_program_instruction_t instruction = {0};
      fd_bincode_decode_ctx_t decode_ctx = {
        .data    = data,
        .dataend = &data[ instr_ctx->instr->data_sz > 1232UL ? 1232UL : instr_ctx->instr->data_sz ],
        .valloc  = instr_ctx->valloc,
      };

      if( FD_UNLIKELY( !fd_bpf_loader_v4_program_instruction_decode( &instruction, &decode_ctx ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      }

      /* 

      
         https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L473-L486 */
      switch( instruction.discriminant ) {
        case fd_bpf_loader_v4_program_instruction_enum_write: {
          /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L474-L476 */
          rc = fd_bpf_loader_v4_program_instruction_write( instr_ctx, &instruction.inner.write );
          break;
        }
        case fd_bpf_loader_v4_program_instruction_enum_truncate: {
          break;
        }
        case fd_bpf_loader_v4_program_instruction_enum_deploy: {
          break;
        }
        case fd_bpf_loader_v4_program_instruction_enum_retract: {
          break;
        }
        case fd_bpf_loader_v4_program_instruction_enum_transfer_authority: {
          break;
        }
      }

    } else {

    }

    return rc;
  } FD_SCRATCH_SCOPE_END;
}
