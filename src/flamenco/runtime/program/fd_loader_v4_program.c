#include "fd_loader_v4_program.h"

/* `loader_v4::get_state`
   https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L28-L40 */
static int
loader_v4_get_state( fd_borrowed_account_t const * program,
                     fd_loader_v4_state_t *        state ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L30-L34 */
  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = program->const_data,
    .dataend = program->const_data + program->const_meta->dlen,
    .valloc  = fd_scratch_virtual(),
  };

  if( FD_UNLIKELY( !fd_loader_v4_state_decode( state, &decode_ctx ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
} 

/* `check_program_account` validates the program account's state from its data.
   Returns an instruction error if any of the checks fail. Writes the decoded
   state into `state`. */
static int
check_program_account( fd_exec_instr_ctx_t *         instr_ctx,
                       fd_borrowed_account_t const * program,
                       fd_pubkey_t const *           authority_address,
                       fd_loader_v4_state_t *        state ) {
  int err;
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L62-L65 */
  if( FD_UNLIKELY( memcmp( program->pubkey->uc, fd_solana_bpf_loader_v4_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program not owned by loader" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L66 */
  err = loader_v4_get_state( program, state );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L67-L70 */
  if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, program->pubkey ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program is not writeable" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L71-L74 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Authority did not sign" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L75-L78 */
  if( FD_UNLIKELY( memcmp( &state->authority_address_or_next_version, authority_address, sizeof(fd_pubkey_t) ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Incorrect authority provided" );
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L79-L82 */
  if( FD_UNLIKELY( fd_loader_v4_status_is_finalized( &state->status ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program is finalized" );
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L83 */
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `process_instruction_write`, this code path is taken when writing ELF data into an undeployed program account.
   This could either be a program which was already deployed and then retracted, or a new program which is uninitialized
   with enough space allocated from a call to `truncate`.

   https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L86-L121 */
static int
fd_bpf_loader_v4_program_instruction_write( fd_exec_instr_ctx_t * instr_ctx,
                                            fd_bpf_loader_v4_program_instruction_write_t const * write ) {
  int err;

  uint offset         = write->offset;
  uchar const * bytes = write->bytes;
  ulong bytes_len     = write->bytes_len;

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L94 */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, program ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L95-L97 */
    fd_pubkey_t const * authority_address = &instr_ctx->instr->acct_pubkeys[ 1UL ];

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L98-L103 */
    fd_loader_v4_state_t state = {0};
    err = check_program_account( instr_ctx, program, authority_address, &state );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L104-L107 */
    if( FD_UNLIKELY( !fd_loader_v4_status_is_retracted( &state.status ) ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Program is not retracted" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L108 */
    ulong end_offset = fd_ulong_sat_add( offset, bytes_len );

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L109-L119 */
    if( FD_UNLIKELY( fd_ulong_sat_add( LOADER_V4_PROGRAM_DATA_OFFSET, end_offset )>program->const_meta->dlen ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Write out of bounds" );
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    /* Note that fd_executor already makes writable accounts modifiable by populating the meta. Since we already
       checked that the program account is writable, the `program->data` access is safe. */
    if( FD_LIKELY( bytes_len>0 ) ) {
      fd_memcpy( program->data+LOADER_V4_PROGRAM_DATA_OFFSET+offset, bytes, bytes_len );
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
  } FD_BORROWED_ACCOUNT_DROP( program );
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

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L473-L486 */
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
