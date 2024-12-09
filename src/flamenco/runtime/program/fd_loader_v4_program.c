#include "fd_loader_v4_program.h"

/* `loader_v4::get_state()`
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

  if( FD_UNLIKELY( fd_loader_v4_state_decode( state, &decode_ctx ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Convenience method to set the state of a writable program account. */
static int
loader_v4_set_state( fd_exec_instr_ctx_t *  instr_ctx,
                     ulong                  instr_acc_idx,
                     fd_loader_v4_state_t * state ) {
  int err;

  uchar * data = NULL;
  ulong   dlen = 0UL;

  err = fd_account_get_data_mut( instr_ctx, instr_acc_idx, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  if( FD_UNLIKELY( LOADER_V4_PROGRAM_DATA_OFFSET>dlen ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  fd_bincode_encode_ctx_t ctx = {
    .data    = data,
    .dataend = data + LOADER_V4_PROGRAM_DATA_OFFSET,
  };

  if( FD_UNLIKELY( fd_loader_v4_state_encode( state, &ctx ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `check_program_account()` validates the program account's state from its data.
   Returns an instruction error if any of the checks fail. Writes the decoded
   state into `state`. */
static int
check_program_account( fd_exec_instr_ctx_t *         instr_ctx,
                       fd_borrowed_account_t const * program,
                       fd_pubkey_t const *           authority_address,
                       fd_loader_v4_state_t *        state ) {
  int err;
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L62-L65 */
  if( FD_UNLIKELY( memcmp( program->const_meta->info.owner, fd_solana_bpf_loader_v4_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
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

/* `process_instruction_write()` writes ELF data into an undeployed program account.
   This could either be a program which was already deployed and then retracted, or 
   a new program which is uninitialized with enough space allocated from a call to `truncate`.

   Accounts:
    0. Program account (writable)
    1. Authority account (signer)

   https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L86-L121 */
static int
fd_loader_v4_program_instruction_write( fd_exec_instr_ctx_t *                            instr_ctx,
                                        fd_loader_v4_program_instruction_write_t const * write ) {
  int           err;
  uint          offset    = write->offset;
  uchar const * bytes     = write->bytes;
  ulong         bytes_len = write->bytes_len;

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

/* `process_instruction_truncate()` resizes an undeployed program account to the specified size. 
   Initialization is taken care of when the program account size is first increased. Decreasing the size
   to 0 will close the program account.

   Accounts:
      0. Program account (writable + signer)
      1. Authority account (signer)
      2. Recipient account to receive excess lamports from rent when decreasing account size (writable)
         - This account is only required when the program account size is being decreased (new_size < program dlen).

   https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L123-L208 */
static int
fd_loader_v4_program_instruction_truncate( fd_exec_instr_ctx_t *                               instr_ctx,
                                           fd_loader_v4_program_instruction_truncate_t const * truncate ) {
  int  err;
  uint new_size = truncate->new_size;

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L130 */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, program ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L131-L133 */
    fd_pubkey_t const * authority_address = &instr_ctx->instr->acct_pubkeys[ 1UL ];

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L134C9-L135 */
    uchar is_initialization = !!( new_size>0UL && program->const_meta->dlen<LOADER_V4_PROGRAM_DATA_OFFSET );

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L136-L164 */
    if( is_initialization ) {
      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L137-L140 */
      if( FD_UNLIKELY( memcmp( program->const_meta->info.owner, fd_solana_bpf_loader_v4_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program not owned by loader" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L141-L144 */
      if( FD_UNLIKELY( !fd_instr_acc_is_writable( instr_ctx->instr, program->pubkey ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program is not writeable" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L145-L148 */
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 0UL ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program did not sign" );
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L149-L152 */
      if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Authority did not sign" );
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
    } else {
      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L154-L159 */
      fd_loader_v4_state_t state = {0};
      err = check_program_account( instr_ctx, program, authority_address, &state ); 
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L160-L163 */
      if(  FD_UNLIKELY( !fd_loader_v4_status_is_retracted( &state.status ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program is not retracted" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L165-L171 */
    fd_rent_t const * rent = fd_sysvar_cache_rent( instr_ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( rent==NULL ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    /* Note that this new_program_dlen is only relevant when new_size > 0 */
    ulong new_program_dlen = fd_ulong_sat_add( LOADER_V4_PROGRAM_DATA_OFFSET, new_size );
    ulong required_lamports = ( new_size==0UL ) ? 
                                0UL : 
                                fd_ulong_max( fd_rent_exempt_minimum_balance( rent, new_program_dlen ),
                                              1UL );

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L172-L193 */
    if( FD_UNLIKELY( program->const_meta->info.lamports<required_lamports ) ) {
      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L174-L179 */
      fd_log_collector_printf_dangerous_max_127( instr_ctx,
        "Insufficient lamports, %lu are required", required_lamports );
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    } else if( program->const_meta->info.lamports>required_lamports ) {
      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L182-L183 */
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 2UL, recipient ) {

        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L184-L187 */
        if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( instr_ctx->instr, 2UL ) ) ) {
          fd_log_collector_msg_literal( instr_ctx, "Recipient is not writeable" );
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }

        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L190 */
        ulong lamports_to_receive = fd_ulong_sat_sub( program->const_meta->info.lamports,
                                                      required_lamports );
        err = fd_account_checked_add_lamports( instr_ctx, 2UL, recipient->const_meta->info.lamports );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
        err = fd_account_checked_sub_lamports( instr_ctx, 0UL, lamports_to_receive );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      } FD_BORROWED_ACCOUNT_DROP( recipient );
    } /* no-op for program lamports == required lamports */

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L194-L206 */
    if( new_size==0UL ) {
      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L195 */
      err = fd_account_set_data_length( instr_ctx, 0UL, 0UL );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    } else {
      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L197-L199 */
      err = fd_account_set_data_length( instr_ctx, 0UL, new_program_dlen );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L200-L205 */
      if( is_initialization ) {
        /* Serialize into the program account directly. Note that an error is impossible
           because `new_program_dlen` > `LOADER_V4_PROGRAM_DATA_OFFSET`.
           https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L201-L204 */
        fd_loader_v4_state_t state = {
          .slot = 0UL,
          .status = {
            .discriminant = fd_loader_v4_status_enum_retracted,
          },
          .authority_address_or_next_version = *authority_address,
        };
        fd_bincode_encode_ctx_t ctx = {
          .data    = program->data,
          .dataend = program->data + LOADER_V4_PROGRAM_DATA_OFFSET,
        };

        err = fd_loader_v4_state_encode( &state, &ctx );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      }
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
  } FD_BORROWED_ACCOUNT_DROP( program );
}

/* `process_instruction_deploy()` will verify the ELF bytes of a program account in a `Retracted`
   state and deploy it if successful, setting the executable status and making it ready for use.
   Optionally, a source buffer account may be provided to copy the ELF bytes from. In this case,
   the program data is overwritten by the data in the buffer account, and the buffer account is closed
   with some of its lamports transferred to the program account if needed to meet the minimum rent exemption
   balance. 

   Other notes:
   - Newly deployed programs may not be retracted/redeployed within `LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS` (750) slots.
   - This does NOT set the account's executable flag. TODO: Find out if this is intentional or accidental. This 
     might be a part of a greater effort to deprecate the account executable flag.

  Accounts:
    0. Program account (writable)
    1. Authority account (signer)
    2. (OPTIONAL) Source buffer account (writable)

   https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L210-L325 */
static int
fd_loader_v4_program_instruction_deploy( fd_exec_instr_ctx_t * instr_ctx ) {
  int err;

  /* These variables should exist outside of borrowed account scopes. */
  uchar                         source_program_present = !!( instr_ctx->instr->acct_cnt>1 );
  fd_loader_v4_state_t          program_state          = {0};
  fd_sol_sysvar_clock_t const * clock                  = fd_sysvar_cache_clock( instr_ctx->slot_ctx->sysvar_cache );

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.r s#L217-L219 */
  fd_pubkey_t const * authority_address = &instr_ctx->instr->acct_pubkeys[ 1UL ];

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L216 */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, program ) {
    /* Here Agave tries to acquire the source buffer account but does not fail if it is not present.
       We will only try to borrow the account when we need it.

       https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L220-L222 
       
       No-op for us... */

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L223-L228 */
    err = check_program_account( instr_ctx, program, authority_address, &program_state );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L229 */
    if( FD_UNLIKELY( clock==NULL ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }
    ulong current_slot = clock->slot;

    /* `current_slot == 0` indicates that the program hasn't been deployed yet, so a cooldown check
       is not needed. Otherwise, a cooldown of 750 slots is applied before being able to 
       redeploy or retract the program. 
       
       https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L231-L240 */
    if( FD_UNLIKELY( current_slot>0UL && fd_ulong_sat_add( program_state.slot, LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS )>current_slot ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Program was deployed recently, cooldown still in effect" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L241-L244 */
    if(  FD_UNLIKELY( !fd_loader_v4_status_is_retracted( &program_state.status ) ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Destination program is not retracted" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
  } FD_BORROWED_ACCOUNT_DROP( program ); // We no longer need the program account

  /* Since our borrowed account semantics are slightly different than Agave's, we drop the program account above
     (since the variable is no longer needed) and acquire a new borrowed account that may point to the program account
     OR a new buffer account, if it's present. This way, the account borrowing semantics stay conformant with Agave. 
     
     If the source program (account key at idx 2) is present, we acquire that as the buffer and perform checks on its
     state to make sure it's valid. Otherwise, we reacquire the same program account from above. */
  ulong buffer_idx = ( source_program_present ) ? 2UL : 0UL;
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, buffer_idx, buffer ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L245-L259 */
    if( source_program_present ) {
      /* buffer == source_program here
         https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L246-L251 */
      fd_loader_v4_state_t source_state = {0};
      err = check_program_account( instr_ctx, buffer, authority_address, &source_state );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L252-L255 */
      if( FD_UNLIKELY( !fd_loader_v4_status_is_retracted( &source_state.status ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Source program is not retracted" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L261-L264 */
    if( FD_UNLIKELY( buffer->const_meta->dlen<LOADER_V4_PROGRAM_DATA_OFFSET ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }
    uchar const * programdata = buffer->const_data + LOADER_V4_PROGRAM_DATA_OFFSET;

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L266-L267 
    
       TODO: I think their logic here is incorrect - using a much older deployment slot from several epochs
       prior means that program validation checks could potentially brick a program forever. For example,
       if a program is newly deployed, we'd be performing ELF validations from the runtime environment from slot 0. */

    /* Our program cache is fundamentally different from Agave's. Here, they would perform verifications and
       add the program to their cache, but we only perform verifications now and defer cache population to the 
       end of the slot. Since programs cannot be invoked until the next slot anyways, doing this is okay.

       https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L269-L293 */
    err = fd_deploy_program( instr_ctx, programdata, buffer->const_meta->dlen - LOADER_V4_PROGRAM_DATA_OFFSET );
    if( FD_UNLIKELY( err ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Transfer enough lamports from the source program, if exists, to the program account to cover
       the rent exempt minimum balance amount. Then, close the source program account.

       https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L295-L303 */
    if( source_program_present ) {
      /* We can safely reacquire the program account here since the buffer account corresponds to the source
         program here. */
      FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, program ) {
        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L296 */
        fd_rent_t const * rent = fd_sysvar_cache_rent( instr_ctx->slot_ctx->sysvar_cache );
        if( FD_UNLIKELY( rent==NULL ) ) {
          return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
        }
        
        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L297 */
        ulong required_lamports = fd_rent_exempt_minimum_balance( rent, buffer->const_meta->dlen );

        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L298 */
        ulong transfer_lamports = fd_ulong_sat_sub( required_lamports, program->const_meta->info.lamports );
        
        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L299 */
        err = fd_account_set_data_from_slice( instr_ctx, 0UL, buffer->const_data, buffer->const_meta->dlen );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }

        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L300 */
        err = fd_account_set_data_length( instr_ctx, 2UL, 0UL );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }

        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L301 */
        err = fd_account_checked_sub_lamports( instr_ctx, 2UL, transfer_lamports );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }

        /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L302 */
        err = fd_account_checked_add_lamports( instr_ctx, 0UL, transfer_lamports );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      } FD_BORROWED_ACCOUNT_DROP( program );
    }
  } FD_BORROWED_ACCOUNT_DROP( buffer ); // Drop the buffer account. At this point, there are no outstanding account borrows.

  /* Reacquire the program account to persist state changes to it. */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, program ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L304-L306 */
    program_state.slot = clock->slot;
    program_state.status.discriminant = fd_loader_v4_status_enum_deployed;
    err = loader_v4_set_state( instr_ctx, 0UL, &program_state );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
  } FD_BORROWED_ACCOUNT_DROP( program );
}

/* `process_instruction_retract()` retracts a currently deployed program, making it writable
   and uninvokable. After a program is retracted, users can write and truncate data freely,
   allowing them to upgrade or close the program account. 
   
   Other notes:
   - Newly deployed programs may not be retracted/redeployed within `LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS` (750) slots.
   
   Accounts:
    0. Program account (writable)
    1. Authority account (signer)

    https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L327-L369 */
static int
fd_loader_v4_program_instruction_retract( fd_exec_instr_ctx_t * instr_ctx ) {
  int err;

  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( instr_ctx, 0UL, program ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L335-L337 */
    fd_pubkey_t const * authority_address = &instr_ctx->instr->acct_pubkeys[ 1UL ];

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L338-L343 */
    fd_loader_v4_state_t state = {0};
    err = check_program_account( instr_ctx, program, authority_address, &state );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L344 */
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( instr_ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( clock==NULL ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }
    ulong current_slot = clock->slot;

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L345-L351 */
    if( FD_UNLIKELY( fd_ulong_sat_add( state.slot, LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS )>current_slot ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Program was deployed recently, cooldown still in effect" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L352-L355 */
    if( FD_UNLIKELY( !fd_loader_v4_status_is_deployed( &state.status ) ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Program is not deployed" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L356 */
    state.status.discriminant = fd_loader_v4_status_enum_retracted;
    err = loader_v4_set_state( instr_ctx, 0UL, &state );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* No need to update program cache - see note in `deploy` processor. */

    return FD_EXECUTOR_INSTR_SUCCESS;
  } FD_BORROWED_ACCOUNT_DROP( program );
}

/* `process_instruction_inner()`, the entrypoint for all loader v4 instruction invocations +
   any loader v4-owned programs.
   
   https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L463-L526 */
int
fd_loader_v4_program_execute( fd_exec_instr_ctx_t * instr_ctx ) {
  if( FD_UNLIKELY( !FD_FEATURE_ACTIVE( instr_ctx->slot_ctx, enable_program_runtime_v2_and_loader_v4 ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

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

      fd_loader_v4_program_instruction_t instruction = {0};
      fd_bincode_decode_ctx_t decode_ctx = {
        .data    = data,
        .dataend = &data[ instr_ctx->instr->data_sz > 1232UL ? 1232UL : instr_ctx->instr->data_sz ],
        .valloc  = instr_ctx->valloc,
      };

      if( FD_UNLIKELY( !fd_loader_v4_program_instruction_decode( &instruction, &decode_ctx ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L473-L486 */
      switch( instruction.discriminant ) {
        case fd_loader_v4_program_instruction_enum_write: {
          if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
            return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
          }

          /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L474-L476 */
          rc = fd_loader_v4_program_instruction_write( instr_ctx, &instruction.inner.write );
          break;
        }
        case fd_loader_v4_program_instruction_enum_truncate: {
          if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
            return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
          }

          /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L477-L479 */
          rc = fd_loader_v4_program_instruction_truncate( instr_ctx, &instruction.inner.truncate );
          break;
        }
        case fd_loader_v4_program_instruction_enum_deploy: {
          if( FD_UNLIKELY( fd_account_check_num_insn_accounts( instr_ctx, 2U ) ) ) {
            return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
          }

          /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/loader-v4/src/lib.rs#L480 */
          rc = fd_loader_v4_program_instruction_deploy( instr_ctx );
          break;
        }
        case fd_loader_v4_program_instruction_enum_retract: {
          rc = fd_loader_v4_program_instruction_retract( instr_ctx );
          break;
        }
        case fd_loader_v4_program_instruction_enum_transfer_authority: {
          break;
        }
      }

    } else {

    }

    return rc;
  } FD_SCRATCH_SCOPE_END;
}
