#include "fd_loader_v4_program.h"

/* Helper functions that would normally be provided by fd_types. */
FD_FN_PURE uchar
fd_loader_v4_status_is_deployed( fd_loader_v4_state_t const * state ) {
  return state->status==FD_LOADER_V4_STATUS_ENUM_DELOYED;
}

FD_FN_PURE uchar
fd_loader_v4_status_is_retracted( fd_loader_v4_state_t const * state ) {
  return state->status==FD_LOADER_V4_STATUS_ENUM_RETRACTED;
}

FD_FN_PURE uchar
fd_loader_v4_status_is_finalized( fd_loader_v4_state_t const * state ) {
  return state->status==FD_LOADER_V4_STATUS_ENUM_FINALIZED;
}

/* Convenience method to get the state of a writable program account as a mutable reference.
   `get_state_mut()` takes a mutable pointer to a borrowed account's writable data and transmutes
   it into a loader v4 state. It is safe to write to the returned loader v4 state. The function
   returns 0 on success or an error code if the account data is too small. Assumes `data` is a
   non-null, writable pointer into an account's data.

   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L46-L58 */
static fd_loader_v4_state_t *
fd_loader_v4_get_state_mut( uchar * data,
                            ulong   dlen,
                            int   * err ) {
  *err = FD_EXECUTOR_INSTR_SUCCESS;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L48-L52 */
  if( FD_UNLIKELY( dlen<LOADER_V4_PROGRAM_DATA_OFFSET ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    return NULL;
  }

  return fd_type_pun( data );
}

/* `loader_v4::get_state()` performs a `transmute` operation which bypasses any decoding and directly
   reinterprets the data as a loader v4 state. The key difference between the transmute and standard
   decoding logic is that `get_state()` won't fail if `state.status` is not a valid discriminant, i.e.
   `state.status` can be any value within a ulong range that's not {Deployed, Retracted, Finalized}.
   Returns a casted pointer to the account data, interpreted as a loader v4 state type, or NULL if the
   account data is too small. The returned state is const and thus is NOT safe to modify.

   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L32-L44 */
fd_loader_v4_state_t const *
fd_loader_v4_get_state( fd_txn_account_t const * program,
                        int *                    err ) {
  *err = FD_EXECUTOR_INSTR_SUCCESS;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L35-L36 */
  if( FD_UNLIKELY( fd_txn_account_get_data_len( program )<LOADER_V4_PROGRAM_DATA_OFFSET ) ) {
    *err = FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    return NULL;
  }

  return fd_type_pun_const( fd_txn_account_get_data( program ) );
}

/* `check_program_account()` validates the program account's state from its data.
   Sets `err` to an instruction error if any of the checks fail. Otherwise, returns a
   const pointer to the program account data, transmuted as a loader v4 state.
   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L60-L88 */
static fd_loader_v4_state_t const *
check_program_account( fd_exec_instr_ctx_t *         instr_ctx,
                       fd_borrowed_account_t const * program,
                       fd_pubkey_t const *           authority_address,
                       int *                         err ) {
  *err = FD_EXECUTOR_INSTR_SUCCESS;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L66-L69 */
  if( FD_UNLIKELY( memcmp( fd_borrowed_account_get_owner( program ), fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program not owned by loader" );
    *err = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L70 */
  fd_loader_v4_state_t const * state = fd_loader_v4_get_state( program->acct, err );
  if( FD_UNLIKELY( *err ) ) {
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L71-L73 */
  if( FD_UNLIKELY( !fd_borrowed_account_is_writable( program ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program is not writeable" );
    *err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L75-L78 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Authority did not sign" );
    *err = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L79-L82 */
  if( FD_UNLIKELY( memcmp( &state->authority_address_or_next_version, authority_address, sizeof(fd_pubkey_t) ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Incorrect authority provided" );
    *err = FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L83-L86 */
  if( FD_UNLIKELY( fd_loader_v4_status_is_finalized( state ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program is finalized" );
    *err = FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
    return NULL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L87 */
  return state;
}

/* `process_instruction_write()` writes ELF data into an undeployed program account.
   This could either be a program which was already deployed and then retracted, or
   a new program which is uninitialized with enough space allocated from a call to `set_program_length`.

   Accounts:
    0. Program account (writable)
    1. Authority account (signer)

   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L90-L122 */
static int
fd_loader_v4_program_instruction_write( fd_exec_instr_ctx_t *                            instr_ctx,
                                        fd_loader_v4_program_instruction_write_t const * write ) {
  int           err;
  uint          offset    = write->offset;
  uchar const * bytes     = write->bytes;
  ulong         bytes_len = write->bytes_len;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L98 */
  fd_guarded_borrowed_account_t program;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 0UL, &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L99-L101 */
  fd_pubkey_t const * authority_address = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( instr_ctx, 1UL, &authority_address );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L102-L107 */
  fd_loader_v4_state_t const * state = check_program_account( instr_ctx, &program, authority_address, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L108-L111 */
  if( FD_UNLIKELY( !fd_loader_v4_status_is_retracted( state ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program is not retracted" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L112 */
  ulong destination_offset = fd_ulong_sat_add( offset, LOADER_V4_PROGRAM_DATA_OFFSET );

  /* Break up the chained operations into separate lines...
     https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L113-L114 */
  uchar * data = NULL;
  ulong dlen = 0UL;
  err = fd_borrowed_account_get_data_mut( &program, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L115-L118 */
  if( FD_UNLIKELY( fd_ulong_sat_add( destination_offset, bytes_len )>dlen ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Write out of bounds" );
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  if( FD_LIKELY( bytes_len>0 ) ) {
    fd_memcpy( data+destination_offset, bytes, bytes_len );
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `fd_loader_v4_program_instruction_copy()` is similar to `fd_loader_v4_program_instruction_write()`, except
   it copies ELF data from a source program account instead of from instruction data. This is useful
   for migrating existing v1/v2/v3 programs to v4.

   Accounts:
    0. Program account (writable)
    1. Authority account (signer)
    2. Source program account

   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L124-L181
*/
static int
fd_loader_v4_program_instruction_copy( fd_exec_instr_ctx_t *                           instr_ctx,
                                       fd_loader_v4_program_instruction_copy_t const * copy ) {
  int  err;
  uint destination_offset = copy->destination_offset;
  uint source_offset      = copy->source_offset;
  uint length             = copy->length;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L133 */
  fd_guarded_borrowed_account_t program;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 0UL, &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L134-L136 */
  fd_pubkey_t const * authority_address = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( instr_ctx, 1UL, &authority_address );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L137-L138 */
  fd_guarded_borrowed_account_t source_program;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 2UL, &source_program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L139-L144 */
  fd_loader_v4_state_t const * state = check_program_account( instr_ctx, &program, authority_address, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L145-L148 */
  if( FD_UNLIKELY( !fd_loader_v4_status_is_retracted( state ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program is not retracted" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L149-L162 */
  fd_pubkey_t const * source_owner = fd_borrowed_account_get_owner( &source_program );
  if( !memcmp( source_owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
    source_offset = fd_uint_sat_add( source_offset, (uint)LOADER_V4_PROGRAM_DATA_OFFSET );
  } else if( !memcmp( source_owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
    source_offset = fd_uint_sat_add( source_offset, (uint)PROGRAMDATA_METADATA_SIZE );
  } else if( FD_UNLIKELY( memcmp( source_owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) &&
                          memcmp( source_owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Source is not a program" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L163-L169 */
  uchar const * data = fd_borrowed_account_get_data( &source_program );
  if( FD_UNLIKELY( fd_uint_sat_add( source_offset, length )>(uint)fd_borrowed_account_get_data_len( &source_program ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Read out of bounds" );
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L170-L179 */
  uchar * data_mut = NULL;
  ulong   dlen     = 0UL;
  err = fd_borrowed_account_get_data_mut( &program, &data_mut, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  destination_offset = fd_uint_sat_add( destination_offset, LOADER_V4_PROGRAM_DATA_OFFSET );
  if( FD_UNLIKELY( fd_uint_sat_add( destination_offset, length )>(uint)dlen ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Write out of bounds" );
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  fd_memcpy( data_mut+destination_offset, data+source_offset, length );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `fd_loader_v4_program_instruction_set_program_length()` resizes an undeployed program account to the specified size.
   Initialization is taken care of when the program account size is first increased. Decreasing the size
   to 0 will close the program account. This instruction does NOT require a native CPI into the system program
   to resize the account.

   Other notes:
   - The executable status is set to true here on initialization.

   Accounts:
      0. Program account (writable)
      1. Authority account (signer)
      2. Recipient account to receive excess lamports from rent when decreasing account size (writable)
         - This account is only required when the program account size is being decreased (new_size < program dlen).

   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L183-L274 */
static int
fd_loader_v4_program_instruction_set_program_length( fd_exec_instr_ctx_t *                                         instr_ctx,
                                                     fd_loader_v4_program_instruction_set_program_length_t const * set_program_length ) {
  int  err;
  uint new_size = set_program_length->new_size;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L190 */
  fd_guarded_borrowed_account_t program;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 0UL, &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L191-L193 */
  fd_pubkey_t const * authority_address = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( instr_ctx, 1UL, &authority_address );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L194-L195 */
  uchar is_initialization = !!( fd_borrowed_account_get_data_len( &program )<LOADER_V4_PROGRAM_DATA_OFFSET );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L196-L220 */
  if( is_initialization ) {
    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L197-L200 */
    if( FD_UNLIKELY( memcmp( fd_borrowed_account_get_owner( &program ), fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Program not owned by loader" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L201-L204 */
    if( FD_UNLIKELY( !fd_borrowed_account_is_writable( &program ) ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Program is not writeable" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L205-L208 */
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 1UL ) ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Authority did not sign" );
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
  } else {
    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L210-L215 */
    fd_loader_v4_state_t const * state = check_program_account( instr_ctx, &program, authority_address, &err );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L216-L219 */
    if(  FD_UNLIKELY( !fd_loader_v4_status_is_retracted( state ) ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Program is not retracted" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L221-L227 */
  fd_rent_t rent_;
  fd_rent_t const * rent = fd_sysvar_cache_rent_read( instr_ctx->sysvar_cache, &rent_ );
  if( FD_UNLIKELY( !rent ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  ulong new_program_dlen  = fd_ulong_sat_add( LOADER_V4_PROGRAM_DATA_OFFSET, new_size );
  ulong required_lamports = ( new_size==0UL ) ?
                              0UL :
                              fd_ulong_max( fd_rent_exempt_minimum_balance( rent, new_program_dlen ),
                                            1UL );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L228-L258 */
  ulong program_lamports = fd_borrowed_account_get_lamports( &program );
  if( FD_UNLIKELY( program_lamports<required_lamports ) ) {

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L229-L236 */
    fd_log_collector_printf_dangerous_max_127( instr_ctx,
      "Insufficient lamports, %lu are required", required_lamports );
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

  } else if( FD_LIKELY( program_lamports>required_lamports ) ) {

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L238-L240 */
    fd_guarded_borrowed_account_t recipient;
    int err = fd_exec_instr_ctx_try_borrow_instr_account( instr_ctx, 2UL, &recipient );

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L241-L245 */
    if( FD_LIKELY( !err ) ) {
      if( FD_UNLIKELY( !instr_ctx->instr->accounts[ 2UL ].is_writable ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Recipient is not writeable" );
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L246-L248 */
      ulong lamports_to_receive = fd_ulong_sat_sub( program_lamports, required_lamports );
      err = fd_borrowed_account_checked_sub_lamports( &program, lamports_to_receive );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
      err = fd_borrowed_account_checked_add_lamports( &recipient, lamports_to_receive );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    } else if( FD_UNLIKELY( new_size==0U ) ) {
      fd_log_collector_msg_literal( instr_ctx, "Closing a program requires a recipient account" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* recipient is dropped when it goes out of scope */
  } /* no-op for program lamports == required lamports */

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L259-L272 */
  if( new_size==0UL ) {
    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L260 */
    err = fd_borrowed_account_set_data_length( &program, 0UL );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
  } else {
    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L262-L264 */
    err = fd_borrowed_account_set_data_length( &program, new_program_dlen );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L265-L271 */
    if( is_initialization ) {
      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L266 */
      err = fd_borrowed_account_set_executable( &program, 1 );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L267 */
      uchar * data = NULL;
      ulong   dlen = 0UL;
      err = fd_borrowed_account_get_data_mut( &program, &data, &dlen );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      fd_loader_v4_state_t * state = fd_loader_v4_get_state_mut( data, dlen, &err );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L268-L270 */
      state->slot                              = 0UL;
      state->status                            = FD_LOADER_V4_STATUS_ENUM_RETRACTED;
      state->authority_address_or_next_version = *authority_address;
    }
  }

  /* program is dropped when it goes out of scope */
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `process_instruction_deploy()` will verify the ELF bytes of a program account in a `Retracted`
   state and deploy it if successful, making it ready for use. Optionally, a source buffer account
   may be provided to copy the ELF bytes from. In this case, the program data is overwritten by the
   data in the buffer account, and the buffer account is closed with some of its lamports transferred
   to the program account if needed to meet the minimum rent exemption balance. If a source program
   is provided, the source program's programdata is copied into the target program, and the source
   program is closed afterwards.

   Other notes:
   - Newly deployed programs may not be retracted/redeployed within `LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS` (750) slots.

  Accounts:
    0. Program account (writable)
    1. Authority account (signer)

   https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L274-L322 */
static int
fd_loader_v4_program_instruction_deploy( fd_exec_instr_ctx_t * instr_ctx ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L278 */
  fd_guarded_borrowed_account_t program;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 0UL, &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L279-L281 */
  fd_pubkey_t const * authority_address = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( instr_ctx, 1UL, &authority_address );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L282-L287 */
  fd_loader_v4_state_t const * state = check_program_account( instr_ctx, &program, authority_address, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L288 */
  fd_sol_sysvar_clock_t clock_;
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( instr_ctx->sysvar_cache, &clock_ );
  if( FD_UNLIKELY( !clock ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }
  ulong current_slot = clock->slot;

  /* `state->slot == 0` indicates that the program hasn't been deployed
     yet, so a cooldown check is not needed. Otherwise, a cooldown of 1
     slot is applied before being able to redeploy or retract the
     program.

      https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L293-L299 */
  if( FD_UNLIKELY( state->slot!=0UL && fd_ulong_sat_add( state->slot, LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS )>current_slot ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program was deployed recently, cooldown still in effect" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L300-L303 */
  if( FD_UNLIKELY( !fd_loader_v4_status_is_retracted( state ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Destination program is not retracted" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L305-L308 */
  ulong buffer_dlen = fd_borrowed_account_get_data_len( &program );
  if( FD_UNLIKELY( buffer_dlen<LOADER_V4_PROGRAM_DATA_OFFSET ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }
  uchar const * programdata = fd_borrowed_account_get_data( &program ) + LOADER_V4_PROGRAM_DATA_OFFSET;

  /* Our program cache is fundamentally different from Agave's. Here, they would perform verifications and
     add the program to their cache, but we only perform verifications now and defer cache population to the
     end of the slot. Since programs cannot be invoked until the next slot anyways, doing this is okay.

     https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L309-L316 */
  err = fd_deploy_program( instr_ctx, program.acct->pubkey, programdata, buffer_dlen - LOADER_V4_PROGRAM_DATA_OFFSET, instr_ctx->txn_ctx->spad );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/programs/loader-v4/src/lib.rs#L318-L321 */
  uchar * data = NULL;
  ulong   dlen = 0UL;
  err = fd_borrowed_account_get_data_mut( &program, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_loader_v4_state_t * mut_state = fd_loader_v4_get_state_mut( data, dlen, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  mut_state->slot   = current_slot;
  mut_state->status = FD_LOADER_V4_STATUS_ENUM_DELOYED;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `process_instruction_retract()` retracts a currently deployed program, making it writable
   and uninvokable. After a program is retracted, users can write and truncate data freely,
   allowing them to upgrade or close the program account.

   Other notes:
   - Newly deployed programs may not be retracted/redeployed within 1 slot.
   - When a program is retracted, the executable flag is NOT changed.

   Accounts:
    0. Program account (writable)
    1. Authority account (signer)

    https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L353-L393 */
static int
fd_loader_v4_program_instruction_retract( fd_exec_instr_ctx_t * instr_ctx ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L357 */
  fd_guarded_borrowed_account_t program;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 0UL, &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L359-L361 */
  fd_pubkey_t const * authority_address = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( instr_ctx, 1UL, &authority_address );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L362-L367 */
  fd_loader_v4_state_t const * state = check_program_account( instr_ctx, &program, authority_address, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L368 */
  fd_sol_sysvar_clock_t clock_;
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( instr_ctx->sysvar_cache, &clock_ );
  if( FD_UNLIKELY( !clock ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }
  ulong current_slot = clock->slot;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L369-L375 */
  if( FD_UNLIKELY( fd_ulong_sat_add( state->slot, LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS )>current_slot ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program was deployed recently, cooldown still in effect" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L376-L379 */
  if( FD_UNLIKELY( !fd_loader_v4_status_is_deployed( state ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program is not deployed" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* No need to update program cache - see note in `deploy` processor.
     https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L380-L391 */
  uchar * data = NULL;
  ulong   dlen = 0UL;
  err = fd_borrowed_account_get_data_mut( &program, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_loader_v4_state_t * mut_state = fd_loader_v4_get_state_mut( data, dlen, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  mut_state->status = FD_LOADER_V4_STATUS_ENUM_RETRACTED;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `process_instruction_transfer_authority()` transfers the authority of a program account.

   Accounts:
   0. Program account (writable)
   1. Current authority (signer)
   2. New authority (signer)

   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L395-L425 */
static int
fd_loader_v4_program_instruction_transfer_authority( fd_exec_instr_ctx_t * instr_ctx ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L401 */
  fd_guarded_borrowed_account_t program;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 0UL, &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L402-L404 */
  fd_pubkey_t const * authority_address = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( instr_ctx, 1UL, &authority_address );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L405-L407 */
  fd_pubkey_t const * new_authority_address = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( instr_ctx, 2UL, &new_authority_address );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L408-L413 */
  fd_loader_v4_state_t const * state = check_program_account( instr_ctx, &program, authority_address, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L414-L417 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( instr_ctx->instr, 2UL ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "New authority did not sign" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L418-L421 */
  if( FD_UNLIKELY( !memcmp( state->authority_address_or_next_version.key, new_authority_address, sizeof(fd_pubkey_t) ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "No change" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L422-L424 */
  uchar * data = NULL;
  ulong   dlen = 0UL;
  err = fd_borrowed_account_get_data_mut( &program, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_loader_v4_state_t * mut_state = fd_loader_v4_get_state_mut( data, dlen, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  mut_state->authority_address_or_next_version = *new_authority_address;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `process_instruction_finalize()` finalizes the program account, rendering it immutable.

   Other notes:
   - Users must specify a "next version" which, from my inspection, serves no functional purpose besides showing up
     as extra information on a block explorer. The next version can be itself.
   - The next version must be a program that...
    - Is not finalized
    - Has the same authority as the current program

   Accounts:
   0. Program account (writable)
   1. Authority account (signer)
   2. Next version of the program

   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L427-L470 */
static int
fd_loader_v4_program_instruction_finalize( fd_exec_instr_ctx_t * instr_ctx ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L433 */
  fd_guarded_borrowed_account_t program;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 0UL, &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L434-L436 */
  fd_pubkey_t const * authority_address = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( instr_ctx, 1UL, &authority_address );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L437-L442 */
  fd_loader_v4_state_t const * state = check_program_account( instr_ctx, &program, authority_address, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L443-L446 */
  if( FD_UNLIKELY( !fd_loader_v4_status_is_deployed( state ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Program must be deployed to be finalized" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L447 */
  fd_borrowed_account_drop( &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L448-L449 */
  fd_guarded_borrowed_account_t next_version;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK(instr_ctx, 2UL, &next_version );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L450-L453 */
  if( FD_UNLIKELY( memcmp( fd_borrowed_account_get_owner( &next_version ), fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Next version is not owned by loader" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L454 */
  fd_loader_v4_state_t const * state_of_next_version = fd_loader_v4_get_state( next_version.acct, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L455-L458 */
  if( FD_UNLIKELY( memcmp( state_of_next_version->authority_address_or_next_version.key, authority_address, sizeof(fd_pubkey_t) ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Next version has different authority" );
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L459-L462 */
  if( FD_UNLIKELY( fd_loader_v4_status_is_finalized( state_of_next_version ) ) ) {
    fd_log_collector_msg_literal( instr_ctx, "Next version is finalized" );
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L463 */
  fd_pubkey_t * address_of_next_version = next_version.acct->pubkey;

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L464 */
  fd_borrowed_account_drop( &next_version );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L465 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, 0UL, &program );

  /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L466-L469 */
  uchar * data = NULL;
  ulong   dlen = 0UL;
  err = fd_borrowed_account_get_data_mut( &program, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_loader_v4_state_t * mut_state = fd_loader_v4_get_state_mut( data, dlen, &err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  mut_state->authority_address_or_next_version = *address_of_next_version;
  mut_state->status                            = FD_LOADER_V4_STATUS_ENUM_FINALIZED;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* `process_instruction_inner()`, the entrypoint for all loader v4 instruction invocations +
   any loader v4-owned programs.

   https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L487-L549 */
int
fd_loader_v4_program_execute( fd_exec_instr_ctx_t * instr_ctx ) {
  if( FD_UNLIKELY( !FD_FEATURE_ACTIVE_BANK( instr_ctx->txn_ctx->bank, enable_loader_v4 ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  FD_SPAD_FRAME_BEGIN( instr_ctx->txn_ctx->spad ) {
    int rc = FD_EXECUTOR_INSTR_SUCCESS;

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L494 */
    fd_pubkey_t const * program_id = NULL;
    rc = fd_exec_instr_ctx_get_last_program_key( instr_ctx, &program_id );
    if( FD_UNLIKELY( rc ) ) {
      return rc;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L495-L519 */
    if( !memcmp( program_id, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L496 */
      FD_EXEC_CU_UPDATE( instr_ctx, LOADER_V4_DEFAULT_COMPUTE_UNITS );

      /* Note the dataend is capped at a 1232 bytes offset to mirror the semantics of `limited_deserialize`.
         https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L497 */

      fd_loader_v4_program_instruction_t * instruction = fd_bincode_decode_spad(
          loader_v4_program_instruction,
          instr_ctx->txn_ctx->spad,
          instr_ctx->instr->data,
          instr_ctx->instr->data_sz > FD_TXN_MTU ? FD_TXN_MTU : instr_ctx->instr->data_sz,
          NULL );
      if( FD_UNLIKELY( !instruction ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L497-L518 */
      switch( instruction->discriminant ) {
        case fd_loader_v4_program_instruction_enum_write: {
          /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L498-L500 */
          rc = fd_loader_v4_program_instruction_write( instr_ctx, &instruction->inner.write );
          break;
        }
        case fd_loader_v4_program_instruction_enum_copy: {
          /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L501-L507 */
          rc = fd_loader_v4_program_instruction_copy( instr_ctx, &instruction->inner.copy );
          break;
        }
        case fd_loader_v4_program_instruction_enum_set_program_length: {
          /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L508-L510 */
          rc = fd_loader_v4_program_instruction_set_program_length( instr_ctx, &instruction->inner.set_program_length );
          break;
        }
        case fd_loader_v4_program_instruction_enum_deploy: {
          /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L511 */
          rc = fd_loader_v4_program_instruction_deploy( instr_ctx );
          break;
        }
        case fd_loader_v4_program_instruction_enum_retract: {
          /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L512 */
          rc = fd_loader_v4_program_instruction_retract( instr_ctx );
          break;
        }
        case fd_loader_v4_program_instruction_enum_transfer_authority: {
          /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L513-L515 */
          rc = fd_loader_v4_program_instruction_transfer_authority( instr_ctx );
          break;
        }
        case fd_loader_v4_program_instruction_enum_finalize: {
          /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L516 */
          rc = fd_loader_v4_program_instruction_finalize( instr_ctx );
          break;
        }
      }
    } else {
      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L520 */
      fd_guarded_borrowed_account_t program;
      rc = fd_exec_instr_ctx_try_borrow_last_program_account( instr_ctx, &program );
      if( FD_UNLIKELY( rc ) ) {
        return rc;
      }

      /* See note in `fd_bpf_loader_program_execute()` as to why we must tie the cache into consensus :(
         https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L522-L528 */
      fd_program_cache_entry_t const * cache_entry = NULL;
      if( FD_UNLIKELY( fd_program_cache_load_entry( instr_ctx->txn_ctx->funk,
                                                    instr_ctx->txn_ctx->xid,
                                                    program_id,
                                                    &cache_entry )!=0 ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program is not cached" );
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      }

      /* The program may be in the cache but could have failed verification in the current epoch. */
      if( FD_UNLIKELY( cache_entry->failed_verification ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program is not deployed" );
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      }

      /* After the program is deployed, we wait a slot before adding it to our program cache. Agave, on the other hand,
         updates their program cache after every transaction. Because of this, for a program that was deployed in the
         current slot, Agave would log "Program is not deployed", while we would log "Program is not cached" since
         the program is not in the cache yet. The same thing holds for very old programs that fail ELF / VM validation
         checks and are thus non-invokable - if this program was invoked, Agave would keep it in their program cache and label
         it as "FailedVerification", while we would not include it at all.

         Because of the difference in our caching behavior, we need to perform checks that will filter out every single program
         from execution that Agave would. In Agave's `load_program_accounts()` function, they filter any retracted programs ("Closed")
         and mark any programs deployed in the current slot as "DelayedVisibility". Any programs that fail verification will also
         not be in the cache anyways. */

      fd_loader_v4_state_t const * state = fd_loader_v4_get_state( program.acct, &rc );
      if( FD_UNLIKELY( rc ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program is not deployed" );
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      }

      if( FD_UNLIKELY( fd_loader_v4_status_is_retracted( state ) ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program is not deployed" );
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      }

      /* Handle `DelayedVisibility` case */
      if( FD_UNLIKELY( state->slot>=instr_ctx->txn_ctx->slot ) ) {
        fd_log_collector_msg_literal( instr_ctx, "Program is not deployed" );
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L531 */
      fd_borrowed_account_drop( &program );

      /* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L542 */
      rc = fd_bpf_execute( instr_ctx, cache_entry, 0 );
    }

    return rc;
  } FD_SPAD_FRAME_END;
}
