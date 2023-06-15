#include "fd_bpf_upgradeable_loader_program.h"

#include "../../base58/fd_base58.h"

int read_bpf_upgradeable_loader_state( fd_global_ctx_t* global, fd_pubkey_t* program_acc, fd_bpf_upgradeable_loader_state_t * result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, program_acc, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  unsigned char *raw_acc_data = fd_alloca_check( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, program_acc, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata.dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;
  if ( fd_bpf_upgradeable_loader_state_decode( result, &ctx ) ) {
    FD_LOG_WARNING(("fd_bpf_upgradeable_loader_state_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_ACC_MGR_SUCCESS;

  return 0;
}

int write_bpf_upgradeable_loader_state(
    fd_global_ctx_t* global,
    fd_pubkey_t* program_acc,
    fd_bpf_upgradeable_loader_state_t * loader_state
) {
    fd_account_meta_t metadata;
    int read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, program_acc, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }

    ulong encoded_loader_state_size = fd_bpf_upgradeable_loader_state_size( loader_state );
    ulong stored_loader_state_size = (metadata.dlen > encoded_loader_state_size) 
        ? metadata.dlen
        : encoded_loader_state_size;
    uchar* encoded_loader_state = (uchar *)(global->allocf)( global->allocf_arg, 8UL, encoded_loader_state_size );

    fd_bincode_encode_ctx_t ctx;
    ctx.data = encoded_loader_state;
    ctx.dataend = encoded_loader_state + encoded_loader_state_size;
    if ( fd_bpf_upgradeable_loader_state_encode( loader_state, &ctx ) ) {
      FD_LOG_ERR(("fd_bpf_upgradeable_loader_state_encode failed"));
      fd_memset( encoded_loader_state, 0, encoded_loader_state_size );
    }

    fd_solana_account_t structured_account;
    structured_account.data = encoded_loader_state;
    structured_account.data_len = encoded_loader_state_size;
    structured_account.executable = 0;
    structured_account.rent_epoch = 0;
    memcpy( &structured_account.owner, global->solana_stake_program, sizeof(fd_pubkey_t) );

    int write_result = fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.solana_bank.slot, program_acc, &structured_account );
    if ( write_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write account data" ));
      return write_result;
    }
    fd_acc_mgr_update_hash ( global->acc_mgr, &metadata, global->funk_txn, global->bank.solana_bank.slot, program_acc, (uchar*)encoded_loader_state, stored_loader_state_size );

    return FD_EXECUTOR_INSTR_SUCCESS;
}


int fd_executor_bpf_upgradeable_loader_program_execute_instruction( instruction_ctx_t ctx ) {
  /* Deserialize the Stake instruction */
  uchar * data            = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off;

  fd_bpf_upgradeable_loader_program_instruction_t instruction;
  fd_bpf_upgradeable_loader_program_instruction_new( &instruction );
  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data = data;
  decode_ctx.dataend = &data[ctx.instr->data_sz];
  decode_ctx.allocf = ctx.global->allocf;
  decode_ctx.allocf_arg = ctx.global->allocf_arg;

  int decode_err;
  if ( ( decode_err = fd_bpf_upgradeable_loader_program_instruction_decode( &instruction, &decode_ctx ) ) ) {
    FD_LOG_WARNING(("fd_bpf_upgradeable_loader_program_instruction_decode failed: err code: %d, %d %x", decode_err, ctx.instr->data_sz, ((uint*)data)[0]));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  uchar* instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t* txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

  if( fd_bpf_upgradeable_loader_program_instruction_is_initialize_buffer( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_bpf_upgradeable_loader_state_t loader_state;
    fd_pubkey_t * buffer_acc = &txn_accs[instr_acc_idxs[0]];

    read_bpf_upgradeable_loader_state( ctx.global, buffer_acc, &loader_state );

    if( !fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[1]];
    loader_state.discriminant = fd_bpf_upgradeable_loader_state_enum_buffer;
    loader_state.inner.buffer.authority_address = authority_acc;

    write_bpf_upgradeable_loader_state( ctx.global, buffer_acc, &loader_state );

    return FD_EXECUTOR_INSTR_SUCCESS;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_write( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    // FIXME: Do we need to check writable?

    fd_pubkey_t * buffer_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[1]];

    fd_bpf_upgradeable_loader_state_t loader_state;
    read_bpf_upgradeable_loader_state( ctx.global, buffer_acc, &loader_state );

    if( !fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if( loader_state.inner.buffer.authority_address==NULL ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
    }

    if( memcmp( authority_acc, loader_state.inner.buffer.authority_address, sizeof(fd_pubkey_t) )!=0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if(instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    
    fd_account_meta_t buffer_acc_metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, &buffer_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    ulong offset = fd_ulong_sat_add(fd_bpf_upgradeable_loader_state_size( &loader_state ), instruction.inner.write.offset);
    ulong write_end = fd_ulong_sat_add( offset, instruction.inner.write.bytes_len );
    if( buffer_acc_metadata.dlen < write_end ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    /* Read the current data in the account */
    uchar * buffer_acc_data = (uchar *)(ctx.global->allocf)(ctx.global->allocf_arg, 8UL, buffer_acc_metadata.dlen);
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, (uchar*)buffer_acc_data, sizeof(fd_account_meta_t), buffer_acc_metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    fd_memcpy( buffer_acc_data + offset, instruction.inner.write.bytes, instruction.inner.write.bytes_len );

    int write_result = fd_acc_mgr_write_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, buffer_acc, &buffer_acc_metadata, sizeof(buffer_acc_metadata), buffer_acc_data, buffer_acc_metadata.dlen, 0 );
    if ( write_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write account data" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    fd_acc_mgr_update_hash ( ctx.global->acc_mgr, &buffer_acc_metadata, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, buffer_acc, buffer_acc_data, buffer_acc_metadata.dlen );

    return FD_EXECUTOR_INSTR_SUCCESS;

  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_deploy_with_max_data_len( &instruction ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_upgrade( &instruction ) ) {
    if( ctx.instr->acct_cnt < 7 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t * programdata_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * program_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t * buffer_acc = &txn_accs[instr_acc_idxs[2]];
    fd_pubkey_t * rent_acc = &txn_accs[instr_acc_idxs[4]];
    fd_pubkey_t * clock_acc = &txn_accs[instr_acc_idxs[5]];
    fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[6]];

    fd_account_meta_t program_acc_metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, program_acc, &program_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    // Is program executable?
    if( !program_acc_metadata.info.executable ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE;
    }

    // Is program writable?
    if( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[1] ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    // Is program owner the BPF upgradeable loader?
    if ( memcmp( program_acc_metadata.info.owner, ctx.global->solana_bpf_loader_upgradeable_program_with_jit, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    fd_bpf_upgradeable_loader_state_t program_acc_loader_state;
    read_result = read_bpf_upgradeable_loader_state( ctx.global, program_acc, &program_acc_loader_state );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }

    if( !fd_bpf_upgradeable_loader_state_is_program( &program_acc_loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    
    if( memcmp( &program_acc_loader_state.inner.program.programdata_address, programdata_acc, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_bpf_upgradeable_loader_state_t buffer_acc_loader_state;
    read_result = read_bpf_upgradeable_loader_state( ctx.global, buffer_acc, &buffer_acc_loader_state );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }
    if( !fd_bpf_upgradeable_loader_state_is_buffer( &buffer_acc_loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

        char addr[100];
        char addr2[100];
        char addr3[100];

    fd_base58_encode_32((uchar*) authority_acc, NULL, addr);
    fd_base58_encode_32((uchar*) &buffer_acc_loader_state.inner.buffer.authority_address, NULL, addr2);
    fd_base58_encode_32((uchar*) &txn_accs[instr_acc_idxs[6]], NULL, addr3);

    FD_LOG_WARNING(( "XXX: %s", addr));
    FD_LOG_WARNING(( "XXX2: %s", addr2));
    FD_LOG_WARNING(( "XXX3: %s", addr3));

    if( memcmp( &buffer_acc_loader_state.inner.buffer.authority_address, authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
    }

    if( instr_acc_idxs[6] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    (void)clock_acc;
    (void)rent_acc;

    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_set_authority( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t * new_authority_acc = NULL;
    if( ctx.instr->acct_cnt >= 3 ) {
      new_authority_acc = &txn_accs[instr_acc_idxs[2]];
    }

    fd_pubkey_t * loader_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * present_authority_acc = &txn_accs[instr_acc_idxs[1]];

    fd_bpf_upgradeable_loader_state_t loader_state;
    // FIXME: HANDLE ERRORS!
    read_bpf_upgradeable_loader_state( ctx.global, loader_acc, &loader_state );

    if( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( new_authority_acc==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if( loader_state.inner.buffer.authority_address==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if ( memcmp( loader_state.inner.buffer.authority_address, present_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if(instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      loader_state.inner.buffer.authority_address = new_authority_acc;
      write_bpf_upgradeable_loader_state( ctx.global, loader_acc, &loader_state );

      return FD_EXECUTOR_INSTR_SUCCESS;
    } else if( fd_bpf_upgradeable_loader_state_is_program_data( &loader_state ) ) {
      if( loader_state.inner.program_data.upgrade_authority_address==NULL ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      }

      if ( memcmp( loader_state.inner.program_data.upgrade_authority_address, present_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
      }

      if(instr_acc_idxs[1] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      loader_state.inner.program_data.upgrade_authority_address = new_authority_acc;

      write_bpf_upgradeable_loader_state( ctx.global, loader_acc, &loader_state );

      return FD_EXECUTOR_INSTR_SUCCESS;
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_close( &instruction ) ) {
    if( ctx.instr->acct_cnt < 2 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t * close_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * recipient_acc = &txn_accs[instr_acc_idxs[1]];

    if ( memcmp( close_acc, recipient_acc, sizeof(fd_pubkey_t) )==0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_bpf_upgradeable_loader_state_t loader_state;
    read_bpf_upgradeable_loader_state( ctx.global, close_acc, &loader_state );

    if( fd_bpf_upgradeable_loader_state_is_uninitialized( &loader_state ) ) {
      fd_account_meta_t close_acc_metadata;
      fd_account_meta_t recipient_acc_metdata;

      int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, close_acc, &close_acc_metadata );
      if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, recipient_acc, &recipient_acc_metdata );
      if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to read account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      // FIXME: Do checked addition
      recipient_acc_metdata.info.lamports += close_acc_metadata.info.lamports;
      close_acc_metadata.info.lamports = 0;

      int write_result = fd_acc_mgr_set_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, close_acc, &close_acc_metadata );
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to write account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }

      write_result = fd_acc_mgr_set_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, recipient_acc, &recipient_acc_metdata );
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to write account metadata" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }

      return FD_EXECUTOR_INSTR_SUCCESS;
    } else if ( fd_bpf_upgradeable_loader_state_is_buffer( &loader_state ) ) {
      if( ctx.instr->acct_cnt < 3 ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
    
      fd_pubkey_t * authority_acc = &txn_accs[instr_acc_idxs[2]];

      (void)authority_acc;
    } else if( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } else if ( fd_bpf_upgradeable_loader_program_instruction_is_extend_program( &instruction ) ) {
   

    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } else {
    FD_LOG_WARNING(( "unsupported bpf upgradeable loader program instruction: discriminant: %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
}