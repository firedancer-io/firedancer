#include "fd_bpf_loader_serialization.h"
#include "../fd_account.h"


/**
 * num accounts
 * serialized accounts
 * instr data len
 * instr data
 * program id public key
*/
// 64-bit aligned
uchar *
fd_bpf_loader_input_serialize_aligned( fd_exec_instr_ctx_t ctx, ulong * sz, ulong * pre_lens ) {
  ulong serialized_size = 0;
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;

  uchar acc_idx_seen[256];
  ushort dup_acc_idx[256];
  memset(acc_idx_seen, 0, sizeof(acc_idx_seen));
  memset(dup_acc_idx, 0, sizeof(dup_acc_idx));

  serialized_size += sizeof(ulong);
  for( ushort i = 0; i < ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];

  // fd_pubkey_t * acc = &txn_accs[acc_idx];
  // FD_LOG_WARNING(( "START OF ACC: %32J %x %lu", acc, serialized_size, serialized_size ));

    serialized_size++; // dup byte
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      serialized_size += 7; // pad to 64-bit alignment
    } else {
      acc_idx_seen[acc_idx] = 1;
      dup_acc_idx[acc_idx] = i;
      fd_pubkey_t * acc = &txn_accs[acc_idx];
      fd_borrowed_account_t * view_acc = NULL;
      int read_result = fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
      fd_account_meta_t const * metadata = view_acc->const_meta;

      ulong acc_data_len = 0;
      if ( FD_LIKELY( read_result == FD_ACC_MGR_SUCCESS ) ) {
        acc_data_len = metadata->dlen;
      } else if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
        acc_data_len = 0;
      } else {
        FD_LOG_DEBUG(( "failed to read account data - pubkey: %32J, err: %d", acc, read_result ));
        return NULL;
      }

      ulong aligned_acc_data_len = fd_ulong_align_up(acc_data_len, 8);

      serialized_size += sizeof(uchar)  // is_signer
          + sizeof(uchar)               // is_writable
          + sizeof(uchar)               // is_executable
          + sizeof(uint)                // original_data_len
          + sizeof(fd_pubkey_t)         // key
          + sizeof(fd_pubkey_t)         // owner
          + sizeof(ulong)               // lamports
          + sizeof(ulong)               // data_len
          + aligned_acc_data_len
          + MAX_PERMITTED_DATA_INCREASE
          + sizeof(ulong);              // rent_epoch
    }
  }

  serialized_size += sizeof(ulong)
      + ctx.instr->data_sz
      + sizeof(fd_pubkey_t);
  uchar * serialized_params = fd_valloc_malloc( ctx.valloc, 8UL, serialized_size );
  uchar * serialized_params_start = serialized_params;

  FD_STORE( ulong, serialized_params, ctx.instr->acct_cnt );
  serialized_params += sizeof(ulong);

  for( ushort i = 0; i < ctx.instr->acct_cnt; i++ ) {
    // FD_LOG_DEBUG(( "SERIAL OF ACC: %x %lu", serialized_params - serialized_params_start, serialized_params-serialized_params_start ));
    uchar acc_idx = instr_acc_idxs[i];
    fd_pubkey_t * acc = &txn_accs[acc_idx];

    // FD_LOG_DEBUG(( "SERIAL OF ACC2: %lu, %lu, %32J %x %lu", i, acc_idx, acc, serialized_params - serialized_params_start, serialized_params-serialized_params_start ));

    if( FD_UNLIKELY( acc_idx_seen[acc_idx] && dup_acc_idx[acc_idx] != i ) ) {
      // Duplicate
      FD_STORE( ulong, serialized_params, 0 );
      FD_STORE( uchar, serialized_params, (uchar)dup_acc_idx[acc_idx] );
      serialized_params += sizeof(ulong);
    } else {
      FD_STORE( uchar, serialized_params, 0xFF );
      serialized_params += sizeof(uchar);

      fd_borrowed_account_t * view_acc = NULL;
      int read_result = fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
      if (FD_UNLIKELY(read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT)) {
        // FD_LOG_DEBUG(( "SERIAL OF ACC4: %32J UNK", acc ));

        uchar is_signer = (uchar)fd_instr_acc_is_signer_idx( ctx.instr, (uchar)i );
        FD_STORE( uchar, serialized_params, is_signer );
        serialized_params += sizeof(uchar);

        uchar is_writable = (uchar)fd_instr_acc_is_writable_idx( ctx.instr, (uchar)i );
        FD_STORE( uchar, serialized_params, is_writable );
        serialized_params += sizeof(uchar);

        fd_memset( serialized_params, 0,
          sizeof(uchar)                                 // is_executable
          + sizeof(uint));                                // original_data_len

        serialized_params +=
          sizeof(uchar)                     // is_executable
          + sizeof(uint);                     // original_data_len

        fd_pubkey_t key = *acc;
        FD_STORE( fd_pubkey_t, serialized_params, key );
        serialized_params += sizeof(fd_pubkey_t);

        fd_memset( serialized_params, 0, sizeof(fd_pubkey_t)  // owner
          + sizeof(ulong)                                       // lamports
          + sizeof(ulong)                                       // data_len
          + 0                                                   // data
          + MAX_PERMITTED_DATA_INCREASE
          + sizeof(ulong));                                     // rent_epoch
        serialized_params += sizeof(fd_pubkey_t)  // owner
          + sizeof(ulong)                           // lamports
          + sizeof(ulong)                           // data_len
          + 0                                       // data
          + MAX_PERMITTED_DATA_INCREASE;
        if (FD_FEATURE_ACTIVE( ctx.slot_ctx, set_exempt_rent_epoch_max)) {
          FD_STORE( ulong, serialized_params, ULONG_MAX );
        }
        serialized_params += sizeof(ulong);                     // rent_epoch
        pre_lens[i] = 0;
        continue;
      } else if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_DEBUG(( "failed to read account data - pubkey: %32J, err: %d", acc, read_result ));
        return NULL;
      }

      fd_account_meta_t const * metadata = view_acc->const_meta;
      uchar const * acc_data             = view_acc->const_data;

      // FD_LOG_DEBUG(( "SERIAL OF ACC3: pubkey: %32J, acc, flags: 0x%x, %lu %lu %lu", acc, ctx.instr->acct_flags[i], serialized_params - serialized_params_start, serialized_params-serialized_params_start, metadata->dlen ));

      uchar is_signer = (uchar)fd_instr_acc_is_signer_idx( ctx.instr, (uchar)i );
      FD_STORE( uchar, serialized_params, is_signer );
      serialized_params += sizeof(uchar);

      uchar is_writable = (uchar)(fd_instr_acc_is_writable_idx( ctx.instr, (uchar)i ) && !fd_pubkey_is_sysvar_id( acc ) && !fd_pubkey_is_builtin_program( acc ));
      FD_STORE( uchar, serialized_params, is_writable );
      serialized_params += sizeof(uchar);

      uchar is_executable = (uchar)metadata->info.executable;
      FD_STORE( uchar, serialized_params, is_executable );
      serialized_params += sizeof(uchar);

      uint padding_0 = 0;
      FD_STORE( uint, serialized_params, padding_0 );
      serialized_params += sizeof(uint);

      fd_pubkey_t key = *acc;
      FD_STORE( fd_pubkey_t, serialized_params, key );
      serialized_params += sizeof(fd_pubkey_t);

      fd_pubkey_t owner = *(fd_pubkey_t *)&metadata->info.owner;
      FD_STORE( fd_pubkey_t, serialized_params, owner );
      serialized_params += sizeof(fd_pubkey_t);

      ulong lamports = metadata->info.lamports;
      FD_STORE( ulong, serialized_params, lamports );
      serialized_params += sizeof(ulong);
      FD_LOG_DEBUG(("Serialize lamports %lu for %32J", lamports, acc->uc));

      ulong acc_data_len = metadata->dlen;
      pre_lens[i] = acc_data_len;
      ulong aligned_acc_data_len = fd_ulong_align_up(acc_data_len, 8);
      ulong alignment_padding_len = aligned_acc_data_len - acc_data_len;

      ulong data_len = acc_data_len;
      FD_STORE( ulong, serialized_params, data_len );
      serialized_params += sizeof(ulong);

      fd_memcpy( serialized_params, acc_data, acc_data_len);
      serialized_params += acc_data_len;

      fd_memset( serialized_params, 0, MAX_PERMITTED_DATA_INCREASE + alignment_padding_len);
      serialized_params += MAX_PERMITTED_DATA_INCREASE + alignment_padding_len;

      ulong rent_epoch = metadata->info.rent_epoch;
      FD_STORE( ulong, serialized_params, rent_epoch );
      serialized_params += sizeof(ulong);
    }

  }

  ulong instr_data_len = ctx.instr->data_sz;
  FD_STORE( ulong, serialized_params, instr_data_len );
  serialized_params += sizeof(ulong);

  uchar * instr_data = ctx.instr->data;
  fd_memcpy( serialized_params, instr_data, instr_data_len );
  serialized_params += instr_data_len;

  FD_STORE( fd_pubkey_t, serialized_params, txn_accs[ctx.instr->program_id] );
  serialized_params += sizeof(fd_pubkey_t);
  FD_TEST( serialized_params == serialized_params_start + serialized_size );

  // FD_LOG_DEBUG(( "SERIALIZE - sz: %lu, diff: %lu", serialized_size, serialized_params - serialized_params_start ));
  *sz = serialized_size;

  return serialized_params_start;
}

int
fd_bpf_loader_input_deserialize_aligned( fd_exec_instr_ctx_t ctx,
                                         ulong const * pre_lens,
                                         uchar * input,
                                         ulong input_sz ) {
  uchar * input_cursor = input;

  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, sizeof(acc_idx_seen));

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs =  ctx.txn_ctx->accounts;

  input_cursor += sizeof(ulong);
  for( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];
    fd_pubkey_t * acc = &txn_accs[instr_acc_idxs[i]];
    // FD_LOG_DEBUG(( "DESERIAL OF ACC: %lu, %lu, %32J %x %lu", i, acc_idx, acc, input_cursor - input, input_cursor-input ));
    input_cursor++;
    fd_borrowed_account_t * view_acc = NULL;
    int view_err = fd_instr_borrowed_account_view(&ctx, acc, &view_acc);
    if ( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      input_cursor += 7;
    } else if ( fd_instr_acc_is_writable_idx(ctx.instr, (uchar)i) && !fd_pubkey_is_sysvar_id( acc ) ) {

      acc_idx_seen[acc_idx] = 1;
      input_cursor += sizeof(uchar) // is_signer
          + sizeof(uchar)           // is_writable
          + sizeof(uchar)           // executable
          + sizeof(uint)            // original_data_len
          + sizeof(fd_pubkey_t);    // key

      if ( view_acc->const_meta ) {
        if (view_acc->const_meta->info.executable && memcmp( view_acc->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0) {
          // no-op
        } else if (view_acc->const_meta->info.executable) {
          input_cursor += sizeof(fd_pubkey_t);  // owner
          input_cursor += sizeof(ulong);        // lamports
          input_cursor += sizeof(ulong);        // data_len

          fd_account_meta_t const * metadata = view_acc->const_meta;

          if ( view_err == FD_ACC_MGR_SUCCESS ) {
            input_cursor += fd_ulong_align_up(metadata->dlen, 8);
          }
          input_cursor += MAX_PERMITTED_DATA_INCREASE;

          input_cursor += sizeof(ulong);
          continue;
        }
      }


      fd_pubkey_t * owner = (fd_pubkey_t *)input_cursor;
      input_cursor += sizeof(fd_pubkey_t);

      ulong lamports = FD_LOAD(ulong, input_cursor);
      // FD_LOG_DEBUG(("Deserialize lamports %lu for account %32J", lamports, acc->uc));
      input_cursor += sizeof(ulong);

      ulong post_data_len = FD_LOAD(ulong, input_cursor);
      input_cursor += sizeof(ulong);

      uchar * post_data = input_cursor;

      ulong acc_sz = post_data_len;

      // fd_borrowed_account_t * view_acc = NULL;
      // int view_err = fd_instr_borrowed_account_view(&ctx, acc, &view_acc);

      if (FD_LIKELY(view_acc->const_meta != NULL)) {
        fd_account_meta_t const * metadata_check = view_acc->const_meta;
        // FD_LOG_DEBUG(("dlen %lu post data len %lu owner %32J for %32J", metadata_check->dlen, post_data_len, metadata_check->info.owner, acc->uc));
        if ( fd_ulong_sat_sub( post_data_len, metadata_check->dlen ) > MAX_PERMITTED_DATA_INCREASE || post_data_len > MAX_PERMITTED_DATA_LENGTH ) {
          fd_valloc_free( ctx.valloc, input ); // FIXME: need to return an invalid realloc error
          return -1;
        }

        fd_borrowed_account_t * modify_acc = NULL;
        int modify_err = fd_instr_borrowed_account_modify(&ctx, acc, acc_sz, &modify_acc);
        if ( modify_err != FD_ACC_MGR_SUCCESS ) {
          fd_valloc_free( ctx.valloc, input );
          return -1;
        }
        fd_account_meta_t * metadata = (fd_account_meta_t *)modify_acc->meta;

        ulong pre_len = pre_lens[i];

        uchar * acc_data = fd_account_get_data( metadata );
        input_cursor += fd_ulong_align_up( pre_len, 8 );

        int err1;
        int err2;
        if (fd_account_can_data_be_resized(&ctx, metadata, post_data_len, &err1)
            && fd_account_can_data_be_changed(&ctx, metadata, acc, &err2)) {
          metadata->dlen = post_data_len;
          fd_memcpy( acc_data, post_data, post_data_len );
        } else if (metadata->dlen != post_data_len || memcmp(acc_data, post_data, post_data_len) != 0) {
          FD_LOG_DEBUG(("Data resize failed"));
          fd_valloc_free( ctx.valloc, input );  // FIXME: need to return an invalid realloc error
          return -1;
        }

        metadata->info.lamports = lamports;
        // if (memcmp(metadata->info.owner, owner, sizeof(fd_pubkey_t)) != 0) {
        //   fd_account_set_owner(&ctx, metadata, acc, owner);
        // }
        fd_memcpy(metadata->info.owner, owner, sizeof(fd_pubkey_t));

        // add to dirty list
        metadata->slot = ctx.slot_ctx->slot_bank.slot;
        // FD_LOG_DEBUG(("Deserialize success %32J", acc->uc));
      } else if ( view_err == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
        // no-op
        input_cursor += fd_ulong_align_up( pre_lens[i], 8 );
        // FD_LOG_DEBUG(("Account %32J unknown", acc->uc));
      } else {
        input_cursor += fd_ulong_align_up( pre_lens[i], 8 );
        // FD_LOG_DEBUG(("Account %32J not found in deserialize", acc->uc));
      }

      input_cursor += MAX_PERMITTED_DATA_INCREASE;

      input_cursor += sizeof(ulong);
    } else {
      acc_idx_seen[acc_idx] = 1;
      // Account is not writable, skip over
      input_cursor += sizeof(uchar)         // is_signer
          + sizeof(uchar)                   // is_writable
          + sizeof(uchar)                   // executable
          + sizeof(uint)                    // original_data_len
          + sizeof(fd_pubkey_t);            // key
      input_cursor += sizeof(fd_pubkey_t);  // owner
      input_cursor += sizeof(ulong);        // lamports
      input_cursor += sizeof(ulong);        // data_len

      // fd_borrowed_account_t * view_acc = NULL;
      // int view_err = fd_instr_borrowed_account_view(&ctx, acc, &view_acc);
      fd_account_meta_t const * metadata = view_acc->const_meta;

      if ( view_err == FD_ACC_MGR_SUCCESS ) {
        input_cursor += fd_ulong_align_up(metadata->dlen, 8);
      }
      input_cursor += MAX_PERMITTED_DATA_INCREASE;

      input_cursor += sizeof(ulong);
    }
  }

  FD_TEST( input_cursor <= input + input_sz );

  fd_valloc_free( ctx.valloc, input );

  return 0;
}

uchar *
fd_bpf_loader_input_serialize_unaligned( fd_exec_instr_ctx_t ctx,
                                         ulong * sz,
                                         ulong * pre_lens ) {
  ulong serialized_size = 0;
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs = ctx.txn_ctx->accounts;

  uchar acc_idx_seen[256];
  ushort dup_acc_idx[256];
  memset(acc_idx_seen, 0, sizeof(acc_idx_seen));
  memset(dup_acc_idx, 0, sizeof(dup_acc_idx));

  serialized_size += sizeof(ulong);
  for( ushort i = 0; i < ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];

    // fd_pubkey_t * acc = &txn_accs[acc_idx];
    // FD_LOG_DEBUG(( "START OF ACC: %32J %x", acc, serialized_size ));

    serialized_size++; // dup byte
    if( FD_LIKELY( !acc_idx_seen[acc_idx] ) ) {
      acc_idx_seen[acc_idx] = 1;
      dup_acc_idx[acc_idx] = i;

      fd_pubkey_t const * acc = &txn_accs[acc_idx];
      fd_borrowed_account_t * view_acc = NULL;
      int read_result = fd_instr_borrowed_account_view(&ctx, acc, &view_acc);
      fd_account_meta_t const * metadata = view_acc->const_meta;
      // FD_LOG_DEBUG(( "START OF ACC 2: %d %d %d %d", !fd_account_is_sysvar( &ctx, acc ), fd_account_is_writable_idx(&ctx, i), i, instr_acc_idxs[i]));

      ulong acc_data_len = 0;
      if ( FD_LIKELY( read_result == FD_ACC_MGR_SUCCESS ) ) {
        acc_data_len = metadata->dlen;
      } else if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
        // FD_LOG_DEBUG(( "START OF ACC 3: %d %d %d %d", !fd_account_is_sysvar( &ctx, acc ), fd_account_is_writable_idx(&ctx, i), i, instr_acc_idxs[i]));
        acc_data_len = 0;
      } else {
        FD_LOG_DEBUG(( "failed to read account data - pubkey: %32J, err: %d", acc, read_result ));
        return NULL;
      }

      pre_lens[i] = acc_data_len;

      serialized_size += sizeof(uchar)  // is_signer
          + sizeof(uchar)               // is_writable
          + sizeof(fd_pubkey_t)         // key
          + sizeof(ulong)               // lamports
          + sizeof(ulong)               // data_len
          + acc_data_len
          + sizeof(fd_pubkey_t)         // owner
          + sizeof(uchar)               // is_executable
          + sizeof(ulong);              // rent_epoch
    }
  }

  serialized_size += sizeof(ulong)
      + ctx.instr->data_sz
      + sizeof(fd_pubkey_t);

  uchar * serialized_params = fd_valloc_malloc( ctx.valloc, 1UL, serialized_size);
  uchar * serialized_params_start = serialized_params;

  FD_STORE( ulong, serialized_params, ctx.instr->acct_cnt );
  serialized_params += sizeof(ulong);

  for( ulong i = 0; i < ctx.txn_ctx->accounts_cnt; i++ ) {
    // FD_LOG_DEBUG(( "TXN ACC: %3lu - %32J %lu", i, &txn_accs[i], fd_account_is_writable_idx( ctx.txn_ctx->txn_descriptor,  ctx.txn_ctx->accounts, ctx.instr->program_id, (int)i ) ) );
  }
  for( ushort i = 0; i < ctx.instr->acct_cnt; i++ ) {
    // FD_LOG_DEBUG(( "SERIAL OF ACC: %x %lu", serialized_params - serialized_params_start, serialized_params-serialized_params_start ));
    uchar acc_idx = instr_acc_idxs[i];
    fd_pubkey_t const * acc = &txn_accs[acc_idx];

    // FD_LOG_DEBUG(( "SERIAL OF ACC2: %lu, %lu, %32J %x %lu", i, acc_idx, acc, serialized_params - serialized_params_start, serialized_params-serialized_params_start ));

    if( FD_UNLIKELY( acc_idx_seen[acc_idx] && dup_acc_idx[acc_idx] != i ) ) {
      // Duplicate
      FD_STORE( uchar, serialized_params, (uchar)dup_acc_idx[acc_idx] );
      serialized_params += sizeof(uchar);
    } else {
      FD_STORE( uchar, serialized_params, 0xFF );
      serialized_params += sizeof(uchar);

      fd_borrowed_account_t * view_acc = NULL;
      int read_result = fd_instr_borrowed_account_view(&ctx, acc, &view_acc);
      if (FD_UNLIKELY(!fd_acc_exists(view_acc->const_meta))) {
          FD_LOG_DEBUG(( "SERIAL OF ACC4: %32J UNK", acc ));

          fd_memset( serialized_params, 0, sizeof(uchar)  // is_signer
          + sizeof(uchar));              // is_writable

          serialized_params += sizeof(uchar)  // is_signer
          + sizeof(uchar);               // is_writable

          fd_pubkey_t key = *acc;
          FD_STORE( fd_pubkey_t, serialized_params, key );
          serialized_params += sizeof(fd_pubkey_t);

          fd_memset( serialized_params, 0, sizeof(ulong)               // lamports
          + sizeof(ulong)               // data_len
          + 0
          + sizeof(fd_pubkey_t)         // owner
          + sizeof(uchar)               // is_executable
          + sizeof(ulong));              // rent_epoch
          serialized_params += sizeof(ulong)               // lamports
          + sizeof(ulong)               // data_len
          + 0
          + sizeof(fd_pubkey_t)         // owner
          + sizeof(uchar)               // is_executable
          + sizeof(ulong);              // rent_epoch

          // FIXME: rent epoch = ULONG_MAX for active feature
        continue;
      } else if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_DEBUG(( "failed to read account data - pubkey: %32J, err: %d", acc, read_result ));
        return NULL;
      }
      fd_account_meta_t const * metadata = view_acc->const_meta;
      uchar const * acc_data             = view_acc->const_data;

      uchar is_signer = (uchar)fd_instr_acc_is_signer_idx( ctx.instr, (uchar)i );
      FD_STORE( uchar, serialized_params, is_signer );
      serialized_params += sizeof(uchar);

      uchar is_writable = (uchar)(fd_instr_acc_is_writable_idx( ctx.instr, (uchar)i ) && !fd_pubkey_is_sysvar_id( acc ));
      FD_STORE( uchar, serialized_params, is_writable );
      serialized_params += sizeof(uchar);

      fd_pubkey_t key = *acc;
      FD_STORE( fd_pubkey_t, serialized_params, key );
      serialized_params += sizeof(fd_pubkey_t);

      ulong lamports = metadata->info.lamports;
      FD_STORE( ulong, serialized_params, lamports );
      serialized_params += sizeof(ulong);

      ulong acc_data_len = metadata->dlen;
      FD_STORE( ulong, serialized_params, acc_data_len );
      serialized_params += sizeof(ulong);

      fd_memcpy( serialized_params, acc_data, acc_data_len);
      serialized_params += acc_data_len;

      fd_pubkey_t owner = *(fd_pubkey_t *)&metadata->info.owner;
      FD_STORE( fd_pubkey_t, serialized_params, owner );
      serialized_params += sizeof(fd_pubkey_t);

      uchar is_executable = (uchar)metadata->info.executable;
      FD_STORE( uchar, serialized_params, is_executable );
      serialized_params += sizeof(uchar);

      ulong rent_epoch = metadata->info.rent_epoch;
      FD_STORE( ulong, serialized_params, rent_epoch );
      serialized_params += sizeof(ulong);
    }
  }

  ulong instr_data_len = ctx.instr->data_sz;
  FD_STORE( ulong, serialized_params, instr_data_len );
  serialized_params += sizeof(ulong);

  uchar * instr_data = (uchar *)ctx.instr->data;
  fd_memcpy( serialized_params, instr_data, instr_data_len );
  serialized_params += instr_data_len;

  FD_STORE( fd_pubkey_t, serialized_params, txn_accs[ctx.instr->program_id] );
  serialized_params += sizeof(fd_pubkey_t);

  FD_TEST( serialized_params == serialized_params_start + serialized_size );
  // FD_LOG_NOTICE(( "SERIALIZE (UNALIGNED) - sz: %lu, diff: %lu", serialized_size, serialized_params - serialized_params_start ));
  // FD_LOG_HEXDUMP_WARNING(( "SERIALIZED", serialized_params_start, serialized_size));
  *sz = serialized_size;
  return serialized_params_start;
}

int
fd_bpf_loader_input_deserialize_unaligned( fd_exec_instr_ctx_t ctx, ulong const * pre_lens, uchar * input, ulong input_sz ) {
  uchar * input_cursor = input;

  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, sizeof(acc_idx_seen));

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs = ctx.txn_ctx->accounts;

  input_cursor += sizeof(ulong);

  for( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];
    fd_pubkey_t const * acc = &txn_accs[instr_acc_idxs[i]];

    input_cursor++;
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      // no-op
    } else if ( fd_instr_acc_is_writable_idx(ctx.instr, (uchar)i) && !fd_pubkey_is_sysvar_id( acc ) ) {
      acc_idx_seen[acc_idx] = 1;
      input_cursor += sizeof(uchar) + sizeof(uchar) + sizeof(fd_pubkey_t);

      fd_borrowed_account_t * view_acc = NULL;
      (void)fd_instr_borrowed_account_view(&ctx, acc, &view_acc);
      if ( view_acc->const_meta ) {
        if (view_acc->const_meta->info.executable && memcmp( view_acc->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0) {
          // no-op
        } else if (view_acc->const_meta->info.executable) {
          input_cursor += sizeof(ulong);

          /* Consume data_len */
          input_cursor += sizeof(ulong);

          input_cursor += pre_lens[i];

          input_cursor += sizeof(fd_pubkey_t);

          /* Consume executable flag */
          input_cursor += sizeof(uchar);

          input_cursor += sizeof(ulong);
          continue;
        }
      }

      ulong lamports = FD_LOAD(ulong, input_cursor);
      input_cursor += sizeof(ulong);

      /* Consume data_len */
      input_cursor += sizeof(ulong);

      uchar * post_data = input_cursor;
      fd_borrowed_account_t * modify_acc = NULL;
      int modify_err = fd_instr_borrowed_account_modify( &ctx, acc, 0, &modify_acc );
      FD_TEST(modify_err == FD_ACC_MGR_SUCCESS);
      fd_account_meta_t * metadata = modify_acc->meta;
      uchar * acc_data             = modify_acc->data;

      input_cursor += pre_lens[i];

      fd_pubkey_t * owner = (fd_pubkey_t *)input_cursor;
      input_cursor += sizeof(fd_pubkey_t);

      /* Consume executable flag */
      input_cursor += sizeof(uchar);

      metadata->info.lamports = lamports;
      // if (memcmp(metadata->info.owner, owner, sizeof(fd_pubkey_t)) != 0) {
      //   fd_account_set_owner(&ctx, metadata, acc, owner);
      // }
      fd_memcpy(metadata->info.owner, owner, sizeof(fd_pubkey_t));

      metadata->dlen = pre_lens[i];
      fd_memcpy( acc_data, post_data, pre_lens[i] );

      metadata->slot = ctx.slot_ctx->slot_bank.slot;
      input_cursor += sizeof(ulong);
    } else {
        // Account is not writable
        acc_idx_seen[acc_idx] = 1;
        input_cursor += sizeof(uchar) + sizeof(uchar) + sizeof(fd_pubkey_t);
        input_cursor += sizeof(ulong);

        /* Consume data_len */
        input_cursor += sizeof(ulong);

        input_cursor += pre_lens[i];

        input_cursor += sizeof(fd_pubkey_t);

        /* Consume executable flag */
        input_cursor += sizeof(uchar);

        input_cursor += sizeof(ulong);
    }
  }

  FD_TEST( input_cursor <= input + input_sz );

  fd_valloc_free( ctx.valloc, input);

  return 0;
}
