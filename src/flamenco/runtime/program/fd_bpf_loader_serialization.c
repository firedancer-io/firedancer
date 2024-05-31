#include "fd_bpf_loader_serialization.h"
#include "../fd_account.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define BPF_ALIGN_OF_U128 (8UL)

/**
 * num accounts
 * serialized accounts
 * instr data len
 * instr data
 * program id public key
*/
// 64-bit aligned
uchar *
fd_bpf_loader_input_serialize_aligned( fd_exec_instr_ctx_t ctx,
                                       ulong *             sz,
                                       ulong *             pre_lens ) {
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

    serialized_size++; /* dup */
    if( FD_UNLIKELY( acc_idx_seen[ acc_idx ] ) ) {
      serialized_size += 7UL; // pad to 64-bit alignment
    } else {
      acc_idx_seen[ acc_idx ] = 1;
      dup_acc_idx[ acc_idx ] = i;
      fd_pubkey_t * acc = &txn_accs[ acc_idx ];
      fd_borrowed_account_t * view_acc = NULL;
      int read_result = fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
      fd_account_meta_t const * metadata = view_acc->const_meta;

      ulong acc_data_len = 0UL;
      if ( FD_LIKELY( read_result == FD_ACC_MGR_SUCCESS ) ) {
        acc_data_len = metadata->dlen;
      } else if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
        acc_data_len = 0UL;
      } else {
        return NULL;
      }

      ulong aligned_acc_data_len = fd_ulong_align_up( acc_data_len, BPF_ALIGN_OF_U128 );

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
    uchar acc_idx = instr_acc_idxs[i];
    fd_pubkey_t * acc = &txn_accs[acc_idx];

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
        return NULL;
      }

      fd_account_meta_t const * metadata = view_acc->const_meta;
      uchar const * acc_data             = view_acc->const_data;

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

  *sz = serialized_size;

  return serialized_params_start;
}

int
fd_bpf_loader_input_deserialize_aligned( fd_exec_instr_ctx_t ctx,
                                         ulong const *       pre_lens,
                                         uchar *             buffer,
                                         ulong               buffer_sz ) {
  uchar * start_cursor = buffer;

  /* Used to track duplicate state */
  uchar acc_idx_seen[ 256 ];
  memset( acc_idx_seen, 0, sizeof(acc_idx_seen) );

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs       = ctx.txn_ctx->accounts;

  start_cursor += sizeof(ulong);
  /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L508-L602 */
  for( ulong i=0; i<ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx     = instr_acc_idxs[ i ];
    fd_pubkey_t * acc = &txn_accs[ instr_acc_idxs[ i ] ];

    start_cursor++;
    fd_borrowed_account_t * view_acc = NULL;
    int view_err = fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
    /* Due to differences in how borrowed accounts are handled across the
       different clients the non-duplicate case must be handled differently.
       If an account is not writable or a sysvar then we don't do any reading
       as those accounts could not have changed in the program execution. */
    /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L515-L516 */
    if( FD_UNLIKELY( acc_idx_seen[ acc_idx ] ) ) {
      start_cursor += 7;
    } else if( fd_instr_acc_is_writable_idx( ctx.instr, (uchar)i ) && !fd_pubkey_is_sysvar_id( acc ) ) {
      if( view_err ) {
        FD_LOG_NOTICE(("VIEW ERR %d", view_err));
      }
      acc_idx_seen[ acc_idx ] = 1;
      start_cursor += sizeof(uchar)        // is_signer
                    + sizeof(uchar)        // is_writable
                    + sizeof(uchar)        // executable
                    + sizeof(uint)         // original_data_len
                    + sizeof(fd_pubkey_t); // key

      if( FD_UNLIKELY( start_cursor+sizeof(fd_pubkey_t)>buffer+buffer_sz ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      fd_pubkey_t * owner = (fd_pubkey_t *)start_cursor;
      start_cursor += sizeof(fd_pubkey_t);

      if( FD_UNLIKELY( start_cursor+sizeof(ulong)>buffer+buffer_sz ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      ulong lamports = FD_LOAD(ulong, start_cursor);
      start_cursor += sizeof(ulong);
      /* The lamports are updated after a modifiable borrowed account has been created */

      if( FD_UNLIKELY( start_cursor+sizeof(ulong)>buffer+buffer_sz ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      ulong post_len = FD_LOAD(ulong, start_cursor);
      start_cursor += sizeof(ulong);

      uchar * post_data = start_cursor;

      ulong acc_sz = post_len;

      if ( FD_UNLIKELY( fd_ulong_sat_sub( post_len, view_acc->const_meta->dlen ) > MAX_PERMITTED_DATA_INCREASE || 
                        post_len > MAX_PERMITTED_DATA_LENGTH ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
      }

      fd_borrowed_account_t * modify_acc = NULL;
      int modify_err = fd_instr_borrowed_account_modify( &ctx, acc, acc_sz, &modify_acc );
      if( FD_UNLIKELY( modify_err != FD_ACC_MGR_SUCCESS ) ) {
        return modify_err;
      }

      ulong pre_len = pre_lens[ i ];

      start_cursor += fd_ulong_align_up( pre_len, BPF_ALIGN_OF_U128 );

      uchar * acc_data = fd_account_get_data( modify_acc->meta );

      int err;
      if( fd_account_can_data_be_resized( &ctx, modify_acc->meta, post_len, &err ) &&
          fd_account_can_data_be_changed( ctx.instr, i, &err ) ) {
        modify_acc->meta->dlen = post_len;
        fd_memcpy( acc_data, post_data, post_len );
      } else if( modify_acc->meta->dlen != post_len || memcmp( acc_data, post_data, post_len ) ) {
        fd_valloc_free( ctx.valloc, buffer );
        return err;
      }

      // Update slot so that it gets hashed
      modify_acc->meta->slot = ctx.slot_ctx->slot_bank.slot;

      start_cursor += MAX_PERMITTED_DATA_INCREASE;
      start_cursor += sizeof(ulong);

      modify_acc->meta->info.lamports = lamports;
      if( memcmp( modify_acc->meta->info.owner, owner, sizeof(fd_pubkey_t) ) ) {
        int err = fd_account_set_owner( &ctx, i, owner );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      }

    } else {
      acc_idx_seen[ acc_idx ] = 1;
      // Account is not writable, skip over
      start_cursor += sizeof(uchar)         // is_signer
                    + sizeof(uchar)         // is_writable
                    + sizeof(uchar)         // executable
                    + sizeof(uint)          // original_data_len
                    + sizeof(fd_pubkey_t);  // key
      start_cursor += sizeof(fd_pubkey_t);  // owner
      start_cursor += sizeof(ulong);        // lamports
      start_cursor += sizeof(ulong);        // data_len

      fd_account_meta_t const * metadata = view_acc->const_meta;

      if( view_err == FD_ACC_MGR_SUCCESS ) {
        start_cursor += fd_ulong_align_up( metadata->dlen, BPF_ALIGN_OF_U128 );
      }
      start_cursor += MAX_PERMITTED_DATA_INCREASE;
      start_cursor += sizeof(ulong);
    }
  }

  FD_TEST( start_cursor <= buffer + buffer_sz );

  return FD_EXECUTOR_INSTR_SUCCESS;
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

    serialized_size++; // dup byte
    if( FD_LIKELY( !acc_idx_seen[acc_idx] ) ) {
      acc_idx_seen[acc_idx] = 1;
      dup_acc_idx[acc_idx] = i;

      fd_pubkey_t const * acc = &txn_accs[acc_idx];
      fd_borrowed_account_t * view_acc = NULL;
      int read_result = fd_instr_borrowed_account_view(&ctx, acc, &view_acc);
      fd_account_meta_t const * metadata = view_acc->const_meta;

      ulong acc_data_len = 0;
      if ( FD_LIKELY( read_result == FD_ACC_MGR_SUCCESS ) ) {
        acc_data_len = metadata->dlen;
      } else if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
        acc_data_len = 0;
      } else {
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

  for( ushort i = 0; i < ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];
    fd_pubkey_t const * acc = &txn_accs[acc_idx];

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
