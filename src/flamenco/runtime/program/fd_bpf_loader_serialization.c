#include "fd_bpf_loader_serialization.h"
#include "../fd_account.h"

/* As a general note, copy_account_data implies that direct mapping is not being
   used/is inactive. This file is responsible for serializing and deserializing
   the input region of the BPF virtual machine. The input region contains
   instruction information, account metadata, and account data. The high level
   format is as follows: 
   
   [ account 1 metadata, account 1 data, account 2 metadata, account 2 data, ...,
     account N metadata, account N data, instruction info. ]

  This format by no means comprehensive, but it should give an idea of how 
  the input region is laid out. When direct mapping is not enabled, the input
  region is stored as a single contiguous buffer. This buffer in the host
  address space is then mapped to the VM virtual address space (the range 
  starting with 0x400...). This means to serialize into the input region, we
  need to copy in the account metadata and account data into the buffer for
  each account. Everything must get copied out after execution is complete. 
  A consequence of this is that a memcpy for the account data is required 
  for each serialize and deserialize operation: this can potentially become
  expensive if there are many accounts and many nested CPI calls. Also, the 
  entire memory region is treated as writable even though many accounts are
  read-only. This means that for all read-only accounts, a memcmp must be done
  while deserializing to make sure that the account (meta)data has not changed.

  Direct mapping offers a solution to this by introducing a more sophisticated
  memory translation protocol. Now the account data is not copied into a single
  contiguous buffer, but instead a borrowed account's data is directly mapped
  into the VM's virtual address space. The host memory for the input region is
  now represented by a list of fragmented memory regions. These sub regions
  also have different write permissions. This should solve the problem of 
  having to memcpy/memcmp account data regions (which can be up to 10MiB each).
  There is some nuance to this, as the account data can be resized. This means
  that memcpys for account data regions can't totally be avoided. */

/* Add a new memory region to represent the input region. All of the memory
   regions here have sorted virtual addresses. These regions may or may not
   correspond to an account's data region. If it corresponds to metadata,
   the pubkey for the region will be NULL. */
static void
new_input_mem_region( fd_vm_input_region_t * input_mem_regions,
                      uint *                 input_mem_regions_cnt,
                      const uchar *          buffer,
                      ulong                  region_sz,
                      uint                   is_writable ) {

  /* The start vaddr of the new region should be equal to start of the previous
     region added to its size. */
  ulong vaddr_offset = *input_mem_regions_cnt==0UL ? 0UL : input_mem_regions[ *input_mem_regions_cnt-1U ].vaddr_offset + 
                                                           input_mem_regions[ *input_mem_regions_cnt-1U ].region_sz;
  input_mem_regions[ *input_mem_regions_cnt ].is_writable  = is_writable;
  input_mem_regions[ *input_mem_regions_cnt ].haddr        = (ulong)buffer;
  input_mem_regions[ *input_mem_regions_cnt ].region_sz    = (uint)region_sz;
  input_mem_regions[ *input_mem_regions_cnt ].vaddr_offset = vaddr_offset;
  (*input_mem_regions_cnt)++;
}

/* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L93-L130 */
/* This function handles casing for direct mapping being enabled as well as if
   the alignment is being stored. In the case where direct mapping is not 
   enabled, we copy in the account data and a 10KiB buffer into the input region.
   These both go into the same memory buffer. However, when direct mapping is
   enabled, the account data and resizing buffers are represented by two
   different memory regions. In both cases, padding is used to maintain 8 byte
   alignment. If alignment is not required, then a resizing buffer is not used
   as the deprecated loader doesn't allow for resizing accounts. */
void
write_account( fd_exec_instr_ctx_t *     instr_ctx,
               fd_borrowed_account_t *   account,
               uchar                     instr_acc_idx,
               uchar * *                 serialized_params,
               uchar * *                 serialized_params_start,
               fd_vm_input_region_t *    input_mem_regions,
               uint *                    input_mem_regions_cnt,
               fd_vm_acc_region_meta_t * acc_region_metas,
               int                       is_aligned,
               int                       copy_account_data ) {

  uchar const * data = account ? account->const_data       : NULL;
  ulong         dlen = account ? account->const_meta->dlen : 0UL;

  if( copy_account_data ) {
    /* Copy the account data into input region buffer */
    fd_memcpy( *serialized_params, data, dlen );
    *serialized_params += dlen;

    if( FD_LIKELY( is_aligned ) ) {
      /* Zero out padding bytes and max permitted data increase */
      ulong align_offset = fd_ulong_align_up( dlen, FD_BPF_ALIGN_OF_U128 ) - dlen;
      fd_memset( *serialized_params, 0, MAX_PERMITTED_DATA_INCREASE + align_offset );
      *serialized_params += MAX_PERMITTED_DATA_INCREASE + align_offset;
    }
  } else { /* direct_mapping == true */
    /* First, push on the region for the metadata that has just been serialized.
       This function will push the metadata in the serialized_params from
       serialized_params_start to serialized_params as a region to the input
       memory regions array. */
    /* TODO: This region always has length of 96 and this can be set as a constant. */

    ulong region_sz = (ulong)(*serialized_params) - (ulong)(*serialized_params_start);
    new_input_mem_region( input_mem_regions, input_mem_regions_cnt, *serialized_params_start, region_sz, 1L );

    /* Next, push the region for the account data if there is account data. We 
       intentionally omit copy on write as a region type. */
    int err = 0;
    uint is_writable = (uint)(fd_account_can_data_be_changed( instr_ctx->instr, instr_acc_idx, &err ) && !err);

    /* Update the mapping from instruction account index to memory region index.
       This is an optimization to avoid redundant lookups to find accounts. */
    acc_region_metas[instr_acc_idx] = (fd_vm_acc_region_meta_t){ .region_idx          = *input_mem_regions_cnt, 
                                                                 .has_data_region     = !!dlen,
                                                                 .has_resizing_region = (uchar)is_aligned };
    
    if( dlen ) {
      new_input_mem_region( input_mem_regions, input_mem_regions_cnt, data, dlen, is_writable );
    }

    if( FD_LIKELY( is_aligned ) ) {
      /* Finally, push a third region for the max resizing data region. This is
         done even if there is no account data. This must be aligned so padding
         bytes must be inserted. This resizing region is also padded to result
         in 8 byte alignment for the combination of the account data region with
         the resizing region.
         
         We add the max permitted resizing limit along with 8 bytes of padding
         to the serialization buffer. However, the padding bytes are used to
         maintain alignment in the VM virtual address space. */
      ulong align_offset = fd_ulong_align_up( dlen, FD_BPF_ALIGN_OF_U128 ) - dlen;

      fd_memset( *serialized_params, 0, MAX_PERMITTED_DATA_INCREASE + FD_BPF_ALIGN_OF_U128 );

      /* Leave a gap for alignment */
      uchar * region_buffer = *serialized_params + (FD_BPF_ALIGN_OF_U128 - align_offset);
      ulong   region_sz     = MAX_PERMITTED_DATA_INCREASE + align_offset;
      new_input_mem_region( input_mem_regions, input_mem_regions_cnt, region_buffer, region_sz, is_writable );

      *serialized_params += MAX_PERMITTED_DATA_INCREASE + FD_BPF_ALIGN_OF_U128;
    }
    *serialized_params_start = *serialized_params;
  }
}

uchar *
fd_bpf_loader_input_serialize_aligned( fd_exec_instr_ctx_t       ctx,
                                       ulong *                   sz,
                                       ulong *                   pre_lens,
                                       fd_vm_input_region_t *    input_mem_regions,    
                                       uint *                    input_mem_regions_cnt,
                                       fd_vm_acc_region_meta_t * acc_region_metas,
                                       int                       copy_account_data ) {
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs       = ctx.txn_ctx->accounts;

  uchar acc_idx_seen[256] = {0};
  ushort dup_acc_idx[256] = {0};

  /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L429-L459 */
  ulong serialized_size = 0UL;
  serialized_size += sizeof(ulong);
  /* First pass is to calculate size of buffer to allocate */
  for( ushort i=0; i<ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];

    serialized_size++; // dup byte
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      serialized_size += 7UL; // pad to 64-bit alignment
    } else {
      acc_idx_seen[acc_idx] = 1;
      dup_acc_idx[acc_idx]  = i;
      fd_pubkey_t *           acc      = &txn_accs[acc_idx];
      fd_borrowed_account_t * view_acc = NULL;
      int read_result = fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
      fd_account_meta_t const * metadata = view_acc->const_meta;

      ulong acc_data_len = 0UL;
      if( FD_LIKELY( read_result==FD_ACC_MGR_SUCCESS ) ) {
        acc_data_len = metadata->dlen;
      } else if( FD_UNLIKELY( read_result==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
        acc_data_len = 0UL;
      } else {
        return NULL;
      }

      serialized_size += sizeof(uchar)               // is_signer
                       + sizeof(uchar)               // is_writable
                       + sizeof(uchar)               // executable
                       + sizeof(uint)                // original_data_len
                       + sizeof(fd_pubkey_t)         // key
                       + sizeof(fd_pubkey_t)         // owner
                       + sizeof(ulong)               // lamports
                       + sizeof(ulong)               // data len
                       + MAX_PERMITTED_DATA_INCREASE
                       + sizeof(ulong);              // rent_epoch
      if( copy_account_data ) {
        serialized_size += fd_ulong_align_up( acc_data_len, FD_BPF_ALIGN_OF_U128 );
      } else {
        serialized_size += FD_BPF_ALIGN_OF_U128;
      }
    }
  }

  serialized_size += sizeof(ulong)        // data len 
                  +  ctx.instr->data_sz
                  +  sizeof(fd_pubkey_t); // program id

  uchar * serialized_params            = fd_valloc_malloc( ctx.valloc, FD_BPF_ALIGN_OF_U128, fd_ulong_align_up( serialized_size, 16UL ) );
  uchar * serialized_params_start      = serialized_params;
  uchar * curr_serialized_params_start = serialized_params;

  FD_STORE( ulong, serialized_params, ctx.instr->acct_cnt );
  serialized_params += sizeof(ulong);

  /* Second pass over the account is to serialize into the buffer. */
  for( ushort i=0; i<ctx.instr->acct_cnt; i++ ) {
    uchar         acc_idx = instr_acc_idxs[i];
    fd_pubkey_t * acc     = &txn_accs[acc_idx];

    if( FD_UNLIKELY( acc_idx_seen[acc_idx] && dup_acc_idx[acc_idx] != i ) ) {
      /* Duplicate. Store 8 byte buffer to maintain alignment but store the
         account index in the first byte.*/
      FD_STORE( ulong, serialized_params, 0UL );
      FD_STORE( uchar, serialized_params, (uchar)dup_acc_idx[acc_idx] );
      serialized_params += sizeof(ulong);
    } else {
      FD_STORE( uchar, serialized_params, FD_NON_DUP_MARKER );
      serialized_params += sizeof(uchar);

      fd_borrowed_account_t * view_acc    = NULL;
      int                     read_result = fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
      /* Note: due to differences in borrowed account handling. The case where
         the account is unknown must be handled differently. Notably, when the 
         account data is null and everything must be zero initialized. */
      if( FD_UNLIKELY( read_result==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
        uchar is_signer = (uchar)fd_instr_acc_is_signer_idx( ctx.instr, (uchar)i );
        FD_STORE( uchar, serialized_params, is_signer );
        serialized_params += sizeof(uchar);

        uchar is_writable = (uchar)fd_instr_acc_is_writable_idx( ctx.instr, (uchar)i );
        FD_STORE( uchar, serialized_params, is_writable );
        serialized_params += sizeof(uchar);

        fd_memset( serialized_params, 0, sizeof(uchar) + // is_executable
                                         sizeof(uint) ); // original_data_len

        serialized_params += sizeof(uchar) + // executable
                             sizeof(uint);   // original_data_len

        fd_pubkey_t key = *acc;
        FD_STORE( fd_pubkey_t, serialized_params, key );
        serialized_params += sizeof(fd_pubkey_t);

        fd_memset( serialized_params, 0, sizeof(fd_pubkey_t) +         // owner
                                         sizeof(ulong) +               // lamports
                                         sizeof(ulong) );              // data_len
        serialized_params += sizeof(fd_pubkey_t) + // owner
                             sizeof(ulong) +       // lamports
                             sizeof(ulong);        // data_len

        write_account( &ctx, view_acc, (uchar)i, &serialized_params, &curr_serialized_params_start,
                       input_mem_regions, input_mem_regions_cnt, acc_region_metas, 1, copy_account_data );

        FD_STORE( ulong, serialized_params, ULONG_MAX );
        serialized_params += sizeof(ulong); // rent_epoch

        pre_lens[i] = 0UL;
        continue;
      } else if( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        return NULL;
      }

      /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L465 */
      fd_account_meta_t const * metadata = view_acc->const_meta;

      uchar is_signer = (uchar)fd_instr_acc_is_signer_idx( ctx.instr, (uchar)i );
      FD_STORE( uchar, serialized_params, is_signer );
      serialized_params += sizeof(uchar);

      uchar is_writable = (uchar)fd_instr_acc_is_writable_idx( ctx.instr, (uchar)i );
      FD_STORE( uchar, serialized_params, is_writable );
      serialized_params += sizeof(uchar);

      uchar is_executable = (uchar)metadata->info.executable;
      FD_STORE( uchar, serialized_params, is_executable );
      serialized_params += sizeof(uchar);

      /* The original data len field is intentionally NOT populated. */
      uint padding_0 = 0U;
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

      ulong acc_data_len = metadata->dlen;
      pre_lens[i] = acc_data_len;

      ulong data_len = acc_data_len;
      FD_STORE( ulong, serialized_params, data_len );
      serialized_params += sizeof(ulong);

      write_account( &ctx, view_acc, (uchar)i, &serialized_params, &curr_serialized_params_start, 
                     input_mem_regions, input_mem_regions_cnt, acc_region_metas, 1, copy_account_data );

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

  if( FD_UNLIKELY( serialized_params!=serialized_params_start+serialized_size ) ) {
    FD_LOG_ERR(( "Serializing error" )); /* TODO: we can likely get rid of this check altogether */
  }

  /* Write out the final region. */
  new_input_mem_region( input_mem_regions, input_mem_regions_cnt, curr_serialized_params_start, 
                        (ulong)(serialized_params - curr_serialized_params_start), 1 );

  *sz = serialized_size;

  return serialized_params_start;
}

/* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L500-L603 */
int
fd_bpf_loader_input_deserialize_aligned( fd_exec_instr_ctx_t ctx,
                                         ulong const *       pre_lens,
                                         uchar *             buffer,
                                         ulong FD_FN_UNUSED  buffer_sz,
                                         int                 copy_account_data ) {
  /* TODO: An optimization would be to skip ahead through non-writable accounts */
  /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L507 */
  ulong start = 0UL;

  uchar acc_idx_seen[256] = {0};

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs       = ctx.txn_ctx->accounts;

  start += sizeof(ulong); // number of accounts
  /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L508-L600 */
  for( ulong i=0UL; i<ctx.instr->acct_cnt; i++ ) {
    uchar         acc_idx = instr_acc_idxs[i];
    fd_pubkey_t * acc     = &txn_accs[instr_acc_idxs[i]];

    start++; // position
    fd_borrowed_account_t * view_acc = NULL;
    /* Intentionally ignore the borrowed account error because it is not used */
    fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
    if( FD_UNLIKELY( !view_acc ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L515-517 */
      start += 7UL;
    } else {
      /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L518-524 */
      acc_idx_seen[acc_idx] = 1;
      start += sizeof(uchar)        // is_signer
             + sizeof(uchar)        // is_writable
             + sizeof(uchar)        // executable
             + sizeof(uint)         // original_data_len
             + sizeof(fd_pubkey_t); // key

      /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L525-548 */

      fd_pubkey_t * owner = (fd_pubkey_t *)(buffer+start);
      start += sizeof(fd_pubkey_t); // owner

      ulong lamports = FD_LOAD( ulong, buffer+start );
      if( lamports!=view_acc->const_meta->info.lamports ) {
        int err = fd_account_set_lamports( &ctx, i, lamports );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      }
      start += sizeof(ulong); // lamports

      ulong post_len = FD_LOAD( ulong, buffer+start );
      start += sizeof(ulong); // data length

      ulong pre_len = pre_lens[i];
      ulong alignment_offset = fd_ulong_align_up( pre_len, FD_BPF_ALIGN_OF_U128 ) - pre_len;

      uchar * post_data = buffer+start;

      fd_account_meta_t const * metadata_check = view_acc->const_meta;
      if( FD_UNLIKELY( fd_ulong_sat_sub( post_len, metadata_check->dlen )>MAX_PERMITTED_DATA_INCREASE || 
                       post_len>MAX_PERMITTED_DATA_LENGTH ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
      }

      if( copy_account_data ) {
        /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L551-563 */
        int err = 0;
        if( fd_account_can_data_be_resized( &ctx, view_acc->const_meta, post_len, &err ) && 
            fd_account_can_data_be_changed( ctx.instr, i, &err ) ) {
          FD_LOG_WARNING(("DESERIALIZATION %s %lu %lu", FD_BASE58_ENC_32_ALLOCA(view_acc->pubkey), pre_len, post_len));
          int err = fd_account_set_data_from_slice( &ctx, i, post_data, post_len );
          if( FD_UNLIKELY( err ) ) {
            return err;
          }

        } else if( FD_UNLIKELY( view_acc->const_meta->dlen!=post_len || 
                                memcmp( view_acc->const_data, post_data, post_len ) ) ) {
          return err;
        }
        start += pre_len;
      } else { /* If direct mapping is enabled */
        /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L564-587 */
        start += FD_BPF_ALIGN_OF_U128 - alignment_offset;
        int err = 0;
        if( fd_account_can_data_be_resized( &ctx, view_acc->const_meta, post_len, &err ) && 
            fd_account_can_data_be_changed( ctx.instr, i, &err ) ) {

          err = fd_account_set_data_length( &ctx, i, post_len );
          if( FD_UNLIKELY( err ) ) {
            return err;
          }

          ulong allocated_bytes = fd_ulong_sat_sub( post_len, pre_len );
          if( allocated_bytes ) {
            uchar * acc_data = NULL;
            ulong   acc_dlen = 0UL;
            err = fd_account_get_data_mut( &ctx, i, &acc_data, &acc_dlen );
            if( FD_UNLIKELY( err ) ) {
              return err;
            }
            if( FD_UNLIKELY( pre_len+allocated_bytes>acc_dlen ) ) {
              return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
            }
            /* We want to copy in the reallocated bytes from the input
               buffer directly into the borrowed account data buffer
               which has now been extended. */
              memcpy( acc_data+pre_len, buffer+start, allocated_bytes );
          }
        } else if( FD_UNLIKELY( view_acc->const_meta->dlen!=post_len ) ) {
          return err;
        }
      }
    
      /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/serialization.rs#L593-598 */
      start += MAX_PERMITTED_DATA_INCREASE;
      start += alignment_offset;
      start += sizeof(ulong); // rent epoch        
      if( memcmp( view_acc->const_meta->info.owner, owner, sizeof(fd_pubkey_t) ) ) {
        int err = fd_account_set_owner( &ctx, i, owner );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      }
    }
  }

  fd_valloc_free( ctx.valloc, buffer );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

uchar *
fd_bpf_loader_input_serialize_unaligned( fd_exec_instr_ctx_t       ctx,
                                         ulong *                   sz,
                                         ulong *                   pre_lens,
                                         fd_vm_input_region_t *    input_mem_regions,            
                                         uint *                    input_mem_regions_cnt,
                                         fd_vm_acc_region_meta_t * acc_region_metas,
                                         int                       copy_account_data ) {
  ulong serialized_size = 0UL;
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs = ctx.txn_ctx->accounts;

  uchar acc_idx_seen[256] = {0}; 
  ushort dup_acc_idx[256] = {0};

  serialized_size += sizeof(ulong);
  for( ushort i=0; i<ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];

    serialized_size++; // dup
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      continue;
    }

    acc_idx_seen[acc_idx] = 1;
    dup_acc_idx[acc_idx]  = i;

    fd_pubkey_t const * acc = &txn_accs[acc_idx];
    fd_borrowed_account_t * view_acc = NULL;
    int read_result = fd_instr_borrowed_account_view(&ctx, acc, &view_acc);
    fd_account_meta_t const * metadata = view_acc->const_meta;

    ulong acc_data_len = 0UL;
    if( FD_LIKELY( read_result == FD_ACC_MGR_SUCCESS ) ) {
      acc_data_len = metadata->dlen;
    } else if( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
      acc_data_len = 0UL;
    } else {
      return NULL;
    }

    pre_lens[i] = acc_data_len;

    serialized_size += sizeof(uchar)        // is_signer
                      + sizeof(uchar)       // is_writable
                      + sizeof(fd_pubkey_t) // key
                      + sizeof(ulong)       // lamports
                      + sizeof(ulong)       // data_len
                      + sizeof(fd_pubkey_t) // owner
                      + sizeof(uchar)       // executable
                      + sizeof(ulong);      // rent_epoch
    if( copy_account_data ) {
      serialized_size += acc_data_len;
    }
  }

  serialized_size += sizeof(ulong)        // instruction data len
                   + ctx.instr->data_sz   // instruction data
                   + sizeof(fd_pubkey_t); // program id

  uchar * serialized_params = fd_valloc_malloc( ctx.valloc, 1UL, serialized_size );
  uchar * serialized_params_start = serialized_params;
  uchar * curr_serialized_params_start = serialized_params;

  FD_STORE( ulong, serialized_params, ctx.instr->acct_cnt );
  serialized_params += sizeof(ulong);

  for( ushort i=0; i<ctx.instr->acct_cnt; i++ ) {
    uchar               acc_idx = instr_acc_idxs[i];
    fd_pubkey_t const * acc     = &txn_accs[acc_idx];

    if( FD_UNLIKELY( acc_idx_seen[acc_idx] && dup_acc_idx[acc_idx] != i ) ) {
      // Duplicate
      FD_STORE( uchar, serialized_params, (uchar)dup_acc_idx[acc_idx] );
      serialized_params += sizeof(uchar);
    } else {
      FD_STORE( uchar, serialized_params, FD_NON_DUP_MARKER );
      serialized_params += sizeof(uchar);

      fd_borrowed_account_t * view_acc = NULL;
      int read_result = fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
      if( FD_UNLIKELY( !fd_acc_exists( view_acc->const_meta ) ) ) {
          fd_memset( serialized_params, 0, sizeof(uchar)    // is_signer
                                         + sizeof(uchar) ); // is_writable
          serialized_params += sizeof(uchar)  // is_signer
                             + sizeof(uchar); // is_writable

          fd_pubkey_t key = *acc;
          FD_STORE( fd_pubkey_t, serialized_params, key );
          serialized_params += sizeof(fd_pubkey_t);

          fd_memset( serialized_params, 0, sizeof(ulong)    // lamports
                                         + sizeof(ulong) ); // data_len
          serialized_params += sizeof(ulong) +
                               sizeof(ulong);

          write_account( &ctx, view_acc, (uchar)i, &serialized_params, &curr_serialized_params_start, 
                         input_mem_regions, input_mem_regions_cnt, acc_region_metas, 0, copy_account_data );

          fd_memset( serialized_params, 0, sizeof(fd_pubkey_t) // owner
                                         + sizeof(uchar) );    // is_executable
          serialized_params += sizeof(fd_pubkey_t)
                             + sizeof(uchar);


          /* The rent epoch is always ulong max */
          FD_STORE( ulong, serialized_params, ULONG_MAX );
          serialized_params += sizeof(ulong);

        continue;
      } else if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_DEBUG(( "failed to read account data - pubkey: %s, err: %d", FD_BASE58_ENC_32_ALLOCA( acc ), read_result ));
        return NULL;
      }
      fd_account_meta_t const * metadata = view_acc->const_meta;

      uchar is_signer = (uchar)fd_instr_acc_is_signer_idx( ctx.instr, (uchar)i );
      FD_STORE( uchar, serialized_params, is_signer );
      serialized_params += sizeof(uchar);

      uchar is_writable = (uchar)fd_instr_acc_is_writable_idx( ctx.instr, (uchar)i );
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

      write_account( &ctx, view_acc, (uchar)i, &serialized_params, &curr_serialized_params_start, 
                     input_mem_regions, input_mem_regions_cnt, acc_region_metas, 0, copy_account_data );

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

  new_input_mem_region( input_mem_regions, input_mem_regions_cnt, curr_serialized_params_start,
              (ulong)(serialized_params - curr_serialized_params_start), 1 );

  return serialized_params_start;
}

int
fd_bpf_loader_input_deserialize_unaligned( fd_exec_instr_ctx_t ctx, 
                                           ulong const *       pre_lens, 
                                           uchar *             input, 
                                           ulong               input_sz,
                                           int                 copy_account_data ) {
  uchar * input_cursor = input;

  uchar acc_idx_seen[256] = {0};

  uchar const *       instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs       = ctx.txn_ctx->accounts;

  input_cursor += sizeof(ulong);

  for( ulong i=0UL; i<ctx.instr->acct_cnt; i++ ) {
    uchar acc_idx           = instr_acc_idxs[i];
    fd_pubkey_t const * acc = &txn_accs[instr_acc_idxs[i]];

    input_cursor++; /* is_dup */
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      /* no-op */
    } else {
      acc_idx_seen[acc_idx] = 1;
      input_cursor += sizeof(uchar) +      /* is_signer */
                      sizeof(uchar) +      /* is_writable */
                      sizeof(fd_pubkey_t); /* key */

      fd_borrowed_account_t * view_acc = NULL;
      fd_instr_borrowed_account_view( &ctx, acc, &view_acc );
      if( FD_UNLIKELY( !view_acc ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      ulong lamports = FD_LOAD( ulong, input_cursor );
      if( view_acc->const_meta && view_acc->const_meta->info.lamports!=lamports ) {
        int err = fd_account_set_lamports( &ctx, i, lamports );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      }
      input_cursor += sizeof(ulong); /* lamports */

      input_cursor += sizeof(ulong); /* data length */

      if( copy_account_data ) {
        ulong   pre_len   = pre_lens[i]; 
        uchar * post_data = input_cursor;
        if( view_acc->const_meta ) {    
          int err = 0;
          if( fd_account_can_data_be_resized( &ctx, view_acc->const_meta, pre_len, &err ) &&
              fd_account_can_data_be_changed( ctx.instr, i, &err ) ) {
            err = fd_account_set_data_from_slice( &ctx, i, post_data, pre_len );
            if( FD_UNLIKELY( err ) ) {
              return err;
            }
          } else if( view_acc->const_meta->dlen != pre_len || 
                     memcmp( post_data, view_acc->const_data, pre_len ) ) {
            return err;
          }
        }
        input_cursor += pre_len;
      }
      input_cursor += sizeof(fd_pubkey_t) + /* owner */
                      sizeof(uchar) +       /* executable */
                      sizeof(ulong);        /* rent_epoch*/
    }
  }

  if( FD_UNLIKELY( input_cursor>input+input_sz ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_valloc_free( ctx.valloc, input );

  return 0;
}
