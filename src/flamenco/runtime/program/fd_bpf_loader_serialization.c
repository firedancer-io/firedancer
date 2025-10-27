#include "fd_bpf_loader_serialization.h"
#include "../fd_borrowed_account.h"
#include "../fd_runtime.h"

/* This file is responsible for serializing and deserializing
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
  that memcpys for account data regions can't totally be avoided.

  SERIALIZATION BEHAVIOR
  ==========================================

  This implementation supports three distinct serialization modes based on two
  feature flags: stricter_abi_and_runtime_constraints and
  account_data_direct_mapping.

  MODE 1
  --------------------------------------
  stricter_abi_and_runtime_constraints = false
  account_data_direct_mapping          = false

  Memory Layout:
  - Single contiguous buffer in host memory
  - Buffer contains: [metadata1, data1, realloc_buffer1, metadata2, data2,
    realloc_buffer2, ..., metadataN, dataN, realloc_bufferN, instruction_info]
  - Each account gets: original data + MAX_PERMITTED_DATA_INCREASE (10KiB)
  - Padding added to maintain 16-byte alignment between accounts
  - Entire buffer is writable

  Memory Regions:
  - The entire input region buffer is mapped as one contiguous VM address
    space region

  Serialization Process:
  - Account data is memcpy'd into the buffer
  - 10KiB realloc buffer is zeroed out and appended after each account's data
  - Alignment padding is zeroed and added after realloc buffer

  Deserialization Process:
  - Account data must be memcpy'd back from buffer to borrowed account
  - For writable accounts: always copy data back
  - For read-only accounts: memcmp to verify data unchanged, error if modified
  - Account resizing allowed if account permissions permit it

  MODE 2
  -------------------------------------------
  stricter_abi_and_runtime_constraints = true
  account_data_direct_mapping          = false

  Memory Layout:
  - Still uses a single contiguous buffer, but organized into fragmented
    regions.
  - Each account now has separate regions for metadata and data+realloc.
  - Buffer contains: [metadata1, data1+realloc1, metadata2, data2+realloc2, ...,
    metadataN, dataN+reallocN, instruction_info].
  - Each metadata region and data region tracked separately in
    input_mem_regions.

  Memory Regions:
  - For each account:
    * Region 0: Account metadata (writable)
    * Region 1: Account data + realloc space (writable if account is writable)
  - If the account is owned by the deprecated loader, no realloc region is
    created as the deprecated loader does not support resizing accounts.

  Serialization:
  - Account metadata serialized first, added as a memory region.
  - Account data memcpy'd into buffer - not directly mapped.
  - 10KiB realloc buffer zeroed and appended (not direct mapped).
  - Data region created pointing to copied data in buffer.

  MODE 3: Direct Mapping (requires stricter_abi_and_runtime_constraints)
  -----------------------------------------------
  stricter_abi_and_runtime_constraints = true
  account_data_direct_mapping          = true

  This is very similar to stricter_abi_and_runtime_constraints, but account
  data is NOT copied into the input region buffer.

  Instead, the data region points directly to the staging area for the
  account in the transaction account's data. This staging area has enough
  space to hold the account data and the realloc buffer. Changes to this
  staging area will be written back to the account database in transaction
  finalization.
 */

/* Add a new memory region to represent the input region. All of the memory
   regions here have sorted virtual addresses. These regions may or may not
   correspond to an account's data region. If it corresponds to metadata,
   the pubkey for the region will be NULL. */
static void
new_input_mem_region( fd_vm_input_region_t * input_mem_regions,
                      uint *                 input_mem_regions_cnt,
                      const uchar *          buffer,
                      ulong                  region_sz,
                      ulong                  address_space_reserved,
                      uchar                  is_writable,
                      ulong                  acc_region_meta_idx ) {

  /* The start vaddr of the new region should be equal to start of the previous
     region added to the address space reserved for the region. */
  ulong vaddr_offset = *input_mem_regions_cnt==0UL ? 0UL : input_mem_regions[ *input_mem_regions_cnt-1U ].vaddr_offset +
                                                           input_mem_regions[ *input_mem_regions_cnt-1U ].address_space_reserved;
  input_mem_regions[ *input_mem_regions_cnt ].is_writable            = is_writable;
  input_mem_regions[ *input_mem_regions_cnt ].haddr                  = (ulong)buffer;
  input_mem_regions[ *input_mem_regions_cnt ].region_sz              = (uint)region_sz;
  input_mem_regions[ *input_mem_regions_cnt ].address_space_reserved = address_space_reserved;
  input_mem_regions[ *input_mem_regions_cnt ].vaddr_offset           = vaddr_offset;
  input_mem_regions[ *input_mem_regions_cnt ].acc_region_meta_idx    = acc_region_meta_idx;
  (*input_mem_regions_cnt)++;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L127-L189 */
/* This function handles casing for direct mapping being enabled as well as if
   the alignment is being stored. In the case where direct mapping is not
   enabled, we copy in the account data and a 10KiB buffer into the input region.
   These both go into the same memory buffer. However, when direct mapping is
   enabled, the account data and resizing buffers are represented by two
   different memory regions. In both cases, padding is used to maintain 8 byte
   alignment. If alignment is not required, then a resizing buffer is not used
   as the deprecated loader doesn't allow for resizing accounts. */
static ulong
write_account( fd_borrowed_account_t *   account,
               uchar                     instr_acc_idx,
               uchar * *                 serialized_params,
               uchar * *                 serialized_params_start,
               fd_vm_input_region_t *    input_mem_regions,
               uint *                    input_mem_regions_cnt,
               fd_vm_acc_region_meta_t * acc_region_metas,
               int                       is_loader_v1,
               int                       stricter_abi_and_runtime_constraints,
               int                       direct_mapping ) {

  uchar const * data = account ? fd_borrowed_account_get_data( account )     : NULL;
  ulong         dlen = account ? fd_borrowed_account_get_data_len( account ) : 0UL;

  acc_region_metas[instr_acc_idx].original_data_len = dlen;
  acc_region_metas[instr_acc_idx].acct              = account->acct;

  /* Legacy behavior: no stricter_abi_and_runtime_constraints (also implies no direct mapping)
     https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L131-L140 */
  if( !stricter_abi_and_runtime_constraints ) {
    /* Copy the account data into input region buffer */
    fd_memcpy( *serialized_params, data, dlen );
    *serialized_params += dlen;

    if( FD_LIKELY( !is_loader_v1 ) ) {
      /* Zero out padding bytes and max permitted data increase */
      ulong align_offset = fd_ulong_align_up( dlen, FD_BPF_ALIGN_OF_U128 ) - dlen;
      fd_memset( *serialized_params, 0, MAX_PERMITTED_DATA_INCREASE + align_offset );
      *serialized_params += MAX_PERMITTED_DATA_INCREASE + align_offset;
    }
    acc_region_metas[instr_acc_idx].region_idx = UINT_MAX;
  } else { /* stricter_abi_and_runtime_constraints == true */

    /* Set up account region metadata */
    acc_region_metas[instr_acc_idx].region_idx = *input_mem_regions_cnt;

    /* First, push on the region for the metadata that has just been serialized.
       This function will push the metadata in the serialized_params from
       serialized_params_start to serialized_params as a region to the input
       memory regions array.

       https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L142 */
    ulong region_sz = (ulong)(*serialized_params) - (ulong)(*serialized_params_start);
    new_input_mem_region( input_mem_regions, input_mem_regions_cnt, *serialized_params_start, region_sz, region_sz, 1U, ULONG_MAX );

    /* If direct mapping isn't enabled, then copy the account data in directly
       https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L144-L150 */
    if( !direct_mapping ) {
      fd_memcpy( *serialized_params, data, dlen );
      *serialized_params += dlen;
      if( FD_LIKELY( !is_loader_v1 ) ) {
        fd_memset( *serialized_params, 0, MAX_PERMITTED_DATA_INCREASE );
        *serialized_params += MAX_PERMITTED_DATA_INCREASE;
      }
    }

    /* Calculate address space reserved for account (data + realloc space)
       https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L151-L158 */
    ulong address_space_reserved = !is_loader_v1 ?
      fd_ulong_sat_add( dlen, MAX_PERMITTED_DATA_INCREASE ) : dlen;

    /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L159-L169 */
    if( address_space_reserved > 0 ) {
      int err = 0;
      uchar is_writable = !!(fd_borrowed_account_can_data_be_changed( account, &err ) && !err);

      if( !direct_mapping ) {
        /* Create region pointing to the copied data in buffer
           https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L160-L164 */
        uchar * data_start = *serialized_params - address_space_reserved;
        new_input_mem_region( input_mem_regions, input_mem_regions_cnt, data_start, dlen, address_space_reserved, is_writable, instr_acc_idx );
      } else {
        /* Direct mapping: create region pointing directly to account data */
        new_input_mem_region( input_mem_regions, input_mem_regions_cnt, data, dlen, address_space_reserved, is_writable, instr_acc_idx );
      }
    }

    *serialized_params_start = *serialized_params;

    /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L170-L186 */
    if( FD_LIKELY( !is_loader_v1 ) ) {
      ulong align_offset = fd_ulong_align_up( dlen, FD_BPF_ALIGN_OF_U128 ) - dlen;
      if( !direct_mapping ) {
        /* If direct mapping is not enabled, we do not align the start of each
           region metadata to FD_BPF_ALIGN_OF_U128, but we do align the start
           of the actual contents of the metadata region.

           This follows Agave's logic
           https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L173-L176 */
        fd_memset( *serialized_params, 0, align_offset );
        *serialized_params += align_offset;
      } else {
        /* If direct mapping is enabled, we align the start of each region
           metadata to FD_BPF_ALIGN_OF_U128. */
        fd_memset( *serialized_params, 0, FD_BPF_ALIGN_OF_U128 );
        *serialized_params       += FD_BPF_ALIGN_OF_U128;
        *serialized_params_start += fd_ulong_sat_sub( FD_BPF_ALIGN_OF_U128, align_offset );
      }
    }

    return region_sz + address_space_reserved;
  }

  return 0UL;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L466 */
static uchar *
fd_bpf_loader_input_serialize_aligned( fd_exec_instr_ctx_t *     ctx,
                                       ulong *                   sz,
                                       ulong *                   pre_lens,
                                       fd_vm_input_region_t *    input_mem_regions,
                                       uint *                    input_mem_regions_cnt,
                                       fd_vm_acc_region_meta_t * acc_region_metas,
                                       int                       stricter_abi_and_runtime_constraints,
                                       int                       direct_mapping ) {
  fd_pubkey_t * txn_accs = ctx->txn_ctx->account_keys;

  uchar acc_idx_seen[256] = {0};
  ushort dup_acc_idx[256] = {0};

  /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L482-L511 */
  ulong serialized_size = 0UL;
  serialized_size += sizeof(ulong); // acct_cnt
  /* First pass is to calculate size of buffer to allocate */
  for( ushort i=0; i<ctx->instr->acct_cnt; i++ ) {
    uchar acc_idx = (uchar)ctx->instr->accounts[i].index_in_transaction;

    serialized_size++; // dup byte
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      serialized_size += 7UL; // pad to 64-bit alignment
    } else {
      acc_idx_seen[acc_idx] = 1;
      dup_acc_idx[acc_idx]  = i;

      /* Borrow the account without checking the error, as it is guaranteed to exist
         https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L244-L257 */
      fd_guarded_borrowed_account_t view_acc = {0};
      fd_exec_instr_ctx_try_borrow_instr_account( ctx, i, &view_acc );

      ulong acc_data_len = fd_borrowed_account_get_data_len( &view_acc );

      serialized_size += sizeof(uchar)               // is_signer
                       + sizeof(uchar)               // is_writable
                       + sizeof(uchar)               // executable
                       + sizeof(uint)                // original_data_len
                       + sizeof(fd_pubkey_t)         // key
                       + sizeof(fd_pubkey_t)         // owner
                       + sizeof(ulong)               // lamports
                       + sizeof(ulong)               // data len
                       + sizeof(ulong);              // rent_epoch
      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L499-L505 */
      if( !(stricter_abi_and_runtime_constraints && direct_mapping) ) {
        serialized_size += MAX_PERMITTED_DATA_INCREASE + fd_ulong_align_up( acc_data_len, FD_BPF_ALIGN_OF_U128 );
      } else {
        serialized_size += FD_BPF_ALIGN_OF_U128;
      }
    }
  }

  serialized_size += sizeof(ulong)        // data len
                  +  ctx->instr->data_sz
                  +  sizeof(fd_pubkey_t); // program id

  /* 16-byte aligned buffer:
     https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L60
   */
  uchar * serialized_params            = fd_spad_alloc(
    ctx->txn_ctx->spad,
    FD_RUNTIME_EBPF_HOST_ALIGN,
    fd_ulong_align_up( serialized_size, FD_RUNTIME_EBPF_HOST_ALIGN ) );
  uchar * serialized_params_start      = serialized_params;
  uchar * curr_serialized_params_start = serialized_params;

  /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L522 */
  FD_STORE( ulong, serialized_params, ctx->instr->acct_cnt );
  serialized_params += sizeof(ulong);

  /* Second pass over the account is to serialize into the buffer.
     https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L523-L557 */
  for( ushort i=0; i<ctx->instr->acct_cnt; i++ ) {
    uchar         acc_idx = (uchar)ctx->instr->accounts[i].index_in_transaction;
    fd_pubkey_t * acc     = &txn_accs[acc_idx];

    if( FD_UNLIKELY( acc_idx_seen[acc_idx] && dup_acc_idx[acc_idx] != i ) ) {
      /* Duplicate. Store 8 byte buffer to maintain alignment but store the
         account index in the first byte.

         https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L551-L555 */
      FD_STORE( ulong, serialized_params, 0UL );
      FD_STORE( uchar, serialized_params, (uchar)dup_acc_idx[acc_idx] );
      serialized_params += sizeof(ulong);
    } else {
      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L526 */
      FD_STORE( uchar, serialized_params, FD_NON_DUP_MARKER );
      serialized_params += sizeof(uchar);

      /* Borrow the account without checking the error, as it is guaranteed to exist
         https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L244-L257 */
      fd_guarded_borrowed_account_t view_acc = {0};
      fd_exec_instr_ctx_try_borrow_instr_account( ctx, i, &view_acc );

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L525 */
      fd_account_meta_t const * metadata = fd_borrowed_account_get_acc_meta( &view_acc );

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L527 */
      uchar is_signer = (uchar)fd_instr_acc_is_signer_idx( ctx->instr, (uchar)i, NULL );
      FD_STORE( uchar, serialized_params, is_signer );
      serialized_params += sizeof(uchar);

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L528 */
      uchar is_writable = (uchar)fd_instr_acc_is_writable_idx( ctx->instr, (uchar)i );
      FD_STORE( uchar, serialized_params, is_writable );
      serialized_params += sizeof(uchar);

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L529-L530 */
      uchar is_executable = (uchar)metadata->executable;
      FD_STORE( uchar, serialized_params, is_executable );
      serialized_params += sizeof(uchar);

      /* The original data len field is intentionally NOT populated. */
      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L531 */
      uint padding_0 = 0U;
      FD_STORE( uint, serialized_params, padding_0 );
      serialized_params += sizeof(uint);

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L532 */
      fd_pubkey_t key = *acc;
      FD_STORE( fd_pubkey_t, serialized_params, key );
      acc_region_metas[i].expected_pubkey_offset = (uint)(serialized_params - curr_serialized_params_start);
      serialized_params += sizeof(fd_pubkey_t);

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L533 */
      fd_pubkey_t owner = *(fd_pubkey_t *)&metadata->owner;
      FD_STORE( fd_pubkey_t, serialized_params, owner );
      acc_region_metas[i].expected_owner_offset = (uint)(serialized_params - curr_serialized_params_start);
      serialized_params += sizeof(fd_pubkey_t);

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L534 */
      ulong lamports = metadata->lamports;
      FD_STORE( ulong, serialized_params, lamports );
      acc_region_metas[i].expected_lamports_offset = (uint)(serialized_params - curr_serialized_params_start);
      serialized_params += sizeof(ulong);

      ulong acc_data_len = metadata->dlen;
      pre_lens[i] = acc_data_len;

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L535 */
      ulong data_len = acc_data_len;
      FD_STORE( ulong, serialized_params, data_len );
      serialized_params += sizeof(ulong);

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L536 */
      write_account(
        &view_acc,
        (uchar)i,
        &serialized_params,
        &curr_serialized_params_start,
        input_mem_regions,
        input_mem_regions_cnt,
        acc_region_metas,
        0,
        stricter_abi_and_runtime_constraints,
        direct_mapping );

      /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L537-L541 */
      FD_STORE( ulong, serialized_params, ULONG_MAX );
      serialized_params += sizeof(ulong);
    }

  }

  /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L558 */
  ulong instr_data_len = ctx->instr->data_sz;
  FD_STORE( ulong, serialized_params, instr_data_len );
  serialized_params += sizeof(ulong);

  /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L559 */
  uchar * instr_data = ctx->instr->data;
  fd_memcpy( serialized_params, instr_data, instr_data_len );
  serialized_params += instr_data_len;

  /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L560 */
  FD_STORE( fd_pubkey_t, serialized_params, txn_accs[ctx->instr->program_id] );
  serialized_params += sizeof(fd_pubkey_t);

  /* Write out the final region. */
  ulong region_sz = (ulong)(serialized_params - curr_serialized_params_start);
  new_input_mem_region( input_mem_regions, input_mem_regions_cnt, curr_serialized_params_start,
                        region_sz, region_sz, 1U, ULONG_MAX );

  *sz = serialized_size;

  return serialized_params_start;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L566-L653 */
static int
fd_bpf_loader_input_deserialize_aligned( fd_exec_instr_ctx_t * ctx,
                                         ulong const *         pre_lens,
                                         uchar *               buffer,
                                         ulong FD_FN_UNUSED    buffer_sz,
                                         int                   stricter_abi_and_runtime_constraints,
                                         int                   direct_mapping ) {
  /* TODO: An optimization would be to skip ahead through non-writable accounts */
  /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L573 */
  ulong start = 0UL;

  uchar acc_idx_seen[256] = {0};

  start += sizeof(ulong); // number of accounts
  /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L574-L650 */
  for( ushort i=0; i<ctx->instr->acct_cnt; i++ ) {
    uchar acc_idx = (uchar)ctx->instr->accounts[i].index_in_transaction;

    start++; // position

    /* get the borrowed account
       https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L584-L585 */
    fd_guarded_borrowed_account_t view_acc = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, i, &view_acc );

    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L582 */
      start += 7UL;
    } else {
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L586-L590 */
      acc_idx_seen[acc_idx] = 1;
      start += sizeof(uchar)        // is_signer
             + sizeof(uchar)        // is_writable
             + sizeof(uchar)        // executable
             + sizeof(uint)         // original_data_len
             + sizeof(fd_pubkey_t); // key

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L591-L593 */

      fd_pubkey_t * owner = (fd_pubkey_t *)(buffer+start);
      start += sizeof(fd_pubkey_t); // owner

      ulong lamports = FD_LOAD( ulong, buffer+start );
      if( lamports!=fd_borrowed_account_get_lamports( &view_acc ) ) {
        int err = fd_borrowed_account_set_lamports( &view_acc, lamports );
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

      fd_account_meta_t const * metadata_check = fd_borrowed_account_get_acc_meta( &view_acc );
      if( FD_UNLIKELY( fd_ulong_sat_sub( post_len, metadata_check->dlen )>MAX_PERMITTED_DATA_INCREASE ||
                       post_len>MAX_PERMITTED_DATA_LENGTH ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
      }

      int can_data_be_changed_err = 0;
      if( !stricter_abi_and_runtime_constraints ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L617-L627 */

        /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L618-L620 */
        if( FD_UNLIKELY( start + post_len > buffer_sz ) ) {
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }

        /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L621-L626 */
        int can_data_be_resized_err = 0;
        if( fd_borrowed_account_can_data_be_resized( &view_acc, post_len, &can_data_be_resized_err ) &&
            fd_borrowed_account_can_data_be_changed( &view_acc, &can_data_be_changed_err ) ) {
          int set_data_err = fd_borrowed_account_set_data_from_slice( &view_acc, post_data, post_len );
          if( FD_UNLIKELY( set_data_err ) ) {
            return set_data_err;
          }
        } else {
          if( FD_UNLIKELY( fd_borrowed_account_get_data_len( &view_acc )!=post_len ||
                           memcmp( fd_borrowed_account_get_data( &view_acc ), post_data, post_len ) ) ) {
            return can_data_be_resized_err ? can_data_be_resized_err : can_data_be_changed_err;
          }
        }

      } else if( !direct_mapping && fd_borrowed_account_can_data_be_changed( &view_acc, &can_data_be_changed_err ) ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L629-L631 */
        if( FD_UNLIKELY( start + post_len > buffer_sz ) ) {
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }

        /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L627-L633 */
        int set_data_err = fd_borrowed_account_set_data_from_slice( &view_acc, post_data, post_len );
        if( FD_UNLIKELY( set_data_err ) ) {
          return set_data_err;
        }
      } else if( fd_borrowed_account_get_data_len( &view_acc ) != post_len ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L633-L635 */
        int set_data_length_err = fd_borrowed_account_set_data_length( &view_acc, post_len );
        if( FD_UNLIKELY( set_data_length_err ) ) {
          return set_data_length_err;
        }
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L636-L644 */
      if( !( stricter_abi_and_runtime_constraints && direct_mapping ) ) {
        start += fd_ulong_sat_add( MAX_PERMITTED_DATA_INCREASE, fd_ulong_sat_add( pre_len, alignment_offset ) );
      } else {
        start += FD_BPF_ALIGN_OF_U128;
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L645 */
      start += sizeof(ulong); // rent epoch
      if( memcmp( fd_borrowed_account_get_owner( &view_acc ), owner, sizeof(fd_pubkey_t) ) ) {
        int err = fd_borrowed_account_set_owner( &view_acc, owner );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      }
    }
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static uchar *
fd_bpf_loader_input_serialize_unaligned( fd_exec_instr_ctx_t *     ctx,
                                         ulong *                   sz,
                                         ulong *                   pre_lens,
                                         fd_vm_input_region_t *    input_mem_regions,
                                         uint *                    input_mem_regions_cnt,
                                         fd_vm_acc_region_meta_t * acc_region_metas,
                                         int                       stricter_abi_and_runtime_constraints,
                                         int                       direct_mapping ) {
  ulong               serialized_size = 0UL;
  fd_pubkey_t const * txn_accs        = ctx->txn_ctx->account_keys;

  uchar acc_idx_seen[256] = {0};
  ushort dup_acc_idx[256] = {0};

  serialized_size += sizeof(ulong);
  for( ushort i=0; i<ctx->instr->acct_cnt; i++ ) {
    uchar acc_idx = (uchar)ctx->instr->accounts[i].index_in_transaction;

    serialized_size++; // dup
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      continue;
    }

    acc_idx_seen[acc_idx] = 1;
    dup_acc_idx[acc_idx]  = i;

    /* Borrow the account without checking the error, as it is guaranteed to exist
         https://github.com/anza-xyz/agave/blob/v2.1.4/programs/bpf_loader/src/serialization.rs#L225 */
    fd_guarded_borrowed_account_t view_acc = {0};
    fd_exec_instr_ctx_try_borrow_instr_account( ctx, i, &view_acc );

    ulong acc_data_len = fd_borrowed_account_get_data_len( &view_acc );

    pre_lens[i] = acc_data_len;

    serialized_size += sizeof(uchar)        // is_signer
                      + sizeof(uchar)       // is_writable
                      + sizeof(fd_pubkey_t) // key
                      + sizeof(ulong)       // lamports
                      + sizeof(ulong)       // data_len
                      + sizeof(fd_pubkey_t) // owner
                      + sizeof(uchar)       // executable
                      + sizeof(ulong);      // rent_epoch
    if( !(stricter_abi_and_runtime_constraints && direct_mapping) ) {
      serialized_size += acc_data_len;
    }
  }

  serialized_size += sizeof(ulong)        // instruction data len
                   + ctx->instr->data_sz  // instruction data
                   + sizeof(fd_pubkey_t); // program id

  /* 16-byte aligned buffer:
     https://github.com/anza-xyz/agave/blob/v2.2.13/programs/bpf_loader/src/serialization.rs#L32
   */
  uchar * serialized_params            = fd_spad_alloc( ctx->txn_ctx->spad, FD_RUNTIME_EBPF_HOST_ALIGN, serialized_size );
  uchar * serialized_params_start      = serialized_params;
  uchar * curr_serialized_params_start = serialized_params;

  FD_STORE( ulong, serialized_params, ctx->instr->acct_cnt );
  serialized_params += sizeof(ulong);

  for( ushort i=0; i<ctx->instr->acct_cnt; i++ ) {
    uchar               acc_idx = (uchar)ctx->instr->accounts[i].index_in_transaction;
    fd_pubkey_t const * acc     = &txn_accs[acc_idx];

    if( FD_UNLIKELY( acc_idx_seen[acc_idx] && dup_acc_idx[acc_idx] != i ) ) {
      // Duplicate
      FD_STORE( uchar, serialized_params, (uchar)dup_acc_idx[acc_idx] );
      serialized_params += sizeof(uchar);
    } else {
      FD_STORE( uchar, serialized_params, FD_NON_DUP_MARKER );
      serialized_params += sizeof(uchar);

      /* Borrow the account without checking the error, as it is guaranteed to exist
         https://github.com/anza-xyz/agave/blob/v2.1.4/programs/bpf_loader/src/serialization.rs#L225 */
      fd_guarded_borrowed_account_t view_acc = {0};
      fd_exec_instr_ctx_try_borrow_instr_account( ctx, i, &view_acc );

      fd_account_meta_t const * metadata = fd_borrowed_account_get_acc_meta( &view_acc );

      uchar is_signer = (uchar)fd_instr_acc_is_signer_idx( ctx->instr, (uchar)i, NULL );
      FD_STORE( uchar, serialized_params, is_signer );
      serialized_params += sizeof(uchar);

      uchar is_writable = (uchar)fd_instr_acc_is_writable_idx( ctx->instr, (uchar)i );
      FD_STORE( uchar, serialized_params, is_writable );
      serialized_params += sizeof(uchar);

      fd_pubkey_t key = *acc;
      FD_STORE( fd_pubkey_t, serialized_params, key );
      acc_region_metas[i].expected_pubkey_offset = (uint)(serialized_params - curr_serialized_params_start);
      serialized_params += sizeof(fd_pubkey_t);

      ulong lamports = metadata->lamports;
      FD_STORE( ulong, serialized_params, lamports );
      acc_region_metas[i].expected_lamports_offset = (uint)(serialized_params - curr_serialized_params_start);
      serialized_params += sizeof(ulong);

      ulong acc_data_len = metadata->dlen;
      FD_STORE( ulong, serialized_params, acc_data_len );
      serialized_params += sizeof(ulong);

      ulong next_region_offset = write_account( &view_acc, (uchar)i,
        &serialized_params, &curr_serialized_params_start,
        input_mem_regions, input_mem_regions_cnt, acc_region_metas, 1,
        stricter_abi_and_runtime_constraints, direct_mapping );

      fd_pubkey_t owner = *(fd_pubkey_t *)&metadata->owner;
      FD_STORE( fd_pubkey_t, serialized_params, owner );
      acc_region_metas[i].expected_owner_offset = (uint)next_region_offset;
      serialized_params += sizeof(fd_pubkey_t);

      uchar is_executable = (uchar)metadata->executable;
      FD_STORE( uchar, serialized_params, is_executable );
      serialized_params += sizeof(uchar);

      FD_STORE( ulong, serialized_params, ULONG_MAX );
      serialized_params += sizeof(ulong);
    }
  }

  ulong instr_data_len = ctx->instr->data_sz;
  FD_STORE( ulong, serialized_params, instr_data_len );
  serialized_params += sizeof(ulong);

  uchar * instr_data = (uchar *)ctx->instr->data;
  fd_memcpy( serialized_params, instr_data, instr_data_len );
  serialized_params += instr_data_len;

  FD_STORE( fd_pubkey_t, serialized_params, txn_accs[ctx->instr->program_id] );
  serialized_params += sizeof(fd_pubkey_t);

  FD_TEST( serialized_params == serialized_params_start + serialized_size );
  *sz = serialized_size;

  ulong region_sz = (ulong)(serialized_params - curr_serialized_params_start);
  new_input_mem_region( input_mem_regions, input_mem_regions_cnt, curr_serialized_params_start,
    region_sz, region_sz, 1U, ULONG_MAX );

  return serialized_params_start;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L404 */
static int
fd_bpf_loader_input_deserialize_unaligned( fd_exec_instr_ctx_t * ctx,
                                           ulong const *         pre_lens,
                                           uchar *               input,
                                           ulong                 input_sz,
                                           int                   stricter_abi_and_runtime_constraints,
                                           int                   direct_mapping ) {
  uchar *       input_cursor      = input;
  uchar         acc_idx_seen[256] = {0};

  input_cursor += sizeof(ulong);

  for( ushort i=0; i<ctx->instr->acct_cnt; i++ ) {
    uchar acc_idx = (uchar)ctx->instr->accounts[i].index_in_transaction;

    input_cursor++; /* is_dup */
    if( FD_UNLIKELY( acc_idx_seen[acc_idx] ) ) {
      /* no-op */
    } else {
      acc_idx_seen[acc_idx] = 1;
      input_cursor += sizeof(uchar) +      /* is_signer */
                      sizeof(uchar) +      /* is_writable */
                      sizeof(fd_pubkey_t); /* key */

      /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/bpf_loader/src/serialization.rs#L378 */
      fd_guarded_borrowed_account_t view_acc = {0};
      FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, i, &view_acc );

      ulong lamports = FD_LOAD( ulong, input_cursor );
      if( fd_borrowed_account_get_acc_meta( &view_acc ) && fd_borrowed_account_get_lamports( &view_acc )!=lamports ) {
        int err = fd_borrowed_account_set_lamports( &view_acc, lamports );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      }

      input_cursor += sizeof(ulong); /* lamports */

      ulong post_len = FD_LOAD( ulong, input_cursor );
      input_cursor  += sizeof(ulong); /* data length */

      ulong pre_len     = pre_lens[i];
      uchar * post_data = input_cursor;

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L436-L446 */
      int can_data_be_changed_err = 0;
      if( !stricter_abi_and_runtime_constraints ) {
        int can_data_be_resized_err = 0;
        if( fd_borrowed_account_can_data_be_resized( &view_acc, pre_len, &can_data_be_resized_err ) &&
            fd_borrowed_account_can_data_be_changed( &view_acc, &can_data_be_changed_err ) ) {
          int set_data_err = fd_borrowed_account_set_data_from_slice( &view_acc, post_data, pre_len );
          if( FD_UNLIKELY( set_data_err ) ) {
            return set_data_err;
          }
        } else if( fd_borrowed_account_get_data_len( &view_acc ) != pre_len ||
                     memcmp( post_data, fd_borrowed_account_get_data( &view_acc ), pre_len ) ) {
            return can_data_be_resized_err ? can_data_be_resized_err : can_data_be_changed_err;
          }
      } else if( !direct_mapping && fd_borrowed_account_can_data_be_changed( &view_acc, &can_data_be_changed_err ) ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L446-L452 */
        int set_data_err = fd_borrowed_account_set_data_from_slice( &view_acc, post_data, post_len );
        if( FD_UNLIKELY( set_data_err ) ) {
          return set_data_err;
        }
      } else if( fd_borrowed_account_get_data_len( &view_acc ) != pre_len ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L452-L454 */
        int set_data_length_err = fd_borrowed_account_set_data_length( &view_acc, pre_len );
        if( FD_UNLIKELY( set_data_length_err ) ) {
          return set_data_length_err;
        }
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L455-L457 */
      if( !( stricter_abi_and_runtime_constraints && direct_mapping ) ) {
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

  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L221 */
int
fd_bpf_loader_input_serialize_parameters( fd_exec_instr_ctx_t *     instr_ctx,
                                          ulong *                   sz,
                                          ulong *                   pre_lens,
                                          fd_vm_input_region_t *    input_mem_regions,
                                          uint *                    input_mem_regions_cnt,
                                          fd_vm_acc_region_meta_t * acc_region_metas,
                                          int                       stricter_abi_and_runtime_constraints,
                                          int                       direct_mapping,
                                          uchar                     is_deprecated,
                                          uchar **                  out /* output */ ) {

  /* https://github.com/anza-xyz/agave/blob/v3.0.0/program-runtime/src/serialization.rs#L234-L237 */
  ulong num_ix_accounts = instr_ctx->instr->acct_cnt;
  if( FD_UNLIKELY( num_ix_accounts>=FD_INSTR_ACCT_MAX ) ) {
    return FD_EXECUTOR_INSTR_ERR_MAX_ACCS_EXCEEDED;
  }

  /* TODO: Like Agave's serialization functions, ours should probably return error codes

     https://github.com/anza-xyz/agave/blob/v2.1.11/programs/bpf_loader/src/serialization.rs#L237-L251 */
  if( FD_UNLIKELY( is_deprecated ) ) {
    *out = fd_bpf_loader_input_serialize_unaligned( instr_ctx, sz, pre_lens,
                                                    input_mem_regions, input_mem_regions_cnt,
                                                    acc_region_metas, stricter_abi_and_runtime_constraints,
                                                    direct_mapping );
  } else {
    *out = fd_bpf_loader_input_serialize_aligned( instr_ctx, sz, pre_lens,
                                                  input_mem_regions, input_mem_regions_cnt,
                                                  acc_region_metas, stricter_abi_and_runtime_constraints,
                                                  direct_mapping );
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L284-L311 */
int
fd_bpf_loader_input_deserialize_parameters( fd_exec_instr_ctx_t * ctx,
                                            ulong const *         pre_lens,
                                            uchar *               input,
                                            ulong                 input_sz,
                                            int                   stricter_abi_and_runtime_constraints,
                                            int                   direct_mapping,
                                            uchar                 is_deprecated ) {
  if( FD_UNLIKELY( is_deprecated ) ) {
    return fd_bpf_loader_input_deserialize_unaligned(
      ctx, pre_lens, input, input_sz, stricter_abi_and_runtime_constraints, direct_mapping );
  } else {
    return fd_bpf_loader_input_deserialize_aligned(
      ctx, pre_lens, input, input_sz, stricter_abi_and_runtime_constraints, direct_mapping );
  }
}
