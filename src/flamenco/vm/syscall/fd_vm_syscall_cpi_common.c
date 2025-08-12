/* This file contains all the logic that is common to both the C and Rust
   CPI syscalls (sol_invoke_signed_{rust/c}). As such, all of the functions in
   here are templated and will be instantiated for both the C and Rust CPI ABIs.

   The only difference between the C and Rust CPI syscalls is the ABI data layout
   of the parameters to these calls - all the logic is identical. As such, we have
   defined a series of macros to abstract away the ABI differences from the CPI implementation.

   The entry-point for these syscalls is VM_SYSCALL_CPI_ENTRYPOINT.

   Note that the code for these syscalls could be simplified somewhat, but we have opted to keep
   it as close to the Solana code as possible to make it easier to audit that we execute equivalently.
   Most of the top-level functions in this file correspond directly to functions in the Solana codebase
   and links to the source have been provided.
 */

/* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L23

   This is used for checking that the account info pointers given by the
   user match up with the addresses in the serialized account metadata.

   Field name length is restricted to 54 because
   127 - (37 + 18 + 18) leaves 54 characters for the field name
 */
#define VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, vm_addr, expected_vm_addr, field_name) \
  if( FD_UNLIKELY( vm_addr!=expected_vm_addr )) {                                                         \
    fd_log_collector_printf_dangerous_max_127( vm->instr_ctx,                                             \
      "Invalid account info pointer `%s': %#lx != %#lx", field_name, vm_addr, expected_vm_addr );         \
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );                                   \
    return FD_VM_SYSCALL_ERR_INVALID_POINTER;                                                             \
  }

/* fd_vm_syscall_cpi_instruction_to_instr_{c/rust} takes the translated
   CPI ABI structures (instruction and account meta list), and uses these
   to populate a fd_instr_info_t struct. This struct can then be given to the
   FD runtime for execution.

   WARNING:  out_instr will be partially filled if there are unmatched account
   metas (i.e,. no corresponding entry in the transaction accounts list). This
   is not an error condition. fd_vm_prepare_instruction has to handle that case
   in order to match Agave's behavior of checking presence in both transaction
   accounts list and caller instruction accounts list in a single loop iteration.

Parameters:
- vm: handle to the vm
- cpi_instr: instruction to execute laid out in the CPI ABI format (Rust or C)
- cpi_acc_metas: list of account metas, again in the CPI ABI format
- signers: derived signers for this CPI call
- signers_cnt: length of the signers list
- cpi_instr_data: instruction data in host address space

TODO: return codes/errors?
*/
#define VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_instruction_to_instr_, VM_SYSCALL_CPI_ABI)
static int
VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC( fd_vm_t *                         vm,
                                          VM_SYSCALL_CPI_INSTR_T const *    cpi_instr,
                                          VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_metas,
                                          fd_pubkey_t const *               program_id,
                                          uchar const *                     cpi_instr_data,
                                          fd_instr_info_t *                 out_instr,
                                          fd_pubkey_t                       out_instr_acct_keys[ FD_INSTR_ACCT_MAX ] ) {
  out_instr->program_id = UCHAR_MAX;
  out_instr->data_sz    = (ushort)VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instr );
  out_instr->data       = (uchar *)cpi_instr_data;
  out_instr->acct_cnt   = (ushort)VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instr );

  /* Find the index of the CPI instruction's program account in the transaction */
  int program_id_idx = fd_exec_txn_ctx_find_index_of_account( vm->instr_ctx->txn_ctx, program_id );
  if( FD_LIKELY( program_id_idx != -1 ) ) {
    out_instr->program_id = (uchar)program_id_idx;
  }

  uchar acc_idx_seen[ FD_INSTR_ACCT_MAX ] = {0};

  for( ushort i=0; i<VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instr ); i++ ) {
    VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_meta = &cpi_acct_metas[i];
    fd_pubkey_t const * pubkey = fd_type_pun_const( VM_SYSCALL_CPI_ACC_META_PUBKEY( vm, cpi_acct_meta ) );
    out_instr_acct_keys[i] = *pubkey;

    /* The parent flag(s) for is writable/signer is checked in
       fd_vm_prepare_instruction. Signer privilege is allowed iff the account
       is a signer in the caller or if it is a derived signer. */
    /* TODO: error if flags are wrong */
    out_instr->accounts[i] = fd_instruction_account_init( USHORT_MAX,
                                                          USHORT_MAX,
                                                          USHORT_MAX,
                                                          VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( cpi_acct_meta ),
                                                          VM_SYSCALL_CPI_ACC_META_IS_SIGNER( cpi_acct_meta ) );

    /* Use USHORT_MAX to indicate account not found
        https://github.com/anza-xyz/agave/blob/v2.1.14/program-runtime/src/invoke_context.rs#L366-L370 */
    int idx_in_txn    = fd_exec_txn_ctx_find_index_of_account( vm->instr_ctx->txn_ctx, pubkey );
    int idx_in_caller = fd_exec_instr_ctx_find_idx_of_instr_account( vm->instr_ctx, pubkey );

    fd_instr_info_setup_instr_account( out_instr,
                                       acc_idx_seen,
                                       idx_in_txn!=-1 ? (ushort)idx_in_txn : USHORT_MAX,
                                       idx_in_caller!=-1 ? (ushort)idx_in_caller : USHORT_MAX,
                                       i,
                                       VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( cpi_acct_meta ),
                                       VM_SYSCALL_CPI_ACC_META_IS_SIGNER( cpi_acct_meta ) );

  }

  return FD_VM_SUCCESS;
}

/*
fd_vm_syscall_cpi_update_callee_acc_{rust/c} corresponds to solana_bpf_loader_program::syscalls::cpi::update_callee_account:
https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L1302

(the copy of the account stored in the instruction context's
borrowed accounts cache)

This function should be called before the CPI instruction is executed. Its purpose is to
update the callee account's view of the given account with any changes the caller may made
to the account before the CPI instruction is executed.

The callee's view of the account is the borrowed accounts cache, so to update the
callee account we look up the account in the borrowed accounts cache and update it.

Paramaters:
- vm: pointer to the virtual machine handle
- account_info: account info object
- callee_acc_pubkey: pubkey of the account. this is used to look up the account in the borrowed accounts cache
  (TODO: this seems redundant? we can probably remove this, as the account_info contains the pubkey)
*/
#define VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_update_callee_acc_, VM_SYSCALL_CPI_ABI)
static int
VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC( fd_vm_t *                          vm,
                                      fd_vm_cpi_caller_account_t const * caller_account,
                                      uchar                              instr_acc_idx ) {
  int err;

  /* Borrow the callee account.
     TODO: Agave borrows before this function call. Consider refactoring to borrow the account at the same place as Agave.
     https://github.com/anza-xyz/agave/blob/v2.1.14/programs/bpf_loader/src/syscalls/cpi.rs#L893 */
  fd_guarded_borrowed_account_t callee_acc;
  err = fd_exec_instr_ctx_try_borrow_instr_account( vm->instr_ctx, instr_acc_idx, &callee_acc );
  if( FD_UNLIKELY( err ) ) {
    /* No need to do anything if the account is missing from the borrowed accounts cache */
    return FD_VM_SUCCESS;
  }

  if( fd_borrowed_account_get_lamports( &callee_acc )!=*(caller_account->lamports) ) {
    err = fd_borrowed_account_set_lamports( &callee_acc, *(caller_account->lamports) );
    if( FD_UNLIKELY( err ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }
  }

  if( !vm->direct_mapping ) {
    /* Get the account data */
    /* Update the account data, if the account data can be changed */
    /* FIXME: double-check these permissions, especially the callee_acc_idx */

    if( fd_borrowed_account_can_data_be_resized( &callee_acc, caller_account->serialized_data_len, &err ) &&
        fd_borrowed_account_can_data_be_changed( &callee_acc, &err ) ) {
        /* We must ignore the errors here, as they are informational and do not mean the result is invalid. */
        /* TODO: not pass informational errors like this? */

      err = fd_borrowed_account_set_data_from_slice( &callee_acc, caller_account->serialized_data, caller_account->serialized_data_len );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return -1;
      }
    } else if( FD_UNLIKELY( caller_account->serialized_data_len!=fd_borrowed_account_get_data_len( &callee_acc ) ||
                            memcmp( fd_borrowed_account_get_data( &callee_acc ), caller_account->serialized_data, caller_account->serialized_data_len ) ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }

  } else { /* Direct mapping enabled */
    ulong * ref_to_len = FD_VM_MEM_HADDR_ST( vm, caller_account->ref_to_len_in_vm.vaddr, alignof(ulong), sizeof(ulong) );
    ulong   orig_len   = caller_account->orig_data_len;
    ulong   prev_len   = fd_borrowed_account_get_data_len( &callee_acc );
    ulong   post_len   = *ref_to_len;

    int err;
    if( fd_borrowed_account_can_data_be_resized( &callee_acc, post_len, &err ) &&
        fd_borrowed_account_can_data_be_changed( &callee_acc, &err ) ) {

      ulong realloc_bytes_used = fd_ulong_sat_sub( post_len, orig_len );

      if( FD_UNLIKELY( vm->is_deprecated && realloc_bytes_used ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC );
        return -1;
      }

      err = fd_borrowed_account_set_data_length( &callee_acc, post_len );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return -1;
      }


      if( realloc_bytes_used ) {
        /* We need to get the relevant data slice. However, we know that the
           current length currently exceeds the original length for the account
           data. This means that all of the additional bytes must exist in the
           account data resizing region. As an invariant, original_len must be
           equal to the length of the account data region. This means we can
           smartly look up the right region and don't need to worry about
           multiple region access.We just need to load in the bytes from
           (original len, post_len]. */
        uchar const * realloc_data = FD_VM_MEM_SLICE_HADDR_LD( vm, caller_account->vm_data_vaddr+orig_len, alignof(uchar), realloc_bytes_used );

        uchar * data = NULL;
        ulong   dlen = 0UL;
        err = fd_borrowed_account_get_data_mut( &callee_acc, &data, &dlen );
        if( FD_UNLIKELY( err ) ) {
          FD_VM_ERR_FOR_LOG_INSTR( vm, err );
          return -1;
        }
        fd_memcpy( data+orig_len, realloc_data, realloc_bytes_used );
      }

    } else if( FD_UNLIKELY( prev_len!=post_len ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }
  }

  if( FD_UNLIKELY( memcmp( fd_borrowed_account_get_owner( &callee_acc ), caller_account->owner, sizeof(fd_pubkey_t) ) ) ) {
    err = fd_borrowed_account_set_owner( &callee_acc, caller_account->owner );
    if( FD_UNLIKELY( err ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }
  }

  return FD_VM_SUCCESS;
}

/*
fd_vm_syscall_cpi_translate_and_update_accounts_ mirrors the behaviour of
solana_bpf_loader_program::syscalls::cpi::translate_and_update_accounts:
https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L954-L1085

It translates the caller accounts to the host address space, and then calls
fd_vm_syscall_cpi_update_callee_acc to update the callee borrowed account with any changes
the caller has made to the account during execution before this CPI call.

It also populates the out_callee_indices and out_caller_indices arrays:
- out_callee_indices: indices of the callee accounts in the transaction
- out_caller_indices: indices of the caller accounts in the account_infos array

Parameters:
- vm: pointer to the virtual machine handle
- instruction_accounts: array of instruction accounts
- instruction_accounts_cnt: length of the instruction_accounts array
- account_infos: array of account infos
- account_infos_length: length of the account_infos array

Populates the given out_callee_indices and out_caller_indices arrays:
- out_callee_indices: indices of the callee accounts in the transaction
- out_caller_indices: indices of the caller accounts in the account_infos array
- out_len: length of the out_callee_indices and out_caller_indices arrays
*/
#define VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_translate_and_update_accounts_, VM_SYSCALL_CPI_ABI)
static int
VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC(
                              fd_vm_t *                         vm,
                              fd_instruction_account_t const *  instruction_accounts,
                              ulong const                       instruction_accounts_cnt,
                              ulong                             acct_infos_va,
                              fd_pubkey_t const * *             account_info_keys, /* same length as account_infos_length */
                              VM_SYSCALL_CPI_ACC_INFO_T const * account_infos,
                              ulong const                       account_infos_length,
                              ushort *                          out_callee_indices,
                              ushort *                          out_caller_indices,
                              fd_vm_cpi_caller_account_t *      caller_accounts,
                              ulong *                           out_len ) {
  for( ulong i=0UL; i<instruction_accounts_cnt; i++ ) {
    if( i!=instruction_accounts[i].index_in_callee ) {
      /* Skip duplicate accounts */
      continue;
    }

    /* `fd_vm_prepare_instruction()` will always set up a valid index for `index_in_caller`, so we can access the borrowed account directly.
       A borrowed account will always have non-NULL meta (if the account doesn't exist, `fd_executor_setup_accounts_for_txn()`
       will set its meta up) */

    /* https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L878-L881 */
    fd_guarded_borrowed_account_t callee_acct;
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( vm->instr_ctx, instruction_accounts[i].index_in_caller, &callee_acct );

    fd_pubkey_t const *       account_key = callee_acct.acct->pubkey;
    fd_account_meta_t const * acc_meta    = fd_borrowed_account_get_acc_meta( &callee_acct );

    /* If the account is known and executable, we only need to consume the compute units.
       Executable accounts can't be modified, so we don't need to update the callee account. */
    if( fd_borrowed_account_is_executable( &callee_acct ) ) {
      // FIXME: should this be FD_VM_CU_MEM_UPDATE? Changing this changes the CU behaviour from main (because of the base cost)
      FD_VM_CU_UPDATE( vm, acc_meta->dlen / FD_VM_CPI_BYTES_PER_UNIT );
      continue;
    }

    /* FIXME: we should not need to drop the account here to avoid a double borrow.
       Instead, we should borrow the account before entering this function. */
    fd_borrowed_account_drop( &callee_acct );

    /* Find the indicies of the account in the caller and callee instructions */
    uint found = 0;
    for( ushort j=0; j<account_infos_length && !found; j++ ) {
      fd_pubkey_t const * acct_addr = account_info_keys[ j ];
      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L912
       */
      if( memcmp( account_key->uc, acct_addr->uc, sizeof(fd_pubkey_t) ) != 0 ) {
        continue;
      }


      /* The following error is practically unreachable because
         essentially the same check is performed in
         prepare_instruction().  So a missing account error would have
         been returned then and there.  Hence, we are skipping this
         duplicate check here.
         https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L914-L923
       */


      /* The next iteration will overwrite this if it turns out that we
         do not need to preserve this for update_caller().
       */
      fd_vm_cpi_caller_account_t * caller_account = caller_accounts + *out_len;
      /* Record the indicies of this account */
      ushort index_in_caller = instruction_accounts[i].index_in_caller;
      if (instruction_accounts[i].is_writable) {
        out_callee_indices[*out_len] = index_in_caller;
        out_caller_indices[*out_len] = j;
        (*out_len)++;
      }
      found = 1;

      /* Logically this check isn't ever going to fail due to how the
         account_info_keys array is set up.  We replicate the check for
         clarity and also to guard against accidental violation of the
         assumed invariant in the future.
         https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L926-L928
       */
      if( FD_UNLIKELY( j >= account_infos_length ) ) {
        FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );
        return FD_VM_SYSCALL_ERR_INVALID_LENGTH;
      }

      /* The following implements the checks in from_account_info which
         is invoked as do_translate() in translate_and_update_accounts()
         https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L931
       */
      ////// BEGIN from_account_info

      fd_vm_acc_region_meta_t * acc_region_meta = &vm->acc_region_metas[index_in_caller];
      if( FD_LIKELY( vm->direct_mapping ) ) {
        /* https://github.com/anza-xyz/agave/blob/v2.1.7/programs/bpf_loader/src/syscalls/cpi.rs#L116
         */
        ulong expected_pubkey_vaddr = serialized_pubkey_vaddr( vm, acc_region_meta );
        /* Max msg_sz: 40 + 18 + 18 = 76 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, account_infos[j].pubkey_addr, expected_pubkey_vaddr, "key");

        /* https://github.com/anza-xyz/agave/blob/v2.1.7/programs/bpf_loader/src/syscalls/cpi.rs#L122
         */
        ulong expected_owner_vaddr = serialized_owner_vaddr( vm, acc_region_meta );
        /* Max msg_sz: 42 + 18 + 18 = 78 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, account_infos[j].owner_addr, expected_owner_vaddr, "owner");
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L134
       */
      VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_VADDR( vm, (account_infos + j), lamports_vaddr );
      if( FD_LIKELY( vm->direct_mapping ) ) {
        /* https://github.com/anza-xyz/agave/blob/v2.1.7/programs/bpf_loader/src/syscalls/cpi.rs#L140
           Check that the account's lamports Rc<RefCell<&mut u64>> is
           not stored in the account.
           Because a refcell is only present if the Rust SDK is used, we
           only need to check this for the Rust ABI.
        */
        #ifdef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_RC_REFCELL_VADDR
        VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_RC_REFCELL_VADDR( vm, (account_infos + j), lamports_rc_vaddr )
        if ( FD_UNLIKELY( lamports_rc_vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
          FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
          return FD_VM_SYSCALL_ERR_INVALID_POINTER;
        }
        #endif

        /* https://github.com/anza-xyz/agave/blob/v2.1.7/programs/bpf_loader/src/syscalls/cpi.rs#L144
         */
        ulong expected_lamports_vaddr = serialized_lamports_vaddr( vm, acc_region_meta );
        /* Max msg_sz: 45 + 18 + 18 = 81 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, lamports_vaddr, expected_lamports_vaddr, "lamports");
      }
      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L151
       */
      VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, (account_infos + j), lamports_haddr );
      caller_account->lamports = lamports_haddr;

      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L154
       */
      caller_account->owner = FD_VM_MEM_HADDR_ST( vm, (account_infos + j)->owner_addr, alignof(uchar), sizeof(fd_pubkey_t) );

      if( FD_LIKELY( vm->direct_mapping ) ) {
        /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L161
           Check that the account's data Rc<RefCell<T>> is not stored in
           the account.
           Because a refcell is only present if the Rust SDK is used, we
           only need to check this for the Rust ABI.
         */
        #ifdef VM_SYSCALL_CPI_ACC_INFO_DATA_RC_REFCELL_VADDR
        VM_SYSCALL_CPI_ACC_INFO_DATA_RC_REFCELL_VADDR( vm, (account_infos + j), data_rc_vaddr )
        if( FD_UNLIKELY( data_rc_vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
          FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
          return FD_VM_SYSCALL_ERR_INVALID_POINTER;
        }
        #endif
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L166
       */
      VM_SYSCALL_CPI_ACC_INFO_DATA_VADDR( vm, (account_infos + j), data_vaddr );

      if( FD_LIKELY( vm->direct_mapping ) ) {
        /* https://github.com/anza-xyz/agave/blob/v2.1.7/programs/bpf_loader/src/syscalls/cpi.rs#L172 */
        ulong expected_data_region_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START +
          vm->input_mem_regions[acc_region_meta->region_idx].vaddr_offset;
        /* Max msg_sz: 41 + 18 + 18 = 77 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, data_vaddr, expected_data_region_vaddr, "data");
      }

      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L180
       */
      VM_SYSCALL_CPI_SET_ACC_INFO_DATA_GET_LEN( vm, (account_infos + j), data_vaddr );
      FD_VM_CU_UPDATE( vm, data_vaddr_len / FD_VM_CPI_BYTES_PER_UNIT );

      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L187
         https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L331
       */
      #ifdef VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR
      /* Rust ABI */
      VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR( vm, (account_infos + j), data_len_vaddr );
      (void)acct_infos_va;
      #else
      /* C ABI */
      ulong data_len_vaddr = vm_syscall_cpi_data_len_vaddr_c(
        fd_ulong_sat_add( acct_infos_va, fd_ulong_sat_mul( j, VM_SYSCALL_CPI_ACC_INFO_SIZE ) ),
        (ulong)&((account_infos + j)->data_sz),
        (ulong)(account_infos + j)
      );
      #endif
      if( FD_LIKELY( vm->direct_mapping ) ) {
        #ifdef VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR
        /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L193
         */
        if( FD_UNLIKELY( data_len_vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
          FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
          return FD_VM_SYSCALL_ERR_INVALID_POINTER;
        }
        #endif
        caller_account->ref_to_len_in_vm.vaddr = data_len_vaddr;
      }
      if( FD_UNLIKELY( !vm->direct_mapping ) ) {
        ulong * data_len = FD_VM_MEM_HADDR_ST(
          vm,
          data_len_vaddr,
          1UL,
          sizeof(ulong)
        );
        caller_account->ref_to_len_in_vm.translated = data_len;
      }
      caller_account->vm_data_vaddr   = data_vaddr;

      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L228
       */
      caller_account->serialized_data = NULL;
      if( FD_UNLIKELY( !vm->direct_mapping ) ) {
        VM_SYSCALL_CPI_ACC_INFO_DATA( vm, (account_infos + j), data_haddr );
        (void)data_haddr_vm_addr;
        caller_account->serialized_data     = data_haddr;
        caller_account->serialized_data_len = data_haddr_len;
      }

      caller_account->orig_data_len = acc_region_meta->original_data_len;

      ////// END from_account_info

      // TODO We should be able to cache the results of translation and reuse them in the update function.
      /* Update the callee account to reflect any changes the caller has made */
      int err = VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC( vm, caller_account, (uchar)index_in_caller );
      if( FD_UNLIKELY( err ) ) {
        /* errors are propagated in the function itself. */
        return err;
      }
    }

    if( !found ) {
      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L966 */
      FD_BASE58_ENCODE_32_BYTES( account_key->uc, id_b58 );
      fd_log_collector_msg_many( vm->instr_ctx, 2, "Instruction references an unknown account ", 42UL, id_b58, id_b58_len );
      FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_MISSING_ACC );
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
  }

  return FD_VM_SUCCESS;
}

/* fd_vm_cpi_update_caller_acc_{rust/c} mirrors the behaviour of
solana_bpf_loader_program::syscalls::cpi::update_caller_account:
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1291

This method should be called after a CPI instruction execution has
returned. It updates the given caller account info with any changes the callee
has made to this account during execution, so that those changes are
reflected in the rest of the caller's execution.

Those changes will be in the instructions borrowed accounts cache.

Paramaters:
- vm: handle to the vm
- caller_acc_info: caller account info object, which should be updated
- pubkey: pubkey of the account

TODO: error codes
*/
#define VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_cpi_update_caller_acc_, VM_SYSCALL_CPI_ABI)
static int
VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC( fd_vm_t *                          vm,
                                       VM_SYSCALL_CPI_ACC_INFO_T const *  caller_acc_info,
                                       fd_vm_cpi_caller_account_t const * caller_account,
                                       uchar                              instr_acc_idx,
                                       fd_pubkey_t const *                pubkey ) {
  int err;

  if( !vm->direct_mapping ) {
    /* Look up the borrowed account from the instruction context, which will contain
      the callee's changes.
      TODO: Agave borrows before entering this function. We should consider doing the same.
      https://github.com/anza-xyz/agave/blob/v2.1.14/programs/bpf_loader/src/syscalls/cpi.rs#L1168-L1169 */
    fd_guarded_borrowed_account_t borrowed_callee_acc;
    err = fd_exec_instr_ctx_try_borrow_instr_account_with_key( vm->instr_ctx, pubkey, &borrowed_callee_acc );
    if( FD_UNLIKELY( err && ( err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) ) {
      return 1;
    }

    fd_txn_account_t * callee_acc = borrowed_callee_acc.acct;
    /* Update the caller account lamports with the value from the callee */
    *(caller_account->lamports) = fd_txn_account_get_lamports( callee_acc );

    /* Update the caller account owner with the value from the callee */
    fd_pubkey_t const * updated_owner = fd_txn_account_get_owner( callee_acc );
    if( updated_owner ) *caller_account->owner = *updated_owner;
    else                fd_memset( caller_account->owner, 0,             sizeof(fd_pubkey_t) );

    /* Update the caller account data with the value from the callee */
    VM_SYSCALL_CPI_ACC_INFO_DATA( vm, caller_acc_info, caller_acc_data );

    ulong const updated_data_len = fd_txn_account_get_data_len( callee_acc );
    if( !updated_data_len ) fd_memset( (void*)caller_acc_data, 0, caller_acc_data_len );
    ulong * ref_to_len = caller_account->ref_to_len_in_vm.translated;
    if( *ref_to_len != updated_data_len ) {
      ulong max_increase = (vm->direct_mapping && vm->is_deprecated) ? 0UL : MAX_PERMITTED_DATA_INCREASE;
      // https://github.com/anza-xyz/agave/blob/7f3a6cf6d3c2dcc81bb38e49a5c9ef998a6f4dd9/programs/bpf_loader/src/syscalls/cpi.rs#L1387-L1397
      if( FD_UNLIKELY( updated_data_len>fd_ulong_sat_add( caller_account->orig_data_len, max_increase ) ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC);
        return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
      }

      /* FIXME: do we need to zero the memory that was previously used, if the new data_len is smaller?
      https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1361
        I don't think we do but need to double-check. */

      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L1453
       */
      caller_acc_data = FD_VM_MEM_SLICE_HADDR_ST( vm, caller_acc_data_vm_addr, alignof(uchar), updated_data_len );

      *ref_to_len = updated_data_len;

      /* Update the serialized len field
        https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1437 */
      ulong * caller_len = FD_VM_MEM_HADDR_ST( vm, fd_ulong_sat_sub(caller_acc_data_vm_addr, sizeof(ulong)), alignof(ulong), sizeof(ulong) );
      *caller_len = updated_data_len;

      /* FIXME return instruction error account data size too small in the same scenarios solana does
        https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1534 */
    }

    fd_memcpy( caller_acc_data, fd_txn_account_get_data( callee_acc ), updated_data_len );
  } else { /* Direct mapping enabled */

    /* Look up the borrowed account from the instruction context, which will
       contain the callee's changes.
       TODO: Agave borrows before entering this function. We should consider doing the same.
       https://github.com/anza-xyz/agave/blob/v2.1.14/programs/bpf_loader/src/syscalls/cpi.rs#L1168-L1169 */
    fd_guarded_borrowed_account_t borrowed_callee_acc;
    err = fd_exec_instr_ctx_try_borrow_instr_account_with_key( vm->instr_ctx, pubkey, &borrowed_callee_acc );
    if( FD_UNLIKELY( err && ( err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) ) {
      return 1;
    }

    fd_txn_account_t * callee_acc = borrowed_callee_acc.acct;

    /* Update the caller account lamports with the value from the callee */
    *(caller_account->lamports) = fd_txn_account_get_lamports( callee_acc );

    /* Update the caller account owner with the value from the callee */
    fd_pubkey_t const * updated_owner = fd_txn_account_get_owner( callee_acc );
    if( updated_owner ) {
      *caller_account->owner = *updated_owner;
    } else {
      fd_memset( caller_account->owner, 0,             sizeof(fd_pubkey_t) );
    }

    /* Make sure that the capacity of the borrowed account is sized up in case
       it was shrunk in the CPI. It needs to be sized up in order to fit within
       the originally delinated regions when the account data was serialized.
       https://github.com/anza-xyz/agave/blob/36323b6dcd3e29e4d6fe6d73d716a3f33927148b/programs/bpf_loader/src/syscalls/cpi.rs#L1311 */
    VM_SYSCALL_CPI_ACC_INFO_METADATA( vm, caller_acc_info, caller_acc_data );
    ulong original_len = caller_account->orig_data_len;

    uchar zero_all_mapped_spare_capacity = 0;
    /* This case can only be triggered if the original length is more than 0 */
    if( fd_txn_account_get_data_len( callee_acc )<original_len ) {
      ulong new_len = fd_txn_account_get_data_len( callee_acc );
      /* Allocate into the buffer to make sure that the original data len
         is still valid but don't change the dlen. Zero out the rest of the
         memory which is not used. */
      fd_txn_account_resize( callee_acc, original_len );
      fd_txn_account_set_data_len( callee_acc, new_len );
      zero_all_mapped_spare_capacity = 1;
    }

    /* Update the account data region if an account data region exists. We
       know that one exists iff the original len was non-zero. */
    ulong acc_region_idx = vm->acc_region_metas[instr_acc_idx].region_idx;
    if( original_len && vm->input_mem_regions[ acc_region_idx ].haddr!=(ulong)fd_txn_account_get_data_mut( callee_acc ) ) {
      vm->input_mem_regions[ acc_region_idx ].haddr = (ulong)fd_txn_account_get_data_mut( callee_acc );
      zero_all_mapped_spare_capacity = 1;
    }

    ulong prev_len = caller_acc_data_len;
    ulong post_len = fd_txn_account_get_data_len( callee_acc );

    /* Do additional handling in the case where the data size has changed in
       the course of the callee's CPI. */
    if( prev_len!=post_len ) {
      /* There is an illegal data overflow if the post len is greater than the
         original data len + the max resizing limit (10KiB). Can't resize the
         account if the deprecated loader is being used */
      ulong max_increase = vm->is_deprecated ? 0UL : MAX_PERMITTED_DATA_INCREASE;
      if( FD_UNLIKELY( post_len>fd_ulong_sat_add( (ulong)original_len, max_increase ) ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC);
        return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
      }
      /* There is additonal handling in the case where the account is larger
         than it was previously, but it has still grown since it was initially
         serialized. To handle this, we need to just zero out the now unused
         space in the account resizing region. */
      if( post_len<prev_len && prev_len>original_len ) {
        ulong dirty_realloc_start = fd_ulong_max( post_len, original_len );
        ulong dirty_realloc_len   = fd_ulong_sat_sub( prev_len, dirty_realloc_start );
        /* We don't have to worry about multiple region writes here since we
           know the amount to zero out is located in the account's data
           resizing region. We intentionally write to the pointer despite
           loading it in because we assume that the permissions were changed
           in the callee. */
        uchar * dirty_region = FD_VM_MEM_HADDR_ST_WRITE_UNCHECKED( vm, caller_acc_data_vm_addr + dirty_realloc_start,
                                                                   alignof(uchar), dirty_realloc_len );
        fd_memset( dirty_region, 0, dirty_realloc_len );
      }

      /* Because the account data length changed from before to after the
         CPI we must update the fields appropriately. */
      ulong * ref_to_len = FD_VM_MEM_HADDR_ST( vm, caller_account->ref_to_len_in_vm.vaddr, alignof(ulong), sizeof(ulong) );
      *ref_to_len = post_len;
      ulong * serialized_len_ptr = FD_VM_MEM_HADDR_ST( vm, fd_ulong_sat_sub( caller_acc_data_vm_addr, sizeof(ulong) ), alignof(ulong), sizeof(ulong) );
      *serialized_len_ptr = post_len;
    }

    /* We need to zero out the end of the account data buffer if the account
       shrunk in size. This is because the bytes are accessible from within
       the VM but should be equal to zero to prevent undefined behavior. If
       prev_len > post_len, then dlen should be equal to original_len. */
    ulong spare_len = fd_ulong_sat_sub( fd_ulong_if( zero_all_mapped_spare_capacity, original_len, prev_len ), post_len );
    if( FD_UNLIKELY( spare_len ) ) {
      if( fd_txn_account_get_data_len( callee_acc )>spare_len ) {
        memset( fd_txn_account_get_data_mut( callee_acc ) + fd_txn_account_get_data_len( callee_acc ) - spare_len, 0, spare_len );
      }
    }

    ulong realloc_bytes_used = fd_ulong_sat_sub( post_len, original_len );
    if( realloc_bytes_used && !vm->is_deprecated ) {
      /* We intentionally do a load in the case where we are writing to because
         we want to ignore the write checks. We load from the first byte of the
         resizing region */
      ulong resizing_idx = vm->acc_region_metas[ instr_acc_idx ].region_idx;
      if( vm->acc_region_metas[ instr_acc_idx ].has_data_region ) {
        resizing_idx++;
      }
      uchar * to_slice   = (uchar*)vm->input_mem_regions[ resizing_idx ].haddr;
      uchar * from_slice = fd_txn_account_get_data_mut( callee_acc ) + original_len;

      fd_memcpy( to_slice, from_slice, realloc_bytes_used );
    }
  }

  return FD_VM_SUCCESS;
}

/* fd_vm_syscall_cpi_{rust/c} is the entrypoint for the sol_invoke_signed_{rust/c} syscalls.

The bulk of the high-level logic mirrors Solana's cpi_common entrypoint function at
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1060
The only differences should be in the order of the error checks, which does not affect consensus.

100-foot flow:
- Translate the CPI ABI structures to the FD runtime's instruction format
- Update the callee accounts with any changes made by the caller prior to this CPI instruction
- Dispatch the instruction to the FD runtime (actually making the CPI call)
- Update the caller accounts with any changes made by the callee during CPI execution

Paramaters:
- vm: pointer to the virtual machine handle
- instruction_va: vm address of the instruction to execute, which will be in the language-specific ABI format.
- acct_infos_va: vm address of the account infos, which will be in the language-specific ABI format.
- acct_info_cnt: number of account infos
- signers_seeds_va: vm address of the signers seeds
- signers_seeds_cnt: number of signers seeds
- _ret: pointer to the return value
*/
#define VM_SYSCALL_CPI_ENTRYPOINT FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_, VM_SYSCALL_CPI_ABI)
int
VM_SYSCALL_CPI_ENTRYPOINT( void *  _vm,
                           ulong   instruction_va,
                           ulong   acct_infos_va,
                           ulong   acct_info_cnt,
                           ulong   signers_seeds_va,
                           ulong   signers_seeds_cnt,
                           ulong * _ret ) {

  fd_vm_t * vm = (fd_vm_t *)_vm;

  FD_VM_CU_UPDATE( vm, FD_VM_INVOKE_UNITS );

  /* Translate instruction ********************************************/
  /* translate_instruction is the first thing that agave does
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/programs/bpf_loader/src/syscalls/cpi.rs#L1089 */

  /* Translating the CPI instruction
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/programs/bpf_loader/src/syscalls/cpi.rs#L420-L424 */
  VM_SYSCALL_CPI_INSTR_T const * cpi_instruction =
    FD_VM_MEM_HADDR_LD( vm, instruction_va, VM_SYSCALL_CPI_INSTR_ALIGN, VM_SYSCALL_CPI_INSTR_SIZE );

  /* This needs to be here for the C ABI
     https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L655
   */
  fd_pubkey_t const * program_id = (fd_pubkey_t *)VM_SYSCALL_CPI_INSTR_PROGRAM_ID( vm, cpi_instruction );

  /* Translate CPI account metas *************************************************/
  VM_SYSCALL_CPI_ACC_META_T const * cpi_account_metas =
    FD_VM_MEM_SLICE_HADDR_LD( vm, VM_SYSCALL_CPI_INSTR_ACCS_ADDR( cpi_instruction ),
                              VM_SYSCALL_CPI_ACC_META_ALIGN,
                              fd_ulong_sat_mul( VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ), VM_SYSCALL_CPI_ACC_META_SIZE ) );

  /* Translate instruction data *************************************************/

  uchar const * data = FD_VM_MEM_SLICE_HADDR_LD(
    vm, VM_SYSCALL_CPI_INSTR_DATA_ADDR( cpi_instruction ),
    FD_VM_ALIGN_RUST_U8,
    VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ));


  /* Instruction checks ***********************************************/

  int err = fd_vm_syscall_cpi_check_instruction( vm, VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ), VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) );
  if( FD_UNLIKELY( err ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, err );
    return err;
  }

  /* Agave consumes CU in translate_instruction
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/programs/bpf_loader/src/syscalls/cpi.rs#L445 */
  if( FD_FEATURE_ACTIVE_BANK( vm->instr_ctx->txn_ctx->bank, loosen_cpi_size_restriction ) ) {
    FD_VM_CU_UPDATE( vm, VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) / FD_VM_CPI_BYTES_PER_UNIT );
  }

  /* Final checks for translate_instruction
   */
  for( ulong i=0UL; i<VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ); i++ ) {
    VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_meta = &cpi_account_metas[i];
    if( FD_UNLIKELY( cpi_acct_meta->is_signer > 1U || cpi_acct_meta->is_writable > 1U ) ) {
      /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L471
         https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L698
       */
      FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_ARG );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    /* https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L700
     */
    (void)VM_SYSCALL_CPI_ACC_META_PUBKEY( vm, cpi_acct_meta );
  }

  /* Derive PDA signers ************************************************/
  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ] = {0};
  fd_pubkey_t * caller_program_id = &vm->instr_ctx->txn_ctx->account_keys[ vm->instr_ctx->instr->program_id ];
  /* This is the equivalent of translate_slice in translate_signers:
     https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L595 */
  if( FD_LIKELY( signers_seeds_cnt > 0UL ) ) {
    fd_vm_vec_t const * signers_seeds = FD_VM_MEM_SLICE_HADDR_LD( vm, signers_seeds_va, FD_VM_ALIGN_RUST_SLICE_U8_REF, fd_ulong_sat_mul( signers_seeds_cnt, FD_VM_VEC_SIZE ) );
    /* Right after translating, Agave checks against MAX_SIGNERS:
       https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L602 */
    if( FD_UNLIKELY( signers_seeds_cnt > FD_CPI_MAX_SIGNER_CNT ) ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_TOO_MANY_SIGNERS );
      return FD_VM_SYSCALL_ERR_TOO_MANY_SIGNERS;
    }

    for( ulong i=0UL; i<signers_seeds_cnt; i++ ) {

      /* This function will precompute the memory translation required and do
        some preflight checks. */
      void const * signer_seed_haddrs[ FD_VM_PDA_SEEDS_MAX ];
      ulong        signer_seed_lens  [ FD_VM_PDA_SEEDS_MAX ];

      int err = fd_vm_translate_and_check_program_address_inputs( vm,
                                                                  signers_seeds[i].addr,
                                                                  signers_seeds[i].len,
                                                                  0UL,
                                                                  signer_seed_haddrs,
                                                                  signer_seed_lens ,
                                                                  NULL,
                                                                  0U );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

      err = fd_vm_derive_pda( vm, caller_program_id, signer_seed_haddrs, signer_seed_lens, signers_seeds[i].len, NULL, &signers[i] );
      if( FD_UNLIKELY( err ) ) {
        FD_TXN_PREPARE_ERR_OVERWRITE( vm->instr_ctx->txn_ctx );
        FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_BAD_SEEDS );
        return FD_VM_SYSCALL_ERR_BAD_SEEDS;
      }
    }
  }

  /* Create the instruction to execute (in the input format the FD runtime expects) from
     the translated CPI ABI inputs. */
  fd_pubkey_t cpi_instr_acct_keys[ FD_INSTR_ACCT_MAX ];
  fd_instr_info_t * instruction_to_execute = &vm->instr_ctx->txn_ctx->cpi_instr_infos[ vm->instr_ctx->txn_ctx->cpi_instr_info_cnt++ ];

  err = VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC( vm, cpi_instruction, cpi_account_metas, program_id, data, instruction_to_execute, cpi_instr_acct_keys );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* Prepare the instruction for execution in the runtime. This is required by the runtime
     before we can pass an instruction to the executor. */
  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;
  err = fd_vm_prepare_instruction( instruction_to_execute, vm->instr_ctx, program_id, cpi_instr_acct_keys, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  /* Errors are propagated in the function itself. */
  if( FD_UNLIKELY( err ) ) return err;

  /* Authorized program check *************************************************/

  if( FD_UNLIKELY( fd_vm_syscall_cpi_check_authorized_program( program_id, vm->instr_ctx->txn_ctx, data, VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) ) ) ) {
    /* https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1054 */
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_PROGRAM_NOT_SUPPORTED );
    return FD_VM_SYSCALL_ERR_PROGRAM_NOT_SUPPORTED;
  }

  /* Translate account infos ******************************************/
  /* Direct mapping check
     https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/cpi.rs#L805-L814 */
  ulong acc_info_total_sz = fd_ulong_sat_mul( acct_info_cnt, VM_SYSCALL_CPI_ACC_INFO_SIZE );
  if( FD_UNLIKELY( vm->direct_mapping && fd_ulong_sat_add( acct_infos_va, acc_info_total_sz ) >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
    return FD_VM_SYSCALL_ERR_INVALID_POINTER;
  }

  /* This is the equivalent of translate_slice in translate_account_infos:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/programs/bpf_loader/src/syscalls/cpi.rs#L816 */
  VM_SYSCALL_CPI_ACC_INFO_T const * acc_infos = FD_VM_MEM_SLICE_HADDR_LD( vm, acct_infos_va, VM_SYSCALL_CPI_ACC_INFO_ALIGN, acc_info_total_sz );

  /* Right after translating, Agave checks the number of account infos:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/programs/bpf_loader/src/syscalls/cpi.rs#L822 */
  if( FD_FEATURE_ACTIVE_BANK( vm->instr_ctx->txn_ctx->bank, loosen_cpi_size_restriction ) ) {
    if( FD_UNLIKELY( acct_info_cnt > get_cpi_max_account_infos( vm->instr_ctx->txn_ctx ) ) ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED );
      return FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED;
    }
  } else {
    ulong adjusted_len = fd_ulong_sat_mul( acct_info_cnt, sizeof( fd_pubkey_t ) );
    if ( FD_UNLIKELY( adjusted_len > FD_VM_MAX_CPI_INSTRUCTION_SIZE ) ) {
      /* "Cap the number of account_infos a caller can pass to approximate
          maximum that accounts that could be passed in an instruction" */
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_TOO_MANY_ACCOUNTS );
      return FD_VM_SYSCALL_ERR_TOO_MANY_ACCOUNTS;
    }
  }

  fd_pubkey_t const * acct_info_keys[ FD_CPI_MAX_ACCOUNT_INFOS ];
  for( ulong acct_idx = 0UL; acct_idx < acct_info_cnt; acct_idx++ ) {
    /* Translate each pubkey address specified in account_infos.
       Failed translation should lead to an access violation and
       implies that obviously bad account_info has been supplied.
       https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L833-L841 */
      acct_info_keys[ acct_idx ] = FD_VM_MEM_HADDR_LD( vm, acc_infos[ acct_idx ].pubkey_addr, alignof(uchar), sizeof(fd_pubkey_t) );
  }

  /* Update the callee accounts with any changes made by the caller prior to this CPI execution */
  fd_vm_cpi_caller_account_t caller_accounts[ 256 ];
  ushort callee_account_keys[256];
  ushort caller_accounts_to_update[256];
  ulong caller_accounts_to_update_len = 0;
  err = VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC(
    vm,
    instruction_accounts,
    instruction_accounts_cnt,
    acct_infos_va,
    acct_info_keys,
    acc_infos,
    acct_info_cnt,
    callee_account_keys,
    caller_accounts_to_update,
    caller_accounts,
    &caller_accounts_to_update_len
  );
  /* errors are propagated in the function itself. */
  if( FD_UNLIKELY( err ) ) return err;

  /* Set the transaction compute meter to be the same as the VM's compute meter,
     so that the callee cannot use compute units that the caller has already used. */
  vm->instr_ctx->txn_ctx->compute_budget_details.compute_meter = vm->cu;

  /* Execute the CPI instruction in the runtime */
  int err_exec = fd_execute_instr( vm->instr_ctx->txn_ctx, instruction_to_execute );
  ulong instr_exec_res = (ulong)err_exec;

  /* Set the CU meter to the instruction context's transaction context's compute meter,
     so that the caller can't use compute units that the callee has already used. */
  vm->cu = vm->instr_ctx->txn_ctx->compute_budget_details.compute_meter;

  *_ret = instr_exec_res;

  /* Errors are propagated in fd_execute_instr. */
  if( FD_UNLIKELY( err_exec ) ) return err_exec;

  /* https://github.com/anza-xyz/agave/blob/b5f5c3cdd3f9a5859c49ebc27221dc27e143d760/programs/bpf_loader/src/syscalls/cpi.rs#L1128-L1145 */
  /* Update all account permissions before updating the account data updates.
     We have inlined the anza function update_caller_account_perms here.
     TODO: consider factoring this out */
  if( vm->direct_mapping ) {
    for( ulong i=0UL; i<caller_accounts_to_update_len; i++ ) {
      ushort acc_instr_idx = callee_account_keys[i];

      /* https://github.com/firedancer-io/solana/blob/508f325e19c0fd8e16683ea047d7c1a85f127e74/programs/bpf_loader/src/syscalls/cpi.rs#L939-L943 */
      /* Anza only even attemps to update the account permissions if it is a
         "caller account". Only writable accounts are caller accounts. */
      if( fd_instr_acc_is_writable_idx( vm->instr_ctx->instr, acc_instr_idx ) ) {

        /* Borrow the callee account
           https://github.com/anza-xyz/agave/blob/v2.1.14/programs/bpf_loader/src/syscalls/cpi.rs#L1154-L1155 */
        fd_guarded_borrowed_account_t callee_acc;
        FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( vm->instr_ctx, acc_instr_idx, &callee_acc );

        /* https://github.com/anza-xyz/agave/blob/v2.1.14/programs/bpf_loader/src/syscalls/cpi.rs#L1298 */
        uchar is_writable = !!fd_borrowed_account_can_data_be_changed( &callee_acc, &err );
        /* Lookup memory regions for the account data and the realloc region. */
        ulong data_region_idx    = vm->acc_region_metas[ acc_instr_idx ].has_data_region ? vm->acc_region_metas[ acc_instr_idx ].region_idx : 0;
        ulong realloc_region_idx = vm->acc_region_metas[ acc_instr_idx ].has_resizing_region ? vm->acc_region_metas[ acc_instr_idx ].region_idx : 0;
        if( data_region_idx && realloc_region_idx ) {
          realloc_region_idx++;
        }

        if( data_region_idx ) {
          vm->input_mem_regions[ data_region_idx ].is_writable = is_writable;
        }
        if( FD_LIKELY( realloc_region_idx ) ) { /* Unless is deprecated loader */
          vm->input_mem_regions[ realloc_region_idx ].is_writable = is_writable;
        }
      }
    }
  }

  /* Update the caller accounts with any changes made by the callee during CPI execution */
  for( ulong i=0UL; i<caller_accounts_to_update_len; i++ ) {
    /* https://github.com/firedancer-io/solana/blob/508f325e19c0fd8e16683ea047d7c1a85f127e74/programs/bpf_loader/src/syscalls/cpi.rs#L939-L943 */
    /* We only want to update the writable accounts, because the non-writable
       caller accounts can't be changed during a CPI execution. */
    if( fd_instr_acc_is_writable_idx( vm->instr_ctx->instr, callee_account_keys[i] ) ) {
      ushort              idx_in_txn = vm->instr_ctx->instr->accounts[ callee_account_keys[i] ].index_in_transaction;
      fd_pubkey_t const * callee     = &vm->instr_ctx->txn_ctx->account_keys[ idx_in_txn ];
      err = VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC(vm, &acc_infos[ caller_accounts_to_update[i] ], caller_accounts + i, (uchar)callee_account_keys[i], callee);
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    }
  }

  return FD_VM_SUCCESS;
}

#undef VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC
#undef VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC
#undef VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC
#undef VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC
#undef VM_SYSCALL_CPI_FUNC
