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

/* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L21-L38

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
        https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/invoke_context.rs#L395-L397 */
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
https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1067-L1132

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
     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L817 */
  fd_guarded_borrowed_account_t callee_acc = {0};
  err = fd_exec_instr_ctx_try_borrow_instr_account( vm->instr_ctx, instr_acc_idx, &callee_acc );
  if( FD_UNLIKELY( err ) ) {
    /* No need to do anything if the account is missing from the borrowed accounts cache */
    return FD_VM_SUCCESS;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1087-L1089 */
  if( fd_borrowed_account_get_lamports( &callee_acc )!=*(caller_account->lamports) ) {
    err = fd_borrowed_account_set_lamports( &callee_acc, *(caller_account->lamports) );
    if( FD_UNLIKELY( err ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }
  }

  /* With stricter_abi_and_runtime_constraints enabled, we validate account
     length changes and update the associated borrowed account with any
     changed made. If direct mapping is also enabled, we skip actually copying
     the data back to the borrowed account, as it is already updated in-place.

     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1091-L1113 */
  if( vm->stricter_abi_and_runtime_constraints ) {
    ulong prev_len = fd_borrowed_account_get_data_len( &callee_acc );
    ulong post_len = *caller_account->ref_to_len_in_vm;

    /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1094-L1109 */
    if( FD_UNLIKELY( prev_len!=post_len ) ) {
      ulong address_space_reserved_for_account;
      if( vm->is_deprecated ) {
        address_space_reserved_for_account = caller_account->orig_data_len;
      } else {
        address_space_reserved_for_account = fd_ulong_sat_add( caller_account->orig_data_len, MAX_PERMITTED_DATA_INCREASE );
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1103-L1105 */
      if( FD_UNLIKELY( post_len>address_space_reserved_for_account ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC );
        return -1;
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1106 */
      err = fd_borrowed_account_set_data_length( &callee_acc, post_len );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return -1;
      }
    }

    /* Without direct mapping, we need to copy the account data from the VM's
       serialized buffer back to the borrowed account. With direct mapping,
       data is modified in-place so no copy is needed.
       https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1110-L1112 */
    int err;
    if( !vm->direct_mapping && fd_borrowed_account_can_data_be_changed( &callee_acc, &err ) ) {
      err = fd_borrowed_account_set_data_from_slice( &callee_acc, caller_account->serialized_data, caller_account->serialized_data_len );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return -1;
      }
    }
  } else {
    /* Direct mapping is not enabled, so we need to copy the account data
       from the VM's serialized buffer back to the borrowed account.

       https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1114-L1121 */
    int err;
    if( fd_borrowed_account_can_data_be_resized( &callee_acc, caller_account->serialized_data_len, &err ) &&
        fd_borrowed_account_can_data_be_changed( &callee_acc, &err ) ) {
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1116 */
      err = fd_borrowed_account_set_data_from_slice( &callee_acc, caller_account->serialized_data, caller_account->serialized_data_len );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return -1;
      }
    } else if( FD_UNLIKELY( caller_account->serialized_data_len!=fd_borrowed_account_get_data_len( &callee_acc ) ||
      memcmp( fd_borrowed_account_get_data( &callee_acc ), caller_account->serialized_data, caller_account->serialized_data_len ) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1117-L1119 */
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1124-L1129 */
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
https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L767-L892

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

    /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L817 */
    fd_guarded_borrowed_account_t callee_acct = {0};
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
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L832
       */
      if( memcmp( account_key->uc, acct_addr->uc, sizeof(fd_pubkey_t) ) != 0 ) {
        continue;
      }

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
         https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L846-L849
       */
      if( FD_UNLIKELY( j >= account_infos_length ) ) {
        FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );
        return FD_VM_SYSCALL_ERR_INVALID_LENGTH;
      }

      /* The following implements the checks in from_account_info which
         is invoked as do_translate() in translate_and_update_accounts()
         https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L850-L861
       */
      ////// BEGIN from_account_info

      fd_vm_acc_region_meta_t * acc_region_meta = &vm->acc_region_metas[index_in_caller];
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L138 */
      if( FD_LIKELY( vm->stricter_abi_and_runtime_constraints ) ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L139-L144 */
        ulong expected_pubkey_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START +
          vm->input_mem_regions[acc_region_meta->region_idx].vaddr_offset +
          acc_region_meta->expected_pubkey_offset;
        /* Max msg_sz: 40 + 18 + 18 = 76 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, account_infos[j].pubkey_addr, expected_pubkey_vaddr, "key");

        /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L145-L150 */
        ulong expected_owner_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START +
          vm->input_mem_regions[acc_region_meta->region_idx].vaddr_offset +
          acc_region_meta->expected_owner_offset;
        /* Max msg_sz: 42 + 18 + 18 = 78 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, account_infos[j].owner_addr, expected_owner_vaddr, "owner");
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L155-L175 */
      VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_VADDR( vm, (account_infos + j), lamports_vaddr );
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L162-L173  */
      if( FD_LIKELY( vm->stricter_abi_and_runtime_constraints ) ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L163-L165
           Check that the account's lamports Rc<RefCell<&mut u64>> is not
           stored in the account region. Because a refcell is only present if
           the Rust SDK is used, we only need to check this for the Rust ABI. */
        #ifdef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_RC_REFCELL_VADDR
        VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_RC_REFCELL_VADDR( vm, (account_infos + j), lamports_rc_vaddr )
        if ( FD_UNLIKELY( lamports_rc_vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
          FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
          return FD_VM_SYSCALL_ERR_INVALID_POINTER;
        }
        #endif

        /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L167-L172 */
        ulong expected_lamports_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START +
          vm->input_mem_regions[acc_region_meta->region_idx].vaddr_offset +
          acc_region_meta->expected_lamports_offset;
        /* Max msg_sz: 45 + 18 + 18 = 81 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, lamports_vaddr, expected_lamports_vaddr, "lamports");
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L153-L175
       */
      VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, (account_infos + j), lamports_haddr );
      caller_account->lamports = lamports_haddr;

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L177-L181
       */
      caller_account->owner = FD_VM_MEM_HADDR_ST( vm, (account_infos + j)->owner_addr, alignof(uchar), sizeof(fd_pubkey_t) );

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L190-L203
       */
      VM_SYSCALL_CPI_ACC_INFO_DATA_VADDR( vm, (account_infos + j), data_vaddr );

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L196-L203 */
      if( vm->stricter_abi_and_runtime_constraints ) {
        fd_vm_input_region_t * region = &vm->input_mem_regions[ acc_region_meta->region_idx ];
        ulong expected_data_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START +
          region->vaddr_offset + region->address_space_reserved;
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, data_vaddr, expected_data_vaddr, "data");
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L205-L210
       */
      VM_SYSCALL_CPI_SET_ACC_INFO_DATA_GET_LEN( vm, (account_infos + j), data_vaddr );
      FD_VM_CU_UPDATE( vm, data_vaddr_len / FD_VM_CPI_BYTES_PER_UNIT );

      #ifdef VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR
      /* Rust ABI
         https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L212-L221 */
      VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR( vm, (account_infos + j), data_len_vaddr );
      if( FD_UNLIKELY( vm->stricter_abi_and_runtime_constraints && data_len_vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
        FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
        return FD_VM_SYSCALL_ERR_INVALID_POINTER;
      }
      (void)acct_infos_va;
      #else
      /* C ABI
         https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L310-L316 */
      ulong data_len_vaddr = vm_syscall_cpi_data_len_vaddr_c(
        fd_ulong_sat_add( acct_infos_va, fd_ulong_sat_mul( j, VM_SYSCALL_CPI_ACC_INFO_SIZE ) ),
        (ulong)&((account_infos + j)->data_sz),
        (ulong)(account_infos + j)
      );
      #endif

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L222
         C ABI:    https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L317 */
      ulong * data_len = FD_VM_MEM_HADDR_ST( vm, data_len_vaddr, 1UL, sizeof(ulong) );
      caller_account->ref_to_len_in_vm = data_len;

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L226
         C ABI:    https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L324 */
      caller_account->vm_data_vaddr = data_vaddr;

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L224-L230
         C ABI:    https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L302-L308

         Both ABIs call CallerAccount::get_serialized_data:
         https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L90-L123

         With both stricter_abi_and_runtime_constraints and direct_mapping,
         account data is modified in-place so we don't track the
         serialized_data pointer.

         With stricter_abi only (no direct_mapping), data was copied into the input
         region buffer. We don't apply the extra memory translation checks, as
         we have checked the data pointer is valid above. So instead we add
         the vaddr to the start of the input region address space - copying
         this logic from Agave.

         In legacy mode, we translate the data pointer directly, as it just
         maps to a location in the single input region. */
      if( vm->stricter_abi_and_runtime_constraints && vm->direct_mapping ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L97-L99 */
        caller_account->serialized_data     = NULL;
        caller_account->serialized_data_len = 0UL;
      } else if( vm->stricter_abi_and_runtime_constraints ) {
        /* Skip translation checks here, following the Agave logic:
           https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L99-L115 */
        uchar * serialization_ptr           = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, FD_VM_MEM_MAP_INPUT_REGION_START, alignof(uchar), 1UL );
        caller_account->serialized_data     = serialization_ptr + fd_ulong_sat_sub( data_vaddr, FD_VM_MEM_MAP_INPUT_REGION_START );
        caller_account->serialized_data_len = data_vaddr_len;
      } else {
        /* https://github.com/anza-xyz/agave/blob/v3.0.1/syscalls/src/cpi.rs#L115-L122 */
        VM_SYSCALL_CPI_ACC_INFO_DATA( vm, (account_infos + j), data_haddr );
        (void)data_haddr_vm_addr;
        caller_account->serialized_data     = data_haddr;
        caller_account->serialized_data_len = data_haddr_len;
      }

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L237
         C ABI:    https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L322 */
      caller_account->orig_data_len = acc_region_meta->original_data_len;

      ////// END from_account_info

      // TODO We should be able to cache the results of translation and reuse them in the update function.
      /* Update the callee account to reflect any changes the caller has made
         https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L863-L873 */
      int err = VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC( vm, caller_account, (uchar)index_in_caller );
      if( FD_UNLIKELY( err ) ) {
        /* errors are propagated in the function itself. */
        return err;
      }
    }

    if( !found ) {
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L882-L887 */
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
https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1171-L1268

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
                                       VM_SYSCALL_CPI_ACC_INFO_T const *  caller_acc_info FD_FN_UNUSED,
                                       fd_vm_cpi_caller_account_t *       caller_account,
                                       uchar                              instr_acc_idx FD_FN_UNUSED,
                                       fd_pubkey_t const *                pubkey ) {
  int err;

  /* Look up the borrowed account from the instruction context, which will contain
     the callee's changes.
     TODO: Agave borrows before entering this function. We should consider doing the same.
     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1033-L1034 */
  fd_guarded_borrowed_account_t borrowed_callee_acc = {0};
  err = fd_exec_instr_ctx_try_borrow_instr_account_with_key( vm->instr_ctx, pubkey, &borrowed_callee_acc );
  if( FD_UNLIKELY( err && ( err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) ) {
    return 1;
  }

  fd_txn_account_t * callee_acc = borrowed_callee_acc.acct;
  /* Update the caller account lamports with the value from the callee
     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1191 */
  *(caller_account->lamports) = fd_txn_account_get_lamports( callee_acc );

  /* Update the caller account owner with the value from the callee
     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1192 */
  fd_pubkey_t const * updated_owner = fd_txn_account_get_owner( callee_acc );
  if( updated_owner ) *caller_account->owner = *updated_owner;
  else                fd_memset( caller_account->owner, 0,             sizeof(fd_pubkey_t) );

  /* Update the caller account data with the value from the callee
     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1194-L1195 */
  ulong prev_len = *caller_account->ref_to_len_in_vm;
  ulong post_len = fd_txn_account_get_data_len( callee_acc );

  /* Calculate the address space reserved for the account. With stricter_abi_and_runtime_constraints
     and deprecated loader, the reserved space equals original length (no realloc space).
     Otherwise, we add MAX_PERMITTED_DATA_INCREASE for reallocation.
     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1197-L1204 */
  ulong address_space_reserved_for_account;
  if( vm->stricter_abi_and_runtime_constraints && vm->is_deprecated ) {
    address_space_reserved_for_account = caller_account->orig_data_len;
  } else {
    address_space_reserved_for_account = fd_ulong_sat_add( caller_account->orig_data_len, MAX_PERMITTED_DATA_INCREASE );
  }

  /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1206-L1216 */
  if( post_len > address_space_reserved_for_account &&
    ( vm->stricter_abi_and_runtime_constraints || prev_len != post_len ) ) {
    ulong max_increase = fd_ulong_sat_sub( address_space_reserved_for_account, caller_account->orig_data_len );
    fd_log_collector_printf_dangerous_max_127( vm->instr_ctx, "Account data size realloc limited to %lu in inner instructions", max_increase );
    FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC );
    return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  }

  /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1218-L1252 */
  if( prev_len != post_len ) {

    /* Without direct mapping, we need to adjust the serialized data buffer
       when the length changes.

       With direct mapping, data is mapped in-place so no buffer manipulation
       is needed.

       https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1219-L1239 */
    if( !( vm->stricter_abi_and_runtime_constraints && vm->direct_mapping ) ) {

      /* If the account has shrunk, zero out memory that was previously used
         https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1222-L1230 */
      if( post_len < prev_len ) {
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1227-L1228 */
        if( caller_account->serialized_data_len < post_len ) {
          FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL );
          return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
        }

        /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1225-L1229 */
        fd_memset( caller_account->serialized_data + post_len, 0, caller_account->serialized_data_len - post_len );
      }

      /* Set caller_account.serialized_data to post_len.
         https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1231-L1238 */
      if( vm->stricter_abi_and_runtime_constraints ) {
        /* Calculate the serialized data pointer from the input region base,
           as described above.

           https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L99-L115 */
        uchar * serialization_ptr           = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, FD_VM_MEM_MAP_INPUT_REGION_START, alignof(uchar), 1UL );
        /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1234 */
        caller_account->serialized_data     = serialization_ptr + fd_ulong_sat_sub( caller_account->vm_data_vaddr, FD_VM_MEM_MAP_INPUT_REGION_START );
        caller_account->serialized_data_len = post_len;
      } else {
        /* Translate the data pointer directly from the VM address, if
           stricter_abi_and_runtime_constraints (or direct mapping) is not
           enabled.

          https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L115-L122 */
        caller_account->serialized_data     = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, caller_account->vm_data_vaddr, alignof(uchar), post_len );
        caller_account->serialized_data_len = post_len;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1240-L1241 */
    *caller_account->ref_to_len_in_vm = post_len;

    /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1243-L1251 */
    ulong * caller_len = FD_VM_MEM_HADDR_ST( vm, fd_ulong_sat_sub(caller_account->vm_data_vaddr, sizeof(ulong)), alignof(ulong), sizeof(ulong) );
    *caller_len = post_len;
  }

  /* Without direct mapping, copy the updated account data from the callee's
     account back to the caller's serialized data buffer. With direct mapping,
     data was modified in-place so no copy is needed.

     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1254-L1265 */
  if( !(vm->stricter_abi_and_runtime_constraints && vm->direct_mapping) ) {
    fd_memcpy( caller_account->serialized_data, fd_txn_account_get_data( callee_acc ), post_len );
  }


  return FD_VM_SUCCESS;
}

/* fd_vm_syscall_cpi_{rust/c} is the entrypoint for the sol_invoke_signed_{rust/c} syscalls.

The bulk of the high-level logic mirrors Solana's cpi_common entrypoint function at
https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L964-L1065
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

  /* Authorized program check *************************************************/

  if( FD_UNLIKELY( fd_vm_syscall_cpi_check_authorized_program( program_id, vm->instr_ctx->txn_ctx, data, VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) ) ) ) {
    /* https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1054 */
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_PROGRAM_NOT_SUPPORTED );
    return FD_VM_SYSCALL_ERR_PROGRAM_NOT_SUPPORTED;
  }

  /* Prepare the instruction for execution in the runtime. This is required by the runtime
     before we can pass an instruction to the executor. */
  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;
  err = fd_vm_prepare_instruction( instruction_to_execute, vm->instr_ctx, program_id, cpi_instr_acct_keys, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  /* Errors are propagated in the function itself. */
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* Translate account infos ******************************************/

  /* With stricter_abi_and_runtime_constraints, verify that the account_infos array
     is not inside the input region. This prevents programs from passing pointers to
     the serialized account data region as account_infos, which would allow them to
     bypass pointer validation checks.
     https://github.com/anza-xyz/agave/blob/v3.0.1/syscalls/src/cpi.rs#L735-L744 */
  ulong acc_info_total_sz = fd_ulong_sat_mul( acct_info_cnt, VM_SYSCALL_CPI_ACC_INFO_SIZE );
  if( vm->stricter_abi_and_runtime_constraints ) {
    if( FD_UNLIKELY( fd_ulong_sat_add( acct_infos_va, acc_info_total_sz ) >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
      return FD_VM_SYSCALL_ERR_INVALID_POINTER;
    }
  }

  /* This is the equivalent of translate_slice in translate_account_infos:
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/programs/bpf_loader/src/syscalls/cpi.rs#L816 */
  VM_SYSCALL_CPI_ACC_INFO_T const * acc_infos = FD_VM_MEM_SLICE_HADDR_LD( vm, acct_infos_va, VM_SYSCALL_CPI_ACC_INFO_ALIGN, acc_info_total_sz );

  /* Right after translating, Agave checks the number of account infos:
     https://github.com/anza-xyz/agave/blob/v3.0.1/syscalls/src/cpi.rs#L752 */
  if( FD_UNLIKELY( acct_info_cnt > get_cpi_max_account_infos( vm->instr_ctx->txn_ctx ) ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED );
    return FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED;
  }

  fd_pubkey_t const * acct_info_keys[ FD_CPI_MAX_ACCOUNT_INFOS ];
  for( ulong acct_idx = 0UL; acct_idx < acct_info_cnt; acct_idx++ ) {
    /* Translate each pubkey address specified in account_infos.
       Failed translation should lead to an access violation and
       implies that obviously bad account_info has been supplied.
       https://github.com/anza-xyz/agave/blob/v2.1.6/programs/bpf_loader/src/syscalls/cpi.rs#L833-L841 */
      acct_info_keys[ acct_idx ] = FD_VM_MEM_HADDR_LD( vm, acc_infos[ acct_idx ].pubkey_addr, alignof(uchar), sizeof(fd_pubkey_t) );
  }

  /* translate_and_update_accounts ************************************************************
     Update the callee accounts with any changes made by the caller prior to this CPI execution

     https://github.com/anza-xyz/agave/blob/v3.0.1/syscalls/src/cpi.rs#L767-L892 */
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

  /* With stricter_abi_and_runtime_constraints, update the caller's memory regions
     to reflect any changes the callee made to account data. This ensures the caller's
     view of account regions (tracked in acc_region_metas) remains consistent.
     https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1047-L1061 */
  if( vm->stricter_abi_and_runtime_constraints ) {
    for( ulong i=0UL; i<caller_accounts_to_update_len; i++ ) {
      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1033-L1034 */
      fd_guarded_borrowed_account_t borrowed_callee_acc = {0};
      ushort idx_in_txn          = vm->instr_ctx->instr->accounts[ callee_account_keys[i] ].index_in_transaction;
      fd_pubkey_t const * callee = &vm->instr_ctx->txn_ctx->account_keys[ idx_in_txn ];
      err = fd_exec_instr_ctx_try_borrow_instr_account_with_key( vm->instr_ctx, callee, &borrowed_callee_acc );
      if( FD_UNLIKELY( err && ( err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) ) {
        return 1;
      }

      /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1052-L1058 */
      err = fd_vm_cpi_update_caller_account_region( vm, (ulong)callee_account_keys[i], caller_accounts + i, &borrowed_callee_acc );
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
