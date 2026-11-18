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

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L187-L205

   This is used for checking that the account info pointers given by the
   user match up with the addresses in the serialized account metadata.

   Field name length is restricted to 54 because
   127 - (37 + 18 + 18) leaves 54 characters for the field name
 */
#define VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, vm_addr, expected_vm_addr, field_name) \
  if( FD_UNLIKELY( vm_addr!=expected_vm_addr )) {                                                         \
    fd_log_collector_printf_dangerous_max_127( vm->instr_ctx,                                             \
      "Invalid account info pointer `%s': 0x%lx != 0x%lx", field_name, vm_addr, expected_vm_addr );         \
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
- program_id: translated program pubkey
- out_instr: output instruction
- out_instr_acct_keys: output instruction account pubkeys
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
                                          fd_pubkey_t                       out_instr_acct_keys[ FD_TXN_INSTR_ACCT_MAX ] ) {

  out_instr->program_id   = UCHAR_MAX;
  out_instr->stack_height = (uchar)( vm->instr_ctx->runtime->instr.stack_sz+1 );
  out_instr->data_sz      = (ushort)VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instr );
  out_instr->acct_cnt     = (ushort)VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instr );
  if( FD_LIKELY( out_instr->data_sz ) ) memcpy( out_instr->data, cpi_instr_data, out_instr->data_sz );

  /* Find the index of the CPI instruction's program account in the transaction */
  ulong program_id_idx = fd_runtime_find_index_of_account( vm->instr_ctx->txn_out, program_id );
  if( FD_LIKELY( program_id_idx!=ULONG_MAX ) ) out_instr->program_id = (uchar)program_id_idx;

  uchar  acc_idx_seen[ FD_TXN_ACCT_ADDR_MAX ] = {0};
  ushort caller_map[ MAX_TX_ACCOUNT_LOCKS ];
  fd_exec_instr_ctx_instr_account_map( vm->instr_ctx, caller_map );

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
        https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/invoke_context.rs#L415-L425 */
    ulong idx_in_txn = fd_runtime_find_index_of_account( vm->instr_ctx->txn_out, pubkey );

    fd_instr_info_setup_instr_account( out_instr,
                                       acc_idx_seen,
                                       idx_in_txn!=ULONG_MAX ? (ushort)idx_in_txn : USHORT_MAX,
                                       idx_in_txn!=ULONG_MAX ? caller_map[ idx_in_txn ] : USHORT_MAX,
                                       i,
                                       VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( cpi_acct_meta ),
                                       VM_SYSCALL_CPI_ACC_META_IS_SIGNER( cpi_acct_meta ) );

  }

  return FD_VM_SUCCESS;
}

/*
fd_vm_syscall_cpi_update_callee_acc_{rust/c} corresponds to solana_bpf_loader_program::syscalls::cpi::update_callee_account:
https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1265-L1339

(the copy of the account stored in the instruction context's
borrowed accounts cache)

This function should be called before the CPI instruction is executed. Its purpose is to
update the callee account's view of the given account with any changes the caller may made
to the account before the CPI instruction is executed.

The callee's view of the account is the borrowed accounts cache, so to update the
callee account we look up the account in the borrowed accounts cache and update it.

Parameters:
- vm: pointer to the virtual machine handle
- caller_account: translated caller account
- callee_acc: borrowed callee account
- out_must_update_caller: set when caller metadata must be updated after CPI
*/
#define VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_update_callee_acc_, VM_SYSCALL_CPI_ABI)
static int
VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC( fd_vm_t *                          vm,
                                      fd_vm_cpi_caller_account_t const * caller_account,
                                      fd_borrowed_account_t *            callee_acc,
                                      uchar *                            out_must_update_caller ) {
  int err;
  *out_must_update_caller = 0;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1286-L1288 */
  if( fd_borrowed_account_get_lamports( callee_acc )!=FD_LOAD( ulong, caller_account->lamports ) ) {
    err = fd_borrowed_account_set_lamports( callee_acc, FD_LOAD( ulong, caller_account->lamports ) );
    if( FD_UNLIKELY( err ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }
  }

  /* With virtual_address_space_adjustments enabled, we validate account
     length changes and update the associated borrowed account with any
     changed made. If direct mapping is also enabled, we skip actually copying
     the data back to the borrowed account, as it is already updated in-place.

     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1290-L1319 */
  if( vm->virtual_address_space_adjustments ) {
    ulong prev_len = fd_borrowed_account_get_data_len( callee_acc );
    ulong post_len = FD_LOAD( ulong, caller_account->ref_to_len_in_vm );

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1293-L1316 */
    if( FD_UNLIKELY( prev_len!=post_len ) ) {
      /* If the account has been shrunk, we're going to zero the unused
         memory that was previously used. */
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1294-L1312 */
      if( FD_UNLIKELY( !vm->direct_mapping && ( post_len < prev_len ) ) ) {
        fd_memset( caller_account->serialized_data + post_len, 0, prev_len - post_len );
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1313 */
      err = fd_borrowed_account_set_data_length( callee_acc, post_len );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return -1;
      }
      /* Pointer to data may have changed, caller must be updated.
         https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1313-L1315 */
      *out_must_update_caller = 1;
    }

    /* Without direct mapping, we need to copy the account data from the VM's
       serialized buffer back to the borrowed account. With direct mapping,
       data is modified in-place so no copy is needed.
       https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1317-L1319 */
    int err;
    if( !vm->direct_mapping && fd_borrowed_account_can_data_be_changed( callee_acc, &err ) ) {
      err = fd_borrowed_account_set_data_from_slice( callee_acc, caller_account->serialized_data, caller_account->serialized_data_len );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return -1;
      }
    }
  } else {
    /* Direct mapping is not enabled, so we need to copy the account data
       from the VM's serialized buffer back to the borrowed account.

       https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1321-L1328 */
    int err;
    if( fd_borrowed_account_can_data_be_resized( callee_acc, caller_account->serialized_data_len, &err ) ) {
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1323 */
      err = fd_borrowed_account_set_data_from_slice( callee_acc, caller_account->serialized_data, caller_account->serialized_data_len );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return -1;
      }
    } else if( FD_UNLIKELY( caller_account->serialized_data_len!=fd_borrowed_account_get_data_len( callee_acc ) ||
                            (caller_account->serialized_data_len &&
                              memcmp( fd_borrowed_account_get_data( callee_acc ), caller_account->serialized_data, caller_account->serialized_data_len )) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1324-L1326 */
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1331-L1336 */
  if( FD_UNLIKELY( memcmp( fd_borrowed_account_get_owner( callee_acc ), caller_account->owner, sizeof(fd_pubkey_t) ) ) ) {
    err = fd_borrowed_account_set_owner( callee_acc, caller_account->owner );
    if( FD_UNLIKELY( err ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, err );
      return -1;
    }
    /* Caller gave ownership and thus write access away, so caller must be updated.
       https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1333-L1335 */
    *out_must_update_caller = 1;
  }

  return FD_VM_SUCCESS;
}

/*
fd_vm_syscall_cpi_translate_and_update_accounts_ mirrors the behaviour of
solana_program_runtime::cpi::SyscallInvokeSigned::translate_accounts_common:
https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1151-L1263

It translates the caller accounts to the host address space.  Without
SIMD-0339, it also updates callee accounts here.  With SIMD-0339, those
updates are deferred to the syscall entrypoint after translation.

Parameters:
- vm: pointer to the virtual machine handle
- instruction_accounts: array of instruction accounts
- instruction_accounts_cnt: length of the instruction_accounts array
- account_infos: array of account infos
- account_infos_length: length of the account_infos array

Populates:
- translated_accounts: the translated account entries
- out_len: number of translated account entries
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
                              fd_vm_cpi_translated_account_t *  translated_accounts,
                              ulong *                           out_len ) {
  for( ulong i=0UL; i<instruction_accounts_cnt; i++ ) {
    if( i!=instruction_accounts[i].index_in_callee ) {
      /* Skip duplicate accounts */
      continue;
    }

    /* `fd_vm_prepare_instruction()` will always set up a valid index for `index_in_caller`, so we can access the borrowed account directly.
       A borrowed account will always have non-NULL meta (if the account doesn't exist, `fd_executor_setup_accounts_for_txn()`
       will set its meta up) */

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1197 */
    fd_guarded_borrowed_account_t callee_acct = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( vm->instr_ctx, instruction_accounts[i].index_in_caller, &callee_acct );

    fd_pubkey_t const *      account_key = (fd_pubkey_t*)callee_acct.acc->pubkey;

    /* If the account is known and executable, we only need to consume the compute units.
       Executable accounts can't be modified, so we don't need to update the callee account. */
    if( fd_borrowed_account_is_executable( &callee_acct ) ) {
      // FIXME: should this be FD_VM_CU_MEM_OP_UPDATE? Changing this changes the CU behaviour from main (because of the base cost)
      FD_VM_CU_UPDATE( vm, callee_acct.acc->data_len / FD_VM_CPI_BYTES_PER_UNIT );
      continue;
    }

    /* FIXME: we should not need to drop the account here to avoid a double borrow.
       Instead, we should borrow the account before entering this function. */
    fd_borrowed_account_drop( &callee_acct );

    /* Find the indices of the account in the caller and callee instructions */
    uint found = 0;
    for( ushort j=0; j<account_infos_length && !found; j++ ) {
      fd_pubkey_t const * acct_addr = account_info_keys[ j ];
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1210
       */
      if( memcmp( account_key->uc, acct_addr->uc, sizeof(fd_pubkey_t) ) != 0 ) {
        continue;
      }

      fd_vm_cpi_translated_account_t * translated_account = translated_accounts + *out_len;
      fd_vm_cpi_caller_account_t *     caller_account     = &translated_account->caller_account;
      ushort                           index_in_caller    = instruction_accounts[i].index_in_caller;
      translated_account->index_in_caller                 = index_in_caller;
      translated_account->update_caller_account_info      = (uchar)!!instruction_accounts[i].is_writable;
      found = 1;

      /* Logically this check isn't ever going to fail due to how the
         account_info_keys array is set up.  We replicate the check for
         clarity and also to guard against accidental violation of the
         assumed invariant in the future.
         https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1224-L1227
       */
      if( FD_UNLIKELY( j >= account_infos_length ) ) {
        FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );
        return FD_VM_SYSCALL_ERR_INVALID_LENGTH;
      }

      /* The following implements the checks in from_account_info which
         is invoked as do_translate() in translate_and_update_accounts()
         https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1229-L1239
       */
      ////// BEGIN from_account_info

      fd_vm_acc_region_meta_t * acc_region_meta = &vm->acc_region_metas[index_in_caller];
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L377-L388 */
      if( FD_LIKELY( vm->syscall_parameter_address_restrictions ) ) {
        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L377-L382 */
        ulong expected_pubkey_vaddr = acc_region_meta->vm_key_addr;
        /* Max msg_sz: 40 + 18 + 18 = 76 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, account_infos[j].pubkey_addr, expected_pubkey_vaddr, "key");

        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L383-L388 */
        ulong expected_owner_vaddr = acc_region_meta->vm_owner_addr;
        /* Max msg_sz: 42 + 18 + 18 = 78 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, account_infos[j].owner_addr, expected_owner_vaddr, "owner");
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L392-L408 */
      VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_VADDR( vm, (account_infos + j), lamports_vaddr );
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L396-L405  */
      if( FD_LIKELY( vm->syscall_parameter_address_restrictions ) ) {
        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L396-L398
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

        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L400-L405 */
        ulong expected_lamports_vaddr = acc_region_meta->vm_lamports_addr;
        /* Max msg_sz: 45 + 18 + 18 = 81 < 127 */
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(vm, lamports_vaddr, expected_lamports_vaddr, "lamports");
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L407
       */
      VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, (account_infos + j), lamports_haddr );
      caller_account->lamports = lamports_haddr;

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L410-L414
       */
      caller_account->owner = FD_VM_MEM_HADDR_ST( vm, (account_infos + j)->owner_addr, alignof(uchar), sizeof(fd_pubkey_t) );

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L416-L428
       */
      VM_SYSCALL_CPI_ACC_INFO_DATA_VADDR( vm, (account_infos + j), data_vaddr );

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L429-L434 */
      if( vm->syscall_parameter_address_restrictions ) {
        VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54(
          vm, data_vaddr, acc_region_meta->vm_data_addr, "data");
      } else {
        /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.3/program-runtime/src/cpi.rs#L388-L392 */
        VM_SYSCALL_CPI_SET_ACC_INFO_DATA_GET_LEN( vm, (account_infos + j), data_vaddr );
        FD_VM_CU_UPDATE( vm, data_vaddr_len / FD_VM_CPI_BYTES_PER_UNIT );
      }

      #ifdef VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR
      /* Rust ABI
         https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L162-L164 */
      VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR( vm, (account_infos + j), data_len_vaddr );
      (void)acct_infos_va;
      #else
      /* C ABI
         https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L529-L535 */
      ulong data_len_vaddr = vm_syscall_cpi_data_len_vaddr_c(
        fd_ulong_sat_add( acct_infos_va, fd_ulong_sat_mul( j, VM_SYSCALL_CPI_ACC_INFO_SIZE ) ),
        (ulong)&((account_infos + j)->data_sz),
        (ulong)(account_infos + j)
      );
      #endif

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L436-L441
         C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L536-L541 */
      if( FD_UNLIKELY( vm->syscall_parameter_address_restrictions && data_len_vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
        FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
        return FD_VM_SYSCALL_ERR_INVALID_POINTER;
      }

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L466
         C ABI:    https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L561 */
      caller_account->vm_data_vaddr = data_vaddr;

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L442-L446
         C ABI:    https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L542-L543 */
      void * data_len = FD_VM_MEM_HADDR_ST( vm, data_len_vaddr, 1UL, sizeof(ulong) );
      caller_account->ref_to_len_in_vm = data_len;

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L447-L457
         C ABI:    https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L544-L554

         Both ABIs call CallerAccount::get_serialized_data:
         https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L299-L358 */

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L319-L327 */
      if( vm->syscall_parameter_address_restrictions ) {
        ulong address_space_reserved_for_account;
        if( vm->is_deprecated ) {
          address_space_reserved_for_account = acc_region_meta->original_data_len;
        } else {
          address_space_reserved_for_account = fd_ulong_sat_add( acc_region_meta->original_data_len, MAX_PERMITTED_DATA_INCREASE );
        }
        if( FD_UNLIKELY( FD_LOAD( ulong, data_len ) > address_space_reserved_for_account ) ) {
          FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC );
          return -1;
        }
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L328-L357

         With both virtual_address_space_adjustments and direct_mapping,
         account data is modified in-place so we don't track the
         serialized_data pointer.

         With virtual_address_space_adjustments only (no direct_mapping), data was copied into the input
         region buffer. We don't apply the extra memory translation checks, as
         we have checked the data pointer is valid above. So instead we add
         the vaddr to the start of the input region address space - copying
         this logic from Agave.

         In legacy mode, we translate the data pointer directly, as it just
         maps to a location in the single input region. */
      if( vm->virtual_address_space_adjustments && vm->direct_mapping ) {
        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L328-L330 */
        caller_account->serialized_data     = NULL;
        caller_account->serialized_data_len = 0UL;
      } else if( vm->virtual_address_space_adjustments ) {
        /* Skip translation checks here, following the Agave logic:
           https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L330-L347 */
        uchar * serialization_ptr           = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, FD_VM_MEM_MAP_INPUT_REGION_START, alignof(uchar), 1UL );
        caller_account->serialized_data     = serialization_ptr + fd_ulong_sat_sub( data_vaddr, FD_VM_MEM_MAP_INPUT_REGION_START );
        caller_account->serialized_data_len = FD_LOAD( ulong, data_len );
      } else if( vm->syscall_parameter_address_restrictions ) {
        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L347-L356 */
        caller_account->serialized_data_len = FD_LOAD( ulong, data_len );
        caller_account->serialized_data     = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, data_vaddr, alignof(uchar), caller_account->serialized_data_len );
      } else {
        /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.3/program-runtime/src/cpi.rs#L291-L298 */
        VM_SYSCALL_CPI_ACC_INFO_DATA( vm, (account_infos + j), data_haddr );
        (void)data_haddr_vm_addr;
        caller_account->serialized_data     = data_haddr;
        caller_account->serialized_data_len = data_haddr_len;
      }

      /* Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L464
         C ABI:    https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L559 */
      caller_account->orig_data_len = acc_region_meta->original_data_len;

      ////// END from_account_info

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1241-L1244 */
      if( vm->syscall_parameter_address_restrictions ) {
        FD_VM_CU_UPDATE( vm, FD_LOAD( ulong, data_len ) / FD_VM_CPI_BYTES_PER_UNIT );
      }

      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1246-L1251 */
      uchar update_caller = 0;
      if( vm->syscall_parameter_address_restrictions ) {
        update_caller = 1;
      } else {
        fd_guarded_borrowed_account_t callee_acc = {0};
        FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( vm->instr_ctx, index_in_caller, &callee_acc );
        int err = VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC( vm, caller_account, &callee_acc, &update_caller );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }
      }
      translated_account->update_caller_account_region =
          (uchar)( translated_account->update_caller_account_info || update_caller );
      (*out_len)++;
    }

    if( !found ) {
      /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1253-L1258 */
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
https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1384-L1474

This method should be called after a CPI instruction execution has
returned. It updates the given caller account info with any changes the callee
has made to this account during execution, so that those changes are
reflected in the rest of the caller's execution.

Those changes will be in the instructions borrowed accounts cache.

Parameters:
- vm: handle to the vm
- caller_account: translated caller account to update
- borrowed_callee_acc: already-borrowed callee account
*/
#define VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_cpi_update_caller_acc_, VM_SYSCALL_CPI_ABI)
static int
VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC( fd_vm_t *                          vm,
                                       fd_vm_cpi_caller_account_t *       caller_account,
                                       fd_borrowed_account_t *            borrowed_callee_acc ) {

  /* Update the caller account lamports with the value from the callee
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1400 */
  FD_STORE( ulong, caller_account->lamports, borrowed_callee_acc->acc->lamports );

  /* Update the caller account owner with the value from the callee
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1401 */
  fd_memcpy( caller_account->owner, borrowed_callee_acc->acc->owner, sizeof(fd_pubkey_t) );

  /* Update the caller account data with the value from the callee
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1403-L1404 */
  ulong prev_len = FD_LOAD( ulong, caller_account->ref_to_len_in_vm );
  ulong post_len = borrowed_callee_acc->acc->data_len;

  /* Calculate the address space reserved for the account. With syscall_parameter_address_restrictions
     and deprecated loader, the reserved space equals original length (no realloc space).
     Otherwise, we add MAX_PERMITTED_DATA_INCREASE for reallocation.
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1405-L1407 */
  ulong address_space_reserved_for_account;
  if( vm->syscall_parameter_address_restrictions && vm->is_deprecated ) {
    address_space_reserved_for_account = caller_account->orig_data_len;
  } else {
    address_space_reserved_for_account = fd_ulong_sat_add( caller_account->orig_data_len, MAX_PERMITTED_DATA_INCREASE );
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1409-L1417 */
  if( post_len > address_space_reserved_for_account &&
    ( vm->syscall_parameter_address_restrictions || prev_len != post_len ) ) {
    ulong max_increase = fd_ulong_sat_sub( address_space_reserved_for_account, caller_account->orig_data_len );
    fd_log_collector_printf_dangerous_max_127( vm->instr_ctx, "Account data size realloc limited to %lu in inner instructions", max_increase );
    FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC );
    return FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1420-L1458 */
  if( prev_len != post_len ) {

    /* Without direct mapping, we need to adjust the serialized data buffer
       when the length changes.

       With direct mapping, data is mapped in-place so no buffer manipulation
       is needed.

       https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1423-L1445 */
    if( !( vm->virtual_address_space_adjustments && vm->direct_mapping ) ) {

      /* If the account has shrunk, zero out memory that was previously used
         https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1426-L1432 */
      if( post_len < prev_len ) {
        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1429-L1430 */
        if( caller_account->serialized_data_len < post_len ) {
          FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL );
          return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
        }

        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1426-L1432 */
        fd_memset( caller_account->serialized_data + post_len, 0, caller_account->serialized_data_len - post_len );
      }

      /* Set caller_account.serialized_data to post_len.
         https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1433-L1444 */
      if( vm->virtual_address_space_adjustments ) {
        /* Calculate the serialized data pointer from the input region base,
           as described above.

           https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L330-L347 */
        uchar * serialization_ptr           = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, FD_VM_MEM_MAP_INPUT_REGION_START, alignof(uchar), 1UL );
        /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1435 */
        caller_account->serialized_data     = serialization_ptr + fd_ulong_sat_sub( caller_account->vm_data_vaddr, FD_VM_MEM_MAP_INPUT_REGION_START );
        caller_account->serialized_data_len = post_len;
      } else {
        /* Translate the data pointer directly from the VM address, if
           virtual_address_space_adjustments (or direct mapping) is not
           enabled.

          https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L347-L356 */
        caller_account->serialized_data     = (uchar *)FD_VM_MEM_SLICE_HADDR_ST( vm, caller_account->vm_data_vaddr, alignof(uchar), post_len );
        caller_account->serialized_data_len = post_len;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1446-L1447 */
    FD_STORE( ulong, caller_account->ref_to_len_in_vm, post_len );

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1449-L1457 */
    void * caller_len = FD_VM_MEM_HADDR_ST( vm, fd_ulong_sat_sub(caller_account->vm_data_vaddr, sizeof(ulong)), alignof(ulong), sizeof(ulong) );
    FD_STORE( ulong, caller_len, post_len );
  }

  /* Without direct mapping, copy the updated account data from the callee's
     account back to the caller's serialized data buffer. With direct mapping,
     data was modified in-place so no copy is needed.

     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1460-L1471 */
  if( !(vm->virtual_address_space_adjustments && vm->direct_mapping) ) {

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1467-L1469 */
    if( FD_UNLIKELY( caller_account->serialized_data_len!=post_len ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL );
      return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
    }

    fd_memcpy( caller_account->serialized_data, borrowed_callee_acc->acc->data, post_len );
  }


  return FD_VM_SUCCESS;
}

/* fd_vm_syscall_cpi_{rust/c} is the entrypoint for the sol_invoke_signed_{rust/c} syscalls.

The bulk of the high-level logic mirrors Solana's cpi_common entrypoint function at
https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L981-L1093

100-foot flow:
- Translate the CPI ABI structures to the FD runtime's instruction format
- Update the callee accounts with any changes made by the caller prior to this CPI instruction
- Dispatch the instruction to the FD runtime (actually making the CPI call)
- Update the caller accounts with any changes made by the callee during CPI execution

Parameters:
- vm: pointer to the virtual machine handle
- instruction_va: vm address of the instruction to execute, which will be in the language-specific ABI format.
- acct_infos_va: vm address of the account infos, which will be in the language-specific ABI format.
- acct_info_cnt: number of account infos
- signers_seeds_va: vm address of the signers seeds
- signers_seeds_cnt: number of signers seeds
*/
#define VM_SYSCALL_CPI_ENTRYPOINT FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_, VM_SYSCALL_CPI_ABI)
int
VM_SYSCALL_CPI_ENTRYPOINT( void *  _vm,
                           ulong   instruction_va,
                           ulong   acct_infos_va,
                           ulong   acct_info_cnt,
                           ulong   signers_seeds_va,
                           ulong   signers_seeds_cnt ) {
  long const regime0 = fd_tickcount();

  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L994-L995 */
  FD_VM_CU_UPDATE( vm, get_cpi_invoke_unit_cost() );

  /* Translate instruction ********************************************/
  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1002
     Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L643-L704
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L780-L866 */

  /* Translating the CPI instruction
     Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L649
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L791 */
  VM_SYSCALL_CPI_INSTR_T const * cpi_instruction =
    FD_VM_MEM_HADDR_LD( vm, instruction_va, VM_SYSCALL_CPI_INSTR_ALIGN, VM_SYSCALL_CPI_INSTR_SIZE );

  /* This needs to be here for the C ABI
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L793
   */
  fd_pubkey_t const * program_id = (fd_pubkey_t *)VM_SYSCALL_CPI_INSTR_PROGRAM_ID( vm, cpi_instruction );

  /* Translate CPI account metas
     Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L650-L655
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L794-L799 */
  VM_SYSCALL_CPI_ACC_META_T const * cpi_account_metas =
    FD_VM_MEM_SLICE_HADDR_LD( vm, VM_SYSCALL_CPI_INSTR_ACCS_ADDR( cpi_instruction ),
                              VM_SYSCALL_CPI_ACC_META_ALIGN,
                              fd_ulong_sat_mul( VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ), VM_SYSCALL_CPI_ACC_META_SIZE ) );

  /* Translate instruction data
     Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L656-L661
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L800 */

  uchar const * data = FD_VM_MEM_SLICE_HADDR_LD(
    vm, VM_SYSCALL_CPI_INSTR_DATA_ADDR( cpi_instruction ),
    FD_VM_ALIGN_RUST_U8,
    VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ));


  /* Instruction checks
     Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L663
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L802 */

  int err = fd_vm_syscall_cpi_check_instruction( VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ), VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) );
  if( FD_UNLIKELY( err ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, err );
    return err;
  }

  /* Agave consumes CU in translate_instruction
     Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L665-L667
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L804-L806 */
  ulong total_cu_translation_cost = VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) / FD_VM_CPI_BYTES_PER_UNIT;

  /* Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L669-L678
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L808-L818 */
  /* Agave bills the same regardless of ABI */
  ulong account_meta_translation_cost =
    fd_ulong_sat_mul(
      VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ),
      FD_VM_RUST_ACCOUNT_META_SIZE ) /
    FD_VM_CPI_BYTES_PER_UNIT;
  total_cu_translation_cost = fd_ulong_sat_add( total_cu_translation_cost, account_meta_translation_cost );
  FD_VM_CU_UPDATE( vm, total_cu_translation_cost );

  /* Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L680-L697
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L838-L862 */
  for( ulong i=0UL; i<VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ); i++ ) {
    VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_meta = &cpi_account_metas[i];
    if( FD_UNLIKELY( cpi_acct_meta->is_signer > 1U || cpi_acct_meta->is_writable > 1U ) ) {
      FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_INVALID_ARG );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    /* Rust ABI: no-op
       C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L852-L856
     */
    (void)VM_SYSCALL_CPI_ACC_META_PUBKEY( vm, cpi_acct_meta );
  }

  /* Derive PDA signers
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1006-L1012
     Rust ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L734-L777
     C    ABI: https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L734-L777

     Note that we don't need any ABI-specific logic here, because the two ABIs are actually identical for the seeds.*/
  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ] = {0};
  fd_pubkey_t * caller_program_id = &vm->instr_ctx->txn_out->accounts.keys[ vm->instr_ctx->instr->program_id ];
  if( FD_LIKELY( signers_seeds_cnt > 0UL ) ) {
    fd_vm_vec_t const * signers_seeds = FD_VM_MEM_SLICE_HADDR_LD( vm, signers_seeds_va, FD_VM_ALIGN_RUST_SLICE_U8_REF, fd_ulong_sat_mul( signers_seeds_cnt, FD_VM_VEC_SIZE ) );
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
        FD_TXN_PREPARE_ERR_OVERWRITE( vm->instr_ctx->txn_out );
        FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_BAD_SEEDS );
        return FD_VM_SYSCALL_ERR_BAD_SEEDS;
      }
    }
  }

  /* Authorized program check
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1013 */
  if( FD_UNLIKELY( !fd_vm_syscall_cpi_check_authorized_program( program_id, vm->instr_ctx->bank, data, VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) ) ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_PROGRAM_NOT_SUPPORTED );
    return FD_VM_SYSCALL_ERR_PROGRAM_NOT_SUPPORTED;
  }

  /* Create the instruction to execute (in the input format the FD runtime expects) from
     the translated CPI ABI inputs.
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1014 */
  fd_pubkey_t cpi_instr_acct_keys[ FD_TXN_INSTR_ACCT_MAX ];
  fd_instr_info_t * instruction_to_execute = &vm->instr_ctx->runtime->instr.trace[ vm->instr_ctx->runtime->instr.trace_length++ ];

  err = VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC( vm, cpi_instruction, cpi_account_metas, program_id, data, instruction_to_execute, cpi_instr_acct_keys );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* Prepare the instruction for execution in the runtime. This is required by the runtime
     before we can pass an instruction to the executor. */
  fd_instruction_account_t instruction_accounts[ FD_TXN_INSTR_ACCT_MAX ];
  ulong instruction_accounts_cnt;
  err = fd_vm_prepare_instruction( instruction_to_execute, vm->instr_ctx, program_id, cpi_instr_acct_keys, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  /* Errors are propagated in the function itself. */
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* Translate account infos
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1017-L1018
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1103-L1149 */

  /* With syscall_parameter_address_restrictions, verify that the account_infos array
     is not inside the input region. This prevents programs from passing pointers to
     the serialized account data region as account_infos, which would allow them to
     bypass pointer validation checks.
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1112-L1120 */
  ulong acc_info_total_sz = fd_ulong_sat_mul( acct_info_cnt, VM_SYSCALL_CPI_ACC_INFO_SIZE );
  if( vm->syscall_parameter_address_restrictions ) {
    if( FD_UNLIKELY( fd_ulong_sat_add( acct_infos_va, acc_info_total_sz ) >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
      return FD_VM_SYSCALL_ERR_INVALID_POINTER;
    }
  }

  /* This is the equivalent of translate_slice in translate_account_infos */
  VM_SYSCALL_CPI_ACC_INFO_T const * acc_infos = FD_VM_MEM_SLICE_HADDR_LD( vm, acct_infos_va, VM_SYSCALL_CPI_ACC_INFO_ALIGN, acc_info_total_sz );

  /* Right after translating, Agave checks the number of account infos */
  if( FD_UNLIKELY( acct_info_cnt > get_cpi_max_account_infos() ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED );
    return FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED;
  }

  /* Consume compute units proportional to the number of account infos */
  ulong account_infos_bytes = fd_ulong_sat_mul( acct_info_cnt, FD_VM_ACCOUNT_INFO_BYTE_SIZE );
  FD_VM_CU_UPDATE( vm, account_infos_bytes / FD_VM_CPI_BYTES_PER_UNIT );

  fd_pubkey_t const * acct_info_keys[ FD_CPI_MAX_ACCOUNT_INFOS ];
  for( ulong acct_idx = 0UL; acct_idx < acct_info_cnt; acct_idx++ ) {
    /* Translate each pubkey address specified in account_infos.
       Failed translation should lead to an access violation and
       implies that obviously bad account_info has been supplied. */
      acct_info_keys[ acct_idx ] = FD_VM_MEM_HADDR_LD( vm, acc_infos[ acct_idx ].pubkey_addr, alignof(uchar), sizeof(fd_pubkey_t) );
  }

  /* translate_accounts_common ***************************************************************
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1151-L1263 */
  fd_vm_cpi_translated_account_t translated_accounts[ FD_TXN_INSTR_ACCT_MAX ];
  ulong translated_accounts_len = 0UL;
  err = VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC(
    vm,
    instruction_accounts,
    instruction_accounts_cnt,
    acct_infos_va,
    acct_info_keys,
    acc_infos,
    acct_info_cnt,
    translated_accounts,
    &translated_accounts_len
  );
  /* errors are propagated in the function itself. */
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1020-L1040 */
  if( vm->syscall_parameter_address_restrictions ) {
    for( ulong i=0UL; i<translated_accounts_len; i++ ) {
      fd_vm_cpi_translated_account_t * translated_account = &translated_accounts[i];
      fd_guarded_borrowed_account_t callee_acc = {0};
      FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( vm->instr_ctx, translated_account->index_in_caller, &callee_acc );
      uchar update_caller = 0;
      err = VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC( vm, &translated_account->caller_account, &callee_acc, &update_caller );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
      translated_account->update_caller_account_region =
          (uchar)( translated_account->update_caller_account_info || update_caller );
    }
  }

  /* Set the transaction compute meter to be the same as the VM's compute meter,
     so that the callee cannot use compute units that the caller has already used. */
  vm->instr_ctx->txn_out->details.compute_budget.compute_meter = vm->cu;

  long const regime1 = fd_tickcount();

  /* Execute the CPI instruction in the runtime */
  int err_exec = fd_execute_instr( vm->instr_ctx->runtime, vm->instr_ctx->bank, vm->instr_ctx->txn_in, vm->instr_ctx->txn_out, instruction_to_execute );
  ulong instr_exec_res = (ulong)err_exec;

  long const regime2 = fd_tickcount();
  vm->instr_ctx->runtime->metrics.cpi_setup_cum_ticks += (ulong)( regime1-regime0 );

  /* Set the CU meter to the instruction context's transaction context's compute meter,
     so that the caller can't use compute units that the callee has already used. */
  vm->cu = vm->instr_ctx->txn_out->details.compute_budget.compute_meter;

  vm->reg[0] = instr_exec_res;

  /* Errors are propagated in fd_execute_instr. */
  if( FD_UNLIKELY( err_exec ) ) return err_exec;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1051-L1067 */
  for( ulong i=0UL; i<translated_accounts_len; i++ ) {
    fd_vm_cpi_translated_account_t * translated_account = &translated_accounts[i];
    fd_guarded_borrowed_account_t callee_acc = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( vm->instr_ctx, translated_account->index_in_caller, &callee_acc );
    if( !translated_account->update_caller_account_info ) continue;
    err = VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC( vm, &translated_account->caller_account, &callee_acc );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
  }

  /* With virtual_address_space_adjustments, update the caller's memory regions
     to reflect any changes the callee made to account data.
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/program-runtime/src/cpi.rs#L1069-L1090 */
  if( vm->virtual_address_space_adjustments ) {
    for( ulong i=0UL; i<translated_accounts_len; i++ ) {
      fd_vm_cpi_translated_account_t * translated_account = &translated_accounts[i];
      fd_guarded_borrowed_account_t borrowed_callee_acc = {0};
      err = fd_exec_instr_ctx_try_borrow_instr_account( vm->instr_ctx, translated_account->index_in_caller, &borrowed_callee_acc );
      if( FD_UNLIKELY( err ) ) return err;
      if( !translated_account->update_caller_account_region ) continue;

      err = fd_vm_cpi_update_caller_account_region( vm, translated_account, &borrowed_callee_acc );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    }
  }

  long const regime3 = fd_tickcount();
  vm->instr_ctx->runtime->metrics.cpi_commit_cum_ticks += (ulong)( regime3-regime2 );

  return FD_VM_SUCCESS;
}

#undef VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC
#undef VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC
#undef VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC
#undef VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC
#undef VM_SYSCALL_CPI_FUNC
