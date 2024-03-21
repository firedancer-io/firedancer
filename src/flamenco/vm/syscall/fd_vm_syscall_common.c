/* fd_vm_syscall_cpi_instruction_to_instr_{c/rust} takes the translated
   CPI ABI structures (instruction and account meta list), and uses these
   to populate a fd_instr_info_t struct. This struct can then be given to the
   FD runtime for execution.
   
Paramaters:
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
VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC( fd_vm_t * vm,
                            VM_SYSCALL_CPI_INSTR_T const * cpi_instr,
                            VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_metas,
                            fd_pubkey_t const * program_id,
                            fd_pubkey_t const * signers,
                            ulong const signers_cnt,
                            uchar const * cpi_instr_data,
                            fd_instr_info_t * out_instr ) {

  // Find the index of the CPI instruction's program account in the transaction
  // FIXME: what if this is not present?
  fd_pubkey_t * txn_accs = vm->instr_ctx->txn_ctx->accounts;
  for( ulong i=0UL; i < vm->instr_ctx->txn_ctx->accounts_cnt; i++ ) {
    if( !memcmp( program_id, &txn_accs[i], sizeof( fd_pubkey_t ) ) ) {
      FD_LOG_DEBUG(( "CPI PI: %lu %32J", i, program_id ));
      out_instr->program_id = (uchar)i;
      out_instr->program_id_pubkey = txn_accs[i];
      break;
    }
  }

  // Iterate over the instruction accounts
  ulong starting_lamports = 0UL;
  uchar acc_idx_seen[256] = {0};
  
  // Iterate over all the accounts laid out in the CPI
  for( ulong i=0UL; i<VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instr ); i++ ) {
    VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_meta = &cpi_acct_metas[i];
    uchar const * pubkey = VM_SYSCALL_CPI_TRANSLATE_ACC_META_PUBKEY( vm, cpi_acct_meta );
    if (FD_UNLIKELY( !pubkey )) return FD_VM_ERR_PERM;

    // FIXME: error if translation failed

    for( ulong j=0UL; j<vm->instr_ctx->txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( pubkey, &txn_accs[j], sizeof( fd_pubkey_t ) ) ) {
        // TODO: error if not found, if flags are wrong;
        memcpy( out_instr->acct_pubkeys[i].uc, pubkey, sizeof( fd_pubkey_t ) );
        out_instr->acct_txn_idxs[i] = (uchar)j;
        out_instr->acct_flags[i] = 0;
        out_instr->borrowed_accounts[i] = &vm->instr_ctx->txn_ctx->borrowed_accounts[j];

        out_instr->is_duplicate[i] = acc_idx_seen[j];
        if( FD_LIKELY( !acc_idx_seen[j] ) ) {
          /* This is the first time seeing this account */
          acc_idx_seen[j] = 1;
          if( out_instr->borrowed_accounts[i]->const_meta ) {
            // TODO: what if this account is borrowed as writable?
            starting_lamports += out_instr->borrowed_accounts[i]->const_meta->info.lamports;
          }
        }

        // TODO: should check the parent has writable flag set
        if( VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( cpi_acct_meta ) && fd_instr_acc_is_writable( vm->instr_ctx->instr, (fd_pubkey_t*)pubkey) ) {
          out_instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
        }

        // TODO: should check the parent has signer flag set
        if( VM_SYSCALL_CPI_ACC_META_IS_SIGNER( cpi_acct_meta ) ) {
          out_instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
        } else {
          // If this account is a signer in the transaction list, then mark as signer
          for( ulong k = 0; k < signers_cnt; k++ ) {
            if( !memcmp( &signers[k], pubkey, sizeof( fd_pubkey_t ) ) ) {
              out_instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
              break;
            }
          }
        }

        break;
      }
    }
  }

  out_instr->data_sz = (ushort)VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instr );
  out_instr->data = (uchar *)cpi_instr_data;
  out_instr->acct_cnt = (ushort)VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instr );
  out_instr->starting_lamports = starting_lamports;

  return FD_VM_SUCCESS;
}

/* 
fd_vm_syscall_cpi_update_callee_acc_{rust/c} corresponds to solana_bpf_loader_program::syscalls::cpi::update_callee_account:
https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L1302

This function should be called before the CPI instruction is executed. It's purpose is to 
update the callee account's view (the copy of the account stored in the instruction context's
borrowed accounts cache) of the given account. The caller may have made changes to the account
before the CPI instruction is executed. This function updates the borrowed accounts cache with
these changes.
*/
#define VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_update_callee_acc_, VM_SYSCALL_CPI_ABI)
static int
VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC( fd_vm_t * vm,
                                      VM_SYSCALL_CPI_ACC_INFO_T const * account_info,
                                      fd_pubkey_t const * callee_acc_pubkey ) {

  fd_borrowed_account_t * callee_acc = NULL;
  int err = fd_instr_borrowed_account_modify(vm->instr_ctx, callee_acc_pubkey, 0, &callee_acc);
  if( FD_UNLIKELY( err ) ) {
    // No need to do anything if the account is missing from the borrowed accounts cache
    return FD_VM_SUCCESS;
  }

  if( FD_UNLIKELY( !callee_acc->meta ) ) {
    // If the account is not modifiable, we can't change it (and it can't have been changed by the callee)
    FD_LOG_DEBUG(( "account is not modifiable - key: %32J", callee_acc_pubkey ));
    return FD_VM_SUCCESS;
  }
  
  // Update the lamports
  VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, account_info, caller_acc_lamports );
  if( callee_acc->meta->info.lamports!=*caller_acc_lamports ) callee_acc->meta->info.lamports = *caller_acc_lamports;

  // FIXME: do we also need to consume the compute units if the account is not known?
  VM_SYSCALL_CPI_ACC_INFO_DATA( vm, account_info, caller_acc_data );
  (void)caller_acc_data_vm_addr;

  err = fd_vm_consume_compute( vm, caller_acc_data_len / FD_VM_CPI_BYTES_PER_UNIT );
  if( FD_UNLIKELY( err ) ) return err;

  // Update the account data, if the account data can be changed.
  int err1;
  int err2;
  if( fd_account_can_data_be_resized( vm->instr_ctx, callee_acc->meta, caller_acc_data_len, &err1 ) &&
      fd_account_can_data_be_changed( vm->instr_ctx, callee_acc->meta, callee_acc_pubkey, &err2 ) ) {
      // We must ignore the errors here, as they are informational and do not mean the result is invalid.
      // TODO: not pass informational errors like this?
    callee_acc->meta->dlen = caller_acc_data_len;
    fd_memcpy( callee_acc->data, caller_acc_data, caller_acc_data_len );
  }

  int is_disable_cpi_setting_executable_and_rent_epoch_active = FD_FEATURE_ACTIVE(vm->instr_ctx->slot_ctx, disable_cpi_setting_executable_and_rent_epoch);
  if( !is_disable_cpi_setting_executable_and_rent_epoch_active &&
      fd_account_is_executable(vm->instr_ctx, callee_acc->meta, NULL)!=account_info->executable ) {
    fd_pubkey_t const * program_acc = &vm->instr_ctx->instr->acct_pubkeys[vm->instr_ctx->instr->program_id];
    fd_account_set_executable(vm->instr_ctx, program_acc, callee_acc->meta, (char)account_info->executable);
  }

  uchar * caller_acc_owner = fd_vm_translate_vm_to_host( vm, account_info->owner_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  if ( !caller_acc_owner ) return FD_VM_ERR_PERM;
  if (memcmp(callee_acc->meta->info.owner, caller_acc_owner, sizeof(fd_pubkey_t))) {
    fd_memcpy(callee_acc->meta->info.owner, caller_acc_owner, sizeof(fd_pubkey_t));
  }

  if( !is_disable_cpi_setting_executable_and_rent_epoch_active         &&
      callee_acc->meta->info.rent_epoch!=account_info->rent_epoch ) {
    if( FD_UNLIKELY( FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, enable_early_verification_of_account_modifications ) ) ) return 1;
    else callee_acc->meta->info.rent_epoch = account_info->rent_epoch;
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
                              fd_vm_t *                        vm,
                              fd_instruction_account_t const * instruction_accounts,
                              ulong const                      instruction_accounts_cnt,
                              VM_SYSCALL_CPI_ACC_INFO_T const  * account_infos,
                              ulong const                      account_infos_length,
                              ulong *                          out_callee_indices,
                              ulong *                          out_caller_indices,
                              ulong *                          out_len ) {

  for( ulong i=0UL; i<instruction_accounts_cnt; i++ ) {
    if( i!=instruction_accounts[i].index_in_callee ) {
      // Skip duplicate accounts
      continue;
    }

    fd_pubkey_t const * callee_account = &vm->instr_ctx->instr->acct_pubkeys[instruction_accounts[i].index_in_caller];
    fd_pubkey_t const * account_key = &vm->instr_ctx->txn_ctx->accounts[instruction_accounts[i].index_in_transaction];
    fd_borrowed_account_t * acc_rec = NULL;
    int err = fd_instr_borrowed_account_view( vm->instr_ctx, callee_account, &acc_rec );
    if( FD_UNLIKELY( err && ( err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) ) return 1000;

    // const_meta is NULL if the account is a new account (it doesn't exist in Funk at the time of the transaction)
    fd_account_meta_t const * acc_meta = acc_rec->const_meta;
    uchar known_account = !!acc_meta;

    // If the account is known and executable, we only need to consume the compute units.
    // Executable accounts can't be modified, so we don't need to update the callee account.
    if( known_account && fd_account_is_executable(vm->instr_ctx, acc_meta, NULL) ) {
      int err = fd_vm_consume_compute( vm, acc_meta->dlen / FD_VM_CPI_BYTES_PER_UNIT );
      if( FD_UNLIKELY( err ) ) return err;
      continue;
    }

    // Find the indicies of the account in the caller and callee instructions
    uint found = 0;
    for( ulong j=0; j < account_infos_length; j++ ) {

      // Look up the pubkey to see if it is the account we're looking for
      fd_pubkey_t const * acct_addr = fd_vm_translate_vm_to_host_const( 
        vm, account_infos[j].pubkey_addr, sizeof(fd_pubkey_t), alignof(uchar) );
      if( FD_UNLIKELY( !acct_addr ) ) return FD_VM_ERR_PERM;
      if( memcmp( account_key->uc, acct_addr->uc, sizeof(fd_pubkey_t) ) != 0 ) {
        continue;
      }

      // Record the indicies of this account
      if (instruction_accounts[i].is_writable) {
        out_callee_indices[*out_len] = instruction_accounts[i].index_in_caller;
        out_caller_indices[*out_len] = j;
        (*out_len)++;
      }
      found = 1;

      // Update the callee account to reflect any changes the caller has made
      if( FD_UNLIKELY( acc_meta && VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC(vm, &account_infos[j], callee_account) ) ) {
        // TODO: which error code does this correspond to?
        return 1001;
      }
    }

    // TODO: which error code should this return?
    if( !found ) return 1002;
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
VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC( fd_vm_t *                        vm,
                                      VM_SYSCALL_CPI_ACC_INFO_T const * caller_acc_info,
                                      fd_pubkey_t const *               pubkey ) {

  // Look up the borrowed account from the instruction context, which will contain
  // the callee's changes.
  fd_borrowed_account_t * callee_acc_rec = NULL;
  int err = fd_instr_borrowed_account_view( vm->instr_ctx, pubkey, &callee_acc_rec );
  if( FD_UNLIKELY( err && ( err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) ) {
    return 1;
  }
  
  /* Update the caller account lamports with the value from the callee */
  VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, caller_acc_info, caller_acc_lamports );
  *caller_acc_lamports = callee_acc_rec->const_meta->info.lamports;;

  /* Update the caller account owner with the value from the callee */
  uchar const * updated_owner = callee_acc_rec->const_meta->info.owner;
  uchar * caller_acc_owner = fd_vm_translate_vm_to_host( vm, caller_acc_info->owner_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  if ( !caller_acc_owner ) return FD_VM_ERR_PERM;
  if( updated_owner ) fd_memcpy( caller_acc_owner, updated_owner, sizeof(fd_pubkey_t) );
  else                fd_memset( caller_acc_owner, 0,             sizeof(fd_pubkey_t) );

  /* Update the caller account data with the value from the callee */
  VM_SYSCALL_CPI_ACC_INFO_DATA( vm, caller_acc_info, caller_acc_data );

  ulong const updated_data_len = callee_acc_rec->const_meta->dlen;
  if( !updated_data_len ) fd_memset( caller_acc_data, 0, caller_acc_data_len );

  if( caller_acc_data_len != updated_data_len ) {    
    // FIXME: missing MAX_PERMITTED_DATA_INCREASE check from solana
    // https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1342

    // FIXME: do we need to zero the memory that was previously used, if the new data_len is smaller?
    // https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1361
    // I don't think we do but need to double-check.

    FD_LOG_DEBUG(( "account size mismatch while updating CPI caller account - key: %32J, caller: %lu, callee: %lu", pubkey, caller_acc_data_len, updated_data_len ));

    VM_SYSCALL_CPI_SET_ACC_INFO_DATA_LEN( vm, caller_acc_info, caller_acc_data, updated_data_len );

    // Update the serialized len field 
    // https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1437
    ulong * caller_len =
      fd_vm_translate_vm_to_host( vm, fd_ulong_sat_sub(caller_acc_data_vm_addr, sizeof(ulong)), sizeof(ulong), alignof(ulong) );
    if (FD_UNLIKELY( !caller_len )) return FD_VM_ERR_PERM;
    *caller_len = updated_data_len;

    // FIXME return instruction error account data size too small in the same scenarios solana does
    // https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1534
  }

  fd_memcpy( caller_acc_data, callee_acc_rec->const_data, updated_data_len );

  return 0;
}

/* Same logic as cpi_common:
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1060 */
#define VM_SYSCALL_CPI_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_, VM_SYSCALL_CPI_ABI)
int
VM_SYSCALL_CPI_FUNC( void *  _vm,
                        ulong   instruction_va,
                        ulong   acct_infos_va,
                        ulong   acct_info_cnt,
                        ulong   signers_seeds_va,
                        ulong   signers_seeds_cnt,
                        ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  int err = fd_vm_consume_compute( vm, FD_VM_INVOKE_UNITS );
  if( FD_UNLIKELY( err ) ) return err;

  /* Pre-flight checks ************************************************/
  err = fd_vm_syscall_cpi_preflight_check( signers_seeds_cnt, acct_info_cnt, vm->instr_ctx->slot_ctx );
  if( FD_UNLIKELY( err ) ) return err;
  
  /* Translate instruction ********************************************/
  VM_SYSCALL_CPI_INSTR_T const * cpi_instruction =
    fd_vm_translate_vm_to_host_const( vm, instruction_va, VM_SYSCALL_CPI_INSTR_SIZE, VM_SYSCALL_CPI_INSTR_ALIGN );
  if( FD_UNLIKELY( !cpi_instruction ) ) return FD_VM_ERR_PERM;

  if( FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, loosen_cpi_size_restriction ) ) {
    fd_vm_consume_compute( vm,
      fd_ulong_if( FD_VM_CPI_BYTES_PER_UNIT, 
        VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction )/FD_VM_CPI_BYTES_PER_UNIT, ULONG_MAX ) );
  }

  /* Derive PDA signers ************************************************/
  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  err = fd_vm_syscall_cpi_derive_signers( vm, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate CPI account metas *************************************************/
  VM_SYSCALL_CPI_ACC_META_T const * cpi_account_metas =
    fd_vm_translate_vm_to_host_const( vm, VM_SYSCALL_CPI_INSTR_ACCS_ADDR( cpi_instruction ),
                                      VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction )*VM_SYSCALL_CPI_ACC_META_SIZE, VM_SYSCALL_CPI_ACC_META_ALIGN );

  // FIXME: what to do in the case where we have no accounts? At the moment this "works" almost by accident
  // This is another case where we are not correctly handling translation of empty arrays
  if( FD_UNLIKELY( !cpi_account_metas && VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ) ) ) {
    return FD_VM_ERR_PERM;
  }

  /* Translate instruction data *************************************************/

  uchar const * data = fd_vm_translate_vm_to_host_const( 
    vm, 
    VM_SYSCALL_CPI_INSTR_DATA_ADDR( cpi_instruction ),
    VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ),
    alignof(uchar) );
  if (FD_UNLIKELY( !data )) return FD_VM_ERR_PERM;

  /* Authorized program check *************************************************/

  fd_pubkey_t const * program_id = (fd_pubkey_t *)VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR( vm, cpi_instruction );
  if( FD_UNLIKELY( fd_vm_syscall_cpi_check_authorized_program( program_id, vm->instr_ctx->slot_ctx, data, VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) ) ) )
    return FD_VM_ERR_PERM;

  /* Instruction checks ***********************************************/

  err = fd_vm_syscall_cpi_check_instruction( vm, VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ), VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate account infos ******************************************/
  VM_SYSCALL_CPI_ACC_INFO_T const * acc_infos =
    fd_vm_translate_vm_to_host_const( vm, acct_infos_va,
                                      acct_info_cnt*VM_SYSCALL_CPI_ACC_INFO_SIZE, VM_SYSCALL_CPI_ACC_INFO_ALIGN );
  if( FD_UNLIKELY( !acc_infos ) ) return FD_VM_ERR_PERM;

  // Create the instruction to execute (in the input format the FD runtime expects) from
  // the translated CPI ABI inputs.
  fd_instr_info_t instruction_to_execute;
  err = VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC( vm, cpi_instruction, cpi_account_metas, program_id, signers, signers_seeds_cnt, data, &instruction_to_execute );
  if( FD_UNLIKELY( err ) ) return err;

  // Prepare the instruction for execution
  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;
  err = fd_vm_prepare_instruction(vm->instr_ctx->instr, &instruction_to_execute, vm->instr_ctx, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(("PREPARE FAILED"));
    return err;
  }

  // Update the callee accounts with any changes made by the caller prior to this CPI execution
  ulong callee_account_keys[256];
  ulong caller_accounts_to_update[256];
  ulong caller_accounts_to_update_len = 0;
  err = VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC(vm, instruction_accounts, instruction_accounts_cnt, acc_infos, acct_info_cnt, callee_account_keys, caller_accounts_to_update, &caller_accounts_to_update_len);
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "translate failed %lu", err ));
    return err;
  }

  ulong caller_lamports = fd_instr_info_sum_account_lamports( vm->instr_ctx->instr );
  if( caller_lamports!=vm->instr_ctx->instr->starting_lamports ) return FD_VM_ERR_INSTR_ERR;
  
  vm->instr_ctx->txn_ctx->compute_meter = vm->compute_meter;

  // Actually perform the execution
  int err_exec = fd_execute_instr( vm->instr_ctx->txn_ctx, &instruction_to_execute );
  ulong instr_exec_res = (ulong)err_exec;

  // TODO: harmonise CU usage using kevin's macros
  FD_LOG_DEBUG(( "CPI CUs CONSUMED: %lu %lu %lu ", vm->compute_meter, vm->instr_ctx->txn_ctx->compute_meter, vm->compute_meter - vm->instr_ctx->txn_ctx->compute_meter));
  vm->compute_meter = vm->instr_ctx->txn_ctx->compute_meter;
  FD_LOG_DEBUG(( "AFTER CPI: %lu CUs: %lu Err: %d", *_ret, vm->compute_meter, err_exec ));

  *_ret = instr_exec_res;
  if( FD_UNLIKELY( instr_exec_res ) ) return FD_VM_ERR_INSTR_ERR;

  for( ulong i = 0; i < caller_accounts_to_update_len; i++ ) {
    fd_pubkey_t const * callee = &vm->instr_ctx->instr->acct_pubkeys[callee_account_keys[i]];
    err = VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC(vm, &acc_infos[caller_accounts_to_update[i]], callee);
    if( FD_UNLIKELY( err ) ) return err;
  }

  caller_lamports = fd_instr_info_sum_account_lamports( vm->instr_ctx->instr );
  if( caller_lamports!=vm->instr_ctx->instr->starting_lamports ) return FD_VM_ERR_INSTR_ERR;

  return FD_VM_SUCCESS;
}

#undef VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC
#undef VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC
#undef VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC
#undef VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC
#undef VM_SYSCALL_CPI_FUNC