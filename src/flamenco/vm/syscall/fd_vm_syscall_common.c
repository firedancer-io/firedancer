#define VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_instruction_to_instr_, VM_SYSCALL_CPI_ABI)
static void
VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC( fd_vm_t * vm,
                            VM_SYSCALL_CPI_INSTR_T const * cpi_instr,
                            VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_metas,
                            fd_pubkey_t const * signers,
                            ulong signers_cnt,
                            uchar const * cpi_instr_data,
                            fd_instr_info_t * instr ) {

  fd_pubkey_t * txn_accs = vm->instr_ctx->txn_ctx->accounts;
  for( ulong i=0UL; i < vm->instr_ctx->txn_ctx->accounts_cnt; i++ ) {
    uchar const * program_id = VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR( vm, cpi_instr );
    // TODO: error if translation failed

    if( !memcmp( program_id, &txn_accs[i], sizeof( fd_pubkey_t ) ) ) {
      FD_LOG_DEBUG(( "CPI PI: %lu %32J", i, program_id ));
      instr->program_id = (uchar)i;
      instr->program_id_pubkey = txn_accs[i];
      break;
    }

  }

  ulong starting_lamports = 0UL;
  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, 256);
  // FD_LOG_DEBUG(("Accounts cnt %lu %lu", vm->instr_ctx->txn_ctx->accounts_cnt, vm->instr_ctx->txn_ctx->txn_descriptor->acct_addr_cnt));
  for( ulong i=0UL; i<VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instr ); i++ ) {
    VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_meta = &cpi_acct_metas[i];
    uchar const * pubkey = VM_SYSCALL_CPI_TRANSLATE_ACC_META_PUBKEY( vm, cpi_acct_meta );
    // FIXME: error if translation failed

    for( ulong j=0UL; j<vm->instr_ctx->txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( pubkey, &txn_accs[j], sizeof( fd_pubkey_t ) ) ) {
        // TODO: error if not found, if flags are wrong;
        memcpy( instr->acct_pubkeys[i].uc, pubkey, sizeof( fd_pubkey_t ) );
        instr->acct_txn_idxs[i] = (uchar)j;
        instr->acct_flags[i] = 0;
        instr->borrowed_accounts[i] = &vm->instr_ctx->txn_ctx->borrowed_accounts[j];

        instr->is_duplicate[i] = acc_idx_seen[j];
        if( FD_LIKELY( !acc_idx_seen[j] ) ) {
          /* This is the first time seeing this account */
          acc_idx_seen[j] = 1;
          if( instr->borrowed_accounts[i]->const_meta )
            starting_lamports += instr->borrowed_accounts[i]->const_meta->info.lamports;
        }

        // TODO: should check the parent has writable flag set
        if( VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( cpi_acct_meta ) && fd_instr_acc_is_writable( vm->instr_ctx->instr, (fd_pubkey_t*)pubkey) )
          instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;

        // TODO: should check the parent has signer flag set
        if( VM_SYSCALL_CPI_ACC_META_IS_SIGNER( cpi_acct_meta ) ) instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
        else
          for( ulong k = 0; k < signers_cnt; k++ ) {
            if( !memcmp( &signers[k], pubkey, sizeof( fd_pubkey_t ) ) ) {
              instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
              break;
            }
          }

        // FD_LOG_DEBUG(( "CPI ACCT: %lu %lu %u %32J %32J %x", i, j, (uchar)vm->instr_ctx->instr->acct_txn_idxs[j], instr->acct_pubkeys[i].uc, cpi_acct_meta->pubkey, instr->acct_flags[i] ));

        break;
      }
    }
  }

  instr->data_sz = (ushort)VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instr );
  instr->data = (uchar *)cpi_instr_data;
  instr->acct_cnt = (ushort)VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instr );
  instr->starting_lamports = starting_lamports;

}

#define VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_from_account_info_, VM_SYSCALL_CPI_ABI)
static int
VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC( fd_vm_t *            vm,
                                   VM_SYSCALL_CPI_ACC_INFO_T const * account_info,
                                   fd_caller_account_t *             out ) {

  /* Caller account lamports */
  VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, account_info, caller_acc_lamports );
  out->lamports = *caller_acc_lamports;

  /* Caller account owner */
  uchar * caller_acc_owner = fd_vm_translate_vm_to_host( vm, account_info->owner_addr, sizeof(fd_pubkey_t), alignof(uchar) );

  /* FIXME: TEST? */
  fd_memcpy(out->owner.uc, caller_acc_owner, sizeof(fd_pubkey_t));

  /* Caller account data */
  VM_SYSCALL_CPI_ACC_INFO_DATA( vm, account_info, caller_acc_data );
  (void)caller_acc_data_vm_addr;

  int err = fd_vm_consume_compute( vm, caller_acc_data_len / FD_VM_CPI_BYTES_PER_UNIT );
  if( FD_UNLIKELY( err ) ) return err;

  out->serialized_data = caller_acc_data;
  out->serialized_data_len = caller_acc_data_len;
  out->executable = account_info->executable;
  out->rent_epoch = account_info->rent_epoch;
  return 0;
}

/* 
fd_vm_syscall_cpi_translate_and_update_accounts_ mirrors the behaviour of 
solana_bpf_loader_program::syscalls::cpi::translate_and_update_accounts:
https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L954-L1085

It translates the caller accounts to the host address space, and then calls 
fd_vm_cpi_update_callee_account to set up the callee accounts ready for the 
CPI call.

Parameters:
- vm: pointer to the virtual machine handle
- instruction_accounts: 
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
    if( i!=instruction_accounts[i].index_in_callee ) continue;

    fd_pubkey_t const * callee_account = &vm->instr_ctx->instr->acct_pubkeys[instruction_accounts[i].index_in_caller];
    fd_pubkey_t const * account_key = &vm->instr_ctx->txn_ctx->accounts[instruction_accounts[i].index_in_transaction];
    fd_borrowed_account_t * acc_rec = NULL;
    fd_account_meta_t const * acc_meta = NULL;
    // FIXME: should this check be here?
    // int view_err = fd_instr_borrowed_account_view( vm->instr_ctx, callee_account, &acc_rec );
    // if( (!view_err || view_err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT) && acc_rec ) {
    //   acc_meta = acc_rec->const_meta;
    // } else {
    //   FD_LOG_DEBUG(( "account missing in translation - acc: %32J", callee_account->key ));
    // }
    fd_instr_borrowed_account_view( vm->instr_ctx, callee_account, &acc_rec );
    acc_meta = acc_rec->const_meta;

    if( acc_meta && fd_account_is_executable(vm->instr_ctx, acc_meta, NULL) ) {
      // FD_LOG_DEBUG(("CPI Acc data len %lu", acc_meta->dlen));
      int err = fd_vm_consume_compute( vm, acc_meta->dlen / FD_VM_CPI_BYTES_PER_UNIT );
      if( FD_UNLIKELY( err ) ) return err;
    } else {
      uint found = 0;

      // TODO: remove this?
      fd_pubkey_t account_info_keys[ account_infos_length ];
      for( ulong i=0UL; i<account_infos_length; i++ ) {
        fd_pubkey_t const * acct_addr = fd_vm_translate_vm_to_host_const( vm, account_infos[i].pubkey_addr, sizeof(fd_pubkey_t), alignof(uchar) );
        if( FD_UNLIKELY( !acct_addr ) ) return FD_VM_ERR_PERM;
        memcpy( account_info_keys[i].uc, acct_addr->uc, sizeof(fd_pubkey_t) );
      }

      for( ulong j=0; j < account_infos_length; j++ ) {
        if( !memcmp( account_key->uc, account_info_keys[j].uc, sizeof(fd_pubkey_t) ) ) {
          fd_caller_account_t caller_account;
          int err = VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC( vm, &account_infos[j], &caller_account );
          if( FD_UNLIKELY( err ) ) return err;

          if( FD_UNLIKELY( acc_meta && fd_vm_cpi_update_callee_account(vm, &caller_account, callee_account) ) ) return 1001;

          if (instruction_accounts[i].is_writable) {
            out_callee_indices[*out_len] = instruction_accounts[i].index_in_caller;
            out_caller_indices[*out_len] = j;
            (*out_len)++;
          }
          found = 1;
        }
      }

      // TODO: magic number?
      if( !found ) return 1002;
    }
  }
  return 0;
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
  ulong updated_lamports, updated_data_len;
  uchar const * updated_owner = NULL;
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_DEBUG(( "account missing while updating CPI caller account - key: %32J", pubkey ));
    // TODO: do we need to do something anyways
    updated_lamports = 0;
    updated_data_len = 0;
  } else {
    updated_lamports = callee_acc_rec->const_meta->info.lamports;
    updated_data_len = callee_acc_rec->const_meta->dlen;
    updated_owner = callee_acc_rec->const_meta->info.owner;
  }

  /* Update the caller account lamports */
  VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, caller_acc_info, caller_acc_lamports );
  *caller_acc_lamports = updated_lamports;

  /* Update the caller account owner */
  uchar * caller_acc_owner = fd_vm_translate_vm_to_host( vm, caller_acc_info->owner_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  if ( !caller_acc_owner ) return FD_VM_ERR_PERM;
  if( updated_owner ) fd_memcpy( caller_acc_owner, updated_owner, sizeof(fd_pubkey_t) );
  else                fd_memset( caller_acc_owner, 0,             sizeof(fd_pubkey_t) );

  /* Update the caller account data */
  VM_SYSCALL_CPI_ACC_INFO_DATA( vm, caller_acc_info, caller_acc_data );

  // TODO: deal with all functionality in update_caller_account
  if( !updated_data_len ) fd_memset( caller_acc_data, 0, caller_acc_data_len );
  if( caller_acc_data_len != updated_data_len ) {
    // FIXME: missing MAX_PERMITTED_DATA_INCREASE check from solana
    // https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1342

    // FIXME: do we need to zero the memory that was previously used, if the new data_len is smaller?
    // https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1361
    // I don't think we do but need to double-check.

    // FIXME: should this fail the transaction?
    FD_LOG_DEBUG(( "account size mismatch while updating CPI caller account - key: %32J, caller: %lu, callee: %lu", pubkey, caller_acc_data_len, updated_data_len ));

    // Update the caller data_len
    VM_SYSCALL_CPI_SET_ACC_INFO_DATA_LEN( vm, caller_acc_info, caller_acc_data, updated_data_len );
    ulong * caller_len =
      fd_vm_translate_vm_to_host( vm, fd_ulong_sat_sub(caller_acc_data_vm_addr, sizeof(ulong)), sizeof(ulong), alignof(ulong) );
    if (FD_UNLIKELY( !caller_len )) return FD_VM_ERR_PERM;
    *caller_len = updated_data_len;
    // TODO return instruction error account data size too small.
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
  VM_SYSCALL_CPI_INSTR_T const * instruction =
    fd_vm_translate_vm_to_host_const( vm, instruction_va, VM_SYSCALL_CPI_INSTR_SIZE, VM_SYSCALL_CPI_INSTR_ALIGN );
  if( FD_UNLIKELY( !instruction ) ) return FD_VM_ERR_PERM;

  if( FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, loosen_cpi_size_restriction ) ) {
    fd_vm_consume_compute( vm,
      fd_ulong_if( FD_VM_CPI_BYTES_PER_UNIT, 
        VM_SYSCALL_CPI_INSTR_DATA_LEN( instruction )/FD_VM_CPI_BYTES_PER_UNIT, ULONG_MAX ) );
  }

  /* Derive PDA signers ************************************************/
  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  err = fd_vm_syscall_cpi_derive_signers( vm, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate accounts *************************************************/
  VM_SYSCALL_CPI_ACC_META_T const * accounts =
    fd_vm_translate_vm_to_host_const( vm, VM_SYSCALL_CPI_INSTR_ACCS_ADDR( instruction ),
                                      VM_SYSCALL_CPI_INSTR_ACCS_LEN( instruction )*VM_SYSCALL_CPI_ACC_META_SIZE, VM_SYSCALL_CPI_ACC_META_ALIGN );

  // FIXME: what to do in the case where we have no accounts? At the moment this "works" almost by accident
  // This is another case where we are not correctly handling translation of empty arrays
  if( FD_UNLIKELY( !accounts && VM_SYSCALL_CPI_INSTR_ACCS_LEN( instruction ) ) ) {
    return FD_VM_ERR_PERM;
  }

  /* Translate data *************************************************/

  uchar const * data = fd_vm_translate_vm_to_host_const( vm, VM_SYSCALL_CPI_INSTR_DATA_ADDR( instruction ), VM_SYSCALL_CPI_INSTR_DATA_LEN( instruction ), alignof(uchar) );
  // if (FD_UNLIKELY( !data )) return FD_VM_ERR_PERM;

  /* Authorized program check *************************************************/

  uchar const * program_id = VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR( vm, instruction );
  if( FD_UNLIKELY( fd_vm_syscall_cpi_check_authorized_program( program_id, vm->instr_ctx->slot_ctx, data, VM_SYSCALL_CPI_INSTR_DATA_LEN( instruction ) ) ) )
    return FD_VM_ERR_PERM;

  /* Instruction checks ***********************************************/

  err = fd_vm_syscall_cpi_check_instruction( vm, VM_SYSCALL_CPI_INSTR_ACCS_LEN( instruction ), VM_SYSCALL_CPI_INSTR_DATA_LEN( instruction ) );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate account infos ******************************************/
  VM_SYSCALL_CPI_ACC_INFO_T const * acc_infos =
    fd_vm_translate_vm_to_host_const( vm, acct_infos_va,
                                      acct_info_cnt*VM_SYSCALL_CPI_ACC_INFO_SIZE, VM_SYSCALL_CPI_ACC_INFO_ALIGN );
  if( FD_UNLIKELY( !acc_infos ) ) return FD_VM_ERR_PERM;

  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;
  fd_instr_info_t cpi_instr;

  // FIXME: what if this fails?
  VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC( vm, instruction, accounts, signers, signers_seeds_cnt, data, &cpi_instr );
  err = fd_vm_prepare_instruction(vm->instr_ctx->instr, &cpi_instr, vm->instr_ctx, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(("PREPARE FAILED"));
    return err;
  }

  ulong callee_account_keys[256];
  ulong caller_accounts_to_update[256];
  ulong update_len = 0;

  err = VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC(vm, instruction_accounts, instruction_accounts_cnt, acc_infos, acct_info_cnt, callee_account_keys, caller_accounts_to_update, &update_len);
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "translate failed %lu", err ));
    return err;
  }

  ulong caller_lamports = fd_instr_info_sum_account_lamports( vm->instr_ctx->instr );
  if( caller_lamports!=vm->instr_ctx->instr->starting_lamports ) return FD_VM_ERR_INSTR_ERR;
  
  vm->instr_ctx->txn_ctx->compute_meter = vm->compute_meter;
  int err_exec = fd_execute_instr( vm->instr_ctx->txn_ctx, &cpi_instr );
  ulong instr_exec_res = (ulong)err_exec;
  FD_LOG_DEBUG(( "CPI CUs CONSUMED: %lu %lu %lu ", vm->compute_meter, vm->instr_ctx->txn_ctx->compute_meter, vm->compute_meter - vm->instr_ctx->txn_ctx->compute_meter));
  vm->compute_meter = vm->instr_ctx->txn_ctx->compute_meter;
  FD_LOG_DEBUG(( "AFTER CPI: %lu CUs: %lu Err: %d", *_ret, vm->compute_meter, err_exec ));

  *_ret = instr_exec_res;
  if( FD_UNLIKELY( instr_exec_res ) ) return FD_VM_ERR_INSTR_ERR;

  for( ulong i = 0; i < update_len; i++ ) {
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