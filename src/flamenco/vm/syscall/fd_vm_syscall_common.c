/* Same logic as cpi_common:
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1060 */

#define VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC FD_EXPAND_THEN_CONCAT2(fd_vm_syscall_cpi_instruction_to_instr, VM_SYSCALL_CPI_ABI)
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

#define VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC FD_EXPAND_THEN_CONCAT2(from_account_info_, VM_SYSCALL_CPI_ABI)
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

  int err = fd_vm_consume_compute( vm, caller_acc_data_len / FD_VM_CPI_BYTES_PER_UNIT );
  if( FD_UNLIKELY( err ) ) return err;

  out->serialized_data = caller_acc_data;
  out->serialized_data_len = caller_acc_data_len;
  out->executable = account_info->executable;
  out->rent_epoch = account_info->rent_epoch;
  return 0;
}

/* FIXME: PREFIX */
/* https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L971 */
#define VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC FD_EXPAND_THEN_CONCAT2(translate_and_update_accounts_, VM_SYSCALL_CPI_ABI)
static int
VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC( fd_vm_t *       vm,
                               fd_instruction_account_t *   instruction_accounts,
                               ulong                        instruction_accounts_cnt,
                               fd_pubkey_t const *          account_info_keys,
                               VM_SYSCALL_CPI_ACC_INFO_T    const * account_infos,
                               ulong                        account_info_cnt,
                               ulong *                      out_callee_indices,
                               ulong *                      out_caller_indices,
                               ulong *                      out_len ) {

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
      for( ulong j=0; j < account_info_cnt; j++ ) {
        if( !memcmp( account_key->uc, account_info_keys[j].uc, sizeof(fd_pubkey_t) ) ) {
          fd_caller_account_t caller_account;
          int err = VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC( vm, &account_infos[j], &caller_account );
          if( FD_UNLIKELY( err ) ) return err;

          // FD_LOG_DEBUG(("CPI Acc data len %lu for %32J", caller_account.serialized_data_len, account_key->uc));
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

  /* Translate signers ************************************************/
  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  err = fd_vm_syscall_cpi_derive_signers( vm, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate accounts *************************************************/
  VM_SYSCALL_CPI_ACC_META_T const * accounts =
    fd_vm_translate_vm_to_host_const( vm, VM_SYSCALL_CPI_INSTR_ACCS_ADDR( instruction ),
                                      VM_SYSCALL_CPI_INSTR_ACCS_LEN( instruction )*VM_SYSCALL_CPI_ACC_META_SIZE, VM_SYSCALL_CPI_ACC_META_ALIGN );

  // FIXME: what to do in the case where we have no accounts? At the moment this "works" almost by accident
  if( FD_UNLIKELY( !accounts && VM_SYSCALL_CPI_INSTR_ACCS_LEN( instruction ) ) ) {
    return FD_VM_ERR_PERM;
  }

  /* Translate data *************************************************/

  uchar const * data = fd_vm_translate_vm_to_host_const( vm, VM_SYSCALL_CPI_INSTR_DATA_ADDR( instruction ), VM_SYSCALL_CPI_INSTR_DATA_LEN( instruction ), alignof(uchar) );

  /* Authorized program check *************************************************/

  uchar const * program_id = VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR( vm, instruction );
  if( FD_UNLIKELY( check_authorized_program( program_id, vm->instr_ctx->slot_ctx, data, VM_SYSCALL_CPI_INSTR_DATA_LEN( instruction ) ) ) )
    return FD_VM_ERR_PERM;

  /* Instruction checks ***********************************************/

  err = fd_vm_syscall_cpi_check_instruction( vm, VM_SYSCALL_CPI_INSTR_ACCS_LEN( instruction ), VM_SYSCALL_CPI_INSTR_DATA_LEN( instruction ) );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate account infos ******************************************/

  VM_SYSCALL_CPI_ACC_INFO_T const * acc_infos =
    fd_vm_translate_vm_to_host_const( vm, acct_infos_va,
                                      acct_info_cnt*VM_SYSCALL_CPI_ACC_INFO_SIZE, VM_SYSCALL_CPI_ACC_INFO_ALIGN );
  if( FD_UNLIKELY( !acc_infos ) ) return FD_VM_ERR_PERM;

  /* Collect pubkeys */
  fd_pubkey_t acct_keys[ acct_info_cnt ];  /* FIXME get rid of VLA */
  for( ulong i=0UL; i<acct_info_cnt; i++ ) {
    fd_pubkey_t const * acct_addr =
      fd_vm_translate_vm_to_host_const( vm, acc_infos[i].pubkey_addr, sizeof(fd_pubkey_t), alignof(uchar) );
    if( FD_UNLIKELY( !acct_addr ) ) return FD_VM_ERR_PERM;
    memcpy( acct_keys[i].uc, acct_addr->uc, sizeof(fd_pubkey_t) );
  }

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

  err = VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC(vm, instruction_accounts, instruction_accounts_cnt, acct_keys, acc_infos, acct_info_cnt, callee_account_keys, caller_accounts_to_update, &update_len);
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

#undef VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC
#undef VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC
#undef VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC
#undef VM_SYSCALL_CPI_FUNC