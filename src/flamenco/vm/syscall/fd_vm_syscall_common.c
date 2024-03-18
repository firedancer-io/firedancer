/* Same logic as cpi_common:
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1060 */
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
        instruction->VM_SYSCALL_CPI_INSTR_DATA_LEN/FD_VM_CPI_BYTES_PER_UNIT, ULONG_MAX ) );
  }

  /* Translate signers ************************************************/
  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  err = fd_vm_syscall_cpi_derive_signers( vm, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate accounts *************************************************/
  VM_SYSCALL_CPI_ACC_META_T const * accounts =
    fd_vm_translate_vm_to_host_const( vm, instruction->VM_SYSCALL_CPI_INSTR_ACCS_ADDR,
                                      instruction->VM_SYSCALL_CPI_INSTR_ACCS_LEN*VM_SYSCALL_CPI_ACC_META_SIZE, VM_SYSCALL_CPI_ACC_META_ALIGN );

  // FIXME: what to do in the case where we have no accounts? At the moment this "works" almost by accident
  if( FD_UNLIKELY( !accounts && instruction->VM_SYSCALL_CPI_INSTR_ACCS_LEN ) ) {
    return FD_VM_ERR_PERM;
  }

  /* Translate data *************************************************/

  uchar const * data = fd_vm_translate_vm_to_host_const( vm, instruction->VM_SYSCALL_CPI_INSTR_DATA_ADDR, instruction->VM_SYSCALL_CPI_INSTR_DATA_LEN, alignof(uchar) );

  /* Authorized program check *************************************************/

  uchar const * program_id = VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR( vm, instruction );
  if( FD_UNLIKELY( check_authorized_program( program_id, vm->instr_ctx->slot_ctx, data, instruction->VM_SYSCALL_CPI_INSTR_DATA_LEN ) ) )
    return FD_VM_ERR_PERM;

  /* Instruction checks ***********************************************/

  err = fd_vm_syscall_cpi_check_instruction( vm, instruction->VM_SYSCALL_CPI_INSTR_ACCS_LEN, instruction->VM_SYSCALL_CPI_INSTR_DATA_LEN );
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
  VM_SYSCALL_CPI_CONV_FUNC( vm, instruction, accounts, signers, signers_seeds_cnt, data, &cpi_instr );
  err = fd_vm_prepare_instruction(vm->instr_ctx->instr, &cpi_instr, vm->instr_ctx, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(("PREPARE FAILED"));
    return err;
  }

  ulong callee_account_keys[256];
  ulong caller_accounts_to_update[256];
  ulong update_len = 0;
  fd_vm_account_info_t acc_info = {.discriminant = VM_SYSCALL_ACC_INFO_DISCRIMINANT, .inner = {.VM_SYSCALL_ACC_INFO_INNER = acc_infos }};
  err = translate_and_update_accounts(vm, instruction_accounts, instruction_accounts_cnt, acct_keys, &acc_info, acct_info_cnt, callee_account_keys, caller_accounts_to_update, &update_len);
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