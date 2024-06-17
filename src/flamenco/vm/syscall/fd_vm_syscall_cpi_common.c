/* This file contains all the logic that is common to both the C and Rust 
   CPI syscalls (sol_invoke_signed_{rust/c}). As such, all of the functions in 
   here are templated and will be instantiated for both the C and Rust CPI ABIs.

   The only difference between the C and Rust CPI syscalls is the ABI data layout
   of the paramaters to these calls - all the logic is identical. As such, we have
   defined a series of macros to abstract away the ABI differences from the CPI implementation.

   The entry-point for these syscalls is VM_SYSCALL_CPI_ENTRYPOINT.

   Note that the code for these syscalls could be simplified somewhat, but we have opted to keep 
   it as close to the Solana code as possible to make it easier to audit that we execute equivalently.
   Most of the top-level functions in this file correspond directly to functions in the Solana codebase
   and links to the source have been provided.
 */

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

  /* Find the index of the CPI instruction's program account in the transaction */
  /* TODO: what if this is not present? */
  fd_pubkey_t * txn_accs = vm->instr_ctx->txn_ctx->accounts;
  for( ulong i=0UL; i < vm->instr_ctx->txn_ctx->accounts_cnt; i++ ) {
    if( !memcmp( program_id, &txn_accs[i], sizeof( fd_pubkey_t ) ) ) {
      out_instr->program_id = (uchar)i;
      out_instr->program_id_pubkey = txn_accs[i];
      break;
    }
  }

  /* Calculate summary information for the account list */
  ulong starting_lamports_h = 0UL;
  ulong starting_lamports_l = 0UL;
  uchar acc_idx_seen[256] = {0};
  for( ulong i=0UL; i<VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instr ); i++ ) {
    VM_SYSCALL_CPI_ACC_META_T const * cpi_acct_meta = &cpi_acct_metas[i];
    uchar const * pubkey = VM_SYSCALL_CPI_ACC_META_PUBKEY( vm, cpi_acct_meta );

    for( ulong j=0UL; j<vm->instr_ctx->txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( pubkey, &txn_accs[j], sizeof( fd_pubkey_t ) ) ) {
        /* TODO: error if not found, if flags are wrong */
        memcpy( out_instr->acct_pubkeys[i].uc, pubkey, sizeof( fd_pubkey_t ) );
        out_instr->acct_txn_idxs[i]     = (uchar)j;
        out_instr->acct_flags[i]        = 0;
        out_instr->borrowed_accounts[i] = &vm->instr_ctx->txn_ctx->borrowed_accounts[j];
        out_instr->is_duplicate[i]      = acc_idx_seen[j];

        if( FD_LIKELY( !acc_idx_seen[j] ) ) {
          /* This is the first time seeing this account */
          acc_idx_seen[j] = 1;
          if( out_instr->borrowed_accounts[i]->const_meta ) {
            /* TODO: what if this account is borrowed as writable? */
            fd_uwide_inc( 
              &starting_lamports_h, &starting_lamports_l,
              starting_lamports_h, starting_lamports_l,
              out_instr->borrowed_accounts[i]->const_meta->info.lamports );
          }
        }

        /* The parent flag(s) for is writable/signer is checked in fd_vm_prepare_instruction */
        if( VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( cpi_acct_meta ) ) {
          out_instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
        }

        if( VM_SYSCALL_CPI_ACC_META_IS_SIGNER( cpi_acct_meta ) ) {
          out_instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
        } else {
          /* If this account is a signer in the transaction list, then mark as signer */
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
  out_instr->starting_lamports_h = starting_lamports_h;
  out_instr->starting_lamports_l = starting_lamports_l;

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
VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC( fd_vm_t * vm,
                                      VM_SYSCALL_CPI_ACC_INFO_T const * account_info,
                                      fd_pubkey_t const * callee_acc_pubkey ) {

  /* Consume compute units for the account data access */

  /* FIXME: do we also need to consume the compute units if the account is not known? */
  VM_SYSCALL_CPI_ACC_INFO_DATA( vm, account_info, caller_acc_data );
  (void)caller_acc_data_vm_addr;

  // FIXME: should this be FD_VM_CU_MEM_UPDATE? Changing this changes the CU behaviour from main
  FD_VM_CU_UPDATE( vm, caller_acc_data_len / FD_VM_CPI_BYTES_PER_UNIT );

  fd_borrowed_account_t * callee_acc = NULL;
  int err = fd_instr_borrowed_account_modify(vm->instr_ctx, callee_acc_pubkey, 0, &callee_acc);
  if( FD_UNLIKELY( err ) ) {
    /* No need to do anything if the account is missing from the borrowed accounts cache */
    return FD_VM_SUCCESS;
  }

  if( FD_UNLIKELY( !callee_acc->meta ) ) {
    /* If the account is not modifiable, we can't change it (and it can't have been changed by the callee) */
    return FD_VM_SUCCESS;
  }
  
  /* Update the lamports */
  VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, account_info, caller_acc_lamports );
  if( callee_acc->meta->info.lamports!=*caller_acc_lamports ) callee_acc->meta->info.lamports = *caller_acc_lamports;

  /* Update the account data, if the account data can be changed */
  int err1;
  int err2;
  /* FIXME: double-check these permissions, especially the callee_acc_idx */
  if( fd_account_can_data_be_resized( vm->instr_ctx, callee_acc->meta, caller_acc_data_len, &err1 ) &&
      fd_account_can_data_be_changed2( vm->instr_ctx, callee_acc->meta, callee_acc_pubkey, &err2 ) ) {
      /* We must ignore the errors here, as they are informational and do not mean the result is invalid. */
      /* TODO: not pass informational errors like this? */
    callee_acc->meta->dlen = caller_acc_data_len;
    fd_memcpy( callee_acc->data, caller_acc_data, caller_acc_data_len );
  }

  int is_disable_cpi_setting_executable_and_rent_epoch_active = FD_FEATURE_ACTIVE(vm->instr_ctx->slot_ctx, disable_cpi_setting_executable_and_rent_epoch);
  if( !is_disable_cpi_setting_executable_and_rent_epoch_active &&
      fd_account_is_executable( callee_acc->meta )!=account_info->executable ) {
    fd_pubkey_t const * program_acc = &vm->instr_ctx->instr->acct_pubkeys[vm->instr_ctx->instr->program_id];
    fd_account_set_executable2( vm->instr_ctx, program_acc, callee_acc->meta, (char)account_info->executable);
  }

  uchar const * caller_acc_owner = FD_VM_MEM_HADDR_LD( vm, account_info->owner_addr, alignof(uchar), sizeof(fd_pubkey_t) );
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
                              fd_vm_t *                         vm,
                              fd_instruction_account_t const *  instruction_accounts,
                              ulong const                       instruction_accounts_cnt,
                              VM_SYSCALL_CPI_ACC_INFO_T const * account_infos,
                              ulong const                       account_infos_length,
                              ulong *                           out_callee_indices,
                              ulong *                           out_caller_indices,
                              ulong *                           out_len ) {

  for( ulong i=0UL; i<instruction_accounts_cnt; i++ ) {
    if( i!=instruction_accounts[i].index_in_callee ) {
      /* Skip duplicate accounts */
      continue;
    }

    fd_pubkey_t const * callee_account = &vm->instr_ctx->instr->acct_pubkeys[instruction_accounts[i].index_in_caller];
    fd_pubkey_t const * account_key = &vm->instr_ctx->txn_ctx->accounts[instruction_accounts[i].index_in_transaction];
    fd_borrowed_account_t * acc_rec = NULL;
    int err = fd_instr_borrowed_account_view( vm->instr_ctx, callee_account, &acc_rec );
    if( FD_UNLIKELY( err && ( err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) ) {
      /* TODO: magic number */
      return 1000;
    }

    /* const_meta is NULL if the account is a new account (it doesn't exist in Funk at the time of the transaction) */
    fd_account_meta_t const * acc_meta = acc_rec->const_meta;
    uchar known_account = !!acc_meta;

    /* If the account is known and executable, we only need to consume the compute units.
       Executable accounts can't be modified, so we don't need to update the callee account. */
    if( known_account && fd_account_is_executable( acc_meta ) ) {
      // FIXME: should this be FD_VM_CU_MEM_UPDATE? Changing this changes the CU behaviour from main (because of the base cost)
      FD_VM_CU_UPDATE( vm, acc_meta->dlen / FD_VM_CPI_BYTES_PER_UNIT );
      continue;
    }

    /* Find the indicies of the account in the caller and callee instructions */
    uint found = 0;
    for( ulong j=0; (j < account_infos_length) && !found; j++ ) {

      /* Look up the pubkey to see if it is the account we're looking for */
      fd_pubkey_t const * acct_addr = FD_VM_MEM_HADDR_LD( 
        vm, account_infos[j].pubkey_addr, alignof(uchar), sizeof(fd_pubkey_t) );
      if( memcmp( account_key->uc, acct_addr->uc, sizeof(fd_pubkey_t) ) != 0 ) {
        continue;
      }

      /* Record the indicies of this account */
      if (instruction_accounts[i].is_writable) {
        out_callee_indices[*out_len] = instruction_accounts[i].index_in_caller;
        out_caller_indices[*out_len] = j;
        (*out_len)++;
      }
      found = 1;

      /* Update the callee account to reflect any changes the caller has made */
      if( FD_UNLIKELY( acc_meta && VM_SYCALL_CPI_UPDATE_CALLEE_ACC_FUNC(vm, &account_infos[j], callee_account ) ) ) {
        
        return 1001;
      }
    }

    if( !found ) {
      /* TODO: magic number */
      return 1002;
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
VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC( fd_vm_t *                  vm,
                                      VM_SYSCALL_CPI_ACC_INFO_T * caller_acc_info,
                                      fd_pubkey_t const *         pubkey ) {

  /* Look up the borrowed account from the instruction context, which will contain
    the callee's changes. */
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
  uchar * caller_acc_owner = FD_VM_MEM_HADDR_ST( vm, caller_acc_info->owner_addr, alignof(uchar), sizeof(fd_pubkey_t) );
  if( updated_owner ) fd_memcpy( caller_acc_owner, updated_owner, sizeof(fd_pubkey_t) );
  else                fd_memset( caller_acc_owner, 0,             sizeof(fd_pubkey_t) );

  /* Update the caller account data with the value from the callee */
  VM_SYSCALL_CPI_ACC_INFO_DATA( vm, caller_acc_info, caller_acc_data );

  ulong const updated_data_len = callee_acc_rec->const_meta->dlen;
  if( !updated_data_len ) fd_memset( caller_acc_data, 0, caller_acc_data_len );

  if( caller_acc_data_len != updated_data_len ) {    
    /* FIXME: missing MAX_PERMITTED_DATA_INCREASE check from solana
       https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1342 */

    /* FIXME: do we need to zero the memory that was previously used, if the new data_len is smaller?
      https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1361
      I don't think we do but need to double-check. */

    VM_SYSCALL_CPI_SET_ACC_INFO_DATA_LEN( vm, caller_acc_info, caller_acc_data, updated_data_len );

    /* Update the serialized len field 
       https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1437 */
    ulong * caller_len = FD_VM_MEM_HADDR_ST( vm, fd_ulong_sat_sub(caller_acc_data_vm_addr, sizeof(ulong)), alignof(ulong), sizeof(ulong) );
    *caller_len = updated_data_len;

    /* FIXME return instruction error account data size too small in the same scenarios solana does
       https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1534 */
  }

  fd_memcpy( caller_acc_data, callee_acc_rec->const_data, updated_data_len );

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

  /* Pre-flight checks ************************************************/
  int err = fd_vm_syscall_cpi_preflight_check( signers_seeds_cnt, acct_info_cnt, vm->instr_ctx->slot_ctx );
  if( FD_UNLIKELY( err ) ) return err;
  
  /* Translate instruction ********************************************/
  VM_SYSCALL_CPI_INSTR_T const * cpi_instruction =
    FD_VM_MEM_HADDR_LD( vm, instruction_va, VM_SYSCALL_CPI_INSTR_ALIGN, VM_SYSCALL_CPI_INSTR_SIZE );

  if( FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, loosen_cpi_size_restriction ) ) {
    // FIXME: should this be FD_VM_CU_MEM_UPDATE? Changing this changes the CU behaviour from main
    FD_VM_CU_UPDATE( vm, VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) / FD_VM_CPI_BYTES_PER_UNIT );
  }

  /* Derive PDA signers ************************************************/
  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ] = {0};
  fd_pubkey_t * caller_program_id = &vm->instr_ctx->txn_ctx->accounts[ vm->instr_ctx->instr->program_id ];
  fd_vm_vec_t const * signers_seeds = FD_VM_MEM_HADDR_LD( vm, signers_seeds_va, FD_VM_VEC_ALIGN, signers_seeds_cnt*FD_VM_VEC_SIZE );
  for ( ulong i=0UL; i<signers_seeds_cnt; i++ ) {
    int err = fd_vm_derive_pda( vm, caller_program_id, signers_seeds[i].addr, signers_seeds[i].len, NULL, &signers[i] );
    if ( FD_UNLIKELY( err ) ) {
      return err;
    }
  }

  /* Translate CPI account metas *************************************************/
  VM_SYSCALL_CPI_ACC_META_T const * cpi_account_metas =
    FD_VM_MEM_HADDR_LD( vm, VM_SYSCALL_CPI_INSTR_ACCS_ADDR( cpi_instruction ),
                        VM_SYSCALL_CPI_ACC_META_ALIGN,
                        VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction )*VM_SYSCALL_CPI_ACC_META_SIZE );

  /* Translate instruction data *************************************************/

  uchar const * data = FD_VM_MEM_HADDR_LD( 
    vm, VM_SYSCALL_CPI_INSTR_DATA_ADDR( cpi_instruction ),
    alignof(uchar),
    VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ));

  /* Authorized program check *************************************************/

  fd_pubkey_t const * program_id = (fd_pubkey_t *)VM_SYSCALL_CPI_INSTR_PROGRAM_ID( vm, cpi_instruction );
  if( FD_UNLIKELY( fd_vm_syscall_cpi_check_authorized_program( program_id, vm->instr_ctx->slot_ctx, data, VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) ) ) )
    return FD_VM_ERR_PERM;

  /* Instruction checks ***********************************************/

  err = fd_vm_syscall_cpi_check_instruction( vm, VM_SYSCALL_CPI_INSTR_ACCS_LEN( cpi_instruction ), VM_SYSCALL_CPI_INSTR_DATA_LEN( cpi_instruction ) );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate account infos ******************************************/
  VM_SYSCALL_CPI_ACC_INFO_T * acc_infos =
    FD_VM_MEM_HADDR_ST( vm, 
                        acct_infos_va,
                        VM_SYSCALL_CPI_ACC_INFO_ALIGN,
                        acct_info_cnt*VM_SYSCALL_CPI_ACC_INFO_SIZE );

  /* Create the instruction to execute (in the input format the FD runtime expects) from
     the translated CPI ABI inputs. */
  fd_instr_info_t instruction_to_execute;
  err = VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC( vm, cpi_instruction, cpi_account_metas, program_id, signers, signers_seeds_cnt, data, &instruction_to_execute );
  if( FD_UNLIKELY( err ) ) return err;

  /* Prepare the instruction for execution in the runtime. This is required by the runtime
     before we can pass an instruction to the executor. */
  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;
  err = fd_vm_prepare_instruction( vm->instr_ctx->instr, &instruction_to_execute, vm->instr_ctx, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) return err;

  /* Update the callee accounts with any changes made by the caller prior to this CPI execution */
  ulong callee_account_keys[256];
  ulong caller_accounts_to_update[256];
  ulong caller_accounts_to_update_len = 0;
  err = VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC(vm, instruction_accounts, instruction_accounts_cnt, acc_infos, acct_info_cnt, callee_account_keys, caller_accounts_to_update, &caller_accounts_to_update_len);
  if( FD_UNLIKELY( err ) ) return err;

  /* Check that the caller lamports haven't changed */
  ulong caller_lamports_h = 0UL;
  ulong caller_lamports_l = 0UL;

  err = fd_instr_info_sum_account_lamports( vm->instr_ctx->instr, &caller_lamports_h, &caller_lamports_l );
  if ( FD_UNLIKELY( err ) ) return FD_VM_ERR_INSTR_ERR;

  if( caller_lamports_h != vm->instr_ctx->instr->starting_lamports_h || 
      caller_lamports_l != vm->instr_ctx->instr->starting_lamports_l ) {
    return FD_VM_ERR_INSTR_ERR;
  }
  
  /* Set the transaction compute meter to be the same as the VM's compute meter,
     so that the callee cannot use compute units that the caller has already used. */
  vm->instr_ctx->txn_ctx->compute_meter = vm->cu;

  /* Execute the CPI instruction in the runtime */
  int err_exec = fd_execute_instr( vm->instr_ctx->txn_ctx, &instruction_to_execute );
  ulong instr_exec_res = (ulong)err_exec;

  /* Set the CU meter to the instruction context's transaction context's compute meter,
     so that the caller can't use compute units that the callee has already used. */
  vm->cu = vm->instr_ctx->txn_ctx->compute_meter;

  *_ret = instr_exec_res;
  if( FD_UNLIKELY( instr_exec_res ) ) return FD_VM_ERR_INSTR_ERR;

  /* Update the caller accounts with any changes made by the callee during CPI execution */
  for( ulong i = 0; i < caller_accounts_to_update_len; i++ ) {
    fd_pubkey_t const * callee = &vm->instr_ctx->instr->acct_pubkeys[callee_account_keys[i]];
    err = VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC(vm, &acc_infos[caller_accounts_to_update[i]], callee);
    if( FD_UNLIKELY( err ) ) return err;
  }

  caller_lamports_h = 0UL;
  caller_lamports_l = 0UL;
  err = fd_instr_info_sum_account_lamports( vm->instr_ctx->instr, &caller_lamports_h, &caller_lamports_l );
  if ( FD_UNLIKELY( err ) ) return FD_VM_ERR_INSTR_ERR;

  if( caller_lamports_h != vm->instr_ctx->instr->starting_lamports_h || 
      caller_lamports_l != vm->instr_ctx->instr->starting_lamports_l ) {
    return FD_VM_ERR_INSTR_ERR;
  }
  
  return FD_VM_SUCCESS;
}

#undef VM_SYSCALL_CPI_UPDATE_CALLER_ACC_FUNC
#undef VM_SYSCALL_CPI_FROM_ACC_INFO_FUNC
#undef VM_SYSCALL_CPI_TRANSLATE_AND_UPDATE_ACCOUNTS_FUNC
#undef VM_SYSCALL_CPI_INSTRUCTION_TO_INSTR_FUNC
#undef VM_SYSCALL_CPI_FUNC
