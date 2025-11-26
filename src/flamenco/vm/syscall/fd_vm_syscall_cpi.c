#include "fd_vm_syscall.h"
#include "../../runtime/fd_borrowed_account.h"
#include "../../runtime/fd_system_ids.h"

/* FIXME: ALGO EFFICIENCY */
static inline int
fd_vm_syscall_cpi_is_signer( fd_pubkey_t const * account,
           fd_pubkey_t const * signers,
           ulong               signers_cnt ) {
  for( ulong i=0UL; i<signers_cnt; i++ ) if( !memcmp( account->uc, signers[i].uc, sizeof(fd_pubkey_t) ) ) return 1;
  return 0;
}

/*
fd_vm_prepare_instruction populates instruction_accounts and instruction_accounts_cnt
with the instruction accounts ready for execution.

The majority of this logic is taken from
https://github.com/solana-labs/solana/blob/v1.17.22/program-runtime/src/invoke_context.rs#L535,
and is not vm-specific, but a part of the runtime.
TODO: should we move this out of the CPI section?

The bulk of the logic is concerned with unifying the privileges for each duplicated account,
ensuring that each duplicate account referenced has the same privileges. It also performs some
priviledge checks, for example ensuring the necessary signatures are present.

TODO: instruction calling convention: const parameters after non-const.

Assumptions:
- We do not have more than 256 unique accounts in the callee_instr.
  This limit comes from the fact that a Solana transaction cannot
  refefence more than 256 unique accounts, due to the transaction
  serialization format.
- callee_instr is not null.
- callee_instr->acct_pubkeys is at least as long as callee_instr->acct_cnt
- instr_ctx->txn_ctx->accounts_cnt is less than UCHAR_MAX.
  This is likely because the transaction is limited to 256 accounts.
- callee_instr->program_id is set to UCHAR_MAX if account is not in instr_ctx->txn_ctx.
- instruction_accounts is a 256-length empty array.

Parameters:
- callee_instr
- instr_ctx
- instruction_accounts
- instruction_accounts_cnt
- signers
- signers_cnt

Returns:
- instruction_accounts
- instruction_accounts_cnt
Populated with the instruction accounts with normalized permissions.

TODO: is it possible to pass the transaction indexes of the accounts in?
This would allow us to make some of these algorithms more efficient.
*/
int
fd_vm_prepare_instruction( fd_instr_info_t *        callee_instr,
                           fd_exec_instr_ctx_t *    instr_ctx,
                           fd_pubkey_t const *      callee_program_id_pubkey,
                           fd_pubkey_t const        instr_acct_keys[ FD_INSTR_ACCT_MAX ],
                           fd_instruction_account_t instruction_accounts[ FD_INSTR_ACCT_MAX ],
                           ulong *                  instruction_accounts_cnt,
                           fd_pubkey_t const *      signers,
                           ulong                    signers_cnt ) {

  /* De-duplicate the instruction accounts, using the same logic as Solana */
  ulong deduplicated_instruction_accounts_cnt = 0;
  fd_instruction_account_t deduplicated_instruction_accounts[256] = {0};
  ulong duplicate_indicies_cnt = 0;
  ulong duplicate_indices[256] = {0};

  /* Normalize the privileges of each instruction account in the callee, after de-duping
     the account references.
    https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/program-runtime/src/invoke_context.rs#L540-L595 */
  for( ulong i=0UL; i<callee_instr->acct_cnt; i++ ) {
    ushort index_in_transaction = callee_instr->accounts[i].index_in_transaction;
    ushort index_in_caller      = callee_instr->accounts[i].index_in_caller;

    if( index_in_transaction==USHORT_MAX ) {
      /* In this case the callee instruction is referencing an unknown account not listed in the
         transactions accounts. */
      FD_BASE58_ENCODE_32_BYTES( instr_acct_keys[i].uc, id_b58 );
      fd_log_collector_msg_many( instr_ctx, 2, "Instruction references an unknown account ", 42UL, id_b58, id_b58_len );
      FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_MISSING_ACC, instr_ctx->txn_out->err.exec_err_idx );
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    /* If there was an instruction account before this one which referenced the same
       transaction account index, find it's index in the deduplicated_instruction_accounts
       array. */
    ulong duplicate_index = ULONG_MAX;
    for( ulong j=0UL; j<deduplicated_instruction_accounts_cnt; j++ ) {
      if( deduplicated_instruction_accounts[j].index_in_transaction==index_in_transaction ) {
        duplicate_index = j;
        break;
      }
    }

    /* If this was account referenced in a previous iteration, update the flags to include those set
       in this iteration. This ensures that after all the iterations, the de-duplicated account flags
       for each account are the union of all the flags in all the references to that account in this instruction. */

    /* TODO: FD_UNLIKELY? Need to check which branch is more common by running against a larger mainnet ledger */
    /* TODO: this code would maybe be easier to read if we inverted the branches */
    if( duplicate_index!=ULONG_MAX ) {
      if ( FD_UNLIKELY( duplicate_index >= deduplicated_instruction_accounts_cnt ) ) {
        FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_MISSING_ACC, instr_ctx->txn_out->err.exec_err_idx );
        return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
      }

      duplicate_indices[duplicate_indicies_cnt++] = duplicate_index;
      fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[duplicate_index];
      instruction_account->is_signer   = !!(instruction_account->is_signer   | callee_instr->accounts[i].is_signer);
      instruction_account->is_writable = !!(instruction_account->is_writable | callee_instr->accounts[i].is_writable);
    } else {
      /* In the case where the callee instruction is NOT a duplicate, we need to
         create the deduplicated_instruction_accounts fd_instruction_account_t object. */

      /* Add the instruction account to the duplicate indicies array */
      duplicate_indices[duplicate_indicies_cnt++] = deduplicated_instruction_accounts_cnt;

      /* Initialize the instruction account in the deduplicated_instruction_accounts array */
      fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[deduplicated_instruction_accounts_cnt++];
      *instruction_account = fd_instruction_account_init( index_in_transaction,
                                                          index_in_caller,
                                                          (ushort)i,
                                                          !!(callee_instr->accounts[i].is_writable),
                                                          !!(callee_instr->accounts[i].is_signer) );
    }
  }

  /* Check the normalized account permissions for privilege escalation.
     https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/program-runtime/src/invoke_context.rs#L596-L624 */
  for( ulong i = 0; i < deduplicated_instruction_accounts_cnt; i++ ) {
    fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[i];

    /* https://github.com/anza-xyz/agave/blob/v2.1.14/program-runtime/src/invoke_context.rs#L390-L393 */
    fd_guarded_borrowed_account_t borrowed_caller_acct = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( instr_ctx, instruction_account->index_in_caller, &borrowed_caller_acct );

    /* Check that the account is not read-only in the caller but writable in the callee */
    if( FD_UNLIKELY( instruction_account->is_writable && !fd_borrowed_account_is_writable( &borrowed_caller_acct ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( borrowed_caller_acct.acct->pubkey->uc, id_b58 );
      fd_log_collector_msg_many( instr_ctx, 2, id_b58, id_b58_len, "'s writable privilege escalated", 31UL );
      FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION, instr_ctx->txn_out->err.exec_err_idx );
      return FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION;
    }

    /* If the account is signed in the callee, it must be signed by the caller or the program */
    if ( FD_UNLIKELY( instruction_account->is_signer && !( fd_borrowed_account_is_signer( &borrowed_caller_acct ) || fd_vm_syscall_cpi_is_signer( borrowed_caller_acct.acct->pubkey, signers, signers_cnt) ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( borrowed_caller_acct.acct->pubkey->uc, id_b58 );
      fd_log_collector_msg_many( instr_ctx, 2, id_b58, id_b58_len, "'s signer privilege escalated", 29UL );
      FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION, instr_ctx->txn_out->err.exec_err_idx );
      return FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION;
    }
  }

  /* Copy the accounts with their normalized permissions over to the final instruction_accounts array,
     and set the callee_instr acct_flags. */
  for (ulong i = 0; i < duplicate_indicies_cnt; i++) {
    ulong duplicate_index = duplicate_indices[i];

    /* Failing this condition is technically impossible, but it is probably safest to keep this in
       so that we throw InstructionError::NotEnoughAccountKeys at the same point at Solana does,
       in the event any surrounding code is changed.
       https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/program-runtime/src/invoke_context.rs#L625-L633 */
    if ( FD_LIKELY( duplicate_index < deduplicated_instruction_accounts_cnt ) ) {
      instruction_accounts[i] = deduplicated_instruction_accounts[duplicate_index];
      callee_instr->accounts[i].is_writable = !!(instruction_accounts[i].is_writable);
      callee_instr->accounts[i].is_signer   = !!(instruction_accounts[i].is_signer);
    } else {
      FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_MISSING_ACC, instr_ctx->txn_out->err.exec_err_idx );
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
  }

  /* Obtain the program account index and return a MissingAccount error if not found.
    https://github.com/anza-xyz/agave/blob/v2.1.14/program-runtime/src/invoke_context.rs#L430-L435 */
  int program_idx = fd_exec_instr_ctx_find_idx_of_instr_account( instr_ctx, callee_program_id_pubkey );
  if( FD_UNLIKELY( program_idx == -1 ) ) {
    FD_BASE58_ENCODE_32_BYTES( callee_program_id_pubkey->uc, id_b58 );
    fd_log_collector_msg_many( instr_ctx, 2, "Unknown program ", 16UL, id_b58, id_b58_len );
    FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_MISSING_ACC, instr_ctx->txn_out->err.exec_err_idx );
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  /* Caller is in charge of setting an appropriate sentinel value (i.e., UCHAR_MAX) for callee_instr->program_id if not found.
    Borrow the program account here.
    https://github.com/anza-xyz/agave/blob/v2.1.14/program-runtime/src/invoke_context.rs#L436-L437 */
  fd_guarded_borrowed_account_t borrowed_program_account = {0};
  int err = fd_exec_instr_ctx_try_borrow_instr_account( instr_ctx, (ushort)program_idx, &borrowed_program_account );
  if( FD_UNLIKELY( err ) ) {
    FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, err, instr_ctx->txn_out->err.exec_err_idx );
    return err;
  }

  if( FD_UNLIKELY( err ) ) {
    /* https://github.com/anza-xyz/agave/blob/a9ac3f55fcb2bc735db0d251eda89897a5dbaaaa/program-runtime/src/invoke_context.rs#L434 */
    FD_BASE58_ENCODE_32_BYTES( callee_program_id_pubkey->uc, id_b58 );
    fd_log_collector_msg_many( instr_ctx, 2, "Unknown program ", 16UL, id_b58, id_b58_len );
    FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_MISSING_ACC, instr_ctx->txn_out->err.exec_err_idx );
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }
  /* Check that the program account is executable. We need to ensure that the
    program account is a valid instruction account.
    https://github.com/anza-xyz/agave/blob/v2.1.14/program-runtime/src/invoke_context.rs#L438 */
  if( !FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, remove_accounts_executable_flag_checks ) ) {
    if( FD_UNLIKELY( !fd_borrowed_account_is_executable( &borrowed_program_account ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( callee_program_id_pubkey->uc, id_b58 );
      fd_log_collector_msg_many( instr_ctx, 3, "Account ", 8UL, id_b58, id_b58_len, " is not executable", 18UL );
      FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE, instr_ctx->txn_out->err.exec_err_idx );
      return FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE;
    }
  }

  *instruction_accounts_cnt = duplicate_indicies_cnt;

  return 0;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (Generic logic)
 **********************************************************************/

/* FD_CPI_MAX_SIGNER_CNT is the max amount of PDA signer addresses that
   a cross-program invocation can include in an instruction.

   https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/mod.rs#L80 */

#define FD_CPI_MAX_SIGNER_CNT              (16UL)

/* "Maximum number of account info structs that can be used in a single CPI
   invocation. A limit on account info structs is effectively the same as
   limiting the number of unique accounts. 128 was chosen to match the max
   number of locked accounts per transaction (MAX_TX_ACCOUNT_LOCKS)."

   https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/sdk/program/src/syscalls/mod.rs#L25
   https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/programs/bpf_loader/src/syscalls/cpi.rs#L1011 */

#define FD_CPI_MAX_ACCOUNT_INFOS           (128UL)
/* This is just encoding what Agave says in their code comments into a
   compile-time check, so if anyone ever inadvertently changes one of
   the limits, they will have to take a look. */
FD_STATIC_ASSERT( FD_CPI_MAX_ACCOUNT_INFOS==MAX_TX_ACCOUNT_LOCKS, cpi_max_account_info );
static inline ulong
get_cpi_max_account_infos( fd_bank_t * bank ) {
  return fd_ulong_if( FD_FEATURE_ACTIVE_BANK( bank, increase_tx_account_lock_limit ), FD_CPI_MAX_ACCOUNT_INFOS, 64UL );
}

/* Maximum CPI instruction data size. 10 KiB was chosen to ensure that CPI
   instructions are not more limited than transaction instructions if the size
   of transactions is doubled in the future.

   https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/sdk/program/src/syscalls/mod.rs#L14 */

#define FD_CPI_MAX_INSTRUCTION_DATA_LEN    (10240UL)

/* Maximum CPI instruction accounts. 255 was chosen to ensure that instruction
   accounts are always within the maximum instruction account limit for BPF
   program instructions.

   https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/sdk/program/src/syscalls/mod.rs#L19
   https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/serialization.rs#L26 */

#define FD_CPI_MAX_INSTRUCTION_ACCOUNTS    (255UL)


/* fd_vm_syscall_cpi_check_instruction contains common instruction acct
   count and data sz checks.  Also consumes compute units proportional
   to instruction data size. */

static int
fd_vm_syscall_cpi_check_instruction( fd_vm_t const * vm,
                                     ulong           acct_cnt,
                                     ulong           data_sz ) {
  /* https://github.com/anza-xyz/agave/blob/v3.1.2/program-runtime/src/cpi.rs#L146-L161 */
  if( FD_FEATURE_ACTIVE_BANK( vm->instr_ctx->bank, loosen_cpi_size_restriction ) ) {
    if( FD_UNLIKELY( acct_cnt > FD_CPI_MAX_INSTRUCTION_ACCOUNTS ) ) {
      FD_LOG_WARNING(( "cpi: too many accounts (%#lx)", acct_cnt ));
      // SyscallError::MaxInstructionAccountsExceeded
      return FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNTS_EXCEEDED;
    }
    if( FD_UNLIKELY( data_sz > FD_CPI_MAX_INSTRUCTION_DATA_LEN ) ) {
      FD_LOG_WARNING(( "cpi: data too long (%#lx)", data_sz ));
      // SyscallError::MaxInstructionDataLenExceeded
      return FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_DATA_LEN_EXCEEDED;
    }
  } else {
    // https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L1114
    ulong tot_sz = fd_ulong_sat_add( fd_ulong_sat_mul( FD_VM_RUST_ACCOUNT_META_SIZE, acct_cnt ), data_sz );
    if ( FD_UNLIKELY( tot_sz > FD_VM_MAX_CPI_INSTRUCTION_SIZE ) ) {
      FD_LOG_WARNING(( "cpi: instruction too long (%#lx)", tot_sz ));
      // SyscallError::InstructionTooLarge
      return FD_VM_SYSCALL_ERR_INSTRUCTION_TOO_LARGE;
    }
  }

  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.1/syscalls/src/cpi.rs#L1134-L1169 */
static inline int
fd_vm_cpi_update_caller_account_region( fd_vm_t *                    vm,
                                        ulong                        instr_acc_idx,
                                        fd_vm_cpi_caller_account_t * caller_account,
                                        fd_borrowed_account_t *      borrowed_account ) {
  /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1141-L1148 */
  ulong address_space_reserved_for_account;
  if( vm->stricter_abi_and_runtime_constraints && vm->is_deprecated ) {
    address_space_reserved_for_account = caller_account->orig_data_len;
  } else {
    address_space_reserved_for_account = fd_ulong_sat_add( caller_account->orig_data_len, MAX_PERMITTED_DATA_INCREASE );
  }

  /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1159-L1164 */
  if( address_space_reserved_for_account > 0UL ) {
    /* Note that we don't special-case direct mapping here, as Agave does,
       because we do not create regions using CoW upon resize like Agave does.

       Therefore we do not need the logic in the Agave code to create a new
       region, as we have already created all the regions for each account.

       Therefore we do not have equivalents of Agave's
       modify_memory_region_of_account and create_memory_region_of_account
       functions, but we instead inline this logic directly below. */
    fd_vm_acc_region_meta_t * acc_region_meta = &vm->acc_region_metas[instr_acc_idx];
    fd_vm_input_region_t *    region          = &vm->input_mem_regions[acc_region_meta->region_idx + 1UL];

    /* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L1159-L1165 */
    /* https://github.com/anza-xyz/agave/blob/v3.0.4/program-runtime/src/serialization.rs#L23-L35 */
    region->region_sz = (uint)fd_borrowed_account_get_data_len( borrowed_account );

    int err;
    int is_writable = fd_borrowed_account_can_data_be_changed( borrowed_account, &err );

    region->is_writable = (uchar)is_writable && ( err == FD_EXECUTOR_INSTR_SUCCESS );
  }

  return FD_VM_SUCCESS;
}

/**********************************************************************
  CROSS PROGRAM INVOCATION HELPERS
 **********************************************************************/

static inline int
fd_vm_syscall_cpi_check_id( fd_pubkey_t const * program_id,
          uchar const * loader ) {
  return !memcmp( program_id, loader, sizeof(fd_pubkey_t) );
}

/* fd_vm_syscall_cpi_is_precompile returns true if the given program_id
   corresponds to a precompile. It does this by checking against a hardcoded
   list of known pre-compiles.

   This mirrors the behaviour in solana_sdk::precompiles::is_precompile
   https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/sdk/src/precompiles.rs#L93
 */
static inline int
fd_vm_syscall_cpi_is_precompile( fd_pubkey_t const * program_id, fd_bank_t * bank ) {
  return fd_vm_syscall_cpi_check_id(program_id, fd_solana_keccak_secp_256k_program_id.key) |
         fd_vm_syscall_cpi_check_id(program_id, fd_solana_ed25519_sig_verify_program_id.key) |
         ( fd_vm_syscall_cpi_check_id(program_id, fd_solana_secp256r1_program_id.key) &&
           FD_FEATURE_ACTIVE_BANK( bank, enable_secp256r1_precompile ) );
}

/* fd_vm_syscall_cpi_check_authorized_program corresponds to
solana_bpf_loader_program::syscalls::cpi::check_authorized_program:
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1032

It determines if the given program_id is authorized to execute a CPI call.

FIXME: return type
 */
static inline ulong
fd_vm_syscall_cpi_check_authorized_program( fd_pubkey_t const * program_id,
                                            fd_bank_t *         bank,
                                            uchar const *       instruction_data,
                                            ulong               instruction_data_len ) {
  /* FIXME: do this in a branchless manner? using bitwise comparison would probably be faster */
  return ( fd_vm_syscall_cpi_check_id(program_id, fd_solana_native_loader_id.key) ||
           fd_vm_syscall_cpi_check_id(program_id, fd_solana_bpf_loader_program_id.key) ||
           fd_vm_syscall_cpi_check_id(program_id, fd_solana_bpf_loader_deprecated_program_id.key) ||
           ( fd_vm_syscall_cpi_check_id(program_id, fd_solana_bpf_loader_upgradeable_program_id.key) &&
             !(( instruction_data_len != 0 && instruction_data[0] == fd_bpf_upgradeable_loader_program_instruction_enum_upgrade ) ||
               ( instruction_data_len != 0 && instruction_data[0] == fd_bpf_upgradeable_loader_program_instruction_enum_set_authority ) ||
               ( FD_FEATURE_ACTIVE_BANK( bank, enable_bpf_loader_set_authority_checked_ix ) &&
                 ( instruction_data_len != 0 && instruction_data[0] == fd_bpf_upgradeable_loader_program_instruction_enum_set_authority_checked )) ||
               ( FD_FEATURE_ACTIVE_BANK( bank, enable_extend_program_checked ) &&
                 ( instruction_data_len != 0 && instruction_data[0] == fd_bpf_upgradeable_loader_program_instruction_enum_extend_program_checked )) ||
               ( instruction_data_len != 0 && instruction_data[0] == fd_bpf_upgradeable_loader_program_instruction_enum_close ))) ||
           fd_vm_syscall_cpi_is_precompile( program_id, bank ) );
}

/* The data and lamports fields are in an Rc<Refcell<T>> in the Rust ABI AccountInfo.
   These macros perform the equivalent of Rc<Refcell<T>>.as_ptr() in Agave.
   This function doesn't actually touch any memory.
   It performs pointer arithmetic.
 */
FD_FN_CONST static inline
ulong vm_syscall_cpi_acc_info_rc_refcell_as_ptr( ulong rc_refcell_vaddr ) {
  return (ulong) &(((fd_vm_rc_refcell_t *)rc_refcell_vaddr)->payload);
}

/* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L310-L316
 */
FD_FN_CONST static inline
ulong vm_syscall_cpi_data_len_vaddr_c( ulong acct_info_vaddr, ulong data_len_haddr, ulong acct_info_haddr ) {
  return fd_ulong_sat_sub( fd_ulong_sat_add( acct_info_vaddr, data_len_haddr ), acct_info_haddr );
}

/**********************************************************************
  CROSS PROGRAM INVOCATION (C ABI)
 **********************************************************************/

#define VM_SYSCALL_CPI_ABI                     c
#define VM_SYSCALL_CPI_INSTR_T                 fd_vm_c_instruction_t
#define VM_SYSCALL_CPI_INSTR_ALIGN             (FD_VM_C_INSTRUCTION_ALIGN)
#define VM_SYSCALL_CPI_INSTR_SIZE              (FD_VM_C_INSTRUCTION_SIZE)
#define VM_SYSCALL_CPI_ACC_META_T              fd_vm_c_account_meta_t
#define VM_SYSCALL_CPI_ACC_META_ALIGN          (FD_VM_C_ACCOUNT_META_ALIGN)
#define VM_SYSCALL_CPI_ACC_META_SIZE           (FD_VM_C_ACCOUNT_META_SIZE)
#define VM_SYSCALL_CPI_ACC_INFO_T              fd_vm_c_account_info_t
#define VM_SYSCALL_CPI_ACC_INFO_ALIGN          (FD_VM_C_ACCOUNT_INFO_ALIGN)
#define VM_SYSCALL_CPI_ACC_INFO_SIZE           (FD_VM_C_ACCOUNT_INFO_SIZE)

/* VM_SYSCALL_CPI_INSTR_T accessors */
#define VM_SYSCALL_CPI_INSTR_DATA_ADDR( instr ) instr->data_addr
#define VM_SYSCALL_CPI_INSTR_DATA_LEN( instr )  instr->data_len
#define VM_SYSCALL_CPI_INSTR_ACCS_ADDR( instr ) instr->accounts_addr
#define VM_SYSCALL_CPI_INSTR_ACCS_LEN( instr )  instr->accounts_len
#define VM_SYSCALL_CPI_INSTR_PROGRAM_ID( vm, instr ) \
  FD_VM_MEM_HADDR_LD( vm, instr->program_id_addr, alignof(uchar), sizeof(fd_pubkey_t)  )

/* VM_SYSCALL_CPI_ACC_META_T accessors */
#define VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( acc_meta ) acc_meta->is_writable
#define VM_SYSCALL_CPI_ACC_META_IS_SIGNER( acc_meta ) acc_meta->is_signer
#define VM_SYSCALL_CPI_ACC_META_PUBKEY( vm, acc_meta ) \
  FD_VM_MEM_HADDR_LD( vm, acc_meta->pubkey_addr, alignof(uchar), sizeof(fd_pubkey_t) )

/* VM_SYSCALL_CPI_ACC_INFO_T accessors */
#define VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_VADDR( vm, acc_info, decl ) \
  ulong decl = acc_info->lamports_addr;
#define VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, acc_info, decl ) \
  ulong * decl = FD_VM_MEM_HADDR_ST( vm, acc_info->lamports_addr, alignof(ulong), sizeof(ulong) );

/* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L304 */
#define VM_SYSCALL_CPI_ACC_INFO_DATA_VADDR( vm, acc_info, decl ) \
  ulong decl = acc_info->data_addr;
#define VM_SYSCALL_CPI_ACC_INFO_DATA( vm, acc_info, decl ) \
  uchar * decl = FD_VM_MEM_SLICE_HADDR_ST( vm, acc_info->data_addr, alignof(uchar), acc_info->data_sz ); \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _vm_addr) = acc_info->data_addr; \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = acc_info->data_sz;

#define VM_SYSCALL_CPI_ACC_INFO_METADATA( vm, acc_info, decl ) \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _vm_addr) = acc_info->data_addr; \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = acc_info->data_sz;

#define VM_SYSCALL_CPI_SET_ACC_INFO_DATA_GET_LEN( vm, acc_info, decl ) \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = acc_info->data_sz;

#include "fd_vm_syscall_cpi_common.c"

#undef VM_SYSCALL_CPI_ABI
#undef VM_SYSCALL_CPI_INSTR_T
#undef VM_SYSCALL_CPI_INSTR_ALIGN
#undef VM_SYSCALL_CPI_INSTR_SIZE
#undef VM_SYSCALL_CPI_ACC_META_T
#undef VM_SYSCALL_CPI_ACC_META_ALIGN
#undef VM_SYSCALL_CPI_ACC_META_SIZE
#undef VM_SYSCALL_CPI_ACC_INFO_T
#undef VM_SYSCALL_CPI_ACC_INFO_ALIGN
#undef VM_SYSCALL_CPI_ACC_INFO_SIZE
#undef VM_SYSCALL_CPI_INSTR_DATA_ADDR
#undef VM_SYSCALL_CPI_INSTR_DATA_LEN
#undef VM_SYSCALL_CPI_INSTR_ACCS_ADDR
#undef VM_SYSCALL_CPI_INSTR_ACCS_LEN
#undef VM_SYSCALL_CPI_INSTR_PROGRAM_ID
#undef VM_SYSCALL_CPI_ACC_META_IS_WRITABLE
#undef VM_SYSCALL_CPI_ACC_META_IS_SIGNER
#undef VM_SYSCALL_CPI_ACC_META_PUBKEY
#undef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_VADDR
#undef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS
#undef VM_SYSCALL_CPI_ACC_INFO_DATA_VADDR
#undef VM_SYSCALL_CPI_ACC_INFO_DATA
#undef VM_SYSCALL_CPI_ACC_INFO_METADATA
#undef VM_SYSCALL_CPI_SET_ACC_INFO_DATA_GET_LEN

/**********************************************************************
   CROSS PROGRAM INVOCATION (Rust ABI)
 **********************************************************************/

#define VM_SYSCALL_CPI_ABI                     rust
#define VM_SYSCALL_CPI_INSTR_T                 fd_vm_rust_instruction_t
#define VM_SYSCALL_CPI_INSTR_ALIGN             (FD_VM_RUST_INSTRUCTION_ALIGN)
#define VM_SYSCALL_CPI_INSTR_SIZE              (FD_VM_RUST_INSTRUCTION_SIZE)
#define VM_SYSCALL_CPI_ACC_META_T              fd_vm_rust_account_meta_t
#define VM_SYSCALL_CPI_ACC_META_ALIGN          (FD_VM_RUST_ACCOUNT_META_ALIGN)
#define VM_SYSCALL_CPI_ACC_META_SIZE           (FD_VM_RUST_ACCOUNT_META_SIZE)
#define VM_SYSCALL_CPI_ACC_INFO_T              fd_vm_rust_account_info_t
#define VM_SYSCALL_CPI_ACC_INFO_ALIGN          (FD_VM_RUST_ACCOUNT_INFO_ALIGN)
#define VM_SYSCALL_CPI_ACC_INFO_SIZE           (FD_VM_RUST_ACCOUNT_INFO_SIZE)

/* VM_SYSCALL_CPI_INSTR_T accessors */
#define VM_SYSCALL_CPI_INSTR_DATA_ADDR( instr ) instr->data.addr
#define VM_SYSCALL_CPI_INSTR_DATA_LEN( instr )  instr->data.len
#define VM_SYSCALL_CPI_INSTR_ACCS_ADDR( instr ) instr->accounts.addr
#define VM_SYSCALL_CPI_INSTR_ACCS_LEN( instr )  instr->accounts.len
#define VM_SYSCALL_CPI_INSTR_PROGRAM_ID( vm, instr ) instr->pubkey

/* VM_SYSCALL_CPI_ACC_META_T accessors */
#define VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( acc_meta ) acc_meta->is_writable
#define VM_SYSCALL_CPI_ACC_META_IS_SIGNER( acc_meta ) acc_meta->is_signer
#define VM_SYSCALL_CPI_ACC_META_PUBKEY( vm, acc_meta ) acc_meta->pubkey

/* VM_SYSCALL_CPI_ACC_INFO_T accessors */

/* The lamports and the account data are stored behind RefCells,
   so we have an additional layer of indirection to unwrap. */
#define VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_VADDR( vm, acc_info, decl )                                                                             \
    ulong const * FD_EXPAND_THEN_CONCAT2(decl, _hptr_) =                                                                                         \
      FD_VM_MEM_HADDR_LD( vm, vm_syscall_cpi_acc_info_rc_refcell_as_ptr( acc_info->lamports_box_addr ), FD_VM_RC_REFCELL_ALIGN, sizeof(ulong) ); \
    /* Extract the vaddr embedded in the RefCell */                                                                                              \
    ulong decl = *FD_EXPAND_THEN_CONCAT2(decl, _hptr_);

/* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L184-L195 */
#define VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, acc_info, decl )                                                                                                     \
    ulong FD_EXPAND_THEN_CONCAT2(decl, _vaddr_) =                                                                                                                  \
      *((ulong const *)FD_VM_MEM_HADDR_LD( vm, vm_syscall_cpi_acc_info_rc_refcell_as_ptr( acc_info->lamports_box_addr ), FD_VM_RC_REFCELL_ALIGN, sizeof(ulong) )); \
    ulong * decl = FD_VM_MEM_HADDR_ST( vm, FD_EXPAND_THEN_CONCAT2(decl, _vaddr_), alignof(ulong), sizeof(ulong) );

/* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L184-L195 */
#define VM_SYSCALL_CPI_ACC_INFO_DATA_VADDR( vm, acc_info, decl )                                                                                   \
    if( FD_UNLIKELY( vm->stricter_abi_and_runtime_constraints && acc_info->data_box_addr >= FD_VM_MEM_MAP_INPUT_REGION_START ) ) {                 \
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );                                                                          \
      return FD_VM_SYSCALL_ERR_INVALID_POINTER;                                                                                                    \
    }                                                                                                                                              \
    /* Translate the vaddr to the slice */                                                                                                         \
    fd_vm_vec_t const * FD_EXPAND_THEN_CONCAT2(decl, _hptr_) =                                                                                     \
      FD_VM_MEM_HADDR_LD( vm, vm_syscall_cpi_acc_info_rc_refcell_as_ptr( acc_info->data_box_addr ), FD_VM_RC_REFCELL_ALIGN, sizeof(fd_vm_vec_t) ); \
    /* Extract the vaddr embedded in the slice */                                                                                                  \
    ulong decl = FD_EXPAND_THEN_CONCAT2(decl, _hptr_)->addr;

/* https://github.com/anza-xyz/agave/blob/v3.0.4/syscalls/src/cpi.rs#L212-L221 */
#define VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR( vm, acc_info, decl ) \
    ulong decl = fd_ulong_sat_add( vm_syscall_cpi_acc_info_rc_refcell_as_ptr( acc_info->data_box_addr ), sizeof(ulong) );

#define VM_SYSCALL_CPI_ACC_INFO_DATA( vm, acc_info, decl )                                                                                         \
    /* Translate the vaddr to the slice */                                                                                                         \
    fd_vm_vec_t const * FD_EXPAND_THEN_CONCAT2(decl, _hptr_) =                                                                                     \
      FD_VM_MEM_HADDR_LD( vm, vm_syscall_cpi_acc_info_rc_refcell_as_ptr( acc_info->data_box_addr ), FD_VM_RC_REFCELL_ALIGN, sizeof(fd_vm_vec_t) ); \
    /* Declare the vaddr of the slice's underlying byte array */                                                                                   \
    ulong FD_EXPAND_THEN_CONCAT2(decl, _vm_addr) = FD_EXPAND_THEN_CONCAT2(decl, _hptr_)->addr;                                                     \
    /* Declare the size of the slice's underlying byte array */                                                                                    \
    ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = FD_EXPAND_THEN_CONCAT2(decl, _hptr_)->len;                                                          \
    /* Translate the vaddr to the underlying byte array */                                                                                         \
    uchar * decl = FD_VM_MEM_SLICE_HADDR_ST(                                                                                                       \
      vm, FD_EXPAND_THEN_CONCAT2(decl, _hptr_)->addr, alignof(uchar), FD_EXPAND_THEN_CONCAT2(decl, _hptr_)->len );

#define VM_SYSCALL_CPI_ACC_INFO_METADATA( vm, acc_info, decl )                                                                                     \
    /* Translate the vaddr to the slice */                                                                                                         \
    fd_vm_vec_t const * FD_EXPAND_THEN_CONCAT2(decl, _hptr_) =                                                                                     \
      FD_VM_MEM_HADDR_LD( vm, vm_syscall_cpi_acc_info_rc_refcell_as_ptr( acc_info->data_box_addr ), FD_VM_RC_REFCELL_ALIGN, sizeof(fd_vm_vec_t) ); \
    /* Declare the vaddr of the slice's underlying byte array */                                                                                   \
    ulong FD_EXPAND_THEN_CONCAT2(decl, _vm_addr) = FD_EXPAND_THEN_CONCAT2(decl, _hptr_)->addr;                                                     \
    /* Declare the size of the slice's underlying byte array */                                                                                    \
    ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = FD_EXPAND_THEN_CONCAT2(decl, _hptr_)->len;

#define VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_RC_REFCELL_VADDR( vm, acc_info, decl ) \
    ulong decl = vm_syscall_cpi_acc_info_rc_refcell_as_ptr( acc_info->lamports_box_addr );

#define VM_SYSCALL_CPI_ACC_INFO_DATA_RC_REFCELL_VADDR( vm, acc_info, decl ) \
    ulong decl = vm_syscall_cpi_acc_info_rc_refcell_as_ptr( acc_info->data_box_addr );

#define VM_SYSCALL_CPI_SET_ACC_INFO_DATA_GET_LEN( vm, acc_info, decl ) \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = FD_EXPAND_THEN_CONCAT2(decl, _hptr_)->len;

#include "fd_vm_syscall_cpi_common.c"

#undef VM_SYSCALL_CPI_ABI
#undef VM_SYSCALL_CPI_INSTR_T
#undef VM_SYSCALL_CPI_INSTR_ALIGN
#undef VM_SYSCALL_CPI_INSTR_SIZE
#undef VM_SYSCALL_CPI_ACC_META_T
#undef VM_SYSCALL_CPI_ACC_META_ALIGN
#undef VM_SYSCALL_CPI_ACC_META_SIZE
#undef VM_SYSCALL_CPI_ACC_INFO_T
#undef VM_SYSCALL_CPI_ACC_INFO_ALIGN
#undef VM_SYSCALL_CPI_ACC_INFO_SIZE
#undef VM_SYSCALL_CPI_INSTR_DATA_ADDR
#undef VM_SYSCALL_CPI_INSTR_DATA_LEN
#undef VM_SYSCALL_CPI_INSTR_ACCS_ADDR
#undef VM_SYSCALL_CPI_INSTR_ACCS_LEN
#undef VM_SYSCALL_CPI_INSTR_PROGRAM_ID
#undef VM_SYSCALL_CPI_ACC_META_IS_WRITABLE
#undef VM_SYSCALL_CPI_ACC_META_IS_SIGNER
#undef VM_SYSCALL_CPI_ACC_META_PUBKEY
#undef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_VADDR
#undef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS
#undef VM_SYSCALL_CPI_ACC_INFO_DATA_VADDR
#undef VM_SYSCALL_CPI_ACC_INFO_DATA
#undef VM_SYSCALL_CPI_ACC_INFO_DATA_LEN_VADDR
#undef VM_SYSCALL_CPI_ACC_INFO_METADATA
#undef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS_RC_REFCELL_VADDR
#undef VM_SYSCALL_CPI_ACC_INFO_DATA_RC_REFCELL_VADDR
#undef VM_SYSCALL_CPI_SET_ACC_INFO_DATA_GET_LEN
