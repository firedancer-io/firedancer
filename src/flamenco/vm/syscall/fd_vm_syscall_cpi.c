#include "fd_vm_syscall.h"

#include "../../../ballet/ed25519/fd_curve25519.h"
#include "../../runtime/fd_account.h"

/* Representation of a caller account, used to update callee accounts. */

struct fd_caller_account {
  ulong       lamports;
  fd_pubkey_t owner;
  uchar *     serialized_data;
  ulong       serialized_data_len;
  uchar       executable;
  ulong       rent_epoch;
};

typedef struct fd_caller_account fd_caller_account_t;

/* FIXME: PREFIX NAME / ALGO EFFICIENCY */
static inline int
is_signer( fd_pubkey_t const * account,
           fd_pubkey_t const * signers,
           ulong               signers_cnt ) {
  for( ulong i=0UL; i<signers_cnt; i++ ) if( !memcmp( account->uc, signers[i].uc, sizeof(fd_pubkey_t) ) ) return 1;
  return 0;
}

/*
fd_vm_prepare_instruction populates instruction_accounts and instruction_accounts_cnt,
laying out in memory each instruction account needed for a CPI call, and their privileges.

As part of this, it unifies the privileges for each duplicated account, ensuring that 
each duplicate account referenced has the same privileges.

The majority of this logic is taken from
https://github.com/solana-labs/solana/blob/v1.17.22/program-runtime/src/invoke_context.rs#L535

TODO: instruction calling convention: const parameters after non-const.

Assumptions:
- We do not have more than 256 unique accounts in the callee_instr.
  This limit comes from the fact that a Solana transaction cannot 
  refefence more than 256 unique accounts, due to the transaction
  serialization format.
- callee_instr is not null.
- callee_instr->acct_pubkeys is at least as long as callee_instr->acct_cnt
- instr_ctx->txn_ctx->accounts_cnt is less than USHORT_MAX.
  This is likely because the transaction is limited to 256 accounts.
- instruction_accounts is a 256-length empty array.

Parameters:
- caller_instr
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
fd_vm_prepare_instruction( fd_instr_info_t const *  caller_instr,
                           fd_instr_info_t *        callee_instr,
                           fd_exec_instr_ctx_t *    instr_ctx,
                           fd_instruction_account_t instruction_accounts[256],
                           ulong *                  instruction_accounts_cnt,
                           fd_pubkey_t const *      signers,
                           ulong                    signers_cnt ) {

  /* De-duplicate the instruction accounts, using the same logic as Solana */
  ulong deduplicated_instruction_accounts_cnt = 0;
  fd_instruction_account_t deduplicated_instruction_accounts[256] = {0};
  ulong duplicate_indicies_cnt = 0;
  ulong duplicate_indices[256] = {0};

  // Normalize the privileges of each instruction account in the callee, after de-duping 
  // the account references.
  // https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/program-runtime/src/invoke_context.rs#L540-L595
  for( ulong i=0UL; i<callee_instr->acct_cnt; i++ ) {
    fd_pubkey_t const * callee_pubkey = &callee_instr->acct_pubkeys[i];

    // Find the corresponding transaction account index for this callee instruction account
    // TODO: passing in the transaction indicies would mean we didn't have to do this
    ushort index_in_transaction = USHORT_MAX;
    for( ulong j=0UL; j<instr_ctx->txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( instr_ctx->txn_ctx->accounts[j].uc, callee_pubkey->uc, sizeof(fd_pubkey_t) ) ) {
        index_in_transaction = (ushort)j;
        break;
      }
    }
    if( index_in_transaction==USHORT_MAX) {
      // In this case the callee instruction is referencing an unknown account not listed in the 
      // transactions accounts.
      // TODO: return InstructionError::MissingAccount
      return 1;
    }

    // If there was an instruction account before this one which referenced the same
    // transaction account index, find it's index in the deduplicated_instruction_accounts
    // array.
    ulong duplicate_index = ULONG_MAX;
    for( ulong j=0UL; j<deduplicated_instruction_accounts_cnt; j++ ) {
      if( deduplicated_instruction_accounts[j].index_in_transaction==index_in_transaction ) {
        duplicate_index = j;
        break;
      }
    }

    // If this was account referenced in a previous iteration, update the flags to include those set
    // in this iteration. This ensures that after all the iterations, the de-duplicated account flags 
    // for each account are the union of all the flags in all the references to that account in this instruction.
    // 
    // TODO: FD_UNLIKELY? Need to check which branch is more common by running against a mainnet ledger
    // TODO: this code would maybe be easier to read if we inverted the branches
    if( duplicate_index!=ULONG_MAX ) {
      if ( FD_UNLIKELY( duplicate_index >= deduplicated_instruction_accounts_cnt ) ) {
        // TODO: return InstructionError::NotEnoughAccountKeys
        return 1;
      }

      duplicate_indices[duplicate_indicies_cnt++] = duplicate_index;
      fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[duplicate_index];
      instruction_account->is_signer   |= !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
      instruction_account->is_writable |= !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
    } else {
      // In the case where the callee instruction is NOT a duplicate, we need to 
      // create the deduplicated_instruction_accounts fd_instruction_account_t object.

      // Find the index of the instruction account in the caller instruction
      ushort index_in_caller = USHORT_MAX;
      for( ulong j=0UL; j<caller_instr->acct_cnt; j++ ) {
        // TODO: passing transaction indicies in would also allow us to remove these memcmp's
        if( !memcmp( caller_instr->acct_pubkeys[j].uc, callee_instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) ) ) {
          index_in_caller = (ushort)j;
          break;
        }
      }

      if( index_in_caller==USHORT_MAX ) {
        // TODO: return InstructionError::MissingAccount
        return 1;
      }

      // Add the instruction account to the duplicate indicies array
      duplicate_indices[duplicate_indicies_cnt++] = deduplicated_instruction_accounts_cnt;

      // Initialize the instruction account in the deduplicated_instruction_accounts array
      fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[deduplicated_instruction_accounts_cnt++];
      instruction_account->index_in_callee      = (ushort)i;
      instruction_account->index_in_caller      = index_in_caller;
      instruction_account->index_in_transaction = index_in_transaction;
      instruction_account->is_signer            = !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
      instruction_account->is_writable          = !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
    }
  }

  // Check the normalized account permissions for privilege escalation.
  // https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/program-runtime/src/invoke_context.rs#L596-L624
  for( ulong i = 0; i < deduplicated_instruction_accounts_cnt; i++ ) {
    fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[i];
    fd_pubkey_t const * pubkey = &caller_instr->acct_pubkeys[instruction_account->index_in_caller];

    // Check that the account is not read-only in the caller but writable in the callee
    if ( FD_UNLIKELY( instruction_account->is_writable && !fd_instr_acc_is_writable(instr_ctx->instr, pubkey) ) ) {
      // TODO: return InstructionError::PrivilegeEscalation
      return 1;
    }

    // If the account is signed in the callee, it must be signed by the caller or the program
    if ( FD_UNLIKELY( instruction_account->is_signer && !(fd_instr_acc_is_signer(instr_ctx->instr, pubkey) || is_signer(pubkey, signers, signers_cnt)) ) ) {
      // TODO: return InstructionError::PrivilegeEscalation
      return 1;
    }
  }

  // Copy the accounts with their normalised permissions over to the final instruction_accounts array,
  // and set the callee_instr acct_flags.
  for (ulong i = 0; i < duplicate_indicies_cnt; i++) {
    ulong duplicate_index = duplicate_indices[i];

    // Failing this condition is technically impossible, but it is probably safest to keep this in 
    // so that we throw InstructionError::NotEnoughAccountKeys at the same point at Solana does,
    // in the event any surrounding code is changed.
    // https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/program-runtime/src/invoke_context.rs#L625-L633.
    if ( FD_LIKELY( duplicate_index < deduplicated_instruction_accounts_cnt ) ) {
      instruction_accounts[i] = deduplicated_instruction_accounts[duplicate_index];
      callee_instr->acct_flags[i] |= ( !!(instruction_accounts[i].is_signer) * FD_INSTR_ACCT_FLAGS_IS_SIGNER );
      callee_instr->acct_flags[i] |= ( !!(instruction_accounts[i].is_writable) * FD_INSTR_ACCT_FLAGS_IS_WRITABLE );
    } else {
      // TODO: return InstructionError::NotEnoughAccountKeys
      return 1;
    }
  }

  // Check that the program account is executable
  // https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/program-runtime/src/invoke_context.rs#L635-L648
  fd_borrowed_account_t * program_rec = NULL;
  int err = fd_txn_borrowed_account_view( instr_ctx->txn_ctx, &instr_ctx->instr->program_id_pubkey, &program_rec );

  if( FD_UNLIKELY( err ) ) {
    return 1;
  }

  fd_account_meta_t const * program_meta = program_rec->const_meta;

  if( FD_UNLIKELY( !fd_account_is_executable( program_meta ) ) ) {
    // TODO: log "Account {} is not executable"
    // TODO: return InstructionError::AccountNotExecutable
    return 1;
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

/* Maximum number of account info structs that can be used in a single CPI
   invocation. A limit on account info structs is effectively the same as
   limiting the number of unique accounts. 128 was chosen to match the max
   number of locked accounts per transaction (MAX_TX_ACCOUNT_LOCKS).
   
   https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/sdk/program/src/syscalls/mod.rs#L25 */

#define FD_CPI_MAX_ACCOUNT_INFOS           ( fd_ulong_if( FD_FEATURE_ACTIVE(slot_ctx, increase_tx_account_lock_limit), 128UL, 64UL ) )

/* Maximum CPI instruction data size. 10 KiB was chosen to ensure that CPI
   instructions are not more limited than transaction instructions if the size
   of transactions is doubled in the future.
   
   https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/sdk/program/src/syscalls/mod.rs#L14 */

#define FD_CPI_MAX_INSTRUCTION_DATA_LEN    (10240UL)

/* Maximum CPI instruction accounts. 255 was chosen to ensure that instruction
   accounts are always within the maximum instruction account limit for BPF
   program instructions.
   
   https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/serialization.rs#L26 */

#define FD_CPI_MAX_INSTRUCTION_ACCOUNTS    (255UL)

/* fd_vm_syscall_cpi_preflight_check contains common argument checks
   for cross-program invocations.

   Solana Labs does these checks after address translation.
   We do them before to avoid length overflow.  Reordering checks can
   change the error code, but this is fine as consensus only cares about
   whether an error occurred at all or not. */

static int
fd_vm_syscall_cpi_preflight_check( ulong signers_seeds_cnt,
                                   ulong acct_info_cnt,
                                   fd_exec_slot_ctx_t const * slot_ctx ) {

  // https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L602
  if( FD_UNLIKELY( signers_seeds_cnt > FD_CPI_MAX_SIGNER_CNT ) ) {
    // TODO: return SyscallError::TooManySigners
    FD_LOG_WARNING(("TODO: return too many signers" ));
    return FD_VM_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/eb35a5ac1e7b6abe81947e22417f34508f89f091/programs/bpf_loader/src/syscalls/cpi.rs#L996-L997 */
  if( FD_FEATURE_ACTIVE( slot_ctx, loosen_cpi_size_restriction ) ) {
    if( FD_UNLIKELY( acct_info_cnt > FD_CPI_MAX_ACCOUNT_INFOS  ) ) {
      // TODO: return SyscallError::MaxInstructionAccountInfosExceeded
      FD_LOG_WARNING(( "TODO: return max instruction account infos exceeded" ));
      return FD_VM_ERR_INVAL;
    }
  } else {
    ulong adjusted_len = fd_ulong_sat_mul( acct_info_cnt, sizeof( fd_pubkey_t ) );
    if ( FD_UNLIKELY( adjusted_len > FD_VM_MAX_CPI_INSTRUCTION_SIZE ) ) {
      // Cap the number of account_infos a caller can pass to approximate
      // maximum that accounts that could be passed in an instruction
      // TODO: return SyscallError::TooManyAccounts
      return FD_VM_ERR_INVAL;
    }
  }

  return FD_VM_SUCCESS;
}

/* fd_vm_syscall_cpi_check_instruction contains common instruction acct
   count and data sz checks.  Also consumes compute units proportional
   to instruction data size. */

static int
fd_vm_syscall_cpi_check_instruction( fd_vm_t const * vm,
                                     ulong                        acct_cnt,
                                     ulong                        data_sz ) {
  /* https://github.com/solana-labs/solana/blob/eb35a5ac1e7b6abe81947e22417f34508f89f091/programs/bpf_loader/src/syscalls/cpi.rs#L958-L959 */
  if( FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, loosen_cpi_size_restriction ) ) {
    if( FD_UNLIKELY( data_sz > FD_CPI_MAX_INSTRUCTION_DATA_LEN ) ) {
      FD_LOG_WARNING(( "cpi: data too long (%#lx)", data_sz ));
      // SyscallError::MaxInstructionDataLenExceeded
      return FD_VM_ERR_INVAL;
    }
    if( FD_UNLIKELY( acct_cnt > FD_CPI_MAX_INSTRUCTION_ACCOUNTS ) ) {
      FD_LOG_WARNING(( "cpi: too many accounts (%#lx)", acct_cnt ));
      // SyscallError::MaxInstructionAccountsExceeded
      return FD_VM_ERR_INVAL;
    }
  } else {
    // https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L1114
    ulong tot_sz = fd_ulong_sat_add( fd_ulong_sat_mul( FD_VM_C_ACCOUNT_META_SIZE, acct_cnt ), data_sz );
    if ( FD_UNLIKELY( tot_sz > FD_VM_MAX_CPI_INSTRUCTION_SIZE ) ) {
      FD_LOG_WARNING(( "cpi: instruction too long (%#lx)", tot_sz ));
      // SyscallError::InstructionTooLarge
      return FD_VM_ERR_INVAL;
    }
  }

  return FD_VM_SUCCESS;
}

/* fd_vm_syscall_pdas_t is buffer holding program derived accounts. */

struct fd_vm_syscall_pdas_t {
  ulong         idx;  /* <=FD_CPI_MAX_SIGNER_CNT */
  fd_pubkey_t * keys; /* cnt==FD_CPI_MAX_SIGNER_CNT */
  fd_sha256_t   sha[1];
};

typedef struct fd_vm_syscall_pdas_t fd_vm_syscall_pdas_t;

/* fd_vm_syscall_pdas_{new,join,leave,delete} follows the Firedancer
   object lifecycle pattern. */

static inline void *
fd_vm_syscall_pdas_new( void *        mem,
                        fd_pubkey_t * keys ) {
  fd_vm_syscall_pdas_t * pdas = (fd_vm_syscall_pdas_t *)mem;
  *pdas = (fd_vm_syscall_pdas_t) { .idx  = 0UL, .keys = keys };
  fd_sha256_new( &pdas->sha );
  return mem;
}

static inline fd_vm_syscall_pdas_t * fd_vm_syscall_pdas_join( void * mem ) { return (fd_vm_syscall_pdas_t *)mem; }
static inline void * fd_vm_syscall_pdas_leave( fd_vm_syscall_pdas_t * pdas ) { return (void *)pdas; }
static inline void * fd_vm_syscall_pdas_delete( fd_vm_syscall_pdas_t * pdas ) { return (void *)pdas; }

/* fd_vm_syscall_pda_next starts the calculation of a program derived
   address.  Panics if called more than FD_CPI_MAX_SIGNER_CNT times. */

static void
fd_vm_syscall_pda_next( fd_vm_syscall_pdas_t *       pdas ) {
  fd_sha256_t * sha = fd_sha256_join( pdas->sha );
  fd_sha256_init  ( sha );
  fd_sha256_leave ( sha );
}

/* fd_vm_syscall_pda_seed_append adds a seed to the hash state that will
   eventually produce the program derived address. */

static void
fd_vm_syscall_pda_seed_append( fd_vm_syscall_pdas_t * pdas,
                               uchar const *          piece,
                               ulong                  piece_sz ) {
  fd_sha256_leave( fd_sha256_append( fd_sha256_join( pdas->sha ), piece, piece_sz ) );
}

/* fd_vm_syscall_pda_fini finalizes the current PDA calculation.
   Returns pointer to resulting pubkey on success.  Pointer is valid for
   duration of join.  On failure, returns NULL.  Reasons for failure
   include address is not a valid PDA. */

static fd_pubkey_t const *
fd_vm_syscall_pda_fini( fd_vm_t const * vm,
                        fd_vm_syscall_pdas_t * pdas ) {
  fd_pubkey_t * pda = &pdas->keys[ pdas->idx ];

  fd_pubkey_t * txn_accs = vm->instr_ctx->txn_ctx->accounts;

  fd_sha256_t * sha = fd_sha256_join( pdas->sha );
  fd_sha256_append( sha, &txn_accs[ vm->instr_ctx->instr->program_id ], sizeof(fd_pubkey_t) );
  /* TODO use char const[] symbol for PDA marker */
  fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
  fd_sha256_fini  ( sha, pda->uc );
  fd_sha256_leave ( sha );

  /* A PDA is valid if is not an Ed25519 curve point */
  if( FD_UNLIKELY( fd_ed25519_point_validate( pda->key ) ) ) return NULL;

  pdas->idx++;
  return (fd_pubkey_t const *)pda;
}

/* fd_vm_syscall_cpi_derive_signers loads a vector of PDA derive
   paths provided by the user.  Part of fd_vm_syscall_cpi_{c,rust}.
   This code was implemented twice in Solana Labs (for C and Rust ABIs
   respectively), but the logic is identical. The memory layout of the 
   paramaters is identical in either case, so we don't need to templatize 
   this function.
   
   This function corresponds to solana_bpf_loader_program::syscalls::cpi::SyscallInvokeSigned{C/Rust}::translate_signers
   https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L749
*/

static int
fd_vm_syscall_cpi_derive_signers_( fd_vm_t * vm,
                                   fd_vm_syscall_pdas_t * pdas,
                                   ulong                  signers_seeds_va,
                                   ulong                  signers_seeds_cnt ) {

  // FIXME: behaviour if seeds is 0? or seeds contains an empty array?
  // Rust just returns an empty valid array in host space in this case, we should probably
  // do the same.

  /* Translate array of seeds.  Each seed is an array of byte arrays. */
  fd_vm_vec_t const * seeds =
    fd_vm_translate_vm_to_host_const( vm, signers_seeds_va, signers_seeds_cnt*FD_VM_VEC_SIZE, FD_VM_VEC_ALIGN );
  if( FD_UNLIKELY( !seeds ) ) return FD_VM_ERR_PERM;

  /* Create program addresses. */
  if ( FD_UNLIKELY( signers_seeds_cnt > FD_CPI_MAX_SIGNER_CNT ) ) return FD_VM_ERR_INVAL;

  for( ulong i=0UL; i<signers_seeds_cnt; i++ ) {

    /* Check seed count (avoid overflow) */
    if( FD_UNLIKELY( seeds[i].len > FD_VM_CPI_SEED_MAX ) ) return FD_VM_ERR_INVAL;

    /* Translate inner seed slice.  Each element points to a byte array. */
    // FIXME: if seed is NULL (the array contains an empty array), this is a valid mapping
    // but fd_vm_translate_vm_to_host_const does not handle this case correctly.
    fd_vm_vec_t const * seed =
      fd_vm_translate_vm_to_host_const( vm, seeds[i].addr, seeds[i].len * FD_VM_VEC_SIZE, FD_VM_VEC_ALIGN );
    if( FD_UNLIKELY( !seed ) ) return FD_VM_ERR_PERM;

    /* Derive PDA */
    fd_vm_syscall_pda_next( pdas );

    if( FD_UNLIKELY( !seed ) ) {
      if( FD_UNLIKELY( !fd_vm_syscall_pda_fini( vm, pdas ) ) ) {
        return FD_VM_ERR_INVAL;
      }
      return FD_VM_SUCCESS;
    }

    /* Check seed count (avoid overflow) */
    if( FD_UNLIKELY( seeds[i].len > 32UL ) ) {
      return FD_VM_ERR_INVAL;
    }

    /* Derive PDA */

    for( ulong j=0UL; j < seeds[i].len; j++ ) {
      /* Check seed limb length */
      /* TODO use constant */
      if( FD_UNLIKELY( seed[j].len > 32 ) ) return FD_VM_ERR_INVAL;

      /* Translate inner seed limb (type &[u8]) */
      uchar const * seed_limb = fd_vm_translate_vm_to_host_const( vm, seed[j].addr, seed[j].len, alignof(uchar) );
      // FIXME: check if translation failed
      fd_vm_syscall_pda_seed_append( pdas, seed_limb, seed[j].len );
    }

    if( FD_UNLIKELY( !fd_vm_syscall_pda_fini( vm, pdas ) ) ) {
      FD_LOG_WARNING(("fini failed"));
      return FD_VM_ERR_INVAL;
    }

  }

  return FD_VM_SUCCESS;
}

static int
fd_vm_syscall_cpi_derive_signers( fd_vm_t * vm,
                                  fd_pubkey_t *          out,
                                  ulong                  signers_seeds_va,
                                  ulong                  signers_seeds_cnt ) {
  fd_vm_syscall_pdas_t _pdas[1];
  fd_vm_syscall_pdas_t * pdas = fd_vm_syscall_pdas_join( fd_vm_syscall_pdas_new( _pdas, out ) );

  if( signers_seeds_cnt>0UL ) {
    int err = fd_vm_syscall_cpi_derive_signers_( vm, pdas, signers_seeds_va, signers_seeds_cnt );
    if( FD_UNLIKELY( err ) ) return err;
  }

  fd_vm_syscall_pdas_delete( fd_vm_syscall_pdas_leave( pdas ) );
  return FD_VM_SUCCESS;
}

/**********************************************************************
  CROSS PROGRAM INVOCATION HELPERS
 **********************************************************************/

/* https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L1319 */
static ulong
fd_vm_cpi_update_callee_account( fd_vm_t * vm,
                                 fd_caller_account_t const * caller_account,
                                 fd_pubkey_t const * callee_acc_pubkey,
                                 ulong callee_acc_idx ) {

  fd_borrowed_account_t * callee_acc = NULL;
  int err = fd_instr_borrowed_account_modify(vm->instr_ctx, callee_acc_pubkey, 0, &callee_acc);

  if( FD_UNLIKELY( err ) ) {
    // TODO: do we need to do something anyways?
    return 0;
  }

  if( FD_UNLIKELY( !callee_acc->meta ) ) {
    return 0;
  }

  fd_account_meta_t * callee_acc_metadata = (fd_account_meta_t *)callee_acc->meta;
  uint is_disable_cpi_setting_executable_and_rent_epoch_active = FD_FEATURE_ACTIVE(vm->instr_ctx->slot_ctx, disable_cpi_setting_executable_and_rent_epoch);
  if( callee_acc_metadata->info.lamports!=caller_account->lamports ) callee_acc_metadata->info.lamports = caller_account->lamports;

  int err1;
  int err2;
  if( fd_account_can_data_be_resized( vm->instr_ctx->instr, callee_acc_metadata, caller_account->serialized_data_len, &err1 ) &&
      fd_account_can_data_be_changed( vm->instr_ctx->instr, callee_acc_idx, &err2 ) ) {
  //if ( FD_UNLIKELY( err1 || err2 ) ) return 1;
    err1 = fd_instr_borrowed_account_modify(vm->instr_ctx, callee_acc_pubkey, caller_account->serialized_data_len, &callee_acc);
    if( err1 ) return 1;
    callee_acc_metadata = (fd_account_meta_t *)callee_acc->meta;
    callee_acc->meta->dlen = caller_account->serialized_data_len;
    fd_memcpy( callee_acc->data, caller_account->serialized_data, caller_account->serialized_data_len );
  }

  if( !is_disable_cpi_setting_executable_and_rent_epoch_active &&
      fd_account_is_executable( callee_acc_metadata )!=caller_account->executable ) {
    fd_pubkey_t const * program_acc = &vm->instr_ctx->instr->acct_pubkeys[vm->instr_ctx->instr->program_id];
    fd_account_set_executable2(vm->instr_ctx, program_acc, callee_acc_metadata, (char)caller_account->executable);
  }

  if (memcmp(callee_acc_metadata->info.owner, caller_account->owner.uc, sizeof(fd_pubkey_t))) {
    fd_memcpy(callee_acc_metadata->info.owner, caller_account->owner.uc, sizeof(fd_pubkey_t));
  }

  if( !is_disable_cpi_setting_executable_and_rent_epoch_active         &&
      callee_acc_metadata->info.rent_epoch!=caller_account->rent_epoch ) {
    if( FD_UNLIKELY( FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, enable_early_verification_of_account_modifications ) ) ) return 1;
    else callee_acc_metadata->info.rent_epoch = caller_account->rent_epoch;
  }

  return 0;
}

/* FIXME: PREFIX */
static inline int
check_id( uchar const * program_id,
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
fd_vm_syscall_cpi_is_precompile( uchar const * program_id ) {
  return check_id(program_id, fd_solana_keccak_secp_256k_program_id.key) |
         check_id(program_id, fd_solana_ed25519_sig_verify_program_id.key);
}

/* fd_vm_syscall_cpi_check_authorized_program corresponds to 
solana_bpf_loader_program::syscalls::cpi::check_authorized_program:
https://github.com/solana-labs/solana/blob/2afde1b028ed4593da5b6c735729d8994c4bfac6/programs/bpf_loader/src/syscalls/cpi.rs#L1032

It determines if the given program_id is authorized to execute a CPI call.

FIXME: return type
 */
static inline ulong
fd_vm_syscall_cpi_check_authorized_program( uchar const *        program_id,
                          fd_exec_slot_ctx_t * slot_ctx,
                          uchar const *        instruction_data,
                          ulong                instruction_data_len ) {
  /* FIXME: do this in a branchless manner? using bitwise comparison would probably be faster */
  return check_id( program_id, fd_solana_native_loader_id.key                 )                 ||
         check_id( program_id, fd_solana_bpf_loader_program_id.key            )                 ||
         check_id( program_id, fd_solana_bpf_loader_deprecated_program_id.key )                 ||
         ( check_id( program_id, fd_solana_bpf_loader_upgradeable_program_id.key ) &&
           ( (instruction_data_len == 0 || instruction_data[0] != 3)                        ||
             (instruction_data_len != 0 && instruction_data[0] == 4)                        ||
             ( FD_FEATURE_ACTIVE( slot_ctx, enable_bpf_loader_set_authority_checked_ix ) &&
               (instruction_data_len != 0 && instruction_data[0] == 4) )                    ||
             (instruction_data_len != 0 && instruction_data[0] == 5)                        ) ) ||
         fd_vm_syscall_cpi_is_precompile(program_id);
}

/*
TODO: check_align is set wrong in the runtime, ensure that it is set correctly:
https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/program-runtime/src/invoke_context.rs#L869-L881.
- Programs owned by the bpf_loader_deprecated should set this to false.
- All other programs should set this to true.
*/


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

// Instruction accessors
#define VM_SYSCALL_CPI_INSTR_DATA_ADDR( instr ) instr->data_addr
#define VM_SYSCALL_CPI_INSTR_DATA_LEN( instr )  instr->data_len
#define VM_SYSCALL_CPI_INSTR_ACCS_ADDR( instr ) instr->accounts_addr
#define VM_SYSCALL_CPI_INSTR_ACCS_LEN( instr )  instr->accounts_len

// The C ABI requires that we translate the program ID as it stores a pointer
#define VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR( vm, instr ) \
  fd_vm_translate_vm_to_host_const( vm, instr->program_id_addr, sizeof(fd_pubkey_t), alignof(uchar) )

// Account Meta accessors
#define VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( acc_meta ) acc_meta->is_writable
#define VM_SYSCALL_CPI_ACC_META_IS_SIGNER( acc_meta ) acc_meta->is_signer

// The C ABI requires that we translate the account meta pubkey as it stores a pointer
#define VM_SYSCALL_CPI_TRANSLATE_ACC_META_PUBKEY( vm, acc_meta ) \
  fd_vm_translate_vm_to_host_const( vm, acc_meta->pubkey_addr, sizeof(fd_pubkey_t), alignof(uchar) )

#define VM_SYSCALL_CALLER_ACC_DATA( vm, acc_info, decl ) \
  uchar * decl = fd_vm_translate_vm_to_host( vm, acc_info->data_addr, acc_info->data_sz, alignof(uchar) ); \
  if( FD_UNLIKELY( !decl ) ) return FD_VM_ERR_PERM; \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = acc_info->data_sz;

// Account Info accessors
#define VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, acc_info, decl ) \
  ulong * decl = fd_vm_translate_vm_to_host( vm, acc_info->lamports_addr, sizeof(ulong), alignof(ulong) ); \
  if( FD_UNLIKELY( !decl ) ) return FD_VM_ERR_PERM;

#define VM_SYSCALL_CPI_ACC_INFO_DATA( vm, acc_info, decl ) \
  uchar * decl = fd_vm_translate_vm_to_host( vm, acc_info->data_addr, acc_info->data_sz, alignof(uchar) ); \
  if( FD_UNLIKELY( !decl ) ) return FD_VM_ERR_PERM; \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _vm_addr) = acc_info->data_addr; \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = acc_info->data_sz;

#define VM_SYSCALL_CPI_SET_ACC_INFO_DATA_LEN( vm, acc_info, decl, len ) //TODO: we don't set this for C?

#include "fd_vm_syscall_common.c"

#undef VM_SYSCALL_CPI_ABI
#undef VM_SYSCALL_CPI_INSTR_T
#undef VM_SYSCALL_CPI_INSTR_ALIGN
#undef VM_SYSCALL_CPI_INSTR_SIZE
#undef VM_SYSCALL_CPI_INSTR_DATA_ADDR
#undef VM_SYSCALL_CPI_INSTR_DATA_LEN
#undef VM_SYSCALL_CPI_INSTR_ACCS_ADDR
#undef VM_SYSCALL_CPI_INSTR_ACCS_LEN
#undef VM_SYSCALL_CPI_ACC_META_T
#undef VM_SYSCALL_CPI_ACC_META_ALIGN
#undef VM_SYSCALL_CPI_ACC_META_SIZE
#undef VM_SYSCALL_CPI_ACC_META_IS_WRITABLE
#undef VM_SYSCALL_CPI_ACC_META_IS_SIGNER
#undef VM_SYSCALL_CPI_TRANSLATE_ACC_META_PUBKEY
#undef VM_SYSCALL_CPI_ACC_INFO_T
#undef VM_SYSCALL_CPI_ACC_INFO_ALIGN
#undef VM_SYSCALL_CPI_ACC_INFO_SIZE
#undef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS
#undef VM_SYSCALL_CPI_ACC_INFO_DATA
#undef VM_SYSCALL_CPI_SET_ACC_INFO_DATA_LEN
#undef VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR

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

// Instruction accessors
#define VM_SYSCALL_CPI_INSTR_DATA_ADDR( instr ) instr->data.addr
#define VM_SYSCALL_CPI_INSTR_DATA_LEN( instr )  instr->data.len
#define VM_SYSCALL_CPI_INSTR_ACCS_ADDR( instr ) instr->accounts.addr
#define VM_SYSCALL_CPI_INSTR_ACCS_LEN( instr )  instr->accounts.len
// The Rust ABI already has the the pubkey in host space
#define VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR( vm, instr ) instr->pubkey

// Account Meta accessors
#define VM_SYSCALL_CPI_ACC_META_IS_WRITABLE( acc_meta ) acc_meta->is_writable
#define VM_SYSCALL_CPI_ACC_META_IS_SIGNER( acc_meta ) acc_meta->is_signer

// The Rust Account Meta ABI stores the pubkey inline in the data structure, so no need to translate
#define VM_SYSCALL_CPI_TRANSLATE_ACC_META_PUBKEY( vm, acc_meta ) acc_meta->pubkey

#define VM_SYSCALL_CPI_ACC_INFO_LAMPORTS( vm, acc_info, decl ) \
  fd_vm_rc_refcell_t const * FD_EXPAND_THEN_CONCAT2(decl, _box) = fd_vm_translate_vm_to_host( vm, acc_info->lamports_box_addr, sizeof(fd_vm_rc_refcell_t), FD_VM_RC_REFCELL_ALIGN ); \
  if( FD_UNLIKELY( !FD_EXPAND_THEN_CONCAT2(decl, _box) ) ) return FD_VM_ERR_PERM; \
  ulong * decl = fd_vm_translate_vm_to_host( vm, FD_EXPAND_THEN_CONCAT2(decl, _box)->addr, sizeof(ulong), alignof(ulong) ); \
  if ( FD_UNLIKELY( !decl ) ) return FD_VM_ERR_PERM;

// TODO: define a refcell macro to simplify this boilerplate
#define VM_SYSCALL_CPI_ACC_INFO_DATA( vm, acc_info, decl ) \
  fd_vm_rc_refcell_vec_t * FD_EXPAND_THEN_CONCAT2(decl, _box) = fd_vm_translate_vm_to_host( vm, acc_info->data_box_addr, sizeof(fd_vm_rc_refcell_vec_t), FD_VM_RC_REFCELL_ALIGN ); \
  if( FD_UNLIKELY( !FD_EXPAND_THEN_CONCAT2(decl, _box) ) ) return FD_VM_ERR_PERM; \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _vm_addr) = FD_EXPAND_THEN_CONCAT2(decl, _box)->addr; \
  uchar * decl = fd_vm_translate_vm_to_host( vm, FD_EXPAND_THEN_CONCAT2(decl, _box)->addr, FD_EXPAND_THEN_CONCAT2(decl, _box)->len, alignof(uchar) ); \
  if ( FD_UNLIKELY( !decl ) ) return FD_VM_ERR_PERM; \
  ulong FD_EXPAND_THEN_CONCAT2(decl, _len) = FD_EXPAND_THEN_CONCAT2(decl, _box)->len;

#define VM_SYSCALL_CPI_SET_ACC_INFO_DATA_LEN( vm, acc_info, decl, len_ ) \
  FD_EXPAND_THEN_CONCAT2(decl, _box)->len = len_;

#include "fd_vm_syscall_common.c"

#undef VM_SYSCALL_CPI_ABI
#undef VM_SYSCALL_CPI_INSTR_T
#undef VM_SYSCALL_CPI_INSTR_ALIGN
#undef VM_SYSCALL_CPI_INSTR_SIZE
#undef VM_SYSCALL_CPI_INSTR_DATA_ADDR
#undef VM_SYSCALL_CPI_INSTR_DATA_LEN
#undef VM_SYSCALL_CPI_INSTR_ACCS_LEN
#undef VM_SYSCALL_CPI_ACC_META_T
#undef VM_SYSCALL_CPI_ACC_META_ALIGN
#undef VM_SYSCALL_CPI_ACC_META_SIZE   
#undef VM_SYSCALL_CPI_ACC_META_IS_WRITABLE
#undef VM_SYSCALL_CPI_ACC_META_IS_SIGNER
#undef VM_SYSCALL_CPI_TRANSLATE_ACC_META_PUBKEY
#undef VM_SYSCALL_CPI_INSTR_ACCS_ADDR
#undef VM_SYSCALL_CPI_INSTR_ACCS_LEN
#undef VM_SYSCALL_CPI_ACC_INFO_T
#undef VM_SYSCALL_CPI_ACC_INFO_ALIGN
#undef VM_SYSCALL_CPI_ACC_INFO_SIZE
#undef VM_SYSCALL_CPI_ACC_INFO_LAMPORTS
#undef VM_SYSCALL_CPI_ACC_INFO_DATA
#undef VM_SYSCALL_CPI_SET_ACC_INFO_DATA_LEN
#undef VM_SYSCALL_CPI_TRANSLATE_PROGRAM_ID_ADDR
