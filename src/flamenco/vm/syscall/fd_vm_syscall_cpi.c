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

int
fd_vm_prepare_instruction( fd_instr_info_t const *  caller_instr,
                           fd_instr_info_t *        callee_instr,
                           fd_exec_instr_ctx_t *    instr_ctx,
                           fd_instruction_account_t instruction_accounts[256],
                           ulong *                  instruction_accounts_cnt,
                           fd_pubkey_t const *      signers,
                           ulong                    signers_cnt ) {
  ulong deduplicated_instruction_accounts_cnt = 0;
  fd_instruction_account_t deduplicated_instruction_accounts[256];
  ulong duplicate_indicies_cnt = 0;
  ulong duplicate_indices[256];
  for( ulong i=0UL; i<callee_instr->acct_cnt; i++ ) {
    fd_pubkey_t const * callee_pubkey = &callee_instr->acct_pubkeys[i];

    ushort index_in_transaction = USHORT_MAX;
    for( ulong j=0UL; j<instr_ctx->txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( instr_ctx->txn_ctx->accounts[j].uc, callee_pubkey->uc, sizeof(fd_pubkey_t) ) ) {
        index_in_transaction = (ushort)j;
        break;
      }
    }
    if( index_in_transaction==USHORT_MAX) return 1;

    // Check if duplicate
    ulong duplicate_index = ULONG_MAX;
    for( ulong j=0UL; j<deduplicated_instruction_accounts_cnt; j++ )
      if( deduplicated_instruction_accounts[j].index_in_transaction==index_in_transaction ) {
        duplicate_index = j;
        break;
      }

    if( duplicate_index!=ULONG_MAX ) {
      duplicate_indices[duplicate_indicies_cnt++] = duplicate_index;
      fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[duplicate_index];
      instruction_account->is_signer |= !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
      instruction_account->is_writable |= !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
    } else {
      ushort index_in_caller = USHORT_MAX;
      for( ulong j=0UL; j<caller_instr->acct_cnt; j++ )
        if( !memcmp( caller_instr->acct_pubkeys[j].uc, callee_instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) ) ) {
          index_in_caller = (ushort)j;
          break;
        }

      if( index_in_caller==USHORT_MAX ) return 1;

      duplicate_indices[duplicate_indicies_cnt++] = deduplicated_instruction_accounts_cnt;
      fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[deduplicated_instruction_accounts_cnt++];
      instruction_account->index_in_callee      = (ushort)i;
      instruction_account->index_in_caller      = index_in_caller;
      instruction_account->index_in_transaction = index_in_transaction;
      instruction_account->is_signer            = !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
      instruction_account->is_writable          = !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
    }
  }

  for( ulong i = 0; i < deduplicated_instruction_accounts_cnt; i++ ) {
    fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[i];
    fd_borrowed_account_t borrowed_account;
    fd_memcpy(borrowed_account.pubkey, &caller_instr->acct_pubkeys[instruction_account->index_in_caller], sizeof(fd_pubkey_t));

    if ( FD_UNLIKELY( instruction_account->is_writable && !fd_instr_acc_is_writable(instr_ctx->instr, borrowed_account.pubkey) ) ) {
      return 1;
    }

    if ( FD_UNLIKELY( instruction_account->is_signer && !(fd_instr_acc_is_signer(instr_ctx->instr, borrowed_account.pubkey) || is_signer(borrowed_account.pubkey, signers, signers_cnt)) ) ) {
      return 1;
    }
  }

  for (ulong i = 0; i < duplicate_indicies_cnt; i++) {
    ulong duplicate_index = duplicate_indices[i];
    if ( FD_LIKELY( duplicate_index < deduplicated_instruction_accounts_cnt ) ) {
      instruction_accounts[i] = deduplicated_instruction_accounts[duplicate_index];
      int flags = callee_instr->acct_flags[i];
      flags |= instruction_accounts[i].is_signer ? (uchar)FD_INSTR_ACCT_FLAGS_IS_SIGNER : (uchar)0U;
      flags |= instruction_accounts[i].is_writable ? (uchar)FD_INSTR_ACCT_FLAGS_IS_WRITABLE : (uchar)0U;
      callee_instr->acct_flags[i] = (uchar)flags;
    } else {
      return 1;
    }
  }

  fd_borrowed_account_t * program_rec = NULL;
  int err = fd_txn_borrowed_account_view( instr_ctx->txn_ctx, &instr_ctx->instr->program_id_pubkey, &program_rec );

  if( FD_UNLIKELY( err ) ) {
    return 1;
  }

  fd_account_meta_t const * program_meta = program_rec->const_meta;

  if( FD_UNLIKELY( !fd_account_is_executable( program_meta ) ) ) return 1;

  *instruction_accounts_cnt = duplicate_indicies_cnt;

  return 0;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (Generic logic)
 **********************************************************************/

/* FD_CPI_MAX_SIGNER_CNT is the max amount of PDA signer addresses that
   a cross-program invocation can include in an instruction. */

#define FD_CPI_MAX_SIGNER_CNT              (16UL)

/* Maximum number of account info structs that can be used in a single CPI
   invocation. A limit on account info structs is effectively the same as
   limiting the number of unique accounts. 128 was chosen to match the max
   number of locked accounts per transaction (MAX_TX_ACCOUNT_LOCKS). */

#define FD_CPI_MAX_ACCOUNT_INFOS           (FD_FEATURE_ACTIVE(slot_ctx, increase_tx_account_lock_limit) ? 128UL : 64UL)

/* Maximum CPI instruction data size. 10 KiB was chosen to ensure that CPI
   instructions are not more limited than transaction instructions if the size
   of transactions is doubled in the future. */

#define FD_CPI_MAX_INSTRUCTION_DATA_LEN    (10240UL)

/* Maximum CPI instruction accounts. 255 was chosen to ensure that instruction
   accounts are always within the maximum instruction account limit for BPF
   program instructions. */

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

  if( FD_UNLIKELY( signers_seeds_cnt > FD_CPI_MAX_SIGNER_CNT ) ) {
    FD_LOG_WARNING(("TODO: return too many signers" ));
    return FD_VM_ERR_INVAL;
  }

  /* https://github.com/solana-labs/solana/blob/eb35a5ac1e7b6abe81947e22417f34508f89f091/programs/bpf_loader/src/syscalls/cpi.rs#L996-L997 */
  if( FD_FEATURE_ACTIVE( slot_ctx, loosen_cpi_size_restriction ) ) {
    if( FD_UNLIKELY( acct_info_cnt > FD_CPI_MAX_ACCOUNT_INFOS  ) ) {
      FD_LOG_WARNING(( "TODO: return max instruction account infos exceeded" ));
      return FD_VM_ERR_INVAL;
    }
  } else {
    ulong adjusted_len = fd_ulong_sat_mul( acct_info_cnt, sizeof( fd_pubkey_t ) );
    if ( FD_UNLIKELY( adjusted_len > vm_compute_budget.max_cpi_instruction_size ) ) {
      // Cap the number of account_infos a caller can pass to approximate
      // maximum that accounts that could be passed in an instruction
      // todo: correct return code type. Too many accounts passed to inner instruction.
      return FD_VM_ERR_INVAL;
    }
  }

  return FD_VM_SUCCESS;
}

// FIXME: NEED TO DO IS_DUPLICATE INIT HERE
static void
fd_vm_syscall_cpi_c_instruction_to_instr( fd_vm_t * vm,
                                          fd_vm_c_instruction_t const * cpi_instr,
                                          fd_vm_c_account_meta_t const * cpi_acct_metas,
                                          fd_pubkey_t const * signers,
                                          ulong signers_cnt,
                                          uchar const * cpi_instr_data,
                                          fd_instr_info_t * instr ) {
  fd_pubkey_t * txn_accs = vm->instr_ctx->txn_ctx->accounts;
  for( ulong i=0UL; i < vm->instr_ctx->txn_ctx->accounts_cnt; i++ ) {
    fd_pubkey_t const * program_id_pubkey =
      fd_vm_translate_vm_to_host_const( vm, cpi_instr->program_id_addr, sizeof(fd_pubkey_t), alignof(uchar) );
    if( !memcmp( program_id_pubkey->uc, &txn_accs[i], sizeof(fd_pubkey_t) ) ) {
      instr->program_id = (uchar)i;
      instr->program_id_pubkey = txn_accs[i];
      break;
    }
  }

  ulong starting_lamports = 0;
  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, 256);
  for( ulong i=0UL; i<cpi_instr->accounts_len; i++ ) {
    fd_vm_c_account_meta_t const * cpi_acct_meta = &cpi_acct_metas[i];
    fd_pubkey_t const * acct_pubkey =
      fd_vm_translate_vm_to_host_const( vm, cpi_acct_meta->pubkey_addr, sizeof(fd_pubkey_t), alignof(uchar) );
    //FD_LOG_DEBUG(("Accounts cnt %lu, account %32J addr %lu", vm->instr_ctx->txn_ctx->accounts_cnt, acct_pubkey->uc, cpi_acct_meta->pubkey_addr));
    for( ulong j=0UL; j<vm->instr_ctx->txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( acct_pubkey->uc, &txn_accs[j], sizeof( fd_pubkey_t ) ) ) {
        // TODO: error if not found, if flags are wrong;
        memcpy( instr->acct_pubkeys[i].uc, acct_pubkey->uc, sizeof( fd_pubkey_t ) );
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

        if( cpi_acct_meta->is_writable && fd_instr_acc_is_writable( vm->instr_ctx->instr, acct_pubkey) ) {
          instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
        }
        // TODO: should check the parent has signer flag set
        if( cpi_acct_meta->is_signer ) {
          instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
        } else {
          for( ulong k=0UL; k<signers_cnt; k++ ) {
            if( !memcmp( &signers[k], acct_pubkey->uc, sizeof( fd_pubkey_t ) ) ) {
              instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
              break;
            }
          }
        }

        // FD_LOG_DEBUG(( "CPI ACCT: %lu %lu %u %32J %32J %x", i, j, (uchar)vm->instr_ctx->instr->acct_txn_idxs[j], instr->acct_pubkeys[i].uc, acct_pubkey, instr->acct_flags[i] ));

        break;
      }
    }
  }

  instr->data_sz = (ushort)cpi_instr->data_len;
  instr->data = (uchar *)cpi_instr_data;
  instr->acct_cnt = (ushort)cpi_instr->accounts_len;
  instr->starting_lamports = starting_lamports;

}

static void
fd_vm_syscall_cpi_rust_instruction_to_instr( fd_vm_t const * vm,
                                             fd_vm_rust_instruction_t const * cpi_instr,
                                             fd_vm_rust_account_meta_t const * cpi_acct_metas,
                                             fd_pubkey_t const * signers,
                                             ulong signers_cnt,
                                             uchar const * cpi_instr_data,
                                             fd_instr_info_t * instr ) {

  fd_pubkey_t * txn_accs = vm->instr_ctx->txn_ctx->accounts;
  for( ulong i=0UL; i < vm->instr_ctx->txn_ctx->accounts_cnt; i++ )
    if( !memcmp( &cpi_instr->pubkey, &txn_accs[i], sizeof( fd_pubkey_t ) ) ) {
      // TODO: error if not found
      instr->program_id = (uchar)i;
      instr->program_id_pubkey = txn_accs[i];
      break;
    }

  ulong starting_lamports = 0UL;
  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, 256);
  // FD_LOG_DEBUG(("Accounts cnt %lu %lu", vm->instr_ctx->txn_ctx->accounts_cnt, vm->instr_ctx->txn_ctx->txn_descriptor->acct_addr_cnt));
  for( ulong i=0UL; i<cpi_instr->accounts.len; i++ ) {
    fd_vm_rust_account_meta_t const * cpi_acct_meta = &cpi_acct_metas[i];

    for( ulong j=0UL; j<vm->instr_ctx->txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( &cpi_acct_meta->pubkey, &txn_accs[j], sizeof( fd_pubkey_t ) ) ) {
        // TODO: error if not found, if flags are wrong;
        memcpy( instr->acct_pubkeys[i].uc, cpi_acct_meta->pubkey, sizeof( fd_pubkey_t ) );
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
        if( cpi_acct_meta->is_writable && fd_instr_acc_is_writable( vm->instr_ctx->instr, (fd_pubkey_t*)cpi_acct_meta->pubkey) )
          instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;

        // TODO: should check the parent has signer flag set
        if( cpi_acct_meta->is_signer ) instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
        else
          for( ulong k = 0; k < signers_cnt; k++ ) {
            if( !memcmp( &signers[k], &cpi_acct_meta->pubkey, sizeof( fd_pubkey_t ) ) ) {
              instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
              break;
            }
          }

        // FD_LOG_DEBUG(( "CPI ACCT: %lu %lu %u %32J %32J %x", i, j, (uchar)vm->instr_ctx->instr->acct_txn_idxs[j], instr->acct_pubkeys[i].uc, cpi_acct_meta->pubkey, instr->acct_flags[i] ));

        break;
      }
    }
  }

  instr->data_sz = (ushort)cpi_instr->data.len;
  instr->data = (uchar *)cpi_instr_data;
  instr->acct_cnt = (ushort)cpi_instr->accounts.len;
  instr->starting_lamports = starting_lamports;

  // FD_LOG_WARNING(("starting lamps CPI: %lu", instr->starting_lamports));

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
      return FD_VM_ERR_INVAL;
    }
    if( FD_UNLIKELY( acct_cnt > FD_CPI_MAX_INSTRUCTION_ACCOUNTS ) ) {
      FD_LOG_WARNING(( "cpi: too many accounts (%#lx)", acct_cnt ));
      return FD_VM_ERR_INVAL;
    }
  } else {
    ulong tot_sz;
    int too_long  = __builtin_umull_overflow( acct_cnt, sizeof(fd_vm_c_account_meta_t), &tot_sz );
        too_long |= __builtin_uaddl_overflow( tot_sz, data_sz, &tot_sz );
    if( FD_UNLIKELY( too_long ) ) {
      FD_LOG_WARNING(( "cpi: instruction too long (%#lx)", tot_sz ));
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
  FD_TEST( pdas->idx < FD_CPI_MAX_SIGNER_CNT );

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
   respectively), but the logic is identical. */

static int
fd_vm_syscall_cpi_derive_signers_( fd_vm_t * vm,
                                   fd_vm_syscall_pdas_t * pdas,
                                   ulong                  signers_seeds_va,
                                   ulong                  signers_seeds_cnt ) {

  /* Translate array of seeds.  Each seed is an array of byte arrays. */
  fd_vm_vec_t const * seeds =
    fd_vm_translate_vm_to_host_const( vm, signers_seeds_va, signers_seeds_cnt*sizeof(fd_vm_vec_t), FD_VM_VEC_ALIGN );
  if( FD_UNLIKELY( !seeds ) ) return FD_VM_ERR_PERM;

  if( FD_UNLIKELY( signers_seeds_cnt > FD_CPI_MAX_SIGNER_CNT ) ) {
    return FD_VM_ERR_INVAL;
  }
  /* Create program addresses */

  for( ulong i=0UL; i<signers_seeds_cnt; i++ ) {

    /* Check seed count (avoid overflow) */
    if( FD_UNLIKELY( seeds[i].len > FD_VM_CPI_SEED_MAX ) ) return FD_VM_ERR_INVAL;

    /* Translate inner seed slice.  Each element points to a byte array. */
    fd_vm_vec_t const * seed =
      fd_vm_translate_vm_to_host_const( vm, seeds[i].addr, seeds[i].len * sizeof(fd_vm_vec_t), FD_VM_VEC_ALIGN );
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

static int
fd_vm_cpi_update_caller_account_rust( fd_vm_t *            vm,
                                      fd_vm_rust_account_info_t const * caller_acc_info,
                                      fd_pubkey_t const *               callee_acc_pubkey ) {
  fd_borrowed_account_t * callee_acc_rec = NULL;
  int err = fd_instr_borrowed_account_view( vm->instr_ctx, callee_acc_pubkey, &callee_acc_rec );
  ulong updated_lamports, data_len;
  uchar const * updated_owner = NULL;
  if( FD_UNLIKELY( err ) ) {
    // TODO: do we need to do something anyways
    updated_lamports = 0;
    data_len = 0;
  } else {
    updated_lamports = callee_acc_rec->const_meta->info.lamports;
    data_len = callee_acc_rec->const_meta->dlen;
    updated_owner = callee_acc_rec->const_meta->info.owner;
  }

  fd_vm_rc_refcell_t const * caller_acc_lamports_box =
    fd_vm_translate_vm_to_host_const( vm, caller_acc_info->lamports_box_addr, sizeof(fd_vm_rc_refcell_t), FD_VM_RC_REFCELL_ALIGN );
  if( FD_UNLIKELY( !caller_acc_lamports_box ) ) return FD_VM_ERR_PERM;

  ulong * caller_acc_lamports =
    fd_vm_translate_vm_to_host( vm, caller_acc_lamports_box->addr, sizeof(ulong), alignof(ulong) );
  if( FD_UNLIKELY( !caller_acc_lamports ) ) return FD_VM_ERR_PERM;
  *caller_acc_lamports = updated_lamports;

  fd_vm_rc_refcell_vec_t * caller_acc_data_box =
    fd_vm_translate_vm_to_host( vm, caller_acc_info->data_box_addr, sizeof(fd_vm_rc_refcell_vec_t), FD_VM_RC_REFCELL_ALIGN );
  if( FD_UNLIKELY( !caller_acc_data_box ) ) return FD_VM_ERR_PERM;

  uchar * caller_acc_data =
    fd_vm_translate_vm_to_host( vm, caller_acc_data_box->addr, caller_acc_data_box->len, alignof(uchar) );
  if( FD_UNLIKELY( !caller_acc_data ) ) return FD_VM_ERR_PERM;

  uchar * caller_acc_owner = fd_vm_translate_vm_to_host( vm, caller_acc_info->owner_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  if( updated_owner ) fd_memcpy( caller_acc_owner, updated_owner, sizeof(fd_pubkey_t) );
  else                fd_memset( caller_acc_owner, 0,             sizeof(fd_pubkey_t) );

  // TODO: deal with all functionality in update_caller_account
  if( !data_len ) fd_memset(caller_acc_data, 0, caller_acc_data_box->len );
  if( caller_acc_data_box->len!=data_len ) {
    caller_acc_data_box->len = data_len;
    ulong * caller_len =
      fd_vm_translate_vm_to_host( vm, fd_ulong_sat_sub(caller_acc_data_box->addr, sizeof(ulong)), sizeof(ulong), alignof(ulong) );
    *caller_len = data_len;
    // TODO return instruction error account data size too small.
  }

  fd_memcpy( caller_acc_data, callee_acc_rec->const_data, data_len );

  return 0;
}

static int
fd_vm_cpi_update_caller_account_c( fd_vm_t *         vm,
                                   fd_vm_c_account_info_t const * caller_acc_info,
                                   fd_pubkey_t const *            callee_acc_pubkey ) {
  fd_borrowed_account_t * callee_acc_rec =NULL;
  int err = fd_instr_borrowed_account_view( vm->instr_ctx, callee_acc_pubkey, &callee_acc_rec );
  ulong updated_lamports, data_len;
  uchar const * updated_owner = NULL;
  if( FD_UNLIKELY( err ) ) {
    // TODO: do we need to do something anyways
    updated_lamports = 0;
    data_len = 0;
  } else {
    updated_lamports = callee_acc_rec->const_meta->info.lamports;
    data_len = callee_acc_rec->const_meta->dlen;
    updated_owner = callee_acc_rec->const_meta->info.owner;
  }

  ulong * caller_acc_lamports = fd_vm_translate_vm_to_host( vm, caller_acc_info->lamports_addr, sizeof(ulong), alignof(ulong) );
  if( FD_UNLIKELY( !caller_acc_lamports ) ) return FD_VM_ERR_PERM;
  *caller_acc_lamports = updated_lamports;

  uchar * caller_acc_data = fd_vm_translate_vm_to_host( vm, caller_acc_info->data_addr, caller_acc_info->data_sz, alignof(uchar) );
  if( FD_UNLIKELY( !caller_acc_data ) ) return FD_VM_ERR_PERM;

  uchar * caller_acc_owner = fd_vm_translate_vm_to_host( vm, caller_acc_info->owner_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  if( updated_owner ) fd_memcpy( caller_acc_owner, updated_owner, sizeof(fd_pubkey_t) );
  else                fd_memset( caller_acc_owner, 0,             sizeof(fd_pubkey_t) );

  // TODO: deal with all functionality in update_caller_account
  if( !data_len ) fd_memset( caller_acc_data, 0, caller_acc_info->data_sz );
  if( caller_acc_info->data_sz!=data_len ) {
    ulong * caller_len =
      fd_vm_translate_vm_to_host( vm, fd_ulong_sat_sub(caller_acc_info->data_addr, sizeof(ulong)), sizeof(ulong), alignof(ulong) );
    *caller_len = data_len;
    // TODO return instruction error account data size too small.
  }

  fd_memcpy( caller_acc_data, callee_acc_rec->const_data, data_len );

  return 0;
}

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

/* FIXME: PREFIX */
static inline int
is_precompile( uchar const * program_id ) {
  return check_id(program_id, fd_solana_keccak_secp_256k_program_id.key) ||
         check_id(program_id, fd_solana_ed25519_sig_verify_program_id.key);
}

/* FIXME: PREFIX / RET TYPE? (THIS BRANCH NEST MAKES BABIES CRY) */
static inline ulong
check_authorized_program( uchar const *        program_id,
                          fd_exec_slot_ctx_t * slot_ctx,
                          uchar const *        instruction_data,
                          ulong                instruction_data_len ) {
  return check_id( program_id, fd_solana_native_loader_id.key                 )                 ||
         check_id( program_id, fd_solana_bpf_loader_program_id.key            )                 ||
         check_id( program_id, fd_solana_bpf_loader_deprecated_program_id.key )                 ||
         ( check_id( program_id, fd_solana_bpf_loader_upgradeable_program_id.key ) &&
           ( (instruction_data_len == 0 || instruction_data[0] != 3)                        ||
             (instruction_data_len != 0 && instruction_data[0] == 4)                        ||
             ( FD_FEATURE_ACTIVE( slot_ctx, enable_bpf_loader_set_authority_checked_ix ) &&
               (instruction_data_len != 0 && instruction_data[0] == 4) )                    ||
             (instruction_data_len != 0 && instruction_data[0] == 5)                        ) ) ||
         is_precompile(program_id);
}

/* FIXME: PREFIX */
static int
from_account_info_rust( fd_vm_t *            vm,
                        fd_vm_rust_account_info_t const * account_info,
                        fd_caller_account_t *             out ) {
  fd_vm_rc_refcell_t const * caller_acc_lamports_box =
    fd_vm_translate_vm_to_host_const( vm, account_info->lamports_box_addr, sizeof(fd_vm_rc_refcell_t), FD_VM_RC_REFCELL_ALIGN );
  if( FD_UNLIKELY( !caller_acc_lamports_box ) ) return FD_VM_ERR_PERM;

  ulong * caller_acc_lamports = fd_vm_translate_vm_to_host( vm, caller_acc_lamports_box->addr, sizeof(ulong), alignof(ulong) );
  if( FD_UNLIKELY( !caller_acc_lamports ) ) return FD_VM_ERR_PERM;

  out->lamports = *caller_acc_lamports;

  uchar * caller_acc_owner = fd_vm_translate_vm_to_host( vm, account_info->owner_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  /* FIXME: TEST? */
  fd_memcpy(out->owner.uc, caller_acc_owner, sizeof(fd_pubkey_t));

  fd_vm_rc_refcell_vec_t * caller_acc_data_box =
    fd_vm_translate_vm_to_host( vm, account_info->data_box_addr, sizeof(fd_vm_rc_refcell_vec_t), FD_VM_RC_REFCELL_ALIGN );
  if( FD_UNLIKELY( !caller_acc_data_box ) ) return FD_VM_ERR_PERM;

  int err = fd_vm_consume_compute( vm, caller_acc_data_box->len / vm_compute_budget.cpi_bytes_per_unit );
  if( FD_UNLIKELY( err ) ) return err;

  uchar * caller_acc_data = fd_vm_translate_vm_to_host( vm, caller_acc_data_box->addr, caller_acc_data_box->len, alignof(uchar) );
  if( FD_UNLIKELY( !caller_acc_data ) ) return FD_VM_ERR_PERM;

  out->serialized_data = caller_acc_data;
  out->serialized_data_len = caller_acc_data_box->len;
  out->executable = FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, disable_cpi_setting_executable_and_rent_epoch ) ? 0 : account_info->executable;
  out->rent_epoch = FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, disable_cpi_setting_executable_and_rent_epoch ) ? 0 : account_info->rent_epoch;
  return 0;
}

/* FIXME: PREFIX */
static int
from_account_info_c( fd_vm_t * vm,
                     fd_vm_c_account_info_t const * account_info,
                     fd_caller_account_t * out ) {

  ulong * caller_acc_lamports = fd_vm_translate_vm_to_host( vm, account_info->lamports_addr, sizeof(ulong), alignof(ulong) );
  if( FD_UNLIKELY( !caller_acc_lamports ) ) return FD_VM_ERR_PERM;

  out->lamports = *caller_acc_lamports;

  uchar * caller_acc_owner = fd_vm_translate_vm_to_host( vm, account_info->owner_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  /* FIXME: TEST? */
  fd_memcpy(out->owner.uc, caller_acc_owner, sizeof(fd_pubkey_t));

  int err = fd_vm_consume_compute( vm, account_info->data_sz / vm_compute_budget.cpi_bytes_per_unit );
  if( FD_UNLIKELY( err ) ) return err;

  uchar * caller_acc_data = fd_vm_translate_vm_to_host( vm, account_info->data_addr, account_info->data_sz, alignof(uchar) );
  /* FIXME: TEST? */

  out->serialized_data = caller_acc_data;
  out->serialized_data_len = account_info->data_sz;
  out->executable = FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, disable_cpi_setting_executable_and_rent_epoch ) ? 0 : account_info->executable;
  out->rent_epoch = FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, disable_cpi_setting_executable_and_rent_epoch ) ? 0 : account_info->rent_epoch;
  return 0;
}

/* FIXME: PREFIX */
static int
translate_and_update_accounts( fd_vm_t *       vm,
                               fd_instruction_account_t *   instruction_accounts,
                               ulong                        instruction_accounts_cnt,
                               fd_pubkey_t const *          account_info_keys,
                               fd_vm_account_info_t const * account_info,
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
    // int view_err = fd_instr_borrowed_account_view( vm->instr_ctx, callee_account, &acc_rec );
    // if( (!view_err || view_err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT) && acc_rec ) {
    //   acc_meta = acc_rec->const_meta;
    // } else {
    //   FD_LOG_DEBUG(( "account missing in translation - acc: %32J", callee_account->key ));
    // }
    fd_instr_borrowed_account_view( vm->instr_ctx, callee_account, &acc_rec );
    acc_meta = acc_rec->const_meta;

    if( acc_meta && fd_account_is_executable( acc_meta ) ) {
      // FD_LOG_DEBUG(("CPI Acc data len %lu", acc_meta->dlen));
      int err = fd_vm_consume_compute( vm, acc_meta->dlen / vm_compute_budget.cpi_bytes_per_unit );
      if( FD_UNLIKELY( err ) ) return err;
    } else {
      uint found = 0;
      for( ulong j=0; j < account_info_cnt; j++ ) {
        if( !memcmp( account_key->uc, account_info_keys[j].uc, sizeof(fd_pubkey_t) ) ) {
          fd_caller_account_t caller_account;
          int err;
          switch (account_info->discriminant) {
            case FD_VM_ACCOUNT_INFO_RUST: {
              err = from_account_info_rust(vm, &account_info->inner.rust_acct_infos[j], &caller_account);
              break;
            }
            case FD_VM_ACCOUNT_INFO_C: {
              err = from_account_info_c(vm, &account_info->inner.c_acct_infos[j], &caller_account);
              break;
            }
            default: {
              err = 1005;
            }
          }
          if( FD_UNLIKELY( err ) ) return err;

          // FD_LOG_DEBUG(("CPI Acc data len %lu for %32J", caller_account.serialized_data_len, account_key->uc));
          if( FD_UNLIKELY( acc_meta && fd_vm_cpi_update_callee_account(vm, &caller_account, callee_account, i) ) ) return 1001;

          if (instruction_accounts[i].is_writable) {
            out_callee_indices[*out_len] = instruction_accounts[i].index_in_caller;
            out_caller_indices[*out_len] = j;
            (*out_len)++;
          }
          found = 1;
        }
      }
      if( !found ) return 1002;
    }
  }
  return 0;
}

/**********************************************************************
  CROSS PROGRAM INVOCATION (C ABI)
 **********************************************************************/

/* fd_vm_syscall_cpi_c implements Solana VM syscall sol_invoked_signed_c. */

int
fd_vm_syscall_cpi_c( void *  _vm,
                     ulong   instruction_va,
                     ulong   acct_infos_va,
                     ulong   acct_info_cnt,
                     ulong   signers_seeds_va,
                     ulong   signers_seeds_cnt,
                     ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.invoke_units );
  if( FD_UNLIKELY( err ) ) return err;

  /* Pre-flight checks ************************************************/

  err = fd_vm_syscall_cpi_preflight_check( signers_seeds_cnt, acct_info_cnt, vm->instr_ctx->slot_ctx);
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate instruction ********************************************/

  fd_vm_c_instruction_t const * instruction =
    fd_vm_translate_vm_to_host_const( vm, instruction_va, sizeof(fd_vm_c_instruction_t), FD_VM_C_INSTRUCTION_ALIGN );
  if( FD_UNLIKELY( !instruction ) ) return FD_VM_ERR_PERM;

  fd_vm_c_account_meta_t const * accounts =
    fd_vm_translate_vm_to_host_const( vm, instruction->accounts_addr,
                                      instruction->accounts_len*sizeof(fd_vm_c_account_meta_t), FD_VM_C_ACCOUNT_META_ALIGN );
  if( FD_UNLIKELY( !accounts ) ) return FD_VM_ERR_PERM;

  uchar const * data = fd_vm_translate_vm_to_host_const( vm, instruction->data_addr, instruction->data_len, alignof(uchar) );
  if( FD_UNLIKELY( !data ) ) return FD_VM_ERR_PERM;

  /* Instruction checks ***********************************************/

  err = fd_vm_syscall_cpi_check_instruction( vm, instruction->accounts_len, instruction->data_len );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate signers ************************************************/

  /* Order of operations is liberally rearranged.
     For inputs that cause multiple errors, this means that Solana Labs
     and Firedancer may return different error codes (as we abort at the
     first error).  (See above) */

  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  err = fd_vm_syscall_cpi_derive_signers( vm, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) return err;

  fd_vm_c_account_info_t const * acc_infos =
    fd_vm_translate_vm_to_host_const( vm, acct_infos_va,
                                      acct_info_cnt*sizeof(fd_vm_c_account_info_t), FD_VM_C_ACCOUNT_INFO_ALIGN );
  if( FD_UNLIKELY( !acc_infos ) ) return FD_VM_ERR_PERM;

  /* Collect pubkeys */

  fd_pubkey_t acct_keys[ acct_info_cnt ];  /* FIXME get rid of VLA */
  for( ulong i=0UL; i<acct_info_cnt; i++ ) {
    fd_pubkey_t const * acct_addr =
      fd_vm_translate_vm_to_host_const( vm, acc_infos[i].key_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  // FD_LOG_DEBUG(( "CPI9: %lu %lx %32J", i, acc_infos[i].key_addr, acct_addr->uc ));
    if( FD_UNLIKELY( !acct_addr ) ) {
      FD_LOG_WARNING(("Translate failed %lu", i));
      return FD_VM_ERR_PERM;
    }
    memcpy( acct_keys[i].uc, acct_addr->uc, sizeof(fd_pubkey_t) );
  }

  /* TODO: Dispatch CPI to executor.
           For now, we'll just log parameters. */

  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;
  fd_instr_info_t cpi_instr;

  fd_vm_syscall_cpi_c_instruction_to_instr( vm, instruction, accounts, signers, signers_seeds_cnt, data, &cpi_instr );
  err = fd_vm_prepare_instruction(vm->instr_ctx->instr, &cpi_instr, vm->instr_ctx, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "PREPARE FAILED" ));
    return err;
  }

  ulong callee_account_keys[256];
  ulong caller_accounts_to_update[256];
  ulong update_len = 0;
  fd_vm_account_info_t acc_info = {.discriminant = 1, .inner = {.c_acct_infos = acc_infos }};
  err = translate_and_update_accounts(vm, instruction_accounts, instruction_accounts_cnt, acct_keys, &acc_info, acct_info_cnt, callee_account_keys, caller_accounts_to_update, &update_len);
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "translate failed %d", err ));
    return err;
  }

  ulong caller_lamports = fd_instr_info_sum_account_lamports( vm->instr_ctx->instr );
  if( caller_lamports!=vm->instr_ctx->instr->starting_lamports ) return FD_VM_ERR_INSTR_ERR;
  vm->instr_ctx->txn_ctx->compute_meter = vm->compute_meter;
  int err_exec = fd_execute_instr( vm->instr_ctx->txn_ctx, &cpi_instr );
  ulong instr_exec_res = (ulong)err_exec;
  // FD_LOG_WARNING(( "CPI CUs CONSUMED: %lu %lu %lu ", vm->compute_meter, vm->instr_ctx->txn_ctx->compute_meter, vm->compute_meter - vm->instr_ctx->txn_ctx->compute_meter));
  vm->compute_meter = vm->instr_ctx->txn_ctx->compute_meter;
  // FD_LOG_WARNING(( "AFTER CPI: %lu CUs: %lu Err: %d", *_ret, vm->compute_meter, err_exec ));

  *_ret = instr_exec_res;
  if( FD_UNLIKELY( instr_exec_res ) ) return FD_VM_ERR_INSTR_ERR;

  for( ulong i = 0; i < update_len; i++ ) {
    fd_pubkey_t const * callee = &vm->instr_ctx->instr->acct_pubkeys[callee_account_keys[i]];
    err = fd_vm_cpi_update_caller_account_c(vm, &acc_infos[caller_accounts_to_update[i]], callee);
    if( FD_UNLIKELY( err ) ) return err;
  }

  caller_lamports = fd_instr_info_sum_account_lamports( vm->instr_ctx->instr );
  if( caller_lamports!=vm->instr_ctx->instr->starting_lamports ) return FD_VM_ERR_INSTR_ERR;

  return FD_VM_SUCCESS;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (Rust ABI)
 **********************************************************************/

int
fd_vm_syscall_cpi_rust( void *  _vm,
                        ulong   instruction_va,
                        ulong   acct_infos_va,
                        ulong   acct_info_cnt,
                        ulong   signers_seeds_va,
                        ulong   signers_seeds_cnt,
                        ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  int err = fd_vm_consume_compute( vm, vm_compute_budget.invoke_units );
  if( FD_UNLIKELY( err ) ) return err;

  /* Pre-flight checks ************************************************/

  err = fd_vm_syscall_cpi_preflight_check( signers_seeds_cnt, acct_info_cnt, vm->instr_ctx->slot_ctx );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate instruction ********************************************/

  fd_vm_rust_instruction_t const * instruction =
    fd_vm_translate_vm_to_host_const( vm, instruction_va, sizeof(fd_vm_rust_instruction_t), FD_VM_RUST_INSTRUCTION_ALIGN );
  if( FD_UNLIKELY( !instruction ) ) return FD_VM_ERR_PERM;

  if( FD_FEATURE_ACTIVE( vm->instr_ctx->slot_ctx, loosen_cpi_size_restriction ) )
    fd_vm_consume_compute( vm, vm_compute_budget.cpi_bytes_per_unit ? instruction->data.len/vm_compute_budget.cpi_bytes_per_unit : ULONG_MAX );

  /* Translate signers ************************************************/

  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  err = fd_vm_syscall_cpi_derive_signers( vm, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) return err;

  fd_vm_rust_account_meta_t const * accounts =
    fd_vm_translate_vm_to_host_const( vm, instruction->accounts.addr,
                                      instruction->accounts.len*sizeof(fd_vm_rust_account_meta_t), FD_VM_RUST_ACCOUNT_META_ALIGN );

  uchar const * data = fd_vm_translate_vm_to_host_const( vm, instruction->data.addr, instruction->data.len, alignof(uchar) );
  if( FD_UNLIKELY( check_authorized_program( instruction->pubkey, vm->instr_ctx->slot_ctx, data, instruction->data.len ) ) )
    return FD_VM_ERR_PERM;

  /* Instruction checks ***********************************************/

  err = fd_vm_syscall_cpi_check_instruction( vm, instruction->accounts.len, instruction->data.len );
  if( FD_UNLIKELY( err ) ) return err;

  /* Translate account infos ******************************************/

  fd_vm_rust_account_info_t const * acc_infos =
    fd_vm_translate_vm_to_host_const( vm, acct_infos_va,
                                      acct_info_cnt*sizeof(fd_vm_rust_account_info_t), FD_VM_RUST_ACCOUNT_INFO_ALIGN );
  if( FD_UNLIKELY( !acc_infos ) ) return FD_VM_ERR_PERM;

  /* Collect pubkeys */

  fd_pubkey_t acct_keys[ acct_info_cnt ];  /* FIXME get rid of VLA */
  for( ulong i=0UL; i<acct_info_cnt; i++ ) {
    fd_pubkey_t const * acct_addr =
      fd_vm_translate_vm_to_host_const( vm, acc_infos[i].pubkey_addr, sizeof(fd_pubkey_t), alignof(uchar) );
    if( FD_UNLIKELY( !acct_addr ) ) return FD_VM_ERR_PERM;
    memcpy( acct_keys[i].uc, acct_addr->uc, sizeof(fd_pubkey_t) );
  }

  /* TODO: Dispatch CPI to executor.
           For now, we'll just log parameters. */

  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;
  fd_instr_info_t cpi_instr;

  fd_vm_syscall_cpi_rust_instruction_to_instr( vm, instruction, accounts, signers, signers_seeds_cnt, data, &cpi_instr );
  err = fd_vm_prepare_instruction(vm->instr_ctx->instr, &cpi_instr, vm->instr_ctx, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(("PREPARE FAILED"));
    return err;
  }

  ulong callee_account_keys[256];
  ulong caller_accounts_to_update[256];
  ulong update_len = 0;
  fd_vm_account_info_t acc_info = {.discriminant = 0, .inner = {.rust_acct_infos = acc_infos }};
  err = translate_and_update_accounts(vm, instruction_accounts, instruction_accounts_cnt, acct_keys, &acc_info, acct_info_cnt, callee_account_keys, caller_accounts_to_update, &update_len);
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "translate failed %d", err ));
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
    err = fd_vm_cpi_update_caller_account_rust(vm, &acc_infos[caller_accounts_to_update[i]], callee);
    if( FD_UNLIKELY( err ) ) return err;
  }

  caller_lamports = fd_instr_info_sum_account_lamports( vm->instr_ctx->instr );
  if( caller_lamports!=vm->instr_ctx->instr->starting_lamports ) return FD_VM_ERR_INSTR_ERR;

  return FD_VM_SUCCESS;
}
