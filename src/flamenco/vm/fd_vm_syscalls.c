#include "fd_vm_syscalls.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/keccak256/fd_keccak256.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../../ballet/sbpf/fd_sbpf_maps.c"
#include "../../ballet/secp256k1/fd_secp256k1.h"
#include "fd_vm_context.h"
#include "fd_vm_cpi.h"
#include "../runtime/sysvar/fd_sysvar.h"
#include "../runtime/fd_account.h"
#include "../../ballet/base64/fd_base64.h"

#include <stdio.h>

/* FIXME: Temporary scaffolding */
#if FD_USING_GCC==1 /* Clang doesn't understand the below */
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#endif

/* Represents an account for a CPI*/
struct fd_instruction_account {
  ushort index_in_transaction;
  ushort index_in_caller;
  ushort index_in_callee;
  uint is_signer;
  uint is_writable;
};
typedef struct fd_instruction_account fd_instruction_account_t;

/* Representation of a caller account, used to
  update callee accounts. */
struct fd_caller_account {
  ulong lamports;
  fd_pubkey_t owner;
  uchar * serialized_data;
  ulong serialized_data_len;
  uchar executable;
  ulong rent_epoch;
};
typedef struct fd_caller_account fd_caller_account_t;

#if !FD_HAS_SECP256K1
#error "This file requires secp256k1"
#endif

/* Consume compute units for mem ops*/
static ulong fd_vm_mem_op_consume(fd_vm_exec_context_t * ctx, ulong n) {
  ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, n / vm_compute_budget.cpi_bytes_per_unit);
  return fd_vm_consume_compute_meter(ctx, cost);
}

void
fd_vm_register_syscall( fd_sbpf_syscalls_t *     syscalls,
                        char const *             name,
                        fd_sbpf_syscall_fn_ptr_t fn_ptr) {

  ulong name_len     = strlen(name);
  uint  syscall_hash = fd_murmur3_32( name, name_len, 0U );

  fd_sbpf_syscalls_t * syscall_entry = fd_sbpf_syscalls_insert( syscalls, syscall_hash );
  syscall_entry->func_ptr            = fn_ptr;
  syscall_entry->name = name;
}

static uint
is_signer( fd_pubkey_t const * account,
           fd_pubkey_t const * signers,
           ulong signers_cnt ) {
  for (ulong i = 0; i < signers_cnt; i++) {
    if (memcmp(account->uc, signers[i].uc, sizeof(fd_pubkey_t)) == 0) {
      return 1;
    }
  }
  return 0;
}

static ulong
fd_vm_prepare_instruction(
  fd_instr_info_t const * caller_instr,
  fd_instr_info_t * callee_instr,
  fd_exec_instr_ctx_t * instr_ctx,
  fd_instruction_account_t instruction_accounts[256],
  ulong * instruction_accounts_cnt,
  fd_pubkey_t const * signers,
  ulong signers_cnt
) {
  ulong deduplicated_instruction_accounts_cnt = 0;
  fd_instruction_account_t deduplicated_instruction_accounts[256];
  ulong duplicate_indicies_cnt = 0;
  ulong duplicate_indices[256];
  FD_LOG_DEBUG(("Num accounts %lu", callee_instr->acct_cnt));
  for( ulong i = 0; i < callee_instr->acct_cnt; i++ ) {
    fd_pubkey_t const * callee_pubkey = &callee_instr->acct_pubkeys[i];

    ushort index_in_transaction = USHORT_MAX;
    for( ulong j = 0; j < instr_ctx->txn_ctx->accounts_cnt; j++ ) {
      if( memcmp( instr_ctx->txn_ctx->accounts[j].uc, callee_pubkey->uc, sizeof(fd_pubkey_t) ) == 0 ) {
        index_in_transaction = (ushort)j;
        break;
      }
    }
    if( index_in_transaction == USHORT_MAX) {
      return 1;
    }

    // Check if duplicate
    ulong duplicate_index = ULONG_MAX;
    for( ulong j = 0; j < deduplicated_instruction_accounts_cnt; j++ ) {
      if( deduplicated_instruction_accounts[j].index_in_transaction == index_in_transaction ) {
        duplicate_index = j;
        break;
      }
    }
    FD_LOG_DEBUG(("Duplicate index %lu for %32J", duplicate_index, callee_pubkey->uc));
    if( duplicate_index != ULONG_MAX ) {
      duplicate_indices[duplicate_indicies_cnt++] = duplicate_index;
      fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[duplicate_index];
      instruction_account->is_signer |= !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
      instruction_account->is_writable |= !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
      FD_LOG_DEBUG(("PREP1: %32J %lu %lu %lu", callee_pubkey->uc, instruction_account->is_signer, instruction_account->is_writable, duplicate_index));
    } else {
      ushort index_in_caller = USHORT_MAX;
      for( ulong j = 0; j < caller_instr->acct_cnt; j++ ) {
        if( memcmp( caller_instr->acct_pubkeys[j].uc, callee_instr->acct_pubkeys[i].uc, sizeof(fd_pubkey_t) ) == 0 ) {
          index_in_caller = (ushort)j;
          break;
        }
      }

      if( index_in_caller == USHORT_MAX ) {
        return 1;
      }

      duplicate_indices[duplicate_indicies_cnt++] = deduplicated_instruction_accounts_cnt;
      fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[deduplicated_instruction_accounts_cnt++];
      instruction_account->index_in_callee      = (ushort)i;
      instruction_account->index_in_caller      = index_in_caller;
      instruction_account->index_in_transaction = index_in_transaction;
      instruction_account->is_signer            = !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
      instruction_account->is_writable          = !!(callee_instr->acct_flags[i] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
      FD_LOG_WARNING(( "PREP2: %32J %lu %lu %lu", callee_pubkey->uc, instruction_account->is_signer, instruction_account->is_writable, deduplicated_instruction_accounts_cnt - 1 ));
    }
  }

  for( ulong i = 0; i < deduplicated_instruction_accounts_cnt; i++ ) {
    fd_instruction_account_t * instruction_account = &deduplicated_instruction_accounts[i];
    fd_borrowed_account_t borrowed_account;
    borrowed_account.pubkey = &caller_instr->acct_pubkeys[instruction_account->index_in_caller];

    if ( FD_UNLIKELY( instruction_account->is_writable && !fd_instr_acc_is_writable(instr_ctx->instr, borrowed_account.pubkey) ) ) {
      return 1;
    }

    if ( FD_UNLIKELY( instruction_account->is_signer && !(fd_instr_acc_is_signer(instr_ctx->instr, borrowed_account.pubkey) || is_signer(borrowed_account.pubkey, signers, signers_cnt)) ) ) {
      FD_LOG_WARNING(( "PREP: %32J %lu %lu %lu %lu", borrowed_account.pubkey->uc, instruction_account->is_signer, fd_instr_acc_is_signer(instr_ctx->instr, borrowed_account.pubkey), is_signer(borrowed_account.pubkey, signers, signers_cnt), signers_cnt ));
      return 1;
    }
  }

  for (ulong i = 0; i < duplicate_indicies_cnt; i++) {
    ulong duplicate_index = duplicate_indices[i];
    if ( FD_LIKELY( duplicate_index < deduplicated_instruction_accounts_cnt ) ) {
      instruction_accounts[i] = deduplicated_instruction_accounts[duplicate_index];
      FD_LOG_DEBUG(("Final instr account %lu %lu %lu %lu", i, instruction_accounts[i].is_signer, instruction_accounts[i].is_writable, duplicate_index));
      callee_instr->acct_flags[i] |= instruction_accounts[i].is_signer ? FD_INSTR_ACCT_FLAGS_IS_SIGNER : 0;
      callee_instr->acct_flags[i] |= instruction_accounts[i].is_writable ? FD_INSTR_ACCT_FLAGS_IS_WRITABLE : 0;
    } else {
      return 1;
    }
  }

  fd_account_meta_t const * program_meta = (fd_account_meta_t const *)fd_acc_mgr_view_raw(instr_ctx->acc_mgr, instr_ctx->funk_txn, &instr_ctx->instr->program_id_pubkey, NULL, NULL);
  if ( FD_UNLIKELY( !fd_account_is_executable(instr_ctx, program_meta, NULL) ) ) {
    return 1;
  }

  *instruction_accounts_cnt = duplicate_indicies_cnt;

  return 0;
}

static void
fd_vm_syscall_register_base( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_register_syscall( syscalls, "abort",                  fd_vm_syscall_abort     );
  fd_vm_register_syscall( syscalls, "sol_panic_",             fd_vm_syscall_sol_panic );

  fd_vm_register_syscall( syscalls, "sol_log_",               fd_vm_syscall_sol_log                 );
  fd_vm_register_syscall( syscalls, "sol_log_64_",            fd_vm_syscall_sol_log_64              );
  fd_vm_register_syscall( syscalls, "sol_log_pubkey",         fd_vm_syscall_sol_log_pubkey          );
  fd_vm_register_syscall( syscalls, "sol_log_data",           fd_vm_syscall_sol_log_data            );
  fd_vm_register_syscall( syscalls, "sol_log_compute_units_", fd_vm_syscall_sol_log_compute_units   );

  fd_vm_register_syscall( syscalls, "sol_sha256",             fd_vm_syscall_sol_sha256            );
  fd_vm_register_syscall( syscalls, "sol_keccak256",          fd_vm_syscall_sol_keccak256         );

  fd_vm_register_syscall( syscalls, "sol_memcpy_",            fd_vm_syscall_sol_memcpy  );
  fd_vm_register_syscall( syscalls, "sol_memcmp_",            fd_vm_syscall_sol_memcmp  );
  fd_vm_register_syscall( syscalls, "sol_memset_",            fd_vm_syscall_sol_memset  );
  fd_vm_register_syscall( syscalls, "sol_memmove_",           fd_vm_syscall_sol_memmove );

  fd_vm_register_syscall( syscalls, "sol_invoke_signed_c",           fd_vm_syscall_cpi_c                );
  fd_vm_register_syscall( syscalls, "sol_invoke_signed_rust",        fd_vm_syscall_cpi_rust             );
  fd_vm_register_syscall( syscalls, "sol_alloc_free_",               fd_vm_syscall_sol_alloc_free       );
  fd_vm_register_syscall( syscalls, "sol_set_return_data",           fd_vm_syscall_sol_set_return_data  );
  fd_vm_register_syscall( syscalls, "sol_get_return_data",           fd_vm_syscall_sol_get_return_data  );
  fd_vm_register_syscall( syscalls, "sol_get_stack_height",          fd_vm_syscall_sol_get_stack_height );

  fd_vm_register_syscall( syscalls, "sol_get_clock_sysvar",          fd_vm_syscall_sol_get_clock_sysvar          );
  fd_vm_register_syscall( syscalls, "sol_get_epoch_schedule_sysvar", fd_vm_syscall_sol_get_epoch_schedule_sysvar );
  fd_vm_register_syscall( syscalls, "sol_get_rent_sysvar",           fd_vm_syscall_sol_get_rent_sysvar           );

  fd_vm_register_syscall( syscalls, "sol_create_program_address",            fd_vm_syscall_sol_create_program_address            );
  fd_vm_register_syscall( syscalls, "sol_try_find_program_address",          fd_vm_syscall_sol_try_find_program_address          );
  fd_vm_register_syscall( syscalls, "sol_get_processed_sibling_instruction", fd_vm_syscall_sol_get_processed_sibling_instruction );
}

static void
fd_vm_syscall_register_fees_sysvar( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_register_syscall( syscalls, "sol_get_fees_sysvar", fd_vm_syscall_sol_get_fees_sysvar );
}

static void
fd_vm_syscall_register_secp256k1( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_register_syscall( syscalls, "sol_secp256k1_recover", fd_vm_syscall_sol_secp256k1_recover );
}

static void
fd_vm_syscall_register_blake3( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_register_syscall( syscalls, "sol_blake3", fd_vm_syscall_sol_blake3 );
}

static void
fd_vm_syscall_register_curve25519( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_register_syscall( syscalls, "sol_curve_validate_point",  fd_vm_syscall_sol_curve_validate_point  );
  fd_vm_register_syscall( syscalls, "sol_curve_group_op",        fd_vm_syscall_sol_curve_group_op        );
  fd_vm_register_syscall( syscalls, "sol_curve_multiscalar_mul", fd_vm_syscall_sol_curve_multiscalar_mul );
}

void
fd_vm_syscall_register_ctx( fd_sbpf_syscalls_t *       syscalls,
                            fd_exec_slot_ctx_t const * slot_ctx ) {
  fd_vm_syscall_register_base( syscalls );
  if( !FD_FEATURE_ACTIVE( slot_ctx, disable_fees_sysvar ) )
    fd_vm_syscall_register_fees_sysvar( syscalls );
  if( FD_FEATURE_ACTIVE( slot_ctx, secp256k1_recover_syscall_enabled ) )
    fd_vm_syscall_register_secp256k1( syscalls );
  if( FD_FEATURE_ACTIVE( slot_ctx, blake3_syscall_enabled ) )
    fd_vm_syscall_register_blake3( syscalls );
  if( FD_FEATURE_ACTIVE( slot_ctx, curve25519_syscall_enabled ) )
    fd_vm_syscall_register_curve25519( syscalls );
}

void
fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_syscall_register_base       ( syscalls );
  fd_vm_syscall_register_fees_sysvar( syscalls );
  fd_vm_syscall_register_blake3     ( syscalls );
  fd_vm_syscall_register_secp256k1  ( syscalls );
  fd_vm_syscall_register_curve25519 ( syscalls );
}

ulong
fd_vm_syscall_abort(
    void * _ctx FD_PARAM_UNUSED,
    ulong arg0 FD_PARAM_UNUSED,
    ulong arg1 FD_PARAM_UNUSED,
    ulong arg2 FD_PARAM_UNUSED,
    ulong arg3 FD_PARAM_UNUSED,
    ulong arg4 FD_PARAM_UNUSED,
    ulong * ret
) {
  *ret = 0;
  return FD_VM_SYSCALL_ERR_ABORT;
}

ulong
fd_vm_syscall_sol_panic(
    void *  _ctx,
    ulong   msg_vaddr,
    ulong   msg_len,
    ulong   r3  FD_PARAM_UNUSED,
    ulong   r4  FD_PARAM_UNUSED,
    ulong   r5  FD_PARAM_UNUSED,
    ulong * pr0 FD_PARAM_UNUSED) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter(ctx, msg_len);
  if ( FD_UNLIKELY( err ) ) return err;
  /* Here, Solana Labs charges compute units, does UTF-8 validation,
     and checks for a cstr terminating NUL.  We skip all of this since
     this syscall always aborts the transaction.  The type of error
     does not matter. */

  char const * str = fd_vm_translate_vm_to_host_const( ctx, msg_vaddr, msg_len, alignof(uchar) );

  /* TODO write to log collector instead of writing to fd_log */

  if( FD_UNLIKELY( !str ) ) {
    FD_LOG_WARNING(( "sol_panic_ called with invalid string (addr=%#lx, len=%#lx)",
                     msg_vaddr, msg_len ));
    return FD_VM_SYSCALL_ERR_MEM_OVERLAP;
  }

  if( FD_UNLIKELY( msg_len > 1024UL ) )
    FD_LOG_WARNING(( "Truncating sol_panic_ message (orig %#lx bytes)", msg_len ));
  FD_LOG_HEXDUMP_DEBUG(( "sol_panic", str, msg_len ));

  return FD_VM_SYSCALL_ERR_PANIC;
}


ulong
fd_vm_syscall_sol_sha256(
    void *  _ctx,
    ulong   slices_vaddr,
    ulong   slices_cnt,
    ulong   res_vaddr,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0
) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) )
    return FD_VM_SYSCALL_ERR_INVAL;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.sha256_base_cost);
  if ( FD_UNLIKELY( err ) ) return err;
  ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices =
      fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );
  void * hash =
      fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!slices) | (!hash) ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  for( ulong i = 0; i < slices_cnt; i++ ) {
    uchar const * slice = fd_vm_translate_vm_to_host_const( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
    if( FD_UNLIKELY( !slice ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len) / 2);
    ulong err = fd_vm_consume_compute_meter(ctx, cost);
    if ( FD_UNLIKELY( err ) ) return err;

    fd_sha256_append( &sha, slice, slices[i].len );
  }

  fd_sha256_fini( &sha, hash );
  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_keccak256(
    void *  _ctx,
    ulong   slices_vaddr,
    ulong   slices_cnt,
    ulong   res_vaddr,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0
) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) )
    return FD_VM_SYSCALL_ERR_INVAL;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.sha256_base_cost);
  if ( FD_UNLIKELY( err ) ) return err;
  ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices =
      fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );
  void * hash =
      fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!slices) | (!hash) ) ) {
    return FD_VM_MEM_MAP_ERR_ACC_VIO;
  }

  fd_keccak256_t sha;
  fd_keccak256_init(&sha);

  for (ulong i = 0; i < slices_cnt; i++) {
    void const * slice = fd_vm_translate_vm_to_host_const( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
    if( FD_UNLIKELY( !slice ) ) {
      return FD_VM_MEM_MAP_ERR_ACC_VIO;
    }

    ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len / 2));
    ulong err = fd_vm_consume_compute_meter(ctx, cost);
    if ( FD_UNLIKELY( err ) ) return err;

    fd_keccak256_append( &sha, slice, slices[i].len );
  }

  fd_keccak256_fini(&sha, hash);
  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_blake3(
    void *  _ctx,
    ulong   slices_vaddr,
    ulong   slices_cnt,
    ulong   res_vaddr,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  /* TODO don't hardcode limit */
  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) )
    return FD_VM_SYSCALL_ERR_INVAL;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.sha256_base_cost);
  if ( FD_UNLIKELY( err ) ) return err;
  ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices =
      fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );
  void * hash =
      fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!slices) | (!hash) ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_blake3_t b3;
  fd_blake3_init(&b3);

  for (ulong i = 0; i < slices_cnt; i++) {
    void const * slice = fd_vm_translate_vm_to_host( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
    if( FD_UNLIKELY( !slice ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len) / 2);
    ulong err = fd_vm_consume_compute_meter(ctx, cost);
    if ( FD_UNLIKELY( err ) ) return err;

    fd_blake3_append( &b3, slice, slices[i].len );
  }

  fd_blake3_fini( &b3, hash );
  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_secp256k1_recover(
    void * _ctx,
    ulong hash_vaddr,
    ulong recovery_id_val,
    ulong signature_vaddr,
    ulong result_vaddr,
    ulong arg4 FD_PARAM_UNUSED,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.secp256k1_recover_cost);
  if ( FD_UNLIKELY( err ) ) return err;

  void const * hash = fd_vm_translate_vm_to_host_const(
    ctx,
    hash_vaddr,
    sizeof(fd_hash_t),
    alignof(uchar) );
  if( FD_UNLIKELY( !hash ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void const * signature = fd_vm_translate_vm_to_host_const(
    ctx,
    signature_vaddr,
    64,
    alignof(uchar) );
  if( FD_UNLIKELY( !hash ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void * pubkey_result = fd_vm_translate_vm_to_host(
    ctx,
    result_vaddr,
    64,
    alignof(uchar) );
  if( FD_UNLIKELY( !pubkey_result ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  if( recovery_id_val > 4 ) {
    *pr0 = 1; // Secp256k1RecoverError::InvalidRecoveryId
    return FD_VM_SYSCALL_SUCCESS;
  }

  uchar secp256k1_pubkey[64];
  if( !fd_secp256k1_recover(secp256k1_pubkey, hash, signature, (int)recovery_id_val) ) {
    *pr0 = 2; // Secp256k1RecoverError::InvalidSignature
    return FD_VM_SYSCALL_SUCCESS;
  }

  for( ulong j = 0; j < 16; ++j ) {
    uchar tmp0 = secp256k1_pubkey[31-j];
    secp256k1_pubkey[31-j] = secp256k1_pubkey[j];
    secp256k1_pubkey[j] = tmp0;

    uchar tmp1 = secp256k1_pubkey[63-j];
    secp256k1_pubkey[63-j] = secp256k1_pubkey[j+32];
    secp256k1_pubkey[j+32] = tmp1;
  }

  fd_memcpy(pubkey_result, secp256k1_pubkey, 64);
  *pr0 = 0;

  return FD_VM_SYSCALL_SUCCESS;
}


ulong
fd_vm_syscall_sol_log(
    void *  _ctx,
    ulong   msg_vm_addr,
    ulong   msg_len,
    ulong   r3 FD_PARAM_UNUSED,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter( ctx, fd_ulong_max(msg_len, vm_compute_budget.syscall_base_cost) );
  if ( FD_UNLIKELY( err ) ) return err;

  void const * msg_host_addr =
      fd_vm_translate_vm_to_host_const( ctx, msg_vm_addr, msg_len, alignof(uchar) );
  if( FD_UNLIKELY( !msg_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_log_collector_log( &ctx->log_collector, msg_host_addr, msg_len );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_64(
    void *  _ctx,
    ulong   r1,
    ulong   r2,
    ulong   r3,
    ulong   r4,
    ulong   r5,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.log_64_units );
  if ( FD_UNLIKELY( err ) ) return err;

  char msg[1024];
  int msg_len = sprintf( msg, "Program log: %lx %lx %lx %lx %lx", r1, r2, r3, r4, r5 );

  fd_vm_log_collector_log( &ctx->log_collector, msg, (ulong)msg_len );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_pubkey(
    void *  _ctx,
    ulong   pubkey_vm_addr,
    ulong   r2 FD_PARAM_UNUSED,
    ulong   r3 FD_PARAM_UNUSED,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.log_pubkey_units );
  if ( FD_UNLIKELY( err ) ) return err;

  char msg[128];
  char pubkey_str[FD_BASE58_ENCODED_32_SZ];

  void * pubkey_host_addr =
      fd_vm_translate_vm_to_host( ctx, pubkey_vm_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  if( FD_UNLIKELY( !pubkey_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_base58_encode_32( pubkey_host_addr, NULL, pubkey_str );

  int msg_len = sprintf( msg, "Program log: %s", pubkey_str );

  fd_vm_log_collector_log( &ctx->log_collector, msg, (ulong)msg_len );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_compute_units(
    void * _ctx,
    ulong arg0 FD_PARAM_UNUSED,
    ulong arg1 FD_PARAM_UNUSED,
    ulong arg2 FD_PARAM_UNUSED,
    ulong arg3 FD_PARAM_UNUSED,
    ulong arg4 FD_PARAM_UNUSED,
    FD_FN_UNUSED ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  if ( FD_UNLIKELY( !ctx)) {
    return FD_VM_SYSCALL_ERR_INVOKE_CONTEXT_BORROW_FAILED;
  }

  ulong result = fd_vm_consume_compute_meter( ctx, vm_compute_budget.syscall_base_cost );
  if (result != FD_VM_SYSCALL_SUCCESS) {
    return result;
  }

  char msg[1024];
  int msg_len = sprintf( msg, "Program consumption: %lu units remaining\n", ctx->compute_meter);

  fd_vm_log_collector_log( &ctx->log_collector, msg, (ulong)msg_len );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_data(
    void * _ctx,
    ulong vm_addr,
    ulong len,
    ulong r3 FD_PARAM_UNUSED,
    ulong r4 FD_PARAM_UNUSED,
    ulong r5 FD_PARAM_UNUSED,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.syscall_base_cost );
  if ( FD_UNLIKELY( err ) ) return err;

  ulong sz = len * sizeof (fd_vm_vec_t);

  fd_vm_vec_t const * untranslated_fields = fd_vm_translate_slice_vm_to_host_const(
    ctx,
    vm_addr,
    sz,
    FD_VM_VEC_ALIGN );

  err = fd_vm_consume_compute_meter( ctx, fd_ulong_sat_mul(vm_compute_budget.syscall_base_cost, len) );
  if ( FD_UNLIKELY( err ) ) return err;

  char msg[102400];
  ulong msg_len = (ulong) sprintf( msg, "Program data: " );

  ulong total = 0UL;
  for (ulong i = 0; i < len; ++i) {
    total += untranslated_fields[i].len;
    void const * translated_addr = fd_vm_translate_vm_to_host_const( ctx, untranslated_fields[i].addr, untranslated_fields[i].len, alignof(uchar) );
    char encoded[1024];
    ulong encoded_len = fd_base64_encode( (const uchar *) translated_addr, (int)untranslated_fields[i].len, encoded);
    if ( i !=0 ) {
      sprintf( msg + msg_len, " ");
      ++ msg_len;
    }
    memcpy( msg + msg_len, encoded, encoded_len);
    msg_len += encoded_len;
  }
  err = fd_vm_consume_compute_meter( ctx, total );
  if ( FD_UNLIKELY( err ) ) return err;

  *pr0 = 0;
  fd_vm_log_collector_log( &ctx->log_collector, msg, msg_len );
  return FD_VM_SYSCALL_SUCCESS;

}

ulong
fd_vm_syscall_sol_memcpy(
    void *  _ctx,
    ulong   dst_vm_addr,
    ulong   src_vm_addr,
    ulong   n,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0
) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_mem_op_consume(ctx, n);
  if ( FD_UNLIKELY( err ) ) return err;

  /* Check for overlap */
  if ((dst_vm_addr <= src_vm_addr && src_vm_addr < dst_vm_addr + n)
  || (src_vm_addr <= dst_vm_addr && dst_vm_addr < src_vm_addr + n))
    return FD_VM_SYSCALL_ERR_MEM_OVERLAP;

  void *       dst_host_addr =
      fd_vm_translate_vm_to_host      ( ctx, dst_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !dst_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void const * src_host_addr =
      fd_vm_translate_vm_to_host_const( ctx, src_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !src_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_memcpy(dst_host_addr, src_host_addr, n);

  *pr0 = 0;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memcmp(
    void *  _ctx,
    ulong   vm_addr1,
    ulong   vm_addr2,
    ulong   n,
    ulong   cmp_result_vm_addr,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_mem_op_consume(ctx, n);
  if ( FD_UNLIKELY( err ) ) return err;

  uchar const * host_addr1 =
      fd_vm_translate_vm_to_host_const( ctx, vm_addr1, n, alignof(uchar) );
  if( FD_UNLIKELY( !host_addr1 ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  uchar const * host_addr2 =
      fd_vm_translate_vm_to_host_const( ctx, vm_addr2, n, alignof(uchar) );
  if( FD_UNLIKELY( !host_addr2 ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  int * cmp_result_host_addr =
      fd_vm_translate_vm_to_host( ctx, cmp_result_vm_addr, sizeof(int), alignof(int) );
  if ( FD_UNLIKELY( !cmp_result_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  if( FD_UNLIKELY( (!host_addr1) | (!host_addr2) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *pr0 = 0;

  for( ulong i = 0; i < n; i++ ) {
    uchar byte1 = host_addr1[i];
    uchar byte2 = host_addr2[i];

    if( byte1 != byte2 ) {
      *cmp_result_host_addr = (int)byte1 - (int)byte2;
      break;
    }
  }
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memset(
    void *  _ctx,
    ulong   dst_vm_addr,
    ulong   c,
    ulong   n,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_mem_op_consume(ctx, n);
  if ( FD_UNLIKELY( err ) ) return err;

  void * dst_host_addr = fd_vm_translate_vm_to_host( ctx, dst_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !dst_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_memset( dst_host_addr, (int)c, n );

  *ret = 0;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memmove(
    void *  _ctx,
    ulong   dst_vm_addr,
    ulong   src_vm_addr,
    ulong   n,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_mem_op_consume(ctx, n);
  if ( FD_UNLIKELY( err ) ) return err;

  void *       dst_host_addr = fd_vm_translate_vm_to_host      ( ctx, dst_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !dst_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void const * src_host_addr = fd_vm_translate_vm_to_host_const( ctx, src_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !src_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* FIXME: use fd_memcpy here? */
  memmove( dst_host_addr, src_host_addr, n );

  *ret = 0;

  return FD_VM_SYSCALL_SUCCESS;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (Generic logic)
 **********************************************************************/

/* FD_CPI_MAX_SIGNER_CNT is the max amount of PDA signer addresses that
   a cross-program invocation can include in an instruction. */

#define FD_CPI_MAX_SIGNER_CNT (16UL)

/* fd_vm_syscall_cpi_preflight_check contains common argument checks
   for cross-program invocations.

   Solana Labs does these checks after address translation.
   We do them before to avoid length overflow.  Reordering checks can
   change the error code, but this is fine as consensus only cares about
   whether an error occurred at all or not. */

static ulong
fd_vm_syscall_cpi_preflight_check( ulong signers_seeds_cnt,
                                   ulong acct_info_cnt,
                                   fd_exec_slot_ctx_t const * slot_ctx ) {

  /* TODO use MAX_SIGNERS constant */

  if( FD_UNLIKELY( signers_seeds_cnt > FD_CPI_MAX_SIGNER_CNT ) ) {
    FD_LOG_WARNING(("TODO: return too many signers" ));
    return FD_VM_SYSCALL_ERR_INVAL;
  }

  ulong MAX_CPI_ACCOUNT_INFOS = FD_FEATURE_ACTIVE( slot_ctx, increase_tx_account_lock_limit ) ? 128UL : 64UL;

  if( FD_UNLIKELY( acct_info_cnt > MAX_CPI_ACCOUNT_INFOS ) ) {
    FD_LOG_ERR(( "TODO: return max instruction account infos exceeded" ));
    return FD_VM_SYSCALL_ERR_INVAL;
  }

  return FD_VM_SYSCALL_SUCCESS;
}

static void
fd_vm_syscall_cpi_rust_instruction_to_instr( fd_vm_exec_context_t const * ctx,
                                             fd_vm_rust_instruction_t const * cpi_instr,
                                             fd_vm_rust_account_meta_t const * cpi_acct_metas,
                                             fd_pubkey_t const * signers,
                                             ulong signers_cnt,
                                             uchar const * cpi_instr_data,
                                             fd_instr_info_t * instr ) {

  fd_pubkey_t * txn_accs = ctx->instr_ctx.txn_ctx->accounts;
  for( ulong i = 0; i < ctx->instr_ctx.txn_ctx->accounts_cnt; i++ ) {
    if( memcmp( &cpi_instr->pubkey, &txn_accs[i], sizeof( fd_pubkey_t ) )==0 ) {
      // TODO: error if not found
      FD_LOG_WARNING(( "CPI PI: %lu %32J", i, &cpi_instr->pubkey ));

      instr->program_id = (uchar)i;
      instr->program_id_pubkey = txn_accs[i];
      break;
    }
  }

  FD_LOG_WARNING(("Accounts cnt %lu %lu", ctx->instr_ctx.txn_ctx->accounts_cnt, ctx->instr_ctx.txn_ctx->txn_descriptor->acct_addr_cnt));
  for( ulong i = 0; i < cpi_instr->accounts.len; i++ ) {
    fd_vm_rust_account_meta_t const * cpi_acct_meta = &cpi_acct_metas[i];

    for( ulong j = 0; j < ctx->instr_ctx.txn_ctx->accounts_cnt; j++ ) {
      if( memcmp( &cpi_acct_meta->pubkey, &txn_accs[j], sizeof( fd_pubkey_t ) )==0 ) {
        // TODO: error if not found, if flags are wrong;
        memcpy( instr->acct_pubkeys[i].uc, cpi_acct_meta->pubkey, sizeof( fd_pubkey_t ) );
        instr->acct_txn_idxs[i] = (uchar)j;
        instr->acct_flags[i] = 0;
        instr->borrowed_accounts[i] = &ctx->instr_ctx.txn_ctx->borrowed_accounts[j];
          // TODO: should check the parent has writable flag set
        if( cpi_acct_meta->is_writable ) {
          instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
        }
        // TODO: should check the parent has signer flag set
        if( cpi_acct_meta->is_signer ) {
          instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
        } else {
          for( ulong k = 0; k < signers_cnt; k++ ) {
            if( memcmp( &signers[k], &cpi_acct_meta->pubkey, sizeof( fd_pubkey_t ) )==0 ) {
              instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
              break;
            }
          }
        }

        FD_LOG_WARNING(( "CPI ACCT: %lu %lu %u %32J %32J %x", i, j, (uchar)ctx->instr_ctx.instr->acct_txn_idxs[j], instr->acct_pubkeys[i].uc, cpi_acct_meta->pubkey, instr->acct_flags[i] ));

        break;
      }
    }
  }

  instr->data_sz = (ushort)cpi_instr->data.len;
  instr->data = (uchar *)cpi_instr_data;
  instr->acct_cnt = (ushort)cpi_instr->accounts.len;

}

/* fd_vm_syscall_cpi_check_instruction contains common instruction acct
   count and data sz checks.  Also consumes compute units proportional
   to instruction data size. */

static ulong
fd_vm_syscall_cpi_check_instruction( fd_vm_exec_context_t const * ctx,
                                     ulong                        acct_cnt,
                                     ulong                        data_sz ) {

  if( FD_FEATURE_ACTIVE( ctx->instr_ctx.slot_ctx, loosen_cpi_size_restriction ) ) {
    if( FD_UNLIKELY( data_sz > 0x2800UL ) ) {
      FD_LOG_WARNING(( "cpi: data too long (%#lx)", data_sz ));
      return FD_VM_SYSCALL_ERR_INVAL;
    }
    if( FD_UNLIKELY( acct_cnt > 0xFFUL ) ) {
      FD_LOG_WARNING(( "cpi: too many accounts (%#lx)", acct_cnt ));
      return FD_VM_SYSCALL_ERR_INVAL;
    }
  } else {
    ulong tot_sz;
    int too_long  = __builtin_umull_overflow( acct_cnt, sizeof(fd_vm_c_account_meta_t), &tot_sz );
        too_long |= __builtin_uaddl_overflow( tot_sz, data_sz, &tot_sz );
    if( FD_UNLIKELY( too_long ) ) {
      FD_LOG_WARNING(( "cpi: instruction too long (%#lx)", tot_sz ));
      return FD_VM_SYSCALL_ERR_INVAL;
    }
  }

  return FD_VM_SYSCALL_SUCCESS;
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
  *pdas = (fd_vm_syscall_pdas_t) {
    .idx  = 0UL,
    .keys = keys
  };

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
fd_vm_syscall_pda_fini( fd_vm_exec_context_t const * ctx,
                        fd_vm_syscall_pdas_t * pdas ) {
  fd_pubkey_t * pda = &pdas->keys[ pdas->idx ];

  fd_pubkey_t * txn_accs = ctx->instr_ctx.txn_ctx->accounts;

  fd_sha256_t * sha = fd_sha256_join( pdas->sha );
  fd_sha256_append( sha, &txn_accs[ ctx->instr_ctx.instr->program_id ], sizeof(fd_pubkey_t) );
  /* TODO use char const[] symbol for PDA marker */
  fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
  fd_sha256_fini  ( sha, pda->uc );
  fd_sha256_leave ( sha );

  /* A PDA is valid if is not an Ed25519 curve point */
  FD_LOG_WARNING(( "FD_VM_SCDS KEY VALIDATE: %32J", pda->key));
  if( FD_UNLIKELY(fd_ed25519_validate_public_key( pda->key ) != 0) ) return NULL;

  pdas->idx++;
  return (fd_pubkey_t const *)pda;
}

/* fd_vm_syscall_cpi_derive_signers loads a vector of PDA derive
   paths provided by the user.  Part of fd_vm_syscall_cpi_{c,rust}.
   This code was implemented twice in Solana Labs (for C and Rust ABIs
   respectively), but the logic is identical. */

static ulong
fd_vm_syscall_cpi_derive_signers_( fd_vm_exec_context_t * ctx,
                                   fd_vm_syscall_pdas_t * pdas,
                                   ulong signers_seeds_va,
                                   ulong signers_seeds_cnt ) {

  /* Translate array of seeds.  Each seed is an array of byte arrays. */
  fd_vm_vec_t const * seeds = fd_vm_translate_vm_to_host_const(
      ctx,
      signers_seeds_va,
      signers_seeds_cnt * sizeof(fd_vm_vec_t),
      FD_VM_VEC_ALIGN );
  FD_LOG_WARNING(( "FD_VM_SCDS A: %lu", signers_seeds_cnt ));
  if( FD_UNLIKELY( !seeds ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Create program addresses.
      TODO use MAX_SIGNERS constant */

  for( ulong i=0UL; i<signers_seeds_cnt; i++ ) {
    FD_LOG_WARNING(( "FD_VM_SCDS B: %lu", i ));

    /* Check seed count (avoid overflow) */
    /* TODO use constant */
    if( FD_UNLIKELY( seeds[i].len > 16UL ) ) return FD_VM_SYSCALL_ERR_INVAL;

    /* Translate inner seed slice.  Each element points to a byte array. */
    fd_vm_vec_t const * seed = fd_vm_translate_vm_to_host_const(
        ctx,
        seeds[i].addr,
        seeds[i].len * sizeof(fd_vm_vec_t),
        FD_VM_VEC_ALIGN );
    if( FD_UNLIKELY( !seed ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    /* Derive PDA */

    fd_vm_syscall_pda_next( pdas );

    FD_LOG_WARNING(( "FD_VM_SCDS C: %lu %lu", i, seeds->len ));
    for( ulong j=0UL; j < seeds->len; j++ ) {
      FD_LOG_WARNING(( "FD_VM_SCDS D: %lu %lu", i, j ));
      /* Check seed limb length */
      /* TODO use constant */
      if( FD_UNLIKELY( seed[j].len > 32 ) ) return FD_VM_SYSCALL_ERR_INVAL;

      /* Translate inner seed limb (type &[u8]) */
      uchar const * seed_limb = fd_vm_translate_vm_to_host_const(
          ctx,
          seed[j].addr,
          seed[j].len,
          alignof(uchar) );
      if( FD_UNLIKELY( !seed_limb ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

      fd_vm_syscall_pda_seed_append( pdas, seed_limb, seed[j].len );
    }

    if( FD_UNLIKELY( !fd_vm_syscall_pda_fini( ctx, pdas ) ) )
      return FD_VM_SYSCALL_ERR_INVAL;

    FD_LOG_WARNING(( "FD_VM_SCDS KEY: %lu %32J", i, &pdas->keys[pdas->idx-1] ));
  }

  return FD_VM_SYSCALL_SUCCESS;
}

static ulong
fd_vm_syscall_cpi_derive_signers( fd_vm_exec_context_t * ctx,
                                  fd_pubkey_t *          out,
                                  ulong                  signers_seeds_va,
                                  ulong                  signers_seeds_cnt ) {

  fd_vm_syscall_pdas_t _pdas[1];
  fd_vm_syscall_pdas_t * pdas = fd_vm_syscall_pdas_join( fd_vm_syscall_pdas_new( _pdas, out ) );

  if( signers_seeds_cnt>0UL ) {
    ulong res = fd_vm_syscall_cpi_derive_signers_( ctx, pdas, signers_seeds_va, signers_seeds_cnt );
    if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;
  }

  fd_vm_syscall_pdas_delete( fd_vm_syscall_pdas_leave( pdas ) );
  return FD_VM_SYSCALL_SUCCESS;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (C ABI)
 **********************************************************************/

/* fd_vm_syscall_cpi_c implements Solana VM syscall sol_invoked_signed_c. */

ulong
fd_vm_syscall_cpi_c(
    void *  _ctx,
    ulong   instruction_va,
    ulong   acct_infos_va,
    ulong   acct_info_cnt,
    ulong   signers_seeds_va,
    ulong   signers_seeds_cnt,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.invoke_units);
  if ( FD_UNLIKELY( err ) ) return err;
  /* Pre-flight checks ************************************************/

  ulong res = fd_vm_syscall_cpi_preflight_check( signers_seeds_cnt, acct_info_cnt, ctx->instr_ctx.slot_ctx);
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* Translate instruction ********************************************/

  fd_vm_c_instruction_t const * instruction =
    fd_vm_translate_vm_to_host_const(
      ctx,
      instruction_va,
      sizeof(fd_vm_c_instruction_t),
      FD_VM_C_INSTRUCTION_ALIGN );
  if( FD_UNLIKELY( !instruction ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_c_account_meta_t const * accounts =
    fd_vm_translate_vm_to_host_const(
      ctx,
      acct_infos_va,
      acct_info_cnt * sizeof(fd_vm_c_account_meta_t),
      FD_VM_C_ACCOUNT_META_ALIGN );
  if( FD_UNLIKELY( !accounts ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  uchar const * data = fd_vm_translate_vm_to_host_const(
      ctx,
      instruction->data.addr,
      instruction->data.len,
      alignof(uchar) );
  if( FD_UNLIKELY( !data ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Instruction checks ***********************************************/

  res = fd_vm_syscall_cpi_check_instruction( ctx, instruction->accounts.len, instruction->data.len );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* Translate signers ************************************************/

  /* Order of operations is liberally rearranged.
     For inputs that cause multiple errors, this means that Solana Labs
     and Firedancer may return different error codes (as we abort at the
     first error).  (See above) */

  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  res = fd_vm_syscall_cpi_derive_signers( ctx, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* TODO: Dispatch CPI to executor.
           For now, we'll just log parameters. */

  FD_LOG_WARNING(( "TODO implement CPIs" ));
  *pr0 = 0UL;
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (Rust ABI)
 **********************************************************************/


static ulong
fd_vm_cpi_update_caller_account( fd_vm_exec_context_t * ctx,
                                 fd_vm_rust_account_info_t const * caller_acc_info,
                                 fd_pubkey_t const * callee_acc_pubkey ) {
  FD_BORROWED_ACCOUNT_DECL(callee_acc_rec);
  int err = fd_acc_mgr_view(ctx->instr_ctx.acc_mgr, ctx->instr_ctx.funk_txn, callee_acc_pubkey, callee_acc_rec);
  ulong updated_lamports, data_len;
  uchar const * updated_owner = NULL;
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "account missing while updating CPI caller account - key: %32J", callee_acc_pubkey ));
    // TODO: do we need to do something anyways
    updated_lamports = 0;
    data_len = 0;
  } else {
    updated_lamports = callee_acc_rec->const_meta->info.lamports;
    data_len = callee_acc_rec->const_meta->dlen;
    updated_owner = callee_acc_rec->const_meta->info.owner;
  }

  fd_vm_rc_refcell_t const * caller_acc_lamports_box = fd_vm_translate_vm_to_host_const(
    ctx,
    caller_acc_info->lamports_box_addr,
    sizeof(fd_vm_rc_refcell_t),
    FD_VM_RC_REFCELL_ALIGN );
  if( FD_UNLIKELY( !caller_acc_lamports_box ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  ulong * caller_acc_lamports = fd_vm_translate_vm_to_host(
    ctx,
    caller_acc_lamports_box->addr,
    sizeof(ulong),
    alignof(ulong) );
  if( FD_UNLIKELY( !caller_acc_lamports_box ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  *caller_acc_lamports = updated_lamports;

  fd_vm_rc_refcell_vec_t * caller_acc_data_box = fd_vm_translate_vm_to_host(
    ctx,
    caller_acc_info->data_box_addr,
    sizeof(fd_vm_rc_refcell_vec_t),
    FD_VM_RC_REFCELL_ALIGN );
  if( FD_UNLIKELY( !caller_acc_data_box ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  uchar * caller_acc_data = fd_vm_translate_vm_to_host(
    ctx,
    caller_acc_data_box->addr,
    caller_acc_data_box->len,
    alignof(uchar) );
  if( FD_UNLIKELY( !caller_acc_data ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  uchar * caller_acc_owner = fd_vm_translate_vm_to_host(
    ctx,
    caller_acc_info->owner_addr,
    sizeof(fd_pubkey_t),
    alignof(uchar) );
  if (updated_owner) {
    fd_memcpy( caller_acc_owner, updated_owner, sizeof(fd_pubkey_t) );
  } else {
    fd_memset( caller_acc_owner, 0, sizeof(fd_pubkey_t) );
  }

  // TODO: deal with all functionality in update_caller_account
  if (data_len == 0) {
   fd_memset(caller_acc_data, 0, caller_acc_data_box->len);
  }
  if( caller_acc_data_box->len != data_len ) {
    FD_LOG_WARNING(( "account size mismatch while updating CPI caller account - key: %32J, caller: %lu, callee: %lu", callee_acc_pubkey, caller_acc_data_box->len, data_len ));

    caller_acc_data_box->len = data_len;
    ulong * caller_len = fd_vm_translate_vm_to_host(
      ctx,
      fd_ulong_sat_sub(caller_acc_data_box->addr, sizeof(ulong)),
      sizeof(ulong),
      alignof(ulong)
    );
    *caller_len = data_len;
    // TODO return instruction error account data size too small.
  }

  fd_memcpy( caller_acc_data, callee_acc_rec->const_data, data_len );

  return 0;
}

FD_FN_UNUSED static ulong
fd_vm_cpi_update_callee_account( fd_vm_exec_context_t * ctx,
                                 fd_caller_account_t const * caller_account,
                                 fd_pubkey_t const * callee_acc_pubkey ) {
  int modify_result = 0;
  uchar * raw_callee_acc_data = fd_acc_mgr_modify_raw( ctx->instr_ctx.acc_mgr, ctx->instr_ctx.funk_txn, callee_acc_pubkey, 0, 0UL, NULL, NULL, &modify_result );
  if (FD_UNLIKELY(raw_callee_acc_data == NULL)) {
    FD_LOG_WARNING(( "account missing while updating CPI callee account - key: %32J", callee_acc_pubkey ));
    // TODO: do we need to do something anyways?
    return 0;
  }

  fd_account_meta_t * callee_acc_metadata = (fd_account_meta_t *)raw_callee_acc_data;

  uchar * callee_acc_data = fd_account_get_data( callee_acc_metadata );

  uint is_disable_cpi_setting_executable_and_rent_epoch_active = FD_FEATURE_ACTIVE(ctx->instr_ctx.slot_ctx, disable_cpi_setting_executable_and_rent_epoch);
  if (callee_acc_metadata->info.lamports != caller_account->lamports) {
    callee_acc_metadata->info.lamports = caller_account->lamports;
  }

  int err1;
  int err2;
  if (fd_account_can_data_be_resized(&ctx->instr_ctx, callee_acc_metadata, caller_account->serialized_data_len, &err1)
      && fd_account_can_data_be_changed(&ctx->instr_ctx, callee_acc_metadata, callee_acc_pubkey, &err2)) {
    // if ( FD_UNLIKELY( err1 || err2 ) ) {
    //   return 1;
    // }
    callee_acc_metadata->dlen = caller_account->serialized_data_len;
    fd_memcpy( callee_acc_data, caller_account->serialized_data, callee_acc_metadata->dlen );
  }

  if (!is_disable_cpi_setting_executable_and_rent_epoch_active &&
      fd_account_is_executable(&ctx->instr_ctx, callee_acc_metadata, NULL) != caller_account->executable) {
    fd_pubkey_t const * program_acc = &ctx->instr_ctx.instr->acct_pubkeys[ctx->instr_ctx.instr->program_id];
    fd_account_set_executable(&ctx->instr_ctx, program_acc, callee_acc_metadata, (char)caller_account->executable);
  }

  if (memcmp(callee_acc_metadata->info.owner, caller_account->owner.uc, sizeof(fd_pubkey_t))) {
    fd_memcpy(callee_acc_metadata->info.owner, caller_account->owner.uc, sizeof(fd_pubkey_t));
  }

  if (!is_disable_cpi_setting_executable_and_rent_epoch_active &&
      callee_acc_metadata->info.rent_epoch != caller_account->rent_epoch) {
    if (FD_UNLIKELY( FD_FEATURE_ACTIVE(ctx->instr_ctx.slot_ctx, enable_early_verification_of_account_modifications))) {
      return 1;
    } else {
      callee_acc_metadata->info.rent_epoch = caller_account->rent_epoch;
    }
  }
  return 0;
}

static bool check_id(const uchar * program_id, uchar * loader) {
  return memcmp(program_id, loader, sizeof(fd_pubkey_t)) == 0;
}

static bool is_precompile(const uchar * program_id) {
  return check_id(program_id, fd_solana_keccak_secp_256k_program_id.key) ||
         check_id(program_id, fd_solana_ed25519_sig_verify_program_id.key);
}

static ulong check_authorized_program(const uchar * program_id, fd_exec_slot_ctx_t * slot_ctx, uchar const * instruction_data, ulong instruction_data_len) {
  return ( check_id(program_id, fd_solana_native_loader_id.key) ||
       check_id(program_id, fd_solana_bpf_loader_program_id.key) ||
       check_id(program_id, fd_solana_bpf_loader_deprecated_program_id.key) ||
       (check_id(program_id, fd_solana_bpf_loader_upgradeable_program_id.key) &&
       ((instruction_data_len == 0 || instruction_data[0] != 3) ||
       (instruction_data_len != 0 && instruction_data[0] == 4) ||
       (FD_FEATURE_ACTIVE(slot_ctx, enable_bpf_loader_set_authority_checked_ix) && (instruction_data_len != 0 && instruction_data[0] == 4))
       || (instruction_data_len != 0 && instruction_data[0] == 5)))
       || is_precompile(program_id));

}

static ulong
from_account_info(
    fd_vm_exec_context_t * ctx,
    fd_vm_rust_account_info_t const * account_info,
    fd_caller_account_t * out
) {
  fd_vm_rc_refcell_t const * caller_acc_lamports_box = fd_vm_translate_vm_to_host_const(
    ctx,
    account_info->lamports_box_addr,
    sizeof(fd_vm_rc_refcell_t),
    FD_VM_RC_REFCELL_ALIGN );
  if( FD_UNLIKELY( !caller_acc_lamports_box ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  ulong * caller_acc_lamports = fd_vm_translate_vm_to_host(
    ctx,
    caller_acc_lamports_box->addr,
    sizeof(ulong),
    alignof(ulong) );
  if( FD_UNLIKELY( !caller_acc_lamports_box ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  out->lamports = *caller_acc_lamports;

  uchar * caller_acc_owner = fd_vm_translate_vm_to_host(
    ctx,
    account_info->owner_addr,
    sizeof(fd_pubkey_t),
    alignof(uchar) );

  fd_memcpy(out->owner.uc, caller_acc_owner, sizeof(fd_pubkey_t));

  fd_vm_rc_refcell_vec_t * caller_acc_data_box = fd_vm_translate_vm_to_host(
    ctx,
    account_info->data_box_addr,
    sizeof(fd_vm_rc_refcell_vec_t),
    FD_VM_RC_REFCELL_ALIGN );
  if( FD_UNLIKELY( !caller_acc_data_box ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  ulong err = fd_vm_consume_compute_meter( ctx, caller_acc_data_box->len / vm_compute_budget.cpi_bytes_per_unit );
  if ( FD_UNLIKELY( err ) ) return err;

  uchar * caller_acc_data = fd_vm_translate_vm_to_host(
    ctx,
    caller_acc_data_box->addr,
    caller_acc_data_box->len,
    alignof(uchar) );
  if( FD_UNLIKELY( !caller_acc_data ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  out->serialized_data = caller_acc_data;
  out->serialized_data_len = caller_acc_data_box->len;
  out->executable = account_info->executable;
  out->rent_epoch = account_info->rent_epoch;
  return 0;
}

static ulong
translate_and_update_accounts(
    fd_vm_exec_context_t * ctx,
    fd_instruction_account_t * instruction_accounts,
    ulong instruction_accounts_cnt,
    fd_pubkey_t const * account_info_keys,
    fd_vm_rust_account_info_t const * account_infos,
    ulong account_info_cnt,
    ulong * out_callee_indices,
    ulong * out_caller_indices,
    ulong * out_len
) {

  for (ulong i = 0; i < instruction_accounts_cnt; i++) {
    if( i != instruction_accounts[i].index_in_callee ) {
      continue;
    }
    fd_pubkey_t const * callee_account = &ctx->instr_ctx.instr->acct_pubkeys[instruction_accounts[i].index_in_caller];
    fd_pubkey_t const * account_key = &ctx->instr_ctx.txn_ctx->accounts[instruction_accounts[i].index_in_transaction];
    fd_account_meta_t const * acc_meta = (fd_account_meta_t const *)fd_acc_mgr_view_raw(ctx->instr_ctx.acc_mgr, ctx->instr_ctx.funk_txn, callee_account, NULL, NULL);

    if (acc_meta && fd_account_is_executable(&ctx->instr_ctx, acc_meta, NULL)) {
      FD_LOG_WARNING(("CPI Acc data len %lu", acc_meta->dlen));
      ulong err = fd_vm_consume_compute_meter( ctx, acc_meta->dlen / vm_compute_budget.cpi_bytes_per_unit );
      if ( FD_UNLIKELY( err ) ) return err;
    } else {
      uint found = 0;
      for (ulong j = 0; j < account_info_cnt; j++) {
        if (memcmp(account_key->uc, account_info_keys[j].uc, sizeof(fd_pubkey_t)) == 0) {
          fd_caller_account_t caller_account;
          ulong err = from_account_info(ctx, &account_infos[j], &caller_account);
          if ( FD_UNLIKELY( err ) ) {
            return err;
          }
          FD_LOG_WARNING(("CPI Acc data len %lu for %32J", caller_account.serialized_data_len, account_key->uc));
          if( FD_UNLIKELY( acc_meta && fd_vm_cpi_update_callee_account(ctx, &caller_account, callee_account) ) ) {
            return 1001;
          }

          if (instruction_accounts[i].is_writable) {
            out_callee_indices[*out_len] = instruction_accounts[i].index_in_caller;
            out_caller_indices[*out_len] = j;
            (*out_len)++;
          }
          found = 1;
        }
      }
      if (!found) {
        return 1002;
      }
    }
  }
  return 0;
}

ulong
fd_vm_syscall_cpi_rust(
    void *  _ctx,
    ulong   instruction_va,
    ulong   acct_infos_va,
    ulong   acct_info_cnt,
    ulong   signers_seeds_va,
    ulong   signers_seeds_cnt,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.invoke_units);
  if ( FD_UNLIKELY( err ) ) return err;

  /* Pre-flight checks ************************************************/

  ulong res = fd_vm_syscall_cpi_preflight_check( signers_seeds_cnt, acct_info_cnt, ctx->instr_ctx.slot_ctx );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* Translate instruction ********************************************/

  fd_vm_rust_instruction_t const * instruction =
    fd_vm_translate_vm_to_host_const(
      ctx,
      instruction_va,
      sizeof(fd_vm_rust_instruction_t),
      FD_VM_RUST_INSTRUCTION_ALIGN );
  if( FD_UNLIKELY( !instruction ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    /* Translate signers ************************************************/

  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  res = fd_vm_syscall_cpi_derive_signers( ctx, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  fd_vm_rust_account_meta_t const * accounts =
    fd_vm_translate_vm_to_host_const(
      ctx,
      instruction->accounts.addr,
      instruction->accounts.len * sizeof(fd_vm_rust_account_meta_t),
      FD_VM_RUST_ACCOUNT_META_ALIGN );
  if( FD_UNLIKELY( !accounts ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  uchar const * data = fd_vm_translate_vm_to_host_const(
      ctx,
      instruction->data.addr,
      instruction->data.len,
      alignof(uchar) );
  if( FD_UNLIKELY( !data ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  if ( FD_UNLIKELY( check_authorized_program(instruction->pubkey, ctx->instr_ctx.slot_ctx, data, instruction->data.len) ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  /* Instruction checks ***********************************************/

  res = fd_vm_syscall_cpi_check_instruction( ctx, instruction->accounts.len, instruction->data.len );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* Translate account infos ******************************************/

  fd_vm_rust_account_info_t const * acc_infos =
    fd_vm_translate_vm_to_host_const(
      ctx,
      acct_infos_va,
      acct_info_cnt * sizeof(fd_vm_rust_account_info_t),
      FD_VM_RUST_ACCOUNT_INFO_ALIGN );
  if( FD_UNLIKELY( !acc_infos ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Collect pubkeys */

  fd_pubkey_t acct_keys[ acct_info_cnt ];  /* FIXME get rid of VLA */
  for( ulong i=0UL; i<acct_info_cnt; i++ ) {
    fd_pubkey_t const * acct_addr = fd_vm_translate_vm_to_host_const(
        ctx,
        acc_infos[i].pubkey_addr,
        sizeof(fd_pubkey_t),
        alignof(uchar) );
    FD_LOG_WARNING(( "CPI9: %lu %lx", i, acc_infos[i].pubkey_addr ));
    if( FD_UNLIKELY( !acct_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
    memcpy( acct_keys[i].uc, acct_addr->uc, sizeof(fd_pubkey_t) );
  }

  /* TODO: Dispatch CPI to executor.
           For now, we'll just log parameters. */

  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;
  fd_instr_info_t cpi_instr;

  fd_vm_syscall_cpi_rust_instruction_to_instr( ctx, instruction, accounts, signers, signers_seeds_cnt, data, &cpi_instr );
  err = fd_vm_prepare_instruction(ctx->instr_ctx.instr, &cpi_instr, &ctx->instr_ctx, instruction_accounts, &instruction_accounts_cnt, signers, signers_seeds_cnt );
  if( err != 0 ) {
    return err;
  }

  ulong callee_account_keys[256];
  ulong caller_accounts_to_update[256];
  ulong update_len = 0;

  err = translate_and_update_accounts(ctx, instruction_accounts, instruction_accounts_cnt, acct_keys, acc_infos, acct_info_cnt, callee_account_keys, caller_accounts_to_update, &update_len);
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(("translate failed %lu", err));
    return err;
  }

  ctx->instr_ctx.txn_ctx->compute_meter = ctx->compute_meter;
  int err_exec = fd_execute_instr( &cpi_instr, ctx->instr_ctx.txn_ctx );
  ulong instr_exec_res = (ulong)err_exec;
  FD_LOG_WARNING(( "CPI CUs CONSUMED: %lu %lu %lu ", ctx->compute_meter, ctx->instr_ctx.txn_ctx->compute_meter, ctx->compute_meter - ctx->instr_ctx.txn_ctx->compute_meter));
  ctx->compute_meter = ctx->instr_ctx.txn_ctx->compute_meter;
  FD_LOG_WARNING(( "AFTER CPI: %lu CUs: %lu Err: %d", *pr0, ctx->compute_meter, err_exec ));

  *pr0 = instr_exec_res;
  if( instr_exec_res != 0) {
    return FD_VM_SYSCALL_ERR_INSTR_ERR;
  }

  for( ulong i = 0; i < update_len; i++ ) {
    fd_pubkey_t const * callee = &ctx->instr_ctx.instr->acct_pubkeys[callee_account_keys[i]];
    res = fd_vm_cpi_update_caller_account(ctx, &acc_infos[caller_accounts_to_update[i]], callee);
    if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;
  }

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_alloc_free( void * _ctx,
                              ulong sz,
                              ulong free_addr,
                              FD_FN_UNUSED ulong r3,
                              FD_FN_UNUSED ulong r4,
                              FD_FN_UNUSED ulong r5,
                              ulong * ret ) {
  fd_vm_exec_context_t * ctx     = (fd_vm_exec_context_t *) _ctx;
  /* Value to return */
  ulong r0 = 0UL;

  ulong align = ctx->check_align ? 8UL : 1UL;

  fd_vm_heap_allocator_t * alloc = &ctx->alloc;

  /* Non-zero free address implies that this is a free() call.
     However, we provide a bump allocator, so free is a no-op. */

  if( free_addr ) goto fini;

  /* Rest of function provides malloc() ... */

  ulong pos   = fd_ulong_align_up( alloc->offset, align );
  ulong vaddr = fd_ulong_sat_add ( pos,           FD_VM_MEM_MAP_HEAP_REGION_START );
        pos   = fd_ulong_sat_add ( pos,           sz    );

  /* Bail if allocation overruns heap size */

  if( FD_UNLIKELY( pos > ctx->heap_sz ) ) goto fini;

  /* Success. Return virtual address of allocation and update allocator */

  r0            = vaddr;
  alloc->offset = pos;

fini:
  *ret = r0;
  return FD_VM_SYSCALL_SUCCESS;
}

static uint is_nonoverlapping(ulong src, ulong src_len, ulong dst, ulong dst_len) {
  if (src > dst) {
    return (uint) (fd_ulong_sat_sub(src, dst) >= dst_len);
  } else {
    return (uint) (fd_ulong_sat_sub(dst, src) >= src_len);
  }
}

ulong
fd_vm_syscall_sol_get_return_data(
    void *  _ctx,
    ulong   return_data_addr,
    ulong   length,
    ulong   program_id_addr,
    ulong   arg3  FD_PARAM_UNUSED,
    ulong   arg4  FD_PARAM_UNUSED,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.syscall_base_cost);
  if ( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_transaction_return_data_t * return_data = &ctx->instr_ctx.txn_ctx->return_data;
  length = fd_ulong_min(length, return_data->len);

  if (FD_LIKELY(length != 0)) {
    ulong cost = fd_ulong_sat_add(length, sizeof(fd_pubkey_t)) / vm_compute_budget.cpi_bytes_per_unit;
    err = fd_vm_consume_compute_meter(ctx, cost);
    if ( FD_UNLIKELY( err ) ) {
      return err;
    }

    uchar * return_data_result = fd_vm_translate_vm_to_host(
      ctx,
      return_data_addr,
      length,
      alignof(uchar)
    );
    if (FD_UNLIKELY( !return_data_result )) {
      return FD_VM_MEM_MAP_ERR_ACC_VIO;
    }

    // Copy over return data
    fd_memcpy(return_data_result, return_data->data, length);
    fd_pubkey_t * program_id_result = fd_vm_translate_vm_to_host(
      ctx,
      program_id_addr,
      sizeof(fd_pubkey_t),
      alignof(fd_pubkey_t)
    );
    if (FD_UNLIKELY( !program_id_result)) {
      return FD_VM_MEM_MAP_ERR_ACC_VIO;
    }

    if (!is_nonoverlapping((ulong)return_data_result, length, (ulong)program_id_result, sizeof(fd_pubkey_t))) {
      return FD_VM_SYSCALL_ERR_MEM_OVERLAP;
    }
    fd_memcpy(program_id_result->uc, return_data->program_id.uc, sizeof(fd_pubkey_t));
  }

  *ret = return_data->len;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_set_return_data(
    void *  _ctx,
    ulong   addr,
    ulong   len,
    ulong   arg2  FD_PARAM_UNUSED,
    ulong   arg3  FD_PARAM_UNUSED,
    ulong   arg4  FD_PARAM_UNUSED,
    ulong * ret   FD_PARAM_UNUSED
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong cost = fd_ulong_sat_add(len / vm_compute_budget.cpi_bytes_per_unit, vm_compute_budget.syscall_base_cost);
  ulong err = fd_vm_consume_compute_meter(ctx, cost);
  if ( FD_UNLIKELY( err ) ) {
    return err;
  }

  if ( FD_UNLIKELY( len > MAX_RETURN_DATA ) ) {
    return FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE;
  }

  uchar const * return_data = fd_vm_translate_vm_to_host_const(
    ctx,
    addr,
    len,
    alignof(uchar)
  );
  if (FD_UNLIKELY( !return_data )) {
    return FD_VM_MEM_MAP_ERR_ACC_VIO;
  }

  fd_pubkey_t const * program_id = &ctx->instr_ctx.instr->program_id_pubkey;
  fd_memcpy(ctx->instr_ctx.txn_ctx->return_data.program_id.uc, program_id->uc, sizeof(fd_pubkey_t));
  ctx->instr_ctx.txn_ctx->return_data.len = len;
  if (len != 0) {
    fd_memcpy(ctx->instr_ctx.txn_ctx->return_data.data, return_data, len);
  }
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_stack_height(
    void *  _ctx,
    ulong   arg0  FD_PARAM_UNUSED,
    ulong   arg1  FD_PARAM_UNUSED,
    ulong   arg2  FD_PARAM_UNUSED,
    ulong   arg3  FD_PARAM_UNUSED,
    ulong   arg4  FD_PARAM_UNUSED,
    ulong * ret ) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.syscall_base_cost);
  if ( FD_UNLIKELY( err ) ) return err;

  *ret = ctx->stack.frames_used;

  return FD_VM_SYSCALL_SUCCESS;
}

/**********************************************************************
   SYSVAR GETTERS
 **********************************************************************/

ulong
fd_vm_syscall_sol_get_clock_sysvar(
    void *  _ctx,
    ulong   out_addr,
    ulong   r2 FD_PARAM_UNUSED,
    ulong   r3 FD_PARAM_UNUSED,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  FD_TEST( ctx->instr_ctx.instr );  /* TODO */

  ulong err = fd_vm_consume_compute_meter( ctx, fd_ulong_sat_add( vm_compute_budget.sysvar_base_cost, sizeof(fd_sol_sysvar_clock_t) ) );
  if ( FD_UNLIKELY( err ) ) return err;

  fd_sol_sysvar_clock_t clock;
  fd_sol_sysvar_clock_new( &clock );
  fd_sysvar_clock_read( ctx->instr_ctx.slot_ctx, &clock );

  void * out = fd_vm_translate_vm_to_host(
      ctx,
      out_addr,
      sizeof(fd_sol_sysvar_clock_t),
      FD_SOL_SYSVAR_CLOCK_ALIGN );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  memcpy( out, &clock, sizeof(fd_sol_sysvar_clock_t ) );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_epoch_schedule_sysvar(
    void *  _ctx,
    ulong   out_addr,
    ulong   r2 FD_PARAM_UNUSED,
    ulong   r3 FD_PARAM_UNUSED,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  FD_TEST( ctx->instr_ctx.instr );  /* TODO */

  ulong err = fd_vm_consume_compute_meter( ctx, fd_ulong_sat_add( vm_compute_budget.sysvar_base_cost, sizeof(fd_epoch_schedule_t) ) );
  if ( FD_UNLIKELY( err ) ) return err;

  fd_epoch_schedule_t schedule;
  fd_epoch_schedule_new( &schedule );
  fd_sysvar_epoch_schedule_read( ctx->instr_ctx.slot_ctx, &schedule );

  void * out = fd_vm_translate_vm_to_host(
      ctx,
      out_addr,
      sizeof(fd_epoch_schedule_t),
      FD_EPOCH_SCHEDULE_ALIGN );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  memcpy( out, &schedule, sizeof(fd_epoch_schedule_t) );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_fees_sysvar(
    void *  _ctx,
    ulong   out_addr,
    ulong   r2 FD_PARAM_UNUSED,
    ulong   r3 FD_PARAM_UNUSED,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  FD_TEST( ctx->instr_ctx.instr );  /* TODO */

  ulong err = fd_vm_consume_compute_meter( ctx, fd_ulong_sat_add( vm_compute_budget.sysvar_base_cost, sizeof(fd_sysvar_fees_t) ) );
  if ( FD_UNLIKELY( err ) ) return err;

  fd_sysvar_fees_t fees;
  fd_sysvar_fees_new( &fees );
  fd_sysvar_fees_read( ctx->instr_ctx.slot_ctx, &fees );

  void * out = fd_vm_translate_vm_to_host(
      ctx,
      out_addr,
      sizeof(fd_sysvar_fees_t),
      FD_SYSVAR_FEES_ALIGN );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  memcpy( out, &fees, sizeof(fd_sysvar_fees_t) );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_rent_sysvar(
    void *  _ctx,
    ulong   out_addr,
    ulong   r2 FD_PARAM_UNUSED,
    ulong   r3 FD_PARAM_UNUSED,
    ulong   r4 FD_PARAM_UNUSED,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  FD_TEST( ctx->instr_ctx.instr );  /* TODO */

  ulong err = fd_vm_consume_compute_meter( ctx, fd_ulong_sat_add( vm_compute_budget.sysvar_base_cost, sizeof(fd_rent_t) ) );
  if ( FD_UNLIKELY( err ) ) return err;

  fd_rent_t rent;
  fd_rent_new( &rent );
  fd_sysvar_rent_read( ctx->instr_ctx.slot_ctx, &rent );

  void * out = fd_vm_translate_vm_to_host(
      ctx,
      out_addr,
      sizeof(fd_rent_t),
      FD_RENT_ALIGN );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  memcpy( out, &rent, sizeof(fd_rent_t) );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

/**********************************************************************
   PROGRAM DERIVED ADDRESSES
 **********************************************************************/

/* fd_vm_partial_derive_address begins the SHA calculation for a program
   derived account address.  sha is an uninitialized, joined SHA state
   object. program_id_vaddr points to the program address in VM address
   space. seeds_vaddr points to the first element of an iovec-like
   scatter of a seed byte array (&[&[u8]]) in VM address space.
   seed_cnt is the number of scatter elems.  Returns in-flight sha
   calculation on success.  On failure, returns NULL.  Reasons for
   failure include out-of-bounds memory access or invalid seed list. */

static fd_sha256_t *
fd_vm_partial_derive_address( fd_vm_exec_context_t * ctx,
                              fd_sha256_t *          sha,
                              ulong                  program_id_vaddr,
                              ulong                  seeds_vaddr,
                              ulong                  seeds_cnt,
                              uchar *                bump_seed ) {

  /* TODO use constant macro */
  if( FD_UNLIKELY( seeds_cnt > 16UL ) ) return NULL;

  /* Translate program ID address */

  fd_pubkey_t const * program_id = fd_vm_translate_vm_to_host_const(
      ctx,
      program_id_vaddr,
      sizeof(fd_pubkey_t),
      alignof(uchar) );

  /* Translate seed scatter array address */

  fd_vm_vec_t const * seeds = fd_vm_translate_vm_to_host_const(
      ctx,
      seeds_vaddr,
      /* no overflow, as fd_vm_vec_t<=16UL */
      seeds_cnt * sizeof(fd_vm_rust_vec_t),
      FD_VM_VEC_ALIGN );

  /* Bail if translation fails */

  if( FD_UNLIKELY( ( !program_id )
                 | ( !seeds      ) ) ) return NULL;

  /* Start hashing */

  fd_sha256_init( sha );

  for( ulong i=0UL; i<seeds_cnt; i++ ) {

    /* Refuse to hash overlong parts */

    if( FD_UNLIKELY( seeds[ i ].len > 32UL ) ) return NULL;

    /* Translate seed */

    void const * seed_part = fd_vm_translate_vm_to_host_const(
        ctx,
        seeds[ i ].addr,
        seeds[ i ].len,
        alignof(uchar) );
    if( FD_UNLIKELY( !seed_part ) ) return NULL;

    /* Append to hash (gather) */

    fd_sha256_append( sha, seed_part, seeds[ i ].len );

  }

  if( bump_seed != NULL ) {
    fd_sha256_append( sha, bump_seed, 1UL );
  }

  fd_sha256_append( sha, program_id, sizeof(fd_pubkey_t) );

  return sha;
}

ulong
fd_vm_syscall_sol_create_program_address(
    void *  _ctx,
    ulong   seeds_vaddr,
    ulong   seeds_cnt,
    ulong   program_id_vaddr,
    ulong   out_vaddr,
    ulong   r5 FD_PARAM_UNUSED,
    ulong * ret )  {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *)_ctx;
  ulong r0 = 1UL;  /* 1 implies fail */

  /* Charge CUs */
  ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.create_program_address_units );
  if ( FD_UNLIKELY( err ) ) return err;
  /* Calculate PDA */

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  if( FD_UNLIKELY( !fd_vm_partial_derive_address( ctx, sha, program_id_vaddr, seeds_vaddr, seeds_cnt, NULL ) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_pubkey_t result;
  fd_sha256_append( sha, "ProgramDerivedAddress", 21L );
  fd_sha256_fini( sha, &result );

  /* Return failure if PDA overlaps with a valid curve point */

  if( FD_UNLIKELY( fd_ed25519_validate_public_key( &result ) ) )
    goto fini;

  /* Translate output address
     Cannot reorder - Out may be an invalid pointer if PDA is invalid */

  fd_pubkey_t * out = fd_vm_translate_vm_to_host(
      ctx,
      out_vaddr,
      sizeof(fd_pubkey_t),
      alignof(uchar) );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Write result into out */

  memcpy( out, result.uc, sizeof(fd_pubkey_t) );
  r0 = 0UL; /* success */

fini:
  fd_sha256_delete( fd_sha256_leave( sha ) );
  *ret = r0;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_try_find_program_address(
    void *  _ctx,
    ulong   seeds_vaddr,
    ulong   seeds_cnt,
    ulong   program_id_vaddr,
    ulong   out_vaddr,
    ulong   bump_seed_vaddr,
    ulong * ret ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *)_ctx;
  ulong r0 = 1UL;  /* 1 implies fail */

  /* Charge CUs */
  ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.create_program_address_units );
  if ( FD_UNLIKELY( err ) ) return err;
  /* Similar to create_program_address, but suffixes a 1 byte nonce
     that it decrements from 255 down to 1, until a valid PDA is found.

     Solana Labs recomputes the SHA hash for each iteration here. We
     leverage SHA's streaming properties to precompute all but the last
     two blocks (1 data, 0 or 1 padding). */



  /* Translate outputs but delay validation.

     In the unlikely case that none of the 255 iterations yield a valid
     PDA, Solana Labs never validates whether out_vaddr is a valid
     pointer */

  fd_pubkey_t * address_out = fd_vm_translate_vm_to_host(
      ctx,
      out_vaddr,
      sizeof(fd_pubkey_t),
      alignof(uchar) );

  uchar * bump_seed_out = fd_vm_translate_vm_to_host(
      ctx,
      bump_seed_vaddr,
      1UL,
      alignof(uchar) );

  /* Calculate PDA prefix */


  /* Iterate through bump prefix and hash */

  fd_pubkey_t result;
  for( ulong i = 0UL; i < 256UL; i++ ) {
    fd_sha256_t _sha[1];
    fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
    uchar suffix[1] = {(uchar)(255UL - i)};

    if( FD_UNLIKELY( !fd_vm_partial_derive_address( ctx, sha, program_id_vaddr, seeds_vaddr, seeds_cnt, suffix ) ) ) {
      return FD_VM_MEM_MAP_ERR_ACC_VIO;
    }

    /* Compute PDA on copy of SHA state */

    fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
    fd_sha256_fini( sha, &result );

    fd_sha256_delete( fd_sha256_leave( sha ) );

    /* PDA is valid if it's not a curve point */

    if( FD_LIKELY( !fd_ed25519_validate_public_key( &result ) ) ) {

      /* Delayed translation and overlap check */

      if( FD_UNLIKELY( ( !address_out   ) | ( !bump_seed_out ) ) ) {
        return FD_VM_MEM_MAP_ERR_ACC_VIO;
      }

      if( (ulong)address_out > (ulong)bump_seed_out ) {
        if( !( ( (ulong)address_out - (ulong)bump_seed_out ) >= 1UL ) ) {
          return FD_VM_MEM_MAP_ERR_ACC_VIO;
        }
      } else {
         if( !( ( (ulong)bump_seed_out - (ulong)address_out ) >= 32UL ) ) {
          return FD_VM_MEM_MAP_ERR_ACC_VIO;
        }
      }

      /* Write results */
      *bump_seed_out = (uchar)*suffix;
      memcpy( address_out, &result, sizeof(fd_pubkey_t) );
      r0 = 0UL; /* success */
      goto fini;
    }
    ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.create_program_address_units );
    if ( FD_UNLIKELY( err ) ) return err;
  }

  /* Exhausted all 255 iterations and failed to find a valid PDA.
     Return failure. */

fini:

  *ret = r0;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_processed_sibling_instruction(
    void * _ctx FD_PARAM_UNUSED,
    ulong arg0 FD_PARAM_UNUSED,
    ulong arg1 FD_PARAM_UNUSED,
    ulong arg2 FD_PARAM_UNUSED,
    ulong arg3 FD_PARAM_UNUSED,
    ulong arg4 FD_PARAM_UNUSED,
    ulong * ret FD_PARAM_UNUSED
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

/* FIXME: SEE ABOVE PUSH */
