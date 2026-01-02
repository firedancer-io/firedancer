#include "fd_vm_syscall.h"
#include "../../runtime/program/fd_vote_program.h"
#include "../../runtime/context/fd_exec_instr_ctx.h"
#include "../../runtime/fd_system_ids.h"
#include "fd_vm_syscall_macros.h"

/* FIXME: In the original version of this code, there was an FD_TEST
   to check if the VM was attached to an instruction context (that
   would have crashed anyway because of pointer chasing).  If the VM
   is being run outside the Solana runtime, it should never invoke
   this syscall in the first place.  So we treat this as a SIGCALL in
   a non-crashing way for the time being. */

int
fd_vm_syscall_sol_get_clock_sysvar( /**/            void *  _vm,
                                    /**/            ulong   out_vaddr,
                                    FD_PARAM_UNUSED ulong   r2,
                                    FD_PARAM_UNUSED ulong   r3,
                                    FD_PARAM_UNUSED ulong   r4,
                                    FD_PARAM_UNUSED ulong   r5,
                                    /**/            ulong * _ret ) {
  fd_vm_t * vm = _vm;
  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sol_sysvar_clock_t) ) );

  if( FD_UNLIKELY( vm->stricter_abi_and_runtime_constraints && out_vaddr>=FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
    return FD_VM_ERR_INVAL;
  }

  fd_vm_haddr_query_t var_query = {
    .vaddr    = out_vaddr,
    .align    = FD_VM_ALIGN_RUST_SYSVAR_CLOCK,
    .sz       = sizeof(fd_sol_sysvar_clock_t),
    .is_slice = 0,
  };

  fd_vm_haddr_query_t * queries[] = { &var_query };
  FD_VM_TRANSLATE_MUT( vm, queries );

  fd_sol_sysvar_clock_t clock = fd_sysvar_cache_clock_read_nofail( instr_ctx->sysvar_cache );
  memcpy( var_query.haddr, &clock, sizeof(fd_sol_sysvar_clock_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_epoch_schedule_sysvar( /**/            void *  _vm,
                                             /**/            ulong   out_vaddr,
                                             FD_PARAM_UNUSED ulong   r2,
                                             FD_PARAM_UNUSED ulong   r3,
                                             FD_PARAM_UNUSED ulong   r4,
                                             FD_PARAM_UNUSED ulong   r5,
                                             /**/            ulong * _ret ) {
  fd_vm_t * vm = _vm;
  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_epoch_schedule_t) ) );

  if( FD_UNLIKELY( vm->stricter_abi_and_runtime_constraints && out_vaddr>=FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
    return FD_VM_ERR_INVAL;
  }

  fd_vm_haddr_query_t var_query = {
    .vaddr    = out_vaddr,
    .align    = FD_VM_ALIGN_RUST_SYSVAR_EPOCH_SCHEDULE,
    .sz       = sizeof(fd_epoch_schedule_t),
    .is_slice = 0,
  };

  fd_vm_haddr_query_t * queries[] = { &var_query };
  FD_VM_TRANSLATE_MUT( vm, queries );

  fd_epoch_schedule_t schedule;
  if( FD_UNLIKELY( !fd_sysvar_cache_epoch_schedule_read( instr_ctx->sysvar_cache, &schedule ) ) ) {
    FD_TXN_ERR_FOR_LOG_INSTR( vm->instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR, vm->instr_ctx->txn_out->err.exec_err_idx );
    return FD_VM_ERR_INVAL;
  }
  memcpy( var_query.haddr, &schedule, sizeof(fd_epoch_schedule_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_rent_sysvar( /**/            void *  _vm,
                                   /**/            ulong   out_vaddr,
                                   FD_PARAM_UNUSED ulong   r2,
                                   FD_PARAM_UNUSED ulong   r3,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = _vm;

  /* Unreachable in a real SVM, used for testing */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_rent_t) ) );

  if( FD_UNLIKELY( vm->stricter_abi_and_runtime_constraints && out_vaddr>=FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
    return FD_VM_ERR_INVAL;
  }

  fd_vm_haddr_query_t var_query = {
    .vaddr    = out_vaddr,
    .align    = FD_VM_ALIGN_RUST_SYSVAR_RENT,
    .sz       = sizeof(fd_rent_t),
    .is_slice = 0,
  };

  fd_vm_haddr_query_t * queries[] = { &var_query };
  FD_VM_TRANSLATE_MUT( vm, queries );

  fd_rent_t rent = fd_sysvar_cache_rent_read_nofail( instr_ctx->sysvar_cache );
  memcpy( var_query.haddr, &rent, sizeof(fd_rent_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.3.2/programs/bpf_loader/src/syscalls/sysvar.rs#L149 */
int
fd_vm_syscall_sol_get_last_restart_slot_sysvar( /**/            void *  _vm,
                                                /**/            ulong   out_vaddr,
                                                FD_PARAM_UNUSED ulong   r2,
                                                FD_PARAM_UNUSED ulong   r3,
                                                FD_PARAM_UNUSED ulong   r4,
                                                FD_PARAM_UNUSED ulong   r5,
                                                /**/            ulong * _ret ) {
  fd_vm_t * vm = _vm;
  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sol_sysvar_last_restart_slot_t) ) );

  if( FD_UNLIKELY( vm->stricter_abi_and_runtime_constraints && out_vaddr>=FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
    return FD_VM_ERR_INVAL;
  }

  fd_vm_haddr_query_t var_query = {
    .vaddr    = out_vaddr,
    .align    = FD_VM_ALIGN_RUST_SYSVAR_LAST_RESTART_SLOT,
    .sz       = sizeof(fd_sol_sysvar_last_restart_slot_t),
    .is_slice = 0,
  };

  fd_vm_haddr_query_t * queries[] = { &var_query };
  FD_VM_TRANSLATE_MUT( vm, queries );

  fd_sol_sysvar_last_restart_slot_t last_restart_slot;
  if( FD_UNLIKELY( !fd_sysvar_cache_last_restart_slot_read( vm->instr_ctx->sysvar_cache, &last_restart_slot ) ) ) {
    FD_TXN_ERR_FOR_LOG_INSTR( vm->instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR, vm->instr_ctx->txn_out->err.exec_err_idx );
    return FD_VM_ERR_INVAL;
  }

  memcpy( var_query.haddr, &last_restart_slot, sizeof(fd_sol_sysvar_last_restart_slot_t) );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L167-L232 */
int
fd_vm_syscall_sol_get_sysvar( /**/            void *  _vm,
                              /**/            ulong   sysvar_id_vaddr,
                              /**/            ulong   out_vaddr,
                              /**/            ulong   offset,
                              /**/            ulong   sz,
                              FD_PARAM_UNUSED ulong   r5,
                              /**/            ulong * _ret ) {
  fd_vm_t * vm = _vm;
  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  /* sysvar_id_cost seems to just always be 32 / 250 = 0...
     https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L190-L197 */
  ulong sysvar_buf_cost = sz / FD_VM_CPI_BYTES_PER_UNIT;
  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, fd_ulong_max( sysvar_buf_cost, FD_VM_MEM_OP_BASE_COST ) ) );

  if( FD_UNLIKELY( vm->stricter_abi_and_runtime_constraints && out_vaddr>=FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
    return FD_VM_ERR_INVAL;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/sysvar.rs#L207-L211 */
  fd_vm_haddr_query_t var_query = {
    .vaddr    = out_vaddr,
    .align    = FD_VM_ALIGN_RUST_U8,
    .sz       = sz,
    .is_slice = 1,
  };

  fd_vm_haddr_query_t * queries[] = { &var_query };
  FD_VM_TRANSLATE_MUT( vm, queries );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L199-L200 */
  const fd_pubkey_t * sysvar_id = FD_VM_MEM_HADDR_LD( vm, sysvar_id_vaddr, FD_VM_ALIGN_RUST_PUBKEY, FD_PUBKEY_FOOTPRINT );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L205-L208 */
  ulong offset_length;
  int err = fd_int_if( __builtin_uaddl_overflow( offset, sz, &offset_length ), FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW, FD_EXECUTOR_INSTR_SUCCESS );
  if( FD_UNLIKELY( err ) ) {
    FD_VM_ERR_FOR_LOG_INSTR( vm, err );
    return FD_VM_SYSCALL_ERR_ABORT;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L210-L213
     We don't need this, we already checked we can store in out_vaddr with requested sz. */

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L215-L221 */
  if( FD_UNLIKELY( memcmp( sysvar_id->uc, fd_sysvar_clock_id.uc,             FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_epoch_schedule_id.uc,    FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_epoch_rewards_id.uc,     FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_rent_id.uc,              FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_slot_hashes_id.uc,       FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_stake_history_id.uc,     FD_PUBKEY_FOOTPRINT ) &&
                   memcmp( sysvar_id->uc, fd_sysvar_last_restart_slot_id.uc, FD_PUBKEY_FOOTPRINT ) ) ) {
    *_ret = 2UL;
    return FD_VM_SUCCESS;
  }

  ulong         sysvar_buf_len;
  uchar const * sysvar_buf =
    fd_sysvar_cache_data_query( vm->instr_ctx->sysvar_cache, sysvar_id, &sysvar_buf_len );
  if( FD_UNLIKELY( !sysvar_buf ) ) {
    *_ret = 2UL;
    return FD_VM_SUCCESS;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/sysvar.rs#L223-L228
     Note the length check is at the very end to fail after performing sufficient checks. */

  if( FD_UNLIKELY( offset_length>sysvar_buf_len ) ) {
    *_ret = 1UL;
    return FD_VM_SUCCESS;
  }

  if( FD_UNLIKELY( sz==0UL ) ) {
    *_ret = 0UL;
    return FD_VM_SUCCESS;
  }

  fd_memcpy( var_query.haddr, sysvar_buf + offset, sz );
  *_ret = 0;
  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2043-L2118 */
int
fd_vm_syscall_sol_get_epoch_stake( /**/            void *  _vm,
                                   /**/            ulong   var_addr,
                                   FD_PARAM_UNUSED ulong   r2,
                                   FD_PARAM_UNUSED ulong   r3,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* Var addr of 0 returns the total active stake on the cluster.

     https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2057-L2075 */
  if( FD_UNLIKELY( var_addr==0UL ) ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2065-L2066 */
    FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

    /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2074 */
    *_ret = fd_bank_total_epoch_stake_get( vm->instr_ctx->bank );
    return FD_VM_SUCCESS;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2083-L2091
     FD_PUBKEY_FOOTPRINT/FD_VM_CPI_BYTES_PER_UNIT is always 32/250 = 0,
     so we can omit it */

  FD_VM_CU_UPDATE( vm, FD_VM_MEM_OP_BASE_COST + FD_VM_SYSCALL_BASE_COST );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/programs/bpf_loader/src/syscalls/mod.rs#L2103-L2104 */
  const fd_pubkey_t * vote_address = FD_VM_MEM_HADDR_LD( vm, var_addr, FD_VM_ALIGN_RUST_PUBKEY, FD_PUBKEY_FOOTPRINT );

  /* https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank.rs#L6954 */
  fd_vote_states_t const *    vote_states    = fd_bank_vote_states_prev_locking_query( vm->instr_ctx->bank );
  fd_vote_state_ele_t const * vote_state_ele = fd_vote_states_query_const( vote_states, vote_address );
  *_ret = vote_state_ele ? vote_state_ele->stake : 0UL;

  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_stack_height( /**/            void *  _vm,
                                    FD_PARAM_UNUSED ulong   r1,
                                    FD_PARAM_UNUSED ulong   r2,
                                    FD_PARAM_UNUSED ulong   r3,
                                    FD_PARAM_UNUSED ulong   r4,
                                    FD_PARAM_UNUSED ulong   r5,
                                    /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1547 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  *_ret = vm->instr_ctx->runtime->instr.stack_sz;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_return_data( /**/            void *  _vm,
                                   /**/            ulong   return_data_vaddr,
                                   /**/            ulong   sz,
                                   /**/            ulong   program_id_vaddr,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1465 */
  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1467 */
  fd_txn_return_data_t const * return_data = &vm->instr_ctx->txn_out->details.return_data;

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1468 */
  ulong length = fd_ulong_min( return_data->len, sz );

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1469-L1492 */
  if( FD_LIKELY( length ) ) {

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1470-L1474 */
    FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( length, sizeof(fd_pubkey_t) ) / FD_VM_CPI_BYTES_PER_UNIT );

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1476-L1481 */
    fd_vm_haddr_query_t return_data_query = {
      .vaddr    = return_data_vaddr,
      .align    = FD_VM_ALIGN_RUST_U8,
      .sz       = length,
      .is_slice = 1
    };

    fd_vm_haddr_query_t program_id_query = {
      .vaddr    = program_id_vaddr,
      .align    = FD_VM_ALIGN_RUST_PUBKEY,
      .sz       = sizeof(fd_pubkey_t),
      .is_slice = 0
    };

    fd_vm_haddr_query_t * queries[] = { &return_data_query, &program_id_query };
    FD_VM_TRANSLATE_MUT( vm, queries );

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1490-L1491 */
    memcpy( return_data_query.haddr, return_data->data, length );
    memcpy( program_id_query.haddr, &return_data->program_id, sizeof(fd_pubkey_t) );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1495 */
  *_ret = return_data->len;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_set_return_data( /**/            void *  _vm,
                                   /**/            ulong   src_vaddr,
                                   /**/            ulong   src_sz,
                                   FD_PARAM_UNUSED ulong   r3,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1297 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way for the time being. */
  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSCALL_BASE_COST, src_sz / FD_VM_CPI_BYTES_PER_UNIT ) );

  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1316 */
  if( FD_UNLIKELY( src_sz>FD_VM_RETURN_DATA_MAX ) ) {
    /* TODO: this is a bit annoying, we may want to unify return codes...
       - FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE is Agave's return code,
         also used for logging */
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE );
    return FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE;
  }

  /* src_sz == 0 is ok */
  void const * src = FD_VM_MEM_SLICE_HADDR_LD( vm, src_vaddr, FD_VM_ALIGN_RUST_U8, src_sz );

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/programs/bpf_loader/src/syscalls/mod.rs#L1480-L1484 */
  fd_pubkey_t const * program_id = NULL;
  int err = fd_exec_instr_ctx_get_last_program_key( vm->instr_ctx, &program_id );
  if( FD_UNLIKELY( err ) ) {
    FD_VM_ERR_FOR_LOG_INSTR( vm, err );
    return err;
  }

  fd_txn_return_data_t * return_data = &instr_ctx->txn_out->details.return_data;

  return_data->len = src_sz;
  if( FD_LIKELY( src_sz!=0UL ) ) {
    fd_memcpy( return_data->data, src, src_sz );
  }
  return_data->program_id = *program_id;

  *_ret = 0;
  return FD_VM_SUCCESS;
}

/* Used to query and convey information about the sibling instruction
   https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/sdk/program/src/instruction.rs#L676

    */
struct fd_vm_syscall_processed_sibling_instruction {
  /* Length of the instruction data */
  ulong data_len;
  /* Number of accounts */
  ulong accounts_len;
};
typedef struct fd_vm_syscall_processed_sibling_instruction fd_vm_syscall_processed_sibling_instruction_t;

#define FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE  (16UL)
#define FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_ALIGN (8UL )

/* https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1402 */
int
fd_vm_syscall_sol_get_processed_sibling_instruction(
    void * _vm,
    ulong index,
    ulong result_meta_vaddr,
    ulong result_program_id_vaddr,
    ulong result_data_vaddr,
    ulong result_accounts_vaddr,
    ulong * _ret
) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* Consume base compute cost
     https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1513 */
  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  /* Get the current instruction stack height.  This value is 1-indexed
     (top level instruction has a stack height of 1).
    https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1517 */
  ulong stack_height = vm->instr_ctx->runtime->instr.stack_sz;

  /* Reverse iterate through the instruction trace, ignoring anything except instructions on the same level.
     https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1518-L1522 */
  ulong instruction_trace_length = vm->instr_ctx->runtime->instr.trace_length;
  ulong reverse_index_at_stack_height = 0UL;
  fd_instr_info_t * found_instruction_context = NULL;
  for( ulong index_in_trace=instruction_trace_length; index_in_trace>0UL; index_in_trace-- ) {

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1524-L1526
       This error can never happen */

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1527-L1529 */
    fd_instr_info_t * instruction_context = &vm->instr_ctx->runtime->instr.trace[ index_in_trace-1UL ];
    if( FD_LIKELY( instruction_context->stack_height<stack_height ) ) {
      break;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1530-L1536 */
    if( FD_UNLIKELY( instruction_context->stack_height==stack_height ) ) {
      if( FD_UNLIKELY( fd_ulong_sat_add( index, 1UL )==reverse_index_at_stack_height ) ) {
        found_instruction_context = instruction_context;
        break;
      }
      reverse_index_at_stack_height = fd_ulong_sat_add( reverse_index_at_stack_height, 1UL );
    }
  }

  /* If we have found an entry, then copy the instruction into the
     result addresses.
     https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1539-L1588
   */
  if( FD_LIKELY( found_instruction_context != NULL ) ) {
    fd_vm_haddr_query_t result_header_query = {
      .vaddr    = result_meta_vaddr,
      .align    = FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_ALIGN,
      .sz       = FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE,
      .is_slice = 0,
    };

    fd_vm_haddr_query_t * queries[] = { &result_header_query };
    FD_VM_TRANSLATE_MUT( vm, queries );

    fd_vm_syscall_processed_sibling_instruction_t * result_header = result_header_query.haddr;

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1546-L1583 */
    if( result_header->data_len==found_instruction_context->data_sz && result_header->accounts_len==found_instruction_context->acct_cnt ) {
      fd_vm_haddr_query_t program_id_query = {
        .vaddr    = result_program_id_vaddr,
        .align    = FD_VM_ALIGN_RUST_PUBKEY,
        .sz       = sizeof(fd_pubkey_t),
        .is_slice = 0,
      };

      fd_vm_haddr_query_t data_query = {
        .vaddr    = result_data_vaddr,
        .align    = FD_VM_ALIGN_RUST_U8,
        .sz       = result_header->data_len,
        .is_slice = 1,
      };

      fd_vm_haddr_query_t accounts_query = {
        .vaddr    = result_accounts_vaddr,
        .align    = FD_VM_RUST_ACCOUNT_META_ALIGN,
        .sz       = fd_ulong_sat_mul( result_header->accounts_len, FD_VM_RUST_ACCOUNT_META_SIZE ),
        .is_slice = 1,
      };

      fd_vm_haddr_query_t * queries[] = { &program_id_query, &data_query, &accounts_query, &result_header_query };
      FD_VM_TRANSLATE_MUT( vm, queries );

      fd_pubkey_t *               program_id = program_id_query.haddr;
      uchar *                     data       = data_query.haddr;
      fd_vm_rust_account_meta_t * accounts   = accounts_query.haddr;

      /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1561-L1562 */
      fd_pubkey_t const * instr_ctx_program_id = NULL;
      int err = fd_runtime_get_key_of_account_at_index(
          vm->instr_ctx->txn_out,
          found_instruction_context->program_id,
          &instr_ctx_program_id
      );
      if( FD_UNLIKELY( err ) ) {
        FD_VM_ERR_FOR_LOG_INSTR( vm, err );
        return err;
      }
      fd_memcpy( program_id, instr_ctx_program_id, sizeof(fd_pubkey_t) );

      /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1563 */
      fd_memcpy( data, found_instruction_context->data, found_instruction_context->data_sz );

      /* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1564-L1581 */
      for( ushort i=0; i<found_instruction_context->acct_cnt; i++ ) {
        fd_pubkey_t const * account_key;
        ushort txn_idx = found_instruction_context->accounts[ i ].index_in_transaction;
        err            = fd_runtime_get_key_of_account_at_index( vm->instr_ctx->txn_out, txn_idx, &account_key );
        if( FD_UNLIKELY( err ) ) {
          FD_VM_ERR_FOR_LOG_INSTR( vm, err );
          return err;
        }

        fd_memcpy( accounts[ i ].pubkey, account_key, sizeof(fd_pubkey_t) );
        accounts[ i ].is_signer   = !!(found_instruction_context->accounts[ i ].is_signer );
        accounts[ i ].is_writable = !!(found_instruction_context->accounts[ i ].is_writable );
      }
    } else {
      /* Copy the actual metadata into the result meta struct
         https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1584-L1586 */
      result_header->data_len     = found_instruction_context->data_sz;
      result_header->accounts_len = found_instruction_context->acct_cnt;
    }

    /* Return true as we found a sibling instruction
       https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1588 */
    *_ret = 1UL;
    return FD_VM_SUCCESS;
  }

  /* Return false if we didn't find a sibling instruction
     https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/mod.rs#L1590 */
  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.3.1/programs/bpf_loader/src/syscalls/sysvar.rs#L80 */
int
fd_vm_syscall_sol_get_epoch_rewards_sysvar( /**/            void *  _vm,
                                            /**/            ulong   out_vaddr,
                                            FD_PARAM_UNUSED ulong   r2,
                                            FD_PARAM_UNUSED ulong   r3,
                                            FD_PARAM_UNUSED ulong   r4,
                                            FD_PARAM_UNUSED ulong   r5,
                                            /**/            ulong * _ret ) {
  fd_vm_t * vm = _vm;
  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_SYSCALL_ERR_OUTSIDE_RUNTIME;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sysvar_epoch_rewards_t) ) );

  if( FD_UNLIKELY( vm->stricter_abi_and_runtime_constraints && out_vaddr>=FD_VM_MEM_MAP_INPUT_REGION_START ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_POINTER );
    return FD_VM_ERR_INVAL;
  }

  uchar * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_EPOCH_REWARDS, sizeof(fd_sysvar_epoch_rewards_t) );

  fd_sysvar_epoch_rewards_t epoch_rewards;
  if( FD_UNLIKELY( !fd_sysvar_cache_epoch_rewards_read( instr_ctx->sysvar_cache, &epoch_rewards ) ) ) {
    FD_TXN_ERR_FOR_LOG_INSTR( vm->instr_ctx->txn_out, FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR, vm->instr_ctx->txn_out->err.exec_err_idx );
    return FD_VM_ERR_INVAL;
  }
  memcpy( out, &epoch_rewards, sizeof(fd_sysvar_epoch_rewards_t) );
  memset( out+81, 0, 15 ); /* padding */

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}
