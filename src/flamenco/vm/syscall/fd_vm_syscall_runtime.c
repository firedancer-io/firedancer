#include "fd_vm_syscall.h"
#include "../../runtime/sysvar/fd_sysvar.h"
#include "../../runtime/sysvar/fd_sysvar_clock.h"
#include "../../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../runtime/sysvar/fd_sysvar_fees.h"
#include "../../runtime/sysvar/fd_sysvar_rent.h"
#include "../../runtime/sysvar/fd_sysvar_last_restart_slot.h"
#include "../../runtime/context/fd_exec_txn_ctx.h"
#include "../../runtime/context/fd_exec_instr_ctx.h"

int
fd_vm_syscall_sol_get_clock_sysvar( /**/            void *  _vm,
                                    /**/            ulong   out_vaddr,
                                    FD_PARAM_UNUSED ulong   r2,
                                    FD_PARAM_UNUSED ulong   r3,
                                    FD_PARAM_UNUSED ulong   r4,
                                    FD_PARAM_UNUSED ulong   r5,
                                    /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, FD_SOL_SYSVAR_CLOCK_FOOTPRINT ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_CLOCK, FD_SOL_SYSVAR_CLOCK_FOOTPRINT );

  /* FIXME: is it possible to do the read in-place? */
  fd_sol_sysvar_clock_t clock[1];
  fd_sol_sysvar_clock_new( clock ); /* FIXME: probably should be init as not a distributed persistent object */
  fd_sysvar_clock_read( clock, instr_ctx->slot_ctx );
  /* FIXME: no delete function to match new (probably should be fini for the same reason anyway) */

  memcpy( out, clock, FD_SOL_SYSVAR_CLOCK_FOOTPRINT );

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way for the time being. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, FD_EPOCH_SCHEDULE_FOOTPRINT ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_EPOCH_SCHEDULE, FD_EPOCH_SCHEDULE_FOOTPRINT );

  /* FIXME: is it possible to do the read in-place? */
  fd_epoch_schedule_t schedule[1];
  fd_epoch_schedule_new( schedule ); /* FIXME: probably should be init as not a distributed persistent object */
  fd_sysvar_epoch_schedule_read( schedule, instr_ctx->slot_ctx );
  /* FIXME: no delete function to match new (probably should be fini for the same reason anyway) */

  memcpy( out, schedule, FD_EPOCH_SCHEDULE_FOOTPRINT );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_fees_sysvar( /**/            void *  _vm,
                                   /**/            ulong   out_vaddr,
                                   FD_PARAM_UNUSED ulong   r2,
                                   FD_PARAM_UNUSED ulong   r3,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way for the time being. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, FD_SYSVAR_FEES_FOOTPRINT ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_FEES, FD_SYSVAR_FEES_FOOTPRINT );

  /* FIXME: is it possible to do the read in-place? */
  fd_sysvar_fees_t fees[1];
  fd_sysvar_fees_new( fees ); /* FIXME: probably should be init as not a distributed persistent object */
  fd_sysvar_fees_read( fees, instr_ctx->slot_ctx );
  /* FIXME: no delete function to match new (probably should be fini for the same reason anyway) */

  memcpy( out, fees, FD_SYSVAR_FEES_FOOTPRINT );

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: In the original version of this code, there was an FD_TEST
     to check if the VM was attached to an instruction context (that
     would have crashed anyway because of pointer chasing).  If the VM
     is being run outside the Solana runtime, it should never invoke
     this syscall in the first place.  So we treat this as a SIGCALL in
     a non-crashing way for the time being. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, FD_RENT_FOOTPRINT ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_RENT, FD_RENT_FOOTPRINT );

  /* FIXME: is it possible to do the read in-place? */
  fd_rent_t rent[1];
  fd_rent_new( rent ); /* FIXME: probably should be init as not a distributed persistent object */
  fd_sysvar_rent_read( rent, instr_ctx->slot_ctx );
  /* FIXME: no delete function to match new (probably should be fini for the same reason anyway) */

  memcpy( out, rent, FD_RENT_FOOTPRINT );

  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/36323b6dcd3e29e4d6fe6d73d716a3f33927148b/programs/bpf_loader/src/syscalls/sysvar.rs#L144 */
int
fd_vm_syscall_sol_get_last_restart_slot_sysvar( /**/            void *  _vm,
                                                /**/            ulong   out_vaddr,
                                                FD_PARAM_UNUSED ulong   r2,
                                                FD_PARAM_UNUSED ulong   r3,
                                                FD_PARAM_UNUSED ulong   r4,
                                                FD_PARAM_UNUSED ulong   r5,
                                                /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, FD_SOL_SYSVAR_LAST_RESTART_SLOT_FOOTPRINT ) );

  fd_sol_sysvar_last_restart_slot_t * out = 
    FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_VM_ALIGN_RUST_SYSVAR_LAST_RESTART_SLOT, FD_SOL_SYSVAR_LAST_RESTART_SLOT_FOOTPRINT );
  if( FD_UNLIKELY( fd_sysvar_last_restart_slot_read( out, vm->instr_ctx->slot_ctx ) == NULL ) ) {
    return FD_VM_ERR_ABORT;
  }

  *_ret = 0UL;
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

  *_ret = vm->instr_ctx->txn_ctx->instr_stack_sz;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_return_data( /**/            void *  _vm,
                                   /**/            ulong   dst_vaddr,
                                   /**/            ulong   dst_max,
                                   /**/            ulong   program_id_vaddr,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1345 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  fd_txn_return_data_t const * return_data    = &instr_ctx->txn_ctx->return_data;
  ulong                        return_data_sz = return_data->len;

  ulong cpy_sz = fd_ulong_min( return_data_sz, dst_max );

  if( FD_LIKELY( cpy_sz ) ) {

    FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( cpy_sz, sizeof(fd_pubkey_t) ) / FD_VM_CPI_BYTES_PER_UNIT );

    void * dst        = FD_VM_MEM_SLICE_HADDR_ST( vm, dst_vaddr, FD_VM_ALIGN_RUST_U8, cpy_sz );

    /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1376-L1381
       These can never happen. */

    void * program_id = FD_VM_MEM_HADDR_ST( vm, program_id_vaddr, FD_VM_ALIGN_RUST_PUBKEY, sizeof(fd_pubkey_t) );

    FD_VM_MEM_CHECK_NON_OVERLAPPING( vm, dst_vaddr, cpy_sz, program_id_vaddr, sizeof(fd_pubkey_t) );

    memcpy( dst,         return_data->data,       cpy_sz              );
    memcpy( program_id, &return_data->program_id, sizeof(fd_pubkey_t) );
  }

  *_ret = return_data_sz;
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

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSCALL_BASE_COST, src_sz / FD_VM_CPI_BYTES_PER_UNIT ) );

  /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1316 */
  if( FD_UNLIKELY( src_sz>FD_VM_RETURN_DATA_MAX ) ) {
    /* TODO: this is a bit annoying, we may want to unify return codes...
       - FD_VM_ERR_SYSCALL_RETURN_DATA_TOO_LARGE is Agave's return code,
         also used for logging
       - FD_VM_ERR_RETURN_DATA_TOO_LARGE is Firedancer return code */
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_ERR_SYSCALL_RETURN_DATA_TOO_LARGE );
    return FD_VM_ERR_RETURN_DATA_TOO_LARGE;
  }

  /* src_sz == 0 is ok */
  void const * src = FD_VM_MEM_SLICE_HADDR_LD( vm, src_vaddr, 1UL, src_sz );

  fd_pubkey_t const    * program_id  = &instr_ctx->instr->program_id_pubkey;
  fd_txn_return_data_t * return_data = &instr_ctx->txn_ctx->return_data;

  return_data->len = src_sz;
  fd_memcpy( return_data->data, src, src_sz );
  memcpy( &return_data->program_id, program_id, sizeof(fd_pubkey_t) );

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

/*
sol_get_last_processed_sibling_instruction returns the last element from a reverse-ordered
list of successfully processed sibling instructions: the "processed sibling instruction list".

For example, given the call flow:
A
B -> C -> D
B
B -> F          (current execution point)

B's processed sibling instruction list is [A]
F's processed sibling instruction list is [E, C]

This allows the current instruction to know what the last processed sibling instruction was.
This is useful to check that critical preceeding instructions have actually executed: for example
ensuring that an assert instruction has successfully executed.

Parameters:
- index:
- result_meta_vaddr: virtual address of the object where metadata about the last processed sibling instruction will be stored upon successful execution (the length of the arrays in the result).
  Has the type solana_program::instruction::ProcessedSiblingInstruction
    https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/sdk/program/src/instruction.rs#L672-L681
- result_program_id_vaddr: virtual address where the pubkey of the program ID of the last processed sibling instruction will be stored upon successful execution
- result_data_vaddr: virtual address where the instruction data of the last processed sibling instruction will be stored upon successful execution. The length of the data will be stored in ProcessedSiblingInstruction.data_len
- result_accounts_vaddr: virtual address where an array of account meta structures will be stored into upon successful execution. The length of the data will be stored in ProcessedSiblingInstruction.accounts_len
  Each account meta has the type solana_program::instruction::AccountMeta
    https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/sdk/program/src/instruction.rs#L525-L548

Result:
If a processed sibling instruction is found then 1 will be written into r0, and the result_* data structures
above will be populated with the last processed sibling instruction.
If there is no processed sibling instruction, 0 will be written into r0.

Syscall entrypoint: https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1402
*/
int
fd_vm_syscall_sol_get_processed_sibling_instruction(
    void * _vm,
    ulong index,
    ulong result_meta_vaddr,
    ulong result_program_id_vaddr,
    ulong result_data_vaddr,
    ulong result_accounts_vaddr,
    ulong * ret
) {

  /* stop_sibling_instruction_search_at_parent has been activated on mainnet and testnet, so 
     we treat it has hardcoded (always activated) here. */

  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* Consume base compute cost
     https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1414 */
  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  /* 
    Get the current instruction stack height.

    Top-level instructions in Agave's invocation stack have a depth of 1
    https://github.com/anza-xyz/agave/blob/d87e23d8d91c32d5f2be2bb3557c730bee1e9434/sdk/program/src/instruction.rs#L732-L733
    Ours have a depth of 0, so we need to add 1 to account for the difference
   */
  ulong stack_height = fd_ulong_sat_add( vm->instr_ctx->depth, 1UL );

  /* Reverse iterate through the instruction trace, ignoring anything except instructions on the same level.
  https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1422 */
  ulong instruction_trace_length = vm->instr_ctx->txn_ctx->instr_trace_length;
  ulong reverse_index_at_stack_height = 0UL;
  fd_exec_instr_trace_entry_t * trace_entry = NULL;
  for( ulong index_in_trace = instruction_trace_length; index_in_trace > 0UL; index_in_trace-- ) {

    /* https://github.com/anza-xyz/agave/blob/v2.0.8/programs/bpf_loader/src/syscalls/mod.rs#L1432-L1434
       This error can never happen */

    fd_exec_instr_trace_entry_t * candidate_trace_entry = &vm->instr_ctx->txn_ctx->instr_trace[ index_in_trace - 1UL ];
    if( FD_LIKELY( candidate_trace_entry->stack_height < stack_height ) ) {
      break;
    }

    if( FD_UNLIKELY( candidate_trace_entry->stack_height == stack_height ) ) {
      if( FD_UNLIKELY( fd_ulong_sat_add( index, 1UL ) == reverse_index_at_stack_height ) ) {
        trace_entry = candidate_trace_entry;
        break;
      }
      reverse_index_at_stack_height = fd_ulong_sat_add( reverse_index_at_stack_height, 1UL );
    }
  }

  /* If we have found an entry, then copy the instruction into the result addresses
     https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1440-L1533
   */
  if( FD_LIKELY( trace_entry != NULL ) ) {
    fd_instr_info_t * instr_info = trace_entry->instr_info;

    fd_vm_syscall_processed_sibling_instruction_t * result_meta_haddr = FD_VM_MEM_HADDR_ST(
      vm,
      result_meta_vaddr,
      FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_ALIGN,
      FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE );

    /* https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1447 */
    if( ( result_meta_haddr->data_len == trace_entry->instr_info->data_sz ) && 
        ( result_meta_haddr->accounts_len == trace_entry->instr_info->acct_cnt ) ) {

      fd_pubkey_t * result_program_id_haddr = FD_VM_MEM_HADDR_ST( 
        vm,
        result_program_id_vaddr,
        FD_VM_ALIGN_RUST_PUBKEY,
        sizeof(fd_pubkey_t) );

      uchar * result_data_haddr = FD_VM_MEM_SLICE_HADDR_ST(
        vm,
        result_data_vaddr,
        FD_VM_ALIGN_RUST_U8,
        result_meta_haddr->data_len);

      ulong accounts_meta_total_size = fd_ulong_sat_mul( result_meta_haddr->accounts_len, FD_VM_RUST_ACCOUNT_META_SIZE );
      fd_vm_rust_account_meta_t * result_accounts_haddr = FD_VM_MEM_SLICE_HADDR_ST(
        vm,
        result_accounts_vaddr,
        FD_VM_RUST_ACCOUNT_META_ALIGN,
        accounts_meta_total_size);

      /* Check for memory overlaps
         https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1469 */

      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        result_meta_vaddr, FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE,
        result_program_id_vaddr, sizeof(fd_pubkey_t) );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        result_meta_vaddr, FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE,
        result_accounts_vaddr, accounts_meta_total_size );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        result_meta_vaddr, FD_VM_SYSCALL_PROCESSED_SIBLING_INSTRUCTION_SIZE,
        result_data_vaddr, result_meta_haddr->data_len );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        result_program_id_vaddr, sizeof(fd_pubkey_t),
        result_data_vaddr, result_meta_haddr->data_len );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        result_program_id_vaddr, sizeof(fd_pubkey_t),
        result_accounts_vaddr, accounts_meta_total_size );
      FD_VM_MEM_CHECK_NON_OVERLAPPING( vm,
        result_data_vaddr, result_meta_haddr->data_len,
        result_accounts_vaddr, accounts_meta_total_size );

      /* Copy the instruction into the result addresses
         https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1506-L1528

         Note: we assume that the instr accounts are already correct at this point.
         Agave has many error checks. */
      fd_memcpy( result_program_id_haddr->key, instr_info->program_id_pubkey.key, FD_PUBKEY_FOOTPRINT );
      fd_memcpy( result_data_haddr, instr_info->data, instr_info->data_sz );
      for( ulong i = 0UL; i < instr_info->acct_cnt; i++ ) {
        fd_memcpy( result_accounts_haddr[ i ].pubkey,
                   vm->instr_ctx->txn_ctx->accounts[ instr_info->acct_txn_idxs[ i ] ].key,
                   FD_PUBKEY_FOOTPRINT );
        result_accounts_haddr[ i ].is_signer   = !!(instr_info->acct_flags[ i ] & FD_INSTR_ACCT_FLAGS_IS_SIGNER);
        result_accounts_haddr[ i ].is_writable = !!(instr_info->acct_flags[ i ] & FD_INSTR_ACCT_FLAGS_IS_WRITABLE);
      }
    }

    /* Copy the actual metadata into the result meta struct
       https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1529-L1531 */
    result_meta_haddr->data_len     = instr_info->data_sz;
    result_meta_haddr->accounts_len = instr_info->acct_cnt;

    /* Return true as we found a sibling instruction
       https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1532 */
    *ret = 1UL;
    return FD_VM_SUCCESS;
  }

  /* Return false if we didn't find a sibling instruction
     https://github.com/anza-xyz/agave/blob/70089cce5119c9afaeb2986e2ecaa6d4505ec15d/programs/bpf_loader/src/syscalls/mod.rs#L1534 */
  *ret = 0UL;
  return FD_VM_SUCCESS;
}
