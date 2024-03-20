#include "fd_vm_syscall.h"
#include "../../runtime/sysvar/fd_sysvar.h"
#include "../../runtime/sysvar/fd_sysvar_clock.h"
#include "../../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../runtime/sysvar/fd_sysvar_fees.h"
#include "../../runtime/sysvar/fd_sysvar_rent.h"
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

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sol_sysvar_clock_t) ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_SOL_SYSVAR_CLOCK_ALIGN, sizeof(fd_sol_sysvar_clock_t) );

  /* FIXME: is it possible to do the read in-place? */
  fd_sol_sysvar_clock_t clock[1];
  fd_sol_sysvar_clock_new( clock ); /* FIXME: probably should be init as not a distributed persistent object */
  fd_sysvar_clock_read( clock, instr_ctx->slot_ctx );
  /* FIXME: no delete function to match new (probably should be fini for the same reason anyway) */

  memcpy( out, clock, sizeof(fd_sol_sysvar_clock_t) );

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

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_epoch_schedule_t) ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_EPOCH_SCHEDULE_ALIGN, sizeof(fd_epoch_schedule_t) );

  /* FIXME: is it possible to do the read in-place? */
  fd_epoch_schedule_t schedule[1];
  fd_epoch_schedule_new( schedule ); /* FIXME: probably should be init as not a distributed persistent object */
  fd_sysvar_epoch_schedule_read( schedule, instr_ctx->slot_ctx );
  /* FIXME: no delete function to match new (probably should be fini for the same reason anyway) */

  memcpy( out, schedule, sizeof(fd_epoch_schedule_t) );

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

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_sysvar_fees_t) ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_SYSVAR_FEES_ALIGN, sizeof(fd_sysvar_fees_t) );

  /* FIXME: is it possible to do the read in-place? */
  fd_sysvar_fees_t fees[1];
  fd_sysvar_fees_new( fees ); /* FIXME: probably should be init as not a distributed persistent object */
  fd_sysvar_fees_read( fees, instr_ctx->slot_ctx );
  /* FIXME: no delete function to match new (probably should be fini for the same reason anyway) */

  memcpy( out, fees, sizeof(fd_sysvar_fees_t) );

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

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSVAR_BASE_COST, sizeof(fd_rent_t) ) );

  void * out = FD_VM_MEM_HADDR_ST( vm, out_vaddr, FD_RENT_ALIGN, sizeof(fd_rent_t) );

  /* FIXME: is it possible to do the read in-place? */
  fd_rent_t rent[1];
  fd_rent_new( rent ); /* FIXME: probably should be init as not a distributed persistent object */
  fd_sysvar_rent_read( rent, instr_ctx->slot_ctx );
  /* FIXME: no delete function to match new (probably should be fini for the same reason anyway) */

  memcpy( out, rent, sizeof(fd_rent_t) );

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: The original version didn't have the same crashing FD_TEST
     all the others had to tell if the vm was attached to an instruction
     context.  If the VM is being run outside the Solana runtime, it
     should never invoke this syscall in the first place.  So we treat
     this as a SIGCALL in a non-crashing way for the time being. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  FD_VM_CU_UPDATE( vm, FD_VM_SYSCALL_BASE_COST );

  *_ret = instr_ctx->txn_ctx->instr_stack_sz;
  return FD_VM_SUCCESS;
}

/* FIXME: PREFIX? */
/* FIXME: BRANCHLESS? */
/* FIXME: MAKE MORE BROADLY AVAILABLE, REPLACE WITH IMPL IN MEMCPY TOO? */

static inline int
is_nonoverlapping( ulong src, ulong src_sz,
                   ulong dst, ulong dst_sz ) {
  if( src>dst ) return (src-dst)>=dst_sz;
  else          return (dst-src)>=src_sz;
}

int
fd_vm_syscall_sol_get_return_data( /**/            void *  _vm,
                                   /**/            ulong   dst_vaddr,
                                   /**/            ulong   dst_max,
                                   /**/            ulong   program_id_vaddr,
                                   FD_PARAM_UNUSED ulong   r4,
                                   FD_PARAM_UNUSED ulong   r5,
                                   /**/            ulong * _ret ) {
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: The original version didn't have the same crashing FD_TEST
     all the others had to tell if the vm was attached to an instruction
     context.  If the VM is being run outside the Solana runtime, it
     should never invoke this syscall in the first place.  So we treat
     this as a SIGCALL in a non-crashing way for the time being. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  fd_txn_return_data_t const * return_data    = &instr_ctx->txn_ctx->return_data;
  ulong                        return_data_sz = return_data->len;

  /* FIXME: USE DST_MAX OR CPY_SZ HERE FOR CU UPDATE AND/OR THE
     OVERLAPPING CHECK (SEEMS ODD TO USE CPY_SZ IN PARTICULAR FOR THE
     OVERLAPPING CHECK). */

  /* FIXME: SAT ADDS PROBABLY NOT NECESSARY (SUSPECT RETURN_DATA_SZ
     ALREADY HAS A REASONABLE BOUND OF RETURN_DATA_MAX, WHICH IS
     REASONABLE). */

  /* FIXME: CHECK MODEL .. THIS LOOKS VERY SIMILAR TO CU_MEM_UPDATE
     EXCEPT FOR THE MAX VS ADD BEHAVIOR FOR THE BASE_COST */

  ulong cpy_sz = fd_ulong_min( return_data_sz, dst_max );
  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSCALL_BASE_COST,
                                         fd_ulong_sat_add( cpy_sz, sizeof(fd_pubkey_t) ) / FD_VM_CPI_BYTES_PER_UNIT ) );

  /* FIXME: IN THE ORIGINAL IMPLEMENTATION, THIS WAS AFTER ADDRESS
     TRANSLATION AND THEN IN TERMS OF HOST ADDRESS.  VERY STRANGE.  MOVE
     HERE MIGHT CHANGE THE ERROR CODE REASON BUT NOT IF THE INSTRUCTION
     FAULTS BUT THAT SHOULD NOT AFFECT CONSENSUS.  MOVE BACK IF AS
     NECESSARY. */

  if( FD_UNLIKELY( !is_nonoverlapping( dst_vaddr, cpy_sz, program_id_vaddr, sizeof(fd_pubkey_t) ) ) ) return FD_VM_ERR_MEM_OVERLAP;

  /* FIXME: IN THE ORIGINAL IMPLEMENTATION, WHOSE BEHAVOR IS REPLICATED
     BELOW, CPY_SZ==0 IMPLIES PROGRAM_ID WILL NOT BE COPIED ... SEEMS
     VERY STRANGE.  SEEMS LIKE THE API SHOULD LET YOU PASS DST_MAX==0
     (AND IF SO, MAYBE NULL FOR DST_VADDR) AND STILL GET SUCCESS AND THE
     PROGRAM_ID.  SUSPECT THE CPY_SZ CHECK SHOULD ONLY APPLY TO THE
     MEMCPY TO PREVENT UB BEHAVIOR THERE. */

  if( FD_LIKELY( cpy_sz ) ) {
    /* FIXME: CHECK alignof(fd_pubkey_t) IS CORRECT */
    void * dst        = FD_VM_MEM_HADDR_ST( vm, dst_vaddr,        1UL,                  cpy_sz              );
    void * program_id = FD_VM_MEM_HADDR_ST( vm, program_id_vaddr, alignof(fd_pubkey_t), sizeof(fd_pubkey_t) );

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
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* FIXME: The original version didn't have the same crashing FD_TEST
     all the others had to tell if the vm was attached to an instruction
     context.  If the VM is being run outside the Solana runtime, it
     should never invoke this syscall in the first place.  So we treat
     this as a SIGCALL in a non-crashing way for the time being. */

  fd_exec_instr_ctx_t const * instr_ctx = vm->instr_ctx;
  if( FD_UNLIKELY( !instr_ctx ) ) return FD_VM_ERR_SIGCALL;

  /* FIXME: CHECK MODEL .. THIS LOOKS VERY SIMILAR TO CU_MEM_UPDATE
     EXCEPT FOR THE MAX VS ADD BEHAVIOR FOR THE BASE_COST */

  FD_VM_CU_UPDATE( vm, fd_ulong_sat_add( FD_VM_SYSCALL_BASE_COST, src_sz / FD_VM_CPI_BYTES_PER_UNIT ) );

  /* FIXME: THIS CHECK PROBABLY SHOULD BE MOVED ABOVE THE CU_UPDATE AND
     IN THE PROCESS GET RID OF NEED FOR THE SAT_ADD AS SUSPECT
     RETURN_DATA_MAX ALREADY HAS A REASONABLE BOUND.  COULD ALSO
     CONSIDER FUSING ERROR_CDOE WITH THE CU MODEL.  THIS REPLICATES THE
     ORIGINAL IMPLEMENTATION'S BEHAVIOR. */

  if( FD_UNLIKELY( src_sz>FD_VM_RETURN_DATA_MAX ) ) return FD_VM_ERR_RETURN_DATA_TOO_LARGE;

  void const * src = FD_VM_MEM_HADDR_LD( vm, src_vaddr, 1UL, src_sz );

  fd_pubkey_t const    * program_id  = &instr_ctx->instr->program_id_pubkey;
  fd_txn_return_data_t * return_data = &instr_ctx->txn_ctx->return_data;

  return_data->len = src_sz;
  if( FD_LIKELY( src_sz ) ) memcpy( return_data->data, src, src_sz );
  memcpy( &return_data->program_id, program_id, sizeof(fd_pubkey_t) );

  *_ret = 0;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_get_processed_sibling_instruction( FD_PARAM_UNUSED void *  _vm,
                                                     FD_PARAM_UNUSED ulong   r1,
                                                     FD_PARAM_UNUSED ulong   r2,
                                                     FD_PARAM_UNUSED ulong   r3,
                                                     FD_PARAM_UNUSED ulong   r4,
                                                     FD_PARAM_UNUSED ulong   r5,
                                                     FD_PARAM_UNUSED ulong * _ret ) {
  return FD_VM_ERR_UNSUP;
}
