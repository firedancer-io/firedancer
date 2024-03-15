#include "fd_vm_private.h"

/* FIXME: MAKE DIFFERENT VERSIONS FOR EACH COMBO OF CHECK_ALIGN/TRACE? */

int
fd_vm_private_exec_notrace( fd_vm_t * vm ) {

  ulong const * FD_RESTRICT text          = vm->text;
  ulong                     text_cnt      = vm->text_cnt;
  ulong                     text_word_off = vm->text_off / 8UL; /* FIXME: HMMM ... MULTIPLE OF 8? SIGNED? ETC */
  ulong                     entrypoint    = vm->entrypoint;
  ulong const * FD_RESTRICT calldests     = vm->calldests;

  fd_sbpf_syscalls_t const * syscalls = vm->syscalls;

  fd_vm_mem_cfg( vm );
  ulong const * FD_RESTRICT region_haddr = vm->region_haddr;
  uint  const * FD_RESTRICT region_ld_sz = vm->region_ld_sz;
  uint  const * FD_RESTRICT region_st_sz = vm->region_st_sz;

  ulong * FD_RESTRICT reg = vm->reg; /* Indexed [0,FD_VM_REG_MAX) */

  int check_align = vm->check_align;

  ulong pc                         = entrypoint;
  ulong ic                         = vm->instruction_counter;
  ulong compute_meter              = vm->compute_meter;
  ulong due_insn_cnt               = vm->due_insn_cnt;
  ulong previous_instruction_meter = vm->previous_instruction_meter;

  ulong skipped_insns = 0UL;
  ulong start_pc      = pc;

  int err = FD_VM_SUCCESS;

  // let heap_size = compute_budget.heap_size.unwrap_or(HEAP_LENGTH);
  // let _ = invoke_context.consume_checked(
  //     ((heap_size as u64).saturating_div(32_u64.saturating_mul(1024)))
  //         .saturating_sub(1)
  //         .saturating_mul(compute_budget.heap_cost),
  // );

  ulong heap_cus_consumed = fd_ulong_sat_mul( fd_ulong_sat_sub( vm->heap_max/(32*1024), 1 ), FD_VM_HEAP_COST );
  int heap_err = fd_vm_consume_compute( vm, heap_cus_consumed );
  compute_meter = vm->compute_meter;
  if( FD_UNLIKELY( heap_err ) ) goto sigheap;

# include "fd_vm_interp_core.c"

  /* FIXME: PROBABLY SHOULD ADD A SIGTEXT FOR A PROGRAM COUNTER GOING
     OUT OF BOUNDS, A SIGRODATA FOR A PROGRAM TRYING TO WRITE READ-ONLY
     REGIONS, A SIGSTACK FOR HITTING STACK FRAME LIMITS, ETC. */
  /* FIXME: FIX ERROR CODES */
sigheap: err = FD_VM_ERR_MEM_TRANS; goto interp_halt;
sigill:  err = FD_VM_ERR_MEM_TRANS; goto interp_halt;
sigsegv: err = FD_VM_ERR_MEM_TRANS; goto interp_halt;
sigbus:  err = FD_VM_ERR_MEM_TRANS; goto interp_halt;
sigcall: /* FIXME: sets err */      goto interp_halt;
sigcost:
  compute_meter              = 0;                   /* FIXME: HMMM */
  due_insn_cnt               = 0;                   /* FIXME: HMMM */
  previous_instruction_meter = 0;                   /* FIXME: HMMM */
  err                        = FD_VM_ERR_MEM_TRANS;
  goto interp_halt;

interp_halt:

  vm->compute_meter              = compute_meter;
  vm->due_insn_cnt               = fd_ulong_sat_add( due_insn_cnt, 1 );
  vm->previous_instruction_meter = previous_instruction_meter;

  vm->compute_meter              = fd_ulong_sat_sub(vm->compute_meter, vm->due_insn_cnt);
  vm->due_insn_cnt               = 0;
  vm->previous_instruction_meter = vm->compute_meter;
  vm->program_counter            = pc;
  vm->instruction_counter        = ic;
  vm->cond_fault                 = err; /* FIXME: REMOVE THIS */

  return FD_VM_SUCCESS; /* FIXME: return err ... such currently causes runtime tests to fail because of runtime error handling not correct yet */
}

int
fd_vm_private_exec_trace( fd_vm_t * vm ) {
#if 1
  (void)vm;
  return FD_VM_ERR_UNSUP;
#else
  long    entrypoint = (long)vm->entrypoint; /* FIXME: HMMM */
  long    pc         = entrypoint;           /* FIXME: HMMM */
  ulong   ic         = vm->instruction_counter;
  ulong * reg        = vm->reg;

  ulong const * text          = vm->text;
  ulong         text_cnt      = vm->text_cnt;
  long          text_word_off = (long)(vm->text_off / 8L); /* FIXME: HMMM ... MULTIPLE OF 8, SIGN HANDLING, ETC */
  ulong const * calldests     = vm->calldests;

  fd_sbpf_syscalls_t const * syscalls = vm->syscalls;

  int cond_fault = 994; /* FIXME: HMMMM */
  ulong compute_meter              = vm->compute_meter;
  ulong due_insn_cnt               = vm->due_insn_cnt;
  ulong previous_instruction_meter = vm->previous_instruction_meter;
  ulong skipped_insns              = 0;
  long  start_pc = pc;

#define JMP_TAB_ID interp_trace

  /* FIXME: IS PC LONG OR ULONG? */
#define JMP_TAB_PRE_CASE_CODE                                                                      \
  fd_vm_trace_event_exe( vm->trace, (ulong)pc, ic, previous_instruction_meter - due_insn_cnt, reg, \
                         vm->text + pc, vm->text_cnt - (ulong)pc );

#define JMP_TAB_POST_CASE_CODE

#include "fd_jump_tab.c"

  ulong heap_cus_consumed = fd_ulong_sat_mul( fd_ulong_sat_sub( vm->heap_max/(32*1024), 1 ), FD_VM_HEAP_COST );
  cond_fault = fd_vm_consume_compute( vm, heap_cus_consumed );
  compute_meter = vm->compute_meter;
  if( FD_UNLIKELY( cond_fault ) ) goto JT_RET_LOC;

  fd_sbpf_instr_t instr;

  static const void * locs[222] = {
#include "fd_vm_interp_locs.c"
  };

  instr = fd_sbpf_instr( vm->text[pc] );

  goto *(locs[instr.opcode.raw]);

interp_fault:
  compute_meter              = 0;
  due_insn_cnt               = 0;
  previous_instruction_meter = 0;
  cond_fault                 = FD_VM_ERR_MEM_TRANS; /* FIXME: HMMM */
  goto JT_RET_LOC;

JT_START;
#include "fd_vm_interp_dispatch_tab.c"
JT_END;
  vm->compute_meter = compute_meter;
  vm->due_insn_cnt = due_insn_cnt;
  vm->previous_instruction_meter = previous_instruction_meter;

  vm->compute_meter = fd_ulong_sat_sub(vm->compute_meter, vm->due_insn_cnt);
  vm->due_insn_cnt = 0;
  vm->previous_instruction_meter = vm->compute_meter;
  vm->program_counter = (ulong) pc;
  vm->instruction_counter = ic;
  vm->cond_fault = cond_fault;

#include "fd_jump_tab_teardown.c"
#undef JMP_TAB_ID

  // FIXME: Actual errors!
  return 0;
#endif
}
