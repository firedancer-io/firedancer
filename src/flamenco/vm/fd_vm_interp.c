#include "fd_vm_private.h"

/* FIXME: MAKE DIFFERENT VERSIONS FOR EACH COMBO OF CHECK_ALIGN/TRACE? */

int
fd_vm_exec_notrace( fd_vm_t * vm ) {

  if( FD_UNLIKELY( !vm ) ) return FD_VM_ERR_INVAL;

  /* Unpack the VM configuration */

  int   check_align = vm->check_align;
  ulong frame_max   = FD_VM_STACK_FRAME_MAX; /* FIXME: vm->frame_max to make this run-time configured */
  ulong heap_max    = vm->heap_max;

  ulong const * FD_RESTRICT text          = vm->text;
  ulong                     text_cnt      = vm->text_cnt;
  ulong                     text_word_off = vm->text_off / 8UL;
  ulong                     entry_pc      = vm->entry_pc;
  ulong const * FD_RESTRICT calldests     = vm->calldests;

  fd_sbpf_syscalls_t const * FD_RESTRICT syscalls = vm->syscalls;

  fd_vm_mem_cfg( vm ); /* unpacks input and rodata */
  ulong const * FD_RESTRICT region_haddr = vm->region_haddr;
  uint  const * FD_RESTRICT region_ld_sz = vm->region_ld_sz;
  uint  const * FD_RESTRICT region_st_sz = vm->region_st_sz;

  /* Initialize the VM state */

  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;

  vm->heap_sz = 0UL;
  vm->log_sz  = 0UL;

  /* FIXME: Zero out reg, shadow, stack and heap here? */

  ulong * FD_RESTRICT reg = vm->reg;
  reg[ 1] = FD_VM_MEM_MAP_INPUT_REGION_START;
  reg[10] = FD_VM_MEM_MAP_STACK_REGION_START + 0x1000;

  fd_vm_shadow_t * FD_RESTRICT shadow = vm->shadow;

  /* Run the VM */

  int err = FD_VM_SUCCESS;

# include "fd_vm_interp_core.c"

  return err;
}

int
fd_vm_exec_trace( fd_vm_t * vm ) {
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
