#include "fd_vm_interp.h"

/* TODO: consider doing renaming read/write -> ld/st */

/* TODO: consider writing in a branchless way (e.g. for read, would do a
   load and store from sentinel location on error or, more optimally,
   would change the API specification to allow *val to be clobbered on
   error so a conditional store doesn't need to be used). */

/* TODO: Note that if alignment checks are done by
   translate_vm_to_host_const (which is likely the case though it is
   currently inexplicably a run-time configured option), then the read
   operations don't need any special treatment to be loaded. */

/* fd_vm_mem_map_read_* are helper functions for reading a * from VM
   memory.  Returns FD_VM_SUCCESS (0) on success and FD_VM_ERR_PERM
   (negative) on failure.  Assumes val points to a valid ulong.  On
   success, *val holds the value read (zero padded out to a width of
   64-bits) and, on failure, *val is touched. */

#define DECL(T,op)                                                                               \
static inline int                                                                                \
fd_vm_mem_map_read_##T( fd_vm_exec_context_t * ctx,                                              \
                        ulong                  vm_addr,                                          \
                        ulong *                val ) {                                           \
  void const * vm_mem = fd_vm_translate_vm_to_host_const( ctx, vm_addr, sizeof(T), alignof(T) ); \
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_ERR_PERM;                                            \
  *val = op( vm_mem );                                                                           \
  return FD_VM_SUCCESS;                                                                          \
}

DECL( uchar,  fd_ulong_load_1 )
DECL( ushort, fd_ulong_load_2 )
DECL( uint,   fd_ulong_load_4 )
DECL( ulong,  fd_ulong_load_8 )

#undef DECL

/* fd_vm_mem_map_write_* are helper functions for writing a * to VM
   memory.  Returns FD_VM_MEM_SUCCESS (0) on success and FD_VM_ERR_PERM
   (negative) on failure.  On success, val has been written to vm_addr
   in the VM memory.  On failure, the VM memory was unchanged. */

#define DECL(T)                                                                      \
static inline int                                                                    \
fd_vm_mem_map_write_##T( fd_vm_exec_context_t * ctx,                                 \
                         ulong                  vm_addr,                             \
                         T                      val ) {                              \
  void * vm_mem = fd_vm_translate_vm_to_host( ctx, vm_addr, sizeof(T), alignof(T) ); \
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_ERR_PERM;                                \
  memcpy( vm_mem, &val, sizeof(T) ); /* FIXME: So gross */                           \
  return FD_VM_SUCCESS;                                                              \
}

DECL( uchar  )
DECL( ushort )
DECL( uint   )
DECL( ulong  )

#undef DECL

ulong
fd_vm_interp_instrs( fd_vm_exec_context_t * ctx ) {
  long pc = ctx->entrypoint;
  ulong ic = ctx->instruction_counter;
  ulong * register_file = ctx->register_file;
  // memset(register_file, 0, sizeof(register_file));

    // let heap_size = compute_budget.heap_size.unwrap_or(HEAP_LENGTH);
    // let _ = invoke_context.consume_checked(
    //     ((heap_size as u64).saturating_div(32_u64.saturating_mul(1024)))
    //         .saturating_sub(1)
    //         .saturating_mul(compute_budget.heap_cost),
    // );
    // let heap =

  int cond_fault = 0;

  ulong compute_meter = ctx->compute_meter;
  ulong due_insn_cnt = ctx->due_insn_cnt;
  ulong previous_instruction_meter = ctx->previous_instruction_meter;
  ulong skipped_insns = 0;

  long start_pc = pc;

#define JMP_TAB_ID interp
#define JMP_TAB_PRE_CASE_CODE
#define JMP_TAB_POST_CASE_CODE
#include "fd_jump_tab.c"

  ulong heap_cus_consumed = fd_ulong_sat_mul(fd_ulong_sat_sub(ctx->heap_sz / (32*1024), 1), vm_compute_budget.heap_cost);
  cond_fault = fd_vm_consume_compute(ctx, heap_cus_consumed);
  compute_meter = ctx->compute_meter;
  if( cond_fault != 0 ) {
    goto JT_RET_LOC;
  }

  fd_sbpf_instr_t instr;

  static const void * locs[222] = {
#include "fd_vm_interp_locs.c"
  };

  instr = ctx->instrs[pc];

  goto *(locs[instr.opcode.raw]);

interp_fault:
    compute_meter = 0; \
    due_insn_cnt = 0; \
    previous_instruction_meter = 0; \
    cond_fault = 1; \
    goto JT_RET_LOC;

JT_START;
#include "fd_vm_interp_dispatch_tab.c"
JT_END;

  ctx->compute_meter = compute_meter;
  ctx->due_insn_cnt = due_insn_cnt; 
  ctx->previous_instruction_meter = previous_instruction_meter;

  ctx->compute_meter = fd_ulong_sat_sub(ctx->compute_meter, ctx->due_insn_cnt);
  ctx->due_insn_cnt = 0;
  ctx->previous_instruction_meter = ctx->compute_meter;
  ctx->program_counter = (ulong) pc;
  ctx->instruction_counter = ic;
  ctx->cond_fault = cond_fault;

#include "fd_jump_tab_teardown.c"
#undef JMP_TAB_ID
#undef JMP_TAB_PRE_CASE_CODE
#undef JMP_TAB_POST_CASE_CODE

  // FIXME: Actual errors!
  return 0;
}

ulong
fd_vm_interp_instrs_trace( fd_vm_exec_context_t * ctx ) {
  long pc = ctx->entrypoint;
  ulong ic = ctx->instruction_counter;
  ulong * register_file = ctx->register_file;
  // memset( register_file, 0, sizeof(register_file) );

  int cond_fault = 994;
  ulong compute_meter = ctx->compute_meter;
  ulong due_insn_cnt = ctx->due_insn_cnt;
  ulong previous_instruction_meter = ctx->previous_instruction_meter;
  ulong skipped_insns = 0;
  long start_pc = pc;

#define JMP_TAB_ID interp_trace

/* FIXME: IS PC LONG OR ULONG? */
#define JMP_TAB_PRE_CASE_CODE \
  fd_vm_trace_event_exe( ctx->trace, (ulong)pc, ic, previous_instruction_meter - due_insn_cnt, register_file );

#define JMP_TAB_POST_CASE_CODE

#include "fd_jump_tab.c"

  ulong heap_cus_consumed = fd_ulong_sat_mul(fd_ulong_sat_sub(ctx->heap_sz / (32*1024), 1), vm_compute_budget.heap_cost);
  cond_fault = fd_vm_consume_compute( ctx, heap_cus_consumed );
  compute_meter = ctx->compute_meter;
  if( cond_fault != 0) {
    goto JT_RET_LOC;
  }

  fd_sbpf_instr_t instr;

  static const void * locs[222] = {
#include "fd_vm_interp_locs.c"
  };

  instr = ctx->instrs[pc];

  goto *(locs[instr.opcode.raw]);

interp_fault:
    compute_meter = 0; \
    due_insn_cnt = 0; \
    previous_instruction_meter = 0; \
    cond_fault = 1; \
    goto JT_RET_LOC;

JT_START;
#include "fd_vm_interp_dispatch_tab.c"
JT_END;
  ctx->compute_meter = compute_meter;
  ctx->due_insn_cnt = due_insn_cnt;
  ctx->previous_instruction_meter = previous_instruction_meter;
  /* Subtract final accumulated due_insn_cnt */
  ctx->compute_meter = fd_ulong_sat_sub(ctx->compute_meter, ctx->due_insn_cnt);
  ctx->due_insn_cnt = 0;
  ctx->previous_instruction_meter = ctx->compute_meter;
  ctx->program_counter = (ulong) pc;
  ctx->instruction_counter = ic;
  ctx->cond_fault = cond_fault;

#include "fd_jump_tab_teardown.c"
#undef JMP_TAB_ID

  // FIXME: Actual errors!
  return 0;
}
