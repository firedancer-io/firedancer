#include "fd_vm_interp.h"

#include "../../ballet/murmur3/fd_murmur3.h"
#include "../../util/bits/fd_sat.h"

#include "fd_vm_context.h"
#include "../runtime/fd_runtime.h"

#include <stdio.h>

/* Helper function for reading a uchar from VM memory. Returns success or a fault for the memory
 * access. Sets the value pointed to by `val` on success.
 */
static inline ulong
fd_vm_mem_map_read_uchar( fd_vm_exec_context_t * ctx,
                          ulong                  vm_addr,
                          ulong *                val ) {

  void const * vm_mem = fd_vm_translate_vm_to_host_const( ctx, vm_addr, sizeof(uchar), alignof(uchar) );
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *val = fd_ulong_load_1( vm_mem );
  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for reading a ushort from VM memory. Returns success or a fault for the memory
 * access. Sets the value pointed to by `val` on success.
 */
static inline ulong
fd_vm_mem_map_read_ushort( fd_vm_exec_context_t * ctx,
                           ulong                  vm_addr,
                           ulong *                val ) {

  void const * vm_mem = fd_vm_translate_vm_to_host_const( ctx, vm_addr, sizeof(ushort), alignof(uchar) );
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *val = fd_ulong_load_2( vm_mem );
  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for reading a uint from VM memory. Returns success or a fault for the memory
 * access. Sets the value pointed to by `val` on success.
 */
static inline ulong
fd_vm_mem_map_read_uint( fd_vm_exec_context_t * ctx,
                         ulong                  vm_addr,
                         ulong *                val ) {

  void const * vm_mem = fd_vm_translate_vm_to_host_const( ctx, vm_addr, sizeof(uint), alignof(uchar) );
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *val = fd_ulong_load_4( vm_mem );
  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for reading a ulong from VM memory. Returns success or a fault for the memory
 * access. Sets the value pointed to by `val` on success.
 */
static inline ulong
fd_vm_mem_map_read_ulong( fd_vm_exec_context_t * ctx,
                          ulong                  vm_addr,
                          ulong *                val ) {

  void const * vm_mem = fd_vm_translate_vm_to_host_const( ctx, vm_addr, sizeof(ulong), alignof(uchar) );
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *val = fd_ulong_load_8( vm_mem );
  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for writing a uchar to VM memory. Returns success or a fault for the memory
 * access. The value `val` is written to vm_addr on success.
 */
static inline ulong
fd_vm_mem_map_write_uchar( fd_vm_exec_context_t *  ctx,
                           ulong                   vm_addr,
                           uchar                   val ) {

  void * vm_mem = fd_vm_translate_vm_to_host( ctx, vm_addr, sizeof(uchar), alignof(uchar) );
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *(uchar *)vm_mem = val;
  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for writing a ushort to VM memory. Returns success or a fault for the memory
 * access. The value `val` is written to vm_addr on success.
 */
static inline ulong
fd_vm_mem_map_write_ushort( fd_vm_exec_context_t * ctx,
                            ulong                  vm_addr,
                            ushort                 val ) {

  void * vm_mem = fd_vm_translate_vm_to_host( ctx, vm_addr, sizeof(ushort), alignof(uchar) );
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  memcpy( vm_mem, &val, sizeof(ushort) );
  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for writing a uint to VM memory. Returns success or a fault for the memory
 * access. The value `val` is written to vm_addr on success.
 */
static inline ulong
fd_vm_mem_map_write_uint( fd_vm_exec_context_t * ctx,
                          ulong                  vm_addr,
                          uint                   val ) {

  void * vm_mem = fd_vm_translate_vm_to_host( ctx, vm_addr, sizeof(uint), alignof(uchar) );
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  memcpy( vm_mem, &val, sizeof(uint) );
  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for writing a ulong to VM memory. Returns success or a fault for the memory
 * access. The value `val` is written to vm_addr on success.
 */
static inline ulong
fd_vm_mem_map_write_ulong( fd_vm_exec_context_t *  ctx,
                          ulong                    vm_addr,
                          ulong                    val ) {

  void * vm_mem = fd_vm_translate_vm_to_host( ctx, vm_addr, sizeof(ulong), alignof(uchar) );
  if( FD_UNLIKELY( !vm_mem ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  memcpy( vm_mem, &val, sizeof(ulong) );
  return FD_VM_MEM_MAP_SUCCESS;
}

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

  ulong cond_fault = 0;

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
  cond_fault = fd_vm_consume_compute_meter(ctx, heap_cus_consumed);
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
  ctx->due_insn_cnt = fd_ulong_sat_add( due_insn_cnt, 1 );
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

  ulong cond_fault = 994;
  ulong compute_meter = ctx->compute_meter;
  ulong due_insn_cnt = ctx->due_insn_cnt;
  ulong previous_instruction_meter = ctx->previous_instruction_meter;
  ulong skipped_insns = 0;
  long start_pc = pc;

#define JMP_TAB_ID interp_trace
#define JMP_TAB_PRE_CASE_CODE \
  if( ic > ctx->trace_ctx->trace_entries_sz ) goto JT_RET_LOC; \
  fd_vm_trace_context_add_entry( ctx->trace_ctx, (ulong)pc, ic, previous_instruction_meter - due_insn_cnt, register_file );
#define JMP_TAB_POST_CASE_CODE
#include "fd_jump_tab.c"

  ulong heap_cus_consumed = fd_ulong_sat_mul(fd_ulong_sat_sub(ctx->heap_sz / (32*1024), 1), vm_compute_budget.heap_cost);
  cond_fault = fd_vm_consume_compute_meter(ctx, heap_cus_consumed);
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
