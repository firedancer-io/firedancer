#include "fd_vm_interp.h"

#include "../ballet/murmur3/fd_murmur3.h"

/* Helper function for reading a uchar from VM memory. Returns success or a fault for the memory
 * access. Sets the value pointed to by `val` on success.
 */
static ulong
fd_vm_mem_map_read_uchar( fd_vm_exec_context_t * ctx,
                          ulong                       vm_addr,
                          ulong *                     val ) {
  void * vm_mem;
  ulong translation_res = fd_vm_translate_vm_to_host(ctx, 0, vm_addr, sizeof(uchar), &vm_mem);
  if( translation_res != FD_VM_MEM_MAP_SUCCESS ) {
    return translation_res;
  }

  
  *val = (*(uchar *)vm_mem) & 0xFFUL;

  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for reading a ushort from VM memory. Returns success or a fault for the memory
 * access. Sets the value pointed to by `val` on success.
 */
static ulong
fd_vm_mem_map_read_ushort( fd_vm_exec_context_t *  ctx,
                           ulong                        vm_addr,
                           ulong *                      val ) {
  void * vm_mem;
  ulong translation_res = fd_vm_translate_vm_to_host(ctx, 0, vm_addr, sizeof(ushort), &vm_mem);
  if( translation_res != FD_VM_MEM_MAP_SUCCESS ) {
    return translation_res;
  }

  *val = (*(ushort *)vm_mem) & 0xFFFFUL;

  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for reading a uint from VM memory. Returns success or a fault for the memory
 * access. Sets the value pointed to by `val` on success.
 */
static ulong
fd_vm_mem_map_read_uint( fd_vm_exec_context_t *  ctx,
                         ulong                        vm_addr,
                         ulong *                      val ) {
  void * vm_mem;
  ulong translation_res = fd_vm_translate_vm_to_host(ctx, 0, vm_addr, sizeof(uint), &vm_mem);
  if( translation_res != FD_VM_MEM_MAP_SUCCESS ) {
    return translation_res;
  }

  *val = (*(uint *)vm_mem) & 0xFFFFFFFFUL;

  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for reading a ulong from VM memory. Returns success or a fault for the memory
 * access. Sets the value pointed to by `val` on success.
 */
static ulong
fd_vm_mem_map_read_ulong( fd_vm_exec_context_t * ctx,
                          ulong                       vm_addr,
                          ulong *                     val ) {
  void * vm_mem;
  ulong translation_res = fd_vm_translate_vm_to_host(ctx, 0, vm_addr, sizeof(ulong), &vm_mem);
  if( translation_res != FD_VM_MEM_MAP_SUCCESS ) {
    return translation_res;
  }

  *val = *(ulong *)vm_mem;

  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for writing a uchar to VM memory. Returns success or a fault for the memory
 * access. The value `val` is written to vm_addr on success.
 */
static ulong
fd_vm_mem_map_write_uchar( fd_vm_exec_context_t *  ctx,
                           ulong                        vm_addr,
                           uchar                        val ) {
  void * vm_mem;
  ulong translation_res = fd_vm_translate_vm_to_host(ctx, 1, vm_addr, sizeof(uchar), &vm_mem);
  if( translation_res != FD_VM_MEM_MAP_SUCCESS ) {
    return translation_res;
  }

  *(uchar *)vm_mem = val;

  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for writing a ushort to VM memory. Returns success or a fault for the memory
 * access. The value `val` is written to vm_addr on success.
 */
static ulong
fd_vm_mem_map_write_ushort( fd_vm_exec_context_t * ctx,
                            ulong                       vm_addr,
                            ushort                      val ) {
  void * vm_mem;
  ulong translation_res = fd_vm_translate_vm_to_host(ctx, 1, vm_addr, sizeof(ushort), &vm_mem);
  if( translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  *(ushort *)vm_mem = val;

  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for writing a uint to VM memory. Returns success or a fault for the memory
 * access. The value `val` is written to vm_addr on success.
 */
static ulong
fd_vm_mem_map_write_uint( fd_vm_exec_context_t * ctx,
                          ulong                       vm_addr,
                          uint                        val ) {
  void * vm_mem;
  ulong translation_res = fd_vm_translate_vm_to_host(ctx, 1, vm_addr, sizeof(uint), &vm_mem);
  if( translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  *(uint *)vm_mem = val;

  return FD_VM_MEM_MAP_SUCCESS;
}

/* Helper function for writing a ulong to VM memory. Returns success or a fault for the memory
 * access. The value `val` is written to vm_addr on success.
 */
static ulong
fd_vm_mem_map_write_ulong( fd_vm_exec_context_t *  ctx,
                          ulong                         vm_addr,
                          ulong                         val ) {
  void * vm_mem;
  ulong translation_res = fd_vm_translate_vm_to_host(ctx, 1, vm_addr, sizeof(ulong), &vm_mem);
  if( translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  *(ulong *)vm_mem = val;

  return FD_VM_MEM_MAP_SUCCESS;
}

ulong
fd_vm_interp_instrs( fd_vm_exec_context_t * ctx ) {
  long pc = ctx->entrypoint;
  ulong ic = ctx->instruction_counter;
  ulong * register_file = ctx->register_file;
  fd_memset(register_file, 0, sizeof(register_file));

  ulong cond_fault = 0;

#define JMP_TAB_ID interp
#define JMP_TAB_PRE_CASE_CODE
#define JMP_TAB_POST_CASE_CODE \
  ic++; \
  instr = ctx->instrs[++pc]; \
  goto *(locs[instr.opcode.raw]);
#include "fd_jump_tab.c"

  fd_sbpf_instr_t instr;

  static const void * locs[222] = {
#include "fd_vm_interp_locs.c"
  };

  instr = ctx->instrs[pc];

  goto *(locs[instr.opcode.raw]);

JT_START;
#include "fd_vm_interp_dispatch_tab.c"
JT_END;

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
fd_vm_interp_instrs_trace( fd_vm_exec_context_t *       ctx,
                           fd_vm_trace_entry_t *        trace,
                           ulong trace_sz, ulong *      trace_used ) {
  long pc = ctx->entrypoint;
  ulong ic = ctx->instruction_counter;
  ulong * register_file = ctx->register_file;
  fd_memset( register_file, 0, sizeof(register_file) );

  ulong cond_fault = 0;

  *trace_used = 0;

#define JMP_TAB_ID interp_trace
#define JMP_TAB_PRE_CASE_CODE \
  fd_memcpy( trace[*trace_used].register_file, register_file, 11*sizeof(ulong)); \
  trace[*trace_used].pc = (ulong)pc; \
  trace[*trace_used].ic = ic; \
  (*trace_used)++;
#define JMP_TAB_POST_CASE_CODE \
  ic++; \
  if( ic > trace_sz ) goto JT_RET_LOC; \
  instr = ctx->instrs[++pc]; \
  goto *(locs[instr.opcode.raw]);
#include "fd_jump_tab.c"

  fd_sbpf_instr_t instr;

  static const void * locs[222] = {
#include "fd_vm_interp_locs.c"
  };

  instr = ctx->instrs[pc];

  goto *(locs[instr.opcode.raw]);

JT_START;
#include "fd_vm_interp_dispatch_tab.c"
JT_END;

  ctx->program_counter = (ulong) pc;
  ctx->instruction_counter = ic;
  ctx->cond_fault = cond_fault;

#include "fd_jump_tab_teardown.c"
#undef JMP_TAB_ID

  // FIXME: Actual errors!
  return 0;
}

