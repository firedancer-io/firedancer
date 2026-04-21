#include "fd_vm_base.h"
#include "fd_vm_private.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../runtime/tests/fd_dump_pb.h"

/* FIXME: MAKE DIFFERENT VERSIONS FOR EACH COMBO OF CHECK_ALIGN/TRACE? */
/* TODO: factor out common unpacking code */

int
fd_vm_exec_notrace( fd_vm_t * vm ) {

# undef FD_VM_INTERP_EXE_TRACING_ENABLED
# undef FD_VM_INTERP_MEM_TRACING_ENABLED

  /* Pull out variables needed for the fd_vm_interp_core template */
  ulong frame_max   = FD_VM_STACK_FRAME_MAX; /* FIXME: vm->frame_max to make this run-time configured */

  ulong const * FD_RESTRICT text          = vm->text;
  ulong                     text_cnt      = vm->text_cnt;
  ulong                     entry_pc      = vm->entry_pc;
  ulong const * FD_RESTRICT calldests     = vm->calldests;

  fd_sbpf_syscalls_t const * FD_RESTRICT syscalls = vm->syscalls;

  ulong const * FD_RESTRICT region_haddr = vm->region_haddr;
  uint  const * FD_RESTRICT region_ld_sz = vm->region_ld_sz;
  uint  const * FD_RESTRICT region_st_sz = vm->region_st_sz;

  ulong * FD_RESTRICT reg = vm->reg;

  fd_vm_shadow_t * FD_RESTRICT shadow = vm->shadow;

  /* Precompute stack gap flag to avoid struct field load on every TLB miss (B1a) */
  int stack_gaps_enabled = (vm->stack_push_frame_count > 1);

  /* Skip the TLB entirely for input-region accesses when direct
     mapping is on.  Under DM the input region is split into many
     small per-account sub-regions, so the single-slot TLB tends to
     thrash on alternating-account workloads (audit §1.2): each
     access misses, calls into the noinline miss handler, runs the
     binary search, and writes a slot that the next access invalidates.
     Routing input accesses straight to fd_vm_mem_haddr (binary search
     only, no TLB read or write) avoids the hit-check + miss-call
     overhead for those accesses while preserving the TLB benefit for
     stack/heap/program/rodata.

     Encoding: holds the high-32-bit value that triggers the bypass.
     Set to FD_VM_INPUT_REGION (4) when DM is on; set to 0xFFUL
     (unreachable for any valid SBPF vaddr, since the highest live
     region index is 5) when DM is off so the predicate is a single
     compare that is constant-false for every access. */
  ulong skip_tlb_input_region = vm->direct_mapping ? FD_VM_INPUT_REGION : 0xFFUL;

  /* Soft TLB: single-slot cache for load and store translations.
     Bounds stored in vaddr space (region bits included) so the hit
     check is just two comparisons.  Initialized to guaranteed-miss
     state (vaddr_hi=0). */
  ulong tlb_ld_haddr_base = 0;
  ulong tlb_ld_vaddr_lo   = ULONG_MAX;
  ulong tlb_ld_vaddr_hi   = 0;
  ulong tlb_st_haddr_base = 0;
  ulong tlb_st_vaddr_lo   = ULONG_MAX;
  ulong tlb_st_vaddr_hi   = 0;

  int err = FD_VM_SUCCESS;

  /* Run the VM */
# include "fd_vm_interp_core.c"

  (void)stack_gaps_enabled;
  (void)skip_tlb_input_region;
  (void)tlb_ld_haddr_base; (void)tlb_ld_vaddr_lo; (void)tlb_ld_vaddr_hi;
  (void)tlb_st_haddr_base; (void)tlb_st_vaddr_lo; (void)tlb_st_vaddr_hi;

  return err;
}

int
fd_vm_exec_trace( fd_vm_t * vm ) {

# define FD_VM_INTERP_EXE_TRACING_ENABLED 1
# define FD_VM_INTERP_MEM_TRACING_ENABLED 1

  /* Pull out variables needed for the fd_vm_interp_core template */
  ulong frame_max   = FD_VM_STACK_FRAME_MAX; /* FIXME: vm->frame_max to make this run-time configured */

  ulong const * FD_RESTRICT text          = vm->text;
  ulong                     text_cnt      = vm->text_cnt;
  ulong                     entry_pc      = vm->entry_pc;
  ulong const * FD_RESTRICT calldests     = vm->calldests;

  fd_sbpf_syscalls_t const * FD_RESTRICT syscalls = vm->syscalls;

  ulong const * FD_RESTRICT region_haddr = vm->region_haddr;
  uint  const * FD_RESTRICT region_ld_sz = vm->region_ld_sz;
  uint  const * FD_RESTRICT region_st_sz = vm->region_st_sz;

  ulong * FD_RESTRICT reg = vm->reg;

  fd_vm_shadow_t * FD_RESTRICT shadow = vm->shadow;

  int err = FD_VM_SUCCESS;

  /* Run the VM */
# include "fd_vm_interp_core.c"

# undef FD_VM_INTERP_EXE_TRACING_ENABLED
# undef FD_VM_INTERP_MEM_TRACING_ENABLED

  return err;
}
