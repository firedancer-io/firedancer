#include "fd_vm_base.h"
#include "fd_vm_private.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../runtime/tests/fd_dump_pb.h"

/* GCC >= 15 generates excessive NOP padding when aligning jump targets
   to 32 bytes inside the computed-goto interpreter dispatch.  The
   indirect branch targets are predicted by the BTB, not decoded inline,
   so the padding only wastes I-cache capacity.  Override the
   project-wide -falign-* flags for this translation unit. */
#if defined(FD_USING_GCC) && (__GNUC__ >= 15)
#pragma GCC optimize("align-jumps=1", "align-labels=1", "align-loops=1")
#endif

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
