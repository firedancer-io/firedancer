#include "fd_transpile_runtime.h"
#include "../fd_vm_private.h"

long
fd_vm_transpiled_mmu_translate( fd_vm_t * vm,
                                ulong     vaddr,
                                ulong     width,
                                uchar     is_write ) {

  vm->transpiled.tlb_vaddr_lo    = 0UL;
  vm->transpiled.tlb_vaddr_ld_hi = 0UL;
  vm->transpiled.tlb_vaddr_st_hi = 0UL;
  vm->transpiled.tlb_haddr_lo    = 0UL;

  uint * region_sz = is_write ? vm->region_st_sz : vm->region_ld_sz;
  ulong haddr = fd_vm_mem_haddr( vm, vaddr, width, vm->region_haddr, region_sz, !!is_write, 0UL );
  vm->transpiled.frame_clean_cnt = vm->stack_clean / FD_VM_STACK_FRAME_SZ;
  if( FD_UNLIKELY( !haddr ) ) {
    vm->segv_vaddr       = vaddr;
    vm->segv_access_type = (uchar)(is_write ? FD_VM_ACCESS_TYPE_ST : FD_VM_ACCESS_TYPE_LD);
    vm->segv_access_len  = width;
    return (long)fd_vm_generate_access_violation( vaddr, vm->sbpf_version );
  }

  if( FD_LIKELY( FD_VADDR_TO_REGION( vaddr )==FD_VM_INPUT_REGION ) ) {
    ulong offset     = vaddr & FD_VM_OFFSET_MASK;
    ulong region_idx = fd_vm_get_input_mem_region_idx( vm, offset );
    fd_vm_input_region_t const * region = &vm->input_mem_regions[ region_idx ];
    ulong vaddr_lo = FD_VM_MEM_MAP_INPUT_REGION_START + region->vaddr_offset;
    ulong vaddr_hi = vaddr_lo + (ulong)region->region_sz;
    vm->transpiled.tlb_vaddr_lo    = vaddr_lo;
    vm->transpiled.tlb_vaddr_ld_hi = vaddr_hi;
    vm->transpiled.tlb_vaddr_st_hi = region->is_writable ? vaddr_hi : vaddr_lo;
    vm->transpiled.tlb_haddr_lo    = region->haddr;
  }

  return (long)haddr;
}

void
fd_vm_transpiled_frame_init( fd_vm_t * vm ) {
  fd_vm_stack_grow( vm, (vm->frame_cnt+1UL)*FD_VM_STACK_FRAME_SZ );
  vm->transpiled.frame_clean_cnt = vm->stack_clean / FD_VM_STACK_FRAME_SZ;
}

__attribute__((weak)) fd_transpile_export_t const * const fd_transpiled_ext[1] = {NULL};
