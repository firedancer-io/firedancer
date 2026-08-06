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
     vaddr_lo is in vaddr space (region bits included); region_sz is the
     covered byte span.  Initialized to guaranteed-miss state
     (region_sz=0, so any access of size>=1 misses). */
  fd_vm_tlb_slot_t tlb_ld = { .haddr_base = 0, .vaddr_lo = 0, .region_sz = 0 };
  fd_vm_tlb_slot_t tlb_st = { .haddr_base = 0, .vaddr_lo = 0, .region_sz = 0 };

  int err = FD_VM_SUCCESS;

  /* Run the VM */
# include "fd_vm_interp_core.c"

  (void)stack_gaps_enabled;
  (void)skip_tlb_input_region;
  (void)tlb_ld; (void)tlb_st;

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

/* Out-of-line soft-TLB miss handler.  Defined here (and not inlined) so
   the hot hit-path wrapper in fd_vm_private.h stays tiny. */

ulong
fd_vm_mem_haddr_tlb_miss( fd_vm_t const *    vm,
                          ulong              vaddr,
                          ulong              sz,
                          uchar              write,
                          fd_vm_tlb_slot_t * slot,
                          int                stack_gaps_enabled ) {
  /* Region tables and the failure sentinel are derived here, on the cold
     path, so the hot caller need not pass them. */
  ulong const * vm_region_haddr = vm->region_haddr;
  uint  const * vm_region_sz    = write ? vm->region_st_sz : vm->region_ld_sz;
  ulong const   sentinel        = 0UL;

  ulong region = FD_VADDR_TO_REGION( vaddr );
  ulong offset = vaddr & FD_VM_OFFSET_MASK;
  ulong region_bits = region << FD_VM_MEM_MAP_REGION_VIRT_ADDR_BITS;

  if( FD_UNLIKELY( region == FD_VM_INPUT_REGION ) ) {
    if( FD_UNLIKELY( vm->input_mem_regions_cnt==0 ) ) return sentinel;

    ulong idx = fd_vm_get_input_mem_region_idx( vm, offset );
    if( FD_UNLIKELY( idx>=vm->input_mem_regions_cnt ) ) return sentinel;

    fd_vm_input_region_t const * ir = &vm->input_mem_regions[ idx ];

    ulong bytes_in_region = fd_ulong_sat_sub( ir->region_sz,
                              fd_ulong_sat_sub( offset, ir->vaddr_offset ) );
    if( FD_UNLIKELY( sz>bytes_in_region ) ) {
      fd_vm_handle_input_mem_region_oob( vm, offset, sz, idx, write );
      ir = &vm->input_mem_regions[ idx ];
      bytes_in_region = fd_ulong_sat_sub( ir->region_sz,
                          fd_ulong_sat_sub( offset, ir->vaddr_offset ) );
      if( FD_UNLIKELY( sz>bytes_in_region ) ) return sentinel;
    }

    if( FD_UNLIKELY( write && ir->is_writable==0U ) ) return sentinel;

    ulong haddr = ir->haddr + offset - ir->vaddr_offset;
    slot->vaddr_lo   = region_bits | ir->vaddr_offset;
    slot->region_sz  = ir->region_sz;       /* span of the input sub-region */
    slot->haddr_base = ir->haddr;            /* host addr of vaddr_lo        */
    return haddr;
  }

  ulong adj_offset = offset;
  if( FD_UNLIKELY( region == FD_VM_STACK_REGION && stack_gaps_enabled ) ) {
    if( FD_UNLIKELY( !!(vaddr & 0x1000) ) ) return sentinel;
    ulong gap_mask = 0xFFFFFFFFFFFFF000UL;
    adj_offset = ( ( offset & gap_mask ) >> 1 ) | ( offset & ~gap_mask );
  }

  ulong region_sz = (ulong)vm_region_sz[ region ];
  ulong sz_max    = region_sz - fd_ulong_min( adj_offset, region_sz );
  if( FD_UNLIKELY( sz > sz_max ) ) return sentinel;

  ulong haddr = vm_region_haddr[ region ] + adj_offset;

  /* Determine the covered vaddr range [vaddr_lo, vaddr_lo+slot_sz).  The
     vaddr->haddr map is linear within this range, so haddr_base (the host
     addr of vaddr_lo) is haddr - (vaddr - vaddr_lo). */
  ulong vaddr_lo, slot_sz;
  if( FD_UNLIKELY( region == FD_VM_STACK_REGION && stack_gaps_enabled ) ) {
    ulong frame_base = offset & ~0x1FFFUL;
    vaddr_lo = region_bits | frame_base;
    slot_sz  = 0x1000UL;
    fd_vm_t * vm_mut = (fd_vm_t *)vm;
    fd_vm_lazy_zero_pages( vm_mut->stack_zero_bitmap, vm_mut->stack, frame_base >> 1, 0x1000UL );
  } else if( FD_UNLIKELY( region == FD_VM_STACK_REGION || region == FD_VM_HEAP_REGION ) ) {
    ulong page_base = offset & ~(FD_VM_LAZY_PAGE_SZ - 1UL);
    vaddr_lo = region_bits | page_base;
    /* Clamp to the region boundary: heap_max is only 1KB-aligned, so the
       last lazy page can extend past region_sz.  Without the clamp the
       cached slot would accept out-of-bounds accesses in
       [region_sz, page_base+FD_VM_LAZY_PAGE_SZ) that the miss path
       correctly rejects (consensus divergence vs agave). */
    slot_sz  = fd_ulong_min( FD_VM_LAZY_PAGE_SZ, region_sz - page_base );
    fd_vm_t * vm_mut = (fd_vm_t *)vm;
    ulong * bitmap = (region == FD_VM_STACK_REGION) ? vm_mut->stack_zero_bitmap : vm_mut->heap_zero_bitmap;
    uchar * base   = (region == FD_VM_STACK_REGION) ? vm_mut->stack : vm_mut->heap;
    fd_vm_lazy_zero_pages( bitmap, base, page_base, ( adj_offset + sz ) - page_base );
  } else {
    vaddr_lo = region_bits;
    slot_sz  = region_sz;
  }

  slot->vaddr_lo   = vaddr_lo;
  slot->region_sz  = slot_sz;
  slot->haddr_base = haddr - ( vaddr - vaddr_lo );

  return haddr;
}
