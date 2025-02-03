#ifndef HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_macros_h
#define HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_macros_h
#include "../fd_vm_private.h"

/* fd_vm_cu API *******************************************************/

/* FD_VM_CU_UPDATE charges the vm cost compute units.

   If the vm does not have more than cost cu available, this will cause
   the caller to zero out the vm->cu and return with FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED.
   This macro is robust.
   This is meant to be used by syscall implementations and strictly
   conforms with the vm-syscall ABI interface.

   Note: in Agave a syscall can return success leaving 0 available CUs.
   The instruction will fail at the next instruction (e.g., exit).
   To reproduce the same behavior, we do not return FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED
   when cu == 0.

   FD_VM_CU_MEM_UPDATE charges the vm the equivalent of sz bytes of
   compute units.  Behavior is otherwise identical to FD_VM_CU_UPDATE.
   FIXME: THIS API PROBABLY BELONGS IN SYSCALL CPI LAND. */

#define FD_VM_CU_UPDATE( vm, cost ) (__extension__({ \
    fd_vm_t * _vm   = (vm);                          \
    ulong     _cost = (cost);                        \
    ulong     _cu   = _vm->cu;                       \
    if( FD_UNLIKELY( _cost>_cu ) ) {                 \
      _vm->cu = 0UL;                                 \
      FD_VM_ERR_FOR_LOG_INSTR( vm, FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED ); \
      return FD_VM_SYSCALL_ERR_COMPUTE_BUDGET_EXCEEDED; \
    }                                                \
    _vm->cu = _cu - _cost;                           \
  }))

/* https://github.com/anza-xyz/agave/blob/5263c9d61f3af060ac995956120bef11c1bbf182/programs/bpf_loader/src/syscalls/mem_ops.rs#L7 */
#define FD_VM_CU_MEM_OP_UPDATE( vm, sz ) \
  FD_VM_CU_UPDATE( vm, fd_ulong_max( FD_VM_MEM_OP_BASE_COST, sz / FD_VM_CPI_BYTES_PER_UNIT ) )


/* fd_vm_mem API *****************************************************/

/* FD_VM_MEM_HADDR_LD returns a read only pointer to the first byte
   in the host address space corresponding to vm's virtual address range
   [vaddr,vaddr+sz).  If the vm has check_align enabled, the vaddr
   should be aligned to align and the returned pointer will be similarly
   aligned.  Align is assumed to be a power of two <= 8 (FIXME: CHECK
   THIS LIMIT).

   If the virtual address range cannot be mapped to the host address
   space completely and/or (when applicable) vaddr is not appropriately
   aligned, this will cause the caller to return FD_VM_SYSCALL_ERR_SEGFAULT.
   This macro is robust.  This is meant to be used by syscall
   implementations and strictly conforms with the vm-syscall ABI
   interface.

   FD_VM_MEM_HADDR_ST returns a read-write pointer but is otherwise
   identical to FD_VM_MEM_HADDR_LD.

   FD_VM_MEM_HADDR_LD_FAST and FD_VM_HADDR_ST_FAST are for use when the
   corresponding vaddr region it known to correctly resolve (e.g.  a
   syscall has already done preflight checks on them).

   These macros intentionally don't support multi region loads/stores.
   The load/store macros are used by vm syscalls and mirror the use
   of translate_slice{_mut}. However, this check does not allow for 
   multi region accesses. So if there is an attempt at a multi region
   translation, an error will be returned. 

   FD_VM_MEM_HADDR_ST_UNCHECKED has all of the checks of a load or a 
   store, but intentionally omits the is_writable checks for the 
   input region that are done during memory translation. 
   
   FD_VM_MEM_HADDR_ST_NO_SZ_CHECK does all of the checks of a load,
   except for a check on the validity of the size of a load. It only
   checks that the specific vaddr that is being translated is valid. */

#define FD_VM_MEM_HADDR_LD( vm, vaddr, align, sz ) (__extension__({                                         \
    fd_vm_t const * _vm       = (vm);                                                                       \
    uchar           _is_multi = 0;                                                                          \
    ulong           _vaddr    = (vaddr);                                                                    \
    ulong           _haddr    = fd_vm_mem_haddr( vm, _vaddr, (sz), _vm->region_haddr, _vm->region_ld_sz, 0, 0UL, &_is_multi ); \
    int             _sigbus   = fd_vm_is_check_align_enabled( vm ) & (!fd_ulong_is_aligned( _haddr, (align) )); \
    if ( FD_UNLIKELY( sz > LONG_MAX ) ) {                                                                   \
      FD_VM_ERR_FOR_LOG_SYSCALL( _vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );                                   \
      return FD_VM_SYSCALL_ERR_SEGFAULT;                                                                             \
    }                                                                                                       \
    if( FD_UNLIKELY( (!_haddr) | _is_multi) ) {                                                             \
      FD_VM_ERR_FOR_LOG_EBPF( _vm, FD_VM_ERR_EBPF_ACCESS_VIOLATION );                                       \
      return FD_VM_SYSCALL_ERR_SEGFAULT;                                                                             \
    }                                                                                                       \
    if ( FD_UNLIKELY( _sigbus ) ) {                                                                         \
      FD_VM_ERR_FOR_LOG_SYSCALL( _vm, FD_VM_SYSCALL_ERR_UNALIGNED_POINTER );                                \
      return FD_VM_SYSCALL_ERR_SEGFAULT;                                                                             \
    }                                                                                                       \
    (void const *)_haddr;                                                                                   \
  }))

#define FD_VM_MEM_HADDR_LD_UNCHECKED( vm, vaddr, align, sz ) (__extension__({                               \
    fd_vm_t const * _vm       = (vm);                                                                       \
    uchar           _is_multi = 0;                                                                          \
    ulong           _vaddr    = (vaddr);                                                                    \
    ulong           _haddr    = fd_vm_mem_haddr( vm, _vaddr, (sz), _vm->region_haddr, _vm->region_ld_sz, 0, 0UL, &_is_multi ); \
    (void const *)_haddr;                                                                                   \
  }))


#define FD_VM_MEM_HADDR_LD_NO_SZ_CHECK( vm, vaddr, align ) (__extension__({ \
  FD_VM_MEM_HADDR_LD( vm, vaddr, align, 1UL );                              \
  }))

static inline void *
FD_VM_MEM_HADDR_ST_( fd_vm_t const *vm, ulong vaddr, ulong align, ulong sz, int *err ) {
  fd_vm_t const * _vm       = (vm);
  uchar           _is_multi = 0;
  ulong           _vaddr    = (vaddr);
  ulong           _haddr    = fd_vm_mem_haddr( vm, _vaddr, (sz), _vm->region_haddr, _vm->region_st_sz, 1, 0UL, &_is_multi );
  int             _sigbus   = fd_vm_is_check_align_enabled( vm ) & (!fd_ulong_is_aligned( _haddr, (align) ));
  if ( FD_UNLIKELY( sz > LONG_MAX ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( _vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );
    *err = FD_VM_SYSCALL_ERR_SEGFAULT;
    return 0;
  }
  if( FD_UNLIKELY( (!_haddr) | _is_multi) ) {
    FD_VM_ERR_FOR_LOG_EBPF( _vm, FD_VM_ERR_EBPF_ACCESS_VIOLATION );
    *err = FD_VM_SYSCALL_ERR_SEGFAULT;
    return 0;
  }
  if ( FD_UNLIKELY( _sigbus ) ) {
    FD_VM_ERR_FOR_LOG_SYSCALL( _vm, FD_VM_SYSCALL_ERR_UNALIGNED_POINTER );
    *err = FD_VM_SYSCALL_ERR_SEGFAULT;
    return 0;
  }
  return (void *)_haddr;
}

#define FD_VM_MEM_HADDR_ST( vm, vaddr, align, sz ) (__extension__({                                         \
    int _err = 0;                                                                                           \
    void * ret = FD_VM_MEM_HADDR_ST_( vm, vaddr, align, sz, &_err );                                        \
    if ( FD_UNLIKELY( 0 != _err ))                                                                          \
      return _err;                                                                                          \
    ret;                                                                                                    \
}))

#define FD_VM_MEM_HADDR_ST_UNCHECKED( vm, vaddr, align, sz ) (__extension__({                               \
    fd_vm_t const * _vm       = (vm);                                                                       \
    uchar           _is_multi = 0;                                                                          \
    ulong           _vaddr    = (vaddr);                                                                    \
    ulong           _haddr    = fd_vm_mem_haddr( vm, _vaddr, (sz), _vm->region_haddr, _vm->region_st_sz, 1, 0UL, &_is_multi ); \
    (void const *)_haddr;                                                                                   \
  }))

#define FD_VM_MEM_HADDR_ST_WRITE_UNCHECKED( vm, vaddr, align, sz ) (__extension__({                         \
    fd_vm_t const * _vm       = (vm);                                                                       \
    uchar           _is_multi = 0;                                                                          \
    ulong           _vaddr    = (vaddr);                                                                    \
    ulong           _haddr    = fd_vm_mem_haddr( vm, _vaddr, (sz), _vm->region_haddr, _vm->region_st_sz, 0, 0UL, &_is_multi ); \
    int             _sigbus   = fd_vm_is_check_align_enabled( vm ) & (!fd_ulong_is_aligned( _haddr, (align) )); \
    if ( FD_UNLIKELY( sz > LONG_MAX ) ) {                                                                   \
      FD_VM_ERR_FOR_LOG_SYSCALL( _vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );                                   \
      return FD_VM_SYSCALL_ERR_SEGFAULT;                                                                             \
    }                                                                                                       \
    if( FD_UNLIKELY( (!_haddr) | _is_multi ) ) {                                                            \
      FD_VM_ERR_FOR_LOG_EBPF( _vm, FD_VM_ERR_EBPF_ACCESS_VIOLATION );                                       \
      return FD_VM_SYSCALL_ERR_SEGFAULT;                                                                             \
    }                                                                                                       \
    if ( FD_UNLIKELY( _sigbus ) ) {                                                                         \
      FD_VM_ERR_FOR_LOG_SYSCALL( _vm, FD_VM_SYSCALL_ERR_UNALIGNED_POINTER );                                \
      return FD_VM_SYSCALL_ERR_SEGFAULT;                                                                             \
    }                                                                                                       \
    (void *)_haddr;                                                                                         \
  }))


#define FD_VM_MEM_HADDR_ST_NO_SZ_CHECK( vm, vaddr, align ) (__extension__({                                 \
    int _err = 0;                                                                                           \
    void * ret = FD_VM_MEM_HADDR_ST_( vm, vaddr, align, 1UL, &_err );                                       \
    if ( FD_UNLIKELY( 0 != _err ))                                                                          \
      return _err;                                                                                          \
    ret;                                                                                                    \
}))


#define FD_VM_MEM_HADDR_LD_FAST( vm, vaddr ) ((void const *)fd_vm_mem_haddr_fast( (vm), (vaddr), (vm)->region_haddr ))
#define FD_VM_MEM_HADDR_ST_FAST( vm, vaddr ) ((void       *)fd_vm_mem_haddr_fast( (vm), (vaddr), (vm)->region_haddr ))

/* FD_VM_MEM_HADDR_AND_REGION_IDX_FROM_INPUT_REGION_CHECKED simply converts a vaddr within the input memory region
   into an haddr. The sets the region_idx and haddr. */
#define FD_VM_MEM_HADDR_AND_REGION_IDX_FROM_INPUT_REGION_CHECKED( _vm, _offset, _out_region_idx, _out_haddr ) (__extension__({                \
  _out_region_idx = fd_vm_get_input_mem_region_idx( _vm, _offset );                                                                             \
  if( FD_UNLIKELY( _offset>=vm->input_mem_regions[ _out_region_idx ].vaddr_offset+vm->input_mem_regions[ _out_region_idx ].region_sz ) ) {                    \
    FD_VM_ERR_FOR_LOG_EBPF( vm, FD_VM_ERR_EBPF_ACCESS_VIOLATION );                                                                              \
    return FD_VM_SYSCALL_ERR_SEGFAULT;                                                                                                                   \
  }                                                                                                                                             \
  _out_haddr      = (uchar*)_vm->input_mem_regions[ _out_region_idx ].haddr + _offset - _vm->input_mem_regions[ _out_region_idx ].vaddr_offset; \
}))

/* FD_VM_MEM_SLICE_HADDR_[LD, ST] macros return an arbitrary value if sz == 0. This is because
   Agave's translate_slice function returns an empty array if the sz == 0.

   Users of this macro should be aware that they should never access the returned value if sz==0.

   https://github.com/solana-labs/solana/blob/767d24e5c10123c079e656cdcf9aeb8a5dae17db/programs/bpf_loader/src/syscalls/mod.rs#L560 

   LONG_MAX check: https://github.com/anza-xyz/agave/blob/dc4b9dcbbf859ff48f40d00db824bde063fdafcc/programs/bpf_loader/src/syscalls/mod.rs#L580
   Technically, the check in Agave is against
   "pointer-sized signed integer type ... The size of this primitive is
    how many bytes it takes to reference any location in memory. For
    example, on a 32 bit target, this is 4 bytes and on a 64 bit target,
    this is 8 bytes."
   Realistically, given the amount of memory that a validator consumes,
   no one is going to be running on a 32 bit target. So, we don't bother
   with conditionally compiling in an INT_MAX check. We just assume
   LONG_MAX. */
#define FD_VM_MEM_SLICE_HADDR_LD( vm, vaddr, align, sz ) (__extension__({                                       \
    if ( FD_UNLIKELY( sz > LONG_MAX ) ) {                                                                       \
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );                                        \
      return FD_VM_SYSCALL_ERR_INVALID_LENGTH;                                                                  \
    }                                                                                                           \
    void const * haddr = 0UL;                                                                                   \
    if ( FD_LIKELY( (ulong)sz > 0UL ) ) {                                                                       \
      haddr = FD_VM_MEM_HADDR_LD( vm, vaddr, align, sz );                                                       \
    }                                                                                                           \
    haddr;                                                                                                      \
}))


/* This is the same as the above function but passes in a size of 1 to support
   loads with no size bounding support. */
#define FD_VM_MEM_SLICE_HADDR_LD_SZ_UNCHECKED( vm, vaddr, align ) (__extension__({                              \
    if ( FD_UNLIKELY( sz > LONG_MAX ) ) {                                                                       \
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );                                        \
      return FD_VM_SYSCALL_ERR_INVALID_LENGTH;                                                                  \
    }                                                                                                           \
    void const * haddr = 0UL;                                                                                   \
    if ( FD_LIKELY( (ulong)sz > 0UL ) ) {                                                                       \
      haddr = FD_VM_MEM_HADDR_LD( vm, vaddr, align, 1UL );                                                      \
    }                                                                                                           \
    haddr;                                                                                                      \
}))

#define FD_VM_MEM_SLICE_HADDR_ST( vm, vaddr, align, sz ) (__extension__({                                       \
    if ( FD_UNLIKELY( sz > LONG_MAX ) ) {                                                                       \
      FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_INVALID_LENGTH );                                        \
      return FD_VM_SYSCALL_ERR_INVALID_LENGTH;                                                                  \
    }                                                                                                           \
    void * haddr = 0UL;                                                                                         \
    if ( FD_LIKELY( (ulong)sz > 0UL ) ) {                                                                       \
      haddr = FD_VM_MEM_HADDR_ST( vm, vaddr, align, sz );                                                       \
    }                                                                                                           \
    haddr;                                                                                                      \
}))

/* FIXME: use overlap logic from runtime? */
#define FD_VM_MEM_CHECK_NON_OVERLAPPING( vm, vaddr0, sz0, vaddr1, sz1 ) do {                                    \
  if( FD_UNLIKELY( ((vaddr0> vaddr1) && ((vaddr0-vaddr1)<sz1)) ||                                               \
                   ((vaddr1>=vaddr0) && ((vaddr1-vaddr0)<sz0)) ) ) {                                            \
    FD_VM_ERR_FOR_LOG_SYSCALL( vm, FD_VM_SYSCALL_ERR_COPY_OVERLAPPING );                                        \
    return FD_VM_SYSCALL_ERR_COPY_OVERLAPPING;                                                                  \
  }                                                                                                             \
} while(0)

#endif /* HEADER_fd_src_flamenco_vm_syscall_fd_vm_syscall_macros_h */
