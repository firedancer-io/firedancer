#ifndef HEADER_fd_src_flamenco_vm_fd_vm_private_h
#define HEADER_fd_src_flamenco_vm_fd_vm_private_h

#include "fd_vm.h"

#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../runtime/context/fd_exec_txn_ctx.h"

/* FD_VM_ALIGN_RUST_{} define the alignments for relevant rust types.
   Alignments are derived with std::mem::align_of::<T>() and are enforced
   by the VM (with the exception of v1 loader).

   In our implementation, when calling FD_VM_MEM_HADDR_ST / FD_VM_MEM_HADDR_LD,
   we need to make sure we're passing the correct alignment based on the Rust
   type in the corresponding mapping in Agave.

   FD_VM_ALIGN_RUST_{} has been generated with this Rust code:
   ```rust
      pub type Epoch = u64;
      pub struct Pubkey(pub [u8; 32]);
      pub struct AccountMeta {
          pub lamports: u64,
          pub rent_epoch: Epoch,
          pub owner: Pubkey,
          pub executable: bool,
      }

      pub struct PodScalar(pub [u8; 32]);

      fn main() {
          println!("u8: {}", std::mem::align_of::<u8>());
          println!("u32: {}", std::mem::align_of::<u32>());
          println!("u64: {}", std::mem::align_of::<u64>());
          println!("u128: {}", std::mem::align_of::<u128>());
          println!("&[u8]: {}", std::mem::align_of::<&[u8]>());
          println!("AccountMeta: {}", std::mem::align_of::<AccountMeta>());
          println!("PodScalar: {}", std::mem::align_of::<PodScalar>());
      }
    ``` */

#define FD_VM_ALIGN_RUST_U8           (1UL)
#define FD_VM_ALIGN_RUST_U32          (4UL)
#define FD_VM_ALIGN_RUST_U64          (8UL)
#define FD_VM_ALIGN_RUST_U128        (16UL)
#define FD_VM_ALIGN_RUST_SLICE_U8_REF (8UL)
#define FD_VM_ALIGN_RUST_ACCOUNT_META (8UL)
#define FD_VM_ALIGN_RUST_POD_U8_ARRAY (1UL)

/* fd_vm_vec_t is the in-memory representation of a vector descriptor.
   Equal in layout to the Rust slice header &[_] and various vector
   types in the C version of the syscall API. */
/* FIXME: WHEN IS VADDR NULL AND/OR SZ 0 OKAY? */
/* FIXME: MOVE FD_VM_RUST_VEC_T FROM SYSCALL/FD_VM_CPI.H HERE TOO? */

#define FD_VM_VEC_ALIGN FD_VM_ALIGN_RUST_SLICE_U8_REF
#define FD_VM_VEC_SIZE  (16UL)

struct __attribute__((packed)) fd_vm_vec {
  ulong addr; /* FIXME: NAME -> VADDR */
  ulong len;  /* FIXME: NAME -> SZ */
};

typedef struct fd_vm_vec fd_vm_vec_t;

FD_PROTOTYPES_BEGIN

/* fd_vm_cu API *******************************************************/

/* FIXME: CONSIDER MOVING TO FD_VM_SYSCALL.H */
/* FD_VM_CU_UPDATE charges the vm cost compute units.

   If the vm does not have more than cost cu available, this will cause
   the caller to zero out the vm->cu and return with FD_VM_ERR_SIGCOST.
   This macro is robust.
   This is meant to be used by syscall implementations and strictly
   conforms with the vm-syscall ABI interface.

   Note: in Agave a sycall can return success leaving 0 available CUs.
   The instruction will fail at the next instruction (e.g., exit).
   To reproduce the same behavior, we do not return FD_VM_ERR_SIGCOST
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
      return FD_VM_ERR_SIGCOST;                      \
    }                                                \
    _vm->cu = _cu - _cost;                           \
  }))


/* FIXME: IS THIS MORE A CPI THING? */
#define FD_VM_CU_MEM_UPDATE( vm, sz ) (__extension__({                                        \
    fd_vm_t * _vm   = (vm);                                                                   \
    ulong     _sz   = (sz);                                                                   \
    ulong     _cost = fd_ulong_max( FD_VM_MEM_OP_BASE_COST, _sz / FD_VM_CPI_BYTES_PER_UNIT ); \
    ulong     _cu   = _vm->cu;                                                                \
    if( FD_UNLIKELY( _cost>_cu ) ) {                                                          \
      _vm->cu = 0UL;                                                                          \
      return FD_VM_ERR_SIGCOST;                                                               \
    }                                                                                         \
    _vm->cu = _cu - _cost;                                                                    \
  }))

/* FIXME: THESE APIS ARE DEPRECATED */

/* fd_vm_consume_compute consumes `cost` compute units from vm.  Returns
   FD_VM_SUCCESS (0) on success (vm->cu will be strictly positive with
   cost deducted from its value on entry) and FD_VM_ERR_SIGCOST
   (negative) on failure.

   fd_vm_consume_mem is identical except that it consumes 'sz' bytes
   equivalent compute units from vm. */

static inline int
fd_vm_consume_compute( fd_vm_t * vm,
                       ulong     cost ) {
  ulong cu_before = vm->cu;
  vm->cu = cu_before - fd_ulong_min( cost, cu_before );
  return fd_int_if( cost<cu_before, FD_VM_SUCCESS, FD_VM_ERR_SIGCOST ); /* cmov */
}

static inline int
fd_vm_consume_mem( fd_vm_t * vm,
                   ulong     sz ) {
  return fd_vm_consume_compute( vm, fd_ulong_max( FD_VM_MEM_OP_BASE_COST, sz / FD_VM_CPI_BYTES_PER_UNIT ) );
}

/* fd_vm_instr APIs ***************************************************/

/* FIXME: MIGRATE FD_SBPF_INSTR_T STUFF TO THIS API */

/* fd_vm_instr returns the SBPF instruction word corresponding to the
   given fields. */

FD_FN_CONST static inline ulong
fd_vm_instr( ulong opcode, /* Assumed valid */
             ulong dst,    /* Assumed in [0,FD_VM_REG_CNT) */
             ulong src,    /* Assumed in [0,FD_VM_REG_CNT) */
             short offset,
             uint  imm ) {
  return opcode | (dst<<8) | (src<<12) | (((ulong)(ushort)offset)<<16) | (((ulong)imm)<<32);
}

/* fd_vm_instr_* return the SBPF instruction field for the given word.
   fd_vm_instr_{normal,mem}_* only apply to {normal,mem} opclass
   instructions. */

FD_FN_CONST static inline ulong fd_vm_instr_opcode( ulong instr ) { return   instr      & 255UL;       } /* In [0,256) */
FD_FN_CONST static inline ulong fd_vm_instr_dst   ( ulong instr ) { return ((instr>> 8) &  15UL);      } /* In [0,16)  */
FD_FN_CONST static inline ulong fd_vm_instr_src   ( ulong instr ) { return ((instr>>12) &  15UL);      } /* In [0,16)  */
FD_FN_CONST static inline short fd_vm_instr_offset( ulong instr ) { return (short)(ushort)(instr>>16); }
FD_FN_CONST static inline uint  fd_vm_instr_imm   ( ulong instr ) { return (uint)(instr>>32);          }

FD_FN_CONST static inline ulong fd_vm_instr_opclass       ( ulong instr ) { return  instr      & 7UL; } /* In [0,8)  */
FD_FN_CONST static inline ulong fd_vm_instr_normal_opsrc  ( ulong instr ) { return (instr>>3) &  1UL; } /* In [0,2)  */
FD_FN_CONST static inline ulong fd_vm_instr_normal_opmode ( ulong instr ) { return (instr>>4) & 15UL; } /* In [0,16) */
FD_FN_CONST static inline ulong fd_vm_instr_mem_opsize    ( ulong instr ) { return (instr>>3) &  3UL; } /* In [0,4)  */
FD_FN_CONST static inline ulong fd_vm_instr_mem_opaddrmode( ulong instr ) { return (instr>>5) &  7UL; } /* In [0,16) */

/* fd_vm_mem API ******************************************************/

/* fd_vm_mem APIs support the fast mapping of virtual address ranges to
   host address ranges.  Since the SBPF virtual address space consists
   of 4 consecutive 4GiB regions and the mapable size of each region is
   less than 4 GiB (as implied by FD_VM_MEM_MAP_REGION_SZ==2^32-1 and
   that Solana protocol limits are much smaller still), it is impossible
   for a valid virtual address range to span multiple regions. */

/* fd_vm_mem_cfg configures the vm's tlb arrays.  Assumes vm is valid
   and vm already has configured the rodata, stack, heap and input
   regions.  Returns vm. */

static inline fd_vm_t *
fd_vm_mem_cfg( fd_vm_t * vm ) {
  vm->region_haddr[0] = 0UL;               vm->region_ld_sz[0] = (uint)0UL;             vm->region_st_sz[0] = (uint)0UL;
  vm->region_haddr[1] = (ulong)vm->rodata; vm->region_ld_sz[1] = (uint)vm->rodata_sz;   vm->region_st_sz[1] = (uint)0UL;
  vm->region_haddr[2] = (ulong)vm->stack;  vm->region_ld_sz[2] = (uint)FD_VM_STACK_MAX; vm->region_st_sz[2] = (uint)FD_VM_STACK_MAX;
  vm->region_haddr[3] = (ulong)vm->heap;   vm->region_ld_sz[3] = (uint)vm->heap_max;    vm->region_st_sz[3] = (uint)vm->heap_max;
  vm->region_haddr[4] = (ulong)vm->input;  vm->region_ld_sz[4] = (uint)vm->input_sz;    vm->region_st_sz[4] = (uint)vm->input_sz;
  vm->region_haddr[5] = 0UL;               vm->region_ld_sz[5] = (uint)0UL;             vm->region_st_sz[5] = (uint)0UL;
  return vm;
}

/* fd_vm_mem_haddr translates the vaddr range [vaddr,vaddr+sz) (in
   infinite precision math) into the non-wrapping haddr range
   [haddr,haddr+sz).  On success, returns haddr and every byte in the
   haddr range is a valid address.  On failure, returns sentinel and
   there was at least one byte in the virtual address range that did not
   have a corresponding byte inthe host address range.

   IMPORTANT SAFETY TIP!  When sz==0, the return value currently is
   arbitrary.  This is often fine as there should be no
   actual accesses to a sz==0 region.  However, this also means that
   testing return for sentinel is insufficient to tell if mapping
   failed.  That is, assuming sentinel is a location that could never
   happen on success):

     sz!=0 and ret!=sentinel -> success
     sz!=0 and ret==sentinel -> failure
     sz==0 -> ignore ret, application specific handling

   With ~O(2) extra fast branchless instructions, the below could be
   tweaked in the sz==0 case to return NULL or return a non-NULL
   sentinel value.  What is most optimal practically depends on how
   empty ranges and NULL vaddr handling is defined in the application.

   Requires ~O(10) fast branchless assembly instructions with 2 L1 cache
   hit loads and pretty good ILP.

   fd_vm_mem_haddr_fast is when the vaddr is for use when it is already
   known that the vaddr region has a valid mapping. */

FD_FN_PURE static inline ulong
fd_vm_mem_haddr( FD_FN_UNUSED fd_vm_t const *  vm,
                 ulong                         vaddr,
                 ulong                         sz,
                 ulong const *                 vm_region_haddr, /* indexed [0,6) */
                 uint  const *                 vm_region_sz,    /* indexed [0,6) */
                 FD_FN_UNUSED uchar            write,           /* 1 if the access is a write, 0 if it is a read */
                 ulong                         sentinel ) {
  ulong vaddr_hi  = vaddr >> 32;
  ulong region    = fd_ulong_min( vaddr_hi, 5UL );
  ulong offset    = vaddr & 0xffffffffUL;
  ulong region_sz = (ulong)vm_region_sz[ region ];
  ulong sz_max    = region_sz - fd_ulong_min( offset, region_sz );
# ifdef FD_VM_INTERP_MEM_TRACING_ENABLED
  if ( FD_LIKELY( sz<=sz_max ) ) {
    fd_vm_trace_event_mem( vm->trace, write, vaddr, sz, vm_region_haddr[ region ] + offset );
  }
# endif
  return fd_ulong_if( sz<=sz_max, vm_region_haddr[ region ] + offset, sentinel );
}

FD_FN_PURE static inline ulong
fd_vm_mem_haddr_fast( ulong         vaddr,
                      ulong const * vm_region_haddr ) { /* indexed [0,6) */
  ulong region = vaddr >> 32;
  ulong offset = vaddr & 0xffffffffUL;
  return vm_region_haddr[ region ] + offset;
}

/* fd_vm_mem_ld_N loads N bytes from the host address location haddr,
   zero extends it to a ulong and returns the ulong.  haddr need not be
   aligned. */

FD_FN_PURE static inline ulong fd_vm_mem_ld_1( ulong haddr ) { return (ulong)*(uchar const *)haddr; }
FD_FN_PURE static inline ulong fd_vm_mem_ld_2( ulong haddr ) { ushort t; memcpy( &t, (void const *)haddr, sizeof(ushort) ); return (ulong)t; }
FD_FN_PURE static inline ulong fd_vm_mem_ld_4( ulong haddr ) { uint   t; memcpy( &t, (void const *)haddr, sizeof(uint)   ); return (ulong)t; }
FD_FN_PURE static inline ulong fd_vm_mem_ld_8( ulong haddr ) { ulong  t; memcpy( &t, (void const *)haddr, sizeof(ulong)  ); return (ulong)t; }

/* fd_vm_mem_st_N stores val in little endian order to the host address
   location haddr.  haddr need not be aligned. */

static inline void fd_vm_mem_st_1( ulong haddr, uchar  val ) { *(uchar *)haddr = val; }
static inline void fd_vm_mem_st_2( ulong haddr, ushort val ) { memcpy( (void *)haddr, &val, sizeof(ushort) ); }
static inline void fd_vm_mem_st_4( ulong haddr, uint   val ) { memcpy( (void *)haddr, &val, sizeof(uint)   ); }
static inline void fd_vm_mem_st_8( ulong haddr, ulong  val ) { memcpy( (void *)haddr, &val, sizeof(ulong)  ); }

/* FIXME: CONSIDER MOVING TO FD_VM_SYSCALL.H */
/* FD_VM_MEM_HADDR_LD returns a read only pointer to the first byte
   in the host address space corresponding to vm's virtual address range
   [vaddr,vaddr+sz).  If the vm has check_align enabled, the vaddr
   should be aligned to align and the returned pointer will be similarly
   aligned.  Align is assumed to be a power of two <= 8 (FIXME: CHECK
   THIS LIMIT).

   If the virtual address range cannot be mapped to the host address
   space completely and/or (when applicable) vaddr is not appropriately
   aligned, this will cause the caller to return FD_VM_ERR_SIGSEGV.
   This macro is robust.  This is meant to be used by syscall
   implementations and strictly conforms with the vm-syscall ABI
   interface.

   FD_VM_MEM_HADDR_ST returns a read-write pointer but is otherwise
   identical to FD_VM_MEM_HADDR_LD.

   FD_VM_MEM_HADDR_LD_FAST and FD_VM_HADDR_ST_FAST are for use when the
   corresponding vaddr region it known to correctly resolve (e.g.  a
   syscall has already done preflight checks on them). */

#define FD_VM_MEM_HADDR_LD( vm, vaddr, align, sz ) (__extension__({                                       \
    fd_vm_t const * _vm     = (vm);                                                                       \
    ulong           _vaddr  = (vaddr);                                                                    \
    int             _sigbus = _vm->check_align & (!fd_ulong_is_aligned( _vaddr, (align) ));               \
    ulong           _haddr  = fd_vm_mem_haddr( vm, _vaddr, (sz), _vm->region_haddr, _vm->region_ld_sz, 0, 0UL ); \
    if( FD_UNLIKELY( (!_haddr) | _sigbus) ) return FD_VM_ERR_SIGSEGV;                                     \
    (void const *)_haddr;                                                                                 \
  }))

#define FD_VM_MEM_HADDR_ST( vm, vaddr, align, sz ) (__extension__({                                       \
    fd_vm_t const * _vm     = (vm);                                                                       \
    ulong           _vaddr  = (vaddr);                                                                    \
    int             _sigbus = _vm->check_align & (!fd_ulong_is_aligned( _vaddr, (align) ));               \
    ulong           _haddr  = fd_vm_mem_haddr( vm, _vaddr, (sz), _vm->region_haddr, _vm->region_st_sz, 1, 0UL ); \
    if( FD_UNLIKELY( (!_haddr) | _sigbus) ) return FD_VM_ERR_SIGSEGV;                                     \
    (void *)_haddr;                                                                                       \
  }))

#define FD_VM_MEM_HADDR_LD_FAST( vm, vaddr ) ((void const *)fd_vm_mem_haddr_fast( (vaddr), (vm)->region_haddr ))
#define FD_VM_MEM_HADDR_ST_FAST( vm, vaddr ) ((void       *)fd_vm_mem_haddr_fast( (vaddr), (vm)->region_haddr ))

/* fd_vm_log API ******************************************************/

/* fd_vm_log returns the location where VM log messages are appended
   (will be non-NULL and aligned 8).  fd_vm_log_{max,sz,rem} return how
   the VM log message buffer is currently utilized.  max will be
   FD_VM_LOG_MAX (positive multiple of 8) and sz will be in [0,max].
   Bytes [0,sz) are currently buffered log bytes and [sz,max) are bytes
   available for additional buffering.  rem = max-sz is the number of
   bytes available for logging.  These assume vm is valid. */

FD_FN_CONST static inline uchar const * fd_vm_log    ( fd_vm_t const * vm ) { return vm->log;                    }
FD_FN_CONST static inline ulong         fd_vm_log_max( fd_vm_t const * vm ) { (void)vm; return FD_VM_LOG_MAX;    }
FD_FN_PURE  static inline ulong         fd_vm_log_sz ( fd_vm_t const * vm ) { return vm->log_sz;                 }
FD_FN_PURE  static inline ulong         fd_vm_log_rem( fd_vm_t const * vm ) { return FD_VM_LOG_MAX - vm->log_sz; }

/* fd_vm_log_prepare starts zero-copy preparation of a new vm log
   message.  The lifetime of the returned location is the lesser of the
   lifetime of the vm or until the prepare is published or cancelled.
   The caller is free to clobber any bytes in this region while it is
   preparing the message.  This region has arbitrary alignment.

   fd_vm_log_prepare_max returns the number bytes available in the log
   preparation region.  Will be at least FD_VM_LOG_TAIL and at most
   FD_VM_LOG_MAX+FD_VM_LOG_TAIL.  Assumes there is a message in
   preparation.

   fd_vm_log_cancel stops preparing a message in preparation without
   publishing it.  Assumes there is a message in preparation.  Returns
   vm.  There is no message in preparation on return.

   fd_vm_log_publish appends the leading fd_vm_log_rem bytes of the
   prepare region to the VM log.  Assumes there is message in
   preparation and sz is in [0,prepare_max].  Returns vm.  There is no
   message in preparation on return.

   These all assume vm valid. */

FD_FN_PURE static inline ulong
fd_vm_log_prepare_max( fd_vm_t const * vm ) {
  return FD_VM_LOG_MAX + FD_VM_LOG_TAIL - vm->log_sz;
}

FD_FN_PURE  static inline void *    fd_vm_log_prepare( fd_vm_t * vm ) { return vm->log + vm->log_sz; }
FD_FN_CONST static inline fd_vm_t * fd_vm_log_cancel ( fd_vm_t * vm ) { return vm;                   }

static inline fd_vm_t *
fd_vm_log_publish( fd_vm_t * vm,
                   ulong     sz ) {
  vm->log_sz = fd_ulong_min( FD_VM_LOG_MAX, vm->log_sz + sz );
  return vm;
}

/* fd_vm_log_reset resets the VM's log to empty and cancels any messages
   in preparation.  Assumes vm is valid. */

static inline fd_vm_t * fd_vm_log_reset( fd_vm_t * vm ) { vm->log_sz = 0UL; return vm; }

/* fd_vm_log_append cancels any VM log message in preparation on vm and
   appends a message of sz bytes to the VM's log, truncating as
   necessary.  Assumes vm, msg and sz are valid.  sz 0 is fine (and NULL
   msg is fine if sz is 0).  Returns vm. */

static inline fd_vm_t *
fd_vm_log_append( fd_vm_t *    vm,
                  void const * msg,
                  ulong        sz ) {
  ulong log_sz = vm->log_sz;
  ulong cpy_sz = fd_ulong_min( sz, FD_VM_LOG_MAX - log_sz );
  if( FD_LIKELY( cpy_sz ) ) memcpy( vm->log + log_sz, msg, cpy_sz ); /* Sigh ... branchless if sz==0 wasn't UB */
  vm->log_sz = log_sz + cpy_sz;
  return vm;
}

/* fd_vm_log_append_printf is analogous to fd_vm_log_append and allows
   to format arguments like printf.
   It cancels any VM log message in preparation on vm and appends the message
   resulting from formatting args to the VM's log.  The formatted message
   includes a last byte set to 0.
   Assumes vm is valid.
   In case of formatting errors, no log is appended and the error is ignored
   (internally, _vm->log[_vm->log_sz] is overwritten with 0).
   Returns vm. */

#define fd_vm_log_append_printf( vm, fmt, ... ) (__extension__({             \
    fd_vm_t * _vm  = (vm);                                                   \
    ulong     _sz  = _vm->log_sz; /* In [0,FD_VM_LOG_MAX] */                 \
    ulong     _len;                                                          \
    fd_cstr_printf_check( (char *)_vm->log + _sz, FD_VM_LOG_MAX + 1UL - _sz, \
                          &_len, (fmt), __VA_ARGS__ );                       \
    _vm->log_sz = _sz + _len;                                                \
    (_vm);                                                                   \
}))

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_private_h */
