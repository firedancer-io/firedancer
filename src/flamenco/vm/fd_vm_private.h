#ifndef HEADER_fd_src_flamenco_vm_fd_vm_private_h
#define HEADER_fd_src_flamenco_vm_fd_vm_private_h

#include "fd_vm.h"

#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../ballet/murmur3/fd_murmur3.h"

/* fd_vm_vec_t is the in-memory representation of a vector descriptor.
   Equal in layout to the Rust slice header &[_] and various vector
   types in the C version of the syscall API. */
/* FIXME: WHEN IS VADDR NULL AND/OR SZ 0 OKAY? */
/* FIXME: MOVE FD_VM_RUST_VEC_T FROM SYSCALL/FD_VM_CPI.H HERE TOO? */

#define FD_VM_VEC_ALIGN (8UL)

struct __attribute__((packed)) fd_vm_vec {
  ulong addr; /* FIXME: NAME -> VADDR */
  ulong len;  /* FIXME: NAME -> SZ */
};

typedef struct fd_vm_vec fd_vm_vec_t;

FD_PROTOTYPES_BEGIN

/* fd_vm_cu API *******************************************************/

/* fd_vm_consume_compute consumes `cost` compute units from vm.  Returns
   FD_VM_SUCCESS (0) on success and FD_VM_ERR_BUDGET (negative) on
   failure.  On return, the compute_meter is updated (to zero in the
   ERR_BUDGET case). */

/* FIXME: OPTIMIZE FUNCTION SIGNATURE FOR USE CASE */

static inline int
fd_vm_consume_compute( fd_vm_t * vm,
                       ulong     cost ) {
  ulong compute_meter = vm->compute_meter;
  ulong consumed      = fd_ulong_min( cost, compute_meter );
  vm->compute_meter   = compute_meter - consumed;
  return consumed<=cost ? FD_VM_SUCCESS : FD_VM_ERR_BUDGET; /* cmov */
}

/* fd_vm_consume_mem consumes 'sz' bytes equivalent compute units from
   vm.  Returns FD_VM_SUCCESS (0) on success and FD_VM_ERR_BUDGET
   (negative) on failure.  On return, the compute_meter is updated (to
   zero in the ERR_BUDGET case). */

/* FIXME: OPTIMIZE FUNCTION SIGNATURE FOR USE CASE */

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
   hit loads and pretty good ILP. */

FD_FN_PURE static inline ulong
fd_vm_mem_haddr( ulong         vaddr,
                 ulong         sz,
                 ulong const * vm_region_haddr, /* indexed [0,6) */
                 uint  const * vm_region_sz,    /* indexed [0,6) */
                 ulong         sentinel ) {
  ulong vaddr_hi  = vaddr >> 32;
  ulong region    = fd_ulong_min( vaddr_hi, 5UL );
  ulong offset    = vaddr & 0xffffffffUL;
  ulong region_sz = (ulong)vm_region_sz[ region ];
  ulong sz_max    = region_sz - fd_ulong_min( offset, region_sz );
  return fd_ulong_if( sz<=sz_max, vm_region_haddr[ region ] + offset, sentinel );
}

/* fd_vm_mem_ld_N loads N bytes from the host address location haddr,
   zero extends it to a ulong and returns the ulong.  haddr need not be
   aligned. */

static inline ulong fd_vm_mem_ld_1( ulong haddr ) { return (ulong)*(uchar const *)haddr; }
static inline ulong fd_vm_mem_ld_2( ulong haddr ) { ushort t; memcpy( &t, (void const *)haddr, sizeof(ushort) ); return (ulong)t; }
static inline ulong fd_vm_mem_ld_4( ulong haddr ) { uint   t; memcpy( &t, (void const *)haddr, sizeof(uint)   ); return (ulong)t; }
static inline ulong fd_vm_mem_ld_8( ulong haddr ) { ulong  t; memcpy( &t, (void const *)haddr, sizeof(ulong)  ); return (ulong)t; }

/* fd_vm_mem_st_N stores val in little endian order to the host address
   location haddr.  haddr need not be aligned. */

static inline void fd_vm_mem_st_1( ulong haddr, uchar  val ) { *(uchar *)haddr = val; }
static inline void fd_vm_mem_st_2( ulong haddr, ushort val ) { memcpy( (void *)haddr, &val, sizeof(ushort) ); }
static inline void fd_vm_mem_st_4( ulong haddr, uint   val ) { memcpy( (void *)haddr, &val, sizeof(uint)   ); }
static inline void fd_vm_mem_st_8( ulong haddr, ulong  val ) { memcpy( (void *)haddr, &val, sizeof(ulong)  ); }

/* FIXME: THE BELOW TRANSLATE APIS ARE ALL DEPRECATED */

/* fd_vm_translate_vm_to_host{_const} translates a vm memory area into
   the caller's local address space.  [vaddr,vaddr+sz) are the memory
   area in the virtual address space.  align is vaddr's required
   alignment (integer power of two).  Returns a pointer to same memory
   region in local address space on success.  On failure, returns NULL.
   Reasons for failure include access violation (out-of-bounds access,
   write requested on read-only region).

   fd_vm_translate_vm_to_host checks whether the target area is writable
   and returns a pointer to a mutable data region.

   fd_vm_translate_vm_to_host_const is the read-only equivalent and
   checks for a read-only or writable data region.

   Security note: Watch out for pointer aliasing when translating
   multiple user-specified data types. */
/* FIXME: NAME? */
/* FIXME: INLINE? */
/* FIXME: SZ==0 HANDLING? */
/* FIXME: FUNC SIGNATURE? */
/* FIXME: ARG ORDERING CONVENTION IS ALIGN/SZ */

ulong
fd_vm_translate_vm_to_host_private( fd_vm_t * vm,
                                    ulong     vaddr,
                                    ulong     sz,
                                    int       write );

static inline void *
fd_vm_translate_vm_to_host( fd_vm_t * vm,
                            ulong     vaddr,
                            ulong     sz,
                            ulong     align ) {
  if( vm->check_align && FD_UNLIKELY( !fd_ulong_is_aligned( vaddr, align ) ) ) return NULL;
  return (void *)fd_vm_translate_vm_to_host_private( vm, vaddr, sz, 1 );
}

static inline void const *
fd_vm_translate_vm_to_host_const( fd_vm_t * vm,
                                  ulong     vaddr,
                                  ulong     sz,
                                  ulong     align ) {
  if( vm->check_align && FD_UNLIKELY( !fd_ulong_is_aligned( vaddr, align ) ) ) return NULL;
  return (void const *)fd_vm_translate_vm_to_host_private( vm, vaddr, sz, 0 );
}

static inline fd_vm_vec_t *
fd_vm_translate_slice_vm_to_host( fd_vm_t * vm,
                                  ulong     vaddr,
                                  ulong     sz,
                                  ulong     align ) {
  if( vm->check_size && FD_UNLIKELY( fd_ulong_sat_mul( sz, sizeof(fd_vm_vec_t) )>LONG_MAX ) ) return NULL;
  return (fd_vm_vec_t *)fd_vm_translate_vm_to_host( vm, vaddr, sz, align );
}

static inline fd_vm_vec_t const *
fd_vm_translate_slice_vm_to_host_const( fd_vm_t * vm,
                                        ulong     vaddr,
                                        ulong     sz,
                                        ulong     align ) {
  if( vm->check_size && FD_UNLIKELY( fd_ulong_sat_mul( sz, sizeof(fd_vm_vec_t) )>LONG_MAX ) ) return NULL;
  return (fd_vm_vec_t const *)fd_vm_translate_vm_to_host_const( vm, vaddr, sz, align );
}

/* fd_vm_stack API ****************************************************/

/* FIXME: CONSIDER HANDLING THE STACK POINTER REG IN HERE TOO! */

/* fd_vm_stack_empty/full returns 1 if the stack is empty/full and 0 if
   not.  Assumes vm is valid. */

FD_FN_PURE static inline int fd_vm_stack_is_empty( fd_vm_t const * vm ) { return !vm->frame_cnt;                       }
FD_FN_PURE static inline int fd_vm_stack_is_full ( fd_vm_t const * vm ) { return vm->frame_cnt==FD_VM_STACK_FRAME_MAX; }

/* FIXME: consider zero copy API and/or failure free API? */

/* fd_vm_stack_reset pops all frames off the stack.  Assumes vm is
   valid.  Returns FD_VM_SUCCESS (0). */

static inline int
fd_vm_stack_reset( fd_vm_t * vm ) {
  vm->frame_cnt = 0UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_stack_push pushes a new frame onto the VM stack.  Assumes vm,
   rip and reg is valid.  Returns FD_VM_SUCCESS (0) on success or
   FD_VM_ERR_FULL (negative) on failure. */

static inline int
fd_vm_stack_push( fd_vm_t *   vm,
                  ulong       rip,
                  ulong const reg[ FD_VM_SHADOW_REG_CNT ] ) {
  ulong frame_idx = vm->frame_cnt;
  if( FD_UNLIKELY( frame_idx>=FD_VM_STACK_FRAME_MAX ) ) return FD_VM_ERR_FULL;
  fd_vm_shadow_t * shadow = vm->shadow + frame_idx;
  shadow->rip = rip;
  memcpy( shadow->reg, reg, FD_VM_SHADOW_REG_CNT*sizeof(ulong) );
  vm->frame_cnt = frame_idx + 1UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_stack_pop pops a frame off the VM stack.  Assumes vm, _rip and
   reg are valid.  Returns FD_VM_SUCCESS (0) on success and
   FD_VM_ERR_EMPTY (negative) on failure.  On success, *_rip and reg[*]
   hold the values popped off the stack on return.  These are unchanged
   otherwise. */

static inline int
fd_vm_stack_pop( fd_vm_t * vm,
                 ulong *   _rip,
                 ulong     reg[ FD_VM_SHADOW_REG_CNT ] ) {
  ulong frame_idx = vm->frame_cnt;
  if( FD_UNLIKELY( !frame_idx ) ) return FD_VM_ERR_EMPTY;
  frame_idx--;
  fd_vm_shadow_t * shadow = vm->shadow + frame_idx;
  *_rip = shadow->rip;
  memcpy( reg, shadow->reg, FD_VM_SHADOW_REG_CNT*sizeof(ulong) );
  vm->frame_cnt = frame_idx;
  return FD_VM_SUCCESS;
}

/* FIXME: Consider a fd_vm_heap API here */

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

/* fd_vm_log_prepare cancels any message currently in preparation and
   starts zero-copy preparation of a new VM log message.  There are
   fd_vm_log_rem bytes available at the returned location (IMPORTANT
   SAFETY TIP!  THIS COULD BE ZERO IF THE VM LOG BUFFER IS FULL).  The
   lifetime of the returned location is the lesser of the lifetime of
   the vm or until the prepare is published or cancelled.  The caller is
   free to clobber any bytes in this region while it is preparing the
   message.

   fd_vm_log_publish appends the first sz bytes of the prepare region to
   the VM log.  Assumes vm is valid with a message in preparation and sz
   is in [0,rem].  Returns vm.  There is no message in preparation on
   return.

   fd_vm_log_cancel stops preparing a message in preparation without
   publishing it.  Returns vm.  There is no message in preparation on
   return.

   These assume vm valid. */

FD_FN_PURE  static inline void *    fd_vm_log_prepare( fd_vm_t * vm           ) { return vm->log + vm->log_sz; }
/**/        static inline fd_vm_t * fd_vm_log_publish( fd_vm_t * vm, ulong sz ) { vm->log_sz += sz; return vm; }
FD_FN_CONST static inline fd_vm_t * fd_vm_log_cancel ( fd_vm_t * vm           ) { return vm;                   }

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_private_h */
