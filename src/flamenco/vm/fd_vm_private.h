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

/* fd_vm_mem API ******************************************************/

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
