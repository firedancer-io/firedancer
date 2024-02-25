#ifndef HEADER_fd_src_flamenco_vm_fd_vm_base_h
#define HEADER_fd_src_flamenco_vm_fd_vm_base_h

/* TODO: Headers included from other modules need cleanup.  At it
   stands, this also brings in util, flamenco_base, ballet/base58,
   ballet/sha256, and a bunch of other stuff (that may or may not be
   necessary) in a somewhat haphazard fashion (include no-no things that
   are only available in hosted environments like stdio and stdlib) */

/* TODO: Separate into external-public-user /
   internal-private-implementor APIs */

#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../runtime/fd_runtime.h"

/* FD_VM_SUCCESS is zero and returned to indicate that an operation
   completed successfully.  FD_VM_ERR_* are negative integers and
   returned to indicate an operation that failed and why. */

/* FIXME: Renumber and harmonize after consolidating */

#define FD_VM_SUCCESS           (0)
#define FD_VM_ERR_PUSH_OVERFLOW (-1)
#define FD_VM_ERR_POP_UNDERFLOW (-2)
#define FD_VM_ERR_ACC_VIO       (-3) /* TODO: consider disambiguating ERR_ACC_VIO cases (misaligned, out-of-bounds, etc) */
#define FD_VM_ERR_BUDGET        (-4) /* Compute budget was exceeded */

//#define FD_VM_ERR_POP_EMPTY   (-1) /* FIXME: WHY WAS THIS DEFINED BEFORE ... NOT USED, SEEMS REDUNDANT WITH POP_UNDERFLOW */

/* fd_vm_log_collector API ********************************************/

/* TODO: ADD SPECIFIC UNIT TEST COVERAGE OF THIS API */

/* A fd_vm_log_collector_t is used by the vm for storing text/bytes
   logged by programs running in the vm.  The collector can collect up
   to FD_VM_LOG_COLLECTOR_BUF_MAX bytes of log data, beyond which the
   log is truncated. */

#define FD_VM_LOG_COLLECTOR_BUF_MAX (10000UL) /* FIXME: IS THIS NUMBER A PROTOCOL REQUIREMENT OR IS 10K JUST LUCKY? */

struct fd_vm_log_collector_private {
  uchar buf[ FD_VM_LOG_COLLECTOR_BUF_MAX ];
  ulong buf_used;
};

typedef struct fd_vm_log_collector_private fd_vm_log_collector_t;

FD_PROTOTYPES_BEGIN

/* fd_vm_log_collector_flush flushes all bytes from a log collector.
   Assumes collector is valid and returns collector.  Use this to
   initial a log collector.  fd_vm_log_collector_wipe is the same as the
   above but also zeros out all memory. */

static inline fd_vm_log_collector_t *
fd_vm_log_collector_flush( fd_vm_log_collector_t * collector ) {
  collector->buf_used = 0UL;
  return collector;
}

static inline fd_vm_log_collector_t *
fd_vm_log_collector_wipe( fd_vm_log_collector_t * collector ) {
  collector->buf_used = 0UL;
  fd_memset( collector->buf, 0, FD_VM_LOG_COLLECTOR_BUF_MAX );
  return collector;
}

/* fd_vm_log_collector_log appends a message of sz bytes to the log,
   truncating it if the collector is already full.  Assumes collector is
   valid and returns collector and msg / sz are valid.  sz 0 is fine. */

static inline fd_vm_log_collector_t *
fd_vm_log_collector_append( fd_vm_log_collector_t * collector,
                            void const *            msg,
                            ulong                   sz ) {
  ulong buf_used = collector->buf_used;
  ulong cpy_sz   = fd_ulong_min( sz, FD_VM_LOG_COLLECTOR_BUF_MAX - buf_used );
  if( FD_LIKELY( cpy_sz ) ) fd_memcpy( collector->buf + buf_used, msg, cpy_sz ); /* Sigh ... branchless if sz==0 wasn't UB */
  collector->buf_used = buf_used + cpy_sz;
  return collector;
}

/* fd_vm_log_collector_{buf,max,used,avail} access the state of the log
   collector.  Assumes collector is valid.  buf returns the location of
   the first buffer buf, the lifetime of the returned pointer is the
   collector lifetime.  max gives the size of buf (positive), used gives
   the number currently in use, in [0,max], avail gives the number of
   bytes free for additional logging (max-used).  Used bytes are at
   offsets [0,used) and available bytes are at offset [used,max). */

FD_FN_CONST static inline uchar const *
fd_vm_log_collector_buf( fd_vm_log_collector_t const * collector ) {
  return collector->buf;
}

FD_FN_CONST static inline ulong
fd_vm_log_collector_buf_max( fd_vm_log_collector_t const * collector ) {
  (void)collector;
  return FD_VM_LOG_COLLECTOR_BUF_MAX;
}

FD_FN_PURE static inline ulong
fd_vm_log_collector_buf_used( fd_vm_log_collector_t const * collector ) {
  return collector->buf_used;
}

FD_FN_PURE static inline ulong
fd_vm_log_collector_buf_avail( fd_vm_log_collector_t const * collector ) {
  return FD_VM_LOG_COLLECTOR_BUF_MAX - collector->buf_used;
}

FD_PROTOTYPES_END

/* fd_vm_stack API ****************************************************/

/* FIXME: ADD SPECIFIC UNIT TEST COVERAGE OF THIS API */

/* FIXME: The max depth of the stack is configurable by the compute
   budget */

/* FIXME: DOCUMENT SOLANA PROTOCOL REQUIRMENTS HERE */

#define FD_VM_STACK_DEPTH_MAX           (64UL)
#define FD_VM_STACK_FRAME_SZ            (0x1000UL)
#define FD_VM_STACK_FRAME_WITH_GUARD_SZ (0x2000UL)

#define FD_VM_STACK_DATA_MAX (FD_VM_STACK_DEPTH_MAX*FD_VM_STACK_FRAME_WITH_GUARD_SZ)

/* A fd_vm_stack_private_shadow_t holds stack frame information hidden
   from VM program execution. */

struct fd_vm_stack_private_shadow {
  ulong ret_instr_ptr;
  ulong saved_reg[4];
};

typedef struct fd_vm_stack_private_shadow fd_vm_stack_private_shadow_t;

/* A fd_vm_stack_t gives the VM program stack state. */

struct fd_vm_stack {
  ulong                        stack_pointer;                   /* FIXME: DOCUMENT THIS BETTER */
  ulong                        depth;                           /* In [0,DEPTH_MAX] */
  fd_vm_stack_private_shadow_t shadow[ FD_VM_STACK_DEPTH_MAX ]; /* Indexed [0,depth), if not empty, bottom at 0, top at depth-1 */
  uchar                        data  [ FD_VM_STACK_DATA_MAX  ]; /* FIXME: DOCUMENT THIS BETTER */
};

typedef struct fd_vm_stack fd_vm_stack_t;

FD_PROTOTYPES_BEGIN

/* fd_vm_stack_wipe zeros out stack data, shadow frames, stack_pointer
   and depth.  Assumes stack is valid.  Returns stack.  Use this to
   initialize a newly allocated VM stack. */

static inline fd_vm_stack_t *
fd_vm_stack_wipe( fd_vm_stack_t * stack ) {
  fd_memset( stack, 0, sizeof(fd_vm_stack_t) );
  return stack;
}

/* fd_vm_stack_push pushes a new frame onto the VM stack.  Assumes
   stack, ret_instr_ptr and saved_reg is valid.  Returns FD_VM_SUCCESS
   (0) on success or FD_VM_ERR_PUSH_OVERFLOW (negative) on failure. */

static inline int
fd_vm_stack_push( fd_vm_stack_t * stack,
                  ulong           ret_instr_ptr,
                  ulong const     saved_reg[4] ) {
  ulong top_idx = stack->depth;
  if( FD_UNLIKELY( top_idx>=FD_VM_STACK_DEPTH_MAX ) ) return FD_VM_ERR_PUSH_OVERFLOW;
  fd_vm_stack_private_shadow_t * shadow = stack->shadow + top_idx;
  shadow->ret_instr_ptr = ret_instr_ptr;
  shadow->saved_reg[0]  = saved_reg[0];
  shadow->saved_reg[1]  = saved_reg[1];
  shadow->saved_reg[2]  = saved_reg[2];
  shadow->saved_reg[3]  = saved_reg[3];
  stack->depth = top_idx + 1UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_stack_pop pops a frame off the VM stack.  Assumes stack,
   ret_instr_ptr and saved_reg is valid.  Returns FD_VM_SUCCESS (0) on
   success and FD_VM_ERR_POP_UNDERFLOW (negative) on failure.  On
   success, *_ret_instr_ptr and saved_reg[0:3] hold the values popped
   off the stack on return.  These are unchanged otherwise. */
/* TODO: CONSIDER ZERO COPY API? */

static inline int
fd_vm_stack_pop( fd_vm_stack_t * stack,
                 ulong *         _ret_instr_ptr,
                 ulong           saved_reg[4] ) {
  ulong top_idx = stack->depth;
  if( FD_UNLIKELY( !top_idx ) ) return FD_VM_ERR_POP_UNDERFLOW;
  top_idx--;
  fd_vm_stack_private_shadow_t * shadow = stack->shadow + top_idx;
  *_ret_instr_ptr = shadow->ret_instr_ptr;
  saved_reg[0]    = shadow->saved_reg[0];
  saved_reg[1]    = shadow->saved_reg[1];
  saved_reg[2]    = shadow->saved_reg[2];
  saved_reg[3]    = shadow->saved_reg[3];
  stack->depth = top_idx;
  return FD_VM_SUCCESS;
}

/* fd_vm_stack_data returns a pointer to the first byte a VM's program
   stack region in the hosts's address space.  There are
   FD_VM_STACK_DATA_MAX bytes available at this region.  Assumes stack
   is valid.  The lifetime of the returned pointer is the lifetime of
   the stack. */

FD_FN_CONST static inline void * fd_vm_stack_data( fd_vm_stack_t * stack ) { return stack->data; }

/* fd_vm_stack_empty returns 1 if the stack is empty and 0 if not.
   Assumes stack is valid. */

FD_FN_PURE static inline int fd_vm_stack_is_empty( fd_vm_stack_t const * stack ) { return !stack->depth; }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_base_h */
