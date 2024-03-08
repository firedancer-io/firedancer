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

/* FIXME: consider disambiguating PERM case out-of-bounds, etc) into
   something like ACCES (e.g. out of bounds VM memory request),
   FAULT/BUS cases (e.g. misaligned VM memory access), and/or PERM (e.g.
   disallowed VM memory access like writing read-only memory) */

/* TODO: Specify exactly how these map onto Labs SyscallError (and
   provide full coverage of Lab SyscallErrors) */

#define FD_VM_SUCCESS                          (  0) /* Request completed normally */
#define FD_VM_ERR_INVAL                        ( -1) /* Request failed because it did not make sense */
#define FD_VM_ERR_UNSUP                        ( -2) /* Request failed because it is not supported on this target currently */
#define FD_VM_ERR_FULL                         ( -3) /* Request failed because there is no space available for the request */
#define FD_VM_ERR_EMPTY                        ( -4) /* Request failed because there is no resource for the request */
#define FD_VM_ERR_PERM                         ( -5) /* Request failed because the requestor does not have permission */
#define FD_VM_ERR_IO                           ( -6) /* Request failed because an I/O error occurred */

#define FD_VM_ERR_BUDGET                       ( -7) /* Request failed because the compute budget was exceeded */
#define FD_VM_ERR_ABORT                        ( -8)
#define FD_VM_ERR_PANIC                        ( -9)
#define FD_VM_ERR_MEM_OVERLAP                  (-10)
#define FD_VM_ERR_INSTR_ERR                    (-11)
#define FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED (-12)
#define FD_VM_ERR_RETURN_DATA_TOO_LARGE        (-13)

/* fd_vm_log_collector API ********************************************/

/* FIXME: ADD SPECIFIC UNIT TEST COVERAGE OF THIS API */
/* FIXME: RENAME AGGREGATOR FOR CONSISTENT WITH OTHER APIS? */

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
   (0) on success or FD_VM_ERR_FULL (negative) on failure. */

static inline int
fd_vm_stack_push( fd_vm_stack_t * stack,
                  ulong           ret_instr_ptr,
                  ulong const     saved_reg[4] ) {
  ulong top_idx = stack->depth;
  if( FD_UNLIKELY( top_idx>=FD_VM_STACK_DEPTH_MAX ) ) return FD_VM_ERR_FULL;
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
   success and FD_VM_ERR_EMPTY (negative) on failure.  On success,
   *_ret_instr_ptr and saved_reg[0:3] hold the values popped off the
   stack on return.  These are unchanged otherwise. */
/* TODO: CONSIDER ZERO COPY API? */

static inline int
fd_vm_stack_pop( fd_vm_stack_t * stack,
                 ulong *         _ret_instr_ptr,
                 ulong           saved_reg[4] ) {
  ulong top_idx = stack->depth;
  if( FD_UNLIKELY( !top_idx ) ) return FD_VM_ERR_EMPTY;
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

/* fd_vm_disasm API ***************************************************/

/* FIXME: pretty good case these actually belongs in ballet/sbpf */
/* FIXME: fd_sbpf_instr_t is nominally a ulong but implemented using
   bit-fields.  Compilers tend to generate notoriously poor asm for bit
   fields ... check ASM here. */

FD_PROTOTYPES_BEGIN

/* fd_vm_disasm_{instr,text} appends to the *_out_len (in strlen sense)
   cstr in the out_max byte buffer out a pretty printed cstr of the
   {instruction,program}.  On input, *_out_len should be strlen(out) and
   in [0,out_max).  For instr, pc is the program counter corresponding
   to instr[0] (as such instr_cnt should be positive) and instr_cnt is
   the number of instruction words available at instr to support safely
   printing multiword instructions.  Given a valid out on input, on
   output, *_out_len will be strlen(out) and in [0,out_max), even if
   there was an error.

   Returns:

   FD_VM_SUCCESS - out buffer and *_out_len updated.

   FD_VM_ERR_INVAL - Invalid input.  For instr, out buffer and *_out_len
   are unchanged.  For program, out buffer and *_out_len will have been
   updated up to the point where the error occurred.

   FD_VM_ERR_FULL - Not enough room in out to hold the result so output
   was truncated.  out buffer and *_out_len updated.

   FD_VM_ERR_IO - An error occured formatting the string to append.  For
   instr, out_buffer and *_out_len unchanged.  For program, out buffer
   and *_out_len will have been updated up to the point where the error
   occurred.  In both cases, trailing bytes of out might have been
   clobbered. */

int
fd_vm_disasm_instr( fd_sbpf_instr_t const *    instr,     /* Indexed [0,instr_cnt) */
                    ulong                      instr_cnt,
                    ulong                      pc,
                    fd_sbpf_syscalls_t const * syscalls,
                    char *                     out,       /* Indexed [0,out_max) */
                    ulong                      out_max,
                    ulong *                    _out_len );

int
fd_vm_disasm_program( fd_sbpf_instr_t const *    text,       /* Indexed [0,text_cnt) */
                      ulong                      text_cnt,
                      fd_sbpf_syscalls_t const * syscalls,
                      char *                     out,        /* Indexed [0,out_max) */
                      ulong                      out_max,
                      ulong *                    _out_len );

FD_PROTOTYPES_END

/* fd_vm_trace API ****************************************************/

/* FIXME: pretty good case these actually belongs in ballet/sbpf */

/* A FD_VM_TRACE_EVENT_TYPE_* indicates how a fd_vm_trace_event_t should
   be interpreted. */

#define FD_VM_TRACE_EVENT_TYPE_EXE   (0)
#define FD_VM_TRACE_EVENT_TYPE_READ  (1)
#define FD_VM_TRACE_EVENT_TYPE_WRITE (2)

#define FD_VM_TRACE_EVENT_EXE_REG_CNT (11UL) /* FIXME: LINK UP WITH REST OF SOLANA */

struct fd_vm_trace_event_exe {
  /* This point is aligned 8 */
  ulong info;                                 /* Event info bit field */
  ulong pc;                                   /* pc */
  ulong ic;                                   /* ic */
  ulong cu;                                   /* cu */
  ulong reg[ FD_VM_TRACE_EVENT_EXE_REG_CNT ]; /* registers */
  /* FIXME: ENCODE OP CODE? */
  /* This point is aligned 8 */
};

typedef struct fd_vm_trace_event_exe fd_vm_trace_event_exe_t;

struct fd_vm_trace_event_mem {
  /* This point is aligned 8 */
  ulong info;  /* Event info bit field */
  ulong vaddr; /* VM address range associated with event */
  ulong sz;
  /* This point is aligned 8
     If event has valid set:
       min(sz,event_data_max) bytes user data bytes
       padding to aligned 8 */
};

typedef struct fd_vm_trace_event_mem fd_vm_trace_event_mem_t;

#define FD_VM_TRACE_MAGIC (0xfdc377ace3a61c00UL) /* FD VM TRACE MAGIC version 0 */

struct fd_vm_trace {
  /* This point is aligned 8 */
  ulong magic;          /* ==FD_VM_TRACE_MAGIC */
  ulong event_max;      /* Number bytes of event storage */
  ulong event_data_max; /* Max bytes to capture per data event */
  ulong event_off;      /* byte offset to unused event storage */
  /* This point is aligned 8
     event_max bytes storage
     padding to aligned 8 */
};

typedef struct fd_vm_trace fd_vm_trace_t;

FD_PROTOTYPES_BEGIN

/* trace object structors */
/* FIXME: DOCUMENT (USUAL CONVENTIONS) */

FD_FN_CONST ulong
fd_vm_trace_align( void );

FD_FN_CONST ulong
fd_vm_trace_footprint( ulong event_max,        /* Maximum amount of event storage (<=1 EiB) */
                       ulong event_data_max ); /* Maximum number of bytes that can be captured in an event (<=1 EiB) */

void *
fd_vm_trace_new( void * shmem,
                 ulong  event_max,
                 ulong  event_data_max );

fd_vm_trace_t *
fd_vm_trace_join( void * _trace );

void *
fd_vm_trace_leave( fd_vm_trace_t * trace );

void *
fd_vm_trace_delete( void * _trace );

/* Given a current local join, fd_vm_trace_event returns the location in
   the caller's address space where trace events are stored and
   fd_vm_trace_event_sz returns number of bytes of trace events stored
   at that location.  event_max is the number of bytes of event storage
   (value used to construct the trace) and event_data_max is the maximum
   number of data bytes that can be captured per event (value used to
   construct the trace).  event will be aligned 8 and event_sz will be a
   multiple of 8 in [0,event_max].  The lifetime of the returned pointer
   is the lifetime of the current join.  The first 8 bytes of an event
   are an info field used by trace inspection tools how to interpret the
   event. */

FD_FN_CONST static inline void const * fd_vm_trace_event         ( fd_vm_trace_t const * trace ) { return (void *)(trace+1);     }
FD_FN_CONST static inline ulong        fd_vm_trace_event_sz      ( fd_vm_trace_t const * trace ) { return trace->event_off;      }
FD_FN_CONST static inline ulong        fd_vm_trace_event_max     ( fd_vm_trace_t const * trace ) { return trace->event_max;      }
FD_FN_CONST static inline ulong        fd_vm_trace_event_data_max( fd_vm_trace_t const * trace ) { return trace->event_data_max; }

/* fd_vm_trace_event_info returns the event info corresponding to the
   given (type,valid) tuple.  Assumes type is a FD_VM_TRACE_EVENT_TYPE_*
   and that valid is in [0,1].  fd_vm_trace_event_info_{type,valid}
   extract from the given info {type,valid}.  Assumes info is valid. */

FD_FN_CONST static inline ulong fd_vm_trace_event_info( int type, int valid ) { return (ulong)((valid<<2) | type); }

FD_FN_CONST static inline int fd_vm_trace_event_info_type ( ulong info ) { return (int)(info & 3UL); } /* EVENT_TYPE_* */
FD_FN_CONST static inline int fd_vm_trace_event_info_valid( ulong info ) { return (int)(info >> 2);  } /* In [0,1] */

/* fd_vm_trace_reset frees all events in the trace.  Returns
   FD_VM_SUCCESS (0) on success or FD_VM_ERR code (negative) on failure.
   Reasons for failure include NULL trace. */

static inline int
fd_vm_trace_reset( fd_vm_trace_t * trace ) {
  if( FD_UNLIKELY( !trace ) ) return FD_VM_ERR_INVAL;
  trace->event_off = 0UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_trace_event_exe records the the current pc, ic, cu and
   register file of the VM.  Returns FD_VM_SUCCESS (0) on success and a
   FD_VM_ERR code (negative) on failure.  Reasons for failure include
   INVAL (trace NULL) and FULL (insufficient trace event storage
   available to store the event). */

int
fd_vm_trace_event_exe( fd_vm_trace_t * trace,
                       ulong           pc,
                       ulong           ic,
                       ulong           cu,
                       ulong           reg[ FD_VM_TRACE_EVENT_EXE_REG_CNT ] );

/* fd_vm_trace_event_mem records an attempt to access the VM address
   range [vaddr,vaddr+sz).  If write==0, it was a read attempt,
   otherwise, it was a write attempt.  Data points to the location of
   the memory range in host memory or NULL if the range is invalid.  If
   data is not NULL and sz is non-zero, this will record
   min(sz,event_data_max) of data for the event and mark the event has
   having valid data.  Returns FD_VM_SUCCESS (0) on success and a
   FD_VM_ERR code (negative) on failure.  Reasons for failure include
   INVAL (trace NULL) and FULL (insufficient trace event storage
   available to store the event). */

int
fd_vm_trace_event_mem( fd_vm_trace_t * trace,
                       int             write,
                       ulong           vaddr,
                       ulong           sz,
                       void *          data );

/* fd_vm_trace_printf pretty prints the current trace to stdout.
   Returns FD_VM_SUCCESS (0) on success and a FD_VM_ERR code (negative)
   on failure.  If text_cnt is non-zero, this will also include
   annotations from the text.  Reasons for failure include INVAL
   (NULL trace, non-zero text_cnt with NULL text or NULL syscalls)
   and IO (corruption detected while parsing the trace events).  FIXME:
   REVAMP THIS API FOR MORE GENERAL USE CASES. */

int
fd_vm_trace_printf( fd_vm_trace_t      const * trace,
                    fd_sbpf_instr_t    const * text,       /* Indexed [0,text_cnt) */
                    ulong                      text_cnt,
                    fd_sbpf_syscalls_t const * syscalls );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_base_h */
