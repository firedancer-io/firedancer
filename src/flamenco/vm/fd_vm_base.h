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

/* FIXME: consider disambiguating PERM case into something like ACCES
   (e.g. out of bounds VM memory request), FAULT/BUS cases (e.g.
   misaligned VM memory access), PERM (e.g. disallowed VM memory access
   like writing read-only memory) and maybe making MEM_OVERLAP something
   like INVAL). */

/* "Standard" Firedancer error codes (FIXME: harmonize and consolidate) */

#define FD_VM_SUCCESS   ( 0) /* success */
#define FD_VM_ERR_INVAL (-1) /* invalid request */
#define FD_VM_ERR_AGAIN (-2) /* try again later */
#define FD_VM_ERR_UNSUP (-3) /* unsupported request */
#define FD_VM_ERR_PERM  (-4) /* unauthorized request */
#define FD_VM_ERR_FULL  (-5) /* storage full */
#define FD_VM_ERR_EMPTY (-6) /* nothing to do */
#define FD_VM_ERR_IO    (-7) /* input-output error */

/* VM syscall error codes.  These are only produced by fd_vm_syscall
   implementations.  FIXME: Consider having syscalls return standard
   error codes and then provide detail like this through an info arg.
   FIXME: Are these exact matches to Solana?  If so, provide link?  If
   not document and refine names / consolidate further. */

#define FD_VM_ERR_BUDGET                       ( -8) /* compute budget exceeded (FIXME: probably more a "standard" error) */
#define FD_VM_ERR_ABORT                        ( -9) /* FIXME: descrption */
#define FD_VM_ERR_PANIC                        (-10) /* FIXME: descrption */
#define FD_VM_ERR_MEM_OVERLAP                  (-11) /* FIXME: descrption */
#define FD_VM_ERR_INSTR_ERR                    (-12) /* FIXME: descrption */
#define FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED (-13) /* FIXME: descrption */
#define FD_VM_ERR_RETURN_DATA_TOO_LARGE        (-14) /* FIXME: descrption */

/* sBPF validation error codes.  These are only produced by
   fd_vm_validate.  FIXME: Consider having fd_vm_validate return
   standard error codes and then provide detail like this through an
   info arg.  FIXME: Are these exact matches to Solana?  If so, provide
   link, if not, document and refine name / consolidate further. */

#define FD_VM_ERR_INVALID_OPCODE    (-15) /* detected an invalid opcode */
#define FD_VM_ERR_INVALID_SRC_REG   (-16) /* detected an invalid source register */
#define FD_VM_ERR_INVALID_DST_REG   (-17) /* detected an invalid destination register */
#define FD_VM_ERR_INF_LOOP          (-18) /* detected an infinite loop */
#define FD_VM_ERR_JMP_OUT_OF_BOUNDS (-19) /* detected an out of bounds jump */
#define FD_VM_ERR_JMP_TO_ADDL_IMM   (-20) /* detected a jump to an addl imm */
#define FD_VM_ERR_INVALID_END_IMM   (-21) /* detected an invalid immediate for an endianness conversion instruction */
#define FD_VM_ERR_INCOMPLETE_LDQ    (-22) /* detected an incomplete ldq at program end */
#define FD_VM_ERR_LDQ_NO_ADDL_IMM   (-23) /* detected a ldq without an addl imm following it */
#define FD_VM_ERR_NO_SUCH_EXT_CALL  (-24) /* detected a call imm with no function was registered for that immediate */

FD_PROTOTYPES_BEGIN

/* fd_vm_strerror converts an FD_VM_SUCCESS / FD_VM_ERR_* code into
   a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

FD_FN_CONST char const * fd_vm_strerror( int err );

FD_PROTOTYPES_END

/* fd_vm_log_collector API ********************************************/

/* FIXME: RENAME FOR CONSISTENT WITH OTHER APIS AND/OR ADD MORE STANDARD
   INIT/FINI OR OTHER OBJECT LIFECYCLE SEMANTICS? */

/* A fd_vm_log_collector_t is used by the vm for storing text/bytes
   logged by programs running in the vm.  The collector can collect up
   to FD_VM_LOG_COLLECTOR_BUF_MAX bytes of log data, beyond which the
   log is truncated. */

#define FD_VM_LOG_COLLECTOR_BUF_MAX (10000UL) /* FIXME: IS THIS NUMBER A PROTOCOL REQUIREMENT OR IS 10K JUST LUCKY? */

struct fd_vm_log_collector_private {
  ulong buf_used;
  uchar buf[ FD_VM_LOG_COLLECTOR_BUF_MAX ];
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
  memset( collector->buf, 0, FD_VM_LOG_COLLECTOR_BUF_MAX );
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
  if( FD_LIKELY( cpy_sz ) ) memcpy( collector->buf + buf_used, msg, cpy_sz ); /* Sigh ... branchless if sz==0 wasn't UB */
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

/* FIXME: RENAME FOR CONSISTENCY WITH OTHER APIS AND/OR ADD MORE
   STANDARD LIFECYCLE SEMANTICS? */
/* FIXME: document Solana requirements here */
/* FIXME: FRAME_MAX should be run time configurable by compute budget
   (is there an upper bound to how configurable ... there needs to be!) */

#define FD_VM_STACK_FRAME_MAX           (64UL)
#define FD_VM_STACK_FRAME_SZ            (0x1000UL)
#define FD_VM_STACK_FRAME_WITH_GUARD_SZ (0x2000UL)

#define FD_VM_STACK_DATA_MAX (FD_VM_STACK_FRAME_MAX*FD_VM_STACK_FRAME_WITH_GUARD_SZ) /* FIXME: see note below */

/* A fd_vm_stack_frame_shadow_t holds stack frame information hidden
   from VM program execution. */

struct fd_vm_stack_frame_shadow {
  ulong ret_instr_ptr;
  ulong saved_reg[4];
};

typedef struct fd_vm_stack_frame_shadow fd_vm_stack_frame_shadow_t;

/* A fd_vm_stack_t gives the VM program stack state. */

struct fd_vm_stack {
  ulong                      frame_cnt;                       /* In [0,FRAME_MAX] */
  fd_vm_stack_frame_shadow_t shadow[ FD_VM_STACK_FRAME_MAX ]; /* Indexed [0,frame_cnt), if not empty, bottom at 0, top at frame_cnt-1 */
  uchar                      data  [ FD_VM_STACK_DATA_MAX  ]; /* FIXME: should this be part of the fd_vm_stack_t? */
};

typedef struct fd_vm_stack fd_vm_stack_t;

FD_PROTOTYPES_BEGIN

/* fd_vm_stack_wipe zeros out stack data, shadow frames, stack_pointer
   and frame_cnt.  Assumes stack is valid.  Returns stack.  Use this to
   initialize a newly allocated VM stack. */

static inline fd_vm_stack_t *
fd_vm_stack_wipe( fd_vm_stack_t * stack ) {
  memset( stack, 0, sizeof(fd_vm_stack_t) );
  return stack;
}

/* fd_vm_stack_data returns a pointer to the first byte a VM's program
   stack region in the hosts's address space.  There are
   FD_VM_STACK_DATA_MAX bytes available at this region.  Assumes stack
   is valid.  The lifetime of the returned pointer is the lifetime of
   the stack. */

FD_FN_CONST static inline void * fd_vm_stack_data( fd_vm_stack_t * stack ) { return stack->data; }

/* fd_vm_stack_empty/full returns 1 if the stack is empty/full and 0 if
   not.  Assumes stack is valid. */

FD_FN_PURE static inline int fd_vm_stack_is_empty( fd_vm_stack_t const * stack ) { return !stack->frame_cnt;                       }
FD_FN_PURE static inline int fd_vm_stack_is_full ( fd_vm_stack_t const * stack ) { return stack->frame_cnt==FD_VM_STACK_FRAME_MAX; }

/* fd_vm_stack_push pushes a new frame onto the VM stack.  Assumes
   stack, ret_instr_ptr and saved_reg is valid.  Returns FD_VM_SUCCESS
   (0) on success or FD_VM_ERR_FULL (negative) on failure. */
/* FIXME: consider zero copy API and/or failure free API? */

static inline int
fd_vm_stack_push( fd_vm_stack_t * stack,
                  ulong           ret_instr_ptr,
                  ulong const     saved_reg[4] ) {
  ulong frame_cnt = stack->frame_cnt;
  if( FD_UNLIKELY( frame_cnt>=FD_VM_STACK_FRAME_MAX ) ) return FD_VM_ERR_FULL;
  fd_vm_stack_frame_shadow_t * shadow = stack->shadow + frame_cnt;
  shadow->ret_instr_ptr = ret_instr_ptr;
  shadow->saved_reg[0]  = saved_reg[0];
  shadow->saved_reg[1]  = saved_reg[1];
  shadow->saved_reg[2]  = saved_reg[2];
  shadow->saved_reg[3]  = saved_reg[3];
  stack->frame_cnt = frame_cnt + 1UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_stack_pop pops a frame off the VM stack.  Assumes stack,
   ret_instr_ptr and saved_reg is valid.  Returns FD_VM_SUCCESS (0) on
   success and FD_VM_ERR_EMPTY (negative) on failure.  On success,
   *_ret_instr_ptr and saved_reg[0:3] hold the values popped off the
   stack on return.  These are unchanged otherwise. */
/* FIXME: consider zero copy API and/or failure free API? */

static inline int
fd_vm_stack_pop( fd_vm_stack_t * stack,
                 ulong *         _ret_instr_ptr,
                 ulong           saved_reg[4] ) {
  ulong frame_idx = stack->frame_cnt;
  if( FD_UNLIKELY( !frame_idx ) ) return FD_VM_ERR_EMPTY;
  frame_idx--;
  fd_vm_stack_frame_shadow_t * shadow = stack->shadow + frame_idx;
  *_ret_instr_ptr = shadow->ret_instr_ptr;
  saved_reg[0]    = shadow->saved_reg[0];
  saved_reg[1]    = shadow->saved_reg[1];
  saved_reg[2]    = shadow->saved_reg[2];
  saved_reg[3]    = shadow->saved_reg[3];
  stack->frame_cnt = frame_idx;
  return FD_VM_SUCCESS;
}

FD_PROTOTYPES_END

/* fd_vm_heap_allocator API *******************************************/

/* fd_vm_heap_allocator_t provides the allocator backing the
   sol_alloc_free_ syscall.

   IMPORANT SAFETY TIP!  THE BEHAVIOR OF THIS HEAP ALLOCATOR MUST MATCH
   THE SOLANA VALIDATOR HEAP ALLOCATOR:

   https://github.com/solana-labs/solana/blob/v1.17.23/program-runtime/src/invoke_context.rs#L122-L148

   BIT-FOR-BIT AND BUG-FOR-BUG.  SEE THE SYSCALL_ALLOC_FREE FOR MORE
   DETAILS.

   Like many syscalls, the same allocation logic could trivially be
   implemented in on-chain bytecode. */

struct fd_vm_heap_allocator {
  ulong offset; /* Points to beginning of free region within heap, relative to start of heap region. */
};

typedef struct fd_vm_heap_allocator fd_vm_heap_allocator_t;

/* FIXME: WRAP UP USAGE HERE AND ADD UNIT TEST COVERAGE? */

/* fd_vm_cu API *******************************************************/

/* FIXME: DO THESE MIRROR THE SOLANA NAMES?  IF SO, LINK CORRESPONDING
   SOLANA CODE.  IF NOT, ADJUST TO FD CONVENTIONS. */
/* FIXME: PREFIX? */
/* FIXME: REPLACE WITH COMPILE TIME MACROS FOR PERFORMANCE AND SECURITY */
/* FIXME: MOVE TO SBPF? */

#define FD_VM_MAX_COMPUTE_UNIT_LIMIT              (1400000UL)
#define FD_VM_MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES (64UL*1024UL*1024UL)

struct fd_vm_exec_compute_budget {
  ulong compute_unit_limit;                        /* Number of compute units that a transaction or individual instruction is
                                                      allowed to consume.  Compute units are consumed by program execution,
                                                      resources they use, etc ... */
  ulong log_64_units;                              /* Number of compute units consumed by a log_u64 call */ /* FIXME: NAME? */
  ulong create_program_address_units;              /* Number of compute units consumed by a create_program_address call */
  ulong invoke_units;                              /* Number of compute units consumed by an invoke call (not including the cost
                                                      incurred by the called program */
  ulong max_invoke_depth;                          /* Maximum cross-program invocation depth allowed */
  ulong sha256_base_cost;                          /* Base number of compute units consumed to call SHA256 */
  ulong sha256_byte_cost;                          /* Incremental number of units consumed by SHA256 (based on bytes) */
  ulong sha256_max_slices;                         /* Maximum number of slices hashed per syscall */
  ulong max_call_depth;                            /* Maximum BPF to BPF call depth */
  ulong stack_frame_size;                          /* Size of a stack frame in bytes, must match the size specified in the LLVM BPF
                                                      backend */
  ulong log_pubkey_units;                          /* Number of compute units consumed by logging a `Pubkey` */
  ulong max_cpi_instruction_size;                  /* Maximum cross-program invocation instruction size */
  ulong cpi_bytes_per_unit;                        /* Number of account data bytes per compute unit charged during a cross-program
                                                      invocation */
  ulong sysvar_base_cost;                          /* Base number of compute units consumed to get a sysvar */
  ulong secp256k1_recover_cost;                    /* Number of compute units consumed to call secp256k1_recover */
  ulong syscall_base_cost;                         /* Number of compute units consumed to do a syscall without any work */
  ulong curve25519_edwards_validate_point_cost;    /* Number of compute units consumed to validate a curve25519 edwards point */
  ulong curve25519_edwards_add_cost;               /* Number of compute units consumed to add two curve25519 edwards points */
  ulong curve25519_edwards_subtract_cost;          /* Number of compute units consumed to subtract two curve25519 edwards points */
  ulong curve25519_edwards_multiply_cost;          /* Number of compute units consumed to multiply a curve25519 edwards point */
  ulong curve25519_edwards_msm_base_cost;          /* Number of compute units consumed for a multiscalar multiplication (msm) of
                                                      edwards points.  The total cost is calculated as
                                                      `msm_base_cost + (length - 1) * msm_incremental_cost`. */
  ulong curve25519_edwards_msm_incremental_cost;   /* Number of compute units consumed for a multiscalar multiplication (msm) of
                                                      edwards points.  The total cost is calculated as
                                                      `msm_base_cost + (length - 1) * msm_incremental_cost`. */
  ulong curve25519_ristretto_validate_point_cost;  /* Number of compute units consumed to validate a curve25519 ristretto point */
  ulong curve25519_ristretto_add_cost;             /* Number of compute units consumed to add two curve25519 ristretto points */
  ulong curve25519_ristretto_subtract_cost;        /* Number of compute units consumed to subtract two curve25519 ristretto
                                                      points */
  ulong curve25519_ristretto_multiply_cost;        /* Number of compute units consumed to multiply a curve25519 ristretto point */
  ulong curve25519_ristretto_msm_base_cost;        /* Number of compute units consumed for a multiscalar multiplication (msm) of
                                                      ristretto points.  The total cost is calculated as
                                                      `msm_base_cost + (length - 1) * msm_incremental_cost`. */
  ulong curve25519_ristretto_msm_incremental_cost; /* Number of compute units consumed for a multiscalar multiplication (msm) of
                                                      ristretto points.  The total cost is calculated as
                                                      `msm_base_cost + (length - 1) * msm_incremental_cost`. */
  ulong heap_size;                                 /* Optional program heap region size, if 0 then loader default */
  ulong heap_cost;                                 /* Number of compute units per additional 32k heap above the default
                                                      (~.5 us per 32k at 15 units/us rounded up) */
  ulong mem_op_base_cost;                          /* Memory operation syscall base cost */
  ulong loaded_accounts_data_size_limit;           /* Maximum accounts data size, in bytes, that a transaction is allowed to load; the
                                                      value is capped by MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES to prevent overuse of
                                                      memory. */
};

typedef struct fd_vm_exec_compute_budget fd_vm_exec_compute_budget_t;

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

   FD_VM_ERR_UNSUP - For program, too many functions and/or labels for
   the current implementation.  out buffer and *_out_len unchanged.

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
  /* FIXME: ENCODE INSTR WORDS? */
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
