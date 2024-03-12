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

#define FD_VM_ERR_BUDGET                       ( -8) /* compute budget exceeded (FIXME: fault error code) */
#define FD_VM_ERR_ABORT                        ( -9) /* FIXME: description */
#define FD_VM_ERR_PANIC                        (-10) /* FIXME: description */
#define FD_VM_ERR_MEM_OVERLAP                  (-11) /* FIXME: description */
#define FD_VM_ERR_INSTR_ERR                    (-12) /* FIXME: description */
#define FD_VM_ERR_INVOKE_CONTEXT_BORROW_FAILED (-13) /* FIXME: description */
#define FD_VM_ERR_RETURN_DATA_TOO_LARGE        (-14) /* FIXME: description */

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

/* VM fault error codes.  This are only produced by the vm interpreter.
   FIXME: Are these exact matches to Solana?  If so, provide link, if
   not, document and refine name / consolidate further. */

#define FD_VM_ERR_MEM_TRANS (-25) /* FIXME: description */
#define FD_VM_ERR_BAD_CALL  (-26) /* FIXME: description */

FD_PROTOTYPES_BEGIN

/* fd_vm_strerror converts an FD_VM_SUCCESS / FD_VM_ERR_* code into
   a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

FD_FN_CONST char const * fd_vm_strerror( int err );

FD_PROTOTYPES_END

/* fd_vm_limits API ***************************************************/

/* FIXME: DOCUMENT THESE / LINK TO SOLANA CODE / ETC */

/* VM register constants */

#define FD_VM_REG_CNT (11UL)

#define FD_VM_SHADOW_REG_CNT (4UL)

/* VM stack constants */

#define FD_VM_STACK_FRAME_MAX (64UL)
#define FD_VM_STACK_FRAME_SZ  (0x1000UL)
#define FD_VM_STACK_GUARD_SZ  (0x1000UL)
#define FD_VM_STACK_MAX       (FD_VM_STACK_FRAME_MAX*(FD_VM_STACK_FRAME_SZ+FD_VM_STACK_GUARD_SZ))

/* VM heap constants */

#define FD_VM_HEAP_DEFAULT ( 32UL*1024UL)
#define FD_VM_HEAP_MAX     (256UL*1024UL)

/* VM log constants */

#define FD_VM_LOG_MAX (10000UL)

/* VM memory map constants */

#define FD_VM_MEM_MAP_PROGRAM_REGION_START  (0x100000000UL)
#define FD_VM_MEM_MAP_STACK_REGION_START    (0x200000000UL)
#define FD_VM_MEM_MAP_HEAP_REGION_START     (0x300000000UL)
#define FD_VM_MEM_MAP_INPUT_REGION_START    (0x400000000UL)
#define FD_VM_MEM_MAP_REGION_SZ             (0x0FFFFFFFFUL)
#define FD_VM_MEM_MAP_REGION_MASK           (~FD_VM_MEM_MAP_REGION_SZ)
#define FD_VM_MEM_MAP_REGION_VIRT_ADDR_BITS (32)

/* VM compute budget */

/* FIXME: PREFIX? */
/* FIXME: REPLACE WITH COMPILE TIME MACROS FOR PERFORMANCE AND SECURITY */
/* FIXME: MOVE TO SBPF? */

#define FD_VM_MAX_COMPUTE_UNIT_LIMIT              (1400000UL)
#define FD_VM_MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES (64UL*1024UL*1024UL)

/* https://github.com/anza-xyz/agave/blob/v1.18.5/program-runtime/src/compute_budget.rs#L19 */
struct fd_vm_exec_compute_budget {
   /* Number of compute units that a transaction or individual instruction is
      allowed to consume. Compute units are consumed by program execution,
      resources they use, etc... */
   ulong compute_unit_limit;
   /* Number of compute units consumed by a log_u64 call */
   ulong log_64_units;
   /* Number of compute units consumed by a create_program_address call */
   ulong create_program_address_units;
   /* Number of compute units consumed by an invoke call (not including the cost incurred by
      the called program) */
   ulong invoke_units;
   /* Maximum program instruction invocation stack height. Invocation stack
      height starts at 1 for transaction instructions and the stack height is
      incremented each time a program invokes an instruction and decremented
      when a program returns. */
   ulong max_invoke_stack_height;
   /* Maximum cross-program invocation and instructions per transaction */
   ulong max_instruction_trace_length;
   /* Base number of compute units consumed to call SHA256 */
   ulong sha256_base_cost;
   /* Incremental number of units consumed by SHA256 (based on bytes) */
   ulong sha256_byte_cost;
   /* Maximum number of slices hashed per syscall */
   ulong sha256_max_slices;
   /* Maximum SBF to BPF call depth */
   ulong max_call_depth;
   /* Size of a stack frame in bytes, must match the size specified in the LLVM SBF backend */
   ulong stack_frame_size;
   /* Number of compute units consumed by logging a `Pubkey` */
   ulong log_pubkey_units;
   /* Maximum cross-program invocation instruction size */
   ulong max_cpi_instruction_size;
   /* Number of account data bytes per compute unit charged during a cross-program invocation */
   ulong cpi_bytes_per_unit;
   /* Base number of compute units consumed to get a sysvar */
   ulong sysvar_base_cost;
   /* Number of compute units consumed to call secp256k1_recover */
   ulong secp256k1_recover_cost;
   /* Number of compute units consumed to do a syscall without any work */
   ulong syscall_base_cost;
   /* Number of compute units consumed to validate a curve25519 edwards point */
   ulong curve25519_edwards_validate_point_cost;
   /* Number of compute units consumed to add two curve25519 edwards points */
   ulong curve25519_edwards_add_cost;
   /* Number of compute units consumed to subtract two curve25519 edwards points */
   ulong curve25519_edwards_subtract_cost;
   /* Number of compute units consumed to multiply a curve25519 edwards point */
   ulong curve25519_edwards_multiply_cost;
   /* Number of compute units consumed for a multiscalar multiplication (msm) of edwards points.
      The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`. */
   ulong curve25519_edwards_msm_base_cost;
   /* Number of compute units consumed for a multiscalar multiplication (msm) of edwards points.
      The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`. */
   ulong curve25519_edwards_msm_incremental_cost;
   /* Number of compute units consumed to validate a curve25519 ristretto point */
   ulong curve25519_ristretto_validate_point_cost;
   /* Number of compute units consumed to add two curve25519 ristretto points */
   ulong curve25519_ristretto_add_cost;
   /* Number of compute units consumed to subtract two curve25519 ristretto points */
   ulong curve25519_ristretto_subtract_cost;
   /* Number of compute units consumed to multiply a curve25519 ristretto point */
   ulong curve25519_ristretto_multiply_cost;
   /* Number of compute units consumed for a multiscalar multiplication (msm) of ristretto points.
      The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`. */
   ulong curve25519_ristretto_msm_base_cost;
   /* Number of compute units consumed for a multiscalar multiplication (msm) of ristretto points.
      The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`. */
   ulong curve25519_ristretto_msm_incremental_cost;
   /* program heap region size, default: solana_sdk::entrypoint::HEAP_LENGTH */
   ulong heap_size;
   /* Number of compute units per additional 32k heap above the default (~.5
      us per 32k at 15 units/us rounded up) */
   ulong heap_cost;
   /* Memory operation syscall base cost */
   ulong mem_op_base_cost;
   /* Number of compute units consumed to call alt_bn128_addition */
   ulong alt_bn128_addition_cost;
   /* Number of compute units consumed to call alt_bn128_multiplication. */
   ulong alt_bn128_multiplication_cost;
   /* Total cost will be alt_bn128_pairing_one_pair_cost_first
      + alt_bn128_pairing_one_pair_cost_other * (num_elems - 1) */
   ulong alt_bn128_pairing_one_pair_cost_first;
   ulong alt_bn128_pairing_one_pair_cost_other;
   /* Big integer modular exponentiation cost */
   ulong big_modular_exponentiation_cost;
   /* Coefficient `a` of the quadratic function which determines the number
      of compute units consumed to call poseidon syscall for a given number
      of inputs. */
   ulong poseidon_cost_coefficient_a;
   /* Coefficient `c` of the quadratic function which determines the number
      of compute units consumed to call poseidon syscall for a given number
      of inputs. */
   ulong poseidon_cost_coefficient_c;
   /* Number of compute units consumed for accessing the remaining compute units. */
   ulong get_remaining_compute_units_cost;
   /* Number of compute units consumed to call alt_bn128_g1_compress. */
   ulong alt_bn128_g1_compress;
   /* Number of compute units consumed to call alt_bn128_g1_decompress. */
   ulong alt_bn128_g1_decompress;
   /* Number of compute units consumed to call alt_bn128_g2_compress. */
   ulong alt_bn128_g2_compress;
   /* Number of compute units consumed to call alt_bn128_g2_decompress. */
   ulong alt_bn128_g2_decompress;
   /* Maximum accounts data size, in bytes, that a transaction is allowed to load; the
      value is capped by MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES to prevent overuse of
      memory. */
   ulong loaded_accounts_data_size_limit;
};

typedef struct fd_vm_exec_compute_budget fd_vm_exec_compute_budget_t;

/* fd_vm_disasm API ***************************************************/

/* FIXME: pretty good case these actually belongs in ballet/sbpf */
/* FIXME: fd_sbpf_instr_t is nominally a ulong but implemented using
   bit-fields.  Compilers tend to generate notoriously poor asm for bit
   fields ... check ASM here. */

FD_PROTOTYPES_BEGIN

/* fd_vm_disasm_{instr,program} appends to the *_out_len (in strlen
   sense) cstr in the out_max byte buffer out a pretty printed cstr of
   the {instruction,program}.  On input, *_out_len should be strlen(out)
   and in [0,out_max).  For instr, pc is the program counter corresponding
   to text[0] (as such instr_cnt should be positive) and text_cnt is the
   number of words available at text to support safely printing
   multiword instructions.  Given a valid out on input, on output,
   *_out_len will be strlen(out) and in [0,out_max), even if there was
   an error.

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
fd_vm_disasm_instr( ulong const *              text,      /* Indexed [0,text_cnt) */
                    ulong                      text_cnt,
                    ulong                      pc,
                    fd_sbpf_syscalls_t const * syscalls,
                    char *                     out,       /* Indexed [0,out_max) */
                    ulong                      out_max,
                    ulong *                    _out_len );

int
fd_vm_disasm_program( ulong const *              text,       /* Indexed [0,text_cnt) */
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

struct fd_vm_trace_event_exe {
  /* This point is aligned 8 */
  ulong info;                 /* Event info bit field */
  ulong pc;                   /* pc */
  ulong ic;                   /* ic */
  ulong cu;                   /* cu */
  ulong reg[ FD_VM_REG_CNT ]; /* registers */
  /* FIXME: ENCODE 1-2 INSTR WORDS HERE SO THAT TEXT SECTION ISN'T
     NEEDED BY TRACE_PRINTF? (USE INFO TO ENCOE MW OR NOT) */
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
                       ulong           reg[ FD_VM_REG_CNT ] );

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
                    ulong              const * text,       /* Indexed [0,text_cnt) */
                    ulong                      text_cnt,
                    fd_sbpf_syscalls_t const * syscalls );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_base_h */
