#ifndef HEADER_fd_src_flamenco_vm_fd_vm_base_h
#define HEADER_fd_src_flamenco_vm_fd_vm_base_h

/* FIXME: Headers included from other modules need cleanup.  As it
   stands, flamenco_base brings in types/custom, types/meta,
   types/bincode, ballet/base58, ballet/sha256, ballet/sha512,
   ballet/ed25519, ballet/txnthis also brings in util, flamenco_base,
   ballet/base58, util and the optional util/net/ipv4 ballet/sha256,
   most of which is probably not necessary to use this module in a
   somewhat haphazard fashion (include no-no things that are only
   available in hosted environments like stdio and stdlib) */

#include "../fd_flamenco_base.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h" /* FIXME: functionality needed from here probably should be moved here */

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

/* FIXME: pretty good case these actually belong in ballet/sbpf */
/* FIXME: DOCUMENT THESE / LINK TO SOLANA CODE / ETC */

/* VM register constants */

#define FD_VM_REG_CNT (11UL)
#define FD_VM_REG_MAX (16UL) /* Actual number of SBPF instruction src/dst register indices */

#define FD_VM_SHADOW_REG_CNT (4UL)

/* VM stack constants */

#define FD_VM_STACK_FRAME_MAX (64UL)
#define FD_VM_STACK_FRAME_SZ  (0x1000UL) /* FIXME: SHOULD THIS MACH FD_VM_STACK_FRAME_SIZE BELOW? */
#define FD_VM_STACK_GUARD_SZ  (0x1000UL)
#define FD_VM_STACK_MAX       (FD_VM_STACK_FRAME_MAX*(FD_VM_STACK_FRAME_SZ+FD_VM_STACK_GUARD_SZ))

/* VM heap constants */

#define FD_VM_HEAP_DEFAULT ( 32UL*1024UL) /* FIXME: SHOULD THIS MATCH FD_VM_HEAP_SIZE LIMIT BELOW? */
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

/* VM compute budget.  Note: these names should match exactly the names
   used in existing Solana validator.  See:
   https://github.com/anza-xyz/agave/blob/v1.18.5/program-runtime/src/compute_budget.rs#L19
   https://github.com/anza-xyz/agave/blob/v1.18.5/program-runtime/src/compute_budget.rs#L133 */
/* FIXME: DOUBLE CHECK THESE */

/* FD_VM_COMPUTE_UNIT_LIMIT is the number of compute units that a
   transaction or individual instruction is allowed to consume.  Compute
   units are consumed by program execution, resources they use, etc ... */

#define FD_VM_COMPUTE_UNIT_LIMIT                        (         1400000UL)

/* FD_VM_LOG_64_UNITS is the number of compute units consumed by a
   log_64 call */

#define FD_VM_LOG_64_UNITS                              (             100UL)

/* FD_VM_CREATE_PROGRAM_ADDRESS_UNITS is the number of compute units
   consumed by a create_program_address call */

#define FD_VM_CREATE_PROGRAM_ADDRESS_UNITS              (            1500UL)

/* FD_VM_INVOKE_UNITS is the number of compute units consumed by an
   invoke call (not including the cost incurred by the called program) */

#define FD_VM_INVOKE_UNITS                              (            1000UL)

/* FD_VM_MAX_INVOKE_STACK_HEIGHT is the maximum program instruction
   invocation stack height. Invocation stack height starts at 1 for
   transaction instructions and the stack height is incremented each
   time a program invokes an instruction and decremented when a program
   returns */

#define FD_VM_MAX_INVOKE_STACK_HEIGHT                   (               5UL)

/* FD_VM_MAX_INSTRUCTION_TRACE_LENGTH is the maximum cross-program
   invocation and instructions per transaction */

#define FD_VM_MAX_INSTRUCTION_TRACE_LENGTH              (              64UL)

/* FD_VM_SHA256_BASE_COST is the base number of compute units consumed
   to call SHA256 */

#define FD_VM_SHA256_BASE_COST                          (              85UL)

/* FD_VM_SHA256_BYTE_COST is the incremental number of units consumed by
   SHA256 (based on bytes) */

#define FD_VM_SHA256_BYTE_COST                          (               1UL)

/* FD_VM_SHA256_MAX_SLICES is the maximum number of slices hashed per
   syscall */

#define FD_VM_SHA256_MAX_SLICES                         (           20000UL)

/* FD_VM_MAX_CALL_DEPTH is the maximum SBF to BPF call depth */

#define FD_VM_MAX_CALL_DEPTH                            (              64UL)

/* FD_VM_STACK_FRAME_SIZE is the size of a stack frame in bytes, must
   match the size specified in the LLVM SBF backend */

#define FD_VM_STACK_FRAME_SIZE                          (            4096UL)

/* FD_VM_LOG_PUBKEY_UNITS is the number of compute units consumed by
   logging a `Pubkey` */

#define FD_VM_LOG_PUBKEY_UNITS                          (             100UL)

/* FD_VM_MAX_CPI_INSTRUCTION_SIZE is the maximum cross-program
   invocation instruction size */

#define FD_VM_MAX_CPI_INSTRUCTION_SIZE                  (            1280UL) /* IPv6 Min MTU size */

/* FD_VM_CPI_BYTES_PER_UNIT is the number of account data bytes per
   compute unit charged during a cross-program invocation */

#define FD_VM_CPI_BYTES_PER_UNIT                        (             250UL) /* ~50MB at 200,000 units */

/* FD_VM_SYSVAR_BASE_COST is the base number of compute units consumed
   to get a sysvar */

#define FD_VM_SYSVAR_BASE_COST                          (             100UL)

/* FD_VM_SECP256K1_RECOVER_COST is the number of compute units consumed
   to call secp256k1_recover */

#define FD_VM_SECP256K1_RECOVER_COST                    (           25000UL)

/* FD_VM_SYSCALL_BASE_COST is the number of compute units consumed to do
   a syscall without any work */

#define FD_VM_SYSCALL_BASE_COST                         (             100UL)

/* FD_VM_CURVE25519_EDWARDS_VALIDATE_POINT_COST is the number of compute
   units consumed to validate a curve25519 edwards point */

#define FD_VM_CURVE25519_EDWARDS_VALIDATE_POINT_COST    (             159UL)

/* FD_VM_CURVE25519_EDWARDS_ADD_COST is the number of compute units
   consumed to add two curve25519 edwards points */

#define FD_VM_CURVE25519_EDWARDS_ADD_COST               (             473UL)

/* FD_VM_CURVE25519_EDWARDS_SUBTRACT_COST is the number of compute units
   consumed to subtract two curve25519 edwards points */

#define FD_VM_CURVE25519_EDWARDS_SUBTRACT_COST          (             475UL)

/* FD_VM_CURVE25519_EDWARDS_MULTIPLY_COST is the number of compute units
   consumed to multiply a curve25519 edwards point */

#define FD_VM_CURVE25519_EDWARDS_MULTIPLY_COST          (            2177UL)

/* FD_VM_CURVE25519_EDWARDS_MSM_BASE_COST is the number of compute units
   consumed for a multiscalar multiplication (msm) of edwards points.
   The total cost is calculated as
     `msm_base_cost + (length - 1) * msm_incremental_cost` */

#define FD_VM_CURVE25519_EDWARDS_MSM_BASE_COST          (            2273UL)

/* FD_VM_CURVE25519_EDWARDS_MSM_INCREMENTAL_COST is the number of
   compute units consumed for a multiscalar multiplication (msm) of
   edwards points.  The total cost is calculated as
     `msm_base_cost + (length - 1) * msm_incremental_cost` */

#define FD_VM_CURVE25519_EDWARDS_MSM_INCREMENTAL_COST   (             758UL)

/* FD_VM_CURVE25519_RISTRETTO_VALIDATE_POINT_COST is the number of
   compute units consumed to validate a curve25519 ristretto point */

#define FD_VM_CURVE25519_RISTRETTO_VALIDATE_POINT_COST  (             169UL)

/* FD_VM_CURVE25519_RISTRETTO_ADD_COST is the number of compute units
   consumed to add two curve25519 ristretto points */

#define FD_VM_CURVE25519_RISTRETTO_ADD_COST             (             521UL)

/* FD_VM_CURVE25519_RISTRETTO_SUBTRACT_COST is the number of compute
   units consumed to subtract two curve25519 ristretto points */

#define FD_VM_CURVE25519_RISTRETTO_SUBTRACT_COST        (             519UL)

/* FD_VM_CURVE25519_RISTRETTO_MULTIPLY_COST is the number of compute
   units consumed to multiply a curve25519 ristretto point */

#define FD_VM_CURVE25519_RISTRETTO_MULTIPLY_COST        (            2208UL)

/* FD_VM_CURVE25519_RISTRETTO_MSM_BASE_COST is the number of compute
   units consumed for a multiscalar multiplication (msm) of ristretto
   points.  The total cost is calculated as
     `msm_base_cost + (length - 1) * msm_incremental_cost` */

#define FD_VM_CURVE25519_RISTRETTO_MSM_BASE_COST        (            2303UL)

/* FD_VM_CURVE25519_RISTRETTO_MSM_INCREMENTAL_COST is the number of
   compute units consumed for a multiscalar multiplication (msm) of
   ristretto points.  The total cost is calculated as
     `msm_base_cost + (length - 1) * msm_incremental_cost` */

#define FD_VM_CURVE25519_RISTRETTO_MSM_INCREMENTAL_COST (             788UL)

/* FD_VM_HEAP_SIZE is the program heap region size, default:
   solana_sdk::entrypoint::HEAP_LENGTH */

#define FD_VM_HEAP_SIZE                                 (           32768UL)

/* FD_VM_HEAP_COST is the number of compute units per additional 32k
   heap above the default (~.5 us per 32k at 15 units/us rounded up) */

#define FD_VM_HEAP_COST                                 (               8UL) /* DEFAULT_HEAP_COST */

/* FD_VM_MEM_OP_BASE_COST is the memory operation syscall base cost */

#define FD_VM_MEM_OP_BASE_COST                          (              10UL)

/* FD_VM_ALT_BN128_ADDITION_COST is the number of compute units consumed
   to call alt_bn128_addition */

#define FD_VM_ALT_BN128_ADDITION_COST                   (             334UL)

/* FD_VM_ALT_BN128_MULTIPLICATION_COST is the number of compute units
   consumed to call alt_bn128_multiplication */

#define FD_VM_ALT_BN128_MULTIPLICATION_COST             (            3840UL)

/* FD_VM_ALT_BN128_PAIRING_ONE_PAIR_COST_FIRST
   FD_VM_ALT_BN128_PAIRING_ONE_PAIR_COST_OTHER give the total cost as
     alt_bn128_pairing_one_pair_cost_first + alt_bn128_pairing_one_pair_cost_other * (num_elems - 1) */

#define FD_VM_ALT_BN128_PAIRING_ONE_PAIR_COST_FIRST     (           36364UL)
#define FD_VM_ALT_BN128_PAIRING_ONE_PAIR_COST_OTHER     (           12121UL)

/* FD_VM_BIG_MODULAR_EXPONENTIATION_COST is the big integer modular
   exponentiation cost */

#define FD_VM_BIG_MODULAR_EXPONENTIATION_COST           (              33UL)

/* FD_VM_POSEIDON_COST_COEFFICIENT_A is the coefficient `a` of the
   quadratic function which determines the number of compute units
   consumed to call poseidon syscall for a given number of inputs */

#define FD_VM_POSEIDON_COST_COEFFICIENT_A               (              61UL)

/* FD_VM_POSEIDON_COST_COEFFICIENT_C is the coefficient `c` of the
   quadratic function which determines the number of compute units
   consumed to call poseidon syscall for a given number of inputs */

#define FD_VM_POSEIDON_COST_COEFFICIENT_C               (             542UL)

/* FD_VM_GET_REMAINING_COMPUTE_UNITS_COST is the number of compute units
   consumed for reading the remaining compute units */

#define FD_VM_GET_REMAINING_COMPUTE_UNITS_COST          (             100UL)

/* FD_VM_ALT_BN128_G1_COMPRESS is the number of compute units consumed
   to call alt_bn128_g1_compress */

#define FD_VM_ALT_BN128_G1_COMPRESS                     (              30UL)

/* FD_VM_ALT_BN128_G1_DECOMPRESS is the number of compute units consumed
   to call alt_bn128_g1_decompress */

#define FD_VM_ALT_BN128_G1_DECOMPRESS                   (             398UL)

/* FD_VM_ALT_BN128_G2_COMPRESS is the number of compute units consumed
   to call alt_bn128_g2_compress */

#define FD_VM_ALT_BN128_G2_COMPRESS                     (              86UL)

/* FD_VM_ALT_BN128_G2_DECOMPRESS is the number of compute units consumed
   to call alt_bn128_g2_decompress */

#define FD_VM_ALT_BN128_G2_DECOMPRESS                   (           13610UL)

/* FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT is the maximum accounts data
   size, in bytes, that a transaction is allowed to load */

#define FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT           (64UL*1024UL*1024UL) /* 64MiB */

/* fd_vm_disasm API ***************************************************/

/* FIXME: pretty good case this actually belongs in ballet/sbpf */
/* FIXME: fd_sbpf_instr_t is nominally a ulong but implemented using
   bit-fields.  Compilers tend to generate notoriously poor asm for bit
   fields ... check ASM here. */

FD_PROTOTYPES_BEGIN

/* fd_vm_disasm_{instr,program} appends to the *_out_len (in strlen
   sense) cstr in the out_max byte buffer out a pretty printed cstr of
   the {instruction,program}.  If syscalls is non-NULL, syscalls will be
   annotated with the names from the provided syscall mapping.

   On input, *_out_len should be strlen(out) and in [0,out_max).  For
   instr, pc is the program counter corresponding to text[0] (as such
   text_cnt should be positive) and text_cnt is the number of words
   available at text to support safely printing multiword instructions.

   Given a valid out on input, on output, *_out_len will be strlen(out)
   and in [0,out_max), even if there was an error.

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

/* FIXME: pretty good case this actually belongs in ballet/sbpf */

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
  ulong text[ 2 ];            /* If the event has valid clear, this is actually text[1] */
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
  ulong event_sz;       /* Used bytes of event storage */
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
FD_FN_CONST static inline ulong        fd_vm_trace_event_sz      ( fd_vm_trace_t const * trace ) { return trace->event_sz;       }
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
  trace->event_sz = 0UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_trace_event_exe records the the current pc, ic, cu and
   register file of the VM and the instruction about to execute.  Text
   points to the first word of the instruction about to execute and
   text_cnt points to the number of words available at that point.
   Returns FD_VM_SUCCESS (0) on success and a FD_VM_ERR code (negative)
   on failure.  Reasons for failure include INVAL (trace NULL, reg NULL,
   text NULL, and/or text_cnt 0) and FULL (insufficient trace event
   storage available). */

int
fd_vm_trace_event_exe( fd_vm_trace_t * trace,
                       ulong           pc,
                       ulong           ic,
                       ulong           cu,
                       ulong           reg[ FD_VM_REG_CNT ],
                       ulong const *   text,       /* Indexed [0,text_cnt) */
                       ulong           text_cnt );

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

/* fd_vm_trace_printf pretty prints the current trace to stdout.  If
   syscalls is non-NULL, the trace will annotate syscalls in its
   disassembly according the syscall mapping.  Returns FD_VM_SUCCESS (0)
   on success and a FD_VM_ERR code (negative) on failure.  Reasons for
   failure include INVAL (NULL trace) and IO (corruption detected while
   parsing the trace events).  FIXME: REVAMP THIS API FOR MORE GENERAL
   USE CASES. */

int
fd_vm_trace_printf( fd_vm_trace_t      const * trace,
                    fd_sbpf_syscalls_t const * syscalls );

/* fd_vm_syscall API **************************************************/

/* FIXME: fd_sbpf_syscalls_t and fd_sbpf_syscall_func_t probably should
   be moved from ballet/sbpf to here. */

/* Note: the syscall map is kept separate from the fd_vm_t itself to
   support, for example, multiple fd_vm_t executing transactions
   concurrently for a slot.  They could use the same syscalls for setup,
   memory and cache efficiency. */

/* fd_vm_syscall_register inserts the syscall with the given cstr name
   into the given syscalls.  The VM syscall implementation to use is
   given by func (NULL is fine though a VM itself may not accept such as
   valid).  The caller promises there is room in the syscall map.
   Returns FD_VM_SUCCESS (0) on success or a FD_VM_ERR code (negative)
   on failure.  Reasons for failure include INVAL (NULL syscalls, NULL
   name, name or the hash of name already in the map).  On success,
   syscalls retains a read-only interest in name (e.g. use an infinite
   lifetime cstr here).  (This function is exposed to allow VM users to
   add custom syscalls but most use cases probably should just call
   fd_vm_syscall_register_slot below.) */

int
fd_vm_syscall_register( fd_sbpf_syscalls_t *   syscalls,
                        char const *           name,
                        fd_sbpf_syscall_func_t func );

/* fd_vm_syscall_register_slot unmaps all syscalls in the current map
   (also ending any interest in the corresponding name cstr) and
   registers all syscalls appropriate for the slot described by
   slot_ctx.  Returns FD_VM_SUCCESS (0) on success and FD_VM_ERR code
   (negative) on failure.  Reasons for failure include INVAL (NULL
   syscalls) and FULL (tried to register too many system calls ...
   compile time map size needs to be adjusted).  If slot_ctx is NULL,
   will register all fd_vm syscall implementations (whether or not that
   makes sense ... may change between Firedancer versions without
   warning).  FIXME: probably better to pass the features for a slot
   than pass the whole slot_ctx. */

int
fd_vm_syscall_register_slot( fd_sbpf_syscalls_t *       syscalls,
                             fd_exec_slot_ctx_t const * slot_ctx );

/* fd_vm_syscall_register_all is a shorthand for registering all
   syscalls (see register slot). */

static inline int
fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls ) {
  return fd_vm_syscall_register_slot( syscalls, NULL );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_base_h */
