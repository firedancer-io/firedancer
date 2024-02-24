#ifndef HEADER_fd_src_flamenco_vm_fd_vm_context_h
#define HEADER_fd_src_flamenco_vm_fd_vm_context_h

#include "fd_vm_stack.h"
#include "fd_vm_cpi.h"
#include "fd_vm_trace.h"

/* FIXME: NEGATIVE INTEGER ERROR CODES */
/* FIXME: UNIFY THE ERROR CODES */
/* FIXME: HAVE AN ERROR CODE CSTR */

/* sBPF instruction validation error codes */
#define FD_VM_SBPF_VALIDATE_SUCCESS               (0UL)  /* Program is valid. */
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_OPCODE    (1UL)  /* An invalid opcode was used. */
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_SRC_REG   (2UL)  /* An invalid source register was used. */
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_DST_REG   (3UL)  /* An invalid destination register was used. */
#define FD_VM_SBPF_VALIDATE_ERR_INF_LOOP          (4UL)  /* An infinite loop was detected. */
#define FD_VM_SBPF_VALIDATE_ERR_JMP_OUT_OF_BOUNDS (5UL)  /* An out of bounds jump was detected. */
#define FD_VM_SBPF_VALIDATE_ERR_JMP_TO_ADDL_IMM   (6UL)  /* A jump to a FD_BPF_INSTR_ADDL_IMM was detected. */
#define FD_VM_SBPF_VALIDATE_ERR_INVALID_END_IMM   (7UL)  /* An invalid immediate was used for an endianness conversion instruction. */
#define FD_VM_SBPF_VALIDATE_ERR_INCOMPLETE_LDQ    (8UL)  /* The program ends with an FD_BPF_INSTR_LDQ. */
#define FD_VM_SBPF_VALIDATE_ERR_LDQ_NO_ADDL_IMM   (9UL)  /* An FD_BPF_INSTR_LDQ did not have an FD_BPF_ADDL_IMM after it. */
#define FD_VM_SBPF_VALIDATE_ERR_NO_SUCH_EXT_CALL  (10UL) /* An FD_BPF_INSTR_CALL had an immediate but no function was registered for that immediate. */

#define FD_VM_COND_FAULT_FLAG_NONE        (0x0UL)
#define FD_VM_COND_FAULT_FLAG_MEM_TRANS   (0x1UL)
#define FD_VM_COND_FAULT_FLAG_BAD_CALL    (0x2UL)

/* TODO: consider disambiguating different ERR_ACC_VIO cases
   (misaligned, out of bounds, etc) */

#define FD_VM_MEM_MAP_SUCCESS     (0)
#define FD_VM_MEM_MAP_ERR_ACC_VIO (1)

/* VM memory map constants */
#define FD_VM_MEM_MAP_PROGRAM_REGION_START   (0x100000000UL)
#define FD_VM_MEM_MAP_STACK_REGION_START     (0x200000000UL)
#define FD_VM_MEM_MAP_HEAP_REGION_START      (0x300000000UL)
#define FD_VM_MEM_MAP_INPUT_REGION_START     (0x400000000UL)
#define FD_VM_MEM_MAP_REGION_SZ              (0x0FFFFFFFFUL)
#define FD_VM_MEM_MAP_REGION_MASK            (~FD_VM_MEM_MAP_REGION_SZ)
#define FD_VM_MEM_MAP_REGION_VIRT_ADDR_BITS  (32)
#define FD_VM_MAX_HEAP_SZ (256*1024)
#define FD_VM_DEFAULT_HEAP_SZ (32*1024)

/* Forward definition of fd_vm_sbpf_exec_context_t. */
struct fd_vm_exec_context;
typedef struct fd_vm_exec_context fd_vm_exec_context_t;

/* Syscall function type for all sBPF syscall/external function calls.
   They take a context from the VM and VM registers 1-5 as input, and
   return a value to VM register 0.  The syscall return value is a
   status code for the syscall. */

typedef ulong /* FIXME: MAKE AN INT */
(*fd_vm_syscall_fn_ptr_t)( fd_vm_exec_context_t * ctx,
                           ulong                  arg0,
                           ulong                  arg1,
                           ulong                  arg2,
                           ulong                  arg3,
                           ulong                  arg4,
                           ulong *                ret );

/* fd_vm_heap_allocator_t is the state of VM's native allocator backing
   the sol_alloc_free_ syscall.  Provides a naive bump allocator.
   Obviously, this feature is redundant.  The same allocation logic
   could trivially be implemented in on-chain bytecode.

   TODO Document if this is a legacy feature.  I think it has been
        removed in later runtime versions. */

struct fd_vm_heap_allocator {
  ulong offset;   /* Points to beginning of free region within heap,
                     relative to start of heap region. */
};
typedef struct fd_vm_heap_allocator fd_vm_heap_allocator_t;

struct fd_vm_exec_compute_budget {
    /// Number of compute units that a transaction or individual instruction is
    /// allowed to consume. Compute units are consumed by program execution,
    /// resources they use, etc...
    ulong compute_unit_limit;
    /// Number of compute units consumed by a log_u64 call
    ulong log_64_units;
    /// Number of compute units consumed by a create_program_address call
    ulong create_program_address_units;
    /// Number of compute units consumed by an invoke call (not including the cost incurred by
    /// the called program)
    ulong invoke_units;
    /// Maximum cross-program invocation depth allowed
    ulong max_invoke_depth;
    /// Base number of compute units consumed to call SHA256
    ulong sha256_base_cost;
    /// Incremental number of units consumed by SHA256 (based on bytes)
    ulong sha256_byte_cost;
    /// Maximum number of slices hashed per syscall
    ulong sha256_max_slices;
    /// Maximum BPF to BPF call depth
    ulong max_call_depth;
    /// Size of a stack frame in bytes, must match the size specified in the LLVM BPF backend
    ulong stack_frame_size;
    /// Number of compute units consumed by logging a `Pubkey`
    ulong log_pubkey_units;
    /// Maximum cross-program invocation instruction size
    ulong max_cpi_instruction_size;
    /// Number of account data bytes per compute unit charged during a cross-program invocation
    ulong cpi_bytes_per_unit;
    /// Base number of compute units consumed to get a sysvar
    ulong sysvar_base_cost;
    /// Number of compute units consumed to call secp256k1_recover
    ulong secp256k1_recover_cost;
    /// Number of compute units consumed to do a syscall without any work
    ulong syscall_base_cost;
    /// Number of compute units consumed to validate a curve25519 edwards point
    ulong curve25519_edwards_validate_point_cost;
    /// Number of compute units consumed to add two curve25519 edwards points
    ulong curve25519_edwards_add_cost;
    /// Number of compute units consumed to subtract two curve25519 edwards points
    ulong curve25519_edwards_subtract_cost;
    /// Number of compute units consumed to multiply a curve25519 edwards point
    ulong curve25519_edwards_multiply_cost;
    /// Number of compute units consumed for a multiscalar multiplication (msm) of edwards points.
    /// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
    ulong curve25519_edwards_msm_base_cost;
    /// Number of compute units consumed for a multiscalar multiplication (msm) of edwards points.
    /// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
    ulong curve25519_edwards_msm_incremental_cost;
    /// Number of compute units consumed to validate a curve25519 ristretto point
    ulong curve25519_ristretto_validate_point_cost;
    /// Number of compute units consumed to add two curve25519 ristretto points
    ulong curve25519_ristretto_add_cost;
    /// Number of compute units consumed to subtract two curve25519 ristretto points
    ulong curve25519_ristretto_subtract_cost;
    /// Number of compute units consumed to multiply a curve25519 ristretto point
    ulong curve25519_ristretto_multiply_cost;
    /// Number of compute units consumed for a multiscalar multiplication (msm) of ristretto points.
    /// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
    ulong curve25519_ristretto_msm_base_cost;
    /// Number of compute units consumed for a multiscalar multiplication (msm) of ristretto points.
    /// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
    ulong curve25519_ristretto_msm_incremental_cost;
    /// Optional program heap region size, if `None` then loader default
    ulong heap_size;
    /// Number of compute units per additional 32k heap above the default (~.5
    /// us per 32k at 15 units/us rounded up)
    ulong heap_cost;
    /// Memory operation syscall base cost
    ulong mem_op_base_cost;
    /// Maximum accounts data size, in bytes, that a transaction is allowed to load; The
    /// value is capped by MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES to prevent overuse of memory.
    ulong loaded_accounts_data_size_limit;
};
typedef struct fd_vm_exec_compute_budget fd_vm_exec_compute_budget_t;

#define MAX_COMPUTE_UNIT_LIMIT 1400000
#define MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES (64 * 1024 * 1024)
static const fd_vm_exec_compute_budget_t vm_compute_budget = {
  .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
  .log_64_units = 100,
  .create_program_address_units = 1500,
  .invoke_units = 1000,
  .max_invoke_depth = 4,
  .sha256_base_cost = 85,
  .sha256_byte_cost = 1,
  .sha256_max_slices = 20000,
  .max_call_depth = 64,
  .stack_frame_size = 4096,
  .log_pubkey_units = 100,
  .max_cpi_instruction_size = 1280, // IPv6 Min MTU size
  .cpi_bytes_per_unit = 250,        // ~50MB at 200,000 units
  .sysvar_base_cost = 100,
  .secp256k1_recover_cost = 25000,
  .syscall_base_cost = 100,
  .curve25519_edwards_validate_point_cost = 159,
  .curve25519_edwards_add_cost = 473,
  .curve25519_edwards_subtract_cost = 475,
  .curve25519_edwards_multiply_cost = 2177,
  .curve25519_edwards_msm_base_cost = 2273,
  .curve25519_edwards_msm_incremental_cost = 758,
  .curve25519_ristretto_validate_point_cost = 169,
  .curve25519_ristretto_add_cost = 521,
  .curve25519_ristretto_subtract_cost = 519,
  .curve25519_ristretto_multiply_cost = 2208,
  .curve25519_ristretto_msm_base_cost = 2303,
  .curve25519_ristretto_msm_incremental_cost = 788,
  // .heap_size = NULL,
  .heap_cost = 8,
  .mem_op_base_cost = 10,
  .loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES, // 64MiB
};


// FIXME: THE HEAP IS RESIZEABLE AT INVOCATION ~~ugh~~
/* The sBPF execution context. This is the primary data structure that is evolved before, during
   and after contract execution. */
struct fd_vm_exec_context {
  /* Read-only VM parameters: */
  long                        entrypoint;     /* The initial program counter to start at */
  fd_sbpf_syscalls_t *        syscall_map;    /* The map of syscalls that can be called into */
  ulong *                     calldests;      /* The bit vector of local functions that can be called into */
  fd_sbpf_instr_t const *     instrs;         /* The program instructions */
  ulong                       instrs_sz;      /* The number of program instructions FIXME this should be _cnt, not _sz */
  ulong                       instrs_offset;  /* This is the relocation offset we must apply to indirect calls (callx/CALL_REGs) */
  uint                        check_align;    /* If non-zero, VM does alignment checks where necessary (syscalls) */
  uint                        check_size;     /* If non-zero, VM does size checks where necessary (syscalls) */

  /* Writable VM parameters: */
  ulong                 register_file[11];           /* The sBPF register file */
  ulong                 program_counter;             /* The current instruction index being executed */
  ulong                 instruction_counter;         /* The number of instructions which have been executed */
  fd_vm_log_collector_t log_collector[1];            /* The log collector used by `sol_log_*` syscalls */
  ulong                 compute_meter;               /* The remaining CUs left for the transaction */
  ulong                 due_insn_cnt;                /* Currently executed instructions */
  ulong                 previous_instruction_meter;  /* Last value of remaining compute units */
  int                   cond_fault;                  /* If non-zero, indicates a fault occured during execution */

  /* Memory regions: */
  uchar *       read_only;                /* The read-only memory region, typically just the relocated program binary blob */
  ulong         read_only_sz;             /* The read-only memory region size */
  uchar *       input;                    /* The program input memory region */
  ulong         input_sz;                 /* The program input memory region size */
  fd_vm_stack_t stack;                    /* The sBPF call frame stack */
  ulong         heap_sz;                  /* The configured size of the heap */
  uchar         heap[FD_VM_MAX_HEAP_SZ];  /* The heap memory allocated by the bump allocator syscall */

  /* Runtime context */
  fd_exec_instr_ctx_t * instr_ctx;

  /* Miscellaneous native state:
     Below contains state of syscall logic for the lifetime of the
     execution context.
     TODO Separate this out from the core virtual machine */
  fd_vm_heap_allocator_t alloc; /* Bump allocator provided through syscall */

  fd_vm_trace_context_t * trace_ctx;
};
typedef struct fd_vm_exec_context fd_vm_exec_context_t;

FD_PROTOTYPES_BEGIN

/* Consume `cost` compute units */
ulong
fd_vm_consume_compute_meter( fd_vm_exec_context_t * ctx, ulong cost );

/* Validates the sBPF program from the given context. Returns success or an error code. */
FD_FN_PURE ulong
fd_vm_context_validate( fd_vm_exec_context_t const * ctx );

/* fd_vm_translate_vm_to_host{_const} translates a virtual memory area
   into the local address space.  ctx is the current execution context.
   vm_addr points to the region's first byte in VM address space.  sz is
   the number of bytes in the requested access.  align is the required
   alignment for vm_addr (2^n where n in [1,63) and may not be zero).
   Returns pointer to same memory region in local address space on
   success.  On failure, returns NULL.  Reasons for failure include
   access violation (out-of-bounds access, write requested on read-only
   region).

   fd_vm_translate_vm_to_host checks whether the target area is writable
   and returns a pointer to a mutable data region.

   fd_vm_translate_vm_to_host_const is the read-only equivalent and
   checks for a read-only or writable data region.

   Security note: Watch out for pointer aliasing when translating
                  multiple user-specified data types. */

ulong
fd_vm_translate_vm_to_host_private( fd_vm_exec_context_t * ctx,
                                    ulong                  vm_addr,
                                    ulong                  sz,
                                    int                    write );

/* TODO: WHY IS CTX->CHECK_ALIGN / CTX->CHECK_SIZE A THING?  CONSIDERING
   REMOVING THESE OR MAKING A COMPILE TIME OPTION (WITH A DEFAULT OF
   TRUE). */

/* FIXME: ARG ORDERING CONVENTION IS ALIGN/SZ */

static inline void *
fd_vm_translate_vm_to_host( fd_vm_exec_context_t * ctx,
                            ulong                  vm_addr,
                            ulong                  sz,
                            ulong                  align ) {
  if( FD_UNLIKELY( ctx->check_align && !fd_ulong_is_aligned( vm_addr, align ) ) ) {
    return NULL;
  }
  return (void *)fd_vm_translate_vm_to_host_private( ctx, vm_addr, sz, 1 );
}

static inline void const *
fd_vm_translate_vm_to_host_const( fd_vm_exec_context_t * ctx,
                                  ulong                  vm_addr,
                                  ulong                  sz,
                                  ulong                  align ) {
  if( ctx->check_align && FD_UNLIKELY( !fd_ulong_is_aligned( vm_addr, align ) ) ) {
    return NULL;
  }
  return (void const *)fd_vm_translate_vm_to_host_private( ctx, vm_addr, sz, 0 );
}

static inline fd_vm_vec_t *
fd_vm_translate_slice_vm_to_host( fd_vm_exec_context_t * ctx,
                                  ulong                  vm_addr,
                                  ulong                  sz,
                                  ulong                  align) {
  if ( ctx->check_size  && FD_UNLIKELY(fd_ulong_sat_mul( sz, sizeof(fd_vm_vec_t) ) > LONG_MAX )) {
    return NULL;
  }
  return (fd_vm_vec_t *) fd_vm_translate_vm_to_host(ctx, vm_addr, sz, align);
}

static inline fd_vm_vec_t const *
fd_vm_translate_slice_vm_to_host_const( fd_vm_exec_context_t * ctx,
                                  ulong                  vm_addr,
                                  ulong                  sz,
                                  ulong                  align) {
  if ( ctx->check_size  && FD_UNLIKELY(fd_ulong_sat_mul( sz, sizeof(fd_vm_vec_t) ) > LONG_MAX )) {
    return NULL;
  }
  return (fd_vm_vec_t const *) fd_vm_translate_vm_to_host_const(ctx, vm_addr, sz, align);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_context_h */
