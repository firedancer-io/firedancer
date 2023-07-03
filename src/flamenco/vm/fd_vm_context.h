#ifndef HEADER_fd_src_flamenco_vm_fd_vm_context_h
#define HEADER_fd_src_flamenco_vm_fd_vm_context_h

#include "../fd_flamenco_base.h"
#include "fd_vm_log_collector.h"
#include "fd_vm_stack.h"

#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"

#include "fd_vm_log_collector.h"
#include "fd_vm_stack.h"

#include "../runtime/fd_executor.h"

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

/* VM memory map constants */
#define FD_VM_MEM_MAP_PROGRAM_REGION_START   (0x100000000UL)
#define FD_VM_MEM_MAP_STACK_REGION_START     (0x200000000UL)
#define FD_VM_MEM_MAP_HEAP_REGION_START      (0x300000000UL)
#define FD_VM_MEM_MAP_INPUT_REGION_START     (0x400000000UL)
#define FD_VM_MEM_MAP_REGION_SZ              (0x0FFFFFFFFUL)
#define FD_VM_MEM_MAP_REGION_MASK            (~FD_VM_MEM_MAP_REGION_SZ)
#define FD_VM_MEM_MAP_REGION_VIRT_ADDR_BITS  (32)
#define FD_VM_HEAP_SZ (64*1024)

#define FD_VM_MEM_MAP_SUCCESS       (0)
#define FD_VM_MEM_MAP_ERR_ACC_VIO   (1)

/* Foward definition of fd_vm_sbpf_exec_context_t. */
struct fd_vm_exec_context;
typedef struct fd_vm_exec_context fd_vm_exec_context_t;

/* Syscall function type for all sBPF syscall/external function calls. They take a context from
   the VM and VM registers 1-5 as input, and return a value to VM register 0. The syscall return
   value is a status code for the syscall. */
typedef ulong (*fd_vm_syscall_fn_ptr_t)(fd_vm_exec_context_t * ctx, ulong arg0, ulong arg1, ulong arg2, ulong arg3, ulong arg4, ulong * ret);

/* fd_vm_heap_allocator_t is the state of VM's native allocator backing
   the sol_alloc_free_ syscall.  Provides a naive bump allocator.
   Obviously, this feature is redundant.  The same allocation logic
   could trivially be implemented in on-chain bytecode.

   TODO Document if this is a legacy feature.  I think it has been
        removed in later runtime versions. */

struct fd_vm_heap_allocator {
  ulong heap_sz;  /* Total size of heap region */
  ulong offset;   /* Points to beginning of free region within heap,
                     relative to start of heap region. */
};
typedef struct fd_vm_heap_allocator fd_vm_heap_allocator_t;

// FIXME: THE HEAP IS RESIZEABLE AT INVOCATION ~~ugh~~
/* The sBPF execution context. This is the primary data structure that is evolved before, during
   and after contract execution. */
struct fd_vm_exec_context {
  /* Read-only VM parameters: */
  long                        entrypoint;     /* The initial program counter to start at */
  fd_sbpf_syscalls_t *        syscall_map;    /* The map of syscalls that can be called into */
  fd_sbpf_calldests_t *       local_call_map; /* The map of local functions that can be called into */
  fd_sbpf_instr_t const *     instrs;         /* The program instructions */
  ulong                       instrs_sz;      /* The number of program instructions FIXME this should be _cnt, not _sz */
  ulong                       instrs_offset;  /* This is the relocation offset we must apply to indirect calls (callx/CALL_REGs) */

  /* Writable VM parameters: */
  ulong                 register_file[11];    /* The sBPF register file */
  ulong                 program_counter;      /* The current instruction index being executed */
  ulong                 instruction_counter;  /* The number of instructions which have been executed */
  fd_vm_log_collector_t log_collector;        /* The log collector used by `sol_log_*` syscalls */
  ulong                 compute_budget;       /* The remaining CUs left for the transaction */
  ulong                 cond_fault;           /* If non-zero, indicates a fault occured during execution */

  /* Memory regions: */
  uchar *       read_only;            /* The read-only memory region, typically just the relocated program binary blob */
  ulong         read_only_sz;         /* The read-only memory region size */
  uchar *       input;                /* The program input memory region */
  ulong         input_sz;             /* The program input memory region size */
  fd_vm_stack_t stack;                /* The sBPF call frame stack */
  uchar         heap[FD_VM_HEAP_SZ];  /* The heap memory allocated by the bump allocator syscall */

  /* Runtime context */
  instruction_ctx_t instr_ctx;

  /* Miscellaneous native state:
     Below contains state of syscall logic for the lifetime of the
     execution context.
     TODO Separate this out from the core virtual machine */
  fd_vm_heap_allocator_t alloc; /* Bump allocator provided through syscall */
};
typedef struct fd_vm_exec_context fd_vm_exec_context_t;

struct fd_vm_trace_entry {
  ulong pc;
  ulong ic;
  ulong register_file[11];
};
typedef struct fd_vm_trace_entry fd_vm_trace_entry_t;


FD_PROTOTYPES_BEGIN


/* Validates the sBPF program from the given context. Returns success or an error code. */
FD_FN_PURE ulong fd_vm_context_validate( fd_vm_exec_context_t const * ctx );

/* fd_vm_translate_vm_to_host translates a virtual memory area into the
   local address space.  ctx is the current execution context.  write is
   1 if requesting a write, 0 if requesting a read.  vm_addr points to
   the region's first byte in VM address space.  sz is the number of
   bytes in the requested access.  Returns pointer to same memory region
   in local address space on success.  On failure, returns NULL.
   Reasons for failure include access violation (out-of-bounds access,
   write requested on read-only region). */

void *
fd_vm_translate_vm_to_host( fd_vm_exec_context_t *  ctx,
                            uint                    write,
                            ulong                   vm_addr,
                            ulong                   sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_context_h */
