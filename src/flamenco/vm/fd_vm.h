#ifndef HEADER_fd_src_flamenco_vm_fd_vm_h
#define HEADER_fd_src_flamenco_vm_fd_vm_h

#include "fd_vm_cpi.h"

/* VM memory map constants */

#define FD_VM_MEM_MAP_PROGRAM_REGION_START  (0x100000000UL)
#define FD_VM_MEM_MAP_STACK_REGION_START    (0x200000000UL)
#define FD_VM_MEM_MAP_HEAP_REGION_START     (0x300000000UL)
#define FD_VM_MEM_MAP_INPUT_REGION_START    (0x400000000UL)
#define FD_VM_MEM_MAP_REGION_SZ             (0x0FFFFFFFFUL)
#define FD_VM_MEM_MAP_REGION_MASK           (~FD_VM_MEM_MAP_REGION_SZ)
#define FD_VM_MEM_MAP_REGION_VIRT_ADDR_BITS (32)
#define FD_VM_MAX_HEAP_SZ                   (256UL*1024UL)
#define FD_VM_DEFAULT_HEAP_SZ               (32UL*1024UL)

/* FIXME: THE HEAP IS RESIZEABLE AT INVOCATION ~~ugh~~ */

/* The sBPF execution context. This is the primary data structure that
   is evolved before, during and after contract execution. */

struct fd_vm {

  /* FIXME: ORGANIZATION FOR PERFORMANCE */

  /* Read-only VM parameters */
  long                 entrypoint;  /* The initial program counter to start at */ /* FIXME: WHY LONG? IS IT IN [0,TEXT_CNT)? */
  fd_sbpf_syscalls_t * syscalls;    /* The map of syscalls that can be called into */ /* FIXME: CONST? */
  ulong *              calldests;   /* The bit vector of local functions that can be called into (FIXME: INDEXING, CONST) */
  ulong const *        text;        /* The program instructions, indexed [0,text_cnt) */
  ulong                text_cnt;    /* The number of program instructions (FIXME: BOUNDS?) */
  ulong                text_off;    /* This is the relocation offset we must apply to indirect calls (callx/CALL_REGs) in bytes
                                       (FIXME: SHOULD THIS BE IN BYTES, MULTIPLE OF 8, ULONG, WHAT ARE BOUNDS?) */
  int                  check_align; /* If non-zero, VM does alignment checks where necessary (syscalls) */
  int                  check_size;  /* If non-zero, VM does size checks where necessary (syscalls) */

  /* Writable VM parameters */
  ulong                 register_file[11];          /* The sBPF register file */ /* FIXME: MAGIC NUMBER */
  ulong                 program_counter;            /* The current instruction index being executed */
  ulong                 instruction_counter;        /* The number of instructions which have been executed */
  fd_vm_log_collector_t log_collector[1];           /* The log collector used by `sol_log_*` syscalls */
  ulong                 compute_meter;              /* The remaining CUs left for the transaction */
  ulong                 due_insn_cnt;               /* Currently executed instructions */ /* FIXME: DOCUMENT */
  ulong                 previous_instruction_meter; /* Last value of remaining compute units */
  int                   cond_fault;                 /* If non-zero, holds an FD_VM_ERR code describing the execution fault that occured */

  /* Memory regions */
  uchar *       read_only;                 /* The read-only memory region, typically just the relocated program binary blob */
  ulong         read_only_sz;              /* The read-only memory region size */
  uchar *       input;                     /* The program input memory region */
  ulong         input_sz;                  /* The program input memory region size */
  fd_vm_stack_t stack[1];                  /* The sBPF call frame stack */ /* FIXME: SEPARATE STACK AND SHADOW STACK */
  ulong         heap_sz;                   /* The configured size of the heap */
  uchar         heap[ FD_VM_MAX_HEAP_SZ ]; /* The heap memory allocated by the bump allocator syscall */

  /* Runtime context */
  fd_exec_instr_ctx_t * instr_ctx;

  /* Miscellaneous native state

     Below contains state of syscall logic for the lifetime of the
     execution context.  FIXME: Consider separating this out from the
     core virtual machine? */

  fd_vm_heap_allocator_t alloc[1]; /* Bump allocator provided through syscall */

  fd_vm_trace_t * trace;
};

typedef struct fd_vm fd_vm_t;

FD_PROTOTYPES_BEGIN

extern fd_vm_exec_compute_budget_t const vm_compute_budget; /* FIXME: IF NOT COMPILE TIME MACROS, SHOULD THIS BE AN ELEMENT OF FD_VM_T */

/* FIXME: FD_VM_T NEEDS PROPER CONSTRUCTORS */

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
   zero in the ERR_BUDGET case).  FIXME: double check that sz 0 should
   have zero cost due to things like address translation costs and what
   not. */

/* FIXME: OPTIMIZE FUNCTION SIGNATURE FOR USE CASE */

static inline int
fd_vm_consume_mem( fd_vm_t * vm,
                   ulong     sz ) {
  ulong cost = fd_ulong_max( vm_compute_budget.mem_op_base_cost, sz / vm_compute_budget.cpi_bytes_per_unit );
  return fd_vm_consume_compute( vm, cost );
}

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

/* syscall/fd_vm_syscall_admin ****************************************/

/* FIXME: SHOULD THESE TAKE A FD_VM_EXEC_CONTEXT_T? MOVE TO VM_BASE? */
/* FIXME: DOCUMENT IN MORE DETAIL */

/* fd_vm_syscall_register registers a syscall by name to an execution
   context. */

void
fd_vm_syscall_register( fd_sbpf_syscalls_t *   syscalls,
                        char const *           name,
                        fd_sbpf_syscall_func_t func );

/* fd_vm_syscall_register_slot registers all syscalls appropriate for a
   slot context. */

void
fd_vm_syscall_register_slot( fd_sbpf_syscalls_t *       syscalls,
                             fd_exec_slot_ctx_t const * slot_ctx );

/* fd_vm_syscall_register all reigsters all syscalls implemented.  May
   change between Firedancer versions without warning. */

void
fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls );

/* fd_vm_validate validates the sBPF program in the given vm.  Returns
 * success or an error code.  Called before executing a sBPF
   program. */

FD_FN_PURE int
fd_vm_validate( fd_vm_t const * vm );

/* fd_vm_exec runs the sBPF program in the VM until completion or a
   fault occurs.  Returns FD_VM_SUCCESS (0) on success and an FD_VM_ERR
   code (negative) on failure.  FIXME: DOCUMENT FAILURE REASONS */
/* FIXME: PASS TRACE AS FLAG?  USE TRACE!=NULL IN VM TO INDICATE
   TRACING?  REMOVE TRACE FROM VM AND PASS TRACE TO EXEC?  MAKE TRACING
   COMPILE TIME? */

int
fd_vm_exec( fd_vm_t * vm );

int
fd_vm_exec_trace( fd_vm_t * vm );

FD_PROTOTYPES_END

/* FIXME: TEMPORARY SCAFFOLDING */
#define fd_vm_exec_context_t fd_vm_t

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_h */
