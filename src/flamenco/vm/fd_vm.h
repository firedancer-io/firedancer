#ifndef HEADER_fd_src_flamenco_vm_fd_vm_h
#define HEADER_fd_src_flamenco_vm_fd_vm_h

/* An fd_vm_t is an opaque handle of a virtual machine that can execute
   sBPF programs. */

#include "fd_vm_base.h"

struct fd_vm;
typedef struct fd_vm fd_vm_t;

/**********************************************************************/
/* FIXME: MOVE TO PRIVATE WHEN CONSTRUCTORS READY */

/* A fd_vm_shadow_t holds stack frame information not accessible from
   within a VM program. */

struct fd_vm_shadow {
  ulong rip;
  ulong reg[ FD_VM_SHADOW_REG_CNT ];
};

typedef struct fd_vm_shadow fd_vm_shadow_t;

struct fd_vm {

  /* FIXME: ORGANIZATION FOR PERFORMANCE */

  /* Read-only VM parameters */

  long                 entrypoint;  /* The initial program counter to start at */ /* FIXME: WHY LONG? IS IT IN [0,TEXT_CNT)? */
  fd_sbpf_syscalls_t * syscalls;    /* The map of syscalls that can be called into */ /* FIXME: CONST? */
  ulong *              calldests;   /* The bit vector of local functions that can be called into (FIXME: INDEXING, CONST) */
  int                  check_align; /* If non-zero, VM does alignment checks where necessary (syscalls) */
  int                  check_size;  /* If non-zero, VM does size checks where necessary (syscalls) */

  /* Read-write VM parameters */

  ulong program_counter;            /* The current instruction index being executed */
  ulong instruction_counter;        /* The number of instructions which have been executed */
  ulong compute_meter;              /* The remaining CUs left for the transaction */
  ulong due_insn_cnt;               /* Currently executed instructions */ /* FIXME: DOCUMENT */
  ulong previous_instruction_meter; /* Last value of remaining compute units */
  int   cond_fault;                 /* If non-zero, holds an FD_VM_ERR code describing the execution fault that occured */

  /* Memory regions */

  ulong const *   text;      /* Program sBPF words, indexed [0,text_cnt) */
  ulong           text_cnt;  /* Program sBPF word count (FIXME: BOUNDS?) */
  ulong           text_off;  /* This is the relocation offset we must apply to indirect calls (callx/CALL_REGs)
                                IMPORANT SAFETY TIP!  THIS IS IN BYTES (FIXME: SHOULD THIS BE IN BYTES, MULTIPLE OF 8, ULONG, BOUNDS?) */
  uchar *         input;     /* Program input memory region */
  ulong           input_sz;  /* Program input memory region size, FIXME: BOUNDS */
  uchar const *   rodata;    /* Program read only data, typically just the relocated program binary blob */
  ulong           rodata_sz; /* Program read only data size in bytes (FIXME: BOUNDS) */
  fd_vm_trace_t * trace;     /* Location to hold traces (ignored and can be NULL if not tracing) */

  /* Runtime context */

  fd_exec_instr_ctx_t * instr_ctx; /* FIXME: DOCUMENT */

  /* VM stack state */

  /* FIXME: FRAME_MAX should be run time configurable by compute budget
     (is there an upper bound to how configurable ... there needs to be
     ...  regardless fixable by adding a ulong frame_max here!). */

//ulong frame_max; /* In [0,FD_VM_STACK_FRAME_MAX] */
  ulong frame_cnt; /* In [0,frame_max] */

  /* VM heap state */
  /* FIXME: THE HEAP IS RESIZEABLE AT INVOCATION ~~ugh~~ (IS THIS
     COMMENT STILL CURRENT? ... LOOKS LIKE THE BELOW SUPPORTS THIS) */

  /* IMPORANT SAFETY TIP!  THE BEHAVIOR OF THIS ALLOCATOR MUST EXACTLY
     MATCH THE SOLANA VALIDATOR ALLOCATOR:

     https://github.com/solana-labs/solana/blob/v1.17.23/program-runtime/src/invoke_context.rs#L122-L148

     BIT-FOR-BIT AND BUG-FOR-BUG.  SEE THE SYSCALL_ALLOC_FREE FOR MORE
     DETAILS. */

  ulong heap_max; /* Heap max size in bytes, in [0,FD_VM_HEAP_MAX] (FIXME: DOUBLE CHECK BOUNDS) */
  ulong heap_sz;  /* Heap size in bytes, in [0,heap_max] */

  /* VM log state */

  /* Note that we try to match syscall log messages with the existing
     Solana validator byte-for-byte (as there are things out there
     scraping log messages from the existing validator) though this is
     not strictly required for consensus. */

  ulong log_sz; /* In [0,FD_VM_LOG_MAX] */

  /* Large VM state */
  /* FIXME: ALIGNMENT */

  ulong          reg   [ FD_VM_REG_CNT         ]; /* registers (FIXME: USAGE) */
  fd_vm_shadow_t shadow[ FD_VM_STACK_FRAME_MAX ]; /* shadow frames, indexed [0,frame_cnt), if frame_cnt>0, 0/frame_cnt-1 is bottom/top */
  uchar          stack [ FD_VM_STACK_MAX       ]; /* stack (FIXME: USAGE) */
  uchar          heap  [ FD_VM_HEAP_MAX        ]; /* sol_alloc_free syscall heap, [0,heap_sz) used, [heap_sz,heap_max) free */
  uchar          log   [ FD_VM_LOG_MAX         ]; /* sol_log_* syscalls log, [0,log_sz) used, [log_sz,FD_VM_LOG_MAX) free */
};

/* FIXME: MOVE ABOVE INTO PRIVATE WHEN CONSTRUCTORS READY */
/**********************************************************************/

FD_PROTOTYPES_BEGIN

/* FIXME: FD_VM_T NEEDS PROPER CONSTRUCTORS */

extern fd_vm_exec_compute_budget_t const vm_compute_budget; /* FIXME: IF NOT COMPILE TIME MACROS, SHOULD THIS BE AN ELEMENT OF FD_VM_T */

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
/* FIXME: PASS TRACE TO THIS DIRECTLY AND THEN SWITCH UNDER THE HOOD
   (REMOVING TRACE FROM VM IN THE PROCESS?) MAKE TRACING COMPILE TIME? */

int
fd_vm_exec( fd_vm_t * vm );

int
fd_vm_exec_trace( fd_vm_t * vm );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_h */
