#ifndef HEADER_fd_src_flamenco_vm_fd_vm_h
#define HEADER_fd_src_flamenco_vm_fd_vm_h

#include "fd_vm_base.h"

/* A fd_vm_t is an opaque handle of a virtual machine that can execute
   sBPF programs. */

struct fd_vm;
typedef struct fd_vm fd_vm_t;

/**********************************************************************/
/* FIXME: MOVE TO FD_VM_PRIVATE WHEN CONSTRUCTORS READY */

/* A fd_vm_shadow_t holds stack frame information not accessible from
   within a VM program. */

struct fd_vm_shadow {
  ulong rip;
  ulong reg[ FD_VM_SHADOW_REG_CNT ];
};

typedef struct fd_vm_shadow fd_vm_shadow_t;

struct fd_vm {

  /* FIXME: ORGANIZE FOR PERFORMANCE */

  /* Read-only VM parameters */

  int check_align; /* If non-zero, VM does alignment checks where necessary (syscalls) */
  int check_size;  /* If non-zero, VM does size checks where necessary (syscalls) */

  /* Read-write VM parameters */

  ulong program_counter;            /* The current instruction index being executed, FIXME: NAME -> PC? */
  ulong instruction_counter;        /* The number of instructions which have been executed, FIXME: NAME -> IC? */
  ulong compute_meter;              /* The remaining CUs left for the transaction */ /* FIXME: NAME -> CC? */
  ulong due_insn_cnt;               /* Currently executed instructions */ /* FIXME: DOCUMENT */
  ulong previous_instruction_meter; /* Last value of remaining compute units */ /* FIXME: NAME -> CC_LAST? */
  int   cond_fault;                 /* If non-zero, holds an FD_VM_ERR code describing the fault that occured, FIXME: NAME: FAULT? */

  /* External memory regions */
  /* FIXME: MAKE CALLDESTS AN INTERNAL MEMORY REGION IF TEXT_CNT
     HAS A REASONABLY UPPER BOUND? */
  /* FIXME: ADD BIT VECTOR TO FORBID BRANCHING INTO MULTIWORD
     INSTRUCTIONS (OR AS AN INTERNAL MEMORY REGION) AND/OR HAVE VALIDATE
     COMPUTE. */

  ulong const * text;       /* Program sBPF words, indexed [0,text_cnt) */
  ulong         text_cnt;   /* Program sBPF word count (FIXME: BOUNDS?) */
  ulong         text_off;   /* Relocation offset we must apply to indirect calls (callx/CALL_REGs)
                               IMPORANT SAFETY TIP!  THIS IS IN BYTES (FIXME: SHOULD IT BE? MULTIPLE OF 8? LONG? BOUNDS?) */
  ulong         entrypoint; /* Initial program counter */ /* FIXME: NAME, BOUNDS [0,TEXT_CNT)? */
  ulong const * calldests;  /* Bit vector of local functions that can be called into (FIXME: BIT INDEXED [0,TEXT_CNT)?) */

  fd_sbpf_syscalls_t const * syscalls; /* The map of syscalls (sharable over multiple concurrently running VM) */

  uchar * input;    /* Program input memory, indexed [0,input_sz) FIXME: ALIGN? */
  ulong   input_sz; /* Program input memory size in bytes, FIXME: BOUNDS? */

  uchar const * rodata;    /* Program read only data, indexed [0,rodata_sz) FIXME: ALIGN?, usually the relocated program binary blob */
  ulong         rodata_sz; /* Program read only data size in bytes, FIXME: BOUNDS? */

  fd_vm_trace_t * trace; /* Location to stream traces (no tracing if NULL) */

  /* Runtime context */

  fd_exec_instr_ctx_t * instr_ctx; /* FIXME: DOCUMENT */

  /* VM stack state */

  /* FIXME: FRAME_MAX should be run time configurable by compute budget
     (is there an upper bound to how configurable ... there needs to be
     ... regardless fixable by adding a ulong frame_max here!) and
     potentally making the stack and shadow regions external if there is
     no reasonable bound on frame_max. */

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

  /* Internal memory regions */
  /* FIXME: ALIGNMENT */

  ulong          reg   [ FD_VM_REG_CNT         ]; /* registers (FIXME: USAGE) */
  fd_vm_shadow_t shadow[ FD_VM_STACK_FRAME_MAX ]; /* shadow stack, indexed [0,frame_cnt), if frame_cnt>0, 0/frame_cnt-1 is bottom/top */
  uchar          stack [ FD_VM_STACK_MAX       ]; /* stack (FIXME: USAGE) */
  uchar          heap  [ FD_VM_HEAP_MAX        ]; /* sol_alloc_free syscall heap, [0,heap_sz) used, [heap_sz,heap_max) free */
  uchar          log   [ FD_VM_LOG_MAX         ]; /* sol_log_* syscalls log, [0,log_sz) used, [log_sz,FD_VM_LOG_MAX) free */
};

/* FIXME: MOVE ABOVE INTO PRIVATE WHEN CONSTRUCTORS READY */
/**********************************************************************/

FD_PROTOTYPES_BEGIN

/* FIXME: FD_VM_T NEEDS PROPER CONSTRUCTORS */

/* fd_vm_validate validates the sBPF program in the given vm.  Returns
   success or an error code.  Called before executing a sBPF program. */

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
