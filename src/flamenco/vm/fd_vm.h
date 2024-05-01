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
   within a program. */

struct fd_vm_shadow { ulong r6; ulong r7; ulong r8; ulong r9; ulong pc; };
typedef struct fd_vm_shadow fd_vm_shadow_t;

struct fd_vm {

  /* VM configuration */

  /* FIXME: suspect these three should be replaced by some kind of VM
     enabled feature struct (though syscalls do seem to make additional
     non-trivial use of instr_ctx). */

  fd_exec_instr_ctx_t * instr_ctx;   /* FIXME: DOCUMENT */
  int                   check_align; /* If non-zero, the vm does alignment checks where necessary (syscalls) */
  int                   check_size;  /* If non-zero, the vm does size checks where necessary (syscalls) */

  /* FIXME: frame_max should be run time configurable by compute budget.
     If there is no reasonable upper bound on this, shadow and stack
     will need to be provided by users. */

//ulong frame_max; /* Maximum number of stack frames, in [0,FD_VM_STACK_FRAME_MAX] */
  ulong heap_max;  /* Maximum amount of heap in bytes, in [0,FD_VM_HEAP_MAX] */
  ulong entry_cu;  /* Initial number of compute units for this program, in [0,FD_VM_COMPUTE_UNIT_LIMIT] */

  /* FIXME: The below are practically an exact match to the
     fields of an fd_sbpf_program_t (sans ELF info) */

  uchar const * rodata;    /* Program read only data, indexed [0,rodata_sz), aligned 8 */
  ulong         rodata_sz; /* Program read only data size in bytes, FIXME: BOUNDS? */
  ulong const * text;      /* Program sBPF words, indexed [0,text_cnt), aligned 8 */
  ulong         text_cnt;  /* Program sBPF word count, all text words are inside the rodata */
  ulong         text_off;  /* ==(ulong)text - (ulong)rodata, relocation offset in bytes we must apply to indirect calls
                              (callx/CALL_REGs), IMPORTANT SAFETY TIP!  THIS IS IN BYTES, NOT WORDS! */
  ulong         entry_pc;  /* Initial program counter, in [0,text_cnt)
                              FIXME: MAKE SURE NOT INTO MW INSTRUCTION, MAKE SURE VALID CALLDEST? */
  ulong const * calldests; /* Bit vector of local functions that can be called into, bit indexed in [0,text_cnt) */
  /* FIXME: ADD BIT VECTOR OF FORBIDDEN BRANCH TARGETS (E.G.
     INTO THE MIDDLE OF A MULTIWORD INSTRUCTION) */

  fd_sbpf_syscalls_t const * syscalls; /* The map of syscalls (sharable over multiple concurrently running vm) */

  uchar * input;    /* Program input memory, indexed [0,input_sz) FIXME: ALIGN? */
  ulong   input_sz; /* Program input memory size in bytes, FIXME: BOUNDS? */

  fd_vm_trace_t * trace; /* Location to stream traces (no tracing if NULL) */

  /* VM execution and syscall state */

  /* These are used to communicate the execution and syscall state to
     users and syscalls.  These are initialized based on the above when
     a program starts executing.  When program halts or faults, these
     provide precise execution diagnostics to the user (and potential
     breakpoint/continue functionality in the future).  When the vm
     makes a syscall, the vm will set these precisely and, when a
     syscall returns, the vm will update its internal execution state
     appropriately. */

  /* Note that we try to match syscall log messages with the existing
     Solana validator byte-for-byte (as there are things out there
     scraping log messages from the existing validator) though this is
     not strictly required for consensus. */

  /* IMPORTANT SAFETY TIP!  THE BEHAVIOR OF THE SYSCALL ALLOCATOR FOR
     HEAP_SZ MUST EXACTLY MATCH THE SOLANA VALIDATOR ALLOCATOR:

     https://github.com/solana-labs/solana/blob/v1.17.23/program-runtime/src/invoke_context.rs#L122-L148

     BIT-FOR-BIT AND BUG-FOR-BUG.  SEE THE SYSCALL_ALLOC_FREE FOR MORE
     DETAILS. */

  ulong pc;        /* The current instruction, in [0,text_cnt) in normal execution, may be out of bounds in a fault */
  ulong ic;        /* The number of instructions which have been executed */
  ulong cu;        /* The remaining CUs left for the transaction, positive in normal execution, may be zero in a fault */
  ulong frame_cnt; /* The current number of stack frames pushed, in [0,frame_max] */

  ulong heap_sz; /* Heap size in bytes, in [0,heap_max] */
  ulong log_sz;  /* Log message bytes buffered, [0,FD_VM_LOG_MAX] */

  /* VM memory */

  /* The vm classifies the 64-bit vm address space into 6 regions:

       0 - unmapped lo
       1 - program  -> [FD_VM_MEM_MAP_PROGRAM_REGION_START,FD_VM_MEM_MAP_PROGRAM_REGION_START+4GiB)
       2 - stack    -> [FD_VM_MEM_MAP_STACK_REGION_START,  FD_VM_MEM_MAP_STACK_REGION_START  +4GiB)
       3 - heap     -> [FD_VM_MEM_MAP_HEAP_REGION_START,   FD_VM_MEM_MAP_HEAP_REGION_START   +4GiB)
       4 - input    -> [FD_VM_MEM_MAP_INPUT_REGION_START,  FD_VM_MEM_MAP_INPUT_REGION_START  +4GiB)
       5 - unmapped hi

     These mappings are encoded in a software TLB consisting of three
     6-element arrays: region_haddr, region_ld_sz and region_st_sz.

     region_haddr[i] gives the location in host address space of the
     first byte in region i.  region_{ld,st}_sz[i] gives the number of
     mappable bytes in this region for {loads,stores}.  Note that
     region_{ld,st}_sz[i]<2^32.  Further note that
     [region_haddr[i],region_haddr[i]+region_{ld,st}_sz[i]) does not
     wrap around in host address space and does not overlap with any
     other usages.

     region_{ld,st}_sz[0] and region_{ld,st}_sz[5] are zero such that
     requests to access data from a positive sz range in these regions
     will fail, making regions 0 and 5 unreadable and unwriteable.  As
     such, region_haddr[0] and region_haddr[5] are arbitrary; NULL is
     used as the obvious default.

     region_st_sz[1] is also zero such that requests to store data to
     any positive sz range in this region will fail, making region 1
     unwriteable. */

   /* FIXME: If accessing memory beyond the end of the current heap
      region is not allowed, sol_alloc_free will need to update the tlb
      arrays during program execution (this is trivial).  At the same
      time, given sol_alloc_free is deprecated, this is unlikely to be
      the case. */

  ulong region_haddr[6];
  uint  region_ld_sz[6];
  uint  region_st_sz[6];

  ulong          reg   [ FD_VM_REG_MAX         ]; /* registers, indexed [0,FD_VM_REG_CNT).  Note that FD_VM_REG_MAX>FD_VM_REG_CNT.
                                                     As such, malformed instructions, which can have src/dst reg index in
                                                     [0,FD_VM_REG_MAX), cannot access info outside reg.  Aligned 8. */
  fd_vm_shadow_t shadow[ FD_VM_STACK_FRAME_MAX ]; /* shadow stack, indexed [0,frame_cnt), if frame_cnt>0, 0/frame_cnt-1 is
                                                     bottom/top.  Aligned 8. */
  uchar          stack [ FD_VM_STACK_MAX       ]; /* stack, indexed [0,FD_VM_STACK_MAX).  Divided into FD_VM_STACK_FRAME_MAX
                                                     frames.  Each frame has a FD_VM_STACK_GUARD_SZ region followed by a
                                                     FD_VM_STACK_FRAME_SZ region.  reg[10] gives the offset of the start of the
                                                     current stack frame.  Aligned 8. */
  uchar          heap  [ FD_VM_HEAP_MAX        ]; /* syscall heap, [0,heap_sz) used, [heap_sz,heap_max) free.  Aligned 8. */
  uchar          log   [ FD_VM_LOG_MAX + FD_VM_LOG_TAIL ]; /* syscall log, [0,log_sz) used, [log_sz,FD_VM_LOG_MAX) free.
                                                              Aligned 8.  Includes a tail region large enough so various string
                                                              operations can clobber to simplify a lot of string parsing code. */

   fd_sha256_t * sha; /* Pre-joined SHA instance. This should be re-initialised before every use. */

   ulong magic;    /* ==FD_VM_MAGIC */
};

/* FIXME: MOVE ABOVE INTO PRIVATE WHEN CONSTRUCTORS READY */
/**********************************************************************/

FD_PROTOTYPES_BEGIN

/* FIXME: FD_VM_T NEEDS PROPER CONSTRUCTORS */

/* FD_VM_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a fd_vm_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align. These are provided to facilitate compile time declarations. */
#define FD_VM_ALIGN     (8UL)
#define FD_VM_FOOTPRINT (799528UL)

/* fd_vm_{align,footprint} give the needed alignment and footprint
   of a memory region suitable to hold an fd_vm_t.
   Declaration / aligned_alloc / fd_alloca friendly (e.g. a memory
   region declared as "fd_vm_t _vm[1];", or created by
   "aligned_alloc(alignof(fd_vm_t),sizeof(fd_vm_t))" or created
   by "fd_alloca(alignof(fd_vm_t),sizeof(fd_vm_t))" will all
   automatically have the needed alignment and footprint).
   fd_vm_{align,footprint} return the same value as
   FD_VM_{ALIGN,FOOTPRINT}. */
FD_FN_CONST ulong
fd_vm_align( void );

FD_FN_CONST ulong
fd_vm_footprint( void );

#define FD_VM_MAGIC (0xF17EDA2CEF0) /* FIREDANCE SBPF V0 */

/* fd_vm_new formats memory region with suitable alignment and
   footprint suitable for holding a fd_vm_t.  Assumes
   shmem points on the caller to the first byte of the memory region
   owned by the caller to use.  Returns shmem on success and NULL on
   failure (logs details).  The memory region will be owned by the state
   on successful return.  The caller is not joined on return. */

void *
fd_vm_new( void * shmem );

/* fd_vm_join joins the caller to a vm.
   Assumes shmem points to the first byte of the memory region holding
   the vm.  Returns a local handle to the join on success (this is
   not necessarily a simple cast of the address) and NULL on failure
   (logs details). */
fd_vm_t *
fd_vm_join( void * shmem );

/* fd_vm_init initializes the given fd_vm_t struct, checking that it is
   not null and has the correct magic value.

   It modifies the vm object and also returns the object for convenience. */
fd_vm_t *
fd_vm_init(
   fd_vm_t * vm,
   fd_exec_instr_ctx_t *instr_ctx,
   ulong heap_max,
   ulong entry_cu,
   uchar const * rodata,
   ulong rodata_sz,
   ulong const * text,
   ulong text_cnt,
   ulong text_off,
   ulong entry_pc,
   ulong * calldests,
   fd_sbpf_syscalls_t * syscalls,
   uchar * input,
   ulong input_sz,
   fd_vm_trace_t * trace,
   fd_sha256_t * sha );

/* fd_vm_leave leaves the caller's current local join to a vm.
   Returns a pointer to the memory region holding the vm on success
   (this is not necessarily a simple cast of the
   address) and NULL on failure (logs details).  The caller is not
   joined on successful return. */
void *
fd_vm_leave( fd_vm_t * vm );

/* fd_vm_delete unformats a memory region that holds a vm.
   Assumes shmem points on the caller to the first
   byte of the memory region holding the state and that nobody is
   joined.  Returns a pointer to the memory region on success and NULL
   on failure (logs details).  The caller has ownership of the memory
   region on successful return. */
void *
fd_vm_delete( void * shmem );

/* fd_vm_validate validates the sBPF program in the given vm.  Returns
   success or an error code.  Called before executing a sBPF program.
   FIXME: DOCUMENT BETTER */

FD_FN_PURE int
fd_vm_validate( fd_vm_t const * vm );

/* FIXME: make this trace-aware, and move into fd_vm_init
   This is a temporary hack to make the fuzz harness work. */
int
fd_vm_setup_state_for_execution( fd_vm_t * vm ) ;

/* fd_vm_exec runs vm from program start to program halt or program
   fault, appending an execution trace if vm is attached to a trace.

   Since this is running from program start, this will init r1 and r10,
   pop all stack frames, free all heap allocations and flush out all
   buffered log messages.

   IMPORTANT SAFETY TIP!  This currently does not zero out any other
   registers, the user stack region or the user heap.  (FIXME: SHOULD
   IT??)

   Returns FD_VM_SUCCESS (0) on success and an FD_VM_ERR code (negative)
   on failure.  Reasons for failure include:

     INVAL     - NULL vm (or, for fd_vm_exec_trace, the vm is not
                 attached to trace).  FIXME: ADD OTHER INPUT ARG CHECKS?

     SIGTEXT   - A jump/call set the program counter outside the text
                 region or the program counter incremented beyond the
                 text region.  pc will be at the out of bounds location.
                 ic and cu will not include the out of bounds location.
                 For a call, the call stack frame was allocated.

     SIGSPLIT  - A jump/call set the program counter into the middle of
                 a multiword instruction or a multiword instruction went
                 past the text region end.  pc will be at the split.  ic
                 and cu will not include the split.  For a call, the
                 call stack frame was allocated.

     SIGCALL   - A call set the program counter to a non-function
                 location.  pc will be at the non-function location.  ic
                 and cu will include the call but not include the
                 non-function location.  The call stack frame was
                 allocated.

     SIGSTACK  - The call depth limit was exceeded.  pc will be at the
                 call.  ic and cu will include the call but not the call
                 target.  The call stack frame was not allocated.

     SIGILL    - An invalid instruction was encountered (including an
                 invalid opcode and an endian swap with an invalid bit
                 width).  pc will be at the invalid instruction.  ic and
                 cu will not include the invalid instruction.

     SIGSEGV   - An invalid memory access (outside the program memory
                 map) was encountered.  pc will be at the faulting
                 instruction.  ic and cu will not include the faulting
                 instruction.

     SIGBUS    - An unaligned memory access was encountered.  pc will be
                 at the faulting instruction.  ic and cu will not
                 include the faulting instruction.  (Note: currently
                 mapped to SIGSEGV and then only if check_align is
                 enabled.)

     SIGRDONLY - A write to read-only memory address was encountered.
                 pc will be at the faulting instruction.  ic and cu will
                 not include the faulting instruction.  (Note: currently
                 mapped to SIGSEGV.)

     SIGCOST   - The compute limit was exceeded.  pc will be at the
                 first non-executed instruction (if pc is a syscall, the
                 syscall might have been partially executed when it ran
                 out of budget .. see safety tip below).  ic will cover
                 all executed instructions.  cu will be zero.

   This will considers any error returned by a syscall as a fault and
   returns the syscall error code here.  See syscall documentation for
   details here.  When a syscall faults, pc will be at the syscall, ic
   will include the syscall and cu will include the syscall and any
   additional costs the syscall might have incurred up to that point of
   the fault.

   IMPORTANT SAFETY TIP!  Ideally, a syscall should only modify vm's
   state when it knows its overall syscall will be successful.
   Unfortunately, this is often not practical (e.g. a syscall starts
   processing a list of user provided commands and discovers an error
   condition late in the command list that did not exist at syscall
   start because the error condition was created by successfully
   executed commands earlier in the list).  As such, vm's state on a
   faulting syscall may not be clean.

   FIXME: SINCE MOST SYSCALLS CAN BE IMPLEMENTED TO HAVE CLEAN FAULTING
   BEHAVIOR, PROVIDE A MECHANISM SO USERS CAN EASILY DETECT UNCLEAN
   SYSCALL FAULTS?

   For SIGCOST, note that the vm can speculate ahead when processing
   instructions.  This makes it is possible to have a situation where
   a vm faults with, for example, SIGSEGV from a speculatively
   executed memory access while a non-speculative execution would have
   faulted with SIGCOST on an earlier instruction.  In these situations,
   pc will be at the faulting speculatively executed instruction, ic
   will include all the speculatively executed instructions, cu will be
   zero and vm's state will include the impact of all the speculation.

   IMPORTANT SAFETY TIP!  While different vm implementations can
   disagree on why a program faulted (e.g. SIGCOST versus SIGSEGV in the
   example above), they cannot disagree on whether or not a program
   faulted.  As a result, the specific fault reason must never be
   allowed to be part of consensus.

   fd_vm_exec_trace runs with tracing and requires vm to be attached to
   a trace.  fd_vm_exec_notrace runs without without tracing even if vm
   is attached to a trace. */

int
fd_vm_exec_trace( fd_vm_t * vm );

int
fd_vm_exec_notrace( fd_vm_t * vm );

static inline int
fd_vm_exec( fd_vm_t * vm ) {
  if( FD_UNLIKELY( vm->trace ) ) return fd_vm_exec_trace  ( vm );
  else                           return fd_vm_exec_notrace( vm );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_h */
