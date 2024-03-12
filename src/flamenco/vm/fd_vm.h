#ifndef HEADER_fd_src_flamenco_vm_fd_vm_h
#define HEADER_fd_src_flamenco_vm_fd_vm_h

#include "fd_vm_cpi.h"

/* The sBPF execution context. This is the primary data structure that
   is evolved before, during and after contract execution. */

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

/* fd_vm_stack API ****************************************************/

/* FIXME: CONSIDER HANDLING THE REG AND STACK IN HERE TOO */

/* fd_vm_stack_empty/full returns 1 if the stack is empty/full and 0 if
   not.  Assumes vm is valid. */

FD_FN_PURE static inline int fd_vm_stack_is_empty( fd_vm_t const * vm ) { return !vm->frame_cnt;                       }
FD_FN_PURE static inline int fd_vm_stack_is_full ( fd_vm_t const * vm ) { return vm->frame_cnt==FD_VM_STACK_FRAME_MAX; }

/* FIXME: consider zero copy API and/or failure free API? */

/* fd_vm_stack_reset pops all frames off the stack.  Assumes vm is
   valid.  Returns FD_VM_SUCCESS (0). */

static inline int
fd_vm_stack_reset( fd_vm_t * vm ) {
  vm->frame_cnt = 0UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_stack_push pushes a new frame onto the VM stack.  Assumes vm,
   rip and reg is valid.  Returns FD_VM_SUCCESS (0) on success or
   FD_VM_ERR_FULL (negative) on failure. */

static inline int
fd_vm_stack_push( fd_vm_t *   vm,
                  ulong       rip,
                  ulong const reg[ FD_VM_SHADOW_REG_CNT ] ) {
  ulong frame_idx = vm->frame_cnt;
  if( FD_UNLIKELY( frame_idx>=FD_VM_STACK_FRAME_MAX ) ) return FD_VM_ERR_FULL;
  fd_vm_shadow_t * shadow = vm->shadow + frame_idx;
  shadow->rip = rip;
  memcpy( shadow->reg, reg, FD_VM_SHADOW_REG_CNT*sizeof(ulong) );
  vm->frame_cnt = frame_idx + 1UL;
  return FD_VM_SUCCESS;
}

/* fd_vm_stack_pop pops a frame off the VM stack.  Assumes vm, _rip and
   reg are valid.  Returns FD_VM_SUCCESS (0) on success and
   FD_VM_ERR_EMPTY (negative) on failure.  On success, *_rip and reg[*]
   hold the values popped off the stack on return.  These are unchanged
   otherwise. */

static inline int
fd_vm_stack_pop( fd_vm_t * vm,
                 ulong *   _rip,
                 ulong     reg[ FD_VM_SHADOW_REG_CNT ] ) {
  ulong frame_idx = vm->frame_cnt;
  if( FD_UNLIKELY( !frame_idx ) ) return FD_VM_ERR_EMPTY;
  frame_idx--;
  fd_vm_shadow_t * shadow = vm->shadow + frame_idx;
  *_rip = shadow->rip;
  memcpy( reg, shadow->reg, FD_VM_SHADOW_REG_CNT*sizeof(ulong) );
  vm->frame_cnt = frame_idx;
  return FD_VM_SUCCESS;
}

/* FIXME: Consider a fd_vm_heap API here */

/* fd_vm_log API ******************************************************/

/* fd_vm_log returns the location where VM log messages are appended
   (will be non-NULL and aligned 8).  fd_vm_log_{max,sz,rem} return how
   the VM log message buffer is currently utilized.  max will be
   FD_VM_LOG_MAX (positive multiple of 8) and sz will be in [0,max].
   Bytes [0,sz) are currently buffered log bytes and [sz,max) are bytes
   available for additional buffering.  rem = max-sz is the number of
   bytes available for logging.  These assume vm is valid. */

FD_FN_CONST static inline uchar const * fd_vm_log    ( fd_vm_t const * vm ) { return vm->log;                    }
FD_FN_CONST static inline ulong         fd_vm_log_max( fd_vm_t const * vm ) { (void)vm; return FD_VM_LOG_MAX;    }
FD_FN_PURE  static inline ulong         fd_vm_log_sz ( fd_vm_t const * vm ) { return vm->log_sz;                 }
FD_FN_PURE  static inline ulong         fd_vm_log_rem( fd_vm_t const * vm ) { return FD_VM_LOG_MAX - vm->log_sz; }

/* fd_vm_log_prepare cancels any message currently in preparation and
   starts zero-copy preparation of a new VM log message.  There are
   fd_vm_log_rem bytes available at the returned location.  IMPORTANT
   SAFETY TIP!  THIS COULD BE ZERO IF THE VM LOG BUFFER IS FULL.
   The lifetime of the returned location is until the prepare is
   published or canceled or the VM is destroyed.  The caller is free to
   clobber any bytes in this region while it is preparing the message.

   fd_vm_log_publish appends the first sz bytes of the prepare region to
   the VM log.  Assumes vm is valid with a message in preparation and sz
   is in [0,rem].  Returns vm.  There is no message in preparation on
   return.

   fd_vm_log_cancel stops preparing a message in preparation without
   publishing it.  Returns vm.  There is no message in preparation on
   return.

   These assume vm valid. */

FD_FN_PURE  static inline void *    fd_vm_log_prepare( fd_vm_t * vm           ) { return vm->log + vm->log_sz; }
/**/        static inline fd_vm_t * fd_vm_log_publish( fd_vm_t * vm, ulong sz ) { vm->log_sz += sz; return vm; }
FD_FN_CONST static inline fd_vm_t * fd_vm_log_cancel ( fd_vm_t * vm           ) { return vm;                   }

/* fd_vm_log_reset resets the VM's log to empty and cancels any messages
   in preparation.  Assumes vm is valid. */

static inline fd_vm_t * fd_vm_log_reset( fd_vm_t * vm ) { vm->log_sz = 0UL; return vm; }

/* fd_vm_log_append cancels any VM log message in preparation and
   appends a message of sz bytes to the VM's log, truncating as
   necessary.  Assumes vm is valid, msg and sz are valid.  sz 0 is fine.
   Returns fd_vm_t. */

static inline fd_vm_t *
fd_vm_log_append( fd_vm_t *    vm,
                  void const * msg,
                  ulong        sz ) {
  ulong log_sz = vm->log_sz;
  ulong cpy_sz = fd_ulong_min( sz, FD_VM_LOG_MAX - log_sz );
  if( FD_LIKELY( cpy_sz ) ) memcpy( vm->log + log_sz, msg, cpy_sz ); /* Sigh ... branchless if sz==0 wasn't UB */
  vm->log_sz = log_sz + cpy_sz;
  return vm;
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
