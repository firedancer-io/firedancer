#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_vm_jit_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_vm_jit_h

/* fd_vm_jit runs sBPF programs as native code produced by the
   transpiler (fd_transpile.h), falling back to the interpreter
   whenever a program cannot be compiled or bails out.

   Code lives in an arena backed by a memfd that is mapped twice when
   the arena is created (before the tile enters its sandbox): once
   read-write, where the compiler writes, and once read-execute, where
   code runs.  No page is ever writable and executable in the same
   mapping, and no memory syscalls are needed afterwards.

   Compiled programs are cached per arena, keyed by everything the
   generated code depends on: the program's bytes (identified by its
   program cache record: fork id, program id, deploy slot, feature slot
   and data address; fork ids are never reused and a record's contents
   never change), its sBPF version and the syscall table it was
   compiled against.  When the arena fills up the whole cache is
   dropped and compilation starts over.  An arena is used by one
   thread only. */

#include "fd_transpile.h"
#include "fd_transpile_runtime.h"

#if FD_HAS_X86 && defined(__linux__)
#define FD_VM_JIT_SUPPORTED 1
#else
#define FD_VM_JIT_SUPPORTED 0
#endif

/* FD_VM_JIT_TEXT_CNT_MAX bounds the programs the JIT compiles (it
   covers the largest program a 10 MiB account can hold); larger
   programs run in the interpreter.  The compile scratch is sized for
   worst case code of FD_VM_JIT_SCRATCH_TEXT_CNT slots (42 MiB).  Real
   programs need about a fifth of that per slot (the largest seen on
   mainnet, 615k slots, uses 20 MiB), so larger programs fit too.  A
   program that doesn't fails to compile and is interpreted. */

#define FD_VM_JIT_TEXT_CNT_MAX     (1UL<<21)
#define FD_VM_JIT_SCRATCH_TEXT_CNT (1UL<<18)

#define FD_VM_JIT_ENTRY_MAX (4096UL)

struct fd_vm_jit_key {
  ulong       xid;
  fd_pubkey_t prog;
  ulong       deploy_slot;
  ulong       feature_slot;
  ulong       data_gaddr;
  ulong       sbpf_version;
  ulong       syscalls_hash;
};

typedef struct fd_vm_jit_key fd_vm_jit_key_t;

struct fd_vm_jit_metrics {
  ulong hit_cnt;
  ulong compile_cnt;
  ulong compile_fail_cnt;
  ulong compile_ticks;
  ulong bail_cnt;
  ulong reset_cnt;
};

typedef struct fd_vm_jit_metrics fd_vm_jit_metrics_t;

struct fd_vm_jit;
typedef struct fd_vm_jit fd_vm_jit_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong fd_vm_jit_align    ( void );
FD_FN_CONST ulong fd_vm_jit_footprint( void );

/* fd_vm_jit_new formats shmem as a JIT with a code arena of arena_sz
   bytes (a multiple of 4 KiB).  Creates the memfd and both mappings,
   so it must run before the sandbox is entered.  Returns shmem on
   success, NULL on failure (logs details). */

void *
fd_vm_jit_new( void * shmem,
               ulong  arena_sz );

fd_vm_jit_t *
fd_vm_jit_join( void * shjit );

/* fd_vm_jit_exec runs vm (initialized with fd_vm_init, trace NULL)
   like fd_vm_exec, using native code for the program identified by
   key when possible.  Results are identical to fd_vm_exec. */

int
fd_vm_jit_exec( fd_vm_jit_t *           jit,
                fd_vm_jit_key_t const * key,
                fd_vm_t *               vm );

/* fd_vm_jit_syscalls_hash returns a hash of the syscall table (keys and
   handlers), which the generated code depends on. */

ulong
fd_vm_jit_syscalls_hash( fd_sbpf_syscalls_t const * syscalls );

fd_vm_jit_metrics_t const *
fd_vm_jit_metrics( fd_vm_jit_t const * jit );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_vm_jit_h */
