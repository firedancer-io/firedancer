#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_h

/* fd_transpile.h provides low-level APIs to transpile sBPF v0, v1, and
   v3 programs to x86.  (See fd_transpile_obj.h for a friendly wrapper.) */

#include "../../../ballet/elf/fd_elf64.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"

/* fd_vm_transpile_dasm_t is a DynASM session (the Dst argument of the
   dasm_* functions).  All of its memory is bump allocated from a
   caller-provided scratch region, so transpiling never calls malloc
   and fails gracefully when scratch runs out. */

typedef struct fd_vm_transpile_dasm fd_vm_transpile_dasm_t;

#define Dst_DECL fd_vm_transpile_dasm_t * Dst
#define Dst_REF  (Dst->D)
#include "../../../third_party/luajit/dasm_proto.h"

struct fd_vm_transpile_dasm {
  dasm_State * D;
  uchar *      mem;      /* scratch region */
  ulong        mem_sz;
  ulong        mem_used; /* scratch bytes used */
  void *       fail;     /* private */
};

/* fd_vm_transpile_code return codes */

#define FD_VM_TRANSPILE_SUCCESS   ( 0)
#define FD_VM_TRANSPILE_ERR_INVAL (-1) /* invalid or unsupported program */
#define FD_VM_TRANSPILE_ERR_NOMEM (-2) /* out of scratch or reloc space */

/* FD_VM_TRANSPILE_RELOC_MAX bounds the number of relocations of a
   transpiled program: one per syscall thunk plus a few for the runtime
   helpers. */

#define FD_VM_TRANSPILE_RELOC_MAX (FD_SBPF_SYSCALLS_SLOT_CNT+16UL)

/* FD_VM_TRANSPILE_SYM_* give ELF symbol IDs for use in relocations. */

#define FD_VM_TRANSPILE_SYM_MMU_TRANSLATE 1 /* fd_vm_transpiled_mmu_translate */
#define FD_VM_TRANSPILE_SYM_FRAME_INIT    2 /* fd_vm_transpiled_frame_init */
#define FD_VM_TRANSPILE_SYM_BB_BITMAP     3 /* bitmap of basic block starts */
#define FD_VM_TRANSPILE_SYM_BB_SEQ        4 /* bitmap popcnt() left sum, 64-bit blocks */
#define FD_VM_TRANSPILE_SYM_BB_JMP        5 /* jump table of basic block starts */
#define FD_VM_TRANSPILE_SYM_MAX           6

/* FD_VM_TRANSPILE_DASM_LBL_RELOC0 gives the first DynASM PC label index
   used for relocations.  The label just before it marks the end of the
   translated instruction stream (code past it holds the runtime helper
   subroutines). */

#define FD_VM_TRANSPILE_DASM_LBL_RELOC0( bpf_text_cnt ) ( 2UL*(bpf_text_cnt) + (ulong)FD_SBPF_SYSCALLS_SLOT_CNT + 1UL )

FD_PROTOTYPES_BEGIN

/* fd_vm_transpile_bb_splits recovers the basic block starts of prog
   for use as fd_vm_transpile_code's bpf_bb_splits.  bpf_bb_splits
   points to a bit vector of ceil(text_cnt/64) words, which is fully
   overwritten.  Marks the entrypoint, calldests, internal call
   targets, branch targets, and instructions following a branch or
   exit. */

void
fd_vm_transpile_bb_splits( ulong *                   bpf_bb_splits,
                           fd_sbpf_program_t const * prog );

/* fd_vm_transpile_scratch_footprint returns an upper bound on the
   scratch memory fd_vm_transpile_code needs for a program with
   bpf_text_cnt instruction slots: 168 bytes per slot (40 DynASM action
   buffer ints and 2 PC labels) plus about 22 KiB (runtime helpers and
   syscall thunks), with the action buffer part capped at 64 MiB.
   Programs that need a larger action buffer fail with
   FD_VM_TRANSPILE_ERR_NOMEM regardless of scratch size. */

FD_FN_CONST ulong
fd_vm_transpile_scratch_footprint( ulong bpf_text_cnt );

/* fd_vm_transpile_code emits position-independent x86_64 code from sBPF
   text.  Addressing is like `-mcmodel=small`.

   dasm is initialized to a LuaJIT DynASM session backed by the
   scratch_sz bytes at scratch (any alignment).  On success, the caller
   finishes it with dasm_link, dasm_encode and dasm_getpclabel while
   scratch is still valid (on failure, dasm is invalid).  There is
   nothing to free (the caller owns scratch).  fd_vm_transpile_scratch_footprint( bpf_text_cnt ) bytes
   of scratch always suffice.

   sbpf_version is the sBPF version of the program (FD_SBPF_V*).
   bpf_text points to eBPF instructions (indexed with 8-byte stride).
   bpf_text_cnt is the number of 8-byte eBPF instruction slots.
   bpf_entry_pc is the instruction slot index of the entrypoint.
   bpf_calldests are valid CALL_IMM destinations (consensus defined).
   syscalls is the syscall table; CALL_IMM to a registered hash emits a
   call to that handler.  The symbol ID of a syscall handler is
   FD_VM_TRANSPILE_SYM_MAX plus its slot index in syscalls.
   bpf_bb_splits is a bit vector indicating which instruction slots mark
   the start of a basic block (implementation defined).
   bpf_func_starts, if non-NULL, points to a bit vector of
   ceil(bpf_text_cnt/64) words which is fully overwritten with the
   instruction slots that start an sBPF function (the entrypoint and
   every BPF-to-BPF call destination reached via a direct call).
   reloc is populated with ELF relocation entries.  On entry, *reloc_cnt
   is the capacity of reloc (FD_VM_TRANSPILE_RELOC_MAX suffices).  On
   success, *reloc_cnt is set to the number of relocations.  The symbol IDs in reloc[i] are either
   - in [0,FD_VM_TRANSPILE_SYM_MAX) for fd_transpile_runtime symbols
   - a syscall Murmur3 hash ID for syscall handlers

   Returns FD_VM_TRANSPILE_SUCCESS on success, or on failure (logs
   reason) FD_VM_TRANSPILE_ERR_INVAL if the program cannot be
   transpiled, or FD_VM_TRANSPILE_ERR_NOMEM if scratch or reloc ran
   out.  Never allocates from the heap. */

int
fd_vm_transpile_code( fd_vm_transpile_dasm_t *   dasm,
                      void *                     scratch,
                      ulong                      scratch_sz,
                      ulong                      sbpf_version,
                      uchar const *              bpf_text,
                      ulong                      bpf_text_cnt,
                      ulong                      bpf_entry_pc,
                      ulong const *              bpf_calldests,
                      fd_sbpf_syscalls_t const * syscalls,
                      ulong const *              bpf_bb_splits,
                      ulong *                    bpf_func_starts,
                      fd_elf64_rela *            reloc,
                      ulong *                    reloc_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_h */
