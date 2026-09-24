#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_h

/* fd_transpile.h provides low-level APIs to transpile sBPF v0, v1, and
   v3 programs to x86.  (See fd_transpile_obj.h for a friendly wrapper.) */

#include "../../../ballet/elf/fd_elf64.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"
#include "../../../ballet/sbpf/fd_sbpf_loader.h"
#include "fd_transpile_runtime.h"

/* FD_TRANSPILE_ABI_VERSION is incremented anytime anything in this ABI
   changes.  (e.g. transpile_obj, transpile_runtime, or fd_vm) */

#define FD_TRANSPILE_ABI_VERSION (1UL)

/* FD_VM_TRANSPILE_SYM_* give ELF symbol IDs for use in relocations. */

#define FD_VM_TRANSPILE_SYM_MMU_TRANSLATE 1 /* fd_vm_transpiled_mmu_translate */
#define FD_VM_TRANSPILE_SYM_FRAME_INIT    2 /* fd_vm_transpiled_frame_init */
#define FD_VM_TRANSPILE_SYM_TEXT          3 /* start of transpiler->code */
#define FD_VM_TRANSPILE_SYM_RODATA        4 /* start of transpiler->rodata */
#define FD_VM_TRANSPILE_SYM_MAX           5

/* FD_VM_TRANSPILE_DASM_LBL_RELOC0 gives the first DynASM PC label index
   used for relocations.  The label just before it marks the end of the
   translated instruction stream (code past it holds the runtime helper
   subroutines). */

#define FD_VM_TRANSPILE_DASM_LBL_RELOC0( bpf_text_cnt ) ( 2UL*(bpf_text_cnt) + (ulong)FD_SBPF_SYSCALLS_SLOT_CNT + 1UL )

/* DynASM state management

   The DynASM state is pre-allocated with fixed size in a scratch buffer
   and never changes.  malloc() is yucky, realloc() is insane, and it is
   regrettable that DynASM assumes it is available.  We begrudingly
   resort to working around alloc errors through exceptions (longjmp()). */

#define FD_DASM_POS_MAX            (1UL<<23)
#define FD_DASM_LGLABELS_MAX       (1UL<<18)
#define FD_DASM_GLOB_MAX           (1UL<<16)
#define FD_TRANSPILER_RELOC_MAX    (1UL<<18)
#define FD_TRANSPILER_CODE_MAX     (1UL<<24)
#define FD_TRANSPILER_TEXT_CNT_MAX (1UL<<19)
#define FD_DASM_PCLABELS_MAX       (1UL<<21)
#define FD_TRANSPILER_BB_MAX       (1UL<<19)
#define FD_TRANSPILER_RODATA_MAX   (1UL<<22)
#define FD_TRANSPILER_SYM_MAX      (1UL<<19)

/* fd_transpiler_sym_t names a code range for debuggers and
   disassemblers (exported as a local ELF function symbol).  kind is
   FD_TRANSPILER_SYM_KIND_*, and arg is the sBPF pc for FUNC and THUNK,
   the syscall slot index for SYSCALL, and the fd_xlat_ global label
   index for HELPER. */

#define FD_TRANSPILER_SYM_KIND_FUNC    (0) /* sBPF function (call destination or entrypoint) */
#define FD_TRANSPILER_SYM_KIND_THUNK   (1) /* frame push stub in front of an sBPF function */
#define FD_TRANSPILER_SYM_KIND_SYSCALL (2) /* FFI stub around a syscall handler */
#define FD_TRANSPILER_SYM_KIND_HELPER  (3) /* shared runtime routine */

struct fd_transpiler_sym {
  uint  off;  /* byte offset in code[] */
  uint  sz;   /* byte size, may be 0 if unknown */
  uint  arg;
  uchar kind;
};

typedef struct fd_transpiler_sym fd_transpiler_sym_t;

/* fd_transpiler_t holds all internal state needed to translate an
   sBPF program.  (Large struct, do not stack declare) */

struct fd_transpiler {
  ulong bpf_text_cnt;
  ulong bb_cnt;           /* basic block count */
  ulong reloc_cnt;        /* reloc[] population count */
  ulong rodata_reloc_cnt; /* rodata_reloc[] population count */
  ulong code_sz;          /* size of code[] */
  ulong rodata_sz;        /* size of rodata[] */
  ulong entrypoint_off;   /* exec function offset in code[] */
  ulong sym_cnt;          /* sym[] population count */

  /* DynASM dynamic labels enumerate as follows:
     - [0,dasm_lbl_thunk0)              bpf_text_cnt labels, one for each BPF instruction
     - [dasm_lbl_thunk0,dasm_lbl_sys0)  thunk_cnt labels, one for each BPF direct call destination
     - [dasm_lbl_sys0,fd_lbl_reloc0)    one label for each syscall thunk (not all used)
     - [dasm_lbl_reloc0,dasm_lbl_max)   relocation site labels, one for each `call rel32` x86 instruction */
  ulong dasm_lbl_thunk0;
  ulong dasm_lbl_sys0;
  ulong dasm_lbl_reloc0;
  ulong dasm_lbl_max;

  fd_transpile_meta_t meta;

  __attribute__((aligned(64))) uchar state_[ 256 ]; /* dasm_State with one section */
  struct dasm_State * state;

  int    lglabels[ FD_DASM_LGLABELS_MAX    ];
  int    pclabels[ FD_DASM_PCLABELS_MAX    ];
  ulong  thunk_bv[ FD_SBPF_TEXT_CNT_MAX>>6 ]; /* bit vector indicating which BPF offsets need call thunks */
  void * glob    [ FD_DASM_GLOB_MAX        ];

  __attribute__((aligned(64)))
  int code_bits[ FD_DASM_POS_MAX ];

  uchar code[ FD_TRANSPILER_CODE_MAX ]; /* relocatable x86 code */

  /* rodata layout (see emit_callx_handler):
       bb_bitmap ulong[ ceil(bpf_text_cnt/64) ]  basic block starts
       bb_seq    ulong[ ceil(bpf_text_cnt/64) ]  popcnt of bb_bitmap left of each word
       bb_jmp    int  [ bb_cnt ]                 x86 offset of each basic block relative to bb_jmp */
  __attribute__((aligned(8)))
  uchar rodata[ FD_TRANSPILER_RODATA_MAX ];

  fd_elf64_rela reloc       [ FD_TRANSPILER_RELOC_MAX ]; /* against code[] */
  fd_elf64_rela rodata_reloc[ FD_TRANSPILER_BB_MAX    ]; /* against rodata[] */

  fd_transpiler_sym_t sym[ FD_TRANSPILER_SYM_MAX ]; /* sorted by off */
};

typedef struct fd_transpiler fd_transpiler_t;

FD_PROTOTYPES_BEGIN

/* fd_vm_transpile_code emits position-independent x86_64 code from sBPF
   text.  Addressing is like `-mcmodel=small`.

   transpiler is an uninitialized buffer.
   sbpf_version is the sBPF version of the program (FD_SBPF_V*).
   bpf_text points to eBPF instructions (indexed with 8-byte stride).
   bpf_text_cnt is the number of 8-byte eBPF instruction slots.
   bpf_entry_pc is the instruction slot index of the entrypoint.
   bpf_calldests are valid CALL_IMM destinations (consensus defined).
   syscalls is the syscall table; CALL_IMM to a registered hash emits a
   call to that handler.  The symbol ID of a syscall handler is
   FD_VM_TRANSPILE_SYM_MAX plus its slot index in syscalls.

   Returns 0 on success, or -1 on failure (logs reason).

   On success:
   - transpiler->code contains the relocatable machine code
   - transpiler->code_sz contains the machine code size in bytes
   - transpiler->entrypoint_off contains the byte offset of the exec function in code
   - transpiler->rodata contains read-only tables referenced by code
   - transpiler->rodata_sz contains the size of these tables in bytes
   - transpiler->reloc contains reloc_cnt ELF relocation entries against
     code.  The symbol IDs are either
     - in [0,FD_VM_TRANSPILE_SYM_MAX) for FD_VM_TRANSPILE_SYM_*
     - FD_VM_TRANSPILE_SYM_MAX plus a syscall slot index
     r_offset is the byte offset of the rel32 field in code.
   - transpiler->rodata_reloc contains rodata_reloc_cnt ELF relocation
     entries against rodata, all PC32 against FD_VM_TRANSPILE_SYM_TEXT
   - transpiler->thunk_bv is a bit vector of the instruction slots that
     are BPF-to-BPF call destinations reached via a direct call
   - transpiler->sym contains sym_cnt code range names sorted by
     offset (see fd_transpiler_sym_t), truncated at FD_TRANSPILER_SYM_MAX
   - transpiler->meta contains program metadata (text_cnt, text_sz,
     entry_pc, sbpf_version).  meta.prog_id and meta.elf_hash are
     left for the caller to set. */

struct dasm_State;

/* bpf_rodata/bpf_rodata_sz is the loaded (relocated) program image and
   bpf_text_off the byte offset of the text section within it; they are used to find
   address-taken functions.  rodata may be NULL. */

int
fd_vm_transpile_code( fd_transpiler_t *          transpiler,
                      ulong                      sbpf_version,
                      uchar const *              bpf_text,
                      ulong                      bpf_text_cnt,
                      ulong                      bpf_entry_pc,
                      ulong const *              bpf_calldests,
                      fd_sbpf_syscalls_t const * syscalls,
                      uchar const *              bpf_rodata,
                      ulong                      bpf_rodata_sz,
                      ulong                      bpf_text_off );

/* fd_transpiler_helper_name returns the label name of a
   FD_TRANSPILER_SYM_KIND_HELPER symbol (e.g. "mmu_translate_ld_8"), or
   NULL if idx is out of range. */

char const *
fd_transpiler_helper_name( ulong idx );

static inline int
fd_vm_transpile_prog( fd_transpiler_t *          transpiler,
                      fd_sbpf_program_t const *  prog,
                      fd_sbpf_syscalls_t const * syscalls ) {
  return fd_vm_transpile_code(
      transpiler,
      prog->info.sbpf_version,
      (uchar const *)prog->text,
      prog->info.text_cnt,
      prog->entry_pc,
      prog->calldests,
      syscalls,
      (uchar const *)prog->rodata,
      prog->rodata_sz,
      prog->info.text_off
  );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_h */
