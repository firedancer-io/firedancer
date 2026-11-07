#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_jit_proto_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_jit_proto_h

/* fd_jit_proto.h is the wire format between exec tiles, the jit tile
   and the jitmap tile.

     exec --exec_jit-->  jit --jit_jitmap--> jitmap --(progcache rec)--> exec

   An exec tile that loads a program the AOT archive does not cover
   sends its verified image to the jit tile.  The jit tile transpiles it
   and hands code, rodata and relocations to jitmap.  jitmap places the
   program in the JIT arena, resolves relocations, and binds the
   progcache record.  Exec tiles never see jit's output directly.

   Both links are unreliable: an overrun drops the request and the
   program stays on the interpreter.  Frags are larger than the 16 bit
   mcache size field allows, so frags are published with sz 0 and each
   header states its own length. */

#include "fd_transpile_runtime.h"
#include "../../../ballet/elf/fd_elf64.h"
#include "../../features/fd_features.h"
#include "../../progcache/fd_progcache_rec.h"

/* fd_jit_req_t heads an exec_jit frag.  It is followed in the same
   frag by val_sz bytes: the progcache value slot (calldests + loaded
   rodata image) exactly as fd_progcache_rec_load produced it.  The
   rec header fields let jit rebuild an fd_sbpf_program_t view and let
   jitmap recheck the record still describes this revision. */

struct __attribute__((aligned(64))) fd_jit_req {
  fd_progcache_rec_key_t key;          /* (xid, prog) */
  ulong                  feature_slot;
  ulong                  deploy_slot;
  uint                   rec_idx;      /* index into the progcache record array */
  uint                   data_max;
  uint                   entry_pc;
  uint                   text_cnt;
  uint                   text_off;
  uint                   text_sz;
  uint                   rodata_sz;
  uint                   calldests_off;
  uint                   rodata_off;
  uint                   sbpf_version;
  uint                   val_sz;       /* bytes of value slot that follow */
  uint                   src_tile;     /* exec tile index, for logs */
  fd_features_t          features;
};

typedef struct fd_jit_req fd_jit_req_t;

#define FD_JIT_REQ_MTU ( sizeof(fd_jit_req_t) + FD_RUNTIME_ACC_SZ_MAX + 2UL*(1UL<<20) )

/* fd_jit_res_t heads a jit_jitmap frag.  Variable parts follow in this
   order, each 8 byte aligned: code[code_sz], rodata[rodata_sz],
   reloc[reloc_cnt], rodata_reloc[rodata_reloc_cnt].  Syscall relocs
   name fd_sbpf_syscalls slots (FD_VM_TRANSPILE_SYM_MAX+slot); jitmap
   resolves them through the vm's own syscall table at run time, so the
   jit tile needs no host function addresses. */

struct __attribute__((aligned(64))) fd_jit_res {
  fd_progcache_rec_key_t key;
  ulong                  feature_slot;
  ulong                  deploy_slot;
  uint                   rec_idx;
  uint                   src_tile;
  ulong                  code_sz;
  ulong                  rodata_sz;
  ulong                  reloc_cnt;
  ulong                  rodata_reloc_cnt;
  ulong                  entrypoint_off;
  fd_transpile_meta_t    meta;
  fd_features_t          features;     /* lets jitmap rebuild the syscall table and check every slot a reloc names */
};

typedef struct fd_jit_res fd_jit_res_t;

/* Bounds a jit_jitmap frag.  Real programs stay far below the
   transpiler's internal maxima; this caps the dcache without wasting
   the full 16 MiB code buffer per slot. */

#define FD_JIT_RES_CODE_MAX         (1UL<<23)
#define FD_JIT_RES_RODATA_MAX       (1UL<<21)
#define FD_JIT_RES_RELOC_MAX        (1UL<<16) /* calls out of code: one per syscall/helper site */
#define FD_JIT_RES_RODATA_RELOC_MAX (1UL<<18) /* callx table: one per basic block */
#define FD_JIT_RES_MTU ( sizeof(fd_jit_res_t) + FD_JIT_RES_CODE_MAX + FD_JIT_RES_RODATA_MAX + \
                         ( FD_JIT_RES_RELOC_MAX + FD_JIT_RES_RODATA_RELOC_MAX )*sizeof(fd_elf64_rela) + 64UL )

static inline ulong
fd_jit_res_layout( fd_jit_res_t const * res,
                   ulong *              code_off,
                   ulong *              rodata_off,
                   ulong *              reloc_off,
                   ulong *              rodata_reloc_off ) {
  ulong off = sizeof(fd_jit_res_t);
  *code_off         = off; off = fd_ulong_align_up( off + res->code_sz,   8UL );
  *rodata_off       = off; off = fd_ulong_align_up( off + res->rodata_sz, 8UL );
  *reloc_off        = off; off += res->reloc_cnt       *sizeof(fd_elf64_rela);
  *rodata_reloc_off = off; off += res->rodata_reloc_cnt*sizeof(fd_elf64_rela);
  return off;
}

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_jit_proto_h */
