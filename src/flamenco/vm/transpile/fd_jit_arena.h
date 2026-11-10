#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_jit_arena_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_jit_arena_h

/* fd_jit_arena.h is the shared memory region holding JIT compiled
   programs.  The jitmap tile owns it (read-write) and appends programs;
   exec tiles map it read-execute and only ever look up entrypoints.

   Layout: [ header | slot table | code region ].  The code region is
   bump allocated and never reclaimed.  Each program occupies one
   extent [ code | veneers | rodata ] so every rel32 inside it reaches.

   Code must run at a different virtual address in every process, so
   nothing in the arena holds an absolute pointer.  Calls out of
   transpiled code go through 16 byte veneers that load a function
   pointer from the fd_vm_t in r12 (vm->syscalls for syscalls,
   vm->transpiled.rt for the runtime helpers) and tail jump to it. */

#include "fd_jit_proto.h"
#include "fd_transpile_target.h"

#define FD_JIT_ARENA_MAGIC    (0xf17eda2c3e71a4e0UL)
#define FD_JIT_ARENA_ALIGN    (4096UL)
#define FD_JIT_ARENA_SLOT_MAX (4096UL)

struct fd_jit_slot {
  ulong entry_off;    /* arena relative entrypoint */
  ulong prog_off;     /* arena relative start of extent */
  ulong prog_sz;
  ulong feature_slot;
  uchar prog_id[ 32 ];
  uchar image_hash[ 32 ]; /* BLAKE3 of the loaded program image (res->meta.elf_hash) */
};

typedef struct fd_jit_slot fd_jit_slot_t;

struct __attribute__((aligned(FD_JIT_ARENA_ALIGN))) fd_jit_arena {
  ulong magic;
  ulong code_off;   /* arena relative, page aligned */
  ulong code_max;
  ulong code_used;
  ulong slot_cnt;   /* published slots; release-stored after the slot is complete */
  ulong prog_cnt;   /* distinct programs (slot_cnt minus dedup hits) */
  fd_jit_slot_t slot[ FD_JIT_ARENA_SLOT_MAX ];
};

typedef struct fd_jit_arena fd_jit_arena_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_jit_arena_align( void ) {
  return FD_JIT_ARENA_ALIGN;
}

FD_FN_CONST static inline ulong
fd_jit_arena_footprint( ulong code_max ) {
  return fd_ulong_align_up( sizeof(fd_jit_arena_t), FD_JIT_ARENA_ALIGN ) + fd_ulong_align_up( code_max, FD_JIT_ARENA_ALIGN );
}

void *
fd_jit_arena_new( void * mem,
                  ulong  code_max );

fd_jit_arena_t *
fd_jit_arena_join( void * mem );

static inline fd_vm_transpiled_exec_func_t
fd_jit_arena_exec( fd_jit_arena_t const * arena,
                   ulong                  slot_idx ) {
  fd_transpile_icache_sync(); /* jitmap flushed the lines; this core may still hold stale fetches */
  return (fd_vm_transpiled_exec_func_t)( (ulong)arena + arena->slot[ slot_idx ].entry_off );
}

/* fd_jit_arena_place copies the program described by res (header) and
   frag (res followed by its variable parts, see fd_jit_res_layout)
   into the arena, resolving all relocations.  A program with the same
   prog_id, image hash and feature slot as an existing slot is not
   copied again.
   Returns the slot index, or -1 if the arena is full or the response
   is malformed (logs reason).  Only the arena owner may call this. */

long
fd_jit_arena_place( fd_jit_arena_t *     arena,
                    fd_jit_res_t const * res,
                    uchar const *        frag,
                    ulong                frag_sz,
                    int *                opt_dedup );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_jit_arena_h */
