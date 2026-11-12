#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_jit_arena_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_jit_arena_h

/* fd_jit_arena.h is the shared memory region holding JIT compiled
   programs.  The jitmap tile owns it (read-write) and appends programs;
   exec tiles map it read-execute and only ever look up entrypoints.

   Layout: [ header | slot table | free list | code region ].  Each
   program occupies one extent [ code | veneers | rodata ] of the code
   region so every rel32 inside it reaches.  Extents are allocated
   first fit.  The owner frees a slot once no program cache record
   names it and no exec tile can still be running its code, after which
   both the slot index and the extent are reused.

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

#define FD_JIT_ARENA_ERR_INVAL (-1L) /* malformed response */
#define FD_JIT_ARENA_ERR_FULL  (-2L) /* no free slot or no free extent large enough */

struct fd_jit_slot {
  ulong entry_off;    /* arena relative entrypoint */
  ulong prog_off;     /* arena relative start of extent */
  ulong prog_sz;      /* 0 if the slot is free */
  ulong feature_slot;
  uchar prog_id[ 32 ];
  uchar image_hash[ 32 ]; /* BLAKE3 of the loaded program image (res->meta.elf_hash) */
};

typedef struct fd_jit_slot fd_jit_slot_t;

struct fd_jit_extent {
  ulong off; /* code region relative */
  ulong sz;
};

typedef struct fd_jit_extent fd_jit_extent_t;

struct __attribute__((aligned(FD_JIT_ARENA_ALIGN))) fd_jit_arena {
  ulong magic;
  ulong code_off;   /* arena relative, page aligned */
  ulong code_max;
  ulong code_used;  /* bytes in allocated extents */
  ulong slot_cnt;   /* slots ever published; release-stored after the slot is complete */
  ulong prog_cnt;   /* slots in use */
  ulong free_cnt;
  fd_jit_slot_t   slot[ FD_JIT_ARENA_SLOT_MAX ];
  fd_jit_extent_t free[ FD_JIT_ARENA_SLOT_MAX+1UL ]; /* ascending by off, no two adjacent */
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

/* fd_jit_arena_protect_exec makes the caller's mapping of the arena at
   mem executable, which is what an exec tile needs before it is
   sandboxed.  mprotect on a hugetlbfs mapping needs huge page bounds,
   so this flips the whole workspace join.  A read-write join (single
   process mode, where the jitmap tile shares the mapping) stays
   writable. */

#if FD_HAS_HOSTED
void
fd_jit_arena_protect_exec( void * mem );
#endif

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
   Returns the slot index, FD_JIT_ARENA_ERR_FULL if there is no room
   (freeing a slot may help), or FD_JIT_ARENA_ERR_INVAL if the response
   is malformed (logs reason).  Only the arena owner may call this. */

long
fd_jit_arena_place( fd_jit_arena_t *     arena,
                    fd_jit_res_t const * res,
                    uchar const *        frag,
                    ulong                frag_sz,
                    int *                opt_dedup );

/* fd_jit_arena_find returns the slot holding the program with the
   given identity, or -1 if there is none. */

FD_FN_PURE long
fd_jit_arena_find( fd_jit_arena_t const * arena,
                   uchar const *          prog_id,
                   uchar const *          image_hash,
                   ulong                  feature_slot );

/* fd_jit_arena_free releases slot_idx and its extent for reuse.  The
   caller guarantees that no program cache record is bound to the slot
   and that no exec tile is executing it or holds its entrypoint.
   Only the arena owner may call this. */

void
fd_jit_arena_free( fd_jit_arena_t * arena,
                   ulong            slot_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_jit_arena_h */
