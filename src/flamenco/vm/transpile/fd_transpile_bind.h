#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h

/* fd_transpile_bind.h binds program cache records to transpiled
   programs, either ahead-of-time compiled and linked into the binary
   (fd_transpiled_ext) or JIT compiled into the shared JIT arena.

   A transpiled program applies to exactly one sBPF ELF and one feature
   set.  For AOT programs the feature set is fixed at link time and the
   ELF is matched by hash when the program cache loads a revision.  For
   JIT programs the jitmap tile compiles exactly the image the record
   holds, so a match is implied.  Either way the record remembers the
   binding in fd_progcache_rec_t::transpiled_idx: 0 means interpreter,
   values below FD_TRANSPILE_BIND_JIT are 1+index into fd_transpiled_ext,
   and FD_TRANSPILE_BIND_JIT|slot names a JIT arena slot.  A redeploy
   loads a new record, so nothing else needs to track revisions.  Every
   exec tile runs the same binary and maps the same arena, so both
   kinds of index are valid in all of them. */

#include "fd_transpile_runtime.h"
#include "../../progcache/fd_progcache_rec.h"

#define FD_TRANSPILE_BIND_JIT (0x80000000U)

struct fd_jit_arena;

/* fd_transpile_bind_t is the per-tile view of the transpiled program
   sources.  arena is NULL when JIT is disabled. */

struct fd_transpile_bind {
  struct fd_jit_arena const * arena;
};

typedef struct fd_transpile_bind fd_transpile_bind_t;

FD_PROTOTYPES_BEGIN

/* fd_transpile_bind_lookup returns 1+index of the AOT program for
   prog_id whose ELF hash matches bin, or 0 if there is none. */

uint
fd_transpile_bind_lookup( fd_pubkey_t const * prog_id,
                          uchar const *       bin,
                          ulong               bin_sz );

/* fd_transpile_bind_exec returns the transpiled entrypoint bound to
   rec, or NULL if the interpreter should be used. */

fd_vm_transpiled_exec_func_t
fd_transpile_bind_exec( fd_transpile_bind_t const * bind,
                        fd_progcache_rec_t const *  rec );

/* fd_transpile_bind_unbind permanently falls back to the interpreter
   for rec (e.g. after transpiled code bailed). */

void
fd_transpile_bind_unbind( fd_progcache_rec_t * rec,
                          char const *         reason );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h */
