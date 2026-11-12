#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h

/* fd_transpile_bind.h binds program cache records to transpiled
   programs, either ahead-of-time compiled and linked into the binary
   (fd_transpiled_ext) or JIT compiled into the shared JIT arena.

   A transpiled program applies to exactly one sBPF ELF and one feature
   set.  For AOT programs the feature set is fixed at link time and the
   ELF is matched by hash when the program cache loads a revision.  For
   JIT programs the jitmap tile has the image the record holds compiled,
   so a match is implied.  Either way the record remembers the
   binding in fd_progcache_rec_t::transpiled_idx: 0 means interpreter,
   values below FD_TRANSPILE_BIND_JIT are 1+index into fd_transpiled_ext,
   and FD_TRANSPILE_BIND_JIT|slot names a JIT arena slot.  A redeploy
   loads a new record, so nothing else needs to track revisions.  Every
   exec tile runs the same binary and maps the same arena, so both
   kinds of index are valid in all of them. */

#include "fd_transpile_runtime.h"
#include "fd_jit_heat.h"
#include "../../progcache/fd_progcache_rec.h"

#define FD_TRANSPILE_BIND_JIT         (0x80000000U)
#define FD_TRANSPILE_BIND_HOLD        (0x40000000U) /* interpreter for good: compile failed, did not fit, or bailed */

struct fd_jit_arena;

/* fd_transpile_bind_t is the per-tile view of the transpiled program
   sources.  arena and heat are NULL when JIT is disabled.  heat is
   this tile's row of the heat table, indexed by the position of a
   record in [rec0,rec0+rec_max). */

struct fd_transpile_bind {
  struct fd_jit_arena const * arena;
  fd_jit_heat_row_t *         heat;
  fd_progcache_rec_t const *  rec0;
  ulong                       rec_max;
};

typedef struct fd_transpile_bind fd_transpile_bind_t;

FD_PROTOTYPES_BEGIN

/* fd_transpile_bind_lookup returns 1+index of the AOT program for
   prog_id whose ELF hash matches bin, or 0 if there is none. */

uint
fd_transpile_bind_lookup( fd_pubkey_t const * prog_id,
                          uchar const *       bin,
                          ulong               bin_sz );

/* fd_transpile_bind_jit_init points bind at the JIT arena at arena_mem
   and at row row_idx of the heat table at heat_mem.  [rec0,rec0+rec_max)
   are the program cache's records.  Returns bind, or NULL if either
   object is invalid or does not match the program cache. */

fd_transpile_bind_t *
fd_transpile_bind_jit_init( fd_transpile_bind_t *      bind,
                            void *                     arena_mem,
                            void *                     heat_mem,
                            ulong                      row_idx,
                            fd_progcache_rec_t const * rec0,
                            ulong                      rec_max );

/* fd_transpile_bind_exec returns the transpiled entrypoint bound to
   rec, or NULL if the interpreter should be used. */

fd_vm_transpiled_exec_func_t
fd_transpile_bind_exec( fd_transpile_bind_t const * bind,
                        fd_progcache_rec_t const *  rec );

/* fd_transpile_bind_heat credits rec with cu compute units of
   interpreter time, which is what the jitmap tile ranks programs by.
   features is the feature set rec was loaded under.  Spill records
   have no stable index and are not counted. */

static inline void
fd_transpile_bind_heat( fd_transpile_bind_t const * bind,
                        fd_progcache_rec_t const *  rec,
                        fd_features_t const *       features,
                        ulong                       cu ) {
  if( !bind || !bind->heat ) return;
  ulong idx = (ulong)( rec - bind->rec0 );
  if( FD_UNLIKELY( rec<bind->rec0 || idx>=bind->rec_max ) ) return;
  fd_jit_heat_row_t * row = bind->heat;
  if( FD_UNLIKELY( row->feature_slot!=rec->feature_slot ) ) fd_jit_heat_row_features_publish( row, rec->feature_slot, features );
  FD_VOLATILE( row->cu[ idx ] ) = row->cu[ idx ] + (uint)cu;
}

/* fd_transpile_bind_unbind permanently falls back to the interpreter
   for rec (e.g. after transpiled code bailed). */

void
fd_transpile_bind_unbind( fd_progcache_rec_t * rec,
                          char const *         reason );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h */
