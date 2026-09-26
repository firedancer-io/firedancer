#ifndef HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h
#define HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h

/* fd_transpile_bind.h binds program cache records to ahead-of-time
   transpiled programs linked into the binary (fd_transpiled_ext).

   A transpiled program applies to exactly one sBPF ELF and one feature
   set.  The feature set is fixed at link time (the object symbol name
   carries FD_FEATURE_SET_ID).  The ELF is matched when the program
   cache loads a program revision: fd_transpile_bind_lookup compares
   the ELF hash against the export and the record remembers the match
   (fd_progcache_rec_t::transpiled_idx).  A redeploy loads a new
   record, so nothing else needs to track revisions.  Every exec tile
   runs the same binary, so an index into fd_transpiled_ext is valid in
   all of them. */

#include "fd_transpile_runtime.h"
#include "../../progcache/fd_progcache.h"

FD_PROTOTYPES_BEGIN

/* fd_transpile_bind_lookup returns 1+index of the transpiled program
   for prog_id whose ELF hash matches bin, or 0 if there is none. */

uint
fd_transpile_bind_lookup( fd_pubkey_t const * prog_id,
                          uchar const *       bin,
                          ulong               bin_sz );

/* fd_transpile_bind_exec returns the transpiled entrypoint bound to
   rec, or NULL if the interpreter should be used. */

static inline fd_vm_transpiled_exec_func_t
fd_transpile_bind_exec( fd_progcache_rec_t const * rec ) {
  uint idx = FD_VOLATILE_CONST( rec->transpiled_idx );
  return idx ? fd_transpiled_ext[ idx-1U ]->exec : NULL;
}

/* fd_transpile_bind_unbind permanently falls back to the interpreter
   for rec (e.g. after transpiled code bailed). */

void
fd_transpile_bind_unbind( fd_progcache_rec_t * rec,
                          char const *         reason );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_fd_transpile_bind_h */
