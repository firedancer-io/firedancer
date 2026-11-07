#ifndef HEADER_fd_src_discof_jit_fd_jit_client_h
#define HEADER_fd_src_discof_jit_fd_jit_client_h

/* fd_jit_client.h is the exec tile side of the JIT: it owns the
   exec_jit out link and the read-execute arena mapping, and plugs into
   the program cache's load path to request compilation. */

#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/progcache/fd_progcache_user.h" /* fd_progcache_t */
#include "../../flamenco/vm/transpile/fd_transpile_bind.h"

struct fd_jit_client {
  fd_transpile_bind_t bind[1];

  fd_frag_meta_t * mcache;
  ulong            depth;
  ulong            seq;
  fd_wksp_t *      mem;
  ulong            chunk0;
  ulong            wmark;
  ulong            chunk;
  fd_wksp_t *      pc_wksp;
  ulong            tile_idx;
  ulong            sent;
  ulong            dropped;
};

typedef struct fd_jit_client fd_jit_client_t;

FD_PROTOTYPES_BEGIN

/* fd_jit_client_privileged_init makes the JIT arena mapping executable.
   Must run before the tile is sandboxed.  No-op if jit_arena_obj_id is
   ULONG_MAX. */

void
fd_jit_client_privileged_init( fd_topo_t const * topo,
                               ulong             jit_arena_obj_id );

/* fd_jit_client_init wires client to the tile's exec_jit out link
   (kind_id tile_idx) and the JIT arena, and hooks it into progcache.
   Returns 0 and leaves everything NULL if the tile has no exec_jit
   link, in which case runtime->transpile may stay NULL.  Otherwise
   returns 1. */

int
fd_jit_client_init( fd_jit_client_t *      client,
                    fd_topo_t const *      topo,
                    fd_topo_tile_t const * tile,
                    ulong                  tile_idx,
                    ulong                  jit_arena_obj_id,
                    fd_progcache_t *       progcache );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_jit_fd_jit_client_h */
