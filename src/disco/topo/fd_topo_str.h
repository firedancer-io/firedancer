#ifndef HEADER_fd_src_disco_topo_fd_topo_str_h
#define HEADER_fd_src_disco_topo_fd_topo_str_h

#include "../../util/fd_util_base.h"

/* fd_topo_str_t is a self-relative reference to a NUL terminated
   string stored in a string arena that lives in the same allocation as
   the field (the strs array of an fd_topo_t or fd_config_t).  rel is
   the byte offset from the field itself to the string, so a zero
   initialized field reads as "" (it points at its own zero bytes) and
   the reference stays valid when the whole enclosing struct is
   memcpy'd, written to a memfd or to disk.  It is only valid while the
   field stays inside its enclosing struct: copying a lone
   fd_topo_tile_t out of its fd_topo_t leaves the reference dangling. */

struct fd_topo_str {
  int rel;
};

typedef struct fd_topo_str fd_topo_str_t;

FD_PROTOTYPES_BEGIN

static inline char const *
fd_topo_str( fd_topo_str_t const * s ) {
  return (char const *)s + s->rel;
}

#define FD_TOPO_STR(field) fd_topo_str( &(field) )

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_topo_str_h */
