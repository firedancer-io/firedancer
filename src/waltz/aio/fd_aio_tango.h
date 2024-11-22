#ifndef HEADER_fd_src_waltz_aio_fd_aio_tango_h
#define HEADER_fd_src_waltz_aio_fd_aio_tango_h

#include "fd_aio.h"
#include "../../tango/fd_tango.h"

/* fd_aio_tango_tx_t provides an API to submit frags to an mcache/dcache
   pair via fd_aio_send.

   Assumes dcache is compactly stored with burst==1.
   Assumes mcache and dcache have same depth.
   Assumes dcache has enough room for frags with max size 'mtu'. */

struct fd_aio_tango_tx {
  fd_aio_t         aio;
  fd_frag_meta_t * mcache;
  void *           dcache;
  void *           base;
  ulong            chunk0;
  ulong            wmark;
  ulong            depth;
  ulong            mtu;
  ulong            orig;
  ulong            chunk;
  ulong            seq;
};

typedef struct fd_aio_tango_tx fd_aio_tango_tx_t;

FD_PROTOTYPES_BEGIN

fd_aio_tango_tx_t *
fd_aio_tango_tx_new( fd_aio_tango_tx_t * self,
                     fd_frag_meta_t *    mcache,
                     void *              dcache,
                     void *              base,
                     ulong               mtu,
                     ulong               orig );

void *
fd_aio_tango_delete( fd_aio_tango_tx_t * self );

FD_FN_CONST static inline fd_aio_t const *
fd_aio_tango_get_aio( fd_aio_tango_tx_t const * self ) {
  return &self->aio;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_aio_fd_aio_tango_h */
