#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_out_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_out_h
#include "../../util/fd_util.h"
#include "../../disco/stem/fd_stem.h"

struct fd_gossip_out_ctx {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       idx;
};

typedef struct fd_gossip_out_ctx fd_gossip_out_ctx_t;


FD_PROTOTYPES_BEGIN
/* returns a pointer to the next available chunk in the dcache line.
   Writes to this line must never exceed the link's MTU.

   Call must be followed by a call to fd_gossip_tx_publish_chunk before
   a subsequent call to fd_gossip_out_get_chunk for the same ctx */
void *
fd_gossip_out_get_chunk( fd_gossip_out_ctx_t * ctx );

/* publish a chunk previously acquired with fd_gossip_out_get_chunk */
void
fd_gossip_tx_publish_chunk( fd_gossip_out_ctx_t * ctx,
                            fd_stem_context_t *  stem,
                            ulong                sig,
                            ulong                sz,
                            long                 now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_out_h */
