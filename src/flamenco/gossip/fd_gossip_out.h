#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_tx_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_tx_h
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
/* returns a pointer to the next available chunk in the dcache line
   writes to this line must never exceed the link's MTU.

   Gossip should have at least two out links, one for update messages and
   the other to the net tile for tx messages. The net link MTU should be
   FD_NET_MTU, while the update link should be 2048b.

   Call must be followed by a call to fd_gossip_tx_publish_chunk before
   a subsequent call to fd_gossip_out_get_chunk */
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

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_tx_h */
