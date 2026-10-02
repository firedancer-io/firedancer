#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_out_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_out_h
#include "../../util/fd_util.h"
#include "../../disco/stem/fd_stem.h"
#include "fd_gossip_message.h"

struct fd_gossip_out_ctx {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       idx;
};

typedef struct fd_gossip_out_ctx fd_gossip_out_ctx_t;

#define FD_GOSSIP_UPDATE_LINK_CI_ADDR (0UL)
#define FD_GOSSIP_UPDATE_LINK_CI_SEEN (1UL)
#define FD_GOSSIP_UPDATE_LINK_VOTE    (2UL)
#define FD_GOSSIP_UPDATE_LINK_MISC    (3UL)
#define FD_GOSSIP_UPDATE_LINK_CNT     (4UL)

FD_FN_CONST static inline ulong
fd_gossip_update_link( ulong tag ) {
  switch( tag ) {
    case FD_GOSSIP_UPDATE_TAG_VOTE:            return FD_GOSSIP_UPDATE_LINK_VOTE;
    case FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED:
    case FD_GOSSIP_UPDATE_TAG_WFS_DONE:        return FD_GOSSIP_UPDATE_LINK_MISC;
    default:                                   return FD_GOSSIP_UPDATE_LINK_CI_ADDR;
  }
}


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
