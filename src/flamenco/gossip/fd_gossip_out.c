#include "fd_gossip_out.h"
#include "../../tango/fd_tango.h"

void *
fd_gossip_out_get_chunk( fd_gossip_out_ctx_t * ctx ) {
  return fd_chunk_to_laddr( ctx->mem, ctx->chunk );
}

void
fd_gossip_tx_publish_chunk( fd_gossip_out_ctx_t * ctx,
                            fd_stem_context_t *   stem,
                            ulong                 sig,
                            ulong                 sz,
                            long                  now ) {
  if( FD_UNLIKELY( ctx->chunk<ctx->chunk0 || ctx->chunk>ctx->wmark || sz>FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", ctx->chunk, sz, ctx->chunk0, ctx->wmark ));
  fd_stem_publish( stem, ctx->idx, sig, ctx->chunk, sz, 0UL, 0UL, (ulong)now );
  ctx->chunk = fd_dcache_compact_next( ctx->chunk, sz, ctx->chunk0, ctx->wmark );
}
