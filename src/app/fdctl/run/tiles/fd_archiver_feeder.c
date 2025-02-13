#include "../../../../disco/tiles.h"

#include "fd_archiver.h"
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/archiver_feeder_seccomp.h"

#define FD_ARCHIVER_FEEDER_MAX_INPUT_LINKS (32UL)

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_archiver_feeder_in_ctx_t;

struct fd_archiver_feeder_tile_ctx {  
  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  ulong count;

  ulong round_robin_idx;
  ulong round_robin_cnt;

  /* Map of input link idxs to header tile IDs */
  uint link_to_header_tile_ids[ FD_ARCHIVER_FEEDER_MAX_INPUT_LINKS ];

  fd_archiver_feeder_in_ctx_t in[ FD_ARCHIVER_FEEDER_MAX_INPUT_LINKS ];
};
typedef struct fd_archiver_feeder_tile_ctx fd_archiver_feeder_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_archiver_feeder( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_archiver_feeder_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;
  (void)out_fds_cnt;

  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

  return out_cnt;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_archiver_feeder_tile_ctx_t), sizeof(fd_archiver_feeder_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
    (void)topo;
    (void)tile;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {    
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );  
  fd_archiver_feeder_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_feeder_tile_ctx_t), sizeof(fd_archiver_feeder_tile_ctx_t) );
  memset( ctx, 0, sizeof(fd_archiver_feeder_tile_ctx_t) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );

    /* Set the link tile ID correctly in the map */
    if( !strcmp( link->name, "net_shred" ) ) {
      ctx->link_to_header_tile_ids[ i ] = FD_ARCHIVER_TILE_ID_SHRED;
    } else if( !strcmp( link->name, "net_gossip" ) ) {
      ctx->link_to_header_tile_ids[ i ] = FD_ARCHIVER_TILE_ID_GOSSIP;
    } else if( !strcmp( link->name, "net_repair" ) ) {
      ctx->link_to_header_tile_ids[ i ] = FD_ARCHIVER_TILE_ID_REPAIR;
    } else if( !strcmp( link->name, "net_quic" ) ) {
      ctx->link_to_header_tile_ids[ i ] = FD_ARCHIVER_TILE_ID_QUIC;
    } else {
      FD_LOG_ERR(( "unsupported input link" ));
    }

  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }
}

static int
before_frag( fd_archiver_feeder_tile_ctx_t * ctx,
             ulong                           in_idx,
             ulong                           seq,
             ulong                           sig ) {
  (void)in_idx;
  (void)sig;
  (void)seq;

  return 0;

 
    /* gossip */
    if ( ctx->round_robin_idx == 0) {
      // if( ctx->count >= 100000 ) {
      //   return 1;
      // }
      // ctx->count += 1;
      return 0;
    }

    /* repair */
    if( ctx->round_robin_idx == 1 ) {
      return 0;
      // return !((seq % 4) == 1);
    }
    // if( ctx->round_robin_idx == 2 ) {
    //   return !((seq % 4) == 2);
    // }
    // if( ctx->round_robin_idx == 3 ) {
    //   return !((seq % 4) == 3);
    // }
    // if( ctx->round_robin_idx == 4 ) {
    //   return !((seq % 4) == 0);
    // }

    /* shred */
    if( ctx->round_robin_idx == 5 ) {
      // if( ctx->count >= 50000 ) {
      //   return 1;
      // }
      // ctx->count += 1;
      return 0;
    }
    // if( ctx->round_robin_idx == 6 ) {
    //   return !((seq % 5) == 2);
    // }
    // if( ctx->round_robin_idx == 7 ) {
    //   return !((seq % 5) == 3);
    // }
    // if( ctx->round_robin_idx == 8 ) {
    //   return !((seq % 5) == 4);
    // }
    // if( ctx->round_robin_idx == 9 ) {
    //   return !((seq % 5) == 0);
    // }
    
  return 1;
}

static inline void
during_frag( fd_archiver_feeder_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq,
             ulong                    sig,
             ulong                    tspub,
             ulong                    chunk,
             ulong                    sz ) {
  (void)seq;
  (void)sig;
  (void)tspub;

  /* TODO: filter by signature in before_credit */
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  }

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  if( FD_LIKELY( sz ) ) {
    /* Write the header to the dst */
    fd_archiver_frag_header_t * header = fd_type_pun( dst );
    header->magic                      = FD_ARCHIVER_HEADER_MAGIC;
    header->version                    = FD_ARCHIVER_HEADER_VERSION;
    header->tile_id                    = ctx->link_to_header_tile_ids[ in_idx ];
    /* header->ns_since_prev_fragment is set in the single writer tile, so that we have a total order */
    header->sz                         = sz;
    header->sig                        = sig;
    header->seq                        = seq;
    
    /* Write the frag to the dst */
    fd_memcpy( dst + FD_ARCHIVER_FRAG_HEADER_FOOTPRINT, src, sz );                                   
  }
}        

static inline void
after_frag( fd_archiver_feeder_tile_ctx_t * ctx,
            ulong                           in_idx,
            ulong                           seq,
            ulong                           sig,
            ulong                           sz,
            ulong                           tsorig,
            fd_stem_context_t *             stem ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)tsorig;
  (void)stem;

  /* Publish the message to the queue */
  ulong full_sz = sz + FD_ARCHIVER_FRAG_HEADER_FOOTPRINT;
  fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, full_sz, 0UL, tsorig, 0UL);
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, full_sz, ctx->out_chunk0, ctx->out_wmark );
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_archiver_feeder_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_archiver_feeder_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_archiver_feeder = {
  .name                     = "arch_f",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
