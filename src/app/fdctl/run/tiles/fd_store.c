#define _GNU_SOURCE 

#include "tiles.h"

#include "generated/store_seccomp.h"
#include "../../../../flamenco/repair/fd_repair.h"
#include "../../../../flamenco/runtime/fd_blockstore.h"
#include "../../../../util/fd_util.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>


#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"

#define SHRED_IN_IDX    0
#define REPAIR_IN_IDX   1

#define REPAIR_OUT_IDX  0
#define REPLAY_OUT_IDX  1

#define MAX_REPAIR_PEERS 40200UL


struct fd_store_tile_ctx {
  fd_wksp_t * wksp;
  
  fd_blockstore_t * blockstore;

  fd_wksp_t *     net_in;
  ulong           chunk;
  ulong           wmark;

  fd_wksp_t * shred_in_mem;
  ulong       shred_in_chunk0;
  ulong       shred_in_wmark;

  fd_wksp_t * repair_in_mem;
  ulong       repair_in_chunk0;
  ulong       repair_in_wmark;

  fd_shred34_t s34_buffer[1];
};
typedef struct fd_store_tile_ctx fd_store_tile_ctx_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  return 4UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_store_tile_ctx_t) );
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_store_tile_ctx_t * ctx = (fd_store_tile_ctx_t *)_ctx;
  (void)ctx;

  if( FD_UNLIKELY( in_idx==SHRED_IN_IDX )) {
    return;
  }
}



static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;
  (void)sig;

  fd_store_tile_ctx_t * ctx = (fd_store_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==SHRED_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->shred_in_chunk0 || chunk>ctx->shred_in_wmark || sz > sizeof(fd_shred34_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->shred_in_chunk0, ctx->wmark ));
    }

    fd_shred34_t const * s34 = fd_chunk_to_laddr_const( ctx->shred_in_mem, chunk );

    memcpy( ctx->s34_buffer, s34, sz );
    FD_LOG_WARNING(( "SHRED: %lu", sz ));
    *opt_filter = 0;
    
    return;
  }

  *opt_filter = 1;

  return;
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_filter;
  (void)mux;
  (void)seq;
  (void)opt_tsorig;
  (void)opt_sig;

  fd_store_tile_ctx_t * ctx = (fd_store_tile_ctx_t *)_ctx;
      FD_LOG_WARNING(("AAHHH!"));

  if( FD_UNLIKELY( in_idx==SHRED_IN_IDX ) ) {
    for( ulong i = 0; i < ctx->s34_buffer->shred_cnt; i++ ) {
      if( fd_blockstore_shred_insert( ctx->blockstore, &ctx->s34_buffer->pkts[i].shred ) != FD_BLOCKSTORE_OK ) {
        FD_LOG_ERR(( "failed inserting to blockstore" ));
      }
      FD_LOG_WARNING(("SHREDS INSERTED!"));
    }
  }

  if( FD_UNLIKELY( in_idx==REPAIR_IN_IDX ) ) {
    return;
  }

  *opt_filter = 1;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;
}

static void
during_housekeeping( void * _ctx ) {
  fd_store_tile_ctx_t * ctx = (fd_store_tile_ctx_t *)_ctx;
  (void)ctx;
}

void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( tile->in_cnt != 2 ||
                   topo->links[ tile->in_link_id[ SHRED_IN_IDX     ] ].kind != FD_TOPO_LINK_KIND_SHRED_TO_STORE    ||
                   topo->links[ tile->in_link_id[ REPAIR_IN_IDX ] ].kind != FD_TOPO_LINK_KIND_REPAIR_TO_STORE ) )
    FD_LOG_ERR(( "store tile has none or unexpected input links %lu %lu %lu",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].kind, topo->links[ tile->in_link_id[ 1 ] ].kind ));

  // if( FD_UNLIKELY( tile->out_cnt != 1 ||
  //                  topo->links[ tile->out_link_id[ NET_OUT_IDX ] ].kind != FD_TOPO_LINK_KIND_REPAIR_TO_NETMUX ) )
  //   FD_LOG_ERR(( "repair tile has none or unexpected output links %lu %lu %lu",
  //                tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].kind, topo->links[ tile->out_link_id[ 1 ] ].kind ));
      
  if( FD_UNLIKELY( tile->out_link_id_primary != ULONG_MAX ) )
    FD_LOG_ERR(( "store tile has a primary output link" ));

  /* Scratch mem setup */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_store_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_tile_ctx_t), sizeof(fd_store_tile_ctx_t) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }
  
  ctx->wksp = topo->workspaces[ tile->wksp_id ].wksp;

  /* TODO: combine with fd_tvu_main_setup */
  ulong hashseed = 42;

  fd_blockstore_t *        blockstore = NULL;
  fd_wksp_tag_query_info_t blockstore_info;
  ulong                    blockstore_tag = FD_BLOCKSTORE_MAGIC;
  if( fd_wksp_tag_query( ctx->wksp, &blockstore_tag, 1, &blockstore_info, 1 ) > 0 ) {
    void * shmem = fd_wksp_laddr_fast( ctx->wksp, blockstore_info.gaddr_lo );
    blockstore   = fd_blockstore_join( shmem );
    if( blockstore == NULL ) FD_LOG_ERR( ( "failed to join a blockstore" ) );
  } else {
    void * shmem = fd_wksp_alloc_laddr(
        ctx->wksp, fd_blockstore_align(), fd_blockstore_footprint(), FD_BLOCKSTORE_MAGIC );
    if( shmem == NULL ) FD_LOG_ERR( ( "failed to allocate a blockstore" ) );

    // Sensible defaults for an anon blockstore:
    // - 1mb of shreds
    // - 64 slots of history (~= finalized = 31 slots on top of a confirmed block)
    // - 1mb of txns
    ulong tmp_shred_max    = 1UL << 20;
    ulong slot_history_max = FD_BLOCKSTORE_SLOT_HISTORY_MAX;
    int   lg_txn_max       = 20;
    blockstore             = fd_blockstore_join(
        fd_blockstore_new( shmem, 1, hashseed, tmp_shred_max, slot_history_max, lg_txn_max ) );
    if( blockstore == NULL ) {
      fd_wksp_free_laddr( shmem );
      FD_LOG_ERR( ( "failed to allocate a blockstore" ) );
    }
  }

  ctx->blockstore = blockstore;

  void * alloc_shmem = fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { 
    FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); 
  }
  
  fd_topo_link_t * netmux_link = &topo->links[ tile->in_link_id[ 0 ] ];

  ctx->net_in = topo->workspaces[ netmux_link->wksp_id ].wksp;
  ctx->chunk  = fd_disco_compact_chunk0( ctx->net_in );
  ctx->wmark  = fd_disco_compact_wmark( ctx->net_in, netmux_link->mtu );

  /* Set up contact info tile output */

  fd_topo_link_t * shred_in_link = &topo->links[ tile->in_link_id[ SHRED_IN_IDX ] ];
  ctx->shred_in_mem    = topo->workspaces[ shred_in_link->wksp_id ].wksp;
  ctx->shred_in_chunk0 = fd_dcache_compact_chunk0( ctx->shred_in_mem, shred_in_link->dcache );
  ctx->shred_in_wmark  = fd_dcache_compact_wmark( ctx->shred_in_mem, shred_in_link->dcache, shred_in_link->mtu );

  /* Valloc setup */
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { 
    FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) ); 
  }

  fd_valloc_t valloc = fd_alloc_virtual( alloc );
  (void)valloc;
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_store( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_store_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_tile_config_t fd_tile_store = {
  .mux_flags                = FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .mux_during_housekeeping  = during_housekeeping,
};
