#include "../../fdctl/run/tiles/tiles.h"

#include "../rpc_client/fd_rpc_client.h"
#include "../rpc_client/fd_rpc_client_private.h"

#include "../../../util/net/fd_ip4.h"

#include <linux/unistd.h>

#define FD_BENCHO_STATE_INIT  0UL
#define FD_BENCHO_STATE_WAIT  1UL
#define FD_BENCHO_STATE_READY 2UL
#define FD_BENCHO_STATE_SENT  3UL

#define FD_BENCHO_RPC_RESPONSE_TIMEOUT (5L * 1000L * 1000L * 1000L)

typedef struct {
  long  rpc_ready_deadline;

  long  blockhash_request;
  ulong blockhash_state;
  long  blockhash_deadline;

  int   txncount_measured1;
  long  txncount_request;
  ulong txncount_state;
  long  txncount_nextprint;
  long  txncount_deadline;

  ulong txncount_prev;

  fd_rpc_client_t rpc[ 1 ];

  fd_wksp_t * mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_bencho_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_bencho_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_bencho_ctx_t ), sizeof( fd_bencho_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
service_block_hash( fd_bencho_ctx_t *  ctx,
                    fd_mux_context_t * mux ) {
  if( FD_UNLIKELY( ctx->blockhash_state==FD_BENCHO_STATE_WAIT ) ) {
    if( FD_LIKELY( fd_log_wallclock()>=ctx->blockhash_deadline ) )
      ctx->blockhash_state = FD_BENCHO_STATE_READY;
  }

  if( FD_UNLIKELY( ctx->blockhash_state==FD_BENCHO_STATE_READY ) ) {
    ctx->blockhash_request  = fd_rpc_client_request_latest_block_hash( ctx->rpc );
    if( FD_UNLIKELY( ctx->blockhash_request<0L ) ) FD_LOG_ERR(( "failed to send RPC request" ));

    ctx->blockhash_state    = FD_BENCHO_STATE_SENT;
    ctx->blockhash_deadline = fd_log_wallclock() + FD_BENCHO_RPC_RESPONSE_TIMEOUT;
  }

  if( FD_UNLIKELY( ctx->blockhash_state==FD_BENCHO_STATE_SENT ) ) {
    fd_rpc_client_response_t * response = fd_rpc_client_status( ctx->rpc, ctx->blockhash_request, 0 );
    if( FD_UNLIKELY( response->status==FD_RPC_CLIENT_PENDING ) ) {
      if( FD_UNLIKELY( fd_log_wallclock()>=ctx->blockhash_deadline ) )
        FD_LOG_ERR(( "timed out waiting for RPC server to respond" ));
      return;
    }

    if( FD_UNLIKELY( fd_log_wallclock()<ctx->rpc_ready_deadline && response->status==FD_RPC_CLIENT_ERR_NETWORK ) ) {
      /* RPC server not yet responding, give it some more time... */
      ctx->blockhash_state = FD_BENCHO_STATE_WAIT;
      ctx->blockhash_deadline = fd_log_wallclock() + 100L * 1000L * 1000L; /* 100 millis to retry */
      return;
    }

    if( FD_UNLIKELY( response->status!=FD_RPC_CLIENT_SUCCESS ) )
      FD_LOG_ERR(( "RPC server returned error %ld", response->status ));

    ctx->blockhash_state = FD_BENCHO_STATE_WAIT;
    ctx->blockhash_deadline = fd_log_wallclock() + 400L * 1000L * 1000L; /* 400 millis til we fetch new blockhash */
    fd_memcpy( fd_chunk_to_laddr( ctx->mem, ctx->out_chunk ), response->result.latest_block_hash.block_hash, 32 );
    fd_mux_publish( mux, 0UL, ctx->out_chunk, 32UL, 0UL, 0UL, 0UL );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, 32, ctx->out_chunk0, ctx->out_wmark );

    fd_rpc_client_close( ctx->rpc, ctx->blockhash_request );
    if( FD_UNLIKELY( !ctx->txncount_nextprint ) ) {
      ctx->txncount_nextprint = fd_log_wallclock();
    }
  }
}

static void
service_txn_count( fd_bencho_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx->txncount_nextprint ) ) return;

  if( FD_UNLIKELY( ctx->txncount_state==FD_BENCHO_STATE_WAIT ) ) {
    if( FD_LIKELY( fd_log_wallclock()>=ctx->txncount_deadline ) )
      ctx->txncount_state = FD_BENCHO_STATE_READY;
  }

  if( FD_UNLIKELY( ctx->txncount_state==FD_BENCHO_STATE_READY ) ) {
    ctx->txncount_request  = fd_rpc_client_request_transaction_count( ctx->rpc );
    if( FD_UNLIKELY( ctx->txncount_request<0L ) ) FD_LOG_ERR(( "failed to send RPC request" ));

    ctx->txncount_state    = FD_BENCHO_STATE_SENT;
    ctx->txncount_deadline = fd_log_wallclock() + FD_BENCHO_RPC_RESPONSE_TIMEOUT;
  }

  if( FD_UNLIKELY( ctx->txncount_state==FD_BENCHO_STATE_SENT ) ) {
    fd_rpc_client_response_t * response = fd_rpc_client_status( ctx->rpc, ctx->txncount_request, 0 );
    if( FD_UNLIKELY( response->status==FD_RPC_CLIENT_PENDING ) ) {
      if( FD_UNLIKELY( fd_log_wallclock()>=ctx->txncount_deadline ) )
        FD_LOG_ERR(( "timed out waiting for RPC server to respond" ));
      return;
    }

    if( FD_UNLIKELY( response->status!=FD_RPC_CLIENT_SUCCESS ) )
      FD_LOG_ERR(( "RPC server returned error %ld", response->status ));
    
    ulong txns = response->result.transaction_count.transaction_count;
    if( FD_LIKELY( ctx->txncount_measured1 ) )
      FD_LOG_NOTICE(( "%lu txn/s", (ulong)((double)(txns - ctx->txncount_prev)/1.2 )));
    ctx->txncount_measured1 = 1;
    ctx->txncount_prev      = txns;
    ctx->txncount_nextprint += 1200L * 1000L * 1000L; /* 1.2 seconds til we print again, multiple of slot duration to prevent jitter */

    fd_rpc_client_close( ctx->rpc, ctx->txncount_request );
    ctx->txncount_state = FD_BENCHO_STATE_WAIT;
    ctx->txncount_deadline = ctx->txncount_nextprint;
  }
}

static inline void
after_credit( void *             _ctx,
              fd_mux_context_t * mux ) {
  fd_bencho_ctx_t * ctx = (fd_bencho_ctx_t *)_ctx;

  fd_rpc_client_service( ctx->rpc, 0 );
  service_block_hash( ctx, mux );
  service_txn_count( ctx );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bencho_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bencho_ctx_t ), sizeof( fd_bencho_ctx_t ) );

  ctx->mem        = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id_primary ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->mem, topo->links[ tile->out_link_id_primary ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->mem, topo->links[ tile->out_link_id_primary ].dcache, topo->links[ tile->out_link_id_primary ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ctx->rpc_ready_deadline = fd_log_wallclock() + 5L * 1000L * 1000L * 1000L; /* 30 seconds to initialize */
  ctx->blockhash_state    = FD_BENCHO_STATE_READY;
  ctx->txncount_nextprint = 0;
  ctx->txncount_state     = FD_BENCHO_STATE_READY;
  ctx->txncount_measured1 = 0;

  FD_LOG_NOTICE(( "connecting to RPC server " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( tile->bencho.rpc_ip_addr ), tile->bencho.rpc_port ));
  FD_TEST( fd_rpc_client_join( fd_rpc_client_new( ctx->rpc, tile->bencho.rpc_ip_addr, tile->bencho.rpc_port ) ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static void
run( fd_topo_t *             topo,
     fd_topo_tile_t *        tile,
     void *                  scratch,
     fd_cnc_t *              cnc,
     ulong                   in_cnt,
     fd_frag_meta_t const ** in_mcache,
     ulong **                in_fseq,
     fd_frag_meta_t *        mcache,
     ulong                   out_cnt,
     ulong **                out_fseq ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bencho_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bencho_ctx_t ), sizeof( fd_bencho_ctx_t ) );

  fd_mux_callbacks_t callbacks = {
    .after_credit = after_credit,
  };

  fd_rng_t rng[1];
  fd_mux_tile( cnc,
               FD_MUX_FLAG_COPY | FD_MUX_FLAG_MANUAL_PUBLISH,
               in_cnt,
               in_mcache,
               in_fseq,
               mcache,
               out_cnt,
               out_fseq,
               1UL,
               0UL,
               0L,
               fd_rng_join( fd_rng_new( rng, 0, 0UL ) ),
               fd_alloca( FD_MUX_TILE_SCRATCH_ALIGN, FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt ) ),
               ctx,
               &callbacks );
}

fd_topo_run_tile_t fd_tile_bencho = {
  .name                     = "bencho",
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
};
