#include "../../rpc_client/fd_rpc_client.h"
#include "../../rpc_client/fd_rpc_client_private.h"
#include "../../../../disco/topo/fd_topo.h"
#include "../../../../third_party/cjson/cJSON_alloc.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../discof/replay/fd_replay_tile.h"

#include <stdlib.h>

#define FD_BENCHO_STATE_INIT  0UL
#define FD_BENCHO_STATE_WAIT  1UL
#define FD_BENCHO_STATE_READY 2UL
#define FD_BENCHO_STATE_SENT  3UL

#define FD_BENCHO_RPC_INITIALIZE_TIMEOUT (30L * 1000L * 1000L * 1000L)
#define FD_BENCHO_RPC_RESPONSE_TIMEOUT   (5L  * 1000L * 1000L * 1000L)

typedef struct {
  long  rpc_ready_deadline;

  long  blockhash_request;
  ulong blockhash_state;
  long  blockhash_deadline;

  fd_rpc_client_t rpc[ 1 ];

  fd_wksp_t * in_mem;

  ulong duration_s;
  ulong start_txns;
  long  start_nanos;
  ulong last_txns;
  long  last_nanos;
  ulong slots;
  ulong max_tps;

  fd_wksp_t * mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_bencho_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong a = alignof( fd_bencho_ctx_t );
  a = fd_ulong_max( a, fd_alloc_align() );
  return a;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_bencho_ctx_t ), sizeof( fd_bencho_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),           fd_alloc_footprint()      );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 256UL * (1UL<<20UL); /* 256MiB of heap space for the cJSON allocator */
}

static int
service_block_hash( fd_bencho_ctx_t *   ctx,
                    fd_stem_context_t * stem ) {
  int did_work = 0;

  if( FD_UNLIKELY( ctx->blockhash_state==FD_BENCHO_STATE_WAIT ) ) {
    if( FD_LIKELY( fd_log_wallclock()>=ctx->blockhash_deadline ) )
      ctx->blockhash_state = FD_BENCHO_STATE_READY;
  }

  if( FD_UNLIKELY( ctx->blockhash_state==FD_BENCHO_STATE_READY ) ) {
    ctx->blockhash_request  = fd_rpc_client_request_latest_block_hash( ctx->rpc );
    if( FD_UNLIKELY( ctx->blockhash_request<0L ) ) FD_LOG_ERR(( "failed to send RPC request" ));

    ctx->blockhash_state    = FD_BENCHO_STATE_SENT;
    ctx->blockhash_deadline = fd_log_wallclock() + FD_BENCHO_RPC_RESPONSE_TIMEOUT;

    did_work = 1;
  }

  if( FD_UNLIKELY( ctx->blockhash_state==FD_BENCHO_STATE_SENT ) ) {
    fd_rpc_client_response_t * response = fd_rpc_client_status( ctx->rpc, ctx->blockhash_request, 0 );
    if( FD_UNLIKELY( response->status==FD_RPC_CLIENT_PENDING ) ) {
      if( FD_UNLIKELY( fd_log_wallclock()>=ctx->blockhash_deadline ) ) {
        FD_LOG_WARNING(( "timed out waiting for RPC server to respond" ));
        fd_rpc_client_close( ctx->rpc, ctx->blockhash_request );
        ctx->blockhash_state    = FD_BENCHO_STATE_WAIT;
        ctx->blockhash_deadline = fd_log_wallclock() + 100L * 1000L * 1000L; /* 100 millis to retry */
      }
      return did_work;
    }

    if( FD_UNLIKELY( fd_log_wallclock()<ctx->rpc_ready_deadline &&
                     ( response->status==FD_RPC_CLIENT_ERR_NETWORK ||
                       response->status==FD_RPC_CLIENT_ERR_MALFORMED ) ) ) {
      /* RPC server not yet responding, give it some more time... */
      ctx->blockhash_state = FD_BENCHO_STATE_WAIT;
      ctx->blockhash_deadline = fd_log_wallclock() + 100L * 1000L * 1000L; /* 100 millis to retry */
      fd_rpc_client_close( ctx->rpc, ctx->blockhash_request );
      return did_work;
    }

    if( FD_UNLIKELY( response->status!=FD_RPC_CLIENT_SUCCESS ) )
      FD_LOG_ERR(( "RPC server returned error %ld-%s", response->status, fd_rpc_client_strerror( response->status ) ));

    ctx->blockhash_state = FD_BENCHO_STATE_WAIT;
    ctx->blockhash_deadline = fd_log_wallclock() + 400L * 1000L * 1000L; /* 400 millis til we fetch new blockhash */
    fd_memcpy( fd_chunk_to_laddr( ctx->mem, ctx->out_chunk ), response->result.latest_block_hash.block_hash, 32 );
    fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, 32UL, 0UL, 0UL, 0UL );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, 32, ctx->out_chunk0, ctx->out_wmark );

    fd_rpc_client_close( ctx->rpc, ctx->blockhash_request );

    did_work = 1;
  }

  return did_work;
}

static int
returnable_frag( fd_bencho_ctx_t *   ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sz; (void)ctl; (void)tsorig; (void)tspub; (void)stem;
  if( FD_UNLIKELY( sig!=REPLAY_SIG_SLOT_COMPLETED ) ) return 0;
  fd_replay_slot_completed_t const * msg = fd_chunk_to_laddr_const( ctx->in_mem, chunk );
  ulong txns  = msg->transaction_count;
  long  nanos = msg->completion_time_nanos;
  ulong slot_txns = txns-ctx->last_txns;
  long  slot_ns   = nanos-ctx->last_nanos;
  ctx->last_txns  = txns;
  ctx->last_nanos = nanos;
  if( FD_UNLIKELY( !ctx->start_nanos ) ) {
    if( FD_LIKELY( slot_txns ) ) { ctx->start_txns = txns; ctx->start_nanos = nanos; }
    return 0;
  }
  ulong tps = (ulong)((double)slot_txns*1e9/(double)slot_ns);
  ctx->slots++;
  ctx->max_tps = fd_ulong_max( ctx->max_tps, tps );
  FD_LOG_INFO(( "bench slot=%lu txns=%lu dt=%.3f s tps=%lu", msg->slot, slot_txns, (double)slot_ns/1e9, tps ));
  if( FD_UNLIKELY( ctx->duration_s && nanos-ctx->start_nanos>=(long)ctx->duration_s*1000L*1000L*1000L ) ) {
    double span = (double)(nanos-ctx->start_nanos)/1e9;
    FD_LOG_INFO(( "BENCH_SUMMARY slots=%lu span_s=%.3f txns=%lu tps=%.0f max_slot_tps=%lu",
                  ctx->slots, span, txns-ctx->start_txns, (double)(txns-ctx->start_txns)/span, ctx->max_tps ));
    exit( 0 );
  }
  return 0;
}

static inline void
after_credit( fd_bencho_ctx_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;

  int did_work_rpc                = fd_rpc_client_service( ctx->rpc, 0 );
  int did_work_service_block_hash = service_block_hash( ctx, stem );

  *charge_busy = did_work_rpc | did_work_service_block_hash;
}

extern FD_TL fd_alloc_t * g_cjson_alloc_ctx;

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_bencho_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_bencho_ctx_t ), sizeof( fd_bencho_ctx_t ) );
  void * _alloc         = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),           fd_alloc_footprint() );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( alloc );
  cJSON_alloc_install( alloc );

  ctx->mem        = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ctx->rpc_ready_deadline = fd_log_wallclock() + FD_BENCHO_RPC_INITIALIZE_TIMEOUT;
  ctx->blockhash_state    = FD_BENCHO_STATE_READY;
  FD_LOG_NOTICE(( "connecting to RPC server " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( tile->bencho.rpc_ip_addr ), tile->bencho.rpc_port ));
  FD_TEST( fd_rpc_client_join( fd_rpc_client_new( ctx->rpc, tile->bencho.rpc_ip_addr, tile->bencho.rpc_port ) ) );

  ctx->in_mem = NULL;
  if( FD_LIKELY( tile->in_cnt ) ) {   /* replay_out, when the topology has replay */
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ 0 ] ];
    ctx->in_mem = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  } else if( FD_UNLIKELY( tile->bencho.duration_s ) ) {
    FD_LOG_ERR(( "--duration needs a replay tile" ));
  }
  ctx->duration_s  = tile->bencho.duration_s;
  ctx->start_txns  = 0UL;
  ctx->start_nanos = 0L;
  ctx->last_txns   = 0UL;
  ctx->last_nanos  = 0L;
  ctx->slots       = 0UL;
  ctx->max_tps     = 0UL;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST (1UL)
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#define STEM_CALLBACK_CONTEXT_TYPE  fd_bencho_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_bencho_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_bencho = {
  .name              = "bencho",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .loose_footprint   = loose_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};
