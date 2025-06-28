// fd_consumer_tile.c
#include "../../../../disco/topo/fd_topo.h"

struct fd_consumer_tile_ctx {
  void * in_base;  // Base address of input workspace to read data
  ulong  fragments_received;
  ulong  last_counter_seen;
  long   last_receive_time;  // Time when last fragment was received
};
typedef struct fd_consumer_tile_ctx fd_consumer_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_consumer_tile_ctx_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_consumer_tile_ctx_t);
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_consumer_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  
  // Get workspace base for reading data chunks
  if( tile->in_cnt > 0 ) {
    ulong link_id = tile->in_link_id[0];
    ulong dcache_obj_id = topo->links[link_id].dcache_obj_id;
    ulong wksp_id = topo->objs[dcache_obj_id].wksp_id;
    ctx->in_base = topo->workspaces[wksp_id].wksp;
  }
  
  ctx->fragments_received = 0UL;
  ctx->last_counter_seen = 0UL;
  ctx->last_receive_time = 0L;
}

static void
during_frag( fd_consumer_tile_ctx_t * ctx,
             ulong                    in_idx,
             ulong                    seq,
             ulong                    sig,
             ulong                    chunk,
             ulong                    sz,
             ulong                    ctl ) {
  (void)in_idx; (void)seq; (void)sig; (void)sz; (void)ctl;
  
  long now = fd_log_wallclock();
  
  // Read the counter value from the fragment
  uchar * data = fd_chunk_to_laddr( ctx->in_base, chunk );
  ulong counter = FD_LOAD( ulong, data );
  
  ctx->fragments_received++;
  ctx->last_counter_seen = counter;
  
  // Calculate time difference from last message
  long time_diff_ns = 0L;
  if( ctx->last_receive_time > 0L ) {
    time_diff_ns = now - ctx->last_receive_time;
  }
  ctx->last_receive_time = now;
  
  // Log every fragment to show timing information
  if( ctx->fragments_received == 1UL ) {
    FD_LOG_NOTICE(( "Consumer received first fragment %lu with counter %lu at time %ld", 
                    ctx->fragments_received, counter, now ));
  } else {
    double time_diff_sec = (double)time_diff_ns / 1e9;
    FD_LOG_NOTICE(( "Consumer received fragment %lu with counter %lu at time %ld (%.3f seconds since last)", 
                    ctx->fragments_received, counter, now, time_diff_sec ));
  }
}

#define STEM_BURST (1UL)
#define STEM_ALWAYS_SPINNING (0)
#define STEM_CALLBACK_CONTEXT_TYPE fd_consumer_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_consumer_tile_ctx_t)
#define STEM_CALLBACK_DURING_FRAG during_frag
#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_consum = {
  .name              = "consum",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};