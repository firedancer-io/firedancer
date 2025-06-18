#include "fd_accdb_tile.h"
#include "../../disco/tiles.h"

#include "generated/fd_accdb_tile_seccomp.h"

#include "../../disco/metrics/fd_metrics.h"

#include "fd_accdb.h"

#include <fcntl.h>
#include <errno.h>

struct fd_accdb_tile_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_accdb_tile_in fd_accdb_tile_in_t;

struct fd_accdb_tile_ctx {
  int fd;

  int idle;
  fd_accdb_t * accdb;

  ulong seed;

  fd_accdb_tile_in_t in[ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
};

typedef struct fd_accdb_tile_ctx fd_accdb_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_accdb_tile_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),               fd_accdb_footprint( tile->accdb.max_accounts, tile->accdb.max_unrooted_slots, tile->accdb.cache_footprint ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_accdb_tile_ctx_t * ctx ) {
  fd_accdb_metrics_t const * metrics = fd_accdb_metrics( ctx->accdb );

  FD_MGAUGE_SET( ACCDB, ACCOUNTS_TOTAL,         metrics->accounts_total );
  FD_MGAUGE_SET( ACCDB, ACCOUNTS_CAPACITY,      metrics->accounts_capacity );
  FD_MCNT_SET( ACCDB, BYTES_READ,               metrics->bytes_read );
  FD_MCNT_SET( ACCDB, BYTES_WRITTEN,            metrics->bytes_written );
  FD_MCNT_SET( ACCDB, ACCOUNTS_READ,            metrics->accounts_read );
  FD_MCNT_SET( ACCDB, ACCOUNTS_WRITTEN,         metrics->accounts_written );
  FD_MCNT_SET( ACCDB, ACCOUNTS_RELOCATED,       metrics->accounts_relocated );
  FD_MGAUGE_SET( ACCDB, DISK_ALLOCATED_BYTES,   metrics->disk_allocated_bytes );
  FD_MGAUGE_SET( ACCDB, DISK_USED_BYTES,        metrics->disk_used_bytes );
  FD_MGAUGE_SET( ACCDB, IN_COMPACTION,          (ulong)metrics->in_compaction );
  FD_MCNT_SET( ACCDB, COMPACTIONS_REQUESTED,    metrics->compactions_requested );
  FD_MCNT_SET( ACCDB, COMPACTIONS_COMPLETED,    metrics->compactions_completed );
  FD_MCNT_SET( ACCDB, ACCOUNTS_RELOCATED_BYTES, metrics->accounts_relocated_bytes );
}

static inline void
before_credit( fd_accdb_tile_ctx_t * ctx,
               fd_stem_context_t *   stem FD_FN_UNUSED,
               int *                 charge_busy ) {
  if( FD_UNLIKELY( ctx->idle ) ) fd_accdb_compact( ctx->accdb, charge_busy );
  ctx->idle = 1;
}

static inline void
during_frag( fd_accdb_tile_ctx_t * ctx,
             ulong                 in_idx,
             ulong                 seq FD_PARAM_UNUSED,
             ulong                 sig,
             ulong                 chunk,
             ulong                 sz,
             ulong                 ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  ctx->idle = 0;

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );

  switch( sig ) {
    case FD_ACCDB_OP_READ: {
      FD_TEST( sz==sizeof( fd_accdb_read_request_t ) );
      fd_accdb_read_request_t * req = (fd_accdb_read_request_t *)src;
      fd_accdb_read_response_t * resp = (fd_accdb_read_response_t *)dst;
      fd_accdb_read( ctx->accdb, req->slot, req->pubkey, &resp->lamports, (uchar *)(resp+1UL), &resp->data_len, resp->owner );
      break;
    }
    case FD_ACCDB_OP_WRITE: {
      FD_TEST( sz>=sizeof( fd_accdb_write_request_t ) );
      fd_accdb_write_request_t * req = (fd_accdb_write_request_t *)src;
      FD_TEST( sz==sizeof( fd_accdb_write_request_t )+req->data_len );
      fd_accdb_write( ctx->accdb, req->slot, req->pubkey, req->lamports, (uchar *)(req+1UL), req->data_len, req->owner );
      break;
    }
    case FD_ACCDB_OP_BEGIN: {
      FD_TEST( sz==sizeof( fd_accdb_begin_t ) );
      fd_accdb_begin_t * req = (fd_accdb_begin_t *)src;
      fd_accdb_attach_child( ctx->accdb, req->slot, req->parent_slot );
      break;
    }
    case FD_ACCDB_OP_ROOT: {
      FD_TEST( sz==sizeof( fd_accdb_root_t ) );
      fd_accdb_root_t * req = (fd_accdb_root_t *)src;
      fd_accdb_root( ctx->accdb, req->slot );
      break;
    }
    case FD_ACCDB_OP_PURGE: {
      FD_TEST( sz==sizeof( fd_accdb_purge_t ) );
      fd_accdb_purge_t * req = (fd_accdb_purge_t *)src;
      fd_accdb_purge( ctx->accdb, req->slot );
      break;
    }
    default: 
      FD_LOG_ERR(( "unexpected accounts db operation %lu", sig ));
  }
}

static inline void
after_frag( fd_accdb_tile_ctx_t * ctx,
            ulong                 in_idx FD_PARAM_UNUSED,
            ulong                 seq FD_PARAM_UNUSED,
            ulong                 sig,
            ulong                 sz FD_PARAM_UNUSED,
            ulong                 tsorig FD_PARAM_UNUSED,
            ulong                 _tspub FD_PARAM_UNUSED,
            fd_stem_context_t *   stem ) {
  switch( sig ) {
    case FD_ACCDB_OP_READ:
      break;
    case FD_ACCDB_OP_WRITE:
    case FD_ACCDB_OP_BEGIN:
    case FD_ACCDB_OP_ROOT:
    case FD_ACCDB_OP_PURGE:
      return;
    default: 
      FD_LOG_ERR(( "unexpected accounts db operation %lu", sig ));
  }

  fd_accdb_read_response_t * dst = (fd_accdb_read_response_t *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, 0, ctx->out_chunk, sizeof(fd_accdb_read_response_t)+dst->data_len, 0UL, tsorig, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_accdb_read_response_t)+dst->data_len, ctx->out_chunk0, ctx->out_wmark );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_accdb_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );
  FD_TEST( fd_rng_secure( &ctx->seed, 8U ) );

  ctx->fd = open( tile->accdb.path, O_RDWR|O_TRUNC|O_CREAT|O_CLOEXEC, 0644 );
  if( FD_UNLIKELY( ctx->fd<0 ) ) {
    FD_LOG_ERR(( "failed to open accounts database file %s (%d-%s)", tile->accdb.path, errno, fd_io_strerror( errno ) ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_accdb_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );
  ctx->accdb = fd_accdb_join( fd_accdb_new( FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(), fd_accdb_footprint( tile->accdb.max_accounts, tile->accdb.max_unrooted_slots, tile->accdb.cache_footprint ) ), tile->accdb.max_accounts, tile->accdb.max_unrooted_slots, tile->accdb.cache_footprint, ctx->seed ), ctx->fd );
  FD_TEST( ctx->accdb );

  ctx->idle = 0;

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].mtu    = link->mtu;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_accdb_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );

  populate_sock_filter_policy_fd_accdb_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->fd );
  return sock_filter_policy_fd_accdb_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_accdb_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->fd; /* accounts db fd */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_accdb_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_accdb_tile_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_accdb = {
  .name                     = "accdb",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
