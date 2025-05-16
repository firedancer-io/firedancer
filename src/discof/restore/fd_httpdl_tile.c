#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/snapshot/fd_snapshot_http.h"
#include "stream/fd_stream_writer.h"
#include "stream/fd_stream_ctx.h"
#include <unistd.h>

#define NAME "HttpDl"
#define HTTP_CHUNK_SZ 8 * 1024 * 1024UL

struct fd_httpdl_tile {
  fd_snapshot_http_t * http;
  fd_stream_writer_t * writer;
};
typedef struct fd_httpdl_tile fd_httpdl_tile_t;

FD_FN_PURE static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_httpdl_tile_t),
                       fd_ulong_max( fd_snapshot_http_align(), fd_stream_writer_align() ) );
}

FD_FN_PURE static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_httpdl_tile_t), sizeof(fd_httpdl_tile_t) );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_http_align(), fd_snapshot_http_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_httpdl_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_httpdl_tile_t), sizeof(fd_httpdl_tile_t) );
  void * http_mem        = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_http_align(), fd_snapshot_http_footprint() );

  fd_memset( ctx, 0, sizeof(fd_httpdl_tile_t) );

  if( FD_UNLIKELY( !tile->httpdl.dest[0] ) ) {
    FD_LOG_ERR(( "http dest not set" ));
  }

  /* TODO: is null ok for the name? */
  ctx->http = fd_snapshot_http_new( http_mem,
                                    tile->httpdl.dest,
                                    tile->httpdl.ip4,
                                    tile->httpdl.port,
                                    tile->httpdl.snapshot_dir,
                                    NULL );

  fd_snapshot_http_privileged_init( ctx->http );
}

static void
unprivileged_init( fd_topo_t * topo,
                   fd_topo_tile_t * tile ) {
  (void)topo;
  if( FD_UNLIKELY( tile->in_cnt !=0UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 0",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));
}

static void
fd_httpdl_init_from_stream_ctx( void *            _ctx,
                                fd_stream_ctx_t * stream_ctx ) {
  fd_httpdl_tile_t * ctx = fd_type_pun(_ctx);

  /* join writer */
  ctx->writer = fd_stream_writer_join( &stream_ctx->writers[0] );
  fd_stream_writer_set_frag_sz_max( ctx->writer, HTTP_CHUNK_SZ );
}

__attribute__((noreturn)) FD_FN_UNUSED static void
fd_httpdl_shutdown( fd_httpdl_tile_t * ctx ) {
  fd_snapshot_http_cleanup_fds( ctx->http );
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  fd_stream_writer_notify_shutdown( ctx->writer );
  FD_COMPILER_MFENCE();
  FD_LOG_WARNING(("Done downloading snapshot"));

  for(;;) pause();
}

__attribute__((unused)) static void
after_credit_chunk( void *             _ctx,
                    fd_stream_ctx_t *  stream_ctx,
                    int *              opt_poll_in FD_PARAM_UNUSED ) {
  fd_httpdl_tile_t * ctx = fd_type_pun(_ctx);
  (void)stream_ctx;
  ulong downloaded_sz = 0UL;

  /* Don't do anything if backpressured */
  if( FD_UNLIKELY( fd_stream_writer_is_backpressured( ctx->writer ) ) ) {
    return;
  }

  for(;;) {
    if( downloaded_sz >= HTTP_CHUNK_SZ ) {
      fd_stream_writer_publish( ctx->writer, downloaded_sz );
      break;
    }
    /* get write pointers into dcache buffer */
    uchar * out     = fd_stream_writer_get_write_ptr( ctx->writer );
    ulong dst_max   = fd_stream_writer_get_avail_bytes( ctx->writer );
    ulong sz        = 0UL;

    if( dst_max==0 ) {
      fd_stream_writer_publish( ctx->writer, downloaded_sz );
      break;
    }

    int err = fd_io_istream_snapshot_http_read( ctx->http, out, dst_max, &sz );
    if( FD_UNLIKELY( err==1 ) ) fd_httpdl_shutdown( ctx );
    else if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "http err: %d", err ));

    if( sz ) {
      fd_stream_writer_advance( ctx->writer, sz );
      downloaded_sz += sz;
    }
  }
}

__attribute__((unused)) static void
after_credit_stream( void *             _ctx,
                     fd_stream_ctx_t *  stream_ctx,
                     int *              opt_poll_in FD_PARAM_UNUSED ) {
  fd_httpdl_tile_t * ctx = fd_type_pun(_ctx);
  (void)stream_ctx;

  /* Don't do anything if backpressured */
  if( FD_UNLIKELY( fd_stream_writer_is_backpressured( ctx->writer ) ) ) {
    return;
  }

  /* get write pointers into dcache buffer */
  uchar * out     = fd_stream_writer_get_write_ptr( ctx->writer );
  ulong dst_max   = fd_stream_writer_get_avail_bytes( ctx->writer );
  ulong sz        = 0UL;

  int err = fd_io_istream_snapshot_http_read( ctx->http, out, dst_max, &sz );
  if( FD_UNLIKELY( err==1 ) ) fd_httpdl_shutdown( ctx );
  else if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "http err: %d", err ));

  if( FD_LIKELY( sz ) ) {
    fd_stream_writer_advance( ctx->writer, sz );
    fd_stream_writer_publish( ctx->writer, sz );
  }
}

__attribute__((noinline)) static void
fd_httpdl_run1(
  fd_httpdl_tile_t * ctx,
  fd_stream_ctx_t *  stream_ctx ) {

  FD_LOG_INFO(( "Running httpdl tile" ));

  fd_stream_ctx_run( stream_ctx,
                     ctx,
                     fd_httpdl_init_from_stream_ctx,
                     NULL,
                     NULL,
                     NULL,
                     after_credit_stream,
                     NULL );
}

static void
fd_httpdl_run( fd_topo_t *      topo,
               fd_topo_tile_t * tile ) {
  fd_httpdl_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong in_cnt           = fd_topo_tile_producer_cnt( topo, tile );
  ulong out_cnt          = tile->out_cnt;

  void * ctx_mem = fd_alloca( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_scratch_footprint( in_cnt, out_cnt ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile, in_cnt, out_cnt );
  fd_httpdl_run1( ctx, stream_ctx );
}

fd_topo_run_tile_t fd_tile_snapshot_restore_HttpDl = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = fd_httpdl_run,
};

#undef NAME



