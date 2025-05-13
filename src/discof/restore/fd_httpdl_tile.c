#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/snapshot/fd_snapshot_http.h"
#include "stream/fd_stream_writer.h"
#include "stream/fd_stream_ctx.h"
#include <unistd.h>

#define NAME "http"

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
  ctx->writer            = FD_SCRATCH_ALLOC_APPEND( l, fd_stream_writer_align(), fd_stream_writer_footprint() );

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
fd_httpdl_init_from_stream_ctx( void * _ctx,
                                fd_stream_ctx_t * stream_ctx ) {
  fd_httpdl_tile_t * ctx = fd_type_pun(_ctx);

  /* There's only one writer */
  ctx->writer = &stream_ctx->writers[0];
}

static void
during_housekeeping( void * _ctx,
                     fd_stream_ctx_t *  stream_ctx ) {
  (void)_ctx;
  (void)stream_ctx;
}

static void
metrics_write( fd_httpdl_tile_t * ctx ) {
  (void)ctx;
}

__attribute__((noreturn)) FD_FN_UNUSED static void
fd_httpdl_shutdown( fd_httpdl_tile_t * ctx ) {
  fd_snapshot_http_cleanup_fds( ctx->http );
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_COMPILER_MFENCE();
  FD_LOG_WARNING(("Done downloading snapshot"));

  for(;;) pause();
}

__attribute__((noinline)) static void
fd_httpdl_run1(
  fd_httpdl_tile_t * ctx,
  fd_stream_ctx_t *  stream_ctx ) {

  FD_LOG_INFO(( "Running httpdl tile" ));

  fd_stream_ctx_init_run_loop( stream_ctx, ctx, fd_httpdl_init_from_stream_ctx );
  for(;;) {
    fd_stream_ctx_do_housekeeping( stream_ctx,
                                   ctx,
                                   NULL,
                                   during_housekeeping,
                                   NULL );

    /* Check if we are backpressured, otherwise poll */
    if( FD_UNLIKELY( fd_stream_writer_is_backpressured( ctx->writer ) ) ) {
      fd_stream_ctx_process_backpressure( stream_ctx );
    } else {
      after_credit( ctx );
    }
  }
}

fd_topo_run_tile_t fd_tile_snapshot_restore_HttpDl = {
    .name              = NAME,
    .scratch_align     = scratch_align,
    .scratch_footprint = scratch_footprint,
    .privileged_init   = privileged_init,
    .run               = fd_httpdl_run,
};

#undef NAME



