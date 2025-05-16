#include "fd_restore_base.h"
#include "stream/fd_stream_ctx.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define NAME "FileRd"
#define FILE_READ_MAX 8UL<<20

struct fd_filerd_tile {
  fd_stream_writer_t * writer;
  int                  fd;
};

typedef struct fd_filerd_tile fd_filerd_tile_t;

static ulong
scratch_align( void ) {
  return alignof(fd_filerd_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_filerd_tile_t);
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_filerd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_memset( ctx, 0, sizeof(fd_filerd_tile_t) );

  if( FD_UNLIKELY( !tile->filerd.file_path[0] ) ) FD_LOG_ERR(( "File path not set" ));
  ctx->fd = open( tile->filerd.file_path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( ctx->fd<0 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  (void)topo;
  if( FD_UNLIKELY( tile->in_cnt !=0UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 0",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));
}

static void
fd_filerd_init_from_stream_ctx( void *            _ctx,
                                fd_stream_ctx_t * stream_ctx ) {
  fd_filerd_tile_t * ctx = fd_type_pun(_ctx);

  /* TODO: this should be a join */
  ctx->writer = &stream_ctx->writers[0];
  fd_stream_writer_set_read_max( ctx->writer, FILE_READ_MAX );
}

__attribute__((noreturn)) FD_FN_UNUSED static void
fd_filerd_shutdown( fd_filerd_tile_t * ctx ) {
  if( FD_UNLIKELY( close( ctx->fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->fd = -1;
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  fd_stream_writer_notify_shutdown( ctx->writer );
  FD_COMPILER_MFENCE();
  FD_LOG_INFO(( "Reached end of file" ));

  for(;;) pause();
}

static void
after_credit( void *            _ctx,
              fd_stream_ctx_t * stream_ctx,
              int *             poll_in FD_PARAM_UNUSED ) {
  fd_filerd_tile_t * ctx = fd_type_pun(_ctx);
  (void)stream_ctx;

  /* technically, this is not needed because fd_stream_ctx_run_loop
     checks for backpresure on all outgoing links and there is only one
     outgoing link anyways. But, it is added for clarity that
     callbacks should handle backpressure for their out links. */
  if( FD_UNLIKELY( fd_stream_writer_is_backpressured( ctx->writer ) ) ) {
    return;
  }

  int fd = ctx->fd;
  if( FD_UNLIKELY( fd<0 ) ) return;

  uchar * out   = fd_stream_writer_get_write_ptr( ctx->writer );
  ulong dst_max = fd_stream_writer_get_avail_bytes( ctx->writer );

  long res = read( fd, out, dst_max );
  if( FD_UNLIKELY( res<=0L ) ) {
    if( FD_UNLIKELY( res==0 ) ) {
      fd_filerd_shutdown( ctx );
      return;
    }
    if( FD_LIKELY( errno==EAGAIN ) ) return;
    FD_LOG_ERR(( "readv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    /* aborts app */
  }

  ulong sz = (ulong)res;
  if( FD_LIKELY( sz ) ) {
    fd_stream_writer_advance( ctx->writer, sz );
    fd_stream_writer_publish( ctx->writer, sz );
  }
}

__attribute__((noinline)) static void
fd_filerd_run1( fd_filerd_tile_t *         ctx,
                fd_stream_ctx_t *          stream_ctx ) {
  FD_LOG_INFO(( "Running filerd tile" ));

  fd_stream_ctx_run( stream_ctx,
                     ctx,
                     fd_filerd_init_from_stream_ctx,
                     NULL,
                     NULL,
                     NULL,
                     after_credit,
                     NULL );
}

static void
fd_filerd_run( fd_topo_t *        topo,
               fd_topo_tile_t *   tile ) {
  fd_filerd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong in_cnt           = fd_topo_tile_producer_cnt( topo, tile );
  ulong out_cnt          = tile->out_cnt;

  void * ctx_mem = fd_alloca( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_scratch_footprint( in_cnt, out_cnt ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile, in_cnt, out_cnt );
  fd_filerd_run1( ctx, stream_ctx );
}

fd_topo_run_tile_t fd_tile_snapshot_restore_FileRd = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = fd_filerd_run,
};

#undef NAME
