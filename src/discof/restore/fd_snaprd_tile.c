#include "fd_restore_base.h"
#include "stream/fd_stream_ctx.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define NAME "SnapRd"
#define FILE_READ_MAX 8UL<<20

#define SNAP_RD_STATUS_WAITING 0UL
#define SNAP_RD_STATUS_FULL    1UL
#define SNAP_RD_STATUS_INC     2UL
#define SNAP_RD_STATUS_DONE    3UL

struct fd_snaprd_tile {
  fd_stream_writer_t * writer;
  int                  full_fd;
  int                  inc_fd;
  int                  curr_fd;

  struct {
    ulong full_bytes_read;
    ulong full_bytes_total;
    ulong incremental_bytes_read;
    ulong incremental_bytes_total;
    ulong status;
  } metrics;
};

typedef struct fd_snaprd_tile fd_snaprd_tile_t;

static ulong
scratch_align( void ) {
  return alignof(fd_snaprd_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_snaprd_tile_t);
}

static void
fd_snaprd_close_fd( int * fd ) {
  if( FD_UNLIKELY( close( *fd ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  *fd = -1;
}

static void
fd_snaprd_set_status( fd_snaprd_tile_t * ctx,
                      ulong              status ) {
  ctx->metrics.status = status;
  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( SNAPRD, STATUS, status );
  FD_COMPILER_MFENCE();
}

__attribute__((noreturn)) FD_FN_UNUSED static void
fd_snaprd_shutdown( fd_snaprd_tile_t * ctx ) {
  fd_snaprd_close_fd( &ctx->full_fd );
  fd_snaprd_close_fd( &ctx->inc_fd );

  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_COMPILER_MFENCE();

  FD_LOG_INFO(( "snaprd: shutting down" ));

  for(;;) pause();
}

static void
fd_snaprd_on_file_complete( fd_snaprd_tile_t * ctx ) {
  if( ctx->metrics.status == SNAP_RD_STATUS_FULL ) {
    ctx->curr_fd = ctx->inc_fd;

    FD_LOG_INFO(("snaprd: done reading full snapshot, now reading incremental snapshot, seq is %lu", ctx->writer->seq ));
    fd_snaprd_set_status( ctx, SNAP_RD_STATUS_INC );
    fd_stream_writer_notify( ctx->writer, 
                             fd_frag_meta_ctl( 0UL, 0, 1, 0 ) );
    fd_stream_writer_reset_stream( ctx->writer );

  } else if( ctx->metrics.status == SNAP_RD_STATUS_INC ) {

    FD_LOG_INFO(( "snaprd: done reading incremental snapshot!" ));
    fd_snaprd_set_status( ctx, SNAP_RD_STATUS_DONE );
    fd_stream_writer_notify( ctx->writer,
                             fd_frag_meta_ctl( 0UL, 0, 1, 0 ) );
    fd_snaprd_shutdown( ctx );
  } else {
    FD_LOG_ERR(("snaprd: unexpected status"));
  }
}

static void
metrics_write( void * _ctx ) {
  fd_snaprd_tile_t * ctx = fd_type_pun( _ctx );
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_READ, ctx->metrics.full_bytes_read );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_TOTAL, ctx->metrics.full_bytes_total );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_TOTAL, ctx->metrics.incremental_bytes_total );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_snaprd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_memset( ctx, 0, sizeof(fd_snaprd_tile_t) );

  if( FD_UNLIKELY( !tile->snaprd.full_snapshot_path[0] ) ) FD_LOG_ERR(( "Full snapshot path not set" ));
  ctx->full_fd = open( tile->snaprd.full_snapshot_path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( ctx->full_fd<0 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( !tile->snaprd.incremental_snapshot_path[0] ) ) FD_LOG_ERR(( "Incremental snapshot path not set" ));
  ctx->inc_fd = open( tile->snaprd.incremental_snapshot_path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( ctx->inc_fd<0 ) ) FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct stat full_stat;
  if( FD_UNLIKELY( 0!=fstat( ctx->full_fd, &full_stat ) ) ) {
    FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->metrics.full_bytes_total = (ulong)full_stat.st_size;

  struct stat inc_stat;
  if( FD_UNLIKELY( 0!=fstat( ctx->inc_fd, &inc_stat ) ) ) {
    FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ctx->metrics.incremental_bytes_total = (ulong)inc_stat.st_size;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  (void)topo;
  if( FD_UNLIKELY( tile->in_cnt !=0UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 0",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  fd_snaprd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ctx->curr_fd                         = ctx->full_fd;
  ctx->metrics.full_bytes_read         = 0UL;
  ctx->metrics.full_bytes_total        = 0UL;
  ctx->metrics.incremental_bytes_read  = 0UL;
  ctx->metrics.incremental_bytes_total = 0UL;

  fd_snaprd_set_status( ctx, SNAP_RD_STATUS_FULL );
}

static void
fd_snaprd_init_from_stream_ctx( void *            _ctx,
                                fd_stream_ctx_t * stream_ctx ) {
  fd_snaprd_tile_t * ctx = _ctx;
  ctx->writer = fd_stream_writer_join( stream_ctx->writers[0] );
  FD_TEST( ctx->writer );
  fd_stream_writer_set_frag_sz_max( ctx->writer, FILE_READ_MAX );
}

static void
after_credit( void *            _ctx,
              fd_stream_ctx_t * stream_ctx,
              int *             poll_in FD_PARAM_UNUSED ) {
  fd_snaprd_tile_t * ctx = _ctx;
  (void)stream_ctx;

  uchar * out     = fd_stream_writer_prepare( ctx->writer );
  ulong   out_max = fd_stream_writer_publish_sz_max( ctx->writer );

  /* technically, this is not needed because fd_stream_ctx_run_loop
     checks for backpresure on all outgoing links and there is only one
     outgoing link anyways. But, it is added for clarity that
     callbacks should handle backpressure for their out links. */
  if( FD_UNLIKELY( !out_max ) ) return;

  int fd = ctx->curr_fd;
  if( FD_UNLIKELY( fd<0 ) ) return;

  long res = read( fd, out, out_max );
  if( FD_UNLIKELY( res<=0L ) ) {
    if( FD_UNLIKELY( res==0 ) ) {
      fd_snaprd_on_file_complete( ctx );
      return;
    }
    if( FD_LIKELY( errno==EAGAIN ) ) return;
    FD_LOG_ERR(( "readv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    /* aborts app */
  }

  fd_stream_writer_publish( ctx->writer, (ulong)res, 0UL );
  ctx->metrics.full_bytes_read += (ulong)res;
}

__attribute__((noinline)) static void
fd_snaprd_run1( fd_snaprd_tile_t *         ctx,
                fd_stream_ctx_t *          stream_ctx ) {
  FD_LOG_INFO(( "Running snaprd tile" ));

  fd_stream_ctx_run( stream_ctx,
                     ctx,
                     fd_snaprd_init_from_stream_ctx,
                     NULL,
                     NULL,
                     metrics_write,
                     after_credit,
                     NULL );
}

static void
fd_snaprd_run( fd_topo_t *        topo,
               fd_topo_tile_t *   tile ) {
  fd_snaprd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  void * ctx_mem = fd_alloca_check( FD_STEM_SCRATCH_ALIGN, fd_stream_ctx_footprint( topo, tile ) );
  fd_stream_ctx_t * stream_ctx = fd_stream_ctx_new( ctx_mem, topo, tile );
  fd_snaprd_run1( ctx, stream_ctx );
}

fd_topo_run_tile_t fd_tile_snapshot_restore_SnapRd = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = fd_snaprd_run,
};

#undef NAME
