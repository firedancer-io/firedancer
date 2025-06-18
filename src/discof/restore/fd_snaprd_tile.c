#include "fd_restore_base.h"
#include "stream/fd_stream_ctx.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "fd_snapshot_archive.h"
#include "fd_snapshot_reader.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define NAME "SnapRd"
#define FILE_READ_MAX 8UL<<20

#define CLUSTER_SNAPSHOT_SLOT 326672166UL
#define PEER1 "http://emfr-ccn-solana-testnet-val2.jumpisolated.com"
#define PEER2 "http://emfr-ccn-solana-testnet-val2.jumpisolated.com:8899"
#define PEER3 "http://emfr-ccn-solana-testnet-val2.jumpisolated.com:8899"

fd_ip4_port_t const peers[ 16UL ] = {
  { .addr = FD_IP4_ADDR( 145, 40, 95, 69 ), .port = 8899 },
  { .addr = FD_IP4_ADDR( 145, 40, 95, 69 ), .port = 8899 },
  { .addr = FD_IP4_ADDR( 145, 40, 95, 69 ), .port = 8899 }
};

struct fd_snaprd_tile {
  fd_stream_writer_t * writer;

  fd_snapshot_archive_entry_t             full_snapshot_entry;
  fd_incremental_snapshot_archive_entry_t incremental_snapshot_entry;

  fd_snapshot_reader_t * snapshot_reader;
  uint                   num_aborts;

  struct {
    char path[ PATH_MAX ];
    int  do_download;
    int  incremental_snapshot_fetch;
    uint maximum_local_snapshot_age;
    uint minimum_download_speed_mib;
    uint maximum_download_retry_abort;
  } config;

  struct {

    struct {
      ulong bytes_read;
      ulong bytes_total;
    } full;

    struct {
      ulong bytes_read;
      ulong bytes_total;
    } incremental;

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
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaprd_tile_t),  sizeof(fd_snaprd_tile_t)       );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_reader_align(), fd_snapshot_reader_footprint() );
  return FD_LAYOUT_FINI( l, alignof(fd_snaprd_tile_t) );
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
  fd_snapshot_reader_delete( ctx->snapshot_reader );

  FD_COMPILER_MFENCE();
  FD_MGAUGE_SET( TILE, STATUS, 2UL );
  FD_COMPILER_MFENCE();

  FD_LOG_INFO(( "snaprd: shutting down" ));

  for(;;) pause();
}

static void
fd_snaprd_on_file_complete( fd_snaprd_tile_t * ctx ) {
  if( ctx->metrics.status == STATUS_FULL && ctx->config.incremental_snapshot_fetch ) {
    fd_snapshot_reader_set_source_incremental( ctx->snapshot_reader );

    FD_LOG_INFO(("snaprd: done reading full snapshot, now reading incremental snapshot, seq is %lu", ctx->writer->seq ));
    fd_snaprd_set_status( ctx, STATUS_INC );
    fd_stream_writer_notify( ctx->writer, 
                             fd_frag_meta_ctl( 1UL, 0, 1, 0 ) );
    fd_stream_writer_reset_stream( ctx->writer );

  } else if( ctx->metrics.status == STATUS_INC || !ctx->config.incremental_snapshot_fetch ) {

    if( ctx->config.incremental_snapshot_fetch ) {
      FD_LOG_INFO(( "snaprd: done reading incremental snapshot!" ));
    } else {
      FD_LOG_INFO(( "snaprd: done reading full snapshot with size %lu", ctx->metrics.full.bytes_total ));
    }

    fd_snaprd_set_status( ctx, STATUS_DONE );
    fd_stream_writer_notify( ctx->writer,
                             fd_frag_meta_ctl( 0UL, 0, 1, 0 ) );
    fd_snaprd_shutdown( ctx );
  } else {
    FD_LOG_ERR(("snaprd: unexpected status"));
  }
}

static void
fd_snaprd_on_abort( fd_snaprd_tile_t * ctx ) {
  ctx->num_aborts++;
  fd_stream_writer_notify( ctx->writer,
                           fd_frag_meta_ctl( 0UL, 0, 0, 1 ) );
  fd_stream_writer_reset_stream( ctx->writer );

  if( FD_UNLIKELY( ctx->num_aborts > ctx->config.maximum_download_retry_abort ) ) {
    /* TODO: should we shutdown or just error out here? */
    fd_snaprd_set_status( ctx, STATUS_FAILED );
    FD_LOG_ERR(( "Hit the maximum number of download retries, aborting." ));
  }
}

static void
fd_snaprd_accumulate_metrics( fd_snaprd_tile_t *             ctx,
                              fd_snapshot_reader_metrics_t * metrics ) {
  if( ctx->metrics.status == STATUS_FULL ) {
    ctx->metrics.full.bytes_read += metrics->bytes_read;
    ctx->metrics.full.bytes_total = metrics->bytes_total;
  } else if( ctx->metrics.status == STATUS_INC ) {
    ctx->metrics.incremental.bytes_read += metrics->bytes_read;
    ctx->metrics.incremental.bytes_total = metrics->bytes_total;
  } else {
    FD_LOG_ERR(("snaprd: unexpected status"));
  }
}

static void
metrics_write( void * _ctx ) {
  fd_snaprd_tile_t * ctx = fd_type_pun( _ctx );
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_READ,         ctx->metrics.full.bytes_read );
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_TOTAL,        ctx->metrics.full.bytes_total );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_READ,  ctx->metrics.incremental.bytes_read );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_TOTAL, ctx->metrics.incremental.bytes_total );
}

static void
fd_snaprd_init_config( fd_snaprd_tile_t * ctx,
                       fd_topo_tile_t *   tile ) {
  fd_memcpy( ctx->config.path, tile->snaprd.snapshots_path, PATH_MAX );
  ctx->config.incremental_snapshot_fetch   = tile->snaprd.incremental_snapshot_fetch;
  ctx->config.do_download                  = tile->snaprd.do_download;
  ctx->config.maximum_download_retry_abort = tile->snaprd.maximum_local_snapshot_age;
  ctx->config.minimum_download_speed_mib   = tile->snaprd.minimum_download_speed_mib;
  ctx->config.maximum_download_retry_abort = tile->snaprd.maximum_download_retry_abort;
}

static int
fd_snaprd_should_download( fd_snaprd_tile_t * ctx ) {
  /* first, check if there are any full local snapshots and get the highest slot */
  int res = fd_snapshot_archive_get_latest_full_snapshot( ctx->config.path,
                                                          &ctx->full_snapshot_entry );

  /* If we don't have any full snapshots in the snapshots archive path, we need to download  */
  if( FD_UNLIKELY( res ) ) {
    FD_LOG_INFO(( "There are no valid local full snapshots in the\
                  snapshots path: %s. Downloading from peers.", ctx->config.path ));
    return 1;
  }

  ulong highest_slot = ctx->full_snapshot_entry.slot;
  if( ctx->config.incremental_snapshot_fetch ) {
    /* Next, get the incremental snapshot entry */
    res = fd_snapshot_archive_get_latest_incremental_snapshot( ctx->config.path,
                                                             &ctx->incremental_snapshot_entry );
    if( FD_UNLIKELY( res ) ) {
      /* there is no incremental snapshot entry */
      FD_LOG_INFO(( "There are no valid local incremental snapshots\
                    in the snapshots path %s. Downloading from peers.", ctx->config.path ));
      return 1;
    }

    /* Validate the incremental snapshot builds off the full snapshot */
    if( ctx->incremental_snapshot_entry.base_slot != ctx->full_snapshot_entry.slot ) {
      FD_LOG_INFO(( "Local incremental snapshot at slot %lu does not build off the full snapshot at slot %lu.\
                    Downloading from peers.", 
                    ctx->incremental_snapshot_entry.inner.slot, 
                    ctx->full_snapshot_entry.slot ));
      fd_memset( &ctx->incremental_snapshot_entry, 0, sizeof(fd_incremental_snapshot_archive_entry_t) );
      return 1;
    }

    highest_slot = ctx->incremental_snapshot_entry.inner.slot;
  }

  /* Check that the snapshot age is within the maximum local snapshot age */
  if( highest_slot >= fd_ulong_sat_sub( CLUSTER_SNAPSHOT_SLOT, ctx->config.maximum_local_snapshot_age ) ) {
    FD_LOG_INFO(( "Re-using local snapshots at slot %lu", ctx->full_snapshot_entry.slot ));
    return 0;
  } else {
    FD_LOG_INFO(( "Local snapshot at slot %lu is too old. ", ctx->full_snapshot_entry.slot ));
    fd_memset( &ctx->full_snapshot_entry, 0, sizeof(fd_snapshot_archive_entry_t) );
    return 1;
  }
}

static void
fd_snaprd_init( fd_snaprd_tile_t * ctx,
                void *             snapshot_reader_mem ) {
  int download = fd_snaprd_should_download( ctx );

  if( download && !ctx->config.do_download ) {
    FD_LOG_ERR(( "There are no valid local snapshots and the validator was configured to not download snapshots.\
                      Please reconfigure the validator to enable snapshot downloading by setting [snapshots.do_download] to true." ));
  }

  if( download ) {
    /* configure snaprd tile with download configuration, including peer ip, port, etc. */
    FD_LOG_ERR(("I can't support this yet!"));
  }
  else {
    FD_LOG_WARNING(("booting snapshot reader with local snapshots"));
    ctx->snapshot_reader = fd_snapshot_reader_new_local( snapshot_reader_mem,
                                                         &ctx->full_snapshot_entry,
                                                         &ctx->incremental_snapshot_entry,
                                                         ctx->config.incremental_snapshot_fetch );
  }

}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snaprd_tile_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t), sizeof(fd_snaprd_tile_t) );
  void * snapshot_reader_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_reader_align(), fd_snapshot_reader_footprint() );
  fd_memset( ctx, 0, sizeof(fd_snaprd_tile_t) );

  fd_snaprd_init_config( ctx, tile );

  fd_snaprd_init( ctx, snapshot_reader_mem );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  (void)topo;
  if( FD_UNLIKELY( tile->in_cnt !=0UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 0",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  fd_snaprd_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ctx->metrics.full.bytes_read         = 0UL;
  ctx->metrics.incremental.bytes_read  = 0UL;

  fd_snaprd_set_status( ctx, STATUS_FULL );
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
  ulong   sz      = 0UL;

  fd_snapshot_reader_metrics_t metrics =
    fd_snapshot_reader_read( ctx->snapshot_reader, out, out_max, &sz );

  if( metrics.status == FD_SNAPSHOT_READER_DONE ) {
    fd_snaprd_on_file_complete( ctx );
  } else if( metrics.status == FD_SNAPSHOT_READER_ABORT ) {
    fd_snaprd_on_abort( ctx );
  }

  fd_stream_writer_publish( ctx->writer, sz, 0UL );
  fd_snaprd_accumulate_metrics( ctx, &metrics );
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
