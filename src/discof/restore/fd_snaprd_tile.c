#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "utils/fd_snapshot_messages_internal.h"
#include "utils/fd_snapshot_archive.h"
#include "utils/fd_ssping.h"
#include "utils/fd_sshttp.h"

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#define NAME "snaprd"

/* The snaprd tile at a high level is a state machine that downloads
   snapshots from the network or reads snapshots from disk and produces
   a byte stream that is parsed by downstream snapshot consumer tiles.
   The snaprd tile gathers the latest SnapshotHashes information from
   gossip to decide whether to download snapshots or read local
   snapshots from disk.  If the snaprd tile needs to download a snapshot,
   it goes through the process of discovering and selecting elegible
   peers from gossip to download from. */

/* The initial state is waiting for peer ContactInfo and SnapshotHashes
   to arrive from the gossip tile.  These gossip messages arrive over
   time in a non-deterministic order, so there is not a clear indicator
   when we have all such messages.

   If snaprd receives at least one valid gossip peer, it will transition
   to COLLECTING_PEERS, where it will wait a fixed duration to wait for
   additional gossip peers to arrive.  */
#define FD_SNAPRD_STATE_WAITING_FOR_PEERS                    ( 0)

/* snaprd waits until it sees a single valid gossip peer which we could
   download a snapshot from, and then waits a further fixed duration
   before transitioning to peer selection.  If no single peer has been
   received, or all received peers are invalid, snaprd will stay in the
   waiting state indefinitely.

   If there are elegible peers and at least one known validator peer and
   there exists a local snapshot whose slot is recent enough compared to
   the collected SnapshotHashes slot numbers, snaprd transitions to
   loading a snapshot from disk.

   If there are elegible peers and at least one known validator peer
   and no local snapshot is recent enough, snaprd transitions to
   FULL_DOWNLOAD. */
#define FD_SNAPRD_STATE_COLLECTING_PEERS                     ( 1)

/* If SnapRd has decided to load the full snapshot from a local file, it
   can now begin reading it.  This choice is not reversible, and so any
   error encountered while reading the file will abort the boot process,
   rather than retrying from gossip.  Once the full snapshot is loaded,
   SnapRd may optionally load an incremental snapshot or due to
   configuration simply transition to the WAITING_FOR_LOAD stage. */
#define FD_SNAPRD_STATE_READING_FULL_FILE                    ( 2)

/* Optionally, after loading the full snapshot SnapRd loads the
   incremental snapshot from a local file.  This is also not reversible,
   and any error encountered while reading the file will abort the boot
   process, rather than retrying from gossip.  Once the incremental
   snapshot is loaded, the tile will transition to the WAITING_FOR_LOAD
   state. */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_FILE             ( 3)

/* Once SnapRd has decided to download from a peer, it can begin to
   download the full snapshot from them.  This choice is still
   reversible if the peer turns out to be downloading to slow, or goes
   offline, or serves something corrupt, or we hit some other transient
   networking issue.  Once the full snapshot is downloaded, we may
   optionally download an incremental snapshot, or otherwise proceed to
   the WAITING_FOR_LOAD state. */
#define FD_SNAPRD_STATE_FULL_DOWNLOAD                        ( 4)

/* Optionally, after downloading the full snapshot we can now download
   the incremental snapshot from the same peer.  The choice to continue
   from the same peer is arbitrary, but we may later switch if the peer
   goes down or encounters an issue with the incremental snapshot.  This
   download is therefore reversible, and any error encountered while
   downloading the file will mark the peer as invalid, and transition to
   the PINGING_PEERS_INCREMENTAL state.  Once the incremental download
   successfully completes, the tile will transition to the
   WAITING_FOR_LOAD state. */
#define FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD                 ( 5)

/* Once we have fully downloaded the full snapshot, and there is no
   following incremental snapshot, we are almost done, except that the
   load may fail later in the pipeline due to a decompression
   corruption, corrupt file, or some invalid account state.  If such a
   failure happens, we may wish to retry the process, by going back to
   the PINGING_PEERS state.  Once the full snapshot is successfully
   fully loaded, the tile will transition to the DONE state and
   shutdown. */
#define FD_SNAPRD_STATE_FULL_FLUSH                           ( 6)

/* Once we have fully downloaded an incremental snapshot, we are almost
   done except that the load may fail later in the pipeline due to a
   decompression corruption, corrupt file, or some invalid account
   state.  If such a failure happens, we may wish to retry the process,
   by going back to the PINGING_PEERS_INCREMENTAL state.  Once the
   incremental snapshot is successfully fully loaded, the tile will
   transition to the DONE state and shutdown. */
#define FD_SNAPRD_STATE_INCREMENTAL_FLUSH                    ( 7)

/* The terminal state of the tile, snapshot load is completed and
   the tile has exited. */
#define FD_SNAPRD_STATE_DONE                                 ( 8)

#define CLUSTER_SNAPSHOT_SLOT 0

struct fd_snaprd_tile {
  fd_ssping_t * ssping;
  fd_sshttp_t * sshttp;

  int  state;
  long deadline_nanos;

  fd_ip4_port_t addr;
  int fd;

  fd_full_snapshot_archive_entry_t        full_snapshot_entry;
  fd_incremental_snapshot_archive_entry_t incremental_snapshot_entry;

  struct {
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
      uint  num_retries;
    } full;

    struct {
      ulong bytes_read;
      ulong bytes_total;
      uint  num_retries;
    } incremental;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } out;
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaprd_tile_t), sizeof(fd_snaprd_tile_t)       );
  l = FD_LAYOUT_APPEND( l, fd_sshttp_align(),         fd_sshttp_footprint()          );
  l = FD_LAYOUT_APPEND( l, fd_ssping_align(),         fd_ssping_footprint( 65536UL ) );
  return FD_LAYOUT_FINI( l, alignof(fd_snaprd_tile_t) );
}

static void
metrics_write( fd_snaprd_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_READ,               ctx->metrics.full.bytes_read );
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_TOTAL,              ctx->metrics.full.bytes_total );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_READ,        ctx->metrics.incremental.bytes_read );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_TOTAL,       ctx->metrics.incremental.bytes_total );
  FD_MGAUGE_SET( SNAPRD, FULL_DOWNLOAD_RETRIES,         ctx->metrics.full.num_retries );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_DOWNLOAD_RETRIES,  ctx->metrics.incremental.num_retries );

  FD_MGAUGE_SET( SNAPRD, STATE, (ulong)ctx->state );
}

static void
read_file_data( fd_snaprd_tile_t *  ctx,
                fd_stem_context_t * stem ) {
  uchar * out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );

  long result = read( ctx->fd, out, ctx->out.mtu );
  if( FD_UNLIKELY( -1==result && errno==EAGAIN ) ) return;
  else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  switch( ctx->state ) {
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:
      ctx->metrics.incremental.bytes_read += (ulong)result;
      break;
    case FD_SNAPRD_STATE_READING_FULL_FILE:
      ctx->metrics.full.bytes_read += (ulong)result;
      break;
    default:
      break;
  }

  if( FD_UNLIKELY( !result ) ) {
    switch( ctx->state ) {
      case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_INCREMENTAL_FLUSH;
        FD_LOG_NOTICE(( "Waiting for incremental snapshot to fully load" ));
        FD_MGAUGE_SET( TILE, STATUS, 2UL ); /* TODO: Remove */
        break;
      case FD_SNAPRD_STATE_READING_FULL_FILE:
        if( FD_LIKELY( ctx->config.incremental_snapshot_fetch ) ) {
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_FULL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_FILE;
        } else {
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI, 0UL, 0UL, 0UL, 0UL, 0UL );
          // ctx->state = FD_SNAPRD_STATE_FULL_FLUSH;
          FD_LOG_NOTICE(( "Waiting for full snapshot to fully load" ));
          FD_MGAUGE_SET( TILE, STATUS, 2UL ); /* TODO: Remove */
        }
        break;
      default:
        break;
    }
    return;
  }
  
  fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out.chunk, (ulong)result, 0UL, 0UL, 0UL );
  ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, (ulong)result, ctx->out.chunk0, ctx->out.wmark );
}

static void
read_http_data( fd_snaprd_tile_t *  ctx,
                fd_stem_context_t * stem,
                long                now ) {
  uchar * out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );

  ulong data_len = ctx->out.mtu;
  int result = fd_sshttp_advance( ctx->sshttp, &data_len, out, now );

  switch( result ) {
    case FD_SSHTTP_ADVANCE_AGAIN: break;
    case FD_SSHTTP_ADVANCE_ERROR: {
      FD_LOG_NOTICE(( "Error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                     FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
      fd_ssping_invalidate( ctx->ssping, ctx->addr, now );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RETRY, 0UL, 0UL, 0UL, 0UL, 0UL );
      ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
      ctx->deadline_nanos = now;
      break;
    }
    case FD_SSHTTP_ADVANCE_DONE: {
      switch( ctx->state ) {
        case FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD:
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_INCREMENTAL_FLUSH;
          FD_LOG_NOTICE(( "Waiting for incremental snapshot to fully load" ));
          FD_MGAUGE_SET( TILE, STATUS, 2UL ); /* TODO: Remove */
          break;
        case FD_SNAPRD_STATE_FULL_DOWNLOAD:
          if( FD_LIKELY( ctx->config.incremental_snapshot_fetch ) ) {
            FD_LOG_NOTICE(( "Downloading incremental snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
            fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_FULL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
            ctx->state = FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD;
            fd_sshttp_init( ctx->sshttp, ctx->addr, "/incremental-snapshot.tar.bz2", 29UL, now );
          } else {
            fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_FINI, 0UL, 0UL, 0UL, 0UL, 0UL );
            ctx->state = FD_SNAPRD_STATE_FULL_FLUSH;
            FD_LOG_NOTICE(( "Waiting for full snapshot to fully load" ));
            FD_MGAUGE_SET( TILE, STATUS, 2UL ); /* TODO: Remove */
          }
          break;
        default:
          break;
      }
      break;
    }
    case FD_SSHTTP_ADVANCE_DATA: {
      switch( ctx->state ) {
        case FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD:
          ctx->metrics.incremental.bytes_read += data_len;
          break;
        case FD_SNAPRD_STATE_FULL_DOWNLOAD:
          ctx->metrics.full.bytes_read += data_len;
          break;
        default:
          break;
      }

      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out.chunk, data_len, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, data_len, ctx->out.chunk0, ctx->out.wmark );
      break;
    }
    default: break;
  }
}

static void
after_credit( fd_snaprd_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)stem;
  (void)opt_poll_in;
  (void)charge_busy;
  
  long now = fd_log_wallclock();
  fd_ssping_advance( ctx->ssping, now );

  switch ( ctx->state ) {
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS: {
      fd_ip4_port_t best = fd_ssping_best( ctx->ssping );
      if( FD_LIKELY( best.l ) ) {
        ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
        ctx->deadline_nanos = now + 500L*1000L*1000L;
      }
      break;
    }
    case FD_SNAPRD_STATE_COLLECTING_PEERS: {
      if( FD_UNLIKELY( now<ctx->deadline_nanos ) ) break;

      fd_ip4_port_t best = fd_ssping_best( ctx->ssping );
      if( FD_UNLIKELY( !best.l ) ) {
        ctx->state = FD_SNAPRD_STATE_WAITING_FOR_PEERS;
        break;
      }

      ulong highest_cluster_slot = 0UL; /* TODO: Implement */
      if( FD_LIKELY( ctx->local.full_snapshot_slot!=ULONG_MAX && ctx->local.full_snapshot_slot>=fd_ulong_sat_sub( highest_cluster_slot, ctx->config.maximum_local_snapshot_age ) ) ) {
        FD_LOG_NOTICE(( "Loading full snapshot from local file `%s`", ctx->local.full_snapshot_path ));
        ctx->state = FD_SNAPRD_STATE_READING_FULL_FILE;
      } else {
        FD_LOG_NOTICE(( "Downloading full snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( best.addr ), best.port ));
        ctx->addr  = best;
        ctx->state = FD_SNAPRD_STATE_FULL_DOWNLOAD;
        fd_sshttp_init( ctx->sshttp, best, "/snapshot.tar.bz2", 17UL, now );
      }
      break;
    }
    case FD_SNAPRD_STATE_READING_FULL_FILE:
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:
      read_file_data( ctx, stem );
      break;
    case FD_SNAPRD_STATE_FULL_DOWNLOAD:
    case FD_SNAPRD_STATE_INCREMENTAL_DOWNLOAD: {
      read_http_data( ctx, stem, now );
      break;
    }
    case FD_SNAPRD_STATE_FULL_FLUSH:
    case FD_SNAPRD_STATE_INCREMENTAL_FLUSH:
    case FD_SNAPRD_STATE_DONE: {
      break;
    }
    default: {
      FD_LOG_ERR(( "unexpected state %d", ctx->state ));
      break;
    }
  }
}

static void
determine_snapshots( fd_snaprd_tile_t * ctx,
                     char const *       snapshot_dir ) {
  /* first, check if there are any full local snapshots and get the highest slot */
  int res = fd_snapshot_archive_get_latest_full_snapshot( snapshot_dir,
                                                          &ctx->full_snapshot_entry );

  /* If we don't have any full snapshots in the snapshots archive path, we need to download  */
  if( FD_UNLIKELY( res ) ) {
    FD_LOG_NOTICE(( "Unable to find any local full snapshots in the "
                    "snapshots path: %s. Downloading from peers.", snapshot_dir ));
    return;
  }

  ulong highest_slot = ctx->full_snapshot_entry.slot;
  if( ctx->config.incremental_snapshot_fetch ) {
    /* Next, get the incremental snapshot entry */
    res = fd_snapshot_archive_get_latest_incremental_snapshot( snapshot_dir,
                                                               &ctx->incremental_snapshot_entry );
    if( FD_UNLIKELY( res ) ) {
      /* there is no incremental snapshot entry */
      FD_LOG_NOTICE(( "Unable to find any local incremental snapshots "
                      "in the snapshots path %s. Downloading from peers.", snapshot_dir ));
    }

    /* Validate the incremental snapshot builds off the full snapshot */
    if( ctx->incremental_snapshot_entry.base_slot != ctx->full_snapshot_entry.slot ) {
      FD_LOG_NOTICE(( "Local incremental snapshot at slot %lu does not build off the full snapshot at slot %lu. "
                      "Downloading from peers.",
                      ctx->incremental_snapshot_entry.slot,
                      ctx->full_snapshot_entry.slot ));
    }

    highest_slot = ctx->incremental_snapshot_entry.slot;
  }

  /* Check that the snapshot age is within the maximum local snapshot age */
  if( highest_slot >= fd_ulong_sat_sub( CLUSTER_SNAPSHOT_SLOT, ctx->config.maximum_local_snapshot_age ) ) {
    FD_LOG_NOTICE(( "Re-using local full snapshot at slot %lu", ctx->full_snapshot_entry.slot ));
    if( ctx->config.incremental_snapshot_fetch ) {
      FD_LOG_NOTICE(( "Re-using local incremental snapshot at slot %lu", ctx->incremental_snapshot_entry.slot ));
    }
  } else {
    FD_LOG_NOTICE(( "Local full snapshot at slot %lu is too old. ", ctx->full_snapshot_entry.slot ));
    if( ctx->incremental_snapshot_entry.slot!=ULONG_MAX ) {
      FD_LOG_NOTICE(( "Local incremental snapshot at slot %lu is too old. ", ctx->incremental_snapshot_entry.slot ));
    }
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaprd_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t),  sizeof(fd_snaprd_tile_t) );

  determine_snapshots( ctx, tile->snaprd.snapshots_path );

  if( FD_LIKELY( ctx->full_snapshot_entry.slot!=ULONG_MAX ) ) {
    // ctx->local.full_snapshot_fd = open( ctx->local.full_snapshot_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
    // if( FD_UNLIKELY( -1==ctx->local.full_snapshot_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", ctx->local.full_snapshot_path, errno, fd_io_strerror( errno ) ));
  }

  if( FD_LIKELY( ctx->incremental_snapshot_entry.slot!=ULONG_MAX ) ) {
    // ctx->local.incremental_snapshot_fd = open( ctx->local.incremental_snapshot_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
    // if( FD_UNLIKELY( -1==ctx->local.incremental_snapshot_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", ctx->local.incremental_snapshot_path, errno, fd_io_strerror( errno ) ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaprd_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t),  sizeof(fd_snaprd_tile_t)       );
  void * _sshttp          = FD_SCRATCH_ALLOC_APPEND( l, fd_sshttp_align(),          fd_sshttp_footprint()          );
  void * _ssping          = FD_SCRATCH_ALLOC_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( 65536UL ) );

  ctx->state = FD_SNAPRD_STATE_WAITING_FOR_PEERS;

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  ctx->config.incremental_snapshot_fetch = tile->snaprd.incremental_snapshot_fetch;
  ctx->config.do_download                = tile->snaprd.do_download;
  ctx->config.maximum_local_snapshot_age = tile->snaprd.maximum_local_snapshot_age;
  ctx->config.minimum_download_speed_mib = tile->snaprd.minimum_download_speed_mib;

  if( FD_UNLIKELY( !tile->snaprd.maximum_download_retry_abort ) ) ctx->config.maximum_download_retry_abort = UINT_MAX;
  else                                                            ctx->config.maximum_download_retry_abort = tile->snaprd.maximum_download_retry_abort;

  ctx->ssping = fd_ssping_join( fd_ssping_new( _ssping, 65536UL, 1UL ) );
  FD_TEST( ctx->ssping );

  ctx->sshttp = fd_sshttp_join( fd_sshttp_new( _sshttp ) );
  FD_TEST( ctx->sshttp );

  if( FD_LIKELY( !strcmp( tile->snaprd.cluster, "testnet" ) ) ) {
    fd_ip4_port_t initial_peers[ 2UL ] = {
      { .addr = FD_IP4_ADDR( 145, 40, 95, 69 ), .port = 8899 }, /* Solana testnet peer */
      { .addr = FD_IP4_ADDR( 177, 54, 155, 187 ), .port = 8899 } /* A fast testnet peer from snapshot-finder script */
    };

    for( ulong i=0UL; i<2UL; i++ ) fd_ssping_add( ctx->ssping, initial_peers[ i ] );
  } else if( FD_LIKELY( !strcmp( tile->snaprd.cluster, "private" ) ) ) {
    fd_ip4_port_t initial_peers[ 1UL ] = {
      { .addr = FD_IP4_ADDR( 147, 28, 185, 47 ), .port = 8899 } /* A private cluster peer */
    };

    for( ulong i=0UL; i<1UL; i++ ) fd_ssping_add( ctx->ssping, initial_peers[ i ] );
  } else {
    FD_LOG_ERR(( "unexpected cluster %s", tile->snaprd.cluster ));
  }

  if( FD_UNLIKELY( tile->in_cnt ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 0",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  ctx->out.wksp   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0 = fd_dcache_compact_chunk0( ctx->out.wksp, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out.wmark  = fd_dcache_compact_wmark ( ctx->out.wksp, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out.chunk  = ctx->out.chunk0;
  ctx->out.mtu    = topo->links[ tile->out_link_id[ 0 ] ].mtu;
}

#define STEM_BURST                  1UL

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaprd_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaprd_tile_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_AFTER_CREDIT  after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaprd = {
  .name                 = NAME,
  .scratch_align        = scratch_align,
  .scratch_footprint    = scratch_footprint,
  .privileged_init      = privileged_init,
  .unprivileged_init    = unprivileged_init,
  .run                  = stem_run,
  .keep_host_networking = 1,
  .allow_connect        = 1
};

#undef NAME
