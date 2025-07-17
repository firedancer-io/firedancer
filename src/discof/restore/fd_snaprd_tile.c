#include "utils/fd_ssping.h"
#include "utils/fd_sshttp.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_ssarchive.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/gossip/fd_gossip_types.h"

#include "../../disco/plugin/fd_plugin.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#define NAME "snaprd"

/* The snaprd tile at a high level is a state machine that downloads
   snapshots from the network or reads snapshots from disk and produces
   a byte stream that is parsed by downstream snapshot consumer tiles.
   The snaprd tile gathers the latest SnapshotHashes information from
   gossip to decide whether to download snapshots or read local
   snapshots from disk.  If the snaprd tile needs to download a snapshot,
   it goes through the process of discovering and selecting elegible
   peers from gossip to download from. */

#define FD_SNAPRD_STATE_WAITING_FOR_PEERS         ( 0) /* Waiting for first peer to arrive from gossip to download from */
#define FD_SNAPRD_STATE_COLLECTING_PEERS          ( 1) /* First peer arrived, wait a little longer to see if a better one arrives */
#define FD_SNAPRD_STATE_READING_FULL_FILE         ( 2) /* Full file looks better than peer, reading it from disk */
#define FD_SNAPRD_STATE_FLUSHING_FULL_FILE        ( 3) /* Full file was read ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET  ( 4) /* Resetting to load full snapshot from file again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_FULL_HTTP         ( 5) /* Peer was selected, reading full snapshot from HTTP */
#define FD_SNAPRD_STATE_FLUSHING_FULL_HTTP        ( 6) /* Full snapshot was downloaded ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET  ( 7) /* Resetting to load full snapshot from HTTP again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_FILE  ( 8) /* Incremental file looks better than peer, reading it from disk */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE ( 9) /* Incremental file was read ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP  (10) /* Peer was selected, reading incremental snapshot from HTTP */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP (11) /* Incremental snapshot was downloaded ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_SHUTDOWN                  (12) /* The tile is done, and has likely already exited */

#define SNAPRD_FILE_BUF_SZ (1024UL*1024UL) /* 1 MiB */

#define IN_KIND_SNAPCTL (0)
#define IN_KIND_GOSSIP  (1)
#define MAX_IN_LINKS    (3)

#define FD_SNAPRD_CTL_OUT_IDX    (0)
#define FD_SNAPRD_PLUGIN_OUT_IDX (1)

typedef struct {
  fd_wksp_t * wksp;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
  ulong       out_idx;
} fd_snaprd_out_ctx_t;

struct fd_snaprd_tile {
  fd_ssping_t * ssping;
  fd_sshttp_t * sshttp;

  int   state;
  int   malformed;
  long  deadline_nanos;
  ulong ack_cnt;
  int   peer_selection;

  fd_ip4_port_t addr;

  struct {
    ulong write_buffer_pos;
    ulong write_buffer_len;
    uchar write_buffer[ SNAPRD_FILE_BUF_SZ ];

    char  full_snapshot_path[ PATH_MAX ];
    char  incremental_snapshot_path[ PATH_MAX ];

    int   dir_fd;
    int   full_snapshot_fd;
    int   incremental_snapshot_fd;
  } local_out;

  uchar in_kind[ MAX_IN_LINKS ];

  struct {
    ulong full_snapshot_slot;
    int   full_snapshot_fd;
    char  full_snapshot_path[ PATH_MAX ];
    ulong incremental_snapshot_slot;
    int   incremental_snapshot_fd;
    char  incremental_snapshot_path[ PATH_MAX ];
  } local_in;

  struct {
    char path[ PATH_MAX ];
    int  do_download;
    int  incremental_snapshot_fetch;
    uint maximum_local_snapshot_age;
    uint minimum_download_speed_mib;
    uint maximum_download_retry_abort;
    uint max_full_snapshots_to_keep;
    uint max_incremental_snapshots_to_keep;
  } config;

  struct {
    struct {
      ulong bytes_read;
      ulong bytes_written;
      ulong bytes_total;
      uint  num_retries;
    } full;

    struct {
      ulong bytes_read;
      ulong bytes_written;
      ulong bytes_total;
      uint  num_retries;
    } incremental;
  } metrics;

  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } gossip_in;

  struct {
    fd_gossip_update_message_t tmp_upd_buf;
    fd_contact_info_t *        ci_table;
  } gossip;

  fd_snaprd_out_ctx_t out[ 2UL ];
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
  l = FD_LAYOUT_APPEND( l, fd_sshttp_align(),          fd_sshttp_footprint()          );
  l = FD_LAYOUT_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( 65536UL ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_contact_info_t), sizeof(fd_contact_info_t) * FD_CONTACT_INFO_TABLE_SIZE );
  return FD_LAYOUT_FINI( l, alignof(fd_snaprd_tile_t) );
}

static inline int
should_shutdown( fd_snaprd_tile_t * ctx ) {
  return ctx->state==FD_SNAPRD_STATE_SHUTDOWN;
}

static void
metrics_write( fd_snaprd_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_READ,               ctx->metrics.full.bytes_read );
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_WRITTEN,            ctx->metrics.full.bytes_written );
  FD_MGAUGE_SET( SNAPRD, FULL_BYTES_TOTAL,              ctx->metrics.full.bytes_total );
  FD_MGAUGE_SET( SNAPRD, FULL_DOWNLOAD_RETRIES,         ctx->metrics.full.num_retries );

  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_READ,        ctx->metrics.incremental.bytes_read );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_WRITTEN,     ctx->metrics.incremental.bytes_written );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_BYTES_TOTAL,       ctx->metrics.incremental.bytes_total );
  FD_MGAUGE_SET( SNAPRD, INCREMENTAL_DOWNLOAD_RETRIES,  ctx->metrics.incremental.num_retries );

  FD_MGAUGE_SET( SNAPRD, STATE, (ulong)ctx->state );
}

static void
read_file_data( fd_snaprd_tile_t *  ctx,
                fd_stem_context_t * stem ) {
  fd_snaprd_out_ctx_t * out_ctx = &ctx->out[ FD_SNAPRD_CTL_OUT_IDX ];
  uchar * out = fd_chunk_to_laddr( ctx->out[ FD_SNAPRD_CTL_OUT_IDX ].wksp, out_ctx->chunk );

  FD_TEST( ctx->state==FD_SNAPRD_STATE_READING_INCREMENTAL_FILE || ctx->state==FD_SNAPRD_STATE_READING_FULL_FILE );
  int full = ctx->state==FD_SNAPRD_STATE_READING_FULL_FILE;
  long result = read( full ? ctx->local_in.full_snapshot_fd : ctx->local_in.incremental_snapshot_fd , out, out_ctx->mtu );
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
        fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE;
        break;
      case FD_SNAPRD_STATE_READING_FULL_FILE:
        if( FD_LIKELY( ctx->config.incremental_snapshot_fetch ) ) {
          fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_EOF_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        } else {
          fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        }
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_FILE;
        break;
      default:
        break;
    }
    return;
  }

  fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_DATA, out_ctx->chunk, (ulong)result, 0UL, 0UL, 0UL );
  out_ctx->chunk = fd_dcache_compact_next( out_ctx->chunk, (ulong)result, out_ctx->chunk0, out_ctx->wmark );
}

static void
read_http_data( fd_snaprd_tile_t *  ctx,
                fd_stem_context_t * stem,
                long                now ) {
  fd_snaprd_out_ctx_t * out_ctx = &ctx->out[ FD_SNAPRD_CTL_OUT_IDX ];
  uchar * out = fd_chunk_to_laddr( out_ctx->wksp, out_ctx->chunk );

  ulong buffer_avail = fd_ulong_if( -1!=ctx->local_out.dir_fd, SNAPRD_FILE_BUF_SZ-ctx->local_out.write_buffer_len, ULONG_MAX );
  ulong data_len = fd_ulong_min( buffer_avail, out_ctx->mtu );
  int result = fd_sshttp_advance( ctx->sshttp, &data_len, out, now );

  switch( result ) {
    case FD_SSHTTP_ADVANCE_AGAIN: break;
    case FD_SSHTTP_ADVANCE_ERROR: {
      FD_LOG_NOTICE(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                      FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ) ));
      fd_ssping_invalidate( ctx->ssping, ctx->addr, now );
      fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
      ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
      ctx->deadline_nanos = now;
      break;
    }
    case FD_SSHTTP_ADVANCE_DONE: {
      switch( ctx->state ) {
        case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
          fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP;
          break;
        case FD_SNAPRD_STATE_READING_FULL_HTTP:
          if( FD_LIKELY( ctx->config.incremental_snapshot_fetch ) ) {
            fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_EOF_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
          } else {
            fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
          }
          ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP;
          break;
        default:
          break;
      }
      break;
    }
    case FD_SSHTTP_ADVANCE_DATA: {
      fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_DATA, out_ctx->chunk, data_len, 0UL, 0UL, 0UL );
      out_ctx->chunk = fd_dcache_compact_next( out_ctx->chunk, data_len, out_ctx->chunk0, out_ctx->wmark );

      ulong written_sz = 0UL;
      if( FD_LIKELY( -1!=ctx->local_out.dir_fd && !ctx->local_out.write_buffer_len ) ) {
        while( written_sz<data_len ) {
          int full = ctx->state==FD_SNAPRD_STATE_READING_FULL_HTTP;
          int fd = full ? ctx->local_out.full_snapshot_fd : ctx->local_out.incremental_snapshot_fd;
          long result = write( fd, out+written_sz, data_len-written_sz );
          if( FD_UNLIKELY( -1==result && errno==EAGAIN ) ) break;
          else if( FD_UNLIKELY( -1==result && errno==ENOSPC ) ) {
            char const * snapshot_path = full ? ctx->local_out.full_snapshot_path : ctx->local_out.incremental_snapshot_path;
            FD_LOG_ERR(( "Out of disk space when writing out snapshot data to `%s`", snapshot_path ));
          } else if( FD_UNLIKELY( -1==result ) ) {
            FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
            break;
          }
          written_sz += (ulong)result;
        }
      }

      if( FD_UNLIKELY( written_sz<data_len ) ) {
        fd_memcpy( ctx->local_out.write_buffer+ctx->local_out.write_buffer_len, out+written_sz, data_len-written_sz );
      }
      ctx->local_out.write_buffer_len += data_len-written_sz;

      ulong size; fd_sshttp_download_size( ctx->sshttp, &size );
      switch( ctx->state ) {
        case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
          if( FD_LIKELY( size!=ULONG_MAX ) ) ctx->metrics.incremental.bytes_total = fd_ulong_max( size, ctx->metrics.incremental.bytes_total );
          ctx->metrics.incremental.bytes_read += data_len;
          ctx->metrics.incremental.bytes_written += written_sz;
          break;
        case FD_SNAPRD_STATE_READING_FULL_HTTP:
          if( FD_LIKELY( size!=ULONG_MAX ) ) ctx->metrics.full.bytes_total = fd_ulong_max( size, ctx->metrics.full.bytes_total );
          ctx->metrics.full.bytes_read += data_len;
          ctx->metrics.full.bytes_written += written_sz;
          break;
        default:
          FD_LOG_ERR(( "unexpected state %d", ctx->state ));
          break;
      }

      break;
    }
    default:
      FD_LOG_ERR(( "unexpected fd_sshttp_advance result %d", result ));
      break;
  }
}

static void
drain_buffer( fd_snaprd_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->state!=FD_SNAPRD_STATE_READING_FULL_HTTP &&
                   ctx->state!=FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP &&
                   ctx->state!=FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP &&
                   ctx->state!=FD_SNAPRD_STATE_FLUSHING_FULL_HTTP ) ) return;

  if( FD_LIKELY( -1==ctx->local_out.dir_fd || !ctx->local_out.write_buffer_len ) ) return;

  int full = ctx->state==FD_SNAPRD_STATE_READING_FULL_HTTP || ctx->state==FD_SNAPRD_STATE_FLUSHING_FULL_HTTP;
  int fd = full ? ctx->local_out.full_snapshot_fd : ctx->local_out.incremental_snapshot_fd;

  ulong written_sz = 0UL;
  while( ctx->local_out.write_buffer_pos+written_sz<ctx->local_out.write_buffer_len ) {
    long result = write( fd, ctx->local_out.write_buffer+ctx->local_out.write_buffer_pos+written_sz, ctx->local_out.write_buffer_len-written_sz );
    if( FD_UNLIKELY( -1==result && errno==EAGAIN ) ) break;
    else if( FD_UNLIKELY( -1==result && errno==ENOSPC ) ) {
      char const * snapshot_path = full ? ctx->local_out.full_snapshot_path : ctx->local_out.incremental_snapshot_path;
      FD_LOG_ERR(( "Out of disk space when writing out snapshot data to `%s`", snapshot_path ));
    } else if( FD_UNLIKELY( -1==result ) ) {
      FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      break;
    }
    written_sz += (ulong)result;
  }

  ctx->local_out.write_buffer_pos += written_sz;

  if( FD_LIKELY( ctx->local_out.write_buffer_pos==ctx->local_out.write_buffer_len ) ) {
    ctx->local_out.write_buffer_pos = 0UL;
    ctx->local_out.write_buffer_len = 0UL;
  }

  if( FD_LIKELY( full ) ) ctx->metrics.full.bytes_written += written_sz;
  else                    ctx->metrics.incremental.bytes_written += written_sz;
}

static void
rename_snapshots( fd_snaprd_tile_t * ctx ) {
  if( FD_UNLIKELY( -1==ctx->local_out.dir_fd ) ) return;
  char const * full_snapshot_name;
  char const * incremental_snapshot_name;
  fd_sshttp_snapshot_names( ctx->sshttp, NULL, NULL, &full_snapshot_name, &incremental_snapshot_name );

  if( FD_LIKELY( -1!=ctx->local_out.full_snapshot_fd ) ) {
    if( FD_UNLIKELY( -1==renameat( ctx->local_out.dir_fd, "snapshot.tar.bz2-partial", ctx->local_out.dir_fd, full_snapshot_name ) ) )
      FD_LOG_ERR(( "renameat() failed (%i-%s) when renaming snapshot.tar.bz2-partial to %s", errno, fd_io_strerror( errno ), full_snapshot_name ));
  }
  if( FD_LIKELY( ctx->config.incremental_snapshot_fetch && -1!=ctx->local_out.incremental_snapshot_fd ) ) {
    if( FD_UNLIKELY( -1==renameat( ctx->local_out.dir_fd, "incremental-snapshot.tar.bz2-partial", ctx->local_out.dir_fd, incremental_snapshot_name ) ) )
      FD_LOG_ERR(( "renameat() failed (%i-%s) when renaming incremental-snapshot.tar.bz2-partial to %s", errno, fd_io_strerror( errno ), incremental_snapshot_name ));
  }
}

static void
fd_snaprd_publish_snapshot_update( fd_snaprd_tile_t *  ctx,
                                        fd_stem_context_t * stem,
                                        int                 type,
                                        ulong               slot,
                                        int                 remote,
                                        const char *        path ) {
  fd_snaprd_out_ctx_t * out_plugin_ctx = &ctx->out[ FD_SNAPRD_PLUGIN_OUT_IDX ];
  fd_restore_snapshot_update_t * snapshot_update = fd_chunk_to_laddr( out_plugin_ctx->wksp , out_plugin_ctx->chunk );
  snapshot_update->type = type;
  snapshot_update->slot = slot;
  if( FD_UNLIKELY( remote ) ) {
    FD_TEST( fd_cstr_printf_check( snapshot_update->read_path, sizeof(snapshot_update->read_path), NULL, "http://" FD_IP4_ADDR_FMT ":%hu/%s", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port, path ) );
  } else {
    FD_TEST( fd_cstr_printf_check( snapshot_update->read_path, sizeof(snapshot_update->read_path), NULL, "%s", path ) );
  }
  snapshot_update->peer_addr = fd_uint_if( remote, ctx->addr.addr, 0U );
  snapshot_update->peer_port = fd_ushort_if( remote, ctx->addr.port, 0U );

  ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, out_plugin_ctx->out_idx, FD_PLUGIN_MSG_SNAPSHOT_UPDATE, out_plugin_ctx->chunk, sizeof(fd_restore_snapshot_update_t), 0UL, tspub, tspub );
  out_plugin_ctx->chunk = fd_dcache_compact_next( out_plugin_ctx->chunk, sizeof(fd_restore_snapshot_update_t), out_plugin_ctx->chunk0, out_plugin_ctx->wmark );
}

static void
after_credit( fd_snaprd_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  (void)charge_busy;

  long now = fd_log_wallclock();
  if( FD_LIKELY( ctx->peer_selection ) ) {
    fd_ssping_advance( ctx->ssping, now );
  }

  drain_buffer( ctx );
  fd_snaprd_out_ctx_t * out_ctx = &ctx->out[ FD_SNAPRD_CTL_OUT_IDX ];

  /* All control fragments sent by the snaprd tile must be fully
     acknowledged by all downstream consumers before processing can
     proceed, to prevent tile state machines from getting out of sync
     (see fd_ssctrl.h for more details).  Currently there are two
     downstream consumers, snapdc and snapin. */
#define NUM_SNAP_CONSUMERS (2UL)

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

      ulong highest_cluster_slot = 0UL; /* TODO: Implement, using incremental snapshot slot for age */
      if( FD_LIKELY( ctx->local_in.full_snapshot_slot!=ULONG_MAX && ctx->local_in.full_snapshot_slot>=fd_ulong_sat_sub( highest_cluster_slot, ctx->config.maximum_local_snapshot_age ) ) ) {
        FD_LOG_NOTICE(( "loading full snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        {
          struct stat st;
          if( FD_UNLIKELY( -1==fstat( ctx->local_in.full_snapshot_fd, &st ) ) ) {
            FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
          }
          ctx->metrics.full.bytes_total = (ulong)st.st_size;
        }
        ctx->state = FD_SNAPRD_STATE_READING_FULL_FILE;
        fd_snaprd_publish_snapshot_update( ctx, stem, FD_PLUGIN_MSG_SNAPSHOT_TYPE_FULL, ctx->local_in.full_snapshot_slot, 0, ctx->local_in.full_snapshot_path );
      } else {
        FD_LOG_NOTICE(( "downloading full snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( best.addr ), fd_ushort_bswap( best.port ) ));
        ctx->addr  = best;
        ctx->state = FD_SNAPRD_STATE_READING_FULL_HTTP;
        fd_sshttp_init( ctx->sshttp, best, "/snapshot.tar.bz2", 17UL, 1, now );

        ulong full_snapshot_slot[ 1 ];
        ulong incremental_snapshot_slot[ 1 ];
        char const * full_snapshot_name;
        char const * incremental_snapshot_name;
        do { /* run until redirect is fully resolved */
          read_http_data( ctx, stem, now );
          fd_sshttp_snapshot_names( ctx->sshttp, full_snapshot_slot, incremental_snapshot_slot, &full_snapshot_name, &incremental_snapshot_name );
        } while( full_snapshot_slot[ 0 ] == 0 );
        fd_snaprd_publish_snapshot_update( ctx, stem, FD_PLUGIN_MSG_SNAPSHOT_TYPE_FULL, full_snapshot_slot[ 0 ], 1, full_snapshot_name );
      }
      break;
    }
    case FD_SNAPRD_STATE_READING_FULL_FILE:
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:
      read_file_data( ctx, stem );
      break;
    case FD_SNAPRD_STATE_READING_FULL_HTTP:
    case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP: {
      read_http_data( ctx, stem, now );
      break;
    }
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE:
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        ctx->malformed = 0;
        break;
      }

      if( FD_UNLIKELY( ctx->local_out.write_buffer_len ) ) break;

      rename_snapshots( ctx );
      ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
      break;
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      if( FD_LIKELY( !ctx->config.incremental_snapshot_fetch ) ) {
        ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
        metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
        fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      FD_LOG_NOTICE(( "reading incremental snapshot from local file `%s`", ctx->local_in.incremental_snapshot_path ));

      {
        struct stat st;
        if( FD_UNLIKELY( -1==fstat( ctx->local_in.incremental_snapshot_fd, &st ) ) ) {
          FD_LOG_ERR(( "fstat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        }
        ctx->metrics.incremental.bytes_total = (ulong)st.st_size;
      }

      ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_FILE;
      fd_snaprd_publish_snapshot_update( ctx, stem, FD_PLUGIN_MSG_SNAPSHOT_TYPE_INCREMENTAL, ctx->local_in.incremental_snapshot_slot, 0, ctx->local_in.incremental_snapshot_path );
      break;
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        ctx->malformed = 0;
        break;
      }

      if( FD_UNLIKELY( ctx->local_out.write_buffer_len ) ) break;

      if( FD_LIKELY( !ctx->config.incremental_snapshot_fetch ) ) {
        rename_snapshots( ctx );
        ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
        metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
        fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      FD_LOG_NOTICE(( "downloading incremental snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap(ctx->addr.port) ));
      fd_sshttp_init( ctx->sshttp, ctx->addr, "/incremental-snapshot.tar.bz2", 29UL, 0, fd_log_wallclock() );
      ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP;

        ulong full_snapshot_slot[ 1 ];
        ulong incremental_snapshot_slot[ 1 ];
        char const * full_snapshot_name;
        char const * incremental_snapshot_name;
        do { /* run until redirect is fully resolved */
          read_http_data( ctx, stem, now );
          fd_sshttp_snapshot_names( ctx->sshttp, full_snapshot_slot, incremental_snapshot_slot, &full_snapshot_name, &incremental_snapshot_name );
        } while( incremental_snapshot_slot[ 0 ] == 0 );
        fd_snaprd_publish_snapshot_update( ctx, stem, FD_PLUGIN_MSG_SNAPSHOT_TYPE_INCREMENTAL, incremental_snapshot_slot[ 0 ], 1, incremental_snapshot_name );
      break;
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      ctx->metrics.full.bytes_read = 0UL;
      ctx->metrics.full.bytes_written = 0UL;
      ctx->metrics.full.bytes_total = 0UL;

      ctx->metrics.incremental.bytes_read = 0UL;
      ctx->metrics.incremental.bytes_written = 0UL;
      ctx->metrics.incremental.bytes_total = 0UL;

      ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
      ctx->deadline_nanos = 0L;
      break;
    case FD_SNAPRD_STATE_SHUTDOWN:
      break;
    default: {
      FD_LOG_ERR(( "unexpected state %d", ctx->state ));
      break;
    }
  }
}

static int
before_frag( fd_snaprd_tile_t * ctx FD_PARAM_UNUSED,
             ulong              in_idx,
             ulong              seq FD_PARAM_UNUSED,
             ulong              sig ) {
  if( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ){
    (void)sig;
    // return !( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ||
    //           sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ||
    //           sig==FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES );
    return 1;
  }
  return 0;
}

static void
during_frag( fd_snaprd_tile_t * ctx,
             ulong              in_idx,
             ulong              seq FD_PARAM_UNUSED,
             ulong              sig FD_PARAM_UNUSED,
             ulong              chunk,
             ulong              sz,
             ulong              ctl FD_PARAM_UNUSED) {
  if( ctx->in_kind[ in_idx ]!= IN_KIND_GOSSIP ) return;

  if( FD_UNLIKELY( chunk<ctx->gossip_in.chunk0 ||
                   chunk>ctx->gossip_in.wmark ) ) {
    FD_LOG_ERR(( "snaprd: unexpected chunk %lu", chunk ));
  }
  /* TODO: Size checks */
  fd_memcpy( &ctx->gossip.tmp_upd_buf, fd_chunk_to_laddr( ctx->gossip_in.mem, chunk ), sz );
}

static void
after_frag( fd_snaprd_tile_t *  ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx;

  (void)seq;
  (void)tsorig;
  (void)tspub;
  (void)sz;

  FD_TEST( sig==FD_SNAPSHOT_MSG_CTRL_ACK || sig==FD_SNAPSHOT_MSG_CTRL_MALFORMED );
  fd_snaprd_out_ctx_t * out_ctx = &ctx->out[ FD_SNAPRD_CTL_OUT_IDX ];

  if( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) {
    fd_gossip_update_message_t * msg = &ctx->gossip.tmp_upd_buf;
    switch( msg->tag ) {
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
          fd_contact_info_t * cur      = &ctx->gossip.ci_table[ msg->contact_info.idx ];
          fd_ip4_port_t       cur_addr = ctx->gossip.ci_table[ msg->contact_info.idx ].sockets[ FD_CONTACT_INFO_SOCKET_RPC ];
          if( cur_addr.l ){
            fd_ssping_remove( ctx->ssping, cur_addr );
          }
          fd_contact_info_t * new = msg->contact_info.contact_info;
          fd_ip4_port_t new_addr  = new->sockets[ FD_CONTACT_INFO_SOCKET_RPC ];
          if( new_addr.l ) {
            fd_ssping_add( ctx->ssping, new_addr );
          }
          *cur = *new;
        }
        break;
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
          fd_contact_info_t * cur  = &ctx->gossip.ci_table[ msg->contact_info_remove.idx ];
          fd_ip4_port_t       addr = cur->sockets[ FD_CONTACT_INFO_SOCKET_RPC ];
          if( addr.l ) {
            fd_ssping_remove( ctx->ssping, addr );
          }
        }
        break;
      case FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES:
        /* TODO */
        break;
    }

  } else {
    FD_TEST( sig==FD_SNAPSHOT_MSG_CTRL_ACK || sig==FD_SNAPSHOT_MSG_CTRL_MALFORMED );

    if( FD_LIKELY( sig==FD_SNAPSHOT_MSG_CTRL_ACK ) ) ctx->ack_cnt++;
    else {
      FD_TEST( ctx->state!=FD_SNAPRD_STATE_SHUTDOWN &&
              ctx->state!=FD_SNAPRD_STATE_COLLECTING_PEERS &&
              ctx->state!=FD_SNAPRD_STATE_WAITING_FOR_PEERS );

      switch( ctx->state) {
        case FD_SNAPRD_STATE_READING_FULL_FILE:
        case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:
        case FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET:
          FD_LOG_ERR(( "error reading snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:
        case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE:
          FD_LOG_ERR(( "error reading snapshot from local file `%s`", ctx->local_in.incremental_snapshot_path ));
        case FD_SNAPRD_STATE_READING_FULL_HTTP:
        case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
          FD_LOG_NOTICE(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                          FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
          fd_sshttp_cancel( ctx->sshttp );
          fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
          fd_stem_publish( stem, out_ctx->out_idx, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
          break;
        case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:
        case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:
          FD_LOG_NOTICE(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2",
                          FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
          fd_sshttp_cancel( ctx->sshttp );
          fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
          /* We would like to transition to FULL_HTTP_RESET, but we can't
            do it just yet, because we have already sent a DONE control
            fragment, and need to wait for acknowledges to come back
            first, to ensure there's only one control message outstanding
            at a time. */
          ctx->malformed = 1;
          break;
        case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:
          break;
        default:
          FD_LOG_ERR(( "unexpected state %d", ctx->state ));
          break;
      }
    }
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaprd_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t),  sizeof(fd_snaprd_tile_t) );

  /* By default, the snaprd tile selects peers and its initial state is
     WAITING_FOR_PEERS. */
  ctx->peer_selection = 1;
  ctx->state          = FD_SNAPRD_STATE_WAITING_FOR_PEERS;

  fd_ssarchive_remove_old_snapshots( tile->snaprd.snapshots_path,
                                     tile->snaprd.max_full_snapshots_to_keep,
                                     tile->snaprd.max_incremental_snapshots_to_keep );

  ulong full_slot = ULONG_MAX;
  ulong incremental_slot = ULONG_MAX;
  char full_path[ PATH_MAX ] = {0};
  char incremental_path[ PATH_MAX ] = {0};
  if( FD_UNLIKELY( -1==fd_ssarchive_latest_pair( tile->snaprd.snapshots_path,
                                                 tile->snaprd.incremental_snapshot_fetch,
                                                 &full_slot,
                                                 &incremental_slot,
                                                 full_path,
                                                 incremental_path ) ) ) {
    ctx->local_in.full_snapshot_slot        = ULONG_MAX;
    ctx->local_in.incremental_snapshot_slot = ULONG_MAX;

    ctx->local_out.dir_fd = open( tile->snaprd.snapshots_path, O_DIRECTORY|O_CLOEXEC );
    if( FD_UNLIKELY( -1==ctx->local_out.dir_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", tile->snaprd.snapshots_path, errno, fd_io_strerror( errno ) ));

    FD_TEST( fd_cstr_printf_check( ctx->local_out.full_snapshot_path, PATH_MAX, NULL, "%s/snapshot.tar.bz2-partial", tile->snaprd.snapshots_path ) );
    ctx->local_out.full_snapshot_fd = openat( ctx->local_out.dir_fd, "snapshot.tar.bz2-partial", O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK, S_IRUSR|S_IWUSR );
    if( FD_UNLIKELY( -1==ctx->local_out.full_snapshot_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", ctx->local_out.full_snapshot_path, errno, fd_io_strerror( errno ) ));

    if( FD_LIKELY( tile->snaprd.incremental_snapshot_fetch ) ) {
      FD_TEST( fd_cstr_printf_check( ctx->local_out.incremental_snapshot_path, PATH_MAX, NULL, "%s/incremental-snapshot.tar.bz2-partial", tile->snaprd.snapshots_path ) );
      ctx->local_out.incremental_snapshot_fd = openat( ctx->local_out.dir_fd, "incremental-snapshot.tar.bz2-partial", O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK, S_IRUSR|S_IWUSR );
      if( FD_UNLIKELY( -1==ctx->local_out.incremental_snapshot_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", ctx->local_out.incremental_snapshot_path, errno, fd_io_strerror( errno ) ));
    } else {
      ctx->local_out.incremental_snapshot_fd = -1;
    }

  } else {
    FD_TEST( full_slot!=ULONG_MAX );

    ctx->local_in.full_snapshot_slot = full_slot;
    ctx->local_in.incremental_snapshot_slot = incremental_slot;

    strncpy( ctx->local_in.full_snapshot_path, full_path, PATH_MAX );
    ctx->local_in.full_snapshot_fd = open( ctx->local_in.full_snapshot_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
    if( FD_UNLIKELY( -1==ctx->local_in.full_snapshot_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", ctx->local_in.full_snapshot_path, errno, fd_io_strerror( errno ) ));

    if( tile->snaprd.incremental_snapshot_fetch ) {
      FD_TEST( incremental_slot!=ULONG_MAX );
    }

    if( FD_LIKELY( incremental_slot!=ULONG_MAX ) ) {
      strncpy( ctx->local_in.incremental_snapshot_path, incremental_path, PATH_MAX );
      ctx->local_in.incremental_snapshot_fd = open( ctx->local_in.incremental_snapshot_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
      if( FD_UNLIKELY( -1==ctx->local_in.incremental_snapshot_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", ctx->local_in.incremental_snapshot_path, errno, fd_io_strerror( errno ) ));
    }

    ctx->local_out.dir_fd = -1;
    ctx->local_out.full_snapshot_fd = -1;
    ctx->local_out.incremental_snapshot_fd = -1;

    if( FD_UNLIKELY( tile->snaprd.maximum_local_snapshot_age==0 ) ) {
      /* Disable peer selection if we are reading snapshots from disk
         and there is no maximum local snapshot age set.
         Set the initial state to READING_FULL_FILE to avoid peer
         selection logic. */
      ctx->peer_selection = 0;
      ctx->state          = FD_SNAPRD_STATE_READING_FULL_FILE;
      FD_LOG_NOTICE(( "loading full snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
    }
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
  // void * _gossip_peers_rx = FD_SCRATCH_ALLOC_APPEND( l, gossip_peers_rx_align(),    gossip_peers_rx_footprint()    );
  void * _ci_table        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_contact_info_t), sizeof(fd_contact_info_t) * FD_CONTACT_INFO_TABLE_SIZE );

  ctx->ack_cnt = 0UL;
  ctx->malformed = 0;

  ctx->local_out.write_buffer_pos = 0UL;
  ctx->local_out.write_buffer_len = 0UL;

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  fd_memcpy( ctx->config.path, tile->snaprd.snapshots_path, PATH_MAX );
  ctx->config.incremental_snapshot_fetch        = tile->snaprd.incremental_snapshot_fetch;
  ctx->config.do_download                       = tile->snaprd.do_download;
  ctx->config.maximum_local_snapshot_age        = tile->snaprd.maximum_local_snapshot_age;
  ctx->config.minimum_download_speed_mib        = tile->snaprd.minimum_download_speed_mib;
  ctx->config.max_full_snapshots_to_keep        = tile->snaprd.max_full_snapshots_to_keep;
  ctx->config.max_incremental_snapshots_to_keep = tile->snaprd.max_incremental_snapshots_to_keep;

  if( FD_UNLIKELY( !tile->snaprd.maximum_download_retry_abort ) ) ctx->config.maximum_download_retry_abort = UINT_MAX;
  else                                                            ctx->config.maximum_download_retry_abort = tile->snaprd.maximum_download_retry_abort;

  ctx->ssping = fd_ssping_join( fd_ssping_new( _ssping, 65536UL, 1UL ) );
  FD_TEST( ctx->ssping );

  ctx->sshttp = fd_sshttp_join( fd_sshttp_new( _sshttp ) );
  FD_TEST( ctx->sshttp );

  ctx->gossip.ci_table = _ci_table;
  /* zero-out memory so that we can perform null checks in after_frag */
  fd_memset( ctx->gossip.ci_table, 0, sizeof(fd_contact_info_t) * FD_CONTACT_INFO_TABLE_SIZE );

  FD_TEST( tile->in_cnt<=MAX_IN_LINKS );
  uchar has_gossip_in = 0;
  for( ulong i=0UL; i<(tile->in_cnt); i++ ){
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( in_link->name, "gossip_out" ) ) {
      // has_gossip_in         = 1;
      ctx->in_kind[ i ]     = IN_KIND_GOSSIP;
      // ctx->gossip_in.mem    = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
      // ctx->gossip_in.chunk0 = fd_dcache_compact_chunk0( ctx->gossip_in.mem, in_link->dcache );
      // ctx->gossip_in.wmark  = fd_dcache_compact_wmark ( ctx->gossip_in.mem, in_link->dcache, in_link->mtu );
      // ctx->gossip_in.mtu    = in_link->mtu;
    } else if( 0==strcmp( in_link->name, "snapdc_rd" ) ||
               0==strcmp( in_link->name, "snapin_rd" ) ) {
      ctx->in_kind[ i ] = IN_KIND_SNAPCTL;
    }
  }

  if( FD_UNLIKELY( !has_gossip_in ) ) {
    if( FD_LIKELY( !strcmp( tile->snaprd.cluster, "testnet" ) ) ) {
      FD_LOG_NOTICE(( "no gossip input link found, using initial peers for testnet" ));
      fd_ip4_port_t initial_peers[ 2UL ] = {
        { .addr = FD_IP4_ADDR( 35 , 214, 172, 227 ), .port = fd_ushort_bswap(8899) },
        { .addr = FD_IP4_ADDR( 145, 40 , 95 , 69  ), .port = fd_ushort_bswap(8899) }, /* Solana testnet peer */
      };

      for( ulong i=0UL; i<2UL; i++ ) fd_ssping_add( ctx->ssping, initial_peers[ i ] );
    } else if( FD_LIKELY( !strcmp( tile->snaprd.cluster, "private" ) ) ) {
      fd_ip4_port_t initial_peers[ 1UL ] = {
        { .addr = FD_IP4_ADDR( 147, 28, 185, 47 ), .port = fd_ushort_bswap( 8899 ) } /* A private cluster peer */
      };

      for( ulong i=0UL; i<1UL; i++ ) fd_ssping_add( ctx->ssping, initial_peers[ i ] );
    } else {
      FD_LOG_ERR(( "unexpected cluster %s", tile->snaprd.cluster ));
    }
  }

  if( FD_UNLIKELY( tile->out_cnt!=2UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2", tile->out_cnt ));

  for( ulong i=0; i<tile->out_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ i ] ];
    ulong out_kind;
    if(      !strcmp( link->name, "snap_zstd" ) )    out_kind = FD_SNAPRD_CTL_OUT_IDX;
    else if( !strcmp( link->name, "snaprd_plugi" ) ) out_kind = FD_SNAPRD_PLUGIN_OUT_IDX;
    else FD_LOG_ERR(( "unexpected link name %s", link->name ));

    ctx->out[ out_kind ].wksp    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ i ] ].dcache_obj_id ].wksp_id ].wksp;
    ctx->out[ out_kind ].chunk0  = fd_dcache_compact_chunk0( ctx->out[ out_kind ].wksp, topo->links[ tile->out_link_id[ i ] ].dcache );
    ctx->out[ out_kind ].wmark   = fd_dcache_compact_wmark ( ctx->out[ out_kind ].wksp, topo->links[ tile->out_link_id[ i ] ].dcache, topo->links[ tile->out_link_id[ i ] ].mtu );
    ctx->out[ out_kind ].chunk   = ctx->out[ out_kind ].chunk0;
    ctx->out[ out_kind ].mtu     = topo->links[ tile->out_link_id[ i ] ].mtu;
    ctx->out[ out_kind ].out_idx = i;
  }
}

#define STEM_BURST 2UL /* One control message, and one data message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaprd_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaprd_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_BEFORE_FRAG     before_frag
#define STEM_CALLBACK_DURING_FRAG     during_frag
#define STEM_CALLBACK_AFTER_FRAG      after_frag

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
