#include "utils/fd_ssping.h"
#include "utils/fd_sshttp.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_ssarchive.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/gossip/fd_gossip_types.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
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

#define FD_SNAPRD_STATE_WAITING_FOR_PEERS         ( 0) /* Waiting for first peer to arrive from gossip to download from */
#define FD_SNAPRD_STATE_COLLECTING_PEERS          ( 1) /* First peer arrived, wait a little longer to see if a better one arrives */
#define FD_SNAPRD_STATE_READING_FULL_FILE         ( 2) /* Full file looks better than peer, reading it from disk */
#define FD_SNAPRD_STATE_FLUSHING_FULL_FILE        ( 3) /* Full file was read ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET  ( 4) /* Resetting to load full snapshot from file again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_FILE  ( 5) /* Incremental file looks better than peer, reading it from disk */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE ( 6) /* Incremental file was read ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_READING_FULL_HTTP         ( 7) /* Peer was selected, reading full snapshot from HTTP */
#define FD_SNAPRD_STATE_FLUSHING_FULL_HTTP        ( 8) /* Full snapshot was downloaded ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET  ( 9) /* Resetting to load full snapshot from HTTP again, confirm decompress and inserter are reset too */
#define FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP  (10) /* Peer was selected, reading incremental snapshot from HTTP */
#define FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP (11) /* Incremental snapshot was downloaded ok, confirm it decompressed and inserted ok */
#define FD_SNAPRD_STATE_SHUTDOWN                  (12) /* The tile is done, and has likely already exited */

#define SNAPRD_FILE_BUF_SZ (1024UL*1024UL) /* 1 MiB */

#define IN_KIND_SNAPCTL   (0)
#define IN_KIND_GOSSIP    (1)
#define MAX_IN_LINK_KINDS (3)

struct fd_snaprd_tile {
  fd_ssping_t * ssping;
  fd_sshttp_t * sshttp;

  int   state;
  int   malformed;
  long  deadline_nanos;
  ulong ack_cnt;
  int   peer_selection;

  long diagnostic_deadline_nanos;

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

  uchar in_kind[ MAX_IN_LINK_KINDS ];

  struct {
    ulong full_snapshot_slot;
    int   full_snapshot_fd;
    char  full_snapshot_path[ PATH_MAX ];
    ulong full_snapshot_size;

    ulong incremental_snapshot_slot;
    int   incremental_snapshot_fd;
    char  incremental_snapshot_path[ PATH_MAX ];
    ulong incremental_snapshot_size;
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

  /* TODO: Don't do this ... should be in the monitor instead */
  struct {
    ulong snaplt_tile_cnt;
    ulong prev_bytes_read;
    ulong prev_accounts_inserted;    volatile ulong * cur_accounts_inserted;

    ulong prev_snaprd_backp_prefrag; volatile ulong * cur_snaprd_backp_prefrag;
    ulong prev_snaprd_wait;          volatile ulong * cur_snaprd_caughtup_postfrag;
    ulong prev_snapdc_backp_prefrag; volatile ulong * cur_snapdc_backp_prefrag;
    ulong prev_snapdc_wait;          volatile ulong * cur_snapdc_caughtup_postfrag;
    ulong prev_snapin_backp_prefrag; volatile ulong * cur_snapin_backp_prefrag;
    ulong prev_snapin_wait;          volatile ulong * cur_snapin_caughtup_postfrag;
    ulong prev_snaplt_backp_prefrag; volatile ulong * cur_snaplt_backp_prefrag[ FD_MAX_SNAPLT_TILES ];
    ulong prev_snaplt_wait;          volatile ulong * cur_snaplt_caughtup_postfrag[ FD_MAX_SNAPLT_TILES ];
  } diagnostics;

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
  uchar * out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );

  FD_TEST( ctx->state==FD_SNAPRD_STATE_READING_INCREMENTAL_FILE || ctx->state==FD_SNAPRD_STATE_READING_FULL_FILE );
  int full = ctx->state==FD_SNAPRD_STATE_READING_FULL_FILE;
  long result = read( full ? ctx->local_in.full_snapshot_fd : ctx->local_in.incremental_snapshot_fd , out, ctx->out.mtu );
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
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE;
        break;
      case FD_SNAPRD_STATE_READING_FULL_FILE:
        if( FD_LIKELY( ctx->config.incremental_snapshot_fetch ) ) {
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_EOF_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        } else {
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        }
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_FILE;
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

  ulong buffer_avail = fd_ulong_if( -1!=ctx->local_out.dir_fd, SNAPRD_FILE_BUF_SZ-ctx->local_out.write_buffer_len, ULONG_MAX );
  ulong data_len = fd_ulong_min( buffer_avail, ctx->out.mtu );
  int result = fd_sshttp_advance( ctx->sshttp, &data_len, out, now );

  switch( result ) {
    case FD_SSHTTP_ADVANCE_AGAIN: break;
    case FD_SSHTTP_ADVANCE_ERROR: {
      FD_LOG_NOTICE(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                      FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ) ));
      fd_ssping_invalidate( ctx->ssping, ctx->addr, now );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
      ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
      ctx->deadline_nanos = now;
      break;
    }
    case FD_SSHTTP_ADVANCE_DONE: {
      switch( ctx->state ) {
        case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP;
          break;
        case FD_SNAPRD_STATE_READING_FULL_HTTP:
          if( FD_LIKELY( ctx->config.incremental_snapshot_fetch ) ) {
            fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_EOF_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
          } else {
            fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
          }
          ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP;
          break;
        default:
          break;
      }
      break;
    }
    case FD_SSHTTP_ADVANCE_DATA: {
      if( FD_LIKELY( ctx->state==FD_SNAPRD_STATE_READING_FULL_HTTP ) ) ctx->metrics.full.bytes_total = fd_sshttp_content_len( ctx->sshttp );
      else                                                             ctx->metrics.incremental.bytes_total = fd_sshttp_content_len( ctx->sshttp );

      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_DATA, ctx->out.chunk, data_len, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, data_len, ctx->out.chunk0, ctx->out.wmark );

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

      switch( ctx->state ) {
        case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
          ctx->metrics.incremental.bytes_read += data_len;
          ctx->metrics.incremental.bytes_written += written_sz;
          break;
        case FD_SNAPRD_STATE_READING_FULL_HTTP:
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
  fd_sshttp_snapshot_names( ctx->sshttp, &full_snapshot_name, &incremental_snapshot_name );

  if( FD_LIKELY( -1!=ctx->local_out.full_snapshot_fd ) ) {
    if( FD_UNLIKELY( -1==renameat( ctx->local_out.dir_fd, "snapshot.tar.bz2-partial", ctx->local_out.dir_fd, full_snapshot_name ) ) )
      FD_LOG_ERR(( "renameat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_LIKELY( -1!=ctx->local_out.incremental_snapshot_fd ) ) {
    if( FD_UNLIKELY( -1==renameat( ctx->local_out.dir_fd, "incremental-snapshot.tar.bz2-partial", ctx->local_out.dir_fd, incremental_snapshot_name ) ) )
      FD_LOG_ERR(( "renameat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static void
print_diagnostics( fd_snaprd_tile_t * ctx ) {
  double bandwidth = (double)((ctx->metrics.full.bytes_read+ctx->metrics.incremental.bytes_read)-ctx->diagnostics.prev_bytes_read)/1e6;

  ulong snaprd_backp = *ctx->diagnostics.cur_snaprd_backp_prefrag;
  ulong snaprd_wait = *ctx->diagnostics.cur_snaprd_caughtup_postfrag + snaprd_backp;
  ulong snapdc_backp = *ctx->diagnostics.cur_snapdc_backp_prefrag;
  ulong snapdc_wait = *ctx->diagnostics.cur_snapdc_caughtup_postfrag + snapdc_backp;
  ulong snapin_backp = *ctx->diagnostics.cur_snapin_backp_prefrag;
  ulong snapin_wait = *ctx->diagnostics.cur_snapin_caughtup_postfrag + snapin_backp;

  ulong snaplt_backp = 0UL;
  ulong snaplt_wait  = 0UL;
  for( ulong i=0UL; i<ctx->diagnostics.snaplt_tile_cnt; i++ ) {
    snaplt_backp += *ctx->diagnostics.cur_snaplt_backp_prefrag[ i ];
    snaplt_wait  += *ctx->diagnostics.cur_snaplt_caughtup_postfrag[ i ] + snaplt_backp;
  }

  ulong accounts_inserted = *ctx->diagnostics.cur_accounts_inserted;

  double ns_per_tick = 1.0/fd_tempo_tick_per_ns( NULL );

  switch( ctx->state ) {
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS:
      FD_LOG_NOTICE(( "waiting for peers from gossip" ));
      break;
    case FD_SNAPRD_STATE_COLLECTING_PEERS:
      FD_LOG_NOTICE(( "collecting peers from gossip" ));
      break;
    case FD_SNAPRD_STATE_READING_FULL_FILE: {
      double progress = 0.0;
      if( FD_LIKELY( ctx->metrics.full.bytes_total ) ) progress = 100.0 * (double)ctx->metrics.full.bytes_read / (double)ctx->metrics.full.bytes_total;
      double snaplt_backp_val = ctx->diagnostics.snaplt_tile_cnt ? ((double)( snaplt_backp-ctx->diagnostics.prev_snaplt_backp_prefrag )*ns_per_tick )/1e7/(double)ctx->diagnostics.snaplt_tile_cnt : 0.0;
      double snaplt_busy_val  = ctx->diagnostics.snaplt_tile_cnt ? 100-(((double)( snaplt_wait-ctx->diagnostics.prev_snaplt_wait )*ns_per_tick )/1e7/(double)ctx->diagnostics.snaplt_tile_cnt ) : 0.0;
      FD_LOG_NOTICE(( "restoring full from file ... (%.1f %%) bw=%3.f MB/s backp=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) busy=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) acc=%3.1f M/s",
        progress,
        bandwidth,
        ((double)(snaprd_backp-ctx->diagnostics.prev_snaprd_backp_prefrag)*ns_per_tick )/1e7,
        ((double)(snapdc_backp-ctx->diagnostics.prev_snapdc_backp_prefrag)*ns_per_tick )/1e7,
        ((double)(snapin_backp-ctx->diagnostics.prev_snapin_backp_prefrag)*ns_per_tick )/1e7,
        snaplt_backp_val,
        100-(((double)(snaprd_wait-ctx->diagnostics.prev_snaprd_wait)*ns_per_tick )/1e7 ),
        100-(((double)(snapdc_wait-ctx->diagnostics.prev_snapdc_wait)*ns_per_tick )/1e7 ),
        100-(((double)(snapin_wait-ctx->diagnostics.prev_snapin_wait)*ns_per_tick )/1e7 ),
        snaplt_busy_val,
        (double)( accounts_inserted-ctx->diagnostics.prev_accounts_inserted  )/1e6 ));
      break;
    }
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE: {
      FD_LOG_NOTICE(( "flushing full from file ... 100.0 %% bw=   0 MB/s" ));
      break;
    }
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET:
      FD_LOG_NOTICE(( "resetting full from file ... 100.0 %% bw=   0 MB/s" ));
      break;
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE: {
      double progress = 0.0;
      if( FD_LIKELY( ctx->metrics.incremental.bytes_total ) ) progress = 100.0 * (double)ctx->metrics.incremental.bytes_read / (double)ctx->metrics.incremental.bytes_total;
      double snaplt_backp_val = ctx->diagnostics.snaplt_tile_cnt ? ((double)( snaplt_backp-ctx->diagnostics.prev_snaplt_backp_prefrag )*ns_per_tick )/1e7/(double)ctx->diagnostics.snaplt_tile_cnt : 0.0;
      double snaplt_busy_val  = ctx->diagnostics.snaplt_tile_cnt ? 100-(((double)( snaplt_wait-ctx->diagnostics.prev_snaplt_wait )*ns_per_tick )/1e7/(double)ctx->diagnostics.snaplt_tile_cnt ) : 0.0;
      FD_LOG_NOTICE(( "restoring incremental from file ... (%.1f %%) bw=%3.f MB/s backp=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) busy=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) acc=%3.1f M/s",
        progress,
        bandwidth,
        ((double)(snaprd_backp-ctx->diagnostics.prev_snaprd_backp_prefrag)*ns_per_tick )/1e7,
        ((double)(snapdc_backp-ctx->diagnostics.prev_snapdc_backp_prefrag)*ns_per_tick )/1e7,
        ((double)(snapin_backp-ctx->diagnostics.prev_snapin_backp_prefrag)*ns_per_tick )/1e7,
        snaplt_backp_val,
        100-(((double)(snaprd_wait-ctx->diagnostics.prev_snaprd_wait)*ns_per_tick )/1e7 ),
        100-(((double)(snapdc_wait-ctx->diagnostics.prev_snapdc_wait)*ns_per_tick )/1e7 ),
        100-(((double)(snapin_wait-ctx->diagnostics.prev_snapin_wait)*ns_per_tick )/1e7 ),
        snaplt_busy_val,
        (double)( accounts_inserted-ctx->diagnostics.prev_accounts_inserted  )/1e6 ));
      break;
    }
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE: {
      FD_LOG_NOTICE(( "flushing incremental from file ... 100.0 %% bw=   0 MB/s" ));
      break;
    }
    case FD_SNAPRD_STATE_READING_FULL_HTTP: {
      double progress = 0.0;
      if( FD_LIKELY( ctx->metrics.full.bytes_total ) ) progress = 100.0 * (double)ctx->metrics.full.bytes_read / (double)ctx->metrics.full.bytes_total;
      double snaplt_backp_val = ctx->diagnostics.snaplt_tile_cnt ? ((double)( snaplt_backp-ctx->diagnostics.prev_snaplt_backp_prefrag )*ns_per_tick )/1e7/(double)ctx->diagnostics.snaplt_tile_cnt : 0.0;
      double snaplt_busy_val  = ctx->diagnostics.snaplt_tile_cnt ? 100-(((double)( snaplt_wait-ctx->diagnostics.prev_snaplt_wait )*ns_per_tick )/1e7/(double)ctx->diagnostics.snaplt_tile_cnt ) : 0.0;
      FD_LOG_NOTICE(( "restoring full from http ... (%.1f %%) bw=%3.f MB/s backp=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) busy=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) acc=%3.1f M/s",
        progress,
        bandwidth,
        ((double)(snaprd_backp-ctx->diagnostics.prev_snaprd_backp_prefrag)*ns_per_tick )/1e7,
        ((double)(snapdc_backp-ctx->diagnostics.prev_snapdc_backp_prefrag)*ns_per_tick )/1e7,
        ((double)(snapin_backp-ctx->diagnostics.prev_snapin_backp_prefrag)*ns_per_tick )/1e7,
        snaplt_backp_val,
        100-(((double)(snaprd_wait-ctx->diagnostics.prev_snaprd_wait)*ns_per_tick )/1e7 ),
        100-(((double)(snapdc_wait-ctx->diagnostics.prev_snapdc_wait)*ns_per_tick )/1e7 ),
        100-(((double)(snapin_wait-ctx->diagnostics.prev_snapin_wait)*ns_per_tick )/1e7 ),
        snaplt_busy_val,
        (double)( accounts_inserted-ctx->diagnostics.prev_accounts_inserted  )/1e6 ));
      break;
    }
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP: {
      FD_LOG_NOTICE(( "flushing full from http ... 100.0 %% bw=   0 MB/s" ));
      break;
    }
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET: {
      FD_LOG_NOTICE(( "resetting full from http ... 100.0 %% bw=   0 MB/s" ));
      break;
    }
    case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP: {
      double progress = 0.0;
      if( FD_LIKELY( ctx->metrics.incremental.bytes_total ) ) progress = 100.0 * (double)ctx->metrics.incremental.bytes_read / (double)ctx->metrics.incremental.bytes_total;
      double snaplt_backp_val = ctx->diagnostics.snaplt_tile_cnt ? ((double)( snaplt_backp-ctx->diagnostics.prev_snaplt_backp_prefrag )*ns_per_tick )/1e7/(double)ctx->diagnostics.snaplt_tile_cnt : 0.0;
      double snaplt_busy_val  = ctx->diagnostics.snaplt_tile_cnt ? 100-(((double)( snaplt_wait-ctx->diagnostics.prev_snaplt_wait )*ns_per_tick )/1e7/(double)ctx->diagnostics.snaplt_tile_cnt ) : 0.0;
      FD_LOG_NOTICE(( "restoring incremental from http ... (%.1f %%) bw=%3.f MB/s backp=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) busy=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) acc=%3.1f M/s",
        progress,
        bandwidth,
        ((double)(snaprd_backp-ctx->diagnostics.prev_snaprd_backp_prefrag)*ns_per_tick )/1e7,
        ((double)(snapdc_backp-ctx->diagnostics.prev_snapdc_backp_prefrag)*ns_per_tick )/1e7,
        ((double)(snapin_backp-ctx->diagnostics.prev_snapin_backp_prefrag)*ns_per_tick )/1e7,
        snaplt_backp_val,
        100-(((double)(snaprd_wait-ctx->diagnostics.prev_snaprd_wait)*ns_per_tick )/1e7 ),
        100-(((double)(snapdc_wait-ctx->diagnostics.prev_snapdc_wait)*ns_per_tick )/1e7 ),
        100-(((double)(snapin_wait-ctx->diagnostics.prev_snapin_wait)*ns_per_tick )/1e7 ),
        snaplt_busy_val,
        (double)( accounts_inserted-ctx->diagnostics.prev_accounts_inserted  )/1e6 ));
      break;
    }
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP: {
      FD_LOG_NOTICE(( "flushing incremental from http ... 100.0 %% bw=   0 MB/s" ));
      break;
    }
    case FD_SNAPRD_STATE_SHUTDOWN: {
      break;
    }
    default:
      break;
  }

  ctx->diagnostics.prev_bytes_read = ctx->metrics.full.bytes_read+ctx->metrics.incremental.bytes_read;

  ctx->diagnostics.prev_snaprd_backp_prefrag = snaprd_backp;
  ctx->diagnostics.prev_snaprd_wait          = snaprd_wait;
  ctx->diagnostics.prev_snapdc_backp_prefrag = snapdc_backp;
  ctx->diagnostics.prev_snapdc_wait          = snapdc_wait;
  ctx->diagnostics.prev_snapin_backp_prefrag = snapin_backp;
  ctx->diagnostics.prev_snapin_wait          = snapin_wait;
  ctx->diagnostics.prev_snaplt_backp_prefrag = snaplt_backp;
  ctx->diagnostics.prev_snaplt_wait          = snaplt_wait;

  ctx->diagnostics.prev_accounts_inserted    = accounts_inserted;
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

  /* All control fragments sent by the snaprd tile must be fully
     acknowledged by all downstream consumers before processing can
     proceed, to prevent tile state machines from getting out of sync
     (see fd_ssctrl.h for more details).  Currently there are three
     downstream consumers, snapdc, snapin, and snaplt. */
#define NUM_SNAP_CONSUMERS (2UL + ctx->diagnostics.snaplt_tile_cnt)

  if( FD_UNLIKELY( now>ctx->diagnostic_deadline_nanos ) ) {
    ctx->diagnostic_deadline_nanos = now+(long)1e9;
    print_diagnostics( ctx );
  }

  switch ( ctx->state ) {
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS: {
      fd_ip4_port_t best = fd_ssping_best( ctx->ssping );
      if( FD_LIKELY( best.l ) ) {
        ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
        ctx->deadline_nanos = now+500L*1000L*1000L;
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
        FD_LOG_NOTICE(( "reading full snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        ctx->metrics.full.bytes_total = ctx->local_in.full_snapshot_size;
        ctx->state = FD_SNAPRD_STATE_READING_FULL_FILE;
      } else {
        FD_LOG_NOTICE(( "downloading full snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( best.addr ), fd_ushort_bswap( best.port ) ));
        ctx->addr  = best;
        ctx->state = FD_SNAPRD_STATE_READING_FULL_HTTP;
        fd_sshttp_init( ctx->sshttp, best, "/snapshot.tar.bz2", 17UL, now );
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
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        ctx->malformed = 0;
        break;
      }

      if( FD_UNLIKELY( ctx->local_out.write_buffer_len ) ) break;

      rename_snapshots( ctx );
      ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
      break;
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      if( FD_LIKELY( !ctx->config.incremental_snapshot_fetch ) ) {
        ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
        metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      FD_LOG_NOTICE(( "reading incremental snapshot from local file `%s`", ctx->local_in.incremental_snapshot_path ));
      ctx->metrics.incremental.bytes_total = ctx->local_in.incremental_snapshot_size;
      ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_FILE;
      break;
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        ctx->malformed = 0;
        break;
      }

      if( FD_UNLIKELY( ctx->local_out.write_buffer_len ) ) break;

      if( FD_LIKELY( !ctx->config.incremental_snapshot_fetch ) ) {
        rename_snapshots( ctx );
        ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
        metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      FD_LOG_NOTICE(( "downloading incremental snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ) ));
      fd_sshttp_init( ctx->sshttp, ctx->addr, "/incremental-snapshot.tar.bz2", 29UL, fd_log_wallclock() );
      ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP;
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
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
          break;
        case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:
        case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:
          if( FD_UNLIKELY( ctx->malformed ) ) break;

          FD_LOG_NOTICE(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2",
                          FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
          fd_sshttp_cancel( ctx->sshttp );
          fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
          /* We would like to transition to FULL_HTTP_RESET, but we
             can't do it just yet, because we have already sent a DONE
             control fragment, and need to wait for acknowledges to come
             back first, to ensure there's only one control message
             outstanding at a time. */
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

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  /* By default, the snaprd tile selects peers and its initial state is
     WAITING_FOR_PEERS. */
  ctx->peer_selection = 1;
  ctx->state = FD_SNAPRD_STATE_WAITING_FOR_PEERS;

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
    if( FD_UNLIKELY( !tile->snaprd.do_download ) ) {
      FD_LOG_ERR(( "No snapshots found in `%s` and downloading is disabled. "
                   "Please enable downloading via [snapshots.download] and restart.", tile->snaprd.snapshots_path ));
    }

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

    struct stat full_stat;
    if( FD_UNLIKELY( -1==fstat( ctx->local_in.full_snapshot_fd, &full_stat ) ) ) FD_LOG_ERR(( "stat() failed `%s` (%i-%s)", full_path, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !S_ISREG( full_stat.st_mode ) ) ) FD_LOG_ERR(( "full snapshot path `%s` is not a regular file", full_path ));
    ctx->local_in.full_snapshot_size = (ulong)full_stat.st_size;

    if( FD_LIKELY( tile->snaprd.incremental_snapshot_fetch ) ) FD_TEST( incremental_slot!=ULONG_MAX );

    if( FD_LIKELY( incremental_slot!=ULONG_MAX ) ) {
      strncpy( ctx->local_in.incremental_snapshot_path, incremental_path, PATH_MAX );
      ctx->local_in.incremental_snapshot_fd = open( ctx->local_in.incremental_snapshot_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
      if( FD_UNLIKELY( -1==ctx->local_in.incremental_snapshot_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", ctx->local_in.incremental_snapshot_path, errno, fd_io_strerror( errno ) ));

      struct stat incremental_stat;
      if( FD_UNLIKELY( -1==fstat( ctx->local_in.incremental_snapshot_fd, &incremental_stat ) ) ) FD_LOG_ERR(( "stat() failed `%s` (%i-%s)", incremental_path, errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( !S_ISREG( incremental_stat.st_mode ) ) ) FD_LOG_ERR(( "incremental snapshot path `%s` is not a regular file", incremental_path ));
      ctx->local_in.incremental_snapshot_size = (ulong)incremental_stat.st_size;
    }

    ctx->local_out.dir_fd = -1;
    ctx->local_out.full_snapshot_fd = -1;
    ctx->local_out.incremental_snapshot_fd = -1;

    if( FD_UNLIKELY( tile->snaprd.maximum_local_snapshot_age==0U ) ) {
      /* Disable peer selection if we are reading snapshots from disk
         and there is no maximum local snapshot age set.  Set the
         initial state to READING_FULL_FILE to avoid peer selection
         logic.

         TODO: Why? Document in TOML. */
      ctx->peer_selection = 0;
      ctx->state = FD_SNAPRD_STATE_READING_FULL_FILE;
      ctx->metrics.full.bytes_total = ctx->local_in.full_snapshot_size;
      FD_LOG_NOTICE(( "reading full snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
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

  if( FD_UNLIKELY( tile->snaprd.diagnostics ) ) ctx->diagnostic_deadline_nanos = fd_log_wallclock()+(long)1e9;
  else                                          ctx->diagnostic_deadline_nanos = LONG_MAX;

  ctx->local_out.write_buffer_pos = 0UL;
  ctx->local_out.write_buffer_len = 0UL;

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

  memset( &ctx->diagnostics, 0, sizeof(ctx->diagnostics) );

  fd_topo_tile_t * snaprd_tile = &topo->tiles[ fd_topo_find_tile( topo, "snaprd", 0UL ) ];
  fd_topo_tile_t * snapdc_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapdc", 0UL ) ];
  fd_topo_tile_t * snapin_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];
  ulong volatile * const snaprd_metrics = fd_metrics_tile( snaprd_tile->metrics );
  ulong volatile * const snapdc_metrics = fd_metrics_tile( snapdc_tile->metrics );
  ulong volatile * const snapin_metrics = fd_metrics_tile( snapin_tile->metrics );

  ulong volatile * snaplt_metrics[ FD_MAX_SNAPLT_TILES ];
  ctx->diagnostics.snaplt_tile_cnt = fd_topo_tile_name_cnt( topo, "snaplt" );

  for( ulong i=0UL; i<ctx->diagnostics.snaplt_tile_cnt; i++ ) {
    ulong snaplt_tile_idx = fd_topo_find_tile( topo, "snaplt", i );
    FD_TEST( snaplt_tile_idx!=ULONG_MAX );
    fd_topo_tile_t * snaplt_tile = &topo->tiles[ snaplt_tile_idx ];
    snaplt_metrics[ i ]          = fd_metrics_tile( snaplt_tile->metrics );
  }

  ctx->diagnostics.cur_snaprd_backp_prefrag     = snaprd_metrics+MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG );
  ctx->diagnostics.cur_snaprd_caughtup_postfrag = snaprd_metrics+MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG );
  ctx->diagnostics.cur_snapdc_backp_prefrag     = snapdc_metrics+MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG );
  ctx->diagnostics.cur_snapdc_caughtup_postfrag = snapdc_metrics+MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG );
  ctx->diagnostics.cur_snapin_backp_prefrag     = snapin_metrics+MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG );
  ctx->diagnostics.cur_snapin_caughtup_postfrag = snapin_metrics+MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG );

  for( ulong i=0UL; i<ctx->diagnostics.snaplt_tile_cnt; i++ ) {
    ctx->diagnostics.cur_snaplt_backp_prefrag[ i ] = snaplt_metrics[ i ]+MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG );
    ctx->diagnostics.cur_snaplt_caughtup_postfrag[ i ] = snaplt_metrics[ i ]+MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG );
  }
  ctx->diagnostics.cur_accounts_inserted = snapin_metrics+MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED );

  ctx->gossip.ci_table = _ci_table;
  /* zero-out memory so that we can perform null checks in after_frag */
  fd_memset( ctx->gossip.ci_table, 0, sizeof(fd_contact_info_t) * FD_CONTACT_INFO_TABLE_SIZE );

  FD_TEST( tile->in_cnt<=MAX_IN_LINK_KINDS + ctx->diagnostics.snaplt_tile_cnt );
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
               0==strcmp( in_link->name, "snapin_rd" ) ||
               0==strcmp( in_link->name, "snaplt_rd" ) ) {
      ctx->in_kind[ i ] = IN_KIND_SNAPCTL;
    }
  }

  for( ulong i=0UL; i<tile->snaprd.http.peers_cnt; i++ ) fd_ssping_add( ctx->ssping, tile->snaprd.http.peers[ i ] );

  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt ));

  ctx->out.wksp   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0 = fd_dcache_compact_chunk0( ctx->out.wksp, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out.wmark  = fd_dcache_compact_wmark ( ctx->out.wksp, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out.chunk  = ctx->out.chunk0;
  ctx->out.mtu    = topo->links[ tile->out_link_id[ 0 ] ].mtu;
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
