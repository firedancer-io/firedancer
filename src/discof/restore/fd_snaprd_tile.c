#define _GNU_SOURCE /* SOL_TCP (seccomp) */

#include "fd_snaprd_tile.h"
#include "utils/fd_ssping.h"
#include "utils/fd_sshttp.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_ssarchive.h"
#include "utils/fd_http_resolver.h"
#include "utils/fd_ssmsg.h"

#include "fd_snaprd_tile.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../../app/shared/fd_config.h"

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "generated/fd_snaprd_tile_seccomp.h"

#define FD_SSPING_MAX_PEERS (65536UL)

#define NAME "snaprd"

#define FD_SNAPRD_MAX_HTTP_PEERS (16UL)          /* Maximum number of configured http peers */
#define SNAPRD_FILE_BUF_SZ       (1024UL*1024UL) /* 1 MiB */

#define IN_KIND_SNAPCTL (0)
#define IN_KIND_GOSSIP  (1)
#define MAX_IN_LINKS    (3)

struct fd_restore_out_link {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};

typedef struct fd_restore_out_link fd_restore_out_link_t;

#define FD_SNAPRD_GOSSIP_FRESH_DEADLINE_NANOS              (7.5L*1000L*1000L*1000L)   /* gossip contact info is pushed every 7.5 seconds */
#define FD_SNAPRD_GOSSIP_SATURATION_THRESHOLD              (0.05)                     /* 5% fresh peers */
#define FD_SNAPRD_GOSSIP_TIMEOUT_DEADLINE_NANOS            (2L*60L*1000L*1000L*1000L) /* 2 minutes */
#define FD_SNAPRD_WAITING_FOR_PEERS_TIMEOUT_DEADLINE_NANOS (2L*60L*1000L*1000L*1000L) /* 2 minutes */

struct fd_snaprd_gossip_ci_entry {
  fd_ip4_port_t gossip_addr;
  fd_ip4_port_t rpc_addr;
  fd_pubkey_t   pubkey;
  long          wallclock_nanos;

  struct {
    ulong prev;
    ulong next;
  } map;

  struct {
    ulong next;
  } pool;
};

typedef struct fd_snaprd_gossip_ci_entry fd_snaprd_gossip_ci_entry_t;

#define POOL_NAME  gossip_ci_pool
#define POOL_T     fd_snaprd_gossip_ci_entry_t
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME gossip_ci_map
#define MAP_KEY  pubkey
#define MAP_ELE_T fd_snaprd_gossip_ci_entry_t
#define MAP_KEY_T fd_pubkey_t
#define MAP_PREV  map.prev
#define MAP_NEXT  map.next
#define MAP_KEY_EQ(k0,k1)  fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_snaprd_tile {
  fd_ssping_t *          ssping;
  fd_sshttp_t *          sshttp;
  fd_http_resolver_t *   ssresolver;
  fd_sspeer_selector_t * selector;

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
    struct {
      ulong slot;
    } full;

    struct {
      ulong slot;
    } incremental;
  } http;

  struct {
    ulong slot;
    int   dirty;
  } predicted_incremental;

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
    int  entrypoints_enabled;
    int  gossip_peers_enabled;
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
    fd_snaprd_gossip_ci_entry_t * ci_pool;
    gossip_ci_map_t *             ci_map;
    fd_gossip_update_message_t    tmp_upd_buf;
    fd_ip4_port_t                 entrypoints[ GOSSIP_TILE_ENTRYPOINTS_MAX ];
    ulong                         entrypoints_cnt;
    ulong                         entrypoints_received;
    double                        fresh;
    ulong                         fresh_cnt;
    ulong                         total_cnt;
    int                           saturated;
  } gossip;

  fd_restore_out_link_t out_snapctl;
  fd_restore_out_link_t out_gui;
  fd_restore_out_link_t out_rp;

  /* Ensure snapshot path is only published to the gui tile once */
  int gui_full_path_published;
  int gui_incremental_path_published;
};

typedef struct fd_snaprd_tile fd_snaprd_tile_t;

static ulong
scratch_align( void ) {
  return alignof(fd_snaprd_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaprd_tile_t),  sizeof(fd_snaprd_tile_t)                                                             );
  l = FD_LAYOUT_APPEND( l, fd_sshttp_align(),          fd_sshttp_footprint()                                                                );
  l = FD_LAYOUT_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( FD_SSPING_MAX_PEERS )                                           );
  l = FD_LAYOUT_APPEND( l, gossip_ci_pool_align(),     gossip_ci_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE )                               );
  l = FD_LAYOUT_APPEND( l, gossip_ci_map_align(),      gossip_ci_map_footprint( gossip_ci_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ) ) );
  l = FD_LAYOUT_APPEND( l, fd_http_resolver_align(),   fd_http_resolver_footprint( FD_SNAPRD_MAX_HTTP_PEERS )                               );
  l = FD_LAYOUT_APPEND( l, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( FD_SSPING_MAX_PEERS )                                  );
  return FD_LAYOUT_FINI( l, alignof(fd_snaprd_tile_t) );
}

static inline int
should_shutdown( fd_snaprd_tile_t * ctx ) {
  return ctx->state==FD_SNAPRD_STATE_SHUTDOWN;
}

static inline int
is_entrypoint( fd_snaprd_tile_t * ctx, fd_ip4_port_t addr ) {
  for( ulong i=0UL; i<ctx->gossip.entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( ctx->gossip.entrypoints[ i ].l==addr.l ) ) return 1;
  }
  return 0;
}

static int
all_entrypoints_received( fd_snaprd_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->config.entrypoints_enabled ) ) return 1;
  if( FD_UNLIKELY( ctx->gossip.entrypoints_received==ctx->gossip.entrypoints_cnt ) ) return 1;

  ulong received_gossip_entrypoints = 0UL;
  for( ulong i=0UL; i<ctx->gossip.entrypoints_cnt; i++ ) {
    for( gossip_ci_map_iter_t iter = gossip_ci_map_iter_init( ctx->gossip.ci_map, ctx->gossip.ci_pool );
         !gossip_ci_map_iter_done( iter, ctx->gossip.ci_map, ctx->gossip.ci_pool );
         iter = gossip_ci_map_iter_next( iter, ctx->gossip.ci_map, ctx->gossip.ci_pool ) ) {
      fd_snaprd_gossip_ci_entry_t const * ci_entry = gossip_ci_map_iter_ele_const( iter, ctx->gossip.ci_map, ctx->gossip.ci_pool );
      if( FD_LIKELY( ci_entry->gossip_addr.l==ctx->gossip.entrypoints[ i ].l ) ) {
        received_gossip_entrypoints++;
        break;
      }
    }
  }

  ctx->gossip.entrypoints_received = received_gossip_entrypoints;
  return received_gossip_entrypoints==ctx->gossip.entrypoints_cnt;
}

static int
gossip_saturated( fd_snaprd_tile_t * ctx,
                  long               now ) {
  if( FD_UNLIKELY( !ctx->config.gossip_peers_enabled ) ) return 1;
  if( FD_UNLIKELY( ctx->gossip.saturated ) ) return 1;

  ulong fresh_cnt = 0UL;
  ulong total_cnt = 0UL;
  for( gossip_ci_map_iter_t iter = gossip_ci_map_iter_init( ctx->gossip.ci_map, ctx->gossip.ci_pool );
        !gossip_ci_map_iter_done( iter, ctx->gossip.ci_map, ctx->gossip.ci_pool );
        iter = gossip_ci_map_iter_next( iter, ctx->gossip.ci_map, ctx->gossip.ci_pool ) ) {
    fd_snaprd_gossip_ci_entry_t const * ci_entry = gossip_ci_map_iter_ele_const( iter, ctx->gossip.ci_map, ctx->gossip.ci_pool );
    if( FD_UNLIKELY( ci_entry->wallclock_nanos>(now-FD_SNAPRD_GOSSIP_FRESH_DEADLINE_NANOS) ) ) fresh_cnt++;
    total_cnt++;
  }

  double fresh = total_cnt ? (double)fresh_cnt/(double)total_cnt : 1.0;
  ctx->gossip.fresh_cnt = fresh_cnt;
  ctx->gossip.total_cnt = total_cnt;
  ctx->gossip.fresh     = fresh;
  ctx->gossip.saturated = fresh<FD_SNAPRD_GOSSIP_SATURATION_THRESHOLD;
  return ctx->gossip.saturated;
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

  FD_MGAUGE_SET( SNAPRD, PREDICTED_SLOT,                ctx->predicted_incremental.slot );

  FD_MGAUGE_SET( SNAPRD, STATE, (ulong)ctx->state );
}

static void
snapshot_path_gui_publish( fd_snaprd_tile_t *  ctx,
                           fd_stem_context_t * stem,
                           char const *        path,
                           int                 is_full ) {
  fd_snaprd_update_t * out = fd_chunk_to_laddr( ctx->out_gui.mem, ctx->out_gui.chunk );
  FD_TEST( fd_cstr_printf_check( out->read_path, PATH_MAX, NULL, "%s", path ) );
  out->is_download = 0;
  out->type = fd_int_if( is_full, FD_SNAPRD_SNAPSHOT_TYPE_FULL, FD_SNAPRD_SNAPSHOT_TYPE_INCREMENTAL );
  fd_stem_publish( stem, ctx->out_gui.idx, 0UL, ctx->out_gui.chunk, sizeof(fd_snaprd_update_t) , 0UL, 0UL, 0UL );
  ctx->out_gui.chunk = fd_dcache_compact_next( ctx->out_gui.chunk, sizeof(fd_snaprd_update_t), ctx->out_gui.chunk0, ctx->out_gui.wmark );
  if( is_full ) ctx->gui_full_path_published = 1;
  else          ctx->gui_incremental_path_published = 1;
}

static void
predict_incremental( fd_snaprd_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->config.incremental_snapshot_fetch ) ) return;
  if( FD_UNLIKELY( ctx->http.full.slot==ULONG_MAX ) )          return;

  fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->http.full.slot );

  if( FD_LIKELY( best.addr.l ) ) {
    if( FD_UNLIKELY( ctx->predicted_incremental.slot!=best.ssinfo.incremental.slot ) ) {
      ctx->predicted_incremental.slot  = best.ssinfo.incremental.slot;
      ctx->predicted_incremental.dirty = 1;
    }
  }
}

static void
on_resolve( void *              _ctx,
            fd_ip4_port_t       addr,
            fd_ssinfo_t const * ssinfo ) {
  fd_snaprd_tile_t * ctx = (fd_snaprd_tile_t *)_ctx;

  fd_sspeer_selector_add( ctx->selector, addr, ULONG_MAX, ssinfo );
  fd_sspeer_selector_process_cluster_slot( ctx->selector, ssinfo );
  predict_incremental( ctx );
}

static void
on_ping( void *        _ctx,
         fd_ip4_port_t addr,
         ulong         latency ) {
  fd_snaprd_tile_t * ctx = (fd_snaprd_tile_t *)_ctx;

  fd_sspeer_selector_add( ctx->selector, addr, latency, NULL );
  predict_incremental( ctx );
}

static void
on_snapshot_hash( fd_snaprd_tile_t *                 ctx,
                  fd_ip4_port_t                      addr,
                  fd_gossip_update_message_t const * msg ) {
  ulong full_slot = msg->snapshot_hashes.full->slot;
  ulong incr_slot = 0UL;

  for( ulong i=0UL; i<msg->snapshot_hashes.incremental_len; i++ ) {
    if( FD_LIKELY( msg->snapshot_hashes.incremental[ i ].slot>incr_slot ) ) {
      incr_slot = msg->snapshot_hashes.incremental[ i ].slot;
    }
  }

  fd_ssinfo_t ssinfo = { .full = { .slot = msg->snapshot_hashes.full->slot },
                        .incremental = { .slot = incr_slot, .base_slot = full_slot } };

  fd_sspeer_selector_add( ctx->selector, addr, ULONG_MAX, &ssinfo );
  fd_sspeer_selector_process_cluster_slot( ctx->selector, &ssinfo );
  predict_incremental( ctx );
}

static void
send_expected_slot( fd_stem_context_t * stem,
                    ulong               slot ) {
  uint tsorig; uint tspub;
  fd_ssmsg_slot_to_frag( slot, &tsorig, &tspub );
  fd_stem_publish( stem, 1UL, FD_SSMSG_EXPECTED_SLOT, 0UL, 0UL, 0UL, tsorig, tspub );
}

static void
read_file_data( fd_snaprd_tile_t *  ctx,
                fd_stem_context_t * stem ) {
  uchar * out = fd_chunk_to_laddr( ctx->out_snapctl.mem, ctx->out_snapctl.chunk );

  FD_TEST( ctx->state==FD_SNAPRD_STATE_READING_INCREMENTAL_FILE || ctx->state==FD_SNAPRD_STATE_READING_FULL_FILE );
  int full = ctx->state==FD_SNAPRD_STATE_READING_FULL_FILE;
  long result = read( full ? ctx->local_in.full_snapshot_fd : ctx->local_in.incremental_snapshot_fd , out, ctx->out_snapctl.mtu );
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
        fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE;
        break;
      case FD_SNAPRD_STATE_READING_FULL_FILE:
        if( FD_LIKELY( ctx->config.incremental_snapshot_fetch ) ) {
          fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_EOF_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        } else {
          fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        }
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_FILE;
        break;
      default:
        break;
    }
    return;
  }

  fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_DATA, ctx->out_snapctl.chunk, (ulong)result, 0UL, 0UL, 0UL );
  ctx->out_snapctl.chunk = fd_dcache_compact_next( ctx->out_snapctl.chunk, (ulong)result, ctx->out_snapctl.chunk0, ctx->out_snapctl.wmark );
}

static void
read_http_data( fd_snaprd_tile_t *  ctx,
                fd_stem_context_t * stem,
                long                now ) {
  uchar * out = fd_chunk_to_laddr( ctx->out_snapctl.mem, ctx->out_snapctl.chunk );

  ulong buffer_avail = fd_ulong_if( -1!=ctx->local_out.dir_fd, SNAPRD_FILE_BUF_SZ-ctx->local_out.write_buffer_len, ULONG_MAX );
  ulong data_len     = fd_ulong_min( buffer_avail, ctx->out_snapctl.mtu );
  int   result       = fd_sshttp_advance( ctx->sshttp, &data_len, out, now );

  char const * full_snapshot_name;
  char const * incremental_snapshot_name;
  fd_sshttp_snapshot_names( ctx->sshttp, &full_snapshot_name, &incremental_snapshot_name );
  char snapshot_path[ PATH_MAX+30UL ]; /* 30 is fd_cstr_nlen( "https://255.255.255.255:65536/", ULONG_MAX ) */
  if( FD_LIKELY( !ctx->gui_full_path_published && !strcmp( full_snapshot_name, "" ) ) ) {
    FD_TEST( fd_cstr_printf_check( snapshot_path, sizeof(snapshot_path), NULL, "http://" FD_IP4_ADDR_FMT ":%hu/%s", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ), full_snapshot_name ) );
    snapshot_path_gui_publish( ctx, stem, snapshot_path, /* is_full */ 1 );
  }
  if( FD_LIKELY( !ctx->gui_incremental_path_published && !strcmp( full_snapshot_name, "" ) ) ) {
    FD_TEST( fd_cstr_printf_check( snapshot_path, sizeof(snapshot_path), NULL, "http://" FD_IP4_ADDR_FMT ":%hu/%s", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ), incremental_snapshot_name ) );
    snapshot_path_gui_publish( ctx, stem, snapshot_path, /* is_full */ 0 );
  }

  switch( result ) {
    case FD_SSHTTP_ADVANCE_AGAIN: break;
    case FD_SSHTTP_ADVANCE_ERROR: {

      switch( ctx->state ) {
        case FD_SNAPRD_STATE_READING_FULL_HTTP:
          FD_LOG_NOTICE(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                          FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
          break;
        case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
          FD_LOG_NOTICE(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2",
                        FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
          fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET;
          break;
        default:
          break;
      }
      fd_ssping_invalidate( ctx->ssping, ctx->addr, now );
      fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
      ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
      fd_sspeer_selector_remove( ctx->selector, ctx->addr );
      ctx->deadline_nanos = now;
      break;
    }
    case FD_SSHTTP_ADVANCE_DONE: {
      switch( ctx->state ) {
        case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
          fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP;
          break;
        case FD_SNAPRD_STATE_READING_FULL_HTTP:
          if( FD_LIKELY( ctx->config.incremental_snapshot_fetch ) ) {
            fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_EOF_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
          } else {
            fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
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

      fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_DATA, ctx->out_snapctl.chunk, data_len, 0UL, 0UL, 0UL );
      ctx->out_snapctl.chunk = fd_dcache_compact_next( ctx->out_snapctl.chunk, data_len, ctx->out_snapctl.chunk0, ctx->out_snapctl.wmark );

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
remove_temp_files( fd_snaprd_tile_t * ctx ) {
  if( FD_UNLIKELY( -1==ctx->local_out.dir_fd ) ) return;

  if( FD_LIKELY( -1!=ctx->local_out.full_snapshot_fd ) ) {
    if( FD_UNLIKELY( -1==unlinkat( ctx->local_out.dir_fd, "snapshot.tar.bz2-partial", 0 ) ) )
      FD_LOG_ERR(( "unlinkat(snapshot.tar.bz2-partial) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_LIKELY( -1!=ctx->local_out.incremental_snapshot_fd ) ) {
    if( FD_UNLIKELY( -1==unlinkat( ctx->local_out.dir_fd, "incremental-snapshot.tar.bz2-partial", 0 ) ) )
      FD_LOG_ERR(( "unlinkat(incremental-snapshot.tar.bz2-partial) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  /* stderr, logfile, dirfd, local out full fd, local out incremental
     fd, local in full fd, local in incremental fd, and one spare for a
     socket(). */

  return 1UL +                      /* stderr */
         1UL +                      /* logfile */
         FD_SSPING_MAX_PEERS +      /* ssping max peers sockets */
         FD_SNAPRD_MAX_HTTP_PEERS + /* http resolver max peers sockets */
         3UL +                      /* dirfd + 2 snapshot file fds in the worst case */
         1UL;                       /* sshttp socket */
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaprd_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t), sizeof(fd_snaprd_tile_t) );

  populate_sock_filter_policy_fd_snaprd_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->local_out.dir_fd, (uint)ctx->local_out.full_snapshot_fd, (uint)ctx->local_out.incremental_snapshot_fd, (uint)ctx->local_in.full_snapshot_fd, (uint)ctx->local_in.incremental_snapshot_fd );
  return sock_filter_policy_fd_snaprd_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  /* In the worst case we expect these file descriptors to be open:
     - stderr
     - logfile
     - 5 file descriptors for the directory fd, 2 snapshot file fds for
       http downloads, and 2 snapshot file fds for snapshot files on
       disk. */

  if( FD_UNLIKELY( out_fds_cnt<7UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaprd_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t), sizeof(fd_snaprd_tile_t) );
  if( FD_LIKELY( -1!=ctx->local_out.dir_fd ) )                  out_fds[ out_cnt++ ] = ctx->local_out.dir_fd;
  if( FD_LIKELY( -1!=ctx->local_out.full_snapshot_fd ) )        out_fds[ out_cnt++ ] = ctx->local_out.full_snapshot_fd;
  if( FD_LIKELY( -1!=ctx->local_out.incremental_snapshot_fd ) ) out_fds[ out_cnt++ ] = ctx->local_out.incremental_snapshot_fd;
  if( FD_LIKELY( -1!=ctx->local_in.full_snapshot_fd ) )         out_fds[ out_cnt++ ] = ctx->local_in.full_snapshot_fd;
  if( FD_LIKELY( -1!=ctx->local_in.incremental_snapshot_fd ) )  out_fds[ out_cnt++ ] = ctx->local_in.incremental_snapshot_fd;

  return out_cnt;
}

static void
after_credit( fd_snaprd_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  (void)charge_busy;

  long now = fd_log_wallclock();

  /* If snapshots are read from disk, we can immediatley publish an
     update notificaiton with the snapshot slot and load path */
  if( FD_UNLIKELY( ctx->local_in.full_snapshot_slot!=ULONG_MAX && !ctx->gui_full_path_published ) ) {
    snapshot_path_gui_publish( ctx, stem, ctx->local_in.full_snapshot_path, /* is_full */ 1 );
    *opt_poll_in = 0;
    return;
  }
  if( FD_UNLIKELY( ctx->local_in.incremental_snapshot_slot!=ULONG_MAX && !ctx->gui_incremental_path_published ) ) {
    snapshot_path_gui_publish( ctx, stem, ctx->local_in.incremental_snapshot_path, /* is_full */ 0 );
    *opt_poll_in = 0;
    return;
  }

  if( FD_LIKELY( ctx->peer_selection ) ) {
    fd_ssping_advance( ctx->ssping, now, ctx->selector );
    fd_http_resolver_advance( ctx->ssresolver, now, ctx->selector );

    /* send an expected slot message as the predicted incremental
       could have changed as a result of the pinger, resolver, or from
       processing gossip frags in after_frag. */
    if( FD_LIKELY( ctx->predicted_incremental.dirty ) ) {
      send_expected_slot( stem, ctx->predicted_incremental.slot );
      ctx->predicted_incremental.dirty = 0;
    }
  }

  drain_buffer( ctx );

  /* All control fragments sent by the snaprd tile must be fully
     acknowledged by all downstream consumers before processing can
     proceed, to prevent tile state machines from getting out of sync
     (see fd_ssctrl.h for more details).  Currently there are two
     downstream consumers, snapdc and snapin. */
#define NUM_SNAP_CONSUMERS (2UL)

  switch ( ctx->state ) {
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS: {
      if( FD_UNLIKELY( now>ctx->deadline_nanos ) ) FD_LOG_ERR(( "timed out waiting for peers." ));

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_LIKELY( best.addr.l ) ) {
        ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
        ctx->deadline_nanos = now+FD_SNAPRD_GOSSIP_TIMEOUT_DEADLINE_NANOS;
      }
      break;
    }
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS_INCREMENTAL: {
      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_LIKELY( best.addr.l ) ) {
        ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL;
        ctx->deadline_nanos = now;
      }
      break;
    }
    case FD_SNAPRD_STATE_COLLECTING_PEERS: {
      if( FD_UNLIKELY( (!gossip_saturated( ctx, now ) || !all_entrypoints_received( ctx )) && now<ctx->deadline_nanos ) ) break;

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        ctx->state = FD_SNAPRD_STATE_WAITING_FOR_PEERS;
        break;
      }

      fd_ssinfo_t cluster      = fd_sspeer_selector_cluster_slot( ctx->selector );
      ulong       cluster_slot = ctx->config.incremental_snapshot_fetch ? cluster.incremental.slot : cluster.full.slot;
      ulong       local_slot   = ctx->config.incremental_snapshot_fetch ? ctx->local_in.incremental_snapshot_slot : ctx->local_in.full_snapshot_slot;
      if( FD_LIKELY( local_slot!=ULONG_MAX && local_slot>=fd_ulong_sat_sub( cluster_slot, ctx->config.maximum_local_snapshot_age ) ) ) {
        send_expected_slot( stem, local_slot );

        FD_LOG_NOTICE(( "reading full snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        ctx->metrics.full.bytes_total = ctx->local_in.full_snapshot_size;
        ctx->state                    = FD_SNAPRD_STATE_READING_FULL_FILE;
      } else {
        if( FD_UNLIKELY( !ctx->config.incremental_snapshot_fetch ) ) send_expected_slot( stem, best.ssinfo.full.slot );

        fd_sspeer_t best_incremental = fd_sspeer_selector_best( ctx->selector, 1, best.ssinfo.full.slot );
        if( FD_LIKELY( best_incremental.addr.l ) ) {
          ctx->predicted_incremental.slot = best_incremental.ssinfo.incremental.slot;
          send_expected_slot( stem, best_incremental.ssinfo.incremental.slot );
        }

        FD_LOG_NOTICE(( "downloading full snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( best.addr.addr ), best.addr.port ));
        ctx->addr           = best.addr;
        ctx->state          = FD_SNAPRD_STATE_READING_FULL_HTTP;
        ctx->http.full.slot = best.ssinfo.full.slot;
        fd_sshttp_init( ctx->sshttp, best.addr, "/snapshot.tar.bz2", 17UL, now );
      }
      break;
    }
    case FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL: {
      if( FD_UNLIKELY( now<ctx->deadline_nanos ) ) break;

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->http.full.slot );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        ctx->state = FD_SNAPRD_STATE_WAITING_FOR_PEERS_INCREMENTAL;
        break;
      }

      ctx->addr = best.addr;
      FD_LOG_NOTICE(( "downloading incremental snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( best.addr.addr ), best.addr.port ));
      fd_sshttp_init( ctx->sshttp, best.addr, "/incremental-snapshot.tar.bz2", 29UL, fd_log_wallclock() );
      ctx->state                 = FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP;
      ctx->http.incremental.slot = best.ssinfo.incremental.slot;
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
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET;
        ctx->malformed = 0;
        break;
      }

      ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
      remove_temp_files( ctx );
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
      break;
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        ctx->malformed = 0;
        break;
      }

      if( FD_UNLIKELY( ctx->local_out.write_buffer_len ) ) break;

      rename_snapshots( ctx );
      ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
      break;
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      if( FD_LIKELY( !ctx->config.incremental_snapshot_fetch ) ) {
        ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
        remove_temp_files( ctx );
        metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
        fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
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
        fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        ctx->malformed = 0;
        break;
      }

      if( FD_UNLIKELY( ctx->local_out.write_buffer_len ) ) break;

      if( FD_LIKELY( !ctx->config.incremental_snapshot_fetch ) ) {
        rename_snapshots( ctx );
        ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
        metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
        fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      /* Get the best incremental peer to download from */
      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->http.full.slot );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        fd_stem_publish( stem, 0UL, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        break;
      }

      if( FD_UNLIKELY( ctx->predicted_incremental.slot!=best.ssinfo.incremental.slot ) ) {
        ctx->predicted_incremental.slot = best.ssinfo.incremental.slot;
        send_expected_slot( stem, best.ssinfo.incremental.slot );
      }

      ctx->addr = best.addr;
      FD_LOG_NOTICE(( "downloading incremental snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
      fd_sshttp_init( ctx->sshttp, ctx->addr, "/incremental-snapshot.tar.bz2", 29UL, fd_log_wallclock() );
      ctx->state                 = FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP;
      ctx->http.incremental.slot = best.ssinfo.incremental.slot;
      break;
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      ctx->gui_full_path_published = 0;
      ctx->metrics.full.bytes_read = 0UL;
      ctx->metrics.full.bytes_written = 0UL;
      ctx->metrics.full.bytes_total   = 0UL;

      ctx->gui_incremental_path_published = 0;
      ctx->metrics.incremental.bytes_read = 0UL;
      ctx->metrics.incremental.bytes_written = 0UL;
      ctx->metrics.incremental.bytes_total   = 0UL;

      ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
      ctx->deadline_nanos = 0L;
      break;
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET:
      if( FD_UNLIKELY( ctx->ack_cnt<NUM_SNAP_CONSUMERS ) ) break;
      ctx->ack_cnt = 0UL;

      ctx->metrics.incremental.bytes_read    = 0UL;
      ctx->metrics.incremental.bytes_written = 0UL;
      ctx->metrics.incremental.bytes_total   = 0UL;

      ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL;
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
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    return !( ( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ||
              sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ||
              sig==FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES ) &&
              ( ctx->config.entrypoints_enabled || ctx->config.gossip_peers_enabled ) && ctx->peer_selection );
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
  if( ctx->in_kind[ in_idx ]!=IN_KIND_GOSSIP ) return;

  if( FD_UNLIKELY( chunk<ctx->gossip_in.chunk0 ||
                   chunk>ctx->gossip_in.wmark  ||
                   sz>sizeof(fd_gossip_update_message_t) ) ) {
    FD_LOG_ERR(( "snaprd: unexpected chunk %lu", chunk ));
  }
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
  (void)seq;
  (void)tsorig;
  (void)tspub;
  (void)sz;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    fd_gossip_update_message_t * msg = &ctx->gossip.tmp_upd_buf;
    switch( msg->tag ) {
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
          fd_ip4_port_t                 cur_addr = { .l = 0 };
          fd_snaprd_gossip_ci_entry_t * entry    = NULL;
          ulong idx = gossip_ci_map_idx_query_const( ctx->gossip.ci_map, (fd_pubkey_t const *)msg->origin_pubkey, ULONG_MAX, ctx->gossip.ci_pool );
          if( FD_LIKELY( idx!=ULONG_MAX ) ) {
            entry    = gossip_ci_pool_ele( ctx->gossip.ci_pool, idx );
            cur_addr = entry->rpc_addr;
          }

          fd_ip4_port_t new_addr = msg->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_RPC ];
          new_addr.port          = fd_ushort_bswap( new_addr.port );

          fd_ip4_port_t gossip_addr = msg->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ];
          gossip_addr.port          = fd_ushort_bswap( gossip_addr.port );
          int addr_is_entrypoint    = is_entrypoint( ctx, gossip_addr );
          if( FD_LIKELY( (ctx->config.entrypoints_enabled && addr_is_entrypoint) || ctx->config.gossip_peers_enabled ) ) {
            if( FD_UNLIKELY( cur_addr.l!=new_addr.l ) ) {
              if( FD_LIKELY( !!cur_addr.l ) ) {
                int removed = fd_ssping_remove( ctx->ssping, cur_addr );
                if( FD_LIKELY( removed ) ) fd_sspeer_selector_remove( ctx->selector, cur_addr );
              }
              if( FD_LIKELY( !!new_addr.l ) ) fd_ssping_add( ctx->ssping, new_addr );

              if( FD_LIKELY( entry ) ) {
                entry->rpc_addr = new_addr;
                entry->wallclock_nanos = msg->wallclock_nanos;
              }
            }

            if( FD_UNLIKELY( entry==NULL ) ) {
              entry = gossip_ci_pool_ele( ctx->gossip.ci_pool, msg->contact_info.idx );
              entry->pubkey = *(fd_pubkey_t const *)msg->origin_pubkey;
              gossip_ci_map_idx_insert( ctx->gossip.ci_map, msg->contact_info.idx, ctx->gossip.ci_pool );
              entry->gossip_addr = gossip_addr;
              entry->rpc_addr    = new_addr;
              entry->wallclock_nanos = msg->wallclock_nanos;
            }
          }
          break;
        }
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
        ulong idx = gossip_ci_map_idx_query_const( ctx->gossip.ci_map, (fd_pubkey_t const *)msg->origin_pubkey, ULONG_MAX, ctx->gossip.ci_pool );
        fd_ip4_port_t addr = gossip_ci_pool_ele_const( ctx->gossip.ci_pool, idx )->rpc_addr;
        if( FD_LIKELY( !!addr.l ) ) {
          int removed = fd_ssping_remove( ctx->ssping, addr );
          if( FD_LIKELY( removed ) ) fd_sspeer_selector_remove( ctx->selector, addr );
        }
        gossip_ci_map_idx_remove_fast( ctx->gossip.ci_map, idx, ctx->gossip.ci_pool );
        break;
      }
      case FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES: {
        ulong idx = gossip_ci_map_idx_query_const( ctx->gossip.ci_map, (fd_pubkey_t const *)msg->origin_pubkey, ULONG_MAX, ctx->gossip.ci_pool );

        if( FD_LIKELY( idx!=ULONG_MAX ) ) {
          fd_snaprd_gossip_ci_entry_t * entry = gossip_ci_pool_ele( ctx->gossip.ci_pool, idx );
          int addr_is_entrypoint = is_entrypoint( ctx, entry->gossip_addr );
          if( FD_LIKELY( (ctx->config.entrypoints_enabled && addr_is_entrypoint) || ctx->config.gossip_peers_enabled ) ) {
            on_snapshot_hash( ctx, entry->rpc_addr, msg );
          }
        }
        break;
      }
      default:
        FD_LOG_ERR(( "snaprd: unexpected gossip tag %u", (uint)msg->tag ));
        break;
    }

  } else {
    FD_TEST( sig==FD_SNAPSHOT_MSG_CTRL_ACK || sig==FD_SNAPSHOT_MSG_CTRL_MALFORMED );

    if( FD_LIKELY( sig==FD_SNAPSHOT_MSG_CTRL_ACK ) ) ctx->ack_cnt++;
    else {
      FD_TEST( ctx->state!=FD_SNAPRD_STATE_SHUTDOWN &&
               ctx->state!=FD_SNAPRD_STATE_COLLECTING_PEERS &&
               ctx->state!=FD_SNAPRD_STATE_WAITING_FOR_PEERS );

      switch( ctx->state ) {
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
          fd_stem_publish( stem, ctx->out_snapctl.idx, FD_SNAPSHOT_MSG_CTRL_RESET_FULL, 0UL, 0UL, 0UL, 0UL, 0UL );
          fd_sspeer_selector_remove( ctx->selector, ctx->addr );
          ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
          break;
        case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:
        case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:
          if( FD_UNLIKELY( ctx->malformed ) ) break;

          FD_LOG_NOTICE(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2",
                          FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
          fd_sshttp_cancel( ctx->sshttp );
          fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
          fd_sspeer_selector_remove( ctx->selector, ctx->addr );
          /* We would like to transition to FULL_HTTP_RESET, but we
             can't do it just yet, because we have already sent a DONE
             control fragment, and need to wait for acknowledges to come
             back first, to ensure there's only one control message
             outstanding at a time. */
          ctx->malformed = 1;
          break;
        case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:
        case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET:
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
  ctx->state          = FD_SNAPRD_STATE_WAITING_FOR_PEERS;
  ctx->deadline_nanos = fd_log_wallclock() + FD_SNAPRD_WAITING_FOR_PEERS_TIMEOUT_DEADLINE_NANOS;

  ctx->local_in.full_snapshot_fd         = -1;
  ctx->local_in.incremental_snapshot_fd  = -1;
  ctx->local_out.dir_fd                  = -1;
  ctx->local_out.full_snapshot_fd        = -1;
  ctx->local_out.incremental_snapshot_fd = -1;

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
  } else {
    FD_TEST( full_slot!=ULONG_MAX );

    ctx->local_in.full_snapshot_slot        = full_slot;
    ctx->local_in.incremental_snapshot_slot = incremental_slot;

    strncpy( ctx->local_in.full_snapshot_path, full_path, PATH_MAX );
    ctx->local_in.full_snapshot_fd = open( ctx->local_in.full_snapshot_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
    if( FD_UNLIKELY( -1==ctx->local_in.full_snapshot_fd ) ) FD_LOG_ERR(( "open() failed `%s` (%i-%s)", ctx->local_in.full_snapshot_path, errno, fd_io_strerror( errno ) ));

    struct stat full_stat;
    if( FD_UNLIKELY( -1==fstat( ctx->local_in.full_snapshot_fd, &full_stat ) ) ) FD_LOG_ERR(( "stat() failed `%s` (%i-%s)", full_path, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !S_ISREG( full_stat.st_mode ) ) ) FD_LOG_ERR(( "full snapshot path `%s` is not a regular file", full_path ));
    ctx->local_in.full_snapshot_size = (ulong)full_stat.st_size;

    /* TODO: make it possible to download the incremental if it is too
       old or does not exist. */
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

    ctx->local_out.dir_fd                  = -1;
    ctx->local_out.full_snapshot_fd        = -1;
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

  /* Set up download descriptors because even if we have local
     snapshots, we may need to download new snapshots if the local
     snapshots are too old. */
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
}

static inline fd_restore_out_link_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_restore_out_link_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0, .mtu = 0 };

  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_restore_out_link_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX, .mtu = mtu };

  void * mem   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, mtu );
  return (fd_restore_out_link_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0, .mtu = mtu };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaprd_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t),  sizeof(fd_snaprd_tile_t)       );
  void * _sshttp          = FD_SCRATCH_ALLOC_APPEND( l, fd_sshttp_align(),          fd_sshttp_footprint()          );
  void * _ssping          = FD_SCRATCH_ALLOC_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( FD_SSPING_MAX_PEERS ) );
  void * _ci_pool         = FD_SCRATCH_ALLOC_APPEND( l, gossip_ci_pool_align(),     gossip_ci_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * _ci_map          = FD_SCRATCH_ALLOC_APPEND( l, gossip_ci_map_align(),      gossip_ci_map_footprint( gossip_ci_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ) ) );
  void * _ssresolver      = FD_SCRATCH_ALLOC_APPEND( l, fd_http_resolver_align(),   fd_http_resolver_footprint( FD_SNAPRD_MAX_HTTP_PEERS ) );
  void * _selector        = FD_SCRATCH_ALLOC_APPEND( l, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( FD_SSPING_MAX_PEERS ) );

  ctx->ack_cnt = 0UL;
  ctx->malformed = 0;

  ctx->local_out.write_buffer_pos = 0UL;
  ctx->local_out.write_buffer_len = 0UL;

  fd_memcpy( ctx->config.path, tile->snaprd.snapshots_path, PATH_MAX );
  ctx->config.incremental_snapshot_fetch        = tile->snaprd.incremental_snapshot_fetch;
  ctx->config.do_download                       = tile->snaprd.do_download;
  ctx->config.maximum_local_snapshot_age        = tile->snaprd.maximum_local_snapshot_age;
  ctx->config.minimum_download_speed_mib        = tile->snaprd.minimum_download_speed_mib;
  ctx->config.max_full_snapshots_to_keep        = tile->snaprd.max_full_snapshots_to_keep;
  ctx->config.max_incremental_snapshots_to_keep = tile->snaprd.max_incremental_snapshots_to_keep;
  ctx->config.entrypoints_enabled               = tile->snaprd.entrypoints_enabled;
  ctx->config.gossip_peers_enabled              = tile->snaprd.gossip_peers_enabled;

  if( FD_UNLIKELY( !tile->snaprd.maximum_download_retry_abort ) ) ctx->config.maximum_download_retry_abort = UINT_MAX;
  else                                                            ctx->config.maximum_download_retry_abort = tile->snaprd.maximum_download_retry_abort;

  ctx->ssping = fd_ssping_join( fd_ssping_new( _ssping, FD_SSPING_MAX_PEERS, 1UL, on_ping, ctx ) );
  FD_TEST( ctx->ssping );

  ctx->sshttp = fd_sshttp_join( fd_sshttp_new( _sshttp ) );
  FD_TEST( ctx->sshttp );

  ctx->selector = fd_sspeer_selector_join( fd_sspeer_selector_new( _selector, FD_SSPING_MAX_PEERS, 1UL ) );

  ctx->gossip.ci_pool = gossip_ci_pool_join( gossip_ci_pool_new( _ci_pool, FD_CONTACT_INFO_TABLE_SIZE ) );
  FD_TEST( ctx->gossip.ci_pool );
  ctx->gossip.ci_map = gossip_ci_map_join( gossip_ci_map_new( _ci_map, gossip_ci_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ), 0UL ) );

  ctx->gossip.entrypoints_cnt = tile->snaprd.gossip_entrypoints_cnt;
  for( ulong i=0UL; i<tile->snaprd.gossip_entrypoints_cnt; i++ ) {
    ctx->gossip.entrypoints[ i ].l = tile->snaprd.gossip_entrypoints[ i ].l;
    ctx->gossip.entrypoints[ i ].port = fd_ushort_bswap( tile->snaprd.gossip_entrypoints[ i ].port ); /* TODO: should be fixed in a future PR */
  }

  FD_TEST( tile->in_cnt<=MAX_IN_LINKS );
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( in_link->name, "gossip_out" ) ) {
      ctx->in_kind[ i ]     = IN_KIND_GOSSIP;
      ctx->gossip_in.mem    = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
      ctx->gossip_in.chunk0 = fd_dcache_compact_chunk0( ctx->gossip_in.mem, in_link->dcache );
      ctx->gossip_in.wmark  = fd_dcache_compact_wmark ( ctx->gossip_in.mem, in_link->dcache, in_link->mtu );
      ctx->gossip_in.mtu    = in_link->mtu;
    } else if( 0==strcmp( in_link->name, "snapdc_rd" ) ||
               0==strcmp( in_link->name, "snapin_rd" ) ) {
      ctx->in_kind[ i ] = IN_KIND_SNAPCTL;
    }
  }

  ctx->ssresolver = fd_http_resolver_join( fd_http_resolver_new( _ssresolver, FD_SNAPRD_MAX_HTTP_PEERS, ctx->config.incremental_snapshot_fetch, on_resolve, ctx ) );
  FD_TEST( ctx->ssresolver );

  if( FD_UNLIKELY( tile->out_cnt<2UL || tile->out_cnt>3UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2-3", tile->out_cnt ));
  ctx->out_snapctl = out1( topo, tile, "snap_zstd"  );
  ctx->out_gui     = out1( topo, tile, "snaprd_out" );
  ctx->out_rp      = out1( topo, tile, "snaprd_rp"  );

  ctx->gui_incremental_path_published = fd_int_if( !!ctx->out_gui.mem, 0, 1 );
  ctx->gui_full_path_published        = fd_int_if( !!ctx->out_gui.mem, 0, 1 );

  for( ulong i=0UL; i<tile->snaprd.http.peers_cnt; i++ ) {
    tile->snaprd.http.peers[ i ].port = fd_ushort_bswap( tile->snaprd.http.peers[ i ].port ); /* TODO: should be fixed in a future PR */
    fd_ssping_add( ctx->ssping, tile->snaprd.http.peers[ i ] );
    fd_http_resolver_add( ctx->ssresolver, tile->snaprd.http.peers[ i ] );
  }

  ctx->http.full.slot        = ULONG_MAX;
  ctx->http.incremental.slot = ULONG_MAX;

  ctx->predicted_incremental.slot  = ULONG_MAX;
  ctx->predicted_incremental.dirty = 0;

  ctx->gossip.entrypoints_received = 0UL;
  ctx->gossip.saturated            = 0;
}

#define STEM_BURST 3UL /* One control message, and one data message, and one expected slot message */
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
  .name                     = NAME,
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
  .allow_renameat           = 1,
};

#undef NAME
