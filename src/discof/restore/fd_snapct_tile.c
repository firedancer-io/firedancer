#include "fd_snapct_tile.h"
#include "utils/fd_ssping.h"
#include "utils/fd_ssctrl.h"
#include "utils/fd_ssarchive.h"
#include "utils/fd_http_resolver.h"
#include "utils/fd_ssmsg.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../../waltz/openssl/fd_openssl_tile.h"

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "generated/fd_snapct_tile_seccomp.h"

#define NAME "snapct"

/* FIXME: Implement full_effective_age_cancel_threshold */
/* FIXME: Add more timeout config options and have consistent behavior */
/* FIXME: Do a finishing pass over the default.toml config options / comments */
/* FIXME: Improve behavior when using incremental_snapshots = false */
/* FIXME: Handle cases where no explicitly allowed peers advertise RPC */
/* FIXME: Make the code more strict about duplicate IP:port's */
/* FIXME: Handle cases where the slot number we start downloading differs from advertised */
/* FIXME: Ensure local files are not selected again if they fail the first time. */

#define GOSSIP_PEERS_MAX (FD_CONTACT_INFO_TABLE_SIZE)
#define SERVER_PEERS_MAX (FD_TOPO_SNAPSHOTS_SERVERS_MAX_RESOLVED)
#define TOTAL_PEERS_MAX  (GOSSIP_PEERS_MAX + SERVER_PEERS_MAX)

#define IN_KIND_ACK    (0)
#define IN_KIND_SNAPLD (1)
#define IN_KIND_GOSSIP (2)
#define MAX_IN_LINKS   (3)

#define TEMP_FULL_SNAP_NAME ".snapshot.tar.bz2-partial"
#define TEMP_INCR_SNAP_NAME ".incremental-snapshot.tar.bz2-partial"

struct fd_snapct_out_link {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};
typedef struct fd_snapct_out_link fd_snapct_out_link_t;

#define FD_SNAPCT_GOSSIP_FRESH_DEADLINE_NANOS      (10L*1000L*1000L*1000L)    /* gossip contact info is pushed every ~7.5 seconds */
#define FD_SNAPCT_GOSSIP_SATURATION_CHECK_INTERVAL (      10L*1000L*1000L)
#define FD_SNAPCT_GOSSIP_SATURATION_THRESHOLD      (0.05)                     /* 5% fresh peers */

#define FD_SNAPCT_COLLECTING_PEERS_TIMEOUT         (2L*60L*1000L*1000L*1000L) /* 2 minutes */
#define FD_SNAPCT_WAITING_FOR_PEERS_TIMEOUT        (2L*60L*1000L*1000L*1000L) /* 2 minutes */

struct gossip_ci_entry {
  fd_pubkey_t   pubkey;
  int           allowed;
  fd_ip4_port_t rpc_addr;
  long          added_nanos;
  ulong         map_next;
};
typedef struct gossip_ci_entry gossip_ci_entry_t;

#define MAP_NAME               gossip_ci_map
#define MAP_KEY                pubkey
#define MAP_ELE_T              gossip_ci_entry_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_NEXT               map_next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) fd_hash( seed, key, sizeof(fd_pubkey_t) )
#include "../../util/tmpl/fd_map_chain.c"

struct fd_snapct_tile {
  struct fd_topo_tile_snapct config;
  int                        gossip_enabled;
  int                        download_enabled;

  fd_ssping_t *          ssping;
  fd_http_resolver_t *   ssresolver;
  fd_sspeer_selector_t * selector;

  int           state;
  int           malformed;
  long          deadline_nanos;
  int           flush_ack;
  fd_ip4_port_t addr;
  uint          full_retries;
  uint          incr_retries;

  struct {
    int dir_fd;
    int full_snapshot_fd;
    int incremental_snapshot_fd;
  } local_out;

  char http_full_snapshot_name[ PATH_MAX ];
  char http_incr_snapshot_name[ PATH_MAX ];

  fd_wksp_t const * gossip_in_mem;
  fd_wksp_t const * snapld_in_mem;
  uchar             in_kind[ MAX_IN_LINKS ];

  struct {
    ulong full_slot;
    ulong slot;
    int   dirty;
  } predicted_incremental;

  struct {
    ulong full_snapshot_slot;
    char  full_snapshot_path[ PATH_MAX ];
    ulong full_snapshot_size;
    int   full_snapshot_zstd;

    ulong incremental_snapshot_slot;
    char  incremental_snapshot_path[ PATH_MAX ];
    ulong incremental_snapshot_size;
    int   incremental_snapshot_zstd;
  } local_in;

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
    gossip_ci_entry_t * ci_table;  /* flat array of all gossip entries, allowed or not */
    gossip_ci_map_t *   ci_map;    /* map from pubkey to only allowed gossip entries */
    ulong               fresh_cnt;
    ulong               total_cnt;
    int                 saturated;
    long                next_saturated_check;
  } gossip;

  fd_snapct_out_link_t out_ld;
  fd_snapct_out_link_t out_gui;
  fd_snapct_out_link_t out_rp;
};
typedef struct fd_snapct_tile fd_snapct_tile_t;

static int
gossip_enabled( fd_topo_tile_t const * tile ) {
  return tile->snapct.sources.gossip.allow_any || tile->snapct.sources.gossip.allow_list_cnt>0UL;
}

static int
download_enabled( fd_topo_tile_t const * tile ) {
  return gossip_enabled( tile ) || tile->snapct.sources.servers_cnt>0UL;
}

FD_FN_CONST static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  /* Leftover space for OpenSSL allocations */
  return 1<<26UL; /* 64 MiB */
}

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snapct_tile_t),
         fd_ulong_max( fd_ssping_align(),
         fd_ulong_max( alignof(gossip_ci_entry_t),
         fd_ulong_max( gossip_ci_map_align(),
         fd_ulong_max( fd_http_resolver_align(),
                       fd_sspeer_selector_align() ) ) ) ) );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapct_tile_t),  sizeof(fd_snapct_tile_t)                                                   );
  l = FD_LAYOUT_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( TOTAL_PEERS_MAX )                                     );
  l = FD_LAYOUT_APPEND( l, alignof(gossip_ci_entry_t), sizeof(gossip_ci_entry_t) * GOSSIP_PEERS_MAX                               );
  l = FD_LAYOUT_APPEND( l, gossip_ci_map_align(),      gossip_ci_map_footprint( gossip_ci_map_chain_cnt_est( GOSSIP_PEERS_MAX ) ) );
  l = FD_LAYOUT_APPEND( l, fd_http_resolver_align(),   fd_http_resolver_footprint( SERVER_PEERS_MAX )                             );
  l = FD_LAYOUT_APPEND( l, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( TOTAL_PEERS_MAX )                            );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),           fd_alloc_footprint()                                                       );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline int
should_shutdown( fd_snapct_tile_t * ctx ) {
  return ctx->state==FD_SNAPCT_STATE_SHUTDOWN;
}

static void
during_housekeeping( fd_snapct_tile_t * ctx ) {
  long now = fd_log_wallclock();

  if( FD_UNLIKELY( !ctx->gossip.saturated && now>ctx->gossip.next_saturated_check ) ) {
    ctx->gossip.next_saturated_check = now + FD_SNAPCT_GOSSIP_SATURATION_CHECK_INTERVAL;

    ulong fresh_cnt = 0UL;
    ulong total_cnt = 0UL;
    for( gossip_ci_map_iter_t iter = gossip_ci_map_iter_init( ctx->gossip.ci_map, ctx->gossip.ci_table );
         !gossip_ci_map_iter_done( iter, ctx->gossip.ci_map, ctx->gossip.ci_table );
         iter = gossip_ci_map_iter_next( iter, ctx->gossip.ci_map, ctx->gossip.ci_table ) ) {
      gossip_ci_entry_t const * ci_entry = gossip_ci_map_iter_ele_const( iter, ctx->gossip.ci_map, ctx->gossip.ci_table );
      if( FD_UNLIKELY( ci_entry->added_nanos>(now-FD_SNAPCT_GOSSIP_FRESH_DEADLINE_NANOS) ) ) fresh_cnt++;
      total_cnt++;
    }
    ctx->gossip.fresh_cnt = fresh_cnt;
    ctx->gossip.total_cnt = total_cnt;

    if( total_cnt!=0UL && total_cnt==ctx->config.sources.gossip.allow_list_cnt ) ctx->gossip.saturated = 1;
    else {
      double fresh = total_cnt ? (double)fresh_cnt/(double)total_cnt : 1.0;
      ctx->gossip.saturated = fresh<FD_SNAPCT_GOSSIP_SATURATION_THRESHOLD;
    }
  }
}

static void
metrics_write( fd_snapct_tile_t * ctx ) {
  /* FIXME: Track/report FULL_NUM_RETRIES & INCREMENTAL_NUM_RETRIES */

  FD_MGAUGE_SET( SNAPCT, FULL_BYTES_READ,               ctx->metrics.full.bytes_read );
  FD_MGAUGE_SET( SNAPCT, FULL_BYTES_WRITTEN,            ctx->metrics.full.bytes_written );
  FD_MGAUGE_SET( SNAPCT, FULL_BYTES_TOTAL,              ctx->metrics.full.bytes_total );
  FD_MGAUGE_SET( SNAPCT, FULL_DOWNLOAD_RETRIES,         ctx->metrics.full.num_retries );

  FD_MGAUGE_SET( SNAPCT, INCREMENTAL_BYTES_READ,        ctx->metrics.incremental.bytes_read );
  FD_MGAUGE_SET( SNAPCT, INCREMENTAL_BYTES_WRITTEN,     ctx->metrics.incremental.bytes_written );
  FD_MGAUGE_SET( SNAPCT, INCREMENTAL_BYTES_TOTAL,       ctx->metrics.incremental.bytes_total );
  FD_MGAUGE_SET( SNAPCT, INCREMENTAL_DOWNLOAD_RETRIES,  ctx->metrics.incremental.num_retries );

  FD_MGAUGE_SET( SNAPCT, GOSSIP_FRESH_COUNT,            ctx->gossip.fresh_cnt );
  FD_MGAUGE_SET( SNAPCT, GOSSIP_TOTAL_COUNT,            ctx->gossip.total_cnt );

  FD_MGAUGE_SET( SNAPCT, PREDICTED_SLOT,                ctx->predicted_incremental.slot );

#if FD_HAS_OPENSSL
  FD_MCNT_SET(   SNAPCT, SSL_ALLOC_ERRORS,                fd_ossl_alloc_errors );
#endif

  FD_MGAUGE_SET( SNAPCT, STATE, (ulong)ctx->state );
}

static void
snapshot_path_gui_publish( fd_snapct_tile_t *  ctx,
                           fd_stem_context_t * stem,
                           char const *        path,
                           int                 is_full ) {
  /* FIXME: Consider whether we can get everything we need from metrics
     rather than creating an entire link for this rare message */
  fd_snapct_update_t * out = fd_chunk_to_laddr( ctx->out_gui.mem, ctx->out_gui.chunk );
  FD_TEST( fd_cstr_printf_check( out->read_path, PATH_MAX, NULL, "%s", path ) );
  out->is_download = 0;
  out->type = fd_int_if( is_full, FD_SNAPCT_SNAPSHOT_TYPE_FULL, FD_SNAPCT_SNAPSHOT_TYPE_INCREMENTAL );
  fd_stem_publish( stem, ctx->out_gui.idx, 0UL, ctx->out_gui.chunk, sizeof(fd_snapct_update_t) , 0UL, 0UL, 0UL );
  ctx->out_gui.chunk = fd_dcache_compact_next( ctx->out_gui.chunk, sizeof(fd_snapct_update_t), ctx->out_gui.chunk0, ctx->out_gui.wmark );
}

static void
predict_incremental( fd_snapct_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->config.incremental_snapshots ) ) return;
  if( FD_UNLIKELY( ctx->predicted_incremental.full_slot==ULONG_MAX ) ) return;

  fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->predicted_incremental.full_slot );

  if( FD_LIKELY( best.addr.l ) ) {
    if( FD_UNLIKELY( ctx->predicted_incremental.slot!=best.incr_slot ) ) {
      ctx->predicted_incremental.slot  = best.incr_slot;
      ctx->predicted_incremental.dirty = 1;
    }
  }
}

static void
on_resolve( void *              _ctx,
            fd_ip4_port_t       addr,
            ulong               full_slot,
            ulong               incr_slot ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)_ctx;

  fd_sspeer_selector_add( ctx->selector, addr, ULONG_MAX, full_slot, incr_slot );
  fd_sspeer_selector_process_cluster_slot( ctx->selector, full_slot, incr_slot );
  predict_incremental( ctx );
}

static void
on_ping( void *        _ctx,
         fd_ip4_port_t addr,
         ulong         latency ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)_ctx;

  fd_sspeer_selector_add( ctx->selector, addr, latency, ULONG_MAX, ULONG_MAX);
  predict_incremental( ctx );
}

static void
on_snapshot_hash( fd_snapct_tile_t *                 ctx,
                  fd_ip4_port_t                      addr,
                  fd_gossip_update_message_t const * msg ) {
  ulong full_slot = msg->snapshot_hashes.full->slot;
  ulong incr_slot = 0UL;

  for( ulong i=0UL; i<msg->snapshot_hashes.incremental_len; i++ ) {
    if( FD_LIKELY( msg->snapshot_hashes.incremental[ i ].slot>incr_slot ) ) {
      incr_slot = msg->snapshot_hashes.incremental[ i ].slot;
    }
  }

  fd_sspeer_selector_add( ctx->selector, addr, ULONG_MAX, full_slot, incr_slot );
  fd_sspeer_selector_process_cluster_slot( ctx->selector, full_slot, incr_slot );
  predict_incremental( ctx );
}

static void
send_expected_slot( fd_snapct_tile_t *  ctx,
                    fd_stem_context_t * stem,
                    ulong               slot ) {
  uint tsorig; uint tspub;
  fd_ssmsg_slot_to_frag( slot, &tsorig, &tspub );
  fd_stem_publish( stem, ctx->out_rp.idx, FD_SSMSG_EXPECTED_SLOT, 0UL, 0UL, 0UL, tsorig, tspub );
}

static void
rename_snapshots( fd_snapct_tile_t * ctx ) {
  FD_TEST( -1!=ctx->local_out.dir_fd );

  /* FIXME: We should rename the full snapshot earlier as soon as the
     download is complete.  That way, if the validator crashes during the
     incremental load, we can still use the snapshot on the next run. */

  if( FD_LIKELY( -1!=ctx->local_out.full_snapshot_fd && ctx->http_full_snapshot_name[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( -1==renameat( ctx->local_out.dir_fd, TEMP_FULL_SNAP_NAME, ctx->local_out.dir_fd, ctx->http_full_snapshot_name ) ) )
      FD_LOG_ERR(( "renameat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_LIKELY( -1!=ctx->local_out.incremental_snapshot_fd && ctx->http_incr_snapshot_name[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( -1==renameat( ctx->local_out.dir_fd, TEMP_INCR_SNAP_NAME, ctx->local_out.dir_fd, ctx->http_incr_snapshot_name ) ) )
      FD_LOG_ERR(( "renameat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  ulong cnt = 1UL +                             /* stderr */
              1UL;                              /* logfile */
  if( download_enabled( tile ) ) {
    cnt +=    1UL +                             /* ssping socket */
              2UL +                             /* dirfd + full snapshot download temp fd */
              tile->snapct.sources.servers_cnt; /* http resolver peer full sockets */
    if( tile->snapct.incremental_snapshots ) {
      cnt +=  1UL +                             /* incr snapshot download temp fd */
              tile->snapct.sources.servers_cnt; /* http resolver peer incr sockets */
    }
  }
  return cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapct_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapct_tile_t), sizeof(fd_snapct_tile_t) );

  int ping_fd = download_enabled( tile ) ? fd_ssping_get_sockfd( ctx->ssping ) : -1;
  populate_sock_filter_policy_fd_snapct_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->local_out.dir_fd, (uint)ctx->local_out.full_snapshot_fd, (uint)ctx->local_out.incremental_snapshot_fd, (uint)ping_fd );
  return sock_filter_policy_fd_snapct_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<6UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapct_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapct_tile_t), sizeof(fd_snapct_tile_t) );
  if( FD_LIKELY( -1!=ctx->local_out.dir_fd ) )                  out_fds[ out_cnt++ ] = ctx->local_out.dir_fd;
  if( FD_LIKELY( -1!=ctx->local_out.full_snapshot_fd ) )        out_fds[ out_cnt++ ] = ctx->local_out.full_snapshot_fd;
  if( FD_LIKELY( -1!=ctx->local_out.incremental_snapshot_fd ) ) out_fds[ out_cnt++ ] = ctx->local_out.incremental_snapshot_fd;
  if( FD_LIKELY( download_enabled( tile ) ) )                   out_fds[ out_cnt++ ] = fd_ssping_get_sockfd( ctx->ssping );

  return out_cnt;
}

static void
init_load( fd_snapct_tile_t *  ctx,
           fd_stem_context_t * stem,
           int full,
           int file ) {
  fd_ssctrl_init_t * out = fd_chunk_to_laddr( ctx->out_ld.mem, ctx->out_ld.chunk );
  out->file = file;
  out->zstd = !file || (full ? ctx->local_in.full_snapshot_zstd : ctx->local_in.incremental_snapshot_zstd);
  if( !file ) {
    out->addr = ctx->addr;
    for( ulong i=0UL; i<SERVER_PEERS_MAX; i++ ) {
      if( FD_UNLIKELY( ctx->addr.l==ctx->config.sources.servers[ i ].addr.l ) ) {
        fd_cstr_ncpy( out->hostname, ctx->config.sources.servers[ i ].hostname, sizeof(out->hostname) );
        out->is_https = ctx->config.sources.servers[ i ].is_https;
        break;
      }
    }
  }
  fd_stem_publish( stem, ctx->out_ld.idx, full ? FD_SNAPSHOT_MSG_CTRL_INIT_FULL : FD_SNAPSHOT_MSG_CTRL_INIT_INCR, ctx->out_ld.chunk, sizeof(fd_ssctrl_init_t), 0UL, 0UL, 0UL );
  ctx->out_ld.chunk = fd_dcache_compact_next( ctx->out_ld.chunk, sizeof(fd_ssctrl_init_t), ctx->out_ld.chunk0, ctx->out_ld.wmark );
  ctx->flush_ack = 0;

  if( file ) {
    /* When loading from a local file and not from HTTP, there is no
       future metadata message to initialize total size / filename, as
       these are already known immediately. */
    if( full ) {
      ctx->metrics.full.bytes_total = ctx->local_in.full_snapshot_size;
      fd_cstr_fini( ctx->http_full_snapshot_name );
      if( FD_LIKELY( !!ctx->out_gui.mem ) ) {
        snapshot_path_gui_publish( ctx, stem, ctx->local_in.full_snapshot_path, 1 );
      }
    } else {
      ctx->metrics.incremental.bytes_total = ctx->local_in.incremental_snapshot_size;
      fd_cstr_fini( ctx->http_incr_snapshot_name );
      if( FD_LIKELY( !!ctx->out_gui.mem ) ) {
        snapshot_path_gui_publish( ctx, stem, ctx->local_in.incremental_snapshot_path, 0 );
      }
    }
  }
}

static void
log_download( fd_snapct_tile_t * ctx,
              int                full,
              fd_ip4_port_t      addr,
              ulong              slot ) {
  for( gossip_ci_map_iter_t iter = gossip_ci_map_iter_init( ctx->gossip.ci_map, ctx->gossip.ci_table );
      !gossip_ci_map_iter_done( iter, ctx->gossip.ci_map, ctx->gossip.ci_table );
      iter = gossip_ci_map_iter_next( iter, ctx->gossip.ci_map, ctx->gossip.ci_table ) ) {
    gossip_ci_entry_t const * ci_entry = gossip_ci_map_iter_ele_const( iter, ctx->gossip.ci_map, ctx->gossip.ci_table );
    if( ci_entry->rpc_addr.l==addr.l ) {
      FD_TEST( ci_entry->allowed );
      FD_BASE58_ENCODE_32_BYTES( ci_entry->pubkey.uc, pubkey_b58 );
      FD_LOG_NOTICE(( "downloading %s snapshot at slot %lu from allowed gossip peer %s at http://" FD_IP4_ADDR_FMT ":%hu/%s",
                      full ? "full" : "incremental", slot, pubkey_b58,
                      FD_IP4_ADDR_FMT_ARGS( addr.addr ), fd_ushort_bswap( addr.port ),
                      full ? "snapshot.tar.bz2" : "incremental-snapshot.tar.bz2" ));
      return;
    }
  }

  for( ulong i=0UL; i<ctx->config.sources.servers_cnt; i++ ) {
    if( addr.l==ctx->config.sources.servers[ i ].addr.l ) {
      if( ctx->config.sources.servers[ i ].is_https ) {
        FD_LOG_NOTICE(( "downloading %s snapshot at slot %lu from configured server with index %lu at https://%s:%hu/%s",
                        full ? "full" : "incremental", slot, i,
                        ctx->config.sources.servers[ i ].hostname, fd_ushort_bswap( addr.port ),
                        full ? "snapshot.tar.bz2" : "incremental-snapshot.tar.bz2" ));
      } else {
        FD_LOG_NOTICE(( "downloading %s snapshot at slot %lu from configured server with index %lu at http://" FD_IP4_ADDR_FMT ":%hu/%s",
                        full ? "full" : "incremental", slot, i,
                        FD_IP4_ADDR_FMT_ARGS( addr.addr ), fd_ushort_bswap( addr.port ),
                        full ? "snapshot.tar.bz2" : "incremental-snapshot.tar.bz2" ));
      }
      return;
    }
  }

  FD_TEST( 0 ); /* should not be possible */
}

static void
after_credit( fd_snapct_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy FD_PARAM_UNUSED ) {
  long now = fd_log_wallclock();

  if( FD_LIKELY( ctx->ssping ) ) fd_ssping_advance( ctx->ssping, now, ctx->selector );
  if( FD_LIKELY( ctx->ssresolver ) ) fd_http_resolver_advance( ctx->ssresolver, now, ctx->selector );

  /* send an expected slot message as the predicted incremental
     could have changed as a result of the pinger, resolver, or from
     processing gossip frags in gossip_frag. */
  if( FD_LIKELY( ctx->predicted_incremental.dirty ) ) {
    send_expected_slot( ctx, stem, ctx->predicted_incremental.slot );
    ctx->predicted_incremental.dirty = 0;
  }

  /* Note: All state transitions should occur within this switch
     statement to make it easier to reason about the state management. */

  /* FIXME: Collapse WAITING_FOR_PEERS and COLLECTING_PEERS states for
     both full and incremental variants? */
  /* FIXME: Add INIT state so that we don't put the !download_enabled
     logic in waiting_for_peers, which is weird. */

  switch ( ctx->state ) {

    /* ============================================================== */
    case FD_SNAPCT_STATE_WAITING_FOR_PEERS: {
      if( FD_UNLIKELY( now>ctx->deadline_nanos ) ) FD_LOG_ERR(( "timed out waiting for peers." ));

      if( FD_UNLIKELY( !ctx->download_enabled ) ) {
        ulong local_slot = ctx->config.incremental_snapshots ? ctx->local_in.incremental_snapshot_slot : ctx->local_in.full_snapshot_slot;
        send_expected_slot( ctx, stem, local_slot );
        FD_LOG_NOTICE(( "reading full snapshot at slot %lu from local file `%s`", ctx->local_in.full_snapshot_slot, ctx->local_in.full_snapshot_path ));
        ctx->predicted_incremental.full_slot = ctx->local_in.full_snapshot_slot;
        ctx->state                           = FD_SNAPCT_STATE_READING_FULL_FILE;
        init_load( ctx, stem, 1, 1 );
        break;
      }

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_LIKELY( best.addr.l ) ) {
        ctx->state = FD_SNAPCT_STATE_COLLECTING_PEERS;
        ctx->deadline_nanos = now+FD_SNAPCT_COLLECTING_PEERS_TIMEOUT;
      }
      break;
    }

    /* ============================================================== */
    case FD_SNAPCT_STATE_WAITING_FOR_PEERS_INCREMENTAL: {
      /* FIXME: Handle the case where we have no download peers enabled,
         boot off the local full snapshot but do not have a local incr. */
      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_LIKELY( best.addr.l ) ) {
        ctx->state = FD_SNAPCT_STATE_COLLECTING_PEERS_INCREMENTAL;
        ctx->deadline_nanos = now;
      }
      break;
    }

    /* ============================================================== */
    case FD_SNAPCT_STATE_COLLECTING_PEERS: {
      if( FD_UNLIKELY( !ctx->gossip.saturated && now<ctx->deadline_nanos ) ) break;

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        ctx->state = FD_SNAPCT_STATE_WAITING_FOR_PEERS;
        break;
      }

      fd_sscluster_slot_t cluster = fd_sspeer_selector_cluster_slot( ctx->selector );
      if( FD_UNLIKELY( cluster.incremental==ULONG_MAX && ctx->config.incremental_snapshots ) ) {
        /* We must have a cluster full slot to be in this state. */
        FD_TEST( cluster.full!=ULONG_MAX );
        /* fall back to full snapshot only if the highest cluster slot
           is a full snapshot only */
        ctx->config.incremental_snapshots = 0;
      }

      /* FIXME: Revisit the local age logic with new effective age
         concept.  Measure cluster slot based on snapshots we can
         download / trust.  Reevaluate incremental age after the full
         snapshot download is completed. etc. etc. */

      ulong       cluster_slot    = ctx->config.incremental_snapshots ? cluster.incremental : cluster.full;
      ulong       local_slot      = ctx->config.incremental_snapshots ? ctx->local_in.incremental_snapshot_slot : ctx->local_in.full_snapshot_slot;
      ulong       local_slot_with_download = local_slot;
      int         local_too_old   = local_slot!=ULONG_MAX && local_slot<fd_ulong_sat_sub( cluster_slot, ctx->config.sources.max_local_incremental_age );
      int         local_full_only = ctx->local_in.incremental_snapshot_slot==ULONG_MAX && ctx->local_in.full_snapshot_slot!=ULONG_MAX;
      if( FD_LIKELY( (ctx->config.incremental_snapshots && local_full_only) || local_too_old ) ) {
        fd_sspeer_t best_incremental = fd_sspeer_selector_best( ctx->selector, 1, ctx->local_in.full_snapshot_slot );
        if( FD_LIKELY( best_incremental.addr.l ) ) {
          ctx->predicted_incremental.slot = best_incremental.incr_slot;
          local_slot_with_download = best_incremental.incr_slot;
          ctx->local_in.incremental_snapshot_slot = ULONG_MAX; /* don't use the local incremental snapshot */
        }
      }

      int can_use_local_full = local_slot_with_download!=ULONG_MAX && local_slot_with_download>=fd_ulong_sat_sub( cluster_slot, ctx->config.sources.max_local_full_effective_age );
      if( FD_LIKELY( can_use_local_full ) ) {
        send_expected_slot( ctx, stem, local_slot );

        FD_LOG_NOTICE(( "reading full snapshot at slot %lu from local file `%s`", ctx->local_in.full_snapshot_slot, ctx->local_in.full_snapshot_path ));
        ctx->predicted_incremental.full_slot = ctx->local_in.full_snapshot_slot;
        ctx->state                           = FD_SNAPCT_STATE_READING_FULL_FILE;
        init_load( ctx, stem, 1, 1 );
      } else {
        if( FD_UNLIKELY( !ctx->config.incremental_snapshots ) ) send_expected_slot( ctx, stem, best.full_slot );

        fd_sspeer_t best_incremental = fd_sspeer_selector_best( ctx->selector, 1, best.full_slot );
        if( FD_LIKELY( best_incremental.addr.l ) ) {
          ctx->predicted_incremental.slot = best_incremental.incr_slot;
          send_expected_slot( ctx, stem, best_incremental.incr_slot );
        }

        ctx->addr                            = best.addr;
        ctx->state                           = FD_SNAPCT_STATE_READING_FULL_HTTP;
        ctx->predicted_incremental.full_slot = best.full_slot;
        init_load( ctx, stem, 1, 0 );
        log_download( ctx, 1, best.addr, best.full_slot );
      }
      break;
    }

    /* ============================================================== */
    case FD_SNAPCT_STATE_COLLECTING_PEERS_INCREMENTAL: {
      if( FD_UNLIKELY( now<ctx->deadline_nanos ) ) break;

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->predicted_incremental.full_slot );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        ctx->state = FD_SNAPCT_STATE_WAITING_FOR_PEERS_INCREMENTAL;
        break;
      }

      /* FIXME: predicted_incremental? */

      ctx->addr = best.addr;
      ctx->state = FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP;
      init_load( ctx, stem, 0, 0 );
      log_download( ctx, 0, best.addr, best.incr_slot );
      break;
    }

    /* ============================================================== */
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE:
      if( !ctx->flush_ack ) break;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_RESET;
        FD_LOG_WARNING(( "error reading snapshot from local file `%s`", ctx->local_in.incremental_snapshot_path ));
        break;
      }

      ctx->state = FD_SNAPCT_STATE_SHUTDOWN;
      fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP:
      if( !ctx->flush_ack ) break;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET;
        FD_LOG_WARNING(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2",
                         FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ) ));
        fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
        fd_sspeer_selector_remove( ctx->selector, ctx->addr );
        break;
      }

      ctx->state = FD_SNAPCT_STATE_SHUTDOWN;
      rename_snapshots( ctx );
      fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE:
      if( !ctx->flush_ack ) break;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_FULL_FILE_RESET;
        FD_LOG_WARNING(( "error reading snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        break;
      }

      if( FD_LIKELY( !ctx->config.incremental_snapshots ) ) {
        ctx->state = FD_SNAPCT_STATE_SHUTDOWN;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      if( FD_LIKELY( ctx->local_in.incremental_snapshot_slot==ULONG_MAX ) ) {
        ctx->state = FD_SNAPCT_STATE_COLLECTING_PEERS_INCREMENTAL;
        ctx->deadline_nanos = 0L;
      } else {
        FD_LOG_NOTICE(( "reading incremental snapshot at slot %lu from local file `%s`", ctx->local_in.incremental_snapshot_slot, ctx->local_in.incremental_snapshot_path ));
        ctx->state = FD_SNAPCT_STATE_READING_INCREMENTAL_FILE;
        init_load( ctx, stem, 0, 1 );
      }
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP:
      if( !ctx->flush_ack ) break;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET;
        FD_LOG_WARNING(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                         FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ) ));
        fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
        fd_sspeer_selector_remove( ctx->selector, ctx->addr );
        break;
      }

      if( FD_LIKELY( !ctx->config.incremental_snapshots ) ) {
        ctx->state = FD_SNAPCT_STATE_SHUTDOWN;
        rename_snapshots( ctx );
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      /* Get the best incremental peer to download from */
      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->predicted_incremental.full_slot );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        /* FIXME: We should just transition to collecting_peers_incremental
           here rather than failing the full snapshot? */
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET;
        break;
      }

      if( FD_UNLIKELY( ctx->predicted_incremental.slot!=best.incr_slot ) ) {
        ctx->predicted_incremental.slot = best.incr_slot;
        send_expected_slot( ctx, stem, best.incr_slot );
      }

      ctx->addr = best.addr;
      ctx->state = FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP;
      init_load( ctx, stem, 0, 0 );
      log_download( ctx, 0, best.addr, best.incr_slot );
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET:
    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE_RESET:
      if( !ctx->flush_ack ) break;

      if( ctx->full_retries==ctx->config.max_retry_abort ) {
        FD_LOG_WARNING(( "hit retry limit of %u for full snapshot, aborting", ctx->config.max_retry_abort ));
        ctx->state = FD_SNAPCT_STATE_SHUTDOWN;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      ctx->full_retries++;

      ctx->metrics.full.bytes_read           = 0UL;
      ctx->metrics.full.bytes_written        = 0UL;
      ctx->metrics.full.bytes_total          = 0UL;

      ctx->metrics.incremental.bytes_read    = 0UL;
      ctx->metrics.incremental.bytes_written = 0UL;
      ctx->metrics.incremental.bytes_total   = 0UL;

      ctx->state = FD_SNAPCT_STATE_COLLECTING_PEERS;
      ctx->deadline_nanos = 0L;
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_RESET:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET:
      if( !ctx->flush_ack ) break;

      if( ctx->incr_retries==ctx->config.max_retry_abort ) {
        FD_LOG_WARNING(("hit retry limit of %u for incremental snapshot, aborting", ctx->config.max_retry_abort ));
        ctx->state = FD_SNAPCT_STATE_SHUTDOWN;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      ctx->incr_retries++;

      ctx->metrics.incremental.bytes_read    = 0UL;
      ctx->metrics.incremental.bytes_written = 0UL;
      ctx->metrics.incremental.bytes_total   = 0UL;

      ctx->state = FD_SNAPCT_STATE_COLLECTING_PEERS_INCREMENTAL;
      ctx->deadline_nanos = 0L;
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_READING_FULL_FILE:
      if( FD_UNLIKELY( !ctx->flush_ack ) ) break;
      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_FULL_FILE_RESET;
        FD_LOG_WARNING(( "error reading snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        break;
      }
      FD_TEST( ctx->metrics.full.bytes_total!=0UL );
      if( FD_UNLIKELY( ctx->metrics.full.bytes_read == ctx->metrics.full.bytes_total ) ) {
        ulong sig = ctx->config.incremental_snapshots ? FD_SNAPSHOT_MSG_CTRL_NEXT : FD_SNAPSHOT_MSG_CTRL_DONE;
        fd_stem_publish( stem, ctx->out_ld.idx, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPCT_STATE_FLUSHING_FULL_FILE;
        ctx->flush_ack = 0;
      }
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_READING_INCREMENTAL_FILE:
      if( FD_UNLIKELY( !ctx->flush_ack ) ) break;
      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_RESET;
        FD_LOG_WARNING(( "error reading snapshot from local file `%s`", ctx->local_in.incremental_snapshot_path ));
        break;
      }
      FD_TEST( ctx->metrics.incremental.bytes_total!=0UL );
      if ( FD_UNLIKELY( ctx->metrics.incremental.bytes_read == ctx->metrics.incremental.bytes_total ) ) {
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE;
        ctx->flush_ack = 0;
      }
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_READING_FULL_HTTP:
      if( FD_UNLIKELY( !ctx->flush_ack ) ) break;
      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET;
        FD_LOG_WARNING(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                         FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ) ));
        fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
        fd_sspeer_selector_remove( ctx->selector, ctx->addr );
        break;
      }
      if( FD_UNLIKELY( ctx->metrics.full.bytes_total!=0UL && ctx->metrics.full.bytes_read==ctx->metrics.full.bytes_total ) ) {
        ulong sig = ctx->config.incremental_snapshots ? FD_SNAPSHOT_MSG_CTRL_NEXT : FD_SNAPSHOT_MSG_CTRL_DONE;
        fd_stem_publish( stem, ctx->out_ld.idx, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPCT_STATE_FLUSHING_FULL_HTTP;
        ctx->flush_ack = 0;
      }
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP:
      if( FD_UNLIKELY( !ctx->flush_ack ) ) break;
      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET;
        FD_LOG_WARNING(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2",
                         FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ) ));
        fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
        fd_sspeer_selector_remove( ctx->selector, ctx->addr );
        break;
      }
      if ( FD_UNLIKELY( ctx->metrics.incremental.bytes_total!=0UL && ctx->metrics.incremental.bytes_read==ctx->metrics.incremental.bytes_total ) ) {
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP;
        ctx->flush_ack = 0;
      }
      break;

    /* ============================================================== */
    case FD_SNAPCT_STATE_SHUTDOWN:
      break;

    /* ============================================================== */
    default: FD_LOG_ERR(( "unexpected state %d", ctx->state ));
  }
}

static void
gossip_frag( fd_snapct_tile_t *  ctx,
             ulong               sig,
             ulong               sz FD_PARAM_UNUSED,
             ulong               chunk ) {
  FD_TEST( ctx->gossip_enabled );

  if( !( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ||
         sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ||
         sig==FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES ) ) return;

  fd_gossip_update_message_t const * msg    = fd_chunk_to_laddr_const( ctx->gossip_in_mem, chunk );
  fd_pubkey_t const *                pubkey = (fd_pubkey_t const *)msg->origin_pubkey;
  switch( msg->tag ) {
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
      FD_TEST( msg->contact_info.idx<GOSSIP_PEERS_MAX );
      gossip_ci_entry_t * entry = ctx->gossip.ci_table + msg->contact_info.idx;
      if( FD_UNLIKELY( !fd_pubkey_eq( &entry->pubkey, pubkey ) ) ) {
        /* Initialize the new gossip entry, which may or may not be allowed */
        FD_TEST( fd_pubkey_check_zero( &entry->pubkey ) );
        entry->pubkey      = *pubkey;
        entry->rpc_addr.l  = 0UL;
        entry->added_nanos = fd_log_wallclock();
        if( ctx->config.sources.gossip.allow_any ) {
          entry->allowed = 1;
          for( ulong i=0UL; i<ctx->config.sources.gossip.block_list_cnt; i++ ) {
            if( fd_pubkey_eq( pubkey, &ctx->config.sources.gossip.block_list[ i ] ) ) {
              entry->allowed = 0;
              break;
            }
          }
        } else {
          entry->allowed = 0;
          for( ulong i=0UL; i<ctx->config.sources.gossip.allow_list_cnt; i++ ) {
            if( fd_pubkey_eq( pubkey, &ctx->config.sources.gossip.allow_list[ i ] ) ) {
              entry->allowed = 1;
              break;
            }
          }
        }
        FD_TEST(  ULONG_MAX==gossip_ci_map_idx_query_const( ctx->gossip.ci_map, pubkey, ULONG_MAX, ctx->gossip.ci_table ) );
        if( entry->allowed ) gossip_ci_map_idx_insert( ctx->gossip.ci_map, msg->contact_info.idx, ctx->gossip.ci_table );
      }
      if( !entry->allowed ) break;
      /* Maybe update the RPC address of a new or existing allowed gossip peer */
      fd_ip4_port_t cur_addr = entry->rpc_addr;
      fd_ip4_port_t new_addr = msg->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_RPC ];
      if( FD_UNLIKELY( new_addr.l!=cur_addr.l ) ) {
        entry->rpc_addr = new_addr;
        if( FD_LIKELY( !!cur_addr.l ) ) {
          int removed = fd_ssping_remove( ctx->ssping, cur_addr );
          if( FD_LIKELY( removed ) ) fd_sspeer_selector_remove( ctx->selector, cur_addr );
        }
        if( FD_LIKELY( !!new_addr.l ) ) fd_ssping_add( ctx->ssping, new_addr );
        if( !ctx->config.sources.gossip.allow_any ) {
          FD_BASE58_ENCODE_32_BYTES( pubkey->uc, pubkey_b58 );
          if( FD_LIKELY( !!new_addr.l ) ) {
            FD_LOG_NOTICE(( "allowed gossip peer added with public key `%s` and RPC address `" FD_IP4_ADDR_FMT ":%hu`",
                            pubkey_b58, FD_IP4_ADDR_FMT_ARGS( new_addr.addr ), fd_ushort_bswap( new_addr.port ) ));
          } else {
            FD_LOG_WARNING(( "allowed gossip peer with public key `%s` does not advertise an RPC address", pubkey_b58 ));
          }
        }
      }
      break;
    }
    case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
      FD_TEST( msg->contact_info_remove.idx<GOSSIP_PEERS_MAX );
      gossip_ci_entry_t * entry = ctx->gossip.ci_table + msg->contact_info_remove.idx;
      if( FD_UNLIKELY( !fd_pubkey_eq( &entry->pubkey, pubkey ) ) ) {
        FD_TEST( fd_pubkey_check_zero( &entry->pubkey ) );
        break;
      }
      ulong rem_idx = gossip_ci_map_idx_remove( ctx->gossip.ci_map, pubkey, ULONG_MAX, ctx->gossip.ci_table );
      if( rem_idx==ULONG_MAX ) break;
      FD_TEST( entry->allowed && rem_idx==msg->contact_info_remove.idx );
      fd_ip4_port_t addr = entry->rpc_addr;
      if( FD_LIKELY( !!addr.l ) ) {
        int removed = fd_ssping_remove( ctx->ssping, addr );
        if( FD_LIKELY( removed ) ) fd_sspeer_selector_remove( ctx->selector, addr );
      }
      if( !ctx->config.sources.gossip.allow_any ) {
        FD_BASE58_ENCODE_32_BYTES( pubkey->uc, pubkey_b58 );
        FD_LOG_WARNING(( "allowed gossip peer removed with public key `%s` and RPC address `" FD_IP4_ADDR_FMT ":%hu`",
                         pubkey_b58, FD_IP4_ADDR_FMT_ARGS( addr.addr ), fd_ushort_bswap( addr.port ) ));
      }
      fd_memset( entry, 0, sizeof(*entry) );
      break;
    }
    case FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES: {
      ulong idx = gossip_ci_map_idx_query_const( ctx->gossip.ci_map, pubkey, ULONG_MAX, ctx->gossip.ci_table );
      if( FD_LIKELY( idx!=ULONG_MAX ) ) {
        gossip_ci_entry_t * entry = ctx->gossip.ci_table + idx;
        FD_TEST( entry->allowed );
        on_snapshot_hash( ctx, entry->rpc_addr, msg );
      }
      break;
    }
    default:
      FD_LOG_ERR(( "snapct: unexpected gossip tag %u", (uint)msg->tag ));
      break;
  }
}

static void
snapld_frag( fd_snapct_tile_t *  ctx,
             ulong               sig,
             ulong               sz,
             ulong               chunk,
             fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_META ) ) {
    /* Before snapld starts sending down data fragments, it first sends
       a metadata message containing the total size of the snapshot as
       well as the filename.  This is only done for HTTP loading. */
    int full;
    switch( ctx->state ) {
      case FD_SNAPCT_STATE_READING_FULL_HTTP:        full = 1; break;
      case FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP: full = 0; break;

      case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET:
      case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET:
        return; /* Ignore */
      default: FD_LOG_ERR(( "invalid meta frag in state %d", ctx->state ));
    }

    FD_TEST( sz==sizeof(fd_ssctrl_meta_t) );
    fd_ssctrl_meta_t const * meta = fd_chunk_to_laddr_const( ctx->snapld_in_mem, chunk );

    fd_memcpy( full ? ctx->http_full_snapshot_name : ctx->http_incr_snapshot_name, meta->name, PATH_MAX );

    if( FD_LIKELY( !!ctx->out_gui.mem ) ) {
      char snapshot_path[ PATH_MAX+30UL ]; /* 30 is fd_cstr_nlen( "https://255.255.255.255:65536/", ULONG_MAX ) */
      FD_TEST( fd_cstr_printf_check( snapshot_path, sizeof(snapshot_path), NULL, "http://" FD_IP4_ADDR_FMT ":%hu/%s", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), fd_ushort_bswap( ctx->addr.port ), meta->name ) );
      snapshot_path_gui_publish( ctx, stem, snapshot_path, full );
    }

    if( full ) ctx->metrics.full.bytes_total        = meta->total_sz;
    else       ctx->metrics.incremental.bytes_total = meta->total_sz;

    return;
  }
  if( FD_UNLIKELY( sig!=FD_SNAPSHOT_MSG_DATA ) ) return;

  int full, file;
  switch( ctx->state ) {
    /* Expected cases, fall through below */
    case FD_SNAPCT_STATE_READING_FULL_FILE:        full = 1; file = 1; break;
    case FD_SNAPCT_STATE_READING_INCREMENTAL_FILE: full = 0; file = 1; break;
    case FD_SNAPCT_STATE_READING_FULL_HTTP:        full = 1; file = 0; break;
    case FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP: full = 0; file = 0; break;

    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE_RESET:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_RESET:
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET:
      /* We are waiting for a reset to fully propagate through the
         pipeline, just throw away any trailing data frags. */
      return;

    case FD_SNAPCT_STATE_FLUSHING_FULL_FILE:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE:
    case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP:
    case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP:
      /* Based on previously received data frags, we expected that the
         current full / incremental snapshot was finished, but then we
         received additional data frags.  Unsafe to continue so throw
         away the whole snapshot. */
      if( !ctx->malformed ) {
        ctx->malformed = 1;
        FD_LOG_WARNING(( "complete snapshot loaded but read %lu extra bytes", sz ));
      }
      return;

    case FD_SNAPCT_STATE_WAITING_FOR_PEERS:
    case FD_SNAPCT_STATE_WAITING_FOR_PEERS_INCREMENTAL:
    case FD_SNAPCT_STATE_COLLECTING_PEERS:
    case FD_SNAPCT_STATE_COLLECTING_PEERS_INCREMENTAL:
    case FD_SNAPCT_STATE_SHUTDOWN:
    default:
      FD_LOG_ERR(( "invalid data frag in state %d", ctx->state ));
      return;
  }

  if( full ) FD_TEST( ctx->metrics.full.bytes_total       !=0UL );
  else       FD_TEST( ctx->metrics.incremental.bytes_total!=0UL );

  if( full ) ctx->metrics.full.bytes_read        += sz;
  else       ctx->metrics.incremental.bytes_read += sz;

  if( !file && -1!=ctx->local_out.dir_fd ) {
    uchar const * data = fd_chunk_to_laddr_const( ctx->snapld_in_mem, chunk );
    int fd = full ? ctx->local_out.full_snapshot_fd : ctx->local_out.incremental_snapshot_fd;
    long result = write( fd, data, sz );
    if( FD_UNLIKELY( -1==result && errno==ENOSPC ) ) {
      FD_LOG_ERR(( "Out of disk space when writing out snapshot data to `%s`", ctx->config.snapshots_path ));
    } else if( FD_UNLIKELY( 0L>result ) ) {
      FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    } else if( FD_UNLIKELY( sz!=(ulong)result ) ) {
      FD_LOG_ERR(( "paritial write(%lu)=%ld", sz, result ));
    }
    if( full ) ctx->metrics.full.bytes_written        += sz;
    else       ctx->metrics.incremental.bytes_written += sz;
  }

  if( FD_UNLIKELY( ( full && ctx->metrics.full.bytes_read        > ctx->metrics.full.bytes_total ) ||
                   (!full && ctx->metrics.incremental.bytes_read > ctx->metrics.incremental.bytes_total ) ) ) {
    if( !ctx->malformed ) {
      ctx->malformed = 1;
      FD_LOG_WARNING(( "expected %s snapshot size of %lu bytes but read %lu bytes",
                       full ? "full" : "incremental",
                       full ? ctx->metrics.full.bytes_total : ctx->metrics.incremental.bytes_total,
                       full ? ctx->metrics.full.bytes_read  : ctx->metrics.incremental.bytes_read ));

    }
  }
}

static void
snapin_frag( fd_snapct_tile_t *  ctx,
             ulong               sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
      if( FD_LIKELY( ctx->state==FD_SNAPCT_STATE_READING_FULL_HTTP ||
                     ctx->state==FD_SNAPCT_STATE_READING_FULL_FILE ) ) {
        FD_TEST( !ctx->flush_ack );
        ctx->flush_ack = 1;
      } else FD_LOG_ERR(( "invalid control frag %lu in state %d", sig, ctx->state ));
      break;

    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR:
      if( FD_LIKELY( ctx->state==FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP ||
                     ctx->state==FD_SNAPCT_STATE_READING_INCREMENTAL_FILE ) ) {
        FD_TEST( !ctx->flush_ack );
        ctx->flush_ack = 1;
      } else FD_LOG_ERR(( "invalid control frag %lu in state %d", sig, ctx->state ));
      break;

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
      if( FD_LIKELY( ctx->state==FD_SNAPCT_STATE_FLUSHING_FULL_HTTP ||
                     ctx->state==FD_SNAPCT_STATE_FLUSHING_FULL_FILE ) ) {
        FD_TEST( !ctx->flush_ack );
        ctx->flush_ack = 1;
      } else FD_LOG_ERR(( "invalid control frag %lu in state %d", sig, ctx->state ));
      break;

    case FD_SNAPSHOT_MSG_CTRL_DONE:
      if( FD_LIKELY( ctx->state==FD_SNAPCT_STATE_FLUSHING_FULL_HTTP ||
                     ctx->state==FD_SNAPCT_STATE_FLUSHING_FULL_FILE ||
                     ctx->state==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP ||
                     ctx->state==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE ) ) {
        FD_TEST( !ctx->flush_ack );
        ctx->flush_ack = 1;
      } else FD_LOG_ERR(( "invalid control frag %lu in state %d", sig, ctx->state ));
      break;

    case FD_SNAPSHOT_MSG_CTRL_FAIL:
      if( FD_LIKELY( ctx->state==FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET ||
                     ctx->state==FD_SNAPCT_STATE_FLUSHING_FULL_FILE_RESET ||
                     ctx->state==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP_RESET ||
                     ctx->state==FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE_RESET ) ) {
        FD_TEST( !ctx->flush_ack );
        ctx->flush_ack = 1;
      } else FD_LOG_ERR(( "invalid control frag %lu in state %d", sig, ctx->state ));
      break;

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      break;

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      switch( ctx->state ) {
        case FD_SNAPCT_STATE_READING_FULL_FILE:
        case FD_SNAPCT_STATE_FLUSHING_FULL_FILE:
        case FD_SNAPCT_STATE_READING_INCREMENTAL_FILE:
        case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_FILE:
        case FD_SNAPCT_STATE_READING_FULL_HTTP:
        case FD_SNAPCT_STATE_FLUSHING_FULL_HTTP:
        case FD_SNAPCT_STATE_READING_INCREMENTAL_HTTP:
        case FD_SNAPCT_STATE_FLUSHING_INCREMENTAL_HTTP:
          ctx->malformed = 1;
          break;
        default:
          break;
      }
      break;
  }
}

static int
returnable_frag( fd_snapct_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP ) ) {
    gossip_frag( ctx, sig, sz, chunk );
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_SNAPLD ) {
    snapld_frag( ctx, sig, sz, chunk, stem );
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_ACK ) {
    snapin_frag( ctx, sig );
  } else FD_LOG_ERR(( "invalid in_kind %lu %u", in_idx, (uint)ctx->in_kind[ in_idx ] ));
  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapct_tile_t * ctx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapct_tile_t),  sizeof(fd_snapct_tile_t) );
  void *             _ssping     = FD_SCRATCH_ALLOC_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( TOTAL_PEERS_MAX ) );
                                   FD_SCRATCH_ALLOC_APPEND( l, alignof(gossip_ci_entry_t), sizeof(gossip_ci_entry_t)*GOSSIP_PEERS_MAX );
                                   FD_SCRATCH_ALLOC_APPEND( l, gossip_ci_map_align(),      gossip_ci_map_footprint( gossip_ci_map_chain_cnt_est( GOSSIP_PEERS_MAX ) ) );
  void *             _ssresolver = FD_SCRATCH_ALLOC_APPEND( l, fd_http_resolver_align(),   fd_http_resolver_footprint( SERVER_PEERS_MAX )  );
                                   FD_SCRATCH_ALLOC_APPEND( l, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( TOTAL_PEERS_MAX ) );

#if FD_HAS_OPENSSL
  void * _alloc = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), tile->kind_id );
  fd_ossl_tile_init( alloc );
#endif

  ctx->ssping = NULL;
  if( FD_LIKELY( download_enabled( tile ) ) )         ctx->ssping = fd_ssping_join( fd_ssping_new( _ssping, TOTAL_PEERS_MAX, 1UL, on_ping, ctx ) );
  if( FD_LIKELY( tile->snapct.sources.servers_cnt ) ) ctx->ssresolver = fd_http_resolver_join( fd_http_resolver_new( _ssresolver, SERVER_PEERS_MAX, tile->snapct.incremental_snapshots, on_resolve, ctx ) );
  else                                                ctx->ssresolver = NULL;

  /* FIXME: We will keep too many snapshots if we have local snapshots
     but elect not to use them due to their age. */
  fd_ssarchive_remove_old_snapshots( tile->snapct.snapshots_path,
                                     tile->snapct.max_full_snapshots_to_keep,
                                     tile->snapct.max_incremental_snapshots_to_keep );

  ulong full_slot = ULONG_MAX;
  ulong incremental_slot = ULONG_MAX;
  int full_is_zstd = 0;
  int incremental_is_zstd = 0;
  char full_path[ PATH_MAX ] = {0};
  char incremental_path[ PATH_MAX ] = {0};
  if( FD_UNLIKELY( -1==fd_ssarchive_latest_pair( tile->snapct.snapshots_path,
                                                 tile->snapct.incremental_snapshots,
                                                 &full_slot,
                                                 &incremental_slot,
                                                 full_path,
                                                 incremental_path,
                                                 &full_is_zstd,
                                                 &incremental_is_zstd ) ) ) {
    if( FD_UNLIKELY( !download_enabled( tile ) ) ) {
      FD_LOG_ERR(( "No snapshots found in `%s` and no download sources are enabled. "
                   "Please enable downloading via [snapshots.sources] and restart.", tile->snapct.snapshots_path ));
    }
    ctx->local_in.full_snapshot_slot        = ULONG_MAX;
    ctx->local_in.incremental_snapshot_slot = ULONG_MAX;
    ctx->local_in.full_snapshot_size        = 0UL;
    ctx->local_in.incremental_snapshot_size = 0UL;
    ctx->local_in.full_snapshot_zstd        = 0;
    ctx->local_in.incremental_snapshot_zstd = 0;
    fd_cstr_fini( ctx->local_in.full_snapshot_path );
    fd_cstr_fini( ctx->local_in.incremental_snapshot_path );
  } else {
    FD_TEST( full_slot!=ULONG_MAX );

    ctx->local_in.full_snapshot_slot        = full_slot;
    ctx->local_in.incremental_snapshot_slot = incremental_slot;
    ctx->local_in.full_snapshot_zstd        = full_is_zstd;
    ctx->local_in.incremental_snapshot_zstd = incremental_is_zstd;

    strncpy( ctx->local_in.full_snapshot_path, full_path, PATH_MAX );
    struct stat full_stat;
    if( FD_UNLIKELY( -1==stat( ctx->local_in.full_snapshot_path, &full_stat ) ) ) FD_LOG_ERR(( "stat() failed `%s` (%i-%s)", full_path, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !S_ISREG( full_stat.st_mode ) ) ) FD_LOG_ERR(( "full snapshot path `%s` is not a regular file", full_path ));
    ctx->local_in.full_snapshot_size = (ulong)full_stat.st_size;

    if( FD_LIKELY( incremental_slot!=ULONG_MAX ) ) {
      strncpy( ctx->local_in.incremental_snapshot_path, incremental_path, PATH_MAX );
      struct stat incremental_stat;
      if( FD_UNLIKELY( -1==stat( ctx->local_in.incremental_snapshot_path, &incremental_stat ) ) ) FD_LOG_ERR(( "stat() failed `%s` (%i-%s)", incremental_path, errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( !S_ISREG( incremental_stat.st_mode ) ) ) FD_LOG_ERR(( "incremental snapshot path `%s` is not a regular file", incremental_path ));
      ctx->local_in.incremental_snapshot_size = (ulong)incremental_stat.st_size;
    } else {
      ctx->local_in.incremental_snapshot_size = 0UL;
      fd_cstr_fini( ctx->local_in.incremental_snapshot_path );
    }
  }

  ctx->local_out.dir_fd                  = -1;
  ctx->local_out.full_snapshot_fd        = -1;
  ctx->local_out.incremental_snapshot_fd = -1;
  if( FD_LIKELY( download_enabled( tile ) ) ) {
    ctx->local_out.dir_fd = open( tile->snapct.snapshots_path, O_DIRECTORY|O_CLOEXEC );
    if( FD_UNLIKELY( -1==ctx->local_out.dir_fd ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", tile->snapct.snapshots_path, errno, fd_io_strerror( errno ) ));

    ctx->local_out.full_snapshot_fd = openat( ctx->local_out.dir_fd, TEMP_FULL_SNAP_NAME, O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK, S_IRUSR|S_IWUSR );
    if( FD_UNLIKELY( -1==ctx->local_out.full_snapshot_fd ) ) FD_LOG_ERR(( "open(%s/%s) failed (%i-%s)", tile->snapct.snapshots_path, TEMP_FULL_SNAP_NAME, errno, fd_io_strerror( errno ) ));

    if( FD_LIKELY( tile->snapct.incremental_snapshots ) ) {
      ctx->local_out.incremental_snapshot_fd = openat( ctx->local_out.dir_fd, TEMP_INCR_SNAP_NAME, O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK, S_IRUSR|S_IWUSR );
      if( FD_UNLIKELY( -1==ctx->local_out.incremental_snapshot_fd ) ) FD_LOG_ERR(( "open(%s/%s) failed (%i-%s)", tile->snapct.snapshots_path, TEMP_INCR_SNAP_NAME, errno, fd_io_strerror( errno ) ));
    }
  }
}

static inline fd_snapct_out_link_t
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

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_snapct_out_link_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0, .mtu = 0 };

  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_snapct_out_link_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX, .mtu = mtu };

  void * mem   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, mtu );
  return (fd_snapct_out_link_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0, .mtu = mtu };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapct_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapct_tile_t),  sizeof(fd_snapct_tile_t)       );
                            FD_SCRATCH_ALLOC_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( TOTAL_PEERS_MAX ) );
  void * _ci_table        = FD_SCRATCH_ALLOC_APPEND( l, alignof(gossip_ci_entry_t), sizeof(gossip_ci_entry_t) * GOSSIP_PEERS_MAX );
  void * _ci_map          = FD_SCRATCH_ALLOC_APPEND( l, gossip_ci_map_align(),      gossip_ci_map_footprint( gossip_ci_map_chain_cnt_est( GOSSIP_PEERS_MAX ) ) );
                            FD_SCRATCH_ALLOC_APPEND( l, fd_http_resolver_align(),   fd_http_resolver_footprint( SERVER_PEERS_MAX ) );
  void * _selector        = FD_SCRATCH_ALLOC_APPEND( l, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( TOTAL_PEERS_MAX ) );

  ctx->config = tile->snapct;
  ctx->gossip_enabled   = gossip_enabled( tile );
  ctx->download_enabled = download_enabled( tile );

  if( ctx->config.sources.servers_cnt ) {
    for( ulong i=0UL; i<tile->snapct.sources.servers_cnt; i++ ) {
      fd_ssping_add       ( ctx->ssping, tile->snapct.sources.servers[ i ].addr );
      fd_http_resolver_add( ctx->ssresolver,
                            tile->snapct.sources.servers[ i ].addr,
                            tile->snapct.sources.servers[ i ].hostname,
                            tile->snapct.sources.servers[ i ].is_https );
    }
  }

  ctx->selector = fd_sspeer_selector_join( fd_sspeer_selector_new( _selector, TOTAL_PEERS_MAX, ctx->config.incremental_snapshots, 1UL ) );

  ctx->state          = FD_SNAPCT_STATE_WAITING_FOR_PEERS;
  ctx->malformed      = 0;
  ctx->deadline_nanos = fd_log_wallclock() + FD_SNAPCT_WAITING_FOR_PEERS_TIMEOUT;
  ctx->flush_ack      = 0;
  ctx->addr.l         = 0UL;
  ctx->full_retries   = 0U;
  ctx->incr_retries   = 0U;

  fd_memset( ctx->http_full_snapshot_name, 0, PATH_MAX );
  fd_memset( ctx->http_incr_snapshot_name, 0, PATH_MAX );

  ctx->gossip_in_mem = NULL;
  int has_snapld_dc = 0, has_ack_loopback = 0;
  FD_TEST( tile->in_cnt<=MAX_IN_LINKS );
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( in_link->name, "gossip_out" ) ) {
      ctx->in_kind[ i ]  = IN_KIND_GOSSIP;
      ctx->gossip_in_mem = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
    } else if( 0==strcmp( in_link->name, "snapld_dc" ) ) {
      ctx->in_kind[ i ]  = IN_KIND_SNAPLD;
      ctx->snapld_in_mem = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
      FD_TEST( !has_snapld_dc );
      has_snapld_dc = 1;
    } else if( 0==strcmp( in_link->name, "snapin_ct" ) || 0==strcmp( in_link->name, "snapls_ct" ) ||
               0==strcmp( in_link->name, "snapwm_ct" ) || 0==strcmp( in_link->name, "snaplv_ct" ) ) {
      ctx->in_kind[ i ] = IN_KIND_ACK;
      FD_TEST( !has_ack_loopback );
      has_ack_loopback = 1;
    }
  }
  FD_TEST( has_snapld_dc && has_ack_loopback );
  FD_TEST( ctx->gossip_enabled==(ctx->gossip_in_mem!=NULL) );

  ctx->predicted_incremental.full_slot = ULONG_MAX;
  ctx->predicted_incremental.slot      = ULONG_MAX;
  ctx->predicted_incremental.dirty     = 0;

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  fd_memset( _ci_table, 0, sizeof(gossip_ci_entry_t) * GOSSIP_PEERS_MAX );
  ctx->gossip.ci_table             = _ci_table;
  ctx->gossip.ci_map               = gossip_ci_map_join( gossip_ci_map_new( _ci_map, gossip_ci_map_chain_cnt_est( GOSSIP_PEERS_MAX ), 0UL ) );
  ctx->gossip.fresh_cnt            = 0UL;
  ctx->gossip.total_cnt            = 0UL;
  ctx->gossip.saturated            = !ctx->gossip_enabled;
  ctx->gossip.next_saturated_check = 0;

  if( FD_UNLIKELY( tile->out_cnt<2UL || tile->out_cnt>3UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2-3", tile->out_cnt ));
  ctx->out_ld  = out1( topo, tile, "snapct_ld"   );
  ctx->out_gui = out1( topo, tile, "snapct_gui"  );
  ctx->out_rp  = out1( topo, tile, "snapct_repr" );
}

/* after_credit can result in as many as 5 stem publishes in some code
   paths, and returnable_frag can result in 1. */
#define STEM_BURST 6UL

#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapct_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapct_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN     should_shutdown
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapct = {
  .name                     = NAME,
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
  .allow_renameat           = 1,
};

#undef NAME
