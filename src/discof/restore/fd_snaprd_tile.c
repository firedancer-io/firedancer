#define _GNU_SOURCE /* SOL_TCP (seccomp) */

#include "fd_snaprd_tile.h"
#include "utils/fd_ssping.h"
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

#define IN_KIND_SNAPIN  (0)
#define IN_KIND_SNAPLD  (1)
#define IN_KIND_GOSSIP  (2)
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
  fd_http_resolver_t *   ssresolver;
  fd_sspeer_selector_t * selector;

  int   state;
  int   malformed;
  long  deadline_nanos;
  int   flush_ack;

  fd_ip4_port_t addr;

  struct {
    char  full_snapshot_path[ PATH_MAX ];
    char  incremental_snapshot_path[ PATH_MAX ];
    char  full_snapshot_name[ PATH_MAX ];
    char  incremental_snapshot_name[ PATH_MAX ];

    int   dir_fd;
    int   full_snapshot_fd;
    int   incremental_snapshot_fd;
  } local_out;

  uchar in_kind[ MAX_IN_LINKS ];

  struct {
    ulong full_slot;
    ulong slot;
    int   dirty;
  } predicted_incremental;

  struct {
    ulong full_snapshot_slot;
    char  full_snapshot_path[ PATH_MAX ];
    ulong full_snapshot_size;

    ulong incremental_snapshot_slot;
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
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } snapld_in;

  struct {
    fd_snaprd_gossip_ci_entry_t * ci_pool;
    gossip_ci_map_t *             ci_map;
    fd_ip4_port_t                 entrypoints[ GOSSIP_TILE_ENTRYPOINTS_MAX ];
    ulong                         entrypoints_cnt;
    ulong                         entrypoints_received;
    double                        fresh;
    ulong                         fresh_cnt;
    ulong                         total_cnt;
    int                           saturated;
  } gossip;

  fd_restore_out_link_t out_ld;
  fd_restore_out_link_t out_gui;
  fd_restore_out_link_t out_rp;
};

typedef struct fd_snaprd_tile fd_snaprd_tile_t;

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snaprd_tile_t),
         fd_ulong_max( fd_ssping_align(),
         fd_ulong_max( gossip_ci_pool_align(),
         fd_ulong_max( gossip_ci_map_align(),
         fd_ulong_max( fd_http_resolver_align(),
                       fd_sspeer_selector_align() ) ) ) ) );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaprd_tile_t),  sizeof(fd_snaprd_tile_t)                                                             );
  l = FD_LAYOUT_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( FD_SSPING_MAX_PEERS )                                           );
  l = FD_LAYOUT_APPEND( l, gossip_ci_pool_align(),     gossip_ci_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE )                               );
  l = FD_LAYOUT_APPEND( l, gossip_ci_map_align(),      gossip_ci_map_footprint( gossip_ci_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ) ) );
  l = FD_LAYOUT_APPEND( l, fd_http_resolver_align(),   fd_http_resolver_footprint( FD_SNAPRD_MAX_HTTP_PEERS )                               );
  l = FD_LAYOUT_APPEND( l, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( FD_SSPING_MAX_PEERS )                                  );
  return FD_LAYOUT_FINI( l, scratch_align() );
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

  FD_MGAUGE_SET( SNAPRD, GOSSIP_FRESH_COUNT,            ctx->gossip.fresh_cnt );
  FD_MGAUGE_SET( SNAPRD, GOSSIP_TOTAL_COUNT,            ctx->gossip.total_cnt );

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
}

static void
predict_incremental( fd_snaprd_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->config.incremental_snapshot_fetch ) ) return;
  if( FD_UNLIKELY( ctx->predicted_incremental.full_slot==ULONG_MAX ) ) return;

  fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->predicted_incremental.full_slot );

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
  fd_sspeer_selector_process_cluster_slot( ctx->selector, ssinfo->full.slot, ssinfo->incremental.slot );
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
  fd_sspeer_selector_process_cluster_slot( ctx->selector, full_slot, incr_slot );
  predict_incremental( ctx );
}

static void
send_expected_slot( fd_snaprd_tile_t *  ctx,
                    fd_stem_context_t * stem,
                    ulong               slot ) {
  uint tsorig; uint tspub;
  fd_ssmsg_slot_to_frag( slot, &tsorig, &tspub );
  fd_stem_publish( stem, ctx->out_rp.idx, FD_SSMSG_EXPECTED_SLOT, 0UL, 0UL, 0UL, tsorig, tspub );
}

static void
rename_snapshots( fd_snaprd_tile_t * ctx ) {
  if( FD_UNLIKELY( -1==ctx->local_out.dir_fd ) ) return;

  if( FD_LIKELY( -1!=ctx->local_out.full_snapshot_fd && ctx->local_out.full_snapshot_name[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( -1==renameat( ctx->local_out.dir_fd, "snapshot.tar.bz2-partial", ctx->local_out.dir_fd, ctx->local_out.full_snapshot_name ) ) )
      FD_LOG_ERR(( "renameat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_LIKELY( -1!=ctx->local_out.incremental_snapshot_fd && ctx->local_out.incremental_snapshot_name[ 0 ]!='\0' ) ) {
    if( FD_UNLIKELY( -1==renameat( ctx->local_out.dir_fd, "incremental-snapshot.tar.bz2-partial", ctx->local_out.dir_fd, ctx->local_out.incremental_snapshot_name ) ) )
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
     fd, and one spare for a socket(). */

  return 1UL +                      /* stderr */
         1UL +                      /* logfile */
         FD_SSPING_MAX_PEERS +      /* ssping max peers sockets */
         FD_SNAPRD_MAX_HTTP_PEERS + /* http resolver max peers sockets */
         3UL;                       /* dirfd + 2 snapshot file fds in the worst case */
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaprd_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaprd_tile_t), sizeof(fd_snaprd_tile_t) );

  populate_sock_filter_policy_fd_snaprd_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->local_out.dir_fd, (uint)ctx->local_out.full_snapshot_fd, (uint)ctx->local_out.incremental_snapshot_fd );
  return sock_filter_policy_fd_snaprd_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<5UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

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

  return out_cnt;
}

static void
init_load( fd_snaprd_tile_t *  ctx,
           fd_stem_context_t * stem,
           int full,
           int file ) {
  fd_ssctrl_init_t * out = fd_chunk_to_laddr( ctx->out_ld.mem, ctx->out_ld.chunk );
  out->file = file;
  if( !file ) out->addr = ctx->addr;
  fd_stem_publish( stem, ctx->out_ld.idx, full ? FD_SNAPSHOT_MSG_CTRL_INIT_FULL : FD_SNAPSHOT_MSG_CTRL_INIT_INCR, ctx->out_ld.chunk, sizeof(fd_ssctrl_init_t), 0UL, 0UL, 0UL );
  ctx->out_ld.chunk = fd_dcache_compact_next( ctx->out_ld.chunk, sizeof(fd_ssctrl_init_t), ctx->out_ld.chunk0, ctx->out_ld.wmark );

  if( file ) {
    /* When loading from a local file and not from HTTP, there is no
       future metadata message to initialize total size / filename, as
       these are already known immediately. */
    if( full ) {
      ctx->metrics.full.bytes_total = ctx->local_in.full_snapshot_size;
      fd_cstr_fini( ctx->local_out.full_snapshot_name );
      if( FD_LIKELY( !!ctx->out_gui.mem ) ) {
        snapshot_path_gui_publish( ctx, stem, ctx->local_in.full_snapshot_path, 1 );
      }
    } else {
      ctx->metrics.incremental.bytes_total = ctx->local_in.incremental_snapshot_size;
      fd_cstr_fini( ctx->local_out.incremental_snapshot_name );
      if( FD_LIKELY( !!ctx->out_gui.mem ) ) {
        snapshot_path_gui_publish( ctx, stem, ctx->local_in.incremental_snapshot_path, 0 );
      }
    }
  }
}

static void
after_credit( fd_snaprd_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in FD_PARAM_UNUSED,
              int *               charge_busy FD_PARAM_UNUSED ) {
  long now = fd_log_wallclock();

  fd_ssping_advance( ctx->ssping, now, ctx->selector );
  fd_http_resolver_advance( ctx->ssresolver, now, ctx->selector );

  /* send an expected slot message as the predicted incremental
     could have changed as a result of the pinger, resolver, or from
     processing gossip frags in gossip_frag. */
  if( FD_LIKELY( ctx->predicted_incremental.dirty ) ) {
    send_expected_slot( ctx, stem, ctx->predicted_incremental.slot );
    ctx->predicted_incremental.dirty = 0;
  }

  /* Note: All state transitions should occur within this switch
     statement to make it easier to reason about the state management. */

  switch ( ctx->state ) {

    /* ============================================================== */
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS: {
      if( FD_UNLIKELY( now>ctx->deadline_nanos ) ) FD_LOG_ERR(( "timed out waiting for peers." ));

      if( FD_UNLIKELY( !ctx->config.do_download ) ) {
        ulong local_slot = ctx->config.incremental_snapshot_fetch ? ctx->local_in.incremental_snapshot_slot : ctx->local_in.full_snapshot_slot;
        send_expected_slot( ctx, stem, local_slot );
        FD_LOG_NOTICE(( "reading full snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        ctx->predicted_incremental.full_slot = ctx->local_in.full_snapshot_slot;
        ctx->state                           = FD_SNAPRD_STATE_READING_FULL_FILE;
        init_load( ctx, stem, 1, 1 );
        break;
      }

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_LIKELY( best.addr.l ) ) {
        ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
        ctx->deadline_nanos = now+FD_SNAPRD_GOSSIP_TIMEOUT_DEADLINE_NANOS;
      }
      break;
    }

    /* ============================================================== */
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS_INCREMENTAL: {
      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_LIKELY( best.addr.l ) ) {
        ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL;
        ctx->deadline_nanos = now;
      }
      break;
    }

    /* ============================================================== */
    case FD_SNAPRD_STATE_COLLECTING_PEERS: {
      if( FD_UNLIKELY( (!gossip_saturated( ctx, now ) || !all_entrypoints_received( ctx )) && now<ctx->deadline_nanos ) ) break;

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 0, ULONG_MAX );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        ctx->state = FD_SNAPRD_STATE_WAITING_FOR_PEERS;
        break;
      }

      fd_sscluster_slot_t cluster = fd_sspeer_selector_cluster_slot( ctx->selector );
      if( FD_UNLIKELY( cluster.incremental==ULONG_MAX && ctx->config.incremental_snapshot_fetch ) ) {
        /* We must have a cluster full slot to be in this state. */
        FD_TEST( cluster.full!=ULONG_MAX );
        /* fall back to full snapshot only if the highest cluster slot
           is a full snapshot only */
        ctx->config.incremental_snapshot_fetch = 0;
      }

      ulong       cluster_slot    = ctx->config.incremental_snapshot_fetch ? cluster.incremental : cluster.full;
      ulong       local_slot      = ctx->config.incremental_snapshot_fetch ? ctx->local_in.incremental_snapshot_slot : ctx->local_in.full_snapshot_slot;
      ulong       local_slot_with_download = local_slot;
      int         local_too_old   = local_slot!=ULONG_MAX && local_slot<fd_ulong_sat_sub( cluster_slot, ctx->config.maximum_local_snapshot_age );
      int         local_full_only = ctx->local_in.incremental_snapshot_slot==ULONG_MAX && ctx->local_in.full_snapshot_slot!=ULONG_MAX;
      if( FD_LIKELY( (ctx->config.incremental_snapshot_fetch && local_full_only) || local_too_old ) ) {
        fd_sspeer_t best_incremental = fd_sspeer_selector_best( ctx->selector, 1, ctx->local_in.full_snapshot_slot );
        if( FD_LIKELY( best_incremental.addr.l ) ) {
          ctx->predicted_incremental.slot = best_incremental.ssinfo.incremental.slot;
          local_slot_with_download = best_incremental.ssinfo.incremental.slot;
          ctx->local_in.incremental_snapshot_slot = ULONG_MAX; /* don't use the local incremental snapshot */
        }
      }

      int can_use_local_full = local_slot_with_download!=ULONG_MAX && local_slot_with_download>=fd_ulong_sat_sub( cluster_slot, ctx->config.maximum_local_snapshot_age );
      if( FD_LIKELY( can_use_local_full ) ) {
        send_expected_slot( ctx, stem, local_slot );

        FD_LOG_NOTICE(( "reading full snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        ctx->predicted_incremental.full_slot = ctx->local_in.full_snapshot_slot;
        ctx->state                           = FD_SNAPRD_STATE_READING_FULL_FILE;
        init_load( ctx, stem, 1, 1 );
      } else {
        if( FD_UNLIKELY( !ctx->config.incremental_snapshot_fetch ) ) send_expected_slot( ctx, stem, best.ssinfo.full.slot );

        fd_sspeer_t best_incremental = fd_sspeer_selector_best( ctx->selector, 1, best.ssinfo.full.slot );
        if( FD_LIKELY( best_incremental.addr.l ) ) {
          ctx->predicted_incremental.slot = best_incremental.ssinfo.incremental.slot;
          send_expected_slot( ctx, stem, best_incremental.ssinfo.incremental.slot );
        }

        FD_LOG_NOTICE(( "downloading full snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( best.addr.addr ), best.addr.port ));
        ctx->addr                            = best.addr;
        ctx->state                           = FD_SNAPRD_STATE_READING_FULL_HTTP;
        ctx->predicted_incremental.full_slot = best.ssinfo.full.slot;
        init_load( ctx, stem, 1, 0 );
      }
      break;
    }

    /* ============================================================== */
    case FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL: {
      if( FD_UNLIKELY( now<ctx->deadline_nanos ) ) break;

      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->predicted_incremental.full_slot );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        ctx->state = FD_SNAPRD_STATE_WAITING_FOR_PEERS_INCREMENTAL;
        break;
      }

      ctx->addr = best.addr;
      FD_LOG_NOTICE(( "downloading incremental snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( best.addr.addr ), best.addr.port ));
      ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP;
      init_load( ctx, stem, 0, 0 );
      break;
    }

    /* ============================================================== */
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE:
      if( !ctx->flush_ack ) break;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE_RESET;
        FD_LOG_WARNING(( "error reading snapshot from local file `%s`", ctx->local_in.incremental_snapshot_path ));
        break;
      }

      ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
      remove_temp_files( ctx );
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:
      if( !ctx->flush_ack ) break;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET;
        FD_LOG_WARNING(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2",
                         FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
        fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
        fd_sspeer_selector_remove( ctx->selector, ctx->addr );
        break;
      }

      ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
      rename_snapshots( ctx );
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:
      if( !ctx->flush_ack ) break;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET;
        FD_LOG_WARNING(( "error reading snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        break;
      }

      if( FD_LIKELY( !ctx->config.incremental_snapshot_fetch ) ) {
        ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
        remove_temp_files( ctx );
        metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      if( FD_LIKELY( ctx->local_in.incremental_snapshot_slot==ULONG_MAX ) ) {
        ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL;
        ctx->deadline_nanos = 0L;
      } else {
        FD_LOG_NOTICE(( "reading incremental snapshot from local file `%s`", ctx->local_in.incremental_snapshot_path ));
        ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_FILE;
        init_load( ctx, stem, 0, 1 );
      }
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:
      if( !ctx->flush_ack ) break;

      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        FD_LOG_WARNING(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                         FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
        fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
        fd_sspeer_selector_remove( ctx->selector, ctx->addr );
        break;
      }

      if( FD_LIKELY( !ctx->config.incremental_snapshot_fetch ) ) {
        ctx->state = FD_SNAPRD_STATE_SHUTDOWN;
        rename_snapshots( ctx );
        metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }

      /* Get the best incremental peer to download from */
      /* TODO: We should just transition to collecting_peers_incremental
         here rather than failing the full snapshot? */
      fd_sspeer_t best = fd_sspeer_selector_best( ctx->selector, 1, ctx->predicted_incremental.full_slot );
      if( FD_UNLIKELY( !best.addr.l ) ) {
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        break;
      }

      if( FD_UNLIKELY( ctx->predicted_incremental.slot!=best.ssinfo.incremental.slot ) ) {
        ctx->predicted_incremental.slot = best.ssinfo.incremental.slot;
        send_expected_slot( ctx, stem, best.ssinfo.incremental.slot );
      }

      ctx->addr = best.addr;
      FD_LOG_NOTICE(( "downloading incremental snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2", FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
      ctx->state = FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP;
      init_load( ctx, stem, 0, 0 );
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:
    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET:
      if( !ctx->flush_ack ) break;

      ctx->metrics.full.bytes_read    = 0UL;
      ctx->metrics.full.bytes_written = 0UL;
      ctx->metrics.full.bytes_total   = 0UL;

      ctx->metrics.incremental.bytes_read    = 0UL;
      ctx->metrics.incremental.bytes_written = 0UL;
      ctx->metrics.incremental.bytes_total   = 0UL;

      ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS;
      ctx->deadline_nanos = 0L;
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE_RESET:
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET:
      if( !ctx->flush_ack ) break;

      ctx->metrics.incremental.bytes_read    = 0UL;
      ctx->metrics.incremental.bytes_written = 0UL;
      ctx->metrics.incremental.bytes_total   = 0UL;

      ctx->state = FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL;
      ctx->deadline_nanos = 0L;
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_READING_FULL_FILE:
      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET;
        FD_LOG_WARNING(( "error reading snapshot from local file `%s`", ctx->local_in.full_snapshot_path ));
        break;
      }
      FD_TEST( ctx->metrics.full.bytes_total!=0UL );
      if( FD_UNLIKELY( ctx->metrics.full.bytes_read == ctx->metrics.full.bytes_total ) ) {
        ulong sig = ctx->config.incremental_snapshot_fetch ? FD_SNAPSHOT_MSG_CTRL_NEXT : FD_SNAPSHOT_MSG_CTRL_DONE;
        fd_stem_publish( stem, ctx->out_ld.idx, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_FILE;
        ctx->flush_ack = 0;
      }
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:
      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE_RESET;
        FD_LOG_WARNING(( "error reading snapshot from local file `%s`", ctx->local_in.incremental_snapshot_path ));
        break;
      }
      FD_TEST( ctx->metrics.incremental.bytes_total!=0UL );
      if ( FD_UNLIKELY( ctx->metrics.incremental.bytes_read == ctx->metrics.incremental.bytes_total ) ) {
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE;
        ctx->flush_ack = 0;
      }
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_READING_FULL_HTTP:
      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET;
        FD_LOG_WARNING(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/snapshot.tar.bz2",
                         FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
        fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
        fd_sspeer_selector_remove( ctx->selector, ctx->addr );
        break;
      }
      if( FD_UNLIKELY( ctx->metrics.full.bytes_total!=0UL && ctx->metrics.full.bytes_read==ctx->metrics.full.bytes_total ) ) {
        ulong sig = ctx->config.incremental_snapshot_fetch ? FD_SNAPSHOT_MSG_CTRL_NEXT : FD_SNAPSHOT_MSG_CTRL_DONE;
        fd_stem_publish( stem, ctx->out_ld.idx, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_FULL_HTTP;
        ctx->flush_ack = 0;
      }
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
      if( FD_UNLIKELY( ctx->malformed ) ) {
        ctx->malformed = 0;
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->flush_ack = 0;
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET;
        FD_LOG_WARNING(( "error downloading snapshot from http://" FD_IP4_ADDR_FMT ":%hu/incremental-snapshot.tar.bz2",
                         FD_IP4_ADDR_FMT_ARGS( ctx->addr.addr ), ctx->addr.port ));
        fd_ssping_invalidate( ctx->ssping, ctx->addr, fd_log_wallclock() );
        fd_sspeer_selector_remove( ctx->selector, ctx->addr );
        break;
      }
      if ( FD_UNLIKELY( ctx->metrics.incremental.bytes_total!=0UL && ctx->metrics.incremental.bytes_read==ctx->metrics.incremental.bytes_total ) ) {
        fd_stem_publish( stem, ctx->out_ld.idx, FD_SNAPSHOT_MSG_CTRL_DONE, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->state = FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP;
        ctx->flush_ack = 0;
      }
      break;

    /* ============================================================== */
    case FD_SNAPRD_STATE_SHUTDOWN:
      break;

    /* ============================================================== */
    default: FD_LOG_ERR(( "unexpected state %d", ctx->state ));
  }
}

static void
gossip_frag( fd_snaprd_tile_t *  ctx,
             ulong               sig,
             ulong               sz FD_PARAM_UNUSED,
             ulong               chunk ) {

  if( !( ( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ||
           sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ||
           sig==FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES ) &&
         ( ctx->config.entrypoints_enabled || ctx->config.gossip_peers_enabled ) ) ) return;

  FD_TEST( chunk>=ctx->gossip_in.chunk0 && chunk<=ctx->gossip_in.wmark );
  fd_gossip_update_message_t const * msg = fd_chunk_to_laddr( ctx->gossip_in.mem, chunk );
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
}

static void
snapld_frag( fd_snaprd_tile_t *  ctx,
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
      case FD_SNAPRD_STATE_READING_FULL_HTTP:        full = 1; break;
      case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP: full = 0; break;

      case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:
      case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET:
        return; /* Ignore */
      default: FD_LOG_ERR(( "invalid meta frag in state %d", ctx->state ));
    }

    FD_TEST( sz==sizeof(fd_ssctrl_meta_t) );
    fd_ssctrl_meta_t const * meta = fd_chunk_to_laddr_const( ctx->snapld_in.mem, chunk );

    if( full ) fd_memcpy( ctx->local_out.full_snapshot_name,        meta->name, PATH_MAX );
    else       fd_memcpy( ctx->local_out.incremental_snapshot_name, meta->name, PATH_MAX );

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
    case FD_SNAPRD_STATE_READING_FULL_FILE:        full = 1; file = 1; break;
    case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE: full = 0; file = 1; break;
    case FD_SNAPRD_STATE_READING_FULL_HTTP:        full = 1; file = 0; break;
    case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP: full = 0; file = 0; break;

    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET:
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE_RESET:
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET:
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET:
      /* We are waiting for a reset to fully propagate through the
         pipeline, just throw away any trailing data frags. */
      return;

    case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE:
    case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:
    case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:
      /* Based on previously received data frags, we expected that the
         current full / incremental snapshot was finished, but then we
         received additional data frags.  Unsafe to continue so throw
         away the whole snapshot. */
      if( !ctx->malformed ) {
        ctx->malformed = 1;
        FD_LOG_WARNING(( "complete snapshot loaded but read %lu extra bytes", sz ));
      }
      return;

    case FD_SNAPRD_STATE_WAITING_FOR_PEERS:
    case FD_SNAPRD_STATE_WAITING_FOR_PEERS_INCREMENTAL:
    case FD_SNAPRD_STATE_COLLECTING_PEERS:
    case FD_SNAPRD_STATE_COLLECTING_PEERS_INCREMENTAL:
    case FD_SNAPRD_STATE_SHUTDOWN:
    default:
      FD_LOG_ERR(( "invalid data frag in state %d", ctx->state ));
      return;
  }

  if( full ) FD_TEST( ctx->metrics.full.bytes_total       !=0UL );
  else       FD_TEST( ctx->metrics.incremental.bytes_total!=0UL );

  if( full ) ctx->metrics.full.bytes_read        += sz;
  else       ctx->metrics.incremental.bytes_read += sz;

  if( !file && -1!=ctx->local_out.dir_fd ) {
    uchar const * data = fd_chunk_to_laddr_const( ctx->snapld_in.mem, chunk );
    int fd = full ? ctx->local_out.full_snapshot_fd : ctx->local_out.incremental_snapshot_fd;
    long result = write( fd, data, sz );
    if( FD_UNLIKELY( -1==result && errno==ENOSPC ) ) {
      char const * snapshot_path = full ? ctx->local_out.full_snapshot_path : ctx->local_out.incremental_snapshot_path;
      FD_LOG_ERR(( "Out of disk space when writing out snapshot data to `%s`", snapshot_path ));
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
                       full ? ctx->metrics.full.bytes_read : ctx->metrics.incremental.bytes_read ));

    }
  }
}

static void
snapin_frag( fd_snaprd_tile_t *  ctx,
             ulong               sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR:
      /* Note: We do not need to wait for the init control message to
         be flushed through the entire pipeline, like we do for fail and
         done.  It is safe to immediately send a fail message downstream. */
      break;

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
      if( FD_LIKELY( ctx->state==FD_SNAPRD_STATE_FLUSHING_FULL_HTTP ||
                     ctx->state==FD_SNAPRD_STATE_FLUSHING_FULL_FILE ) ) {
        FD_TEST( !ctx->flush_ack );
        ctx->flush_ack = 1;
      } else FD_LOG_ERR(( "invalid control frag %lu in state %d", sig, ctx->state ));
      break;

    case FD_SNAPSHOT_MSG_CTRL_DONE:
      if( FD_LIKELY( ctx->state==FD_SNAPRD_STATE_FLUSHING_FULL_HTTP ||
                     ctx->state==FD_SNAPRD_STATE_FLUSHING_FULL_FILE ||
                     ctx->state==FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP ||
                     ctx->state==FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE ) ) {
        FD_TEST( !ctx->flush_ack );
        ctx->flush_ack = 1;
      } else FD_LOG_ERR(( "invalid control frag %lu in state %d", sig, ctx->state ));
      break;

    case FD_SNAPSHOT_MSG_CTRL_FAIL:
      if( FD_LIKELY( ctx->state==FD_SNAPRD_STATE_FLUSHING_FULL_HTTP_RESET ||
                     ctx->state==FD_SNAPRD_STATE_FLUSHING_FULL_FILE_RESET ||
                     ctx->state==FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP_RESET ||
                     ctx->state==FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE_RESET ) ) {
        FD_TEST( !ctx->flush_ack );
        ctx->flush_ack = 1;
      } else FD_LOG_ERR(( "invalid control frag %lu in state %d", sig, ctx->state ));
      break;

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      break;

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      switch( ctx->state ) {
        case FD_SNAPRD_STATE_READING_FULL_FILE:
        case FD_SNAPRD_STATE_FLUSHING_FULL_FILE:
        case FD_SNAPRD_STATE_READING_INCREMENTAL_FILE:
        case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_FILE:
        case FD_SNAPRD_STATE_READING_FULL_HTTP:
        case FD_SNAPRD_STATE_FLUSHING_FULL_HTTP:
        case FD_SNAPRD_STATE_READING_INCREMENTAL_HTTP:
        case FD_SNAPRD_STATE_FLUSHING_INCREMENTAL_HTTP:
          ctx->malformed = 1;
          break;
        default:
          break;
      }
      break;
  }
}

static int
returnable_frag( fd_snaprd_tile_t *  ctx,
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
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_SNAPIN ) {
    snapin_frag( ctx, sig );
  } else FD_LOG_ERR(( "invalid in_kind %lu %hhu", in_idx, ctx->in_kind[ in_idx ] ));
  return 0;
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
  ctx->state          = FD_SNAPRD_STATE_WAITING_FOR_PEERS;
  ctx->deadline_nanos = fd_log_wallclock() + FD_SNAPRD_WAITING_FOR_PEERS_TIMEOUT_DEADLINE_NANOS;

  ctx->local_out.dir_fd                  = -1;
  ctx->local_out.full_snapshot_fd        = -1;
  ctx->local_out.incremental_snapshot_fd = -1;
  fd_memset( ctx->local_out.full_snapshot_name, 0, PATH_MAX );
  fd_memset( ctx->local_out.incremental_snapshot_name, 0, PATH_MAX );

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
    }

    ctx->local_out.dir_fd                  = -1;
    ctx->local_out.full_snapshot_fd        = -1;
    ctx->local_out.incremental_snapshot_fd = -1;
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
  void * _ssping          = FD_SCRATCH_ALLOC_APPEND( l, fd_ssping_align(),          fd_ssping_footprint( FD_SSPING_MAX_PEERS ) );
  void * _ci_pool         = FD_SCRATCH_ALLOC_APPEND( l, gossip_ci_pool_align(),     gossip_ci_pool_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * _ci_map          = FD_SCRATCH_ALLOC_APPEND( l, gossip_ci_map_align(),      gossip_ci_map_footprint( gossip_ci_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ) ) );
  void * _ssresolver      = FD_SCRATCH_ALLOC_APPEND( l, fd_http_resolver_align(),   fd_http_resolver_footprint( FD_SNAPRD_MAX_HTTP_PEERS ) );
  void * _selector        = FD_SCRATCH_ALLOC_APPEND( l, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( FD_SSPING_MAX_PEERS ) );

  ctx->malformed = 0;

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

  ctx->selector = fd_sspeer_selector_join( fd_sspeer_selector_new( _selector, FD_SSPING_MAX_PEERS, ctx->config.incremental_snapshot_fetch, 1UL ) );

  ctx->gossip.ci_pool = gossip_ci_pool_join( gossip_ci_pool_new( _ci_pool, FD_CONTACT_INFO_TABLE_SIZE ) );
  FD_TEST( ctx->gossip.ci_pool );
  ctx->gossip.ci_map = gossip_ci_map_join( gossip_ci_map_new( _ci_map, gossip_ci_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ), 0UL ) );

  ctx->gossip.entrypoints_cnt = tile->snaprd.gossip_entrypoints_cnt;
  for( ulong i=0UL; i<tile->snaprd.gossip_entrypoints_cnt; i++ ) {
    ctx->gossip.entrypoints[ i ].l = tile->snaprd.gossip_entrypoints[ i ].l;
    ctx->gossip.entrypoints[ i ].port = fd_ushort_bswap( tile->snaprd.gossip_entrypoints[ i ].port ); /* TODO: should be fixed in a future PR */
  }

  int has_snapld_dc = 0, has_snapin_rd = 0;
  FD_TEST( tile->in_cnt<=MAX_IN_LINKS );
  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( in_link->name, "gossip_out" ) ) {
      ctx->in_kind[ i ]     = IN_KIND_GOSSIP;
      ctx->gossip_in.mem    = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
      ctx->gossip_in.chunk0 = fd_dcache_compact_chunk0( ctx->gossip_in.mem, in_link->dcache );
      ctx->gossip_in.wmark  = fd_dcache_compact_wmark ( ctx->gossip_in.mem, in_link->dcache, in_link->mtu );
      ctx->gossip_in.mtu    = in_link->mtu;
    } else if( 0==strcmp( in_link->name, "snapld_dc" ) ) {
      ctx->in_kind[ i ]     = IN_KIND_SNAPLD;
      ctx->snapld_in.mem    = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
      ctx->snapld_in.chunk0 = fd_dcache_compact_chunk0( ctx->snapld_in.mem, in_link->dcache );
      ctx->snapld_in.wmark  = fd_dcache_compact_wmark ( ctx->snapld_in.mem, in_link->dcache, in_link->mtu );
      ctx->snapld_in.mtu    = in_link->mtu;
      FD_TEST( !has_snapld_dc );
      has_snapld_dc = 1;
    } else if( 0==strcmp( in_link->name, "snapin_rd" ) ) {
      ctx->in_kind[ i ] = IN_KIND_SNAPIN;
      FD_TEST( !has_snapin_rd );
      has_snapin_rd = 1;
    }
  }
  FD_TEST( has_snapld_dc && has_snapin_rd );

  ctx->ssresolver = fd_http_resolver_join( fd_http_resolver_new( _ssresolver, FD_SNAPRD_MAX_HTTP_PEERS, ctx->config.incremental_snapshot_fetch, on_resolve, ctx ) );
  FD_TEST( ctx->ssresolver );

  if( FD_UNLIKELY( tile->out_cnt<2UL || tile->out_cnt>3UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2-3", tile->out_cnt ));
  ctx->out_ld  = out1( topo, tile, "snaprd_ld"   );
  ctx->out_gui = out1( topo, tile, "snaprd_gui"  );
  ctx->out_rp  = out1( topo, tile, "snaprd_repr" );

  for( ulong i=0UL; i<tile->snaprd.http.peers_cnt; i++ ) {
    tile->snaprd.http.peers[ i ].port = fd_ushort_bswap( tile->snaprd.http.peers[ i ].port ); /* TODO: should be fixed in a future PR */
    fd_ssping_add( ctx->ssping, tile->snaprd.http.peers[ i ] );
    fd_http_resolver_add( ctx->ssresolver, tile->snaprd.http.peers[ i ] );
  }

  ctx->predicted_incremental.full_slot = ULONG_MAX;
  ctx->predicted_incremental.slot      = ULONG_MAX;
  ctx->predicted_incremental.dirty     = 0;

  ctx->gossip.entrypoints_received = 0UL;
  ctx->gossip.saturated            = 0;
}

/* after_credit can result in as many as 5 stem publishes in some code
   paths, and returnable_frag can result in 1. */
#define STEM_BURST 6UL

#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaprd_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaprd_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

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
