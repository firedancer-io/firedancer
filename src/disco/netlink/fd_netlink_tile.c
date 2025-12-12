#include "fd_netlink_tile_private.h"
#include "../topo/fd_topo.h"
#include "../topo/fd_topob.h"
#include "../metrics/fd_metrics.h"
#include "../../waltz/ip/fd_fib4_netlink.h"
#include "../../waltz/mib/fd_netdev_netlink.h"
#include "../../waltz/neigh/fd_neigh4_netlink.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../util/log/fd_dtrace.h"
#include "fd_netlink_tile.h"

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h> /* MSG_DONTWAIT */
#include <sys/socket.h> /* SOL_{...} */
#include <sys/random.h> /* getrandom */
#include <sys/time.h> /* struct timeval */
#include <linux/rtnetlink.h> /* RTM_{...} */

#define FD_SOCKADDR_IN_SZ sizeof(struct sockaddr_in)
#include "generated/netlink_seccomp.h"

void
fd_netlink_topo_create( fd_topo_tile_t * netlink_tile,
                        fd_topo_t *      topo,
                        ulong            netlnk_max_routes,
                        ulong            netlnk_max_peer_routes,
                        ulong            netlnk_max_neighbors,
                        char const *     bind_interface ) {
  fd_topo_obj_t * netdev_dbl_buf_obj = fd_topob_obj( topo, "dbl_buf",     "netbase" );
  fd_topo_obj_t * fib4_main_obj      = fd_topob_obj( topo, "fib4",        "netbase" );
  fd_topo_obj_t * fib4_local_obj     = fd_topob_obj( topo, "fib4",        "netbase" );
  fd_topo_obj_t * neigh4_obj         = fd_topob_obj( topo, "neigh4_hmap", "netbase" );

  fd_topob_tile_uses( topo, netlink_tile, netdev_dbl_buf_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, netlink_tile, fib4_main_obj,      FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, netlink_tile, fib4_local_obj,     FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, netlink_tile, neigh4_obj,         FD_SHMEM_JOIN_MODE_READ_WRITE );

  /* Configure double buffer of netdev table */
  ulong const netdev_dbl_buf_mtu = fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX );
  FD_TEST( fd_pod_insertf_ulong( topo->props, netdev_dbl_buf_mtu, "obj.%lu.mtu", netdev_dbl_buf_obj->id ) );

  /* Configure route table */
  FD_TEST( fd_pod_insertf_ulong( topo->props, netlnk_max_routes,           "obj.%lu.route_max",           fib4_main_obj->id  ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, netlnk_max_routes,           "obj.%lu.route_max",           fib4_local_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, netlnk_max_peer_routes,      "obj.%lu.route_peer_max",      fib4_main_obj->id  ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, netlnk_max_peer_routes,      "obj.%lu.route_peer_max",      fib4_local_obj->id ) );
  ulong fib4_seed;
  FD_TEST( 8UL==getrandom( &fib4_seed, sizeof(ulong), 0 ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fib4_seed, "obj.%lu.route_peer_seed", fib4_local_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, fib4_seed, "obj.%lu.route_peer_seed", fib4_main_obj->id  ) );

  /* Configure neighbor hashmap */
  FD_TEST( fd_pod_insertf_ulong( topo->props, netlnk_max_neighbors, "obj.%lu.ele_max", neigh4_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, 16UL, "obj.%lu.probe_max", neigh4_obj->id ) );
  ulong neigh4_seed;
  FD_TEST( 8UL==getrandom( &neigh4_seed, sizeof(ulong), 0 ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, neigh4_seed, "obj.%lu.seed", neigh4_obj->id ) );

  netlink_tile->netlink.netdev_dbl_buf_obj_id = netdev_dbl_buf_obj->id;
  netlink_tile->netlink.fib4_main_obj_id      = fib4_main_obj->id;
  netlink_tile->netlink.fib4_local_obj_id     = fib4_local_obj->id;
  memcpy( netlink_tile->netlink.neigh_if, bind_interface, sizeof(netlink_tile->netlink.neigh_if) );
  netlink_tile->netlink.neigh4_obj_id         = neigh4_obj->id;
}

void
fd_netlink_topo_join( fd_topo_t *      topo,
                      fd_topo_tile_t * netlink_tile,
                      fd_topo_tile_t * join_tile ) {
  fd_topob_tile_uses( topo, join_tile, &topo->objs[ netlink_tile->netlink.neigh4_obj_id     ], FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topob_tile_uses( topo, join_tile, &topo->objs[ netlink_tile->netlink.fib4_main_obj_id  ], FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topob_tile_uses( topo, join_tile, &topo->objs[ netlink_tile->netlink.fib4_local_obj_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );
}

/* Begin tile methods */

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_netlink_tile_ctx_t), FD_NETDEV_TBL_ALIGN );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_netlink_tile_ctx_t), sizeof(fd_netlink_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_netdev_tbl_align(), fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_netlink_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( ctx->magic==FD_NETLINK_TILE_CTX_MAGIC );
  populate_sock_filter_policy_netlink( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->nl_monitor->fd, (uint)ctx->nl_req->fd, (uint)ctx->prober->sock_fd );
  return sock_filter_policy_netlink_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_netlink_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_TEST( ctx->magic==FD_NETLINK_TILE_CTX_MAGIC );

  if( FD_UNLIKELY( out_fds_cnt<5UL ) ) FD_LOG_ERR(( "out_fds_cnt too low (%lu)", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->nl_monitor->fd;
  out_fds[ out_cnt++ ] = ctx->nl_req->fd;
  out_fds[ out_cnt++ ] = ctx->prober->sock_fd;
  return out_cnt;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  if( FD_UNLIKELY( tile->kind_id!=0 ) ) {
    FD_LOG_ERR(( "Topology contains more than one netlink tile" ));
  }

  uint const neigh_if_idx = if_nametoindex( tile->netlink.neigh_if );
  if( FD_UNLIKELY( !neigh_if_idx ) ) FD_LOG_ERR(( "if_nametoindex(%.16s) failed (%i-%s)", tile->netlink.neigh_if, errno, fd_io_strerror( errno ) ));

  fd_netlink_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_memset( ctx, 0, sizeof(fd_netlink_tile_ctx_t) );
  ctx->magic = FD_NETLINK_TILE_CTX_MAGIC;
  ctx->neigh4_ifidx = neigh_if_idx;

  if( FD_UNLIKELY( !fd_netlink_init( ctx->nl_monitor, 1000U ) ) ) {
    FD_LOG_ERR(( "Failed to connect to rtnetlink" ));
  }
  if( FD_UNLIKELY( !fd_netlink_init( ctx->nl_req, 9000000U ) ) ) {
    FD_LOG_ERR(( "Failed to connect to rtnetlink" ));
  }

  union {
    struct sockaddr    sa;
    struct sockaddr_nl sanl;
  } sa;
  sa.sanl = (struct sockaddr_nl) {
    .nl_family = AF_NETLINK,
    .nl_groups = RTMGRP_LINK | RTMGRP_NEIGH | RTMGRP_IPV4_ROUTE
  };
  if( FD_UNLIKELY( 0!=bind( ctx->nl_monitor->fd, &sa.sa, sizeof(struct sockaddr_nl) ) ) ) {
    FD_LOG_ERR(( "bind(sock,RT_NETLINK,RTMGRP_{LINK,NEIGH,IPV4_ROUTE}) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  float const max_probes_per_second =   3.f;
  ulong const max_probe_burst       = 128UL;
  float const probe_delay_seconds   =  15.f;
  fd_neigh4_prober_init( ctx->prober, max_probes_per_second, max_probe_burst, probe_delay_seconds );

  /* Set duration of blocking reads in before_credit */
  struct timeval tv = { .tv_usec = 2000 }; /* 2ms */
  if( FD_UNLIKELY( 0!=setsockopt( ctx->nl_monitor->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval) ) ) ) {
    FD_LOG_ERR(( "setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_netlink_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_netlink_tile_ctx_t), sizeof(fd_netlink_tile_ctx_t) );
  FD_TEST( ctx->magic==FD_NETLINK_TILE_CTX_MAGIC );
  ctx->netdev_sz    = fd_netdev_tbl_footprint( NETDEV_MAX, BOND_MASTER_MAX );
  ctx->netdev_local = FD_SCRATCH_ALLOC_APPEND( l, fd_netdev_tbl_align(), ctx->netdev_sz );

  FD_TEST( tile->netlink.netdev_dbl_buf_obj_id );
  FD_TEST( tile->netlink.neigh4_obj_id         );
  FD_TEST( tile->netlink.fib4_local_obj_id     );
  FD_TEST( tile->netlink.fib4_main_obj_id      );

  FD_TEST( fd_netdev_tbl_new( ctx->netdev_local, NETDEV_MAX, BOND_MASTER_MAX ) );
  FD_TEST( fd_netdev_tbl_join( ctx->netdev_tbl, ctx->netdev_local ) );

  FD_TEST( ctx->netdev_buf = fd_dbl_buf_join( fd_topo_obj_laddr( topo, tile->netlink.netdev_dbl_buf_obj_id ) ) );

  ulong neigh4_obj_id = tile->netlink.neigh4_obj_id;
  ulong neigh_ele_max   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.ele_max",   neigh4_obj_id );
  ulong neigh_probe_max = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.probe_max", neigh4_obj_id );
  ulong neigh_seed      = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.seed",      neigh4_obj_id );
  FD_TEST( neigh_ele_max!=ULONG_MAX && neigh_probe_max!=ULONG_MAX && neigh_seed!=ULONG_MAX );
  FD_TEST( fd_neigh4_hmap_join( ctx->neigh4, fd_topo_obj_laddr( topo, neigh4_obj_id ), neigh_ele_max, neigh_probe_max, neigh_seed ) );

  FD_TEST( fd_fib4_join(        ctx->fib4_local, fd_topo_obj_laddr( topo, tile->netlink.fib4_local_obj_id ) ) );
  FD_TEST( fd_fib4_join(        ctx->fib4_main,  fd_topo_obj_laddr( topo, tile->netlink.fib4_main_obj_id  ) ) );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( link->mtu!=0UL ) ) FD_LOG_ERR(( "netlink solicit links must have an MTU of zero" ));
  }

  ctx->action |= FD_NET_TILE_ACTION_LINK_UPDATE;
  ctx->action |= FD_NET_TILE_ACTION_ROUTE4_UPDATE;
  ctx->action |= FD_NET_TILE_ACTION_NEIGH_UPDATE;

  ctx->update_backoff = (long)( fd_tempo_tick_per_ns( NULL ) * 10e6 ); /* 10ms */
}

/* Begin stem methods

   Note: Using stem here might seem odd since fd_netlink_tile does not
   send or receive any messages.  Use of stem here is justified because of
   the initialization, generic metrics, and event loop functionality it
   provides. */

static inline void
metrics_write( fd_netlink_tile_ctx_t * ctx ) {
  FD_MCNT_SET(       NETLNK, DROP_EVENTS,             fd_netlink_enobufs_cnt            );
  FD_MCNT_SET(       NETLNK, LINK_FULL_SYNCS,         ctx->metrics.link_full_syncs      );
  FD_MCNT_SET(       NETLNK, ROUTE_FULL_SYNCS,        ctx->metrics.route_full_syncs     );
  FD_MCNT_ENUM_COPY( NETLNK, UPDATES,                 ctx->metrics.update_cnt           );
  FD_MGAUGE_SET(     NETLNK, INTERFACE_COUNT,         ctx->netdev_tbl->hdr->dev_cnt     );
  FD_MGAUGE_SET(     NETLNK, ROUTE_COUNT_LOCAL,       fd_fib4_cnt( ctx->fib4_local )    );
  FD_MGAUGE_SET(     NETLNK, ROUTE_COUNT_MAIN,        fd_fib4_cnt( ctx->fib4_main  )    );
  FD_MCNT_SET(       NETLNK, NEIGH_PROBE_SENT,        ctx->metrics.neigh_solicits_sent  );
  FD_MCNT_SET(       NETLNK, NEIGH_PROBE_FAILS,       ctx->metrics.neigh_solicits_fails );
  FD_MCNT_SET(       NETLNK, NEIGH_PROBE_RATE_LIMIT_HOST,   ctx->prober->local_rate_limited_cnt  );
  FD_MCNT_SET(       NETLNK, NEIGH_PROBE_RATE_LIMIT_GLOBAL, ctx->prober->global_rate_limited_cnt );
}

/* netlink_monitor_read calls recvfrom to process a link, route, or
   neighbor update.  Returns 1 if a message was read, 0 otherwise. */

static int
netlink_monitor_read( fd_netlink_tile_ctx_t * ctx,
                      int                     flags ) {

  uchar msg[ 16384 ];
  long msg_sz = recvfrom( ctx->nl_monitor->fd, msg, sizeof(msg), flags, NULL, NULL );
  if( msg_sz<=0L ) {
    if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) return 0;
    if( errno==ENOBUFS ) {
      fd_netlink_enobufs_cnt++;
      return 0;
    }
    FD_LOG_ERR(( "recvfrom(nl_monitor) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct nlmsghdr * nlh = fd_type_pun( msg );
  FD_DTRACE_PROBE_4( netlink_update, nlh->nlmsg_seq, nlh->nlmsg_type, nlh->nlmsg_len, nlh->nlmsg_flags );
  switch( nlh->nlmsg_type ) {
  case RTM_NEWLINK:
  case RTM_DELLINK:
    ctx->action |= FD_NET_TILE_ACTION_LINK_UPDATE;
    ctx->metrics.update_cnt[ FD_METRICS_ENUM_NETLINK_MSG_V_LINK_IDX ]++;
    break;
  case RTM_NEWROUTE:
  case RTM_DELROUTE:
    ctx->action |= FD_NET_TILE_ACTION_ROUTE4_UPDATE;
    ctx->metrics.update_cnt[ FD_METRICS_ENUM_NETLINK_MSG_V_IPV4_ROUTE_IDX ]++;
    break;
  case RTM_NEWNEIGH:
  case RTM_DELNEIGH: {
    fd_neigh4_netlink_ingest_message( ctx->neigh4, nlh, ctx->neigh4_ifidx );
    ctx->metrics.update_cnt[ FD_METRICS_ENUM_NETLINK_MSG_V_NEIGH_IDX ]++;
    break;
  }
  default:
    FD_LOG_INFO(( "Received unexpected netlink message type %u", nlh->nlmsg_type ));
    break;
  }

  return 1;
}

static void
during_housekeeping( fd_netlink_tile_ctx_t * ctx ) {
  long now = fd_tickcount();
  if( ctx->action & FD_NET_TILE_ACTION_LINK_UPDATE ) {
    if( now < ctx->link_update_ts ) return;
    ctx->action &= ~FD_NET_TILE_ACTION_LINK_UPDATE;
    fd_netdev_netlink_load_table( ctx->netdev_tbl, ctx->nl_req );
    fd_dbl_buf_insert( ctx->netdev_buf, ctx->netdev_local, ctx->netdev_sz );
    ctx->link_update_ts = now+ctx->update_backoff;
    ctx->metrics.link_full_syncs++;
  }
  if( ctx->action & FD_NET_TILE_ACTION_ROUTE4_UPDATE ) {
    if( now < ctx->route4_update_ts ) return;
    ctx->action &= ~FD_NET_TILE_ACTION_ROUTE4_UPDATE;
    fd_fib4_netlink_load_table( ctx->fib4_local, ctx->nl_req, RT_TABLE_LOCAL );
    fd_fib4_netlink_load_table( ctx->fib4_main,  ctx->nl_req, RT_TABLE_MAIN  );
    ctx->route4_update_ts = now+ctx->update_backoff;
    ctx->metrics.route_full_syncs++;
  }
  if( ctx->action & FD_NET_TILE_ACTION_NEIGH_UPDATE ) {
    ctx->action &= ~FD_NET_TILE_ACTION_NEIGH_UPDATE;
    fd_neigh4_netlink_request_dump( ctx->nl_req, ctx->neigh4_ifidx );
    uchar buf[ 4096 ];
    fd_netlink_iter_t iter[1];
    for( fd_netlink_iter_init( iter, ctx->nl_req, buf, sizeof(buf) );
        !fd_netlink_iter_done( iter );
        fd_netlink_iter_next( iter, ctx->nl_req ) ) {
      fd_neigh4_netlink_ingest_message( ctx->neigh4, fd_netlink_iter_msg( iter ), ctx->neigh4_ifidx );
    }
  }
}

/* before_credit is called once per loop iteration */

static void
before_credit( fd_netlink_tile_ctx_t * ctx,
               fd_stem_context_t *     stem FD_PARAM_UNUSED,
               int *                   charge_busy ) {

  for(;;) {
    /* Clear socket buffer */
    if( !netlink_monitor_read( ctx, MSG_DONTWAIT ) ) break;
    *charge_busy = 1;
  }

  ctx->idle_cnt++;
  if( FD_UNLIKELY( ctx->idle_cnt >= 128L ) ) {
    /* Blocking read (yield to scheduler) */
    *charge_busy = 0;
    netlink_monitor_read( ctx, 0 );
  }

}

/* after_poll_overrun is called when fd_stem.c was overrun while
   checking for new fragments.  This typically happens when
   before_credit takes too long (e.g. we were in a blocking netlink
   read) */

static void
after_poll_overrun( fd_netlink_tile_ctx_t * ctx ) {
  ctx->idle_cnt = -1L;
}

/* after_frag handles a neighbor solicit request */

static void
after_frag( fd_netlink_tile_ctx_t * ctx,
            ulong                   in_idx,
            ulong                   seq,
            ulong                   sig,
            ulong                   sz,
            ulong                   tsorig,
            ulong                   tspub,
            fd_stem_context_t *     stem ) {
  (void)in_idx; (void)seq; (void)tsorig; (void)tspub; (void)stem;

  long now = fd_tickcount();
  ctx->idle_cnt = -1L;

  /* Parse request (fully contained in sig field) */

  if( FD_UNLIKELY( sz!=0UL ) ) {
    FD_LOG_WARNING(( "unexpected sz %lu", sz ));
  }
  if( FD_UNLIKELY( sig>>48 ) ) {
    FD_LOG_WARNING(( "unexpected high bits in sig %016lx", sig ));
  }
  ushort if_idx   = (ushort)(sig>>32);
  uint   ip4_addr = (uint)sig;
  if( FD_UNLIKELY( if_idx!=ctx->neigh4_ifidx ) ) {
    ctx->metrics.neigh_solicits_fails++;
    FD_LOG_ERR(( "received neighbor solicit request for invalid interface index %u", if_idx ));
    return;
  }

  /* Drop if the kernel is already working on the request */
  if( fd_neigh4_hmap_query( ctx->neigh4, &ip4_addr ) ) {
    ctx->metrics.neigh_solicits_fails++;
    return;
  }

  /* Insert placeholder (take above branch next time) */

  fd_neigh4_entry_t * ele = fd_neigh4_hmap_insert( ctx->neigh4, &ip4_addr );
  if( FD_UNLIKELY( !ele ) ) {
    ctx->metrics.neigh_solicits_fails++;
    return;
  }
  /* Atomically write the entry, initializing MAC and probe suppression timestamp to 0 */
  fd_neigh4_entry_t to_insert = (fd_neigh4_entry_t) {
    .ip4_addr = ip4_addr,
    .state    = FD_NEIGH4_STATE_INCOMPLETE,
  };
  fd_neigh4_entry_atomic_st( ele, &to_insert );

  /* Trigger neighbor solicit via netlink */

  int probe_res = fd_neigh4_probe_rate_limited( ctx->prober, ele, ip4_addr, now );
  if( probe_res==0 ) {
    ctx->metrics.neigh_solicits_sent++;
  } else if( probe_res>0 ) {
    ctx->metrics.neigh_solicits_fails++;
  }

}

#define STEM_BURST (1UL)
#define STEM_LAZY ((ulong)13e6) /* 13ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_netlink_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_netlink_tile_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_POLL_OVERRUN  after_poll_overrun
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../stem/fd_stem.c"

/* End stem methods */

fd_topo_run_tile_t fd_tile_netlnk = {
  .name                     = "netlnk",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
