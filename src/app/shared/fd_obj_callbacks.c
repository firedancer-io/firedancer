#include "../../disco/topo/fd_topo.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/metrics/fd_metrics.h"

#include "../../tango/cnc/fd_cnc.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../tango/fseq/fd_fseq.h"
#include "../../waltz/mib/fd_dbl_buf.h"
#include "../../waltz/neigh/fd_neigh4_map.h"
#include "../../waltz/ip/fd_fib4.h"
#include "../../disco/keyguard/fd_keyswitch.h"

#define VAL(name) (__extension__({                                                             \
  ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
  if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
  __x; }))

static ulong
mcache_footprint( fd_topo_t const *     topo,
                  fd_topo_obj_t const * obj ) {
  return fd_mcache_footprint( VAL("depth"), 0UL );
}

static ulong
mcache_align( fd_topo_t const *     topo FD_FN_UNUSED,
              fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_mcache_align();
}

static void
mcache_new( fd_topo_t const *     topo,
            fd_topo_obj_t const * obj ) {
  FD_TEST( fd_mcache_new( fd_topo_obj_laddr( topo, obj->id ), VAL("depth"), 0UL, 0UL ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_mcache = {
  .name      = "mcache",
  .footprint = mcache_footprint,
  .align     = mcache_align,
  .new       = mcache_new,
};

static ulong
dcache_footprint( fd_topo_t const *     topo,
                   fd_topo_obj_t const * obj ) {
  ulong app_sz  = fd_pod_queryf_ulong( topo->props, 0UL,       "obj.%lu.app_sz",  obj->id );
  ulong data_sz = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.data_sz", obj->id );
  if( data_sz==ULONG_MAX ) {
    data_sz = fd_dcache_req_data_sz( VAL("mtu"), VAL("depth"), VAL("burst"), 1 );
  }
  return fd_dcache_footprint( data_sz, app_sz );
}

static ulong
dcache_align( fd_topo_t const *     topo FD_FN_UNUSED,
              fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_dcache_align();
}

static void
dcache_new( fd_topo_t const *     topo,
            fd_topo_obj_t const * obj ) {
  ulong app_sz  = fd_pod_queryf_ulong( topo->props, 0UL,       "obj.%lu.app_sz",  obj->id );
  ulong data_sz = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.data_sz", obj->id );
  if( data_sz==ULONG_MAX ) {
    data_sz = fd_dcache_req_data_sz( VAL("mtu"), VAL("depth"), VAL("burst"), 1 );
  }
  FD_TEST( fd_dcache_new( fd_topo_obj_laddr( topo, obj->id ), data_sz, app_sz ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_dcache = {
  .name      = "dcache",
  .footprint = dcache_footprint,
  .align     = dcache_align,
  .new       = dcache_new,
};

static ulong
fseq_footprint( fd_topo_t const *     topo FD_FN_UNUSED,
                fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_fseq_footprint();
}

static ulong
fseq_align( fd_topo_t const *     topo FD_FN_UNUSED,
            fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_fseq_align();
}

static void
fseq_new( fd_topo_t const *     topo,
          fd_topo_obj_t const * obj ) {
  FD_TEST( fd_fseq_new( fd_topo_obj_laddr( topo, obj->id ), ULONG_MAX ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_fseq = {
  .name      = "fseq",
  .footprint = fseq_footprint,
  .align     = fseq_align,
  .new       = fseq_new,
};

static ulong
metrics_footprint( fd_topo_t const *     topo,
                   fd_topo_obj_t const * obj ) {
  return FD_METRICS_FOOTPRINT( VAL("in_cnt") );
}

static ulong
metrics_align( fd_topo_t const *     topo FD_FN_UNUSED,
               fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return FD_METRICS_ALIGN;
}

static void
metrics_new( fd_topo_t const *     topo,
             fd_topo_obj_t const * obj ) {
  FD_TEST( fd_metrics_new( fd_topo_obj_laddr( topo, obj->id ), VAL("in_cnt") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_metrics = {
  .name      = "metrics",
  .footprint = metrics_footprint,
  .align     = metrics_align,
  .new       = metrics_new,
};

static ulong
dbl_buf_footprint( fd_topo_t const *     topo,
                   fd_topo_obj_t const * obj ) {
  return fd_dbl_buf_footprint( VAL("mtu") );
}

static ulong
dbl_buf_align( fd_topo_t const *     topo FD_FN_UNUSED,
               fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_dbl_buf_align();
}

static void
dbl_buf_new( fd_topo_t const *     topo,
              fd_topo_obj_t const * obj ) {
  FD_TEST( fd_dbl_buf_new( fd_topo_obj_laddr( topo, obj->id ), VAL("mtu"), 1UL ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_dbl_buf = {
  .name      = "dbl_buf",
  .footprint = dbl_buf_footprint,
  .align     = dbl_buf_align,
  .new       = dbl_buf_new,
};

static ulong
neigh4_hmap_footprint( fd_topo_t const * topo,
                   fd_topo_obj_t const * obj ) {
  ulong slot_cnt = fd_neigh4_hmap_est_slot_cnt( VAL("ele_max") );
  FD_TEST( (slot_cnt!=ULONG_MAX) & (slot_cnt!=0) );
  return fd_neigh4_hmap_footprint( slot_cnt );
}

static ulong
neigh4_hmap_align( fd_topo_t const *     topo FD_FN_UNUSED,
                   fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_neigh4_hmap_align();
}

static void
neigh4_hmap_new( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  ulong slot_cnt = fd_neigh4_hmap_est_slot_cnt( VAL("ele_max") );
  FD_TEST( fd_neigh4_hmap_new( fd_topo_obj_laddr( topo, obj->id ), slot_cnt, 1 ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_neigh4_hmap = {
  .name      = "neigh4_hmap",
  .footprint = neigh4_hmap_footprint,
  .align     = neigh4_hmap_align,
  .new       = neigh4_hmap_new,
};

static ulong
fib4_footprint( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  return fd_fib4_footprint( VAL("route_max"), VAL("route_peer_max") );
}

static ulong
fib4_align( fd_topo_t const *     topo FD_FN_UNUSED,
            fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_fib4_align();
}

static void
fib4_new( fd_topo_t const *     topo,
           fd_topo_obj_t const * obj ) {
  FD_TEST( fd_fib4_new( fd_topo_obj_laddr( topo, obj->id ), VAL("route_max"), VAL("route_peer_max"), VAL("route_peer_seed") ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_fib4 = {
  .name      = "fib4",
  .footprint = fib4_footprint,
  .align     = fib4_align,
  .new       = fib4_new,
};

static ulong
keyswitch_footprint( fd_topo_t const *     topo FD_FN_UNUSED,
                     fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_keyswitch_footprint();
}

static ulong
keyswitch_align( fd_topo_t const *     topo FD_FN_UNUSED,
                 fd_topo_obj_t const * obj  FD_FN_UNUSED ) {
  return fd_keyswitch_align();
}

static void
keyswitch_new( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  FD_TEST( fd_keyswitch_new( fd_topo_obj_laddr( topo, obj->id ), FD_KEYSWITCH_STATE_UNLOCKED ) );
}

fd_topo_obj_callbacks_t fd_obj_cb_keyswitch = {
  .name      = "keyswitch",
  .footprint = keyswitch_footprint,
  .align     = keyswitch_align,
  .new       = keyswitch_new,
};

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static ulong
tile_footprint( fd_topo_t const *     topo,
                fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = NULL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
      tile = &topo->tiles[ i ];
      break;
    }
  }
  FD_TEST( tile );

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_LIKELY( runner.scratch_footprint ) ) return runner.scratch_footprint( tile );
  else                                        return 0UL;
}

static ulong
tile_loose( fd_topo_t const *     topo,
            fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = NULL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
      tile = &topo->tiles[ i ];
      break;
    }
  }
  FD_TEST( tile );

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_UNLIKELY( runner.loose_footprint ) ) return runner.loose_footprint( tile );
  else                                        return 0UL;
}

static ulong
tile_align( fd_topo_t const *     topo,
            fd_topo_obj_t const * obj ) {
  fd_topo_tile_t const * tile = NULL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
      tile = &topo->tiles[ i ];
      break;
    }
  }
  FD_TEST( tile );

  fd_topo_run_tile_t runner = fdctl_tile_run( tile );
  if( FD_LIKELY( runner.scratch_align ) ) return runner.scratch_align();
  else                                    return 1UL;
}

fd_topo_obj_callbacks_t fd_obj_cb_tile = {
  .name      = "tile",
  .footprint = tile_footprint,
  .align     = tile_align,
  .loose     = tile_loose,
  .new       = NULL,
};

#undef VAL
