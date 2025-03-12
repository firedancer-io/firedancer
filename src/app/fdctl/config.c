#define _GNU_SOURCE

#include "fdctl.h"

#include "../../disco/topo/fd_pod_format.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#if FD_HAS_NO_AGAVE
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_runtime.h"
#endif
#include "../../funk/fd_funk.h"
#include "../../waltz/ip/fd_fib4.h"
#include "../../waltz/mib/fd_dbl_buf.h"
#undef FD_MAP_FLAG_BLOCKING
#include "../../waltz/neigh/fd_neigh4_map.h"

fd_topo_run_tile_t *
fd_topo_tile_to_config( fd_topo_tile_t const * tile ) {
  fd_topo_run_tile_t ** run = TILES;
  while( *run ) {
    if( FD_LIKELY( !strcmp( (*run)->name, tile->name ) ) ) return *run;
    run++;
  }
  FD_LOG_ERR(( "unknown tile name `%s`", tile->name ));
}

ulong
fdctl_obj_align( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->scratch_align ) ) return config->scratch_align();
    return 1UL;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "mcache" ) ) ) {
    return fd_mcache_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dcache" ) ) ) {
    return fd_dcache_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "cnc" ) ) ) {
    return fd_cnc_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fseq" ) ) ) {
    return fd_fseq_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "metrics" ) ) ) {
    return FD_METRICS_ALIGN;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "opaque" ) ) ) {
    ulong align = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.align", obj->id );
    if( FD_UNLIKELY( align==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.align was not set", obj->id ));
    return align;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dbl_buf" ) ) ) {
    return fd_dbl_buf_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "funk" ) ) ) {
    return fd_funk_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "neigh4_hmap" ) ) ) {
    return fd_neigh4_hmap_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fib4" ) ) ) {
    return fd_fib4_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "keyswitch" ) ) ) {
    return fd_keyswitch_align();
#if FD_HAS_NO_AGAVE
  } else if( FD_UNLIKELY( !strcmp( obj->name, "replay_pub" ) ) ) {
    return fd_runtime_public_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "blockstore" ) ) ) {
    return fd_blockstore_align();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "txncache" ) ) ) {
    return fd_txncache_align();
#endif /* FD_HAS_NO_AGAVE */
  } else {
    FD_LOG_ERR(( "unknown object `%s`", obj->name ));
    return 0UL;
  }
}

ulong
fdctl_obj_footprint( fd_topo_t const *     topo,
                     fd_topo_obj_t const * obj ) {
  #define VAL(name) (__extension__({                                                               \
      ulong __x = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, name );      \
      if( FD_UNLIKELY( __x==ULONG_MAX ) ) FD_LOG_ERR(( "obj.%lu.%s was not set", obj->id, name )); \
      __x; }))

  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->scratch_footprint ) ) return config->scratch_footprint( tile );
    return 0UL;
  } else if( FD_UNLIKELY( !strcmp( obj->name, "mcache" ) ) ) {
    return fd_mcache_footprint( VAL("depth"), 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dcache" ) ) ) {
    return fd_dcache_footprint( fd_dcache_req_data_sz( VAL("mtu"), VAL("depth"), VAL("burst"), 1), 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "cnc" ) ) ) {
    return fd_cnc_footprint( 0UL );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fseq" ) ) ) {
    return fd_fseq_footprint();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "metrics" ) ) ) {
    return FD_METRICS_FOOTPRINT( VAL("in_cnt"), VAL("cons_cnt") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "opaque" ) ) ) {
    return VAL("footprint");
  } else if( FD_UNLIKELY( !strcmp( obj->name, "dbl_buf" ) ) ) {
    return fd_dbl_buf_footprint( VAL("mtu") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "funk" ) ) ) {
    return fd_funk_footprint();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "neigh4_hmap" ) ) ) {
    return fd_neigh4_hmap_footprint( VAL("ele_max"), VAL("lock_cnt"), VAL("probe_max") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "fib4" ) ) ) {
    return fd_fib4_footprint( VAL("route_max") );
  } else if( FD_UNLIKELY( !strcmp( obj->name, "keyswitch" ) ) ) {
    return fd_keyswitch_footprint();
#if FD_HAS_NO_AGAVE
  } else if( FD_UNLIKELY( !strcmp( obj->name, "replay_pub" ) ) ) {
    return fd_runtime_public_footprint();
  } else if( FD_UNLIKELY( !strcmp( obj->name, "blockstore" ) ) ) {
    return fd_blockstore_footprint( VAL("shred_max"), VAL("block_max"), VAL("idx_max"), VAL("txn_max") ) + VAL("alloc_max");
  } else if( FD_UNLIKELY( !strcmp( obj->name, "txncache" ) ) ) {
    return fd_txncache_footprint( VAL("max_rooted_slots"), VAL("max_live_slots"), VAL("max_txn_per_slot"), FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS );
#endif /* FD_HAS_NO_AGAVE */
  } else {
    FD_LOG_ERR(( "unknown object `%s`", obj->name ));
    return 0UL;
  }
#undef VAL
}

ulong
fdctl_obj_loose( fd_topo_t const *     topo,
                 fd_topo_obj_t const * obj ) {
  ulong loose = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.%s", obj->id, "loose" );
  if( loose!=ULONG_MAX ) {
    return loose;
  }

  if( FD_UNLIKELY( !strcmp( obj->name, "tile" ) ) ) {
    fd_topo_tile_t const * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      if( FD_LIKELY( topo->tiles[ i ].tile_obj_id==obj->id ) ) {
        tile = &topo->tiles[ i ];
        break;
      }
    }
    fd_topo_run_tile_t * config = fd_topo_tile_to_config( tile );
    if( FD_LIKELY( config->loose_footprint ) ) return config->loose_footprint( tile );
  }
  return 0UL;
}

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile ) {
  return *fd_topo_tile_to_config( tile );
}
