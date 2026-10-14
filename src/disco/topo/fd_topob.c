#include "fd_topob.h"
#include "../net/fd_net_tile.h"
#include "../waker/fd_waker.h"
#include "../sleep/fd_sleep.h"

#include "../../util/pod/fd_pod_format.h"

fd_topo_t *
fd_topob_new( void * mem,
              char const * app_name ) {
  fd_topo_t * topo = (fd_topo_t *)mem;

  if( FD_UNLIKELY( !topo ) ) {
    FD_LOG_WARNING( ( "NULL topo" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)topo, alignof(fd_topo_t) ) ) ) {
    FD_LOG_WARNING( ( "misaligned topo" ) );
    return NULL;
  }

  fd_memset( topo, 0, sizeof(fd_topo_t) );

  FD_TEST( fd_pod_new( topo->props, sizeof(topo->props) ) );

  if( FD_UNLIKELY( strlen( app_name )>=sizeof(topo->app_name) ) ) FD_LOG_ERR(( "app_name too long: %s", app_name ));
  fd_cstr_ncpy( topo->app_name, app_name, sizeof(topo->app_name) );

  topo->max_page_size           = FD_SHMEM_GIGANTIC_PAGE_SZ;
  topo->gigantic_page_threshold = 4 * FD_SHMEM_HUGE_PAGE_SZ;

  topo->sleep_obj_id = ULONG_MAX;

  topo->agave_affinity_cnt = 0;
  topo->blocklist_cores_cnt = 0;

  return topo;
}

fd_topo_wksp_t *
fd_topob_wksp( fd_topo_t *  topo,
               char const * name ) {
  if( FD_UNLIKELY( !topo || !name || !strlen( name ) ) ) FD_LOG_ERR(( "NULL args" ));
  if( FD_UNLIKELY( strlen( name )>=sizeof(topo->workspaces[ topo->wksp_cnt ].name ) ) ) FD_LOG_ERR(( "wksp name too long: %s", name ));
  if( FD_UNLIKELY( topo->wksp_cnt>=FD_TOPO_MAX_WKSPS ) ) FD_LOG_ERR(( "too many workspaces" ));

  fd_topo_wksp_t * wksp = &topo->workspaces[ topo->wksp_cnt ];
  strncpy( wksp->name, name, sizeof(wksp->name) );
  wksp->id = topo->wksp_cnt;
  wksp->core_dump_level = FD_TOPO_CORE_DUMP_LEVEL_REGULAR;
  topo->wksp_cnt++;
  return wksp;
}

fd_topo_obj_t *
fd_topob_obj( fd_topo_t *  topo,
              char const * obj_name,
              char const * wksp_name ) {
  if( FD_UNLIKELY( !topo || !obj_name || !wksp_name ) ) FD_LOG_ERR(( "NULL args" ));
  if( FD_UNLIKELY( strlen( obj_name )>=sizeof(topo->objs[ topo->obj_cnt ].name ) ) ) FD_LOG_ERR(( "obj name too long: %s", obj_name ));
  if( FD_UNLIKELY( topo->obj_cnt>=FD_TOPO_MAX_OBJS ) ) FD_LOG_ERR(( "too many objects" ));

  ulong wksp_id = fd_topo_find_wksp( topo, wksp_name );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "workspace not found: %s", wksp_name ));

  fd_topo_obj_t * obj = &topo->objs[ topo->obj_cnt ];
  memset( obj, 0, sizeof(fd_topo_obj_t) );
  strncpy( obj->name, obj_name, sizeof(obj->name) );
  obj->id        = topo->obj_cnt;
  obj->wksp_id   = wksp_id;
  obj->label_idx = ULONG_MAX;
  topo->obj_cnt++;

  return obj;
}

fd_topo_obj_t *
fd_topob_obj_named( fd_topo_t *  topo,
                    char const * obj_type,
                    char const * wksp_name,
                    char const * label ) {
  if( FD_UNLIKELY( !label ) ) FD_LOG_ERR(( "NULL args" ));
  if( FD_UNLIKELY( strlen( label )>=sizeof(topo->objs[ topo->obj_cnt ].label ) ) ) FD_LOG_ERR(( "obj label too long: %s", label ));
  fd_topo_obj_t * obj = fd_topob_obj( topo, obj_type, wksp_name );
  if( FD_UNLIKELY( !obj ) ) return NULL;

  fd_cstr_ncpy( obj->label, label, sizeof(obj->label) );
  obj->label_idx = fd_topo_obj_cnt( topo, obj_type, label );

  return obj;
}

fd_topo_link_t *
fd_topob_link( fd_topo_t *  topo,
               char const * link_name,
               char const * wksp_name,
               ulong        depth,
               ulong        mtu,
               ulong        burst ) {
  if( FD_UNLIKELY( !topo || !link_name || !wksp_name ) ) FD_LOG_ERR(( "NULL args" ));
  if( FD_UNLIKELY( strlen( link_name )>=sizeof(topo->links[ topo->link_cnt ].name ) ) ) FD_LOG_ERR(( "link name too long: %s", link_name ));
  if( FD_UNLIKELY( topo->link_cnt>=FD_TOPO_MAX_LINKS ) ) FD_LOG_ERR(( "too many links" ));

  ulong kind_id = 0UL;
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    if( !strcmp( topo->links[ i ].name, link_name ) ) kind_id++;
  }

  fd_topo_link_t * link = &topo->links[ topo->link_cnt ];
  strncpy( link->name, link_name, sizeof(link->name) );
  link->id       = topo->link_cnt;
  link->kind_id  = kind_id;
  link->depth    = depth;
  link->mtu      = mtu;
  link->burst    = burst;

  fd_topo_obj_t * obj = fd_topob_obj( topo, "mcache", wksp_name );
  link->mcache_obj_id = obj->id;
  FD_TEST( fd_pod_insertf_ulong( topo->props, depth, "obj.%lu.depth", obj->id ) );

  if( mtu ) {
    obj = fd_topob_obj( topo, "dcache", wksp_name );
    link->dcache_obj_id = obj->id;
    FD_TEST( fd_pod_insertf_ulong( topo->props, depth, "obj.%lu.depth", obj->id ) );
    FD_TEST( fd_pod_insertf_ulong( topo->props, burst, "obj.%lu.burst", obj->id ) );
    FD_TEST( fd_pod_insertf_ulong( topo->props, mtu,   "obj.%lu.mtu",   obj->id ) );
  }
  topo->link_cnt++;

  return link;
}

void
fd_topob_tile_uses( fd_topo_t *           topo,
                    fd_topo_tile_t *      tile,
                    fd_topo_obj_t const * obj,
                    int                   mode ) {
  (void)topo;

  /* Links can share an object (e.g. net rx links share the UMEM
     dcache), keep one entry with the strongest mode */
  for( ulong i=0UL; i<tile->uses_obj_cnt; i++ ) {
    if( FD_UNLIKELY( tile->uses_obj_id[ i ]==obj->id ) ) {
      tile->uses_obj_mode[ i ] = fd_int_max( tile->uses_obj_mode[ i ], mode );
      return;
    }
  }

  if( FD_UNLIKELY( tile->uses_obj_cnt>=FD_TOPO_MAX_TILE_OBJS ) ) FD_LOG_ERR(( "tile `%s` uses too many objects", tile->name ));

  tile->uses_obj_id[ tile->uses_obj_cnt ] = obj->id;
  tile->uses_obj_mode[ tile->uses_obj_cnt ] = mode;
  tile->uses_obj_cnt++;
}

fd_topo_tile_t *
fd_topob_tile( fd_topo_t *    topo,
               char const *   tile_name,
               char const *   tile_wksp,
               char const *   metrics_wksp,
               ulong          cpu_idx,
               int            is_agave,
               int            uses_id_keyswitch,
               int            uses_av_keyswitch,
               int            is_waker_client ) {

  if( FD_UNLIKELY( !topo || !tile_name || !tile_wksp || !metrics_wksp ) ) FD_LOG_ERR(( "NULL args" ));
  if( FD_UNLIKELY( strlen( tile_name )>=sizeof(topo->tiles[ topo->tile_cnt ].name ) ) ) FD_LOG_ERR(( "tile name too long: %s", tile_name ));
  if( FD_UNLIKELY( topo->tile_cnt>=FD_TOPO_MAX_TILES ) ) FD_LOG_ERR(( "too many tiles %lu", topo->tile_cnt ));

  ulong kind_id = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( !strcmp( topo->tiles[ i ].name, tile_name ) ) kind_id++;
  }

  fd_topo_tile_t * tile = &topo->tiles[ topo->tile_cnt ];
  strncpy( tile->name, tile_name, sizeof(tile->name) );
  tile->id                  = topo->tile_cnt;
  tile->kind_id             = kind_id;
  tile->is_agave            = is_agave;
  tile->cpu_idx             = fd_ulong_if( cpu_idx<ULONG_MAX, cpu_idx & ~FD_TOPOB_CPU_SHARED, ULONG_MAX );
  tile->in_cnt              = 0UL;
  tile->out_cnt             = 0UL;
  tile->event_link_id       = ULONG_MAX;
  tile->uses_obj_cnt        = 0UL;
  tile->is_waker_client     = is_waker_client;
  tile->floats              = cpu_idx<ULONG_MAX && !!(cpu_idx & FD_TOPOB_CPU_SHARED);
  tile->waker_client_idx    = ULONG_MAX;
  tile->waker_fseq_obj_id   = ULONG_MAX;
  tile->sleep_eventfd       = 0;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", tile_wksp );
  tile->tile_obj_id = tile_obj->id;
  fd_topob_tile_uses( topo, tile, tile_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_obj_t * obj = fd_topob_obj( topo, "metrics", metrics_wksp );
  tile->metrics_obj_id = obj->id;
  fd_topob_tile_uses( topo, tile, obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  if( FD_LIKELY( uses_id_keyswitch ) ) {
    obj = fd_topob_obj( topo, "keyswitch", tile_wksp );
    tile->id_keyswitch_obj_id = obj->id;
    fd_topob_tile_uses( topo, tile, obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  } else {
    tile->id_keyswitch_obj_id = ULONG_MAX;
  }

  if( FD_UNLIKELY( uses_av_keyswitch ) ) {
    obj = fd_topob_obj( topo, "keyswitch", tile_wksp );
    tile->av_keyswitch_obj_id = obj->id;
    fd_topob_tile_uses( topo, tile, obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  } else {
    tile->av_keyswitch_obj_id = ULONG_MAX;
  }

  topo->tile_cnt++;
  return tile;
}

void
fd_topob_waker( fd_topo_t * topo ) {
  ulong waker_client_cnt = 0UL;
  fd_topo_tile_t * waker_tile = NULL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * client = &topo->tiles[ i ];
    if( FD_LIKELY( !client->is_waker_client ) ) continue;
    if( FD_UNLIKELY( !waker_tile ) ) {
      char const * metrics_wksp = topo->workspaces[ topo->objs[ client->metrics_obj_id ].wksp_id ].name;
      fd_topob_wksp( topo, "waker"       );
      fd_topob_wksp( topo, "waker_ready" );
      waker_tile = fd_topob_tile( topo, "waker", "waker", metrics_wksp, ULONG_MAX, 0, 0, 0, 0 );
    }
    fd_topo_obj_t * fseq_obj = fd_topob_obj( topo, "fseq", "waker_ready" );
    fd_topob_tile_uses( topo, client,     fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, waker_tile, fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    client->waker_client_idx  = waker_client_cnt++;
    client->waker_fseq_obj_id = fseq_obj->id;
  }
  FD_TEST( waker_client_cnt<=FD_WAKER_CLIENT_MAX );
}

void
fd_topob_sleep( fd_topo_t *  topo,
                char const * metrics_wksp,
                ulong        mwaitx_cpu_idx ) {
  fd_topob_wksp( topo, "mwaitx" );
  fd_topob_wksp( topo, "sleep"  );
  topo->sleep_obj_id = fd_topob_obj( topo, "sleep", "sleep" )->id;
  fd_topob_tile( topo, "mwaitx", "mwaitx", metrics_wksp, mwaitx_cpu_idx, 0, 0, 0, 0 );
}

void
fd_topob_sleep_finish( fd_topo_t * topo ) {
  if( FD_LIKELY( topo->sleep_obj_id==ULONG_MAX ) ) return;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    int pinned = !!( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_EFFICIENT_PINNED );
    tile->floats = tile->cpu_idx!=ULONG_MAX && !pinned;
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( FD_LIKELY( !tile->floats ) ) continue;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      if( FD_UNLIKELY( topo->tiles[ j ].cpu_idx==tile->cpu_idx && !topo->tiles[ j ].floats ) ) {
        tile->floats = 0;
        break;
      }
    }
  }

  FD_TEST( topo->tile_cnt<=FD_SLEEP_TILE_MAX );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topob_tile_uses( topo, &topo->tiles[ i ], &topo->objs[ topo->sleep_obj_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
}

void
fd_topob_tile_in( fd_topo_t *  topo,
                  char const * tile_name,
                  ulong        tile_kind_id,
                  char const * fseq_wksp,
                  char const * link_name,
                  ulong        link_kind_id,
                  int          reliable,
                  int          polled ) {
  if( FD_UNLIKELY( !topo || !tile_name || !fseq_wksp || !link_name ) ) FD_LOG_ERR(( "NULL args" ));

  ulong tile_id = fd_topo_find_tile( topo, tile_name, tile_kind_id );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile not found: %s:%lu", tile_name, tile_kind_id ));
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];

  ulong link_id = fd_topo_find_link( topo, link_name, link_kind_id );
  if( FD_UNLIKELY( link_id==ULONG_MAX ) ) FD_LOG_ERR(( "link not found: %s:%lu", link_name, link_kind_id ));
  fd_topo_link_t * link = &topo->links[ link_id ];

  if( FD_UNLIKELY( tile->in_cnt>=FD_TOPO_MAX_TILE_IN_LINKS ) ) FD_LOG_ERR(( "too many in links: %s:%lu", tile_name, tile_kind_id ) );
  tile->in_link_id[ tile->in_cnt ] = link->id;
  tile->in_link_reliable[ tile->in_cnt ] = reliable;
  tile->in_link_poll[ tile->in_cnt ] = polled;
  fd_topo_obj_t * obj = fd_topob_obj( topo, "fseq", fseq_wksp );
  fd_topob_tile_uses( topo, tile, obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  tile->in_link_fseq_obj_id[ tile->in_cnt ] = obj->id;
  tile->in_cnt++;

  fd_topob_tile_uses( topo, tile, &topo->objs[ link->mcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );
  if( FD_LIKELY( link->mtu ) ) {
    fd_topob_tile_uses( topo, tile, &topo->objs[ link->dcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );
  }
}

void
fd_topob_tile_out( fd_topo_t *  topo,
                   char const * tile_name,
                   ulong        tile_kind_id,
                   char const * link_name,
                   ulong        link_kind_id ) {
  ulong tile_id = fd_topo_find_tile( topo, tile_name, tile_kind_id );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile not found: %s:%lu", tile_name, tile_kind_id ));
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];

  ulong link_id = fd_topo_find_link( topo, link_name, link_kind_id );
  if( FD_UNLIKELY( link_id==ULONG_MAX ) ) FD_LOG_ERR(( "link not found: %s:%lu", link_name, link_kind_id ));
  fd_topo_link_t * link = &topo->links[ link_id ];

  if( FD_UNLIKELY( tile->out_cnt>=FD_TOPO_MAX_TILE_OUT_LINKS ) ) FD_LOG_ERR(( "too many out links: %s", tile_name ));
  tile->out_link_id[ tile->out_cnt ] = link->id;
  tile->out_cnt++;

  fd_topob_tile_uses( topo, tile, &topo->objs[ link->mcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );
  if( FD_LIKELY( link->mtu ) ) {
    fd_topob_tile_uses( topo, tile, &topo->objs[ link->dcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
}

static void
validate( fd_topo_t const * topo ) {
  /* Objects have valid wksp_ids */
  for( ulong i=0UL; i<topo->obj_cnt; i++ ) {
    if( FD_UNLIKELY( topo->objs[ i ].wksp_id>=topo->wksp_cnt ) )
      FD_LOG_ERR(( "invalid workspace id %lu", topo->objs[ i ].wksp_id ));
  }

  /* Tile ins are valid */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {
      if( FD_UNLIKELY( topo->tiles[ i ].in_link_id[ j ]>=topo->link_cnt ) )
        FD_LOG_ERR(( "tile %lu (%s) has invalid in link %lu", i, topo->tiles[ i ].name, topo->tiles[ i ].in_link_id[ j ] ));
    }
  }

  /* Tile does not have duplicated ins */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {
      for( ulong k=0UL; k<topo->tiles[ i ].in_cnt; k++ ) {
        if( FD_UNLIKELY( j==k ) ) continue;
        if( FD_UNLIKELY( topo->tiles[ i ].in_link_id[ j ] == topo->tiles[ i ].in_link_id[ k ] ) )
          FD_LOG_ERR(( "tile %lu (%s) has duplicated in link %lu (%s)", i, topo->tiles[ i ].name,
              topo->tiles[ i ].in_link_id[ j ], topo->links[ topo->tiles[ i ].in_link_id[ j ] ].name ));
      }
    }
  }

  /* Tile does not have duplicated outs */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].out_cnt; j++ ) {
      for( ulong k=0UL; k<topo->tiles[ i ].out_cnt; k++ ) {
        if( FD_UNLIKELY( j==k ) ) continue;
        if( FD_UNLIKELY( topo->tiles[ i ].out_link_id[ j ] == topo->tiles[ i ].out_link_id[ k ] ) )
          FD_LOG_ERR(( "tile %lu (%s) has duplicated out link %lu (%s)", i, topo->tiles[ i ].name,
              topo->tiles[ i ].out_link_id[ j ], topo->links[ topo->tiles[ i ].out_link_id[ j ] ].name ));
      }
    }
  }

  /* Tile outs are different than ins */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].out_cnt; j++ ) {
      for( ulong k=0UL; k<topo->tiles[ i ].in_cnt; k++ ) {
        if( FD_UNLIKELY( topo->tiles[ i ].out_link_id[ j ] == topo->tiles[ i ].in_link_id[ k ] ) )
          FD_LOG_ERR(( "tile %lu has out link %lu same as in", i, topo->tiles[ i ].out_link_id[ j ] ));
      }
    }
  }

  /* Non polling tile ins are also not reliable */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {
      if( FD_UNLIKELY( !topo->tiles[ i ].in_link_poll[ j ] && topo->tiles[ i ].in_link_reliable[ j ] ) )
        FD_LOG_ERR(( "tile %lu has in link %lu which is not polled but reliable", i, topo->tiles[ i ].in_link_id[ j ] ));
    }
  }

  /* Tile outs are valid */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].out_cnt; j++ ) {
      if( FD_UNLIKELY( topo->tiles[ i ].out_link_id[ j ] >= topo->link_cnt ) )
        FD_LOG_ERR(( "tile %lu has invalid out link %lu", i, topo->tiles[ i ].out_link_id[ j ] ));
    }
  }

  /* Waker clients are wired */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( FD_UNLIKELY( tile->is_waker_client && tile->waker_client_idx==ULONG_MAX ) )
      FD_LOG_ERR(( "tile %s:%lu is a waker client but fd_topob_waker was not called", tile->name, tile->kind_id ));
  }

  /* Floating tiles have a CPU: it places their memory and anchors
     their affinity mask */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( FD_UNLIKELY( tile->floats && tile->cpu_idx>=FD_TILE_MAX ) )
      FD_LOG_ERR(( "tile %s:%lu floats but has no CPU", tile->name, tile->kind_id ));
  }

  /* Workspace names are unique */
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    for( ulong j=0UL; j<topo->wksp_cnt; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      if( FD_UNLIKELY( !strcmp( topo->workspaces[ i ].name, topo->workspaces[ j ].name ) ) )
        FD_LOG_ERR(( "duplicate workspace name %s", topo->workspaces[ i ].name ));
    }
  }

  /* Each workspace is identified correctly */
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_UNLIKELY( topo->workspaces[ i ].id != i ) )
      FD_LOG_ERR(( "workspace %lu has id %lu", i, topo->workspaces[ i ].id ));
  }

  /* Each link has exactly one producer */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    ulong producer_cnt = 0;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      for( ulong k=0UL; k<topo->tiles[ j ].out_cnt; k++ ) {
        if( topo->tiles[ j ].out_link_id[ k ]==i ) producer_cnt++;
      }
    }
    if( FD_UNLIKELY( producer_cnt>1UL || ( producer_cnt==0UL && !topo->links[ i ].permit_no_producers ) ) )
      FD_LOG_ERR(( "link %lu (%s:%lu) has %lu producers", i, topo->links[ i ].name, topo->links[ i ].kind_id, producer_cnt ));
  }

  /* Each link has at least one consumer */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    ulong cnt = fd_topo_link_consumer_cnt( topo, &topo->links[ i ] );
    if( FD_UNLIKELY( cnt < 1UL && !topo->links[ i ].permit_no_consumers ) ) {
      FD_LOG_ERR(( "link %lu (%s:%lu) has 0 consumers", i, topo->links[ i ].name, topo->links[ i ].kind_id ));
    }
  }
}

ulong
fd_numa_node_idx( ulong cpu_idx );

static void
initialize_numa_assignments( fd_topo_t * topo ) {
  /* Assign workspaces to NUMA nodes.  The heuristic here is pretty
     simple for now: workspaces go on the NUMA node of the first
     tile which maps the largest object in the workspace. */

  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    ulong max_footprint = 0UL;
    ulong max_obj = ULONG_MAX;

    for( ulong j=0UL; j<topo->obj_cnt; j++ ) {
      fd_topo_obj_t * obj = &topo->objs[ j ];
      if( obj->wksp_id!=i ) continue;
      if( FD_UNLIKELY( !obj->footprint ) ) FD_LOG_ERR(( "obj %lu (%s) has invalid parameters", j, obj->name ));

      if( FD_UNLIKELY( !max_footprint || obj->footprint>max_footprint ) ) {
        max_footprint = obj->footprint;
        max_obj = j;
      }
    }

    if( FD_UNLIKELY( max_obj==ULONG_MAX ) ) FD_LOG_ERR(( "no object found for workspace %s", topo->workspaces[ i ].name ));

    int found_strict   = 0;
    int found_lazy     = 0;
    int found_assigned = 0;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ j ];
      if( FD_UNLIKELY( tile->tile_obj_id==max_obj && tile->cpu_idx<FD_TILE_MAX ) ) {
        topo->workspaces[ i ].numa_idx = fd_numa_node_idx( tile->cpu_idx );
        FD_TEST( topo->workspaces[ i ].numa_idx!=ULONG_MAX );
        found_strict   = 1;
        found_lazy     = 1;
        found_assigned = 1;
        break;
      } else if( FD_UNLIKELY( tile->tile_obj_id==max_obj && tile->cpu_idx>=FD_TILE_MAX ) ) {
        topo->workspaces[ i ].numa_idx = 0;
        found_lazy = 1;
        break;
      }
    }

    if( FD_LIKELY( !found_strict ) ) {
      for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
        fd_topo_tile_t * tile = &topo->tiles[ j ];
        for( ulong k=0UL; k<tile->uses_obj_cnt; k++ ) {
          if( FD_LIKELY( tile->uses_obj_id[ k ]==max_obj && tile->cpu_idx<FD_TILE_MAX ) ) {
            topo->workspaces[ i ].numa_idx = fd_numa_node_idx( tile->cpu_idx );
            FD_TEST( topo->workspaces[ i ].numa_idx!=ULONG_MAX );
            found_lazy     = 1;
            found_assigned = 1;
            break;
          } else if( FD_UNLIKELY( tile->uses_obj_id[ k ]==max_obj ) && tile->cpu_idx>=FD_TILE_MAX ) {
            topo->workspaces[ i ].numa_idx = 0;
            found_lazy = 1;
            /* Don't break, keep looking -- a tile with a CPU assignment
               might also use object in which case we want to use that
               NUMA node. */
          }
        }

        if( FD_UNLIKELY( found_assigned ) ) break;
      }
    }

    if( FD_UNLIKELY( !found_lazy ) ) FD_LOG_ERR(( "no tile uses object %s for workspace %s", topo->objs[ max_obj ].name, topo->workspaces[ i ].name ));
  }
}

void
fd_topob_finish( fd_topo_t *                topo,
                 fd_topo_obj_callbacks_t ** callbacks ) {
  sock_lo_set_affinity( topo );

  for( ulong z=0UL; z<topo->tile_cnt; z++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ z ];

    ulong in_cnt = 0UL;
    for( ulong i=0UL; i<tile->in_cnt; i++ ) {
      if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;
      in_cnt++;
    }

    FD_TEST( !fd_pod_replacef_ulong( topo->props, in_cnt, "obj.%lu.in_cnt", tile->metrics_obj_id ) );
  }

  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];

    ulong loose_sz = 0UL;
    for( ulong j=0UL; j<topo->obj_cnt; j++ ) {
      fd_topo_obj_t * obj = &topo->objs[ j ];
      if( FD_UNLIKELY( obj->wksp_id!=wksp->id ) ) continue;

      fd_topo_obj_callbacks_t * cb = NULL;
      for( ulong i=0UL; callbacks[ i ]; i++ ) {
        if( FD_UNLIKELY( !strcmp( callbacks[ i ]->name, obj->name ) ) ) {
          cb = callbacks[ i ];
          break;
        }
      }
      if( FD_UNLIKELY( !cb ) ) FD_LOG_ERR(( "no callbacks for object %s", obj->name ));

      if( FD_UNLIKELY( cb->loose ) ) loose_sz += cb->loose( topo, obj );
    }

    ulong part_max = wksp->part_max;
    if( !part_max ) part_max = (loose_sz / (64UL << 10)); /* alloc + residual padding */
    part_max += 3; /* for initial alignment */
    ulong offset = fd_ulong_align_up( fd_wksp_private_data_off( part_max ), fd_topo_workspace_align() );

    for( ulong j=0UL; j<topo->obj_cnt; j++ ) {
      fd_topo_obj_t * obj = &topo->objs[ j ];
      if( FD_UNLIKELY( obj->wksp_id!=wksp->id ) ) continue;

      fd_topo_obj_callbacks_t * cb = NULL;
      for( ulong i=0UL; callbacks[ i ]; i++ ) {
        if( FD_UNLIKELY( !strcmp( callbacks[ i ]->name, obj->name ) ) ) {
          cb = callbacks[ i ];
          break;
        }
      }
      if( FD_UNLIKELY( !cb ) ) FD_LOG_ERR(( "no callbacks for object %s", obj->name ));

      ulong align_ = cb->align( topo, obj );
      if( FD_UNLIKELY( !fd_ulong_is_pow2( align_ ) ) ) FD_LOG_ERR(( "Return value of fdctl_obj_align(%s,%lu) is not a power of 2", obj->name, obj->id ));
      offset = fd_ulong_align_up( offset, align_ );
      obj->offset = offset;
      obj->footprint = cb->footprint( topo, obj );
      if( FD_UNLIKELY( 0!=strcmp( obj->name, "tile" ) && (!obj->footprint || obj->footprint>LONG_MAX) ) ) {
        FD_LOG_ERR(( "fdctl_obj_footprint(%s,%lu) failed", obj->name, obj->id ));
      }
      offset += obj->footprint;
    }

    ulong footprint = fd_ulong_align_up( offset, fd_topo_workspace_align() );

    part_max = fd_ulong_max( part_max, wksp->min_part_max );
    loose_sz = fd_ulong_max( loose_sz, wksp->min_loose_sz );

    /* Compute footprint for a workspace that can store our footprint,
       with an extra align of padding in case gaddr_lo is not aligned. */
    ulong total_wksp_footprint = fd_wksp_footprint( part_max, footprint + fd_topo_workspace_align() + loose_sz );

    ulong page_sz = topo->max_page_size;
    if( total_wksp_footprint < topo->gigantic_page_threshold ) page_sz = FD_SHMEM_HUGE_PAGE_SZ;
    if( FD_UNLIKELY( page_sz!=FD_SHMEM_HUGE_PAGE_SZ && page_sz!=FD_SHMEM_GIGANTIC_PAGE_SZ ) ) FD_LOG_ERR(( "invalid page_sz" ));

    ulong wksp_aligned_footprint = fd_ulong_align_up( total_wksp_footprint, page_sz );

    /* Give any leftover space in the underlying shared memory to the
       data region of the workspace, since we might as well use it. */
    wksp->part_max = part_max;
    wksp->known_footprint = footprint;
    wksp->total_footprint = wksp_aligned_footprint - fd_ulong_align_up( fd_wksp_private_data_off( part_max ), fd_topo_workspace_align() );
    wksp->page_sz = page_sz;
    wksp->page_cnt = wksp_aligned_footprint / page_sz;
  }

  /* Fingerprint the computed layout so attaching processes can detect
     offset divergence from a different build or config. */
  ulong layout_hash = 0UL;
  for( ulong i=0UL; i<topo->obj_cnt; i++ ) {
    fd_topo_obj_t const * obj = &topo->objs[ i ];
    layout_hash = fd_hash( layout_hash, obj->name, strlen( obj->name ) );
    layout_hash = fd_hash( layout_hash, topo->workspaces[ obj->wksp_id ].name, strlen( topo->workspaces[ obj->wksp_id ].name ) );
    layout_hash = fd_hash( layout_hash, &obj->offset, sizeof(obj->offset) );
    layout_hash = fd_hash( layout_hash, &obj->footprint, sizeof(obj->footprint) );
  }
  topo->layout_hash = layout_hash;

  initialize_numa_assignments( topo );

  fd_topob_validate_cpu_overlaps( topo );
  validate( topo );
}
