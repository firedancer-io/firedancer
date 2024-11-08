#include "fd_topob.h"

#include "fd_pod_format.h"
#include "../../util/shmem/fd_shmem_private.h"

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
  strncpy( topo->app_name, app_name, sizeof(topo->app_name) );

  return topo;
}

void
fd_topob_wksp( fd_topo_t *  topo,
               char const * name ) {
  if( FD_UNLIKELY( !topo || !name || !strlen( name ) ) ) FD_LOG_ERR(( "NULL args" ));
  if( FD_UNLIKELY( strlen( name )>=sizeof(topo->workspaces[ topo->wksp_cnt ].name ) ) ) FD_LOG_ERR(( "wksp name too long: %s", name ));
  if( FD_UNLIKELY( topo->wksp_cnt>=FD_TOPO_MAX_WKSPS ) ) FD_LOG_ERR(( "too many workspaces" ));

  fd_topo_wksp_t * wksp = &topo->workspaces[ topo->wksp_cnt ];
  strncpy( wksp->name, name, sizeof(wksp->name) );
  wksp->id = topo->wksp_cnt;
  topo->wksp_cnt++;
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
  strncpy( obj->name, obj_name, sizeof(obj->name) );
  obj->id      = topo->obj_cnt;
  obj->wksp_id = wksp_id;
  topo->obj_cnt++;

  return obj;
}

void
fd_topob_link( fd_topo_t *  topo,
               char const * link_name,
               char const * wksp_name,
               int          is_reasm,
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
  link->is_reasm = is_reasm;
  link->depth    = depth;
  link->mtu      = mtu;
  link->burst    = burst;

  fd_topo_obj_t * obj = fd_topob_obj( topo, "mcache", wksp_name );
  link->mcache_obj_id = obj->id;
  FD_TEST( fd_pod_insertf_ulong( topo->props, depth, "obj.%lu.depth", obj->id ) );

  if( FD_UNLIKELY( is_reasm ) ) {
    obj = fd_topob_obj( topo, "reasm", wksp_name );
    link->reasm_obj_id = obj->id;
    FD_TEST( fd_pod_insertf_ulong( topo->props, depth, "obj.%lu.depth", obj->id ) );
    FD_TEST( fd_pod_insertf_ulong( topo->props, burst, "obj.%lu.burst", obj->id ) );
  } else if( FD_UNLIKELY( mtu ) ) {
    obj = fd_topob_obj( topo, "dcache", wksp_name );
    link->dcache_obj_id = obj->id;
    FD_TEST( fd_pod_insertf_ulong( topo->props, depth, "obj.%lu.depth", obj->id ) );
    FD_TEST( fd_pod_insertf_ulong( topo->props, burst, "obj.%lu.burst", obj->id ) );
    FD_TEST( fd_pod_insertf_ulong( topo->props, mtu, "obj.%lu.mtu", obj->id ) );
  }
  topo->link_cnt++;
}

void
fd_topob_tile_uses( fd_topo_t *      topo,
                    fd_topo_tile_t * tile,
                    fd_topo_obj_t *  obj,
                    int              mode ) {
  (void)topo;

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
               int            is_agave ) {
  if( FD_UNLIKELY( !topo || !tile_name || !tile_wksp || !metrics_wksp ) ) FD_LOG_ERR(( "NULL args" ));
  if( FD_UNLIKELY( strlen( tile_name )>=sizeof(topo->tiles[ topo->tile_cnt ].name ) ) ) FD_LOG_ERR(( "tile name too long: %s", tile_name ));
  if( FD_UNLIKELY( topo->tile_cnt>=FD_TOPO_MAX_TILES ) ) FD_LOG_ERR(( "too many tiles" ));

  ulong kind_id = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( !strcmp( topo->tiles[ i ].name, tile_name ) ) kind_id++;
  }

  fd_topo_tile_t * tile = &topo->tiles[ topo->tile_cnt ];
  strncpy( tile->name, tile_name, sizeof(tile->name) );
  tile->id                  = topo->tile_cnt;
  tile->kind_id             = kind_id;
  tile->is_agave            = is_agave;
  tile->cpu_idx             = cpu_idx;
  tile->in_cnt              = 0UL;
  tile->out_cnt             = 0UL;
  tile->uses_obj_cnt        = 0UL;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", tile_wksp );
  tile->tile_obj_id = tile_obj->id;
  fd_topob_tile_uses( topo, tile, tile_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_obj_t * obj = fd_topob_obj( topo, "metrics", metrics_wksp );
  tile->metrics_obj_id = obj->id;
  fd_topob_tile_uses( topo, tile, obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  topo->tile_cnt++;
  return tile;
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
  if( FD_UNLIKELY( link->is_reasm ) ) {
    fd_topob_tile_uses( topo, tile, &topo->objs[ link->reasm_obj_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );
  } else if( FD_LIKELY( link->mtu ) ) {
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
  if( FD_UNLIKELY( link->is_reasm ) ) {
    fd_topob_tile_uses( topo, tile, &topo->objs[ link->reasm_obj_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );
  } else if( FD_LIKELY( link->mtu ) ) {
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
        char const * link_name = topo->links[ topo->tiles[ i ].out_link_id[ j ] ].name;
        /* PoH tile "publishes" this on behalf of Agave, so it's not
           a real circular link. */
        if( FD_UNLIKELY( !strcmp( link_name, "stake_out" ) ||
                         !strcmp( link_name, "crds_shred" ) ) ) continue;

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

  /* Workspace names are unique */
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    for( ulong j=0UL; j<topo->wksp_cnt; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      if( FD_UNLIKELY( !strcmp( topo->workspaces[ i ].name,  topo->workspaces[ j ].name ) ) )
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
    if( FD_UNLIKELY( producer_cnt!=1UL ) )
      FD_LOG_ERR(( "link %lu (%s:%lu) has %lu producers", i, topo->links[ i ].name, topo->links[ i ].kind_id, producer_cnt ));
  }

  /* Each link has at least one consumer */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    ulong cnt = fd_topo_link_consumer_cnt( topo, &topo->links[ i ] );
    if( FD_UNLIKELY( cnt < 1 ) )
      FD_LOG_ERR(( "link %lu (%s:%lu) has %lu consumers", i, topo->links[ i ].name, topo->links[ i ].kind_id, cnt ));
  }
}

void
fd_topob_auto_layout( fd_topo_t * topo ) {
  /* Incredibly simple automatic layout system for now ... just assign
     tiles to CPU cores in NUMA sequential order, except for a few tiles
     which should be floating. */

  char const * FLOATING[] = {
    "metric",
    "cswtch",
    "bencho",
    "bhole",  /* FIREDANCER only */
  };

  char const * ORDERED[] = {
    "benchg",
    "benchs",
    "net",
    "quic",
    "verify",
    "dedup",
    "resolv",
    "pack",
    "bank",
    "poh",
#ifdef FD_HAS_NO_AGAVE
    "pohi",   /* FIREDANCER only */
#endif
    "shred",
    "store",
#ifdef FD_HAS_NO_AGAVE
    "storei", /* FIREDANCER only */
#endif
    "sign",
    "plugin",
    "gui",
#ifdef FD_HAS_NO_AGAVE
    "gossip", /* FIREDANCER only */
    "repair", /* FIREDANCER only */
    "replay", /* FIREDANCER only */
    "thread", /* FIREDANCER only */
    "sender", /* FIREDANCER only */
    "eqvoc",  /* FIREDANCER only */
    "rpcsrv", /* FIREDANCER only */
#endif
  };

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    tile->cpu_idx = ULONG_MAX;
  }

  ulong cpu_ordering[ FD_TILE_MAX ] = { 0UL };
  ulong num_cpus = fd_numa_cpu_cnt();

  ulong next_cpu_idx = 0UL;
  ulong num_numa_nodes = fd_numa_node_cnt();
  for( ulong i=0UL; i<num_numa_nodes; i++ ) {
    for( ulong j=0UL; j<num_cpus; j++ ) {
      ulong numa_node = fd_numa_node_idx( j );
      if( FD_UNLIKELY( numa_node!=i ) ) continue;
      FD_TEST( next_cpu_idx<FD_TILE_MAX );
      cpu_ordering[ next_cpu_idx++ ] = j;
    }
  }

  FD_TEST( next_cpu_idx==num_cpus );

  ulong cpu_idx = 0UL;
  for( ulong i=0UL; i<sizeof(ORDERED)/sizeof(ORDERED[0]); i++ ) {
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ j ];
      if( !strcmp( tile->name, ORDERED[ i ] ) ) {
        if( FD_UNLIKELY( cpu_idx>=num_cpus ) ) {
          FD_LOG_ERR(( "auto layout cannot set affinity for tile `%s:%lu` because all the CPUs are already assigned", tile->name, tile->kind_id ));
        } else {
          tile->cpu_idx = cpu_ordering[ cpu_idx++ ];
        }
      }
    }
  }

  /* Make sure all the tiles we haven't set are supposed to be floating. */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( tile->cpu_idx!=ULONG_MAX ) continue;

    int found = 0;
    for( ulong j=0UL; j<sizeof(FLOATING)/sizeof(FLOATING[0]); j++ ) {
      if( !strcmp( tile->name, FLOATING[ j ] ) ) {
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) FD_LOG_WARNING(( "auto layout cannot affine tile `%s:%lu` because it is unknown. Leaving it floating", tile->name, tile->kind_id ));
  }

  for( ulong i=cpu_idx; i<num_cpus; i++ ) {
    if( FD_LIKELY( topo->agave_affinity_cnt<sizeof(topo->agave_affinity_cpu_idx)/sizeof(topo->agave_affinity_cpu_idx[0]) ) ) {
      topo->agave_affinity_cpu_idx[ topo->agave_affinity_cnt++ ] = cpu_ordering[ i ];
    }
  }
}

void
fd_topob_finish( fd_topo_t * topo,
                 ulong (* align    )( fd_topo_t const * topo, fd_topo_obj_t const * obj ),
                 ulong (* footprint)( fd_topo_t const * topo, fd_topo_obj_t const * obj ),
                 ulong (* loose    )( fd_topo_t const * topo, fd_topo_obj_t const * obj) ) {
  for( ulong z=0UL; z<topo->tile_cnt; z++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ z ];

    ulong in_cnt = 0UL;
    for( ulong i=0UL; i<tile->in_cnt; i++ ) {
      if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;
      in_cnt++;
    }

    ulong cons_cnt = 0UL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
      for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
        for( ulong k=0UL; k<tile->out_cnt; k++ ) {
          if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
            cons_cnt++;
          }
        }
      }
    }

    FD_TEST( !fd_pod_replacef_ulong( topo->props, in_cnt, "obj.%lu.in_cnt", tile->metrics_obj_id ) );
    FD_TEST( !fd_pod_replacef_ulong( topo->props, cons_cnt, "obj.%lu.cons_cnt", tile->metrics_obj_id ) );
  }

  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];

    ulong loose_sz = 0UL;
    for( ulong j=0UL; j<topo->obj_cnt; j++ ) {
      fd_topo_obj_t * obj = &topo->objs[ j ];
      if( FD_UNLIKELY( obj->wksp_id!=wksp->id ) ) continue;
      loose_sz += loose( topo, obj );
    }

    ulong part_max = 1UL + (loose_sz / (64UL << 10));
    ulong offset = fd_ulong_align_up( fd_wksp_private_data_off( part_max ), fd_topo_workspace_align() );

    for( ulong j=0UL; j<topo->obj_cnt; j++ ) {
      fd_topo_obj_t * obj = &topo->objs[ j ];
      if( FD_UNLIKELY( obj->wksp_id!=wksp->id ) ) continue;

      offset = fd_ulong_align_up( offset, align( topo, obj ) );
      obj->offset = offset;
      obj->footprint = footprint( topo, obj );
      offset += obj->footprint;
    }

    ulong footprint = fd_ulong_align_up( offset, fd_topo_workspace_align() );

    /* Compute footprint for a workspace that can store our footprint,
       with an extra align of padding incase gaddr_lo is not aligned. */
    ulong total_wksp_footprint = fd_wksp_footprint( part_max, footprint + fd_topo_workspace_align() + loose_sz );

    ulong page_sz = FD_SHMEM_GIGANTIC_PAGE_SZ;
    if( FD_UNLIKELY( total_wksp_footprint < 4 * FD_SHMEM_HUGE_PAGE_SZ ) ) page_sz = FD_SHMEM_HUGE_PAGE_SZ;

    ulong wksp_aligned_footprint = fd_ulong_align_up( total_wksp_footprint, page_sz );

    /* Give any leftover space in the underlying shared memory to the
       data region of the workspace, since we might as well use it. */
    wksp->part_max = part_max;
    wksp->known_footprint = footprint;
    wksp->total_footprint = wksp_aligned_footprint - fd_ulong_align_up( fd_wksp_private_data_off( part_max ), fd_topo_workspace_align() );
    wksp->page_sz = page_sz;
    wksp->page_cnt = wksp_aligned_footprint / page_sz;
  }

  validate( topo );
}
