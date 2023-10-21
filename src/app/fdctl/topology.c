#include "topology.h"

#include "run/tiles/tiles.h"
#include "../../disco/fd_disco_base.h"
#include "../../util/wksp/fd_wksp_private.h"

#include <stdio.h>
#include <sys/stat.h>

FD_FN_CONST static ulong
fd_topo_workspace_align( void ) {
  /* This needs to be the max( align ) of all the child members that
     could be aligned into this workspace, otherwise our footprint
     calculation will not be correct.  For now just set to 4096 but this
     should probably be calculated dynamically, or we should reduce
     those child aligns if we can. */
  return 4096UL;
}

static void
fd_topo_join_workspace( char * const     app_name,
                        fd_topo_wksp_t * wksp ) {
  if( FD_UNLIKELY( !wksp->wksp ) ) {
    char name[ PATH_MAX ];
    snprintf( name, PATH_MAX, "%s_%s.wksp", app_name, fd_topo_wksp_kind_str( wksp->kind ) );

    wksp->wksp = fd_wksp_join( fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, NULL ) );
    if( FD_UNLIKELY( !wksp->wksp ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));
  }
}

void
fd_topo_join_tile_workspaces( char * const     app_name,
                              fd_topo_t *      topo,
                              fd_topo_tile_t * tile ) {
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->in_link_id[ i ] ].wksp_id ];
    fd_topo_join_workspace( app_name, link_wksp );
  }

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->out_link_id[ i ] ].wksp_id ];
    fd_topo_join_workspace( app_name, link_wksp );
  }

  if( FD_LIKELY( tile->out_link_id_primary != ULONG_MAX ) ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ];
    fd_topo_join_workspace( app_name, link_wksp );
  }

  fd_topo_wksp_t * tile_wksp = &topo->workspaces[ tile->wksp_id ];
  fd_topo_join_workspace( app_name, tile_wksp );
}

void
fd_topo_join_workspaces( char * const app_name,
                         fd_topo_t *  topo ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_join_workspace( app_name, &topo->workspaces[ i ] );
  }
}

void
fd_topo_leave_workspaces( fd_topo_t *  topo ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];

    if( FD_LIKELY( wksp->wksp ) ) {
      if( FD_UNLIKELY( fd_wksp_detach( wksp->wksp ) ) ) FD_LOG_ERR(( "fd_wksp_detach failed" ));
      wksp->wksp      = NULL;
      wksp->footprint = 0UL;
    }
  }
}

void
fd_topo_create_workspaces( char *      app_name,
                           fd_topo_t * topo ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];

    char name[ PATH_MAX ];
    snprintf1( name, PATH_MAX, "%s_%s.wksp", app_name, fd_topo_wksp_kind_str( wksp->kind ) );

    ulong sub_page_cnt[ 1 ] = { wksp->page_cnt };
    ulong sub_cpu_idx [ 1 ] = { 0 }; /* todo, use CPU nearest to the workspace consumers */

    int err = fd_shmem_create_multi( name, wksp->page_sz, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR ); /* logs details */
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_shmem_create_multi failed" ));

    void * shmem = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, NULL ); /* logs details */

    void * wkspmem = fd_wksp_new( shmem, name, 0U, 1UL, wksp->footprint + fd_topo_workspace_align() ); /* logs details */
    if( FD_UNLIKELY( !wkspmem ) ) FD_LOG_ERR(( "fd_wksp_new failed" ));

    fd_wksp_t * join = fd_wksp_join( wkspmem );
    if( FD_UNLIKELY( !join ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));

    /* Footprint has been predetermined so that this alloc() call will
       precisely succeed inside the data region. */
    ulong offset = fd_wksp_alloc( join, fd_topo_workspace_align(), wksp->footprint, 1UL );
    if( FD_UNLIKELY( !offset ) ) FD_LOG_ERR(( "fd_wksp_alloc failed" ));

    /* gaddr_lo is the start of the workspace data region that can be
       given out in response to wksp alloc requests.  We rely on an
       implicit assumption everywhere that the bytes we are given by
       this single allocation will be at gaddr_lo, so that we can find
       them, so we verify this here for paranoia in case the workspace
       alloc implementation changes. */
    if( FD_UNLIKELY( fd_ulong_align_up( ((struct fd_wksp_private*)join)->gaddr_lo, fd_topo_workspace_align() ) != offset ) )
      FD_LOG_ERR(( "wksp gaddr_lo %lu != offset %lu", fd_ulong_align_up( ((struct fd_wksp_private*)join)->gaddr_lo, fd_topo_workspace_align() ), offset ));

    fd_wksp_leave( join );

    if( FD_UNLIKELY( fd_shmem_leave( shmem, NULL, NULL ) ) ) /* logs details */
      FD_LOG_ERR(( "fd_shmem_leave failed" ));
  }
}

static void
fd_topo_workspace_fill( fd_topo_t *      topo,
                        fd_topo_wksp_t * wksp,
                        ulong            mode ) {
  /* Our first (and only) allocation is always at gaddr_lo in the workspace. */
  ulong scratch_top = 0UL;
  if( FD_LIKELY( mode != FD_TOPO_FILL_MODE_FOOTPRINT ) )
    scratch_top = fd_ulong_align_up( (ulong)wksp->wksp + fd_wksp_private_data_off( 1UL ), fd_topo_workspace_align() );

  char path[ FD_WKSP_CSTR_MAX ];
  void * pod1 = SCRATCH_ALLOC( fd_pod_align(), fd_pod_footprint( 16384 ) );
  uchar * pod = NULL;
  if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_NEW ) ) {
    pod = fd_pod_join( fd_pod_new( pod1, 16384 ) );
    if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "fd_pod_new failed" ));
  }

  if( FD_UNLIKELY( wksp->kind == FD_TOPO_WKSP_KIND_PACK_BANK ) )
    fd_pod_insert_ulong( pod, "cnt", fd_topo_tile_kind_cnt( topo, FD_TOPO_TILE_KIND_BANK ) );

#define INSERT_POD( path, laddr ) do {                                                              \
    if( FD_UNLIKELY( !laddr ) )                                                                     \
      FD_LOG_ERR(( "laddr is NULL" ));                                                              \
    char wksp_cstr[ FD_WKSP_CSTR_MAX ];                                                             \
    if( FD_UNLIKELY( !fd_wksp_cstr( wksp->wksp, fd_wksp_gaddr( wksp->wksp, laddr ), wksp_cstr ) ) ) \
      FD_LOG_ERR(( "fd_wksp_cstr failed" ));                                                        \
    if( FD_UNLIKELY( !fd_pod_insert_cstr( pod, path, wksp_cstr ) ) )                                \
      FD_LOG_ERR(( "fd_pod_insert_cstr failed" ));                                                  \
  } while(0)

  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ i ];
    if( FD_LIKELY( link->wksp_id!=wksp->id ) ) continue;

    ulong dcache_app_sz = 0UL;
    switch( link->kind ) {
      case FD_TOPO_LINK_KIND_QUIC_TO_VERIFY:
        /* The QUIC tile stashes some information in the dcache app region, this
            should probably be changed. */
        dcache_app_sz = fd_quic_dcache_app_footprint( link->depth );
        break;
      default:
        break;
    }

    void * mcache = SCRATCH_ALLOC( fd_mcache_align(), fd_mcache_footprint( link->depth, 0UL ) );
    if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_NEW ) ) {
      snprintf1( path, sizeof(path), "mcache_%s_%lu", fd_topo_link_kind_str( link->kind ), link->kind_id );
      INSERT_POD( path, fd_mcache_new( mcache, link->depth, 0UL, 0UL ) );
    } else if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_JOIN ) ) {
      link->mcache = fd_mcache_join( mcache );
      if( FD_UNLIKELY( !link->mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
    }
  
    if( FD_LIKELY( link->mtu ) ) {
      void * dcache = SCRATCH_ALLOC( fd_dcache_align(), fd_dcache_footprint( fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 ), dcache_app_sz ) );
      if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_NEW ) ) {
        snprintf1( path, sizeof(path), "dcache_%s_%lu", fd_topo_link_kind_str( link->kind ), link->kind_id );
        INSERT_POD( path, fd_dcache_new( dcache, fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 ), dcache_app_sz ) );
      } else if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_JOIN ) ) {
        link->dcache = fd_dcache_join( dcache );
        if( FD_UNLIKELY( !link->dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
      }
    }
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      fd_topo_link_t * link = &topo->links[ tile->in_link_id[ j ] ];
      if( FD_LIKELY( link->wksp_id!=wksp->id ) ) continue;

      void * fseq = SCRATCH_ALLOC( fd_fseq_align(), fd_fseq_footprint() );
      if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_NEW ) ) {
        snprintf1( path, sizeof(path), "fseq_%s_%lu_%s_%lu",
                   fd_topo_link_kind_str( link->kind ), link->kind_id,
                   fd_topo_tile_kind_str( tile->kind ), tile->kind_id );
        INSERT_POD( path, fd_fseq_new( fseq, 0UL ) );
      } else if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_JOIN ) ) {
        tile->in_link_fseq[ j ] = fd_fseq_join( fseq );
        if( FD_UNLIKELY( !tile->in_link_fseq[ j ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
      }
    }

    if( FD_UNLIKELY( wksp->id == FD_TOPO_WKSP_KIND_PACK_BANK && tile->kind == FD_TOPO_TILE_KIND_PACK ) ) {
      ulong bank_cnt = fd_topo_link_consumer_cnt( topo, &topo->links[ tile->out_link_id_primary ] );
      FD_TEST( bank_cnt == fd_topo_tile_kind_cnt( topo, FD_TOPO_TILE_KIND_BANK ) );
      FD_TEST( bank_cnt < sizeof( tile->extra ) );
      for( ulong j=0UL; j<bank_cnt; j++ ) {
        void * fseq = SCRATCH_ALLOC( fd_fseq_align(), fd_fseq_footprint() );
        if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_NEW ) ) {
          snprintf1( path, sizeof(path), "busy_%lu", j );
          INSERT_POD( path, fd_fseq_new( fseq, 0UL ) );
        } else if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_JOIN ) ) {
          tile->extra[ j ] = fd_fseq_join( fseq );
          if( FD_UNLIKELY( !tile->extra[ j ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
        }
      }
    }
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( FD_LIKELY( tile->wksp_id!=wksp->id ) ) continue;

    void * cnc = SCRATCH_ALLOC( fd_cnc_align(), fd_cnc_footprint( FD_CNC_APP_SZ ) );
    if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_NEW ) ) {
      snprintf1( path, sizeof(path), "cnc_%lu", tile->kind_id );
      INSERT_POD( path, fd_cnc_new( cnc, FD_CNC_APP_SZ, 0, fd_tickcount() ) );
    } else if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_JOIN ) ) {
      tile->cnc = fd_cnc_join( cnc );
      if( FD_UNLIKELY( !tile->cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
    }

    switch( tile->kind ) {
      case FD_TOPO_TILE_KIND_PACK: {
        void * poh_slot = SCRATCH_ALLOC( 8UL, 8UL );
        void * poh_parent_slot = SCRATCH_ALLOC( 8UL, 8UL );
        if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_NEW ) ) {
          INSERT_POD( "poh_slot", poh_slot );
          INSERT_POD( "poh_parent_slot", poh_parent_slot );
        }
        break;
      }
      case FD_TOPO_TILE_KIND_SHRED: {
        void * shred_version = SCRATCH_ALLOC( 8UL, 8UL );
        void * mvcc = SCRATCH_ALLOC( fd_mvcc_align(), fd_mvcc_footprint( 16UL + 50000UL*46UL ) ); /* max of 50k validators */
        if( FD_LIKELY( mode==FD_TOPO_FILL_MODE_NEW ) ) {
          *(ulong*)shred_version = 0UL;
          INSERT_POD( "shred_version", shred_version );
          INSERT_POD( "cluster_nodes", fd_mvcc_new( mvcc, 16UL + 50000UL*46UL ) );
        } else if ( FD_LIKELY( mode==FD_TOPO_FILL_MODE_JOIN ) ) {
          tile->extra[ 0 ] = shred_version;
          tile->extra[ 1 ] = fd_mvcc_join( mvcc );
          if( FD_UNLIKELY( !tile->extra[ 1 ] ) ) FD_LOG_ERR(( "fd_mvcc_join failed" ));
        }
        break;
      }
      default:
        break;
    }
  }

  if( FD_LIKELY( mode == FD_TOPO_FILL_MODE_FOOTPRINT ) ) {
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ i ];
      if( FD_LIKELY( tile->wksp_id!=wksp->id ) ) continue;

      fd_tile_config_t * config = fd_topo_tile_to_config( tile );
      if( FD_LIKELY( config->scratch_align ) ) {
        ulong current_wksp_offset = fd_ulong_align_up( fd_wksp_private_data_off( 1UL ), fd_topo_workspace_align() ) + scratch_top;

        ulong desired_scratch_align = config->scratch_align();
        ulong pad_to_align = desired_scratch_align- (current_wksp_offset % desired_scratch_align);

        ulong tile_mem_offset = (ulong)SCRATCH_ALLOC( 1UL, pad_to_align + config->scratch_footprint( tile ) );
        tile->user_mem_offset = fd_ulong_align_up( fd_wksp_private_data_off( 1UL ), fd_topo_workspace_align() ) + tile_mem_offset + pad_to_align;
      }
    }

    ulong footprint = fd_ulong_align_up( scratch_top, fd_topo_workspace_align() );
    /* Compute footprint for a workspace that can store our footprint, with an extra align of
       padding incase gaddr_lo is not aligned. */
    ulong total_wksp_footprint = fd_wksp_footprint( 1UL, footprint + fd_topo_workspace_align() );

    ulong page_sz = FD_SHMEM_GIGANTIC_PAGE_SZ;
    if( FD_UNLIKELY( total_wksp_footprint < 4 * FD_SHMEM_HUGE_PAGE_SZ ) ) page_sz = FD_SHMEM_HUGE_PAGE_SZ;

    ulong wksp_aligned_footprint = fd_ulong_align_up( total_wksp_footprint, page_sz );

    /* Give any leftover space in the underlying shared memory to the
       data region of the workspace, since we might as well use it. */
    wksp->footprint = wksp_aligned_footprint - fd_ulong_align_up( fd_wksp_private_data_off( 1UL ), fd_topo_workspace_align() ) - fd_topo_workspace_align();
    wksp->page_sz = page_sz;
    wksp->page_cnt = wksp_aligned_footprint / page_sz;
  }
}

FD_FN_PURE static int
ulong_arr_contains( ulong   cnt,
                    ulong * arr,
                    ulong   val ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( arr[ i ] == val ) return 1;
  }
  return 0;
}

void
fd_topo_fill_tile( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   ulong            mode ) {
  ulong wksp_seen_cnt = 0UL;
  ulong wksp_seen[ FD_TOPO_MAX_WKSPS ];

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->in_link_id[ i ] ].wksp_id ];
    if( FD_LIKELY( ulong_arr_contains( wksp_seen_cnt, wksp_seen, link_wksp->id ) ) ) continue;
    wksp_seen[ wksp_seen_cnt++ ] = link_wksp->id;

    fd_topo_workspace_fill( topo, link_wksp, mode );
  }

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->out_link_id[ i ] ].wksp_id ];
    if( FD_LIKELY( ulong_arr_contains( wksp_seen_cnt, wksp_seen, link_wksp->id ) ) ) continue;
    wksp_seen[ wksp_seen_cnt++ ] = link_wksp->id;

    fd_topo_workspace_fill( topo, link_wksp, mode );
  }

  if( FD_LIKELY( tile->out_link_id_primary != ULONG_MAX ) ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ];
    if( FD_UNLIKELY( !ulong_arr_contains( wksp_seen_cnt, wksp_seen, link_wksp->id ) ) ) {
      wksp_seen[ wksp_seen_cnt++ ] = link_wksp->id;
      fd_topo_workspace_fill( topo, link_wksp, mode );
    }
  }

  fd_topo_wksp_t * tile_wksp = &topo->workspaces[ tile->wksp_id ];
  if( FD_UNLIKELY( !ulong_arr_contains( wksp_seen_cnt, wksp_seen, tile_wksp->id ) ) ) {
    wksp_seen[ wksp_seen_cnt++ ] = tile_wksp->id;
    fd_topo_workspace_fill( topo, tile_wksp, mode );
  }
}

void
fd_topo_fill( fd_topo_t * topo,
              ulong       mode ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_workspace_fill( topo, &topo->workspaces[ i ], mode );
  }
}

static ulong
fd_topo_mlock_max_tile1( fd_topo_t * topo,
                         fd_topo_tile_t * tile ) {
  #define ADD( wksp ) do {                          \
      int found = 0;                                \
      for( ulong j=0UL; j<wksp_seen_cnt; j++ ) {      \
        if( wksp_seen[ j ] == wksp->id ) {          \
          found = 1;                                \
          break;                                    \
        }                                           \
      }                                             \
      if( FD_LIKELY( !found ) ) {                   \
        wksp_seen[ wksp_seen_cnt++ ] = wksp->id;    \
        tile_mem += wksp->page_cnt * wksp->page_sz; \
      }                                             \
    } while( 0 )

  ulong wksp_seen_cnt = 0UL;
  ulong wksp_seen[ FD_TOPO_MAX_WKSPS ];

  ulong tile_mem = 0UL;

  for( ulong j=0UL; j<tile->in_cnt; j++ ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->in_link_id[ j ] ].wksp_id ];
    ADD( link_wksp );
  }

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->out_link_id[ i ] ].wksp_id ];
    ADD( link_wksp );
  }

  if( FD_LIKELY( tile->out_link_id_primary!=ULONG_MAX ) ) {
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->links[ tile->out_link_id_primary ].wksp_id ];
    ADD( link_wksp );
  }

  fd_topo_wksp_t * tile_wksp = &topo->workspaces[ tile->wksp_id ];
  ADD( tile_wksp );

  if( FD_UNLIKELY( tile->kind == FD_TOPO_TILE_KIND_SHRED ) ) {
    /* Shred tile locks 5 scratch pages for storing private key material. */
    tile_mem += 5UL * FD_SHMEM_NORMAL_PAGE_SZ;
  }

  /* Every tile locks an additional set of pages for the stack. */
  ulong stack_pages = (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL;
  tile_mem += stack_pages * FD_SHMEM_HUGE_PAGE_SZ;

  return tile_mem;
}

ulong
fd_topo_mlock_max_tile( fd_topo_t * topo ) {
  fd_topo_fill( topo, FD_TOPO_FILL_MODE_FOOTPRINT );

  ulong result = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    result = fd_ulong_max( result, fd_topo_mlock_max_tile1( topo, tile ) );
  }

  return result;
}

ulong
fd_topo_mlock( fd_topo_t * topo ) {
  fd_topo_fill( topo, FD_TOPO_FILL_MODE_FOOTPRINT );

  ulong result = 0UL;
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    result += topo->workspaces[ i ].page_cnt * topo->workspaces[ i ].page_sz;
  }
  return result;
}

void
fd_topo_validate( fd_topo_t * topo ) {
  /* Tiles have valid wksp_ids */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( topo->tiles[ i ].wksp_id >= topo->wksp_cnt ) )
      FD_LOG_ERR(( "invalid workspace id %lu", topo->tiles[ i ].wksp_id ));
  }

  /* Links have valid wksp_ids */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    if( FD_UNLIKELY( topo->links[ i ].wksp_id >= topo->wksp_cnt ) )
      FD_LOG_ERR(( "invalid workspace id %lu", topo->links[ i ].wksp_id ));
  }

  /* Tiles of the same kind share the same wksp id */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      if( topo->tiles[ i ].kind == topo->tiles[ j ].kind ) {
        if( FD_UNLIKELY( topo->tiles[ i ].wksp_id != topo->tiles[ j ].wksp_id ) )
          FD_LOG_ERR(( "tiles %lu and %lu of kind %lu have different wksp ids", i, j, topo->tiles[ i ].kind ));
      }
    }
  }

  /* Links of the same kind share the same wksp id */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    for( ulong j=0UL; j<topo->link_cnt; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      if( topo->links[ i ].kind == topo->links[ j ].kind ) {
        if( FD_UNLIKELY( topo->links[ i ].wksp_id != topo->links[ j ].wksp_id ) )
          FD_LOG_ERR(( "links %lu and %lu of kind %lu have different wksp ids", i, j, topo->links[ i ].kind ));
      }
    }
  }

  /* Tiles of different kind have different workspace ids */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      if( topo->tiles[ i ].kind != topo->tiles[ j ].kind ) {
        if( FD_UNLIKELY( topo->tiles[ i ].wksp_id == topo->tiles[ j ].wksp_id ) )
          FD_LOG_ERR(( "tiles %lu and %lu of different kinds have the same wksp id %lu", i, j, topo->tiles[ i ].wksp_id ));
      }
    }
  }

  /* Tiles have valid kinds */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( topo->tiles[ i ].kind >= FD_TOPO_TILE_KIND_MAX ) )
      FD_LOG_ERR(( "invalid tile kind %lu >= FD_TOPO_TILE_KIND_MAX (%s)", topo->tiles[ i ].kind, fd_topo_tile_kind_str( topo->tiles[ i ].kind ) ));
  }

  /* Tile kind names are <= 7 chars */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( strlen( fd_topo_tile_kind_str( topo->tiles[ i ].kind ) ) > 7 ) )
      FD_LOG_ERR(( "tile kind name too long: %s", fd_topo_tile_kind_str( topo->tiles[ i ].kind ) ));
  }

  /* Tile kinds have names */
  for( ulong i=0UL; i<FD_TOPO_TILE_KIND_MAX; i++ ) {
    if( FD_UNLIKELY( !strlen( fd_topo_tile_kind_str( i ) ) ) )
      FD_LOG_ERR(( "tile kind %lu has no name", i ));
  }

  /* Tile kind names are unique */
  for( ulong i=0UL; i<FD_TOPO_TILE_KIND_MAX; i++ ) {
    for( ulong j=0UL; j<FD_TOPO_TILE_KIND_MAX; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      if( FD_UNLIKELY( !strcmp( fd_topo_tile_kind_str( i ), fd_topo_tile_kind_str( j ) ) ) )
        FD_LOG_ERR(( "duplicate tile kind name %s", fd_topo_tile_kind_str( topo->tiles[ i ].kind ) ));
    }
  }

  /* Tile ins are valid */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {
      if( FD_UNLIKELY( topo->tiles[ i ].in_link_id[ j ] >= topo->link_cnt ) )
        FD_LOG_ERR(( "tile %lu has invalid in link %lu", i, topo->tiles[ i ].in_link_id[ j ] ));
    }
  }

  /* Tile does not have duplicated ins */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {
      for( ulong k=0UL; k<topo->tiles[ i ].in_cnt; k++ ) {
        if( FD_UNLIKELY( j==k ) ) continue;
        if( FD_UNLIKELY( topo->tiles[ i ].in_link_id[ j ] == topo->tiles[ i ].in_link_id[ k ] ) )
          FD_LOG_ERR(( "tile %lu has duplicated in link %lu", i, topo->tiles[ i ].in_link_id[ j ] ));
      }
    }
  }

  /* Tile does not have duplicated outs */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].out_cnt; j++ ) {
      for( ulong k=0UL; k<topo->tiles[ i ].out_cnt; k++ ) {
        if( FD_UNLIKELY( j==k ) ) continue;
        if( FD_UNLIKELY( topo->tiles[ i ].out_link_id[ j ] == topo->tiles[ i ].out_link_id[ k ] ) )
          FD_LOG_ERR(( "tile %lu has duplicated out link %lu", i, topo->tiles[ i ].out_link_id[ j ] ));
      }
    }
  }

  /* Tile outs are different than primary out */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( topo->tiles[i].out_link_id_primary != ULONG_MAX ) {
      for( ulong j=0UL; j<topo->tiles[ i ].out_cnt; j++ ) {
        if( FD_UNLIKELY( topo->tiles[ i ].out_link_id[ j ] == topo->tiles[ i ].out_link_id_primary ) )
          FD_LOG_ERR(( "tile %lu has out link %lu same as primary out", i, topo->tiles[ i ].out_link_id[ j ] ));
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

  /* Tile ins are different than primary out */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( topo->tiles[i].out_link_id_primary != ULONG_MAX ) {
      for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {
        if( FD_UNLIKELY( topo->tiles[ i ].in_link_id[ j ] == topo->tiles[ i ].out_link_id_primary ) )
          FD_LOG_ERR(( "tile %lu has in link %lu same as primary out", i, topo->tiles[ i ].in_link_id[ j ] ));
      }
    }
  }

  /* Tile out is valid */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( FD_UNLIKELY( topo->tiles[ i ].out_link_id_primary >= topo->link_cnt && topo->tiles[ i ].out_link_id_primary != ULONG_MAX ) )
      FD_LOG_ERR(( "tile %lu has invalid out link %lu", i, topo->tiles[ i ].out_link_id_primary ));
  }

  /* Tile outs are valid */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for( ulong j=0UL; j<topo->tiles[ i ].out_cnt; j++ ) {
      if( FD_UNLIKELY( topo->tiles[ i ].out_link_id[ j ] >= topo->link_cnt ) )
        FD_LOG_ERR(( "tile %lu has invalid out link %lu", i, topo->tiles[ i ].out_link_id[ j ] ));
    }
  }

  /* Workspaces have valid kinds */
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_UNLIKELY( topo->workspaces[ i ].kind >= FD_TOPO_WKSP_KIND_MAX ) )
      FD_LOG_ERR(( "invalid workspace kind %lu", topo->workspaces[ i ].kind ));
  }

  /* Workspace kinds have names */
  for( ulong i=0UL; i<FD_TOPO_WKSP_KIND_MAX; i++ ) {
    if( FD_UNLIKELY( !strlen( fd_topo_wksp_kind_str( i ) ) ) )
      FD_LOG_ERR(( "workspace kind %lu has no name", i ));
  }

  /* Workspace kind names are unique */
  for( ulong i=0UL; i<FD_TOPO_WKSP_KIND_MAX; i++ ) {
    for( ulong j=0UL; j<FD_TOPO_WKSP_KIND_MAX; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      if( FD_UNLIKELY( !strcmp( fd_topo_wksp_kind_str( i ), fd_topo_wksp_kind_str( j ) ) ) )
        FD_LOG_ERR(( "duplicate workspace kind name %s", fd_topo_wksp_kind_str( topo->workspaces[ i ].kind ) ));
    }
  }

  /* At most one of each workspace kind */
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    for( ulong j=0UL; j<topo->wksp_cnt; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      if( topo->workspaces[ i ].kind == topo->workspaces[ j ].kind )
        FD_LOG_ERR(( "duplicate workspace kind %lu", topo->workspaces[ i ].kind ));
    }
  }

  /* Each workspace is identified correctly */
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_UNLIKELY( topo->workspaces[ i ].id != i ) )
      FD_LOG_ERR(( "workspace %lu has id %lu", i, topo->workspaces[ i ].id ));
  }

  /* Each link has exactly one producer */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    /* gossip/lsched to pack is sent by solana, and not hosted in a tile for now */
    if( FD_UNLIKELY( topo->links[ i ].kind == FD_TOPO_LINK_KIND_GOSSIP_TO_PACK ) ) continue;
    if( FD_UNLIKELY( topo->links[ i ].kind == FD_TOPO_LINK_KIND_LSCHED_TO_PACK ) ) continue;

    /* poh to shred is sent by solana, and not hosted in a tile for now */
    if( FD_UNLIKELY( topo->links[ i ].kind == FD_TOPO_LINK_KIND_POH_TO_SHRED ) ) continue;

    ulong producer_cnt = 0;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      for( ulong k=0UL; k<topo->tiles[ j ].out_cnt; k++ ) {
        if( topo->tiles[ j ].out_link_id[ k ] == i ) producer_cnt++;
      }
      if( topo->tiles[ j ].out_link_id_primary == i ) producer_cnt++;
    }
    if( FD_UNLIKELY( producer_cnt != 1 ) )
      FD_LOG_ERR(( "link %lu (%s %lu) has %lu producers", i, fd_topo_link_kind_str( topo->links[ i ].kind ), topo->links[ i ].kind_id, producer_cnt ));
  }

  /* Each link has at least one consumer */
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    ulong cnt = fd_topo_link_consumer_cnt( topo, &topo->links[ i ] );
    if( FD_UNLIKELY( cnt < 1 ) )
      FD_LOG_ERR(( "link %lu (%s %lu) has %lu consumers", i, fd_topo_link_kind_str( topo->links[ i ].kind ), topo->links[ i ].kind_id, cnt ));
  }
}

static void
fd_topo_mem_sz_string( ulong sz, char out[static 24] ) {
  if( FD_LIKELY( sz >= FD_SHMEM_GIGANTIC_PAGE_SZ ) ) {
    snprintf1( out, 24, "%lu GiB", sz / (1 << 30) );
  } else {
    snprintf1( out, 24, "%lu MiB", sz / (1 << 20) );
  }
}

void
fd_topo_print_log( fd_topo_t * topo ) {
  char message[ 4UL*4096UL ] = {0}; /* Same as FD_LOG_BUF_SZ */

  char * cur = message;
  ulong remaining = sizeof(message) - 1; /* Leave one character at the end to ensure NUL terminated */

#define PRINT( ... ) do {                                                           \
    int n = snprintf( cur, remaining, __VA_ARGS__ );                                \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf1 failed" ));                  \
    if( FD_UNLIKELY( (ulong)n >= remaining ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    remaining -= (ulong)n;                                                          \
    cur += n;                                                                       \
  } while( 0 )

  PRINT( "\nSUMMARY\n" );

  /* The logic to compute number of stack pages is taken from
     fd_tile_thread.cxx, in function fd_tile_private_stack_new, and this
     should match that. */
  ulong stack_pages = topo->tile_cnt * FD_SHMEM_HUGE_PAGE_SZ * ((FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL);

  /* The logic to map these private pages into memory is in utility.c,
     under load_key_into_protected_memory, and the amount of pages
     should be kept in sync. */
  ulong private_key_pages = 5UL * FD_SHMEM_NORMAL_PAGE_SZ;
  ulong total_bytes = fd_topo_mlock( topo ) + stack_pages + private_key_pages;

  PRINT("  %20s: %lu\n", "Total Tiles", topo->tile_cnt );
  PRINT("  %20s: %lu bytes (%lu GiB + %lu MiB + %lu KiB)\n",
    "Total Memory Locked",
    total_bytes,
    total_bytes / (1 << 30),
    (total_bytes % (1 << 30)) / (1 << 20),
    (total_bytes % (1 << 20)) / (1 << 10) );

  PRINT( "\nWORKSPACES\n");
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];

    char size[ 24 ];
    fd_topo_mem_sz_string( wksp->page_sz * wksp->page_cnt, size );
    PRINT( "  %2lu (%6s): %12s  page_cnt=%lu  page_sz=%-8s  footprint=%lu\n", i, size, fd_topo_wksp_kind_str( wksp->kind ), wksp->page_cnt, fd_shmem_page_sz_to_cstr( wksp->page_sz ), wksp->footprint );
  }

  PRINT( "\nLINKS\n" );
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ i ];

    char size[ 24 ];
    fd_topo_mem_sz_string( fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 ), size );
    PRINT( "  %2lu (%6s): %12s  kind_id=%-2lu  wksp_id=%-2lu  depth=%-5lu  mtu=8%lu  burst=%lu\n", i, size, fd_topo_link_kind_str( link->kind ), link->kind_id, link->wksp_id, link->depth, link->mtu, link->burst );
  }

#define PRINTIN( ... ) do {                                                            \
    int n = snprintf( cur_in, remaining_in, __VA_ARGS__ );                             \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf1 failed" ));                     \
    if( FD_UNLIKELY( (ulong)n >= remaining_in ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    remaining_in -= (ulong)n;                                                          \
    cur_in += n;                                                                       \
  } while( 0 )

#define PRINTOUT( ... ) do {                                                            \
    int n = snprintf( cur_out, remaining_in, __VA_ARGS__ );                             \
    if( FD_UNLIKELY( n < 0 ) ) FD_LOG_ERR(( "snprintf1 failed" ));                      \
    if( FD_UNLIKELY( (ulong)n >= remaining_out ) ) FD_LOG_ERR(( "snprintf overflow" )); \
    remaining_out -= (ulong)n;                                                          \
    cur_out += n;                                                                       \
  } while( 0 )

  PRINT( "\nTILES\n" );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];

    char in[ 256 ] = {0};
    char * cur_in = in;
    ulong remaining_in = sizeof( in ) - 1;

    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      if( FD_LIKELY( j != 0 ) ) PRINTIN( ", " );
      if( FD_LIKELY( tile->in_link_reliable[ j ] ) ) PRINTIN( "%2lu", tile->in_link_id[ j ] );
      else PRINTIN( "%2ld", -tile->in_link_id[ j ] );
    }

    char out[ 256 ] = {0};
    char * cur_out = out;
    ulong remaining_out = sizeof( out ) - 1;

    for( ulong j=0UL; j<tile->out_cnt; j++ ) {
      if( FD_LIKELY( j != 0 ) ) PRINTOUT( ", " );
      PRINTOUT( "%2lu", tile->out_link_id[ j ] );
    }

    char out_link_id[ 24 ] = "-1";
    if( tile->out_link_id_primary != ULONG_MAX )
      snprintf1( out_link_id, 24, "%lu", tile->out_link_id_primary );
    char size[ 24 ];
    fd_topo_mem_sz_string( fd_topo_mlock_max_tile1( topo, tile ), size );
    PRINT( "  %2lu (%6s): %12s  kind_id=%-2lu  wksp_id=%-2lu  out_link=%-2s  in=[%s]  out=[%s]\n", i, size, fd_topo_tile_kind_str( tile->kind ), tile->kind_id, tile->wksp_id, out_link_id, in, out );
  }

  FD_LOG_NOTICE(( "%s", message ));
}
