#include "fd_topo.h"
#include "fd_topo_pod_helper.h"

#include <unistd.h>
#include <linux/limits.h>

fd_topo_wksp_sz_t
wksp_sz( uchar const * pod, char const * name );

void *
fd_topo_new( void *        shmem,
             uchar const * pod ) {
  fd_topo_t * topo = (fd_topo_t *)shmem;

  ulong wksp_cnt = fd_pod_query_ulong( pod, "wksp_cnt", 0UL );
  FD_TEST( wksp_cnt && wksp_cnt<=FD_TOPO_WKSP_MAX );

  for( ulong i=0UL; i<wksp_cnt; i++ ) {
    char const * name = fd_pod_queryf_cstr( pod, NULL, "wksp.%lu.name", i );
    ulong loose_sz = fd_pod_queryf_ulong( pod, 0UL, "wksp.%lu.loose_sz", i );

    fd_topo_wksp_t * wksp = topo->wksps[ i ];
    wksp->idx = i;
    wksp->topo = topo;
    FD_TEST( strlen( name )<sizeof( wksp->name ) );
    strncpy( wksp->name, name, sizeof( wksp->name ) );
    wksp->loose_sz = loose_sz;
    wksp->sz = wksp_sz( pod, name );
    wksp->contains_cnt = 0UL;
    wksp->wksp = NULL;
  }

  topo->wksp_cnt = wksp_cnt;

  ulong link_cnt = fd_pod_query_ulong( pod, "link_cnt", 0UL );
  FD_TEST( link_cnt && link_cnt<=FD_TOPO_LINK_MAX );

  for( ulong i=0UL; i<link_cnt; i++ ) {
    char const * wksp_name = fd_pod_queryf_cstr( pod, NULL, "link.%lu.wksp", i );
    char const * link_name = fd_pod_queryf_cstr( pod, NULL, "link.%lu.name", i );
    ulong lidx = fd_pod_queryf_ulong( pod, 0UL, "link.%lu.lidx", i );
    ulong depth = fd_pod_queryf_ulong( pod, 0UL, "link.%lu.depth", i );
    int is_reasm = fd_pod_queryf_int( pod, 0, "link.%lu.reasm", i );
    ulong mtu = fd_pod_queryf_ulong( pod, 0UL, "link.%lu.mtu", i );
    ulong burst = fd_pod_queryf_ulong( pod, 0UL, "link.%lu.burst", i );

    fd_topo_link_t * link = topo->links[ i ];
    link->idx = i;
    link->topo = topo;
    link->lidx = lidx;
    link->depth = depth;
    link->is_reasm = is_reasm;
    link->mtu = mtu;
    link->burst = burst;
    FD_TEST( strlen( link_name )<sizeof( link->name ) );
    strncpy( link->name, link_name, sizeof( link->name ) );

    ulong wksp_idx = 0UL;
    for( ; wksp_idx<topo->wksp_cnt; wksp_idx++ ) {
      if( FD_LIKELY( !strcmp( topo->wksps[ wksp_idx ]->name, wksp_name ) ) ) break;
    }
    FD_TEST( wksp_idx<topo->wksp_cnt );
    link->wksp = topo->wksps[ wksp_idx ];
  }

  topo->link_cnt = link_cnt;

  ulong tile_cnt = fd_pod_query_ulong( pod, "tile_cnt", 0UL );
  FD_TEST( tile_cnt && tile_cnt<=FD_TOPO_TILE_MAX );

  for( ulong i=0UL; i<tile_cnt; i++ ) {
    char const * wksp_name = fd_pod_queryf_cstr( pod, NULL, "tile.%lu.wksp", i );
    char const * tile_name = fd_pod_queryf_cstr( pod, NULL, "tile.%lu.name", i );
    ulong tidx = fd_pod_queryf_ulong( pod, 0UL, "tile.%lu.tidx", i );

    fd_topo_tile_t * tile = topo->tiles[ i ];
    tile->idx = i;
    tile->topo = topo;
    tile->tidx = tidx;
    FD_TEST( strlen( tile_name )<sizeof( tile->name ) );
    strncpy( tile->name, tile_name, sizeof( tile->name ) );

    ulong wksp_idx = 0UL;
    for( ; wksp_idx<topo->wksp_cnt; wksp_idx++ ) {
      if( FD_LIKELY( !strcmp( topo->wksps[ wksp_idx ]->name, wksp_name ) ) ) break;
    }
    FD_TEST( wksp_idx<topo->wksp_cnt );
    tile->wksp = topo->wksps[ wksp_idx ];

    char const * primary_out_name = fd_pod_queryf_cstr( pod, NULL, "tile.%lu.primary_out_link", i );
    ulong primary_out_lidx = fd_pod_queryf_ulong( pod, ULONG_MAX, "tile.%lu.primary_out_lidx", i );

    if( FD_LIKELY( primary_out_lidx!=ULONG_MAX ) ) {
      ulong link_idx = 0UL;
      for( ; link_idx<topo->link_cnt; link_idx++ ) {
        if( FD_LIKELY( !strcmp( topo->links[ link_idx ]->name, primary_out_name ) && topo->links[ link_idx ]->lidx==primary_out_lidx ) ) break;
      }
      FD_TEST( link_idx<topo->link_cnt );
      tile->primary_output = topo->links[ link_idx ];
      topo->links[ link_idx ]->producer = tile;
    }

    ulong in_cnt = fd_pod_queryf_ulong( pod, 0UL, "tile.%lu.in_cnt", i );
    for( ulong j=0UL; j<in_cnt; j++ ) {
      char const * link_name = fd_pod_queryf_cstr( pod, NULL, "tile.%lu.in.%lu.link", i, j );
      ulong link_lidx = fd_pod_queryf_ulong( pod, 0UL, "tile.%lu.in.%lu.lidx", i, j );

      ulong link_idx = 0UL;
      for( ; link_idx<topo->link_cnt; link_idx++ ) {
        if( FD_LIKELY( !strcmp( topo->links[ link_idx ]->name, link_name ) && topo->links[ link_idx ]->lidx==link_lidx ) ) break;
      }
      FD_TEST( link_idx<topo->link_cnt );

      ulong link_in_idx = topo->link_in_cnt++;
      topo->link_ins[ link_in_idx ]->idx = link_in_idx;
      topo->link_ins[ link_in_idx ]->topo = topo;
      topo->link_ins[ link_in_idx ]->reliable = fd_pod_queryf_int( pod, 0, "tile.%lu.in.%lu.reliable", i, j );
      topo->link_ins[ link_in_idx ]->polled = fd_pod_queryf_int( pod, 0, "tile.%lu.in.%lu.polled", i, j );
      topo->link_ins[ link_in_idx ]->producer = topo->links[ link_idx ]->producer;
      topo->link_ins[ link_in_idx ]->link = topo->links[ link_idx ];
      topo->link_ins[ link_in_idx ]->consumer = tile;
      topo->link_ins[ link_in_idx ]->fseq = NULL;
      
      tile->in[ j ] = topo->link_ins[ link_in_idx ];
    }

    tile->in_cnt = in_cnt;

    ulong out_cnt = fd_pod_queryf_ulong( pod, 0UL, "tile.%lu.out_cnt", i );
    for( ulong j=0UL; j<out_cnt; j++ ) {
      char const * link_name = fd_pod_queryf_cstr( pod, NULL, "tile.%lu.out.%lu.link", i, j );
      ulong link_lidx = fd_pod_queryf_ulong( pod, 0UL, "tile.%lu.out.%lu.lidx", i, j );

      ulong link_idx = 0UL;
      for( ; link_idx<topo->link_cnt; link_idx++ ) {
        if( FD_LIKELY( !strcmp( topo->links[ link_idx ]->name, link_name ) && topo->links[ link_idx ]->lidx==link_lidx ) ) break;
      }
      FD_TEST( link_idx<topo->link_cnt );

      tile->secondary_outputs[ j ] = topo->links[ link_idx ];
    }

    tile->secondary_outputs_cnt = out_cnt;
  }

  topo->tile_cnt = tile_cnt;

  return topo;
}

static void
wksp_mmap_inner( fd_topo_t * topo,
                 ulong       wksps[ static FD_TOPO_WKSP_MAX ] ) {
  /* Map in the distinct workspaces with the correct mode. */
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    if( FD_LIKELY( wksps[ i ]==FD_TOPO_WKSP_MMAP_MODE_NONE ) ) continue;

    fd_topo_wksp_t * wksp = topo->wksps[ i ];

    char name[ PATH_MAX ];
    snprintf( name, PATH_MAX, "%s_%s.wksp", topo->app_name, wksp->name );
    fd_wksp_t * joined = fd_wksp_join( fd_shmem_join( name, (int)wksps[ i ]-1, NULL, NULL, NULL ) );
    if( FD_UNLIKELY( !joined ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));

    FD_TEST( !wksp->wksp );
    wksp->wksp = joined;
  }
}

void
fd_topo_mmap_tile( fd_topo_tile_t * tile ) {
  ulong mapped[ FD_TOPO_WKSP_MAX ] = { FD_TOPO_WKSP_MMAP_MODE_NONE };

  for( ulong i=0UL; i<tile->joins_cnt; i++ ) {
    fd_topo_wksp_t const * wksp = tile->joins[ i ];
    mapped[ wksp->idx ] = fd_ulong_max( mapped[ wksp->idx ], tile->joins_mode[ i ] );
  }

  wksp_mmap_inner( tile->topo, mapped );
}

void
fd_topo_wksp_apply( fd_topo_t const * topo,
                    void (* fn )( void * laddr, uchar const * pod, char const * id ) ) {
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t const * wksp = topo->wksps[ i ];
    if( FD_UNLIKELY( !wksp->wksp ) ) continue;

    for( ulong j=0UL; j<wksp->contains_cnt; j++ ) {
      char const * id = wksp->contains[ j ];

      char offset_str[ 64 ];
      FD_TEST( fd_cstr_printf_check( offset_str, sizeof( offset_str ), NULL, "%s.offset", id ) );
      ulong offset = fd_pod_query_ulong( topo->pod, offset_str, ULONG_MAX );
      FD_TEST( offset!=ULONG_MAX );

      void * laddr = (void*)((uchar *)wksp->wksp + offset);
      fn( laddr, topo->pod, id );
    }
  }
}

static void
fd_topo_mem_sz_string( ulong sz, char out[ static 24 ] ) {
  if( FD_LIKELY( sz >= FD_SHMEM_GIGANTIC_PAGE_SZ ) ) {
    FD_TEST( fd_cstr_printf_check( out, 24, NULL, "%lu GiB", sz / (1 << 30) ) );
  } else {
    FD_TEST( fd_cstr_printf_check( out, 24, NULL, "%lu MiB", sz / (1 << 20) ) );
  }
}

void
fd_topo_print( uchar const * pod,
               int           stdout ) {
  fd_topo_t topo[ 1 ];
  fd_topo_new( topo, pod );

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

  ulong total_bytes = fd_topo_memory_mlock_multi_process( pod );
  fd_topo_memory_t pages = fd_topo_memory_required_pages( pod );

  PRINT("  %23s: %lu\n", "Total Tiles", topo->tile_cnt );
  PRINT("  %23s: %lu bytes (%lu GiB + %lu MiB + %lu KiB)\n",
    "Total Memory Locked",
    total_bytes,
    total_bytes / (1 << 30),
    (total_bytes % (1 << 30)) / (1 << 20),
    (total_bytes % (1 << 20)) / (1 << 10) );
  PRINT("  %23s: %lu\n", "Required Gigantic Pages", pages.gigantic_page_cnt );
  PRINT("  %23s: %lu\n", "Required Huge Pages", pages.huge_page_cnt );
  PRINT("  %23s: %lu\n", "Required Normal Pages", pages.normal_page_cnt );

  PRINT( "\nWORKSPACES\n");
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t const * wksp = topo->wksps[ i ];

    fd_topo_wksp_sz_t sz = wksp->sz;
    char size[ 24 ];
    fd_topo_mem_sz_string( wksp->sz.page_sz * wksp->sz.page_cnt, size );
    PRINT( "  %2lu (%7s): %12s  page_cnt=%lu  page_sz=%-8s  footprint=%-10lu  loose=%lu\n", i, size, wksp->name, sz.page_cnt, fd_shmem_page_sz_to_cstr( sz.page_sz ), sz.known_footprint, sz.total_footprint - sz.known_footprint );
  }

  PRINT( "\nLINKS\n" );
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = topo->links[ i ];

    char size[ 24 ];
    char * extra = "";
    if( FD_UNLIKELY( link->is_reasm ) ) {
      fd_topo_mem_sz_string( fd_tpu_reasm_footprint( link->depth, link->burst ), size );
      extra = " (reasm)";
    } else {
      fd_topo_mem_sz_string( fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 ), size );
    }
    PRINT( "  %2lu (%7s): %12s  kind_id=%-2lu  wksp_id=%-2lu  depth=%-5lu  mtu=%-9lu  burst=%lu%s\n", i, size, link->name, link->lidx, link->wksp->idx, link->depth, link->mtu, link->burst, extra );
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
    fd_topo_tile_t * tile = topo->tiles[ i ];

    char in[ 256 ] = {0};
    char * cur_in = in;
    ulong remaining_in = sizeof( in ) - 1;

    for( ulong j=0UL; j<tile->in_cnt; j++ ) {
      fd_topo_link_in_t const * link_in = tile->in[ j ];
      if( FD_LIKELY( j!=0UL ) ) PRINTIN( ", " );
      if( FD_LIKELY( link_in->reliable ) ) PRINTIN( "%2lu", link_in->link->idx );
      else PRINTIN( "%2ld", -link_in->link->idx );
    }

    char out[ 256 ] = {0};
    char * cur_out = out;
    ulong remaining_out = sizeof( out ) - 1;

    for( ulong j=0UL; j<tile->secondary_outputs_cnt; j++ ) {
      if( FD_LIKELY( j!=0UL ) ) PRINTOUT( ", " );
      PRINTOUT( "%2lu", tile->secondary_outputs[ j ]->idx );
    }

    char out_link_id[ 24 ] = "-1";
    if( FD_LIKELY( tile->primary_output!=NULL ) ) {
      FD_TEST( fd_cstr_printf_check( out_link_id, 24, NULL, "%lu", tile->primary_output->idx ) );
    }
    char size[ 24 ];
    fd_topo_mem_sz_string( fd_topo_memory_mlock_tile( tile ), size );
    PRINT( "  %2lu (%7s): %12s  kind_id=%-2lu  wksp_id=%-2lu  out_link=%-2s  in=[%s]  out=[%s]", i, size, tile->name, tile->tidx, tile->wksp->idx, out_link_id, in, out );
    if( FD_LIKELY( i != topo->tile_cnt-1 ) ) PRINT( "\n" );
  }

  if( FD_UNLIKELY( stdout ) ) FD_LOG_STDOUT(( "%s\n", message ));
  else                        FD_LOG_NOTICE(( "%s", message ));
}
