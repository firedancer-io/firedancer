#include "fd_topo_builder.h"
#include "fd_topo_pod_helper.h"

#include "../quic/fd_tpu.h"

void
fd_topo_builder_add_wksp( uchar *      pod,
                          char const * name,
                          ulong        loose_sz ) {
  ulong wksp_cnt = fd_pod_query_ulong( pod, "wksp_cnt", 0UL );
  FD_TEST( fd_pod_insertf_cstr( pod, name, "wksp.%lu.name", wksp_cnt ) );
  if( FD_UNLIKELY( loose_sz ) ) {
    FD_TEST( fd_pod_insertf_ulong( pod, loose_sz, "wksp.%lu.loose_sz", wksp_cnt ) );
  }
  FD_TEST( fd_pod_replacef_ulong( pod, wksp_cnt+1UL, "wksp_cnt" ) );
}

void
fd_topo_builder_add_links( uchar *      pod,
                           ulong        cnt,
                           char const * wksp_name,
                           char const * link_name,
                           ulong        depth,
                           int          reasm,
                           ulong        mtu,
                           ulong        burst ) {
  ulong link_cnt = fd_pod_query_ulong( pod, "link_cnt", 0UL );
  for( ulong i=0UL; i<cnt; i++ ) {
    char link_id[ 20 ];
    FD_TEST( fd_cstr_printf_check( link_id, sizeof( link_id ), NULL, "link.%lu", link_cnt+i ) );

    FD_TEST( fd_pod_insertf_cstr( pod, wksp_name, "link.%lu.wksp", link_cnt+i ) );
    FD_TEST( fd_pod_insertf_cstr( pod, link_name, "link.%lu.name", link_cnt+i ) );
    FD_TEST( fd_pod_insertf_ulong( pod, i, "link.%lu.lidx", link_cnt+i ) );
    FD_TEST( fd_pod_insertf_ulong( pod, depth, "link.%lu.depth", link_cnt+i ) );
    if( FD_UNLIKELY( reasm ) ) {
      FD_TEST( fd_pod_insertf_int( pod, 1, "link.%lu.reasm", link_cnt+i ) );
    } else {
      FD_TEST( fd_pod_insertf_ulong( pod, mtu, "link.%lu.mtu", link_cnt+i ) );
    }
    FD_TEST( fd_pod_insertf_ulong( pod, burst, "link.%lu.burst", link_cnt+i ) );

    ulong wksp_contains_cnt = fd_pod_queryf_ulong( pod, 0UL, "wksp.%s.contains_cnt", wksp_name );
    FD_TEST( fd_pod_insertf_cstr( pod, link_id, "wksp.%s.contains.%lu.id", wksp_name, wksp_contains_cnt ) );
    FD_TEST( fd_pod_replacef_ulong( pod, wksp_contains_cnt+1UL, "wksp.%s.contains_cnt", wksp_name ) );
  }
  FD_TEST( fd_pod_replacef_ulong( pod, link_cnt+cnt, "link_cnt" ) );
}

void
fd_topo_builder_add_tiles( uchar *        pod,
                           ulong          cnt,
                           char const *   wksp_name,
                           char const *   tile_name,
                           char const *   primary_out_name,
                           ulong          primary_out_index,
                           int            is_solana_labs,
                           ushort const * cpu_idx ) {
  ulong tile_cnt = fd_pod_query_ulong( pod, "tile_cnt", 0UL );
  for( ulong i=0UL; i<cnt; i++ ) {
    char tile_id[ 20 ];
    FD_TEST( fd_cstr_printf_check( tile_id, sizeof( tile_id ), NULL, "tile.%lu", tile_cnt+i ) );

    FD_TEST( fd_pod_insertf_cstr( pod, wksp_name, "tile.%lu.wksp", tile_cnt+i ) );
    FD_TEST( fd_pod_insertf_cstr( pod, tile_name, "tile.%lu.name", tile_cnt+i ) );
    FD_TEST( fd_pod_insertf_ulong( pod, i, "tile.%lu.tidx", tile_cnt+i ) );
    FD_TEST( fd_pod_insertf_ulong( pod, cpu_idx[ tile_cnt+i ], "tile.%lu.cpu_idx", tile_cnt+i ) );
    FD_TEST( fd_pod_insertf_int( pod, is_solana_labs, "tile.%lu.solana_labs", tile_cnt+i ) );
    FD_TEST( fd_pod_insertf_cstr( pod, primary_out_name, "tile.%lu.primary_out_link", tile_cnt+i ) );
    FD_TEST( fd_pod_insertf_ulong( pod, primary_out_index==ULONG_MAX?i:primary_out_index, "tile.%lu.primary_out_lidx", tile_cnt+i ) );

    ulong wksp_contains_cnt = fd_pod_queryf_ulong( pod, 0UL, "wksp.%s.contains_cnt", wksp_name );
    FD_TEST( fd_pod_insertf_cstr( pod, tile_id, "wksp.%s.contains.%lu.id", wksp_name, wksp_contains_cnt ) );
    FD_TEST( fd_pod_replacef_ulong( pod, wksp_contains_cnt+1UL, "wksp.%s.contains_cnt", wksp_name ) );
  }
  FD_TEST( fd_pod_replacef_ulong( pod, tile_cnt+cnt, "tile_cnt" ) );
}

void
fd_topo_builder_add_tile_ins( uchar *      pod,
                              ulong        cnt,
                              char const * wksp_name,
                              char const * tile_name,
                              ulong        tile_index,
                              char const * link_name,
                              ulong        link_index,
                              int          reliable,
                              int          polled ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    ulong tile_tidx = tile_index==ULONG_MAX?i:tile_index;
    ulong tile_idx = ULONG_MAX;
    for( ulong i=0UL; i<fd_pod_query_ulong( pod, "tile_cnt", 0UL ); i++ ) {
      if( !strcmp( fd_pod_queryf_cstr( pod, "", "tile.%lu.name", i ), tile_name ) && fd_pod_queryf_ulong( pod, ULONG_MAX, "tile.%lu.tidx", i ) == tile_tidx ) {
        tile_idx = i;
        break;
      }
    }
    FD_TEST( tile_idx!=ULONG_MAX );

    ulong in_cnt = fd_pod_queryf_ulong( pod, 0UL, "tile.%lu.in_cnt", tile_idx );
    
    char in_id[ 20 ];
    FD_TEST( fd_cstr_printf_check( in_id, sizeof( in_id ), NULL, "tile.%lu.in.%lu", tile_idx, in_cnt ) );

    FD_TEST( fd_pod_insertf_cstr( pod, link_name, "tile.%lu.in.%lu.link", tile_idx, in_cnt ) );
    ulong link_lidx = link_index==ULONG_MAX?i:link_index;
    FD_TEST( fd_pod_insertf_ulong( pod, link_lidx, "tile.%lu.in.%lu.lidx", tile_idx, in_cnt ) );
    FD_TEST( fd_pod_insertf_int( pod, reliable, "tile.%lu.in.%lu.reliable", tile_idx, in_cnt ) );
    FD_TEST( fd_pod_insertf_int( pod, polled, "tile.%lu.in.%lu.polled", tile_idx, in_cnt ) );

    ulong wksp_contains_cnt = fd_pod_queryf_ulong( pod, 0UL, "wksp.%s.contains_cnt", wksp_name );
    FD_TEST( fd_pod_insertf_cstr( pod, in_id, "wksp.%s.contains.%lu.id", wksp_name, wksp_contains_cnt ) );
    FD_TEST( fd_pod_replacef_ulong( pod, wksp_contains_cnt+1UL, "wksp.%s.contains_cnt", wksp_name ) );

    FD_TEST( fd_pod_replacef_ulong( pod, in_cnt+1UL, "tile.%lu.in_cnt", tile_idx ) );
  }
}

void
fd_topo_builder_add_tile_outs( uchar *      pod,
                               ulong        cnt,
                               char const * tile_name,
                               ulong        tile_index,
                               char const * link_name,
                               ulong        link_index ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    ulong tile_tidx = tile_index==ULONG_MAX?i:tile_index;
    ulong tile_idx = ULONG_MAX;
    for( ulong i=0UL; i<fd_pod_query_ulong( pod, "tile_cnt", 0UL ); i++ ) {
      if( !strcmp( fd_pod_queryf_cstr( pod, "", "tile.%lu.name", i ), tile_name ) && fd_pod_queryf_ulong( pod, ULONG_MAX, "tile.%lu.tidx", i ) == tile_tidx ) {
        tile_idx = i;
        break;
      }
    }
    FD_TEST( tile_idx!=ULONG_MAX );

    ulong out_cnt = fd_pod_queryf_ulong( pod, 0UL, "tile.%lu.out_cnt", tile_idx );

    FD_TEST( fd_pod_insertf_cstr( pod, link_name, "tile.%lu.out.%lu.link", tile_idx, out_cnt ) );
    ulong link_lidx = link_index==ULONG_MAX?i:link_index;
    FD_TEST( fd_pod_insertf_ulong( pod, link_lidx, "tile.%lu.out.%lu.lidx", tile_idx, out_cnt ) );

    FD_TEST( fd_pod_replacef_ulong( pod, out_cnt+1UL, "tile.%lu.out_cnt", tile_idx ) );
  }
}
