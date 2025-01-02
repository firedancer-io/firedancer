#ifndef HEADER_fd_src_disco_events_generated_fd_event_metrics_h
#define HEADER_fd_src_disco_events_generated_fd_event_metrics_h

#include "fd_event.h"
#include "../../metrics/fd_metrics.h"

#include "../../topo/fd_topo.h"

ulong
fd_event_metrics_footprint( fd_topo_t const * topo ) {
  ulong l = FD_LAYOUT_INIT;  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_t ),      sizeof( fd_event_metrics_sample_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_tile_t ), topo->tile_cnt*sizeof( fd_event_metrics_sample_tile_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_link_t ), fd_topo_polled_in_cnt( topo )*sizeof( fd_event_metrics_sample_link_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_tile_t ), fd_topo_tile_name_cnt( topo, "tile" )*sizeof( fd_event_metrics_sample_tile_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_net_t ), fd_topo_tile_name_cnt( topo, "net" )*sizeof( fd_event_metrics_sample_net_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_quic_t ), fd_topo_tile_name_cnt( topo, "quic" )*sizeof( fd_event_metrics_sample_quic_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_verify_t ), fd_topo_tile_name_cnt( topo, "verify" )*sizeof( fd_event_metrics_sample_verify_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_dedup_t ), fd_topo_tile_name_cnt( topo, "dedup" )*sizeof( fd_event_metrics_sample_dedup_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_resolv_t ), fd_topo_tile_name_cnt( topo, "resolv" )*sizeof( fd_event_metrics_sample_resolv_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_pack_t ), fd_topo_tile_name_cnt( topo, "pack" )*sizeof( fd_event_metrics_sample_pack_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_bank_t ), fd_topo_tile_name_cnt( topo, "bank" )*sizeof( fd_event_metrics_sample_bank_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_shred_t ), fd_topo_tile_name_cnt( topo, "shred" )*sizeof( fd_event_metrics_sample_shred_t ) );
  l = FD_LAYOUT_APPEND( l, alignof( fd_event_metrics_sample_store_t ), fd_topo_tile_name_cnt( topo, "store" )*sizeof( fd_event_metrics_sample_store_t ) );
  return l;
}

void
fd_event_metrics_layout( fd_topo_t const * topo,
                         uchar *           buffer ) {
  ulong off = 0UL;

  fd_event_metrics_sample_t * metrics = (fd_event_metrics_sample_t *)(buffer+off);
  off += sizeof( fd_event_metrics_sample_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_tile_t ) );
  metrics->tile_off = off;
  metrics->tile_len = fd_topo_tile_name_cnt( topo, "tile" );
  off += fd_topo_tile_name_cnt( topo, "tile" )*sizeof( fd_event_metrics_sample_tile_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_link_t ) );
  metrics->link_off = off;
  metrics->link_len = fd_topo_polled_in_cnt( topo );
  off += fd_topo_polled_in_cnt( topo )*sizeof( fd_event_metrics_sample_link_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_net_t ) );
  metrics->net_off = off;
  metrics->net_len = fd_topo_tile_name_cnt( topo, "net" );
  off += fd_topo_tile_name_cnt( topo, "net" )*sizeof( fd_event_metrics_sample_net_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_quic_t ) );
  metrics->quic_off = off;
  metrics->quic_len = fd_topo_tile_name_cnt( topo, "quic" );
  off += fd_topo_tile_name_cnt( topo, "quic" )*sizeof( fd_event_metrics_sample_quic_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_verify_t ) );
  metrics->verify_off = off;
  metrics->verify_len = fd_topo_tile_name_cnt( topo, "verify" );
  off += fd_topo_tile_name_cnt( topo, "verify" )*sizeof( fd_event_metrics_sample_verify_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_dedup_t ) );
  metrics->dedup_off = off;
  metrics->dedup_len = fd_topo_tile_name_cnt( topo, "dedup" );
  off += fd_topo_tile_name_cnt( topo, "dedup" )*sizeof( fd_event_metrics_sample_dedup_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_resolv_t ) );
  metrics->resolv_off = off;
  metrics->resolv_len = fd_topo_tile_name_cnt( topo, "resolv" );
  off += fd_topo_tile_name_cnt( topo, "resolv" )*sizeof( fd_event_metrics_sample_resolv_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_pack_t ) );
  metrics->pack_off = off;
  metrics->pack_len = fd_topo_tile_name_cnt( topo, "pack" );
  off += fd_topo_tile_name_cnt( topo, "pack" )*sizeof( fd_event_metrics_sample_pack_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_bank_t ) );
  metrics->bank_off = off;
  metrics->bank_len = fd_topo_tile_name_cnt( topo, "bank" );
  off += fd_topo_tile_name_cnt( topo, "bank" )*sizeof( fd_event_metrics_sample_bank_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_shred_t ) );
  metrics->shred_off = off;
  metrics->shred_len = fd_topo_tile_name_cnt( topo, "shred" );
  off += fd_topo_tile_name_cnt( topo, "shred" )*sizeof( fd_event_metrics_sample_shred_t );

  off = fd_ulong_align_up( off, alignof( fd_event_metrics_sample_store_t ) );
  metrics->store_off = off;
  metrics->store_len = fd_topo_tile_name_cnt( topo, "store" );
  off += fd_topo_tile_name_cnt( topo, "store" )*sizeof( fd_event_metrics_sample_store_t );

  ulong link_idx = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_event_metrics_sample_tile_t * tile = (fd_event_metrics_sample_tile_t *)(buffer+((fd_event_metrics_sample_t*)buffer)->tile_off)+i;
    strncpy( tile->kind, topo->tiles[ i ].name, sizeof( tile->kind ) );
    tile->kind_id = (ushort)topo->tiles[ i ].kind_id;

    for( ulong j=0UL; j<topo->tiles[ i ].in_cnt; j++ ) {
      if( FD_UNLIKELY( !topo->tiles[ i ].in_link_poll[ j ] ) ) continue;
      fd_event_metrics_sample_link_t * link = (fd_event_metrics_sample_link_t *)(buffer+((fd_event_metrics_sample_t*)buffer)->link_off)+link_idx;
      strncpy( link->kind, topo->tiles[ i ].name, sizeof( link->kind ) );
      link->kind_id = (ushort)topo->tiles[ i ].kind_id;
      strncpy( link->link_kind, topo->links[ topo->tiles[ i ].in_link_id[ j ] ].name, sizeof( link->link_kind ) );
      link->link_kind_id = (ushort)topo->links[ topo->tiles[ i ].in_link_id[ j ] ].kind_id;
      link_idx++;
    }
  }
}

#endif /* HEADER_fd_src_disco_events_generated_fd_event_metrics_h */
