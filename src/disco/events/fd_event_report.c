#include "fd_event_report.h"

static FD_TL fd_event_reporter_t fd_event_tl_storage[1];

void
fd_event_register( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_event_tl = NULL;

  if( FD_LIKELY( tile->event_link_id==ULONG_MAX ) ) return; /* no event link */

  fd_topo_link_t const * link = &topo->links[ tile->event_link_id ];
  FD_TEST( link->mcache );
  FD_TEST( link->dcache );

  fd_event_reporter_t * r = fd_event_tl_storage;
  r->mcache = link->mcache;
  r->depth  = fd_mcache_depth( link->mcache );
  r->seq    = 0UL;
  r->seq_store = fd_mcache_seq_laddr( link->mcache );
  r->mem    = fd_wksp_containing( link->dcache );
  FD_TEST( r->mem );
  r->chunk0 = fd_dcache_compact_chunk0( r->mem, link->dcache );
  r->wmark  = fd_dcache_compact_wmark ( r->mem, link->dcache, link->mtu );
  r->chunk  = r->chunk0;
  r->mtu    = link->mtu;

  r->sleep    = NULL;
  r->link_id  = link->id;
  r->wake_cnt = 0UL;
  if( FD_UNLIKELY( topo->sleep_obj_id!=ULONG_MAX ) ) {
    r->sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
    FD_TEST( r->sleep );
    r->wake_cnt = fd_sleep_wake_table( r->wake, topo, link->id );
  }

  r->cons_fseq = NULL;
  ulong event_tile_idx = fd_topo_find_tile( topo, "event", 0UL );
  if( FD_LIKELY( event_tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * event_tile = &topo->tiles[ event_tile_idx ];
    for( ulong j=0UL; j<event_tile->in_cnt; j++ ) {
      if( event_tile->in_link_id[ j ]!=link->id ) continue;
      void * fseq = fd_topo_obj_laddr( topo, event_tile->in_link_fseq_obj_id[ j ] );
      if( FD_LIKELY( fseq ) ) r->cons_fseq = fd_fseq_join( fseq );
      break;
    }
  }

  fd_event_tl = r;
}
