#include "fd_event_report.h"

static FD_TL fd_event_reporter_t fd_event_tl_storage[1];
static FD_TL fd_event_reporter_t fd_event_internal_tl_storage[1];

static void
event_reporter_init( fd_event_reporter_t *  r,
                     fd_topo_t const *      topo,
                     fd_topo_link_t const * link ) {
  FD_TEST( link->mcache );
  FD_TEST( link->dcache );

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
}

void
fd_event_register( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_event_tl = NULL;

  if( FD_LIKELY( tile->event_link_id==ULONG_MAX ) ) return; /* no event link */

  event_reporter_init( fd_event_tl_storage, topo, &topo->links[ tile->event_link_id ] );
  fd_event_tl = fd_event_tl_storage;
}

void
fd_event_register_internal( fd_topo_t const *      topo,
                            fd_topo_tile_t const * tile ) {
  fd_event_internal_tl = NULL;

  if( FD_LIKELY( tile->event_internal_link_id==ULONG_MAX ) ) return; /* no internal link */

  event_reporter_init( fd_event_internal_tl_storage, topo, &topo->links[ tile->event_internal_link_id ] );
  fd_event_internal_tl = fd_event_internal_tl_storage;
}
