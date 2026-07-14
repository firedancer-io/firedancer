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

  fd_event_tl = r;
}
