#include "fd_event_report.h"
#include "../../util/pod/fd_pod_format.h"

static FD_TL fd_event_reporter_t fd_event_tl_storage[1];

fd_event_reporter_t *
fd_event_reporter_join( fd_event_reporter_t * r,
                        fd_topo_t const *     topo,
                        ulong                 link_id ) {
  fd_topo_link_t const * link = &topo->links[ link_id ];
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
  r->max_sz = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "obj.%lu.event_max_sz", link->dcache_obj_id );
  r->ev_seq = 0UL;
  FD_TEST( r->max_sz!=ULONG_MAX && r->mtu && r->mtu<=FD_EVENT_FRAG_MTU );

  r->sleep    = NULL;
  r->link_id  = link->id;
  r->wake_cnt = 0UL;
  if( FD_UNLIKELY( topo->sleep_obj_id!=ULONG_MAX ) ) {
    r->sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
    FD_TEST( r->sleep );
    r->wake_cnt = fd_sleep_wake_table( r->wake, topo, link->id );
  }
  return r;
}

void
fd_event_register( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_event_tl = NULL;

  if( FD_LIKELY( tile->event_link_id==ULONG_MAX ) ) return; /* no event link */

  fd_event_tl = fd_event_reporter_join( fd_event_tl_storage, topo, tile->event_link_id );
}
