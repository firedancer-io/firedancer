#ifndef HEADER_fd_src_disco_net_fd_net_tile_h
#define HEADER_fd_src_disco_net_fd_net_tile_h

/* fd_net_tile.h contains APIs for providing XDP networking to a
   Firedancer topology using the 'net' tile. */

#include "../fd_disco_base.h"
#include "../../tango/dcache/fd_dcache.h"

struct fd_topo;
typedef struct fd_topo fd_topo_t;

/* Helpers for consumers of net tile RX packets */

struct fd_net_rx_bounds {
  ulong base;       /* base address of wksp containing dcache */
  ulong pkt_lo;     /* lowest permitted pointer to packet payload */
  ulong pkt_wmark;  /* highest " */
};

typedef struct fd_net_rx_bounds fd_net_rx_bounds_t;

FD_PROTOTYPES_BEGIN

/* fd_net_rx_bounds_init initializes a bounds checker for RX packets
   produced by the net tile.  dcache is a local join to a dcache that
   will carry packet payloads. */

FD_FN_UNUSED static void
fd_net_rx_bounds_init( fd_net_rx_bounds_t * bounds,
                       void *               dcache ) {
  bounds->base      = (ulong)fd_wksp_containing( dcache );
  bounds->pkt_lo    = (ulong)dcache;
  bounds->pkt_wmark = bounds->pkt_lo + fd_dcache_data_sz( dcache ) - FD_NET_MTU;
  if( FD_UNLIKELY( !bounds->base ) ) FD_LOG_ERR(( "Failed to find wksp containing dcache" ));
}

/* fd_net_rx_translate_frag helps net tile consumers locate packet
   paylads.  bounds is a net_rx_bounds object for the net tile that the
   frag was received from.  chunk, ctl, sz are frag_meta parameters.

   Returns a pointer in the local address space to the first byte of an
   incoming packet.  Terminates the application if the given {chunk,ctl}
   params would produce an out of bounds buffer. */

FD_FN_UNUSED static void const *
fd_net_rx_translate_frag( fd_net_rx_bounds_t const * bounds,
                          ulong                      chunk,
                          ulong                      ctl,
                          ulong                      sz ) {
  ulong p = ((ulong)bounds->base + (chunk<<FD_CHUNK_LG_SZ) + ctl);
  if( FD_UNLIKELY( !( (p  >= bounds->pkt_lo   ) &
                      (p  <= bounds->pkt_wmark) &
                      (sz <= FD_NET_MTU       ) ) ) ) {
    FD_LOG_ERR(( "frag %p (chunk=%lu ctl=%lu sz=%lu) is not in bounds [%p:%p]",
                 (void *)p, chunk, ctl, sz,
                 (void *)bounds->pkt_lo, (void *)bounds->pkt_wmark ));
  }
  return (void const *)p;
}

FD_PROTOTYPES_END

/* Topology APIs */

FD_PROTOTYPES_BEGIN

/* fd_topos_net_tiles appends the net and netlnk tiles to the
   topology.  These tiles provide fast XDP networking. */

/* FIXME layering violation */
struct fd_config_net;
typedef struct fd_config_net fd_config_net_t;

void
fd_topos_net_tiles( fd_topo_t *             topo,
                    ulong                   net_tile_cnt,
                    fd_config_net_t const * net_config,
                    ulong                   netlnk_max_routes,
                    ulong                   netlnk_max_neighbors,
                    ulong const             tile_to_cpu[ FD_TILE_MAX ] );

/* fd_topos_net_rx_link is like fd_topob_link, but for net->app tile
   packet RX links. */

void
fd_topos_net_rx_link( fd_topo_t *  topo,
                      char const * link_name,
                      ulong        net_kind_id,
                      ulong        depth );

/* fd_topob_tile_in_net registers a net TX link with all net tiles. */

void
fd_topos_tile_in_net( fd_topo_t *  topo,
                      char const * fseq_wksp,
                      char const * link_name,
                      ulong        link_kind_id,
                      int          reliable,
                      int          polled );

/* This should be called *after* all app<->net tile links have been
   created.  Should be called once per net tile. */

void
fd_topos_net_tile_finish( fd_topo_t * topo,
                          ulong       net_kind_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_tile_h */
