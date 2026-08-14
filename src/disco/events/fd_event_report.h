#ifndef HEADER_fd_src_disco_events_fd_event_report_h
#define HEADER_fd_src_disco_events_fd_event_report_h

/* fd_event_report.h provides a thread-local, fire-and-forget path for a
   tile to report a telemetry event to the event tile, mirroring how the
   metrics thread-local (fd_metrics_tl / FD_MCNT_*) works.

   A tile opts in by setting fd_topo_run_tile_t.max_event_sz; the topology
   then auto-wires a dedicated unreliable link from the tile to the event
   tile (see topology construction).  At tile boot, fd_event_register()
   sets up the thread-local reporter from that link.  Generated code emits
   one fd_event_report_<name>( msg ) macro per event schema (see
   generated/fd_event_gen.h) which forwards to fd_event_report_().

   The link is written directly via fd_mcache_publish (outside fd_stem); it
   is unreliable, so events are dropped if the event tile falls behind.
   When a tile has no event link (telemetry off / max_event_sz==0),
   fd_event_tl is NULL and reporting is a no-op. */

#include "../topo/fd_topo.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"

struct fd_event_reporter {
  fd_frag_meta_t * mcache;  /* mcache of the event link (joined) */
  ulong            depth;   /* mcache depth */
  ulong            seq;     /* next sequence number to publish */
  ulong *          seq_store; /* mcache header seq */

  fd_wksp_t *      mem;     /* workspace containing the dcache (chunk base) */
  ulong            chunk;   /* current write chunk */
  ulong            chunk0;  /* first chunk */
  ulong            wmark;   /* wrap watermark */
  ulong            mtu;     /* link mtu (== max_event_sz) */
};

typedef struct fd_event_reporter fd_event_reporter_t;

/* The thread-local reporter for the currently running tile, or NULL if the
   tile has no event link. */

extern FD_TL fd_event_reporter_t * fd_event_tl;

FD_PROTOTYPES_BEGIN

/* fd_event_register sets up fd_event_tl for the calling tile.  If the tile
   has an event link (tile->event_link_id != ULONG_MAX) it joins the link's
   mcache/dcache; otherwise fd_event_tl is left NULL and reporting is a
   no-op.  Must be called once, after the tile's tango objects are joined
   (i.e. after fd_topo_fill_tile), before the run loop. */

void
fd_event_register( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile );

#define FD_EVENT_SIG( type, sz ) ( ((ulong)(sz)<<8) | ((ulong)(type)&0xFFUL) )
#define FD_EVENT_SIG_TYPE( sig ) ( (ulong)(sig)&0xFFUL )
#define FD_EVENT_SIG_SZ( sig )   ( (ulong)(sig)>>8 )

struct fd_event_report_iov {
  void const * base;
  ulong        sz;
};

typedef struct fd_event_report_iov fd_event_report_iov_t;

/* fd_event_report_ publishes a single event of sz bytes (the serialized
   fd_event_<name>_t struct) to the event link.  type is the event schema
   id, carried with the byte size in the frag sig (see FD_EVENT_SIG) so the
   event tile can dispatch and size-validate; the frag sz field is too
   narrow for large events and is published as 0.  No-op when
   fd_event_tl is NULL.  The generated fd_event_report_<name>() helpers call
   this with the right type and size. */

static inline void
fd_event_report_( ulong        type,
                  void const * event,
                  ulong        sz ) {
  fd_event_reporter_t * r = fd_event_tl;
  if( FD_UNLIKELY( !r ) ) return; /* no event link / telemetry off */

  FD_TEST( type<=0xFFUL );
  FD_TEST( sz<=r->mtu );

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

  fd_memcpy( fd_chunk_to_laddr( r->mem, r->chunk ), event, sz );
  fd_mcache_publish( r->mcache, r->depth, r->seq, FD_EVENT_SIG( type, sz ), r->chunk, 0UL, 0UL, 0UL, tspub );
  r->seq   = fd_seq_inc( r->seq, 1UL );
  r->chunk = fd_dcache_compact_next( r->chunk, sz, r->chunk0, r->wmark );
  fd_mcache_seq_update( r->seq_store, r->seq );
}

static inline void
fd_event_report_gather_( ulong                         type,
                         fd_event_report_iov_t const * iov,
                         ulong                         iov_cnt ) {
  fd_event_reporter_t * r = fd_event_tl;
  if( FD_UNLIKELY( !r ) ) return; /* no event link / telemetry off */

  FD_TEST( type<=0xFFUL );
  ulong sz = 0UL;
  for( ulong i=0UL; i<iov_cnt; i++ ) {
    FD_TEST( iov[ i ].sz<=r->mtu-sz );
    sz += iov[ i ].sz;
  }

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

  uchar * dst = fd_chunk_to_laddr( r->mem, r->chunk );
  for( ulong i=0UL; i<iov_cnt; i++ ) {
    fd_memcpy( dst, iov[ i ].base, iov[ i ].sz );
    dst += iov[ i ].sz;
  }
  fd_mcache_publish( r->mcache, r->depth, r->seq, FD_EVENT_SIG( type, sz ), r->chunk, 0UL, 0UL, 0UL, tspub );
  r->seq   = fd_seq_inc( r->seq, 1UL );
  r->chunk = fd_dcache_compact_next( r->chunk, sz, r->chunk0, r->wmark );
  fd_mcache_seq_update( r->seq_store, r->seq );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_report_h */
