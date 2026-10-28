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
   Events larger than FD_EVENT_FRAG_MTU are split into SOM..EOM frags; the
   event tile reassembles them and drops events with a missing frag.
   When a tile has no event link (telemetry off / max_event_sz==0),
   fd_event_tl is NULL and reporting is a no-op. */

#include "../topo/fd_topo.h"
#include "../sleep/fd_sleep.h"
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
  ulong            mtu;     /* link mtu (frag size, <= FD_EVENT_FRAG_MTU) */
  ulong            max_sz;  /* max_event_sz */
  ulong            ev_seq;  /* next event number, low 32 bits in tsorig */

  fd_sleep_t *     sleep;
  ulong            link_id;
  fd_sleep_wake_t  wake[ FD_SLEEP_BITS_CNT ];
  ulong            wake_cnt;
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

/* fd_event_reporter_join sets up r to publish on topo link link_id,
   whose mcache/dcache the calling tile has joined.  Returns r. */

fd_event_reporter_t *
fd_event_reporter_join( fd_event_reporter_t * r,
                        fd_topo_t const *     topo,
                        ulong                 link_id );

#define FD_EVENT_FRAG_MTU (4096UL)

#define FD_EVENT_SIG( type, sz ) ( ((ulong)(sz)<<8) | ((ulong)(type)&0xFFUL) )
#define FD_EVENT_SIG_TYPE( sig ) ( (ulong)(sig)&0xFFUL )
#define FD_EVENT_SIG_SZ( sig )   ( (ulong)(sig)>>8 )

struct fd_event_report_iov {
  void const * base;
  ulong        sz;
};

typedef struct fd_event_report_iov fd_event_report_iov_t;

/* fd_event_report_gather_ publishes one event, the concatenation of
   iov, to the event link.  type is the event schema id, carried with the
   total byte size in every frag's sig (see FD_EVENT_SIG) so the event tile
   can dispatch and size-validate.  The event is split into frags of at
   most mtu bytes flagged SOM/EOM in ctl; tsorig carries the low 32 bits of
   the per-link event number.  No-op when fd_event_tl is NULL. */

static inline void
fd_event_report_ring_( fd_event_reporter_t * r ) {
  if( FD_LIKELY( !r->sleep ) ) return;
  __atomic_store_n( &r->sleep->seq_mirror[ r->link_id ], r->seq, __ATOMIC_RELEASE );
  fd_sleep_wake_check( r->sleep, r->wake, r->wake_cnt );
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
    FD_TEST( iov[ i ].sz<=r->max_sz-sz );
    sz += iov[ i ].sz;
  }

  ulong sig    = FD_EVENT_SIG( type, sz );
  ulong tsorig = (ulong)(uint)r->ev_seq;
  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  r->ev_seq++;

  ulong iov_idx = 0UL;
  ulong iov_off = 0UL;
  ulong left    = sz;
  int   som     = 1;
  do {
    ulong   frag_sz = fd_ulong_min( left, r->mtu );
    uchar * dst     = fd_chunk_to_laddr( r->mem, r->chunk );
    for( ulong n=0UL; n<frag_sz; ) {
      if( iov_off==iov[ iov_idx ].sz ) { iov_idx++; iov_off = 0UL; continue; }
      ulong k = fd_ulong_min( iov[ iov_idx ].sz-iov_off, frag_sz-n );
      fd_memcpy( dst+n, (uchar const *)iov[ iov_idx ].base+iov_off, k );
      n += k; iov_off += k;
    }
    left -= frag_sz;
    fd_mcache_publish( r->mcache, r->depth, r->seq, sig, r->chunk, frag_sz, fd_frag_meta_ctl( 0UL, som, !left, 0 ), tsorig, tspub );
    r->seq   = fd_seq_inc( r->seq, 1UL );
    r->chunk = fd_dcache_compact_next( r->chunk, frag_sz, r->chunk0, r->wmark );
    som      = 0;
  } while( left );
  fd_mcache_seq_update( r->seq_store, r->seq );
  fd_event_report_ring_( r );
}

static inline void
fd_event_report_( ulong        type,
                  void const * event,
                  ulong        sz ) {
  fd_event_report_iov_t iov[1] = {{ event, sz }};
  fd_event_report_gather_( type, iov, 1UL );
}

#define FD_EVENT_TYPE_METRICS_TRIGGER (255UL)

struct fd_event_metrics_trigger {
  uint  reason;
  ulong slot;
  ulong snapct_state;
};

typedef struct fd_event_metrics_trigger fd_event_metrics_trigger_t;

static inline void
fd_event_metrics_trigger( uint  reason,
                          ulong slot,
                          ulong snapct_state ) {
  fd_event_metrics_trigger_t t = { .reason = reason, .slot = slot, .snapct_state = snapct_state };
  fd_event_report_( FD_EVENT_TYPE_METRICS_TRIGGER, &t, sizeof(t) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_report_h */
