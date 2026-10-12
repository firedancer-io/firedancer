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
  ulong            mtu;     /* link mtu (== max_event_sz) */

  fd_sleep_t *     sleep;
  ulong            link_id;
  fd_sleep_wake_t  wake[ FD_SLEEP_BITS_CNT ];
  ulong            wake_cnt;
};

typedef struct fd_event_reporter fd_event_reporter_t;

/* The thread-local reporter for the currently running tile, or NULL if the
   tile has no event link. */

extern FD_TL fd_event_reporter_t * fd_event_tl;

/* The thread-local reporter for the internal link, or NULL if the tile
   has none.  Internal records (see generated/fd_event_internal_gen.h)
   go to the one in-process consumer that asked for them rather than to
   the event tile, on a link of their own, so that their volume cannot
   evict telemetry. */

extern FD_TL fd_event_reporter_t * fd_event_internal_tl;

/* FD_EVENT_INTERNAL_MTU is the MTU of an internal link, and
   FD_EVENT_INTERNAL_FRAG_MAX the largest payload one frag of it
   carries: the frag descriptor's size field is 16 bits.

   FD_EVENT_INTERNAL_SZ_MAX bounds one logical record, and with it the
   reassembly buffer a consumer needs per link.  The largest record is a
   transaction that rewrote a single account of the maximum size. */

#define FD_EVENT_INTERNAL_MTU      (65536UL)
#define FD_EVENT_INTERNAL_FRAG_MAX (65472UL)
#define FD_EVENT_INTERNAL_SZ_MAX   (16UL<<20)

/* A consumer orders the account writes of one slot by a write version
   packed out of three fields of the records: the phase in the top 4
   bits, the write's position within its phase in the next 52, and the
   account's position within the record in the low 8
   (fd_geyser_core.c, geyser_write_version).  The producer holds the
   two positions to those widths, so that a slot far larger than any
   real one orders its last writes together rather than wrapping them
   in front of its first.

   FD_EVENT_INTERNAL_WRITE_INDEX_MAX is the largest position within a
   phase, and FD_EVENT_INTERNAL_WRITE_SUB_MAX the largest position
   within a record. */

#define FD_EVENT_INTERNAL_WRITE_INDEX_MAX (0xFFFFFFFFFFFFFUL) /* 2^52-1 */
#define FD_EVENT_INTERNAL_WRITE_SUB_MAX   (0xFFUL)            /* 2^8-1  */

FD_PROTOTYPES_BEGIN

/* fd_event_register sets up fd_event_tl for the calling tile.  If the tile
   has an event link (tile->event_link_id != ULONG_MAX) it joins the link's
   mcache/dcache; otherwise fd_event_tl is left NULL and reporting is a
   no-op.  Must be called once, after the tile's tango objects are joined
   (i.e. after fd_topo_fill_tile), before the run loop. */

void
fd_event_register( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile );

/* fd_event_register_internal is fd_event_register for the internal link
   (tile->event_internal_link_id), and is called in the same place. */

void
fd_event_register_internal( fd_topo_t const *      topo,
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
fd_event_report_ring_( fd_event_reporter_t * r ) {
  if( FD_LIKELY( !r->sleep ) ) return;
  __atomic_store_n( &r->sleep->seq_mirror[ r->link_id ], r->seq, __ATOMIC_RELEASE );
  fd_sleep_wake_check( r->sleep, r->wake, r->wake_cnt );
}

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
  fd_event_report_ring_( r );
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
  fd_event_report_ring_( r );
}

/* fd_event_internal_pad returns eight zero bytes, which the generated
   publish helpers use to pad an array region out to 8 bytes. */

FD_FN_CONST static inline void const *
fd_event_internal_pad( void ) {
  static uchar const pad[ 8 ] = {0};
  return pad;
}

/* fd_event_internal_arr_t describes one dynamic array of an internal
   record: where its entry count sits in the record's fixed prefix,
   where its base pointer sits in the record's parts view, and how big
   one entry is.  The generated code emits one table per schema. */

struct fd_event_internal_arr {
  ushort cnt_off;
  ushort ptr_off;
  ulong  elem_sz;
};

typedef struct fd_event_internal_arr fd_event_internal_arr_t;

/* fd_event_internal_iov_arrs appends arrs[0..arr_cnt) to iov, skipping
   the empty ones and padding each region out to 8 bytes so that the
   next one starts naturally aligned.  Returns the new iov count. */

static inline ulong
fd_event_internal_iov_arrs( void const *                    prefix,
                            void const *                    parts,
                            fd_event_internal_arr_t const * arrs,
                            ulong                           arr_cnt,
                            fd_event_report_iov_t *         iov,
                            ulong                           iov_cnt ) {
  for( ulong i=0UL; i<arr_cnt; i++ ) {
    ulong cnt = *(ulong const *)( (uchar const *)prefix + arrs[ i ].cnt_off );
    if( FD_UNLIKELY( !cnt ) ) continue;
    ulong sz  = cnt*arrs[ i ].elem_sz;
    ulong pad = fd_ulong_align_up( sz, 8UL )-sz;
    iov[ iov_cnt   ].base = *(void const * const *)( (uchar const *)parts + arrs[ i ].ptr_off );
    iov[ iov_cnt++ ].sz   = sz;
    if( FD_UNLIKELY( pad ) ) {
      iov[ iov_cnt   ].base = fd_event_internal_pad();
      iov[ iov_cnt++ ].sz   = pad;
    }
  }
  return iov_cnt;
}

/* fd_event_report_chunked_ publishes one logical record of
   iov[0..iov_cnt) bytes on the internal link as a run of consecutive
   frags: the first carries som and FD_EVENT_SIG( type, total_sz ), the
   last carries eom, and each carries its own byte count.  Every byte is
   copied once, into the dcache.

   There is no credit check: the link is unreliable, so a consumer that
   falls behind loses records (which it detects as a sequence gap) and
   never slows the producer down.  A record that does not fit the record
   size limit is dropped rather than reported, because a producer on the
   execution path must not fail.  No-op when the tile has no internal
   link. */

static inline void
fd_event_report_chunked_( ulong                         type,
                          fd_event_report_iov_t const * iov,
                          ulong                         iov_cnt ) {
  fd_event_reporter_t * r = fd_event_internal_tl;
  if( FD_LIKELY( !r ) ) return; /* no internal link */

  ulong total = 0UL;
  for( ulong i=0UL; i<iov_cnt; i++ ) total += iov[ i ].sz;
  if( FD_UNLIKELY( !total || total>FD_EVENT_INTERNAL_SZ_MAX ) ) return;

  ulong frag_max = fd_ulong_min( r->mtu, FD_EVENT_INTERNAL_FRAG_MAX );
  ulong tspub    = fd_frag_meta_ts_comp( fd_tickcount() );

  ulong iov_idx = 0UL; /* cursor into iov */
  ulong iov_off = 0UL;
  ulong rem     = total;
  int   som     = 1;

  while( rem ) {
    ulong   frag_sz = fd_ulong_min( rem, frag_max );
    uchar * dst     = fd_chunk_to_laddr( r->mem, r->chunk );

    for( ulong left=frag_sz; left; ) {
      while( iov_off>=iov[ iov_idx ].sz ) { iov_idx++; iov_off = 0UL; }
      ulong cpy = fd_ulong_min( iov[ iov_idx ].sz-iov_off, left );
      fd_memcpy( dst, (uchar const *)iov[ iov_idx ].base+iov_off, cpy );
      dst     += cpy;
      iov_off += cpy;
      left    -= cpy;
    }

    rem -= frag_sz;
    ulong ctl = fd_frag_meta_ctl( 0UL, som, !rem, 0 );
    fd_mcache_publish( r->mcache, r->depth, r->seq,
                       som ? FD_EVENT_SIG( type, total ) : 0UL,
                       r->chunk, frag_sz, ctl, 0UL, tspub );
    r->seq   = fd_seq_inc( r->seq, 1UL );
    r->chunk = fd_dcache_compact_next( r->chunk, frag_sz, r->chunk0, r->wmark );
    som      = 0;
  }

  fd_mcache_seq_update( r->seq_store, r->seq );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_report_h */
