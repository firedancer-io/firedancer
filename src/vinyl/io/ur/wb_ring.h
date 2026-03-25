#ifndef HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_wb_ring_h
#define HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_wb_ring_h

/* wb_ring.h provides a ring buffer for append-only writes.  It is used
   to implement the write-back cache in vinyl_io_ur. */

#include "../../bstream/fd_vinyl_bstream.h"

/* wb_ring maps bstream seqs (logical) to byte offsets in a buffer
   (physical).  Logical addressing is abbreviated as 'seq', and physical
   as 'off'.  Operation is as follows:

   - Users allocate chunks out of a wb_ring.  Each allocation is
     contiguous in logical and physical space.  There are no gaps in
     logical space, but the wb_ring wraps around in physical space, to
     ensure chunks are contiguous.  Allocations implicitly free the
     oldest data.

   - Users may trim the most recent allocations.  Trimming may go out of
     bounds (prior to the oldest available byte), in which case the
     wb_ring gracefully becomes empty.

   - wb_ring allows fast translation of logical addresses to buffer
     offsets. */

struct wb_ring {
  ulong max;

  /* [seq0,seq1+sz1) is the logical range
     [off0,off0+sz0) is the physical range for the logical low range
     [off1,off1+sz1) is the physical range for the logical high range

     invariants:
     - sz0+sz1 <= max
     - seq1-seq0 == sz0
     - off1+sz1 == off0
     - off0+sz0 <= max
     - off1+sz1 <= max
     - [off0,off0+sz0) and [off1,off1+sz1) non-overlapping
     - if sz1==0, then sz0==0 */

  ulong seq0;
  ulong seq1;
  ulong off0;
  ulong off1;
  ulong sz0;
  ulong sz1;
};

typedef struct wb_ring wb_ring_t;

/* wb_ring_init initializes *ring.  seq is the logical address of the
   next append byte.  max is the capacity of the ring. */

static inline wb_ring_t *
wb_ring_init( wb_ring_t * ring,
              ulong       seq,
              ulong       max ) {
  if( FD_UNLIKELY( !max ) ) {
    FD_LOG_WARNING(( "zero max" ));
    return NULL;
  }
  *ring = (wb_ring_t) {
    .max  = max,
    .seq0 = seq,
    .seq1 = seq,
    .off0 = 0UL,
    .off1 = 0UL,
    .sz0  = 0UL,
    .sz1  = 0UL
  };
  return ring;
}

/* wb_ring_alloc appends sz bytes to wb_ring (evicting low bytes as
   necessary). */

static inline void
wb_ring_alloc( wb_ring_t * wb,
               ulong const r_sz ) {
  ulong       off0 = wb->off0;
  ulong       off1 = wb->off1;
  ulong       seq0 = wb->seq0;
  ulong       seq1 = wb->seq1;
  ulong       sz0  = wb->sz0;
  ulong       sz1  = wb->sz1;
  ulong const max  = wb->max;
  FD_CRIT( r_sz<=max, "request too large" );

  /* append to part1? */
  ulong r_off0 = wb->off1 + wb->sz1;
  ulong r_off1 = r_off0   + r_sz;
  if( FD_LIKELY( r_off1<=max ) ) {
    /* can extend part1, handle overlap with part0 */
    FD_CRIT( r_off1>=off0, "gap in middle" );
    ulong overlap = fd_ulong_min( r_off1 - off0, sz0 );
    wb->off0 = fd_ulong_max( off0+overlap, off1+sz1+r_sz );
    wb->seq0 = seq0 + overlap;
    wb->sz0  = sz0  - overlap;
    wb->sz1  = sz1  + r_sz;
    return;
  }

  /* need to wrap around.  move part1 to part0.  remove part1 */
  seq0  = seq1;
  seq1 += sz1;
  sz0   = sz1;
  off0  = off1;
  sz1   = 0UL;
  off1  = 0UL;

  /* left-extend part0 to offset 0 */
  seq0 -= off0;
  sz0  += off0;
  off0  = 0UL;

  /* allocate seq1 */
  if( r_sz>sz0 ) {
    /* destroy part0 if it would cause a gap in the middle, or
       completely overlap it */
    off0 = sz1;
    seq0 = seq1;
    sz0  = 0UL;
  } else {
    /* handle partial overlap of our new part1 with part0 */
    seq0 += r_sz;
    sz0  -= r_sz;
    off0 += r_sz;
    sz1  += r_sz;
  }

  wb->seq0 = seq0;
  wb->seq1 = seq1;
  wb->off0 = off0;
  wb->off1 = off1;
  wb->sz0  = sz0;
  wb->sz1  = sz1;
  /* off0 and off1 don't overlap check */
  FD_CRIT( ( off0>=off1+sz1 ) | ( off1>=off0+sz0 ), "wb_ring internal error" );
}

/* wb_ring_alloc_seq0 simulates an allocation of sz bytes.  Returns the
   logical address of the oldest available byte after the allocation is
   done.  (This method is useful to determine how much old data an
   allocation would evict.) */

FD_FN_PURE static inline ulong
wb_ring_alloc_seq0( wb_ring_t const * wb,
                    ulong const       sz ) {
  wb_ring_t shadow = *wb;
  wb_ring_alloc( &shadow, sz );
  return shadow.seq0;
}

/* wb_ring_trim removes most recently written bytes up to seq_hi.  This
   is useful for callers that over-allocate because they don't know the
   exact required chunk size at the time of allocation, e.g. when
   serializing.  But it is also useful to revert multiple allocations. */

static inline void
wb_ring_trim( wb_ring_t * wb,
              ulong       seq_hi ) {
  ulong seq0 = wb->seq0;
  ulong seq1 = wb->seq1;
  ulong off0 = wb->off0;
  ulong sz0  = wb->sz0;
  ulong sz1  = wb->sz1;

  if( FD_UNLIKELY( fd_vinyl_seq_le( seq_hi, seq0 ) ) ) {
    /* destroy both regions */
    wb->seq0 = seq_hi;
    wb->seq1 = seq_hi;
    wb->off0 = 0UL;
    wb->off1 = 0UL;
    wb->sz0  = 0UL;
    wb->sz1  = 0UL;
    return;
  }

  if( FD_UNLIKELY( fd_vinyl_seq_le( seq_hi, seq1 ) ) ) {
    /* destroy part1, extend part0, and swap */
    seq0 -= off0;
    sz0  += off0;
    off0  = 0UL;
    sz0   = seq_hi - seq0;
    wb->seq0 = seq0;
    wb->seq1 = seq0;
    wb->off0 = sz0;
    wb->off1 = off0;
    wb->sz0  = 0UL;
    wb->sz1  = sz0;
    return;
  }

  /* trim part1, extend part0 backwards (to avoid middle gap) */
  ulong trim = (seq1+sz1) - seq_hi;
  sz1  -= trim;
  off0 -= trim;
  seq0 -= trim;
  sz0  += trim;
  wb->seq0 = seq0;
  wb->sz0  = sz0;
  wb->sz1  = sz1;
  wb->off0 = off0;
  /* if part0 is empty, keep it at seq1 */
  if( sz0==trim ) {
    wb->seq0 = wb->seq1;
    wb->off0 = wb->off1 + wb->sz1;
    wb->sz0  = 0UL;
  }
}

/* wb_ring_seq_to_off returns the byte offset for the given seq.  May
   return out-of-bounds offsets for seq that are not in bounds. */

static inline ulong
wb_ring_seq_to_off( wb_ring_t const * wb,
                    ulong             seq ) {
  ulong const seq0 = wb->seq0;
  ulong const seq1 = wb->seq1;
  ulong const off0 = wb->off0;
  ulong const off1 = wb->off1;
  ulong const sz1  = wb->sz1;

  FD_CRIT( seq>=seq0,     "seq out of bounds" );
  FD_CRIT( seq< seq1+sz1, "seq out of bounds" );

  if( fd_vinyl_seq_lt( seq, seq1 ) ) {
    return off0 + ( seq-seq0 );
  } else {
    return off1 + ( seq-seq1 );
  }
}

/* [wb_ring_seq0,wb_ring_seq1) is the logical range tracked by a
   wb_ring. */

static inline ulong
wb_ring_seq0( wb_ring_t const * wb ) {
  return wb->seq0;
}

static inline ulong
wb_ring_seq1( wb_ring_t const * wb ) {
  return wb->seq1 + wb->sz1;
}

/* wb_ring_translate translates a seq range to a pair of physical
   ranges. */

struct wb_ring_span {
  ulong off0;
  ulong sz0;
  ulong off1;
  ulong sz1;
};

typedef struct wb_ring_span wb_ring_span_t;

static inline wb_ring_span_t
wb_ring_translate( wb_ring_t const * wb,
                   ulong             seq0,
                   ulong             sz ) {
  ulong const src_off0 = wb_ring_seq_to_off( wb, seq0 );
  if( FD_LIKELY( fd_vinyl_seq_ge( seq0, wb->seq1 ) ) ) {
    /* entire read is served by part1 of wb cache */
    FD_CRIT( src_off0+sz<=wb->max, "invariant violation" );
    return (wb_ring_span_t) { .off0=src_off0, .sz0=sz };
  } else {
    /* slow path */
    ulong lsz = fd_ulong_min( wb->seq1 - seq0, sz );
    FD_CRIT( lsz<=sz,      "invariant violation" );
    FD_CRIT( lsz<=wb->sz0, "invariant violation" );
    wb_ring_span_t span = { .off0 = src_off0, .sz0=lsz };
    if( lsz<sz ) {
      ulong src_off1 = wb_ring_seq_to_off( wb, seq0+lsz );
      FD_CRIT( (sz-lsz)<=wb->sz1, "invariant violation" );
      span.off1 = src_off1;
      span.sz1  = sz-lsz;
    }
    return span;
  }
}

#endif /* HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_wb_ring_h */
