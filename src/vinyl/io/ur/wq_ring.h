#ifndef HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_wq_ring_h
#define HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_wq_ring_h

/* wq_ring.h provides a reorder buffer for write completions.  This is
   required because io_uring might post completions out-of-order. */

#include "../../bstream/fd_vinyl_bstream.h"

struct wq_desc {
  ulong seq;
  uint  sz;
  uint  done : 1;
};

typedef struct wq_desc wq_desc_t;

struct wq_ring {
  ulong wq0;
  ulong wq1;
  ulong seq;
  ulong max;
  __extension__ wq_desc_t ring[0];
};

typedef struct wq_ring wq_ring_t;

FD_PROTOTYPES_BEGIN

static inline wq_ring_t *
wq_ring_init( wq_ring_t * ring,
              ulong       seq,
              ulong       max ) {
  if( FD_UNLIKELY( !fd_ulong_is_pow2( max ) ) ) {
    FD_LOG_CRIT(( "max (%lu) is not a power of 2", max ));
  }
  *ring = (wq_ring_t) {
    .wq0 = 0UL,
    .wq1 = 0UL,
    .seq = seq,
    .max = max
  };
  return ring;
}

static inline long
wq_ring_free_cnt( wq_ring_t const * ring ) {
  return (long)( ring->max - (ring->wq1 - ring->wq0) );
}

static inline int
wq_ring_is_full( wq_ring_t const * ring ) {
  return (ring->wq1 - ring->wq0) >= ring->max;
}

FD_FN_PURE static inline wq_desc_t *
wq_ring_desc( wq_ring_t * ring,
              ulong       wq ) {
  ulong mask = ring->max-1UL;
  return &ring->ring[ wq&mask ];
}

static inline ulong
wq_ring_enqueue( wq_ring_t * ring,
                 ulong       seq ) {
  FD_CRIT( !wq_ring_is_full( ring ), "wq_ring overflow" );
  ulong wq   = ring->wq1;
  ulong mask = ring->max-1UL;
  ring->ring[ wq&mask ] = (wq_desc_t){
    .seq  = seq,
    .sz   = 0U,
    .done = 0
  };
  ring->wq1 = wq+1UL;
  return wq;
}

FD_FN_UNUSED static ulong
wq_ring_complete( wq_ring_t * ring,
                  ulong       wq ) {
  FD_CRIT( fd_vinyl_seq_gt( ring->wq1, ring->wq0 ), "stray wq_ring completion" );
  ulong mask = ring->max-1UL;
  FD_CRIT( !ring->ring[ wq&mask ].done, "wq_ring entry already completed" );
  ring->ring[ wq&mask ].done = 1;
  ulong seq = ring->seq;
  while( fd_vinyl_seq_gt( ring->wq1, ring->wq0 ) ) {
    wq_desc_t const * desc = &ring->ring[ ring->wq0&mask ];
    if( !desc->done ) break;
    seq = desc->seq;
    ring->wq0++;
  }
  ring->seq = seq;
  return seq;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_wq_ring_h */
