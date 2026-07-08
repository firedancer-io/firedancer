#ifndef HEADER_fd_src_waltz_slow_fd_slow_inflight_h
#define HEADER_fd_src_waltz_slow_fd_slow_inflight_h

/* fd_slow_inflight.h tracks in-flight frames.  */

#include "fd_slow_base.h"
#include "../../util/bits/fd_bits.h"
#include "../../util/log/fd_log.h"

/* fd_slow_inflight_t represents a single inflight frame.
   This object is created when preparing a new frame to transmit, and
   dies when the frame is acknowledged or considered lost. */

#define FD_SLOW_INFLIGHT_TYPE_NULL             0 /* not used */
#define FD_SLOW_INFLIGHT_TYPE_CRYPTO           1 /* handshake data */
#define FD_SLOW_INFLIGHT_TYPE_HS_DONE          2 /* handshake done */
#define FD_SLOW_INFLIGHT_TYPE_STREAM           3 /* stream data */
#define FD_SLOW_INFLIGHT_TYPE_RST_STREAM       4 /* reset stream */
#define FD_SLOW_INFLIGHT_TYPE_CONN_QUOTA       5 /* quota: max streams, max data */
#define FD_SLOW_INFLIGHT_TYPE_MAX_STREAM_DATA  6 /* quota: max stream data */
#define FD_SLOW_INFLIGHT_TYPE_PING             7 /* ping frame */

struct fd_slow_inflight {

  ulong pktnum : 60;
  ulong type   :  4;
  long  loss_timeout;

  union {

    /* Packet contained a CRYPTO frame */
    struct {
      uint off;
      uint sz;
    } crypto;

    /* Packet contained a STREAM frame */
    struct {
      ulong stream_id;
      uint  off;
      uint  sz : 15;
      uint  fin : 1;
    } stream;

    /* Packet contained a RESET_STREAM frame */
    struct {
      ulong stream_id;
    } rst_stream;

    /* Packet contained a MAX_STREAM_DATA frame */
    struct {
      ulong stream_id;
    } max_stream_data;

  };

};

typedef struct fd_slow_inflight fd_slow_inflight_t;

/* fd_slow_inflight_page_t holds a bunch of in-flight frames on the same
   connection.

   QUIC ACKs usually confirm packets in bulk.  Cache-friendly iteration
   over frames is achieved by reducing the number of linked list hops. */

#define FD_SLOW_INFLIGHT_PAGE_ELE_CNT 31

struct __attribute__((aligned(16))) fd_slow_inflight_page {
  uint  prev;
  uint  next;
  ulong pktnum_base;
  uint  pktnum_range; /* base+range gives the highest pktnum*/
  uint  live_set;

  fd_slow_inflight_t ele[ FD_SLOW_INFLIGHT_PAGE_ELE_CNT ];
};

typedef struct fd_slow_inflight_page fd_slow_inflight_page_t;

FD_STATIC_ASSERT( sizeof(fd_slow_inflight_page_t)==1024UL, fengshui );

#define DLIST_NAME  fd_slow_inflight_list
#define DLIST_ELE_T fd_slow_inflight_page_t
#define DLIST_IDX_T uint
#include "../../util/tmpl/fd_dlist.c"

#define POOL_NAME  fd_slow_inflight_pool
#define POOL_T     fd_slow_inflight_page_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

/* fd_slow_inflight_insert adds a new frame to the inflight tracker.
   Invariant: the pktnum of each call is >= the previous.

   FIXME consider API to bulk-add frames */

fd_slow_inflight_t *
fd_slow_inflight_insert( fd_slow_inflight_list_t * list,
                         fd_slow_inflight_page_t * pool,
                         ulong                     pktnum,
                         uint                      type );

/* fd_slow_inflight_remove removes all packet numbers in range
   [pktnum0,pktnum1) from the inflight tracker. */

void
fd_slow_inflight_remove( fd_slow_inflight_list_t * list,
                         fd_slow_inflight_page_t * pool,
                         ulong                     pktnum0,
                         ulong                     pktnum1 );

void
fd_slow_inflight_remove_all( fd_slow_inflight_list_t * list,
                             fd_slow_inflight_page_t * pool );

/* fd_slow_inflight_verify does runtime integrity checks of the inflight
   tracker. */

void
fd_slow_inflight_verify( fd_slow_inflight_list_t * list,
                         fd_slow_inflight_page_t * pool );

/* fd_slow_inflight_next_timeout returns the timestamp at which the next
   loss timeout event occurs.  Returns -1 if no timeout is pending. */

FD_FN_PURE static inline long
fd_slow_inflight_next_timeout( fd_slow_inflight_list_t const * list,
                               fd_slow_inflight_page_t const * pool ) {

  if( fd_slow_inflight_list_is_empty( list, pool ) ) return -1L;

  fd_slow_inflight_page_t const * head =
      fd_slow_inflight_list_ele_peek_head_const( list, pool );
  FD_CHECK_CRIT( head->live_set, "invariant violation: inflight page has no elements" );

  int ele_idx = fd_ulong_find_lsb( head->live_set );
  FD_DCHECK_CRIT( ele_idx<FD_SLOW_INFLIGHT_PAGE_ELE_CNT, "inflight page bit set corrupt" );
  return pool->ele[ ele_idx ].loss_timeout;
}

/* Iterator API */

struct fd_slow_inflight_iter {
  fd_slow_inflight_page_t * pool;
  uint  page_idx;
  ulong frame_mask;
};

typedef struct fd_slow_inflight_iter fd_slow_inflight_iter_t;

FD_PROTOTYPES_BEGIN

static inline fd_slow_inflight_iter_t *
fd_slow_inflight_iter_init( fd_slow_inflight_iter_t * iter,
                            fd_slow_inflight_page_t * pool,
                            fd_slow_inflight_list_t * list ) {
  *iter = (fd_slow_inflight_iter_t) {
    .pool       = pool,
    .page_idx   = list->head,
    .frame_mask = ULONG_MAX
  };
  return
}

static inline fd_slow_inflight_t *
fd_slow_inflight_iter_ele( fd_slow_inflight_iter_t * iter ) {

}

static inline void
fd_slow_inflight_iter_seek( fd_slow_inflight_iter_t * iter,
                            ulong                     pktnum ) {

}

static inline int
fd_slow_inflight_iter_done( fd_slow_inflight_iter_t * iter ) {

}

static inline void
fd_slow_inflight_iter_next( fd_slow_inflight_iter_t * iter ) {

}

static inline void
fd_slow_inflight_iter_remove( fd_slow_inflight_iter_t * iter ) {

}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_slow_fd_slow_inflight_h */
