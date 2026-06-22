#ifndef HEADER_fd_src_waltz_slow_fd_slow_inflight_h
#define HEADER_fd_src_waltz_slow_fd_slow_inflight_h

/* fd_slow_inflight.h tracks in-flight reliable frames. */

#include "fd_slow_base.h"

#define FD_SLOW_INFLIGHT_PAGE_ELE_CNT (63UL)

#define FD_SLOW_INFLIGHT_TYPE_NULL             0 /* not used */
#define FD_SLOW_INFLIGHT_TYPE_HS_DATA          1 /* handshake data */
#define FD_SLOW_INFLIGHT_TYPE_HS_DONE          2 /* handshake done */
#define FD_SLOW_INFLIGHT_TYPE_STREAM           3 /* stream data */
#define FD_SLOW_INFLIGHT_TYPE_RST_STREAM       4 /* reset stream */
#define FD_SLOW_INFLIGHT_TYPE_CONN_QUOTA       5 /* quota: max streams, max data */
#define FD_SLOW_INFLIGHT_TYPE_MAX_STREAM_DATA  6 /* quota: max stream data */
#define FD_SLOW_INFLIGHT_TYPE_MAX_PING         7 /* ping frame */

struct fd_slow_inflight_frame {

};

typedef struct fd_slow_inflight_frame fd_slow_inflight_frame_t;

/* fd_slow_inflight_page_t holds a contiguous list of in-flight frames
   over the same connection.

   QUIC ACKs usually confirm packets in bulk.  Cache-friendly iteration
   over frames is achieved by reducing the number of linked list hops. */

struct fd_slow_inflight_page {
  uint prev;
  uint next;
};

typedef struct fd_slow_inflight_page fd_slow_inflight_page_t;

FD_PROTOTYPES_BEGIN



FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_slow_fd_slow_inflight_h */
