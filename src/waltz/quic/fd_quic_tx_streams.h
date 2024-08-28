#ifndef HEADER_fd_src_waltz_quic_fd_quic_tx_stream_h
#define HEADER_fd_src_waltz_quic_fd_quic_tx_stream_h

/* fd_quic_tx_streams.h contains internal APIs for outgoing streams.

   Declares the outgoing stream descriptor, an object pool, and a query
   mechanism. */

#include "../../ballet/txn/fd_txn.h" /* we only use fd_quic_stream as a TPU client */
#include "fd_quic_common.h"
#include "../../util/fd_util.h"

/* Forward declarations */

typedef struct fd_quic_conn       fd_quic_conn_t;
typedef struct fd_quic_tx_stream  fd_quic_tx_stream_t;

/* fd_quic_tx_stream_t is an in-flight unidirectional outgoing stream.
   It sends up to FD_TXN_MTU data in a single packet.  Does not support
   streaming.  Practically only used for TPU/QUIC.  Local declaration
   friendly (fine to do `fd_quic_tx_stream stream[1];`)

   A tx_stream has 3 allocation states: FREE, SEND, and WAIT.
   - FREE streams are part of the fd_quic_tx_stream_pool_t dlist.
   - SEND streams are part of the fd_quic_conn_t->send_streams dlist.
   - WAIT streams are part of the fd_quic_conn_t->wait_streams dlist.

   A tx_stream is invariably member of a doubly linked list (see prev,
   next).  If SEND or WAIT, a tx_stream is also member of a treap keyed
   by stream_id. */

struct fd_quic_tx_stream {
  fd_quic_conn_t * conn;
  ulong            stream_id;

  /* last tx packet num with max_stream_data frame referring to this stream */
  ulong upd_pkt_number;

  /* If FREE, is part of a dlist of free streams
     If SEND, is part of a dlist of streams awaiting send
     If WAIT, is part of a dlist of streams awaiting acknowledgement */
  uint next;
  uint prev;

  /* Treap specific fields */
  uint balance; /* used to statistically balance treap */
  uint parent;
  uint left;
  uint right;

  /* Stream data.  Currently assumed to fit in one UDP datagram.
     Only valid for USED streams. */
  uchar  data[ FD_TXN_MTU ];
  ushort data_sz; /* <=FD_TXN_MTU */

  /* FIXME add deadline at which point send attempt is abandoned */
};

/* Define a doubly linked list to serve as an object pool free list */

#define DLIST_NAME       fd_quic_tx_stream_dlist
#define DLIST_ELE_T      fd_quic_tx_stream_t
#define DLIST_IDX_T      uint
#define DLIST_IMPL_STYLE 1
#include "../../util/tmpl/fd_dlist.c"

/* Define a treap/doubly linked list hybrid to serve queries by ID */

#define TREAP_NAME       fd_quic_tx_stream_treap
#define TREAP_T          fd_quic_tx_stream_t
#define TREAP_IDX_T      uint
#define TREAP_QUERY_T    ulong
#define TREAP_CMP(q,e)   (int)((long)(q) - ((long)((e)->stream_id)))
#define TREAP_LT(e0,e1)  ((e0)->stream_id < (e1)->stream_id)
#define TREAP_PRIO       balance
#define TREAP_IMPL_STYLE 1
#include "../../util/tmpl/fd_treap.c"

/* fd_quic_tx_stream_pool_t is an allocator pool for fd_quic_tx_stream_t
   objects.  fd_quic_tx_stream_pool_t must not be declared as-is.
   Instead create it using the constructor below. */

typedef fd_quic_tx_stream_dlist_t fd_quic_tx_stream_pool_t;

FD_PROTOTYPES_BEGIN

/* fd_quic_tx_stream_pool_{align,footprint,new,join,leave,delete}
   provides a constructor and destructor for fd_quic_tx_stream_pool_t. */

#define FD_QUIC_TX_STREAM_POOL_ALIGN (16UL)

FD_FN_CONST ulong
fd_quic_tx_stream_pool_align( void );

FD_FN_CONST ulong
fd_quic_tx_stream_pool_footprint( ulong stream_cnt );

void *
fd_quic_tx_stream_pool_new( void *     shmem,
                            ulong      stream_cnt,
                            fd_rng_t * rng );

fd_quic_tx_stream_dlist_t *
fd_quic_tx_stream_pool_join( void * mem );

void *
fd_quic_tx_stream_pool_leave( fd_quic_tx_stream_dlist_t * pool );

void *
fd_quic_tx_stream_pool_delete( void * mem );

/* Note: No constructor is provided for fd_quic_tx_stream_t because the
   object is always managed by a fd_quic_tx_stream_pool_t. */

static inline fd_quic_tx_stream_t *
fd_quic_tx_stream_pool( fd_quic_tx_stream_pool_t * pool ) {
  return (fd_quic_tx_stream_t *)( (ulong)pool + sizeof(fd_quic_tx_stream_dlist_t) );
}

/* fd_quic_tx_stream_alloc attempts to allocate a stream object.
   On success:
   - transitions stream from FREE to SEND
   - inserts to fd_quic_conn_t stream treap
   - copies stream data to stream object
   - returns newly created stream
   On failure (no free streams) returns NULL.

   Assumes data_sz<=FD_TXN_MTU.
   Assumes that stream_id is the largest outgoing undirectional stream
   ID ever allocated on this conn. */

fd_quic_tx_stream_t *
fd_quic_tx_stream_alloc( fd_quic_tx_stream_pool_t * pool,
                         fd_quic_conn_t *           conn,
                         ulong                      stream_id,
                         void const *               data,
                         ulong                      data_sz );

/* fd_quic_tx_stream_free transitions a stream from WAIT to FREE.
   Assumes that stream state is WAIT (CAUTION: different state than that
   after alloc). */

void
fd_quic_tx_stream_free( fd_quic_tx_stream_pool_t * pool,
                        fd_quic_tx_stream_t *      stream );

/* fd_quic_tx_stream_free_all transitions all streams currently owned
   by conn from USED to FREE, thereby returning them to the allocator
   pool. */

void
fd_quic_tx_stream_free_all( fd_quic_tx_stream_pool_t * pool,
                            fd_quic_conn_t *           conn );

/* fd_quic_tx_stream_query looks up a stream by ID. */

fd_quic_tx_stream_t *
fd_quic_tx_stream_query( fd_quic_tx_stream_pool_t * pool,
                         fd_quic_conn_t *           conn,
                         ulong                      stream_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_tx_stream_h */
