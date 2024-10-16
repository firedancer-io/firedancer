#include "fd_quic_tx_streams.h"
#include "fd_quic_conn.h"

/* Implementations of fd_quic_tx_streams.h collections */

#define DLIST_NAME       fd_quic_tx_stream_dlist
#define DLIST_ELE_T      fd_quic_tx_stream_t
#define DLIST_IMPL_STYLE 2
#include "../../util/tmpl/fd_dlist.c"

#define TREAP_NAME       fd_quic_tx_stream_treap
#define TREAP_T          fd_quic_tx_stream_t
#define TREAP_IDX_T      uint
#define TREAP_QUERY_T    ulong
#define TREAP_CMP(q,e)   ((long)(q) - ((long)((e)->stream_id)))
#define TREAP_LT(e0,e1)  ((e0)->stream_id < (e1)->stream_id)
#define TREAP_PRIO       balance
#define TREAP_IMPL_STYLE 2
#include "../../util/tmpl/fd_treap.c"

FD_FN_CONST ulong
fd_quic_tx_stream_pool_align( void ) {
  return FD_QUIC_TX_STREAM_POOL_ALIGN;
}

FD_FN_CONST ulong
fd_quic_tx_stream_pool_footprint( ulong stream_cnt ) {
  if( FD_UNLIKELY( stream_cnt>UINT_MAX ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_quic_tx_stream_dlist_align(), fd_quic_tx_stream_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(fd_quic_tx_stream_t), stream_cnt * sizeof(fd_quic_tx_stream_t) );
  return l;
}

void *
fd_quic_tx_stream_pool_new( void *     shmem,
                            ulong      stream_cnt,
                            fd_rng_t * rng ) {

  if( FD_UNLIKELY( stream_cnt>UINT_MAX ) ) {
    FD_LOG_WARNING(( "oversz stream_cnt" ));
    return NULL;
  }

  fd_quic_tx_stream_dlist_t * dlist = fd_quic_tx_stream_dlist_join( fd_quic_tx_stream_dlist_new( shmem ) );
  fd_quic_tx_stream_t *       pool  = fd_quic_tx_stream_pool( dlist );

  for( ulong j=0UL; j<stream_cnt; j++ ) {
    pool[j].stream_id = FD_QUIC_STREAM_ID_UNUSED;
    pool[j].balance   = fd_rng_uint( rng );
    fd_quic_tx_stream_dlist_idx_push_tail( dlist, j, pool );
  }

  return dlist;
}

fd_quic_tx_stream_dlist_t *
fd_quic_tx_stream_pool_join( void * mem ) {
  return mem;
}

void *
fd_quic_tx_stream_pool_leave( fd_quic_tx_stream_dlist_t * pool ) {
  return pool;
}

void *
fd_quic_tx_stream_pool_delete( void * mem ) {
  fd_quic_tx_stream_dlist_leave( fd_quic_tx_stream_dlist_delete( mem ) );
  return mem;
}

fd_quic_tx_stream_t *
fd_quic_tx_stream_alloc( fd_quic_tx_stream_pool_t * pool,
                         fd_quic_conn_t *           conn,
                         ulong                      stream_id,
                         void const *               data,
                         ulong                      data_sz ) {

  fd_quic_tx_stream_t * pool_ele = fd_quic_tx_stream_pool( pool );

  /* Remove from free list */
  if( FD_UNLIKELY( fd_quic_tx_stream_dlist_is_empty( pool, pool_ele ) ) ) return NULL;
  fd_quic_tx_stream_t * stream = fd_quic_tx_stream_dlist_ele_pop_head( pool, pool_ele );

  stream->conn              = conn;
  stream->stream_id         = stream_id;
  stream->upd_pkt_number    = FD_QUIC_PKT_NUM_PENDING;

  /* Register in treap (for querying) and send list (for servicing) */
  fd_quic_tx_stream_dlist_ele_push_tail( conn->send_streams, stream, pool_ele );
  fd_quic_tx_stream_treap_ele_insert   ( conn->tx_streams,   stream, pool_ele );

  /* Copy data */
  data_sz = fd_ulong_min( data_sz, FD_TXN_MTU );
  fd_memcpy( stream->data, data, data_sz );
  stream->data_sz = (ushort)data_sz;

  return stream;
}

void
fd_quic_tx_stream_free( fd_quic_tx_stream_pool_t * pool,
                        fd_quic_tx_stream_t *      stream ) {

  fd_quic_conn_t *      conn     = stream->conn;
  fd_quic_tx_stream_t * pool_ele = fd_quic_tx_stream_pool( pool );

  /* Move from wait list to free list */
  fd_quic_tx_stream_treap_ele_remove( conn->tx_streams,   stream, pool_ele );
  fd_quic_tx_stream_dlist_ele_remove( conn->wait_streams, stream, pool_ele );
  fd_quic_tx_stream_dlist_ele_push_head( pool, stream, pool_ele );
}

void
fd_quic_tx_stream_free_all( fd_quic_tx_stream_pool_t * pool,
                            fd_quic_conn_t *           conn ) {

  fd_quic_tx_stream_t * pool_ele = fd_quic_tx_stream_pool( pool );

  /* Bulk move from {wait,send} list to free list */
  fd_quic_tx_stream_dlist_merge_head( pool, conn->wait_streams, pool_ele );
  fd_quic_tx_stream_dlist_merge_head( pool, conn->send_streams, pool_ele );
}

fd_quic_tx_stream_t *
fd_quic_tx_stream_query( fd_quic_tx_stream_pool_t * pool,
                         fd_quic_conn_t *           conn,
                         ulong                      stream_id ) {

  fd_quic_tx_stream_treap_t * treap    = conn->tx_streams;
  fd_quic_tx_stream_t *       pool_ele = fd_quic_tx_stream_pool( pool );

  return fd_quic_tx_stream_treap_ele_query( treap, stream_id, pool_ele );
}
