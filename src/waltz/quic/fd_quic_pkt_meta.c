#include "fd_quic_pkt_meta.h"

void *
fd_quic_pkt_meta_tracker_init( fd_quic_pkt_meta_tracker_t * tracker,
                               ulong                        total_meta_cnt,
                               fd_quic_pkt_meta_t         * pool ) {
  for( ulong enc_level=0; enc_level<4; enc_level++ ) {
    void* mem = fd_quic_pkt_meta_treap_new( &tracker->sent_pkt_metas[enc_level],
                                            total_meta_cnt );
    mem = fd_quic_pkt_meta_treap_join( mem );
    if( FD_UNLIKELY( !mem ) ) return NULL;
  }
  tracker->pool = pool;

  return tracker;
}

void
fd_quic_pkt_meta_ds_init_pool( fd_quic_pkt_meta_t * pool,
                               ulong                total_meta_cnt ) {
  fd_quic_pkt_meta_treap_seed( pool, total_meta_cnt, (ulong)fd_tickcount() );
}

void
fd_quic_pkt_meta_insert( fd_quic_pkt_meta_ds_t * ds,
                         fd_quic_pkt_meta_t    * pkt_meta,
                         fd_quic_pkt_meta_t    * pool ) {
  fd_quic_pkt_meta_treap_ele_insert( ds, pkt_meta, pool );
}


ulong
fd_quic_pkt_meta_remove_range( fd_quic_pkt_meta_ds_t * ds,
                               fd_quic_pkt_meta_t    * pool,
                               ulong                   pkt_number_lo,
                               ulong                   pkt_number_hi ) {

  fd_quic_pkt_meta_ds_fwd_iter_t    l_iter =  fd_quic_pkt_meta_ds_idx_ge( ds, pkt_number_lo, pool );
  fd_quic_pkt_meta_t              * prev   =  NULL;
  ulong                        cnt_removed =  0;

  for( fd_quic_pkt_meta_ds_fwd_iter_t iter = l_iter;
                                            !fd_quic_pkt_meta_ds_fwd_iter_done( iter );
                                            iter = fd_quic_pkt_meta_ds_fwd_iter_next( iter, pool ) ) {
    fd_quic_pkt_meta_t * e = fd_quic_pkt_meta_ds_fwd_iter_ele( iter, pool );
    if( FD_UNLIKELY( e->key.pkt_num > pkt_number_hi ) ) break;
    if( FD_LIKELY( prev ) ) {
      fd_quic_pkt_meta_treap_ele_remove( ds, prev, pool );
      fd_quic_pkt_meta_pool_ele_release( pool, prev );
      cnt_removed++;
    }
    prev = e;
  }
  if( FD_LIKELY( prev ) ) {
    fd_quic_pkt_meta_treap_ele_remove( ds, prev, pool );
    fd_quic_pkt_meta_pool_ele_release( pool, prev );
    cnt_removed++;
  }
  return cnt_removed;
}

void
fd_quic_pkt_meta_remove( fd_quic_pkt_meta_ds_t * ds,
                         fd_quic_pkt_meta_t    * pool,
                         fd_quic_pkt_meta_t    * pkt_meta ) {
  fd_quic_pkt_meta_treap_ele_remove( ds, pkt_meta, pool );
  fd_quic_pkt_meta_pool_ele_release( pool, pkt_meta );
}

fd_quic_pkt_meta_t *
fd_quic_pkt_meta_min( fd_quic_pkt_meta_ds_t * ds,
                      fd_quic_pkt_meta_t    * pool ) {

  fd_quic_pkt_meta_ds_fwd_iter_t iter = fd_quic_pkt_meta_ds_fwd_iter_init( ds, pool );
  if( FD_UNLIKELY( fd_quic_pkt_meta_ds_fwd_iter_done( iter ) ) ) return NULL;
  return fd_quic_pkt_meta_ds_fwd_iter_ele( iter, pool );
}

fd_quic_pkt_meta_ds_fwd_iter_t
fd_quic_pkt_meta_ds_idx_le( fd_quic_pkt_meta_ds_t * ds,
                            fd_quic_pkt_meta_t    * pool,
                            ulong                   pkt_number ) {
  /* One might first consider using le with composite key that sets
     type and stream_id to their max values, and then traversing
     back to the first pkt_meta with this pkt_number. But when we
     have many concurrent streams, that's a lot of traversal.

     We instead use lt to jump to the last pkt_meta right before
     our query. Edge case: if next pkt_meta has the wrong pkt_num,
     we know that 'pkt_number' is missing and should stick with prev */
  fd_quic_pkt_meta_ds_fwd_iter_t prev = fd_quic_pkt_meta_treap_idx_lt( ds,
                                         (fd_quic_pkt_meta_key_t){
                                          .pkt_num = pkt_number & FD_QUIC_PKT_META_PKT_NUM_MASK,
                                          .type = 0,
                                          .stream_id = 0},
                                         pool );
  if( FD_UNLIKELY( fd_quic_pkt_meta_ds_fwd_iter_done( prev ) ) ) return prev;
  fd_quic_pkt_meta_ds_fwd_iter_t next = fd_quic_pkt_meta_treap_fwd_iter_next( prev, pool );
  if( FD_UNLIKELY( fd_quic_pkt_meta_ds_fwd_iter_done( next ) ) ) return prev;

  fd_quic_pkt_meta_t * next_e = fd_quic_pkt_meta_ds_fwd_iter_ele( next, pool );
  return next_e->key.pkt_num==pkt_number ? next : prev;
}


void
fd_quic_pkt_meta_ds_clear( fd_quic_pkt_meta_tracker_t * tracker,
                        uint                         enc_level ) {
  ulong ele_max = fd_quic_pkt_meta_treap_ele_max( &tracker->sent_pkt_metas[enc_level] );
  fd_quic_pkt_meta_treap_new( &tracker->sent_pkt_metas[enc_level], ele_max );
}
