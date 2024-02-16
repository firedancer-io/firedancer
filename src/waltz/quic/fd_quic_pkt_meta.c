#include "fd_quic_pkt_meta.h"

ulong
fd_quic_get_pkt_meta_free_count( fd_quic_pkt_meta_pool_t * pool ) {
  fd_quic_pkt_meta_t * pkt_meta = pool->free.head;
  ulong cnt = 0;
  while( pkt_meta ) {
    cnt++;
    pkt_meta = pkt_meta->next;
  }
  return cnt;
}


/* initialize pool with existing array of pkt_meta */
void
fd_quic_pkt_meta_pool_init( fd_quic_pkt_meta_pool_t * pool,
                            fd_quic_pkt_meta_t *      pkt_meta_array,
                            ulong                     pkt_meta_array_sz ) {
  /* initialize all to zeros */
  fd_memset( pool, 0, sizeof( *pool ) );

  /* free list */
  fd_quic_pkt_meta_list_t * free = &pool->free;

  /* initialize free list of packet metadata */
  for( ulong j = 0; j < pkt_meta_array_sz; ++j ) {
    fd_quic_pkt_meta_push_back( free, &pkt_meta_array[j] );
  }

}


/* pop from front of list */
fd_quic_pkt_meta_t *
fd_quic_pkt_meta_pop_front( fd_quic_pkt_meta_list_t * list ) {
  fd_quic_pkt_meta_t * front = list->head;
  if( front ) {
    list->head = front->next;
  }
  return front;
}


/* push onto front of list */
void
fd_quic_pkt_meta_push_front( fd_quic_pkt_meta_list_t * list,
                             fd_quic_pkt_meta_t *      pkt_meta ) {
  pkt_meta->next = list->head;
  list->head     = pkt_meta;
}


/* push onto back of list */
void
fd_quic_pkt_meta_push_back( fd_quic_pkt_meta_list_t * list,
                            fd_quic_pkt_meta_t *      pkt_meta ) {
  fd_quic_pkt_meta_t * tail = list->tail;
  if( tail ) {
    tail->next = pkt_meta;
    list->tail = pkt_meta;
  } else {
    list->head = list->tail = pkt_meta;
  }

  pkt_meta->next = NULL;
}

/* remove from list
   requires the prior element */
void
fd_quic_pkt_meta_remove( fd_quic_pkt_meta_list_t * list,
                         fd_quic_pkt_meta_t *      pkt_meta_prior,
                         fd_quic_pkt_meta_t *      pkt_meta ) {
  fd_quic_pkt_meta_t * pkt_meta_next = pkt_meta->next;

  if( pkt_meta_prior == NULL ) {
    if( pkt_meta_next == NULL ) {
      /* at tail... then head = tail = NULL */
      list->head = list->tail = NULL;
    } else {
      /* at head... move it to next */
      list->head = pkt_meta_next;
    }
  } else {
    if( pkt_meta_next == NULL ) {
      /* we're removing the last, so move tail */
      list->tail = pkt_meta_prior;
    }

    /* not head, make pkt_meta_prior point to next */
    pkt_meta_prior->next = pkt_meta_next;
  }

  pkt_meta->next = NULL;
}


/* allocate a pkt_meta
   obtains a free pkt_meta from the free list, and returns it
   returns NULL if none is available */
fd_quic_pkt_meta_t *
fd_quic_pkt_meta_allocate( fd_quic_pkt_meta_pool_t * pool ) {
  fd_quic_pkt_meta_t * pkt_meta = fd_quic_pkt_meta_pop_front( &pool->free );
  if( FD_LIKELY( pkt_meta ) ) {
    fd_memset( pkt_meta, 0, sizeof( *pkt_meta ) );
  }
  return pkt_meta;
}


/* free a pkt_meta
   returns a pkt_meta to the free list, ready to be allocated again */
void
fd_quic_pkt_meta_deallocate( fd_quic_pkt_meta_pool_t * pool, fd_quic_pkt_meta_t * pkt_meta ) {
  /* pushing to the front should help cache usage */
  fd_quic_pkt_meta_push_front( &pool->free, pkt_meta );
}


