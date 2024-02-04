#include "fd_list.h"

ulong
fd_list_align( void ) {
  return FD_LIST_ALIGN;
}

ulong
fd_list_footprint( ulong max ) {
  return ( max + 1 ) * sizeof( fd_list_t );
}

void *
fd_list_new( void * mem, ulong max ) {
  fd_list_t * sentinel = (fd_list_t *)mem;
  sentinel->tag        = 0;
  sentinel->curr       = 0;
  sentinel->prev       = 0;
  sentinel->next       = 0;
  fd_list_t * curr = sentinel;
  for ( ulong i = 1; i <= max; i++ ) {
    fd_list_t * new = sentinel + i;
    new->curr = i;
    fd_list_insert( curr, new );
    curr = new;
  }
  return mem;
}

fd_list_t *
fd_list_join( void * mem ) {
  return (fd_list_t *)mem;
}

fd_list_t *
fd_list_prev( fd_list_t * curr ) {
  return curr - curr->curr + curr->prev;
}

fd_list_t *
fd_list_next( fd_list_t * curr ) {
  return curr - curr->curr + curr->next;
}

fd_list_t *
fd_list_sentinel( fd_list_t * list ) {
  return list - list->curr;
}

fd_list_t *
fd_list_head( fd_list_t * list ) {
  fd_list_t * sentinel = fd_list_sentinel( list );
  return sentinel + sentinel->next;
}

fd_list_t *
fd_list_tail( fd_list_t * list ) {
  fd_list_t * sentinel = fd_list_sentinel( list );
  return sentinel + sentinel->prev;
}

int
fd_list_is_empty( fd_list_t * list ) {
  return fd_list_head(list) == fd_list_sentinel( list );
}

fd_list_t *
fd_list_insert( fd_list_t * curr, fd_list_t * new ) {
  new->prev                  = curr->curr;
  new->next                  = curr->next;
  fd_list_next( curr )->prev = new->curr;
  curr->next                 = new->curr;
  return new;
}

fd_list_t *
fd_list_remove( fd_list_t * curr ) {
  if ( FD_UNLIKELY( fd_list_is_empty( curr ) ) ) return NULL;
  fd_list_prev( curr )->next = curr->next;
  fd_list_next( curr )->prev = curr->prev;
  curr->prev                 = 0;
  curr->next                 = 0;
  return curr;
}

fd_list_t *
fd_list_push_back( fd_list_t * list, fd_list_t * new ) {
  return fd_list_insert( fd_list_tail( list ), new );
}

fd_list_t *
fd_list_pop_front( fd_list_t * list ) {
  fd_list_t * head = fd_list_head( list );
  if ( FD_UNLIKELY( fd_list_is_empty( list ) ) ) { return NULL; }
  return fd_list_remove( head );
}
