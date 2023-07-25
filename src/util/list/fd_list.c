#include "../fd_util_base.h"
#include "../bits/fd_bits.h"
#include "../log/fd_log.h"
#include "fd_list.h"

#define FD_LIST_ALIGN ( 32UL ) /* 2-nodes per L1 cache line */

fd_list_t *
fd_list_insert( fd_list_t * list, fd_list_t * ele ) {
  if ( FD_UNLIKELY( fd_list_is_full( list ) ) ) return NULL;
  ele->next        = list->next;
  ele->prev        = list;
  ele->sentinel    = list->sentinel;
  list->next->prev = ele;
  list->next       = ele;
  return ele;
}

fd_list_t *
fd_list_remove( fd_list_t * ele ) {
  if ( FD_UNLIKELY( fd_list_is_empty( ele ) ) ) return NULL; /* this is the sentinel */
  // FD_LOG_NOTICE( ( "removing %lu", *(ulong *)(ele->ele) ) );
  ele->prev->next = ele->next;
  ele->next->prev = ele->prev;
  ele->prev       = NULL;
  ele->next       = NULL;
  return ele;
}

ulong
fd_list_align( void ) {
  return FD_LIST_ALIGN;
}

ulong
fd_list_footprint( ulong lg_max_sz ) {
  return sizeof( fd_list_t ) + sizeof( fd_list_t ) * ( 1UL << lg_max_sz );
}

void *
fd_list_new( void * mem, ulong lg_max_sz ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_list_t * sentinel = FD_SCRATCH_ALLOC_APPEND( l, fd_list_align(), sizeof( fd_list_t ) );
  sentinel->ele        = NULL;
  sentinel->prev       = sentinel;
  sentinel->next       = sentinel;
  sentinel->sentinel   = sentinel;
  fd_list_t * list     = sentinel;
  for ( ulong i = 0; i < ( 1UL << lg_max_sz ); i++ ) {
    fd_list_t * ele = FD_SCRATCH_ALLOC_APPEND( l, fd_list_align(), sizeof( fd_list_t ) );
    fd_list_push_back( list, ele );
  }
  FD_SCRATCH_ALLOC_FINI( l, fd_list_align() );
  return mem;
}

fd_list_t *
fd_list_join( void * mem ) {
  return (fd_list_t *)mem;
}

fd_list_t *
fd_list_head( fd_list_t * list ) {
  return list->sentinel->next;
}

fd_list_t *
fd_list_tail( fd_list_t * list ) {
  return list->sentinel->prev;
}

int
fd_list_is_empty( fd_list_t * list ) {
  return fd_list_head( list ) == list->sentinel;
}

int
fd_list_is_full( fd_list_t * list ) {
  return !fd_list_is_empty( list ) && fd_list_tail( list ) == list->sentinel;
}

fd_list_t *
fd_list_push_back( fd_list_t * list, fd_list_t * curr ) {
  return fd_list_insert( fd_list_tail( list ), curr );
}

fd_list_t *
fd_list_pop_front( fd_list_t * list ) {
  fd_list_t * head = fd_list_head( list );
  if ( FD_UNLIKELY( head == list->sentinel ) ) { /* list is empty*/
    return NULL;
  }
  return fd_list_remove( head );
}
