#ifndef HEADER_fd_src_util_list_fd_list_h
#define HEADER_fd_src_util_list_fd_list_h

#include "../fd_util_base.h"

typedef struct fd_list fd_list_t; /* forward decl */
struct fd_list {
  void *      ele; /* TODO refactor to be a tmpl-based */
  fd_list_t * prev;
  fd_list_t * next;
  fd_list_t * sentinel;
};

ulong
fd_list_align( void );

ulong
fd_list_footprint( ulong lg_max_sz );

void *
fd_list_new( void * mem, ulong lg_max_sz );

fd_list_t *
fd_list_join( void * mem );

fd_list_t *
fd_list_head( fd_list_t * list );

fd_list_t *
fd_list_tail( fd_list_t * list );

int
fd_list_is_empty( fd_list_t * list );

int
fd_list_is_full( fd_list_t * list );

/* a list can insert an element directly after itself */
fd_list_t *
fd_list_insert( fd_list_t * list, fd_list_t * ele );

/* a list can remove itself */
fd_list_t *
fd_list_remove( fd_list_t * ele );

fd_list_t *
fd_list_push_back( fd_list_t * list, fd_list_t * ele );

fd_list_t *
fd_list_pop_front( fd_list_t * list );

#endif /* HEADER_fd_src_util_list_fd_list_h */
