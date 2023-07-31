#ifndef HEADER_fd_src_util_list_fd_list_h
#define HEADER_fd_src_util_list_fd_list_h

#include "../../util/fd_util.h"

/* An implementation of an intrusive doubly-linked list.

   -----
   1    / 0x0  = 0
   -----
   5    / 0x4  = 4
   -----
   3    / 0x8  = 8
   -----
   2    / 0x12 = 12
   -----
   4    / 0x16 = 16
   -----

   tag : 1  -> 2  -> 3  -> 4  -> 5
   curr: 0  -> 12 -> 8  -> 16 -> 4
   prev: /  <- 0  <- 12 <- 8  <- 16
   next: 12 -> 8  -> 16 -> 4  -> /

   TODO generalize to a tmpl data structure? */
typedef struct fd_list fd_list_t; /* forward decl */
struct fd_list {
  ulong tag; /* TODO generic */
  /* below all are offsets from the sentinel */
  ulong curr;
  ulong prev;
  ulong next;
};

ulong
fd_list_align( void );

ulong
fd_list_footprint( ulong max );

void *
fd_list_new( void * mem, ulong max );

fd_list_t *
fd_list_join( void * mem );

fd_list_t *
fd_list_prev( fd_list_t * curr );

fd_list_t *
fd_list_next( fd_list_t * curr );

fd_list_t *
fd_list_sentinel( fd_list_t * list );

fd_list_t *
fd_list_head( fd_list_t * list );

fd_list_t *
fd_list_tail( fd_list_t * list );

int
fd_list_is_empty( fd_list_t * list );

/* a list can insert an element directly after itself */
fd_list_t *
fd_list_insert( fd_list_t * curr, fd_list_t * new );

/* a list can remove itself */
fd_list_t *
fd_list_remove( fd_list_t * new );

fd_list_t *
fd_list_push_back( fd_list_t * list, fd_list_t * new );

fd_list_t *
fd_list_pop_front( fd_list_t * list );

#endif /* HEADER_fd_src_util_list_fd_list_h */
