/* Declares a family of functions implementing a single-threaded
   run-time fixed-capacity stack designed for high performance contexts.
   Example usage:

     #define STACK_NAME my_stack
     #define STACK_T    my_ele_t
     #include "util/tmpl/fd_stack.c"

   This creates the following API for use in the local compilation unit:

     ulong      my_stack_align    ( void               ); // required byte alignment of a stack
     ulong      my_stack_footprint( ulong max          ); // required byte footprint of a stack with max capacity
     void     * my_stack_new      ( void     * shmem,     // format memory region into a my_stack, my_stack will be empty
                                    ulong      max );     // (caller not joined on return, mem has required align/footprint, etc)
     my_ele_t * my_stack_join     ( void     * shstack ); // join a my_stack (unlimited joins, etc) (NOT A CAST OF SHSTACK)
                                                          // join can be indexed like a normal array with max elements
                                                          // stack[i] for i in [0,cnt) are the elements currently in the
                                                          // stack from bottom to top
     void     * my_stack_leave    ( my_ele_t * stack   ); // leave a my_stack (matched with join, etc) (NOT A CAST OF STACK)
     void     * my_stack_delete   ( void     * shstack ); // unformat memory (no active joins, etc)

     // Accessors

     ulong my_stack_max  ( my_ele_t const * stack ); // returns the max elements that could be in the stack
     ulong my_stack_cnt  ( my_ele_t const * stack ); // returns the number of elements in the stack, in [0,max]
     ulong my_stack_avail( my_ele_t const * stack ); // return max-cnt
     int   my_stack_empty( my_ele_t const * stack ); // returns 1 if empty and 0 otherwise
     int   my_stack_full ( my_ele_t const * stack ); // returns 1 if full and 0 otherwise

     // Simple API

     my_ele_t * my_stack_push( my_ele_t * stack, my_ele_t ele ); // push ele to stack, returns stack
     my_ele_t   my_stack_pop ( my_ele_t * stack               ); // pop ele from stack, returns ele

     // Advanced API for zero-copy usage

     my_ele_t * my_stack_peek      ( my_ele_t * stack ); // peeks at stack top, returned ptr lifetime is until next op on stack
     my_ele_t * my_stack_insert    ( my_ele_t * stack ); // inserts uninitialized element at tail, returns stack
     my_ele_t * my_stack_remove    ( my_ele_t * stack ); // removes tail, returns stack
     my_ele_t * my_stack_remove_all( my_ele_t * stack ); // removes all, returns stack, fast O(1)

     my_ele_t const * my_stack_peek_const( my_ele_t const * stack ); // const version of peek

   For performance, none of the functions do any error checking.
   Specifically, the caller promises that max is such that footprint
   will not overflow 2^64 (e.g. max << (2^64)/sizeof(my_ele_t)), cnt<max
   for any push or insert operation and cnt>0 for any pop, peek or
   remove operation (remove_all is fine on an empty stack). */

#include "../bits/fd_bits.h"

#ifndef STACK_NAME
#error "Define STACK_NAME"
#endif

#ifndef STACK_T
#error "Define STACK_T"
#endif

/* Implementation *****************************************************/

#define STACK_(x) FD_EXPAND_THEN_CONCAT3(STACK_NAME,_,x)

struct STACK_(private) {

  /* The number of elements in the stack is cnt and cnt will be in
     [0,max].  If cnt==0, the stack is empty.  If cnt==max, the stack if
     full.  For a non-empty stack, the oldest element in the stack is at
     element stack[0] and the newest element in the stack is at element
     stack[cnt-1UL]. */

  ulong   max;
  ulong   cnt;
  STACK_T stack[1]; /* Actually max in size */
};

typedef struct STACK_(private) STACK_(private_t);

FD_PROTOTYPES_BEGIN

/* private_from_stack return a pointer to the stack_private given a
   pointer to the stack. */

FD_FN_CONST static inline STACK_(private_t) *
STACK_(private_hdr_from_stack)( STACK_T * stack ) {
  return (STACK_(private_t) *)( (ulong)stack - (ulong)&(((STACK_(private_t) *)NULL)->stack) );
}

/* const-correct version of above */

FD_FN_CONST static inline STACK_(private_t) const *
STACK_(private_const_hdr_from_stack)( STACK_T const * stack ) {
  return (STACK_(private_t) const *)( (ulong)stack - (ulong)&(((STACK_(private_t) *)NULL)->stack) );
}

FD_FN_CONST static inline ulong STACK_(align)( void ) { return alignof(STACK_(private_t)); }

FD_FN_CONST static inline ulong
STACK_(footprint)( ulong max ) {
  return fd_ulong_align_up( fd_ulong_align_up( 16UL, alignof(STACK_T) ) + sizeof(STACK_T)*max, alignof(STACK_(private_t)) );
}

static inline void *
STACK_(new)( void * shmem,
             ulong  max ) {
  STACK_(private_t) * hdr = (STACK_(private_t) *)shmem;
  hdr->max = max;
  hdr->cnt = 0UL;
  return hdr;
}

static inline STACK_T *
STACK_(join)( void * shstack ) {
  STACK_(private_t) * hdr = (STACK_(private_t) *)shstack;
  return hdr->stack;
} 

static inline void * STACK_(leave) ( STACK_T * stack   ) { return (void *)STACK_(private_hdr_from_stack)( stack ); }
static inline void * STACK_(delete)( void *    shstack ) { return shstack; }

FD_FN_PURE static inline ulong
STACK_(max)( STACK_T const * stack ) {
  return STACK_(private_const_hdr_from_stack)( stack )->max;
}

FD_FN_PURE static inline ulong
STACK_(cnt)( STACK_T const * stack ) {
  return STACK_(private_const_hdr_from_stack)( stack )->cnt;
}

FD_FN_PURE static inline ulong
STACK_(avail)( STACK_T const * stack ) {
  STACK_(private_t) const * hdr = STACK_(private_const_hdr_from_stack)( stack );
  return hdr->max - hdr->cnt;
}

FD_FN_PURE static inline int
STACK_(full)( STACK_T const * stack ) {
  STACK_(private_t) const * hdr = STACK_(private_const_hdr_from_stack)( stack );
  return hdr->max==hdr->cnt;
}

FD_FN_PURE static inline int
STACK_(empty)( STACK_T const * stack ) {
  return !STACK_(private_const_hdr_from_stack)( stack )->cnt;
}

static inline STACK_T *
STACK_(push)( STACK_T * stack,
              STACK_T   ele ) {
  STACK_(private_t) * hdr = STACK_(private_hdr_from_stack)( stack );
  hdr->stack[ hdr->cnt++ ] = ele;
  return stack;
}

static inline STACK_T
STACK_(pop)( STACK_T * stack ) {
  STACK_(private_t) * hdr = STACK_(private_hdr_from_stack)( stack );
  return hdr->stack[ --hdr->cnt ];
}

FD_FN_PURE static inline STACK_T *
STACK_(peek)( STACK_T * stack ) {
  STACK_(private_t) * hdr = STACK_(private_hdr_from_stack)( stack );
  return hdr->stack + (hdr->cnt-1UL);
}

FD_FN_PURE static inline STACK_T const *
STACK_(peek_const)( STACK_T const * stack ) {
  STACK_(private_t) const * hdr = STACK_(private_const_hdr_from_stack)( stack );
  return hdr->stack + (hdr->cnt-1UL);
}

static inline STACK_T * STACK_(insert)    ( STACK_T * stack ) { STACK_(private_hdr_from_stack)( stack )->cnt++;     return stack; }
static inline STACK_T * STACK_(remove)    ( STACK_T * stack ) { STACK_(private_hdr_from_stack)( stack )->cnt--;     return stack; }
static inline STACK_T * STACK_(remove_all)( STACK_T * stack ) { STACK_(private_hdr_from_stack)( stack )->cnt = 0UL; return stack; }

FD_PROTOTYPES_END

#undef STACK_

#undef STACK_T
#undef STACK_NAME

