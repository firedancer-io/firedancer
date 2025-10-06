#ifndef HEADER_fd_src_funk_fd_funk_private_h
#define HEADER_fd_src_funk_fd_funk_private_h

/* fd_funk_private.h contains internal APIs deemed unsafe for public
   consumption. */

#include "fd_funk.h"

/* fd_funk_all_iter_t iterators over all funk record objects in all funk
   transactions.  This API is not optimized for performance and has a
   high fixed cost (slow even for empty DBs).

   Assumes no concurrent write accesses to the entire funk instance
   during the lifetime of this iterator.

   Usage is:

   fd_funk_all_iter_t iter[1];
   for( fd_funk_all_iter_new( funk, iter ); !fd_funk_all_iter_done( iter ); fd_funk_all_iter_next( iter ) ) {
     fd_funk_rec_t const * rec = fd_funk_all_iter_ele_const( iter );
     ...
   } */

struct fd_funk_all_iter {
  fd_funk_rec_map_t      rec_map;
  ulong                  chain_cnt;
  ulong                  chain_idx;
  fd_funk_rec_map_iter_t rec_map_iter;
};

typedef struct fd_funk_all_iter fd_funk_all_iter_t;

FD_PROTOTYPES_BEGIN

FD_FN_UNUSED static void
fd_funk_all_iter_skip_nulls( fd_funk_all_iter_t * iter ) {
  if( iter->chain_idx == iter->chain_cnt ) return;
  while( fd_funk_rec_map_iter_done( iter->rec_map_iter ) ) {
    if( ++(iter->chain_idx) == iter->chain_cnt ) break;
    iter->rec_map_iter = fd_funk_rec_map_iter( &iter->rec_map, iter->chain_idx );
  }
}

FD_FN_UNUSED static void
fd_funk_all_iter_new( fd_funk_t const *    funk,
                      fd_funk_all_iter_t * iter ) {
  iter->rec_map      = *funk->rec_map;
  iter->chain_cnt    = fd_funk_rec_map_chain_cnt( &iter->rec_map );
  iter->chain_idx    = 0;
  iter->rec_map_iter = fd_funk_rec_map_iter( &iter->rec_map, 0 );
  fd_funk_all_iter_skip_nulls( iter );
}

static inline int
fd_funk_all_iter_done( fd_funk_all_iter_t const * iter ) {
  return ( iter->chain_idx == iter->chain_cnt );
}

FD_FN_UNUSED static void
fd_funk_all_iter_next( fd_funk_all_iter_t * iter ) {
  iter->rec_map_iter = fd_funk_rec_map_iter_next( iter->rec_map_iter );
  fd_funk_all_iter_skip_nulls( iter );
}

static inline fd_funk_rec_t const *
fd_funk_all_iter_ele_const( fd_funk_all_iter_t * iter ) {
  return fd_funk_rec_map_iter_ele_const( iter->rec_map_iter );
}

static inline fd_funk_rec_t *
fd_funk_all_iter_ele( fd_funk_all_iter_t * iter ) {
  return fd_funk_rec_map_iter_ele( iter->rec_map_iter );
}

FD_PROTOTYPES_END

/* fd_funk_txn_all_iter_t iterators over all funk transaction objects.

   Assumes no concurrent write accesses to the entire funk instance
   during the lifetime of this iterator.

   Usage is:

   fd_funk_txn_all_iter_t txn_iter[1];
   for( fd_funk_txn_all_iter_new( funk, txn_iter ); !fd_funk_txn_all_iter_done( txn_iter ); fd_funk_txn_all_iter_next( txn_iter ) ) {
     fd_funk_txn_t const * txn = fd_funk_txn_all_iter_ele_const( txn_iter );
     ...
   }

   FIXME depth-first search transaction tree instead */

struct fd_funk_txn_all_iter {
  fd_funk_txn_map_t txn_map;
  ulong chain_cnt;
  ulong chain_idx;
  fd_funk_txn_map_iter_t txn_map_iter;
};

typedef struct fd_funk_txn_all_iter fd_funk_txn_all_iter_t;

FD_PROTOTYPES_BEGIN

FD_FN_UNUSED static void
fd_funk_txn_all_iter_skip_nulls( fd_funk_txn_all_iter_t * iter ) {
  if( iter->chain_idx == iter->chain_cnt ) return;
  while( fd_funk_txn_map_iter_done( iter->txn_map_iter ) ) {
    if( ++(iter->chain_idx) == iter->chain_cnt ) break;
    iter->txn_map_iter = fd_funk_txn_map_iter( &iter->txn_map, iter->chain_idx );
  }
}

FD_FN_UNUSED static void
fd_funk_txn_all_iter_new( fd_funk_t const *        funk,
                          fd_funk_txn_all_iter_t * iter ) {
  iter->txn_map = *funk->txn_map;
  iter->chain_cnt = fd_funk_txn_map_chain_cnt( funk->txn_map );
  iter->chain_idx = 0;
  iter->txn_map_iter = fd_funk_txn_map_iter( funk->txn_map, 0 );
  fd_funk_txn_all_iter_skip_nulls( iter );
}

static inline int
fd_funk_txn_all_iter_done( fd_funk_txn_all_iter_t const * iter ) {
  return iter->chain_idx == iter->chain_cnt;
}

FD_FN_UNUSED static void
fd_funk_txn_all_iter_next( fd_funk_txn_all_iter_t * iter ) {
  iter->txn_map_iter = fd_funk_txn_map_iter_next( iter->txn_map_iter );
  fd_funk_txn_all_iter_skip_nulls( iter );
}

static inline fd_funk_txn_t const *
fd_funk_txn_all_iter_ele_const( fd_funk_txn_all_iter_t * iter ) {
  return fd_funk_txn_map_iter_ele_const( iter->txn_map_iter );
}

static inline fd_funk_txn_t *
fd_funk_txn_all_iter_ele( fd_funk_txn_all_iter_t * iter ) {
  return fd_funk_txn_map_iter_ele( iter->txn_map_iter );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_private_h */
