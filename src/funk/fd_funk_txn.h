#ifndef HEADER_fd_src_funk_fd_funk_txn_h
#define HEADER_fd_src_funk_fd_funk_txn_h

/* This provides APIs for managing forks (preparing, publishing and
   cancelling funk transactions).  It is generally not meant to be
   included directly.  Use fd_funk.h instead. */

#include "fd_funk_base.h"

/* FD_FUNK_TXN_{ALIGN,FOOTPRINT} describe the alignment and footprint of
   a fd_funk_txn_t.  ALIGN will be a power of 2, footprint will be a
   multiple of align.  These are provided to facilitate compile time
   declarations. */

#define FD_FUNK_TXN_ALIGN     (32UL)
#define FD_FUNK_TXN_FOOTPRINT (96UL)

/* FD_FUNK_TXN_IDX_NULL gives the map transaction idx value used to
   represent NULL.  It also is the maximum value for txn_max in a funk
   to support index compression.  (E.g. could use ushort / USHORT_MAX
   to use more aggressive compression or ulong / ULONG_MAX to disable
   index compression.) */

#define FD_FUNK_TXN_IDX_NULL ((ulong)UINT_MAX)

/* A fd_funk_txn_t is an opaque handle of an in-preparation funk
   transaction.  The details are exposed here to facilitate inlining
   various operations. */

struct __attribute__((aligned(FD_FUNK_TXN_ALIGN))) fd_funk_txn_private {

  /* These fields are managed by the funk's txn_map */

  fd_funk_txn_xid_t xid;      /* Transaction id, at a minimum, unique among all in-prepare and the last published transaction,
                                 ideally globally unique */
  ulong             map_next; /* Internal use by map */
  ulong             map_hash; /* Internal use by map */

  /* These fields are managed by the funk */

  uint   parent_cidx;       /* compr map index of the in-prep parent         txn, compr FD_FUNK_TXN_IDX_NULL if a funk child */
  uint   child_head_cidx;   /* "                              oldest   child      "                             childless */
  uint   child_tail_cidx;   /* "                              youngest child                                    childless */
  uint   sibling_prev_cidx; /* "                              older sibling                                     oldest sibling */
  uint   sibling_next_cidx; /* "                              younger sibling                                   youngest sibling */
  uint   stack_cidx;        /* Internal use by funk */
  ulong  tag;               /* Internal use by funk */

  uint  rec_head_idx;      /* Record map index of the first record, FD_FUNK_REC_IDX_NULL if none (from oldest to youngest) */
  uint  rec_tail_idx;      /* "                       last          " */
};

typedef struct fd_funk_txn_private fd_funk_txn_t;

/* fd_funk_txn_map allows for indexing transactions by their xid */

#define POOL_NAME          fd_funk_txn_pool
#define POOL_ELE_T         fd_funk_txn_t
#define POOL_IDX_T         uint
#define POOL_NEXT          map_next
#define POOL_IMPL_STYLE    1
#include "../util/tmpl/fd_pool_para.c"

#define MAP_NAME              fd_funk_txn_map
#define MAP_ELE_T             fd_funk_txn_t
#define MAP_KEY_T             fd_funk_txn_xid_t
#define MAP_KEY               xid
#define MAP_KEY_EQ(k0,k1)     fd_funk_txn_xid_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_txn_xid_hash((k0),(seed))
#define MAP_NEXT              map_next
#define MAP_HASH              map_hash
#define MAP_MAGIC             (0xf173da2ce7172db0UL) /* Firedancer txn db version 0 */
#define MAP_IMPL_STYLE        1
#include "../util/tmpl/fd_map_chain_para.c"
#undef  MAP_HASH

FD_PROTOTYPES_BEGIN

/* fd_funk_txn_{cidx,idx} convert between an index and a compressed index. */

static inline uint  fd_funk_txn_cidx( ulong idx ) { return (uint) idx; }
static inline ulong fd_funk_txn_idx ( uint  idx ) { return (ulong)idx; }

/* fd_funk_txn_idx_is_null returns 1 if idx is FD_FUNK_TXN_IDX_NULL and
   0 otherwise. */

static inline int fd_funk_txn_idx_is_null( ulong idx ) { return idx==FD_FUNK_TXN_IDX_NULL; }

/* Generate a globally unique pseudo-random xid */
fd_funk_txn_xid_t fd_funk_generate_xid(void);

/* Concurrency control */

/* APIs for marking the start and end of operations that read or write to
   the Funk transactions.

   IMPORTANT SAFETY TIP

   The following APIs need the write lock:
   - fd_funk_txn_prepare
   - fd_funk_txn_publish
   - fd_funk_txn_publish_into_parent
   - fd_funk_txn_cancel
   - fd_funk_txn_cancel_siblings
   - fd_funk_txn_cancel_children

   The following APIs need the read lock:
   - fd_funk_txn_ancestor
   - fd_funk_txn_descendant
   - fd_funk_txn_all_iter

   TODO: in future we may be able to make these lock-free, but they are called
   infrequently so not sure how much of a gain this would be.
   */
void
fd_funk_txn_start_read( fd_funk_t * funk );

void
fd_funk_txn_end_read( fd_funk_t * funk );

void
fd_funk_txn_start_write( fd_funk_t * funk );

void
fd_funk_txn_end_write( fd_funk_t * funk );

/* Accessors */

/* fd_funk_txn_query returns a pointer to an in-preparation transaction
   whose id is pointed to by xid.  Returns NULL if xid is not an
   in-preparation transaction.  Assumes funk is a current local join,
   map==fd_funk_txn_map( funk, fd_funk_wksp( funk ) ), xid points to a
   transaction id in the caller's address space and there are no
   concurrent operations on funk or xid.  Retains no interest in xid.

   The returned pointer is in the caller's address space and, if the
   return is non-NULL, the lifetime of the returned pointer is the
   lesser of the funk join or the transaction is published or canceled
   (either directly or indirectly via publish of a descendant, publish
   of a competing transaction history or cancel of an ancestor). */

FD_FN_PURE static inline fd_funk_txn_t *
fd_funk_txn_query( fd_funk_txn_xid_t const * xid,
                   fd_funk_txn_map_t *       map ) {
  do {
    fd_funk_txn_map_query_t query[1];
    if( FD_UNLIKELY( fd_funk_txn_map_query_try( map, xid, NULL, query, 0 ) ) ) return NULL;
    fd_funk_txn_t * ele = fd_funk_txn_map_query_ele( query );
    if( FD_LIKELY( !fd_funk_txn_map_query_test( query ) ) ) return ele;
  } while( 1 );
}

/* fd_funk_txn_xid returns a pointer in the local address space of the
   ID of an in-preparation transaction.  Assumes txn points to an
   in-preparation transaction in the caller's address space.  The
   lifetime of the returned pointer is the same as the txn's pointer
   lifetime.  The value at the pointer will be stable for the lifetime
   of the returned pointer. */

FD_FN_CONST static inline fd_funk_txn_xid_t const * fd_funk_txn_xid( fd_funk_txn_t const * txn ) { return &txn->xid; }

/* fd_funk_txn_{parent,child_head,child_tail,sibling_prev,sibling_next}
   return a pointer in the caller's address space to the corresponding
   relative in-preparation transaction of in-preparation transaction
   txn.

   Specifically:

   - parent is the parent transaction.  NULL if txn is a child of funk.
   - child_head is txn's oldest child.  NULL if txn has no children.
   - child_tail is txn's youngest child.  NULL if txn has no children.
   - sibling_prev is txn's closest older sibling.  NULL if txn is the
     oldest sibling.
   - sibling_next is txn's closest younger sibling.  NULL if txn is the
     youngest sibling.

   E.g. child_head==NULL indicates txn has no children.
   child_head!=NULL and child_head==child_tail indicates txn has one
   child.  child_head!=NULL and child_tail!=NULL and
   child_head!=child_tail indicates txn has many children.
   sibling_prev==sibling_next==NULL indicate no siblings / locally
   competing transactions to txn.  If the txn and all its ancestors have
   no siblings, there are no transaction histories competing with txn
   globally. */

#define FD_FUNK_ACCESSOR(field)                          \
FD_FN_PURE static inline fd_funk_txn_t *                 \
fd_funk_txn_##field( fd_funk_txn_t const *      txn,     \
                     fd_funk_txn_pool_t const * pool ) { \
  ulong idx = fd_funk_txn_idx( txn->field##_cidx );      \
  if( idx==FD_FUNK_TXN_IDX_NULL ) return NULL;           \
  return pool->ele + idx;                                \
}

FD_FUNK_ACCESSOR( parent       )
FD_FUNK_ACCESSOR( child_head   )
FD_FUNK_ACCESSOR( child_tail   )
FD_FUNK_ACCESSOR( sibling_prev )
FD_FUNK_ACCESSOR( sibling_next )

#undef FD_FUNK_ACCESSOR

/* fd_funk_txn_frozen returns 1 if the in-preparation transaction is
   frozen (i.e. has children) and 0 otherwise (i.e. has no children).
   Assumes txn points to an in-preparation transaction in the caller's
   address space. */

FD_FN_PURE static inline int
fd_funk_txn_is_frozen( fd_funk_txn_t const * txn ) {
  return !fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->child_head_cidx ) );
}

/* fd_funk_txn_is_only_child returns 1 if the in-preparation transaction
   txn if is any only child and 0 if it has one or more siblings.
   Assumes txn points to an in-preparation transaction in the caller's
   address space. */

FD_FN_PURE static inline int
fd_funk_txn_is_only_child( fd_funk_txn_t const * txn ) {
  return ( fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->sibling_prev_cidx ) ) ) &
         ( fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->sibling_next_cidx ) ) );
}

typedef struct fd_funk_rec fd_funk_rec_t;

/* fd_funk_txn_{first,last}_rec return the {first,last} record in a
   transaction.  Returns NULL if the transaction has no records yet, or
   if txn is NULL (root txn). */

fd_funk_rec_t const *
fd_funk_txn_first_rec( fd_funk_t *           funk,
                       fd_funk_txn_t const * txn );

fd_funk_rec_t const *
fd_funk_txn_last_rec( fd_funk_t *           funk,
                      fd_funk_txn_t const * txn );

/* Return the next record in a transaction. Returns NULL if the
   transaction has no more records. */

fd_funk_rec_t const *
fd_funk_txn_next_rec( fd_funk_t *           funk,
                      fd_funk_rec_t const * rec );

/* Return the previous record in a transaction. Returns NULL if the
   transaction has no more records. */

fd_funk_rec_t const *
fd_funk_txn_prev_rec( fd_funk_t *           funk,
                      fd_funk_rec_t const * rec );

/* Operations */

/* fd_funk_txn_ancestor returns a pointer in the caller's address space
   to the youngest transaction among in-preparation transaction txn and
   its ancestors that currently has siblings.  Returns NULL if all
   transactions back to the root transaction have no siblings (e.g.
   there are no competing transaction histories and thus publishing
   transaction txn will not require canceling any other competing
   transactions).  This is a reasonably fast O(length of ancestor
   history) time (theoretical minimum) and a reasonably small O(1) space
   (theoretical minimum).  This is not fortified against transaction map
   data corruption.

   fd_funk_txn_descendant returns a pointer in the caller's address
   space to the first transaction among txn and its youngest direct
   descendant inclusive that currently either has no children or has
   multiple children.  Returns NULL if txn is not an only child.  This
   is a reasonably fast O(length of descendant history) time
   (theoretical minimum) and a reasonably small O(1) space (theoretical
   minimum).  This is not fortified against transaction map data
   corruption.

   That is, if txn's ancestor is NULL, all transactions up to and
   including txn's descendant (which will be non-NULL) can be published
   without cancelling any competing transactions.  Further, if the
   descendant has a child, it has multiple children.  And if has no
   children, all transactions in preparation are linear from the root to
   the descendant.

   In code:

     if( !fd_funk_txn_ancestor( txn, map ) )
       fd_funk_publish( funk, fd_funk_txn_descendant( funk, map ) );

   would publish as much currently uncontested transaction history as
   possible around txn. */

FD_FN_PURE static inline fd_funk_txn_t *
fd_funk_txn_ancestor( fd_funk_txn_t * txn,
                      fd_funk_txn_pool_t * pool ) {
  for(;;) {
    if( !fd_funk_txn_is_only_child( txn ) ) break;
    fd_funk_txn_t * parent = fd_funk_txn_parent( txn, pool );
    if( !parent ) return NULL;
    txn = parent;
  }
  return txn;
}

FD_FN_PURE static inline fd_funk_txn_t *
fd_funk_txn_descendant( fd_funk_txn_t * txn,
                        fd_funk_txn_pool_t * pool ) {
  if( !fd_funk_txn_is_only_child( txn ) ) return NULL;
  for(;;) { /* txn is an only child at this point */
    fd_funk_txn_t * child = fd_funk_txn_child_head( txn, pool );
    if( !child || !fd_funk_txn_is_only_child( child ) ) break;
    txn = child;
  }
  return txn;
}

/* IMPORTANT SAFETY TIP! **********************************************/

/* fd_funk_txn_{prepare,publish,cancel,cancel_siblings,cancel_children}
   are the pointy end of the stick practically.  As such, these are
   fortified against transaction map memory corruption.  Since any such
   corruption would be prima facie evidence of a hardware fault,
   security compromise or software bug, these will FD_LOG_CRIT if
   corruption is detected to contain the blast radius and get as much
   ultra detailed diagnostic information to user (stack backtrace and
   core) as possible.  (This behavior is straightforward to disable in
   fd_funk_txn.c.) */

/**********************************************************************/

/* fd_funk_txn_prepare starts preparation of a transaction.  The
   transaction will be a child of the in-preparation transaction pointed
   to by parent.  A NULL parent means the transaction should be a child
   of funk.  xid points to transaction id that should be used for the
   transaction.  This id must be unique over all in-preparation
   transactions, the root transaction and the last published
   transaction.  It is strongly recommended to use globally unique ids
   when possible.  Returns a pointer in the caller's address space to
   the in-preparation transaction on success and NULL on failure.  The
   lifetime of the returned pointer is as described in
   fd_funk_txn_query.

   At start of preparation, the records in the txn are a virtual clone of the
   records in its parent transaction.  The funk records can be modified
   when the funk has no children.  Similarly, the records of an
   in-preparation transaction can be freely modified when it has
   no children.

   Assumes funk is a current local join.  Reasons for failure include
   funk is NULL, the funk's transaction map is full, the parent is
   neither NULL nor points to an in-preparation funk transaction, xid is
   NULL, the requested xid is in use (i.e. the last published or matches
   another in-preparation transaction).  If verbose is non-zero, these
   will FD_LOG_WARNING details about the reason for failure.

   This is a reasonably fast O(1) time (theoretical minimum), reasonably
   small O(1) space (theoretical minimum), does no allocation, does no
   system calls, and produces no garbage to collect (at this layer at
   least).  That is, we can scalably track forks until we run out of
   resources allocated to the funk. */

fd_funk_txn_t *
fd_funk_txn_prepare( fd_funk_t *               funk,
                     fd_funk_txn_t *           parent,
                     fd_funk_txn_xid_t const * xid,
                     int                       verbose );

/* fd_funk_txn_cancel cancels in-preparation transaction txn and any of
   its in-preparation descendants.  On success, returns the number of
   transactions cancelled and 0 on failure.  The state of records in the
   cancelled transactions will be lost and all resources used under the
   hood are available for reuse.  If this makes the txn's parent
   childless, this will unfreeze the parent.

   fd_funk_txn_cancel_siblings cancels txn's siblings and their
   descendants.

   fd_funk_txn_cancel_children cancels txn's children and their
   descendants.  If txn is NULL, all children of funk will be cancelled
   (such that the number of transactions in preparation afterward will
   be zero).

   Cancellations proceed from youngest to oldest in a tree depth first
   sense.

   Assumes funk is a current local join.  Reasons for failure include
   NULL funk or txn does not point to an in-preparation funk
   transaction.  If verbose is non-zero, these will FD_LOG_WARNING level
   details about the reason for failure.

   These are a reasonably fast O(number of cancelled transactions) time
   (the theoretical minimum), reasonably small O(1) space (the
   theoretical minimum), does no allocation, does no system calls, and
   produces no garbage to collect (at this layer at least).  That is, we
   can scalably track forks until we run out of resources allocated to
   the funk. */

ulong
fd_funk_txn_cancel( fd_funk_t *     funk,
                    fd_funk_txn_t * txn,
                    int             verbose );

ulong
fd_funk_txn_cancel_siblings( fd_funk_t *     funk,
                             fd_funk_txn_t * txn,
                             int             verbose );

ulong
fd_funk_txn_cancel_children( fd_funk_t *     funk,
                             fd_funk_txn_t * txn,
                             int             verbose );

/* fd_funk_txn_cancel_root cancels all transactions, including the
   root transaction.  Funk is guaranteed to be empty after calling
   this function. */

ulong
fd_funk_txn_cancel_root( fd_funk_t * funk );

/* fd_funk_txn_cancel_all cancels all in-preparation
   transactions. Only the last published transaction remains. */

ulong
fd_funk_txn_cancel_all( fd_funk_t *     funk,
                        int             verbose );

/* fd_funk_txn_publish publishes in-preparation transaction txn and any
   of txn's in-preparation ancestors.  Returns the number of
   transactions published.  Any competing histories to this chain will
   be cancelled.

   Assumes funk is a current local join.  Reasons for failure include
   NULL funk, txn does not point to an in-preparation funk transaction.
   If verbose is non-zero, these will FD_LOG_WARNING the details about
   the reason for failure.

   This is a reasonably fast O(number of published transactions) +
   O(number of cancelled transactions) time (theoretical minimum),
   reasonably small O(1) space (theoretical minimum), does no allocation
   does no system calls, and produces no garbage to collect (at this
   layer at least).  That is, we can scalably track forks until we run
   out of resources allocated to the funk. */

ulong
fd_funk_txn_publish( fd_funk_t *     funk,
                     fd_funk_txn_t * txn,
                     int             verbose );

/* This version of publish just combines the transaction with its
   immediate parent. Ancestors will remain unpublished. Any competing
   histories (siblings of the given transaction) are still cancelled.

   Returns FD_FUNK_SUCCESS on success or an error code on failure. */
int
fd_funk_txn_publish_into_parent( fd_funk_t *     funk,
                                 fd_funk_txn_t * txn,
                                 int             verbose );

/* fd_funk_txn_all_iter_t iterators over all funk transaction objects.
   Usage is:

   fd_funk_txn_all_iter_t txn_iter[1];
   for( fd_funk_txn_all_iter_new( funk, txn_iter ); !fd_funk_txn_all_iter_done( txn_iter ); fd_funk_txn_all_iter_next( txn_iter ) ) {
     fd_funk_txn_t const * txn = fd_funk_txn_all_iter_ele_const( txn_iter );
     ...
   }
*/

struct fd_funk_txn_all_iter {
  fd_funk_txn_map_t txn_map;
  ulong chain_cnt;
  ulong chain_idx;
  fd_funk_txn_map_iter_t txn_map_iter;
};

typedef struct fd_funk_txn_all_iter fd_funk_txn_all_iter_t;

void fd_funk_txn_all_iter_new( fd_funk_t * funk, fd_funk_txn_all_iter_t * iter );

int fd_funk_txn_all_iter_done( fd_funk_txn_all_iter_t * iter );

void fd_funk_txn_all_iter_next( fd_funk_txn_all_iter_t * iter );

fd_funk_txn_t const * fd_funk_txn_all_iter_ele_const( fd_funk_txn_all_iter_t * iter );
fd_funk_txn_t * fd_funk_txn_all_iter_ele( fd_funk_txn_all_iter_t * iter );

/* Misc */

/* fd_funk_txn_verify verifies a transaction map.  Returns
   FD_FUNK_SUCCESS if the transaction map appears intact and
   FD_FUNK_ERR_INVAL if not (logs details).  Meant to be called as part
   of fd_funk_verify. */

int
fd_funk_txn_verify( fd_funk_t * funk );

/* fd_funk_txn_valid returns true if txn appears to be a pointer to
   a valid in-prep transaction. */

int
fd_funk_txn_valid( fd_funk_t const * funk, fd_funk_txn_t const * txn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_txn_h */
