#ifndef HEADER_fd_src_funk_fd_funk_txn_h
#define HEADER_fd_src_funk_fd_funk_txn_h

/* This provides APIs for managing forks (preparing, publishing and
   cancelling funk transactions).  It is generally not meant to be
   included directly.  Use fd_funk.h instead.

   Funk transaction-level operations are not thread-safe.  External
   synchronization (e.g. mutex) is required when doing txn operations
   when other txn or rec operations may be concurrently running on other
   threads. */

#include "fd_funk_base.h"
#include "../flamenco/fd_rwlock.h"

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

  /* These fields are managed by the funk */

  uint   parent_cidx;       /* compr map index of the in-prep parent         txn, compr FD_FUNK_TXN_IDX_NULL if a funk child */
  uint   child_head_cidx;   /* "                              oldest   child      "                             childless */
  uint   child_tail_cidx;   /* "                              youngest child                                    childless */
  uint   sibling_prev_cidx; /* "                              older sibling                                     oldest sibling */
  uint   sibling_next_cidx; /* "                              younger sibling                                   youngest sibling */
  uint   stack_cidx;        /* Internal use by funk */
  ulong  tag;               /* Internal use by funk */

  uint  rec_head_idx;       /* Record map index of the first record, FD_FUNK_REC_IDX_NULL if none (from oldest to youngest) */
  uint  rec_tail_idx;       /* "                       last          " */

  uint  state;              /* one of FD_FUNK_TXN_STATE_* */

  fd_rwlock_t lock[1];
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
#define MAP_MAGIC             (0xf173da2ce7172db0UL) /* Firedancer txn db version 0 */
#define MAP_IMPL_STYLE        1
#include "../util/tmpl/fd_map_chain_para.c"
#undef  MAP_HASH

/* Funk transaction states */

#define FD_FUNK_TXN_STATE_FREE    (0U)
#define FD_FUNK_TXN_STATE_ACTIVE  (1U)
#define FD_FUNK_TXN_STATE_CANCEL  (2U)
#define FD_FUNK_TXN_STATE_PUBLISH (3U)

FD_PROTOTYPES_BEGIN

/* fd_funk_txn_{cidx,idx} convert between an index and a compressed index. */

static inline uint  fd_funk_txn_cidx( ulong idx  ) { return (uint)  idx; }
static inline ulong fd_funk_txn_idx ( uint  cidx ) { return (ulong)cidx; }

/* fd_funk_txn_idx_is_null returns 1 if idx is FD_FUNK_TXN_IDX_NULL and
   0 otherwise. */

static inline int fd_funk_txn_idx_is_null( ulong idx ) { return idx==FD_FUNK_TXN_IDX_NULL; }

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

typedef struct fd_funk_rec fd_funk_rec_t;

/* Operations */
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
   another in-preparation transaction).

   This is a reasonably fast O(1) time (theoretical minimum), reasonably
   small O(1) space (theoretical minimum), does no allocation, does no
   system calls, and produces no garbage to collect (at this layer at
   least).  That is, we can scalably track forks until we run out of
   resources allocated to the funk. */

void
fd_funk_txn_prepare( fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * parent,
                     fd_funk_txn_xid_t const * xid );

/* Misc */

/* fd_funk_txn_verify verifies a transaction map.  Returns
   FD_FUNK_SUCCESS if the transaction map appears intact and
   FD_FUNK_ERR_INVAL if not (logs details).  Meant to be called as part
   of fd_funk_verify. */

int
fd_funk_txn_verify( fd_funk_t * funk );

FD_FN_UNUSED static char const *
fd_funk_txn_state_str( uint state ) {
  switch( state ) {
  case FD_FUNK_TXN_STATE_FREE:    return "free";
  case FD_FUNK_TXN_STATE_ACTIVE:  return "alive";
  case FD_FUNK_TXN_STATE_CANCEL:  return "cancel";
  case FD_FUNK_TXN_STATE_PUBLISH: return "publish";
  default:                        return "unknown";
  }
}

#ifndef __cplusplus

FD_FN_UNUSED static void
fd_funk_txn_state_assert( fd_funk_txn_t const * txn,
                          uint                  want ) {
  uint have = FD_VOLATILE_CONST( txn->state );
  if( FD_UNLIKELY( want!=have ) ) {
    FD_LOG_CRIT(( "Invariant violation detected on funk txn: expected state %u-%s, found state %u-%s",
                  want, fd_funk_txn_state_str( want ),
                  have, fd_funk_txn_state_str( have ) ));
  }
}

FD_FN_UNUSED static void
fd_funk_txn_xid_assert( fd_funk_txn_t const *     txn,
                        fd_funk_txn_xid_t const * xid ) {
  uint              found_state = FD_VOLATILE_CONST( txn->state );
  fd_funk_txn_xid_t found_xid   = FD_VOLATILE_CONST( txn->xid   );
  int               xid_ok      = fd_funk_txn_xid_eq( &found_xid, xid );
  int               state_ok    = found_state==FD_FUNK_TXN_STATE_ACTIVE;
  if( FD_UNLIKELY( !xid_ok || !state_ok ) ) {
    if( !xid_ok ) {
      FD_LOG_CRIT(( "Data race detected: funk txn %p %lu:%lu use-after-free",
                    (void *)txn,
                    xid->ul[0], xid->ul[1] ));
    } else {
      FD_LOG_CRIT(( "Data race detected: funk txn %p %lu:%lu in invalid state %u-%s",
                    (void *)txn,
                    xid->ul[0], xid->ul[1],
                    found_state, fd_funk_txn_state_str( found_state ) ));
    }
  }
}

#endif /* !__cplusplus */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_txn_h */
