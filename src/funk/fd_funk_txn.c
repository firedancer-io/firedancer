#include "fd_funk_txn.h"
#include "fd_funk.h"

/* Provide the actual transaction map implementation */

#define POOL_NAME          fd_funk_txn_pool
#define POOL_ELE_T         fd_funk_txn_t
#define POOL_IDX_T         uint
#define POOL_NEXT          map_next
#define POOL_IMPL_STYLE    2
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
#define MAP_IMPL_STYLE        2
#include "../util/tmpl/fd_map_chain_para.c"

#define fd_funk_txn_state_transition(txn, before, after) do {             \
  FD_LOG_DEBUG(( "funk_txn laddr=%p xid=%lu:%lu state change (%u-%s) -> (%u-%s)", \
                 (void *)(txn),                                           \
                 (txn)->xid.ul[0], (txn)->xid.ul[1],                      \
                 (before), fd_funk_txn_state_str( (before) ),             \
                 (after),  fd_funk_txn_state_str( (after)  ) ));          \
  if( FD_HAS_ATOMIC ) {                                                   \
    if( FD_LIKELY( __sync_bool_compare_and_swap( &(txn)->state, before, after ) ) ) break; \
  } else {                                                                \
    if( FD_LIKELY( (txn)->state == (before) ) ) {                         \
      (txn)->state = (after);                                             \
      break;                                                              \
    }                                                                     \
  }                                                                       \
  uint have_ = FD_VOLATILE_CONST( (txn)->state );                         \
  FD_LOG_CRIT(( "Detected data race on funk txn %p: expected state %u-%s, found %u-%s, while transitioning to %u-%s", \
                (void *)(txn),                                            \
                (before), fd_funk_txn_state_str( before ),                \
                have_,    fd_funk_txn_state_str( have_  ),                \
                (after),  fd_funk_txn_state_str( after  ) ));             \
} while(0)

#define fd_funk_last_publish_transition(funk_shmem, after) do {           \
    fd_funk_shmem_t *   _shmem    = (funk_shmem);                         \
    fd_funk_txn_xid_t * _last_pub = _shmem->last_publish;                 \
    fd_funk_txn_xid_t   _prev_pub[1]; fd_funk_txn_xid_copy( _prev_pub, _last_pub ); \
    fd_funk_txn_xid_copy( _last_pub, (after) );                           \
    FD_LOG_DEBUG(( "funk last_publish (%lu:%lu) -> (%lu:%lu)",            \
                   _prev_pub->ul[0], _prev_pub->ul[1],                    \
                   _last_pub->ul[0], _last_pub->ul[1] ));                 \
  } while(0)

void
fd_funk_txn_prepare( fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * parent_xid,
                     fd_funk_txn_xid_t const * xid ) {

  if( FD_UNLIKELY( !funk       ) ) FD_LOG_CRIT(( "NULL funk"       ));
  if( FD_UNLIKELY( !parent_xid ) ) FD_LOG_CRIT(( "NULL parent_xid" ));
  if( FD_UNLIKELY( !xid        ) ) FD_LOG_CRIT(( "NULL xid"        ));
  if( FD_UNLIKELY( fd_funk_txn_xid_eq_root( xid ) ) ) FD_LOG_CRIT(( "xid is root" ));

  if( FD_UNLIKELY( fd_funk_txn_xid_eq( xid, funk->shmem->last_publish ) ) ) {
    FD_LOG_ERR(( "fd_funk_txn_prepare failed: xid %lu:%lu is the last published",
                 xid->ul[0], xid->ul[1] ));
  }

  fd_funk_txn_map_query_t query[1];
  if( FD_UNLIKELY( fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 ) != FD_MAP_ERR_KEY ) ) {
    FD_LOG_ERR(( "fd_funk_txn_prepare failed: xid %lu:%lu already in use",
                 xid->ul[0], xid->ul[1] ));
  }

  ulong  parent_idx;
  uint * _child_head_cidx;
  uint * _child_tail_cidx;

  if( FD_UNLIKELY( fd_funk_txn_xid_eq( parent_xid, funk->shmem->last_publish ) ) ) {

    parent_idx = FD_FUNK_TXN_IDX_NULL;

    _child_head_cidx = &funk->shmem->child_head_cidx;
    _child_tail_cidx = &funk->shmem->child_tail_cidx;

  } else {

    int query_err = fd_funk_txn_map_query_try( funk->txn_map, parent_xid, NULL, query, 0 );
    if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) {
      FD_LOG_CRIT(( "fd_funk_txn_prepare failed: user provided invalid parent XID %lu:%lu (err %i-%s)",
                    parent_xid->ul[0], parent_xid->ul[1],
                    query_err, fd_map_strerror( query_err ) ));
    }

    fd_funk_txn_t * parent = fd_funk_txn_map_query_ele( query );
    fd_funk_txn_state_assert( parent, FD_FUNK_TXN_STATE_ACTIVE );
    parent_idx = (ulong)(parent - funk->txn_pool->ele);

    _child_head_cidx = &parent->child_head_cidx;
    _child_tail_cidx = &parent->child_tail_cidx;

  }

  /* Get a new transaction from the map */

  fd_funk_txn_t * txn = fd_funk_txn_pool_acquire( funk->txn_pool, NULL, 1, NULL );
  if( FD_UNLIKELY( !txn ) ) FD_LOG_ERR(( "fd_funk_txn_prepare failed: transaction object pool out of memory" ));
  fd_funk_txn_xid_copy( &txn->xid, xid );
  ulong txn_idx = (ulong)(txn - funk->txn_pool->ele);

  /* Join the family */

  ulong sibling_prev_idx = fd_funk_txn_idx( *_child_tail_cidx );

  int first_born = fd_funk_txn_idx_is_null( sibling_prev_idx );

  txn->parent_cidx       = fd_funk_txn_cidx( parent_idx           );
  txn->child_head_cidx   = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->child_tail_cidx   = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->sibling_prev_cidx = fd_funk_txn_cidx( sibling_prev_idx     );
  txn->sibling_next_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->stack_cidx        = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
  txn->tag               = 0UL;

  fd_funk_txn_state_transition( txn, FD_FUNK_TXN_STATE_FREE, FD_FUNK_TXN_STATE_ACTIVE );
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;

  /* TODO: consider branchless impl */
  if( FD_LIKELY( first_born ) ) *_child_head_cidx                = fd_funk_txn_cidx( txn_idx ); /* opt for non-compete */
  else funk->txn_pool->ele[ sibling_prev_idx ].sibling_next_cidx = fd_funk_txn_cidx( txn_idx );

  *_child_tail_cidx = fd_funk_txn_cidx( txn_idx );

  if( parent_xid ) {
    if( FD_UNLIKELY( fd_funk_txn_map_query_test( query )!=FD_MAP_SUCCESS ) ) {
      FD_LOG_CRIT(( "Detected data race while preparing a funk txn" ));
    }
  }

  fd_funk_txn_map_insert( funk->txn_map, txn, FD_MAP_FLAG_BLOCKING );
}

/* fd_funk_txn_cancel_childless cancels a transaction that is known
   to be childless.  Callers have already validated our input arguments.
   Assumes that cancelling in the app can't fail but that could be
   straightforward to support by giving this an error and plumbing
   through to abort the overall cancel operation when it hits a error. */

static void
fd_funk_txn_cancel_childless( fd_funk_t * funk,
                              ulong       txn_idx ) {

  /* Remove all records used by this transaction.  Note that we don't
     need to bother doing all the individual removal operations as we
     are removing the whole list.  We do reset the record transaction
     idx with NULL though we can detect cycles as soon as possible
     and abort. */

  fd_wksp_t *          wksp     = funk->wksp;
  fd_alloc_t *         alloc    = funk->alloc;
  fd_funk_rec_map_t *  rec_map  = funk->rec_map;
  fd_funk_rec_pool_t * rec_pool = funk->rec_pool;
  ulong                rec_max  = fd_funk_rec_pool_ele_max( rec_pool );
  fd_funk_txn_map_t *  txn_map  = funk->txn_map;
  fd_funk_txn_pool_t * txn_pool = funk->txn_pool;

  fd_funk_txn_t * txn = &txn_pool->ele[ txn_idx ];
  fd_funk_txn_state_assert( txn, FD_FUNK_TXN_STATE_CANCEL );

  uint rec_idx = txn->rec_head_idx;
  while( !fd_funk_rec_idx_is_null( rec_idx ) ) {

    if( FD_UNLIKELY( rec_idx>=rec_max ) ) FD_LOG_CRIT(( "memory corruption detected (bad idx)" ));
    if( FD_UNLIKELY( !fd_funk_txn_xid_eq( rec_pool->ele[ rec_idx ].pair.xid, &txn->xid ) ) )
      FD_LOG_CRIT(( "memory corruption detected (cycle or bad idx)" ));

    fd_funk_rec_t * rec = &rec_pool->ele[ rec_idx ];
    uint next_idx = rec->next_idx;

    for(;;) {
      fd_funk_rec_map_query_t rec_query[1];
      int err = fd_funk_rec_map_remove( rec_map, fd_funk_rec_pair( rec ), NULL, rec_query, FD_MAP_FLAG_BLOCKING );
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      if( err == FD_MAP_ERR_KEY ) break;
      if( FD_UNLIKELY( err != FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "map corruption" ));
      if( rec != fd_funk_rec_map_query_ele( rec_query ) ) break;
      fd_funk_val_flush( rec, alloc, wksp );
      fd_funk_rec_pool_release( rec_pool, rec, 1 );
      break;
    }

    rec_idx = next_idx;
  }

  /* Leave the family */

  ulong sibling_prev_idx = fd_funk_txn_idx( txn->sibling_prev_cidx );
  ulong sibling_next_idx = fd_funk_txn_idx( txn->sibling_next_cidx );

  /* TODO: Consider branchless impl */
  /* FIXME use compare-and-swap here */

  if( FD_LIKELY( fd_funk_txn_idx_is_null( sibling_prev_idx ) ) ) { /* opt for non-compete */
    ulong parent_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].parent_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) { /* No older sib and is a funk child, opt for incr pub */
      funk->shmem->child_head_cidx = fd_funk_txn_cidx( sibling_next_idx );
    } else { /* No older sib and has parent */
      txn_pool->ele[ parent_idx ].child_head_cidx = fd_funk_txn_cidx( sibling_next_idx );
    }
  } else { /* Has older sib */
    txn_pool->ele[ sibling_prev_idx ].sibling_next_cidx = fd_funk_txn_cidx( sibling_next_idx );
  }

  if( FD_LIKELY( fd_funk_txn_idx_is_null( sibling_next_idx ) ) ) { /* opt for non-compete */
    ulong parent_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].parent_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) { /* No younger sib and is a funk child, opt for incr pub */
      funk->shmem->child_tail_cidx = fd_funk_txn_cidx( sibling_prev_idx );
    } else { /* No younger sib and has parent */
      txn_pool->ele[ parent_idx ].child_tail_cidx = fd_funk_txn_cidx( sibling_prev_idx );
    }
  } else { /* Has younger sib */
    txn_pool->ele[ sibling_next_idx ].sibling_prev_cidx = fd_funk_txn_cidx( sibling_prev_idx );
  }

  fd_funk_txn_map_query_t query[1];
  if( fd_funk_txn_map_remove( txn_map, fd_funk_txn_xid( txn ), NULL, query, FD_MAP_FLAG_BLOCKING ) == FD_MAP_SUCCESS ) {
    fd_funk_txn_state_transition( txn, FD_FUNK_TXN_STATE_CANCEL, FD_FUNK_TXN_STATE_FREE );
    fd_funk_txn_pool_release( txn_pool, txn, 1 );
  }
}

/* fd_funk_txn_cancel_family cancels a transaction and all its
   descendants in a tree-depth-first-ordered sense from youngest to
   oldest.  Callers have already validated our input arguments.  Returns
   the number of transactions canceled. */

static ulong
fd_funk_txn_cancel_family( fd_funk_t * funk,
                           ulong       tag,
                           ulong       txn_idx ) {
  ulong cancel_cnt = 0UL;

  ulong parent_stack_idx = FD_FUNK_TXN_IDX_NULL;

  fd_funk_txn_t * txn = &funk->txn_pool->ele[ txn_idx ];
  fd_funk_txn_state_assert( txn, FD_FUNK_TXN_STATE_CANCEL );

  for(;;) {

    txn = &funk->txn_pool->ele[ txn_idx ];
    txn->tag = tag;

    ulong youngest_idx = fd_funk_txn_idx( txn->child_tail_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( youngest_idx ) ) ) { /* txn is is childless, opt for incr pub */

      fd_funk_txn_cancel_childless( funk, txn_idx ); /* If this can fail, return cancel_cnt here on fail */
      cancel_cnt++;

      txn_idx = parent_stack_idx;                                  /* Pop the parent stack */
      if( FD_LIKELY( fd_funk_txn_idx_is_null( txn_idx ) ) ) break; /* If stack is empty, we are done, opt for incr pub */
      parent_stack_idx = fd_funk_txn_idx( funk->txn_pool->ele[ txn_idx ].stack_cidx );
      continue;
    }

    /* txn has at least one child and the youngest is youngest_idx.  Tag
       the youngest child, push txn onto the parent stack and recurse
       into the youngest child. */

    txn->stack_cidx = fd_funk_txn_cidx( parent_stack_idx );
    parent_stack_idx = txn_idx;
    fd_funk_txn_state_transition( &funk->txn_pool->ele[ youngest_idx ], FD_FUNK_TXN_STATE_ACTIVE, FD_FUNK_TXN_STATE_CANCEL );

    txn_idx = youngest_idx;
  }

  return cancel_cnt;
}

ulong
fd_funk_txn_cancel( fd_funk_t *               funk,
                    fd_funk_txn_xid_t const * xid ) {

  if( FD_UNLIKELY( !funk ) ) FD_LOG_CRIT(( "NULL funk" ));
  if( FD_UNLIKELY( !xid  ) ) FD_LOG_CRIT(( "NULL xid"  ));

  fd_funk_txn_map_query_t query[1];
  int map_err = fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( map_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to cancel txn %lu:%lu (%i-%s)",
                  xid->ul[0], xid->ul[1],
                  map_err, fd_map_strerror( map_err ) ));
  }
  fd_funk_txn_t * txn = fd_funk_txn_map_query_ele( query );
  fd_funk_txn_state_transition( txn, FD_FUNK_TXN_STATE_ACTIVE, FD_FUNK_TXN_STATE_CANCEL );
  if( FD_UNLIKELY( fd_funk_txn_map_query_test( query )!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "Detected data race while cancelling a funk txn" ));
  }

  ulong txn_idx = (ulong)(txn - funk->txn_pool->ele);
  return fd_funk_txn_cancel_family( funk, funk->shmem->cycle_tag++, txn_idx );
}

/* fd_funk_txn_oldest_sibling returns the index of the oldest sibling
   in txn_idx's family.  Callers have already validated our input
   arguments.  The caller should validate the return index. */

static inline ulong
fd_funk_txn_oldest_sibling( fd_funk_t *  funk,
                            ulong        txn_idx ) {
  ulong parent_idx = fd_funk_txn_idx( funk->txn_pool->ele[ txn_idx ].parent_cidx );

  if( FD_LIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) return fd_funk_txn_idx( funk->shmem->child_head_cidx ); /* opt for incr pub */

  return fd_funk_txn_idx( funk->txn_pool->ele[ parent_idx ].child_head_cidx );
}

/* fd_funk_txn_cancel_sibling_list cancels siblings from sibling_idx down
   to the youngest sibling inclusive in the order from youngest to
   sibling_idx.  Callers have already validated our input arguments
   except sibling_idx.  Returns the number of cancelled transactions
   (should be at least 1).  If any sibling is skip_idx, it will be not
   be cancelled but still tagged as visited.  Passing
   FD_FUNK_TXN_IDX_NULL for skip_idx will cancel all siblings from
   sibling_idx to the youngest inclusive. */

static ulong
fd_funk_txn_cancel_sibling_list( fd_funk_t * funk,
                                 ulong       tag,
                                 ulong       sibling_idx,
                                 ulong       skip_idx ) {

  ulong cancel_stack_idx = FD_FUNK_TXN_IDX_NULL;

  /* Push siblings_idx and its younger siblings inclusive (skipping
     sibling skip_idx if encounter) onto the cancel stack from oldest to
     youngest (such that we cancel youngest to oldest). */

  for(;;) {

    /* At this point, sibling_idx is a sibling we might want to add to
       the sibling stack.  Validate and tag it. */

    fd_funk_txn_t * sibling = &funk->txn_pool->ele[ sibling_idx ];
    sibling->tag = tag;

    if( FD_UNLIKELY( sibling_idx!=skip_idx ) ) { /* Not skip_idx so push onto the cancel stack, opt for non-compete */
      fd_funk_txn_state_transition( sibling, FD_FUNK_TXN_STATE_ACTIVE, FD_FUNK_TXN_STATE_CANCEL );
      sibling->stack_cidx = fd_funk_txn_cidx( cancel_stack_idx );
      cancel_stack_idx = sibling_idx;
    }

    ulong younger_idx = fd_funk_txn_idx( sibling->sibling_next_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( younger_idx ) ) ) break; /* opt for non-compete */
    sibling_idx = younger_idx;

  }

  /* Cancel all transactions and their descendants on the cancel stack */

  ulong cancel_cnt = 0UL;

  while( !fd_funk_txn_idx_is_null( cancel_stack_idx ) ) { /* TODO: peel first iter to make more predictable? */
    ulong sibling_idx = cancel_stack_idx;
    cancel_stack_idx  = fd_funk_txn_idx( funk->txn_pool->ele[ sibling_idx ].stack_cidx );
    cancel_cnt += fd_funk_txn_cancel_family( funk, tag, sibling_idx );
  }

  return cancel_cnt;
}

ulong
fd_funk_txn_cancel_children( fd_funk_t *               funk,
                             fd_funk_txn_xid_t const * xid ) {

  if( FD_UNLIKELY( !funk ) ) FD_LOG_CRIT(( "NULL funk" ));

  fd_funk_txn_t * txn = NULL;

  ulong oldest_idx;

  if( FD_LIKELY( !xid ) ) {
    oldest_idx = fd_funk_txn_idx( funk->shmem->child_head_cidx ); /* opt for non-compete */
  } else {
    fd_funk_txn_map_query_t query[1];
    int map_err = fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 );
    if( FD_UNLIKELY( map_err!=FD_MAP_SUCCESS ) ) {
      FD_LOG_ERR(( "Failed to publish txn %lu:%lu: err %i", xid->ul[0], xid->ul[1], map_err ));
    }
    txn = fd_funk_txn_map_query_ele( query );
    oldest_idx = fd_funk_txn_idx( txn->child_head_cidx );
  }

  if( fd_funk_txn_idx_is_null( oldest_idx ) ) {
    return 0UL;
  }

  ulong res = fd_funk_txn_cancel_sibling_list( funk, funk->shmem->cycle_tag++, oldest_idx, FD_FUNK_TXN_IDX_NULL );
  if( txn ) fd_funk_txn_state_assert( txn, FD_FUNK_TXN_STATE_ACTIVE );
  return res;
}

void
fd_funk_txn_remove_published( fd_funk_t * funk ) {
  /* Prevent new funk txn objects from spawning */
  if( FD_UNLIKELY( fd_funk_txn_pool_lock( funk->txn_pool, 1 )!=FD_POOL_SUCCESS ) ) {
    FD_LOG_CRIT(( "Failed to remove published txns: fd_funk_txn_pool_lock failed" ));
  }
  if( FD_UNLIKELY( fd_funk_last_publish_is_frozen( funk ) ) ) {
    fd_funk_txn_pool_unlock( funk->txn_pool );
    FD_LOG_ERR(( "Failed to remove published txns: there are still txns in preparation" ));
  }

  fd_wksp_t *          wksp     = funk->wksp;
  fd_alloc_t *         alloc    = funk->alloc;
  fd_funk_rec_map_t *  rec_map  = funk->rec_map;
  fd_funk_rec_pool_t * rec_pool = funk->rec_pool;

  /* Iterate over all funk records and remove them */
  ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    /* FIXME: Chains could be locked while iterating if the remove API
              supported  */
    //ulong lock_seq[1] = {chain_idx};
    //int lock_err = fd_funk_rec_map_iter_lock( rec_map, lock_seq, 1UL, FD_MAP_FLAG_BLOCKING );
    //if( FD_UNLIKELY( lock_err!=FD_MAP_SUCCESS ) ) {
    //  FD_LOG_CRIT(( "fd_funk_rec_map_iter_lock failed (%i-%s)", lock_err, fd_map_strerror( lock_err ) ));
    //}
    for(
        fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter( rec_map, chain_idx );
        !fd_funk_rec_map_iter_done( iter );
    ) {
      fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( iter );
      ulong next = fd_funk_rec_map_private_idx( rec->map_next );;

      /* Remove rec object from map */
      fd_funk_rec_map_query_t rec_query[1];
      int err = fd_funk_rec_map_remove( rec_map, fd_funk_rec_pair( rec ), NULL, rec_query, FD_MAP_FLAG_BLOCKING );
      fd_funk_rec_key_t key; fd_funk_rec_key_copy( &key, rec->pair.key );
      if( FD_UNLIKELY( err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", err, fd_map_strerror( err ) ));

      /* Sanity check: Record belongs to last published XID */
      if( FD_UNLIKELY( !fd_funk_txn_xid_eq_root( rec->pair.xid ) ) ) {
        FD_LOG_ERR(( "Failed to remove published txns: concurrent in-prep record detected" ));
      }

      /* Free rec resources */
      fd_funk_val_flush( rec, alloc, wksp );
      fd_funk_rec_pool_release( rec_pool, rec, 1 );
      iter.ele_idx = next;
    }
    //fd_funk_rec_map_iter_unlock( rec_map, lock_seq, 1UL );
  }

  /* Reset 'last published' XID to 'root' XID */
  fd_funk_txn_xid_t root_xid; fd_funk_txn_xid_set_root( &root_xid );
  fd_funk_last_publish_transition( funk->shmem, &root_xid );

  fd_funk_txn_pool_unlock( funk->txn_pool );
}

/* Cancel all outstanding transactions */

ulong
fd_funk_txn_cancel_all( fd_funk_t * funk ) {
  return fd_funk_txn_cancel_children( funk, NULL );
}

/* fd_funk_txn_update applies the record updates in transaction txn_idx
   to another transaction or the parent transaction.  Callers have
   already validated our input arguments.

   On entry, the head/tail of the destination records are at
   *_dst_rec_head_idx / *_dst_rec_tail_idx.  All transactions on this
   list will have transaction id dst_xid and vice versa.  That is, this
   is the record list the last published transaction or txn_idx's
   in-prep parent transaction.

   On exit, the head/tail of the updated records is at
   *_dst_rec_head_idx / *_dst_rec_tail_idx.  As before, all transactions
   on this list will have transaction id dst_xid and vice versa.
   Transaction txn_idx will have an _empty_ record list.

   Updates in the transaction txn_idx are processed from oldest to
   youngest.  If an update is to update an existing record, the
   destination record value is updated and the order of the destination
   records is unchanged.  If an update is to create a new record, the
   record is appended to the list of existing values as youngest without
   changing the order of existing values.  If an update erases a record
   in an in-prep parent, the erasure will be moved into the parent as
   the youngest without changing the order of existing values. */

static void
fd_funk_txn_update( fd_funk_t *               funk,
                    uint *                    _dst_rec_head_idx, /* Pointer to the dst list head */
                    uint *                    _dst_rec_tail_idx, /* Pointer to the dst list tail */
                    fd_funk_txn_xid_t const * dst_xid,           /* dst xid */
                    ulong                     txn_idx ) {        /* Transaction index of the records to merge */
  fd_wksp_t *          wksp     = funk->wksp;
  fd_alloc_t *         alloc    = funk->alloc;
  fd_funk_rec_map_t *  rec_map  = funk->rec_map;
  fd_funk_rec_pool_t * rec_pool = funk->rec_pool;
  fd_funk_txn_pool_t * txn_pool = funk->txn_pool;

  fd_funk_txn_t * txn = &txn_pool->ele[ txn_idx ];
  fd_funk_txn_state_assert( txn, FD_FUNK_TXN_STATE_PUBLISH );
  uint rec_idx = txn->rec_head_idx;
  while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
    fd_funk_rec_t * rec = &rec_pool->ele[ rec_idx ];
    uint next_rec_idx = rec->next_idx;

    /* See if (dst_xid,key) already exists.  */
    fd_funk_xid_key_pair_t pair[1];
    fd_funk_xid_key_pair_init( pair, dst_xid, rec->pair.key );
    for(;;) {
      fd_funk_rec_map_query_t rec_query[1];
      int err = fd_funk_rec_map_remove( rec_map, pair, NULL, rec_query, FD_MAP_FLAG_BLOCKING );
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      if( err == FD_MAP_ERR_KEY ) break;
      if( FD_UNLIKELY( err != FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "map corruption" ));

      /* Remove from the transaction */
      fd_funk_rec_t * rec2 = fd_funk_rec_map_query_ele( rec_query );
      uint prev_idx = rec2->prev_idx;
      uint next_idx = rec2->next_idx;
      if( fd_funk_rec_idx_is_null( prev_idx ) ) {
        if( _dst_rec_head_idx ) *_dst_rec_head_idx = next_idx;
      } else {
        rec_pool->ele[ prev_idx ].next_idx = next_idx;
      }
      if( fd_funk_rec_idx_is_null( next_idx ) ) {
        if( _dst_rec_tail_idx ) *_dst_rec_tail_idx = prev_idx;
      } else {
        rec_pool->ele[ next_idx ].prev_idx = prev_idx;
      }
      /* Clean up value */
      fd_funk_val_flush( rec2, alloc, wksp );
      fd_funk_rec_pool_release( rec_pool, rec2, 1 );
      break;
    }

    /* Add the new record to the transaction. We can update the xid in
       place because it is not used for hashing the element. We have
       to preserve the original element to preserve the
       newest-to-oldest ordering in the hash
       chain. fd_funk_rec_query_global relies on this subtle
       property. */

    rec->pair.xid[0] = *dst_xid;

    rec->prev_idx = FD_FUNK_REC_IDX_NULL;
    if( _dst_rec_head_idx ) {
      if( fd_funk_rec_idx_is_null( *_dst_rec_head_idx ) ) {
        *_dst_rec_head_idx = rec_idx;
      } else {
        rec_pool->ele[ *_dst_rec_tail_idx ].next_idx = rec_idx;
        rec->prev_idx = *_dst_rec_tail_idx;
      }
      *_dst_rec_tail_idx = rec_idx;
    }
    rec->next_idx = FD_FUNK_REC_IDX_NULL;

    rec_idx = next_rec_idx;
  }

  txn_pool->ele[ txn_idx ].rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn_pool->ele[ txn_idx ].rec_tail_idx = FD_FUNK_REC_IDX_NULL;
}

/* fd_funk_txn_publish_funk_child publishes a transaction that is known
   to be a child of funk.  Callers have already validated our input
   arguments.  Returns FD_FUNK_SUCCESS on success and an FD_FUNK_ERR_*
   code on failure.  (There are currently no failure cases but the
   plumbing is there if value handling requires it at some point.) */

static int
fd_funk_txn_publish_funk_child( fd_funk_t * const funk,
                                ulong       const tag,
                                ulong       const txn_idx ) {

  /* Apply the updates in txn to the last published transactions */

  fd_funk_txn_update( funk, NULL, NULL, fd_funk_root( funk ), txn_idx );

  /* Cancel all competing transaction histories */

  ulong oldest_idx = fd_funk_txn_oldest_sibling( funk, txn_idx );
  fd_funk_txn_cancel_sibling_list( funk, tag, oldest_idx, txn_idx );

  /* Make all the children children of funk */

  fd_funk_txn_t * txn = fd_funk_txn_pool_ele( funk->txn_pool, txn_idx );
  ulong child_head_idx = fd_funk_txn_idx( txn->child_head_cidx );
  ulong child_tail_idx = fd_funk_txn_idx( txn->child_tail_cidx );

  ulong child_idx = child_head_idx;
  while( FD_UNLIKELY( !fd_funk_txn_idx_is_null( child_idx ) ) ) { /* opt for incr pub */
    fd_funk_txn_t * child_txn = fd_funk_txn_pool_ele( funk->txn_pool, child_idx );
    child_txn->tag = tag;
    child_txn->parent_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
    child_idx = fd_funk_txn_idx( child_txn->sibling_next_cidx );
  }

  funk->shmem->child_head_cidx = fd_funk_txn_cidx( child_head_idx );
  funk->shmem->child_tail_cidx = fd_funk_txn_cidx( child_tail_idx );

  fd_funk_last_publish_transition( funk->shmem, fd_funk_txn_xid( txn ) );

  /* Remove the mapping */

  fd_funk_txn_map_query_t query[1];
  int remove_err = fd_funk_txn_map_remove( funk->txn_map, funk->shmem->last_publish, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( remove_err!=FD_MAP_SUCCESS ) {
    FD_LOG_ERR(( "Failed to remove published txn %lu:%lu from map: error %i",
                 funk->shmem->last_publish->ul[0], funk->shmem->last_publish->ul[1],
                 remove_err ));
  }
  fd_funk_txn_state_transition( txn, FD_FUNK_TXN_STATE_PUBLISH, FD_FUNK_TXN_STATE_FREE );
  fd_funk_txn_pool_release( funk->txn_pool, txn, 1 );

  return FD_FUNK_SUCCESS;
}

ulong
fd_funk_txn_publish( fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * xid ) {

  if( FD_UNLIKELY( !funk ) ) FD_LOG_CRIT(( "NULL funk" ));
  if( FD_UNLIKELY( !xid  ) ) FD_LOG_CRIT(( "NULL xid"  ));

  fd_funk_txn_map_query_t query[1];
  int map_err = fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( map_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_ERR(( "Failed to publish txn %lu:%lu (%i-%s)",
                 xid->ul[0], xid->ul[1],
                 map_err, fd_map_strerror( map_err ) ));
  }
  fd_funk_txn_t * txn = fd_funk_txn_map_query_ele( query );
  ulong txn_idx = (ulong)(txn - funk->txn_pool->ele);

  ulong tag = funk->shmem->cycle_tag++; /* FIXME use atomic add */

  ulong publish_stack_idx = FD_FUNK_TXN_IDX_NULL;

  for(;;) {
    fd_funk_txn_t * txn2 = &funk->txn_pool->ele[ txn_idx ];
    fd_funk_txn_state_transition( txn2, FD_FUNK_TXN_STATE_ACTIVE, FD_FUNK_TXN_STATE_PUBLISH );
    txn2->tag = tag;

    /* At this point, txn_idx is a transaction that needs to be
       published and has been tagged.  If txn is a child of funk, we are
       ready to publish txn and everything on the publish stack. */

    ulong parent_idx = fd_funk_txn_idx( txn2->parent_cidx );
    if( FD_LIKELY( fd_funk_txn_idx_is_null( parent_idx ) ) ) break; /* opt for incr pub */

    /* txn_idx has a parent.  Validate and tag it.  Push txn to the
       publish stack and recurse into the parent. */

    txn2->stack_cidx = fd_funk_txn_cidx( publish_stack_idx );
    publish_stack_idx = txn_idx;

    txn_idx = parent_idx;
  }

  ulong publish_cnt = 0UL;

  for(;;) {

    /* At this point, all the transactions we need to publish are
       tagged, txn is the next up publish funk and publish_stack has the
       transactions to follow in order by pop.  We use a new tag for
       each publish as txn and its siblings we potentially visited in a
       previous iteration of this loop. */

    if( FD_UNLIKELY( fd_funk_txn_publish_funk_child( funk, funk->shmem->cycle_tag++, txn_idx ) ) ) break;
    publish_cnt++;

    txn_idx = publish_stack_idx;
    if( FD_LIKELY( fd_funk_txn_idx_is_null( txn_idx ) ) ) break; /* opt for incr pub */
    publish_stack_idx = fd_funk_txn_idx( funk->txn_pool->ele[ txn_idx ].stack_cidx );
  }

  return publish_cnt;
}

void
fd_funk_txn_publish_into_parent( fd_funk_t *               funk,
                                 fd_funk_txn_xid_t const * xid ) {
  if( FD_UNLIKELY( !funk ) ) FD_LOG_CRIT(( "NULL funk" ));
  if( FD_UNLIKELY( !xid  ) ) FD_LOG_CRIT(( "NULL xid"  ));

  fd_funk_txn_map_query_t query[1];
  int map_err = fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( map_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_ERR(( "Failed to publish txn %lu:%lu: err %i", xid->ul[0], xid->ul[1], map_err ));
  }
  fd_funk_txn_t * txn = fd_funk_txn_map_query_ele( query );
  fd_funk_txn_state_transition( txn, FD_FUNK_TXN_STATE_ACTIVE, FD_FUNK_TXN_STATE_PUBLISH );
  if( FD_UNLIKELY( fd_funk_txn_map_query_test( query )!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "Detected data race while publishing a funk txn" ));
  }

  fd_funk_txn_map_t *  txn_map  = funk->txn_map;
  fd_funk_txn_pool_t * txn_pool = funk->txn_pool;
  ulong txn_idx = (ulong)(txn - txn_pool->ele);

  ulong oldest_idx = fd_funk_txn_oldest_sibling( funk, txn_idx );
  fd_funk_txn_cancel_sibling_list( funk, funk->shmem->cycle_tag++, oldest_idx, txn_idx );

  ulong parent_idx = fd_funk_txn_idx( txn->parent_cidx );
  if( fd_funk_txn_idx_is_null( parent_idx ) ) {
    /* Publish to root */
    fd_funk_txn_update( funk, NULL, NULL, fd_funk_root( funk ), txn_idx );
    /* Inherit the children */
    funk->shmem->child_head_cidx = txn->child_head_cidx;
    funk->shmem->child_tail_cidx = txn->child_tail_cidx;
  } else {
    fd_funk_txn_t * parent_txn = &txn_pool->ele[ parent_idx ];
    fd_funk_txn_update( funk, &parent_txn->rec_head_idx, &parent_txn->rec_tail_idx, &parent_txn->xid, txn_idx );
    /* Inherit the children */
    parent_txn->child_head_cidx = txn->child_head_cidx;
    parent_txn->child_tail_cidx = txn->child_tail_cidx;
  }

  /* Adjust the parent pointers of the children to point to their grandparent */
  ulong child_idx = fd_funk_txn_idx( txn->child_head_cidx );
  while( FD_UNLIKELY( !fd_funk_txn_idx_is_null( child_idx ) ) ) {
    txn_pool->ele[ child_idx ].parent_cidx = fd_funk_txn_cidx( parent_idx );
    child_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_next_cidx );
  }

  if( fd_funk_txn_idx_is_null( parent_idx ) ) {
    fd_funk_last_publish_transition( funk->shmem, xid );
  }

  if( fd_funk_txn_map_remove( txn_map, xid, NULL, query, FD_MAP_FLAG_BLOCKING )!=FD_MAP_SUCCESS ) {
    FD_LOG_ERR(( "Failed to remove published txn %lu:%lu from map: error %i",
                 xid->ul[0], xid->ul[1],
                 map_err ));
  }
  fd_funk_txn_state_transition( txn, FD_FUNK_TXN_STATE_PUBLISH, FD_FUNK_TXN_STATE_FREE );
  fd_funk_txn_pool_release( txn_pool, txn, 1 );
}

fd_funk_rec_t const *
fd_funk_txn_first_rec( fd_funk_t *           funk,
                       fd_funk_txn_t const * txn ) {
  if( FD_UNLIKELY( !txn ) ) return NULL;
  uint rec_idx = txn->rec_head_idx;
  if( fd_funk_rec_idx_is_null( rec_idx ) ) return NULL;
  return funk->rec_pool->ele + rec_idx;
}

fd_funk_rec_t const *
fd_funk_txn_last_rec( fd_funk_t *           funk,
                      fd_funk_txn_t const * txn ) {
  if( FD_UNLIKELY( !txn ) ) return NULL;
  uint rec_idx = txn->rec_tail_idx;
  if( fd_funk_rec_idx_is_null( rec_idx ) ) return NULL;
  return funk->rec_pool->ele + rec_idx;
}

/* Return the next record in a transaction. Returns NULL if the
   transaction has no more records. */

fd_funk_rec_t const *
fd_funk_txn_next_rec( fd_funk_t *           funk,
                      fd_funk_rec_t const * rec ) {
  uint rec_idx = rec->next_idx;
  if( fd_funk_rec_idx_is_null( rec_idx ) ) return NULL;
  return funk->rec_pool->ele + rec_idx;
}

fd_funk_rec_t const *
fd_funk_txn_prev_rec( fd_funk_t *           funk,
                      fd_funk_rec_t const * rec ) {
  uint rec_idx = rec->prev_idx;
  if( fd_funk_rec_idx_is_null( rec_idx ) ) return NULL;
  return funk->rec_pool->ele + rec_idx;
}

fd_funk_txn_xid_t
fd_funk_generate_xid(void) {
  fd_funk_txn_xid_t xid;
  static FD_TL ulong seq = 0;
  xid.ul[0] =
    (fd_log_cpu_id() + 1U)*3138831853UL +
    (fd_log_thread_id() + 1U)*9180195821UL +
    (++seq)*6208101967UL;
  xid.ul[1] = ((ulong)fd_tickcount())*2810745731UL;
  return xid;
}

int
fd_funk_txn_verify( fd_funk_t * funk ) {
  fd_funk_txn_map_t *  txn_map  = funk->txn_map;
  fd_funk_txn_pool_t * txn_pool = funk->txn_pool;
  ulong                txn_max  = fd_funk_txn_pool_ele_max( txn_pool );

  ulong funk_child_head_idx = fd_funk_txn_idx( funk->shmem->child_head_cidx ); /* Previously verified */
  ulong funk_child_tail_idx = fd_funk_txn_idx( funk->shmem->child_tail_cidx ); /* Previously verified */

  fd_funk_txn_xid_t const * last_publish = funk->shmem->last_publish; /* Previously verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

# define IS_VALID( idx ) ( (idx==FD_FUNK_TXN_IDX_NULL) || \
                           ((idx<txn_max) && (!fd_funk_txn_xid_eq( fd_funk_txn_xid( &txn_pool->ele[idx] ), last_publish ))) )

  TEST( !fd_funk_txn_map_verify( txn_map ) );
  TEST( !fd_funk_txn_pool_verify( txn_pool ) );

  /* Tag all transactions as not visited yet */

  for( ulong txn_idx=0UL; txn_idx<txn_max; txn_idx++ ) txn_pool->ele[ txn_idx ].tag = 0UL;

  /* Visit all transactions in preparation, traversing from oldest to
     youngest. */

  do {

    /* Push all children of funk to the stack */

    ulong stack_idx = FD_FUNK_TXN_IDX_NULL;
    ulong child_idx = funk_child_head_idx;
    while( !fd_funk_txn_idx_is_null( child_idx ) ) {

      /* Make sure valid idx, not tagged (detects cycles) and child
         knows it is a child of funk.  Then tag as visited / in-prep,
         push to stack and update prep_cnt */

      TEST( IS_VALID( child_idx ) );
      TEST( !txn_pool->ele[ child_idx ].tag );
      TEST( fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn_pool->ele[ child_idx ].parent_cidx ) ) );
      txn_pool->ele[ child_idx ].tag        = 1UL;
      txn_pool->ele[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
      stack_idx                   = child_idx;

      ulong next_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_next_cidx );
      if( !fd_funk_txn_idx_is_null( next_idx ) ) TEST( fd_funk_txn_idx( txn_pool->ele[ next_idx ].sibling_prev_cidx )==child_idx );
      child_idx = next_idx;
    }

    while( !fd_funk_txn_idx_is_null( stack_idx ) ) {

      /* Pop the next transaction to traverse */

      ulong txn_idx = stack_idx;
      stack_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].stack_cidx );

      /* Push all children of txn to the stack */

      ulong child_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].child_head_cidx );
      while( !fd_funk_txn_idx_is_null( child_idx ) ) {

        /* Make sure valid idx, not tagged (detects cycles) and child
           knows it is a child of txn_idx.  Then tag as visited /
           in-prep, push to stack and update prep_cnt */

        TEST( IS_VALID( child_idx ) );
        TEST( !txn_pool->ele[ child_idx ].tag );
        TEST( fd_funk_txn_idx( txn_pool->ele[ child_idx ].parent_cidx )==txn_idx );
        txn_pool->ele[ child_idx ].tag        = 1UL;
        txn_pool->ele[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
        stack_idx                   = child_idx;

        ulong next_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_next_cidx );
        if( !fd_funk_txn_idx_is_null( next_idx ) ) TEST( fd_funk_txn_idx( txn_pool->ele[ next_idx ].sibling_prev_cidx )==child_idx );
        child_idx = next_idx;
      }
    }

  } while(0);

  /* Do it again with a youngest to oldest traversal to test reverse
     link integrity */

  do {

    /* Push all children of funk to the stack */

    ulong stack_idx = FD_FUNK_TXN_IDX_NULL;
    ulong child_idx = funk_child_tail_idx;
    while( !fd_funk_txn_idx_is_null( child_idx ) ) {

      /* Make sure valid idx, tagged as visited above (detects cycles)
         and child knows it is a child of funk.  Then tag as visited /
         in-prep, push to stack and update prep_cnt */

      TEST( IS_VALID( child_idx ) );
      TEST( txn_pool->ele[ child_idx ].tag==1UL );
      TEST( fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn_pool->ele[ child_idx ].parent_cidx ) ) );
      txn_pool->ele[ child_idx ].tag        = 2UL;
      txn_pool->ele[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
      stack_idx                             = child_idx;

      ulong prev_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_prev_cidx );
      if( !fd_funk_txn_idx_is_null( prev_idx ) ) TEST( fd_funk_txn_idx( txn_pool->ele[ prev_idx ].sibling_next_cidx )==child_idx );
      child_idx = prev_idx;
    }

    while( !fd_funk_txn_idx_is_null( stack_idx ) ) {

      /* Pop the next transaction to traverse */

      ulong txn_idx = stack_idx;
      stack_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].stack_cidx );

      /* Push all children of txn to the stack */

      ulong child_idx = fd_funk_txn_idx( txn_pool->ele[ txn_idx ].child_tail_cidx );
      while( !fd_funk_txn_idx_is_null( child_idx ) ) {

        /* Make sure valid idx, tagged as visited above (detects cycles)
           and child knows it is a child of txn_idx.  Then, tag as
           visited / in-prep, push to stack and update prep_cnt */

        TEST( IS_VALID( child_idx ) );
        TEST( txn_pool->ele[ child_idx ].tag==1UL );
        TEST( fd_funk_txn_idx( txn_pool->ele[ child_idx ].parent_cidx )==txn_idx );
        txn_pool->ele[ child_idx ].tag        = 2UL;
        txn_pool->ele[ child_idx ].stack_cidx = fd_funk_txn_cidx( stack_idx );
        stack_idx                             = child_idx;

        ulong prev_idx = fd_funk_txn_idx( txn_pool->ele[ child_idx ].sibling_prev_cidx );
        if( !fd_funk_txn_idx_is_null( prev_idx ) ) TEST( fd_funk_txn_idx( txn_pool->ele[ prev_idx ].sibling_next_cidx )==child_idx );
        child_idx = prev_idx;
      }
    }
  } while(0);

# undef IS_VALID
# undef TEST

  return FD_FUNK_SUCCESS;
}

int
fd_funk_txn_valid( fd_funk_t const * funk, fd_funk_txn_t const * txn ) {
  ulong txn_idx = (ulong)(txn - funk->txn_pool->ele);
  ulong txn_max = fd_funk_txn_pool_ele_max( funk->txn_pool );
  if( txn_idx>=txn_max || txn != txn_idx + funk->txn_pool->ele ) return 0;
  fd_funk_txn_map_query_t query[1];
  int    err  = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    err = fd_funk_txn_map_query_try( funk->txn_map, &txn->xid, NULL, query, 0 );
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY ) ) {
      FD_LOG_DEBUG(( "fd_funk_txn_map_query_try() failed: %d on chain %lu", err, fd_funk_txn_map_iter_chain_idx( funk->txn_map, &txn->xid ) ));
      return 0;
    }
    if( FD_UNLIKELY( err == FD_MAP_ERR_CORRUPT ) ) {
      FD_LOG_WARNING(( "fd_funk_txn_map_query_try() failed: %d on chain %lu", err, fd_funk_txn_map_iter_chain_idx( funk->txn_map, &txn->xid ) ));
      return 0;
    }
    if( FD_LIKELY( err == FD_MAP_SUCCESS ) ) {
      if( fd_funk_txn_map_query_ele( query ) != txn ) {
        FD_LOG_WARNING(( "fd_funk_txn_map_query_ele() failed: %p != %p", (void *)fd_funk_txn_map_query_ele( query ), (void *)txn ));
        return 0;
      }
      break;
    }
    /* Normally we'd do this, but we didn't really do any non-atomic reads of element fields.
       err = fd_funk_txn_map_query_test( query ); */
  }
  return 1;
}
