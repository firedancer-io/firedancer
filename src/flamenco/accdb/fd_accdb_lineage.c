#include "fd_accdb_lineage.h"
#include "../../funk/fd_funk.h"

void
fd_accdb_lineage_set_fork_slow( fd_accdb_lineage_t *      lineage,
                                fd_funk_t const *         funk,
                                fd_funk_txn_xid_t const * xid ) {
  fd_funk_txn_xid_t     next_xid = *xid;
  fd_funk_txn_t const * tip      = NULL;

  /* Walk transaction graph, recovering from overruns on-the-fly */
  lineage->fork_depth = 0UL;

  ulong txn_max = fd_funk_txn_pool_ele_max( funk->txn_pool );
  ulong i;
  for( i=0UL; i<FD_ACCDB_DEPTH_MAX; i++ ) {
    fd_funk_txn_map_query_t query[1];
    fd_funk_txn_t const *   candidate;
    fd_funk_txn_xid_t       found_xid;
    ulong                   parent_idx;
    fd_funk_txn_xid_t       parent_xid;
retry:
    /* Speculatively look up transaction from map */
    for(;;) {
      int query_err = fd_funk_txn_map_query_try( funk->txn_map, &next_xid, NULL, query, 0 );
      if( FD_UNLIKELY( query_err==FD_MAP_ERR_AGAIN ) ) {
        /* FIXME random backoff */
        FD_SPIN_PAUSE();
        continue;
      }
      if( query_err==FD_MAP_ERR_KEY ) goto done;
      if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) {
        FD_LOG_CRIT(( "fd_funk_txn_map_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
      }
      break;
    }

    /* Lookup parent transaction while recovering from overruns
       FIXME This would be a lot easier if transactions specified
             parent by XID instead of by pointer ... */
    candidate = fd_funk_txn_map_query_ele_const( query );
    FD_COMPILER_MFENCE();
    do {
      found_xid  = FD_VOLATILE_CONST( candidate->xid );
      parent_idx = fd_funk_txn_idx( FD_VOLATILE_CONST( candidate->parent_cidx ) );
      if( fd_funk_txn_idx_is_null( parent_idx ) ) break;
      if( FD_UNLIKELY( parent_idx>=txn_max ) ) FD_LOG_CRIT(( "corrupt txn parent idx %lu", parent_idx ));

      FD_COMPILER_MFENCE();
      fd_funk_txn_t const * parent = &funk->txn_pool->ele[ parent_idx ];
      parent_xid = FD_VOLATILE_CONST( parent->xid );
      FD_COMPILER_MFENCE();

      parent_idx = fd_funk_txn_idx( FD_VOLATILE_CONST( candidate->parent_cidx ) );
      if( fd_funk_txn_idx_is_null( parent_idx ) ) break;
      if( FD_UNLIKELY( parent_idx>=txn_max ) ) FD_LOG_CRIT(( "corrupt txn parent idx %lu", parent_idx ));
    } while(0);
    FD_COMPILER_MFENCE();

    /* Verify speculative loads by ensuring txn still exists in map */
    if( FD_UNLIKELY( fd_funk_txn_map_query_test( query )!=FD_MAP_SUCCESS ) ) {
      FD_SPIN_PAUSE();
      goto retry;
    }

    if( FD_UNLIKELY( !fd_funk_txn_xid_eq( &found_xid, &next_xid ) ) ) {
      FD_LOG_CRIT(( "fd_accdb_load_fork_slow detected memory corruption: expected xid %lu:%lu at %p, found %lu:%lu",
                    next_xid.ul[0], next_xid.ul[1],
                    (void *)candidate,
                    found_xid.ul[0], found_xid.ul[1] ));
    }

    if( !tip ) tip = candidate;  /* remember head of fork */
    lineage->fork[ i ] = next_xid;
    if( fd_funk_txn_idx_is_null( parent_idx ) ) {
      /* Reached root */
      i++;
      break;
    }
    next_xid = parent_xid;
  }

done:
  lineage->fork_depth = i;
  if( FD_UNLIKELY( lineage->fork_depth==FD_ACCDB_DEPTH_MAX ) ) {
    FD_LOG_CRIT(( "Account database fork depth exceeded max of %lu", FD_ACCDB_DEPTH_MAX ));
  }

  /* FIXME crash if fork depth greater than cache depth */
  if( lineage->fork_depth < FD_ACCDB_DEPTH_MAX ) {
    fd_funk_txn_xid_set_root( &lineage->fork[ lineage->fork_depth++ ] );
  }

  /* Remember head of fork */
  if( tip ) {
    lineage->tip_txn_idx = (ulong)( tip - funk->txn_pool->ele );
    fd_funk_txn_state_assert( tip, FD_FUNK_TXN_STATE_ACTIVE );
  } else {
    lineage->tip_txn_idx = ULONG_MAX;  /* XID is rooted */
  }
}

fd_funk_txn_t *
fd_accdb_lineage_write_check( fd_accdb_lineage_t const * lineage,
                              fd_funk_t const *          funk ) {
  ulong txn_idx = lineage->tip_txn_idx;
  fd_funk_txn_xid_t const * xid = &lineage->fork[ 0 ];
  if( FD_UNLIKELY( txn_idx==ULONG_MAX ) ) {
    FD_LOG_CRIT(( "write failed: XID %lu:%lu is rooted", xid->ul[0], xid->ul[1] ));
  }
  if( FD_UNLIKELY( txn_idx >= fd_funk_txn_pool_ele_max( funk->txn_pool ) ) ) {
    FD_LOG_CRIT(( "memory corruption detected: invalid txn_idx %lu (max %lu)",
                  txn_idx, fd_funk_txn_pool_ele_max( funk->txn_pool ) ));
  }
  fd_funk_txn_t * txn = &funk->txn_pool->ele[ txn_idx ];
  if( FD_UNLIKELY( !fd_funk_txn_xid_eq( &txn->xid, xid ) ) ) {
    FD_LOG_CRIT(( "Failed to modify account: data race detected on fork node (expected XID %lu:%lu, found %lu:%lu)",
                  xid->ul[0],     xid->ul[1],
                  txn->xid.ul[0], txn->xid.ul[1] ));
  }
  if( FD_UNLIKELY( fd_funk_txn_is_frozen( txn ) ) ) {
    FD_LOG_CRIT(( "Failed to modify account: XID %lu:%lu has children/is frozen", xid->ul[0], xid->ul[1] ));
  }
  return txn;
}
