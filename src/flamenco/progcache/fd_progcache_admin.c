#include "fd_progcache.h"
#include "fd_progcache_admin.h"
#include "fd_progcache_base.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_rec.h"
#include "fd_progcache_reclaim.h"
#include "fd_progcache_xid.h"
#include "../../util/racesan/fd_racesan_target.h"

/* FIXME get rid of this thread-local */
FD_TL fd_progcache_admin_metrics_t fd_progcache_admin_metrics_g;

/* Begin transaction-level operations.  It is assumed that txn data
   structures are not concurrently modified.  This includes txn_pool and
   txn_map. */

fd_progcache_fork_id_t
fd_progcache_attach_child( fd_progcache_join_t *  cache,
                           fd_progcache_fork_id_t parent_fork_id ) {
  if( FD_UNLIKELY( !cache ) ) FD_LOG_CRIT(( "invalid arguments" ));

  fd_rwlock_write( &cache->shmem->txn.rwlock );
  if( FD_UNLIKELY( fd_prog_txnp_free( cache->txn.pool )==0UL ) ) {
    FD_LOG_ERR(( "fd_progcache_attach_child failed: transaction object pool out of memory" ));
  }

  ulong  txn_max = fd_prog_txnp_max( cache->txn.pool );
  ulong  parent_idx;
  uint * _child_head_idx;
  uint * _child_tail_idx;

  fd_progcache_fork_id_t root = __atomic_load_n( &cache->shmem->txn.root, memory_order_relaxed );
  if( FD_UNLIKELY( parent_fork_id == root ) ) {

    parent_idx = FD_PROGCACHE_TXN_IDX_NULL;

    _child_head_idx = &cache->shmem->txn.child_head_idx;
    _child_tail_idx = &cache->shmem->txn.child_tail_idx;

  } else {

    parent_idx = fd_prog_txnm_idx_query( cache->txn.map, &parent_fork_id, ULONG_MAX, cache->txn.pool );
    if( FD_UNLIKELY( parent_idx==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "fd_progcache_attach_child failed: user provided invalid parent fork_id %lu", parent_fork_id ));
    }
    if( FD_UNLIKELY( parent_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (attach_child parent_idx=%lu txn_max=%lu)", parent_idx, txn_max ));

    _child_head_idx = &cache->txn.pool[ parent_idx ].child_head_idx;
    _child_tail_idx = &cache->txn.pool[ parent_idx ].child_tail_idx;

  }

  uint txn_idx = (uint)fd_prog_txnp_idx_acquire( cache->txn.pool );
  if( FD_UNLIKELY( txn_idx==UINT_MAX ) ) FD_LOG_ERR(( "fd_progcache_attach_child failed: transaction object pool out of memory" ));
  fd_progcache_txn_t * txn = &cache->txn.pool[ txn_idx ];
  txn->xid = __atomic_add_fetch( &cache->shmem->txn.seq, 1UL, memory_order_relaxed );

  uint sibling_prev_idx = *_child_tail_idx;

  int first_born = sibling_prev_idx==UINT_MAX;
  if( FD_UNLIKELY( !first_born && (ulong)sibling_prev_idx >= txn_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (attach_child sibling_prev_idx=%u txn_max=%lu)", sibling_prev_idx, txn_max ));

  txn->parent_idx       = (uint)parent_idx;
  txn->child_head_idx   = UINT_MAX;
  txn->child_tail_idx   = UINT_MAX;
  txn->sibling_prev_idx = (uint)sibling_prev_idx;
  txn->sibling_next_idx = UINT_MAX;

  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;

  /* TODO: consider branchless impl */
  if( FD_LIKELY( first_born ) ) *_child_head_idx            = (uint)txn_idx; /* opt for non-compete */
  else cache->txn.pool[ sibling_prev_idx ].sibling_next_idx = (uint)txn_idx;

  *_child_tail_idx = (uint)txn_idx;

  fd_prog_txnm_idx_insert( cache->txn.map, txn_idx, cache->txn.pool );

  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );
  return txn->xid;
}

static void
fd_progcache_cancel_one( fd_progcache_join_t * cache,
                         fd_progcache_txn_t *  txn ) {
  ulong rec_max = cache->rec.max;
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );

  fd_rwlock_write( &txn->lock );

  if( FD_UNLIKELY( txn->child_head_idx!=UINT_MAX ||
                   txn->child_tail_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_cancel failed: txn at %p with fork_id %lu has children (data corruption?)",
                  (void *)txn, txn->xid ));
  }

  /* Remove records */

  for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; ) {
    if( FD_UNLIKELY( (ulong)idx >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one rec_idx=%u rec_max=%lu)", idx, rec_max ));
    fd_progcache_rec_t * rec = &cache->rec.ele[ idx ];
    uint next_idx = rec->next_idx;
    if( FD_UNLIKELY( next_idx!=UINT_MAX && (ulong)next_idx >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one next_idx=%u rec_max=%lu)", next_idx, rec_max ));
    atomic_store_explicit( &rec->txn_idx, UINT_MAX, memory_order_release );
    fd_racesan_hook( "prog_cancel_one:post_orphan" );
    fd_prog_delete_rec( cache, rec );
    idx = next_idx;
  }

  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;

  /* Remove transaction from fork graph */

  uint self_idx = (uint)( txn - cache->txn.pool );
  uint prev_idx = txn->sibling_prev_idx;
  uint next_idx = txn->sibling_next_idx;
  if( next_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)next_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one sibling_next_idx=%u txn_max=%lu)", next_idx, txn_max ));
    cache->txn.pool[ next_idx ].sibling_prev_idx = prev_idx;
  }
  if( prev_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)prev_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one sibling_prev_idx=%u txn_max=%lu)", prev_idx, txn_max ));
    cache->txn.pool[ prev_idx ].sibling_next_idx = next_idx;
  }
  if( txn->parent_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)txn->parent_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one parent_idx=%u txn_max=%lu)", txn->parent_idx, txn_max ));
    fd_progcache_txn_t * parent = &cache->txn.pool[ txn->parent_idx ];
    if( parent->child_head_idx==self_idx ) parent->child_head_idx = next_idx;
    if( parent->child_tail_idx==self_idx ) parent->child_tail_idx = prev_idx;
  } else {
    if( cache->shmem->txn.child_head_idx==self_idx ) cache->shmem->txn.child_head_idx = next_idx;
    if( cache->shmem->txn.child_tail_idx==self_idx ) cache->shmem->txn.child_tail_idx = prev_idx;
  }

  /* Remove transaction from index */

  if( FD_UNLIKELY( !fd_prog_txnm_ele_remove( cache->txn.map, &txn->xid, NULL, cache->txn.pool ) ) ) {
    FD_LOG_CRIT(( "fd_progcache_cancel failed: fd_prog_txnm_ele_remove(%lu) failed", txn->xid ));
  }

  /* Free transaction object */

  fd_rwlock_unwrite( &txn->lock );
  fd_prog_txnp_ele_release( cache->txn.pool, txn );
}

/* Cancels txn and all children */

static void
fd_progcache_cancel_tree( fd_progcache_join_t * cache,
                          fd_progcache_txn_t *  txn ) {
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  for(;;) {
    uint child_idx = txn->child_head_idx;
    if( child_idx==UINT_MAX ) break;
    if( FD_UNLIKELY( (ulong)child_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_tree child_idx=%u txn_max=%lu)", child_idx, txn_max ));
    fd_progcache_txn_t * child = &cache->txn.pool[ child_idx ];
    fd_progcache_cancel_tree( cache, child );
  }
  fd_progcache_cancel_one( cache, txn );
}

/* Cancels all left/right siblings */

static void
fd_progcache_cancel_prev_list( fd_progcache_join_t * cache,
                               fd_progcache_txn_t *  txn ) {
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  uint cur_idx = txn->sibling_prev_idx;
  while( cur_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)cur_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_prev_list txn_idx=%u txn_max=%lu)", cur_idx, txn_max ));
    fd_progcache_txn_t * sibling = &cache->txn.pool[ cur_idx ];
    uint next = sibling->sibling_prev_idx;
    fd_progcache_cancel_tree( cache, sibling );
    cur_idx = next;
  }
}

static void
fd_progcache_cancel_next_list( fd_progcache_join_t * cache,
                               fd_progcache_txn_t *  txn ) {
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  uint cur_idx = txn->sibling_next_idx;
  while( cur_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)cur_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_next_list txn_idx=%u txn_max=%lu)", cur_idx, txn_max ));
    fd_progcache_txn_t * sibling = &cache->txn.pool[ cur_idx ];
    uint next = sibling->sibling_next_idx;
    fd_progcache_cancel_tree( cache, sibling );
    cur_idx = next;
  }
}

/* fd_progcache_txn_publish_one merges an in-prep transaction whose
   parent is the last published, into the parent. */

static void
fd_progcache_txn_publish_one( fd_progcache_join_t * cache,
                              fd_progcache_txn_t *  txn ) {

  /* Phase 1: Mark transaction as "last published" */

  fd_progcache_fork_id_t const fork_id = txn->xid;
  if( FD_UNLIKELY( txn->parent_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: txn with fork_id %lu is not a child of the last published txn", fork_id ));
  }
  fd_racesan_hook( "prog_publish_one:pre_xid_store" );
  __atomic_store_n( &cache->shmem->txn.root, fork_id, memory_order_release );

  /* Phase 2: Drain inserters from transaction */

  fd_rwlock_write( &txn->lock );

  /* Phase 3: Detach records */

  ulong rec_max = cache->rec.max;
  for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; ) {
    if( FD_UNLIKELY( (ulong)idx >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (publish_one rec_idx=%u rec_max=%lu)", idx, rec_max ));
    /* The detach store makes the record claimable by eviction, which
       reinitializes the link, so the link is read first. */
    uint next_idx = cache->rec.ele[ idx ].next_idx;
    if( FD_UNLIKELY( next_idx!=UINT_MAX && (ulong)next_idx >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (publish_one next_idx=%u rec_max=%lu)", next_idx, rec_max ));
    atomic_store_explicit( &cache->rec.ele[ idx ].txn_idx, UINT_MAX, memory_order_release );
    fd_racesan_hook( "prog_publish_one:post_detach" );
    fd_progcache_admin_metrics_g.root_cnt++;
    idx = next_idx;
  }

  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;

  /* Phase 4: Remove transaction from fork graph */

  { /* Adjust the parent pointers of the children to point to "last published" */
    ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
    ulong child_idx = txn->child_head_idx;
    while( child_idx!=UINT_MAX ) {
      if( FD_UNLIKELY( child_idx >= txn_max ) )
        FD_LOG_CRIT(( "progcache: corruption detected (publish_one child_idx=%lu txn_max=%lu)", child_idx, txn_max ));
      cache->txn.pool[ child_idx ].parent_idx = UINT_MAX;
      child_idx = cache->txn.pool[ child_idx ].sibling_next_idx;
    }
  }

  /* Phase 5: Remove transaction from index */

  if( FD_UNLIKELY( fd_prog_txnm_idx_remove( cache->txn.map, &txn->xid, ULONG_MAX, cache->txn.pool )==ULONG_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: fd_prog_txnm_idx_remove(%lu) failed", txn->xid ));
  }

  /* Phase 6: Free transaction object */

  fd_rwlock_unwrite( &txn->lock );
  txn->parent_idx       = UINT_MAX;
  txn->sibling_prev_idx = UINT_MAX;
  txn->sibling_next_idx = UINT_MAX;
  txn->child_head_idx   = UINT_MAX;
  txn->child_tail_idx   = UINT_MAX;
  fd_prog_txnp_ele_release( cache->txn.pool, txn );
}

void
fd_progcache_advance_root( fd_progcache_join_t *  cache,
                           fd_progcache_fork_id_t fork_id ) {
  if( FD_UNLIKELY( !cache ) ) FD_LOG_CRIT(( "invalid arguments" ));

  /* Detach records from txns without acquiring record locks */

  fd_rwlock_write( &cache->shmem->txn.rwlock );

  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  uint txn_idx = (uint)fd_prog_txnm_idx_query( cache->txn.map, &fork_id, UINT_MAX, cache->txn.pool );
  if( FD_UNLIKELY( txn_idx==UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_advance_root failed: invalid fork_id %lu", fork_id ));
  }
  if( FD_UNLIKELY( (ulong)txn_idx >= txn_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (advance_root txn_idx=%u txn_max=%lu)", txn_idx, txn_max ));
  fd_progcache_txn_t * txn = &cache->txn.pool[ txn_idx ];
  if( FD_UNLIKELY( txn->parent_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_advance_root: parent of txn %lu is not root", fork_id ));
  }

  fd_progcache_cancel_prev_list( cache, txn );
  fd_progcache_cancel_next_list( cache, txn );

  txn->sibling_prev_idx = UINT_MAX;
  txn->sibling_next_idx = UINT_MAX;
  cache->shmem->txn.child_head_idx = txn->child_head_idx;
  cache->shmem->txn.child_tail_idx = txn->child_tail_idx;

  fd_progcache_txn_publish_one( cache, txn );

  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );
}

void
fd_progcache_cancel_fork( fd_progcache_join_t *  cache,
                          fd_progcache_fork_id_t fork_id ) {
  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_CRIT(( "invalid arguments" ));
  }

  fd_rwlock_write( &cache->shmem->txn.rwlock );

  fd_progcache_txn_t * txn = fd_prog_txnm_ele_query( cache->txn.map, &fork_id, NULL, cache->txn.pool );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_progcache_cancel failed: invalid fork_id %lu", fork_id ));
  }
  fd_progcache_cancel_tree( cache, txn );

  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );
}

/* reset_rec_map frees all records in a progcache instance. */

static void
reset_rec_map( fd_progcache_join_t * cache ) {
  ulong chain_cnt = fd_prog_recm_chain_cnt( cache->rec.map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    for(
        fd_prog_recm_iter_t iter = fd_prog_recm_iter( cache->rec.map, chain_idx );
        !fd_prog_recm_iter_done( iter );
    ) {
      fd_progcache_rec_t * rec = fd_prog_recm_iter_ele( iter );
      ulong next = fd_prog_recm_private_idx( rec->map_next );

      fd_prog_recm_query_t rec_query[1];
      int err = fd_prog_recm_remove( cache->rec.map, &rec->pair, NULL, rec_query, FD_MAP_FLAG_BLOCKING );
      if( FD_UNLIKELY( err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_remove failed (%i-%s)", err, fd_map_strerror( err ) ));
      if( FD_UNLIKELY( !fd_rwlock_trywrite( &rec->lock ) ) )
        FD_LOG_CRIT(( "fd_progcache_reset requires quiescence: record still read-locked" ));
      fd_progcache_rec_release( cache, rec );

      iter.ele_idx = next;
    }
  }
}

/* clear_txn_list does a depth-first traversal of the txn tree.
   Removes all txns. */

static void
clear_txn_list( fd_progcache_join_t * join,
                uint                  txn_head_idx ) {
  ulong txn_max = fd_prog_txnp_max( join->txn.pool );
  for( uint idx = txn_head_idx; idx!=UINT_MAX; ) {
    if( FD_UNLIKELY( (ulong)idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (clear_txn_list txn_idx=%u txn_max=%lu)", idx, txn_max ));
    fd_progcache_txn_t * txn = &join->txn.pool[ idx ];
    uint next_idx  = txn->sibling_next_idx;
    uint child_idx = txn->child_head_idx;
    txn->rec_head_idx     = UINT_MAX;
    txn->rec_tail_idx     = UINT_MAX;
    txn->child_head_idx   = UINT_MAX;
    txn->child_tail_idx   = UINT_MAX;
    txn->parent_idx       = UINT_MAX;
    txn->sibling_prev_idx = UINT_MAX;
    txn->sibling_next_idx = UINT_MAX;
    clear_txn_list( join, child_idx );
    if( FD_UNLIKELY( !fd_prog_txnm_ele_remove( join->txn.map, &txn->xid, NULL, join->txn.pool ) ) ) FD_LOG_CRIT(( "fd_prog_txnm_ele_remove failed" ));
    fd_prog_txnp_ele_release( join->txn.pool, txn );
    idx = next_idx;
  }
}

void
fd_progcache_reset( fd_progcache_join_t * cache ) {
  /* Zombies are not in the map, so reset_rec_map cannot see them.  Collect
     them first; one that survives the sweep is held by an active reader. */
  fd_prog_reclaim_work( cache );
  for( ulong i=0UL; i<cache->rec.max; i++ ) {
    uchar st = __atomic_load_n( &cache->rec.ele[ i ].state, __ATOMIC_RELAXED );
    if( FD_UNLIKELY( ( st & ( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_MAPPED ) )==FD_PROGCACHE_REC_LIVE ) )
      FD_LOG_CRIT(( "fd_progcache_reset requires quiescence: record %lu awaits collection (active readers?)", i ));
  }
  if( FD_UNLIKELY( cache->shmem->spill.lock.value || cache->shmem->spill.rec_used || cache->shmem->spill.spad_used ) )
    FD_LOG_CRIT(( "fd_progcache_reset requires quiescence: spill in use" ));
  clear_txn_list( cache, cache->shmem->txn.child_head_idx );
  cache->shmem->txn.child_head_idx = UINT_MAX;
  cache->shmem->txn.child_tail_idx = UINT_MAX;
  reset_rec_map( cache );
  cache->shmem->txn.root = fd_progcache_fork_id_initial();
  cache->shmem->txn.seq  = fd_progcache_fork_id_initial();
}

static int
fd_progcache_verify_siblings( fd_progcache_txn_t * pool,
                              ulong                txn_max,
                              uint                 head_idx,
                              uint                 tail_idx,
                              uint                 expected_parent_idx,
                              uint *               stack,
                              ulong *              stack_top ) {

# define TEST(c) do {                                                    \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  TEST( (head_idx==UINT_MAX)==(tail_idx==UINT_MAX) );

  uint last_idx = UINT_MAX;
  for( uint idx = head_idx; idx!=UINT_MAX; ) {
    TEST( idx<txn_max );
    fd_progcache_txn_t * child = &pool[ idx ];
    TEST( !child->tag );
    TEST( child->parent_idx==expected_parent_idx );
    child->tag = 1;
    TEST( *stack_top<FD_PROGCACHE_DEPTH_MAX );
    stack[ (*stack_top)++ ] = idx;
    last_idx = idx;
    uint next_idx = child->sibling_next_idx;
    if( next_idx!=UINT_MAX ) {
      TEST( next_idx<txn_max );
      TEST( pool[ next_idx ].sibling_prev_idx==idx );
    }
    idx = next_idx;
  }
  TEST( last_idx==tail_idx );

# undef TEST

  return 0;
}

int
fd_progcache_verify( fd_progcache_join_t * join ) {

# define TEST(c) do {                                                    \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  TEST( join );

  fd_progcache_shmem_t * shmem = join->shmem;
  TEST( shmem );
  TEST( shmem->magic==FD_PROGCACHE_SHMEM_MAGIC );
  TEST( shmem->wksp_tag );

  TEST( !fd_prog_recm_verify( join->rec.map ) );

  ulong rec_max = join->rec.max;
  fd_progcache_rec_t * rec0 = join->rec.ele;

  ulong txn_max = fd_prog_txnp_max( join->txn.pool );
  TEST( !fd_prog_txnm_verify( join->txn.map, txn_max, join->txn.pool ) );

  for( ulong i=0UL; i<txn_max; i++ ) join->txn.pool[ i ].tag = 0;

  uint  stack[ FD_PROGCACHE_DEPTH_MAX ];
  ulong stack_top = 0UL;

  TEST( !fd_progcache_verify_siblings( join->txn.pool, txn_max,
      shmem->txn.child_head_idx, shmem->txn.child_tail_idx,
      UINT_MAX, stack, &stack_top ) );

  while( stack_top ) {
    uint txn_idx = stack[ --stack_top ];
    fd_progcache_txn_t * txn = &join->txn.pool[ txn_idx ];
    TEST( !fd_progcache_verify_siblings( join->txn.pool, txn_max,
        txn->child_head_idx, txn->child_tail_idx,
        txn_idx, stack, &stack_top ) );
  }

  for( ulong i=0UL; i<txn_max; i++ ) {
    if( !join->txn.pool[ i ].tag ) continue;
    fd_progcache_txn_t * txn = &join->txn.pool[ i ];

    TEST( (txn->rec_head_idx==UINT_MAX)==(txn->rec_tail_idx==UINT_MAX) );

    ulong rec_cnt = 0UL;
    uint  prev    = UINT_MAX;
    for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; ) {
      TEST( idx<rec_max );
      TEST( rec_cnt<rec_max ); /* cycle detection */
      fd_progcache_rec_t * rec = &rec0[ idx ];
      TEST( rec->prev_idx==prev );
      TEST( rec->exists );
      prev = idx;
      idx  = rec->next_idx;
      rec_cnt++;
    }
    TEST( prev==txn->rec_tail_idx );
  }

  /* A record is mapped, a zombie, free, or in flight -- never two. */
  ulong mapped_cnt = 0UL;
  ulong free_cnt   = 0UL;

  ulong chain_cnt = fd_prog_recm_chain_cnt( join->rec.map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    for(
        fd_prog_recm_iter_t iter = fd_prog_recm_iter( join->rec.map, chain_idx );
        !fd_prog_recm_iter_done( iter );
        iter = fd_prog_recm_iter_next( iter )
    ) {
      fd_progcache_rec_t * rec = fd_prog_recm_iter_ele( iter );
      TEST( rec->exists );

      /* Verify state is LIVE for mapped records */
      ulong rec_idx = (ulong)( rec - rec0 );
      TEST( rec_idx<rec_max );
      uchar st = __atomic_load_n( &rec->state, __ATOMIC_RELAXED );
      /* Mapped means LIVE, or LOADING while its publisher finishes. */
      TEST( st & ( FD_PROGCACHE_REC_LIVE | FD_PROGCACHE_REC_LOADING ) );
      /* Detached means rooted, so the load is over. */
      if( atomic_load_explicit( &rec->txn_idx, memory_order_acquire )==UINT_MAX )
        TEST( st & FD_PROGCACHE_REC_LIVE );
      TEST( st & FD_PROGCACHE_REC_MAPPED );
      TEST( (ulong)rec->size_class==fd_progcache_rec_class( shmem, rec_idx ) );
      mapped_cnt++;
      TEST( rec->lock.value!=FD_RWLOCK_WRITE_LOCK ); /* push relies on this */
    }
  }

  /* A free record is write-locked, dead, and in its own class's list. */
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    ulong base      = shmem->cache.rec_base [ c ];
    ulong class_max = shmem->cache.class_max[ c ];

    ulong cnt = 0UL;
    uint  idx = (uint)( shmem->cache.free_top[ c ].ver_top & (ulong)UINT_MAX );
    while( idx!=UINT_MAX ) {
      TEST( (ulong)idx>=base && (ulong)idx<base+class_max );
      fd_progcache_rec_t * rec = &rec0[ idx ];
      TEST( !rec->exists );
      TEST( rec->lock.value==FD_RWLOCK_WRITE_LOCK );
      TEST( !__atomic_load_n( &rec->state, __ATOMIC_RELAXED ) );
      TEST( cnt<class_max ); /* cycle detection */
      cnt++;
      idx = rec->free_next;
    }
    TEST( cnt<=class_max );
    TEST( cnt==shmem->cache.free_cnt[ c ].val );
    free_cnt += cnt;
  }

  TEST( mapped_cnt+free_cnt<=rec_max );

# undef TEST

  return 0;
}
