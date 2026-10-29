#include "fd_progcache.h"
#include "fd_progcache_admin.h"
#include "fd_progcache_base.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_rec.h"
#include "fd_progcache_reclaim.h"
#include "../../util/racesan/fd_racesan_target.h"

/* FIXME get rid of this thread-local */
FD_TL fd_progcache_admin_metrics_t fd_progcache_admin_metrics_g;

/* Fork-level operations.  The fork table is written here under txn.rwlock
   (write), and read under txn.rwlock (read) by the insert and eviction
   paths. */

/* fork_live_check returns the fork table entry of a live fork, after
   checking that it still belongs to the accdb fork currently holding its
   id.  A LIVE entry whose generation differs means accdb recycled the
   fork id before progcache was told the fork was retired. */

static fd_progcache_txn_t *
fork_live_check( fd_progcache_join_t * cache,
                 fd_accdb_t const *    accdb,
                 ulong                 idx ) {
  fd_progcache_txn_t * txn = &cache->txn.ele[ idx ];
  if( txn->state!=FD_PROGCACHE_TXN_LIVE ) return NULL;
  uint gen = fd_accdb_fork_generation( accdb, (fd_accdb_fork_id_t){ .val=(ushort)idx } );
  if( FD_UNLIKELY( txn->gen!=gen ) )
    FD_LOG_CRIT(( "progcache: fork %lu (generation %u) was retired in accdb but not in progcache (accdb generation %u)",
                  idx, txn->gen, gen ));
  return txn;
}

static void
fd_progcache_cancel_one( fd_progcache_join_t * cache,
                         fd_progcache_txn_t *  txn ) {
  ulong rec_max = cache->rec.max;

  fd_rwlock_write( &txn->lock );

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
  txn->state        = FD_PROGCACHE_TXN_RETIRED;

  fd_rwlock_unwrite( &txn->lock );
}

static void
fd_progcache_root_one( fd_progcache_join_t * cache,
                       fd_progcache_txn_t *  txn ) {
  ulong rec_max = cache->rec.max;

  /* Drain inserters and the eviction sweep's unrooted arm */
  fd_rwlock_write( &txn->lock );

  for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; ) {
    if( FD_UNLIKELY( (ulong)idx >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (root_one rec_idx=%u rec_max=%lu)", idx, rec_max ));
    uint next_idx = cache->rec.ele[ idx ].next_idx;
    if( FD_UNLIKELY( next_idx!=UINT_MAX && (ulong)next_idx >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (root_one next_idx=%u rec_max=%lu)", next_idx, rec_max ));
    atomic_store_explicit( &cache->rec.ele[ idx ].txn_idx, UINT_MAX, memory_order_release );
    fd_racesan_hook( "prog_publish_one:post_detach" );
    fd_progcache_admin_metrics_g.root_cnt++;
    idx = next_idx;
  }

  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;
  txn->state        = FD_PROGCACHE_TXN_RETIRED;

  fd_rwlock_unwrite( &txn->lock );
}

void
fd_progcache_root_fork( fd_progcache_join_t * cache,
                        fd_accdb_t const *    accdb,
                        fd_accdb_fork_id_t    fork_id ) {
  if( FD_UNLIKELY( !cache || !accdb ) ) FD_LOG_CRIT(( "invalid arguments" ));
  if( FD_UNLIKELY( (ulong)fork_id.val>=cache->txn.max ) ) FD_LOG_CRIT(( "invalid fork_id %u", (uint)fork_id.val ));

  fd_rwlock_write( &cache->shmem->txn.rwlock );
  fd_progcache_txn_t * txn = fork_live_check( cache, accdb, fork_id.val );
  if( txn ) fd_progcache_root_one( cache, txn );
  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );
}

void
fd_progcache_cancel_fork( fd_progcache_join_t * cache,
                          fd_accdb_t const *    accdb,
                          fd_accdb_fork_id_t    fork_id ) {
  if( FD_UNLIKELY( !cache || !accdb ) ) FD_LOG_CRIT(( "invalid arguments" ));
  if( FD_UNLIKELY( (ulong)fork_id.val>=cache->txn.max ) ) FD_LOG_CRIT(( "invalid fork_id %u", (uint)fork_id.val ));

  fd_rwlock_write( &cache->shmem->txn.rwlock );
  for( ulong i=0UL; i<cache->txn.max; i++ ) {
    fd_progcache_txn_t * txn = fork_live_check( cache, accdb, i );
    if( !txn ) continue;
    fd_accdb_fork_id_t id = { .val=(ushort)i };
    if( i==fork_id.val || fd_accdb_fork_descends( accdb, id, fork_id ) ) fd_progcache_cancel_one( cache, txn );
  }
  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );
}

void
fd_progcache_advance_root( fd_progcache_join_t * cache,
                           fd_accdb_t const *    accdb,
                           fd_accdb_fork_id_t    fork_id ) {
  if( FD_UNLIKELY( !cache || !accdb ) ) FD_LOG_CRIT(( "invalid arguments" ));
  if( FD_UNLIKELY( (ulong)fork_id.val>=cache->txn.max ) ) FD_LOG_CRIT(( "invalid fork_id %u", (uint)fork_id.val ));

  /* fork_id and its ancestors (the current root) get rooted, its
     descendants stay, everything else lost the fork race.  Cancel the
     losers first so their records never become visible as rooted. */

  fd_rwlock_write( &cache->shmem->txn.rwlock );
  for( ulong i=0UL; i<cache->txn.max; i++ ) {
    fd_progcache_txn_t * txn = fork_live_check( cache, accdb, i );
    if( !txn || i==fork_id.val ) continue;
    fd_accdb_fork_id_t id = { .val=(ushort)i };
    if( fd_accdb_fork_descends( accdb, fork_id, id ) ) continue; /* ancestor */
    if( fd_accdb_fork_descends( accdb, id, fork_id ) ) continue; /* descendant */
    fd_progcache_cancel_one( cache, txn );
  }
  for( ulong i=0UL; i<cache->txn.max; i++ ) {
    fd_progcache_txn_t * txn = fork_live_check( cache, accdb, i );
    if( !txn ) continue;
    fd_accdb_fork_id_t id = { .val=(ushort)i };
    if( i==fork_id.val || fd_accdb_fork_descends( accdb, fork_id, id ) ) fd_progcache_root_one( cache, txn );
  }
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
  for( ulong i=0UL; i<cache->txn.max; i++ ) {
    fd_progcache_txn_t * txn = &cache->txn.ele[ i ];
    txn->state        = FD_PROGCACHE_TXN_FREE;
    txn->gen          = 0U;
    txn->rec_head_idx = UINT_MAX;
    txn->rec_tail_idx = UINT_MAX;
  }
  reset_rec_map( cache );
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

  ulong txn_max = join->txn.max;
  TEST( txn_max==shmem->txn.max );

  for( ulong i=0UL; i<txn_max; i++ ) {
    fd_progcache_txn_t * txn = &join->txn.ele[ i ];
    TEST( txn->state<=FD_PROGCACHE_TXN_RETIRED );
    if( txn->state!=FD_PROGCACHE_TXN_LIVE ) {
      TEST( txn->rec_head_idx==UINT_MAX && txn->rec_tail_idx==UINT_MAX );
      continue;
    }

    TEST( (txn->rec_head_idx==UINT_MAX)==(txn->rec_tail_idx==UINT_MAX) );

    ulong rec_cnt = 0UL;
    uint  prev    = UINT_MAX;
    for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; ) {
      TEST( idx<rec_max );
      TEST( rec_cnt<rec_max ); /* cycle detection */
      fd_progcache_rec_t * rec = &rec0[ idx ];
      TEST( rec->prev_idx==prev );
      TEST( rec->exists );
      TEST( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )==(uint)i );
      TEST( rec->pair.gen==txn->gen && rec->pair.fork_id==(ushort)i );
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
