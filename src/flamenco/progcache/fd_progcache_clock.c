#include "fd_progcache_user.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_reclaim.h"
#include "../../util/racesan/fd_racesan_target.h"

/* evict_inner is the eviction sweep on one size class, the shared body of
   fd_prog_evict and fd_prog_preevict.  metrics==NULL is the admin variant:
   identical scan and claim, no counters. */

static fd_progcache_rec_t *
evict_inner( fd_progcache_join_t *    join,
             fd_progcache_metrics_t * metrics,
             ulong                    class_idx ) {
  fd_progcache_shmem_t * shmem = join->shmem;
  fd_progcache_rec_t *   recs  = join->rec.ele;

  ulong base      = shmem->cache.rec_base [ class_idx ];
  ulong class_max = shmem->cache.class_max[ class_idx ];
  FD_TEST( class_max );

  /* Do at most 2x class_max (number of slots in class) iterations.
     If we can't evict, return NULL and we'll try to spill.  Every skip is a
     continue; the one way out with a slot is the handover at the bottom. */
  fd_progcache_rec_t * claim    = NULL;
  ulong                iter_rem = 2UL*class_max;
  while( iter_rem ) {
    iter_rem--;

    /* Get a candidate */
    ulong ticket = __atomic_fetch_add( &shmem->cache.clock_hand[ class_idx ].val, 1UL, __ATOMIC_RELAXED );
    fd_progcache_rec_t * rec = recs + base + ( ticket % class_max );

    uchar st = __atomic_load_n( &rec->state, __ATOMIC_RELAXED );
    fd_racesan_hook( "prog_clock_evict:post_load_bits" );

    /* Candidate is free or in flight: skip. */
    if( !( st & FD_PROGCACHE_REC_LIVE ) ) continue;

    if( FD_UNLIKELY( !( st & FD_PROGCACHE_REC_MAPPED ) ) ) {

      /* Candidate is a zombie, already unmapped, so we can try to
         write-lock it directly (skip if still read-locked / in use). */

      if( FD_UNLIKELY( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )!=UINT_MAX ) ) continue;
      if( FD_UNLIKELY( !fd_rwlock_trywrite( &rec->lock ) ) ) continue;
      /* The write lock freezes the record, so the re-check under it decides. */
      uchar cur = __atomic_load_n( &rec->state, __ATOMIC_RELAXED );
      if( FD_UNLIKELY( ( ( cur & ( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_MAPPED ) )!=FD_PROGCACHE_REC_LIVE ) |
                       ( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )!=UINT_MAX ) ) ) {
        fd_rwlock_unwrite( &rec->lock );
        continue;
      }
      /* Write locked by the trywrite; fall through to fd_progcache_rec_reinit */

    } else {

      /* Candidate is a live cache record: run CLOCK */
      fd_progcache_rec_key_t pair = rec->pair;

      /* If there's any read-lock on the record, it'll fail later, so might as well
         skipping it now (this is just an optimization) */
      if( FD_UNLIKELY( atomic_load_explicit( &rec->lock.value, memory_order_relaxed )!=0 ) ) continue;

      if( st & FD_PROGCACHE_REC_VISITED ) {
        /* clear the VISITED bit, i.e. CLOCK second chance */
        __atomic_fetch_and( &rec->state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );
        continue;
      }

      /* We skip records still attached to a fork.
         This is a policy / implementation choice, not a correctness requirement,
         and allows us to evict avoiding locks on the fork graph.
         Worst case the class is all unrooted and we spill, but in practice
         records that are still attached to a fork are the newest fills, so
         CLOCK would likely skip them anyway. */
      if( FD_UNLIKELY( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )!=UINT_MAX ) ) continue;

      fd_racesan_hook( "prog_clock_evict:pre_delete" );
      long res = fd_prog_delete_rec_claim( join, rec, &pair );
      fd_racesan_hook( "prog_clock_evict:post_delete" );
      if( FD_UNLIKELY( res<0L ) ) continue;
      /* Write locked by the claim; fall through to fd_progcache_rec_reinit */
    }

    if( FD_LIKELY( metrics ) ) {
      metrics->evict_cnt++;
      metrics->evict_tot_sz += rec->rodata_sz;
      metrics->evict_per_class[ class_idx ]++;
    }

    /* Unmapped and write locked, so nobody else can take the slot */
    claim = fd_progcache_rec_reinit( join, rec );
    break;
  }

  return claim;
}

fd_progcache_rec_t *
fd_prog_evict( fd_progcache_t * cache,
               ulong            sz ) {
  ulong class_idx = fd_progcache_cache_class( sz );
  FD_TEST( class_idx<FD_PROGCACHE_CACHE_CLASS_CNT );
  return evict_inner( cache->join, cache->metrics, class_idx );
}

ulong
fd_prog_preevict( fd_progcache_join_t * join,
                  ulong                 class_idx,
                  ulong                 free_target ) {
  FD_TEST( class_idx<FD_PROGCACHE_CACHE_CLASS_CNT );
  if( FD_LIKELY( fd_progcache_class_free_cnt( join->shmem, class_idx )>=free_target ) ) return 0UL;
  fd_progcache_rec_t * rec = evict_inner( join, NULL, class_idx );
  if( FD_UNLIKELY( !rec ) ) return 0UL;
  fd_progcache_rec_abandon( join, rec );
  return 1UL;
}

void
fd_progcache_housekeeping( fd_progcache_join_t * join ) {
  ulong ticket = __atomic_fetch_add( &join->shmem->cache.housekeep_hand.val, 1UL, __ATOMIC_RELAXED );
  fd_prog_preevict( join, ticket % FD_PROGCACHE_CACHE_CLASS_CNT, 2UL );
}
