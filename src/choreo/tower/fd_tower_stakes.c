#include "fd_tower.h"

#include <errno.h>
#include <unistd.h>

/* Per-slot stake sets are tiered like the lockout lists: the vtr pool
   holds sets for at most stk_wnd resident slots (FIFO by residency
   age, linked by slot number through fd_tower_stakes_slot_t so
   fd_map_dynamic entry moves are harmless).  When a new slot's set
   would exceed the window, the oldest resident set spills whole to the
   stakes area of lck_fd as dense fd_tower_stakes_rec_t records in a
   per-slot file region.  Full worst-case capacity (blk_max regions)
   lives in the file; at mainnet root lag (~32 slots << stk_wnd) the
   file is never touched. */

#define SORT_NAME        stakes_rec_sort
#define SORT_KEY_T       fd_tower_stakes_rec_t
#define SORT_BEFORE(a,b) (memcmp( (a).addr.uc, (b).addr.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

static ulong
stakes_region_off( fd_tower_t const * tower, uint region ) {
  return FD_TOWER_LOCKOS_SPILL_FOOTPRINT( tower->blk_max, tower->vtr_max )
       + (ulong)region*tower->vtr_max*sizeof(fd_tower_stakes_rec_t);
}

static void
stakes_lru_push_tail( fd_tower_t * tower, fd_tower_stakes_slot_t * ss ) {
  ss->lru_prev = tower->stk_lru_tail;
  ss->lru_next = ULONG_MAX;
  if( FD_LIKELY( tower->stk_lru_tail!=ULONG_MAX ) ) {
    fd_tower_stakes_slot_t * tail = fd_tower_stakes_slot_query( tower->stk_slot_map, tower->stk_lru_tail, NULL );
    FD_CHECK_CRIT( tail, "tower stakes lru tail not in slot map" );
    tail->lru_next = ss->slot;
  } else {
    tower->stk_lru_head = ss->slot;
  }
  tower->stk_lru_tail = ss->slot;
  tower->stk_resident++;
}

static void
stakes_lru_unlink( fd_tower_t * tower, fd_tower_stakes_slot_t * ss ) {
  fd_tower_stakes_slot_t * m = tower->stk_slot_map;
  if( FD_UNLIKELY( ss->lru_prev!=ULONG_MAX ) ) {
    fd_tower_stakes_slot_t * prev = fd_tower_stakes_slot_query( m, ss->lru_prev, NULL );
    FD_CHECK_CRIT( prev, "tower stakes lru prev not in slot map" );
    prev->lru_next = ss->lru_next;
  } else {
    tower->stk_lru_head = ss->lru_next;
  }
  if( FD_LIKELY( ss->lru_next!=ULONG_MAX ) ) {
    fd_tower_stakes_slot_t * next = fd_tower_stakes_slot_query( m, ss->lru_next, NULL );
    FD_CHECK_CRIT( next, "tower stakes lru next not in slot map" );
    next->lru_prev = ss->lru_prev;
  } else {
    tower->stk_lru_tail = ss->lru_prev;
  }
  tower->stk_resident--;
}

/* stakes_spill packs the oldest resident slot's set into stk_scratch
   and pwrites it whole to a free file region. */

static void
stakes_spill( fd_tower_t * tower ) {
  FD_CHECK_CRIT( tower->lck_fd>=0, "tower stakes window full and no spill file set" );
  fd_tower_stakes_slot_t * ss = fd_tower_stakes_slot_query( tower->stk_slot_map, tower->stk_lru_head, NULL );
  FD_CHECK_CRIT( ss, "tower stakes lru head not in slot map" );

  fd_tower_stakes_vtr_t * pool = tower->stk_vtr_pool;
  fd_tower_stakes_rec_t * rec  = tower->stk_scratch;
  uint                    cnt  = 0U;
  for( uint idx = ss->head; idx!=UINT_MAX; ) {
    fd_tower_stakes_vtr_t * vs = fd_tower_stakes_vtr_pool_ele( pool, idx );
    idx = vs->prev;
    FD_CHECK_CRIT( cnt<tower->vtr_max, "tower stakes slot set exceeds per-slot bound" );
    rec[ cnt ].addr  = vs->key.addr;
    rec[ cnt ].stake = vs->stake;
    cnt++;
    FD_CHECK_CRIT( fd_tower_stakes_vtr_map_ele_remove( tower->stk_vtr_map, &vs->key, NULL, pool ), "invariant violation: voter stake does not exist in map" );
    fd_tower_stakes_vtr_pool_ele_release( pool, vs );
  }

  FD_CHECK_CRIT( tower->stk_region_free, "no free tower stakes spill regions" );
  uint  region = ((uint *)tower->stk_regions)[ --tower->stk_region_free ];
  ulong sz     = (ulong)cnt*sizeof(fd_tower_stakes_rec_t);
  if( FD_UNLIKELY( pwrite( tower->lck_fd, rec, sz, (off_t)stakes_region_off( tower, region ) )!=(long)sz ) )
    FD_LOG_ERR(( "tower stakes spill pwrite failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  stakes_lru_unlink( tower, ss );
  ss->head     = UINT_MAX;
  ss->region   = region;
  ss->disk_cnt = cnt;
  tower->stk_spill_cnt++;
}

ulong
fd_tower_stakes_load( fd_tower_t *                   tower,
                      fd_tower_stakes_slot_t const * ss ) {
  fd_tower_stakes_rec_t * rec = tower->stk_scratch;
  ulong                   sz  = (ulong)ss->disk_cnt*sizeof(fd_tower_stakes_rec_t);
  if( FD_UNLIKELY( pread( tower->lck_fd, rec, sz, (off_t)stakes_region_off( tower, ss->region ) )!=(long)sz ) )
    FD_LOG_ERR(( "tower stakes pread failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  stakes_rec_sort_inplace( rec, (ulong)ss->disk_cnt );
  tower->stk_load_cnt++;
  return (ulong)ss->disk_cnt;
}

ulong
fd_tower_stakes_spilled_idx( fd_tower_stakes_rec_t const * rec,
                             ulong                         cnt,
                             fd_hash_t const *             addr ) {
  ulong lo = 0UL;
  ulong hi = cnt;
  while( lo<hi ) {
    ulong mid = (lo+hi)/2UL;
    if( memcmp( rec[ mid ].addr.uc, addr->uc, 32UL )<0 ) lo = mid+1UL;
    else                                                 hi = mid;
  }
  if( FD_UNLIKELY( lo>=cnt || memcmp( rec[ lo ].addr.uc, addr->uc, 32UL ) ) ) return ULONG_MAX;
  return lo;
}

ulong
fd_tower_stakes_insert( fd_tower_t *      tower,
                        ulong             slot,
                        fd_hash_t const * vote_account,
                        ulong             stake,
                        ulong             prev_voter_idx ) {

  fd_tower_stakes_slot_t * blk = fd_tower_stakes_slot_query( tower->stk_slot_map, slot, NULL );

  if( FD_UNLIKELY( blk && blk->region!=UINT_MAX ) ) {

    /* Cold append to an already spilled slot (deep-unroot regimes
       only, e.g. a minority fork slot executed long after eviction). */

    FD_CHECK_CRIT( blk->disk_cnt<tower->vtr_max, "tower stakes slot region overflow" );
    fd_tower_stakes_rec_t rec = { .addr = *vote_account, .stake = stake };
    ulong off = stakes_region_off( tower, blk->region ) + (ulong)blk->disk_cnt*sizeof(fd_tower_stakes_rec_t);
    if( FD_UNLIKELY( pwrite( tower->lck_fd, &rec, sizeof(rec), (off_t)off )!=(long)sizeof(rec) ) )
      FD_LOG_ERR(( "tower stakes append pwrite failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    blk->disk_cnt++;
    return ULONG_MAX;
  }

  if( FD_UNLIKELY( !blk ) ) {
    if( FD_UNLIKELY( tower->stk_resident>=tower->stk_wnd ) ) stakes_spill( tower );
    blk = fd_tower_stakes_slot_insert( tower->stk_slot_map, slot );
    FD_CHECK_CRIT( blk, "no free entries in tower stakes slot map" );
    blk->head     = UINT_MAX;
    blk->region   = UINT_MAX;
    blk->disk_cnt = 0U;
    stakes_lru_push_tail( tower, blk );
  }

  fd_tower_stakes_vtr_t * pool = tower->stk_vtr_pool;
  if( FD_UNLIKELY( !fd_tower_stakes_vtr_pool_free( pool ) ) ) FD_LOG_CRIT(( "no free voter stakes in pool" ));
  FD_TEST( prev_voter_idx==ULONG_MAX || prev_voter_idx<UINT_MAX );
  fd_tower_stakes_vtr_t * new_voter_stake = fd_tower_stakes_vtr_pool_ele_acquire( pool );
  new_voter_stake->key   = (fd_tower_stakes_vtr_xid_t){ .addr = *vote_account, .slot = slot };
  new_voter_stake->stake = stake;
  new_voter_stake->prev  = (uint)prev_voter_idx;
  fd_tower_stakes_vtr_map_ele_insert( tower->stk_vtr_map, new_voter_stake, pool );

  /* Point to first vtr (head of list). */

  blk->head = (uint)fd_tower_stakes_vtr_pool_idx( pool, new_voter_stake );
  return (ulong)blk->head;
}

void
fd_tower_stakes_remove( fd_tower_t * tower,
                        ulong        slot ) {

  fd_tower_stakes_slot_t * blk = fd_tower_stakes_slot_query( tower->stk_slot_map, slot, NULL );
  if( FD_UNLIKELY( !blk ) ) return;

  if( FD_UNLIKELY( blk->region!=UINT_MAX ) ) {

    /* Spilled slot: records hold no cross references, so removal is a
       pure region drop. */

    ((uint *)tower->stk_regions)[ tower->stk_region_free++ ] = blk->region;
  } else {
    uint voter_idx = blk->head;

    /* Remove the linked list of voters. */

    while( FD_UNLIKELY( voter_idx!=UINT_MAX ) ) {
      fd_tower_stakes_vtr_t * voter_stake = fd_tower_stakes_vtr_pool_ele( tower->stk_vtr_pool, voter_idx );
      voter_idx = voter_stake->prev;
      fd_tower_stakes_vtr_t * remove = fd_tower_stakes_vtr_map_ele_remove( tower->stk_vtr_map, &voter_stake->key, NULL, tower->stk_vtr_pool );
      if( FD_UNLIKELY( !remove ) ) FD_LOG_CRIT(( "invariant violation: voter stake does not exist in map" ));
      fd_tower_stakes_vtr_pool_ele_release( tower->stk_vtr_pool, voter_stake );
    }
    stakes_lru_unlink( tower, blk );
  }
  fd_tower_stakes_slot_remove( tower->stk_slot_map, blk );
}
