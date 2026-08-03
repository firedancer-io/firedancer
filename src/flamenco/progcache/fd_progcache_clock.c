#include "fd_progcache_user.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_reclaim.h"
#include "../../util/racesan/fd_racesan_target.h"

int
fd_progcache_evict( fd_progcache_t * cache,
                    ulong            sz ) {
  fd_progcache_join_t *  join  = cache->join;
  fd_progcache_shmem_t * shmem = join->shmem;
  uchar *                state = join->rec.state;

  /* Map the value size to its class (footprint 0 -> nx class) and evict one
     entry from that class's CLOCK, freeing its record for reuse. */
  ulong class_idx = fd_progcache_class( sz );
  if( FD_UNLIKELY( class_idx>=FD_PROGCACHE_CLASS_CNT ) ) return 0; /* larger than top class (unreachable) */

  ulong base  = shmem->cache.rec_base[ class_idx ];
  ulong nslot = shmem->cache.nslot   [ class_idx ];
  if( FD_UNLIKELY( !nslot ) ) return 0;

  /* The scan holds no class-wide lock: the hand advances atomically, the state
     bits are updated with atomic RMWs, and a victim is owned by write-locking
     the record itself.  Two scanners therefore cannot pick the same record, and
     a concurrent reclaim never waits on this scan.  The class lock is taken only
     by the free-list operations in rec_acquire / rec_release. */

  int evicted = 0;
  for( ulong iter=0UL; iter<2UL*nslot; iter++ ) {

    /* Claim the next slot in this class's range.  The stored hand starts at
       the class base and only ever increments, so the modulo keeps the
       derived index inside the class. */
    ulong raw  = __atomic_fetch_add( &shmem->cache.clock_hand[ class_idx ], 1UL, __ATOMIC_RELAXED );
    ulong hand = base + ( (raw-base) % nslot );

    uchar st = __atomic_load_n( &state[ hand ], __ATOMIC_RELAXED );
    fd_racesan_hook( "prog_clock_evict:post_load_bits" );
    if( !( st & FD_PROGCACHE_REC_LIVE ) ) continue;

    if( st & FD_PROGCACHE_REC_VISITED ) {
      __atomic_fetch_and( &state[ hand ], (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED ); /* second chance */
      continue;
    }

    /* Take the record for eviction.  The CAS succeeds only when nobody holds it,
       and once held no reader can join: lookups use fd_rwlock_tryread, which
       fails against a write holder.  Free records sit on the class free list
       write-locked, so the CAS cannot take one however stale the bits above are.
       A record that cannot be taken stays mapped and live -- deleting it would
       drop a live entry without freeing its slot. */
    fd_progcache_rec_t * rec = join->rec.ele + hand;
    if( FD_UNLIKELY( !fd_rwlock_trywrite( &rec->lock ) ) ) continue;

    long res = fd_progcache_delete_rec( join, rec );
    fd_racesan_hook( "prog_clock_evict:post_delete" );

    /* Retire the slot's state while the record is still owned.  Releasing
       first would let another join reclaim and refill the slot, and this
       store would then clear the new occupant's bits. */
    __atomic_fetch_and( &state[ hand ], (uchar)~( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_VISITED ), __ATOMIC_RELAXED );

    fd_rwlock_unwrite( &rec->lock );

    if( res>=0L ) {
      evicted = 1;
      cache->metrics->evict_cnt++;
      cache->metrics->evict_tot_sz += (ulong)res;
      cache->metrics->evict_per_class[ class_idx ]++;
      break;
    }
  }

  fd_progcache_reclaim_work( join );
  return evicted;
}
