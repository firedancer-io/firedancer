#include "fd_progcache_user.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_reclaim.h"
#include "../../util/racesan/fd_racesan_target.h"

void
fd_prog_clock_init( atomic_ulong * cbits,
                    ulong          rec_max ) {
  fd_memset( cbits, 0, fd_prog_cbits_footprint( rec_max ) );
}

void
fd_prog_clock_evict( fd_progcache_t * cache,
                     ulong            rec_rem_,
                     ulong            heap_rem_ ) {
  fd_progcache_join_t *  join    = cache->join;
  fd_progcache_shmem_t * shmem   = join->shmem;
  fd_progcache_rec_t *   rec0    = join->rec.pool->ele;
  ulong                  rec_max = join->rec.pool->ele_max;
  atomic_ulong *         cbits   = join->clock.bits;

  /* Fetch and lock CLOCK head */
  fd_rwlock_write( &shmem->clock.lock );
  ulong head = shmem->clock.head;
  if( FD_UNLIKELY( head >= rec_max ) ) head = 0UL;

  long  rec_rem  = (long)rec_rem_;
  long  heap_rem = (long)heap_rem_;
  ulong iter_rem = 2UL*rec_max;
  while( (rec_rem>0L || heap_rem>0L) && iter_rem ) {
    iter_rem--;
    atomic_ulong * slot_p = fd_prog_cbits_slot( cbits, head );

    ulong slot    = atomic_load_explicit( slot_p, memory_order_relaxed );
    int   visited = fd_ulong_extract_bit( slot, fd_prog_visited_bit( head ) );
    int   exists  = fd_ulong_extract_bit( slot, fd_prog_exists_bit ( head ) );
    fd_racesan_hook( "prog_clock_evict:post_load_bits" );

    if( exists ) {
      ulong mask = 0UL;
      if( visited ) {
        mask = 1UL<<fd_prog_visited_bit( head );
      } else {
        long res = fd_prog_delete_rec( cache->join, rec0+head );
        if( res>=0L ) {
          rec_rem--;
          heap_rem -= res;
          cache->metrics->evict_cnt++;
          cache->metrics->evict_tot_sz += (ulong)res;
        }
        mask = 3UL<<fd_prog_visited_bit( head );
      }
      atomic_fetch_and_explicit( slot_p, ~mask, memory_order_relaxed );
    }

    head++;
    if( head>=rec_max ) head = 0UL;
  }

  /* Write back and unlock CLOCK head */
  shmem->clock.head = head;
  fd_rwlock_unwrite( &shmem->clock.lock );

  fd_prog_reclaim_work( join );
}
