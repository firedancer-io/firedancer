#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h

/* fd_progcache_clock.h provides the cache eviction policy for the
   program cache (CLOCK).

   CLOCK is a cache replacement algorithm:
   Entries get evicted when the cache is full.

   There are two "cache is full" conditions:
   - No more progcache_rec descriptors available
   - Insufficient heap space to allocate a val

   The CLOCK algorithm works as follows:
   - There exists a "visited" bit for each progcache_rec
   - Whenever a user accesses a record, the visited bit is set
   - When cache replacement kicks in, the bit set is scanned
     (low-to-high cyclic).  For each record:
     - If the "visited" bit is set, unset it
     - Else ("visited" bit unset), evict the record

   Some implementation details:
   - The "visited" bits are stored in a dense bit array ("cbits")
     (Optimize for fast scans)
   - This bit array shadows the progcache_rec pool (including free
     entries)
   - An additional "exists" bit is interleaved with the "visited" bit,
     to disambiguate an existing idle entry from a free entry */

#include "fd_progcache_base.h"
#include <stdatomic.h>

FD_PROTOTYPES_BEGIN

/* Helper APIs for the CLOCK bit array */

/* fd_prog_cbits_slot returns the 64-bit slot that contains the bit pair
   for the record with pool index rec_idx. */

FD_FN_CONST static inline atomic_ulong *
fd_prog_cbits_slot( atomic_ulong * bits,
                    ulong          rec_idx ) {
  return &bits[ rec_idx>>5 ];
}

/* fd_prog_{visited,exists}_bit return the bit index of the {visited,
   exists} flag for a record within its slot (see fd_prog_cbits_slot).

   Full example:

     slot_p = fd_prog_cbits_slot( bits, idx )
     slot = atomic_load_explicit( slot, memory_order_relaxed )
     rec_exists = fd_ulong_extract_bit( slot, fd_prog_visited_bit( idx ) ) */

FD_FN_CONST static inline int
fd_prog_visited_bit( ulong rec_idx ) {
  return 2*(rec_idx & 31UL);
}

FD_FN_CONST static inline int
fd_prog_exists_bit( ulong rec_idx ) {
  return fd_prog_visited_bit( rec_idx )+1;
}

/* fd_prog_cbits_{align,footprint} return the alignment/size requirement
   for the cbits array. */

static inline ulong
fd_prog_cbits_align( void ) {
  return 64UL;
}

static inline ulong
fd_prog_cbits_footprint( ulong rec_max ) {
  return fd_ulong_align_up( rec_max*2, 512UL ) / 8UL;
}

/* fd_prog_clock_init initializes CLOCK cache replacement algo state. */

void
fd_prog_clock_init( atomic_ulong * cbits,
                    ulong          rec_max );

/* fd_prog_clock_touch marks the record at the given index as recently
   touched which makes it less likely to get evicted. */

static inline void
fd_prog_clock_touch( atomic_ulong * cbits,
                     ulong          rec_idx ) {
  atomic_ulong * slot_p = fd_prog_cbits_slot( cbits, rec_idx );
  /* Set the "exists" and "visited" bits */
  ulong mask = 3UL<<(fd_prog_visited_bit( rec_idx ));
  atomic_fetch_or_explicit( slot_p, mask, memory_order_relaxed );
}

/* fd_prog_clock_remove indicates that the record at the given index is
   about to be deleted.  Should be run before a deletion, not after. */

static inline void
fd_prog_clock_remove( atomic_ulong * cbits,
                      ulong          rec_idx ) {
  atomic_ulong * slot_p = fd_prog_cbits_slot( cbits, rec_idx );
  /* Clear the "exists" and "visited" bits */
  ulong mask = ~( (3UL<<fd_prog_visited_bit( rec_idx )) );
  atomic_fetch_and_explicit( slot_p, mask, memory_order_relaxed );
}

/* fd_prog_clock_evict evicts records until at least rec_min records
   and heap_min bytes of heap space are queued for reclamation. */

void
fd_prog_clock_evict( fd_progcache_t * progcache,
                     ulong            rec_min,
                     ulong            heap_min );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h */
