#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h

/* fd_progcache_clock.h provides the cache eviction policy for the
   program cache (CLOCK).

   CLOCK is a cache replacement algorithm:
   Entries get evicted when their size class is full.

   The CLOCK algorithm works as follows:

   - There exists a "visited" flag for each record
   - Whenever a user accesses a record, the visited flag is set
   - When cache replacement kicks in, the class's record range is
     scanned (low-to-high cyclic).  For each record:
     - If the "visited" flag is set, unset it
     - Else ("visited" flag unset), evict the record

   State is one byte per record (the "state" array), shadowing the record
   array (including free records):

     FREE           (0)  record is on its class free list
     LIVE                record holds a value (mapped, or awaiting reclaim)
     LIVE|VISITED        as LIVE, recently accessed (CLOCK second chance)

   The byte array keeps scans off the 128-byte record lines and is the
   single source of truth for "is this record scannable" (rec->exists
   serves the different purpose of use-after-free detection on close). */

#include "../../util/bits/fd_bits.h"
#include "fd_progcache_base.h"

#define FD_PROGCACHE_REC_LIVE    ((uchar)1)
#define FD_PROGCACHE_REC_VISITED ((uchar)2)

FD_PROTOTYPES_BEGIN

/* Helper APIs for the per-record state array.  All accesses are relaxed
   atomics: CLOCK is approximate by design and lost visited updates are
   benign.  Transitions to/from FREE are additionally ordered by the class
   lock (free-list push/pop). */

static inline ulong
fd_progcache_state_align( void ) {
  return 64UL;
}

static inline ulong
fd_progcache_state_footprint( ulong rec_max ) {
  return fd_ulong_align_up( rec_max, 64UL );
}

/* fd_progcache_state_touch marks the record at the given index as recently
   accessed, which makes it less likely to get evicted. */

static inline void
fd_progcache_state_touch( uchar * state,
                          ulong   rec_idx ) {
  __atomic_fetch_or( &state[ rec_idx ], (uchar)( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_VISITED ), __ATOMIC_RELAXED );
}

/* fd_progcache_state_clear marks the record at the given index as free /
   removed (run when the record's value is released). */

static inline void
fd_progcache_state_clear( uchar * state,
                          ulong   rec_idx ) {
  __atomic_store_n( &state[ rec_idx ], (uchar)0, __ATOMIC_RELAXED );
}

/* fd_progcache_evict evicts a single record from the size class that fits `sz`
   (footprint 0 -> nx class), freeing its record+slot for reuse.  Used when
   that class is full; the caller loops for more.  Uses the class's own
   CLOCK hand, walking only that class's record range, so the scan is
   O(nslot[class]) not O(rec_max).  CLOCK second-chance applies (per-record
   visited flag).

   Records with readers are skipped rather than deleted: deleting one
   unmaps it without freeing its slot, so a class whose slots are all
   read-held would lose every entry and gain nothing.

   Returns 1 if a record was freed, 0 if the class holds nothing
   evictable.  A caller that gets 0 must not rescan in a loop -- the
   answer cannot change until some other thread releases a record -- and
   should wait for the spill buffer instead. */

int
fd_progcache_evict( fd_progcache_t * progcache,
                    ulong            sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h */
