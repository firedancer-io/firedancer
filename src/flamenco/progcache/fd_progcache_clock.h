#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h

/* fd_progcache_clock.h provides the cache eviction policy (CLOCK).

   A record is evicted when its size class is full: slots are drawn from that
   class's range, clearing the visited flag of any record that has it and
   evicting one that does not.  Access sets the flag.

   rec->state holds the flag, one byte per record including free ones:

     0                    free, or acquired and not yet published
     LOADING|MAPPED       published, program not yet loaded
     LIVE|MAPPED          holds a value and is reachable
     LIVE|VISITED|MAPPED  as above, recently accessed (CLOCK second chance)
     LOADING              unmapped mid-load; becomes a zombie when the load ends
     LIVE, LIVE|VISITED   zombie: unmapped; once detached and unheld, the next
                          eviction sweep hands its slot over (or a teardown
                          sweep frees it)

   It is the single source of truth for "is this record scannable" (rec->exists
   serves the different purpose of use-after-free detection on close). */

#include "fd_progcache_base.h"
#include "fd_progcache_rec.h"

#define FD_PROGCACHE_REC_LIVE    ((uchar)1)
#define FD_PROGCACHE_REC_VISITED ((uchar)2)

/* LOADING marks a record that is in the map but whose program is not loaded yet.  It
   serializes loaders: two tiles that miss on the same key do not both run
   fd_sbpf_program_load.  The first publishes the record LOADING and loads it; the rest
   find it in the map and wait.  It is not LIVE, so the CLOCK sweep steps over a record
   under load without a test of its own. */

#define FD_PROGCACHE_REC_LOADING ((uchar)4)

/* MAPPED marks a record reachable through the record map.  It is the only way to
   tell a rooted record, which stays mapped, from one a cancel or drain unmapped:
   both have txn_idx==UINT_MAX. */

#define FD_PROGCACHE_REC_MAPPED  ((uchar)8)

FD_PROTOTYPES_BEGIN

/* The visited flag is a relaxed hint: CLOCK is approximate and a lost update is
   benign.  The load sentinel is not -- setting and clearing it are release stores,
   paired with the acquire in fd_prog_state_is_loading. */

/* fd_prog_state_load_begin publishes the record at the given index as loading:
   reachable through the map, but not yet LIVE.  Ended by fd_prog_state_touch. */

static inline void
fd_prog_state_load_begin( fd_progcache_rec_t * ele,
                          ulong                rec_idx ) {
  __atomic_store_n( &ele[ rec_idx ].state,
                    (uchar)( FD_PROGCACHE_REC_LOADING|FD_PROGCACHE_REC_MAPPED ), __ATOMIC_RELEASE );
}

/* fd_prog_state_touch marks the record at the given index as recently
   accessed, which makes it less likely to get evicted.  It also ends a load: the
   record becomes LIVE and the sentinel goes away in a single release store, so a
   waiter never observes both clear, and the loaded program is visible to anyone
   who sees LIVE. */

static inline void
fd_prog_state_touch( fd_progcache_rec_t * ele,
                     ulong                rec_idx ) {
  uchar cur = __atomic_load_n( &ele[ rec_idx ].state, __ATOMIC_RELAXED );
  if( FD_UNLIKELY( cur & FD_PROGCACHE_REC_LOADING ) ) {
    /* LOADING is set and LIVE|VISITED clear here, so one xor performs the whole
       transition: a waiter never sees both LOADING and LIVE clear, and a
       concurrent unmap's MAPPED clear is not resurrected. */
    __atomic_fetch_xor( &ele[ rec_idx ].state,
                        (uchar)( FD_PROGCACHE_REC_LOADING|FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_VISITED ),
                        __ATOMIC_RELEASE );
    return;
  }
  __atomic_fetch_or( &ele[ rec_idx ].state, (uchar)( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_VISITED ), __ATOMIC_RELAXED );
}

/* fd_prog_state_is_loading returns 1 if a peer is still loading rec's program.  The
   acquire pairs with the release store in fd_prog_state_touch, so a caller that sees
   0 also sees the loaded program.  Deliberately not FD_FN_PURE: the value changes
   between calls, so a spin loop's calls must not be collapsed into one. */

static inline int
fd_prog_state_is_loading( fd_progcache_rec_t const * rec ) {
  return !!( __atomic_load_n( &rec->state, __ATOMIC_ACQUIRE ) & FD_PROGCACHE_REC_LOADING );
}

/* fd_prog_state_clear marks the record at the given index as free / removed, run
   when the record's value is released.  The release keeps the preceding teardown
   ordered before the record reads as free. */

static inline void
fd_prog_state_clear( fd_progcache_rec_t * ele,
                     ulong                rec_idx ) {
  __atomic_store_n( &ele[ rec_idx ].state, (uchar)0, __ATOMIC_RELEASE );
}

/* fd_prog_evict frees a record from the size class that fits sz
   and returns it read-locked and in-flight, as fd_progcache_rec_acquire does.
   Scans only that class's range, giving second chances and stepping over held
   records.  Returns NULL when the draws run out, the caller's cue to spill; that
   does not imply every record was held.  Release the return value with
   fd_progcache_rec_abandon. */

__attribute__((warn_unused_result))
fd_progcache_rec_t *
fd_prog_evict( fd_progcache_t * progcache,
               ulong            sz );

/* fd_prog_preevict tops up class class_idx's free list toward free_target: if
   the list is shorter, it runs one eviction sweep -- the fd_prog_evict scan in
   its admin variant, which bumps no metrics -- and releases the claimed
   victim's slot to the free list.  Returns the number of slots freed (0 or 1).
   Safe from any thread concurrently with everything; bounded by the sweep's
   2*class_max draw budget. */

ulong
fd_prog_preevict( fd_progcache_join_t * join,
                  ulong                 class_idx,
                  ulong                 free_target );

/* fd_progcache_housekeeping is one background maintenance tick: tops the next
   size class (round robin) toward 2 free slots via fd_prog_preevict, at most
   one slot per tick.  A zombie drawn by the sweep is handed over as-is (no
   second chance), so dead slots return to service without a separate
   collection pass.  Safe from any thread concurrently with everything.
   Unused: candidate replay housekeeping hook. */

void
fd_progcache_housekeeping( fd_progcache_join_t * join );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_clock_h */
