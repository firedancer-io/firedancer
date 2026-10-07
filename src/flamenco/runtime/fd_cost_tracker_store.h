#ifndef HEADER_fd_src_flamenco_runtime_fd_cost_tracker_store_h
#define HEADER_fd_src_flamenco_runtime_fd_cost_tracker_store_h

#include "fd_cost_tracker.h"

/* fd_cost_tracker_store_t tracks the cost trackers of live banks.  A
   new fd_cost_tracker_t is acquired when a bank starts executing and is
   released when the bank is frozen or pruned.  The representation of
   the cost trackers is partially in-memory and partially on disk.
   Generally, the cost trackers are not expected to spill to disk and
   will only happen in degenerate network conditions.  The caller is
   expected to manage the lifetime of each cost tracker. */

#define FD_COST_TRACKER_FD          (123455)
#define FD_COST_TRACKER_STORE_ALIGN (128UL)

struct fd_cost_tracker_store;
typedef struct fd_cost_tracker_store fd_cost_tracker_store_t;

FD_PROTOTYPES_BEGIN

/* fd_cost_tracker_store_align returns the alignment of a
   fd_cost_tracker_store_t struct. */

ulong
fd_cost_tracker_store_align( void );

/* fd_cost_tracker_store_footprint sizes the cost tracker store for a
   given max_live_slots and cache_cnt. */

ulong
fd_cost_tracker_store_footprint( ulong max_live_slots,
                                 ulong cache_cnt );

/* fd_cost_tracker_store_new creates a cost tracker store object. */

void *
fd_cost_tracker_store_new( void * shmem,
                           int    disk_fd,
                           ulong  max_live_slots,
                           ulong  cache_cnt,
                           ulong  bench_max_cost_per_block,
                           ulong  seed );

/* fd_cost_tracker_store_join joins a shared memory region that
   corresponds to a valid fd_cost_tracker_store_t struct. */

fd_cost_tracker_store_t *
fd_cost_tracker_store_join( void * shmem,
                            int    disk_fd );

/* fd_cost_tracker_store_new_fork releases old_fork_id (unless it is
   USHORT_MAX), then creates a new, empty cost tracker in the cost
   tracker store and returns its fork id.  Crashes if every cost tracker
   is in use. */

ushort
fd_cost_tracker_store_new_fork( fd_cost_tracker_store_t * store,
                                ushort                    old_fork_id );

/* fd_cost_tracker_store_release releases the cost tracker of fork_id in
   the cost tracker store.  The cost tracker is "deleted".  Crashes if it
   is pinned. */

void
fd_cost_tracker_store_release( fd_cost_tracker_store_t * store,
                               ushort                    fork_id );

/* fd_cost_tracker_store_{pin,unpin} pin and unpin the cost tracker of
   fork_id in memory, reading it from disk if needed.  These two must be
   paired together and is the only way to safely read or write the cost
   tracker.  Pins nest.  _peek can be called safely while the cost
   tracker is pinned. */

fd_cost_tracker_t *
fd_cost_tracker_store_pin( fd_cost_tracker_store_t * store,
                           ushort                    fork_id );

void
fd_cost_tracker_store_unpin( fd_cost_tracker_store_t * store,
                             ushort                    fork_id );

/* fd_cost_tracker_store_peek returns the in-memory cost tracker of
   fork_id.  It does not modify the store, so another thread may call it
   while the cost tracker is pinned.  Crashes if the cost tracker is not
   in memory. */

fd_cost_tracker_t *
fd_cost_tracker_store_peek( fd_cost_tracker_store_t const * store,
                            ushort                          fork_id );

/* fd_cost_tracker_store_reset resets the cost tracker store.  This is
   not meant for production use and is for testing only. */

void
fd_cost_tracker_store_reset( fd_cost_tracker_store_t * store );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_cost_tracker_store_h */
