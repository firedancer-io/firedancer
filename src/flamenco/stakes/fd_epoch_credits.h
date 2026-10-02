#ifndef HEADER_fd_src_flamenco_stakes_fd_epoch_credits_h
#define HEADER_fd_src_flamenco_stakes_fd_epoch_credits_h

#include "../fd_flamenco_base.h"

/* fd_epoch_credits_store_t holds the epoch credits of every rewarded
   vote account.  They are captured when a bank crosses an epoch
   boundary, and are read again for the rest of the epoch: by a
   recalculation that repositions a stake rewards window, and by
   snapshot creation.  Sibling banks crossing the same boundary capture
   different sets, inherited by descendants and reference counted so
   that a set lives exactly as long as the banks and pinned readers
   using it.

   Sets are identified by fork id.  There is one logical set per live
   slot, but only a configured number of full sets reside in memory.
   Unpinned cache entries spill to a backing file.  Every process
   joining the store must have that file open at the same descriptor.

   All operations take an internal exclusive lock. */

/* Sets beyond the in-memory cache spill to this boot-created, unlinked
   file.  123457 is the stake-delegation spill, 123458/123459 are store,
   123460/123461 are accdb, and 123462+ are reserved by XDP. */

#define FD_EPOCH_CREDITS_FD          (123456)
#define FD_EPOCH_CREDITS_STORE_ALIGN (128UL)

struct fd_epoch_credits_store;
typedef struct fd_epoch_credits_store fd_epoch_credits_store_t;

/* A view pins one set in the memory cache.  credits and len are valid
   until fini.  write must be nonzero when credits or len will be
   modified.  Every successful init must be paired with fini promptly so
   another cold set can reuse the cache entry. */

struct fd_epoch_credits_view {
  fd_epoch_credits_t *       credits;
  fd_epoch_credits_store_t * store;
  ulong                      len;
  ulong                      set_idx;
  ulong                      cache_idx;
  int                        write;
};
typedef struct fd_epoch_credits_view fd_epoch_credits_view_t;

FD_PROTOTYPES_BEGIN

ulong
fd_epoch_credits_store_align( void );

/* fd_epoch_credits_store_footprint returns the footprint of a store
   with one logical set per live slot, of which at most cache_cnt reside
   in memory.  Returns 0 if max_live_slots is zero or does not fit a
   fork id, or if cache_cnt is zero.  A cache_cnt above max_live_slots
   is reduced to max_live_slots.  A view waits while every cache entry
   is pinned, so a caller must not hold a view while it starts a view
   of another set unless cache_cnt is at least 2. */

ulong
fd_epoch_credits_store_footprint( ulong max_live_slots,
                                  ulong cache_cnt );

void *
fd_epoch_credits_store_new( void * shmem,
                            int    disk_fd,
                            ulong  max_live_slots,
                            ulong  cache_cnt );

/* disk_fd must match the descriptor provided to
   fd_epoch_credits_store_new. */

fd_epoch_credits_store_t *
fd_epoch_credits_store_join( void * shmem,
                             int    disk_fd );

/* fd_epoch_credits_store_reset releases every set and empties the
   cache.  No view may be active. */

void
fd_epoch_credits_store_reset( fd_epoch_credits_store_t * store );

/* fd_epoch_credits_store_new_fork releases prev_fork_id (unless it is
   USHORT_MAX) and returns the fork id of a fresh, empty set holding one
   reference.  The release happens first so a uniquely held set can be
   replaced when every set is in use. */

ushort
fd_epoch_credits_store_new_fork( fd_epoch_credits_store_t * store,
                                 ushort                     prev_fork_id );

void
fd_epoch_credits_store_acquire( fd_epoch_credits_store_t * store,
                                ushort                     fork_id );

/* fd_epoch_credits_store_release drops a reference.  The set is freed
   when its last reference is dropped. */

void
fd_epoch_credits_store_release( fd_epoch_credits_store_t * store,
                                ushort                     fork_id );

/* fd_epoch_credits_store_clear empties a referenced set in place. */

void
fd_epoch_credits_store_clear( fd_epoch_credits_store_t * store,
                              ushort                     fork_id );

fd_epoch_credits_view_t *
fd_epoch_credits_view_init( fd_epoch_credits_view_t *  view,
                            fd_epoch_credits_store_t * store,
                            ushort                     fork_id,
                            int                        write );

void
fd_epoch_credits_view_fini( fd_epoch_credits_view_t * view );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_epoch_credits_h */
