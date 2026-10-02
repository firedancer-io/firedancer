#ifndef HEADER_fd_src_flamenco_stakes_fd_epoch_credits_h
#define HEADER_fd_src_flamenco_stakes_fd_epoch_credits_h

#include "../fd_flamenco_base.h"

/* fd_epoch_credits_store_t holds the epoch credits of every rewarded
   vote account.  They are captured when a bank crosses an epoch
   boundary, and are read again for the rest of the epoch.  The
   representation of the epoch credits is stored across an in-memory
   cache and a backing file.  Generally, the epoch credits are not
   expected to spill to disk and will only happen in degenerate network
   conditions. */

#define FD_EPOCH_CREDITS_FD          (123456)
#define FD_EPOCH_CREDITS_STORE_ALIGN (128UL)

struct fd_epoch_credits_store;
typedef struct fd_epoch_credits_store fd_epoch_credits_store_t;

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
