#ifndef HEADER_fd_src_flamenco_stakes_fd_epoch_credits_h
#define HEADER_fd_src_flamenco_stakes_fd_epoch_credits_h

#include "../fd_flamenco_base.h"

/* fd_epoch_credits_store_t holds the epoch credits of every rewarded
   vote account.  They are captured when a bank crosses an epoch
   boundary, and are read again for the rest of the epoch.  The
   representation of the epoch credits is stored across an in-memory
   cache and a backing file.  Generally, the epoch credits are not
   expected to spill to disk and will only happen in degenerate network
   conditions.  It's assumed that epoch credits will only have one
   single-threaded caller. */

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

/* fd_epoch_credits_store_align returns the alignment of a
   fd_epoch_credits_store_t struct. */

ulong
fd_epoch_credits_store_align( void );

/* fd_epoch_credits_store_footprint sizes the epoch credits store for a
   given max_live_slots and cache_cnt. */

ulong
fd_epoch_credits_store_footprint( ulong max_live_slots,
                                  ulong cache_cnt );

/* fd_epoch_credits_store_new creates a epoch credits store object */

void *
fd_epoch_credits_store_new( void * shmem,
                            int    disk_fd,
                            ulong  max_live_slots,
                            ulong  cache_cnt );

/* fd_epoch_credits_store_join joins a shared memory region that
   corresponds to a valid fd_epoch_credits_store_t struct. */

fd_epoch_credits_store_t *
fd_epoch_credits_store_join( void * shmem,
                             int    disk_fd );

/* fd_epoch_credits_store_new_fork creates a new fork in the epoch
   credits store and returns the fork id.  */

ushort
fd_epoch_credits_store_new_fork( fd_epoch_credits_store_t * store );

/* fd_epoch_credits_store_acquire acquires a reference to a fork in the
   epoch credits store. */

void
fd_epoch_credits_store_acquire( fd_epoch_credits_store_t * store,
                                ushort                     fork_id );

/* fd_epoch_credits_store_release releases a reference to a fork in the
   epoch credits store. */

void
fd_epoch_credits_store_release( fd_epoch_credits_store_t * store,
                                ushort                     fork_id );

/* fd_epoch_credits_view_{init,fini} pin and unpin the fork's set in
   memory, reading it from disk if needed.  These two must be paired
   together and is the only way to safely read or write the epoch
   credits. */

fd_epoch_credits_view_t *
fd_epoch_credits_view_init( fd_epoch_credits_view_t *  view,
                            fd_epoch_credits_store_t * store,
                            ushort                     fork_id,
                            int                        write );

void
fd_epoch_credits_view_fini( fd_epoch_credits_view_t * view );

/* fd_epoch_credits_store_reset resets the epoch credits store.  This
   is not meant for production use and is for testing only. */

void
fd_epoch_credits_store_reset( fd_epoch_credits_store_t * store );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_epoch_credits_h */
