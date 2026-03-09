#ifndef HEADER_fd_src_choreo_tower_fd_tower_lockos_h
#define HEADER_fd_src_choreo_tower_fd_tower_lockos_h

#include "../fd_choreo_base.h"
#include "fd_tower_voters.h"

/* fd_tower_lockos_interval tracks a map of lockout intervals.

   We need to track a list of lockout intervals per validator per slot.
   Intervals are inclusive.  Example:

   After executing slot 33, validator A votes for slot 32, has a tower

     vote  | confirmation count | lockout interval
     ----- | -------------------|------------------
     32    |  1                 | [32, 33]
     2     |  3                 | [2,  6]
     1     |  4                 | [1,  9]

   The lockout interval is the interval of slots that the validator is
   locked out from voting for if they want to switch off that vote.  For
   example if validator A wants to switch off fork 1, they have to wait
   until slot 9.

   Agave tracks a similar structure.

   key: for an interval [vote, vote+lockout] for validator A,
   it is stored like:
   vote+lockout -> (vote, validator A) -> (2, validator B) -> (any other vote, any other validator)

   Since a validator can have up to 31 entries in the tower, and we have
   a max_vote_accounts, we can pool the interval objects to be
   31*max_vote_accounts entries PER bank / executed slot. We can also
   string all the intervals of the same bank together as a linkedlist. */

struct fd_tower_lockos_interval {
  ulong     key;   /* vote_slot (32 bits) | expiration_slot (32 bits) ie. vote_slot + (1 << confirmation count) */
  ulong     next;  /* reserved for fd_map_chain and fd_pool */
  fd_hash_t addr;  /* vote account address */
  ulong     start; /* start of interval, also vote slot */
};
typedef struct fd_tower_lockos_interval fd_tower_lockos_interval_t;

#define MAP_NAME    fd_tower_lockos_interval_map
#define MAP_ELE_T   fd_tower_lockos_interval_t
#define MAP_MULTI   1
#define MAP_KEY     key
#define MAP_NEXT    next
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_tower_lockos_interval_pool
#define POOL_T    fd_tower_lockos_interval_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

struct fd_tower_lockos_slot {
  ulong   fork_slot;
  ulong   next;      /* reserved for fd_map_chain and fd_pool */
  ulong   interval_end;
};
typedef struct fd_tower_lockos_slot fd_tower_lockos_slot_t;

#define MAP_NAME    fd_tower_lockos_slot_map
#define MAP_ELE_T   fd_tower_lockos_slot_t
#define MAP_MULTI   1
#define MAP_KEY     fork_slot
#define MAP_NEXT    next
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_tower_lockos_slot_pool
#define POOL_T    fd_tower_lockos_slot_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

#define FD_TOWER_LOCKOS_MAX 31UL

struct __attribute__((aligned(128UL))) fd_tower_lockos {
  fd_tower_lockos_slot_map_t *     slot_map;
  fd_tower_lockos_slot_t *         slot_pool;
  fd_tower_lockos_interval_map_t * interval_map;
  fd_tower_lockos_interval_t *     interval_pool;
};
typedef struct fd_tower_lockos fd_tower_lockos_t;

FD_PROTOTYPES_BEGIN

/* fd_tower_lockos_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a tower_lockos. */

FD_FN_CONST static inline ulong
fd_tower_lockos_align( void ) {
  return 128UL;
}

FD_FN_CONST static inline ulong
fd_tower_lockos_footprint( ulong slot_max,
                           ulong vtr_max ) {
  ulong interval_max = fd_ulong_pow2_up( FD_TOWER_LOCKOS_MAX*slot_max*vtr_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_tower_lockos_t),            sizeof(fd_tower_lockos_t)                               ),
      fd_tower_lockos_slot_pool_align(),     fd_tower_lockos_slot_pool_footprint    ( interval_max ) ),
      fd_tower_lockos_slot_map_align(),      fd_tower_lockos_slot_map_footprint     ( slot_max     ) ),
      fd_tower_lockos_interval_pool_align(), fd_tower_lockos_interval_pool_footprint( interval_max ) ),
      fd_tower_lockos_interval_map_align(),  fd_tower_lockos_interval_map_footprint ( interval_max ) ),
    fd_tower_lockos_align() );
}

/* fd_tower_lockos_new formats an unused memory region for use as a
   tower_lockos.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_tower_lockos_new( void * shmem,
                     ulong  slot_max,
                     ulong  vtr_max,
                     ulong  seed );

/* fd_tower_lockos_join joins the caller to the tower_lockos. shlockos
   points to the first byte of the memory region backing the shlockos in
   the caller's address space.

   Returns a pointer in the local address space to lockos on success. */

fd_tower_lockos_t *
fd_tower_lockos_join( void * shlockos );

/* fd_tower_lockos_leave leaves a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include lockos is NULL. */

void *
fd_tower_lockos_leave( fd_tower_lockos_t const * lockos );

/* fd_tower_lockos_delete unformats a memory region used as a lockos.
   Assumes only the local process is joined to the region.  Returns a
   pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. lockos is obviously not a lockos ...  logs
   details).  The ownership of the memory region is transferred to the
   caller. */

void *
fd_tower_lockos_delete( void * lockos );

FD_FN_PURE static inline ulong
fd_tower_lockos_interval_key( ulong fork_slot, ulong end_interval ) {
  return (fork_slot << 32) | end_interval;
}

void
fd_tower_lockos_insert( fd_tower_lockos_t * lockos,
                        ulong               slot,
                        fd_hash_t const *   vote_acc,
                        fd_tower_voters_t * voters );

void
fd_tower_lockos_remove( fd_tower_lockos_t * lockos,
                        ulong               slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_lockos_h */
