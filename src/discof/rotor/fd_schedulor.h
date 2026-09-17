#ifndef HEADER_fd_src_discof_rotor_fd_schedulor_h
#define HEADER_fd_src_discof_rotor_fd_schedulor_h

/* fd_schedulor is a timeout queue of blocks awaiting a repair check.
   It is a data structure, not a state machine: the tile decides when a
   block needs checking and how long it should sleep.

   A block is identified by {slot, block_id}, the chainer's identity for
   a slot version, and its check carries the time it is due.  A block
   has at most one queued check: insert on a block with a check already
   queued is a no-op, so any caller may ask for a check without knowing
   whether one is pending, and nothing a caller does can move a queued
   check.  pop removes and returns the earliest check whose time has
   come; the schedulor then knows nothing about that block until it is
   inserted again.

   Times are floored to FD_SCHEDULOR_QUANTUM_NS so checks due in the
   same quantum are served lowest slot first, which keeps repair
   root-first among whatever is currently due. */

#include "../../flamenco/fd_flamenco_base.h" /* fd_hash_t */

#define FD_SCHEDULOR_QUANTUM_NS         ( 10000000L) /* 10 ms: timeout granularity, ties served lowest slot first        */
#define FD_SCHEDULOR_PARENT_TIMEOUT_NS  ( 50000000L) /* 50 ms: recheck after a parent was requested                       */
#define FD_SCHEDULOR_REQUEST_TIMEOUT_NS ( 80000000L) /* 80 ms: recheck after a fill pass, matches the legacy dedup window */

typedef struct fd_schedulor fd_schedulor_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_schedulor_align( void );

/* fd_schedulor_footprint returns the footprint for slotv_max blocks,
   which must equal the chainer's slotv pool max.  Returns 0 if
   slotv_max is 0 or too large. */

FD_FN_CONST ulong
fd_schedulor_footprint( ulong slotv_max );

void *
fd_schedulor_new( void * mem,
                  ulong  slotv_max,
                  ulong  seed );

fd_schedulor_t *
fd_schedulor_join( void * mem );

void *
fd_schedulor_leave( fd_schedulor_t const * schedulor );

void *
fd_schedulor_delete( void * mem );

/* fd_schedulor_block_insert queues a check of block {slot, block_id} at
   timeout.  If one is already queued this is a no-op. */

void
fd_schedulor_block_insert( fd_schedulor_t *  self,
                           ulong             slot,
                           fd_hash_t const * block_id,
                           long              timeout );

/* fd_schedulor_block_query returns 1 if a check of {slot, block_id} is
   queued, 0 otherwise. */

int
fd_schedulor_block_query( fd_schedulor_t const * self,
                          ulong                  slot,
                          fd_hash_t const *      block_id );

/* fd_schedulor_block_remove drops the queued check of {slot, block_id},
   if any. */

void
fd_schedulor_block_remove( fd_schedulor_t *  self,
                           ulong             slot,
                           fd_hash_t const * block_id );

/* fd_schedulor_block_pop removes the earliest check due at or before
   now, writes its block to *slot and *block_id and returns 1.  Returns
   0 and leaves the outputs untouched if nothing is due. */

int
fd_schedulor_block_pop( fd_schedulor_t * self,
                        long             now,
                        ulong *          slot,
                        fd_hash_t *      block_id );

/* fd_schedulor_publish drops every queued check of a block at or below
   root. */

void
fd_schedulor_publish( fd_schedulor_t * self,
                      ulong            root );

/* Introspection, for tests and metrics. */

ulong
fd_schedulor_queued_cnt( fd_schedulor_t const * self );

long
fd_schedulor_next_timeout( fd_schedulor_t const * self );

int
fd_schedulor_verify( fd_schedulor_t const * self );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rotor_fd_schedulor_h */
