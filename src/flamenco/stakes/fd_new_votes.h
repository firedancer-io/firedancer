#ifndef HEADER_fd_src_flamenco_stakes_fd_new_votes_h
#define HEADER_fd_src_flamenco_stakes_fd_new_votes_h

#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"
#include "../fd_rwlock.h"

/* fd_new_votes_t tracks vote account presence across epoch boundaries.
   It mirrors the memory layout and root/fork-delta pattern of
   fd_stake_delegations_t but uses a single shared pool that backs
   both the root map and the per-fork delta dlists. */

#define FD_NEW_VOTES_MAGIC    (0xF17EDA2CE7601E72UL) /* FIREDANCER NEWVOT V0 */
#define FD_NEW_VOTES_ALIGN    (128UL)
#define FD_NEW_VOTES_FORK_MAX (4096UL)

struct fd_new_vote_ele {
  fd_pubkey_t pubkey;
  uint        next;
  uint        prev;
};
typedef struct fd_new_vote_ele fd_new_vote_ele_t;

struct fd_new_votes {
  ulong magic;
  ulong max_vote_accounts;
  ulong pool_offset;
  ulong map_offset;
  ulong fork_pool_offset;
  ulong dlist_offsets[ FD_NEW_VOTES_FORK_MAX ];

  fd_rwlock_t lock;
};
typedef struct fd_new_votes fd_new_votes_t;

FD_PROTOTYPES_BEGIN

ulong
fd_new_votes_align( void );

ulong
fd_new_votes_footprint( ulong max_vote_accounts,
                        ulong expected_vote_accounts,
                        ulong max_live_forks );

void *
fd_new_votes_new( void * mem,
                  ulong  seed,
                  ulong  max_vote_accounts,
                  ulong  expected_vote_accounts,
                  ulong  max_live_forks );

fd_new_votes_t *
fd_new_votes_join( void * mem );

void
fd_new_votes_reset( fd_new_votes_t * new_votes );

void
fd_new_votes_reset_root( fd_new_votes_t * new_votes );

ulong
fd_new_votes_cnt( fd_new_votes_t const * new_votes );

ushort
fd_new_votes_new_fork( fd_new_votes_t * new_votes );

void
fd_new_votes_evict_fork( fd_new_votes_t * new_votes,
                         ushort           fork_idx );

void
fd_new_votes_insert( fd_new_votes_t *    new_votes,
                     ushort              fork_idx,
                     fd_pubkey_t const * pubkey );

void
fd_new_votes_apply_delta( fd_new_votes_t * new_votes,
                          ushort           fork_idx );


/* Iterates through all distinct pubkeys visible from a bank's
   perspective: first every entry in the root map, then every entry
   in the per-fork dlists (in the order given by fork_idxs), skipping
   any pubkey already present in the root map.

   The caller provides an array of fork indices (child-to-root order)
   and a scratch buffer for the iterator state.

   init acquires a read lock.  The caller MUST call fini after the loop
   to release it.

   Example:
     uchar __attribute__((aligned(FD_NEW_VOTES_ITER_ALIGN)))
       iter_mem[ FD_NEW_VOTES_ITER_FOOTPRINT ];
     for( fd_new_votes_iter_t * iter =
            fd_new_votes_iter_init( nv, fork_idxs, cnt, iter_mem );
          !fd_new_votes_iter_done( iter );
          fd_new_votes_iter_next( iter ) ) {
       fd_pubkey_t const * pk = fd_new_votes_iter_ele( iter );
     }
     fd_new_votes_iter_fini( iter ); */

#define FD_NEW_VOTES_ITER_FOOTPRINT (64UL)
#define FD_NEW_VOTES_ITER_ALIGN     (8UL)

struct fd_new_votes_iter;
typedef struct fd_new_votes_iter fd_new_votes_iter_t;

fd_new_votes_iter_t *
fd_new_votes_iter_init( fd_new_votes_t * new_votes,
                        ushort const *   fork_idxs,
                        ulong            fork_idx_cnt,
                        uchar *          iter_mem );

int
fd_new_votes_iter_done( fd_new_votes_iter_t const * iter );

void
fd_new_votes_iter_next( fd_new_votes_iter_t * iter );

fd_pubkey_t const *
fd_new_votes_iter_ele( fd_new_votes_iter_t const * iter );

void
fd_new_votes_iter_fini( fd_new_votes_iter_t * iter );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_new_votes_h */
