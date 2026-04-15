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
  uint        prev;
  uint        marked;
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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_new_votes_h */
