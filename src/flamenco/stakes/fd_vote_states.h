#ifndef HEADER_fd_src_flamenco_stakes_fd_vote_states_h
#define HEADER_fd_src_flamenco_stakes_fd_vote_states_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../../util/fd_util_base.h"

#define FD_VOTE_STATES_MAGIC (0x0123196511111111UL)

/* fd_vote_states_t is a cache of vote accounts mapping the pubkey of
   a vote account to various infromation about the vote account
   including, stake, last vote slot/timestamp, commission, and the
   epoch credits for the vote account.

   In the runtime, there are 3 instances of fd_vote_states_t that are
   maintained and used at different points, notably around epoch reward
   and leader schedule calculations. The 3 instances are:
   1. vote_states: This is the vote states for the current epoch. This
      is updated through the course of an epoch as vote accounts are
      updated.
   2. vote_states_prev: This is the vote states as of the end of
      previous epoch E-1 if we are currently executing epoch E.
      This gets updated at the end of an epoch when vote_states are
      copied into vote_states_prev.
   3. vote_states_prev_prev: This is the vote states as of the end of
      epoch E-2 if we are currently executing epoch E. This only gets
      updated at the end of an epoch when vote_states_prev is copied
      into vote_states_prev_prev.

   The implementation of fd_vote_states_t is a hash map which is backed
   by a memory pool. Callers are allowed to insert, replace, and remove
   entries from the map.

   In practice, fd_vote_states_t are updated in 3 cases:
   1. They are initially populated from the versioned vote account
      stake accounts in the snapshot manifest. These are populated from
      the raw vote account data. This is done in a single pass over the
      vote account data.
   2. The vote states for the current epoch can be updated after
      transaction execution. This is done for vote accounts that are
      referenced during a transaction.
   3. Vote states are updated at the epoch boundary. The stake
      information for the vote states is refreshed at the boundary.
      TODO: The total stake delegated to a vote account should be
      calculated during execution as the stake delegations are updated.
*/

#define FD_VOTE_STATES_ALIGN (128UL)

/* Agave defines the max number of epoch credits to store to be 64.
   https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v2.2.6/vote-interface/src/state/mod.rs#L37 */
#define EPOCH_CREDITS_MAX (64UL)

/* FD_STAKES_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_VOTE_STATES_USE_HANDHOLDING
#define FD_VOTE_STATES_USE_HANDHOLDING 1
#endif

struct fd_vote_state_ele {
  fd_pubkey_t vote_account;
  fd_pubkey_t node_account;
  ulong       next_; /* Internal pool/map use */
  ulong       stake;
  ulong       last_vote_slot;
  long        last_vote_timestamp;
  uchar       commission;

  ulong       credits_cnt;
  ushort      epoch       [ EPOCH_CREDITS_MAX ];
  ulong       credits     [ EPOCH_CREDITS_MAX ];
  ulong       prev_credits[ EPOCH_CREDITS_MAX ];
};
typedef struct fd_vote_state_ele fd_vote_state_ele_t;


#define POOL_NAME fd_vote_state_pool
#define POOL_T    fd_vote_state_ele_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_vote_state_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_vote_state_ele_t
#define MAP_KEY                vote_account
#define MAP_KEY_EQ(k0,k1)      (!(memcmp( &(k0)->key,&(k1)->key,sizeof(fd_pubkey_t) )))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next_
#include "../../util/tmpl/fd_map_chain.c"

struct __attribute__((aligned(FD_VOTE_STATES_ALIGN))) fd_vote_states {
  ulong magic;
  ulong max_vote_accounts;
};
typedef struct fd_vote_states fd_vote_states_t;

/* This guarantees that the pool alignment is at most 128UL. */
FD_STATIC_ASSERT(alignof(fd_vote_state_ele_t)<=FD_VOTE_STATES_ALIGN, unexpected pool element alignment);

/* The static footprint of the vote states assumes that there are
   FD_RUNTIME_MAX_VOTE_ACCOUNTS. It also assumes worst case alignment
   for each struct. fd_vote_states_t is laid out as first the
   fd_vote_states_t struct, followed by a pool of fd_vote_state_ele_t
   structs, followed by a map of fd_vote_state_map_ele_t structs.
   The pool has FD_RUNTIME_MAX_VOTE_ACCOUNTS elements, and the map
   has a chain count deteremined by a call to
   fd_vote_states_chain_cnt_est.
   NOTE: the footprint is validated to be at least as large as the
   actual runtime-determined footprint (see test_vote_states.c) */

#define FD_VOTE_STATES_CHAIN_CNT_EST (65536UL)
#define FD_VOTE_STATES_FOOTPRINT                                                      \
  /* First, layout the struct with alignment */                                       \
  sizeof(fd_vote_states_t) + alignof(fd_vote_states_t) +                              \
  /* Now layout the pool's data footprint */                                          \
  FD_VOTE_STATES_ALIGN + sizeof(fd_vote_state_ele_t) * FD_RUNTIME_MAX_VOTE_ACCOUNTS + \
  /* Now layout the pool's meta footprint */                                          \
  FD_VOTE_STATES_ALIGN + sizeof(fd_vote_state_pool_private_t) +                       \
  /* Now layout the map.  We must make assumptions about the chain */                 \
  /* count to be equivalent to chain_cnt_est. */                                      \
  FD_VOTE_STATES_ALIGN + sizeof(fd_vote_state_map_private_t) + (FD_VOTE_STATES_CHAIN_CNT_EST * sizeof(ulong))

FD_PROTOTYPES_BEGIN

/* fd_vote_states_get_pool returns the underlying pool that the
   vote states uses to manage the vote states. */

fd_vote_state_ele_t *
fd_vote_states_get_pool( fd_vote_states_t const * vote_states );

/* fd_vote_states_get_map returns the underlying map that the
   vote states uses to manage the vote states. */

fd_vote_state_map_t *
fd_vote_states_get_map( fd_vote_states_t const * vote_states );

/* fd_vote_states_align returns the minimum alignment required for a
   vote states struct. */

FD_FN_CONST ulong
fd_vote_states_align( void );

/* fd_vote_states_footprint returns the footprint of the vote states
   struct for a given amount of max vote accounts. */

FD_FN_CONST ulong
fd_vote_states_footprint( ulong max_vote_accounts );

/* fd_vote_states_new creates a new vote states struct with a given
   number of max vote accounts and a seed. It formats a memory region
   which is sized based off of the number of vote accounts. */

void *
fd_vote_states_new( void * mem,
                    ulong  max_vote_accounts,
                    ulong  seed );

/* fd_vote_states_join joins a vote states struct from a
   memory region. There can be multiple valid joins for a given memory
   region but the caller is responsible for accessing memory in a
   thread-safe manner. */

fd_vote_states_t *
fd_vote_states_join( void * mem );

/* fd_vote_states_update inserts or updates the vote state corresponding
   to a given account. The caller is expected to pass in valid arrays of
   epoch, credits, and prev_credits that corresponds to a length of
   credits_cnt. */

void
fd_vote_states_update( fd_vote_states_t *  vote_states,
                       fd_pubkey_t const * vote_account,
                       fd_pubkey_t const * node_account,
                       uchar               commission,
                       long                last_vote_timestamp,
                       ulong               last_vote_slot,
                       ulong               credits_cnt,
                       ushort *            epoch,
                       ulong *             credits,
                       ulong *             prev_credits );

/* fd_vote_states_update_from_account inserts or updates the vote state
   corresponding to a valid vote account. This is the same as
   fd_vote_states_update but is also responsible for decoding the vote
   account data into a versioned vote state object and extracing the
   commission and credits. */

void
fd_vote_states_update_from_account( fd_vote_states_t *  vote_states,
                                    fd_pubkey_t const * vote_account,
                                    uchar const *       account_data,
                                    ulong               account_data_len );

/* fd_vote_states_reset_stakes_t resets the stakes to 0 for each of the
   vote accounts in fd_vote_states_t. */

void
fd_vote_states_reset_stakes( fd_vote_states_t * vote_states );

/* fd_vote_states_update_stake updates the stake for a given vote
   account. */

void
fd_vote_states_update_stake( fd_vote_states_t *  vote_states,
                             fd_pubkey_t const * vote_account,
                             ulong               stake );

/* fd_vote_states_remove removes the vote state corresponding to a given
   account. Does nothing if the account does not exist. */

void
fd_vote_states_remove( fd_vote_states_t *  vote_states,
                       fd_pubkey_t const * vote_account );

/* fd_vote_states_query returns the vote state corresponding to a given
   account. Returns NULL if the account does not exist. */

static inline fd_vote_state_ele_t *
fd_vote_states_query( fd_vote_states_t const * vote_states,
                      fd_pubkey_t const *      vote_account ) {

  fd_vote_state_ele_t * vote_state = fd_vote_state_map_ele_query(
      fd_vote_states_get_map( vote_states ),
      vote_account,
      NULL,
      fd_vote_states_get_pool( vote_states ) );
  if( FD_UNLIKELY( !vote_state ) ) {
    return NULL;
  }

  return vote_state;
}

/* fd_vote_states_max returns the maximum number of vote accounts that
   the vote states struct can support. */

static inline ulong
fd_vote_states_max( fd_vote_states_t const * vote_states ) {
  return vote_states->max_vote_accounts;
}

/* fd_vote_states_cnt returns the number of vote states in the vote
   states struct. */

static inline ulong
fd_vote_states_cnt( fd_vote_states_t const * vote_states ) {
  return fd_vote_state_pool_used( fd_vote_states_get_pool( vote_states ) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_vote_states_h */
