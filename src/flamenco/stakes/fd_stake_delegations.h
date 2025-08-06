#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"

#define FD_STAKE_DELEGATIONS_MAGIC (0x09151995UL)

/* fd_stakes_delegations_t is a cache of stake accounts mapping the
   pubkey of the stake account to various information including
   stake, activation/deactivation epoch, corresponding vote_account,
   credits observed, and warmup cooldown rate. This is used to quickly
   iterate through all of the stake delegations in the system during
   epoch boundary reward calculations.

   The implementation of fd_stakes_delegations_t is a hash map which
   is backed by a memory pool. Callers are allowed to insert, replace,
   and remove entries from the map.

   In practice, fd_stakes_delegations_t are updated in 3 cases:
   1. During bootup when the snapshot manifest is loaded in. The cache
      is also refreshed during the bootup process to ensure that the
      states are valid and up-to-date.

      The reason we can't populate the stake accounts from the cache
      is because the cache in the manifest is partially incomplete:
      all of the expected keys are there, but the values are not.
      Notably, the credits_observed field is not available until all of
      the accounts are loaded into the database.

      https://github.com/anza-xyz/agave/blob/v2.3.6/runtime/src/bank.rs#L1780-L1806

   2. After transaction execution. If an update is made to a stake
      account, the updated state is reflected in the cache (or the entry
      is evicted).
   3. During rewards distribution. Stake accounts are partitioned over
      several hundred slots where their rewards are distributed. In this
      case, the cache is updated to reflect each stake account post
      reward distribution.
   The stake accounts are read-only during the epoch boundary. */

/* The static footprint fo the stake delegation struct is roughly equal
   to the footprint of each stake_delegation * the number of total
   stake accounts that the system will support. If there are 3M stake
   accounts and each one is 112 bytes, then we can assume that the total
   number is ~360MB.

   TODO: This needs to be more carefully bounded where we account for
   the overhead of the map + pool headers as well as the alignment
   requirements.

   TODO: This needs to be a configurable constant based on the number
   of max delegations. */

#define FD_STAKE_DELEGATIONS_FOOTPRINT (360000000UL)

#define FD_STAKE_DELEGATIONS_ALIGN     (128UL)

/* FD_STAKES_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_STAKES_USE_HANDHOLDING
#define FD_STAKES_USE_HANDHOLDING 1
#endif

struct fd_stake_delegation {
  fd_pubkey_t stake_account;
  fd_pubkey_t vote_account;
  ulong       next_; /* Only for internal pool/map usage */
  ulong       stake;
  ulong       activation_epoch;
  ulong       deactivation_epoch;
  ulong       credits_observed;
  double      warmup_cooldown_rate;
};
typedef struct fd_stake_delegation fd_stake_delegation_t;

#define POOL_NAME fd_stake_delegation_pool
#define POOL_T    fd_stake_delegation_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

/* TODO: replace fd_hash with the more performant fd_funk_rec_key_hash1 */

#define MAP_NAME               fd_stake_delegation_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (!(memcmp(&(k0)->key,&(k1)->key,sizeof(fd_pubkey_t))))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next_
#include "../../util/tmpl/fd_map_chain.c"

struct fd_stake_delegations {
  ulong magic;
  ulong max_stake_accounts;
};
typedef struct fd_stake_delegations fd_stake_delegations_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_delegations_get_pool returns the underlying pool that the
   stake delegations uses to manage the stake delegations. */

fd_stake_delegation_t *
fd_stake_delegations_get_pool( fd_stake_delegations_t const * stake_delegations );

/* fd_stake_delegations_get_map returns the underlying map that the
   stake delegations uses to manage the stake delegations. */

fd_stake_delegation_map_t *
fd_stake_delegations_get_map( fd_stake_delegations_t const * stake_delegations );

/* fd_stake_delegations_align returns the alignment of the stake
   delegations struct. */

ulong
fd_stake_delegations_align( void );

/* fd_stake_delegations_footprint returns the footprint of the stake
   delegations struct for a given amount of max stake accounts. */

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts );

/* fd_stake_delegations_new creates a new stake delegations struct
   with a given amount of max stake accounts. It formats a memory region
   which is sized based off of the number of stake accounts. */

void *
fd_stake_delegations_new( void * mem, ulong max_stake_accounts );

/* fd_stake_delegations_join joins a stake delegations struct from a
   memory region. There can be multiple valid joins for a given memory
   region but the caller is responsible for accessing memory in a
   thread-safe manner. */

fd_stake_delegations_t *
fd_stake_delegations_join( void * mem );

/* fd_stake_delegations_leave returns the stake delegations struct
   from a memory region. */

void *
fd_stake_delegations_leave( fd_stake_delegations_t * self );

/* fd_stake_delegations_delete unformats a memory region that was
   formatted by fd_stake_delegations_new. */

void *
fd_stake_delegations_delete( void * mem );

/* fd_stake_delegations_update will either insert a new stake delegation
   if the pubkey doesn't exist yet, or it will update the stake
   delegation for the pubkey if already in the map, overriding any
   previous data. fd_stake_delegations_t must be a valid local join.

   NOTE: This function CAN be called while iterating over the map, but
   ONLY for keys which already exist in the map. */

void
fd_stake_delegations_update( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account,
                             fd_pubkey_t const *      vote_account,
                             ulong                    stake,
                             ulong                    activation_epoch,
                             ulong                    deactivation_epoch,
                             ulong                    credits_observed,
                             double                   warmup_cooldown_rate );

/* fd_stake_delegations_remove removes a stake delegation corresponding
   to a stake account's pubkey if one exists. Nothing happens if the
   key doesn't exist in the stake delegations. fd_stake_delegations_t
   must be a valid local join. */

void
fd_stake_delegations_remove( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account );


/* fd_stake_delegations_query returns the stake delegation for a
   stake account's pubkey if one exists. If one does not exist, returns
   NULL. fd_stake_delegations_t must be a valid local join. */

static inline fd_stake_delegation_t const *
fd_stake_delegations_query( fd_stake_delegations_t const * stake_delegations,
                            fd_pubkey_t const *            stake_account ) {

  #if FD_STAKES_USE_HANDHOLDING
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
    return NULL;
  }

  if( FD_UNLIKELY( !stake_account ) ) {
    FD_LOG_CRIT(( "NULL stake_account" ));
    return NULL;
  }
  #endif

  fd_stake_delegation_t const * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }

  fd_stake_delegation_map_t const * stake_delegation_map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  return fd_stake_delegation_map_ele_query_const(
      stake_delegation_map,
      stake_account,
      NULL,
      stake_delegation_pool );
}

/* fd_stake_delegations_cnt returns the number of stake delegations
   in the stake delegations struct. fd_stake_delegations_t must be a
   valid local join. */

static inline ulong
fd_stake_delegations_cnt( fd_stake_delegations_t const * stake_delegations ) {
  #if FD_STAKES_USE_HANDHOLDING
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }
  #endif

  fd_stake_delegation_t const * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  return fd_stake_delegation_pool_used( stake_delegation_pool );
}

static inline ulong
fd_stake_delegations_max( fd_stake_delegations_t const * stake_delegations ) {
  #if FD_STAKES_USE_HANDHOLDING
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }
  #endif

  return stake_delegations->max_stake_accounts;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h */
