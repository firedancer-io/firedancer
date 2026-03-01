#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h

#include "../rewards/fd_rewards_base.h"
#include "../runtime/fd_cost_tracker.h"
#include "../../disco/pack/fd_pack.h" /* TODO: Layering violation */
#include "../../disco/pack/fd_pack_cost.h"
#include "../../util/tmpl/fd_map.h"
#include "fd_stake_delegations.h"

#define FD_STAKE_DELEGATIONS_MAGIC (0xF17EDA2CE757A3E0) /* FIREDANCER STAKE V0 */

#define FD_STAKE_DELEGATIONS_ALIGN (128UL)

/* The warmup cooldown rate can only be one of two values: 0.25 or 0.09.
   The reason that the double is mapped to an enum is to save space in
   the stake delegations struct. */
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 (0)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 (1)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025      (0.25)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009      (0.09)

struct fd_stake_delegation_delta {
  fd_pubkey_t stake_account;
  fd_pubkey_t vote_account;
  ulong       stake;
  ulong       credits_observed;
  ushort      activation_epoch;
  ushort      deactivation_epoch;
  uchar       is_tombstone;
  uchar       warmup_cooldown_rate; /* enum representing 0.25 or 0.09 */
  uint        idx;

  uint        next_; /* Only for internal pool/map usage */
  uint        prev;
  uint        next;
};
typedef struct fd_stake_delegation fd_stake_delegation_t;

struct fd_stake_delegations_delta {
  ulong magic;
  ulong pool_offset_;
  ulong map_offset_;

  ushort dlist_offsets_[USHORT_MAX];

  ulong max_stake_accounts_;
};
typedef struct fd_stake_delegations_delta fd_stake_delegations_delta_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_delegations_align returns the alignment of the stake
   delegations struct. */

ulong
fd_stake_delegations_delta_align( void );

/* fd_stake_delegations_footprint returns the footprint of the stake
   delegations struct for a given amount of max stake accounts. */

ulong
fd_stake_delegations_delta_footprint( ulong max_stake_accounts,
                                      ulong max_live_slots );

/* fd_stake_delegations_new creates a new stake delegations struct
   with a given amount of max stake accounts. It formats a memory region
   which is sized based off of the number of stake accounts. The struct
   can optionally be configured to leave tombstones in the map. This is
   useful if fd_stake_delegations is being used as a delta. */

void *
fd_stake_delegations_delta_new( void * mem,
                                ulong  seed,
                                ulong  max_stake_accounts,
                                ulong  max_live_slots,
                                int    leave_tombstones );

/* fd_stake_delegations_join joins a stake delegations struct from a
   memory region. There can be multiple valid joins for a given memory
   region but the caller is responsible for accessing memory in a
   thread-safe manner. */

fd_stake_delegations_delta_t *
fd_stake_delegations_delta_join( void * mem );

/* fd_stake_delegations_new_fork resets the state of a valid join of a
   stake delegations struct. */

ushort
fd_stake_delegations_delta_new_fork( fd_stake_delegations_delta_t * stake_delegations );

/* fd_stake_delegations_update will either insert a new stake delegation
   if the pubkey doesn't exist yet, or it will update the stake
   delegation for the pubkey if already in the map, overriding any
   previous data. fd_stake_delegations_t must be a valid local join.

   NOTE: This function CAN be called while iterating over the map, but
   ONLY for keys which already exist in the map. */

void
fd_stake_delegations_delta_update( fd_stake_delegations_delta_t * stake_delegations,
                                   ushort                         fork_idx,
                                   fd_pubkey_t const *            stake_account,
                                   fd_pubkey_t const *            vote_account,
                                   ulong                          stake,
                                   ulong                          activation_epoch,
                                   ulong                          deactivation_epoch,
                                   ulong                          credits_observed,
                                   double                         warmup_cooldown_rate );

/* fd_stake_delegations_remove removes a stake delegation corresponding
   to a stake account's pubkey if one exists. Nothing happens if the
   key doesn't exist in the stake delegations. fd_stake_delegations_t
   must be a valid local join.

   NOTE: If the leave_tombstones flag is set, then the entry is not
   removed from the map, but rather set to a tombstone. If the
   delegation does not exist in the map, then a tombstone is actually
   inserted into the struct. */

void
fd_stake_delegations_remove( fd_stake_delegations_delta_t * stake_delegations,
                             ushort                         fork_idx,
                             fd_pubkey_t const *            stake_account );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h */
