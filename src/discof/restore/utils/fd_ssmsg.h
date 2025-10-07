#ifndef HEADER_fd_src_discof_restore_utils_fd_ssmsg_h
#define HEADER_fd_src_discof_restore_utils_fd_ssmsg_h

#include "../../../flamenco/types/fd_types.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"
#include "../../../flamenco/stakes/fd_vote_states.h"

#define FD_SSMSG_MANIFEST_FULL        (0) /* A snapshot manifest message from the full snapshot */
#define FD_SSMSG_MANIFEST_INCREMENTAL (1) /* A snapshot manifest message from the incremental snapshot */
#define FD_SSMSG_DONE                 (2) /* Indicates the snapshot is fully loaded and tiles are shutting down */
#define FD_SSMSG_EXPECTED_SLOT        (3) /* Expected rooted slot from incremental snapshot */

FD_FN_CONST static inline ulong
fd_ssmsg_sig( ulong message ) {
  return (message & 0x3UL);
}

FD_FN_CONST static inline ulong fd_ssmsg_sig_message( ulong sig ) { return (sig & 0x3UL); }
struct epoch_credits {
  ulong epoch;
  ulong credits;
  ulong prev_credits;
};

typedef struct epoch_credits epoch_credits_t;

/* The FD_SSMSG_EXPECTED_SLOT uses the tsorig and tspub fields
   of the fd_frag_meta_t struct to store the low and high 32 bits of
   the slot number. */
static inline void
fd_ssmsg_slot_to_frag( ulong slot,
                       uint* low,
                       uint* high ) {
   *low = (uint)(slot & 0xFFFFFFFFUL);
   *high = (uint)((slot >> 32UL) & 0xFFFFFFFFUL);
}

static inline void
fd_ssmsg_frag_to_slot( ulong low,
                       ulong high,
                       ulong* slot ) {
   *slot = (high << 32UL) | low;
}

struct fd_snapshot_manifest_vote_account {
  /* The pubkey of the vote account */
  uchar vote_account_pubkey[ 32UL ];

  /* The pubkey of the node account */
  uchar node_account_pubkey[ 32UL ];

  ulong stake;
  ulong last_slot;
  long  last_timestamp;

  /* The percent of inflation rewards earned by the validator and
     deposited into the validator's vote account, from 0 to 100%.
     The remaning percentage of inflation rewards is distributed to
     all delegated stake accounts by stake weight. */
  uchar commission;

  /* The epoch credits array tracks the history of how many credits the
     provided vote account earned in each of the past epochs.  The
     entry at epoch_credits[0] is for the current epoch,
     epoch_credits[1] is for the previous epoch, and so on.  In cases of
     booting a new chain from genesis, or for new vote accounts the
     epoch credits history may be short.  The maximum number of entries
     in the epoch credits history is 64. */
  ulong epoch_credits_history_len;
  epoch_credits_t epoch_credits[ EPOCH_CREDITS_MAX ];
};

typedef struct fd_snapshot_manifest_vote_account fd_snapshot_manifest_vote_account_t;

struct fd_snapshot_manifest_stake_delegation {
  /* The stake pubkey */
  uchar stake_pubkey[ 32UL ];

  /* The vote pubkey that the stake account is delegated to */
  uchar vote_pubkey[ 32UL ];

  /* The amount of stake delegated */
  ulong stake_delegation;

  /* The activation epoch of the stake delegation */
  ulong activation_epoch;

  /* The deactivation epoch of the stake delegation */
  ulong deactivation_epoch;

  /* The amount of credits observed for the stake delegation */
  ulong credits_observed;

  /* The warmup cooldown rate for the stake delegation */
  double warmup_cooldown_rate;
};

typedef struct fd_snapshot_manifest_stake_delegation fd_snapshot_manifest_stake_delegation_t;

/* TODO: Consider combining this struct with
   fd_snapshot_manifest_vote_account. */

struct fd_snapshot_manifest_vote_stakes {
  /* The vote pubkey */
  uchar vote[ 32UL ];

  /* The validator identity pubkey, aka node pubkey */
  uchar identity[ 32UL ];

  /* The commission account for inflation rewards (vote, before SIMD-0232) */
  uchar commission_inflation[ 32UL ];

  /* The commission account for block revenue (identity, before SIMD-0232) */
  uchar commission_block[ 32UL ];

  /* The validator BLS pubkey (used after SIMD-0326: Alpenglow) */
  uchar identity_bls[ 48UL ];

  /* The total amount of active stake for the vote account */
  ulong stake;

  /* The latest slot and timestmap that the vote account voted on in
     the given epoch. */
  ulong slot;
  long  timestamp;

  /* The validator's commission rate as of the given epoch. */
  uchar commission;

  /* The epoch credits array tracks the history of how many credits the
     provided vote account earned in each of the past epochs.  The
     entry at epoch_credits[0] is for the current epoch,
     epoch_credits[1] is for the previous epoch, and so on.  In cases of
     booting a new chain from genesis, or for new vote accounts the
     epoch credits history may be short.  The maximum number of entries
     in the epoch credits history is 64. */
  ulong           epoch_credits_history_len;
  epoch_credits_t epoch_credits[ EPOCH_CREDITS_MAX ];
};

typedef struct fd_snapshot_manifest_vote_stakes fd_snapshot_manifest_vote_stakes_t;

struct fd_snapshot_manifest_epoch_stakes {
  /* The total amount of active stake at the end of the given epoch.*/
  ulong                              total_stake;

  /* The vote accounts and their stakes for a given epoch. */
  ulong                              vote_stakes_len;
  fd_snapshot_manifest_vote_stakes_t vote_stakes[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];
};

typedef struct fd_snapshot_manifest_epoch_stakes fd_snapshot_manifest_epoch_stakes_t;

struct fd_snapshot_manifest_inflation_params {
  /* The initial inflation percentage starting at genesis.
     This value is set at genesis to 8% and is not expected to change. */
  double initial;

  /* The terminal inflation percentage is the long-term steady state
     inflation rate after a period of disinflation.  This value is set
     at genesis to 1.5% and is not expected to change. */
  double terminal;

  /* The rate per year at which inflation is lowered until it reaches
     the terminal inflation rate.  This value is set to 15% at genesis
     and is not expected to change. */
  double taper;

  /* The percentage of total inflation allocated to the foundation.
     This value is set at genesis to 5% and is not expected to change. */
  double foundation;

  /* The number of years in which a portion of the total inflation is
     allocated to the foundation (see foundation field).  This value is
     set to 7 years at genesis and is not expected to change. */
  double foundation_term;
};

typedef struct fd_snapshot_manifest_inflation_params fd_snapshot_manifest_inflation_params_t;

struct fd_snapshot_manifest_epoch_schedule_params {
  /* The maximum number of slots in each epoch. */
  ulong slots_per_epoch;

  /* A number of slots before beginning of an epoch to calculate a
     leader schedule for that epoch.  This value is set to
     slots_per_epoch (basically one epoch) and is unlikely to change. */
  ulong leader_schedule_slot_offset;

  /* Whether there is a warmup period where epochs are short and grow by
     powers of two until they reach the default epoch length of
     slots_per_epoch.  This value is set by default to true at genesis,
     though it may be configured differently in development
     environments. */
  uchar warmup;

  /* TODO: Probably remove this? Redundant and can be calculated from
     the above. */
  ulong first_normal_epoch;
  ulong first_normal_slot;
};

typedef struct fd_snapshot_manifest_epoch_schedule_params fd_snapshot_manifest_epoch_schedule_params_t;

struct fd_snapshot_manifest_fee_rate_governor {
  /* Transaction fees are calculated by charging a cost for each
     signature.  There is a mechanism to dynamically adjust the cost per
     signature based on the cluster's transaction processing capacity.
     In this mechanism, the cost per signature can vary between 50% to
     1000% of the target_lamports_per_signature value, which is the cost
     per signature when the cluster is operating at the desired
     transaction processing capacity defined by
     target_signatures_per_slot.

     This value is fixed at 10,000 from genesis onwards but may be
     changed in the future with feature flags. */
  ulong target_lamports_per_signature;

  /* The cluster transaction processing capacity is measured by
     signatures per slot.  Solana defines the desired transaction
     processing capacity using the value target_signatures_per_slot.

     This value is fixed at 20,000 from genesis onwards but may be
     changed in the future with feature flags. */
  ulong target_signatures_per_slot;

  /* The minimum cost per signature is 50% of the
     target_lamports_per_signature value.  Under the current default for
     target_lamports_per_signature, this value is at 5,000 lamports per
     signature. */
  ulong min_lamports_per_signature;

  /* The maximum cost per signature is 1000% of the
     target_lamports_per_signature value.  Under the current default for
     target_lamports_per_signature, this value is at 100,000 lamports
     per signature.*/
  ulong max_lamports_per_signature;

  /* The percent of collected fees that are burned.  This value is
     currently set to a fixed value of 50% from genesis onwards, but
     may be changed in the future with feature flags. */
  uchar burn_percent;
};

typedef struct fd_snapshot_manifest_fee_rate_governor fd_snapshot_manifest_fee_rate_governor_t;

struct fd_snapshot_manifest_rent {
  ulong lamports_per_uint8_year;
  double exemption_threshold;
  uchar burn_percent;
};

typedef struct fd_snapshot_manifest_rent fd_snapshot_manifest_rent_t;

struct fd_snapshot_manifest_blockhash {
   uchar hash[ 32UL ];
   ulong lamports_per_signature;
   ulong hash_index;
   ulong timestamp;
};

typedef struct fd_snapshot_manifest_blockhash fd_snapshot_manifest_blockhash_t;

struct fd_snapshot_manifest {
  /* The UNIX timestamp when the genesis block was for this chain
     was created, in nanoseconds.  */
  ulong creation_time_millis;

  /* At genesis, certain parameters can be set which control the
     inflation rewards going forward.  This includes what the initial
     inflation is and how the inflation curve changes over time.

     Currently, these parameters can never change and are fixed from
     genesis onwards, although in future they may change with new
     feature flags. */
  fd_snapshot_manifest_inflation_params_t inflation_params;

  /* At genesis, certain parameters can be set which control the
     epoch schedule going forward.  This includes how many slots
     there are per epoch, and certain development settings like if
     epochs start short and grow longer as the chain progreses.

     Currently, these parameters can never change and are fixed from
     genesis onwards, although in future they may change with new
     feature flags. */
  fd_snapshot_manifest_epoch_schedule_params_t epoch_schedule_params;

  /* At genesis, certain parameters can be set which control
     how transaction fees are dynamically adjusted going forward.

     Currently, these parameters can never change and are fixed from
     genesis onwards, although in future they may change with new
     feature flags. */
  fd_snapshot_manifest_fee_rate_governor_t fee_rate_governor;

  fd_snapshot_manifest_rent_t rent_params;

  /* The slot number for this snapshot */
  ulong slot;

  /* The number of blocks that have been built since genesis.  This is
     kind of like the slot number, in that it increments by 1 for every
     landed block, but it does not increment for skipped slots, so the
     block_height will always be less than or equal to the slot. */
  ulong block_height;

  /* TODO: Document */
  ulong collector_fees;

  /* The parent slot is the slot that this block builds on top of.  It
     is typically slot-1, but can be an arbitrary amount of slots
     earlier in case of forks, when the block skips over preceding
     slots. */
  ulong parent_slot;

  /* The bank hash of the slot represented by this snapshot.  The bank
     hash is used by the validator to detect mismatches.  All validators
     must agree on a bank hash for each slot or they will fork off.

     The bank hash is created for every slot by hashing together the
     parent bank hash with the accounts delta hash, the most recent
     Proof of History blockhash, and the number of signatures in the
     slot.

     The bank hash includes the epoch accounts hash when the epoch
     accounts hash is ready at slot 324000 in the current epoch. See the
     epoch_accounts_hash for more details regarding the epcoh accounts
     hash calculation . */
  uchar bank_hash[ 32UL ];

  /* The bank hash of the parent slot. */
  uchar parent_bank_hash[ 32UL ];

  /* The merkle-based hash of all account state on chain at the slot the
     snapshot is created.  The accounts hash is calculated when producing
     a snapshot. */
  uchar accounts_hash[ 32UL ];

  /* The merkle-based hash of modified accounts for the slot the
     snapshot is created.  The accounts_delta_hash is computed at
     the end of every slot and included into each bank hash.  It is
     computed by hashing all modified account state together. */
  uchar accounts_delta_hash[ 32UL ];

  /* The lattice hash of all account state on chain.  It is not yet used
     but in future will replace the accounts hash and the accounts delta
     hash.  Those hashes are expensive to compute because they require
     sorting the accounts, while the lattice hash uses newer cryptography
     to avoid this. */
  int   has_accounts_lthash;
  uchar accounts_lthash[ 2048UL ];

  /* The hash of all accounts at this snapshot's epoch.
     The epoch account hash is very expensive to calculate, so it is
     only calculated once per epoch during the epoch account hash
     calculation window, which is a range of slots in an epoch starting
     at slot 108000 and ending at slot 324000, where each epoch has
     432000 slots.

     The epoch_account_hash may be empty if the snapshot was produced
     before the epoch account hash calculation window. */
  int   has_epoch_account_hash;
  uchar epoch_account_hash[ 32UL ];

  ulong blockhashes_len;
  fd_snapshot_manifest_blockhash_t blockhashes[ 301UL ];

  /* The fork_id in the status cache for the root slot. */
  ushort txncache_fork_id;

  ulong hard_forks_len;
  ulong hard_forks[ 64UL ];

  /* The proof of history component "proves" the passage of time (see
     extended discussion in PoH tile for what that acutally means) by
     continually doing sha256 hashes.  A certain number of hashes are
     required to be in each slot, to prove the leader spent some amount
     of time on the slot and didn't end it too early.

     In all clusters and environments that matter, this value is fixed
     at 64 and is unlikely to change, however it might be configured
     differently in development environments. */
  ulong ticks_per_slot;

  /* TODO: Document */
  ulong ns_per_slot;

  /* TODO: Document */
  double slots_per_year;

  /* The proof of history component typically requires every block to
     have 64 "ticks" in it (although this is configurable during
     development), but each tick is some flexible number of recursive
     sha256 hashes defined at genesis.

     The number of hashes for mainnet genesis is 12,500, meaning there
     will be 800,000 hashes per slot.

     There are various features, named like update_hashes_per_tick*
     which if enabled update the hashes_per_tick of the chain as-of the
     epoch where they are enabled.  This value incorporates any changes
     due to such features.

     In development environments, sometimes hashes_per_tick will not be
     specified (has_hashes_per_tick will be 0).  Agave refers to this as
     a "low power" mode, where ticks have just one hash in them.  It is
     distinct from just setting hahes_per_tick to 1, because it also
     reduces the slot duration from 400ms down to 0ms (or however long
     it takes to produce the hash).  See comments in the PoH tile for
     more extended discussion. */
  int   has_hashes_per_tick;
  ulong hashes_per_tick;

  /* The sum of all account balances in lamports as of this snapshots
     slot.  Total capitalization is used when computing inflation
     rewards and validating snapshots. */
  ulong capitalization;

  /* TODO: Why is this needed? */
  ulong tick_height;
  ulong max_tick_height;

  /* TODO: What is this? */
  ulong lamports_per_signature;

  /* TODO: Why is this needed? */
  ulong transaction_count;

  /* TODO: Why is this needed? */
  ulong signature_count;

  /* A list of this epoch's vote accounts and their state relating to
     rewards distribution, which includes the vote account's commission
     and vote credits.

     The validator distributes vote and stake rewards for the previous
     epoch in the slots immediately after the epoch boundary.  These
     vote and stake rewards are calculated as a stake-weighted
     percentage of the inflation rewards for the epoch and validator
     uptime, which is measured by vote account vote credits. */
  ulong                               vote_accounts_len;
  fd_snapshot_manifest_vote_account_t vote_accounts[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];

  ulong stake_delegations_len;
  fd_snapshot_manifest_stake_delegation_t stake_delegations[ FD_RUNTIME_MAX_STAKE_ACCOUNTS ];

  /* Epoch stakes represent the exact amount staked to each vote
     account at the beginning of the previous epoch. They are
     primarily used to derive the leader schedule.

     Let's say the manifest is at epoch E.

     The field versioned_epoch_stakes in the manifest is a map

       <epoch> -> <VersionedEpochStakes>

     where <epoch> assumes these values:

       E   - represents the stakes at the beginning of epoch E-1,
             used to compute the leader schedule at E.

       E+1 - represents the stakes at the beginning of epoch E,
             used to compute the leader schedule at E+1.

     The epoch stakes are stored in an array, where epoch_stakes[0]
     contains the data to generate the current leader schedule (i.e. E)
     and epoch_stakes[1] contains the data to generate the next leader
     schedule (i.e. E+1). */
  fd_snapshot_manifest_epoch_stakes_t epoch_stakes[ 2UL ];
};

typedef struct fd_snapshot_manifest fd_snapshot_manifest_t;

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssmsg_h */
