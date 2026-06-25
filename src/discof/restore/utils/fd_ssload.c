#include "fd_ssload.h"

#include "../../../disco/genesis/fd_genesis_cluster.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "fd_ssmsg.h"

FD_STATIC_ASSERT( FD_HARD_FORKS_MAX==sizeof(((fd_snapshot_manifest_t *)0)->hard_forks)/sizeof(fd_hard_fork_t), hard_forks_max );
FD_STATIC_ASSERT( FD_BLOCKHASHES_MAX==sizeof(((fd_snapshot_manifest_t *)0)->blockhashes)/sizeof(fd_snapshot_manifest_blockhash_t), blockhashes_max );
FD_STATIC_ASSERT( FD_VOTE_ACCOUNTS_MAX==sizeof(((fd_snapshot_manifest_t *)0)->vote_accounts)/sizeof(fd_snapshot_manifest_vote_account_t), vote_accounts_max );
FD_STATIC_ASSERT( FD_STAKE_DELEGATIONS_MAX==sizeof(((fd_snapshot_manifest_t *)0)->stake_delegations)/sizeof(fd_snapshot_manifest_stake_delegation_t), stake_delegations_max );
FD_STATIC_ASSERT( FD_EPOCH_STAKES_LEN==sizeof(((fd_snapshot_manifest_t *)0)->epoch_stakes)/sizeof(fd_snapshot_manifest_epoch_stakes_t), epoch_stakes_len );
FD_STATIC_ASSERT( FD_EPOCH_VOTE_STAKES_MAX==sizeof(((fd_snapshot_manifest_epoch_stakes_t *)0)->vote_stakes)/sizeof(fd_snapshot_manifest_vote_stakes_t), epoch_vote_stakes_max );
FD_STATIC_ASSERT( FD_EPOCH_CREDITS_MAX==sizeof(((fd_snapshot_manifest_vote_account_t *)0)->epoch_credits)/sizeof(epoch_credits_t), vote_account_epoch_credits_max );
FD_STATIC_ASSERT( FD_EPOCH_CREDITS_MAX==sizeof(((fd_snapshot_manifest_vote_stakes_t *)0)->epoch_credits)/sizeof(epoch_credits_t), vote_stakes_epoch_credits_max );

int
fd_ssload_manifest_validate( fd_snapshot_manifest_t const * manifest,
                             ulong                          max_vote_accounts,
                             ulong                          max_stake_accounts ) {

  if( FD_UNLIKELY( max_vote_accounts!=FD_RUNTIME_MAX_VOTE_ACCOUNTS ||
                   max_stake_accounts!=FD_RUNTIME_MAX_STAKE_ACCOUNTS ) ) {
    FD_LOG_WARNING(( "banks capacity mismatch: max_vote_accounts=%lu (expected %lu) max_stake_accounts=%lu (expected %lu)",
                     max_vote_accounts,  FD_RUNTIME_MAX_VOTE_ACCOUNTS,
                     max_stake_accounts, FD_RUNTIME_MAX_STAKE_ACCOUNTS ));
    return -1;
  }

  /* slots_per_epoch must be at least FD_EPOCH_LEN_MIN, so that
     fd_slot_to_epoch and related functions produce valid data.
     This check must come before any epoch computation. */

  if( FD_UNLIKELY( manifest->epoch_schedule_params.slots_per_epoch<FD_EPOCH_LEN_MIN ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: slots_per_epoch %lu below minimum %lu",
                     manifest->epoch_schedule_params.slots_per_epoch, FD_EPOCH_LEN_MIN ));
    return -1;
  }

  if( FD_UNLIKELY( manifest->epoch_schedule_params.warmup>1 ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: warmup %u is not boolean", (uint)manifest->epoch_schedule_params.warmup ));
    return -1;
  }

  /* Validate that the manifest's first_normal_{epoch,slot} are
     consistent with the derivation from slots_per_epoch and warmup. */

  fd_epoch_schedule_t derived;
  if( FD_UNLIKELY( !fd_epoch_schedule_derive( &derived,
                                              manifest->epoch_schedule_params.slots_per_epoch,
                                              manifest->epoch_schedule_params.leader_schedule_slot_offset,
                                              manifest->epoch_schedule_params.warmup ) ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: fd_epoch_schedule_derive failed" ));
    return -1;
  }
  if( FD_UNLIKELY( derived.first_normal_epoch!=manifest->epoch_schedule_params.first_normal_epoch ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: first_normal_epoch mismatch (manifest=%lu derived=%lu)",
                     manifest->epoch_schedule_params.first_normal_epoch, derived.first_normal_epoch ));
    return -1;
  }
  if( FD_UNLIKELY( derived.first_normal_slot!=manifest->epoch_schedule_params.first_normal_slot ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: first_normal_slot mismatch (manifest=%lu derived=%lu)",
                     manifest->epoch_schedule_params.first_normal_slot, derived.first_normal_slot ));
    return -1;
  }

  /* Blockhash queue structural validation */

  ulong const age_cnt = manifest->blockhashes_len;
  fd_snapshot_manifest_blockhash_t const * ages = manifest->blockhashes;

  if( FD_UNLIKELY( !age_cnt || age_cnt>FD_BLOCKHASHES_MAX ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: invalid blockhash age count %lu (max %lu)", age_cnt, FD_BLOCKHASHES_MAX ));
    return -1;
  }

  ulong seq_min = ULONG_MAX;
  for( ulong i=0UL; i<age_cnt; i++ ) {
    seq_min = fd_ulong_min( seq_min, ages[ i ].hash_index );
  }
  ulong seq_max;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( seq_min, age_cnt, &seq_max ) ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: blockhash queue sequence number wraparound (seq_min=%lu age_cnt=%lu)", seq_min, age_cnt ));
    return -1;
  }

  /* Check for gaps and duplicates using a bitset (max 301 entries). */

  ulong seen[ (FD_BLOCKHASHES_MAX+63UL)/64UL ];
  fd_memset( seen, 0, sizeof(seen) );
  for( ulong i=0UL; i<age_cnt; i++ ) {
    ulong idx;
    if( FD_UNLIKELY( __builtin_usubl_overflow( ages[ i ].hash_index, seq_min, &idx ) || idx>=age_cnt ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: gap in blockhash queue (seq=[%lu,%lu) hash_index=%lu)",
                       seq_min, seq_max, ages[ i ].hash_index ));
      return -1;
    }
    ulong word = idx/64UL;
    ulong bit  = idx%64UL;
    if( FD_UNLIKELY( seen[ word ] & (1UL<<bit) ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: duplicate blockhash queue hash_index=%lu (relative_idx=%lu seq_min=%lu)",
                       ages[ i ].hash_index, idx, seq_min ));
      return -1;
    }
    seen[ word ] |= (1UL<<bit);
  }

  /* Array bounds checks, reject manifests whose counts exceed the
     fixed-size arrays in fd_snapshot_manifest_t.  Validating here
     enables early recovery from malformed snapshots. */

  if( FD_UNLIKELY( manifest->hard_fork_cnt>FD_HARD_FORKS_MAX ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: hard_fork_cnt %lu exceeds max %lu",
                     manifest->hard_fork_cnt, FD_HARD_FORKS_MAX ));
    return -1;
  }

  if( FD_UNLIKELY( manifest->stake_delegations_len>FD_STAKE_DELEGATIONS_MAX ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: stake_delegations_len %lu exceeds max %lu",
                     manifest->stake_delegations_len, FD_STAKE_DELEGATIONS_MAX ));
    return -1;
  }

  if( FD_UNLIKELY( manifest->stake_delegations_len>max_stake_accounts ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: stake_delegations_len %lu exceeds max_stake_accounts %lu",
                     manifest->stake_delegations_len, max_stake_accounts ));
    return -1;
  }

  if( FD_UNLIKELY( manifest->vote_accounts_len>FD_VOTE_ACCOUNTS_MAX ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: vote_accounts_len %lu exceeds max %lu",
                     manifest->vote_accounts_len, FD_VOTE_ACCOUNTS_MAX ));
    return -1;
  }

  if( FD_UNLIKELY( manifest->vote_accounts_len>max_vote_accounts ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: vote_accounts_len %lu exceeds max_vote_accounts %lu",
                     manifest->vote_accounts_len, max_vote_accounts ));
    return -1;
  }

  /* Epoch credits downcasting only happens on epoch_stakes entries,
     not vote_accounts.  Validated here for consistency. */

  for( ulong i=0UL; i<manifest->vote_accounts_len; i++ ) {
    if( FD_UNLIKELY( manifest->vote_accounts[i].epoch_credits_history_len>FD_EPOCH_CREDITS_MAX ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: vote_accounts[%lu].epoch_credits_history_len %lu exceeds max %lu",
                       i, manifest->vote_accounts[i].epoch_credits_history_len, FD_EPOCH_CREDITS_MAX ));
      return -1;
    }
    ulong ec_base = manifest->vote_accounts[i].epoch_credits_history_len>0UL
                  ? manifest->vote_accounts[i].epoch_credits[0].prev_credits : 0UL;
    for( ulong j=0UL; j<manifest->vote_accounts[i].epoch_credits_history_len; j++ ) {
      epoch_credits_t const * epc = &manifest->vote_accounts[i].epoch_credits[j];
      if( FD_UNLIKELY( epc->epoch>(ulong)USHORT_MAX ) ) {
        FD_LOG_WARNING(( "corrupt snapshot: vote_accounts[%lu].epoch_credits[%lu].epoch %lu exceeds USHORT_MAX",
                         i, j, epc->epoch ));
        return -1;
      }
      if( FD_UNLIKELY( epc->credits<ec_base || epc->credits-ec_base>(ulong)UINT_MAX ) ) {
        FD_LOG_WARNING(( "corrupt snapshot: vote_accounts[%lu].epoch_credits[%lu].credits %lu out of range (base %lu)",
                         i, j, epc->credits, ec_base ));
        return -1;
      }
      if( FD_UNLIKELY( epc->prev_credits<ec_base || epc->prev_credits-ec_base>(ulong)UINT_MAX ) ) {
        FD_LOG_WARNING(( "corrupt snapshot: vote_accounts[%lu].epoch_credits[%lu].prev_credits %lu out of range (base %lu)",
                         i, j, epc->prev_credits, ec_base ));
        return -1;
      }
    }
  }

  /* Epoch credits downcasting validation */

  for( ulong i=0UL; i<FD_EPOCH_STAKES_LEN; i++ ) {
    if( FD_UNLIKELY( manifest->epoch_stakes[i].vote_stakes_len>FD_EPOCH_VOTE_STAKES_MAX ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: epoch_stakes[%lu].vote_stakes_len %lu exceeds max %lu",
                       i, manifest->epoch_stakes[i].vote_stakes_len, FD_EPOCH_VOTE_STAKES_MAX ));
      return -1;
    }
    if( FD_UNLIKELY( manifest->epoch_stakes[i].vote_stakes_len>max_vote_accounts ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: epoch_stakes[%lu].vote_stakes_len %lu exceeds max_vote_accounts %lu",
                       i, manifest->epoch_stakes[i].vote_stakes_len, max_vote_accounts ));
      return -1;
    }
    for( ulong j=0UL; j<manifest->epoch_stakes[i].vote_stakes_len; j++ ) {
      fd_snapshot_manifest_vote_stakes_t const * vs = &manifest->epoch_stakes[i].vote_stakes[j];
      if( FD_UNLIKELY( vs->epoch_credits_history_len>FD_EPOCH_CREDITS_MAX ) ) {
        FD_LOG_WARNING(( "corrupt snapshot: epoch_stakes[%lu].vote_stakes[%lu].epoch_credits_history_len %lu exceeds max %lu",
                         i, j, vs->epoch_credits_history_len, FD_EPOCH_CREDITS_MAX ));
        return -1;
      }
      ulong ec_base = vs->epoch_credits_history_len>0UL ? vs->epoch_credits[0].prev_credits : 0UL;
      for( ulong k=0UL; k<vs->epoch_credits_history_len; k++ ) {
        epoch_credits_t const * epc = &vs->epoch_credits[k];
        if( FD_UNLIKELY( epc->epoch>(ulong)USHORT_MAX ) ) {
          FD_LOG_WARNING(( "corrupt snapshot: epoch_stakes[%lu].vote_stakes[%lu].epoch_credits[%lu].epoch %lu exceeds USHORT_MAX",
                           i, j, k, epc->epoch ));
          return -1;
        }
        if( FD_UNLIKELY( epc->credits<ec_base || epc->credits-ec_base>(ulong)UINT_MAX ) ) {
          FD_LOG_WARNING(( "corrupt snapshot: epoch_stakes[%lu].vote_stakes[%lu].epoch_credits[%lu].credits %lu out of range (base %lu)",
                           i, j, k, epc->credits, ec_base ));
          return -1;
        }
        if( FD_UNLIKELY( epc->prev_credits<ec_base || epc->prev_credits-ec_base>(ulong)UINT_MAX ) ) {
          FD_LOG_WARNING(( "corrupt snapshot: epoch_stakes[%lu].vote_stakes[%lu].epoch_credits[%lu].prev_credits %lu out of range (base %lu)",
                           i, j, k, epc->prev_credits, ec_base ));
          return -1;
        }
      }
    }
  }

  /* Epoch stakes index validation.  fd_slot_to_leader_schedule_epoch
     is inlined here with overflow-safe arithmetic. */

  fd_epoch_schedule_t epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch,
    .leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset,
    .warmup                      = manifest->epoch_schedule_params.warmup,
    .first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch,
    .first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot,
  };

  ulong epoch = fd_slot_to_epoch( &epoch_schedule, manifest->slot, NULL );

  /* Compute leader_schedule_epoch with overflow safety.  Mirrors
     fd_slot_to_leader_schedule_epoch but rejects overflow instead
     of silently wrapping. */

  ulong leader_schedule_epoch;
  if( FD_UNLIKELY( manifest->slot<epoch_schedule.first_normal_slot ) ) {
    if( FD_UNLIKELY( __builtin_uaddl_overflow( epoch, 1UL, &leader_schedule_epoch ) ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: leader_schedule_epoch overflow (epoch=%lu)", epoch ));
      return -1;
    }
  } else {
    ulong delta = manifest->slot-epoch_schedule.first_normal_slot;
    ulong sum;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( delta, epoch_schedule.leader_schedule_slot_offset, &sum ) ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: leader_schedule_slot_offset overflow "
                       "(slot_delta=%lu leader_schedule_slot_offset=%lu)",
                       delta, epoch_schedule.leader_schedule_slot_offset ));
      return -1;
    }
    ulong n_epochs = sum/epoch_schedule.slots_per_epoch;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( epoch_schedule.first_normal_epoch, n_epochs, &leader_schedule_epoch ) ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: leader_schedule_epoch overflow "
                       "(first_normal_epoch=%lu n_epochs=%lu)",
                       epoch_schedule.first_normal_epoch, n_epochs ));
      return -1;
    }
  }

  ulong epoch_stakes_base = epoch>0UL ? epoch-1UL : 0UL;

  if( FD_UNLIKELY( leader_schedule_epoch<epoch_stakes_base ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: leader_schedule_epoch %lu < epoch_stakes_base %lu",
                     leader_schedule_epoch, epoch_stakes_base ));
    return -1;
  }
  ulong t_1_idx = leader_schedule_epoch-epoch_stakes_base;
  if( FD_UNLIKELY( t_1_idx>=FD_EPOCH_STAKES_LEN ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: epoch stakes index %lu out of range (max %lu)",
                     t_1_idx, FD_EPOCH_STAKES_LEN ));
    return -1;
  }

  return 0;
}

static int
blockhashes_recover( fd_blockhashes_t *                       blockhashes,
                     fd_snapshot_manifest_blockhash_t const * ages,
                     ulong                                    age_cnt,
                     ulong                                    seed ) {

  /* The caller must guarantee that fd_ssload_manifest_validate has
     already been invoked, verifying that age_cnt is in the range
     (0, FD_BLOCKHASHES_MAX], that there are no gaps or duplicates in
     the sequence numbers, and that seq_min+age_cnt does not overflow. */

  if( FD_UNLIKELY( !fd_blockhashes_init( blockhashes, seed ) ) ) {
    FD_LOG_WARNING(( "failed to initialize blockhash queue" ));
    return -1;
  }

  ulong seq_min = ULONG_MAX;
  for( ulong i=0UL; i<age_cnt; i++ ) {
    seq_min = fd_ulong_min( seq_min, ages[ i ].hash_index );
  }

  /* Reset */

  for( ulong i=0UL; i<age_cnt; i++ ) {
    fd_blockhash_info_t * ele = fd_blockhash_deq_push_tail_nocopy( blockhashes->d.deque );
    fd_memset( ele, 0, sizeof(fd_blockhash_info_t) );
  }

  /* Load hashes */

  for( ulong i=0UL; i<age_cnt; i++ ) {
    fd_snapshot_manifest_blockhash_t const * elem = &ages[ i ];
    ulong idx = elem->hash_index - seq_min;
    fd_blockhash_info_t * info = &blockhashes->d.deque[ idx ];
    info->exists = 1;
    fd_memcpy( info->hash.uc, elem->hash, 32UL );
    info->lamports_per_signature = elem->lamports_per_signature;
    fd_blockhash_map_idx_insert( blockhashes->map, idx, blockhashes->d.deque );
  }

  return 0;
}

int
fd_ssload_recover_validate( fd_snapshot_manifest_t const * manifest,
                            fd_banks_t const *             banks ) {
  return fd_ssload_manifest_validate( manifest, banks->max_vote_accounts, banks->max_stake_accounts );
}

int
fd_ssload_recover_apply( fd_snapshot_manifest_t * manifest,
                         fd_banks_t *             banks,
                         fd_bank_t *              bank,
                         ulong                    blockhash_seed ) {

  /* Slot */

  bank->f.slot = manifest->slot;
  bank->f.parent_slot = manifest->parent_slot;

  /* Bank Hash */

  fd_hash_t hash;
  fd_memcpy( &hash.uc, manifest->bank_hash, 32UL );
  bank->f.bank_hash = hash;

  fd_hash_t parent_hash;
  fd_memcpy( &parent_hash.uc, manifest->parent_bank_hash, 32UL );
  bank->f.prev_bank_hash = parent_hash;

  fd_fee_rate_governor_t * fee_rate_governor = &bank->f.fee_rate_governor;
  fee_rate_governor->target_lamports_per_signature = manifest->fee_rate_governor.target_lamports_per_signature;
  fee_rate_governor->target_signatures_per_slot    = manifest->fee_rate_governor.target_signatures_per_slot;
  fee_rate_governor->min_lamports_per_signature    = manifest->fee_rate_governor.min_lamports_per_signature;
  fee_rate_governor->max_lamports_per_signature    = manifest->fee_rate_governor.max_lamports_per_signature;
  fee_rate_governor->burn_percent                  = manifest->fee_rate_governor.burn_percent;
  /* https://github.com/anza-xyz/agave/blob/v3.0.3/runtime/src/serde_snapshot.rs#L464-L466 */
  bank->f.rbh_lamports_per_sig = manifest->lamports_per_signature;

  fd_inflation_t * inflation = &bank->f.inflation;
  inflation->initial         = manifest->inflation_params.initial;
  inflation->terminal        = manifest->inflation_params.terminal;
  inflation->taper           = manifest->inflation_params.taper;
  inflation->foundation      = manifest->inflation_params.foundation;
  inflation->foundation_term = manifest->inflation_params.foundation_term;
  inflation->unused          = 0.0;

  fd_epoch_schedule_t * epoch_schedule = &bank->f.epoch_schedule;
  epoch_schedule->slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch;
  epoch_schedule->leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset;
  epoch_schedule->warmup                      = manifest->epoch_schedule_params.warmup;
  epoch_schedule->first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch;
  epoch_schedule->first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot;

  ulong epoch = fd_slot_to_epoch( epoch_schedule, manifest->slot, NULL );
  bank->f.epoch = epoch;

  fd_rent_t * rent = &bank->f.rent;
  rent->lamports_per_uint8_year = manifest->rent_params.lamports_per_uint8_year;
  rent->exemption_threshold     = manifest->rent_params.exemption_threshold;
  rent->burn_percent            = manifest->rent_params.burn_percent;

  /* https://github.com/anza-xyz/agave/blob/v3.0.6/ledger/src/blockstore_processor.rs#L1118
     None gets treated as 0 for hash verification. */
  ulong restored_hashes_per_tick = manifest->has_hashes_per_tick ? manifest->hashes_per_tick : 0UL;

  fd_lthash_value_t * lthash = fd_bank_lthash_locking_modify( bank );
  if( FD_LIKELY( manifest->has_accounts_lthash ) ) {
    fd_memcpy( lthash, manifest->accounts_lthash, sizeof(fd_lthash_value_t) );
  } else {
    fd_memset( lthash, 0, sizeof(fd_lthash_value_t) );
  }
  fd_bank_lthash_end_locking_modify( bank );

  fd_blockhashes_t * blockhashes = &bank->f.block_hash_queue;
  if( FD_UNLIKELY( blockhashes_recover( blockhashes, manifest->blockhashes, manifest->blockhashes_len, blockhash_seed ) ) ) {
    FD_LOG_WARNING(( "blockhash queue recovery failed" ));
    return -1;
  }

  /* PoH */
  fd_blockhashes_t const * bhq = &bank->f.block_hash_queue;
  fd_hash_t const * last_hash = fd_blockhashes_peek_last_hash( bhq );
  if( FD_LIKELY( last_hash ) ) bank->f.poh = *last_hash;

  bank->f.capitalization                   = manifest->capitalization;
  bank->f.txn_count                        = manifest->transaction_count;
  bank->f.signature_count                  = manifest->signature_count;
  bank->f.tick_height                      = manifest->tick_height;
  bank->f.max_tick_height                  = manifest->max_tick_height;
  bank->f.ticks_per_slot                   = manifest->ticks_per_slot;
  bank->f.genesis_creation_time            = manifest->creation_time_seconds;
  bank->f.slot_params                      = FD_SLOT_PARAMS_400MS;
  bank->f.slot_params.ns_per_slot          = manifest->ns_per_slot;
  bank->f.slot_params.ns_per_slot_adjusted = fd_ulong_sat_sub( bank->f.slot_params.ns_per_slot, FD_TARGET_SLOT_ADJUSTMENT_NS );
  bank->f.slot_params.slots_per_year       = manifest->slots_per_year;
  bank->f.slot_params.hashes_per_tick      = restored_hashes_per_tick;
  bank->f.block_height                     = manifest->block_height;
  bank->f.execution_fees                   = manifest->collector_fees;
  bank->f.priority_fees                    = 0UL;

  /* Set the cluster type based on the genesis creation time.  This is
     later cross referenced against the genesis hash. */
  switch( bank->f.genesis_creation_time ) {
    case FD_RUNTIME_GENESIS_CREATION_TIME_TESTNET:
      bank->f.cluster_type = FD_CLUSTER_TESTNET;
      break;
    case FD_RUNTIME_GENESIS_CREATION_TIME_MAINNET:
      bank->f.cluster_type = FD_CLUSTER_MAINNET_BETA;
      break;
    case FD_RUNTIME_GENESIS_CREATION_TIME_DEVNET:
      bank->f.cluster_type = FD_CLUSTER_DEVNET;
      break;
    default:
      bank->f.cluster_type = FD_CLUSTER_UNKNOWN;
  }

  /* Update last restart slot
     https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/runtime/src/bank.rs#L2152

     old_bank->hard_forks is sorted ascending by slot number.
     To find the last restart slot, take the highest hard fork slot
     number that is less or equal than the current slot number.
     (There might be some hard forks in the future, ignore these)

     SIMD-0047: The first restart slot should be `0` */
  bank->f.hard_fork_cnt = manifest->hard_fork_cnt;
  if( FD_LIKELY( manifest->hard_fork_cnt ) ) {
    for( ulong i=0UL; i<manifest->hard_fork_cnt; i++ ) {
      bank->f.hard_forks[ i ] = manifest->hard_forks[ i ];
    }

    for( ulong i=0UL; i<manifest->hard_fork_cnt; i++ ) {
      ulong slot = manifest->hard_forks[ manifest->hard_fork_cnt-1UL-i ].slot;
      if( FD_LIKELY( slot<=manifest->slot ) ) {
        break;
      }
    }
  }

  /* Stake delegations for the current epoch. */
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );
  fd_stake_delegations_reset( stake_delegations );
  for( ulong i=0UL; i<manifest->stake_delegations_len; i++ ) {
    fd_snapshot_manifest_stake_delegation_t const * elem = &manifest->stake_delegations[ i ];
    if( FD_UNLIKELY( elem->stake_delegation==0UL ) ) {
      continue;
    }
    fd_stake_delegations_root_update(
        stake_delegations,
        (fd_pubkey_t *)elem->stake_pubkey,
        (fd_pubkey_t *)elem->vote_pubkey,
        elem->stake_delegation,
        elem->activation_epoch,
        elem->deactivation_epoch,
        elem->credits_observed,
        0UL, /* lamports unknown until fd_stake_delegations_refresh */
        0U,  /* acc_dlen unknown until fd_stake_delegations_refresh */
        FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025
    );
  }

  fd_new_votes_t * new_votes = fd_bank_new_votes( bank );
  fd_new_votes_reset_root( new_votes );
  for( ulong i=0UL; i<manifest->vote_accounts_len; i++ ) {
    fd_snapshot_manifest_vote_account_t const * elem = &manifest->vote_accounts[ i ];
    if( FD_UNLIKELY( elem->stake==0UL ) ) fd_new_votes_root_insert( new_votes, (fd_pubkey_t *)elem->vote_account_pubkey );
  }

  /* We also want to set the total stake to be the total amount of stake
     at the end of the previous epoch. This value is used for the
     get_epoch_stake syscall.

     A note on Agave's indexing scheme for their epoch_stakes
     structure:

     https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank.rs#L6175

     If we are loading a snapshot and replaying in the middle of
     epoch 7, the syscall is supposed to return the total stake at
     the end of epoch 6.  The epoch_stakes structure is indexed in
     Agave by the epoch number of the leader schedule that the
     stakes are meant to determine.  For instance, to get the
     stakes at the end of epoch 6, we should query by 8, because
     the leader schedule for epoch 8 is determined based on the
     stakes at the end of epoch 6.  Therefore, we save the total
     epoch stake by querying for epoch+1.  This logic is encapsulated
     in fd_ssmanifest_parser.c. */

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  fd_vote_stakes_reset( vote_stakes );

  fd_top_votes_t * top_votes_t_1 = fd_bank_top_votes_t_1_modify( bank );
  fd_top_votes_t * top_votes_t_2 = fd_bank_top_votes_t_2_modify( bank );
  fd_top_votes_init( top_votes_t_1 );
  fd_top_votes_init( top_votes_t_2 );

  ulong leader_schedule_epoch = fd_slot_to_leader_schedule_epoch( epoch_schedule, manifest->slot );
  ulong epoch_stakes_base     = epoch > 0UL ? epoch - 1UL : 0UL;
  ulong t_1_idx = leader_schedule_epoch - epoch_stakes_base;

  int   has_t_2 = (t_1_idx > 0UL);
  ulong t_2_idx = has_t_2 ? t_1_idx - 1UL : 0UL;

  bank->f.total_epoch_stake = manifest->epoch_stakes[t_1_idx].total_stake;

  ulong epoch_credits_len = 0UL;

  /* Populate the vote stakes for the end of the T-1 epoch if the
     snapshot is in epoch T. */
  for( ulong i=0UL; i<manifest->epoch_stakes[t_1_idx].vote_stakes_len; i++ ) {
    fd_snapshot_manifest_vote_stakes_t const * elem = &manifest->epoch_stakes[t_1_idx].vote_stakes[i];

    fd_vote_stakes_root_insert_key(
        vote_stakes,
        (fd_pubkey_t *)elem->vote,
        (fd_pubkey_t *)elem->identity,
        elem->stake,
        elem->commission,
        bank->f.epoch );

    fd_top_votes_insert( top_votes_t_1, (fd_pubkey_t *)elem->vote, (fd_pubkey_t *)elem->identity, elem->stake, elem->commission );

    fd_epoch_credits_t * ec = &fd_bank_epoch_credits( bank )[epoch_credits_len];
    fd_memcpy( ec->pubkey, elem->vote, 32UL );
    ec->cnt          = elem->epoch_credits_history_len;
    ec->base_credits = ec->cnt > 0UL ? elem->epoch_credits[0].prev_credits : 0UL;
    for( ulong j=0UL; j<elem->epoch_credits_history_len; j++ ) {
      ec->epoch[ j ]              = (ushort)elem->epoch_credits[ j ].epoch;
      ec->credits_delta[ j ]      = (uint)( elem->epoch_credits[ j ].credits      - ec->base_credits );
      ec->prev_credits_delta[ j ] = (uint)( elem->epoch_credits[ j ].prev_credits - ec->base_credits );
    }
    epoch_credits_len++;
  }
  *fd_bank_epoch_credits_len( bank ) = epoch_credits_len;

  /* Populate the vote stakes for the end of the T-2 epoch if the
     snapshot is in epoch T. */
  if( has_t_2 ) {
    for( ulong i=0UL; i<manifest->epoch_stakes[t_2_idx].vote_stakes_len; i++ ) {
      fd_snapshot_manifest_vote_stakes_t const * elem = &manifest->epoch_stakes[t_2_idx].vote_stakes[i];

      fd_top_votes_insert( top_votes_t_2, (fd_pubkey_t *)elem->vote, (fd_pubkey_t *)elem->identity, elem->stake, elem->commission );
      fd_vote_stakes_root_update_meta(
          vote_stakes,
          (fd_pubkey_t *)elem->vote,
          (fd_pubkey_t *)elem->identity,
          elem->stake,
          elem->commission,
          bank->f.epoch );
    }
  }

  /* Store commissions in the banks for the end of the T-3 epoch if the
     snapshot is in epoch T. */
  if( manifest->epoch_stakes[0].vote_stakes_len > 0UL ) {
    *fd_bank_snapshot_commission_t_3_len( bank ) = manifest->epoch_stakes[0].vote_stakes_len;
    fd_stashed_commission_t * snapshot_commission = fd_bank_snapshot_commission_t_3( bank );
    for( ulong i=0UL; i<manifest->epoch_stakes[0].vote_stakes_len; i++ ) {
      fd_snapshot_manifest_vote_stakes_t const * elem = &manifest->epoch_stakes[0].vote_stakes[i];
      fd_memcpy( snapshot_commission[i].pubkey, elem->vote, 32UL );
      snapshot_commission[i].commission = elem->commission;
    }
  } else {
    *fd_bank_snapshot_commission_t_3_len( bank ) = 0UL;
  }

  bank->txncache_fork_id = (fd_txncache_fork_id_t){ .val = manifest->txncache_fork_id };

  return 0;
}

int
fd_ssload_recover( fd_snapshot_manifest_t * manifest,
                   fd_banks_t *             banks,
                   fd_bank_t *              bank,
                   ulong                    blockhash_seed ) {

  if( FD_UNLIKELY( fd_ssload_recover_validate( manifest, banks ) ) ) {
    FD_LOG_WARNING(( "snapshot manifest validation failed" ));
    return -1;
  }

  return fd_ssload_recover_apply( manifest, banks, bank, blockhash_seed );
}
