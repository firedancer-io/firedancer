#include "fd_ssload.h"

#include "../../../disco/genesis/fd_genesis_cluster.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../../flamenco/runtime/fd_runtime_stack.h"
#include "fd_ssmsg.h"

void
blockhashes_recover( fd_blockhashes_t *                       blockhashes,
                     fd_snapshot_manifest_blockhash_t const * ages,
                     ulong                                    age_cnt,
                     ulong                                    seed ) {
  FD_TEST( fd_blockhashes_init( blockhashes, seed ) );
  FD_TEST( age_cnt && age_cnt<=FD_BLOCKHASHES_MAX );

  /* For depressing reasons, the ages array is not sorted when ingested
     from a snapshot.  The hash_index field is also not validated.
     Firedancer assumes that the sequence of hash_index numbers is
     gapless and does not wrap around. */

  ulong seq_min = ULONG_MAX-1;
  for( ulong i=0UL; i<age_cnt; i++ ) {
    seq_min = fd_ulong_min( seq_min, ages[ i ].hash_index );
  }
  ulong seq_max;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( seq_min, age_cnt, &seq_max ) ) ) {
    /* TODO: Move to snapin validations so we can retry */
    FD_LOG_ERR(( "Corrupt snapshot: blockhash queue sequence number wraparound (seq_min=%lu age_cnt=%lu)", seq_min, age_cnt ));
  }

  /* Reset */

  for( ulong i=0UL; i<age_cnt; i++ ) {
    fd_blockhash_info_t * ele = fd_blockhash_deq_push_tail_nocopy( blockhashes->d.deque );
    memset( ele, 0, sizeof(fd_blockhash_info_t) );
  }

  /* Load hashes */

  for( ulong i=0UL; i<age_cnt; i++ ) {
    fd_snapshot_manifest_blockhash_t const * elem = &ages[ i ];
    ulong idx;
    if( FD_UNLIKELY( __builtin_usubl_overflow( elem->hash_index, seq_min, &idx ) ) ) {
      /* TODO: Move to snapin validations so we can retry */
      FD_LOG_ERR(( "Corrupt snapshot: gap in blockhash queue (seq=[%lu,%lu) idx=%lu)",
                   seq_min, seq_max, elem->hash_index ));
    }
    fd_blockhash_info_t * info = &blockhashes->d.deque[ idx ];
    if( FD_UNLIKELY( info->exists ) ) {
      /* TODO: Move to snapin validations so we can retry */
      FD_LOG_HEXDUMP_NOTICE(( "info", info, sizeof(fd_blockhash_info_t) ));
      FD_LOG_ERR(( "Corrupt snapshot: duplicate blockhash queue index %lu", idx ));
    }
    info->exists         = 1;
    fd_memcpy( info->hash.uc, elem->hash, 32UL );
    info->fee_calculator.lamports_per_signature = elem->lamports_per_signature;
    fd_blockhash_map_idx_insert( blockhashes->map, idx, blockhashes->d.deque );
  }
}

void
fd_ssload_recover( fd_snapshot_manifest_t *  manifest,
                   fd_banks_t *              banks,
                   fd_bank_t *               bank,
                   fd_runtime_stack_t *      runtime_stack,
                   int                       is_incremental ) {

  /* Slot */

  fd_bank_slot_set( bank, manifest->slot );
  fd_bank_parent_slot_set( bank, manifest->parent_slot );

  /* Bank Hash */

  fd_hash_t hash;
  fd_memcpy( &hash.uc, manifest->bank_hash, 32UL );
  fd_bank_bank_hash_set( bank, hash );

  fd_hash_t parent_hash;
  fd_memcpy( &parent_hash.uc, manifest->parent_bank_hash, 32UL );
  fd_bank_prev_bank_hash_set( bank, parent_hash );

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( bank );
  fee_rate_governor->target_lamports_per_signature = manifest->fee_rate_governor.target_lamports_per_signature;
  fee_rate_governor->target_signatures_per_slot    = manifest->fee_rate_governor.target_signatures_per_slot;
  fee_rate_governor->min_lamports_per_signature    = manifest->fee_rate_governor.min_lamports_per_signature;
  fee_rate_governor->max_lamports_per_signature    = manifest->fee_rate_governor.max_lamports_per_signature;
  fee_rate_governor->burn_percent                  = manifest->fee_rate_governor.burn_percent;
  /* https://github.com/anza-xyz/agave/blob/v3.0.3/runtime/src/serde_snapshot.rs#L464-L466 */
  fd_bank_rbh_lamports_per_sig_set( bank, manifest->lamports_per_signature );

  fd_inflation_t * inflation = fd_bank_inflation_modify( bank );
  inflation->initial         = manifest->inflation_params.initial;
  inflation->terminal        = manifest->inflation_params.terminal;
  inflation->taper           = manifest->inflation_params.taper;
  inflation->foundation      = manifest->inflation_params.foundation;
  inflation->foundation_term = manifest->inflation_params.foundation_term;
  inflation->unused          = 0.0;

  fd_epoch_schedule_t * epoch_schedule = fd_bank_epoch_schedule_modify( bank );
  epoch_schedule->slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch;
  epoch_schedule->leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset;
  epoch_schedule->warmup                      = manifest->epoch_schedule_params.warmup;
  epoch_schedule->first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch;
  epoch_schedule->first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot;

  ulong epoch = fd_slot_to_epoch( epoch_schedule, manifest->slot, NULL );
  fd_bank_epoch_set( bank, epoch );

  fd_rent_t * rent = fd_bank_rent_modify( bank );
  rent->lamports_per_uint8_year = manifest->rent_params.lamports_per_uint8_year;
  rent->exemption_threshold     = manifest->rent_params.exemption_threshold;
  rent->burn_percent            = manifest->rent_params.burn_percent;

  /* https://github.com/anza-xyz/agave/blob/v3.0.6/ledger/src/blockstore_processor.rs#L1118
     None gets treated as 0 for hash verification. */
  if( FD_LIKELY( manifest->has_hashes_per_tick ) ) fd_bank_hashes_per_tick_set( bank, manifest->hashes_per_tick );
  else                                             fd_bank_hashes_per_tick_set( bank, 0UL );

  fd_lthash_value_t * lthash = fd_bank_lthash_locking_modify( bank );
  if( FD_LIKELY( manifest->has_accounts_lthash ) ) {
    fd_memcpy( lthash, manifest->accounts_lthash, sizeof(fd_lthash_value_t) );
  } else {
    fd_memset( lthash, 0, sizeof(fd_lthash_value_t) );
  }
  fd_bank_lthash_end_locking_modify( bank );

  fd_blockhashes_t * blockhashes = fd_bank_block_hash_queue_modify( bank );
  blockhashes_recover( blockhashes, manifest->blockhashes, manifest->blockhashes_len, 42UL /* TODO */ );

  /* PoH */
  fd_blockhashes_t const * bhq = fd_bank_block_hash_queue_query( bank );
  fd_hash_t const * last_hash = fd_blockhashes_peek_last_hash( bhq );
  if( FD_LIKELY( last_hash ) ) fd_bank_poh_set( bank, *last_hash );

  fd_bank_capitalization_set( bank, manifest->capitalization );
  fd_bank_txn_count_set( bank, manifest->transaction_count );
  fd_bank_parent_signature_cnt_set( bank, manifest->signature_count );
  fd_bank_tick_height_set( bank, manifest->tick_height );
  fd_bank_max_tick_height_set( bank, manifest->max_tick_height );
  fd_bank_ns_per_slot_set( bank, (fd_w_u128_t) { .ul={ manifest->ns_per_slot, 0UL } } );
  fd_bank_ticks_per_slot_set( bank, manifest->ticks_per_slot );
  fd_bank_genesis_creation_time_set( bank, manifest->creation_time_millis );
  fd_bank_slots_per_year_set( bank, manifest->slots_per_year );
  fd_bank_block_height_set( bank, manifest->block_height );
  fd_bank_execution_fees_set( bank, manifest->collector_fees );
  fd_bank_priority_fees_set( bank, 0UL );

  /* Set the cluster type based on the genesis creation time.  This is
     later cross referenced against the genesis hash. */
  switch( fd_bank_genesis_creation_time_get( bank ) ) {
    case FD_RUNTIME_GENESIS_CREATION_TIME_TESTNET:
      fd_bank_cluster_type_set( bank, FD_CLUSTER_TESTNET );
      break;
    case FD_RUNTIME_GENESIS_CREATION_TIME_MAINNET:
      fd_bank_cluster_type_set( bank, FD_CLUSTER_MAINNET_BETA );
      break;
    case FD_RUNTIME_GENESIS_CREATION_TIME_DEVNET:
      fd_bank_cluster_type_set( bank, FD_CLUSTER_DEVNET );
      break;
    default:
      fd_bank_cluster_type_set( bank, FD_CLUSTER_UNKNOWN );
  }

  /* Update last restart slot
     https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/runtime/src/bank.rs#L2152

     old_bank->hard_forks is sorted ascending by slot number.
     To find the last restart slot, take the highest hard fork slot
     number that is less or equal than the current slot number.
     (There might be some hard forks in the future, ignore these)

     SIMD-0047: The first restart slot should be `0` */
  fd_sol_sysvar_last_restart_slot_t * last_restart_slot = fd_bank_last_restart_slot_modify( bank );
  last_restart_slot->slot = 0UL;
  if( FD_LIKELY( manifest->hard_forks_len ) ) {
    for( ulong i=0UL; i<manifest->hard_forks_len; i++ ) {
      ulong slot = manifest->hard_forks[ manifest->hard_forks_len-1UL-i ];
      if( FD_LIKELY( slot<=manifest->slot ) ) {
        last_restart_slot->slot = slot;
        break;
      }
    }
  }

  /* Stake delegations for the current epoch. */
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );
  if( is_incremental ) fd_stake_delegations_init( stake_delegations );
  for( ulong i=0UL; i<manifest->stake_delegations_len; i++ ) {
    fd_snapshot_manifest_stake_delegation_t const * elem = &manifest->stake_delegations[ i ];
    if( FD_UNLIKELY( elem->stake_delegation==0UL ) ) {
      continue;
    }
    fd_stake_delegations_update(
        stake_delegations,
        (fd_pubkey_t *)elem->stake_pubkey,
        (fd_pubkey_t *)elem->vote_pubkey,
        elem->stake_delegation,
        elem->activation_epoch,
        elem->deactivation_epoch,
        elem->credits_observed,
        elem->warmup_cooldown_rate
    );
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
  fd_bank_total_epoch_stake_set( bank, manifest->epoch_stakes[1].total_stake );


  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes_locking_query( bank );

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( bank );
  if( is_incremental ) fd_vote_states_init( vote_states );
  for( ulong i=0UL; i<manifest->vote_accounts_len; i++ ) {
    fd_snapshot_manifest_vote_account_t const * elem = &manifest->vote_accounts[ i ];

    fd_vote_state_ele_t * vote_state = fd_vote_states_update( vote_states, (fd_pubkey_t *)elem->vote_account_pubkey );

    vote_state->node_account        = *(fd_pubkey_t *)elem->node_account_pubkey;
    vote_state->last_vote_timestamp = elem->last_timestamp;
    vote_state->last_vote_slot      = elem->last_slot;

    fd_vote_stakes_insert_root_key( vote_stakes, (fd_pubkey_t *)elem->vote_account_pubkey );
  }

  fd_vote_ele_map_t * vote_ele_map = fd_type_pun( runtime_stack->stakes.vote_map_mem );

  /* Vote stakes for the previous epoch (E-1). */
  for( ulong i=0UL; i<manifest->epoch_stakes[1].vote_stakes_len; i++ ) {
    fd_snapshot_manifest_vote_stakes_t const * elem = &manifest->epoch_stakes[1].vote_stakes[i];

    /* First convert the epoch credits to the format expected by the
       vote states.  We need to do this because we may need the vote
       state credits from the end of the previous epoch in case we need
       to recalculate the stake reward partitions. */
    fd_vote_state_ele_t * vote_state_curr = fd_vote_states_update( vote_states, (fd_pubkey_t *)elem->vote );
    vote_state_curr->node_account_t_1 = *(fd_pubkey_t *)elem->identity;
    vote_state_curr->stake_t_1 = elem->stake;

    fd_vote_ele_t * vote_ele = &runtime_stack->stakes.vote_ele[i];
    fd_vote_state_credits_t * vote_state_credits = &vote_ele->vote_credits;
    vote_ele->pubkey     = vote_state_curr->vote_account;
    vote_ele->stake      = elem->stake;
    vote_ele->invalid    = 0;
    vote_ele->commission = (uchar)elem->commission;

    fd_vote_ele_map_idx_insert( vote_ele_map, i, runtime_stack->stakes.vote_ele );

    fd_vote_stakes_insert_root_update( vote_stakes,
                                       (fd_pubkey_t *)elem->vote,
                                       (fd_pubkey_t *)elem->identity,
                                       elem->stake,
                                       1 );

    vote_state_credits->credits_cnt = elem->epoch_credits_history_len;
    for( ulong j=0UL; j<elem->epoch_credits_history_len; j++ ) {
      vote_state_credits->epoch[ j ]        = (ushort)elem->epoch_credits[ j ].epoch;
      vote_state_credits->credits[ j ]      = elem->epoch_credits[ j ].credits;
      vote_state_credits->prev_credits[ j ] = elem->epoch_credits[ j ].prev_credits;
    }
  }

  /* Vote stakes for the previous epoch (E-2) */
  for( ulong i=0UL; i<manifest->epoch_stakes[0].vote_stakes_len; i++ ) {
    fd_snapshot_manifest_vote_stakes_t const * elem = &manifest->epoch_stakes[0].vote_stakes[i];

    fd_vote_stakes_insert_root_update( vote_stakes,
      (fd_pubkey_t *)elem->vote,
      (fd_pubkey_t *)elem->identity,
      elem->stake,
      0 );

    fd_vote_state_ele_t * vote_state_curr = fd_vote_states_update( vote_states, (fd_pubkey_t *)elem->vote );
    vote_state_curr->node_account_t_2 = *(fd_pubkey_t *)elem->identity;
    vote_state_curr->stake_t_2 = elem->stake;
  }

  fd_vote_stakes_fini_root( vote_stakes );

  // fd_vote_states_iter_t iter_[1];
  // for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
  //      !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {

  //   fd_vote_state_ele_t * vote_state = fd_vote_states_iter_ele( iter );

  //   fd_vote_stakes_insert( vote_stakes,
  //                          bank->data->vote_stakes_fork_id,
  //                          &vote_state->vote_account,
  //                          vote_state->stake_t_1,
  //                          vote_state->stake_t_2,
  //                          &vote_state->node_account_t_1,
  //                          &vote_state->node_account_t_2 );
  // }

  fd_bank_vote_stakes_end_locking_query( bank );
  fd_bank_vote_states_end_locking_modify( bank );

  bank->data->txncache_fork_id = (fd_txncache_fork_id_t){ .val = manifest->txncache_fork_id };
}
