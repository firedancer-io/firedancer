#include "fd_ssload.h"

#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
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
                   fd_vote_state_credits_t * vote_state_credits ) {

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

  if( FD_LIKELY( manifest->has_hashes_per_tick ) ) fd_bank_hashes_per_tick_set( bank, manifest->hashes_per_tick );
  else                                             fd_bank_hashes_per_tick_set( bank, DEFAULT_HASHES_PER_TICK );

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
  fd_hash_t const * last_hash = fd_blockhashes_peek_last( bhq );
  if( FD_LIKELY( last_hash ) ) fd_bank_poh_set( bank, *last_hash );

  fd_bank_capitalization_set( bank, manifest->capitalization );
  fd_bank_lamports_per_signature_set( bank, manifest->lamports_per_signature );
  fd_bank_prev_lamports_per_signature_set( bank, manifest->lamports_per_signature );
  fd_bank_transaction_count_set( bank, manifest->transaction_count );
  fd_bank_parent_signature_cnt_set( bank, manifest->signature_count );
  fd_bank_tick_height_set( bank, manifest->tick_height );
  fd_bank_max_tick_height_set( bank, manifest->max_tick_height );
  fd_bank_ns_per_slot_set( bank, manifest->ns_per_slot );
  fd_bank_ticks_per_slot_set( bank, manifest->ticks_per_slot );
  fd_bank_genesis_creation_time_set( bank, manifest->creation_time_millis );
  fd_bank_slots_per_year_set( bank, manifest->slots_per_year );
  fd_bank_block_height_set( bank, manifest->block_height );
  fd_bank_execution_fees_set( bank, manifest->collector_fees );
  fd_bank_priority_fees_set( bank, 0UL );

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

  /* Vote stakes for the previous epoch (E-1). */
  fd_vote_states_t * vote_stakes_prev = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_prev_locking_modify( bank ), FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  for( ulong i=0UL; i<manifest->epoch_stakes[1].vote_stakes_len; i++ ) {
    fd_snapshot_manifest_vote_stakes_t const * elem = &manifest->epoch_stakes[1].vote_stakes[i];
    if( FD_UNLIKELY( !elem->stake ) ) continue;
    /* First convert the epoch credits to the format expected by the
       vote states.  We need to do this because we may need the vote
       state credits from the end of the previous epoch in case we need
       to recalculate the  */
    vote_state_credits[ i ].credits_cnt = elem->epoch_credits_history_len;
    for( ulong j=0UL; j<elem->epoch_credits_history_len; j++ ) {
      vote_state_credits[ i ].epoch[ j ]        = (ushort)elem->epoch_credits[ j ].epoch;
      vote_state_credits[ i ].credits[ j ]      = elem->epoch_credits[ j ].credits;
      vote_state_credits[ i ].prev_credits[ j ] = elem->epoch_credits[ j ].prev_credits;
    }

    fd_vote_state_ele_t * vote_state = fd_vote_states_update( vote_stakes_prev, (fd_pubkey_t *)elem->vote );
    vote_state->node_account        = *(fd_pubkey_t *)elem->identity;
    vote_state->commission          = elem->commission;
    vote_state->last_vote_timestamp = elem->timestamp;
    vote_state->last_vote_slot      = elem->slot;
    vote_state->stake               = elem->stake;
  }

  fd_bank_vote_states_prev_end_locking_modify( bank );

  /* We also want to set the total stake to be the total amout of stake
     at the end of the previous epoch. This value is used for the
     get_epoch_stake syscall.

     FIXME: This needs to be updated at the epoch boundary and this
     currently does NOT happen.

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
     epoch stake by querying for epoch+1. This logic is encapsulated
     in fd_ssmanifest_parser.c. */
  fd_bank_total_epoch_stake_set( bank, manifest->epoch_stakes[1].total_stake );

  /* Vote stakes for the previous epoch (E-2) */
  fd_vote_states_t * vote_stakes_prev_prev = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_prev_prev_locking_modify( bank ), FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  for( ulong i=0UL; i<manifest->epoch_stakes[0].vote_stakes_len; i++ ) {
    fd_snapshot_manifest_vote_stakes_t const * elem = &manifest->epoch_stakes[0].vote_stakes[i];
    if( FD_UNLIKELY( !elem->stake ) ) continue;
    fd_vote_state_ele_t * vote_state = fd_vote_states_update( vote_stakes_prev_prev, (fd_pubkey_t *)elem->vote );
    vote_state->node_account        = *(fd_pubkey_t *)elem->identity;
    vote_state->commission          = elem->commission;
    vote_state->last_vote_timestamp = elem->timestamp;
    vote_state->last_vote_slot      = elem->slot;
    vote_state->stake               = elem->stake;
    vote_state->stake               = elem->stake;
  }

  /* Vote states for the current epoch. */
  fd_vote_states_t * vote_states = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_locking_modify( bank ), FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  for( ulong i=0UL; i<manifest->vote_accounts_len; i++ ) {
    fd_snapshot_manifest_vote_account_t const * elem = &manifest->vote_accounts[ i ];

    fd_vote_state_ele_t * vote_state_prev_prev = fd_vote_states_query( vote_stakes_prev_prev, (fd_pubkey_t *)elem->vote_account_pubkey );
    ulong prev_prev_stake = vote_state_prev_prev ? vote_state_prev_prev->stake : 0UL;

    fd_vote_state_ele_t * vote_state = fd_vote_states_update( vote_states, (fd_pubkey_t *)elem->vote_account_pubkey );

    vote_state->node_account        = *(fd_pubkey_t *)elem->node_account_pubkey;
    vote_state->commission          = elem->commission;
    vote_state->last_vote_timestamp = elem->last_timestamp;
    vote_state->last_vote_slot      = elem->last_slot;
    vote_state->stake               = elem->stake;
    vote_state->stake_t_2           = prev_prev_stake;
  }
  fd_bank_vote_states_end_locking_modify( bank );

  fd_bank_vote_states_prev_prev_end_locking_modify( bank );

  bank->txncache_fork_id = (fd_txncache_fork_id_t){ .val = manifest->txncache_fork_id };
}
