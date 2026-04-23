#include "fd_runtime.h"

#include "../types/fd_cast.h"
#include "fd_alut.h"
#include "fd_hashes.h"
#include "fd_runtime_stack.h"
#include "fd_accdb_svm.h"
#include "../genesis/fd_genesis_parse.h"
#include "fd_txncache.h"
#include "fd_compute_budget_details.h"
#include "tests/fd_dump_pb.h"

#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar_last_restart_slot.h"
#include "sysvar/fd_sysvar_slot_hashes.h"
#include "sysvar/fd_sysvar_slot_history.h"

#include "../stakes/fd_stakes.h"
#include "../rewards/fd_rewards.h"

#include "program/fd_precompiles.h"
#include "program/vote/fd_vote_state_versioned.h"

#include "../../disco/pack/fd_pack_tip_prog_blacklist.h"

static fd_pubkey_t const fd_runtime_debug_lthash_account = {{
  0x80, 0xbd, 0xde, 0x6a, 0x55, 0xd6, 0x04, 0xc4,
  0xec, 0x90, 0x0b, 0x86, 0x84, 0x7e, 0x4e, 0x8c,
  0x14, 0x82, 0x3c, 0xc9, 0xe8, 0x04, 0x1c, 0xd1,
  0x1c, 0x5c, 0x47, 0xdf, 0x8a, 0xbf, 0xce, 0xab
}};

static fd_signature_t const fd_runtime_debug_signature = {
  .uc = {
    0x79, 0xbe, 0x5e, 0xe1, 0x31, 0xbe, 0x24, 0x8b,
    0x26, 0x97, 0x75, 0x5f, 0x80, 0x8b, 0x92, 0x00,
    0x52, 0xf8, 0xed, 0xb3, 0xea, 0x20, 0xe3, 0x6d,
    0xe5, 0xa6, 0xe6, 0x79, 0x83, 0x83, 0x27, 0xf4,
    0x11, 0xf2, 0xd7, 0xab, 0xda, 0xe2, 0x37, 0xba,
    0xcb, 0xc9, 0xc4, 0x48, 0x7c, 0x5b, 0x7d, 0xc3,
    0x30, 0xfb, 0xba, 0x17, 0xb2, 0x2d, 0xb6, 0xc3,
    0x8a, 0xb9, 0x4e, 0x0a, 0x8b, 0xf8, 0xd1, 0x08
  }
};

/*
   https://github.com/anza-xyz/agave/blob/v2.1.1/runtime/src/bank.rs#L1254-L1258
   https://github.com/anza-xyz/agave/blob/v2.1.1/runtime/src/bank.rs#L1749
 */
int
fd_runtime_compute_max_tick_height( ulong   ticks_per_slot,
                                    ulong   slot,
                                    ulong * out_max_tick_height /* out */ ) {
  ulong max_tick_height = 0UL;
  if( FD_LIKELY( ticks_per_slot > 0UL ) ) {
    ulong next_slot = fd_ulong_sat_add( slot, 1UL );
    if( FD_UNLIKELY( next_slot == slot ) ) {
      FD_LOG_WARNING(( "max tick height addition overflowed slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
      return -1;
    }
    if( FD_UNLIKELY( ULONG_MAX / ticks_per_slot < next_slot ) ) {
      FD_LOG_WARNING(( "max tick height multiplication overflowed slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
      return -1;
    }
    max_tick_height = fd_ulong_sat_mul( next_slot, ticks_per_slot );
  }
  *out_max_tick_height = max_tick_height;
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static void
update_next_leaders( fd_bank_t *          bank,
                     fd_runtime_stack_t * runtime_stack,
                     fd_vote_stakes_t *   vote_stakes ) {

  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;

  ulong epoch    = fd_slot_to_epoch ( epoch_schedule, bank->f.slot, NULL ) + 1UL;
  ulong slot0    = fd_epoch_slot0   ( epoch_schedule, epoch );
  ulong slot_cnt = fd_epoch_slot_cnt( epoch_schedule, epoch );

  fd_top_votes_t const *   top_votes_t_1    = fd_bank_top_votes_t_1_query( bank );
  fd_vote_stake_weight_t * epoch_weights    = runtime_stack->stakes.stake_weights;
  ulong                    stake_weight_cnt = fd_stake_weights_by_node_next( top_votes_t_1, vote_stakes, bank->vote_stakes_fork_id, epoch_weights, FD_FEATURE_ACTIVE_BANK( bank, validator_admission_ticket ) );

  void * epoch_leaders_mem = fd_bank_epoch_leaders_modify( bank );
  fd_epoch_leaders_t * leaders = fd_epoch_leaders_join( fd_epoch_leaders_new(
      epoch_leaders_mem,
      epoch,
      slot0,
      slot_cnt,
      stake_weight_cnt,
      epoch_weights,
      0UL ) );
  if( FD_UNLIKELY( !leaders ) ) {
    FD_LOG_ERR(( "Unable to init and join fd_epoch_leaders" ));
  }

  /* Populate a compressed set of stake weights for a valid leader
     schedule. */
  fd_vote_stake_weight_t * stake_weights = runtime_stack->epoch_weights.next_stake_weights;
  ulong idx = 0UL;

  int needs_compression = stake_weight_cnt>MAX_COMPRESSED_STAKE_WEIGHTS;

  for( ulong i=0UL; i<stake_weight_cnt; i++ ) {
    fd_pubkey_t const * vote_pubkey = &epoch_weights[i].vote_key;
    fd_pubkey_t const * node_pubkey = &epoch_weights[i].id_key;
    ulong               stake       = epoch_weights[i].stake;

    if( FD_LIKELY( !needs_compression || fd_epoch_leaders_is_leader_idx( leaders, i ) ) ) {
      stake_weights[ idx ].stake = stake;
      memcpy( stake_weights[ idx ].id_key.uc,   node_pubkey, sizeof(fd_pubkey_t) );
      memcpy( stake_weights[ idx ].vote_key.uc, vote_pubkey, sizeof(fd_pubkey_t) );
      idx++;
    } else if( idx!=0UL && !fd_epoch_leaders_is_leader_idx( leaders, i-1UL ) ) {
      stake_weights[ idx-1UL ].stake += stake;
    } else {
      stake_weights[ idx ].id_key   = (fd_pubkey_t){ .uc = FD_DUMMY_ACCOUNT };
      stake_weights[ idx ].vote_key = (fd_pubkey_t){ .uc = FD_DUMMY_ACCOUNT };
      stake_weights[ idx ].stake    = stake;
      idx++;
    }
  }
  runtime_stack->epoch_weights.next_stake_weights_cnt = idx;

  /* Produce truncated set of id weights to send to Shred tile for
     Turbine tree computation. */
  ulong staked_cnt = compute_id_weights_from_vote_weights( runtime_stack->stakes.id_weights, epoch_weights, stake_weight_cnt );
  ulong excluded_stake = 0UL;
  if( FD_UNLIKELY( staked_cnt>MAX_SHRED_DESTS ) ) {
    for( ulong i=MAX_SHRED_DESTS; i<staked_cnt; i++ ) {
      excluded_stake += runtime_stack->stakes.id_weights[i].stake;
    }
  }
  staked_cnt = fd_ulong_min( staked_cnt, MAX_SHRED_DESTS );
  memcpy( runtime_stack->epoch_weights.next_id_weights, runtime_stack->stakes.id_weights, staked_cnt * sizeof(fd_stake_weight_t) );
  runtime_stack->epoch_weights.next_id_weights_cnt      = staked_cnt;
  runtime_stack->epoch_weights.next_id_weights_excluded  = excluded_stake;
}

void
fd_runtime_update_leaders( fd_bank_t *          bank,
                           fd_runtime_stack_t * runtime_stack ) {

  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;

  ulong epoch     = fd_slot_to_epoch ( epoch_schedule, bank->f.slot, NULL );
  ulong vat_epoch = fd_slot_to_epoch ( epoch_schedule, bank->f.features.validator_admission_ticket, NULL );
  ulong slot0     = fd_epoch_slot0   ( epoch_schedule, epoch );
  ulong slot_cnt  = fd_epoch_slot_cnt( epoch_schedule, epoch );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );

  update_next_leaders( bank, runtime_stack, vote_stakes );

  int vat_in_prev = epoch>=vat_epoch+1UL ? 1 : 0;

  fd_top_votes_t const *   top_votes_t_2    = fd_bank_top_votes_t_2_query( bank );
  fd_vote_stake_weight_t * epoch_weights    = runtime_stack->stakes.stake_weights;
  ulong                    stake_weight_cnt = fd_stake_weights_by_node( top_votes_t_2, vote_stakes, bank->vote_stakes_fork_id, epoch_weights, vat_in_prev );

  /* TODO: Can optimize by avoiding recomputing if another fork has
     already computed them for this epoch. */
  void * epoch_leaders_mem = fd_bank_epoch_leaders_modify( bank );
  fd_epoch_leaders_t * leaders = fd_epoch_leaders_join( fd_epoch_leaders_new(
      epoch_leaders_mem,
      epoch,
      slot0,
      slot_cnt,
      stake_weight_cnt,
      epoch_weights,
      0UL ) );
  if( FD_UNLIKELY( !leaders ) ) {
    FD_LOG_ERR(( "Unable to init and join fd_epoch_leaders" ));
  }

  /* Populate a compressed set of stake weights for a valid leader
     schedule. */
  fd_vote_stake_weight_t * stake_weights = runtime_stack->epoch_weights.stake_weights;
  ulong idx = 0UL;

  int needs_compression = stake_weight_cnt>MAX_COMPRESSED_STAKE_WEIGHTS;

  for( ulong i=0UL; i<leaders->pub_cnt; i++ ) {
    fd_pubkey_t const * vote_pubkey = &epoch_weights[i].vote_key;
    fd_pubkey_t const * node_pubkey = &epoch_weights[i].id_key;
    ulong               stake       = epoch_weights[i].stake;

    if( FD_LIKELY( !needs_compression || fd_epoch_leaders_is_leader_idx( leaders, i ) ) ) {
      stake_weights[ idx ].stake = stake;
      memcpy( stake_weights[ idx ].id_key.uc,   node_pubkey, sizeof(fd_pubkey_t) );
      memcpy( stake_weights[ idx ].vote_key.uc, vote_pubkey, sizeof(fd_pubkey_t) );
      idx++;
    } else if( idx!=0UL && !fd_epoch_leaders_is_leader_idx( leaders, i-1UL ) ) {
      stake_weights[ idx-1UL ].stake += stake;
    } else {
      stake_weights[ idx ].id_key   = (fd_pubkey_t){ .uc = FD_DUMMY_ACCOUNT };
      stake_weights[ idx ].vote_key = (fd_pubkey_t){ .uc = FD_DUMMY_ACCOUNT };
      stake_weights[ idx ].stake    = stake;
      idx++;
    }
  }
  runtime_stack->epoch_weights.stake_weights_cnt = idx;

  /* Produce truncated set of id weights to send to Shred tile for
     Turbine tree computation. */
  ulong staked_cnt = compute_id_weights_from_vote_weights( runtime_stack->stakes.id_weights, epoch_weights, stake_weight_cnt );
  ulong excluded_stake = 0UL;
  if( FD_UNLIKELY( staked_cnt>MAX_SHRED_DESTS ) ) {
    for( ulong i=MAX_SHRED_DESTS; i<staked_cnt; i++ ) {
      excluded_stake += runtime_stack->stakes.id_weights[i].stake;
    }
  }
  staked_cnt = fd_ulong_min( staked_cnt, MAX_SHRED_DESTS );
  memcpy( runtime_stack->epoch_weights.id_weights, runtime_stack->stakes.id_weights, staked_cnt * sizeof(fd_stake_weight_t) );
  runtime_stack->epoch_weights.id_weights_cnt      = staked_cnt;
  runtime_stack->epoch_weights.id_weights_excluded = excluded_stake;
}

/******************************************************************************/
/* Various Private Runtime Helpers                                            */
/******************************************************************************/

static int
fd_runtime_validate_fee_collector( fd_bank_t const *        bank,
                                   fd_accdb_entry_t const * collector,
                                   ulong                    fee ) {
  FD_TEST( fee );
  if( FD_UNLIKELY( memcmp( collector->owner, fd_solana_system_program_id.uc, 32UL ) ) ) return 0;

  /* https://github.com/anza-xyz/agave/blob/v1.18.23/runtime/src/bank/fee_distribution.rs#L111
     https://github.com/anza-xyz/agave/blob/v1.18.23/runtime/src/accounts/account_rent_state.rs#L39

     In agave's fee deposit code, rent state transition check logic is as follows:
     The transition is NOT allowed iff
     === BEGIN
     the post deposit account is rent paying AND the pre deposit account is not rent paying
     OR
     the post deposit account is rent paying AND the pre deposit account is rent paying AND !(post_data_size == pre_data_size && post_lamports <= pre_lamports)
     === END
     post_data_size == pre_data_size is always true during fee deposit.
     However, post_lamports > pre_lamports because we are paying a >0 amount.
     So, the above reduces down to
     === BEGIN
     the post deposit account is rent paying AND the pre deposit account is not rent paying
     OR
     the post deposit account is rent paying AND the pre deposit account is rent paying AND TRUE
     === END
     This is equivalent to checking that the post deposit account is rent paying.
     An account is rent paying if the post deposit balance is >0 AND it's not rent exempt.
     We already know that the post deposit balance is >0 because we are paying a >0 amount.
     So TLDR we just check if the account is rent exempt. */
  ulong balance = collector->lamports;
  FD_TEST( !__builtin_uaddl_overflow( balance, fee, &balance ) );
  return balance>=fd_rent_exempt_minimum_balance( &bank->f.rent, collector->data_len );
}

/* fd_runtime_settle_fees settles transaction fees accumulated during a
   slot.  A portion is burnt, another portion is credited to the fee
   collector (typically leader). */

static void
fd_runtime_settle_fees( fd_bank_t *        bank,
                        fd_accdb_t *       accdb,
                        fd_capture_ctx_t * capture_ctx ) {
  ulong slot           = bank->f.slot;
  ulong execution_fees = bank->f.execution_fees;
  ulong priority_fees  = bank->f.priority_fees;
  ulong total_fees;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( execution_fees, priority_fees, &total_fees ) ) ) {
    FD_LOG_EMERG(( "fee overflow detected (slot=%lu execution_fees=%lu priority_fees=%lu)",
                   slot, execution_fees, priority_fees ));
  }

  ulong fee_burn   = execution_fees / 2;
  ulong fee_reward = fd_ulong_sat_add( priority_fees, execution_fees - fee_burn );

  /* Remove fee balance from bank (decreasing capitalization) */
  if( FD_UNLIKELY( total_fees > bank->f.capitalization ) ) {
    FD_LOG_EMERG(( "fee settlement would underflow capitalization (slot=%lu total_fees=%lu cap=%lu)",
                   slot, total_fees, bank->f.capitalization ));
  }
  bank->f.capitalization -= total_fees;
  bank->f.execution_fees  = 0;
  bank->f.priority_fees   = 0;

  if( FD_LIKELY( fee_reward ) ) {
    fd_epoch_leaders_t const * leaders = fd_bank_epoch_leaders_query( bank );
    if( FD_UNLIKELY( !leaders ) ) FD_LOG_CRIT(( "fd_bank_epoch_leaders_query returned NULL" ));
    fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, bank->f.slot );
    if( FD_UNLIKELY( !leader ) ) FD_LOG_CRIT(( "fd_epoch_leaders_get(%lu) returned NULL", bank->f.slot ));

    /* Pay out reward portion of collected fees (increasing capitalization) */
    fd_accdb_svm_update_t update[1];
    fd_accdb_entry_t entry = fd_accdb_svm_open_rw( bank, accdb, update, leader, 1 );
    if( FD_UNLIKELY( !fd_runtime_validate_fee_collector( bank, &entry, fee_reward ) ) ) {  /* validation failed */
      FD_LOG_INFO(( "slot %lu has an invalid fee collector, burning fee reward (%lu lamports)", bank->f.slot, fee_reward ));
    } else {
      entry.lamports += fee_reward; /* guaranteed to not overflow, checked above */
    }
    fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &entry, update );
  }

  FD_LOG_INFO(( "slot=%lu priority_fees=%lu execution_fees=%lu fee_burn=%lu fee_rewards=%lu",
                slot,
                priority_fees, execution_fees, fee_burn, fee_reward ));
}

static void
fd_runtime_freeze( fd_bank_t *        bank,
                   fd_accdb_t *       accdb,
                   fd_capture_ctx_t * capture_ctx ) {
  if( FD_LIKELY( bank->f.slot ) ) fd_sysvar_recent_hashes_update( bank, accdb, capture_ctx );
  fd_sysvar_slot_history_update( bank, accdb, capture_ctx );
  fd_runtime_settle_fees( bank, accdb, capture_ctx );

  /* jito collects a 3% fee at the end of the block + 3% fee at
     distribution time. */
  ulong tips_pre_comission = bank->f.tips;
  bank->f.tips = (tips_pre_comission - (tips_pre_comission * 6UL / 100UL));

  fd_accdb_svm_remove( bank, accdb, capture_ctx, &fd_sysvar_incinerator_id );
}

/******************************************************************************/
/* Block-Level Execution Preparation/Finalization                             */
/******************************************************************************/
void
fd_runtime_new_fee_rate_governor_derived( fd_bank_t * bank,
                                          ulong       latest_signatures_per_slot ) {

  fd_fee_rate_governor_t const * base_fee_rate_governor = &bank->f.fee_rate_governor;

  ulong old_lamports_per_signature = bank->f.rbh_lamports_per_sig;

  fd_fee_rate_governor_t me = {
    .target_signatures_per_slot    = base_fee_rate_governor->target_signatures_per_slot,
    .target_lamports_per_signature = base_fee_rate_governor->target_lamports_per_signature,
    .max_lamports_per_signature    = base_fee_rate_governor->max_lamports_per_signature,
    .min_lamports_per_signature    = base_fee_rate_governor->min_lamports_per_signature,
    .burn_percent                  = base_fee_rate_governor->burn_percent
  };

  ulong new_lamports_per_signature = 0;
  if( me.target_signatures_per_slot > 0 ) {
    me.min_lamports_per_signature = fd_ulong_max( 1UL, (ulong)(me.target_lamports_per_signature / 2) );
    me.max_lamports_per_signature = me.target_lamports_per_signature * 10;
    ulong desired_lamports_per_signature = fd_ulong_min(
      me.max_lamports_per_signature,
      fd_ulong_max(
        me.min_lamports_per_signature,
        me.target_lamports_per_signature
        * fd_ulong_min(latest_signatures_per_slot, (ulong)UINT_MAX)
        / me.target_signatures_per_slot
      )
    );
    long gap = (long)desired_lamports_per_signature - (long)old_lamports_per_signature;
    if ( gap == 0 ) {
      new_lamports_per_signature = desired_lamports_per_signature;
    } else {
      long gap_adjust = (long)(fd_ulong_max( 1UL, (ulong)(me.target_lamports_per_signature / 20) ))
        * (gap != 0)
        * (gap > 0 ? 1 : -1);
      new_lamports_per_signature = fd_ulong_min(
        me.max_lamports_per_signature,
        fd_ulong_max(
          me.min_lamports_per_signature,
          (ulong)((long)old_lamports_per_signature + gap_adjust)
        )
      );
    }
  } else {
    new_lamports_per_signature = base_fee_rate_governor->target_lamports_per_signature;
    me.min_lamports_per_signature = me.target_lamports_per_signature;
    me.max_lamports_per_signature = me.target_lamports_per_signature;
  }
  bank->f.fee_rate_governor = me;
  bank->f.rbh_lamports_per_sig = new_lamports_per_signature;
}

/******************************************************************************/
/* Epoch Boundary                                                             */
/******************************************************************************/

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6704 */
static void
fd_apply_builtin_program_feature_transitions( fd_bank_t *          bank,
                                              fd_accdb_t *         accdb,
                                              fd_runtime_stack_t * runtime_stack,
                                              fd_capture_ctx_t *   capture_ctx ) {
  /* TODO: Set the upgrade authority properly from the core bpf migration config. Right now it's set to None.

     Migrate any necessary stateless builtins to core BPF. So far,
     the only "stateless" builtin is the Feature program. Beginning
     checks in the migrate_builtin_to_core_bpf function will fail if the
     program has already been migrated to BPF. */

  fd_builtin_program_t const * builtins = fd_builtins();
  for( ulong i=0UL; i<fd_num_builtins(); i++ ) {
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6732-L6751 */
    if( builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( bank->f.slot, &bank->f.features, builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( builtins[i].pubkey->key, pubkey_b58 );
      FD_LOG_DEBUG(( "Migrating builtin program %s to core BPF", pubkey_b58 ));
      fd_migrate_builtin_to_core_bpf( bank, accdb, runtime_stack, builtins[i].core_bpf_migration_config, capture_ctx );
    }
    /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6753-L6774 */
    if( builtins[i].enable_feature_offset!=NO_ENABLE_FEATURE_ID && FD_FEATURE_JUST_ACTIVATED_OFFSET( bank, builtins[i].enable_feature_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( builtins[i].pubkey->key, pubkey_b58 );
      FD_LOG_DEBUG(( "Enabling builtin program %s", pubkey_b58 ));
      fd_write_builtin_account( bank, accdb, capture_ctx, *builtins[i].pubkey, builtins[i].data,strlen(builtins[i].data) );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6776-L6793 */
  fd_stateless_builtin_program_t const * stateless_builtins = fd_stateless_builtins();
  for( ulong i=0UL; i<fd_num_stateless_builtins(); i++ ) {
    if( stateless_builtins[i].core_bpf_migration_config && FD_FEATURE_ACTIVE_OFFSET( bank->f.slot, &bank->f.features, stateless_builtins[i].core_bpf_migration_config->enable_feature_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( stateless_builtins[i].pubkey->key, pubkey_b58 );
      FD_LOG_DEBUG(( "Migrating stateless builtin program %s to core BPF", pubkey_b58 ));
      fd_migrate_builtin_to_core_bpf( bank, accdb, runtime_stack, stateless_builtins[i].core_bpf_migration_config, capture_ctx );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/c1080de464cfb578c301e975f498964b5d5313db/runtime/src/bank.rs#L6795-L6805 */
  for( fd_precompile_program_t const * precompiles = fd_precompiles(); precompiles->verify_fn; precompiles++ ) {
    if( precompiles->feature_offset != NO_ENABLE_FEATURE_ID &&
        FD_FEATURE_JUST_ACTIVATED_OFFSET( bank, precompiles->feature_offset ) ) {
      fd_write_builtin_account( bank, accdb, capture_ctx, *precompiles->pubkey, "", 0 );
    }
  }
}

static void
fd_feature_activate( fd_bank_t *             bank,
                     fd_accdb_t *            accdb,
                     fd_capture_ctx_t *      capture_ctx,
                     fd_feature_id_t const * id,
                     fd_pubkey_t const *     addr ) {
  if( FD_UNLIKELY( id->reverted==1 ) ) return;

  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, bank->accdb_fork_id, addr->uc );
  if( FD_UNLIKELY( !entry.lamports ) ) return;
  if( FD_UNLIKELY( memcmp( entry.owner, fd_solana_feature_program_id.uc, 32UL ) ) ) {
    fd_accdb_unread_one( accdb, &entry ); /* Feature account not yet initialized */
    return;
  }

  fd_feature_t feature;
  if( FD_UNLIKELY( !fd_feature_decode( &feature, entry.data, entry.data_len ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( addr->uc, addr_b58 );
    FD_LOG_WARNING(( "cannot activate feature %s, corrupt account data", addr_b58 ));
    FD_LOG_HEXDUMP_NOTICE(( "corrupt feature account", entry.data, entry.data_len ));
    fd_accdb_unread_one( accdb, &entry );
    return;
  }
  fd_accdb_unread_one( accdb, &entry );

  FD_BASE58_ENCODE_32_BYTES( addr->uc, addr_b58 );
  if( FD_UNLIKELY( feature.is_active ) ) {
    FD_LOG_DEBUG(( "feature %s already activated at slot %lu", addr_b58, feature.activation_slot ));
    fd_features_set( &bank->f.features, id, feature.activation_slot);
  } else {
    FD_LOG_DEBUG(( "feature %s not activated at slot %lu, activating", addr_b58, bank->f.slot ));
    fd_accdb_svm_update_t update[1];
    fd_accdb_entry_t entry = fd_accdb_svm_open_rw( bank, accdb, update, addr, 0 );
    if( FD_UNLIKELY( !entry.lamports ) ) return;
    FD_TEST( entry.data_len>=sizeof(fd_feature_t) );

    feature.is_active       = 1;
    feature.activation_slot = bank->f.slot;
    FD_STORE( fd_feature_t, entry.data, feature );
    fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &entry, update );
  }
}

static void
fd_features_activate( fd_bank_t *        bank,
                      fd_accdb_t  *      accdb,
                      fd_capture_ctx_t * capture_ctx ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_activate( bank, accdb, capture_ctx, id, &id->id );
  }
}

/* SIMD-0194: deprecate_rent_exemption_threshold
   https://github.com/anza-xyz/agave/blob/v3.1.4/runtime/src/bank.rs#L5322-L5329 */
static void
deprecate_rent_exemption_threshold( fd_bank_t *        bank,
                                    fd_accdb_t *       accdb,
                                    fd_capture_ctx_t * capture_ctx ) {
  /* We use the bank fields here to mirror Agave - in mainnet, devnet
     and testnet Agave's bank rent.burn_percent field is different to
     the value in the sysvar. When this feature is activated in Agave,
     the sysvar inherits the value from the bank. */
  fd_rent_t rent               = bank->f.rent;
  rent.lamports_per_uint8_year = fd_rust_cast_double_to_ulong(
    (double)rent.lamports_per_uint8_year * rent.exemption_threshold );
  rent.exemption_threshold     = FD_SIMD_0194_NEW_RENT_EXEMPTION_THRESHOLD;

  /* We don't refresh the sysvar cache here. The cache is refreshed in
     fd_sysvar_cache_restore, which is called at the start of every
     block in fd_runtime_block_execute_prepare, after this function. */
  fd_sysvar_rent_write( bank, accdb, capture_ctx, &rent );
  bank->f.rent = rent;
}

// https://github.com/anza-xyz/agave/blob/v3.1.4/runtime/src/bank.rs#L5296-L5391
static void
fd_compute_and_apply_new_feature_activations( fd_bank_t *          bank,
                                              fd_accdb_t *         accdb,
                                              fd_runtime_stack_t * runtime_stack,
                                              fd_capture_ctx_t *   capture_ctx ) {
  /* Activate new features
      https://github.com/anza-xyz/agave/blob/v3.1.4/runtime/src/bank.rs#L5296-L5391 */
  fd_features_activate( bank, accdb, capture_ctx );
  fd_features_restore( bank, accdb );

  /* SIMD-0194: deprecate_rent_exemption_threshold
      https://github.com/anza-xyz/agave/blob/v3.1.4/runtime/src/bank.rs#L5322-L5329 */
  if( FD_UNLIKELY( FD_FEATURE_JUST_ACTIVATED_BANK( bank, deprecate_rent_exemption_threshold ) ) ) {
    deprecate_rent_exemption_threshold( bank, accdb, capture_ctx );
  }

  /* Apply builtin program feature transitions
      https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank.rs#L6621-L6624 */
  fd_apply_builtin_program_feature_transitions( bank, accdb, runtime_stack, capture_ctx );

  if( FD_UNLIKELY( FD_FEATURE_JUST_ACTIVATED_BANK( bank, vote_state_v4 ) ) ) {
    fd_upgrade_core_bpf_program( bank, accdb, runtime_stack, &fd_solana_stake_program_id, &fd_solana_stake_program_vote_state_v4_buffer_address, capture_ctx );
  }

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/bank.rs#L5703-L5716 */
  if( FD_UNLIKELY( FD_FEATURE_JUST_ACTIVATED_BANK( bank, replace_spl_token_with_p_token ) ) ) {
    fd_upgrade_loader_v2_program_with_loader_v3_program(
      bank,
      accdb,
      runtime_stack,
      &fd_solana_spl_token_id,
      &fd_solana_ptoken_program_buffer_address,
      FD_FEATURE_ACTIVE_BANK( bank, relax_programdata_account_check_migration ),
      capture_ctx );
  }

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.4/runtime/src/bank.rs#L5736-L5744 */
  if( FD_UNLIKELY( FD_FEATURE_JUST_ACTIVATED_BANK( bank, upgrade_bpf_stake_program_to_v5 ) ) ) {
    fd_upgrade_core_bpf_program(
      bank,
      accdb,
      runtime_stack,
      &fd_solana_stake_program_id,
      &fd_solana_stake_program_v5_buffer_address,
      capture_ctx );
  }
}

/* Starting a new epoch.
  New epoch:        T
  Just ended epoch: T-1
  Epoch before:     T-2

  In this function:
  - stakes in T-2 (vote_states_prev_prev) should be replaced by T-1 (vote_states_prev)
  - stakes at T-1 (vote_states_prev) should be replaced by updated stakes at T (vote_states)
  - leader schedule should be calculated using new T-2 stakes (vote_states_prev_prev)

  Invariant during an epoch T:
  vote_states_prev holds the stakes at T-1
  vote_states_prev_prev holds the stakes at T-2
 */
/* process for the start of a new epoch */
static void
fd_runtime_process_new_epoch( fd_banks_t *         banks,
                              fd_bank_t *          bank,
                              fd_accdb_t *         accdb,
                              fd_capture_ctx_t *   capture_ctx,
                              ulong                parent_epoch,
                              fd_runtime_stack_t * runtime_stack ) {
  long start = fd_log_wallclock();

  fd_compute_and_apply_new_feature_activations( bank, accdb, runtime_stack, capture_ctx );

  /* Update the cached warmup/cooldown rate epoch now that features may
     have changed (reduce_stake_warmup_cooldown may have just activated). */
  bank->f.warmup_cooldown_rate_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule,
                                                         bank->f.features.reduce_stake_warmup_cooldown,
                                                         NULL );

  /* Updates stake history sysvar accumulated values and recomputes
     stake delegations for vote accounts. */

  fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "stake_delegations is NULL" ));
  }

  fd_stakes_activate_epoch( bank, runtime_stack, accdb, capture_ctx, stake_delegations,
                            &bank->f.warmup_cooldown_rate_epoch );

  /* Distribute rewards.  This involves calculating the rewards for
     every vote and stake account. */

  fd_hash_t const * parent_blockhash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  fd_begin_partitioned_rewards( bank,
                                accdb,
                                runtime_stack,
                                capture_ctx,
                                stake_delegations,
                                parent_blockhash,
                                parent_epoch );

  fd_bank_stake_delegations_end_frontier_query( banks, bank );

  /* The Agave client handles updating their stakes cache with a call to
     update_epoch_stakes() which keys stakes by the leader schedule
     epochs and retains up to 6 epochs of stakes.  However, to correctly
     calculate the leader schedule, we just need to maintain the vote
     states for the current epoch, the previous epoch, and the one
     before that.
     https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank.rs#L2175
  */

  /* Now that our stakes caches have been updated, we can calculate the
     leader schedule for the upcoming epoch epoch using our new
     vote_states_prev_prev (stakes for T-2). */

  fd_runtime_update_leaders( bank, runtime_stack );

  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "starting epoch %lu at slot %lu took %.6f seconds", bank->f.epoch, bank->f.slot, (double)(end - start) / 1e9 ));
}

static void
fd_runtime_block_pre_execute_process_new_epoch( fd_banks_t *         banks,
                                                fd_bank_t *          bank,
                                                fd_accdb_t *         accdb,
                                                fd_capture_ctx_t *   capture_ctx,
                                                fd_runtime_stack_t * runtime_stack,
                                                int *                is_epoch_boundary ) {

  ulong const slot = bank->f.slot;
  if( FD_LIKELY( slot != 0UL ) ) {
    fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;

    ulong prev_epoch = fd_slot_to_epoch( epoch_schedule, bank->f.parent_slot, NULL );
    ulong slot_idx;
    ulong new_epoch  = fd_slot_to_epoch( epoch_schedule, slot, &slot_idx );
    if( FD_UNLIKELY( slot_idx==1UL && new_epoch==0UL ) ) {
      /* The block after genesis has a height of 1. */
      bank->f.block_height = 1UL;
    }

    if( FD_UNLIKELY( prev_epoch<new_epoch || !slot_idx ) ) {
      FD_LOG_DEBUG(( "Epoch boundary starting" ));
      fd_runtime_process_new_epoch( banks, bank, accdb, capture_ctx, prev_epoch, runtime_stack );
      *is_epoch_boundary = 1;
    } else {
      *is_epoch_boundary = 0;
    }

    fd_distribute_partitioned_epoch_rewards( bank, accdb, capture_ctx );
  } else {
    *is_epoch_boundary = 0;
  }
}


static void
fd_runtime_block_sysvar_update_pre_execute( fd_bank_t *          bank,
                                            fd_accdb_t *         accdb,
                                            fd_runtime_stack_t * runtime_stack,
                                            fd_capture_ctx_t *   capture_ctx ) {
  // let (fee_rate_governor, fee_components_time_us) = measure_us!(
  //     FeeRateGovernor::new_derived(&parent.fee_rate_governor, parent.signature_count())
  // );
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1312-L1314 */

  fd_runtime_new_fee_rate_governor_derived( bank, bank->f.parent_signature_cnt );

  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong                       parent_epoch   = fd_slot_to_epoch( epoch_schedule, bank->f.parent_slot, NULL );
  fd_sysvar_clock_update( bank, accdb, capture_ctx, runtime_stack, &parent_epoch );

  // It has to go into the current txn previous info but is not in slot 0
  if( bank->f.slot != 0 ) {
    fd_sysvar_slot_hashes_update( bank, accdb, capture_ctx );
  }
  fd_sysvar_last_restart_slot_update( bank, accdb, capture_ctx, bank->f.last_restart_slot );
}

int
fd_runtime_load_txn_address_lookup_tables( fd_txn_in_t const *    txn_in,
                                           fd_txn_t const *       txn,
                                           uchar const *          payload,
                                           fd_accdb_t *           accdb,
                                           fd_accdb_fork_id_t     fork_id,
                                           ulong                  slot,
                                           fd_slot_hash_t const * hashes, /* deque */
                                           fd_acct_addr_t *       out_accts_alt ) {
  if( FD_LIKELY( txn->transaction_version!=FD_TXN_V0 ) ) return FD_RUNTIME_EXECUTE_SUCCESS;

  fd_alut_interp_t interp[1];
  fd_alut_interp_new( interp, out_accts_alt, txn, payload, hashes, slot );

  fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn );
  for( ulong i=0UL; i<txn->addr_table_lookup_cnt; i++ ) {
    fd_txn_acct_addr_lut_t const * addr_lut = &addr_luts[i];
    fd_pubkey_t addr_lut_acc = FD_LOAD( fd_pubkey_t, payload+addr_lut->addr_off );

    if( FD_UNLIKELY( txn_in && txn_in->bundle.is_bundle ) ) {
      for( ulong j=txn_in->bundle.prev_txn_cnt; j>0UL; j-- ) {
        fd_txn_out_t * prev_txn_out = txn_in->bundle.prev_txn_outs[ j-1 ];
        for( ushort k=0; k<prev_txn_out->accounts.cnt; k++ ) {
          int writable = fd_runtime_account_is_writable_idx( txn_in, prev_txn_out, k );
          if( fd_pubkey_eq( &prev_txn_out->accounts.keys[ k ], &addr_lut_acc ) && writable  ) {
            fd_accdb_entry_t * acc = &prev_txn_out->accounts.account[ k ];
            if( FD_UNLIKELY( !acc->lamports ) ) return FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;

            int err = fd_alut_interp_next( interp, &addr_lut_acc, acc->owner, acc->data, acc->data_len );
            if( FD_UNLIKELY( err ) ) return err;
            return FD_RUNTIME_EXECUTE_SUCCESS;
          }
        }
      }
    }

    fd_accdb_entry_t entry = fd_accdb_read_one( accdb, fork_id, addr_lut_acc.uc );
    if( FD_UNLIKELY( !entry.lamports ) ) return FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
    int err = fd_alut_interp_next( interp, &addr_lut_acc, entry.owner, entry.data, entry.data_len );
    fd_accdb_unread_one( accdb, &entry );
    if( FD_UNLIKELY( err ) ) return err;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* Pre-populate the bank's in-memory feature set with upcoming feature
   activations.  If the current slot is the last slot before an epoch
   boundary, scan all known feature accounts. Otherwise, returns early.

   For any feature that is pending (not yet activated on-chain) but has
   an account owned by the feature program, set the in-memory activation
   slot within the bank's featureset to the first slot of the next
   epoch.  This is needed so that deployment verification (which uses
   slot+1) can detect features that will activate at the next epoch
   boundary.

   In Agave, program deployments use the feature set from the next
   slot via DELAY_VISIBILITY_SLOT_OFFSET.  The runtime environments
   for deployment are selected based on epoch_of(slot+1):
   https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank.rs#L3280-L3295
   https://github.com/anza-xyz/agave/blob/v3.1.8/svm/src/transaction_processor.rs#L339-L345

   This function does NOT write to feature accounts or update the
   lthash.  It only modifies the bank's in-memory feature set. */
static void
fd_features_prepopulate_upcoming( fd_bank_t *  bank,
                                  fd_accdb_t * accdb ) {
  ulong slot = bank->f.slot;
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong curr_epoch = fd_slot_to_epoch( epoch_schedule, slot,     NULL );
  ulong next_epoch = fd_slot_to_epoch( epoch_schedule, slot+1UL, NULL );
  if( FD_LIKELY( curr_epoch==next_epoch ) ) return;

  fd_features_restore( bank, accdb );
}

void
fd_runtime_block_execute_prepare( fd_banks_t *         banks,
                                  fd_bank_t *          bank,
                                  fd_accdb_t *         accdb,
                                  fd_runtime_stack_t * runtime_stack,
                                  fd_capture_ctx_t *   capture_ctx,
                                  int *                is_epoch_boundary ) {
  fd_runtime_block_pre_execute_process_new_epoch( banks, bank, accdb, capture_ctx, runtime_stack, is_epoch_boundary );

  if( FD_LIKELY( bank->f.slot ) ) {
    fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_modify( bank );
    FD_TEST( cost_tracker );
    fd_cost_tracker_init( cost_tracker, &bank->f.features, bank->f.slot );
  }

  fd_features_prepopulate_upcoming( bank, accdb );
  fd_runtime_block_sysvar_update_pre_execute( bank, accdb, runtime_stack, capture_ctx );
  FD_TEST( fd_sysvar_cache_restore( bank, accdb ) );
}

static void
fd_runtime_update_bank_hash( fd_bank_t *        bank,
                             fd_capture_ctx_t * capture_ctx ) {
  /* Compute the new bank hash */
  fd_lthash_value_t const * lthash = fd_bank_lthash_locking_query( bank );
  fd_hash_t new_bank_hash[1] = { 0 };
  fd_hashes_hash_bank(
      lthash,
      &bank->f.prev_bank_hash,
      (fd_hash_t *)bank->f.poh.hash,
      bank->f.signature_count,
      new_bank_hash );

  /* Update the bank hash */
  bank->f.bank_hash = *new_bank_hash;

  if( capture_ctx && capture_ctx->capture_solcap &&
      bank->f.slot>=capture_ctx->solcap_start_slot ) {

    uchar lthash_hash[FD_HASH_FOOTPRINT];
    fd_blake3_hash(lthash->bytes, FD_LTHASH_LEN_BYTES, lthash_hash );
    fd_capture_link_write_bank_preimage(
      capture_ctx,
      bank->f.slot,
      (fd_hash_t *)new_bank_hash->hash,
      (fd_hash_t *)&bank->f.prev_bank_hash,
      (fd_hash_t *)lthash_hash,
      (fd_hash_t *)bank->f.poh.hash,
      bank->f.signature_count );
  }

  fd_bank_lthash_end_locking_query( bank );
}

/******************************************************************************/
/* Transaction Level Execution Management                                     */
/******************************************************************************/

/* fd_runtime_pre_execute_check is responsible for conducting many of
   the transaction sanitization checks.  This is a combination of some
   of the work done in Agave's load_and_execute_transactions(), and some
   of the work done in Agave's transaction ingestion stage, before the
   transaction even hits the scheduler.  We do some of the checks also
   in our transaction ingestion stage.  For example, the duplicate
   account check is performed in both the leader and the replay
   scheduler.  As a result, the duplicate account check below is
   essentially redundant, except that our fuzzing harness expects a
   single entry point to cover all of these checks.  So we keep all of
   the checks below for fuzzing purposes.  We could in theory hoist some
   of the pre-scheduler checks into a public function that is only
   invoked by the fuzzer to avoid duplication in the leader and the
   replay pipeline.  But all the duplicate checks are pretty cheap, and
   the order and placement of the checks are also in motion on Agave's
   side, and performing all the checks faithfully would require access
   to the bank in the scheduler which is kind of gross.  So that's all
   probably more hassle than worth. */

static inline int
fd_runtime_pre_execute_check( fd_runtime_t *      runtime,
                              fd_bank_t *         bank,
                              fd_txn_in_t const * txn_in,
                              fd_txn_out_t *      txn_out ) {

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/sdk/src/transaction/sanitized.rs#L263-L275
     TODO: Agave's precompile verification is done at the slot level, before batching and executing transactions. This logic should probably
     be moved in the future. The Agave call heirarchy looks something like this:
            process_single_slot
                   v
            confirm_full_slot
                   v
            confirm_slot_entries --------------------------------------------------->
                   v                               v                                v
            verify_transaction    ComputeBudget::process_instruction         process_entries
                   v                                                                v
            verify_precompiles                                                process_batches
                                                                                    v
                                                                                   ...
                                                                                    v
                                                                        load_and_execute_transactions
                                                                                    v
                                                                                   ...
                                                                                    v
                                                                              load_accounts --> load_transaction_accounts
                                                                                    v
                                                                       general transaction execution

  */

  /* Verify the transaction. For now, this step only involves processing
     the compute budget instructions. */
  int err = fd_executor_verify_transaction( bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  /* Resolve and verify ALUT-referenced account keys, if applicable */
  err = fd_executor_setup_txn_alut_account_keys( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  /* Set up the transaction accounts and other txn ctx metadata */
  fd_executor_setup_accounts_for_txn( runtime, bank, txn_in, txn_out );

  /* Post-sanitization checks. Called from prepare_sanitized_batch()
     which, for now, only is used to lock the accounts and perform a
     couple basic validations.
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118 */
  err = fd_executor_validate_account_locks( bank, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  /* load_and_execute_transactions() -> check_transactions()
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L3667-L3672 */
  err = fd_executor_check_transactions( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  /* load_and_execute_sanitized_transactions() -> validate_fees() ->
     validate_transaction_fee_payer()
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L236-L249 */
  err = fd_executor_validate_transaction_fee_payer( bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    txn_out->err.is_committable = 0;
    return err;
  }

  txn_out->details.exec_start_timestamp = fd_tickcount();

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L284-L296 */
  err = fd_executor_load_transaction_accounts( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    /* Regardless of whether transaction accounts were loaded successfully, the transaction is
       included in the block and transaction fees are collected.
       https://github.com/anza-xyz/agave/blob/v2.1.6/svm/src/transaction_processor.rs#L341-L357 */
    txn_out->err.is_fees_only = 1;

    /* If the transaction fails to load, the "rollback" accounts will include one of the following:
        1. Nonce account only
        2. Fee payer only
        3. Nonce account + fee payer

        Because the cost tracker uses the loaded account data size in block cost calculations, we need to
        make sure our calculated loaded accounts data size is conformant with Agave's.
        https://github.com/anza-xyz/agave/blob/v2.1.14/runtime/src/bank.rs#L4116

        In any case, we should always add the dlen of the fee payer. */
    txn_out->details.loaded_accounts_data_size = txn_out->accounts.account[ FD_FEE_PAYER_TXN_IDX ].data_len;

    /* Special case handling for if a nonce account is present in the transaction. */
    if( txn_out->accounts.nonce_idx_in_txn!=ULONG_MAX ) {
      /* If the nonce account is not the fee payer, then we separately add the dlen of the nonce account. Otherwise, we would
          be double counting the dlen of the fee payer. */
      if( txn_out->accounts.nonce_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) {
        txn_out->details.loaded_accounts_data_size += txn_out->accounts.account[ txn_out->accounts.nonce_idx_in_txn ].data_len;
      }
    }
  }

  /*
     The fee payer and the nonce account will be stored and hashed so
     long as the transaction landed on chain, or, in Agave terminology,
     the transaction was processed.
     https://github.com/anza-xyz/agave/blob/v2.1.1/runtime/src/account_saver.rs#L72

     A transaction lands on chain in one of two ways:
     (1) Passed fee validation and loaded accounts.
     (2) Passed fee validation and failed to load accounts and the enable_transaction_loading_failure_fees feature is enabled as per
         SIMD-0082 https://github.com/anza-xyz/feature-gate-tracker/issues/52

     So, at this point, the transaction is committable.
   */

  return err;
}

/* fd_runtime_lthash_account updates the running lthash of the bank
   given an account that might have been updated. */

static void
fd_runtime_lthash_account( fd_bank_t *         bank,
                           fd_pubkey_t const * pubkey,
                           fd_accdb_entry_t *  entry,
                           fd_capture_ctx_t *  capture_ctx,
                           fd_signature_t const * txn_signature ) {
  fd_lthash_value_t lthash_prev[1];
  if( FD_LIKELY( entry->prior_data ) ) {
    fd_hashes_account_lthash_simple( pubkey->uc, entry->prior_owner, entry->prior_lamports, entry->prior_executable, entry->prior_data, entry->prior_data_len, lthash_prev );
  } else {
    fd_lthash_zero( lthash_prev );
  }

  //FD_BASE58_ENCODE_32_BYTES( pubkey->uc, pubkey_b58 );
  //FD_LOG_WARNING(("PUBKEY %s", pubkey_b58));

  fd_lthash_value_t lthash_post[1];
  if( FD_LIKELY( entry->prior_data || entry->lamports ) ) {
    fd_hashes_update_simple( lthash_post, lthash_prev, pubkey->uc, entry->owner, entry->lamports, entry->executable, entry->data, entry->data_len, bank, capture_ctx );
    if( FD_UNLIKELY( fd_pubkey_eq( pubkey, &fd_runtime_debug_lthash_account ) ) ) {

      FD_BASE58_ENCODE_32_BYTES( pubkey->uc, pubkey_b58 );
      FD_BASE58_ENCODE_32_BYTES( entry->owner, owner_b58 );
      FD_BASE58_ENCODE_64_BYTES( txn_signature ? txn_signature->uc : NULL, txn_signature_b58 );
      FD_BASE58_ENCODE_32_BYTES( lthash_prev->bytes, lthash_prev_b58 );
      FD_BASE58_ENCODE_32_BYTES( lthash_post->bytes, lthash_post_b58 );
      FD_LOG_WARNING(( "TARGET ACCOUNT LTHASH slot=%lu txn=%s pubkey=%s owner=%s lamports=%lu executable=%d data_len=%lu lthash_prev=%s lthash_post=%s",
                       bank->f.slot, txn_signature_b58, pubkey_b58, owner_b58, entry->lamports, entry->executable, entry->data_len, lthash_prev_b58, lthash_post_b58 ));
      if( FD_LIKELY( entry->data_len ) ) FD_LOG_HEXDUMP_WARNING(( "TARGET ACCOUNT DATA", entry->data, entry->data_len ));
      else                               FD_LOG_WARNING(( "TARGET ACCOUNT DATA <empty>" ));
    }
  }
}

/* fd_runtime_commit_txn is a helper used by the transaction executor to
   finalize account changes back into the database.  It also handles
   txncache insertion and updates to the vote/stake cache.  TODO: This
   function should probably be moved to fd_executor.c. */

void
fd_runtime_commit_txn( fd_runtime_t * runtime,
                       fd_bank_t *    bank,
                       fd_txn_out_t * txn_out ) {
  FD_TEST( txn_out->err.is_committable );

  txn_out->details.commit_start_timestamp = fd_tickcount();

  if( FD_UNLIKELY( fd_signature_eq( &txn_out->details.signature, &fd_runtime_debug_signature ) ) ) {
    FD_LOG_WARNING(( "TXN RESULT %d %d %d", txn_out->err.txn_err, txn_out->err.exec_err, txn_out->err.exec_err_idx ));
  }

  if( FD_UNLIKELY( !txn_out->err.txn_err ) ) {
    fd_top_votes_t * top_votes = fd_bank_top_votes_t_2_modify( bank );
    for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
      /* We are only interested in saving writable accounts and the fee
         payer account. */
      if( FD_UNLIKELY( !txn_out->accounts.account[ i ]._writable ) ) continue;

      fd_pubkey_t const * pubkey  = &txn_out->accounts.keys[ i ];
      fd_accdb_entry_t *  account = &txn_out->accounts.account[ i ];

      account->commit = 1;

      /* Tips for bundles are collected in the bank: a user submitting a
         bundle must include a instruction that transfers lamports to
         a specific tip account.  Tips accumulated through the slot. */
      if( FD_UNLIKELY( fd_pack_tip_is_tip_account( fd_type_pun_const( pubkey->uc ) ) ) ) {
        txn_out->details.tips += fd_ulong_sat_sub( account->lamports, account->prior_lamports );
      }

      if( FD_UNLIKELY( txn_out->accounts.stake_update[ i ] ) ) {
        fd_stakes_update_stake_delegation( pubkey, account, bank );
      }

      if( FD_UNLIKELY( txn_out->accounts.new_vote[ i ] && !FD_FEATURE_ACTIVE_BANK( bank, validator_admission_ticket ) ) ) {
        fd_new_votes_t * new_votes = fd_bank_new_votes( bank );
        fd_new_votes_insert( new_votes, bank->new_votes_fork_id, pubkey );
      }

      if( FD_UNLIKELY( txn_out->accounts.vote_update[ i ] ) ) {
        if( FD_UNLIKELY( !account->lamports || !fd_vsv_is_correct_size_owner_and_init( account->owner, account->data, account->data_len ) ) ) {
          fd_top_votes_invalidate( top_votes, pubkey );
        } else {
          fd_vote_block_timestamp_t last_vote;
          FD_TEST( !fd_vote_account_last_timestamp( account->data, account->data_len, &last_vote ) );
          fd_top_votes_update( top_votes, pubkey, last_vote.slot, last_vote.timestamp );
        }
      }

      fd_runtime_lthash_account( bank, pubkey, account, runtime->log.capture_ctx, &txn_out->details.signature );
    }

    /* Atomically add all accumulated tips to the bank once after
       processing all accounts. */
    if( FD_UNLIKELY( txn_out->details.tips ) ) FD_ATOMIC_FETCH_AND_ADD( &bank->f.tips, txn_out->details.tips );
  }

  FD_ATOMIC_FETCH_AND_ADD( &bank->f.txn_count,       1UL );
  FD_ATOMIC_FETCH_AND_ADD( &bank->f.execution_fees,  txn_out->details.execution_fee );
  FD_ATOMIC_FETCH_AND_ADD( &bank->f.priority_fees,   txn_out->details.priority_fee );
  FD_ATOMIC_FETCH_AND_ADD( &bank->f.signature_count, txn_out->details.signature_count );

  if( FD_LIKELY( !txn_out->details.is_simple_vote ) ) {
    FD_ATOMIC_FETCH_AND_ADD( &bank->f.nonvote_txn_count, 1 );
    if( FD_UNLIKELY( txn_out->err.exec_err ) ) FD_ATOMIC_FETCH_AND_ADD( &bank->f.nonvote_failed_txn_count, 1 );
  }

  if( FD_UNLIKELY( txn_out->err.exec_err ) ) FD_ATOMIC_FETCH_AND_ADD( &bank->f.failed_txn_count, 1 );
  FD_ATOMIC_FETCH_AND_ADD( &bank->f.total_compute_units_used, txn_out->details.compute_budget.compute_unit_limit-txn_out->details.compute_budget.compute_meter );

  fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_modify( bank );
  int res = fd_cost_tracker_try_add_cost( cost_tracker, txn_out );
  if( FD_UNLIKELY( res!=FD_COST_TRACKER_SUCCESS ) ) {
    FD_LOG_DEBUG(( "fd_runtime_commit_txn: transaction failed to fit into block %d", res ));
    txn_out->err.is_committable = 0;
    txn_out->err.txn_err        = fd_cost_tracker_err_to_runtime_err( res );
  }

  if( FD_LIKELY( runtime->status_cache && txn_out->accounts.nonce_idx_in_txn==ULONG_MAX ) ) {
    /* In Agave, durable nonce transactions are inserted to the status
       cache the same as any others, but this is only to serve RPC
       requests, they do not need to be in there for correctness as the
       nonce mechanism itself prevents double spend.  We skip this logic
       entirely to simplify and improve performance of the txn cache. */
    fd_txncache_insert( runtime->status_cache, bank->txncache_fork_id, txn_out->details.blockhash.uc, txn_out->details.blake_txn_msg_hash.uc );
  }

  if( FD_UNLIKELY( txn_out->err.txn_err ) ) {
    /* With nonce account rollbacks, there are three cases:

       1. No nonce account in the transaction
       2. Nonce account is the fee payer
       3. Nonce account is not the fee payer

       We should always rollback the nonce account first.  Note that the
       nonce account may be the fee payer (case 2). */
    if( FD_UNLIKELY( txn_out->accounts.nonce_idx_in_txn!=ULONG_MAX ) ) {
      fd_accdb_entry_t * nonce_account = &txn_out->accounts.account[ txn_out->accounts.nonce_idx_in_txn ];
      fd_memcpy( nonce_account->data, txn_out->accounts.nonce_rollback_data, txn_out->accounts.nonce_rollback_data_len );
      nonce_account->data_len = txn_out->accounts.nonce_rollback_data_len;
      fd_memcpy( nonce_account->owner, nonce_account->prior_owner, 32UL );
      if( FD_UNLIKELY( txn_out->accounts.nonce_idx_in_txn==FD_FEE_PAYER_TXN_IDX ) ) {
        nonce_account->lamports = txn_out->accounts.fee_payer_rollback_lamports;
      } else {
        nonce_account->lamports = nonce_account->prior_lamports;
      }
      nonce_account->executable = nonce_account->prior_executable;

      nonce_account->commit = 1;

      if( FD_UNLIKELY( fd_signature_eq( &txn_out->details.signature, &fd_runtime_debug_signature ) ) ) {
        FD_BASE58_ENCODE_32_BYTES( nonce_account->pubkey, nonce_account_b58 );
        FD_LOG_WARNING(( "TXN RESULT %d %d %d %s", txn_out->err.txn_err, txn_out->err.exec_err, txn_out->err.exec_err_idx, nonce_account_b58 ));

        FD_LOG_HEXDUMP_NOTICE(("ACCOUNT DATA", nonce_account->data, nonce_account->data_len));
        FD_LOG_NOTICE(("LAMPORTS %lu", nonce_account->lamports));
        FD_BASE58_ENCODE_32_BYTES( nonce_account->owner, out)
        FD_LOG_NOTICE(("OWNER %s", out));
        FD_LOG_NOTICE(("EXECUTABLE %u", nonce_account->executable));
      }

      fd_runtime_lthash_account( bank, &txn_out->accounts.keys[ txn_out->accounts.nonce_idx_in_txn ], nonce_account, runtime->log.capture_ctx, &txn_out->details.signature );
    }

    /* Now, we must only save the fee payer if the nonce account was not
       the fee payer (because that was already saved above). */
    if( FD_LIKELY( txn_out->accounts.nonce_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) ) {
      fd_accdb_entry_t * fee_payer_account = &txn_out->accounts.account[ FD_FEE_PAYER_TXN_IDX ];
      fd_memcpy( fee_payer_account->data, fee_payer_account->prior_data, fee_payer_account->prior_data_len );
      fee_payer_account->data_len = fee_payer_account->prior_data_len;
      fd_memcpy( fee_payer_account->owner, fee_payer_account->prior_owner, 32UL );
      fee_payer_account->lamports = txn_out->accounts.fee_payer_rollback_lamports;
      fee_payer_account->executable = fee_payer_account->prior_executable;


      if( FD_UNLIKELY( fd_signature_eq( &txn_out->details.signature, &fd_runtime_debug_signature ) ) ) {
        FD_BASE58_ENCODE_32_BYTES( fee_payer_account->pubkey, nonce_account_b58 );
        FD_LOG_WARNING(( "TXN RESULT %d %d %d %s", txn_out->err.txn_err, txn_out->err.exec_err, txn_out->err.exec_err_idx, nonce_account_b58 ));
      }

      fee_payer_account->commit = 1;
      fd_runtime_lthash_account( bank, &txn_out->accounts.keys[ FD_FEE_PAYER_TXN_IDX ], fee_payer_account, runtime->log.capture_ctx, &txn_out->details.signature );
    }
  }

  fd_accdb_release( runtime->accdb, txn_out->accounts.cnt, txn_out->accounts.account );
  if( FD_LIKELY( runtime->accounts.executable_cnt ) ) {
    fd_accdb_release( runtime->accdb, runtime->accounts.executable_cnt, runtime->accounts.executable );
    runtime->accounts.executable_cnt = 0UL;
  }
}

void
fd_runtime_cancel_txn( fd_runtime_t * runtime,
                       fd_txn_out_t * txn_out ) {
  FD_TEST( !txn_out->err.is_committable );
  if( FD_UNLIKELY( !txn_out->accounts.is_setup ) ) return;

  fd_accdb_release( runtime->accdb, txn_out->accounts.cnt, txn_out->accounts.account );
  if( FD_LIKELY( runtime->accounts.executable_cnt ) ) {
    fd_accdb_release( runtime->accdb, runtime->accounts.executable_cnt, runtime->accounts.executable );
    runtime->accounts.executable_cnt = 0UL;
  }
}
static inline void
fd_runtime_reset_runtime( fd_runtime_t * runtime ) {
  runtime->instr.stack_sz     = 0;
  runtime->instr.trace_length = 0UL;
}

static inline void
fd_runtime_new_txn_out( fd_txn_in_t const * txn_in,
                        fd_txn_out_t *      txn_out ) {
  txn_out->details.prep_start_timestamp   = fd_tickcount();

  txn_out->details.load_start_timestamp   = LONG_MAX;
  txn_out->details.exec_start_timestamp   = LONG_MAX;
  txn_out->details.commit_start_timestamp = LONG_MAX;

  fd_compute_budget_details_new( &txn_out->details.compute_budget );

  txn_out->details.loaded_accounts_data_size = 0UL;
  txn_out->details.accounts_resize_delta     = 0L;

  txn_out->details.return_data.len = 0UL;
  memset( txn_out->details.return_data.program_id.key, 0, sizeof(fd_pubkey_t) );

  txn_out->details.tips            = 0UL;
  txn_out->details.execution_fee   = 0UL;
  txn_out->details.priority_fee    = 0UL;
  txn_out->details.signature_count = 0UL;
  fd_memset( txn_out->details.signature.uc, 0, sizeof(fd_signature_t) );

  txn_out->details.signature_count = TXN( txn_in->txn )->signature_cnt;
  if( FD_LIKELY( txn_out->details.signature_count ) ) {
    fd_memcpy( txn_out->details.signature.uc,
               (uchar const *)txn_in->txn->payload + TXN( txn_in->txn )->signature_off,
               sizeof(fd_signature_t) );
  }
  txn_out->details.is_simple_vote  = fd_txn_is_simple_vote_transaction( TXN( txn_in->txn ), txn_in->txn->payload );

  fd_hash_t * blockhash = (fd_hash_t *)((uchar *)txn_in->txn->payload + TXN( txn_in->txn )->recent_blockhash_off);
  memcpy( txn_out->details.blockhash.uc, blockhash->hash, sizeof(fd_hash_t) );

  txn_out->accounts.is_setup           = 0;
  txn_out->accounts.cnt                = 0UL;
  memset( txn_out->accounts.stake_update, 0, sizeof(txn_out->accounts.stake_update) );
  memset( txn_out->accounts.vote_update, 0, sizeof(txn_out->accounts.vote_update) );
  memset( txn_out->accounts.new_vote, 0, sizeof(txn_out->accounts.new_vote) );

  txn_out->err.is_committable = 1;
  txn_out->err.is_fees_only   = 0;
  txn_out->err.txn_err        = FD_RUNTIME_EXECUTE_SUCCESS;
  txn_out->err.exec_err       = FD_EXECUTOR_INSTR_SUCCESS;
  txn_out->err.exec_err_kind  = FD_EXECUTOR_ERR_KIND_NONE;
  txn_out->err.exec_err_idx   = INT_MAX;
  txn_out->err.custom_err     = 0;

  txn_out->accounts.cnt = (uchar)TXN( txn_in->txn )->acct_addr_cnt;
  fd_pubkey_t * tx_accs = (fd_pubkey_t *)((uchar *)txn_in->txn->payload + TXN( txn_in->txn )->acct_addr_off);

  for( ulong i=0UL; i<TXN( txn_in->txn )->acct_addr_cnt; i++ ) txn_out->accounts.keys[ i ] = tx_accs[ i ];
}

void
fd_runtime_prepare_and_execute_txn( fd_runtime_t *      runtime,
                                    fd_bank_t *         bank,
                                    fd_txn_in_t const * txn_in,
                                    fd_txn_out_t *      txn_out ) {
  fd_runtime_reset_runtime( runtime );
  fd_runtime_new_txn_out( txn_in, txn_out );

  uchar dump_txn = !!( runtime->log.dump_proto_ctx &&
                       bank->f.slot >= runtime->log.dump_proto_ctx->dump_proto_start_slot &&
                       runtime->log.dump_proto_ctx->dump_txn_to_pb );

  /* Phase 1: Capture TxnContext before execution. */
  if( FD_UNLIKELY( dump_txn ) ) {
    if( runtime->log.txn_dump_ctx ) {
      fd_dump_txn_context_to_protobuf( runtime->log.txn_dump_ctx, runtime, bank, txn_in, txn_out );
    } else {
      fd_dump_txn_to_protobuf( runtime, bank, txn_in, txn_out );
    }
  }

  /* Transaction sanitization.  If a transaction can't be commited or is
     fees-only, we return early. */
  txn_out->err.txn_err = fd_runtime_pre_execute_check( runtime, bank, txn_in, txn_out );
  ulong cu_before = txn_out->details.compute_budget.compute_meter;

  /* Execute the transaction if eligible to do so. */
  if( FD_LIKELY( txn_out->err.is_committable ) ) {
    if( FD_LIKELY( !txn_out->err.is_fees_only ) ) {
      txn_out->err.txn_err = fd_execute_txn( runtime, bank, txn_in, txn_out );
    }
    fd_cost_tracker_calculate_cost( bank, txn_in, txn_out );
  }
  ulong cu_after = txn_out->details.compute_budget.compute_meter;
  runtime->metrics.cu_cum += fd_ulong_sat_sub( cu_before, cu_after );

  /* Phase 2: Capture TxnResult after execution and write to disk. */
  if( FD_UNLIKELY( dump_txn && runtime->log.txn_dump_ctx ) ) {
    fd_dump_txn_result_to_protobuf( runtime->log.txn_dump_ctx, txn_in, txn_out, txn_out->err.txn_err );
    fd_dump_txn_fixture_to_file( runtime->log.txn_dump_ctx, runtime->log.dump_proto_ctx, txn_in );
  }
}

/* fd_executor_txn_verify and fd_runtime_pre_execute_check are responisble
   for the bulk of the pre-transaction execution checks in the runtime.
   They aim to preserve the ordering present in the Agave client to match
   parity in terms of error codes. Sigverify is kept separate from the rest
   of the transaction checks for fuzzing convenience.

   For reference this is the general code path which contains all relevant
   pre-transactions checks in the v2.0.x Agave client from upstream
   to downstream is as follows:

   confirm_slot_entries() which calls verify_ticks() and
   verify_transaction(). verify_transaction() calls verify_and_hash_message()
   and verify_precompiles() which parallels fd_executor_txn_verify() and
   fd_executor_verify_transaction().

   process_entries() contains a duplicate account check which is part of
   agave account lock acquiring. This is checked inline in
   fd_runtime_pre_execute_check().

   load_and_execute_transactions() contains the function check_transactions().
   This contains check_age() and check_status_cache() which is paralleled by
   fd_executor_check_transaction_age_and_compute_budget_limits() and
   fd_executor_check_status_cache() respectively.

   load_and_execute_sanitized_transactions() contains validate_fees()
   which is responsible for executing the compute budget instructions,
   validating the fee payer and collecting the fee. This is mirrored in
   firedancer with fd_executor_compute_budget_program_execute_instructions()
   and fd_executor_collect_fees(). load_and_execute_sanitized_transactions()
   also checks the total data size of the accounts in load_accounts() and
   validates the program accounts in load_transaction_accounts(). This
   is paralled by fd_executor_load_transaction_accounts(). */


/******************************************************************************/
/* Genesis                                                                    */
/*******************************************************************************/

static void
fd_runtime_genesis_init_program( fd_bank_t *        bank,
                                 fd_accdb_t *       accdb,
                                 fd_capture_ctx_t * capture_ctx ) {

  fd_sysvar_clock_init( bank, accdb, capture_ctx );
  fd_sysvar_rent_init( bank, accdb, capture_ctx );

  fd_sysvar_slot_history_init( bank, accdb, capture_ctx );
  fd_sysvar_epoch_schedule_init( bank, accdb, capture_ctx );
  fd_sysvar_recent_hashes_init( bank, accdb, capture_ctx );
  fd_sysvar_stake_history_init( bank, accdb, capture_ctx );
  fd_sysvar_last_restart_slot_init( bank, accdb, capture_ctx );

  fd_builtin_programs_init( bank, accdb, capture_ctx );
}

static void
fd_runtime_init_bank_from_genesis( fd_banks_t *         banks,
                                   fd_bank_t *          bank,
                                   fd_runtime_stack_t * runtime_stack,
                                   fd_accdb_t *         accdb,
                                   fd_genesis_t const * genesis,
                                   uchar const *        genesis_blob,
                                   fd_hash_t const *    genesis_hash ) {

  bank->f.parent_slot = ULONG_MAX;
  bank->f.poh = *genesis_hash;

  fd_hash_t * bank_hash = &bank->f.bank_hash;
  memset( bank_hash->hash, 0, FD_SHA256_HASH_SZ );

  uint128 target_tick_duration = (uint128)genesis->poh.tick_duration_secs * 1000000000UL + (uint128)genesis->poh.tick_duration_ns;

  fd_epoch_schedule_t * epoch_schedule = &bank->f.epoch_schedule;
  epoch_schedule->leader_schedule_slot_offset = genesis->epoch_schedule.leader_schedule_slot_offset;
  epoch_schedule->warmup                      = genesis->epoch_schedule.warmup;
  epoch_schedule->first_normal_epoch          = genesis->epoch_schedule.first_normal_epoch;
  epoch_schedule->first_normal_slot           = genesis->epoch_schedule.first_normal_slot;
  epoch_schedule->slots_per_epoch             = genesis->epoch_schedule.slots_per_epoch;

  fd_rent_t * rent = &bank->f.rent;
  rent->lamports_per_uint8_year = genesis->rent.lamports_per_uint8_year;
  rent->exemption_threshold     = genesis->rent.exemption_threshold;
  rent->burn_percent            = genesis->rent.burn_percent;

  fd_inflation_t * inflation = &bank->f.inflation;
  inflation->initial         = genesis->inflation.initial;
  inflation->terminal        = genesis->inflation.terminal;
  inflation->taper           = genesis->inflation.taper;
  inflation->foundation      = genesis->inflation.foundation;
  inflation->foundation_term = genesis->inflation.foundation_term;
  inflation->unused          = 0.0;

  bank->f.block_height = 0UL;

  {
    /* FIXME Why is there a previous blockhash at genesis?  Why is the
             last_hash field an option type in Agave, if even the first
             real block has a previous blockhash? */
    fd_blockhashes_t *    bhq  = fd_blockhashes_init( &bank->f.block_hash_queue, 0UL );
    fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, genesis_hash );
    info->lamports_per_signature = 0UL;
  }

  fd_fee_rate_governor_t * fee_rate_governor = &bank->f.fee_rate_governor;
  fee_rate_governor->target_lamports_per_signature = genesis->fee_rate_governor.target_lamports_per_signature;
  fee_rate_governor->target_signatures_per_slot    = genesis->fee_rate_governor.target_signatures_per_slot;
  fee_rate_governor->min_lamports_per_signature    = genesis->fee_rate_governor.min_lamports_per_signature;
  fee_rate_governor->max_lamports_per_signature    = genesis->fee_rate_governor.max_lamports_per_signature;
  fee_rate_governor->burn_percent                  = genesis->fee_rate_governor.burn_percent;

  bank->f.max_tick_height = genesis->poh.ticks_per_slot * (bank->f.slot + 1);
  bank->f.hashes_per_tick = genesis->poh.hashes_per_tick;
  bank->f.ns_per_slot = (fd_w_u128_t) { .ud=target_tick_duration * genesis->poh.ticks_per_slot };
  bank->f.ticks_per_slot = genesis->poh.ticks_per_slot;
  bank->f.genesis_creation_time = genesis->creation_time;
  bank->f.slots_per_year = SECONDS_PER_YEAR * (1000000000.0 / (double)target_tick_duration) / (double)genesis->poh.ticks_per_slot;
  bank->f.signature_count = 0UL;

  /* Derive epoch stakes */

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "Failed to join and new a stake delegations" ));
  }

  ulong capitalization = 0UL;

  for( ulong i=0UL; i<genesis->account_cnt; i++ ) {
    fd_genesis_account_t account[1];
    fd_genesis_account( genesis, genesis_blob, account, i );

    capitalization = fd_ulong_sat_add( capitalization, account->lamports );

    uchar const * acc_data = account->data;

    if( !memcmp( account->owner.uc, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* If an account is a stake account, then it must be added to the
         stake delegations cache. We should only add stake accounts that
         have a valid non-zero stake. */
      fd_stake_state_t const * stake_state = fd_stake_state_view( acc_data, account->data_len );
      if( FD_UNLIKELY( !stake_state ) ) { FD_BASE58_ENCODE_32_BYTES( account->pubkey.uc, stake_b58 ); FD_LOG_ERR(( "invalid stake account %s", stake_b58 )); }
      if( stake_state->stake_type!=FD_STAKE_STATE_STAKE ) continue;
      if( !stake_state->stake.stake.delegation.stake ) continue;

      fd_stake_delegations_root_update(
          stake_delegations,
          &account->pubkey,
          &stake_state->stake.stake.delegation.voter_pubkey,
          stake_state->stake.stake.delegation.stake,
          stake_state->stake.stake.delegation.activation_epoch,
          stake_state->stake.stake.delegation.deactivation_epoch,
          stake_state->stake.stake.credits_observed,
          FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 /* genesis is epoch 0, always 0.25 */ );

    } else if( !memcmp( account->owner.uc, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) ) {
      /* Feature Account */

      /* Scan list of feature IDs to resolve address=>feature offset */
      fd_feature_id_t const *found = NULL;
      for( fd_feature_id_t const * id = fd_feature_iter_init();
           !fd_feature_iter_done( id );
           id = fd_feature_iter_next( id ) ) {
        if( fd_pubkey_eq( &account->pubkey, &id->id ) ) {
          found = id;
          break;
        }
      }

      if( found ) {
        /* Load feature activation */
        fd_feature_t feature[1];
        if( FD_UNLIKELY( !fd_feature_decode( feature, acc_data, account->data_len ) ) ) {
          FD_BASE58_ENCODE_32_BYTES( account->pubkey.uc, addr_b58 );
          FD_LOG_WARNING(( "genesis contains corrupt feature account %s", addr_b58 ));
          FD_LOG_HEXDUMP_ERR(( "data", acc_data, account->data_len ));
        }
        fd_features_t * features = &bank->f.features;
        if( feature->is_active ) {
          FD_BASE58_ENCODE_32_BYTES( account->pubkey.uc, pubkey_b58 );
          FD_LOG_DEBUG(( "feature %s activated at slot %lu (genesis)", pubkey_b58, feature->activation_slot ));
          fd_features_set( features, found, feature->activation_slot );
        } else {
          FD_BASE58_ENCODE_32_BYTES( account->pubkey.uc, pubkey_b58 );
          FD_LOG_DEBUG(( "feature %s not activated (genesis)", pubkey_b58 ));
          fd_features_set( features, found, ULONG_MAX );
        }
      }
    }
  }

  /* fd_refresh_vote_accounts is responsible for updating the vote
     states with the total amount of active delegated stake.  It does
     this by iterating over all active stake delegations and summing up
     the amount of stake that is delegated to each vote account. */
  ulong new_rate_activation_epoch = 0UL;

  fd_stake_history_t stake_history[1];
  FD_TEST( fd_sysvar_stake_history_read( accdb, bank->accdb_fork_id, stake_history ) );

  fd_refresh_vote_accounts( bank, accdb, runtime_stack, stake_delegations, stake_history, &new_rate_activation_epoch );
  fd_vote_stakes_genesis_fini( fd_bank_vote_stakes( bank ) );

  bank->f.epoch = 0UL;
  bank->f.capitalization = capitalization;
}

static int
fd_runtime_process_genesis_block( fd_bank_t *          bank,
                                  fd_accdb_t *         accdb,
                                  fd_capture_ctx_t *   capture_ctx,
                                  fd_runtime_stack_t * runtime_stack ) {
  fd_sha256_hash_32_repeated( bank->f.poh.hash, bank->f.poh.hash, bank->f.hashes_per_tick * bank->f.ticks_per_slot );

  bank->f.execution_fees = 0UL;
  bank->f.priority_fees = 0UL;
  bank->f.signature_count = 0UL;
  bank->f.txn_count = 0UL;
  bank->f.failed_txn_count = 0UL;
  bank->f.nonvote_failed_txn_count = 0UL;
  bank->f.total_compute_units_used = 0UL;

  fd_runtime_genesis_init_program( bank, accdb, capture_ctx );
  fd_sysvar_slot_history_update( bank, accdb, capture_ctx );
  fd_runtime_update_leaders( bank, runtime_stack );
  fd_runtime_freeze( bank, accdb, capture_ctx );

  fd_hash_t const * prev_bank_hash = &bank->f.bank_hash;

  fd_lthash_value_t const * lthash = fd_bank_lthash_locking_query( bank );

  fd_hash_t * bank_hash = &bank->f.bank_hash;
  fd_hashes_hash_bank( lthash, prev_bank_hash, (fd_hash_t *)bank->f.poh.hash, 0UL, bank_hash );

  fd_bank_lthash_end_locking_query( bank );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_read_genesis( fd_banks_t *              banks,
                         fd_bank_t *               bank,
                         fd_accdb_t *              accdb,
                         fd_capture_ctx_t *        capture_ctx,
                         fd_hash_t const *         genesis_hash,
                         fd_lthash_value_t const * genesis_lthash,
                         fd_genesis_t const *      genesis,
                         uchar const *             genesis_blob,
                         fd_runtime_stack_t *      runtime_stack ) {
  fd_lthash_value_t * lthash = fd_bank_lthash_locking_modify( bank );
  *lthash = *genesis_lthash;
  fd_bank_lthash_end_locking_modify( bank );

  /* Once the accounts have been loaded from the genesis config into
     the accounts db, we can initialize the bank state. This involves
     setting some fields, and notably setting up the vote and stake
     caches which are used for leader scheduling/rewards. */

  fd_runtime_init_bank_from_genesis( banks, bank, runtime_stack, accdb, genesis, genesis_blob, genesis_hash );

  /* Write the native programs to the accounts db. */

  for( ulong i=0UL; i<genesis->builtin_cnt; i++ ) {
    fd_genesis_builtin_t builtin[1];
    fd_genesis_builtin( genesis, genesis_blob, builtin, i );
    fd_write_builtin_account( bank, accdb, capture_ctx, builtin->pubkey, builtin->data, builtin->data_len );
  }

  fd_features_restore( bank, accdb );

  /* At this point, state related to the bank and the accounts db
     have been initialized and we are free to finish executing the
     block. In practice, this updates some bank fields (notably the
     poh and bank hash). */

  int err = fd_runtime_process_genesis_block( bank, accdb, capture_ctx, runtime_stack );
  if( FD_UNLIKELY( err ) ) FD_LOG_CRIT(( "genesis slot 0 execute failed with error %d", err ));
}

void
fd_runtime_block_execute_finalize( fd_bank_t *        bank,
                                   fd_accdb_t *       accdb,
                                   fd_capture_ctx_t * capture_ctx ) {
  fd_runtime_freeze( bank, accdb, capture_ctx );
  fd_runtime_update_bank_hash( bank, capture_ctx );
}

/* Mirrors Agave function solana_sdk::transaction_context::find_index_of_account

   Backward scan over transaction accounts. Returns ULONG_MAX if not found.

   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L233-L238 */

ulong
fd_runtime_find_index_of_account( fd_txn_out_t const * txn_out,
                                  fd_pubkey_t const *  pubkey ) {
  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( pubkey, &txn_out->accounts.keys[ txn_out->accounts.cnt-1UL-i ], sizeof(fd_pubkey_t) ) ) ) return txn_out->accounts.cnt-1UL-i;
  }
  return ULONG_MAX;
}

fd_accdb_entry_t *
fd_runtime_get_account_at_index( fd_txn_in_t const *             txn_in,
                                 fd_txn_out_t *                  txn_out,
                                 ushort                          idx,
                                 fd_txn_account_condition_fn_t * condition ) {
  if( FD_UNLIKELY( idx>=txn_out->accounts.cnt ) ) return NULL;
  if( FD_LIKELY( condition && !condition( txn_in, txn_out, idx ) ) ) return NULL;
  return &txn_out->accounts.account[ idx ];
}

fd_accdb_entry_t *
fd_runtime_get_executable_account( fd_runtime_t *      runtime,
                                   fd_txn_out_t *      txn_out,
                                   fd_pubkey_t const * pubkey ) {
  /* First try to fetch the executable account from the existing
     borrowed accounts.  If the pubkey is in the account keys, then we
     want to re-use that borrowed account since it reflects changes from
     prior instructions.  Referencing the read-only executable accounts
     list is incorrect behavior when the program data account is written
     to in a prior instruction (e.g. program upgrade + invoke within the
     same txn) */

  ulong account_idx = fd_runtime_find_index_of_account( txn_out, pubkey );
  if( FD_LIKELY( account_idx!=ULONG_MAX && txn_out->accounts.account[ account_idx ].lamports ) ) return &txn_out->accounts.account[ account_idx ];

  for( ushort i=0; i<runtime->accounts.executable_cnt; i++ ) {
    fd_accdb_entry_t * ro = &runtime->accounts.executable[ i ];
    if( FD_UNLIKELY( !memcmp( pubkey->uc, ro->pubkey, 32UL ) ) ) {
      if( FD_UNLIKELY( !ro->lamports ) ) return NULL;
      return ro;
    }
  }

  return NULL;
}

int
fd_runtime_get_key_of_account_at_index( fd_txn_out_t *        txn_out,
                                        ushort                idx,
                                        fd_pubkey_t const * * key ) {
  /* Return a MissingAccount error if idx is out of bounds.
     https://github.com/anza-xyz/agave/blob/v3.1.4/transaction-context/src/lib.rs#L187 */
  if( FD_UNLIKELY( idx>=txn_out->accounts.cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  *key = &txn_out->accounts.keys[ idx ];
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.1/sdk/program/src/message/versions/v0/loaded.rs#L162 */
int
fd_txn_account_is_demotion( const int        idx,
                            const fd_txn_t * txn_descriptor,
                            const uint       bpf_upgradeable_in_txn ) {
  uint is_program = 0U;
  for( ulong j=0UL; j<txn_descriptor->instr_cnt; j++ ) {
    if( txn_descriptor->instr[j].program_id == idx ) {
      is_program = 1U;
      break;
    }
  }

  return (is_program && !bpf_upgradeable_in_txn);
}

uint
fd_txn_account_has_bpf_loader_upgradeable( const fd_pubkey_t * account_keys,
                                           const ulong         accounts_cnt ) {
  for( ulong j=0; j<accounts_cnt; j++ ) {
    const fd_pubkey_t * acc = &account_keys[j];
    if ( memcmp( acc->uc, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) {
      return 1U;
    }
  }
  return 0U;
}

static inline int
fd_runtime_account_is_writable_idx_flat( const ushort        idx,
                                         const fd_pubkey_t * addr_at_idx,
                                         const fd_txn_t *    txn_descriptor,
                                         const uint          bpf_upgradeable_in_txn ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L43 */
  if( !fd_txn_is_writable( txn_descriptor, idx ) ) {
    return 0;
  }

  /* See comments in fd_system_ids.h.
     https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L44 */
  if( fd_pubkey_is_active_reserved_key( addr_at_idx ) ||
      fd_pubkey_is_pending_reserved_key( addr_at_idx ) ) {

    return 0;
  }

  if( fd_txn_account_is_demotion( idx, txn_descriptor, bpf_upgradeable_in_txn ) ) {
    return 0;
  }

  return 1;
}


/* This function aims to mimic the writable accounts check to populate the writable accounts cache, used
   to determine if accounts are writable or not.

   https://github.com/anza-xyz/agave/blob/v2.1.11/sdk/program/src/message/sanitized.rs#L38-L47 */
int
fd_runtime_account_is_writable_idx( fd_txn_in_t const *  txn_in,
                                    fd_txn_out_t const * txn_out,
                                    ushort               idx ) {
  uint bpf_upgradeable = fd_txn_account_has_bpf_loader_upgradeable( txn_out->accounts.keys, txn_out->accounts.cnt );
  return fd_runtime_account_is_writable_idx_flat( idx,
                                                   &txn_out->accounts.keys[idx],
                                                   TXN( txn_in->txn ),
                                                   bpf_upgradeable );
}

/* Account pre-condition filtering functions */

int
fd_runtime_account_check_exists( fd_txn_in_t const * txn_in,
                                 fd_txn_out_t *      txn_out,
                                 ushort              idx ) {
  (void) txn_in;
  return txn_out->accounts.account[ idx ].lamports!=0UL;
}

int
fd_runtime_account_check_fee_payer_writable( fd_txn_in_t const * txn_in,
                                             fd_txn_out_t *      txn_out,
                                             ushort              idx ) {
  (void) txn_out;
  return fd_txn_is_writable( TXN( txn_in->txn ), idx );
}


int
fd_account_meta_checked_sub_lamports( fd_accdb_entry_t * entry,
                                      ulong              lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_sub( entry->lamports, lamports, &balance_post );
  if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;

  entry->lamports = balance_post;
  return FD_EXECUTOR_INSTR_SUCCESS;
}
