#include "fd_ssload.h"

#include "../../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../../flamenco/runtime/program/fd_vote_program.h"
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
fd_ssload_recover( fd_snapshot_manifest_t * manifest,
                   fd_exec_slot_ctx_t *     slot_ctx ) {
  slot_ctx->bank = fd_banks_rekey_root_bank( slot_ctx->banks, manifest->slot );
  FD_TEST( slot_ctx->bank );

  /* Bank Hash */

  fd_hash_t hash;
  fd_memcpy( &hash.uc, manifest->bank_hash, 32UL );
  fd_bank_bank_hash_set( slot_ctx->bank, hash );

  fd_hash_t parent_hash;
  fd_memcpy( &parent_hash.uc, manifest->parent_bank_hash, 32UL );
  fd_bank_prev_bank_hash_set( slot_ctx->bank, parent_hash );

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( slot_ctx->bank );
  fee_rate_governor->target_lamports_per_signature = manifest->fee_rate_governor.target_lamports_per_signature;
  fee_rate_governor->target_signatures_per_slot    = manifest->fee_rate_governor.target_signatures_per_slot;
  fee_rate_governor->min_lamports_per_signature    = manifest->fee_rate_governor.min_lamports_per_signature;
  fee_rate_governor->max_lamports_per_signature    = manifest->fee_rate_governor.max_lamports_per_signature;
  fee_rate_governor->burn_percent                  = manifest->fee_rate_governor.burn_percent;

  fd_inflation_t * inflation = fd_bank_inflation_modify( slot_ctx->bank );
  inflation->initial         = manifest->inflation_params.initial;
  inflation->terminal        = manifest->inflation_params.terminal;
  inflation->taper           = manifest->inflation_params.taper;
  inflation->foundation      = manifest->inflation_params.foundation;
  inflation->foundation_term = manifest->inflation_params.foundation_term;
  inflation->unused          = 0.0;

  fd_epoch_schedule_t * epoch_schedule = fd_bank_epoch_schedule_modify( slot_ctx->bank );
  epoch_schedule->slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch;
  epoch_schedule->leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset;
  epoch_schedule->warmup                      = manifest->epoch_schedule_params.warmup;
  epoch_schedule->first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch;
  epoch_schedule->first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot;

  fd_rent_t * rent = fd_bank_rent_modify( slot_ctx->bank );
  rent->lamports_per_uint8_year = manifest->rent_params.lamports_per_uint8_year;
  rent->exemption_threshold     = manifest->rent_params.exemption_threshold;
  rent->burn_percent            = manifest->rent_params.burn_percent;

  if( FD_LIKELY( manifest->has_hashes_per_tick ) ) fd_bank_hashes_per_tick_set( slot_ctx->bank, manifest->hashes_per_tick );
  else                                             fd_bank_hashes_per_tick_set( slot_ctx->bank, 0UL );

  if( FD_LIKELY( manifest->has_epoch_account_hash ) ) {
    fd_hash_t epoch_account_hash;
    fd_memcpy( &epoch_account_hash.uc, manifest->epoch_account_hash, 32UL );
    fd_bank_epoch_account_hash_set( slot_ctx->bank, epoch_account_hash );
  } else {
    fd_hash_t epoch_account_hash = {0};
    fd_bank_epoch_account_hash_set( slot_ctx->bank, epoch_account_hash );
  }

  if( FD_LIKELY( manifest->has_accounts_lthash ) ) {
    fd_slot_lthash_t lthash;
    fd_memcpy( lthash.lthash, manifest->accounts_lthash, 2048UL );
    fd_bank_lthash_set( slot_ctx->bank, lthash );
  } else {
    fd_slot_lthash_t lthash = {0};
    fd_bank_lthash_set( slot_ctx->bank, lthash );
  }

  fd_blockhashes_t * blockhashes = fd_bank_block_hash_queue_modify( slot_ctx->bank );
  blockhashes_recover( blockhashes, manifest->blockhashes, manifest->blockhashes_len, 42UL /* TODO */ );

  /* PoH */
  fd_blockhashes_t const * bhq = fd_bank_block_hash_queue_query( slot_ctx->bank );
  fd_hash_t const * last_hash = fd_blockhashes_peek_last( bhq );
  if( FD_LIKELY( last_hash ) ) fd_bank_poh_set( slot_ctx->bank, *last_hash );

  fd_bank_capitalization_set( slot_ctx->bank, manifest->capitalization );
  fd_bank_lamports_per_signature_set( slot_ctx->bank, manifest->lamports_per_signature );
  fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, manifest->lamports_per_signature );
  fd_bank_transaction_count_set( slot_ctx->bank, manifest->transaction_count );
  fd_bank_parent_signature_cnt_set( slot_ctx->bank, manifest->signature_count );
  fd_bank_tick_height_set( slot_ctx->bank, manifest->tick_height );
  fd_bank_max_tick_height_set( slot_ctx->bank, manifest->max_tick_height );
  fd_bank_ns_per_slot_set( slot_ctx->bank, manifest->ns_per_slot );
  fd_bank_ticks_per_slot_set( slot_ctx->bank, manifest->ticks_per_slot );
  fd_bank_genesis_creation_time_set( slot_ctx->bank, manifest->creation_time_millis );
  fd_bank_slots_per_year_set( slot_ctx->bank, manifest->slots_per_year );
  fd_bank_block_height_set( slot_ctx->bank, manifest->block_height );
  fd_bank_parent_slot_set( slot_ctx->bank, manifest->parent_slot );
  fd_bank_execution_fees_set( slot_ctx->bank, manifest->collector_fees );
  fd_bank_priority_fees_set( slot_ctx->bank, 0UL );

  /* FIXME: Remove the magic number here. */
  fd_clock_timestamp_votes_global_t * clock_timestamp_votes = fd_bank_clock_timestamp_votes_locking_modify( slot_ctx->bank );
  uchar * clock_pool_mem = (uchar *)fd_ulong_align_up( (ulong)clock_timestamp_votes + sizeof(fd_clock_timestamp_votes_global_t), fd_clock_timestamp_vote_t_map_align() );
  fd_clock_timestamp_vote_t_mapnode_t * clock_pool = fd_clock_timestamp_vote_t_map_join( fd_clock_timestamp_vote_t_map_new(clock_pool_mem, 30000UL ) );
  clock_timestamp_votes->votes_pool_offset = (ulong)fd_clock_timestamp_vote_t_map_leave( clock_pool) - (ulong)clock_timestamp_votes;
  clock_timestamp_votes->votes_root_offset = 0UL;
  fd_bank_clock_timestamp_votes_end_locking_modify( slot_ctx->bank );

  for( ulong i=0UL; i<manifest->vote_accounts_len; i++ ) {
    fd_snapshot_manifest_vote_account_t * account = &manifest->vote_accounts[ i ];
    fd_pubkey_t vote_account_pubkey;
    fd_memcpy( vote_account_pubkey.uc, account->vote_account_pubkey, 32UL );
    if( FD_LIKELY( account->last_slot || account->stake ) ) {
      fd_vote_record_timestamp_vote_with_slot( &vote_account_pubkey, account->last_timestamp, account->last_slot, slot_ctx->bank );
    }
  }

  /* Update last restart slot
     https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/runtime/src/bank.rs#L2152

     old_bank->hard_forks is sorted ascending by slot number.
     To find the last restart slot, take the highest hard fork slot
     number that is less or equal than the current slot number.
     (There might be some hard forks in the future, ignore these)

     SIMD-0047: The first restart slot should be `0` */
  fd_sol_sysvar_last_restart_slot_t * last_restart_slot = fd_bank_last_restart_slot_modify( slot_ctx->bank );
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
}
