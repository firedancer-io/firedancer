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
fd_ssload_recover( fd_snapshot_manifest_t * manifest,
                   fd_bank_t *              bank,
                   int                      is_incremental ) {
  (void)is_incremental;

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
  if( FD_LIKELY( manifest->has_hashes_per_tick ) ) bank->f.hashes_per_tick = manifest->hashes_per_tick;
  else                                             bank->f.hashes_per_tick = 0UL;

  fd_lthash_value_t * lthash = fd_bank_lthash_locking_modify( bank );
  if( FD_LIKELY( manifest->has_accounts_lthash ) ) {
    fd_memcpy( lthash, manifest->accounts_lthash, sizeof(fd_lthash_value_t) );
  } else {
    fd_memset( lthash, 0, sizeof(fd_lthash_value_t) );
  }
  fd_bank_lthash_end_locking_modify( bank );

  fd_blockhashes_t * blockhashes = &bank->f.block_hash_queue;
  blockhashes_recover( blockhashes, manifest->blockhashes, manifest->blockhashes_len, 42UL /* TODO */ );

  /* PoH */
  fd_blockhashes_t const * bhq = &bank->f.block_hash_queue;
  fd_hash_t const * last_hash = fd_blockhashes_peek_last_hash( bhq );
  if( FD_LIKELY( last_hash ) ) bank->f.poh = *last_hash;

  bank->f.capitalization = manifest->capitalization;
  bank->f.txn_count = manifest->transaction_count;
  bank->f.parent_signature_cnt = manifest->signature_count;
  bank->f.tick_height = manifest->tick_height;
  bank->f.max_tick_height = manifest->max_tick_height;
  bank->f.ns_per_slot = (fd_w_u128_t) { .ul={ manifest->ns_per_slot, 0UL } };
  bank->f.ticks_per_slot = manifest->ticks_per_slot;
  bank->f.genesis_creation_time = manifest->creation_time_seconds;
  bank->f.slots_per_year = manifest->slots_per_year;
  bank->f.block_height = manifest->block_height;
  bank->f.execution_fees = manifest->collector_fees;
  bank->f.priority_fees = 0UL;

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
  bank->f.last_restart_slot = 0UL;
  if( FD_LIKELY( manifest->hard_forks_len ) ) {
    for( ulong i=0UL; i<manifest->hard_forks_len; i++ ) {
      ulong slot = manifest->hard_forks[ manifest->hard_forks_len-1UL-i ];
      if( FD_LIKELY( slot<=manifest->slot ) ) {
        bank->f.last_restart_slot = slot;
        break;
      }
    }
  }

  /* Stake delegations and epoch stakes (vote_stakes, top_votes,
     epoch_credits, commissions) are processed on-the-fly by the
     snapin tile during manifest parsing.  See the polling interfaces
     in fd_ssmanifest_parser.h.  total_epoch_stake is set by the
     snapin tile after all epoch stakes entries have been drained. */

  bank->txncache_fork_id = (fd_txncache_fork_id_t){ .val = manifest->txncache_fork_id };
}
