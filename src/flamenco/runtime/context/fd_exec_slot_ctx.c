#include "fd_exec_slot_ctx.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../program/fd_vote_program.h"
#include "../../../ballet/lthash/fd_lthash.h"

#include <assert.h>
#include <time.h>

void *
fd_exec_slot_ctx_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_SLOT_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_memset( mem, 0, sizeof(fd_exec_slot_ctx_t) );

  fd_exec_slot_ctx_t * self = (fd_exec_slot_ctx_t *)mem;

  FD_COMPILER_MFENCE();
  self->magic = FD_EXEC_SLOT_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_exec_slot_ctx_t * ctx = (fd_exec_slot_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_SLOT_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_exec_slot_ctx_leave( fd_exec_slot_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_SLOT_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_exec_slot_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_SLOT_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_slot_ctx_t * hdr = (fd_exec_slot_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_EXEC_SLOT_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

/* recover_clock recovers PoH/wallclock synchronization.  Walks all vote
   accounts in current epoch stakes. */

static int
recover_clock( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {

  fd_stakes_global_t const * stakes = fd_bank_stakes_locking_query( slot_ctx->bank );
  if( FD_UNLIKELY( stakes==NULL ) ) {
    FD_LOG_WARNING(( "stakes is NULL" ));
    fd_bank_stakes_end_locking_query( slot_ctx->bank );
    return 0;
  }

  fd_vote_accounts_global_t const *          vote_accounts      = &stakes->vote_accounts;
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( vote_accounts );

  if( FD_UNLIKELY( !vote_accounts_pool ) ) {
    FD_LOG_CRIT(( "vote_accounts_pool is NULL" ));
  }
  if( FD_UNLIKELY( !vote_accounts_root ) ) {
    FD_LOG_CRIT(( "vote_accounts_root is NULL" ));
  }

  for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum(vote_accounts_pool, vote_accounts_root);
       n;
       n = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_pool, n ) ) {

    FD_SPAD_FRAME_BEGIN( runtime_spad ) {

    /* Extract vote timestamp of account */
    int err;

    uchar * data     = fd_solana_account_data_join( &n->elem.value );
    ulong   data_len = n->elem.value.data_len;

    fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
        vote_state_versioned, runtime_spad,
        data,
        data_len,
        &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "vote state decode failed" ));
      fd_bank_stakes_end_locking_query( slot_ctx->bank );
      return 0;
    }

    long timestamp = 0;
    ulong slot = 0;
    switch( vsv->discriminant ) {
      case fd_vote_state_versioned_enum_v0_23_5:
        timestamp = vsv->inner.v0_23_5.last_timestamp.timestamp;
        slot = vsv->inner.v0_23_5.last_timestamp.slot;
        break;
      case fd_vote_state_versioned_enum_v1_14_11:
        timestamp = vsv->inner.v1_14_11.last_timestamp.timestamp;
        slot = vsv->inner.v1_14_11.last_timestamp.slot;
        break;
      case fd_vote_state_versioned_enum_current:
        timestamp = vsv->inner.current.last_timestamp.timestamp;
        slot = vsv->inner.current.last_timestamp.slot;
        break;
      default:
        __builtin_unreachable();
    }

    /* Record timestamp */
    if( slot != 0 || n->elem.stake != 0 ) {
      fd_vote_record_timestamp_vote_with_slot( &n->elem.key, timestamp, slot, slot_ctx->bank );
    }
  } FD_SPAD_FRAME_END;
  }

  fd_bank_stakes_end_locking_query( slot_ctx->bank );
  return 1;
}

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover( fd_exec_slot_ctx_t *                slot_ctx,
                          fd_solana_manifest_global_t const * manifest,
                          fd_spad_t *                         runtime_spad ) {

  slot_ctx->bank = fd_banks_rekey_root_bank( slot_ctx->banks, manifest->bank.slot );
  if( FD_UNLIKELY( !slot_ctx->bank ) ) {
    FD_LOG_CRIT(( "fd_banks_clone_from_parent failed" ));
  }
  FD_LOG_WARNING(( "recovering bank %lu", manifest->bank.slot ));

  fd_versioned_bank_global_t const * old_bank = &manifest->bank;

  ulong stakes_sz = fd_stakes_size_global( &manifest->bank.stakes );
  fd_stakes_global_t * stakes = fd_bank_stakes_locking_modify( slot_ctx->bank );
  fd_memcpy( stakes, &manifest->bank.stakes, stakes_sz );
  /* Verify stakes */

  fd_bank_stakes_end_locking_modify( slot_ctx->bank );

  /* Index vote accounts */

  /* Block Hash Queue */
  {
    fd_blockhashes_t * bhq = fd_bank_block_hash_queue_modify( slot_ctx->bank );
    ulong seed; FD_TEST( fd_rng_secure( &seed, sizeof(ulong) ) );
    FD_TEST( fd_blockhashes_recover(
        bhq,
        fd_block_hash_vec_ages_join( &old_bank->blockhash_queue ),
        old_bank->blockhash_queue.ages_len,
        seed ) );
  }

  /* Bank Hash */

  fd_bank_bank_hash_set( slot_ctx->bank, old_bank->hash );

  /* Fee Rate Governor */

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( slot_ctx->bank );
  *fee_rate_governor = old_bank->fee_rate_governor;

  /* Capitalization */

  fd_bank_capitalization_set( slot_ctx->bank, old_bank->capitalization );

  /* Lamports Per Signature */

  fd_bank_lamports_per_signature_set( slot_ctx->bank, manifest->lamports_per_signature );

  /* Previous Lamports Per Signature */

  fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, manifest->lamports_per_signature );

  /* Transaction Count */

  fd_bank_transaction_count_set( slot_ctx->bank, old_bank->transaction_count );

  /* Parent Signature Count */

  fd_bank_parent_signature_cnt_set( slot_ctx->bank, old_bank->signature_count );

  /* Tick Height */

  fd_bank_tick_height_set( slot_ctx->bank, old_bank->tick_height );

  /* Max Tick Height */

  fd_bank_max_tick_height_set( slot_ctx->bank, old_bank->max_tick_height );

  /* Hashes Per Tick */

  ulong * hashes_per_tick = fd_versioned_bank_hashes_per_tick_join( old_bank );
  fd_bank_hashes_per_tick_set( slot_ctx->bank, !!hashes_per_tick ? *hashes_per_tick : 0UL );

  /* NS Per Slot */

  fd_bank_ns_per_slot_set( slot_ctx->bank, old_bank->ns_per_slot );

  /* Ticks Per Slot */

  fd_bank_ticks_per_slot_set( slot_ctx->bank, old_bank->ticks_per_slot );

  /* Genesis Creation Time */

  fd_bank_genesis_creation_time_set( slot_ctx->bank, old_bank->genesis_creation_time );

  /* Slots Per Year */

  fd_bank_slots_per_year_set( slot_ctx->bank, old_bank->slots_per_year );

  /* Inflation */

  fd_bank_inflation_set( slot_ctx->bank, old_bank->inflation );

  /* Block Height */

  fd_bank_block_height_set( slot_ctx->bank, old_bank->block_height );

  /* Epoch Account Hash */

  fd_hash_t * epoch_account_hash = fd_solana_manifest_epoch_account_hash_join( manifest );
  if( !!epoch_account_hash ) {
    fd_bank_epoch_account_hash_set( slot_ctx->bank, *epoch_account_hash );
  } else {
    fd_bank_epoch_account_hash_set( slot_ctx->bank, (fd_hash_t){0} );
  }

  /* Prev Slot */

  fd_bank_parent_slot_set( slot_ctx->bank, old_bank->parent_slot );

  /* Execution Fees */

  fd_bank_execution_fees_set( slot_ctx->bank, old_bank->collector_fees );

  /* Priority Fees */

  fd_bank_priority_fees_set( slot_ctx->bank, 0UL );

  /* PoH */

  {
    fd_blockhashes_t const * bhq = fd_bank_block_hash_queue_query( slot_ctx->bank );
    fd_hash_t const * last_hash = fd_blockhashes_peek_last( bhq );
    if( last_hash ) fd_bank_poh_set( slot_ctx->bank, *last_hash );
  }

  /* Prev Bank Hash */

  fd_bank_prev_bank_hash_set( slot_ctx->bank, old_bank->parent_hash );

  /* Epoch Schedule */

  fd_bank_epoch_schedule_set( slot_ctx->bank, old_bank->epoch_schedule );

  /* Rent */

  fd_bank_rent_set( slot_ctx->bank, old_bank->rent_collector.rent );

  /* Last Restart Slot */

  /* Update last restart slot
     https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/runtime/src/bank.rs#L2152

     old_bank->hard_forks is sorted ascending by slot number.
     To find the last restart slot, take the highest hard fork slot
     number that is less or equal than the current slot number.
     (There might be some hard forks in the future, ignore these) */
  do {
    fd_sol_sysvar_last_restart_slot_t * last_restart_slot = fd_bank_last_restart_slot_modify( slot_ctx->bank );
    last_restart_slot->slot = 0UL;

    if( FD_UNLIKELY( old_bank->hard_forks.hard_forks_len == 0 ) ) {
      /* SIMD-0047: The first restart slot should be `0` */
      break;
    }

    fd_slot_pair_t const * head = fd_hard_forks_hard_forks_join( &old_bank->hard_forks );
    fd_slot_pair_t const * tail = head + old_bank->hard_forks.hard_forks_len - 1UL;

    for( fd_slot_pair_t const *pair = tail; pair >= head; pair-- ) {
      if( pair->slot <= fd_bank_slot_get( slot_ctx->bank ) ) {
        fd_sol_sysvar_last_restart_slot_t * last_restart_slot = fd_bank_last_restart_slot_modify( slot_ctx->bank );
        last_restart_slot->slot = pair->slot;
        break;
      }
    }
  } while (0);

  /* FIXME: Remove the magic number here. */
  fd_clock_timestamp_votes_global_t * clock_timestamp_votes = fd_bank_clock_timestamp_votes_locking_modify( slot_ctx->bank );
  uchar * clock_pool_mem = (uchar *)fd_ulong_align_up( (ulong)clock_timestamp_votes + sizeof(fd_clock_timestamp_votes_global_t), fd_clock_timestamp_vote_t_map_align() );
  fd_clock_timestamp_vote_t_mapnode_t * clock_pool = fd_clock_timestamp_vote_t_map_join( fd_clock_timestamp_vote_t_map_new(clock_pool_mem, 30000UL ) );
  clock_timestamp_votes->votes_pool_offset = (ulong)fd_clock_timestamp_vote_t_map_leave( clock_pool) - (ulong)clock_timestamp_votes;
  clock_timestamp_votes->votes_root_offset = 0UL;
  fd_bank_clock_timestamp_votes_end_locking_modify( slot_ctx->bank );

  recover_clock( slot_ctx, runtime_spad );


  /* Move EpochStakes */
  do {
    ulong epoch = fd_bank_epoch_get( slot_ctx->bank );

    /* We need to save the vote accounts for the current epoch and the next
       epoch as it is used to calculate the leader schedule at the epoch
       boundary. */

    fd_vote_accounts_global_t * vote_accounts_curr_stakes = NULL;
    fd_vote_accounts_global_t * vote_accounts_next_stakes = NULL;

    fd_epoch_epoch_stakes_pair_global_t * versioned_bank_epoch_stakes = fd_versioned_bank_epoch_stakes_join( &manifest->bank );
    for( ulong i=0UL; i<manifest->bank.epoch_stakes_len; i++ ) {
      if( versioned_bank_epoch_stakes[i].key == epoch ) {
        vote_accounts_curr_stakes = &versioned_bank_epoch_stakes[i].value.stakes.vote_accounts;
      }
      if( versioned_bank_epoch_stakes[i].key == epoch+1UL ) {
        vote_accounts_next_stakes = &versioned_bank_epoch_stakes[i].value.stakes.vote_accounts;
      }

      /* When loading from a snapshot, Agave's stake caches mean that we have to special-case the epoch stakes
         that are used for the second epoch E+2 after the snapshot epoch E.

         If the snapshot contains the epoch stakes for E+2, we should use those.

         If the snapshot does not, we should use the stakes at the end of the E-1 epoch, instead of E-2 as we do for
         all other epochs. */
    }

    fd_versioned_epoch_stakes_pair_global_t * versioned_epoch_stakes = fd_solana_manifest_versioned_epoch_stakes_join( manifest );
    for( ulong i=0UL; i<manifest->versioned_epoch_stakes_len; i++ ) {

      if( versioned_epoch_stakes[i].epoch == epoch ) {
        vote_accounts_curr_stakes = &versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts;
      }
      if( versioned_epoch_stakes[i].epoch == epoch+1UL ) {
        vote_accounts_next_stakes = &versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts;

        /* Save the initial value to be used for the get_epoch_stake
           syscall.

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
           epoch stake by querying for epoch+1. */
        fd_bank_total_epoch_stake_set( slot_ctx->bank, versioned_epoch_stakes[i].val.inner.Current.total_stake );
      }
    }

    fd_bank_use_prev_epoch_stake_set( slot_ctx->bank, epoch + 2UL );

    fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_curr_stakes_pool = fd_vote_accounts_vote_accounts_pool_join( vote_accounts_curr_stakes );
    fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_curr_stakes_root = fd_vote_accounts_vote_accounts_root_join( vote_accounts_curr_stakes );

    fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_next_stakes_pool = fd_vote_accounts_vote_accounts_pool_join( vote_accounts_next_stakes );
    fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_next_stakes_root = fd_vote_accounts_vote_accounts_root_join( vote_accounts_next_stakes );

    if( FD_UNLIKELY( (!vote_accounts_curr_stakes_pool) | (!vote_accounts_next_stakes_pool) ) ) {
      FD_LOG_WARNING(( "snapshot missing EpochStakes for epochs %lu and/or %lu", epoch, epoch+1UL ));
      return 0;
    }

    /* Move current EpochStakes */

    fd_vote_accounts_global_t * epoch_stakes = fd_bank_epoch_stakes_locking_modify( slot_ctx->bank );
    uchar * epoch_stakes_pool_mem = (uchar *)fd_ulong_align_up( (ulong)epoch_stakes + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_global_t_map_align() );
    fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( epoch_stakes_pool_mem, 50000UL ) );
    fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_root = NULL;

    uchar * acc_region_curr = (uchar *)fd_ulong_align_up( (ulong)epoch_stakes_pool + fd_vote_accounts_pair_global_t_map_footprint( 50000UL ), 8UL );

    for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum(
          vote_accounts_curr_stakes_pool,
          vote_accounts_curr_stakes_root );
          n;
          n = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_curr_stakes_pool, n ) ) {

      fd_vote_accounts_pair_global_t_mapnode_t * elem = fd_vote_accounts_pair_global_t_map_acquire(
        epoch_stakes_pool );
      FD_TEST( elem );

      elem->elem.stake = n->elem.stake;
      elem->elem.key   = n->elem.key;

      elem->elem.value.lamports    = n->elem.value.lamports;
      elem->elem.value.data_len    = 0UL;
      elem->elem.value.data_offset = 0UL;
      elem->elem.value.owner       = n->elem.value.owner;
      elem->elem.value.executable  = n->elem.value.executable;
      elem->elem.value.rent_epoch  = n->elem.value.rent_epoch;

      elem->elem.value.data_offset = (ulong)(acc_region_curr - (uchar *)&elem->elem.value);
      elem->elem.value.data_len = n->elem.value.data_len;

      uchar * manifest_data = fd_solana_account_data_join( &n->elem.value );
      memcpy( acc_region_curr, manifest_data, n->elem.value.data_len );
      acc_region_curr += n->elem.value.data_len;

      fd_vote_accounts_pair_global_t_map_insert(
        epoch_stakes_pool,
        &epoch_stakes_root,
        elem );
    }

    fd_vote_accounts_vote_accounts_pool_update( epoch_stakes, epoch_stakes_pool );
    fd_vote_accounts_vote_accounts_root_update( epoch_stakes, epoch_stakes_root );
    fd_bank_epoch_stakes_end_locking_modify( slot_ctx->bank );

    /* Move next EpochStakes */

    fd_vote_accounts_global_t * next_epoch_stakes = fd_bank_next_epoch_stakes_locking_modify( slot_ctx->bank );
    uchar * next_epoch_stakes_pool_mem = (uchar *)fd_ulong_align_up( (ulong)next_epoch_stakes + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_global_t_map_align() );
    fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( next_epoch_stakes_pool_mem, 50000UL ) );
    fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_root = NULL;

    fd_vote_accounts_pair_global_t_mapnode_t * pool = vote_accounts_next_stakes_pool;
    fd_vote_accounts_pair_global_t_mapnode_t * root = vote_accounts_next_stakes_root;

    acc_region_curr = (uchar *)fd_ulong_align_up( (ulong)next_epoch_stakes_pool + fd_vote_accounts_pair_global_t_map_footprint( 50000UL ), 8UL );

    for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum( pool, root );
         n;
         n = fd_vote_accounts_pair_global_t_map_successor( pool, n ) ) {

      fd_vote_accounts_pair_global_t_mapnode_t * elem = fd_vote_accounts_pair_global_t_map_acquire( next_epoch_stakes_pool );
      FD_TEST( elem );

      elem->elem.stake = n->elem.stake;
      elem->elem.key   = n->elem.key;

      elem->elem.value.lamports    = n->elem.value.lamports;
      elem->elem.value.data_len    = 0UL;
      elem->elem.value.data_offset = 0UL;
      elem->elem.value.owner       = n->elem.value.owner;
      elem->elem.value.executable  = n->elem.value.executable;
      elem->elem.value.rent_epoch  = n->elem.value.rent_epoch;

      elem->elem.value.data_offset = (ulong)(acc_region_curr - (uchar *)&elem->elem.value);;
      elem->elem.value.data_len = n->elem.value.data_len;

      uchar * manifest_data = fd_solana_account_data_join( &n->elem.value );
      memcpy( acc_region_curr, manifest_data, n->elem.value.data_len );
      acc_region_curr += n->elem.value.data_len;

      fd_vote_accounts_pair_global_t_map_insert(
        next_epoch_stakes_pool,
        &next_epoch_stakes_root,
        elem );

    }
    fd_vote_accounts_vote_accounts_pool_update( next_epoch_stakes, next_epoch_stakes_pool );
    fd_vote_accounts_vote_accounts_root_update( next_epoch_stakes, next_epoch_stakes_root );
    fd_bank_next_epoch_stakes_end_locking_modify( slot_ctx->bank );

  } while(0);

  fd_slot_lthash_t * lthash = fd_bank_lthash_modify( slot_ctx->bank );

  fd_slot_lthash_t * lthash_value = fd_solana_manifest_lthash_join( manifest );
  if( !!lthash_value ) {
    *lthash = *lthash_value;
  } else {
    fd_lthash_zero( (fd_lthash_value_t *)lthash->lthash );
  }
  /* Setup next epoch stakes */

  return slot_ctx;
}

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover_status_cache( fd_exec_slot_ctx_t *    ctx,
                                       fd_bank_slot_deltas_t * slot_deltas,
                                       fd_spad_t *             runtime_spad ) {

  fd_txncache_t * status_cache = ctx->status_cache;
  if( !status_cache ) {
    FD_LOG_WARNING(("No status cache in slot ctx"));
    return NULL;
  }

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  ulong num_entries = 0;
  for( ulong i = 0; i < slot_deltas->slot_deltas_len; i++ ) {
    fd_slot_delta_t * slot_delta = &slot_deltas->slot_deltas[i];
    for( ulong j = 0; j < slot_delta->slot_delta_vec_len; j++ ) {
      num_entries += slot_delta->slot_delta_vec[j].value.statuses_len;
    }
  }
  fd_txncache_insert_t * insert_vals = fd_spad_alloc_check( runtime_spad, alignof(fd_txncache_insert_t), num_entries * sizeof(fd_txncache_insert_t) );

  /* Dumb sort for 300 slot entries to insert in order. */
  fd_slot_delta_t ** deltas = fd_spad_alloc_check( runtime_spad, alignof(fd_slot_delta_t*), slot_deltas->slot_deltas_len * sizeof(fd_slot_delta_t*) );

  long curr = -1;
  for( ulong i = 0UL; i < slot_deltas->slot_deltas_len; i++ ) {
    ulong curr_min     = ULONG_MAX;
    ulong curr_min_idx = ULONG_MAX;
    for( ulong j = 0; j < slot_deltas->slot_deltas_len; j++ ) {
      fd_slot_delta_t * slot_delta = &slot_deltas->slot_deltas[j];
      if( (long)slot_delta->slot <= curr ) continue;

      if( curr_min > slot_delta->slot ) {
        curr_min = slot_delta->slot;
        curr_min_idx = j;
      }
    }
    deltas[i] = &slot_deltas->slot_deltas[curr_min_idx];
    curr = (long)slot_deltas->slot_deltas[curr_min_idx].slot;
  }

  ulong idx = 0;
  for( ulong i = 0; i < slot_deltas->slot_deltas_len; i++ ) {
    fd_slot_delta_t * slot_delta = deltas[i];
    ulong slot = slot_delta->slot;
    if( slot_delta->is_root ) {
      fd_txncache_register_root_slot( ctx->status_cache, slot );
    }
    for( ulong j = 0; j < slot_delta->slot_delta_vec_len; j++ ) {
      fd_status_pair_t * pair = &slot_delta->slot_delta_vec[j];
      fd_hash_t * blockhash = &pair->hash;
      uchar * results = fd_spad_alloc( runtime_spad, FD_SPAD_ALIGN, pair->value.statuses_len );
      for( ulong k = 0; k < pair->value.statuses_len; k++ ) {
        fd_cache_status_t * status = &pair->value.statuses[k];
        uchar * result = results + k;
        *result = (uchar)status->result.discriminant;
        insert_vals[idx++] = (fd_txncache_insert_t){
          .blockhash = blockhash->uc,
          .slot = slot,
          .txnhash = status->key_slice,
          .result = result
        };
      }
    }
  }
  fd_txncache_insert_batch( ctx->status_cache, insert_vals, num_entries );

  for( ulong i = 0; i < slot_deltas->slot_deltas_len; i++ ) {
    fd_slot_delta_t * slot_delta = deltas[i];
    ulong slot = slot_delta->slot;
    for( ulong j = 0; j < slot_delta->slot_delta_vec_len; j++ ) {
      fd_status_pair_t * pair      = &slot_delta->slot_delta_vec[j];
      fd_hash_t *        blockhash = &pair->hash;
      fd_txncache_set_txnhash_offset( ctx->status_cache, slot, blockhash->uc, pair->value.txn_idx );
    }
  }

  } FD_SPAD_FRAME_END;
  return ctx;
}

ulong
fd_bank_epoch_get( fd_bank_t const * bank ) {
  fd_epoch_schedule_t epoch_schedule = fd_bank_epoch_schedule_get( bank );
  return fd_slot_to_epoch( &epoch_schedule, fd_bank_slot_get( bank ), NULL );
}
