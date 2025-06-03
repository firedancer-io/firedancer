#include "fd_exec_slot_ctx.h"
#include "fd_exec_epoch_ctx.h"
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

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_vote_accounts_t const * vote_accounts = &epoch_bank->stakes.vote_accounts;

  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool = vote_accounts->vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root = vote_accounts->vote_accounts_root;

  for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(vote_accounts_pool, vote_accounts_root);
       n;
       n = fd_vote_accounts_pair_t_map_successor( vote_accounts_pool, n ) ) {

    FD_SPAD_FRAME_BEGIN( runtime_spad ) {

    /* Extract vote timestamp of account */
    int err;
    fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
        vote_state_versioned, runtime_spad,
        n->elem.value.data,
        n->elem.value.data_len,
        &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "vote state decode failed" ));
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
      fd_vote_record_timestamp_vote_with_slot( slot_ctx, &n->elem.key, timestamp, slot );
    }
    } FD_SPAD_FRAME_END;
  }

  return 1;
}

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover( fd_exec_slot_ctx_t *         slot_ctx,
                          fd_solana_manifest_t const * manifest,
                          fd_spad_t *                  runtime_spad ) {

  fd_valloc_t valloc = fd_spad_virtual( runtime_spad );

  fd_exec_epoch_ctx_t * epoch_ctx   = slot_ctx->epoch_ctx;
  fd_epoch_bank_t *     epoch_bank  = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );

  /* Clean out prior bank */
  fd_slot_bank_t * slot_bank = &slot_ctx->slot_bank;
  memset( slot_bank, 0, sizeof(fd_slot_bank_t) );
  fd_slot_bank_new( slot_bank );

  for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
          epoch_bank->stakes.vote_accounts.vote_accounts_pool,
          epoch_bank->stakes.vote_accounts.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( epoch_bank->stakes.vote_accounts.vote_accounts_pool, n ) ) {

      const fd_pubkey_t null_pubkey = {{ 0 }};
      if ( memcmp( &n->elem.key, &null_pubkey, FD_PUBKEY_FOOTPRINT ) == 0 ) {
        continue;
      }
  }

  fd_versioned_bank_t const * oldbank = &manifest->bank;

  /* Populate the epoch context, using the already-allocated statically allocated memory */
  /* Copy stakes */
  epoch_bank->stakes.epoch = oldbank->stakes.epoch;

  /* Copy stakes->vote_accounts */
  for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
          oldbank->stakes.vote_accounts.vote_accounts_pool,
          oldbank->stakes.vote_accounts.vote_accounts_root );
              n;
              n = fd_vote_accounts_pair_t_map_successor( oldbank->stakes.vote_accounts.vote_accounts_pool, n ) ) {

      const fd_pubkey_t null_pubkey = {{ 0 }};
      if ( memcmp( &n->elem.key, &null_pubkey, FD_PUBKEY_FOOTPRINT ) == 0 ) {
        continue;
      }

      FD_TEST( fd_vote_accounts_pair_t_map_free( epoch_bank->stakes.vote_accounts.vote_accounts_pool ) );
      fd_vote_accounts_pair_t_mapnode_t * new_node = fd_vote_accounts_pair_t_map_acquire( epoch_bank->stakes.vote_accounts.vote_accounts_pool );
      FD_TEST( new_node );
      new_node->elem = n->elem;
      fd_vote_accounts_pair_t_map_insert(
        epoch_bank->stakes.vote_accounts.vote_accounts_pool,
        &epoch_bank->stakes.vote_accounts.vote_accounts_root,
        new_node
      );
  }

  /* Copy stakes->stake_delegations */
  for ( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum(
          oldbank->stakes.stake_delegations_pool,
          oldbank->stakes.stake_delegations_root );
          n;
          n = fd_delegation_pair_t_map_successor( oldbank->stakes.stake_delegations_pool, n ) ) {

      const fd_pubkey_t null_pubkey = {{ 0 }};
      if ( memcmp( &n->elem.account, &null_pubkey, FD_PUBKEY_FOOTPRINT ) == 0 ) {
        continue;
      }

      fd_delegation_pair_t_mapnode_t * new_node = fd_delegation_pair_t_map_acquire( epoch_bank->stakes.stake_delegations_pool );
      FD_TEST( new_node );
      new_node->elem = n->elem;
      fd_delegation_pair_t_map_insert(
        epoch_bank->stakes.stake_delegations_pool,
        &epoch_bank->stakes.stake_delegations_root,
        new_node
      );
  }

  /* Copy stakes->stake_history */
  fd_memcpy( &epoch_bank->stakes.stake_history, &oldbank->stakes.stake_history, sizeof(oldbank->stakes.stake_history));

  /* Index vote accounts */

  /* Copy over fields */

  slot_ctx->slot_bank.parent_signature_cnt    = oldbank->signature_count;
  slot_ctx->slot_bank.tick_height             = oldbank->tick_height;

  if( oldbank->blockhash_queue.last_hash ) {
    slot_bank->poh = *oldbank->blockhash_queue.last_hash;
  }
  slot_bank->slot = oldbank->slot;
  slot_bank->prev_slot                        = oldbank->parent_slot;
  slot_bank->banks_hash                       = oldbank->hash;
  slot_ctx->slot_bank.prev_banks_hash         = oldbank->parent_hash;
  slot_bank->fee_rate_governor                = oldbank->fee_rate_governor;
  slot_bank->lamports_per_signature           = manifest->lamports_per_signature;
  slot_ctx->prev_lamports_per_signature       = manifest->lamports_per_signature;
  slot_ctx->slot_bank.parent_signature_cnt    = oldbank->signature_count;
  if( oldbank->hashes_per_tick ) {
    epoch_bank->hashes_per_tick               = *oldbank->hashes_per_tick;
  } else {
    epoch_bank->hashes_per_tick               = 0;
  }
  epoch_bank->ticks_per_slot                  = oldbank->ticks_per_slot;
  epoch_bank->ns_per_slot                     = oldbank->ns_per_slot;
  epoch_bank->genesis_creation_time           = oldbank->genesis_creation_time;
  epoch_bank->slots_per_year                  = oldbank->slots_per_year;
  slot_bank->max_tick_height                  = oldbank->max_tick_height;
  epoch_bank->inflation                       = oldbank->inflation;
  epoch_bank->epoch_schedule                  = oldbank->epoch_schedule;
  epoch_bank->rent                            = oldbank->rent_collector.rent;
  epoch_bank->rent_epoch_schedule             = oldbank->rent_collector.epoch_schedule;

  if( manifest->epoch_account_hash ) {
    slot_bank->epoch_account_hash             = *manifest->epoch_account_hash;
  }

  slot_bank->collected_rent                   = oldbank->collected_rent;
  // did they not change the bank?!
  slot_bank->collected_execution_fees         = oldbank->collector_fees;
  slot_bank->collected_priority_fees          = 0;
  slot_bank->capitalization                   = oldbank->capitalization;
  slot_bank->block_height                     = oldbank->block_height;
  slot_bank->transaction_count                = oldbank->transaction_count;

  if( oldbank->blockhash_queue.last_hash ) {
    slot_bank->block_hash_queue.last_hash     = fd_valloc_malloc( valloc, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );
    *slot_bank->block_hash_queue.last_hash    = *oldbank->blockhash_queue.last_hash;
  } else {
    slot_bank->block_hash_queue.last_hash     = NULL;
  }

  slot_bank->block_hash_queue.last_hash_index = oldbank->blockhash_queue.last_hash_index;
  slot_bank->block_hash_queue.max_age         = oldbank->blockhash_queue.max_age;
  slot_bank->block_hash_queue.ages_root       = NULL;

  /* FIXME: Avoid using magic number for allocations */
  uchar * pool_mem = fd_spad_alloc_check( runtime_spad, fd_hash_hash_age_pair_t_map_align(), fd_hash_hash_age_pair_t_map_footprint( 400 ) );
  slot_bank->block_hash_queue.ages_pool = fd_hash_hash_age_pair_t_map_join( fd_hash_hash_age_pair_t_map_new( pool_mem, 400 ) );
  for ( ulong i = 0; i < oldbank->blockhash_queue.ages_len; i++ ) {
    fd_hash_hash_age_pair_t * elem = &oldbank->blockhash_queue.ages[i];
    fd_hash_hash_age_pair_t_mapnode_t * node = fd_hash_hash_age_pair_t_map_acquire( slot_bank->block_hash_queue.ages_pool );
    node->elem = *elem;
    fd_hash_hash_age_pair_t_map_insert( slot_bank->block_hash_queue.ages_pool, &slot_bank->block_hash_queue.ages_root, node );
  }

  /* FIXME: Remove the magic number here. */
  if( !slot_ctx->slot_bank.timestamp_votes.votes_pool ) {
    pool_mem = fd_spad_alloc_check( runtime_spad, fd_clock_timestamp_vote_t_map_align(), fd_clock_timestamp_vote_t_map_footprint( 15000UL ) );
    slot_ctx->slot_bank.timestamp_votes.votes_pool = fd_clock_timestamp_vote_t_map_join( fd_clock_timestamp_vote_t_map_new( pool_mem, 15000UL ) );
  }
  recover_clock( slot_ctx, runtime_spad );

  /* Pass in the hard forks */

  /* The hard forks should be deep copied over.
     TODO:This should be in the epoch bank and not the slot bank. */
  slot_bank->hard_forks.hard_forks_len = oldbank->hard_forks.hard_forks_len;
  slot_bank->hard_forks.hard_forks     = fd_valloc_malloc( valloc,
                                                           FD_SLOT_PAIR_ALIGN,
                                                           oldbank->hard_forks.hard_forks_len * sizeof(fd_slot_pair_t) );
  memcpy( slot_bank->hard_forks.hard_forks, oldbank->hard_forks.hard_forks,
          oldbank->hard_forks.hard_forks_len * sizeof(fd_slot_pair_t) );

  /* Update last restart slot
     https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/runtime/src/bank.rs#L2152

     oldbank->hard_forks is sorted ascending by slot number.
     To find the last restart slot, take the highest hard fork slot
     number that is less or equal than the current slot number.
     (There might be some hard forks in the future, ignore these) */
  do {
    slot_bank->last_restart_slot.slot = 0UL;
    if( FD_UNLIKELY( oldbank->hard_forks.hard_forks_len == 0 ) ) {
      /* SIMD-0047: The first restart slot should be `0` */
      break;
    }

    fd_slot_pair_t const * head = oldbank->hard_forks.hard_forks;
    fd_slot_pair_t const * tail = head + oldbank->hard_forks.hard_forks_len - 1UL;

    for( fd_slot_pair_t const *pair = tail; pair >= head; pair-- ) {
      if( pair->slot <= slot_bank->slot ) {
        slot_bank->last_restart_slot.slot = pair->slot;
        break;
      }
    }
  } while (0);

  /* Move EpochStakes */
  do {
    ulong epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_bank->slot, NULL );

    /* We need to save the vote accounts for the current epoch and the next
       epoch as it is used to calculate the leader schedule at the epoch
       boundary. */

    fd_vote_accounts_t curr_stakes = { .vote_accounts_pool = NULL, .vote_accounts_root = NULL };
    fd_vote_accounts_t next_stakes = { .vote_accounts_pool = NULL, .vote_accounts_root = NULL };

    for( ulong i=0UL; i<manifest->bank.epoch_stakes_len; i++ ) {
      if( manifest->bank.epoch_stakes[i].key == epoch ) {
        curr_stakes.vote_accounts_pool = manifest->bank.epoch_stakes[i].value.stakes.vote_accounts.vote_accounts_pool;
        curr_stakes.vote_accounts_root = manifest->bank.epoch_stakes[i].value.stakes.vote_accounts.vote_accounts_root;
        manifest->bank.epoch_stakes[i].value.stakes.vote_accounts.vote_accounts_pool = NULL;
        manifest->bank.epoch_stakes[i].value.stakes.vote_accounts.vote_accounts_root = NULL;
      }
      if( manifest->bank.epoch_stakes[i].key == epoch+1UL ) {
        next_stakes.vote_accounts_pool = manifest->bank.epoch_stakes[i].value.stakes.vote_accounts.vote_accounts_pool;
        next_stakes.vote_accounts_root = manifest->bank.epoch_stakes[i].value.stakes.vote_accounts.vote_accounts_root;
        manifest->bank.epoch_stakes[i].value.stakes.vote_accounts.vote_accounts_pool = NULL;
        manifest->bank.epoch_stakes[i].value.stakes.vote_accounts.vote_accounts_root = NULL;
      }

      /* When loading from a snapshot, Agave's stake caches mean that we have to special-case the epoch stakes
         that are used for the second epoch E+2 after the snapshot epoch E.

         If the snapshot contains the epoch stakes for E+2, we should use those.

         If the snapshot does not, we should use the stakes at the end of the E-1 epoch, instead of E-2 as we do for
         all other epochs. */

      if( manifest->bank.epoch_stakes[i].key==epoch+2UL ) {
        slot_ctx->slot_bank.has_use_preceeding_epoch_stakes = 0;
      }
    }

    for( ulong i=0UL; i<manifest->versioned_epoch_stakes_len; i++ ) {
      if( manifest->versioned_epoch_stakes[i].epoch == epoch ) {
        curr_stakes.vote_accounts_pool = manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_pool;
        curr_stakes.vote_accounts_root = manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_root;
        manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_pool = NULL;
        manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_root = NULL;
      }
      if( manifest->versioned_epoch_stakes[i].epoch == epoch+1UL ) {
        next_stakes.vote_accounts_pool = manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_pool;
        next_stakes.vote_accounts_root = manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_root;
        manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_pool = NULL;
        manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_root = NULL;
      }

      if( manifest->versioned_epoch_stakes[i].epoch==epoch+2UL ) {
        slot_ctx->slot_bank.has_use_preceeding_epoch_stakes = 0;
      }
    }

    slot_ctx->slot_bank.has_use_preceeding_epoch_stakes = 1;
    slot_ctx->slot_bank.use_preceeding_epoch_stakes     = epoch + 2UL;

    if( FD_UNLIKELY( (!curr_stakes.vote_accounts_root) | (!next_stakes.vote_accounts_root) ) ) {
      FD_LOG_WARNING(( "snapshot missing EpochStakes for epochs %lu and/or %lu", epoch, epoch+1UL ));
      return 0;
    }

    /* Move current EpochStakes */
    pool_mem = fd_spad_alloc_check( runtime_spad, fd_vote_accounts_pair_t_map_align(), fd_vote_accounts_pair_t_map_footprint( 100000 ) );
    slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool =
      fd_vote_accounts_pair_t_map_join( fd_vote_accounts_pair_t_map_new( pool_mem, 100000 ) ); /* FIXME: Remove magic constant */
    slot_ctx->slot_bank.epoch_stakes.vote_accounts_root = NULL;

    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
          curr_stakes.vote_accounts_pool,
          curr_stakes.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( curr_stakes.vote_accounts_pool, n ) ) {

        fd_vote_accounts_pair_t_mapnode_t * elem = fd_vote_accounts_pair_t_map_acquire(
          slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool );
        FD_TEST( elem );

        elem->elem = n->elem;

        fd_vote_accounts_pair_t_map_insert(
          slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool,
          &slot_ctx->slot_bank.epoch_stakes.vote_accounts_root,
          elem );
    }

    /* Move next EpochStakes
       TODO Can we derive this instead of trusting the snapshot? */

    fd_vote_accounts_pair_t_mapnode_t * pool = next_stakes.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * root = next_stakes.vote_accounts_root;

    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(pool, root);
          n;
          n = fd_vote_accounts_pair_t_map_successor(pool, n) ) {

      fd_vote_accounts_pair_t_mapnode_t * elem = fd_vote_accounts_pair_t_map_acquire(
        epoch_bank->next_epoch_stakes.vote_accounts_pool );
      FD_TEST( elem );

      elem->elem                    = n->elem;
      epoch_ctx->total_epoch_stake += n->elem.stake;

      fd_vote_accounts_pair_t_map_insert(
        epoch_bank->next_epoch_stakes.vote_accounts_pool,
        &epoch_bank->next_epoch_stakes.vote_accounts_root,
        elem );

    }
  } while(0);

  if ( NULL != manifest->lthash )
    slot_ctx->slot_bank.lthash = *manifest->lthash;
  else
    fd_lthash_zero( (fd_lthash_value_t *) slot_ctx->slot_bank.lthash.lthash );

  /* Allocate all the memory for the rent fresh accounts lists */
  fd_rent_fresh_accounts_new( &slot_bank->rent_fresh_accounts );
  slot_bank->rent_fresh_accounts.total_count        = 0UL;
  slot_bank->rent_fresh_accounts.fresh_accounts_len = FD_RENT_FRESH_ACCOUNTS_MAX;
  slot_bank->rent_fresh_accounts.fresh_accounts     = fd_spad_alloc(
    runtime_spad,
    FD_RENT_FRESH_ACCOUNT_ALIGN,
    sizeof(fd_rent_fresh_account_t) * FD_RENT_FRESH_ACCOUNTS_MAX );
  fd_memset(  slot_bank->rent_fresh_accounts.fresh_accounts, 0, sizeof(fd_rent_fresh_account_t) * FD_RENT_FRESH_ACCOUNTS_MAX );

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
