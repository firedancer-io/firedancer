#include "fd_exec_slot_ctx.h"
#include "fd_exec_epoch_ctx.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../program/fd_vote_program.h"

#include <assert.h>
#include <time.h>

void *
fd_exec_slot_ctx_new( void *      mem,
                      fd_valloc_t valloc ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_SLOT_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_memset( mem, 0, sizeof(fd_exec_slot_ctx_t) );

  fd_exec_slot_ctx_t * self = (fd_exec_slot_ctx_t *) mem;
  self->valloc = valloc;
  fd_slot_bank_new(&self->slot_bank);

  self->sysvar_cache = fd_sysvar_cache_new( fd_valloc_malloc( valloc, fd_sysvar_cache_align(), fd_sysvar_cache_footprint() ), valloc );
  self->account_compute_table = fd_account_compute_table_join( fd_account_compute_table_new( fd_valloc_malloc( valloc, fd_account_compute_table_align(), fd_account_compute_table_footprint( 10000 ) ), 10000, 0 ) );

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

  fd_bincode_destroy_ctx_t ctx = { .valloc = hdr->valloc };
  fd_slot_bank_destroy(&hdr->slot_bank, &ctx);

  fd_valloc_free( hdr->valloc, fd_sysvar_cache_delete( hdr->sysvar_cache ) );
  hdr->sysvar_cache = NULL;
  fd_valloc_free( hdr->valloc, fd_account_compute_table_delete( hdr->account_compute_table ) );
  hdr->account_compute_table = NULL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

/* recover_clock recovers PoH/wallclock synchronization.  Walks all vote
   accounts in current epoch stakes. */

static int
recover_clock( fd_exec_slot_ctx_t * slot_ctx ) {

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_vote_accounts_t const * vote_accounts = &epoch_bank->stakes.vote_accounts;

  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool = vote_accounts->vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root = vote_accounts->vote_accounts_root;

  for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(vote_accounts_pool, vote_accounts_root);
       n;
       n = fd_vote_accounts_pair_t_map_successor( vote_accounts_pool, n ) ) {
    /* Extract vote timestamp of account */

    fd_vote_block_timestamp_t vote_state_timestamp;
    FD_SCRATCH_SCOPE_BEGIN {
      /* Deserialize content */
      fd_vote_state_versioned_t vs[1];
      fd_bincode_decode_ctx_t decode =
          { .data    = n->elem.value.data,
            .dataend = n->elem.value.data + n->elem.value.data_len,
            .valloc  = fd_scratch_virtual() };
      int decode_err = fd_vote_state_versioned_decode( vs, &decode );
      if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) {
        FD_LOG_WARNING(( "fd_vote_state_versioned_decode failed (%d)", decode_err ));
        return 0;
      }

      switch( vs->discriminant )
      {
      case fd_vote_state_versioned_enum_current:
        vote_state_timestamp = vs->inner.current.last_timestamp;
        break;
      case fd_vote_state_versioned_enum_v0_23_5:
        vote_state_timestamp = vs->inner.v0_23_5.last_timestamp;
        break;
      case fd_vote_state_versioned_enum_v1_14_11:
        vote_state_timestamp = vs->inner.v1_14_11.last_timestamp;
        break;
      default:
        __builtin_unreachable();
      }

      /* Record timestamp */
      if( vote_state_timestamp.slot != 0 || n->elem.stake != 0 ) {
        fd_vote_record_timestamp_vote_with_slot(slot_ctx, &n->elem.key, vote_state_timestamp.timestamp, vote_state_timestamp.slot);
      }
    } FD_SCRATCH_SCOPE_END;
  }

  return 1;
}

/* Implementation note: fd_exec_slot_ctx_recover moves objects from
   manifest to slot_ctx.  This function must not share pointers between
   slot_ctx and manifest.  Otherwise, would cause a use-after-free.

   Note on memory mgmt:  At this point, fd_types allocated a bunch of
   hash maps and red black trees for us.  The capacity of all of these
   is too small though (they fit exactly the current amount of stake
   delegations, etc).  This method thus also moves these collections
   over to epoch context memory and deallocates the heap structuers.
   This is obviously not ideal, but there's no better way for now.
   See fd_exec_epoch_ctx_fixup_memory.  */

static fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover_( fd_exec_slot_ctx_t *   slot_ctx,
                           fd_solana_manifest_t * manifest ) {

  fd_exec_epoch_ctx_t * epoch_ctx   = slot_ctx->epoch_ctx;
  fd_valloc_t           slot_valloc = slot_ctx->valloc;

  /* Clean out prior bank */

  fd_bincode_destroy_ctx_t destroy = { .valloc = slot_valloc };
  fd_slot_bank_t * slot_bank = &slot_ctx->slot_bank;
  fd_slot_bank_destroy( slot_bank, &destroy );
  fd_slot_bank_new( slot_bank );

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  fd_epoch_bank_new( epoch_bank );

  /* Move stakes data structure */

  fd_deserializable_versioned_bank_t * oldbank = &manifest->bank;
  fd_memcpy( &epoch_bank->stakes, &oldbank->stakes, sizeof(fd_stakes_t) );
  fd_memset( &oldbank->stakes, 0, sizeof(fd_stakes_t) );

  /* Index vote accounts */

  /* Copy over fields */

  if( oldbank->blockhash_queue.last_hash )
    slot_bank->poh = *oldbank->blockhash_queue.last_hash;
  slot_bank->slot = oldbank->slot;
  slot_bank->prev_slot = oldbank->parent_slot;
  fd_memcpy(&slot_bank->banks_hash, &oldbank->hash, sizeof(oldbank->hash));
  fd_memcpy(&slot_bank->fee_rate_governor, &oldbank->fee_rate_governor, sizeof(oldbank->fee_rate_governor));
  slot_bank->lamports_per_signature = oldbank->fee_calculator.lamports_per_signature;
  if( oldbank->hashes_per_tick )
    epoch_bank->hashes_per_tick = *oldbank->hashes_per_tick;
  else
    epoch_bank->hashes_per_tick = 0;
  epoch_bank->ticks_per_slot = oldbank->ticks_per_slot;
  fd_memcpy(&epoch_bank->ns_per_slot, &oldbank->ns_per_slot, sizeof(oldbank->ns_per_slot));
  epoch_bank->genesis_creation_time = oldbank->genesis_creation_time;
  epoch_bank->slots_per_year = oldbank->slots_per_year;
  slot_bank->max_tick_height = oldbank->max_tick_height;
  epoch_bank->inflation = oldbank->inflation;
  epoch_bank->epoch_schedule = oldbank->rent_collector.epoch_schedule;
  epoch_bank->rent = oldbank->rent_collector.rent;

  if( manifest->epoch_account_hash )
    slot_bank->epoch_account_hash = *manifest->epoch_account_hash;

  slot_bank->collected_rent = oldbank->collected_rent;
  slot_bank->collected_fees = oldbank->collector_fees;
  slot_bank->capitalization = oldbank->capitalization;
  slot_bank->block_height = oldbank->block_height;
  slot_bank->transaction_count = oldbank->transaction_count;
  if ( oldbank->blockhash_queue.last_hash ) {
    slot_bank->block_hash_queue.last_hash = fd_valloc_malloc( slot_ctx->valloc, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );
    fd_memcpy( slot_bank->block_hash_queue.last_hash, oldbank->blockhash_queue.last_hash, sizeof(fd_hash_t) );
  } else {
    slot_bank->block_hash_queue.last_hash = NULL;
  }
  slot_bank->block_hash_queue.last_hash_index = oldbank->blockhash_queue.last_hash_index;
  slot_bank->block_hash_queue.max_age = oldbank->blockhash_queue.max_age;
  slot_bank->block_hash_queue.ages_root = NULL;
  slot_bank->block_hash_queue.ages_pool = fd_hash_hash_age_pair_t_map_alloc( slot_ctx->valloc, 400 );
  for ( ulong i = 0; i < oldbank->blockhash_queue.ages_len; i++ ) {
    fd_hash_hash_age_pair_t * elem = &oldbank->blockhash_queue.ages[i];
    fd_hash_hash_age_pair_t_mapnode_t * node = fd_hash_hash_age_pair_t_map_acquire( slot_bank->block_hash_queue.ages_pool );
    fd_memcpy( &node->elem, elem, FD_HASH_HASH_AGE_PAIR_FOOTPRINT );
    fd_hash_hash_age_pair_t_map_insert( slot_bank->block_hash_queue.ages_pool, &slot_bank->block_hash_queue.ages_root, node );
  }

  recover_clock( slot_ctx );

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

    /* Find EpochStakes object matching epoch */
    fd_epoch_epoch_stakes_pair_t * epochs  = oldbank->epoch_stakes;
    fd_epoch_stakes_t *            stakes0 = NULL;  /* current */
    fd_epoch_stakes_t *            stakes1 = NULL;  /* next */
    for( ulong i=0UL; i < manifest->bank.epoch_stakes_len; i++ ) {
      if( epochs[i].key == epoch )
        stakes0 = &epochs[i].value;
      if( epochs[i].key == epoch+1UL )
        stakes1 = &epochs[i].value;
    }
    if( FD_UNLIKELY( (!stakes0) | (!stakes1) ) ) {
      FD_LOG_WARNING(( "snapshot missing EpochStakes for epochs %lu and/or %lu", epoch, epoch+1UL ));
      return 0;
    }

    /* Move current EpochStakes */
    slot_bank->epoch_stakes = stakes0->stakes.vote_accounts;
    fd_memset( &stakes0->stakes.vote_accounts, 0, sizeof(fd_vote_accounts_t) );

    /* Move next EpochStakes
       TODO Can we derive this instead of trusting the snapshot? */

    fd_vote_accounts_pair_t_mapnode_t * pool = stakes1->stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * root = stakes1->stakes.vote_accounts.vote_accounts_root;
    
    // Delete all nodes from existing
    fd_vote_accounts_pair_t_map_release_tree( epoch_bank->next_epoch_stakes.vote_accounts_pool, epoch_bank->next_epoch_stakes.vote_accounts_root );

    epoch_bank->next_epoch_stakes.vote_accounts_pool = fd_exec_epoch_ctx_next_epoch_stakes_join( slot_ctx->epoch_ctx );
    epoch_bank->next_epoch_stakes.vote_accounts_root = NULL;

    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(pool, root); n; n = fd_vote_accounts_pair_t_map_successor(pool, n) ) {
      fd_vote_accounts_pair_t_mapnode_t * elem = fd_vote_accounts_pair_t_map_acquire( epoch_bank->next_epoch_stakes.vote_accounts_pool );
      fd_memcpy( &elem->elem, &n->elem, sizeof(fd_vote_accounts_pair_t));
      fd_vote_accounts_pair_t_map_insert( epoch_bank->next_epoch_stakes.vote_accounts_pool, &epoch_bank->next_epoch_stakes.vote_accounts_root, elem );
    }
    fd_memset( &stakes1->stakes.vote_accounts, 0, sizeof(fd_vote_accounts_t) );
  } while(0);

  // TODO Backup to database
  //int result = fd_runtime_save_epoch_bank(slot_ctx);
  //if( result != FD_EXECUTOR_INSTR_SUCCESS ) {
  //  FD_LOG_WARNING(("save epoch bank failed"));
  //  return result;
  //}
  //
  //return fd_runtime_save_slot_bank(slot_ctx);

  return slot_ctx;
}

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover( fd_exec_slot_ctx_t *   slot_ctx,
                          fd_solana_manifest_t * manifest ) {

  fd_exec_slot_ctx_t * res = fd_exec_slot_ctx_recover_( slot_ctx, manifest );

  /* Regardless of result, always destroy manifest */
  fd_bincode_destroy_ctx_t destroy = { .valloc = slot_ctx->valloc };
  fd_solana_manifest_destroy( manifest, &destroy );
  fd_memset( manifest, 0, sizeof(fd_solana_manifest_t) );

  return res;
}

void
fd_exec_slot_ctx_free( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_bincode_destroy_ctx_t ctx;
  ctx.valloc = slot_ctx->valloc;
  fd_slot_bank_destroy( &slot_ctx->slot_bank, &ctx );

  /* only the slot hashes needs freeing in sysvar cache */
  fd_slot_hashes_destroy( slot_ctx->sysvar_cache_old.slot_hashes, &ctx );

  /* leader points to a caller-allocated leader schedule */

  /* free vec in stake rewards*/
  if( NULL != slot_ctx->epoch_reward_status.stake_rewards_by_partition )
    fd_stake_rewards_vector_destroy( slot_ctx->epoch_reward_status.stake_rewards_by_partition );

  fd_exec_slot_ctx_delete( fd_exec_slot_ctx_leave( slot_ctx ) );
}
