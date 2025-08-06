#include "fd_exec_slot_ctx.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"

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

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover( fd_exec_slot_ctx_t *                slot_ctx,
                          fd_solana_manifest_global_t const * manifest ) {

  fd_stakes_global_t const * manifest_stakes = &manifest->bank.stakes;
  fd_vote_accounts_global_t const  * manifest_vote_accounts = &manifest_stakes->vote_accounts;
  fd_vote_accounts_pair_global_t_mapnode_t * manifest_vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( manifest_vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * manifest_vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( manifest_vote_accounts );

  fd_vote_accounts_global_t * curr_epoch_stakes = fd_bank_curr_epoch_stakes_locking_modify( slot_ctx->bank );
  uchar * curr_epoch_stakes_pool_mem = (uchar *)fd_ulong_align_up( (ulong)curr_epoch_stakes + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_global_t_map_align() );
  fd_vote_accounts_pair_global_t_mapnode_t * curr_epoch_stakes_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( curr_epoch_stakes_pool_mem, 50000UL ) );
  fd_vote_accounts_pair_global_t_mapnode_t * curr_epoch_stakes_root = NULL;
  uchar * acc_region_curr = (uchar *)fd_ulong_align_up( (ulong)curr_epoch_stakes_pool + fd_vote_accounts_pair_global_t_map_footprint( 50000UL ), 8UL );

  for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum( manifest_vote_accounts_pool, manifest_vote_accounts_root );
       n;
       n = fd_vote_accounts_pair_global_t_map_successor( manifest_vote_accounts_pool, n ) ) {

    fd_vote_accounts_pair_global_t_mapnode_t * elem = fd_vote_accounts_pair_global_t_map_acquire( curr_epoch_stakes_pool );
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
      curr_epoch_stakes_pool,
      &curr_epoch_stakes_root,
      elem );
  }

  fd_vote_accounts_vote_accounts_pool_update( curr_epoch_stakes, curr_epoch_stakes_pool );
  fd_vote_accounts_vote_accounts_root_update( curr_epoch_stakes, curr_epoch_stakes_root );
  fd_bank_curr_epoch_stakes_end_locking_modify( slot_ctx->bank );

  fd_bank_epoch_set( slot_ctx->bank, manifest->bank.epoch );

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

    acc_region_curr = (uchar *)fd_ulong_align_up( (ulong)epoch_stakes_pool + fd_vote_accounts_pair_global_t_map_footprint( 50000UL ), 8UL );

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


  /* Copy the stakes delegations */

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_locking_modify( slot_ctx->bank );
  stake_delegations = fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations, FD_RUNTIME_MAX_STAKE_ACCOUNTS ) );

  fd_stakes_global_t const * stakes_global = &manifest->bank.stakes;

  fd_delegation_pair_t_mapnode_t * stake_pool = fd_stakes_stake_delegations_pool_join( stakes_global );
  fd_delegation_pair_t_mapnode_t * stake_root = fd_stakes_stake_delegations_root_join( stakes_global );

  for( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum( stake_pool, stake_root );
       n;
       n = fd_delegation_pair_t_map_successor( stake_pool, n ) ) {

    fd_stake_delegations_update(
        stake_delegations,
        &n->elem.account,
        &n->elem.delegation.voter_pubkey,
        n->elem.delegation.stake,
        n->elem.delegation.activation_epoch,
        n->elem.delegation.deactivation_epoch,
        0UL,
        n->elem.delegation.warmup_cooldown_rate );
  }

  fd_bank_stake_delegations_end_locking_modify( slot_ctx->bank );

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
