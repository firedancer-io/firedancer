#include "fd_exec_slot_ctx.h"
#include "../fd_bank_mgr.h"
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

  fd_stakes_global_t * stakes = fd_bank_mgr_stakes_query( slot_ctx->bank_mgr );
  if( FD_UNLIKELY( stakes==NULL ) ) {
    FD_LOG_WARNING(( "stakes is NULL" ));
    return 0;
  }

  fd_vote_accounts_global_t const * vote_accounts = &stakes->vote_accounts;
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( vote_accounts );
  FD_TEST( vote_accounts_pool );
  FD_TEST( vote_accounts_root );

  for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum(vote_accounts_pool, vote_accounts_root);
       n;
       n = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_pool, n ) ) {

    FD_SPAD_FRAME_BEGIN( runtime_spad ) {

    /* Extract vote timestamp of account */
    int err;

    uchar * data = (uchar*)&n->elem.value + n->elem.value.data_offset;
    ulong   data_len = n->elem.value.data_len;

    fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
        vote_state_versioned, runtime_spad,
        data,
        data_len,
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
      fd_vote_record_timestamp_vote_with_slot( &n->elem.key, timestamp, slot, slot_ctx->banks, slot_ctx->bank );
    }
    } FD_SPAD_FRAME_END;
  }

  return 1;
}

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover( fd_exec_slot_ctx_t *         slot_ctx,
                          fd_solana_manifest_t const * manifest,
                          fd_solana_manifest_global_t * manifest_global,
                          fd_spad_t *                  runtime_spad ) {

  FD_TEST( slot_ctx->banks );
  slot_ctx->bank = fd_banks_init_bank( slot_ctx->banks, manifest->bank.slot );
  FD_TEST( slot_ctx->bank );
  FD_LOG_WARNING(("BANK %p", (void*)slot_ctx->bank));

  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( &manifest_global->bank.stakes.vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( &manifest_global->bank.stakes.vote_accounts );

  for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum( vote_accounts_pool, vote_accounts_root );
       n;
       n = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_pool, n ) ) {
    FD_TEST(n);
  }

  fd_versioned_bank_t const * oldbank = &manifest->bank;

  ulong sz = fd_stakes_size( &oldbank->stakes );
  fd_stakes_global_t * stakes = fd_bank_mgr_stakes_modify( slot_ctx->bank_mgr );
  fd_memcpy( stakes, &manifest_global->bank.stakes, sz * 2 );
  /* Verify stakes */

  fd_delegation_pair_t_mapnode_t * stake_delegations_pool_og = fd_stakes_stake_delegations_pool_join( &manifest_global->bank.stakes );
  FD_TEST( stake_delegations_pool_og );
  /* Verify stakes */
  fd_delegation_pair_t_mapnode_t * stake_delegations_pool = fd_stakes_stake_delegations_pool_join( stakes );
  FD_TEST( stake_delegations_pool );



  fd_bank_mgr_stakes_save( slot_ctx->bank_mgr );

  stakes = fd_bank_mgr_stakes_query( slot_ctx->bank_mgr );

  /* Index vote accounts */

  /* Block Hash Queue */

  fd_block_hash_queue_global_t * bhq = (fd_block_hash_queue_global_t *)&slot_ctx->bank->block_hash_queue[0];
  uchar * last_hash_mem = (uchar *)fd_ulong_align_up( (ulong)bhq + sizeof(fd_block_hash_queue_global_t), alignof(fd_hash_t) );
  uchar * ages_pool_mem = (uchar *)fd_ulong_align_up( (ulong)last_hash_mem + sizeof(fd_hash_t), fd_hash_hash_age_pair_t_map_align() );

  fd_hash_hash_age_pair_t_mapnode_t * ages_pool = fd_hash_hash_age_pair_t_map_join( fd_hash_hash_age_pair_t_map_new( ages_pool_mem, 301 ) );
  fd_hash_hash_age_pair_t_mapnode_t * ages_root = NULL;

  bhq->last_hash_index = oldbank->blockhash_queue.last_hash_index;
  if( oldbank->blockhash_queue.last_hash ) {
    fd_memcpy( last_hash_mem, oldbank->blockhash_queue.last_hash, sizeof(fd_hash_t) );
  } else {
    fd_memset( last_hash_mem, 0, sizeof(fd_hash_t) );
  }
  bhq->last_hash_offset = (ulong)last_hash_mem - (ulong)bhq;

  for( ulong i=0UL; i<oldbank->blockhash_queue.ages_len; i++ ) {
    fd_hash_hash_age_pair_t * elem = &oldbank->blockhash_queue.ages[i];
    fd_hash_hash_age_pair_t_mapnode_t * node = fd_hash_hash_age_pair_t_map_acquire( ages_pool );
    node->elem = *elem;
    fd_hash_hash_age_pair_t_map_insert( ages_pool, &ages_root, node );
  }

  bhq->ages_pool_offset = (ulong)fd_hash_hash_age_pair_t_map_leave( ages_pool ) - (ulong)bhq;
  bhq->ages_root_offset = (ulong)ages_root - (ulong)bhq;

  bhq->max_age = oldbank->blockhash_queue.max_age;


  //fd_bank_mgr_block_hash_queue_save( slot_ctx->bank_mgr );

  /* Bank Hash */
  fd_hash_t * bank_hash = fd_bank_mgr_bank_hash_modify( slot_ctx->bank_mgr );
  *bank_hash = oldbank->hash;
  fd_bank_mgr_bank_hash_save( slot_ctx->bank_mgr );

  /* Slot */

  ulong * slot_ptr = fd_bank_mgr_slot_modify( slot_ctx->bank_mgr );
  *slot_ptr = oldbank->slot;
  fd_bank_mgr_slot_save( slot_ctx->bank_mgr );
  slot_ctx->slot = oldbank->slot;

  /* Fee Rate Governor */

  slot_ctx->bank->fee_rate_governor = oldbank->fee_rate_governor;

  /* Capitalization */

  slot_ctx->bank->capitalization = oldbank->capitalization;

  /* Lamports Per Signature */

  slot_ctx->bank->lamports_per_signature = manifest->lamports_per_signature;

  /* Previous Lamports Per Signature */

  slot_ctx->bank->prev_lamports_per_signature = manifest->lamports_per_signature;

  /* Transaction Count */

  slot_ctx->bank->transaction_count = oldbank->transaction_count;

  /* Parent Signature Count */

  slot_ctx->bank->parent_signature_cnt = oldbank->signature_count;

  /* Tick Height */

  slot_ctx->bank->tick_height = oldbank->tick_height;

  /* Max Tick Height */

  slot_ctx->bank->max_tick_height = oldbank->max_tick_height;

  /* Hashes Per Tick */

  slot_ctx->bank->hashes_per_tick = !!oldbank->hashes_per_tick ? *oldbank->hashes_per_tick : 0UL;

  /* NS Per Slot */

  slot_ctx->bank->ns_per_slot = oldbank->ns_per_slot;

  /* Ticks Per Slot */

  slot_ctx->bank->ticks_per_slot = oldbank->ticks_per_slot;

  /* Genesis Creation Time */

  slot_ctx->bank->genesis_creation_time = oldbank->genesis_creation_time;

  /* Slots Per Year */

  slot_ctx->bank->slots_per_year = oldbank->slots_per_year;

  /* Inflation */

  slot_ctx->bank->inflation = oldbank->inflation;

  /* Block Height */

  slot_ctx->bank->block_height = oldbank->block_height;

  /* Epoch Account Hash */

  if( manifest->epoch_account_hash ) {
    slot_ctx->bank->epoch_account_hash = *manifest->epoch_account_hash;
  } else {
    memset( &slot_ctx->bank->epoch_account_hash, 0, sizeof(fd_hash_t) );
  }

  /* Prev Slot */

  ulong * prev_slot = fd_bank_mgr_prev_slot_modify( slot_ctx->bank_mgr );
  *prev_slot = oldbank->parent_slot;
  fd_bank_mgr_prev_slot_save( slot_ctx->bank_mgr );

  /* Execution Fees */

  slot_ctx->bank->execution_fees = oldbank->collector_fees;

  /* Priority Fees */

  slot_ctx->bank->priority_fees = 0UL;

  /* PoH */

  if( oldbank->blockhash_queue.last_hash ) {
    slot_ctx->bank->poh = *oldbank->blockhash_queue.last_hash;
  }

  /* Prev Bank Hash */

  fd_hash_t * prev_bank_hash = fd_bank_mgr_prev_bank_hash_modify( slot_ctx->bank_mgr );
  *prev_bank_hash = oldbank->parent_hash;
  fd_bank_mgr_prev_bank_hash_save( slot_ctx->bank_mgr );

  /* Epoch Schedule */

  fd_epoch_schedule_t * epoch_schedule = fd_bank_mgr_epoch_schedule_modify( slot_ctx->bank_mgr );
  *epoch_schedule = oldbank->epoch_schedule;
  fd_bank_mgr_epoch_schedule_save( slot_ctx->bank_mgr );

  /* Rent */

  fd_rent_t * rent = fd_bank_mgr_rent_modify( slot_ctx->bank_mgr );
  *rent = oldbank->rent_collector.rent;
  fd_bank_mgr_rent_save( slot_ctx->bank_mgr );

  /* Last Restart Slot */

  /* Update last restart slot
     https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/runtime/src/bank.rs#L2152

     oldbank->hard_forks is sorted ascending by slot number.
     To find the last restart slot, take the highest hard fork slot
     number that is less or equal than the current slot number.
     (There might be some hard forks in the future, ignore these) */
  fd_sol_sysvar_last_restart_slot_t * last_restart_slot = fd_bank_mgr_last_restart_slot_modify( slot_ctx->bank_mgr );
  do {
    last_restart_slot->slot = 0UL;
    if( FD_UNLIKELY( oldbank->hard_forks.hard_forks_len == 0 ) ) {
      /* SIMD-0047: The first restart slot should be `0` */
      break;
    }

    fd_slot_pair_t const * head = oldbank->hard_forks.hard_forks;
    fd_slot_pair_t const * tail = head + oldbank->hard_forks.hard_forks_len - 1UL;

    for( fd_slot_pair_t const *pair = tail; pair >= head; pair-- ) {
      if( pair->slot <= slot_ctx->slot ) {
        last_restart_slot->slot = pair->slot;
        break;
      }
    }
  } while (0);
  fd_bank_mgr_last_restart_slot_save( slot_ctx->bank_mgr );

  /* FIXME: Remove the magic number here. */
  fd_clock_timestamp_votes_global_t * clock_timestamp_votes = fd_bank_clock_timestamp_votes_modify( slot_ctx->banks, slot_ctx->bank );
  uchar * clock_pool_mem = (uchar *)fd_ulong_align_up( (ulong)clock_timestamp_votes + sizeof(fd_clock_timestamp_votes_global_t), fd_clock_timestamp_vote_t_map_align() );
  fd_clock_timestamp_vote_t_mapnode_t * clock_pool = fd_clock_timestamp_vote_t_map_join( fd_clock_timestamp_vote_t_map_new(clock_pool_mem, 30000UL ) );
  clock_timestamp_votes->votes_pool_offset = (ulong)fd_clock_timestamp_vote_t_map_leave( clock_pool) - (ulong)clock_timestamp_votes;
  clock_timestamp_votes->votes_root_offset = 0UL;

  recover_clock( slot_ctx, runtime_spad );


  /* Move EpochStakes */
  do {

    fd_epoch_schedule_t * epoch_schedule = fd_bank_mgr_epoch_schedule_query( slot_ctx->bank_mgr );
    ulong epoch = fd_slot_to_epoch( epoch_schedule, slot_ctx->slot, NULL );

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

      // if( manifest->bank.epoch_stakes[i].key==epoch+2UL ) {
      //   slot_ctx->slot_bank.has_use_preceeding_epoch_stakes = 0;
      // }
    }

    for( ulong i=0UL; i<manifest->versioned_epoch_stakes_len; i++ ) {
      if( manifest->versioned_epoch_stakes[i].epoch == epoch ) {
        curr_stakes.vote_accounts_pool = manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_pool;
        curr_stakes.vote_accounts_root = manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_root;
        manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_pool = NULL;
        manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_root = NULL;

        /* We want to save the total epoch stake for the current epoch */
        slot_ctx->bank->total_epoch_stake = manifest->versioned_epoch_stakes[i].val.inner.Current.total_stake;

      }
      if( manifest->versioned_epoch_stakes[i].epoch == epoch+1UL ) {
        next_stakes.vote_accounts_pool = manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_pool;
        next_stakes.vote_accounts_root = manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_root;
        manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_pool = NULL;
        manifest->versioned_epoch_stakes[i].val.inner.Current.stakes.vote_accounts.vote_accounts_root = NULL;
      }

      // if( manifest->versioned_epoch_stakes[i].epoch==epoch+2UL ) {
      //   slot_ctx->slot_bank.has_use_preceeding_epoch_stakes = 0;
      // }
    }

    slot_ctx->bank->use_prev_epoch_stake = epoch + 2UL;

    // slot_ctx->slot_bank.use_preceeding_epoch_stakes     = epoch + 2UL;

    if( FD_UNLIKELY( (!curr_stakes.vote_accounts_root) | (!next_stakes.vote_accounts_root) ) ) {
      FD_LOG_WARNING(( "snapshot missing EpochStakes for epochs %lu and/or %lu", epoch, epoch+1UL ));
      return 0;
    }

    /* Move current EpochStakes */

    fd_vote_accounts_global_t * epoch_stakes = fd_bank_mgr_epoch_stakes_modify( slot_ctx->bank_mgr );
    uchar * epoch_stakes_pool_mem = (uchar *)fd_ulong_align_up( (ulong)epoch_stakes + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_global_t_map_align() );
    fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( epoch_stakes_pool_mem, 50000UL ) );
    fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_root = NULL;

    uchar * acc_region_curr = (uchar *)fd_ulong_align_up( (ulong)epoch_stakes_pool + fd_vote_accounts_pair_global_t_map_footprint( 50000UL ), 8UL );

    for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
          curr_stakes.vote_accounts_pool,
          curr_stakes.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( curr_stakes.vote_accounts_pool, n ) ) {

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
      memcpy( acc_region_curr, n->elem.value.data, n->elem.value.data_len );
      acc_region_curr += n->elem.value.data_len;

      fd_vote_accounts_pair_global_t_map_insert(
        epoch_stakes_pool,
        &epoch_stakes_root,
        elem );
    }

    fd_vote_accounts_vote_accounts_pool_update( epoch_stakes, epoch_stakes_pool );
    fd_vote_accounts_vote_accounts_root_update( epoch_stakes, epoch_stakes_root );
    fd_bank_mgr_epoch_stakes_save( slot_ctx->bank_mgr );

    /* Move next EpochStakes */

    fd_vote_accounts_global_t * next_epoch_stakes = fd_bank_mgr_next_epoch_stakes_modify( slot_ctx->bank_mgr );
    uchar * next_epoch_stakes_pool_mem = (uchar *)fd_ulong_align_up( (ulong)next_epoch_stakes + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_global_t_map_align() );
    fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( next_epoch_stakes_pool_mem, 50000UL ) );
    fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_root = NULL;

    fd_vote_accounts_pair_t_mapnode_t * pool = next_stakes.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * root = next_stakes.vote_accounts_root;

    acc_region_curr = (uchar *)fd_ulong_align_up( (ulong)next_epoch_stakes_pool + fd_vote_accounts_pair_global_t_map_footprint( 50000UL ), 8UL );

    for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum( pool, root );
         n;
         n = fd_vote_accounts_pair_t_map_successor( pool, n ) ) {

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
      memcpy( acc_region_curr, n->elem.value.data, n->elem.value.data_len );
      acc_region_curr += n->elem.value.data_len;

      fd_vote_accounts_pair_global_t_map_insert(
        next_epoch_stakes_pool,
        &next_epoch_stakes_root,
        elem );

    }
    fd_vote_accounts_vote_accounts_pool_update( next_epoch_stakes, next_epoch_stakes_pool );
    fd_vote_accounts_vote_accounts_root_update( next_epoch_stakes, next_epoch_stakes_root );
    fd_bank_mgr_next_epoch_stakes_save( slot_ctx->bank_mgr );

  } while(0);

  //FD_LOG_WARNING(("Recovered EpochStakes of size %lu", fd_vote_accounts_size( &epoch_bank->next_epoch_stakes )));

  fd_slot_lthash_t * lthash = fd_bank_mgr_lthash_modify( slot_ctx->bank_mgr );

  if( NULL != manifest->lthash ) {
    *lthash = *manifest->lthash;
  } else {
    fd_lthash_zero( (fd_lthash_value_t *) lthash->lthash );
  }

  fd_bank_mgr_lthash_save( slot_ctx->bank_mgr );


  fd_rent_fresh_accounts_global_t * rent_fresh_accounts = fd_bank_mgr_rent_fresh_accounts_modify( slot_ctx->bank_mgr );

  /* Setup rent fresh accounts */
  rent_fresh_accounts->total_count        = 0UL;
  rent_fresh_accounts->fresh_accounts_len = FD_RENT_FRESH_ACCOUNTS_MAX;

  fd_rent_fresh_account_t * fresh_accounts = (fd_rent_fresh_account_t *)fd_ulong_align_up( (ulong)rent_fresh_accounts + sizeof(fd_rent_fresh_accounts_global_t), FD_RENT_FRESH_ACCOUNT_ALIGN );
  memset( fresh_accounts, 0, rent_fresh_accounts->fresh_accounts_len * sizeof(fd_rent_fresh_account_t) );
  fd_rent_fresh_accounts_fresh_accounts_update( rent_fresh_accounts, fresh_accounts );

  fd_bank_mgr_rent_fresh_accounts_save( slot_ctx->bank_mgr );

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
