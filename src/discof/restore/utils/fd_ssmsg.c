#include "fd_ssmsg.h"

#include "../../../flamenco/types/fd_types.h"

static void
fd_snapshot_manifest_init_epoch_stakes_elem( fd_snapshot_manifest_t *                  snapshot_manifest,
                                             fd_versioned_epoch_stakes_pair_global_t * versioned_epoch_stakes,
                                             ulong                                     idx ) {
  fd_versioned_epoch_stakes_global_t * epoch_stakes = &versioned_epoch_stakes[idx].val;

  fd_stake_pair_t_mapnode_t * stake_delegations_pool = fd_stakes_stake_stake_delegations_pool_join( &epoch_stakes->inner.Current.stakes );
  fd_stake_pair_t_mapnode_t * stake_delegations_root = fd_stakes_stake_stake_delegations_root_join( &epoch_stakes->inner.Current.stakes );
  snapshot_manifest->epoch_stakes[idx].stakes_len = fd_stake_pair_t_map_size( stake_delegations_pool,
                                                                              stake_delegations_pool );

  ulong num_stake_delegations = fd_stake_pair_t_map_size( stake_delegations_pool, stake_delegations_root );
  if( FD_UNLIKELY( num_stake_delegations>MAX_STAKE_DELEGATIONS ) ) FD_LOG_ERR(( "too many stake delegations (%lu) max is %lu", num_stake_delegations, MAX_STAKE_DELEGATIONS ));

  ulong i = 0UL;
  for ( fd_stake_pair_t_mapnode_t * n = fd_stake_pair_t_map_minimum( stake_delegations_pool,
                                                                     stake_delegations_root);
        n;
        n = fd_stake_pair_t_map_successor( stake_delegations_pool, n ) ) {
    fd_pubkey_t const * stake_account_pubkey = &n->elem.account;
    fd_pubkey_t const * vote_account_pubkey  = &n->elem.stake.delegation.voter_pubkey;
    FD_TEST( idx<sizeof(snapshot_manifest->epoch_stakes)/sizeof(snapshot_manifest->epoch_stakes[0]) );
    FD_TEST( i<sizeof(snapshot_manifest->epoch_stakes[idx].stakes)/sizeof(snapshot_manifest->epoch_stakes[idx].stakes[0]) );
    fd_memcpy( snapshot_manifest->epoch_stakes[idx].stakes[i].vote_account_pubkey, vote_account_pubkey, sizeof(fd_pubkey_t) );
    fd_memcpy( snapshot_manifest->epoch_stakes[idx].stakes[i].stake_account_pubkey, stake_account_pubkey, sizeof(fd_pubkey_t) );
    snapshot_manifest->epoch_stakes[idx].stakes[i].stake = n->elem.stake.delegation.stake;
    i++;
  }
}

static void
fd_snapshot_manifest_init_epoch_stakes( fd_snapshot_manifest_t *      snapshot_manifest,
                                        fd_solana_manifest_global_t * solana_manifest ) {
  fd_versioned_epoch_stakes_pair_global_t * versioned_epoch_stakes
    = fd_solana_manifest_versioned_epoch_stakes_join( solana_manifest );
  snapshot_manifest->epoch_stakes_len = solana_manifest->versioned_epoch_stakes_len;
  ulong epoch = solana_manifest->bank.epoch;

  for( ulong i=0UL; i<solana_manifest->versioned_epoch_stakes_len; i++ ) {
    if( versioned_epoch_stakes[i].epoch == epoch ) {
      fd_snapshot_manifest_init_epoch_stakes_elem( snapshot_manifest, versioned_epoch_stakes, 0UL );
    }
    if(versioned_epoch_stakes[i].epoch == epoch-1UL ) {
      fd_snapshot_manifest_init_epoch_stakes_elem( snapshot_manifest, versioned_epoch_stakes, 1UL );
    }
    if(versioned_epoch_stakes[i].epoch == epoch-2UL ) {
      fd_snapshot_manifest_init_epoch_stakes_elem( snapshot_manifest, versioned_epoch_stakes, 2UL );
    }
  }
}

static void
fd_snapshot_manifest_init_vote_accounts( fd_snapshot_manifest_t *       snapshot_manifest,
                                         fd_solana_manifest_global_t *  solana_manifest ) {
  uchar * vote_accounts_pool_mem
    = (uchar *)&solana_manifest->bank.stakes.vote_accounts + solana_manifest->bank.stakes.vote_accounts.vote_accounts_pool_offset;
  uchar * vote_accounts_root_mem
    = (uchar *)&solana_manifest->bank.stakes.vote_accounts + solana_manifest->bank.stakes.vote_accounts.vote_accounts_root_offset;
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool =
    fd_vote_accounts_pair_global_t_map_join( vote_accounts_pool_mem );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root =
    (fd_vote_accounts_pair_global_t_mapnode_t *)( vote_accounts_root_mem );

  snapshot_manifest->vote_accounts_len
    = fd_vote_accounts_pair_global_t_map_size( vote_accounts_pool,
                                               vote_accounts_root );

  if( snapshot_manifest->vote_accounts_len > 16384UL ) {
    FD_LOG_ERR(("resize snapshot manifest vote accounts len to be at least %lu", snapshot_manifest->vote_accounts_len ));
  }
  ulong i = 0UL;
  for ( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum( vote_accounts_pool,
                                                                                            vote_accounts_root );
        n;
        n = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_pool, n ) ) {
    fd_pubkey_t const * pubkey = &n->elem.key;
    fd_memcpy( snapshot_manifest->vote_accounts[i].vote_account_pubkey, pubkey, sizeof(fd_pubkey_t) );

    void const * const buf_    = ((uchar *)( (uchar *)&n->elem.value + n->elem.value.data_offset ));
    ulong        const buf_sz_ = (n->elem.value.data_len);

    fd_bincode_decode_ctx_t ctx = {
      .data    = (void const *)( buf_ ),
      .dataend = (void const *)( (ulong)ctx.data + buf_sz_ )
    };

    ulong total_sz = 0UL;
    int err = fd_vote_state_versioned_decode_footprint( &ctx, &total_sz );

    uchar scratch[ 1UL<<20UL ] __attribute__((aligned(FD_VOTE_STATE_VERSIONED_ALIGN)));
    FD_TEST( err==FD_BINCODE_SUCCESS && total_sz<=sizeof(scratch ) );
    fd_vote_state_versioned_t * vs = fd_vote_state_versioned_decode( scratch, &ctx );

    fd_vote_epoch_credits_t * epoch_credits;
    uchar commission;
    switch( vs->discriminant ) {
      case fd_vote_state_versioned_enum_current:
        epoch_credits = vs->inner.current.epoch_credits;
        commission    = vs->inner.current.commission;
        break;
      case fd_vote_state_versioned_enum_v0_23_5:
        epoch_credits = vs->inner.v0_23_5.epoch_credits;
        commission    = vs->inner.v0_23_5.commission;
        break;
      case fd_vote_state_versioned_enum_v1_14_11:
        epoch_credits = vs->inner.v1_14_11.epoch_credits;
        commission    = vs->inner.v1_14_11.commission;
        break;
      default:
        FD_LOG_ERR(( "invalid vote account, should never happen" ));
    }

    snapshot_manifest->vote_accounts[i].commission = commission;
    snapshot_manifest->vote_accounts[i].epoch_credits_history_len = deq_fd_vote_epoch_credits_t_cnt( epoch_credits );

    if( snapshot_manifest->vote_accounts[i].epoch_credits_history_len > 64UL ) {
      FD_LOG_ERR(("resize snapshot manifest vote accounts epoch credit history len to be at least %lu", snapshot_manifest->vote_accounts[i].epoch_credits_history_len ));
    }
    fd_memcpy( snapshot_manifest->vote_accounts[i].epoch_credits, epoch_credits, sizeof(fd_vote_epoch_credits_t)*snapshot_manifest->vote_accounts[i].epoch_credits_history_len );
    i++;
  }
}

fd_snapshot_manifest_t *
fd_snapshot_manifest_init_from_solana_manifest( void *                        mem,
                                                fd_solana_manifest_global_t * solana_manifest ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_snapshot_manifest_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_snapshot_manifest_t * snapshot_manifest = fd_type_pun( mem );

  /* TODO: we should have a chrono API for time conversion */
  snapshot_manifest->creation_time_ns = (long)(solana_manifest->bank.genesis_creation_time * (ulong)1e9);

  /* inflation params */
  snapshot_manifest->inflation_params.initial         = solana_manifest->bank.inflation.initial;
  snapshot_manifest->inflation_params.terminal        = solana_manifest->bank.inflation.terminal;
  snapshot_manifest->inflation_params.taper           = solana_manifest->bank.inflation.taper;
  snapshot_manifest->inflation_params.foundation      = solana_manifest->bank.inflation.foundation;
  snapshot_manifest->inflation_params.foundation_term = solana_manifest->bank.inflation.foundation_term;

  /* epoch schedule params */
  snapshot_manifest->epoch_schedule_params.slots_per_epoch             = solana_manifest->bank.epoch_schedule.slots_per_epoch;
  snapshot_manifest->epoch_schedule_params.leader_schedule_slot_offset = solana_manifest->bank.epoch_schedule.leader_schedule_slot_offset;
  snapshot_manifest->epoch_schedule_params.warmup                      = solana_manifest->bank.epoch_schedule.warmup;

  /* fee rate governor */
  snapshot_manifest->fee_rate_governor.target_lamports_per_signature = solana_manifest->bank.fee_rate_governor.target_lamports_per_signature;
  snapshot_manifest->fee_rate_governor.target_signatures_per_slot    = solana_manifest->bank.fee_rate_governor.target_signatures_per_slot;
  snapshot_manifest->fee_rate_governor.min_lamports_per_signature    = solana_manifest->bank.fee_rate_governor.min_lamports_per_signature;
  snapshot_manifest->fee_rate_governor.max_lamports_per_signature    = solana_manifest->bank.fee_rate_governor.max_lamports_per_signature;
  snapshot_manifest->fee_rate_governor.burn_percent                  = solana_manifest->bank.fee_rate_governor.burn_percent;

  snapshot_manifest->slot         = solana_manifest->bank.slot;
  snapshot_manifest->block_height = solana_manifest->bank.block_height;
  snapshot_manifest->parent_slot  = solana_manifest->bank.parent_slot;
  fd_memcpy( snapshot_manifest->bank_hash,
             &solana_manifest->bank.hash,
             sizeof( snapshot_manifest->bank_hash ) );
  fd_memcpy( snapshot_manifest->accounts_hash,
             &solana_manifest->accounts_db.bank_hash_info.accounts_hash,
             sizeof( snapshot_manifest->accounts_hash ) );
  fd_memcpy( snapshot_manifest->accounts_delta_hash,
             &solana_manifest->accounts_db.bank_hash_info.accounts_delta_hash,
             sizeof( snapshot_manifest->accounts_delta_hash ) );
  fd_memcpy( snapshot_manifest->parent_bank_hash,
             &solana_manifest->bank.parent_hash,
             sizeof( snapshot_manifest->parent_bank_hash ) );

  snapshot_manifest->has_accounts_lthash = !!solana_manifest->lthash_offset;
  if( solana_manifest->lthash_offset ) {
    fd_memcpy( snapshot_manifest->accounts_lthash,
               (uchar *)solana_manifest + solana_manifest->lthash_offset,
               sizeof( snapshot_manifest->accounts_lthash ) );
  }

  snapshot_manifest->has_epoch_account_hash = !!solana_manifest->epoch_account_hash_offset;
  if( solana_manifest->epoch_account_hash_offset ) {
    fd_memcpy( snapshot_manifest->epoch_account_hash,
               (uchar *)solana_manifest + solana_manifest->epoch_account_hash_offset,
               sizeof( snapshot_manifest->epoch_account_hash ) );
  }

  snapshot_manifest->ticks_per_slot = solana_manifest->bank.ticks_per_slot;
  snapshot_manifest->has_hashes_per_tick = !!solana_manifest->bank.hashes_per_tick_offset;
  if( solana_manifest->bank.hashes_per_tick_offset ) {
    snapshot_manifest->hashes_per_tick = *(ulong *)(solana_manifest + solana_manifest->bank.hashes_per_tick_offset);
  }

  snapshot_manifest->capitalization = solana_manifest->bank.capitalization;
  fd_snapshot_manifest_init_vote_accounts( snapshot_manifest, solana_manifest );

  fd_snapshot_manifest_init_epoch_stakes( snapshot_manifest, solana_manifest );

  return snapshot_manifest;
}
