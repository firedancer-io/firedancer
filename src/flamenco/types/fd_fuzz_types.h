// This is an auto-generated file. To add entries, edit fd_types.json
#ifndef HEADER_FUZZ_FD_RUNTIME_TYPES
#define HEADER_FUZZ_FD_RUNTIME_TYPES

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#define SOURCE_fd_src_flamenco_types_fd_types_c
#include "fd_types.h"
#include "fd_types_custom.h"

size_t LLVMFuzzerMutate(uchar *data, size_t size, size_t max_size);

void *fd_flamenco_txn_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_flamenco_txn_t *self = (fd_flamenco_txn_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_flamenco_txn_t);
  fd_flamenco_txn_new(mem);
  LLVMFuzzerMutate( &self->txn_buf[0], FD_TXN_MAX_SZ, FD_TXN_MAX_SZ );
  self->raw_sz = fd_rng_ulong( rng ) % FD_TXN_MTU;
  LLVMFuzzerMutate( &self->raw[0], self->raw_sz, self->raw_sz );
  return mem;
}

void *fd_hash_generate(void *mem, void **alloc_mem, fd_rng_t * rng) {
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_hash_t);
  fd_hash_new(mem);
  LLVMFuzzerMutate( (uchar *) mem, sizeof(fd_hash_t), sizeof(fd_hash_t));
  return mem;
}

void *fd_pubkey_generate(void *mem, void **alloc_mem, fd_rng_t * rng) {
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_pubkey_t);
  fd_pubkey_new(mem);
  LLVMFuzzerMutate( (uchar *) mem, sizeof(fd_pubkey_t), sizeof(fd_pubkey_t));
  return mem;
}

void *fd_signature_generate(void *mem, void **alloc_mem, fd_rng_t * rng) {
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_signature_t);
  fd_signature_new(mem);
  LLVMFuzzerMutate( (uchar *) mem, sizeof(fd_signature_t), sizeof(fd_signature_t));
  return mem;
}

void *fd_gossip_ip4_addr_generate(void *mem, void **alloc_mem, fd_rng_t * rng) {
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_ip4_addr_t);
  fd_gossip_ip4_addr_new(mem);
  LLVMFuzzerMutate( (uchar *) mem, sizeof(fd_gossip_ip4_addr_t), sizeof(fd_gossip_ip4_addr_t));
  return mem;
}

void *fd_gossip_ip6_addr_generate(void *mem, void **alloc_mem, fd_rng_t * rng) {
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_ip6_addr_t);
  fd_gossip_ip6_addr_new(mem);
  LLVMFuzzerMutate( (uchar *) mem, sizeof(fd_gossip_ip6_addr_t), sizeof(fd_gossip_ip6_addr_t));
  return mem;
}

void *fd_feature_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_feature_t *self = (fd_feature_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_feature_t);
  fd_feature_new(mem);
  {
    self->has_activated_at = fd_rng_uchar( rng ) % 2;
    if( self->has_activated_at ) {
      LLVMFuzzerMutate( (uchar *)&(self->activated_at), sizeof(ulong), sizeof(ulong) );
    }
  }
  return mem;
}

void *fd_fee_calculator_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_fee_calculator_t *self = (fd_fee_calculator_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_fee_calculator_t);
  fd_fee_calculator_new(mem);
  self->lamports_per_signature = fd_rng_ulong( rng );
  return mem;
}

void *fd_hash_age_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_hash_age_t *self = (fd_hash_age_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_hash_age_t);
  fd_hash_age_new(mem);
  fd_fee_calculator_generate( &self->fee_calculator, alloc_mem, rng );
  self->hash_index = fd_rng_ulong( rng );
  self->timestamp = fd_rng_ulong( rng );
  return mem;
}

void *fd_hash_hash_age_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_hash_hash_age_pair_t *self = (fd_hash_hash_age_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_hash_hash_age_pair_t);
  fd_hash_hash_age_pair_new(mem);
  fd_hash_generate( &self->key, alloc_mem, rng );
  fd_hash_age_generate( &self->val, alloc_mem, rng );
  return mem;
}

void *fd_block_hash_vec_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_block_hash_vec_t *self = (fd_block_hash_vec_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_block_hash_vec_t);
  fd_block_hash_vec_new(mem);
  self->last_hash_index = fd_rng_ulong( rng );
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->last_hash = (fd_hash_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_HASH_FOOTPRINT;
      fd_hash_new( self->last_hash );
      fd_hash_generate( self->last_hash, alloc_mem, rng );
    }
    else {
    self->last_hash = NULL;
    }
  }
  self->ages_len = fd_rng_ulong( rng ) % 8;
  if( self->ages_len ) {
    self->ages = (fd_hash_hash_age_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_HASH_HASH_AGE_PAIR_FOOTPRINT*self->ages_len;
    for( ulong i=0; i < self->ages_len; i++ ) {
      fd_hash_hash_age_pair_new( self->ages + i );
      fd_hash_hash_age_pair_generate( self->ages + i, alloc_mem, rng );
    }
  } else
    self->ages = NULL;
  self->max_age = fd_rng_ulong( rng );
  return mem;
}

void *fd_block_hash_queue_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_block_hash_queue_t *self = (fd_block_hash_queue_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_block_hash_queue_t);
  fd_block_hash_queue_new(mem);
  self->last_hash_index = fd_rng_ulong( rng );
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->last_hash = (fd_hash_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_HASH_FOOTPRINT;
      fd_hash_new( self->last_hash );
      fd_hash_generate( self->last_hash, alloc_mem, rng );
    }
    else {
    self->last_hash = NULL;
    }
  }
  ulong ages_len = fd_rng_ulong( rng ) % 8;
  self->ages_pool = fd_hash_hash_age_pair_t_map_join_new( alloc_mem, fd_ulong_max( ages_len, 400 ) );
  self->ages_root = NULL;
  for( ulong i=0; i < ages_len; i++ ) {
    fd_hash_hash_age_pair_t_mapnode_t * node = fd_hash_hash_age_pair_t_map_acquire( self->ages_pool );
    fd_hash_hash_age_pair_generate( &node->elem, alloc_mem, rng );
    fd_hash_hash_age_pair_t_map_insert( self->ages_pool, &self->ages_root, node );
  }
  self->max_age = fd_rng_ulong( rng );
  return mem;
}

void *fd_fee_rate_governor_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_fee_rate_governor_t *self = (fd_fee_rate_governor_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_fee_rate_governor_t);
  fd_fee_rate_governor_new(mem);
  self->target_lamports_per_signature = fd_rng_ulong( rng );
  self->target_signatures_per_slot = fd_rng_ulong( rng );
  self->min_lamports_per_signature = fd_rng_ulong( rng );
  self->max_lamports_per_signature = fd_rng_ulong( rng );
  self->burn_percent = fd_rng_uchar( rng );
  return mem;
}

void *fd_slot_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_pair_t *self = (fd_slot_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_pair_t);
  fd_slot_pair_new(mem);
  self->slot = fd_rng_ulong( rng );
  self->val = fd_rng_ulong( rng );
  return mem;
}

void *fd_hard_forks_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_hard_forks_t *self = (fd_hard_forks_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_hard_forks_t);
  fd_hard_forks_new(mem);
  self->hard_forks_len = fd_rng_ulong( rng ) % 8;
  if( self->hard_forks_len ) {
    self->hard_forks = (fd_slot_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_SLOT_PAIR_FOOTPRINT*self->hard_forks_len;
    for( ulong i=0; i < self->hard_forks_len; i++ ) {
      fd_slot_pair_new( self->hard_forks + i );
      fd_slot_pair_generate( self->hard_forks + i, alloc_mem, rng );
    }
  } else
    self->hard_forks = NULL;
  return mem;
}

void *fd_inflation_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_inflation_t *self = (fd_inflation_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_inflation_t);
  fd_inflation_new(mem);
  self->initial = fd_rng_double_o( rng );
  self->terminal = fd_rng_double_o( rng );
  self->taper = fd_rng_double_o( rng );
  self->foundation = fd_rng_double_o( rng );
  self->foundation_term = fd_rng_double_o( rng );
  self->unused = fd_rng_double_o( rng );
  return mem;
}

void *fd_rent_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_rent_t *self = (fd_rent_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_rent_t);
  fd_rent_new(mem);
  self->lamports_per_uint8_year = fd_rng_ulong( rng );
  self->exemption_threshold = fd_rng_double_o( rng );
  self->burn_percent = fd_rng_uchar( rng );
  return mem;
}

void *fd_epoch_schedule_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_epoch_schedule_t *self = (fd_epoch_schedule_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_epoch_schedule_t);
  fd_epoch_schedule_new(mem);
  self->slots_per_epoch = fd_rng_ulong( rng );
  self->leader_schedule_slot_offset = fd_rng_ulong( rng );
  self->warmup = fd_rng_uchar( rng );
  self->first_normal_epoch = fd_rng_ulong( rng );
  self->first_normal_slot = fd_rng_ulong( rng );
  return mem;
}

void *fd_rent_collector_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_rent_collector_t *self = (fd_rent_collector_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_rent_collector_t);
  fd_rent_collector_new(mem);
  self->epoch = fd_rng_ulong( rng );
  fd_epoch_schedule_generate( &self->epoch_schedule, alloc_mem, rng );
  self->slots_per_year = fd_rng_double_o( rng );
  fd_rent_generate( &self->rent, alloc_mem, rng );
  return mem;
}

void *fd_stake_history_entry_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_history_entry_t *self = (fd_stake_history_entry_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_history_entry_t);
  fd_stake_history_entry_new(mem);
  self->epoch = fd_rng_ulong( rng );
  self->effective = fd_rng_ulong( rng );
  self->activating = fd_rng_ulong( rng );
  self->deactivating = fd_rng_ulong( rng );
  return mem;
}

void *fd_stake_history_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_history_t *self = (fd_stake_history_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_history_t);
  fd_stake_history_new(mem);
  self->fd_stake_history_len = fd_rng_ulong( rng ) % 8;
  self->fd_stake_history_size = 512;
  self->fd_stake_history_offset = 0;
  for( ulong i=0; i<self->fd_stake_history_len; i++ ) {
    fd_stake_history_entry_generate( self->fd_stake_history + i, alloc_mem, rng );
  }
  return mem;
}

void *fd_solana_account_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_solana_account_t *self = (fd_solana_account_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_solana_account_t);
  fd_solana_account_new(mem);
  self->lamports = fd_rng_ulong( rng );
  self->data_len = fd_rng_ulong( rng ) % 8;
  if( self->data_len ) {
    self->data = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->data_len;
    for( ulong i=0; i < self->data_len; ++i) { self->data[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->data = NULL;
  fd_pubkey_generate( &self->owner, alloc_mem, rng );
  self->executable = fd_rng_uchar( rng );
  self->rent_epoch = fd_rng_ulong( rng );
  return mem;
}

void *fd_vote_accounts_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_accounts_pair_t *self = (fd_vote_accounts_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_accounts_pair_t);
  fd_vote_accounts_pair_new(mem);
  fd_pubkey_generate( &self->key, alloc_mem, rng );
  self->stake = fd_rng_ulong( rng );
  fd_solana_account_generate( &self->value, alloc_mem, rng );
  return mem;
}

void *fd_vote_accounts_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_accounts_t *self = (fd_vote_accounts_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_accounts_t);
  fd_vote_accounts_new(mem);
  ulong vote_accounts_len = fd_rng_ulong( rng ) % 8;
  self->vote_accounts_pool = fd_vote_accounts_pair_t_map_join_new( alloc_mem, fd_ulong_max( vote_accounts_len, 15000 ) );
  self->vote_accounts_root = NULL;
  for( ulong i=0; i < vote_accounts_len; i++ ) {
    fd_vote_accounts_pair_t_mapnode_t * node = fd_vote_accounts_pair_t_map_acquire( self->vote_accounts_pool );
    fd_vote_accounts_pair_generate( &node->elem, alloc_mem, rng );
    fd_vote_accounts_pair_t_map_insert( self->vote_accounts_pool, &self->vote_accounts_root, node );
  }
  return mem;
}

void *fd_account_keys_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_account_keys_pair_t *self = (fd_account_keys_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_account_keys_pair_t);
  fd_account_keys_pair_new(mem);
  fd_pubkey_generate( &self->key, alloc_mem, rng );
  self->exists = fd_rng_uchar( rng );
  return mem;
}

void *fd_account_keys_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_account_keys_t *self = (fd_account_keys_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_account_keys_t);
  fd_account_keys_new(mem);
  ulong account_keys_len = fd_rng_ulong( rng ) % 8;
  self->account_keys_pool = fd_account_keys_pair_t_map_join_new( alloc_mem, fd_ulong_max( account_keys_len, 100000 ) );
  self->account_keys_root = NULL;
  for( ulong i=0; i < account_keys_len; i++ ) {
    fd_account_keys_pair_t_mapnode_t * node = fd_account_keys_pair_t_map_acquire( self->account_keys_pool );
    fd_account_keys_pair_generate( &node->elem, alloc_mem, rng );
    fd_account_keys_pair_t_map_insert( self->account_keys_pool, &self->account_keys_root, node );
  }
  return mem;
}

void *fd_stake_weight_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_weight_t *self = (fd_stake_weight_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_weight_t);
  fd_stake_weight_new(mem);
  fd_pubkey_generate( &self->key, alloc_mem, rng );
  self->stake = fd_rng_ulong( rng );
  return mem;
}

void *fd_stake_weights_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_weights_t *self = (fd_stake_weights_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_weights_t);
  fd_stake_weights_new(mem);
  ulong stake_weights_len = fd_rng_ulong( rng ) % 8;
  self->stake_weights_pool = fd_stake_weight_t_map_join_new( alloc_mem, stake_weights_len );
  self->stake_weights_root = NULL;
  for( ulong i=0; i < stake_weights_len; i++ ) {
    fd_stake_weight_t_mapnode_t * node = fd_stake_weight_t_map_acquire( self->stake_weights_pool );
    fd_stake_weight_generate( &node->elem, alloc_mem, rng );
    fd_stake_weight_t_map_insert( self->stake_weights_pool, &self->stake_weights_root, node );
  }
  return mem;
}

void *fd_delegation_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_delegation_t *self = (fd_delegation_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_delegation_t);
  fd_delegation_new(mem);
  fd_pubkey_generate( &self->voter_pubkey, alloc_mem, rng );
  self->stake = fd_rng_ulong( rng );
  self->activation_epoch = fd_rng_ulong( rng );
  self->deactivation_epoch = fd_rng_ulong( rng );
  self->warmup_cooldown_rate = fd_rng_double_o( rng );
  return mem;
}

void *fd_delegation_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_delegation_pair_t *self = (fd_delegation_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_delegation_pair_t);
  fd_delegation_pair_new(mem);
  fd_pubkey_generate( &self->account, alloc_mem, rng );
  fd_delegation_generate( &self->delegation, alloc_mem, rng );
  return mem;
}

void *fd_stake_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_t *self = (fd_stake_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_t);
  fd_stake_new(mem);
  fd_delegation_generate( &self->delegation, alloc_mem, rng );
  self->credits_observed = fd_rng_ulong( rng );
  return mem;
}

void *fd_stake_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_pair_t *self = (fd_stake_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_pair_t);
  fd_stake_pair_new(mem);
  fd_pubkey_generate( &self->account, alloc_mem, rng );
  fd_stake_generate( &self->stake, alloc_mem, rng );
  return mem;
}

void *fd_stakes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stakes_t *self = (fd_stakes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stakes_t);
  fd_stakes_new(mem);
  fd_vote_accounts_generate( &self->vote_accounts, alloc_mem, rng );
  ulong stake_delegations_len = fd_rng_ulong( rng ) % 8;
  self->stake_delegations_pool = fd_delegation_pair_t_map_join_new( alloc_mem, stake_delegations_len );
  self->stake_delegations_root = NULL;
  for( ulong i=0; i < stake_delegations_len; i++ ) {
    fd_delegation_pair_t_mapnode_t * node = fd_delegation_pair_t_map_acquire( self->stake_delegations_pool );
    fd_delegation_pair_generate( &node->elem, alloc_mem, rng );
    fd_delegation_pair_t_map_insert( self->stake_delegations_pool, &self->stake_delegations_root, node );
  }
  self->unused = fd_rng_ulong( rng );
  self->epoch = fd_rng_ulong( rng );
  fd_stake_history_generate( &self->stake_history, alloc_mem, rng );
  return mem;
}

void *fd_stakes_stake_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stakes_stake_t *self = (fd_stakes_stake_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stakes_stake_t);
  fd_stakes_stake_new(mem);
  fd_vote_accounts_generate( &self->vote_accounts, alloc_mem, rng );
  ulong stake_delegations_len = fd_rng_ulong( rng ) % 8;
  self->stake_delegations_pool = fd_stake_pair_t_map_join_new( alloc_mem, stake_delegations_len );
  self->stake_delegations_root = NULL;
  for( ulong i=0; i < stake_delegations_len; i++ ) {
    fd_stake_pair_t_mapnode_t * node = fd_stake_pair_t_map_acquire( self->stake_delegations_pool );
    fd_stake_pair_generate( &node->elem, alloc_mem, rng );
    fd_stake_pair_t_map_insert( self->stake_delegations_pool, &self->stake_delegations_root, node );
  }
  self->unused = fd_rng_ulong( rng );
  self->epoch = fd_rng_ulong( rng );
  fd_stake_history_generate( &self->stake_history, alloc_mem, rng );
  return mem;
}

void *fd_bank_incremental_snapshot_persistence_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bank_incremental_snapshot_persistence_t *self = (fd_bank_incremental_snapshot_persistence_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bank_incremental_snapshot_persistence_t);
  fd_bank_incremental_snapshot_persistence_new(mem);
  self->full_slot = fd_rng_ulong( rng );
  fd_hash_generate( &self->full_hash, alloc_mem, rng );
  self->full_capitalization = fd_rng_ulong( rng );
  fd_hash_generate( &self->incremental_hash, alloc_mem, rng );
  self->incremental_capitalization = fd_rng_ulong( rng );
  return mem;
}

void *fd_node_vote_accounts_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_node_vote_accounts_t *self = (fd_node_vote_accounts_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_node_vote_accounts_t);
  fd_node_vote_accounts_new(mem);
  self->vote_accounts_len = fd_rng_ulong( rng ) % 8;
  if( self->vote_accounts_len ) {
    self->vote_accounts = (fd_pubkey_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT*self->vote_accounts_len;
    for( ulong i=0; i < self->vote_accounts_len; i++ ) {
      fd_pubkey_new( self->vote_accounts + i );
      fd_pubkey_generate( self->vote_accounts + i, alloc_mem, rng );
    }
  } else
    self->vote_accounts = NULL;
  self->total_stake = fd_rng_ulong( rng );
  return mem;
}

void *fd_pubkey_node_vote_accounts_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_pubkey_node_vote_accounts_pair_t *self = (fd_pubkey_node_vote_accounts_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_pubkey_node_vote_accounts_pair_t);
  fd_pubkey_node_vote_accounts_pair_new(mem);
  fd_pubkey_generate( &self->key, alloc_mem, rng );
  fd_node_vote_accounts_generate( &self->value, alloc_mem, rng );
  return mem;
}

void *fd_pubkey_pubkey_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_pubkey_pubkey_pair_t *self = (fd_pubkey_pubkey_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_pubkey_pubkey_pair_t);
  fd_pubkey_pubkey_pair_new(mem);
  fd_pubkey_generate( &self->key, alloc_mem, rng );
  fd_pubkey_generate( &self->value, alloc_mem, rng );
  return mem;
}

void *fd_epoch_stakes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_epoch_stakes_t *self = (fd_epoch_stakes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_epoch_stakes_t);
  fd_epoch_stakes_new(mem);
  fd_stakes_generate( &self->stakes, alloc_mem, rng );
  self->total_stake = fd_rng_ulong( rng );
  self->node_id_to_vote_accounts_len = fd_rng_ulong( rng ) % 8;
  if( self->node_id_to_vote_accounts_len ) {
    self->node_id_to_vote_accounts = (fd_pubkey_node_vote_accounts_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->node_id_to_vote_accounts_len;
    for( ulong i=0; i < self->node_id_to_vote_accounts_len; i++ ) {
      fd_pubkey_node_vote_accounts_pair_new( self->node_id_to_vote_accounts + i );
      fd_pubkey_node_vote_accounts_pair_generate( self->node_id_to_vote_accounts + i, alloc_mem, rng );
    }
  } else
    self->node_id_to_vote_accounts = NULL;
  self->epoch_authorized_voters_len = fd_rng_ulong( rng ) % 8;
  if( self->epoch_authorized_voters_len ) {
    self->epoch_authorized_voters = (fd_pubkey_pubkey_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT*self->epoch_authorized_voters_len;
    for( ulong i=0; i < self->epoch_authorized_voters_len; i++ ) {
      fd_pubkey_pubkey_pair_new( self->epoch_authorized_voters + i );
      fd_pubkey_pubkey_pair_generate( self->epoch_authorized_voters + i, alloc_mem, rng );
    }
  } else
    self->epoch_authorized_voters = NULL;
  return mem;
}

void *fd_epoch_epoch_stakes_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_epoch_epoch_stakes_pair_t *self = (fd_epoch_epoch_stakes_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_epoch_epoch_stakes_pair_t);
  fd_epoch_epoch_stakes_pair_new(mem);
  self->key = fd_rng_ulong( rng );
  fd_epoch_stakes_generate( &self->value, alloc_mem, rng );
  return mem;
}

void *fd_pubkey_u64_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_pubkey_u64_pair_t *self = (fd_pubkey_u64_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_pubkey_u64_pair_t);
  fd_pubkey_u64_pair_new(mem);
  fd_pubkey_generate( &self->_0, alloc_mem, rng );
  self->_1 = fd_rng_ulong( rng );
  return mem;
}

void *fd_unused_accounts_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_unused_accounts_t *self = (fd_unused_accounts_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_unused_accounts_t);
  fd_unused_accounts_new(mem);
  self->unused1_len = fd_rng_ulong( rng ) % 8;
  if( self->unused1_len ) {
    self->unused1 = (fd_pubkey_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT*self->unused1_len;
    for( ulong i=0; i < self->unused1_len; i++ ) {
      fd_pubkey_new( self->unused1 + i );
      fd_pubkey_generate( self->unused1 + i, alloc_mem, rng );
    }
  } else
    self->unused1 = NULL;
  self->unused2_len = fd_rng_ulong( rng ) % 8;
  if( self->unused2_len ) {
    self->unused2 = (fd_pubkey_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT*self->unused2_len;
    for( ulong i=0; i < self->unused2_len; i++ ) {
      fd_pubkey_new( self->unused2 + i );
      fd_pubkey_generate( self->unused2 + i, alloc_mem, rng );
    }
  } else
    self->unused2 = NULL;
  self->unused3_len = fd_rng_ulong( rng ) % 8;
  if( self->unused3_len ) {
    self->unused3 = (fd_pubkey_u64_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_U64_PAIR_FOOTPRINT*self->unused3_len;
    for( ulong i=0; i < self->unused3_len; i++ ) {
      fd_pubkey_u64_pair_new( self->unused3 + i );
      fd_pubkey_u64_pair_generate( self->unused3 + i, alloc_mem, rng );
    }
  } else
    self->unused3 = NULL;
  return mem;
}

void *fd_versioned_bank_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_versioned_bank_t *self = (fd_versioned_bank_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_versioned_bank_t);
  fd_versioned_bank_new(mem);
  fd_block_hash_vec_generate( &self->blockhash_queue, alloc_mem, rng );
  self->ancestors_len = fd_rng_ulong( rng ) % 8;
  if( self->ancestors_len ) {
    self->ancestors = (fd_slot_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_SLOT_PAIR_FOOTPRINT*self->ancestors_len;
    for( ulong i=0; i < self->ancestors_len; i++ ) {
      fd_slot_pair_new( self->ancestors + i );
      fd_slot_pair_generate( self->ancestors + i, alloc_mem, rng );
    }
  } else
    self->ancestors = NULL;
  fd_hash_generate( &self->hash, alloc_mem, rng );
  fd_hash_generate( &self->parent_hash, alloc_mem, rng );
  self->parent_slot = fd_rng_ulong( rng );
  fd_hard_forks_generate( &self->hard_forks, alloc_mem, rng );
  self->transaction_count = fd_rng_ulong( rng );
  self->tick_height = fd_rng_ulong( rng );
  self->signature_count = fd_rng_ulong( rng );
  self->capitalization = fd_rng_ulong( rng );
  self->max_tick_height = fd_rng_ulong( rng );
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->hashes_per_tick = (ulong *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong);
      LLVMFuzzerMutate( (uchar *)self->hashes_per_tick, sizeof(ulong), sizeof(ulong) );
    }
    else {
    self->hashes_per_tick = NULL;
    }
  }
  self->ticks_per_slot = fd_rng_ulong( rng );
  self->ns_per_slot = fd_rng_uint128( rng );
  self->genesis_creation_time = fd_rng_ulong( rng );
  self->slots_per_year = fd_rng_double_o( rng );
  self->accounts_data_len = fd_rng_ulong( rng );
  self->slot = fd_rng_ulong( rng );
  self->epoch = fd_rng_ulong( rng );
  self->block_height = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->collector_id, alloc_mem, rng );
  self->collector_fees = fd_rng_ulong( rng );
  fd_fee_calculator_generate( &self->fee_calculator, alloc_mem, rng );
  fd_fee_rate_governor_generate( &self->fee_rate_governor, alloc_mem, rng );
  self->collected_rent = fd_rng_ulong( rng );
  fd_rent_collector_generate( &self->rent_collector, alloc_mem, rng );
  fd_epoch_schedule_generate( &self->epoch_schedule, alloc_mem, rng );
  fd_inflation_generate( &self->inflation, alloc_mem, rng );
  fd_stakes_generate( &self->stakes, alloc_mem, rng );
  fd_unused_accounts_generate( &self->unused_accounts, alloc_mem, rng );
  self->epoch_stakes_len = fd_rng_ulong( rng ) % 8;
  if( self->epoch_stakes_len ) {
    self->epoch_stakes = (fd_epoch_epoch_stakes_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_EPOCH_EPOCH_STAKES_PAIR_FOOTPRINT*self->epoch_stakes_len;
    for( ulong i=0; i < self->epoch_stakes_len; i++ ) {
      fd_epoch_epoch_stakes_pair_new( self->epoch_stakes + i );
      fd_epoch_epoch_stakes_pair_generate( self->epoch_stakes + i, alloc_mem, rng );
    }
  } else
    self->epoch_stakes = NULL;
  self->is_delta = fd_rng_uchar( rng );
  return mem;
}

void *fd_bank_hash_stats_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bank_hash_stats_t *self = (fd_bank_hash_stats_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bank_hash_stats_t);
  fd_bank_hash_stats_new(mem);
  self->num_updated_accounts = fd_rng_ulong( rng );
  self->num_removed_accounts = fd_rng_ulong( rng );
  self->num_lamports_stored = fd_rng_ulong( rng );
  self->total_data_len = fd_rng_ulong( rng );
  self->num_executable_accounts = fd_rng_ulong( rng );
  return mem;
}

void *fd_bank_hash_info_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bank_hash_info_t *self = (fd_bank_hash_info_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bank_hash_info_t);
  fd_bank_hash_info_new(mem);
  fd_hash_generate( &self->accounts_delta_hash, alloc_mem, rng );
  fd_hash_generate( &self->accounts_hash, alloc_mem, rng );
  fd_bank_hash_stats_generate( &self->stats, alloc_mem, rng );
  return mem;
}

void *fd_slot_map_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_map_pair_t *self = (fd_slot_map_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_map_pair_t);
  fd_slot_map_pair_new(mem);
  self->slot = fd_rng_ulong( rng );
  fd_hash_generate( &self->hash, alloc_mem, rng );
  return mem;
}

void *fd_snapshot_acc_vec_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_snapshot_acc_vec_t *self = (fd_snapshot_acc_vec_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_snapshot_acc_vec_t);
  fd_snapshot_acc_vec_new(mem);
  self->id = fd_rng_ulong( rng );
  self->file_sz = fd_rng_ulong( rng );
  return mem;
}

void *fd_snapshot_slot_acc_vecs_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_snapshot_slot_acc_vecs_t *self = (fd_snapshot_slot_acc_vecs_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_snapshot_slot_acc_vecs_t);
  fd_snapshot_slot_acc_vecs_new(mem);
  self->slot = fd_rng_ulong( rng );
  self->account_vecs_len = fd_rng_ulong( rng ) % 8;
  if( self->account_vecs_len ) {
    self->account_vecs = (fd_snapshot_acc_vec_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_SNAPSHOT_ACC_VEC_FOOTPRINT*self->account_vecs_len;
    for( ulong i=0; i < self->account_vecs_len; i++ ) {
      fd_snapshot_acc_vec_new( self->account_vecs + i );
      fd_snapshot_acc_vec_generate( self->account_vecs + i, alloc_mem, rng );
    }
  } else
    self->account_vecs = NULL;
  return mem;
}

void fd_reward_type_inner_generate( fd_reward_type_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
}
void *fd_reward_type_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_reward_type_t *self = (fd_reward_type_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_reward_type_t);
  fd_reward_type_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 4;
  fd_reward_type_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_solana_accounts_db_fields_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_solana_accounts_db_fields_t *self = (fd_solana_accounts_db_fields_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_solana_accounts_db_fields_t);
  fd_solana_accounts_db_fields_new(mem);
  self->storages_len = fd_rng_ulong( rng ) % 8;
  if( self->storages_len ) {
    self->storages = (fd_snapshot_slot_acc_vecs_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_SNAPSHOT_SLOT_ACC_VECS_FOOTPRINT*self->storages_len;
    for( ulong i=0; i < self->storages_len; i++ ) {
      fd_snapshot_slot_acc_vecs_new( self->storages + i );
      fd_snapshot_slot_acc_vecs_generate( self->storages + i, alloc_mem, rng );
    }
  } else
    self->storages = NULL;
  self->version = fd_rng_ulong( rng );
  self->slot = fd_rng_ulong( rng );
  fd_bank_hash_info_generate( &self->bank_hash_info, alloc_mem, rng );
  self->historical_roots_len = fd_rng_ulong( rng ) % 8;
  if( self->historical_roots_len ) {
    self->historical_roots = (ulong *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong)*self->historical_roots_len;
    LLVMFuzzerMutate( (uchar *) self->historical_roots, sizeof(ulong)*self->historical_roots_len, sizeof(ulong)*self->historical_roots_len );
  } else
    self->historical_roots = NULL;
  self->historical_roots_with_hash_len = fd_rng_ulong( rng ) % 8;
  if( self->historical_roots_with_hash_len ) {
    self->historical_roots_with_hash = (fd_slot_map_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_SLOT_MAP_PAIR_FOOTPRINT*self->historical_roots_with_hash_len;
    for( ulong i=0; i < self->historical_roots_with_hash_len; i++ ) {
      fd_slot_map_pair_new( self->historical_roots_with_hash + i );
      fd_slot_map_pair_generate( self->historical_roots_with_hash + i, alloc_mem, rng );
    }
  } else
    self->historical_roots_with_hash = NULL;
  return mem;
}

void *fd_versioned_epoch_stakes_current_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_versioned_epoch_stakes_current_t *self = (fd_versioned_epoch_stakes_current_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_versioned_epoch_stakes_current_t);
  fd_versioned_epoch_stakes_current_new(mem);
  fd_stakes_stake_generate( &self->stakes, alloc_mem, rng );
  self->total_stake = fd_rng_ulong( rng );
  self->node_id_to_vote_accounts_len = fd_rng_ulong( rng ) % 8;
  if( self->node_id_to_vote_accounts_len ) {
    self->node_id_to_vote_accounts = (fd_pubkey_node_vote_accounts_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->node_id_to_vote_accounts_len;
    for( ulong i=0; i < self->node_id_to_vote_accounts_len; i++ ) {
      fd_pubkey_node_vote_accounts_pair_new( self->node_id_to_vote_accounts + i );
      fd_pubkey_node_vote_accounts_pair_generate( self->node_id_to_vote_accounts + i, alloc_mem, rng );
    }
  } else
    self->node_id_to_vote_accounts = NULL;
  self->epoch_authorized_voters_len = fd_rng_ulong( rng ) % 8;
  if( self->epoch_authorized_voters_len ) {
    self->epoch_authorized_voters = (fd_pubkey_pubkey_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT*self->epoch_authorized_voters_len;
    for( ulong i=0; i < self->epoch_authorized_voters_len; i++ ) {
      fd_pubkey_pubkey_pair_new( self->epoch_authorized_voters + i );
      fd_pubkey_pubkey_pair_generate( self->epoch_authorized_voters + i, alloc_mem, rng );
    }
  } else
    self->epoch_authorized_voters = NULL;
  return mem;
}

void fd_versioned_epoch_stakes_inner_generate( fd_versioned_epoch_stakes_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_versioned_epoch_stakes_current_generate( &self->Current, alloc_mem, rng );
    break;
  }
  }
}
void *fd_versioned_epoch_stakes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_versioned_epoch_stakes_t *self = (fd_versioned_epoch_stakes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_versioned_epoch_stakes_t);
  fd_versioned_epoch_stakes_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 1;
  fd_versioned_epoch_stakes_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_versioned_epoch_stakes_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_versioned_epoch_stakes_pair_t *self = (fd_versioned_epoch_stakes_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_versioned_epoch_stakes_pair_t);
  fd_versioned_epoch_stakes_pair_new(mem);
  self->epoch = fd_rng_ulong( rng );
  fd_versioned_epoch_stakes_generate( &self->val, alloc_mem, rng );
  return mem;
}

void *fd_reward_info_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_reward_info_t *self = (fd_reward_info_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_reward_info_t);
  fd_reward_info_new(mem);
  fd_reward_type_generate( &self->reward_type, alloc_mem, rng );
  self->lamports = fd_rng_ulong( rng );
  self->post_balance = fd_rng_ulong( rng );
  self->commission = fd_rng_ulong( rng );
  return mem;
}

void *fd_slot_lthash_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_lthash_t *self = (fd_slot_lthash_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_lthash_t);
  fd_slot_lthash_new(mem);
  LLVMFuzzerMutate( &self->lthash[0], sizeof(self->lthash), sizeof(self->lthash) );
  return mem;
}

void *fd_solana_manifest_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_solana_manifest_t *self = (fd_solana_manifest_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_solana_manifest_t);
  fd_solana_manifest_new(mem);
  fd_versioned_bank_generate( &self->bank, alloc_mem, rng );
  fd_solana_accounts_db_fields_generate( &self->accounts_db, alloc_mem, rng );
  self->lamports_per_signature = fd_rng_ulong( rng );
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->bank_incremental_snapshot_persistence = (fd_bank_incremental_snapshot_persistence_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FOOTPRINT;
      fd_bank_incremental_snapshot_persistence_new( self->bank_incremental_snapshot_persistence );
      fd_bank_incremental_snapshot_persistence_generate( self->bank_incremental_snapshot_persistence, alloc_mem, rng );
    }
    else {
    self->bank_incremental_snapshot_persistence = NULL;
    }
  }
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->epoch_account_hash = (fd_hash_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_HASH_FOOTPRINT;
      fd_hash_new( self->epoch_account_hash );
      fd_hash_generate( self->epoch_account_hash, alloc_mem, rng );
    }
    else {
    self->epoch_account_hash = NULL;
    }
  }
  self->versioned_epoch_stakes_len = fd_rng_ulong( rng ) % 8;
  if( self->versioned_epoch_stakes_len ) {
    self->versioned_epoch_stakes = (fd_versioned_epoch_stakes_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_VERSIONED_EPOCH_STAKES_PAIR_FOOTPRINT*self->versioned_epoch_stakes_len;
    for( ulong i=0; i < self->versioned_epoch_stakes_len; i++ ) {
      fd_versioned_epoch_stakes_pair_new( self->versioned_epoch_stakes + i );
      fd_versioned_epoch_stakes_pair_generate( self->versioned_epoch_stakes + i, alloc_mem, rng );
    }
  } else
    self->versioned_epoch_stakes = NULL;
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->lthash = (fd_slot_lthash_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_SLOT_LTHASH_FOOTPRINT;
      fd_slot_lthash_new( self->lthash );
      fd_slot_lthash_generate( self->lthash, alloc_mem, rng );
    }
    else {
    self->lthash = NULL;
    }
  }
  return mem;
}

void *fd_rust_duration_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_rust_duration_t *self = (fd_rust_duration_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_rust_duration_t);
  fd_rust_duration_new(mem);
  self->seconds = fd_rng_ulong( rng );
  self->nanoseconds = fd_rng_uint( rng );
  return mem;
}

void *fd_poh_config_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_poh_config_t *self = (fd_poh_config_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_poh_config_t);
  fd_poh_config_new(mem);
  fd_rust_duration_generate( &self->target_tick_duration, alloc_mem, rng );
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->target_tick_count = (ulong *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong);
      LLVMFuzzerMutate( (uchar *)self->target_tick_count, sizeof(ulong), sizeof(ulong) );
    }
    else {
    self->target_tick_count = NULL;
    }
  }
  {
    self->has_hashes_per_tick = fd_rng_uchar( rng ) % 2;
    if( self->has_hashes_per_tick ) {
      LLVMFuzzerMutate( (uchar *)&(self->hashes_per_tick), sizeof(ulong), sizeof(ulong) );
    }
  }
  return mem;
}

void *fd_string_pubkey_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_string_pubkey_pair_t *self = (fd_string_pubkey_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_string_pubkey_pair_t);
  fd_string_pubkey_pair_new(mem);
  self->string_len = fd_rng_ulong( rng ) % 8;
  if( self->string_len ) {
    self->string = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->string_len;
    for( ulong i=0; i < self->string_len; ++i) { self->string[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->string = NULL;
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  return mem;
}

void *fd_pubkey_account_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_pubkey_account_pair_t *self = (fd_pubkey_account_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_pubkey_account_pair_t);
  fd_pubkey_account_pair_new(mem);
  fd_pubkey_generate( &self->key, alloc_mem, rng );
  fd_solana_account_generate( &self->account, alloc_mem, rng );
  return mem;
}

void *fd_genesis_solana_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_genesis_solana_t *self = (fd_genesis_solana_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_genesis_solana_t);
  fd_genesis_solana_new(mem);
  self->creation_time = fd_rng_ulong( rng );
  self->accounts_len = fd_rng_ulong( rng ) % 8;
  if( self->accounts_len ) {
    self->accounts = (fd_pubkey_account_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT*self->accounts_len;
    for( ulong i=0; i < self->accounts_len; i++ ) {
      fd_pubkey_account_pair_new( self->accounts + i );
      fd_pubkey_account_pair_generate( self->accounts + i, alloc_mem, rng );
    }
  } else
    self->accounts = NULL;
  self->native_instruction_processors_len = fd_rng_ulong( rng ) % 8;
  if( self->native_instruction_processors_len ) {
    self->native_instruction_processors = (fd_string_pubkey_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_STRING_PUBKEY_PAIR_FOOTPRINT*self->native_instruction_processors_len;
    for( ulong i=0; i < self->native_instruction_processors_len; i++ ) {
      fd_string_pubkey_pair_new( self->native_instruction_processors + i );
      fd_string_pubkey_pair_generate( self->native_instruction_processors + i, alloc_mem, rng );
    }
  } else
    self->native_instruction_processors = NULL;
  self->rewards_pools_len = fd_rng_ulong( rng ) % 8;
  if( self->rewards_pools_len ) {
    self->rewards_pools = (fd_pubkey_account_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT*self->rewards_pools_len;
    for( ulong i=0; i < self->rewards_pools_len; i++ ) {
      fd_pubkey_account_pair_new( self->rewards_pools + i );
      fd_pubkey_account_pair_generate( self->rewards_pools + i, alloc_mem, rng );
    }
  } else
    self->rewards_pools = NULL;
  self->ticks_per_slot = fd_rng_ulong( rng );
  self->unused = fd_rng_ulong( rng );
  fd_poh_config_generate( &self->poh_config, alloc_mem, rng );
  self->__backwards_compat_with_v0_23 = fd_rng_ulong( rng );
  fd_fee_rate_governor_generate( &self->fee_rate_governor, alloc_mem, rng );
  fd_rent_generate( &self->rent, alloc_mem, rng );
  fd_inflation_generate( &self->inflation, alloc_mem, rng );
  fd_epoch_schedule_generate( &self->epoch_schedule, alloc_mem, rng );
  self->cluster_type = fd_rng_uint( rng );
  return mem;
}

void *fd_sol_sysvar_clock_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_sol_sysvar_clock_t *self = (fd_sol_sysvar_clock_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_sol_sysvar_clock_t);
  fd_sol_sysvar_clock_new(mem);
  self->slot = fd_rng_ulong( rng );
  self->epoch_start_timestamp = fd_rng_long( rng );
  self->epoch = fd_rng_ulong( rng );
  self->leader_schedule_epoch = fd_rng_ulong( rng );
  self->unix_timestamp = fd_rng_long( rng );
  return mem;
}

void *fd_sol_sysvar_last_restart_slot_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_sol_sysvar_last_restart_slot_t *self = (fd_sol_sysvar_last_restart_slot_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_sol_sysvar_last_restart_slot_t);
  fd_sol_sysvar_last_restart_slot_new(mem);
  self->slot = fd_rng_ulong( rng );
  return mem;
}

void *fd_vote_lockout_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_lockout_t *self = (fd_vote_lockout_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_lockout_t);
  fd_vote_lockout_new(mem);
  self->slot = fd_rng_ulong( rng );
  self->confirmation_count = fd_rng_uint( rng );
  return mem;
}

void *fd_lockout_offset_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_lockout_offset_t *self = (fd_lockout_offset_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_lockout_offset_t);
  fd_lockout_offset_new(mem);
  self->offset = fd_rng_ulong( rng );
  self->confirmation_count = fd_rng_uchar( rng );
  return mem;
}

void *fd_vote_authorized_voter_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_authorized_voter_t *self = (fd_vote_authorized_voter_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_authorized_voter_t);
  fd_vote_authorized_voter_new(mem);
  self->epoch = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->parent = fd_rng_ulong( rng );
  self->left = fd_rng_ulong( rng );
  self->right = fd_rng_ulong( rng );
  self->prio = fd_rng_ulong( rng );
  return mem;
}

void *fd_vote_prior_voter_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_prior_voter_t *self = (fd_vote_prior_voter_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_prior_voter_t);
  fd_vote_prior_voter_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->epoch_start = fd_rng_ulong( rng );
  self->epoch_end = fd_rng_ulong( rng );
  return mem;
}

void *fd_vote_prior_voter_0_23_5_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_prior_voter_0_23_5_t *self = (fd_vote_prior_voter_0_23_5_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_prior_voter_0_23_5_t);
  fd_vote_prior_voter_0_23_5_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->epoch_start = fd_rng_ulong( rng );
  self->epoch_end = fd_rng_ulong( rng );
  self->slot = fd_rng_ulong( rng );
  return mem;
}

void *fd_vote_epoch_credits_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_epoch_credits_t *self = (fd_vote_epoch_credits_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_epoch_credits_t);
  fd_vote_epoch_credits_new(mem);
  self->epoch = fd_rng_ulong( rng );
  self->credits = fd_rng_ulong( rng );
  self->prev_credits = fd_rng_ulong( rng );
  return mem;
}

void *fd_vote_block_timestamp_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_block_timestamp_t *self = (fd_vote_block_timestamp_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_block_timestamp_t);
  fd_vote_block_timestamp_new(mem);
  self->slot = fd_rng_ulong( rng );
  self->timestamp = fd_rng_long( rng );
  return mem;
}

void *fd_vote_prior_voters_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_prior_voters_t *self = (fd_vote_prior_voters_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_prior_voters_t);
  fd_vote_prior_voters_new(mem);
  for( ulong i=0; i<32; i++ ) {
    fd_vote_prior_voter_generate( self->buf + i, alloc_mem, rng );
  }
  self->idx = fd_rng_ulong( rng );
  self->is_empty = fd_rng_uchar( rng );
  return mem;
}

void *fd_vote_prior_voters_0_23_5_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_prior_voters_0_23_5_t *self = (fd_vote_prior_voters_0_23_5_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_prior_voters_0_23_5_t);
  fd_vote_prior_voters_0_23_5_new(mem);
  for( ulong i=0; i<32; i++ ) {
    fd_vote_prior_voter_0_23_5_generate( self->buf + i, alloc_mem, rng );
  }
  self->idx = fd_rng_ulong( rng );
  return mem;
}

void *fd_landed_vote_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_landed_vote_t *self = (fd_landed_vote_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_landed_vote_t);
  fd_landed_vote_new(mem);
  self->latency = fd_rng_uchar( rng );
  fd_vote_lockout_generate( &self->lockout, alloc_mem, rng );
  return mem;
}

void *fd_vote_state_0_23_5_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_state_0_23_5_t *self = (fd_vote_state_0_23_5_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_state_0_23_5_t);
  fd_vote_state_0_23_5_new(mem);
  fd_pubkey_generate( &self->node_pubkey, alloc_mem, rng );
  fd_pubkey_generate( &self->authorized_voter, alloc_mem, rng );
  self->authorized_voter_epoch = fd_rng_ulong( rng );
  fd_vote_prior_voters_0_23_5_generate( &self->prior_voters, alloc_mem, rng );
  fd_pubkey_generate( &self->authorized_withdrawer, alloc_mem, rng );
  self->commission = fd_rng_uchar( rng );
  ulong votes_len = fd_rng_ulong( rng ) % 8;
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  self->votes = deq_fd_vote_lockout_t_join_new( alloc_mem, votes_max );
  for( ulong i=0; i < votes_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->votes );
    fd_vote_lockout_generate( elem, alloc_mem, rng );
  }
  {
    self->has_root_slot = fd_rng_uchar( rng ) % 2;
    if( self->has_root_slot ) {
      LLVMFuzzerMutate( (uchar *)&(self->root_slot), sizeof(ulong), sizeof(ulong) );
    }
  }
  ulong epoch_credits_len = fd_rng_ulong( rng ) % 8;
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_join_new( alloc_mem, epoch_credits_max );
  for( ulong i=0; i < epoch_credits_len; i++ ) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy( self->epoch_credits );
    fd_vote_epoch_credits_generate( elem, alloc_mem, rng );
  }
  fd_vote_block_timestamp_generate( &self->last_timestamp, alloc_mem, rng );
  return mem;
}

void *fd_vote_authorized_voters_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_authorized_voters_t *self = (fd_vote_authorized_voters_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_authorized_voters_t);
  fd_vote_authorized_voters_new(mem);
  ulong fd_vote_authorized_voters_treap_len = fd_rng_ulong( rng ) % 8;
  ulong fd_vote_authorized_voters_treap_max = fd_ulong_max( fd_vote_authorized_voters_treap_len, FD_VOTE_AUTHORIZED_VOTERS_MIN );
  self->pool = fd_vote_authorized_voters_pool_join_new( alloc_mem, fd_vote_authorized_voters_treap_max );
  self->treap = fd_vote_authorized_voters_treap_join_new( alloc_mem, fd_vote_authorized_voters_treap_max );
  for( ulong i=0; i < fd_vote_authorized_voters_treap_len; i++ ) {
    fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( self->pool );
    fd_vote_authorized_voter_generate( ele, alloc_mem, rng );
    fd_vote_authorized_voter_t * repeated_entry = fd_vote_authorized_voters_treap_ele_query( self->treap, ele->epoch, self->pool );
    if( repeated_entry ) {
        fd_vote_authorized_voters_treap_ele_remove( self->treap, repeated_entry, self->pool ); // Remove the element before inserting it back to avoid duplication
        fd_vote_authorized_voters_pool_ele_release( self->pool, repeated_entry );
    }
    fd_vote_authorized_voters_treap_ele_insert( self->treap, ele, self->pool ); /* this cannot fail */
  }
  return mem;
}

void *fd_vote_state_1_14_11_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_state_1_14_11_t *self = (fd_vote_state_1_14_11_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_state_1_14_11_t);
  fd_vote_state_1_14_11_new(mem);
  fd_pubkey_generate( &self->node_pubkey, alloc_mem, rng );
  fd_pubkey_generate( &self->authorized_withdrawer, alloc_mem, rng );
  self->commission = fd_rng_uchar( rng );
  ulong votes_len = fd_rng_ulong( rng ) % 8;
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  self->votes = deq_fd_vote_lockout_t_join_new( alloc_mem, votes_max );
  for( ulong i=0; i < votes_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->votes );
    fd_vote_lockout_generate( elem, alloc_mem, rng );
  }
  {
    self->has_root_slot = fd_rng_uchar( rng ) % 2;
    if( self->has_root_slot ) {
      LLVMFuzzerMutate( (uchar *)&(self->root_slot), sizeof(ulong), sizeof(ulong) );
    }
  }
  fd_vote_authorized_voters_generate( &self->authorized_voters, alloc_mem, rng );
  fd_vote_prior_voters_generate( &self->prior_voters, alloc_mem, rng );
  ulong epoch_credits_len = fd_rng_ulong( rng ) % 8;
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_join_new( alloc_mem, epoch_credits_max );
  for( ulong i=0; i < epoch_credits_len; i++ ) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy( self->epoch_credits );
    fd_vote_epoch_credits_generate( elem, alloc_mem, rng );
  }
  fd_vote_block_timestamp_generate( &self->last_timestamp, alloc_mem, rng );
  return mem;
}

void *fd_vote_state_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_state_t *self = (fd_vote_state_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_state_t);
  fd_vote_state_new(mem);
  fd_pubkey_generate( &self->node_pubkey, alloc_mem, rng );
  fd_pubkey_generate( &self->authorized_withdrawer, alloc_mem, rng );
  self->commission = fd_rng_uchar( rng );
  ulong votes_len = fd_rng_ulong( rng ) % 8;
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  self->votes = deq_fd_landed_vote_t_join_new( alloc_mem, votes_max );
  for( ulong i=0; i < votes_len; i++ ) {
    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( self->votes );
    fd_landed_vote_generate( elem, alloc_mem, rng );
  }
  {
    self->has_root_slot = fd_rng_uchar( rng ) % 2;
    if( self->has_root_slot ) {
      LLVMFuzzerMutate( (uchar *)&(self->root_slot), sizeof(ulong), sizeof(ulong) );
    }
  }
  fd_vote_authorized_voters_generate( &self->authorized_voters, alloc_mem, rng );
  fd_vote_prior_voters_generate( &self->prior_voters, alloc_mem, rng );
  ulong epoch_credits_len = fd_rng_ulong( rng ) % 8;
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_join_new( alloc_mem, epoch_credits_max );
  for( ulong i=0; i < epoch_credits_len; i++ ) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy( self->epoch_credits );
    fd_vote_epoch_credits_generate( elem, alloc_mem, rng );
  }
  fd_vote_block_timestamp_generate( &self->last_timestamp, alloc_mem, rng );
  return mem;
}

void fd_vote_state_versioned_inner_generate( fd_vote_state_versioned_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_vote_state_0_23_5_generate( &self->v0_23_5, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_vote_state_1_14_11_generate( &self->v1_14_11, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_vote_state_generate( &self->current, alloc_mem, rng );
    break;
  }
  }
}
void *fd_vote_state_versioned_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_state_versioned_t *self = (fd_vote_state_versioned_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_state_versioned_t);
  fd_vote_state_versioned_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 3;
  fd_vote_state_versioned_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_vote_state_update_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_state_update_t *self = (fd_vote_state_update_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_state_update_t);
  fd_vote_state_update_new(mem);
  ulong lockouts_len = fd_rng_ulong( rng ) % 8;
  ulong lockouts_max = fd_ulong_max( lockouts_len, 32 );
  self->lockouts = deq_fd_vote_lockout_t_join_new( alloc_mem, lockouts_max );
  for( ulong i=0; i < lockouts_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->lockouts );
    fd_vote_lockout_generate( elem, alloc_mem, rng );
  }
  {
    self->has_root = fd_rng_uchar( rng ) % 2;
    if( self->has_root ) {
      LLVMFuzzerMutate( (uchar *)&(self->root), sizeof(ulong), sizeof(ulong) );
    }
  }
  fd_hash_generate( &self->hash, alloc_mem, rng );
  {
    self->has_timestamp = fd_rng_uchar( rng ) % 2;
    if( self->has_timestamp ) {
      LLVMFuzzerMutate( (uchar *)&(self->timestamp), sizeof(long), sizeof(long) );
    }
  }
  return mem;
}

void *fd_compact_vote_state_update_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_compact_vote_state_update_t *self = (fd_compact_vote_state_update_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_compact_vote_state_update_t);
  fd_compact_vote_state_update_new(mem);
  self->root = fd_rng_ulong( rng );
  self->lockouts_len = fd_rng_ulong( rng ) % 8;
  if( self->lockouts_len ) {
    self->lockouts = (fd_lockout_offset_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_LOCKOUT_OFFSET_FOOTPRINT*self->lockouts_len;
    for( ulong i=0; i < self->lockouts_len; i++ ) {
      fd_lockout_offset_new( self->lockouts + i );
      fd_lockout_offset_generate( self->lockouts + i, alloc_mem, rng );
    }
  } else
    self->lockouts = NULL;
  fd_hash_generate( &self->hash, alloc_mem, rng );
  {
    self->has_timestamp = fd_rng_uchar( rng ) % 2;
    if( self->has_timestamp ) {
      LLVMFuzzerMutate( (uchar *)&(self->timestamp), sizeof(long), sizeof(long) );
    }
  }
  return mem;
}

void *fd_compact_vote_state_update_switch_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_compact_vote_state_update_switch_t *self = (fd_compact_vote_state_update_switch_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_compact_vote_state_update_switch_t);
  fd_compact_vote_state_update_switch_new(mem);
  fd_compact_vote_state_update_generate( &self->compact_vote_state_update, alloc_mem, rng );
  fd_hash_generate( &self->hash, alloc_mem, rng );
  return mem;
}

void *fd_compact_tower_sync_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_compact_tower_sync_t *self = (fd_compact_tower_sync_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_compact_tower_sync_t);
  fd_compact_tower_sync_new(mem);
  self->root = fd_rng_ulong( rng );
  ulong lockout_offsets_len = fd_rng_ulong( rng ) % 8;
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  self->lockout_offsets = deq_fd_lockout_offset_t_join_new( alloc_mem, lockout_offsets_max );
  for( ulong i=0; i < lockout_offsets_len; i++ ) {
    fd_lockout_offset_t * elem = deq_fd_lockout_offset_t_push_tail_nocopy( self->lockout_offsets );
    fd_lockout_offset_generate( elem, alloc_mem, rng );
  }
  fd_hash_generate( &self->hash, alloc_mem, rng );
  {
    self->has_timestamp = fd_rng_uchar( rng ) % 2;
    if( self->has_timestamp ) {
      LLVMFuzzerMutate( (uchar *)&(self->timestamp), sizeof(long), sizeof(long) );
    }
  }
  fd_hash_generate( &self->block_id, alloc_mem, rng );
  return mem;
}


void *fd_tower_sync_switch_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_tower_sync_switch_t *self = (fd_tower_sync_switch_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_tower_sync_switch_t);
  fd_tower_sync_switch_new(mem);
  fd_hash_generate( &self->hash, alloc_mem, rng );
  return mem;
}

void *fd_slot_history_inner_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_history_inner_t *self = (fd_slot_history_inner_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_history_inner_t);
  fd_slot_history_inner_new(mem);
  self->blocks_len = fd_rng_ulong( rng ) % 8;
  if( self->blocks_len ) {
    self->blocks = (ulong *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong)*self->blocks_len;
    LLVMFuzzerMutate( (uchar *) self->blocks, sizeof(ulong)*self->blocks_len, sizeof(ulong)*self->blocks_len );
  } else
    self->blocks = NULL;
  return mem;
}

void *fd_slot_history_bitvec_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_history_bitvec_t *self = (fd_slot_history_bitvec_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_history_bitvec_t);
  fd_slot_history_bitvec_new(mem);
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->bits = (fd_slot_history_inner_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_SLOT_HISTORY_INNER_FOOTPRINT;
      fd_slot_history_inner_new( self->bits );
      fd_slot_history_inner_generate( self->bits, alloc_mem, rng );
    }
    else {
    self->bits = NULL;
    }
  }
  self->len = fd_rng_ulong( rng );
  return mem;
}

void *fd_slot_history_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_history_t *self = (fd_slot_history_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_history_t);
  fd_slot_history_new(mem);
  fd_slot_history_bitvec_generate( &self->bits, alloc_mem, rng );
  self->next_slot = fd_rng_ulong( rng );
  return mem;
}

void *fd_slot_hash_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_hash_t *self = (fd_slot_hash_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_hash_t);
  fd_slot_hash_new(mem);
  self->slot = fd_rng_ulong( rng );
  fd_hash_generate( &self->hash, alloc_mem, rng );
  return mem;
}

void *fd_slot_hashes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_hashes_t *self = (fd_slot_hashes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_hashes_t);
  fd_slot_hashes_new(mem);
  ulong hashes_len = fd_rng_ulong( rng ) % 8;
  ulong hashes_max = fd_ulong_max( hashes_len, 512 );
  self->hashes = deq_fd_slot_hash_t_join_new( alloc_mem, hashes_max );
  for( ulong i=0; i < hashes_len; i++ ) {
    fd_slot_hash_t * elem = deq_fd_slot_hash_t_push_tail_nocopy( self->hashes );
    fd_slot_hash_generate( elem, alloc_mem, rng );
  }
  return mem;
}

void *fd_block_block_hash_entry_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_block_block_hash_entry_t *self = (fd_block_block_hash_entry_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_block_block_hash_entry_t);
  fd_block_block_hash_entry_new(mem);
  fd_hash_generate( &self->blockhash, alloc_mem, rng );
  fd_fee_calculator_generate( &self->fee_calculator, alloc_mem, rng );
  return mem;
}

void *fd_recent_block_hashes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_recent_block_hashes_t *self = (fd_recent_block_hashes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_recent_block_hashes_t);
  fd_recent_block_hashes_new(mem);
  ulong hashes_len = fd_rng_ulong( rng ) % 8;
  ulong hashes_max = fd_ulong_max( hashes_len, 151 );
  self->hashes = deq_fd_block_block_hash_entry_t_join_new( alloc_mem, hashes_max );
  for( ulong i=0; i < hashes_len; i++ ) {
    fd_block_block_hash_entry_t * elem = deq_fd_block_block_hash_entry_t_push_tail_nocopy( self->hashes );
    fd_block_block_hash_entry_generate( elem, alloc_mem, rng );
  }
  return mem;
}

void *fd_slot_meta_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_meta_t *self = (fd_slot_meta_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_meta_t);
  fd_slot_meta_new(mem);
  self->slot = fd_rng_ulong( rng );
  self->consumed = fd_rng_ulong( rng );
  self->received = fd_rng_ulong( rng );
  self->first_shred_timestamp = fd_rng_long( rng );
  self->last_index = fd_rng_ulong( rng );
  self->parent_slot = fd_rng_ulong( rng );
  self->next_slot_len = fd_rng_ulong( rng ) % 8;
  if( self->next_slot_len ) {
    self->next_slot = (ulong *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong)*self->next_slot_len;
    LLVMFuzzerMutate( (uchar *) self->next_slot, sizeof(ulong)*self->next_slot_len, sizeof(ulong)*self->next_slot_len );
  } else
    self->next_slot = NULL;
  self->is_connected = fd_rng_uchar( rng );
  self->entry_end_indexes_len = fd_rng_ulong( rng ) % 8;
  if( self->entry_end_indexes_len ) {
    self->entry_end_indexes = (uint *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + sizeof(uint)*self->entry_end_indexes_len;
    LLVMFuzzerMutate( (uchar *) self->entry_end_indexes, sizeof(uint)*self->entry_end_indexes_len, sizeof(uint)*self->entry_end_indexes_len );
  } else
    self->entry_end_indexes = NULL;
  return mem;
}

void *fd_clock_timestamp_vote_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_clock_timestamp_vote_t *self = (fd_clock_timestamp_vote_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_clock_timestamp_vote_t);
  fd_clock_timestamp_vote_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->timestamp = fd_rng_long( rng );
  self->slot = fd_rng_ulong( rng );
  return mem;
}

void *fd_clock_timestamp_votes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_clock_timestamp_votes_t *self = (fd_clock_timestamp_votes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_clock_timestamp_votes_t);
  fd_clock_timestamp_votes_new(mem);
  ulong votes_len = fd_rng_ulong( rng ) % 8;
  self->votes_pool = fd_clock_timestamp_vote_t_map_join_new( alloc_mem, fd_ulong_max( votes_len, 15000 ) );
  self->votes_root = NULL;
  for( ulong i=0; i < votes_len; i++ ) {
    fd_clock_timestamp_vote_t_mapnode_t * node = fd_clock_timestamp_vote_t_map_acquire( self->votes_pool );
    fd_clock_timestamp_vote_generate( &node->elem, alloc_mem, rng );
    fd_clock_timestamp_vote_t_map_insert( self->votes_pool, &self->votes_root, node );
  }
  return mem;
}

void *fd_sysvar_fees_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_sysvar_fees_t *self = (fd_sysvar_fees_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_sysvar_fees_t);
  fd_sysvar_fees_new(mem);
  fd_fee_calculator_generate( &self->fee_calculator, alloc_mem, rng );
  return mem;
}

void *fd_sysvar_epoch_rewards_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_sysvar_epoch_rewards_t *self = (fd_sysvar_epoch_rewards_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_sysvar_epoch_rewards_t);
  fd_sysvar_epoch_rewards_new(mem);
  self->distribution_starting_block_height = fd_rng_ulong( rng );
  self->num_partitions = fd_rng_ulong( rng );
  fd_hash_generate( &self->parent_blockhash, alloc_mem, rng );
  self->total_points = fd_rng_uint128( rng );
  self->total_rewards = fd_rng_ulong( rng );
  self->distributed_rewards = fd_rng_ulong( rng );
  self->active = fd_rng_uchar( rng );
  return mem;
}

void *fd_config_keys_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_config_keys_pair_t *self = (fd_config_keys_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_config_keys_pair_t);
  fd_config_keys_pair_new(mem);
  fd_pubkey_generate( &self->key, alloc_mem, rng );
  self->signer = fd_rng_uchar( rng );
  return mem;
}

void *fd_stake_config_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_config_t *self = (fd_stake_config_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_config_t);
  fd_stake_config_new(mem);
  self->config_keys_len = fd_rng_ulong( rng ) % 8;
  if( self->config_keys_len ) {
    self->config_keys = (fd_config_keys_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_CONFIG_KEYS_PAIR_FOOTPRINT*self->config_keys_len;
    for( ulong i=0; i < self->config_keys_len; i++ ) {
      fd_config_keys_pair_new( self->config_keys + i );
      fd_config_keys_pair_generate( self->config_keys + i, alloc_mem, rng );
    }
  } else
    self->config_keys = NULL;
  self->warmup_cooldown_rate = fd_rng_double_o( rng );
  self->slash_penalty = fd_rng_uchar( rng );
  return mem;
}

void *fd_feature_entry_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_feature_entry_t *self = (fd_feature_entry_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_feature_entry_t);
  fd_feature_entry_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->description_len = fd_rng_ulong( rng ) % 8;
  if( self->description_len ) {
    self->description = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->description_len;
    for( ulong i=0; i < self->description_len; ++i) { self->description[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->description = NULL;
  self->since_slot = fd_rng_ulong( rng );
  return mem;
}

void *fd_firedancer_bank_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_firedancer_bank_t *self = (fd_firedancer_bank_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_firedancer_bank_t);
  fd_firedancer_bank_new(mem);
  fd_stakes_generate( &self->stakes, alloc_mem, rng );
  fd_recent_block_hashes_generate( &self->recent_block_hashes, alloc_mem, rng );
  fd_clock_timestamp_votes_generate( &self->timestamp_votes, alloc_mem, rng );
  self->slot = fd_rng_ulong( rng );
  self->prev_slot = fd_rng_ulong( rng );
  fd_hash_generate( &self->poh, alloc_mem, rng );
  fd_hash_generate( &self->banks_hash, alloc_mem, rng );
  fd_fee_rate_governor_generate( &self->fee_rate_governor, alloc_mem, rng );
  self->capitalization = fd_rng_ulong( rng );
  self->block_height = fd_rng_ulong( rng );
  self->lamports_per_signature = fd_rng_ulong( rng );
  self->hashes_per_tick = fd_rng_ulong( rng );
  self->ticks_per_slot = fd_rng_ulong( rng );
  self->ns_per_slot = fd_rng_uint128( rng );
  self->genesis_creation_time = fd_rng_ulong( rng );
  self->slots_per_year = fd_rng_double_o( rng );
  self->max_tick_height = fd_rng_ulong( rng );
  fd_inflation_generate( &self->inflation, alloc_mem, rng );
  fd_epoch_schedule_generate( &self->epoch_schedule, alloc_mem, rng );
  fd_rent_generate( &self->rent, alloc_mem, rng );
  self->collected_fees = fd_rng_ulong( rng );
  self->collected_rent = fd_rng_ulong( rng );
  fd_vote_accounts_generate( &self->epoch_stakes, alloc_mem, rng );
  fd_sol_sysvar_last_restart_slot_generate( &self->last_restart_slot, alloc_mem, rng );
  return mem;
}

void fd_cluster_type_inner_generate( fd_cluster_type_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
}
void *fd_cluster_type_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_cluster_type_t *self = (fd_cluster_type_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_cluster_type_t);
  fd_cluster_type_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 4;
  fd_cluster_type_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_rent_fresh_account_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_rent_fresh_account_t *self = (fd_rent_fresh_account_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_rent_fresh_account_t);
  fd_rent_fresh_account_new(mem);
  self->partition = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->present = fd_rng_ulong( rng );
  return mem;
}

void *fd_rent_fresh_accounts_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_rent_fresh_accounts_t *self = (fd_rent_fresh_accounts_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_rent_fresh_accounts_t);
  fd_rent_fresh_accounts_new(mem);
  self->total_count = fd_rng_ulong( rng );
  self->fresh_accounts_len = fd_rng_ulong( rng ) % 8;
  if( self->fresh_accounts_len ) {
    self->fresh_accounts = (fd_rent_fresh_account_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_RENT_FRESH_ACCOUNT_FOOTPRINT*self->fresh_accounts_len;
    for( ulong i=0; i < self->fresh_accounts_len; i++ ) {
      fd_rent_fresh_account_new( self->fresh_accounts + i );
      fd_rent_fresh_account_generate( self->fresh_accounts + i, alloc_mem, rng );
    }
  } else
    self->fresh_accounts = NULL;
  return mem;
}

void *fd_epoch_bank_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_epoch_bank_t *self = (fd_epoch_bank_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_epoch_bank_t);
  fd_epoch_bank_new(mem);
  fd_stakes_generate( &self->stakes, alloc_mem, rng );
  self->hashes_per_tick = fd_rng_ulong( rng );
  self->ticks_per_slot = fd_rng_ulong( rng );
  self->ns_per_slot = fd_rng_uint128( rng );
  self->genesis_creation_time = fd_rng_ulong( rng );
  self->slots_per_year = fd_rng_double_o( rng );
  self->max_tick_height = fd_rng_ulong( rng );
  fd_inflation_generate( &self->inflation, alloc_mem, rng );
  fd_epoch_schedule_generate( &self->epoch_schedule, alloc_mem, rng );
  fd_rent_generate( &self->rent, alloc_mem, rng );
  self->eah_start_slot = fd_rng_ulong( rng );
  self->eah_stop_slot = fd_rng_ulong( rng );
  self->eah_interval = fd_rng_ulong( rng );
  fd_hash_generate( &self->genesis_hash, alloc_mem, rng );
  self->cluster_type = fd_rng_uint( rng );
    LLVMFuzzerMutate( (uchar *)self->cluster_version, sizeof(uint)*3, sizeof(uint)*3 );
  fd_vote_accounts_generate( &self->next_epoch_stakes, alloc_mem, rng );
  fd_epoch_schedule_generate( &self->rent_epoch_schedule, alloc_mem, rng );
  return mem;
}

void *fd_stake_reward_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_reward_t *self = (fd_stake_reward_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_reward_t);
  fd_stake_reward_new(mem);
  self->prev = fd_rng_ulong( rng );
  self->next = fd_rng_ulong( rng );
  self->parent = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->stake_pubkey, alloc_mem, rng );
  self->credits_observed = fd_rng_ulong( rng );
  self->lamports = fd_rng_ulong( rng );
  self->valid = fd_rng_uchar( rng );
  return mem;
}

void *fd_vote_reward_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_reward_t *self = (fd_vote_reward_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_reward_t);
  fd_vote_reward_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->vote_rewards = fd_rng_ulong( rng );
  self->commission = fd_rng_uchar( rng );
  self->needs_store = fd_rng_uchar( rng );
  return mem;
}

void *fd_point_value_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_point_value_t *self = (fd_point_value_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_point_value_t);
  fd_point_value_new(mem);
  self->rewards = fd_rng_ulong( rng );
  self->points = fd_rng_uint128( rng );
  return mem;
}

void *fd_partitioned_stake_rewards_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_partitioned_stake_rewards_t *self = (fd_partitioned_stake_rewards_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_partitioned_stake_rewards_t);
  fd_partitioned_stake_rewards_new(mem);
  self->partitions_len = fd_rng_ulong( rng ) % 8;
  ulong total_count = 0UL;
  for( ulong i=0; i < 4096; i++ ) {
    self->partitions_lengths[i] = fd_rng_ulong( rng ) % 8;
    total_count += self->partitions_lengths[ i ];
  }
  self->pool = fd_partitioned_stake_rewards_pool_join_new( alloc_mem, total_count );
  self->partitions = fd_partitioned_stake_rewards_dlist_join_new( alloc_mem, self->partitions_len );
  for( ulong i=0; i < self->partitions_len; i++ ) {
    fd_partitioned_stake_rewards_dlist_new( &self->partitions[ i ] );
    for( ulong j=0; j < self->partitions_lengths[ i ]; j++ ) {
      fd_stake_reward_t * ele = fd_partitioned_stake_rewards_pool_ele_acquire( self->pool );
      fd_stake_reward_new( ele );
      fd_stake_reward_generate( ele, alloc_mem, rng );
      fd_partitioned_stake_rewards_dlist_ele_push_tail( &self->partitions[ i ], ele, self->pool );
    }
  }
  return mem;
}

void *fd_stake_reward_calculation_partitioned_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_reward_calculation_partitioned_t *self = (fd_stake_reward_calculation_partitioned_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_reward_calculation_partitioned_t);
  fd_stake_reward_calculation_partitioned_new(mem);
  fd_partitioned_stake_rewards_generate( &self->partitioned_stake_rewards, alloc_mem, rng );
  self->total_stake_rewards_lamports = fd_rng_ulong( rng );
  return mem;
}

void *fd_stake_reward_calculation_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_reward_calculation_t *self = (fd_stake_reward_calculation_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_reward_calculation_t);
  fd_stake_reward_calculation_new(mem);
  self->stake_rewards_len = fd_rng_ulong( rng ) % 8;
  self->pool = fd_stake_reward_calculation_pool_join_new( alloc_mem, self->stake_rewards_len );
  self->stake_rewards = fd_stake_reward_calculation_dlist_join_new( alloc_mem, self->stake_rewards_len );
  fd_stake_reward_calculation_dlist_new( &self->stake_rewards );
  for( ulong i=0; i < self->stake_rewards_len; i++ ) {
    fd_stake_reward_t * ele = fd_stake_reward_calculation_pool_ele_acquire( self->pool );
    fd_stake_reward_new( ele );
    fd_stake_reward_generate( ele, alloc_mem, rng );
    fd_stake_reward_calculation_dlist_ele_push_tail( self->stake_rewards, ele, self->pool );
  }
  self->total_stake_rewards_lamports = fd_rng_ulong( rng );
  return mem;
}

void *fd_calculate_stake_vote_rewards_result_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_calculate_stake_vote_rewards_result_t *self = (fd_calculate_stake_vote_rewards_result_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_calculate_stake_vote_rewards_result_t);
  fd_calculate_stake_vote_rewards_result_new(mem);
  fd_stake_reward_calculation_generate( &self->stake_reward_calculation, alloc_mem, rng );
  ulong vote_reward_map_len = fd_rng_ulong( rng ) % 8;
  self->vote_reward_map_pool = fd_vote_reward_t_map_join_new( alloc_mem, fd_ulong_max( vote_reward_map_len, 15000 ) );
  self->vote_reward_map_root = NULL;
  for( ulong i=0; i < vote_reward_map_len; i++ ) {
    fd_vote_reward_t_mapnode_t * node = fd_vote_reward_t_map_acquire( self->vote_reward_map_pool );
    fd_vote_reward_generate( &node->elem, alloc_mem, rng );
    fd_vote_reward_t_map_insert( self->vote_reward_map_pool, &self->vote_reward_map_root, node );
  }
  return mem;
}

void *fd_calculate_validator_rewards_result_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_calculate_validator_rewards_result_t *self = (fd_calculate_validator_rewards_result_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_calculate_validator_rewards_result_t);
  fd_calculate_validator_rewards_result_new(mem);
  fd_calculate_stake_vote_rewards_result_generate( &self->calculate_stake_vote_rewards_result, alloc_mem, rng );
  fd_point_value_generate( &self->point_value, alloc_mem, rng );
  return mem;
}

void *fd_calculate_rewards_and_distribute_vote_rewards_result_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_calculate_rewards_and_distribute_vote_rewards_result_t *self = (fd_calculate_rewards_and_distribute_vote_rewards_result_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_calculate_rewards_and_distribute_vote_rewards_result_t);
  fd_calculate_rewards_and_distribute_vote_rewards_result_new(mem);
  self->total_rewards = fd_rng_ulong( rng );
  self->distributed_rewards = fd_rng_ulong( rng );
  fd_point_value_generate( &self->point_value, alloc_mem, rng );
  fd_stake_reward_calculation_partitioned_generate( &self->stake_rewards_by_partition, alloc_mem, rng );
  return mem;
}

void *fd_partitioned_rewards_calculation_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_partitioned_rewards_calculation_t *self = (fd_partitioned_rewards_calculation_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_partitioned_rewards_calculation_t);
  fd_partitioned_rewards_calculation_new(mem);
  ulong vote_reward_map_len = fd_rng_ulong( rng ) % 8;
  self->vote_reward_map_pool = fd_vote_reward_t_map_join_new( alloc_mem, fd_ulong_max( vote_reward_map_len, 15000 ) );
  self->vote_reward_map_root = NULL;
  for( ulong i=0; i < vote_reward_map_len; i++ ) {
    fd_vote_reward_t_mapnode_t * node = fd_vote_reward_t_map_acquire( self->vote_reward_map_pool );
    fd_vote_reward_generate( &node->elem, alloc_mem, rng );
    fd_vote_reward_t_map_insert( self->vote_reward_map_pool, &self->vote_reward_map_root, node );
  }
  fd_stake_reward_calculation_partitioned_generate( &self->stake_rewards_by_partition, alloc_mem, rng );
  self->old_vote_balance_and_staked = fd_rng_ulong( rng );
  self->validator_rewards = fd_rng_ulong( rng );
  self->validator_rate = fd_rng_double_o( rng );
  self->foundation_rate = fd_rng_double_o( rng );
  self->prev_epoch_duration_in_years = fd_rng_double_o( rng );
  self->capitalization = fd_rng_ulong( rng );
  fd_point_value_generate( &self->point_value, alloc_mem, rng );
  return mem;
}

void *fd_start_block_height_and_rewards_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_start_block_height_and_rewards_t *self = (fd_start_block_height_and_rewards_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_start_block_height_and_rewards_t);
  fd_start_block_height_and_rewards_new(mem);
  self->distribution_starting_block_height = fd_rng_ulong( rng );
  fd_partitioned_stake_rewards_generate( &self->partitioned_stake_rewards, alloc_mem, rng );
  return mem;
}

void *fd_fd_epoch_reward_status_inner_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_fd_epoch_reward_status_inner_t *self = (fd_fd_epoch_reward_status_inner_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_fd_epoch_reward_status_inner_t);
  fd_fd_epoch_reward_status_inner_new(mem);
  fd_start_block_height_and_rewards_generate( &self->Active, alloc_mem, rng );
  return mem;
}

void fd_epoch_reward_status_inner_generate( fd_epoch_reward_status_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_start_block_height_and_rewards_generate( &self->Active, alloc_mem, rng );
    break;
  }
  }
}
void *fd_epoch_reward_status_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_epoch_reward_status_t *self = (fd_epoch_reward_status_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_epoch_reward_status_t);
  fd_epoch_reward_status_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_epoch_reward_status_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_slot_bank_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_bank_t *self = (fd_slot_bank_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_bank_t);
  fd_slot_bank_new(mem);
  fd_clock_timestamp_votes_generate( &self->timestamp_votes, alloc_mem, rng );
  self->slot = fd_rng_ulong( rng );
  self->prev_slot = fd_rng_ulong( rng );
  fd_hash_generate( &self->poh, alloc_mem, rng );
  fd_hash_generate( &self->banks_hash, alloc_mem, rng );
  fd_hash_generate( &self->epoch_account_hash, alloc_mem, rng );
  fd_fee_rate_governor_generate( &self->fee_rate_governor, alloc_mem, rng );
  self->capitalization = fd_rng_ulong( rng );
  self->block_height = fd_rng_ulong( rng );
  self->max_tick_height = fd_rng_ulong( rng );
  self->collected_execution_fees = fd_rng_ulong( rng );
  self->collected_priority_fees = fd_rng_ulong( rng );
  self->collected_rent = fd_rng_ulong( rng );
  fd_vote_accounts_generate( &self->epoch_stakes, alloc_mem, rng );
  fd_sol_sysvar_last_restart_slot_generate( &self->last_restart_slot, alloc_mem, rng );
  fd_account_keys_generate( &self->stake_account_keys, alloc_mem, rng );
  fd_account_keys_generate( &self->vote_account_keys, alloc_mem, rng );
  self->lamports_per_signature = fd_rng_ulong( rng );
  self->transaction_count = fd_rng_ulong( rng );
  fd_slot_lthash_generate( &self->lthash, alloc_mem, rng );
  fd_block_hash_queue_generate( &self->block_hash_queue, alloc_mem, rng );
  fd_hash_generate( &self->prev_banks_hash, alloc_mem, rng );
  self->parent_signature_cnt = fd_rng_ulong( rng );
  self->tick_height = fd_rng_ulong( rng );
  {
    self->has_use_preceeding_epoch_stakes = fd_rng_uchar( rng ) % 2;
    if( self->has_use_preceeding_epoch_stakes ) {
      LLVMFuzzerMutate( (uchar *)&(self->use_preceeding_epoch_stakes), sizeof(ulong), sizeof(ulong) );
    }
  }
  fd_hard_forks_generate( &self->hard_forks, alloc_mem, rng );
  fd_rent_fresh_accounts_generate( &self->rent_fresh_accounts, alloc_mem, rng );
  fd_epoch_reward_status_generate( &self->epoch_reward_status, alloc_mem, rng );
  return mem;
}

void *fd_prev_epoch_inflation_rewards_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_prev_epoch_inflation_rewards_t *self = (fd_prev_epoch_inflation_rewards_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_prev_epoch_inflation_rewards_t);
  fd_prev_epoch_inflation_rewards_new(mem);
  self->validator_rewards = fd_rng_ulong( rng );
  self->prev_epoch_duration_in_years = fd_rng_double_o( rng );
  self->validator_rate = fd_rng_double_o( rng );
  self->foundation_rate = fd_rng_double_o( rng );
  return mem;
}

void *fd_vote_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_t *self = (fd_vote_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_t);
  fd_vote_new(mem);
  ulong slots_len = fd_rng_ulong( rng ) % 8;
  self->slots = deq_ulong_join_new( alloc_mem, slots_len );
  for( ulong i=0; i < slots_len; i++ ) {
    ulong * elem = deq_ulong_push_tail_nocopy( self->slots );
    LLVMFuzzerMutate( (uchar *) elem, sizeof(ulong), sizeof(ulong) );
  }
  fd_hash_generate( &self->hash, alloc_mem, rng );
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->timestamp = (long *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + sizeof(long);
      LLVMFuzzerMutate( (uchar *)self->timestamp, sizeof(long), sizeof(long) );
    }
    else {
    self->timestamp = NULL;
    }
  }
  return mem;
}

void *fd_vote_init_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_init_t *self = (fd_vote_init_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_init_t);
  fd_vote_init_new(mem);
  fd_pubkey_generate( &self->node_pubkey, alloc_mem, rng );
  fd_pubkey_generate( &self->authorized_voter, alloc_mem, rng );
  fd_pubkey_generate( &self->authorized_withdrawer, alloc_mem, rng );
  self->commission = fd_rng_uchar( rng );
  return mem;
}

void fd_vote_authorize_inner_generate( fd_vote_authorize_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
}
void *fd_vote_authorize_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_authorize_t *self = (fd_vote_authorize_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_authorize_t);
  fd_vote_authorize_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_vote_authorize_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_vote_authorize_pubkey_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_authorize_pubkey_t *self = (fd_vote_authorize_pubkey_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_authorize_pubkey_t);
  fd_vote_authorize_pubkey_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  fd_vote_authorize_generate( &self->vote_authorize, alloc_mem, rng );
  return mem;
}

void *fd_vote_switch_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_switch_t *self = (fd_vote_switch_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_switch_t);
  fd_vote_switch_new(mem);
  fd_vote_generate( &self->vote, alloc_mem, rng );
  fd_hash_generate( &self->hash, alloc_mem, rng );
  return mem;
}

void *fd_update_vote_state_switch_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_update_vote_state_switch_t *self = (fd_update_vote_state_switch_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_update_vote_state_switch_t);
  fd_update_vote_state_switch_new(mem);
  fd_vote_state_update_generate( &self->vote_state_update, alloc_mem, rng );
  fd_hash_generate( &self->hash, alloc_mem, rng );
  return mem;
}

void *fd_vote_authorize_with_seed_args_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_authorize_with_seed_args_t *self = (fd_vote_authorize_with_seed_args_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_authorize_with_seed_args_t);
  fd_vote_authorize_with_seed_args_new(mem);
  fd_vote_authorize_generate( &self->authorization_type, alloc_mem, rng );
  fd_pubkey_generate( &self->current_authority_derived_key_owner, alloc_mem, rng );
  self->current_authority_derived_key_seed_len = fd_rng_ulong( rng ) % 8;
  if( self->current_authority_derived_key_seed_len ) {
    self->current_authority_derived_key_seed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->current_authority_derived_key_seed_len;
    for( ulong i=0; i < self->current_authority_derived_key_seed_len; ++i) { self->current_authority_derived_key_seed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->current_authority_derived_key_seed = NULL;
  fd_pubkey_generate( &self->new_authority, alloc_mem, rng );
  return mem;
}

void *fd_vote_authorize_checked_with_seed_args_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_authorize_checked_with_seed_args_t *self = (fd_vote_authorize_checked_with_seed_args_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_authorize_checked_with_seed_args_t);
  fd_vote_authorize_checked_with_seed_args_new(mem);
  fd_vote_authorize_generate( &self->authorization_type, alloc_mem, rng );
  fd_pubkey_generate( &self->current_authority_derived_key_owner, alloc_mem, rng );
  self->current_authority_derived_key_seed_len = fd_rng_ulong( rng ) % 8;
  if( self->current_authority_derived_key_seed_len ) {
    self->current_authority_derived_key_seed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->current_authority_derived_key_seed_len;
    for( ulong i=0; i < self->current_authority_derived_key_seed_len; ++i) { self->current_authority_derived_key_seed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->current_authority_derived_key_seed = NULL;
  return mem;
}

void fd_vote_instruction_inner_generate( fd_vote_instruction_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_vote_init_generate( &self->initialize_account, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_generate( &self->authorize, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_vote_generate( &self->vote, alloc_mem, rng );
    break;
  }
  case 3: {
    self->withdraw = fd_rng_ulong( rng );
    break;
  }
  case 5: {
    self->update_commission = fd_rng_uchar( rng );
    break;
  }
  case 6: {
    fd_vote_switch_generate( &self->vote_switch, alloc_mem, rng );
    break;
  }
  case 7: {
    fd_vote_authorize_generate( &self->authorize_checked, alloc_mem, rng );
    break;
  }
  case 8: {
    fd_vote_state_update_generate( &self->update_vote_state, alloc_mem, rng );
    break;
  }
  case 9: {
    fd_update_vote_state_switch_generate( &self->update_vote_state_switch, alloc_mem, rng );
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_generate( &self->authorize_with_seed, alloc_mem, rng );
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_generate( &self->authorize_checked_with_seed, alloc_mem, rng );
    break;
  }
  case 12: {
    fd_compact_vote_state_update_generate( &self->compact_update_vote_state, alloc_mem, rng );
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_generate( &self->compact_update_vote_state_switch, alloc_mem, rng );
    break;
  }
  case 14: {
    break;
  }
  case 15: {
    fd_tower_sync_switch_generate( &self->tower_sync_switch, alloc_mem, rng );
    break;
  }
  }
}
void *fd_vote_instruction_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_instruction_t *self = (fd_vote_instruction_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_instruction_t);
  fd_vote_instruction_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 16;
  while( self->discriminant == 14 || self->discriminant == 15 ) { self->discriminant = fd_rng_uint( rng ) % 16; }
  fd_vote_instruction_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_system_program_instruction_create_account_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_system_program_instruction_create_account_t *self = (fd_system_program_instruction_create_account_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_system_program_instruction_create_account_t);
  fd_system_program_instruction_create_account_new(mem);
  self->lamports = fd_rng_ulong( rng );
  self->space = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->owner, alloc_mem, rng );
  return mem;
}

void *fd_system_program_instruction_create_account_with_seed_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_system_program_instruction_create_account_with_seed_t *self = (fd_system_program_instruction_create_account_with_seed_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_system_program_instruction_create_account_with_seed_t);
  fd_system_program_instruction_create_account_with_seed_new(mem);
  fd_pubkey_generate( &self->base, alloc_mem, rng );
  self->seed_len = fd_rng_ulong( rng ) % 8;
  if( self->seed_len ) {
    self->seed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->seed_len;
    for( ulong i=0; i < self->seed_len; ++i) { self->seed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->seed = NULL;
  self->lamports = fd_rng_ulong( rng );
  self->space = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->owner, alloc_mem, rng );
  return mem;
}

void *fd_system_program_instruction_allocate_with_seed_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_system_program_instruction_allocate_with_seed_t *self = (fd_system_program_instruction_allocate_with_seed_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_system_program_instruction_allocate_with_seed_t);
  fd_system_program_instruction_allocate_with_seed_new(mem);
  fd_pubkey_generate( &self->base, alloc_mem, rng );
  self->seed_len = fd_rng_ulong( rng ) % 8;
  if( self->seed_len ) {
    self->seed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->seed_len;
    for( ulong i=0; i < self->seed_len; ++i) { self->seed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->seed = NULL;
  self->space = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->owner, alloc_mem, rng );
  return mem;
}

void *fd_system_program_instruction_assign_with_seed_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_system_program_instruction_assign_with_seed_t *self = (fd_system_program_instruction_assign_with_seed_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_system_program_instruction_assign_with_seed_t);
  fd_system_program_instruction_assign_with_seed_new(mem);
  fd_pubkey_generate( &self->base, alloc_mem, rng );
  self->seed_len = fd_rng_ulong( rng ) % 8;
  if( self->seed_len ) {
    self->seed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->seed_len;
    for( ulong i=0; i < self->seed_len; ++i) { self->seed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->seed = NULL;
  fd_pubkey_generate( &self->owner, alloc_mem, rng );
  return mem;
}

void *fd_system_program_instruction_transfer_with_seed_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_system_program_instruction_transfer_with_seed_t *self = (fd_system_program_instruction_transfer_with_seed_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_system_program_instruction_transfer_with_seed_t);
  fd_system_program_instruction_transfer_with_seed_new(mem);
  self->lamports = fd_rng_ulong( rng );
  self->from_seed_len = fd_rng_ulong( rng ) % 8;
  if( self->from_seed_len ) {
    self->from_seed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->from_seed_len;
    for( ulong i=0; i < self->from_seed_len; ++i) { self->from_seed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->from_seed = NULL;
  fd_pubkey_generate( &self->from_owner, alloc_mem, rng );
  return mem;
}

void fd_system_program_instruction_inner_generate( fd_system_program_instruction_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_system_program_instruction_create_account_generate( &self->create_account, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_pubkey_generate( &self->assign, alloc_mem, rng );
    break;
  }
  case 2: {
    self->transfer = fd_rng_ulong( rng );
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_generate( &self->create_account_with_seed, alloc_mem, rng );
    break;
  }
  case 5: {
    self->withdraw_nonce_account = fd_rng_ulong( rng );
    break;
  }
  case 6: {
    fd_pubkey_generate( &self->initialize_nonce_account, alloc_mem, rng );
    break;
  }
  case 7: {
    fd_pubkey_generate( &self->authorize_nonce_account, alloc_mem, rng );
    break;
  }
  case 8: {
    self->allocate = fd_rng_ulong( rng );
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_generate( &self->allocate_with_seed, alloc_mem, rng );
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_generate( &self->assign_with_seed, alloc_mem, rng );
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_generate( &self->transfer_with_seed, alloc_mem, rng );
    break;
  }
  }
}
void *fd_system_program_instruction_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_system_program_instruction_t *self = (fd_system_program_instruction_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_system_program_instruction_t);
  fd_system_program_instruction_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 13;
  fd_system_program_instruction_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void fd_system_error_inner_generate( fd_system_error_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
}
void *fd_system_error_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_system_error_t *self = (fd_system_error_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_system_error_t);
  fd_system_error_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 9;
  fd_system_error_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_stake_authorized_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_authorized_t *self = (fd_stake_authorized_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_authorized_t);
  fd_stake_authorized_new(mem);
  fd_pubkey_generate( &self->staker, alloc_mem, rng );
  fd_pubkey_generate( &self->withdrawer, alloc_mem, rng );
  return mem;
}

void *fd_stake_lockup_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_lockup_t *self = (fd_stake_lockup_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_lockup_t);
  fd_stake_lockup_new(mem);
  self->unix_timestamp = fd_rng_long( rng );
  self->epoch = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->custodian, alloc_mem, rng );
  return mem;
}

void *fd_stake_instruction_initialize_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_instruction_initialize_t *self = (fd_stake_instruction_initialize_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_instruction_initialize_t);
  fd_stake_instruction_initialize_new(mem);
  fd_stake_authorized_generate( &self->authorized, alloc_mem, rng );
  fd_stake_lockup_generate( &self->lockup, alloc_mem, rng );
  return mem;
}

void *fd_stake_lockup_custodian_args_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_lockup_custodian_args_t *self = (fd_stake_lockup_custodian_args_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_lockup_custodian_args_t);
  fd_stake_lockup_custodian_args_new(mem);
  fd_stake_lockup_generate( &self->lockup, alloc_mem, rng );
  fd_sol_sysvar_clock_generate( &self->clock, alloc_mem, rng );
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->custodian = (fd_pubkey_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT;
      fd_pubkey_new( self->custodian );
      fd_pubkey_generate( self->custodian, alloc_mem, rng );
    }
    else {
    self->custodian = NULL;
    }
  }
  return mem;
}

void fd_stake_authorize_inner_generate( fd_stake_authorize_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
}
void *fd_stake_authorize_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_authorize_t *self = (fd_stake_authorize_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_authorize_t);
  fd_stake_authorize_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_stake_authorize_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_stake_instruction_authorize_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_instruction_authorize_t *self = (fd_stake_instruction_authorize_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_instruction_authorize_t);
  fd_stake_instruction_authorize_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  fd_stake_authorize_generate( &self->stake_authorize, alloc_mem, rng );
  return mem;
}

void *fd_authorize_with_seed_args_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_authorize_with_seed_args_t *self = (fd_authorize_with_seed_args_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_authorize_with_seed_args_t);
  fd_authorize_with_seed_args_new(mem);
  fd_pubkey_generate( &self->new_authorized_pubkey, alloc_mem, rng );
  fd_stake_authorize_generate( &self->stake_authorize, alloc_mem, rng );
  self->authority_seed_len = fd_rng_ulong( rng ) % 8;
  if( self->authority_seed_len ) {
    self->authority_seed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->authority_seed_len;
    for( ulong i=0; i < self->authority_seed_len; ++i) { self->authority_seed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->authority_seed = NULL;
  fd_pubkey_generate( &self->authority_owner, alloc_mem, rng );
  return mem;
}

void *fd_authorize_checked_with_seed_args_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_authorize_checked_with_seed_args_t *self = (fd_authorize_checked_with_seed_args_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_authorize_checked_with_seed_args_t);
  fd_authorize_checked_with_seed_args_new(mem);
  fd_stake_authorize_generate( &self->stake_authorize, alloc_mem, rng );
  self->authority_seed_len = fd_rng_ulong( rng ) % 8;
  if( self->authority_seed_len ) {
    self->authority_seed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->authority_seed_len;
    for( ulong i=0; i < self->authority_seed_len; ++i) { self->authority_seed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->authority_seed = NULL;
  fd_pubkey_generate( &self->authority_owner, alloc_mem, rng );
  return mem;
}

void *fd_lockup_checked_args_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_lockup_checked_args_t *self = (fd_lockup_checked_args_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_lockup_checked_args_t);
  fd_lockup_checked_args_new(mem);
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->unix_timestamp = (long *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + sizeof(long);
      LLVMFuzzerMutate( (uchar *)self->unix_timestamp, sizeof(long), sizeof(long) );
    }
    else {
    self->unix_timestamp = NULL;
    }
  }
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->epoch = (ulong *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong);
      LLVMFuzzerMutate( (uchar *)self->epoch, sizeof(ulong), sizeof(ulong) );
    }
    else {
    self->epoch = NULL;
    }
  }
  return mem;
}

void *fd_lockup_args_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_lockup_args_t *self = (fd_lockup_args_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_lockup_args_t);
  fd_lockup_args_new(mem);
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->unix_timestamp = (long *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + sizeof(long);
      LLVMFuzzerMutate( (uchar *)self->unix_timestamp, sizeof(long), sizeof(long) );
    }
    else {
    self->unix_timestamp = NULL;
    }
  }
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->epoch = (ulong *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong);
      LLVMFuzzerMutate( (uchar *)self->epoch, sizeof(ulong), sizeof(ulong) );
    }
    else {
    self->epoch = NULL;
    }
  }
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->custodian = (fd_pubkey_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT;
      fd_pubkey_new( self->custodian );
      fd_pubkey_generate( self->custodian, alloc_mem, rng );
    }
    else {
    self->custodian = NULL;
    }
  }
  return mem;
}

void fd_stake_instruction_inner_generate( fd_stake_instruction_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_stake_instruction_initialize_generate( &self->initialize, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_generate( &self->authorize, alloc_mem, rng );
    break;
  }
  case 3: {
    self->split = fd_rng_ulong( rng );
    break;
  }
  case 4: {
    self->withdraw = fd_rng_ulong( rng );
    break;
  }
  case 6: {
    fd_lockup_args_generate( &self->set_lockup, alloc_mem, rng );
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_generate( &self->authorize_with_seed, alloc_mem, rng );
    break;
  }
  case 10: {
    fd_stake_authorize_generate( &self->authorize_checked, alloc_mem, rng );
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_generate( &self->authorize_checked_with_seed, alloc_mem, rng );
    break;
  }
  case 12: {
    fd_lockup_checked_args_generate( &self->set_lockup_checked, alloc_mem, rng );
    break;
  }
  case 16: {
    self->move_stake = fd_rng_ulong( rng );
    break;
  }
  case 17: {
    self->move_lamports = fd_rng_ulong( rng );
    break;
  }
  }
}
void *fd_stake_instruction_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_instruction_t *self = (fd_stake_instruction_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_instruction_t);
  fd_stake_instruction_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 18;
  fd_stake_instruction_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_stake_meta_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_meta_t *self = (fd_stake_meta_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_meta_t);
  fd_stake_meta_new(mem);
  self->rent_exempt_reserve = fd_rng_ulong( rng );
  fd_stake_authorized_generate( &self->authorized, alloc_mem, rng );
  fd_stake_lockup_generate( &self->lockup, alloc_mem, rng );
  return mem;
}

void *fd_stake_flags_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_flags_t *self = (fd_stake_flags_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_flags_t);
  fd_stake_flags_new(mem);
  self->bits = fd_rng_uchar( rng );
  return mem;
}

void *fd_stake_state_v2_initialized_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_state_v2_initialized_t *self = (fd_stake_state_v2_initialized_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_state_v2_initialized_t);
  fd_stake_state_v2_initialized_new(mem);
  fd_stake_meta_generate( &self->meta, alloc_mem, rng );
  return mem;
}

void *fd_stake_state_v2_stake_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_state_v2_stake_t *self = (fd_stake_state_v2_stake_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_state_v2_stake_t);
  fd_stake_state_v2_stake_new(mem);
  fd_stake_meta_generate( &self->meta, alloc_mem, rng );
  fd_stake_generate( &self->stake, alloc_mem, rng );
  fd_stake_flags_generate( &self->stake_flags, alloc_mem, rng );
  return mem;
}

void fd_stake_state_v2_inner_generate( fd_stake_state_v2_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 1: {
    fd_stake_state_v2_initialized_generate( &self->initialized, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_stake_state_v2_stake_generate( &self->stake, alloc_mem, rng );
    break;
  }
  }
}
void *fd_stake_state_v2_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_stake_state_v2_t *self = (fd_stake_state_v2_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_stake_state_v2_t);
  fd_stake_state_v2_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 4;
  fd_stake_state_v2_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_nonce_data_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_nonce_data_t *self = (fd_nonce_data_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_nonce_data_t);
  fd_nonce_data_new(mem);
  fd_pubkey_generate( &self->authority, alloc_mem, rng );
  fd_hash_generate( &self->durable_nonce, alloc_mem, rng );
  fd_fee_calculator_generate( &self->fee_calculator, alloc_mem, rng );
  return mem;
}

void fd_nonce_state_inner_generate( fd_nonce_state_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 1: {
    fd_nonce_data_generate( &self->initialized, alloc_mem, rng );
    break;
  }
  }
}
void *fd_nonce_state_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_nonce_state_t *self = (fd_nonce_state_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_nonce_state_t);
  fd_nonce_state_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_nonce_state_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void fd_nonce_state_versions_inner_generate( fd_nonce_state_versions_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_nonce_state_generate( &self->legacy, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_nonce_state_generate( &self->current, alloc_mem, rng );
    break;
  }
  }
}
void *fd_nonce_state_versions_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_nonce_state_versions_t *self = (fd_nonce_state_versions_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_nonce_state_versions_t);
  fd_nonce_state_versions_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_nonce_state_versions_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_compute_budget_program_instruction_request_units_deprecated_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_compute_budget_program_instruction_request_units_deprecated_t *self = (fd_compute_budget_program_instruction_request_units_deprecated_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_compute_budget_program_instruction_request_units_deprecated_t);
  fd_compute_budget_program_instruction_request_units_deprecated_new(mem);
  self->units = fd_rng_uint( rng );
  self->additional_fee = fd_rng_uint( rng );
  return mem;
}

void fd_compute_budget_program_instruction_inner_generate( fd_compute_budget_program_instruction_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_generate( &self->request_units_deprecated, alloc_mem, rng );
    break;
  }
  case 1: {
    self->request_heap_frame = fd_rng_uint( rng );
    break;
  }
  case 2: {
    self->set_compute_unit_limit = fd_rng_uint( rng );
    break;
  }
  case 3: {
    self->set_compute_unit_price = fd_rng_ulong( rng );
    break;
  }
  case 4: {
    self->set_loaded_accounts_data_size_limit = fd_rng_uint( rng );
    break;
  }
  }
}
void *fd_compute_budget_program_instruction_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_compute_budget_program_instruction_t *self = (fd_compute_budget_program_instruction_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_compute_budget_program_instruction_t);
  fd_compute_budget_program_instruction_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 5;
  fd_compute_budget_program_instruction_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_config_keys_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_config_keys_t *self = (fd_config_keys_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_config_keys_t);
  fd_config_keys_new(mem);
  self->keys_len = fd_rng_ulong( rng ) % 8;
  if( self->keys_len ) {
    self->keys = (fd_config_keys_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_CONFIG_KEYS_PAIR_FOOTPRINT*self->keys_len;
    for( ulong i=0; i < self->keys_len; i++ ) {
      fd_config_keys_pair_new( self->keys + i );
      fd_config_keys_pair_generate( self->keys + i, alloc_mem, rng );
    }
  } else
    self->keys = NULL;
  return mem;
}

void *fd_bpf_loader_program_instruction_write_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_loader_program_instruction_write_t *self = (fd_bpf_loader_program_instruction_write_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_loader_program_instruction_write_t);
  fd_bpf_loader_program_instruction_write_new(mem);
  self->offset = fd_rng_uint( rng );
  self->bytes_len = fd_rng_ulong( rng ) % 8;
  if( self->bytes_len ) {
    self->bytes = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->bytes_len;
    for( ulong i=0; i < self->bytes_len; ++i) { self->bytes[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->bytes = NULL;
  return mem;
}

void fd_bpf_loader_program_instruction_inner_generate( fd_bpf_loader_program_instruction_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_bpf_loader_program_instruction_write_generate( &self->write, alloc_mem, rng );
    break;
  }
  }
}
void *fd_bpf_loader_program_instruction_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_loader_program_instruction_t *self = (fd_bpf_loader_program_instruction_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_loader_program_instruction_t);
  fd_bpf_loader_program_instruction_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_bpf_loader_program_instruction_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_loader_v4_program_instruction_write_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_loader_v4_program_instruction_write_t *self = (fd_loader_v4_program_instruction_write_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_loader_v4_program_instruction_write_t);
  fd_loader_v4_program_instruction_write_new(mem);
  self->offset = fd_rng_uint( rng );
  self->bytes_len = fd_rng_ulong( rng ) % 8;
  if( self->bytes_len ) {
    self->bytes = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->bytes_len;
    for( ulong i=0; i < self->bytes_len; ++i) { self->bytes[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->bytes = NULL;
  return mem;
}

void *fd_loader_v4_program_instruction_copy_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_loader_v4_program_instruction_copy_t *self = (fd_loader_v4_program_instruction_copy_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_loader_v4_program_instruction_copy_t);
  fd_loader_v4_program_instruction_copy_new(mem);
  self->destination_offset = fd_rng_uint( rng );
  self->source_offset = fd_rng_uint( rng );
  self->length = fd_rng_uint( rng );
  return mem;
}

void *fd_loader_v4_program_instruction_set_program_length_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_loader_v4_program_instruction_set_program_length_t *self = (fd_loader_v4_program_instruction_set_program_length_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_loader_v4_program_instruction_set_program_length_t);
  fd_loader_v4_program_instruction_set_program_length_new(mem);
  self->new_size = fd_rng_uint( rng );
  return mem;
}

void fd_loader_v4_program_instruction_inner_generate( fd_loader_v4_program_instruction_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_loader_v4_program_instruction_write_generate( &self->write, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_loader_v4_program_instruction_copy_generate( &self->copy, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_loader_v4_program_instruction_set_program_length_generate( &self->set_program_length, alloc_mem, rng );
    break;
  }
  }
}
void *fd_loader_v4_program_instruction_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_loader_v4_program_instruction_t *self = (fd_loader_v4_program_instruction_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_loader_v4_program_instruction_t);
  fd_loader_v4_program_instruction_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 7;
  fd_loader_v4_program_instruction_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_bpf_upgradeable_loader_program_instruction_write_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_upgradeable_loader_program_instruction_write_t *self = (fd_bpf_upgradeable_loader_program_instruction_write_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_write_t);
  fd_bpf_upgradeable_loader_program_instruction_write_new(mem);
  self->offset = fd_rng_uint( rng );
  self->bytes_len = fd_rng_ulong( rng ) % 8;
  if( self->bytes_len ) {
    self->bytes = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->bytes_len;
    for( ulong i=0; i < self->bytes_len; ++i) { self->bytes[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->bytes = NULL;
  return mem;
}

void *fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t *self = (fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t);
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new(mem);
  self->max_data_len = fd_rng_ulong( rng );
  return mem;
}

void *fd_bpf_upgradeable_loader_program_instruction_extend_program_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_upgradeable_loader_program_instruction_extend_program_t *self = (fd_bpf_upgradeable_loader_program_instruction_extend_program_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_extend_program_t);
  fd_bpf_upgradeable_loader_program_instruction_extend_program_new(mem);
  self->additional_bytes = fd_rng_uint( rng );
  return mem;
}

void fd_bpf_upgradeable_loader_program_instruction_inner_generate( fd_bpf_upgradeable_loader_program_instruction_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 1: {
    fd_bpf_upgradeable_loader_program_instruction_write_generate( &self->write, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_generate( &self->deploy_with_max_data_len, alloc_mem, rng );
    break;
  }
  case 6: {
    fd_bpf_upgradeable_loader_program_instruction_extend_program_generate( &self->extend_program, alloc_mem, rng );
    break;
  }
  }
}
void *fd_bpf_upgradeable_loader_program_instruction_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_upgradeable_loader_program_instruction_t *self = (fd_bpf_upgradeable_loader_program_instruction_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_t);
  fd_bpf_upgradeable_loader_program_instruction_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 8;
  fd_bpf_upgradeable_loader_program_instruction_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_bpf_upgradeable_loader_state_buffer_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_upgradeable_loader_state_buffer_t *self = (fd_bpf_upgradeable_loader_state_buffer_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_upgradeable_loader_state_buffer_t);
  fd_bpf_upgradeable_loader_state_buffer_new(mem);
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->authority_address = (fd_pubkey_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT;
      fd_pubkey_new( self->authority_address );
      fd_pubkey_generate( self->authority_address, alloc_mem, rng );
    }
    else {
    self->authority_address = NULL;
    }
  }
  return mem;
}

void *fd_bpf_upgradeable_loader_state_program_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_upgradeable_loader_state_program_t *self = (fd_bpf_upgradeable_loader_state_program_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_upgradeable_loader_state_program_t);
  fd_bpf_upgradeable_loader_state_program_new(mem);
  fd_pubkey_generate( &self->programdata_address, alloc_mem, rng );
  return mem;
}

void *fd_bpf_upgradeable_loader_state_program_data_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_upgradeable_loader_state_program_data_t *self = (fd_bpf_upgradeable_loader_state_program_data_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_upgradeable_loader_state_program_data_t);
  fd_bpf_upgradeable_loader_state_program_data_new(mem);
  self->slot = fd_rng_ulong( rng );
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->upgrade_authority_address = (fd_pubkey_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT;
      fd_pubkey_new( self->upgrade_authority_address );
      fd_pubkey_generate( self->upgrade_authority_address, alloc_mem, rng );
    }
    else {
    self->upgrade_authority_address = NULL;
    }
  }
  return mem;
}

void fd_bpf_upgradeable_loader_state_inner_generate( fd_bpf_upgradeable_loader_state_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 1: {
    fd_bpf_upgradeable_loader_state_buffer_generate( &self->buffer, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_state_program_generate( &self->program, alloc_mem, rng );
    break;
  }
  case 3: {
    fd_bpf_upgradeable_loader_state_program_data_generate( &self->program_data, alloc_mem, rng );
    break;
  }
  }
}
void *fd_bpf_upgradeable_loader_state_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bpf_upgradeable_loader_state_t *self = (fd_bpf_upgradeable_loader_state_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bpf_upgradeable_loader_state_t);
  fd_bpf_upgradeable_loader_state_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 4;
  fd_bpf_upgradeable_loader_state_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_loader_v4_state_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_loader_v4_state_t *self = (fd_loader_v4_state_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_loader_v4_state_t);
  fd_loader_v4_state_new(mem);
  self->slot = fd_rng_ulong( rng );
  fd_pubkey_generate( &self->authority_address_or_next_version, alloc_mem, rng );
  self->status = fd_rng_ulong( rng );
  return mem;
}

void *fd_frozen_hash_status_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_frozen_hash_status_t *self = (fd_frozen_hash_status_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_frozen_hash_status_t);
  fd_frozen_hash_status_new(mem);
  fd_hash_generate( &self->frozen_hash, alloc_mem, rng );
  self->is_duplicate_confirmed = fd_rng_uchar( rng );
  return mem;
}

void fd_frozen_hash_versioned_inner_generate( fd_frozen_hash_versioned_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_frozen_hash_status_generate( &self->current, alloc_mem, rng );
    break;
  }
  }
}
void *fd_frozen_hash_versioned_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_frozen_hash_versioned_t *self = (fd_frozen_hash_versioned_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_frozen_hash_versioned_t);
  fd_frozen_hash_versioned_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 1;
  fd_frozen_hash_versioned_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_lookup_table_meta_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_lookup_table_meta_t *self = (fd_lookup_table_meta_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_lookup_table_meta_t);
  fd_lookup_table_meta_new(mem);
  self->deactivation_slot = fd_rng_ulong( rng );
  self->last_extended_slot = fd_rng_ulong( rng );
  self->last_extended_slot_start_index = fd_rng_uchar( rng );
  {
    self->has_authority = fd_rng_uchar( rng ) % 2;
    if( self->has_authority ) {
      fd_pubkey_generate( &self->authority, alloc_mem, rng );
    }
  }
  self->_padding = fd_rng_ushort( rng );
  return mem;
}

void *fd_address_lookup_table_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_address_lookup_table_t *self = (fd_address_lookup_table_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_address_lookup_table_t);
  fd_address_lookup_table_new(mem);
  fd_lookup_table_meta_generate( &self->meta, alloc_mem, rng );
  return mem;
}

void fd_address_lookup_table_state_inner_generate( fd_address_lookup_table_state_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 1: {
    fd_address_lookup_table_generate( &self->lookup_table, alloc_mem, rng );
    break;
  }
  }
}
void *fd_address_lookup_table_state_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_address_lookup_table_state_t *self = (fd_address_lookup_table_state_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_address_lookup_table_state_t);
  fd_address_lookup_table_state_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_address_lookup_table_state_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_gossip_bitvec_u8_inner_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_bitvec_u8_inner_t *self = (fd_gossip_bitvec_u8_inner_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_bitvec_u8_inner_t);
  fd_gossip_bitvec_u8_inner_new(mem);
  self->vec_len = fd_rng_ulong( rng ) % 8;
  if( self->vec_len ) {
    self->vec = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->vec_len;
    for( ulong i=0; i < self->vec_len; ++i) { self->vec[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->vec = NULL;
  return mem;
}

void *fd_gossip_bitvec_u8_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_bitvec_u8_t *self = (fd_gossip_bitvec_u8_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_bitvec_u8_t);
  fd_gossip_bitvec_u8_new(mem);
  {
    self->has_bits = fd_rng_uchar( rng ) % 2;
    if( self->has_bits ) {
      fd_gossip_bitvec_u8_inner_generate( &self->bits, alloc_mem, rng );
    }
  }
  self->len = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_bitvec_u64_inner_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_bitvec_u64_inner_t *self = (fd_gossip_bitvec_u64_inner_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_bitvec_u64_inner_t);
  fd_gossip_bitvec_u64_inner_new(mem);
  self->vec_len = fd_rng_ulong( rng ) % 8;
  if( self->vec_len ) {
    self->vec = (ulong *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong)*self->vec_len;
    LLVMFuzzerMutate( (uchar *) self->vec, sizeof(ulong)*self->vec_len, sizeof(ulong)*self->vec_len );
  } else
    self->vec = NULL;
  return mem;
}

void *fd_gossip_bitvec_u64_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_bitvec_u64_t *self = (fd_gossip_bitvec_u64_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_bitvec_u64_t);
  fd_gossip_bitvec_u64_new(mem);
  {
    self->has_bits = fd_rng_uchar( rng ) % 2;
    if( self->has_bits ) {
      fd_gossip_bitvec_u64_inner_generate( &self->bits, alloc_mem, rng );
    }
  }
  self->len = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_ping_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_ping_t *self = (fd_gossip_ping_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_ping_t);
  fd_gossip_ping_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  fd_hash_generate( &self->token, alloc_mem, rng );
  fd_signature_generate( &self->signature, alloc_mem, rng );
  return mem;
}

void fd_gossip_ip_addr_inner_generate( fd_gossip_ip_addr_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ip4_addr_generate( &self->ip4, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_gossip_ip6_addr_generate( &self->ip6, alloc_mem, rng );
    break;
  }
  }
}
void *fd_gossip_ip_addr_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_ip_addr_t *self = (fd_gossip_ip_addr_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_ip_addr_t);
  fd_gossip_ip_addr_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_gossip_ip_addr_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_gossip_prune_data_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_prune_data_t *self = (fd_gossip_prune_data_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_prune_data_t);
  fd_gossip_prune_data_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->prunes_len = fd_rng_ulong( rng ) % 8;
  if( self->prunes_len ) {
    self->prunes = (fd_pubkey_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT*self->prunes_len;
    for( ulong i=0; i < self->prunes_len; i++ ) {
      fd_pubkey_new( self->prunes + i );
      fd_pubkey_generate( self->prunes + i, alloc_mem, rng );
    }
  } else
    self->prunes = NULL;
  fd_signature_generate( &self->signature, alloc_mem, rng );
  fd_pubkey_generate( &self->destination, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_prune_sign_data_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_prune_sign_data_t *self = (fd_gossip_prune_sign_data_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_prune_sign_data_t);
  fd_gossip_prune_sign_data_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->prunes_len = fd_rng_ulong( rng ) % 8;
  if( self->prunes_len ) {
    self->prunes = (fd_pubkey_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT*self->prunes_len;
    for( ulong i=0; i < self->prunes_len; i++ ) {
      fd_pubkey_new( self->prunes + i );
      fd_pubkey_generate( self->prunes + i, alloc_mem, rng );
    }
  } else
    self->prunes = NULL;
  fd_pubkey_generate( &self->destination, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_prune_sign_data_with_prefix_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_prune_sign_data_with_prefix_t *self = (fd_gossip_prune_sign_data_with_prefix_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_prune_sign_data_with_prefix_t);
  fd_gossip_prune_sign_data_with_prefix_new(mem);
  self->prefix_len = fd_rng_ulong( rng ) % 8;
  if( self->prefix_len ) {
    self->prefix = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->prefix_len;
    for( ulong i=0; i < self->prefix_len; ++i) { self->prefix[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->prefix = NULL;
  fd_gossip_prune_sign_data_generate( &self->data, alloc_mem, rng );
  return mem;
}

void *fd_gossip_socket_addr_old_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_socket_addr_old_t *self = (fd_gossip_socket_addr_old_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_socket_addr_old_t);
  fd_gossip_socket_addr_old_new(mem);
  fd_gossip_ip_addr_generate( &self->addr, alloc_mem, rng );
  self->port = fd_rng_ushort( rng );
  return mem;
}

void *fd_gossip_socket_addr_ip4_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_socket_addr_ip4_t *self = (fd_gossip_socket_addr_ip4_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_socket_addr_ip4_t);
  fd_gossip_socket_addr_ip4_new(mem);
  fd_gossip_ip4_addr_generate( &self->addr, alloc_mem, rng );
  self->port = fd_rng_ushort( rng );
  return mem;
}

void *fd_gossip_socket_addr_ip6_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_socket_addr_ip6_t *self = (fd_gossip_socket_addr_ip6_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_socket_addr_ip6_t);
  fd_gossip_socket_addr_ip6_new(mem);
  fd_gossip_ip6_addr_generate( &self->addr, alloc_mem, rng );
  self->port = fd_rng_ushort( rng );
  self->flowinfo = fd_rng_uint( rng );
  self->scope_id = fd_rng_uint( rng );
  return mem;
}

void fd_gossip_socket_addr_inner_generate( fd_gossip_socket_addr_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_socket_addr_ip4_generate( &self->ip4, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_gossip_socket_addr_ip6_generate( &self->ip6, alloc_mem, rng );
    break;
  }
  }
}
void *fd_gossip_socket_addr_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_socket_addr_t *self = (fd_gossip_socket_addr_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_socket_addr_t);
  fd_gossip_socket_addr_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_gossip_socket_addr_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_gossip_contact_info_v1_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_contact_info_v1_t *self = (fd_gossip_contact_info_v1_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_contact_info_v1_t);
  fd_gossip_contact_info_v1_new(mem);
  fd_pubkey_generate( &self->id, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->gossip, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->tvu, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->tvu_fwd, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->repair, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->tpu, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->tpu_fwd, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->tpu_vote, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->rpc, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->rpc_pubsub, alloc_mem, rng );
  fd_gossip_socket_addr_generate( &self->serve_repair, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  self->shred_version = fd_rng_ushort( rng );
  return mem;
}

void *fd_gossip_vote_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_vote_t *self = (fd_gossip_vote_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_vote_t);
  fd_gossip_vote_new(mem);
  self->index = fd_rng_uchar( rng );
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  fd_flamenco_txn_generate( &self->txn, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_lowest_slot_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_lowest_slot_t *self = (fd_gossip_lowest_slot_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_lowest_slot_t);
  fd_gossip_lowest_slot_new(mem);
  self->u8 = fd_rng_uchar( rng );
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->root = fd_rng_ulong( rng );
  self->lowest = fd_rng_ulong( rng );
  self->slots_len = fd_rng_ulong( rng ) % 8;
  if( self->slots_len ) {
    self->slots = (ulong *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong)*self->slots_len;
    LLVMFuzzerMutate( (uchar *) self->slots, sizeof(ulong)*self->slots_len, sizeof(ulong)*self->slots_len );
  } else
    self->slots = NULL;
  self->i_dont_know = fd_rng_ulong( rng );
  self->wallclock = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_slot_hashes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_slot_hashes_t *self = (fd_gossip_slot_hashes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_slot_hashes_t);
  fd_gossip_slot_hashes_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->hashes_len = fd_rng_ulong( rng ) % 8;
  if( self->hashes_len ) {
    self->hashes = (fd_slot_hash_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_SLOT_HASH_FOOTPRINT*self->hashes_len;
    for( ulong i=0; i < self->hashes_len; i++ ) {
      fd_slot_hash_new( self->hashes + i );
      fd_slot_hash_generate( self->hashes + i, alloc_mem, rng );
    }
  } else
    self->hashes = NULL;
  self->wallclock = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_slots_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_slots_t *self = (fd_gossip_slots_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_slots_t);
  fd_gossip_slots_new(mem);
  self->first_slot = fd_rng_ulong( rng );
  self->num = fd_rng_ulong( rng );
  fd_gossip_bitvec_u8_generate( &self->slots, alloc_mem, rng );
  return mem;
}

void *fd_gossip_flate2_slots_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_flate2_slots_t *self = (fd_gossip_flate2_slots_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_flate2_slots_t);
  fd_gossip_flate2_slots_new(mem);
  self->first_slot = fd_rng_ulong( rng );
  self->num = fd_rng_ulong( rng );
  self->compressed_len = fd_rng_ulong( rng ) % 8;
  if( self->compressed_len ) {
    self->compressed = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->compressed_len;
    for( ulong i=0; i < self->compressed_len; ++i) { self->compressed[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->compressed = NULL;
  return mem;
}

void fd_gossip_slots_enum_inner_generate( fd_gossip_slots_enum_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_flate2_slots_generate( &self->flate2, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_gossip_slots_generate( &self->uncompressed, alloc_mem, rng );
    break;
  }
  }
}
void *fd_gossip_slots_enum_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_slots_enum_t *self = (fd_gossip_slots_enum_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_slots_enum_t);
  fd_gossip_slots_enum_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_gossip_slots_enum_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_gossip_epoch_slots_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_epoch_slots_t *self = (fd_gossip_epoch_slots_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_epoch_slots_t);
  fd_gossip_epoch_slots_new(mem);
  self->u8 = fd_rng_uchar( rng );
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->slots_len = fd_rng_ulong( rng ) % 8;
  if( self->slots_len ) {
    self->slots = (fd_gossip_slots_enum_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_GOSSIP_SLOTS_ENUM_FOOTPRINT*self->slots_len;
    for( ulong i=0; i < self->slots_len; i++ ) {
      fd_gossip_slots_enum_new( self->slots + i );
      fd_gossip_slots_enum_generate( self->slots + i, alloc_mem, rng );
    }
  } else
    self->slots = NULL;
  self->wallclock = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_version_v1_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_version_v1_t *self = (fd_gossip_version_v1_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_version_v1_t);
  fd_gossip_version_v1_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  self->major = fd_rng_ushort( rng );
  self->minor = fd_rng_ushort( rng );
  self->patch = fd_rng_ushort( rng );
  {
    self->has_commit = fd_rng_uchar( rng ) % 2;
    if( self->has_commit ) {
      LLVMFuzzerMutate( (uchar *)&(self->commit), sizeof(uint), sizeof(uint) );
    }
  }
  return mem;
}

void *fd_gossip_version_v2_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_version_v2_t *self = (fd_gossip_version_v2_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_version_v2_t);
  fd_gossip_version_v2_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  self->major = fd_rng_ushort( rng );
  self->minor = fd_rng_ushort( rng );
  self->patch = fd_rng_ushort( rng );
  {
    self->has_commit = fd_rng_uchar( rng ) % 2;
    if( self->has_commit ) {
      LLVMFuzzerMutate( (uchar *)&(self->commit), sizeof(uint), sizeof(uint) );
    }
  }
  self->feature_set = fd_rng_uint( rng );
  return mem;
}

void *fd_gossip_version_v3_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_version_v3_t *self = (fd_gossip_version_v3_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_version_v3_t);
  fd_gossip_version_v3_new(mem);
  self->major = fd_rng_ushort( rng );
  self->minor = fd_rng_ushort( rng );
  self->patch = fd_rng_ushort( rng );
  self->commit = fd_rng_uint( rng );
  self->feature_set = fd_rng_uint( rng );
  self->client = fd_rng_ushort( rng );
  return mem;
}

void *fd_gossip_node_instance_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_node_instance_t *self = (fd_gossip_node_instance_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_node_instance_t);
  fd_gossip_node_instance_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  self->timestamp = fd_rng_long( rng );
  self->token = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_duplicate_shred_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_duplicate_shred_t *self = (fd_gossip_duplicate_shred_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_duplicate_shred_t);
  fd_gossip_duplicate_shred_new(mem);
  self->duplicate_shred_index = fd_rng_ushort( rng );
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  self->slot = fd_rng_ulong( rng );
  self->_unused = fd_rng_uint( rng );
  self->_unused_shred_type = fd_rng_uchar( rng );
  self->num_chunks = fd_rng_uchar( rng );
  self->chunk_index = fd_rng_uchar( rng );
  self->chunk_len = fd_rng_ulong( rng ) % 8;
  if( self->chunk_len ) {
    self->chunk = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->chunk_len;
    for( ulong i=0; i < self->chunk_len; ++i) { self->chunk[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->chunk = NULL;
  return mem;
}

void *fd_gossip_incremental_snapshot_hashes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_incremental_snapshot_hashes_t *self = (fd_gossip_incremental_snapshot_hashes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_incremental_snapshot_hashes_t);
  fd_gossip_incremental_snapshot_hashes_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  fd_slot_hash_generate( &self->base_hash, alloc_mem, rng );
  self->hashes_len = fd_rng_ulong( rng ) % 8;
  if( self->hashes_len ) {
    self->hashes = (fd_slot_hash_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_SLOT_HASH_FOOTPRINT*self->hashes_len;
    for( ulong i=0; i < self->hashes_len; i++ ) {
      fd_slot_hash_new( self->hashes + i );
      fd_slot_hash_generate( self->hashes + i, alloc_mem, rng );
    }
  } else
    self->hashes = NULL;
  self->wallclock = fd_rng_ulong( rng );
  return mem;
}

void *fd_gossip_socket_entry_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_socket_entry_t *self = (fd_gossip_socket_entry_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_socket_entry_t);
  fd_gossip_socket_entry_new(mem);
  self->key = fd_rng_uchar( rng );
  self->index = fd_rng_uchar( rng );
  self->offset = fd_rng_ushort( rng );
  return mem;
}

void *fd_gossip_contact_info_v2_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_contact_info_v2_t *self = (fd_gossip_contact_info_v2_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_contact_info_v2_t);
  fd_gossip_contact_info_v2_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  self->outset = fd_rng_ulong( rng );
  self->shred_version = fd_rng_ushort( rng );
  fd_gossip_version_v3_generate( &self->version, alloc_mem, rng );
  self->addrs_len = fd_rng_ulong( rng ) % 8;
  if( self->addrs_len ) {
    self->addrs = (fd_gossip_ip_addr_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_GOSSIP_IP_ADDR_FOOTPRINT*self->addrs_len;
    for( ulong i=0; i < self->addrs_len; i++ ) {
      fd_gossip_ip_addr_new( self->addrs + i );
      fd_gossip_ip_addr_generate( self->addrs + i, alloc_mem, rng );
    }
  } else
    self->addrs = NULL;
  self->sockets_len = fd_rng_ulong( rng ) % 8;
  if( self->sockets_len ) {
    self->sockets = (fd_gossip_socket_entry_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_GOSSIP_SOCKET_ENTRY_FOOTPRINT*self->sockets_len;
    for( ulong i=0; i < self->sockets_len; i++ ) {
      fd_gossip_socket_entry_new( self->sockets + i );
      fd_gossip_socket_entry_generate( self->sockets + i, alloc_mem, rng );
    }
  } else
    self->sockets = NULL;
  self->extensions_len = fd_rng_ulong( rng ) % 8;
  if( self->extensions_len ) {
    self->extensions = (uint *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + sizeof(uint)*self->extensions_len;
    LLVMFuzzerMutate( (uchar *) self->extensions, sizeof(uint)*self->extensions_len, sizeof(uint)*self->extensions_len );
  } else
    self->extensions = NULL;
  return mem;
}

void *fd_restart_run_length_encoding_inner_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_restart_run_length_encoding_inner_t *self = (fd_restart_run_length_encoding_inner_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_restart_run_length_encoding_inner_t);
  fd_restart_run_length_encoding_inner_new(mem);
  self->bits = fd_rng_ushort( rng );
  return mem;
}

void *fd_restart_run_length_encoding_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_restart_run_length_encoding_t *self = (fd_restart_run_length_encoding_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_restart_run_length_encoding_t);
  fd_restart_run_length_encoding_new(mem);
  self->offsets_len = fd_rng_ulong( rng ) % 8;
  if( self->offsets_len ) {
    self->offsets = (fd_restart_run_length_encoding_inner_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_RESTART_RUN_LENGTH_ENCODING_INNER_FOOTPRINT*self->offsets_len;
    for( ulong i=0; i < self->offsets_len; i++ ) {
      fd_restart_run_length_encoding_inner_new( self->offsets + i );
      fd_restart_run_length_encoding_inner_generate( self->offsets + i, alloc_mem, rng );
    }
  } else
    self->offsets = NULL;
  return mem;
}

void *fd_restart_raw_offsets_bitvec_u8_inner_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_restart_raw_offsets_bitvec_u8_inner_t *self = (fd_restart_raw_offsets_bitvec_u8_inner_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_restart_raw_offsets_bitvec_u8_inner_t);
  fd_restart_raw_offsets_bitvec_u8_inner_new(mem);
  self->bits_len = fd_rng_ulong( rng ) % 8;
  if( self->bits_len ) {
    self->bits = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->bits_len;
    for( ulong i=0; i < self->bits_len; ++i) { self->bits[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->bits = NULL;
  return mem;
}

void *fd_restart_raw_offsets_bitvec_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_restart_raw_offsets_bitvec_t *self = (fd_restart_raw_offsets_bitvec_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_restart_raw_offsets_bitvec_t);
  fd_restart_raw_offsets_bitvec_new(mem);
  {
    self->has_bits = fd_rng_uchar( rng ) % 2;
    if( self->has_bits ) {
      fd_restart_raw_offsets_bitvec_u8_inner_generate( &self->bits, alloc_mem, rng );
    }
  }
  self->len = fd_rng_ulong( rng );
  return mem;
}

void *fd_restart_raw_offsets_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_restart_raw_offsets_t *self = (fd_restart_raw_offsets_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_restart_raw_offsets_t);
  fd_restart_raw_offsets_new(mem);
  fd_restart_raw_offsets_bitvec_generate( &self->offsets, alloc_mem, rng );
  return mem;
}

void fd_restart_slots_offsets_inner_generate( fd_restart_slots_offsets_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_restart_run_length_encoding_generate( &self->run_length_encoding, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_restart_raw_offsets_generate( &self->raw_offsets, alloc_mem, rng );
    break;
  }
  }
}
void *fd_restart_slots_offsets_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_restart_slots_offsets_t *self = (fd_restart_slots_offsets_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_restart_slots_offsets_t);
  fd_restart_slots_offsets_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_restart_slots_offsets_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_gossip_restart_last_voted_fork_slots_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_restart_last_voted_fork_slots_t *self = (fd_gossip_restart_last_voted_fork_slots_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_restart_last_voted_fork_slots_t);
  fd_gossip_restart_last_voted_fork_slots_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  fd_restart_slots_offsets_generate( &self->offsets, alloc_mem, rng );
  self->last_voted_slot = fd_rng_ulong( rng );
  fd_hash_generate( &self->last_voted_hash, alloc_mem, rng );
  self->shred_version = fd_rng_ushort( rng );
  return mem;
}

void *fd_gossip_restart_heaviest_fork_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_restart_heaviest_fork_t *self = (fd_gossip_restart_heaviest_fork_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_restart_heaviest_fork_t);
  fd_gossip_restart_heaviest_fork_new(mem);
  fd_pubkey_generate( &self->from, alloc_mem, rng );
  self->wallclock = fd_rng_ulong( rng );
  self->last_slot = fd_rng_ulong( rng );
  fd_hash_generate( &self->last_slot_hash, alloc_mem, rng );
  self->observed_stake = fd_rng_ulong( rng );
  self->shred_version = fd_rng_ushort( rng );
  return mem;
}

void fd_crds_data_inner_generate( fd_crds_data_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_contact_info_v1_generate( &self->contact_info_v1, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_gossip_vote_generate( &self->vote, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_gossip_lowest_slot_generate( &self->lowest_slot, alloc_mem, rng );
    break;
  }
  case 3: {
    fd_gossip_slot_hashes_generate( &self->snapshot_hashes, alloc_mem, rng );
    break;
  }
  case 4: {
    fd_gossip_slot_hashes_generate( &self->accounts_hashes, alloc_mem, rng );
    break;
  }
  case 5: {
    fd_gossip_epoch_slots_generate( &self->epoch_slots, alloc_mem, rng );
    break;
  }
  case 6: {
    fd_gossip_version_v1_generate( &self->version_v1, alloc_mem, rng );
    break;
  }
  case 7: {
    fd_gossip_version_v2_generate( &self->version_v2, alloc_mem, rng );
    break;
  }
  case 8: {
    fd_gossip_node_instance_generate( &self->node_instance, alloc_mem, rng );
    break;
  }
  case 9: {
    fd_gossip_duplicate_shred_generate( &self->duplicate_shred, alloc_mem, rng );
    break;
  }
  case 10: {
    fd_gossip_incremental_snapshot_hashes_generate( &self->incremental_snapshot_hashes, alloc_mem, rng );
    break;
  }
  case 11: {
    fd_gossip_contact_info_v2_generate( &self->contact_info_v2, alloc_mem, rng );
    break;
  }
  case 12: {
    fd_gossip_restart_last_voted_fork_slots_generate( &self->restart_last_voted_fork_slots, alloc_mem, rng );
    break;
  }
  case 13: {
    fd_gossip_restart_heaviest_fork_generate( &self->restart_heaviest_fork, alloc_mem, rng );
    break;
  }
  }
}
void *fd_crds_data_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_crds_data_t *self = (fd_crds_data_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_crds_data_t);
  fd_crds_data_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 14;
  fd_crds_data_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_crds_bloom_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_crds_bloom_t *self = (fd_crds_bloom_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_crds_bloom_t);
  fd_crds_bloom_new(mem);
  self->keys_len = fd_rng_ulong( rng ) % 8;
  if( self->keys_len ) {
    self->keys = (ulong *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + sizeof(ulong)*self->keys_len;
    LLVMFuzzerMutate( (uchar *) self->keys, sizeof(ulong)*self->keys_len, sizeof(ulong)*self->keys_len );
  } else
    self->keys = NULL;
  fd_gossip_bitvec_u64_generate( &self->bits, alloc_mem, rng );
  self->num_bits_set = fd_rng_ulong( rng );
  return mem;
}

void *fd_crds_filter_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_crds_filter_t *self = (fd_crds_filter_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_crds_filter_t);
  fd_crds_filter_new(mem);
  fd_crds_bloom_generate( &self->filter, alloc_mem, rng );
  self->mask = fd_rng_ulong( rng );
  self->mask_bits = fd_rng_uint( rng );
  return mem;
}

void *fd_crds_value_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_crds_value_t *self = (fd_crds_value_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_crds_value_t);
  fd_crds_value_new(mem);
  fd_signature_generate( &self->signature, alloc_mem, rng );
  fd_crds_data_generate( &self->data, alloc_mem, rng );
  return mem;
}

void *fd_gossip_pull_req_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_pull_req_t *self = (fd_gossip_pull_req_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_pull_req_t);
  fd_gossip_pull_req_new(mem);
  fd_crds_filter_generate( &self->filter, alloc_mem, rng );
  fd_crds_value_generate( &self->value, alloc_mem, rng );
  return mem;
}

void *fd_gossip_pull_resp_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_pull_resp_t *self = (fd_gossip_pull_resp_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_pull_resp_t);
  fd_gossip_pull_resp_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->crds_len = fd_rng_ulong( rng ) % 8;
  if( self->crds_len ) {
    self->crds = (fd_crds_value_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_CRDS_VALUE_FOOTPRINT*self->crds_len;
    for( ulong i=0; i < self->crds_len; i++ ) {
      fd_crds_value_new( self->crds + i );
      fd_crds_value_generate( self->crds + i, alloc_mem, rng );
    }
  } else
    self->crds = NULL;
  return mem;
}

void *fd_gossip_push_msg_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_push_msg_t *self = (fd_gossip_push_msg_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_push_msg_t);
  fd_gossip_push_msg_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  self->crds_len = fd_rng_ulong( rng ) % 8;
  if( self->crds_len ) {
    self->crds = (fd_crds_value_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_CRDS_VALUE_FOOTPRINT*self->crds_len;
    for( ulong i=0; i < self->crds_len; i++ ) {
      fd_crds_value_new( self->crds + i );
      fd_crds_value_generate( self->crds + i, alloc_mem, rng );
    }
  } else
    self->crds = NULL;
  return mem;
}

void *fd_gossip_prune_msg_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_prune_msg_t *self = (fd_gossip_prune_msg_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_prune_msg_t);
  fd_gossip_prune_msg_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  fd_gossip_prune_data_generate( &self->data, alloc_mem, rng );
  return mem;
}

void fd_gossip_msg_inner_generate( fd_gossip_msg_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_pull_req_generate( &self->pull_req, alloc_mem, rng );
    break;
  }
  case 1: {
    fd_gossip_pull_resp_generate( &self->pull_resp, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_gossip_push_msg_generate( &self->push_msg, alloc_mem, rng );
    break;
  }
  case 3: {
    fd_gossip_prune_msg_generate( &self->prune_msg, alloc_mem, rng );
    break;
  }
  case 4: {
    fd_gossip_ping_generate( &self->ping, alloc_mem, rng );
    break;
  }
  case 5: {
    fd_gossip_ping_generate( &self->pong, alloc_mem, rng );
    break;
  }
  }
}
void *fd_gossip_msg_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_gossip_msg_t *self = (fd_gossip_msg_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_gossip_msg_t);
  fd_gossip_msg_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 6;
  while( self->discriminant == 0 || self->discriminant == 1 || self->discriminant == 2 ) { self->discriminant = fd_rng_uint( rng ) % 6; }
  fd_gossip_msg_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_addrlut_create_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_addrlut_create_t *self = (fd_addrlut_create_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_addrlut_create_t);
  fd_addrlut_create_new(mem);
  self->recent_slot = fd_rng_ulong( rng );
  self->bump_seed = fd_rng_uchar( rng );
  return mem;
}

void *fd_addrlut_extend_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_addrlut_extend_t *self = (fd_addrlut_extend_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_addrlut_extend_t);
  fd_addrlut_extend_new(mem);
  self->new_addrs_len = fd_rng_ulong( rng ) % 8;
  if( self->new_addrs_len ) {
    self->new_addrs = (fd_pubkey_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_PUBKEY_FOOTPRINT*self->new_addrs_len;
    for( ulong i=0; i < self->new_addrs_len; i++ ) {
      fd_pubkey_new( self->new_addrs + i );
      fd_pubkey_generate( self->new_addrs + i, alloc_mem, rng );
    }
  } else
    self->new_addrs = NULL;
  return mem;
}

void fd_addrlut_instruction_inner_generate( fd_addrlut_instruction_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_addrlut_create_generate( &self->create_lut, alloc_mem, rng );
    break;
  }
  case 2: {
    fd_addrlut_extend_generate( &self->extend_lut, alloc_mem, rng );
    break;
  }
  }
}
void *fd_addrlut_instruction_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_addrlut_instruction_t *self = (fd_addrlut_instruction_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_addrlut_instruction_t);
  fd_addrlut_instruction_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 5;
  fd_addrlut_instruction_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_repair_request_header_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_repair_request_header_t *self = (fd_repair_request_header_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_repair_request_header_t);
  fd_repair_request_header_new(mem);
  fd_signature_generate( &self->signature, alloc_mem, rng );
  fd_pubkey_generate( &self->sender, alloc_mem, rng );
  fd_pubkey_generate( &self->recipient, alloc_mem, rng );
  self->timestamp = fd_rng_long( rng );
  self->nonce = fd_rng_uint( rng );
  return mem;
}

void *fd_repair_window_index_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_repair_window_index_t *self = (fd_repair_window_index_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_repair_window_index_t);
  fd_repair_window_index_new(mem);
  fd_repair_request_header_generate( &self->header, alloc_mem, rng );
  self->slot = fd_rng_ulong( rng );
  self->shred_index = fd_rng_ulong( rng );
  return mem;
}

void *fd_repair_highest_window_index_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_repair_highest_window_index_t *self = (fd_repair_highest_window_index_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_repair_highest_window_index_t);
  fd_repair_highest_window_index_new(mem);
  fd_repair_request_header_generate( &self->header, alloc_mem, rng );
  self->slot = fd_rng_ulong( rng );
  self->shred_index = fd_rng_ulong( rng );
  return mem;
}

void *fd_repair_orphan_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_repair_orphan_t *self = (fd_repair_orphan_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_repair_orphan_t);
  fd_repair_orphan_new(mem);
  fd_repair_request_header_generate( &self->header, alloc_mem, rng );
  self->slot = fd_rng_ulong( rng );
  return mem;
}

void *fd_repair_ancestor_hashes_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_repair_ancestor_hashes_t *self = (fd_repair_ancestor_hashes_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_repair_ancestor_hashes_t);
  fd_repair_ancestor_hashes_new(mem);
  fd_repair_request_header_generate( &self->header, alloc_mem, rng );
  self->slot = fd_rng_ulong( rng );
  return mem;
}

void fd_repair_protocol_inner_generate( fd_repair_protocol_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 7: {
    fd_gossip_ping_generate( &self->pong, alloc_mem, rng );
    break;
  }
  case 8: {
    fd_repair_window_index_generate( &self->window_index, alloc_mem, rng );
    break;
  }
  case 9: {
    fd_repair_highest_window_index_generate( &self->highest_window_index, alloc_mem, rng );
    break;
  }
  case 10: {
    fd_repair_orphan_generate( &self->orphan, alloc_mem, rng );
    break;
  }
  case 11: {
    fd_repair_ancestor_hashes_generate( &self->ancestor_hashes, alloc_mem, rng );
    break;
  }
  }
}
void *fd_repair_protocol_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_repair_protocol_t *self = (fd_repair_protocol_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_repair_protocol_t);
  fd_repair_protocol_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 12;
  fd_repair_protocol_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void fd_repair_response_inner_generate( fd_repair_response_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ping_generate( &self->ping, alloc_mem, rng );
    break;
  }
  }
}
void *fd_repair_response_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_repair_response_t *self = (fd_repair_response_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_repair_response_t);
  fd_repair_response_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 1;
  fd_repair_response_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void fd_instr_error_enum_inner_generate( fd_instr_error_enum_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 25: {
    self->custom = fd_rng_uint( rng );
    break;
  }
  case 44: {
    ulong slen = fd_rng_ulong( rng ) % 256;
    char *buffer = (char *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + slen;
    self->borsh_io_error = buffer;
    LLVMFuzzerMutate( (uchar *)self->borsh_io_error, slen, slen );
    self->borsh_io_error[slen] = '\0';
    break;
  }
  }
}
void *fd_instr_error_enum_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_instr_error_enum_t *self = (fd_instr_error_enum_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_instr_error_enum_t);
  fd_instr_error_enum_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 54;
  fd_instr_error_enum_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_txn_instr_error_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_txn_instr_error_t *self = (fd_txn_instr_error_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_txn_instr_error_t);
  fd_txn_instr_error_new(mem);
  self->instr_idx = fd_rng_uchar( rng );
  fd_instr_error_enum_generate( &self->error, alloc_mem, rng );
  return mem;
}

void fd_txn_error_enum_inner_generate( fd_txn_error_enum_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 8: {
    fd_txn_instr_error_generate( &self->instruction_error, alloc_mem, rng );
    break;
  }
  case 30: {
    self->duplicate_instruction = fd_rng_uchar( rng );
    break;
  }
  case 31: {
    self->insufficient_funds_for_rent = fd_rng_uchar( rng );
    break;
  }
  case 35: {
    self->program_execution_temporarily_restricted = fd_rng_uchar( rng );
    break;
  }
  }
}
void *fd_txn_error_enum_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_txn_error_enum_t *self = (fd_txn_error_enum_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_txn_error_enum_t);
  fd_txn_error_enum_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 37;
  fd_txn_error_enum_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void fd_txn_result_inner_generate( fd_txn_result_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 1: {
    fd_txn_error_enum_generate( &self->error, alloc_mem, rng );
    break;
  }
  }
}
void *fd_txn_result_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_txn_result_t *self = (fd_txn_result_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_txn_result_t);
  fd_txn_result_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_txn_result_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_cache_status_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_cache_status_t *self = (fd_cache_status_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_cache_status_t);
  fd_cache_status_new(mem);
  LLVMFuzzerMutate( self->key_slice, 20, 20 );
  fd_txn_result_generate( &self->result, alloc_mem, rng );
  return mem;
}

void *fd_status_value_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_status_value_t *self = (fd_status_value_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_status_value_t);
  fd_status_value_new(mem);
  self->txn_idx = fd_rng_ulong( rng );
  self->statuses_len = fd_rng_ulong( rng ) % 8;
  if( self->statuses_len ) {
    self->statuses = (fd_cache_status_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_CACHE_STATUS_FOOTPRINT*self->statuses_len;
    for( ulong i=0; i < self->statuses_len; i++ ) {
      fd_cache_status_new( self->statuses + i );
      fd_cache_status_generate( self->statuses + i, alloc_mem, rng );
    }
  } else
    self->statuses = NULL;
  return mem;
}

void *fd_status_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_status_pair_t *self = (fd_status_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_status_pair_t);
  fd_status_pair_new(mem);
  fd_hash_generate( &self->hash, alloc_mem, rng );
  fd_status_value_generate( &self->value, alloc_mem, rng );
  return mem;
}

void *fd_slot_delta_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_slot_delta_t *self = (fd_slot_delta_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_slot_delta_t);
  fd_slot_delta_new(mem);
  self->slot = fd_rng_ulong( rng );
  self->is_root = fd_rng_uchar( rng );
  self->slot_delta_vec_len = fd_rng_ulong( rng ) % 8;
  if( self->slot_delta_vec_len ) {
    self->slot_delta_vec = (fd_status_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_STATUS_PAIR_FOOTPRINT*self->slot_delta_vec_len;
    for( ulong i=0; i < self->slot_delta_vec_len; i++ ) {
      fd_status_pair_new( self->slot_delta_vec + i );
      fd_status_pair_generate( self->slot_delta_vec + i, alloc_mem, rng );
    }
  } else
    self->slot_delta_vec = NULL;
  return mem;
}

void *fd_bank_slot_deltas_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_bank_slot_deltas_t *self = (fd_bank_slot_deltas_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_bank_slot_deltas_t);
  fd_bank_slot_deltas_new(mem);
  self->slot_deltas_len = fd_rng_ulong( rng ) % 8;
  if( self->slot_deltas_len ) {
    self->slot_deltas = (fd_slot_delta_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_SLOT_DELTA_FOOTPRINT*self->slot_deltas_len;
    for( ulong i=0; i < self->slot_deltas_len; i++ ) {
      fd_slot_delta_new( self->slot_deltas + i );
      fd_slot_delta_generate( self->slot_deltas + i, alloc_mem, rng );
    }
  } else
    self->slot_deltas = NULL;
  return mem;
}

void *fd_pubkey_rewardinfo_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_pubkey_rewardinfo_pair_t *self = (fd_pubkey_rewardinfo_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_pubkey_rewardinfo_pair_t);
  fd_pubkey_rewardinfo_pair_new(mem);
  fd_pubkey_generate( &self->pubkey, alloc_mem, rng );
  fd_reward_info_generate( &self->reward_info, alloc_mem, rng );
  return mem;
}

void *fd_optional_account_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_optional_account_t *self = (fd_optional_account_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_optional_account_t);
  fd_optional_account_new(mem);
  {
    uchar is_null = fd_rng_uchar( rng ) % 2;
    if( !is_null ) {
      self->account = (fd_solana_account_t *) *alloc_mem;
      *alloc_mem = (uchar *) *alloc_mem + FD_SOLANA_ACCOUNT_FOOTPRINT;
      fd_solana_account_new( self->account );
      fd_solana_account_generate( self->account, alloc_mem, rng );
    }
    else {
    self->account = NULL;
    }
  }
  return mem;
}

void *fd_calculated_stake_points_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_calculated_stake_points_t *self = (fd_calculated_stake_points_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_calculated_stake_points_t);
  fd_calculated_stake_points_new(mem);
  self->points = fd_rng_uint128( rng );
  self->new_credits_observed = fd_rng_ulong( rng );
  self->force_credits_update_with_skipped_reward = fd_rng_uchar( rng );
  return mem;
}

void *fd_calculated_stake_rewards_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_calculated_stake_rewards_t *self = (fd_calculated_stake_rewards_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_calculated_stake_rewards_t);
  fd_calculated_stake_rewards_new(mem);
  self->staker_rewards = fd_rng_ulong( rng );
  self->voter_rewards = fd_rng_ulong( rng );
  self->new_credits_observed = fd_rng_ulong( rng );
  return mem;
}

void *fd_duplicate_slot_proof_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_duplicate_slot_proof_t *self = (fd_duplicate_slot_proof_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_duplicate_slot_proof_t);
  fd_duplicate_slot_proof_new(mem);
  self->shred1_len = fd_rng_ulong( rng ) % 8;
  if( self->shred1_len ) {
    self->shred1 = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->shred1_len;
    for( ulong i=0; i < self->shred1_len; ++i) { self->shred1[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->shred1 = NULL;
  self->shred2_len = fd_rng_ulong( rng ) % 8;
  if( self->shred2_len ) {
    self->shred2 = (uchar *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + self->shred2_len;
    for( ulong i=0; i < self->shred2_len; ++i) { self->shred2[i] = fd_rng_uchar( rng ) % 0x80; }
  } else
    self->shred2 = NULL;
  return mem;
}

void *fd_epoch_info_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_epoch_info_pair_t *self = (fd_epoch_info_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_epoch_info_pair_t);
  fd_epoch_info_pair_new(mem);
  fd_pubkey_generate( &self->account, alloc_mem, rng );
  fd_stake_generate( &self->stake, alloc_mem, rng );
  return mem;
}

void *fd_vote_info_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_vote_info_pair_t *self = (fd_vote_info_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_vote_info_pair_t);
  fd_vote_info_pair_new(mem);
  fd_pubkey_generate( &self->account, alloc_mem, rng );
  fd_vote_state_versioned_generate( &self->state, alloc_mem, rng );
  return mem;
}

void *fd_epoch_info_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_epoch_info_t *self = (fd_epoch_info_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_epoch_info_t);
  fd_epoch_info_new(mem);
  self->stake_infos_len = fd_rng_ulong( rng ) % 8;
  if( self->stake_infos_len ) {
    self->stake_infos = (fd_epoch_info_pair_t *) *alloc_mem;
    *alloc_mem = (uchar *) *alloc_mem + FD_EPOCH_INFO_PAIR_FOOTPRINT*self->stake_infos_len;
    for( ulong i=0; i < self->stake_infos_len; i++ ) {
      fd_epoch_info_pair_new( self->stake_infos + i );
      fd_epoch_info_pair_generate( self->stake_infos + i, alloc_mem, rng );
    }
  } else
    self->stake_infos = NULL;
  ulong vote_states_len = fd_rng_ulong( rng ) % 8;
  self->vote_states_pool = fd_vote_info_pair_t_map_join_new( alloc_mem, vote_states_len );
  self->vote_states_root = NULL;
  for( ulong i=0; i < vote_states_len; i++ ) {
    fd_vote_info_pair_t_mapnode_t * node = fd_vote_info_pair_t_map_acquire( self->vote_states_pool );
    fd_vote_info_pair_generate( &node->elem, alloc_mem, rng );
    fd_vote_info_pair_t_map_insert( self->vote_states_pool, &self->vote_states_root, node );
  }
  self->stake_infos_new_keys_start_idx = fd_rng_ulong( rng );
  return mem;
}

void *fd_usage_cost_details_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_usage_cost_details_t *self = (fd_usage_cost_details_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_usage_cost_details_t);
  fd_usage_cost_details_new(mem);
  self->signature_cost = fd_rng_ulong( rng );
  self->write_lock_cost = fd_rng_ulong( rng );
  self->data_bytes_cost = fd_rng_ulong( rng );
  self->programs_execution_cost = fd_rng_ulong( rng );
  self->loaded_accounts_data_size_cost = fd_rng_ulong( rng );
  self->allocated_accounts_data_size = fd_rng_ulong( rng );
  return mem;
}

void fd_transaction_cost_inner_generate( fd_transaction_cost_inner_t * self, void **alloc_mem, uint discriminant, fd_rng_t * rng ) {
  switch (discriminant) {
  case 1: {
    fd_usage_cost_details_generate( &self->transaction, alloc_mem, rng );
    break;
  }
  }
}
void *fd_transaction_cost_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_transaction_cost_t *self = (fd_transaction_cost_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_transaction_cost_t);
  fd_transaction_cost_new(mem);
  self->discriminant = fd_rng_uint( rng ) % 2;
  fd_transaction_cost_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );
  return mem;
}

void *fd_account_costs_pair_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_account_costs_pair_t *self = (fd_account_costs_pair_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_account_costs_pair_t);
  fd_account_costs_pair_new(mem);
  fd_pubkey_generate( &self->key, alloc_mem, rng );
  self->cost = fd_rng_ulong( rng );
  return mem;
}

void *fd_account_costs_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_account_costs_t *self = (fd_account_costs_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_account_costs_t);
  fd_account_costs_new(mem);
  ulong account_costs_len = fd_rng_ulong( rng ) % 8;
  self->account_costs_pool = fd_account_costs_pair_t_map_join_new( alloc_mem, fd_ulong_max( account_costs_len, 4096 ) );
  self->account_costs_root = NULL;
  for( ulong i=0; i < account_costs_len; i++ ) {
    fd_account_costs_pair_t_mapnode_t * node = fd_account_costs_pair_t_map_acquire( self->account_costs_pool );
    fd_account_costs_pair_generate( &node->elem, alloc_mem, rng );
    fd_account_costs_pair_t_map_insert( self->account_costs_pool, &self->account_costs_root, node );
  }
  return mem;
}

void *fd_cost_tracker_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {
  fd_cost_tracker_t *self = (fd_cost_tracker_t *) mem;
  *alloc_mem = (uchar *) *alloc_mem + sizeof(fd_cost_tracker_t);
  fd_cost_tracker_new(mem);
  self->account_cost_limit = fd_rng_ulong( rng );
  self->block_cost_limit = fd_rng_ulong( rng );
  self->vote_cost_limit = fd_rng_ulong( rng );
  fd_account_costs_generate( &self->cost_by_writable_accounts, alloc_mem, rng );
  self->block_cost = fd_rng_ulong( rng );
  self->vote_cost = fd_rng_ulong( rng );
  self->transaction_count = fd_rng_ulong( rng );
  self->allocated_accounts_data_size = fd_rng_ulong( rng );
  self->transaction_signature_count = fd_rng_ulong( rng );
  self->secp256k1_instruction_signature_count = fd_rng_ulong( rng );
  self->ed25519_instruction_signature_count = fd_rng_ulong( rng );
  self->secp256r1_instruction_signature_count = fd_rng_ulong( rng );
  return mem;
}

#endif // HEADER_FUZZ_FD_RUNTIME_TYPES
