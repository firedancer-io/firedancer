#include "fd_banks_solana.h"

void fd_fee_calculator_decode(fd_fee_calculator_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_signature, data, dataend);
}

void fd_fee_calculator_destroy(FD_FN_UNUSED fd_fee_calculator_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_hash_age_decode(fd_hash_age_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_fee_calculator_decode(&self->fee_calculator, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->hash_index, data, dataend);
  fd_bincode_uint64_decode(&self->timestamp, data, dataend);
}

void fd_hash_age_destroy(fd_hash_age_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_fee_calculator_destroy(&self->fee_calculator, freef, freef_arg);
}

void fd_hash_decode(fd_hash_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->hash[0], sizeof(self->hash), data, dataend);
}

void fd_hash_destroy(FD_FN_UNUSED fd_hash_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_hash_hash_age_pair_decode(fd_hash_hash_age_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(self->key.hash, sizeof(self->key.hash), data, dataend);
  fd_hash_age_decode(&self->val, data, dataend, allocf, allocf_arg);
}

void fd_hash_hash_age_pair_destroy(fd_hash_hash_age_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_hash_destroy(&self->key, freef, freef_arg);
  fd_hash_age_destroy(&self->val, freef, freef_arg);
}

void fd_block_hash_queue_decode(fd_block_hash_queue_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->last_hash_index, data, dataend);

  if (fd_bincode_option_decode(data, dataend)) {
    self->last_hash = (fd_hash_t*)(*allocf)(FD_HASH_FOOTPRINT, FD_HASH_ALIGN, allocf_arg);
    fd_hash_decode(self->last_hash, data, dataend, allocf, allocf_arg);
  } else {
    self->last_hash = NULL;
  }

  fd_bincode_uint64_decode(&self->ages_len, data, dataend);
  if (self->ages_len > 0) {
    self->ages = (fd_hash_hash_age_pair_t*)(*allocf)(FD_HASH_HASH_AGE_PAIR_FOOTPRINT*self->ages_len, FD_HASH_HASH_AGE_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_pair_decode(self->ages + i, data, dataend, allocf, allocf_arg);
  } else
    self->ages = NULL;

  fd_bincode_uint64_decode(&self->max_age, data, dataend);
}

void fd_block_hash_queue_destroy(fd_block_hash_queue_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->last_hash) {
    fd_hash_destroy(self->last_hash, freef, freef_arg);
    freef(self->last_hash, freef_arg);
    self->last_hash = NULL;
  }

  if (NULL != self->ages) {
    for (ulong i = 0; i < self->ages_len; ++i) {
      fd_hash_hash_age_pair_destroy(self->ages + i, freef, freef_arg);
    }
    freef(self->ages, freef_arg);
    self->ages = NULL;
  }
}

void fd_pubkey_decode(fd_pubkey_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->key[0], sizeof(self->key), data, dataend);
}

void fd_pubkey_destroy(FD_FN_UNUSED fd_pubkey_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_epoch_schedule_decode(fd_epoch_schedule_t* self,  void const** data,  void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slots_per_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->leader_schedule_slot_offset, data, dataend);
  fd_bincode_uint8_decode(&self->warmup, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_slot, data, dataend);
}

void fd_epoch_schedule_destroy(FD_FN_UNUSED fd_epoch_schedule_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_fee_rate_governor_decode(fd_fee_rate_governor_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->target_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->target_signatures_per_slot, data, dataend);
  fd_bincode_uint64_decode(&self->min_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->max_lamports_per_signature, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}

void fd_fee_rate_governor_destroy(FD_FN_UNUSED fd_fee_rate_governor_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_slot_pair_decode(fd_slot_pair_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->val, data, dataend);
}

void fd_slot_pair_destroy(FD_FN_UNUSED fd_slot_pair_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_hard_forks_decode(fd_hard_forks_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->len, data, dataend);
  if (self->len > 0) {
    self->hard_forks = (fd_slot_pair_t*)(*allocf)(FD_SLOT_PAIR_FOOTPRINT*self->len, FD_SLOT_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->len; ++i)
      fd_slot_pair_decode(self->hard_forks + i, data, dataend, allocf, allocf_arg);
  } else
    self->hard_forks = NULL;
}

void fd_hard_forks_destroy(fd_hard_forks_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->hard_forks) {
    for (ulong i = 0; i < self->len; ++i) {
      fd_slot_pair_destroy(self->hard_forks, freef, freef_arg);
    }
    freef(self->hard_forks, freef_arg);
    self->hard_forks = NULL;
  }
}

void fd_inflation_decode(fd_inflation_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_double_decode(&self->initial, data, dataend);
  fd_bincode_double_decode(&self->terminal, data, dataend);
  fd_bincode_double_decode(&self->taper, data, dataend);
  fd_bincode_double_decode(&self->foundation, data, dataend);
  fd_bincode_double_decode(&self->foundation_term, data, dataend);
  fd_bincode_double_decode(&self->__unused, data, dataend);
}

void fd_inflation_destroy(FD_FN_UNUSED fd_inflation_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_rent_decode(FD_FN_UNUSED fd_rent_t* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_uint8_year, data, dataend);
  fd_bincode_double_decode(&self->exemption_threshold, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}

void fd_rent_destroy(FD_FN_UNUSED fd_rent_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_rent_collector_decode(fd_rent_collector_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_epoch_schedule_decode(&self->epoch_schedule, data, dataend, allocf, allocf_arg);
  fd_bincode_double_decode(&self->slots_per_year, data, dataend);
  fd_rent_decode(&self->rent, data, dataend, allocf, allocf_arg);
}

void fd_rent_collector_destroy(fd_rent_collector_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_epoch_schedule_destroy(&self->epoch_schedule, freef, freef_arg);
  fd_rent_destroy(&self->rent, freef, freef_arg);
}

void fd_stake_history_entry_decode(FD_FN_UNUSED fd_stake_history_entry_t* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->effective, data, dataend);
  fd_bincode_uint64_decode(&self->activating, data, dataend);
  fd_bincode_uint64_decode(&self->deactivating, data, dataend);
}

void fd_stake_history_entry_destroy(FD_FN_UNUSED fd_stake_history_entry_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}

void fd_stake_history_epochentry_pair_decode(fd_stake_history_epochentry_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_stake_history_entry_decode(&self->entry, data, dataend, allocf, allocf_arg);
}

void fd_stake_history_epochentry_pair_destroy(fd_stake_history_epochentry_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_stake_history_entry_destroy(&self->entry, freef, freef_arg);
}

void fd_stake_history_decode(fd_stake_history_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->len, data, dataend);
  if (self->len > 0) {
    self->entries = (fd_stake_history_epochentry_pair_t*)(*allocf)(FD_STAKE_HISTORY_EPOCHENTRY_PAIR_FOOTPRINT*self->len, FD_STAKE_HISTORY_EPOCHENTRY_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->len; ++i)
      fd_stake_history_epochentry_pair_decode(self->entries + i, data, dataend, allocf, allocf_arg);
  } else
    self->entries = NULL;
}

void fd_stake_history_destroy(fd_stake_history_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->entries) {
    for (ulong i = 0; i < self->len; ++i) {
      fd_stake_history_epochentry_pair_destroy(self->entries + i, freef, freef_arg);
    }
    freef(self->entries, freef_arg);
    self->entries = NULL;
  }
}

void fd_solana_account_decode(fd_solana_account_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports, data, dataend);
  fd_bincode_uint64_decode(&self->data_len, data, dataend);
  if (self->data_len > 0) {
    self->data = (unsigned char*)(*allocf)(self->data_len, 8, allocf_arg);
    fd_bincode_bytes_decode(self->data, self->data_len, data, dataend);
  } else
    self->data = NULL;
  fd_pubkey_decode(&self->owner, data, dataend, allocf, allocf_arg);
  fd_bincode_uint8_decode(&self->executable, data, dataend);
  fd_bincode_uint64_decode(&self->rent_epoch, data, dataend);
}

void fd_solana_account_destroy(fd_solana_account_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->data) {
    freef(self->data, freef_arg);
    self->data = NULL;
  }
}

void fd_vote_accounts_pair_decode(fd_vote_accounts_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake, data, dataend);
  fd_solana_account_decode(&self->value, data, dataend, allocf, allocf_arg);
}

void fd_vote_accounts_pair_destroy(fd_vote_accounts_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->key, freef, freef_arg);
  fd_solana_account_destroy(&self->value, freef, freef_arg);
}

void fd_vote_accounts_decode(fd_vote_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len != 0) {
    self->vote_accounts = (fd_vote_accounts_pair_t*)(*allocf)(FD_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->vote_accounts_len, FD_VOTE_ACCOUNTS_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_vote_accounts_pair_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->vote_accounts = NULL;
}

void fd_vote_accounts_destroy(fd_vote_accounts_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->vote_accounts) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      fd_vote_accounts_pair_destroy(self->vote_accounts + i, freef, freef_arg);
    }
    freef(self->vote_accounts, freef_arg);
    self->vote_accounts = NULL;
  }
}

void fd_delegation_decode(fd_delegation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->voter_pubkey, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake, data, dataend);
  fd_bincode_uint64_decode(&self->activation_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->deactivation_epoch, data, dataend);
  fd_bincode_double_decode(&self->warmup_cooldown_rate, data, dataend);
}

void fd_delegation_destroy(fd_delegation_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->voter_pubkey, freef, freef_arg);
}

void fd_delegation_pair_decode(fd_delegation_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_delegation_decode(&self->value, data, dataend, allocf, allocf_arg);
}

void fd_delegation_pair_destroy(fd_delegation_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->key, freef, freef_arg);
  fd_delegation_destroy(&self->value, freef, freef_arg);
}

void fd_stakes_delegation_decode(fd_stakes_delegation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_vote_accounts_decode(&self->vote_accounts, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake_delegations_len, data, dataend);
  if (self->stake_delegations_len) {
    self->stake_delegations = (fd_delegation_pair_t*)(*allocf)(FD_DELEGATION_PAIR_FOOTPRINT*self->stake_delegations_len, FD_DELEGATION_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->stake_delegations_len; ++i)
      fd_delegation_pair_decode(self->stake_delegations + i, data, dataend, allocf, allocf_arg);
  } else 
    self->stake_delegations = NULL;
  fd_bincode_uint64_decode(&self->unused, data, dataend);
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_stake_history_decode(&self->stake_history, data, dataend, allocf, allocf_arg);
}

void fd_stakes_delegation_destroy(fd_stakes_delegation_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_vote_accounts_destroy(&self->vote_accounts, freef, freef_arg);
  
  if (NULL != self->stake_delegations) {
    for (ulong i = 0; i < self->stake_delegations_len; ++i) {
      fd_delegation_pair_destroy(self->stake_delegations + i, freef, freef_arg);
    }
    freef(self->stake_delegations, freef_arg);
    self->stake_delegations = NULL;
  }

  fd_stake_history_destroy(&self->stake_history, freef, freef_arg);
}

void fd_node_vote_accounts_decode(fd_node_vote_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len) {
    self->vote_accounts = (fd_pubkey_t*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->vote_accounts_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
}

void fd_node_vote_accounts_destroy(fd_node_vote_accounts_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->vote_accounts) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      fd_pubkey_destroy(self->vote_accounts + i, freef, freef_arg);
    }
    freef(self->vote_accounts, freef_arg);
    self->vote_accounts = NULL;
  }
}

void fd_pubkey_node_vote_accounts_pair_decode(fd_pubkey_node_vote_accounts_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_node_vote_accounts_decode(&self->value, data, dataend, allocf, allocf_arg);
}

void fd_pubkey_node_vote_accounts_pair_destroy(fd_pubkey_node_vote_accounts_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->key, freef, freef_arg);
  fd_node_vote_accounts_destroy(&self->value, freef, freef_arg);
}

void fd_pubkey_pubkey_pair_decode(fd_pubkey_pubkey_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_pubkey_decode(&self->value, data, dataend, allocf, allocf_arg);
}

void fd_pubkey_pubkey_pair_destroy(fd_pubkey_pubkey_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->key, freef, freef_arg);
  fd_pubkey_destroy(&self->value, freef, freef_arg);
}

void fd_epoch_stakes_decode(fd_epoch_stakes_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_stakes_delegation_decode(&self->stakes, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
  fd_bincode_uint64_decode(&self->node_id_to_vote_accounts_len, data, dataend);
  if (self->node_id_to_vote_accounts_len > 0) {
    self->node_id_to_vote_accounts = (fd_pubkey_node_vote_accounts_pair_t*)(*allocf)(FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->node_id_to_vote_accounts_len, FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkey_node_vote_accounts_pair_decode(self->node_id_to_vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->node_id_to_vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->epoch_authorized_voters_len, data, dataend);
  if (self->epoch_authorized_voters_len > 0) {
    self->epoch_authorized_voters = (fd_pubkey_pubkey_pair_t*)(*allocf)(FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT*self->epoch_authorized_voters_len, FD_PUBKEY_PUBKEY_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_decode(self->epoch_authorized_voters + i, data, dataend, allocf, allocf_arg);
  } else 
    self->epoch_authorized_voters = NULL;
}

void fd_epoch_stakes_destroy(fd_epoch_stakes_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_stakes_delegation_destroy(&self->stakes, freef, freef_arg);
  
  if (NULL != self->node_id_to_vote_accounts) {
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i) {
      fd_pubkey_node_vote_accounts_pair_destroy(self->node_id_to_vote_accounts + i, freef, freef_arg);
    }
    freef(self->node_id_to_vote_accounts, freef_arg);
    self->node_id_to_vote_accounts = NULL;
  }

  if (NULL != self->epoch_authorized_voters) {
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i) {
      fd_pubkey_pubkey_pair_destroy(self->epoch_authorized_voters + i, freef, freef_arg);
    }
    freef(self->epoch_authorized_voters, freef_arg);
    self->epoch_authorized_voters = NULL;
  }
}

void fd_epoch_epoch_stakes_pair_decode(fd_epoch_epoch_stakes_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->key, data, dataend);
  fd_epoch_stakes_decode(&self->value, data, dataend, allocf, allocf_arg);
}

void fd_epoch_epoch_stakes_pair_destroy(fd_epoch_epoch_stakes_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_epoch_stakes_destroy(&self->value, freef, freef_arg);
}

void fd_pubkey_u64_pair_decode(fd_pubkey_u64_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->_0, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->_1, data, dataend);
}

void fd_pubkey_u64_pair_destroy(fd_pubkey_u64_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->_0, freef, freef_arg);
}

// runtime/src/serde_snapshot/newer.rs:20
void fd_unused_accounts_decode(fd_unused_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->unused1_len, data, dataend);
  if (self->unused1_len > 0) {
    self->unused1 = (fd_pubkey_t*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->unused1_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_decode(self->unused1 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused1 = NULL;

  fd_bincode_uint64_decode(&self->unused2_len, data, dataend);
  if (self->unused2_len > 0) {
    self->unused2 = (fd_pubkey_t*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->unused2_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_decode(self->unused2 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused2 = NULL;

  fd_bincode_uint64_decode(&self->unused3_len, data, dataend);
  if (self->unused3_len > 0) {
    self->unused3 = (fd_pubkey_u64_pair_t*)(*allocf)(FD_PUBKEY_U64_PAIR_FOOTPRINT*self->unused3_len, FD_PUBKEY_U64_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_decode(self->unused3 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused3 = NULL;
}

void fd_unused_accounts_destroy(fd_unused_accounts_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->unused1) {
    for (ulong i = 0; i < self->unused1_len; ++i) {
      fd_pubkey_destroy(self->unused1 + i, freef, freef_arg);
    }
    freef(self->unused1, freef_arg);
    self->unused1 = NULL;
  }
  
  if (NULL != self->unused2) {
    for (ulong i = 0; i < self->unused2_len; ++i) {
      fd_pubkey_destroy(self->unused2 + i, freef, freef_arg);
    }
    freef(self->unused2, freef_arg);
    self->unused2 = NULL;
  }
  
  if (NULL != self->unused3) {
    for (ulong i = 0; i < self->unused3_len; ++i) {
      fd_pubkey_u64_pair_destroy(self->unused3 + i, freef, freef_arg);
    }
    freef(self->unused3, freef_arg);
    self->unused3 = NULL;
  }
}

void fd_deserializable_versioned_bank_decode(fd_deserializable_versioned_bank_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_block_hash_queue_decode(&self->blockhash_queue, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->ancestors_len, data, dataend);
  self->ancestors = (fd_slot_pair_t*)(*allocf)(FD_SLOT_PAIR_FOOTPRINT*self->ancestors_len, FD_SLOT_PAIR_ALIGN, allocf_arg);
  for (ulong i = 0; i < self->ancestors_len; ++i)
    fd_slot_pair_decode(self->ancestors + i, data, dataend, allocf, allocf_arg);
  fd_hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
  fd_hash_decode(&self->parent_hash, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->parent_slot, data, dataend);
  fd_hard_forks_decode(&self->hard_forks, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->transaction_count, data, dataend);
  fd_bincode_uint64_decode(&self->tick_height, data, dataend);
  fd_bincode_uint64_decode(&self->signature_count, data, dataend);
  fd_bincode_uint64_decode(&self->capitalization, data, dataend);
  fd_bincode_uint64_decode(&self->max_tick_height, data, dataend);
  if (fd_bincode_option_decode(data, dataend)) {
    self->hashes_per_tick = (ulong*)(*allocf)(sizeof(ulong), 8, allocf_arg);
    fd_bincode_uint64_decode(self->hashes_per_tick, data, dataend);
  } else
    self->hashes_per_tick = NULL;
  fd_bincode_uint64_decode(&self->ticks_per_slot, data, dataend);
  fd_bincode_uint128_decode(&self->ns_per_slot, data, dataend);
  fd_bincode_uint64_decode((ulong *) &self->genesis_creation_time, data, dataend);
  fd_bincode_double_decode(&self->slots_per_year, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_data_len, data, dataend);
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_bincode_uint64_decode(&self->block_height, data, dataend);
  fd_pubkey_decode(&self->collector_id, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->collector_fees, data, dataend);
  fd_fee_calculator_decode(&self->fee_calculator, data, dataend, allocf, allocf_arg);
  fd_fee_rate_governor_decode(&self->fee_rate_governor, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->collected_rent, data, dataend);
  fd_rent_collector_decode(&self->rent_collector, data, dataend, allocf, allocf_arg);
  fd_epoch_schedule_decode(&self->epoch_schedule, data, dataend, allocf, allocf_arg);
  fd_inflation_decode(&self->inflation, data, dataend, allocf, allocf_arg);
  fd_stakes_delegation_decode(&self->stakes, data, dataend, allocf, allocf_arg);
  fd_unused_accounts_decode(&self->unused_accounts, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->epoch_stakes_len, data, dataend);
  if (self->epoch_stakes_len > 0) {
    self->epoch_stakes = (fd_epoch_epoch_stakes_pair_t*)(*allocf)(FD_EPOCH_EPOCH_STAKES_PAIR_FOOTPRINT*self->epoch_stakes_len, FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      fd_epoch_epoch_stakes_pair_decode(self->epoch_stakes + i, data, dataend, allocf, allocf_arg);
  } else
    self->epoch_stakes = NULL;
  fd_bincode_uint8_decode((unsigned char *) &self->is_delta, data, dataend);
}

void fd_deserializable_versioned_bank_destroy(fd_deserializable_versioned_bank_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_block_hash_queue_destroy(&self->blockhash_queue, freef, freef_arg);
  
  if (NULL != self->ancestors) {
    for (ulong i = 0; i < self->ancestors_len; ++i) {
      fd_slot_pair_destroy(self->ancestors + i, freef, freef_arg);
    }
    freef(self->ancestors, freef_arg);
    self->ancestors = NULL;
  }

  fd_hash_destroy(&self->hash, freef, freef_arg);
  fd_hash_destroy(&self->parent_hash, freef, freef_arg);
  fd_hard_forks_destroy(&self->hard_forks, freef, freef_arg);

  if (NULL != self->hashes_per_tick) {
    freef(self->hashes_per_tick, freef_arg);
    self->hashes_per_tick = NULL;
  }

  fd_pubkey_destroy(&self->collector_id, freef, freef_arg);
  fd_fee_calculator_destroy(&self->fee_calculator, freef, freef_arg);
  fd_fee_rate_governor_destroy(&self->fee_rate_governor, freef, freef_arg);
  fd_rent_collector_destroy(&self->rent_collector, freef, freef_arg);
  fd_epoch_schedule_destroy(&self->epoch_schedule, freef, freef_arg);
  fd_inflation_destroy(&self->inflation, freef, freef_arg);
  fd_stakes_delegation_destroy(&self->stakes, freef, freef_arg);
  fd_unused_accounts_destroy(&self->unused_accounts, freef, freef_arg);

  if (NULL != self->epoch_stakes) {
    for (ulong i = 0; i < self->epoch_stakes_len; ++i) {
      fd_epoch_epoch_stakes_pair_destroy(self->epoch_stakes + i, freef, freef_arg);
    }
    freef(self->epoch_stakes, freef_arg);
    self->epoch_stakes = NULL;
  }
}

void fd_serializable_account_storage_entry_decode(fd_serializable_account_storage_entry_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->id, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_current_len, data, dataend);
}

void fd_serializable_account_storage_entry_destroy(FD_FN_UNUSED fd_serializable_account_storage_entry_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}
  
void fd_bank_hash_stats_decode(fd_bank_hash_stats_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->num_updated_accounts, data, dataend);
  fd_bincode_uint64_decode(&self->num_removed_accounts, data, dataend);
  fd_bincode_uint64_decode(&self->num_lamports_stored, data, dataend);
  fd_bincode_uint64_decode(&self->total_data_len, data, dataend);
  fd_bincode_uint64_decode(&self->num_executable_accounts, data, dataend);
}

void fd_bank_hash_stats_destroy(FD_FN_UNUSED fd_bank_hash_stats_t* self, FD_FN_UNUSED fd_free_fun_t freef, FD_FN_UNUSED void* freef_arg) {
}
  
void fd_bank_hash_info_decode(fd_bank_hash_info_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
  fd_hash_decode(&self->snapshot_hash, data, dataend, allocf, allocf_arg);
  fd_bank_hash_stats_decode(&self->stats, data, dataend, allocf, allocf_arg);
}

void fd_bank_hash_info_destroy(fd_bank_hash_info_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_hash_destroy(&self->hash, freef, freef_arg);
  fd_hash_destroy(&self->snapshot_hash, freef, freef_arg);
  fd_bank_hash_stats_destroy(&self->stats, freef, freef_arg);
}

void fd_slot_account_pair_decode(fd_slot_account_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_len, data, dataend);
  if (self->accounts_len > 0) {
    self->accounts = (fd_serializable_account_storage_entry_t*)(*allocf)(FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_FOOTPRINT*self->accounts_len, FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_serializable_account_storage_entry_decode(self->accounts + i, data, dataend, allocf, allocf_arg);
  } else
    self->accounts = NULL;
}

void fd_slot_account_pair_destroy(fd_slot_account_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->accounts) { 
    for (ulong i = 0; i < self->accounts_len; ++i) {
      fd_serializable_account_storage_entry_destroy(self->accounts + i, freef, freef_arg);
    }
    freef(self->accounts, freef_arg);
    self->accounts = NULL;
  }
}

void fd_slot_map_pair_decode(fd_slot_map_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
}

void fd_slot_map_pair_destroy(fd_slot_map_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_hash_destroy(&self->hash, freef, freef_arg);
}
  
void fd_solana_accounts_db_fields_decode(fd_solana_accounts_db_fields_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->storages_len, data, dataend);
  if (self->storages_len > 0) {
    self->storages = (fd_slot_account_pair_t*)(*allocf)(FD_SLOT_ACCOUNT_PAIR_FOOTPRINT*self->storages_len, FD_SLOT_ACCOUNT_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->storages_len; ++i)
      fd_slot_account_pair_decode(self->storages + i, data, dataend, allocf, allocf_arg);
  } else
    self->storages = NULL;

  fd_bincode_uint64_decode(&self->version, data, dataend);
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bank_hash_info_decode(&self->bank_hash_info, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->historical_roots_len, data, dataend);
  if (self->historical_roots_len > 0) {
    self->historical_roots = (ulong*)(*allocf)(sizeof(ulong)*self->historical_roots_len, 8, allocf_arg);
    for (ulong i = 0; i < self->historical_roots_len; ++i)
      fd_bincode_uint64_decode(self->historical_roots + i, data, dataend);
  } else
    self->historical_roots = NULL;
  fd_bincode_uint64_decode(&self->historical_roots_with_hash_len, data, dataend);
  if (self->historical_roots_with_hash_len > 0) {
    self->historical_roots_with_hash = (fd_slot_map_pair_t*)(*allocf)(FD_SLOT_MAP_PAIR_FOOTPRINT*self->historical_roots_with_hash_len, FD_SLOT_MAP_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_decode(self->historical_roots_with_hash + i, data, dataend, allocf, allocf_arg);
  } else
    self->historical_roots_with_hash = NULL;
}

void fd_solana_accounts_db_fields_destroy(fd_solana_accounts_db_fields_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->storages) {
    for (ulong i = 0; i < self->storages_len; ++i) {
      fd_slot_account_pair_destroy(self->storages + i, freef, freef_arg);
    }
    freef(self->storages, freef_arg);
    self->storages = NULL;
  }
  if (NULL != self->historical_roots) {
    freef(self->historical_roots, freef_arg);
    self->historical_roots = NULL;
  }
  if (NULL != self->historical_roots_with_hash) {
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i) {
      fd_slot_map_pair_destroy(self->historical_roots_with_hash + i, freef, freef_arg);
    }
    freef(self->historical_roots_with_hash, freef_arg);
    self->historical_roots_with_hash = NULL;
  }
  fd_bank_hash_info_destroy(&self->bank_hash_info, freef, freef_arg);
}

void fd_rust_duration_decode(fd_rust_duration_t* self, void const** data, void const* dataend, FD_FN_UNUSED fd_alloc_fun_t allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->seconds, data, dataend);
  fd_bincode_uint32_decode(&self->nanoseconds, data, dataend);
}

void fd_poh_config_decode(fd_poh_config_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_rust_duration_decode(&self->target_tick_duration, data, dataend, allocf, allocf_arg);
  if (fd_bincode_option_decode(data, dataend)) {
    self->target_tick_count = (ulong*)(*allocf)(sizeof(ulong), 8, allocf_arg);
    fd_bincode_uint64_decode(self->target_tick_count, data, dataend);
  } else
    self->target_tick_count = NULL;
  if (fd_bincode_option_decode(data, dataend)) {
    self->hashes_per_tick = (ulong*)(*allocf)(sizeof(ulong), 8, allocf_arg);
    fd_bincode_uint64_decode(self->hashes_per_tick, data, dataend);
  } else
    self->hashes_per_tick = NULL;
}

void fd_string_pubkey_pair_decode(fd_string_pubkey_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  ulong slen;
  fd_bincode_uint64_decode(&slen, data, dataend);
  self->string = (char*)(*allocf)(slen + 1, 1, allocf_arg);
  fd_bincode_bytes_decode((uchar *) self->string, slen, data, dataend);
  self->string[slen] = '\0';
  fd_pubkey_decode(&self->pubkey, data, dataend, allocf, allocf_arg);
}

void fd_pubkey_account_pair_decode(fd_pubkey_account_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_solana_account_decode(&self->account, data, dataend, allocf, allocf_arg);
}

void fd_pubkey_account_pair_destroy(fd_pubkey_account_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_solana_account_destroy(&self->account, freef, freef_arg);
}

void fd_genesis_solana_decode(fd_genesis_solana_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->creation_time, data, dataend);

  fd_bincode_uint64_decode(&self->accounts_len, data, dataend);
  if (self->accounts_len != 0) {
    self->accounts = (fd_pubkey_account_pair_t*)(*allocf)(FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT*self->accounts_len, FD_PUBKEY_ACCOUNT_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_pubkey_account_pair_decode(self->accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->accounts = NULL;

  fd_bincode_uint64_decode(&self->native_instruction_processors_len, data, dataend);
  if (self->native_instruction_processors_len != 0) {
    self->native_instruction_processors = (fd_string_pubkey_pair_t*)(*allocf)(FD_STRING_PUBKEY_PAIR_FOOTPRINT*self->native_instruction_processors_len, FD_STRING_PUBKEY_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
      fd_string_pubkey_pair_decode(self->native_instruction_processors + i, data, dataend, allocf, allocf_arg);
  } else 
    self->native_instruction_processors = NULL;

  fd_bincode_uint64_decode(&self->rewards_pools_len, data, dataend);
  if (self->rewards_pools_len != 0) {
    self->rewards_pools = (fd_pubkey_account_pair_t*)(*allocf)(FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT*self->rewards_pools_len, FD_PUBKEY_ACCOUNT_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->rewards_pools_len; ++i)
      fd_pubkey_account_pair_decode(self->rewards_pools + i, data, dataend, allocf, allocf_arg);
  } else 
    self->rewards_pools = NULL;

  fd_bincode_uint64_decode(&self->ticks_per_slot, data, dataend);
  fd_bincode_uint64_decode(&self->unused, data, dataend);

  fd_poh_config_decode(&self->poh_config, data, dataend, allocf, allocf_arg);

  fd_bincode_uint64_decode(&self->__backwards_compat_with_v0_23, data, dataend);
  fd_fee_rate_governor_decode(&self->fee_rate_governor, data, dataend, allocf, allocf_arg);
  fd_rent_decode(&self->rent, data, dataend, allocf, allocf_arg);
  fd_inflation_decode(&self->inflation, data, dataend, allocf, allocf_arg);
  fd_epoch_schedule_decode(&self->epoch_schedule, data, dataend, allocf, allocf_arg);
  fd_bincode_uint32_decode(&self->cluster_type, data, dataend);
}

void fd_genesis_solana_destroy(fd_genesis_solana_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->accounts) {
    for (ulong i = 0; i < self->accounts_len; ++i) 
      fd_pubkey_account_pair_destroy(self->accounts + i,  freef, freef_arg);
    freef(self->accounts, freef_arg);
    self->accounts = NULL;
  }
  if (NULL != self->native_instruction_processors) {
    freef(self->native_instruction_processors, freef_arg);
    self->native_instruction_processors = NULL;
  }
  if (NULL != self->rewards_pools) {
    freef(self->rewards_pools, freef_arg);
    self->rewards_pools = NULL;
  }
}
