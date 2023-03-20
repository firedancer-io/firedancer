#include "fd_types.h"
#pragma GCC diagnostic ignored "-Wunused-parameter"
void fd_fee_calculator_decode(fd_fee_calculator_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_signature, data, dataend);
}
void fd_fee_calculator_destroy(fd_fee_calculator_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_fee_calculator_size(fd_fee_calculator_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  return size;
}

void fd_fee_calculator_encode(fd_fee_calculator_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->lamports_per_signature, data);
}

void fd_hash_age_decode(fd_hash_age_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_fee_calculator_decode(&self->fee_calculator, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->hash_index, data, dataend);
  fd_bincode_uint64_decode(&self->timestamp, data, dataend);
}
void fd_hash_age_destroy(fd_hash_age_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_fee_calculator_destroy(&self->fee_calculator, freef, freef_arg);
}

ulong fd_hash_age_size(fd_hash_age_t* self) {
  ulong size = 0;
  size += fd_fee_calculator_size(&self->fee_calculator);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

void fd_hash_age_encode(fd_hash_age_t* self, void const** data) {
  fd_fee_calculator_encode(&self->fee_calculator, data);
  fd_bincode_uint64_encode(&self->hash_index, data);
  fd_bincode_uint64_encode(&self->timestamp, data);
}

void fd_hash_decode(fd_hash_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_bytes_decode(&self->hash[0], sizeof(self->hash), data, dataend);
}
void fd_hash_destroy(fd_hash_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_hash_size(fd_hash_t* self) {
  ulong size = 0;
  size += sizeof(char) * 32;
  return size;
}

void fd_hash_encode(fd_hash_t* self, void const** data) {
  fd_bincode_bytes_encode(&self->hash[0], sizeof(self->hash), data);
}

void fd_hash_hash_age_pair_decode(fd_hash_hash_age_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_hash_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_hash_age_decode(&self->val, data, dataend, allocf, allocf_arg);
}
void fd_hash_hash_age_pair_destroy(fd_hash_hash_age_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_hash_destroy(&self->key, freef, freef_arg);
  fd_hash_age_destroy(&self->val, freef, freef_arg);
}

ulong fd_hash_hash_age_pair_size(fd_hash_hash_age_pair_t* self) {
  ulong size = 0;
  size += fd_hash_size(&self->key);
  size += fd_hash_age_size(&self->val);
  return size;
}

void fd_hash_hash_age_pair_encode(fd_hash_hash_age_pair_t* self, void const** data) {
  fd_hash_encode(&self->key, data);
  fd_hash_age_encode(&self->val, data);
}

void fd_block_hash_queue_decode(fd_block_hash_queue_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->last_hash_index, data, dataend);
  if (fd_bincode_option_decode(data, dataend)) {
    self->last_hash = (fd_hash_t*)(*allocf)(FD_HASH_FOOTPRINT, FD_HASH_ALIGN, allocf_arg);
    fd_hash_decode(self->last_hash, data, dataend, allocf, allocf_arg);
  } else
    self->last_hash = NULL;
  fd_bincode_uint64_decode(&self->ages_len, data, dataend);
  if (self->ages_len != 0) {
    self->ages = (fd_hash_hash_age_pair_t*)(*allocf)(FD_HASH_HASH_AGE_PAIR_FOOTPRINT*self->ages_len, FD_HASH_HASH_AGE_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_pair_decode(self->ages + i, data, dataend, allocf, allocf_arg);
  } else
    self->ages = NULL;
  fd_bincode_uint64_decode(&self->max_age, data, dataend);
}
void fd_block_hash_queue_destroy(fd_block_hash_queue_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->last_hash) {
    fd_hash_destroy(self->last_hash,  freef, freef_arg);
    freef(self->last_hash, freef_arg);
    self->last_hash = NULL;
  }
  if (NULL != self->ages) {
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_pair_destroy(self->ages + i,  freef, freef_arg);
    freef(self->ages, freef_arg);
    self->ages = NULL;
  }
}

ulong fd_block_hash_queue_size(fd_block_hash_queue_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(char);
  if (NULL !=  self->last_hash) {
    size += fd_hash_size(self->last_hash);
  }
  size += sizeof(ulong);
  for (ulong i = 0; i < self->ages_len; ++i)
    size += fd_hash_hash_age_pair_size(self->ages + i);
  size += sizeof(ulong);
  return size;
}

void fd_block_hash_queue_encode(fd_block_hash_queue_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->last_hash_index, data);
  if (self->last_hash!= NULL) {
    fd_bincode_option_encode(1, data);
    fd_hash_encode(self->last_hash, data);
  } else
    fd_bincode_option_encode(0, data);
  fd_bincode_uint64_encode(&self->ages_len, data);
  if (self->ages_len != 0) {
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_pair_encode(self->ages + i, data);
  }
  fd_bincode_uint64_encode(&self->max_age, data);
}

void fd_pubkey_decode(fd_pubkey_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_bytes_decode(&self->key[0], sizeof(self->key), data, dataend);
}
void fd_pubkey_destroy(fd_pubkey_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_pubkey_size(fd_pubkey_t* self) {
  ulong size = 0;
  size += sizeof(char) * 32;
  return size;
}

void fd_pubkey_encode(fd_pubkey_t* self, void const** data) {
  fd_bincode_bytes_encode(&self->key[0], sizeof(self->key), data);
}

void fd_epoch_schedule_decode(fd_epoch_schedule_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slots_per_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->leader_schedule_slot_offset, data, dataend);
  fd_bincode_uint8_decode(&self->warmup, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_slot, data, dataend);
}
void fd_epoch_schedule_destroy(fd_epoch_schedule_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_epoch_schedule_size(fd_epoch_schedule_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

void fd_epoch_schedule_encode(fd_epoch_schedule_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->slots_per_epoch, data);
  fd_bincode_uint64_encode(&self->leader_schedule_slot_offset, data);
  fd_bincode_uint8_encode(&self->warmup, data);
  fd_bincode_uint64_encode(&self->first_normal_epoch, data);
  fd_bincode_uint64_encode(&self->first_normal_slot, data);
}

void fd_fee_rate_governor_decode(fd_fee_rate_governor_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->target_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->target_signatures_per_slot, data, dataend);
  fd_bincode_uint64_decode(&self->min_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->max_lamports_per_signature, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}
void fd_fee_rate_governor_destroy(fd_fee_rate_governor_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_fee_rate_governor_size(fd_fee_rate_governor_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  return size;
}

void fd_fee_rate_governor_encode(fd_fee_rate_governor_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->target_lamports_per_signature, data);
  fd_bincode_uint64_encode(&self->target_signatures_per_slot, data);
  fd_bincode_uint64_encode(&self->min_lamports_per_signature, data);
  fd_bincode_uint64_encode(&self->max_lamports_per_signature, data);
  fd_bincode_uint8_encode(&self->burn_percent, data);
}

void fd_slot_pair_decode(fd_slot_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->val, data, dataend);
}
void fd_slot_pair_destroy(fd_slot_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_slot_pair_size(fd_slot_pair_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

void fd_slot_pair_encode(fd_slot_pair_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->slot, data);
  fd_bincode_uint64_encode(&self->val, data);
}

void fd_hard_forks_decode(fd_hard_forks_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->hard_forks_len, data, dataend);
  if (self->hard_forks_len != 0) {
    self->hard_forks = (fd_slot_pair_t*)(*allocf)(FD_SLOT_PAIR_FOOTPRINT*self->hard_forks_len, FD_SLOT_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->hard_forks_len; ++i)
      fd_slot_pair_decode(self->hard_forks + i, data, dataend, allocf, allocf_arg);
  } else
    self->hard_forks = NULL;
}
void fd_hard_forks_destroy(fd_hard_forks_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->hard_forks) {
    for (ulong i = 0; i < self->hard_forks_len; ++i)
      fd_slot_pair_destroy(self->hard_forks + i,  freef, freef_arg);
    freef(self->hard_forks, freef_arg);
    self->hard_forks = NULL;
  }
}

ulong fd_hard_forks_size(fd_hard_forks_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->hard_forks_len; ++i)
    size += fd_slot_pair_size(self->hard_forks + i);
  return size;
}

void fd_hard_forks_encode(fd_hard_forks_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->hard_forks_len, data);
  if (self->hard_forks_len != 0) {
    for (ulong i = 0; i < self->hard_forks_len; ++i)
      fd_slot_pair_encode(self->hard_forks + i, data);
  }
}

void fd_inflation_decode(fd_inflation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_double_decode(&self->initial, data, dataend);
  fd_bincode_double_decode(&self->terminal, data, dataend);
  fd_bincode_double_decode(&self->taper, data, dataend);
  fd_bincode_double_decode(&self->foundation, data, dataend);
  fd_bincode_double_decode(&self->foundation_term, data, dataend);
  fd_bincode_double_decode(&self->__unused, data, dataend);
}
void fd_inflation_destroy(fd_inflation_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_inflation_size(fd_inflation_t* self) {
  ulong size = 0;
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  return size;
}

void fd_inflation_encode(fd_inflation_t* self, void const** data) {
  fd_bincode_double_encode(&self->initial, data);
  fd_bincode_double_encode(&self->terminal, data);
  fd_bincode_double_encode(&self->taper, data);
  fd_bincode_double_encode(&self->foundation, data);
  fd_bincode_double_encode(&self->foundation_term, data);
  fd_bincode_double_encode(&self->__unused, data);
}

void fd_rent_decode(fd_rent_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_uint8_year, data, dataend);
  fd_bincode_double_decode(&self->exemption_threshold, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}
void fd_rent_destroy(fd_rent_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_rent_size(fd_rent_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(char);
  return size;
}

void fd_rent_encode(fd_rent_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->lamports_per_uint8_year, data);
  fd_bincode_double_encode(&self->exemption_threshold, data);
  fd_bincode_uint8_encode(&self->burn_percent, data);
}

void fd_rent_collector_decode(fd_rent_collector_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_epoch_schedule_decode(&self->epoch_schedule, data, dataend, allocf, allocf_arg);
  fd_bincode_double_decode(&self->slots_per_year, data, dataend);
  fd_rent_decode(&self->rent, data, dataend, allocf, allocf_arg);
}
void fd_rent_collector_destroy(fd_rent_collector_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_epoch_schedule_destroy(&self->epoch_schedule, freef, freef_arg);
  fd_rent_destroy(&self->rent, freef, freef_arg);
}

ulong fd_rent_collector_size(fd_rent_collector_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += sizeof(double);
  size += fd_rent_size(&self->rent);
  return size;
}

void fd_rent_collector_encode(fd_rent_collector_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->epoch, data);
  fd_epoch_schedule_encode(&self->epoch_schedule, data);
  fd_bincode_double_encode(&self->slots_per_year, data);
  fd_rent_encode(&self->rent, data);
}

void fd_stake_history_entry_decode(fd_stake_history_entry_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->effective, data, dataend);
  fd_bincode_uint64_decode(&self->activating, data, dataend);
  fd_bincode_uint64_decode(&self->deactivating, data, dataend);
}
void fd_stake_history_entry_destroy(fd_stake_history_entry_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_stake_history_entry_size(fd_stake_history_entry_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

void fd_stake_history_entry_encode(fd_stake_history_entry_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->effective, data);
  fd_bincode_uint64_encode(&self->activating, data);
  fd_bincode_uint64_encode(&self->deactivating, data);
}

void fd_stake_history_epochentry_pair_decode(fd_stake_history_epochentry_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_stake_history_entry_decode(&self->entry, data, dataend, allocf, allocf_arg);
}
void fd_stake_history_epochentry_pair_destroy(fd_stake_history_epochentry_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_stake_history_entry_destroy(&self->entry, freef, freef_arg);
}

ulong fd_stake_history_epochentry_pair_size(fd_stake_history_epochentry_pair_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_stake_history_entry_size(&self->entry);
  return size;
}

void fd_stake_history_epochentry_pair_encode(fd_stake_history_epochentry_pair_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->epoch, data);
  fd_stake_history_entry_encode(&self->entry, data);
}

void fd_stake_history_decode(fd_stake_history_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->entries_len, data, dataend);
  if (self->entries_len != 0) {
    self->entries = (fd_stake_history_epochentry_pair_t*)(*allocf)(FD_STAKE_HISTORY_EPOCHENTRY_PAIR_FOOTPRINT*self->entries_len, FD_STAKE_HISTORY_EPOCHENTRY_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->entries_len; ++i)
      fd_stake_history_epochentry_pair_decode(self->entries + i, data, dataend, allocf, allocf_arg);
  } else
    self->entries = NULL;
}
void fd_stake_history_destroy(fd_stake_history_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->entries) {
    for (ulong i = 0; i < self->entries_len; ++i)
      fd_stake_history_epochentry_pair_destroy(self->entries + i,  freef, freef_arg);
    freef(self->entries, freef_arg);
    self->entries = NULL;
  }
}

ulong fd_stake_history_size(fd_stake_history_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->entries_len; ++i)
    size += fd_stake_history_epochentry_pair_size(self->entries + i);
  return size;
}

void fd_stake_history_encode(fd_stake_history_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->entries_len, data);
  if (self->entries_len != 0) {
    for (ulong i = 0; i < self->entries_len; ++i)
      fd_stake_history_epochentry_pair_encode(self->entries + i, data);
  }
}

void fd_solana_account_decode(fd_solana_account_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports, data, dataend);
  fd_bincode_uint64_decode(&self->data_len, data, dataend);
  if (self->data_len != 0) {
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
  fd_pubkey_destroy(&self->owner, freef, freef_arg);
}

ulong fd_solana_account_size(fd_solana_account_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += self->data_len;
  size += fd_pubkey_size(&self->owner);
  size += sizeof(char);
  size += sizeof(ulong);
  return size;
}

void fd_solana_account_encode(fd_solana_account_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->lamports, data);
  fd_bincode_uint64_encode(&self->data_len, data);
  if (self->data_len != 0) {
    fd_bincode_bytes_encode(self->data, self->data_len, data);
  }
  fd_pubkey_encode(&self->owner, data);
  fd_bincode_uint8_encode(&self->executable, data);
  fd_bincode_uint64_encode(&self->rent_epoch, data);
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

ulong fd_vote_accounts_pair_size(fd_vote_accounts_pair_t* self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += sizeof(ulong);
  size += fd_solana_account_size(&self->value);
  return size;
}

void fd_vote_accounts_pair_encode(fd_vote_accounts_pair_t* self, void const** data) {
  fd_pubkey_encode(&self->key, data);
  fd_bincode_uint64_encode(&self->stake, data);
  fd_solana_account_encode(&self->value, data);
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
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_vote_accounts_pair_destroy(self->vote_accounts + i,  freef, freef_arg);
    freef(self->vote_accounts, freef_arg);
    self->vote_accounts = NULL;
  }
}

ulong fd_vote_accounts_size(fd_vote_accounts_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->vote_accounts_len; ++i)
    size += fd_vote_accounts_pair_size(self->vote_accounts + i);
  return size;
}

void fd_vote_accounts_encode(fd_vote_accounts_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->vote_accounts_len, data);
  if (self->vote_accounts_len != 0) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_vote_accounts_pair_encode(self->vote_accounts + i, data);
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

ulong fd_delegation_size(fd_delegation_t* self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->voter_pubkey);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(double);
  return size;
}

void fd_delegation_encode(fd_delegation_t* self, void const** data) {
  fd_pubkey_encode(&self->voter_pubkey, data);
  fd_bincode_uint64_encode(&self->stake, data);
  fd_bincode_uint64_encode(&self->activation_epoch, data);
  fd_bincode_uint64_encode(&self->deactivation_epoch, data);
  fd_bincode_double_encode(&self->warmup_cooldown_rate, data);
}

void fd_delegation_pair_decode(fd_delegation_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_delegation_decode(&self->value, data, dataend, allocf, allocf_arg);
}
void fd_delegation_pair_destroy(fd_delegation_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->key, freef, freef_arg);
  fd_delegation_destroy(&self->value, freef, freef_arg);
}

ulong fd_delegation_pair_size(fd_delegation_pair_t* self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_delegation_size(&self->value);
  return size;
}

void fd_delegation_pair_encode(fd_delegation_pair_t* self, void const** data) {
  fd_pubkey_encode(&self->key, data);
  fd_delegation_encode(&self->value, data);
}

void fd_stakes_delegation_decode(fd_stakes_delegation_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_vote_accounts_decode(&self->vote_accounts, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake_delegations_len, data, dataend);
  if (self->stake_delegations_len != 0) {
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
    for (ulong i = 0; i < self->stake_delegations_len; ++i)
      fd_delegation_pair_destroy(self->stake_delegations + i,  freef, freef_arg);
    freef(self->stake_delegations, freef_arg);
    self->stake_delegations = NULL;
  }
  fd_stake_history_destroy(&self->stake_history, freef, freef_arg);
}

ulong fd_stakes_delegation_size(fd_stakes_delegation_t* self) {
  ulong size = 0;
  size += fd_vote_accounts_size(&self->vote_accounts);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->stake_delegations_len; ++i)
    size += fd_delegation_pair_size(self->stake_delegations + i);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_stake_history_size(&self->stake_history);
  return size;
}

void fd_stakes_delegation_encode(fd_stakes_delegation_t* self, void const** data) {
  fd_vote_accounts_encode(&self->vote_accounts, data);
  fd_bincode_uint64_encode(&self->stake_delegations_len, data);
  if (self->stake_delegations_len != 0) {
    for (ulong i = 0; i < self->stake_delegations_len; ++i)
      fd_delegation_pair_encode(self->stake_delegations + i, data);
  }
  fd_bincode_uint64_encode(&self->unused, data);
  fd_bincode_uint64_encode(&self->epoch, data);
  fd_stake_history_encode(&self->stake_history, data);
}

void fd_bank_incremental_snapshot_persistence_decode(fd_bank_incremental_snapshot_persistence_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->full_slot, data, dataend);
  fd_hash_decode(&self->full_hash, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->full_capitalization, data, dataend);
  fd_hash_decode(&self->incremental_hash, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->incremental_capitalization, data, dataend);
}
void fd_bank_incremental_snapshot_persistence_destroy(fd_bank_incremental_snapshot_persistence_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_hash_destroy(&self->full_hash, freef, freef_arg);
  fd_hash_destroy(&self->incremental_hash, freef, freef_arg);
}

ulong fd_bank_incremental_snapshot_persistence_size(fd_bank_incremental_snapshot_persistence_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_hash_size(&self->full_hash);
  size += sizeof(ulong);
  size += fd_hash_size(&self->incremental_hash);
  size += sizeof(ulong);
  return size;
}

void fd_bank_incremental_snapshot_persistence_encode(fd_bank_incremental_snapshot_persistence_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->full_slot, data);
  fd_hash_encode(&self->full_hash, data);
  fd_bincode_uint64_encode(&self->full_capitalization, data);
  fd_hash_encode(&self->incremental_hash, data);
  fd_bincode_uint64_encode(&self->incremental_capitalization, data);
}

void fd_node_vote_accounts_decode(fd_node_vote_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len != 0) {
    self->vote_accounts = (fd_pubkey_t*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->vote_accounts_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else
    self->vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
}
void fd_node_vote_accounts_destroy(fd_node_vote_accounts_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->vote_accounts) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_destroy(self->vote_accounts + i,  freef, freef_arg);
    freef(self->vote_accounts, freef_arg);
    self->vote_accounts = NULL;
  }
}

ulong fd_node_vote_accounts_size(fd_node_vote_accounts_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->vote_accounts_len; ++i)
    size += fd_pubkey_size(self->vote_accounts + i);
  size += sizeof(ulong);
  return size;
}

void fd_node_vote_accounts_encode(fd_node_vote_accounts_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->vote_accounts_len, data);
  if (self->vote_accounts_len != 0) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_encode(self->vote_accounts + i, data);
  }
  fd_bincode_uint64_encode(&self->total_stake, data);
}

void fd_pubkey_node_vote_accounts_pair_decode(fd_pubkey_node_vote_accounts_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_node_vote_accounts_decode(&self->value, data, dataend, allocf, allocf_arg);
}
void fd_pubkey_node_vote_accounts_pair_destroy(fd_pubkey_node_vote_accounts_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->key, freef, freef_arg);
  fd_node_vote_accounts_destroy(&self->value, freef, freef_arg);
}

ulong fd_pubkey_node_vote_accounts_pair_size(fd_pubkey_node_vote_accounts_pair_t* self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_node_vote_accounts_size(&self->value);
  return size;
}

void fd_pubkey_node_vote_accounts_pair_encode(fd_pubkey_node_vote_accounts_pair_t* self, void const** data) {
  fd_pubkey_encode(&self->key, data);
  fd_node_vote_accounts_encode(&self->value, data);
}

void fd_pubkey_pubkey_pair_decode(fd_pubkey_pubkey_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_pubkey_decode(&self->value, data, dataend, allocf, allocf_arg);
}
void fd_pubkey_pubkey_pair_destroy(fd_pubkey_pubkey_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->key, freef, freef_arg);
  fd_pubkey_destroy(&self->value, freef, freef_arg);
}

ulong fd_pubkey_pubkey_pair_size(fd_pubkey_pubkey_pair_t* self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_pubkey_size(&self->value);
  return size;
}

void fd_pubkey_pubkey_pair_encode(fd_pubkey_pubkey_pair_t* self, void const** data) {
  fd_pubkey_encode(&self->key, data);
  fd_pubkey_encode(&self->value, data);
}

void fd_epoch_stakes_decode(fd_epoch_stakes_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_stakes_delegation_decode(&self->stakes, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
  fd_bincode_uint64_decode(&self->node_id_to_vote_accounts_len, data, dataend);
  if (self->node_id_to_vote_accounts_len != 0) {
    self->node_id_to_vote_accounts = (fd_pubkey_node_vote_accounts_pair_t*)(*allocf)(FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->node_id_to_vote_accounts_len, FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkey_node_vote_accounts_pair_decode(self->node_id_to_vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else
    self->node_id_to_vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->epoch_authorized_voters_len, data, dataend);
  if (self->epoch_authorized_voters_len != 0) {
    self->epoch_authorized_voters = (fd_pubkey_pubkey_pair_t*)(*allocf)(FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT*self->epoch_authorized_voters_len, FD_PUBKEY_PUBKEY_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_decode(self->epoch_authorized_voters + i, data, dataend, allocf, allocf_arg);
  } else
    self->epoch_authorized_voters = NULL;
}
void fd_epoch_stakes_destroy(fd_epoch_stakes_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_stakes_delegation_destroy(&self->stakes, freef, freef_arg);
  if (NULL != self->node_id_to_vote_accounts) {
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkey_node_vote_accounts_pair_destroy(self->node_id_to_vote_accounts + i,  freef, freef_arg);
    freef(self->node_id_to_vote_accounts, freef_arg);
    self->node_id_to_vote_accounts = NULL;
  }
  if (NULL != self->epoch_authorized_voters) {
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_destroy(self->epoch_authorized_voters + i,  freef, freef_arg);
    freef(self->epoch_authorized_voters, freef_arg);
    self->epoch_authorized_voters = NULL;
  }
}

ulong fd_epoch_stakes_size(fd_epoch_stakes_t* self) {
  ulong size = 0;
  size += fd_stakes_delegation_size(&self->stakes);
  size += sizeof(ulong);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
    size += fd_pubkey_node_vote_accounts_pair_size(self->node_id_to_vote_accounts + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
    size += fd_pubkey_pubkey_pair_size(self->epoch_authorized_voters + i);
  return size;
}

void fd_epoch_stakes_encode(fd_epoch_stakes_t* self, void const** data) {
  fd_stakes_delegation_encode(&self->stakes, data);
  fd_bincode_uint64_encode(&self->total_stake, data);
  fd_bincode_uint64_encode(&self->node_id_to_vote_accounts_len, data);
  if (self->node_id_to_vote_accounts_len != 0) {
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkey_node_vote_accounts_pair_encode(self->node_id_to_vote_accounts + i, data);
  }
  fd_bincode_uint64_encode(&self->epoch_authorized_voters_len, data);
  if (self->epoch_authorized_voters_len != 0) {
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_encode(self->epoch_authorized_voters + i, data);
  }
}

void fd_epoch_epoch_stakes_pair_decode(fd_epoch_epoch_stakes_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->key, data, dataend);
  fd_epoch_stakes_decode(&self->value, data, dataend, allocf, allocf_arg);
}
void fd_epoch_epoch_stakes_pair_destroy(fd_epoch_epoch_stakes_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_epoch_stakes_destroy(&self->value, freef, freef_arg);
}

ulong fd_epoch_epoch_stakes_pair_size(fd_epoch_epoch_stakes_pair_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_epoch_stakes_size(&self->value);
  return size;
}

void fd_epoch_epoch_stakes_pair_encode(fd_epoch_epoch_stakes_pair_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->key, data);
  fd_epoch_stakes_encode(&self->value, data);
}

void fd_pubkey_u64_pair_decode(fd_pubkey_u64_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->_0, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->_1, data, dataend);
}
void fd_pubkey_u64_pair_destroy(fd_pubkey_u64_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->_0, freef, freef_arg);
}

ulong fd_pubkey_u64_pair_size(fd_pubkey_u64_pair_t* self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->_0);
  size += sizeof(ulong);
  return size;
}

void fd_pubkey_u64_pair_encode(fd_pubkey_u64_pair_t* self, void const** data) {
  fd_pubkey_encode(&self->_0, data);
  fd_bincode_uint64_encode(&self->_1, data);
}

void fd_unused_accounts_decode(fd_unused_accounts_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->unused1_len, data, dataend);
  if (self->unused1_len != 0) {
    self->unused1 = (fd_pubkey_t*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->unused1_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_decode(self->unused1 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused1 = NULL;
  fd_bincode_uint64_decode(&self->unused2_len, data, dataend);
  if (self->unused2_len != 0) {
    self->unused2 = (fd_pubkey_t*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->unused2_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_decode(self->unused2 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused2 = NULL;
  fd_bincode_uint64_decode(&self->unused3_len, data, dataend);
  if (self->unused3_len != 0) {
    self->unused3 = (fd_pubkey_u64_pair_t*)(*allocf)(FD_PUBKEY_U64_PAIR_FOOTPRINT*self->unused3_len, FD_PUBKEY_U64_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_decode(self->unused3 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused3 = NULL;
}
void fd_unused_accounts_destroy(fd_unused_accounts_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->unused1) {
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_destroy(self->unused1 + i,  freef, freef_arg);
    freef(self->unused1, freef_arg);
    self->unused1 = NULL;
  }
  if (NULL != self->unused2) {
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_destroy(self->unused2 + i,  freef, freef_arg);
    freef(self->unused2, freef_arg);
    self->unused2 = NULL;
  }
  if (NULL != self->unused3) {
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_destroy(self->unused3 + i,  freef, freef_arg);
    freef(self->unused3, freef_arg);
    self->unused3 = NULL;
  }
}

ulong fd_unused_accounts_size(fd_unused_accounts_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->unused1_len; ++i)
    size += fd_pubkey_size(self->unused1 + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->unused2_len; ++i)
    size += fd_pubkey_size(self->unused2 + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->unused3_len; ++i)
    size += fd_pubkey_u64_pair_size(self->unused3 + i);
  return size;
}

void fd_unused_accounts_encode(fd_unused_accounts_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->unused1_len, data);
  if (self->unused1_len != 0) {
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_encode(self->unused1 + i, data);
  }
  fd_bincode_uint64_encode(&self->unused2_len, data);
  if (self->unused2_len != 0) {
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_encode(self->unused2 + i, data);
  }
  fd_bincode_uint64_encode(&self->unused3_len, data);
  if (self->unused3_len != 0) {
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_encode(self->unused3 + i, data);
  }
}

void fd_deserializable_versioned_bank_decode(fd_deserializable_versioned_bank_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_block_hash_queue_decode(&self->blockhash_queue, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->ancestors_len, data, dataend);
  if (self->ancestors_len != 0) {
    self->ancestors = (fd_slot_pair_t*)(*allocf)(FD_SLOT_PAIR_FOOTPRINT*self->ancestors_len, FD_SLOT_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->ancestors_len; ++i)
      fd_slot_pair_decode(self->ancestors + i, data, dataend, allocf, allocf_arg);
  } else
    self->ancestors = NULL;
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
  fd_bincode_uint64_decode(&self->genesis_creation_time, data, dataend);
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
  if (self->epoch_stakes_len != 0) {
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
    for (ulong i = 0; i < self->ancestors_len; ++i)
      fd_slot_pair_destroy(self->ancestors + i,  freef, freef_arg);
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
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      fd_epoch_epoch_stakes_pair_destroy(self->epoch_stakes + i,  freef, freef_arg);
    freef(self->epoch_stakes, freef_arg);
    self->epoch_stakes = NULL;
  }
}

ulong fd_deserializable_versioned_bank_size(fd_deserializable_versioned_bank_t* self) {
  ulong size = 0;
  size += fd_block_hash_queue_size(&self->blockhash_queue);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->ancestors_len; ++i)
    size += fd_slot_pair_size(self->ancestors + i);
  size += fd_hash_size(&self->hash);
  size += fd_hash_size(&self->parent_hash);
  size += sizeof(ulong);
  size += fd_hard_forks_size(&self->hard_forks);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  if (NULL !=  self->hashes_per_tick) {
    size += sizeof(ulong);
  }
  size += sizeof(ulong);
  size += sizeof(uint128);
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->collector_id);
  size += sizeof(ulong);
  size += fd_fee_calculator_size(&self->fee_calculator);
  size += fd_fee_rate_governor_size(&self->fee_rate_governor);
  size += sizeof(ulong);
  size += fd_rent_collector_size(&self->rent_collector);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += fd_inflation_size(&self->inflation);
  size += fd_stakes_delegation_size(&self->stakes);
  size += fd_unused_accounts_size(&self->unused_accounts);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->epoch_stakes_len; ++i)
    size += fd_epoch_epoch_stakes_pair_size(self->epoch_stakes + i);
  size += sizeof(char);
  return size;
}

void fd_deserializable_versioned_bank_encode(fd_deserializable_versioned_bank_t* self, void const** data) {
  fd_block_hash_queue_encode(&self->blockhash_queue, data);
  fd_bincode_uint64_encode(&self->ancestors_len, data);
  if (self->ancestors_len != 0) {
    for (ulong i = 0; i < self->ancestors_len; ++i)
      fd_slot_pair_encode(self->ancestors + i, data);
  }
  fd_hash_encode(&self->hash, data);
  fd_hash_encode(&self->parent_hash, data);
  fd_bincode_uint64_encode(&self->parent_slot, data);
  fd_hard_forks_encode(&self->hard_forks, data);
  fd_bincode_uint64_encode(&self->transaction_count, data);
  fd_bincode_uint64_encode(&self->tick_height, data);
  fd_bincode_uint64_encode(&self->signature_count, data);
  fd_bincode_uint64_encode(&self->capitalization, data);
  fd_bincode_uint64_encode(&self->max_tick_height, data);
  if (self->hashes_per_tick!= NULL) {
    fd_bincode_option_encode(1, data);
    fd_bincode_uint64_encode(self->hashes_per_tick, data);
  } else
    fd_bincode_option_encode(0, data);
  fd_bincode_uint64_encode(&self->ticks_per_slot, data);
  fd_bincode_uint128_encode(&self->ns_per_slot, data);
  fd_bincode_uint64_encode(&self->genesis_creation_time, data);
  fd_bincode_double_encode(&self->slots_per_year, data);
  fd_bincode_uint64_encode(&self->accounts_data_len, data);
  fd_bincode_uint64_encode(&self->slot, data);
  fd_bincode_uint64_encode(&self->epoch, data);
  fd_bincode_uint64_encode(&self->block_height, data);
  fd_pubkey_encode(&self->collector_id, data);
  fd_bincode_uint64_encode(&self->collector_fees, data);
  fd_fee_calculator_encode(&self->fee_calculator, data);
  fd_fee_rate_governor_encode(&self->fee_rate_governor, data);
  fd_bincode_uint64_encode(&self->collected_rent, data);
  fd_rent_collector_encode(&self->rent_collector, data);
  fd_epoch_schedule_encode(&self->epoch_schedule, data);
  fd_inflation_encode(&self->inflation, data);
  fd_stakes_delegation_encode(&self->stakes, data);
  fd_unused_accounts_encode(&self->unused_accounts, data);
  fd_bincode_uint64_encode(&self->epoch_stakes_len, data);
  if (self->epoch_stakes_len != 0) {
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      fd_epoch_epoch_stakes_pair_encode(self->epoch_stakes + i, data);
  }
  fd_bincode_uint8_encode((unsigned char *) &self->is_delta, data);
}

void fd_serializable_account_storage_entry_decode(fd_serializable_account_storage_entry_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->id, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_current_len, data, dataend);
}
void fd_serializable_account_storage_entry_destroy(fd_serializable_account_storage_entry_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_serializable_account_storage_entry_size(fd_serializable_account_storage_entry_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

void fd_serializable_account_storage_entry_encode(fd_serializable_account_storage_entry_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->id, data);
  fd_bincode_uint64_encode(&self->accounts_current_len, data);
}

void fd_bank_hash_stats_decode(fd_bank_hash_stats_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->num_updated_accounts, data, dataend);
  fd_bincode_uint64_decode(&self->num_removed_accounts, data, dataend);
  fd_bincode_uint64_decode(&self->num_lamports_stored, data, dataend);
  fd_bincode_uint64_decode(&self->total_data_len, data, dataend);
  fd_bincode_uint64_decode(&self->num_executable_accounts, data, dataend);
}
void fd_bank_hash_stats_destroy(fd_bank_hash_stats_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_bank_hash_stats_size(fd_bank_hash_stats_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

void fd_bank_hash_stats_encode(fd_bank_hash_stats_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->num_updated_accounts, data);
  fd_bincode_uint64_encode(&self->num_removed_accounts, data);
  fd_bincode_uint64_encode(&self->num_lamports_stored, data);
  fd_bincode_uint64_encode(&self->total_data_len, data);
  fd_bincode_uint64_encode(&self->num_executable_accounts, data);
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

ulong fd_bank_hash_info_size(fd_bank_hash_info_t* self) {
  ulong size = 0;
  size += fd_hash_size(&self->hash);
  size += fd_hash_size(&self->snapshot_hash);
  size += fd_bank_hash_stats_size(&self->stats);
  return size;
}

void fd_bank_hash_info_encode(fd_bank_hash_info_t* self, void const** data) {
  fd_hash_encode(&self->hash, data);
  fd_hash_encode(&self->snapshot_hash, data);
  fd_bank_hash_stats_encode(&self->stats, data);
}

void fd_slot_account_pair_decode(fd_slot_account_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_len, data, dataend);
  if (self->accounts_len != 0) {
    self->accounts = (fd_serializable_account_storage_entry_t*)(*allocf)(FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_FOOTPRINT*self->accounts_len, FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_serializable_account_storage_entry_decode(self->accounts + i, data, dataend, allocf, allocf_arg);
  } else
    self->accounts = NULL;
}
void fd_slot_account_pair_destroy(fd_slot_account_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->accounts) {
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_serializable_account_storage_entry_destroy(self->accounts + i,  freef, freef_arg);
    freef(self->accounts, freef_arg);
    self->accounts = NULL;
  }
}

ulong fd_slot_account_pair_size(fd_slot_account_pair_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->accounts_len; ++i)
    size += fd_serializable_account_storage_entry_size(self->accounts + i);
  return size;
}

void fd_slot_account_pair_encode(fd_slot_account_pair_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->slot, data);
  fd_bincode_uint64_encode(&self->accounts_len, data);
  if (self->accounts_len != 0) {
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_serializable_account_storage_entry_encode(self->accounts + i, data);
  }
}

void fd_slot_map_pair_decode(fd_slot_map_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
}
void fd_slot_map_pair_destroy(fd_slot_map_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_hash_destroy(&self->hash, freef, freef_arg);
}

ulong fd_slot_map_pair_size(fd_slot_map_pair_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_hash_size(&self->hash);
  return size;
}

void fd_slot_map_pair_encode(fd_slot_map_pair_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->slot, data);
  fd_hash_encode(&self->hash, data);
}

void fd_solana_accounts_db_fields_decode(fd_solana_accounts_db_fields_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->storages_len, data, dataend);
  if (self->storages_len != 0) {
    self->storages = (fd_slot_account_pair_t*)(*allocf)(FD_SLOT_ACCOUNT_PAIR_FOOTPRINT*self->storages_len, FD_SLOT_ACCOUNT_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->storages_len; ++i)
      fd_slot_account_pair_decode(self->storages + i, data, dataend, allocf, allocf_arg);
  } else
    self->storages = NULL;
  fd_bincode_uint64_decode(&self->version, data, dataend);
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bank_hash_info_decode(&self->bank_hash_info, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->historical_roots_len, data, dataend);
  if (self->historical_roots_len != 0) {
    self->historical_roots = (ulong*)(*allocf)(sizeof(ulong)*self->historical_roots_len, 8, allocf_arg);
    for (ulong i = 0; i < self->historical_roots_len; ++i)
      fd_bincode_uint64_decode(self->historical_roots + i, data, dataend);
  } else
    self->historical_roots = NULL;
  fd_bincode_uint64_decode(&self->historical_roots_with_hash_len, data, dataend);
  if (self->historical_roots_with_hash_len != 0) {
    self->historical_roots_with_hash = (fd_slot_map_pair_t*)(*allocf)(FD_SLOT_MAP_PAIR_FOOTPRINT*self->historical_roots_with_hash_len, FD_SLOT_MAP_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_decode(self->historical_roots_with_hash + i, data, dataend, allocf, allocf_arg);
  } else
    self->historical_roots_with_hash = NULL;
}
void fd_solana_accounts_db_fields_destroy(fd_solana_accounts_db_fields_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->storages) {
    for (ulong i = 0; i < self->storages_len; ++i)
      fd_slot_account_pair_destroy(self->storages + i,  freef, freef_arg);
    freef(self->storages, freef_arg);
    self->storages = NULL;
  }
  fd_bank_hash_info_destroy(&self->bank_hash_info, freef, freef_arg);
  if (NULL != self->historical_roots) {
    freef(self->historical_roots, freef_arg);
    self->historical_roots = NULL;
  }
  if (NULL != self->historical_roots_with_hash) {
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_destroy(self->historical_roots_with_hash + i,  freef, freef_arg);
    freef(self->historical_roots_with_hash, freef_arg);
    self->historical_roots_with_hash = NULL;
  }
}

ulong fd_solana_accounts_db_fields_size(fd_solana_accounts_db_fields_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  for (ulong i = 0; i < self->storages_len; ++i)
    size += fd_slot_account_pair_size(self->storages + i);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_bank_hash_info_size(&self->bank_hash_info);
  size += sizeof(ulong);
  size += self->historical_roots_len * sizeof(ulong);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
    size += fd_slot_map_pair_size(self->historical_roots_with_hash + i);
  return size;
}

void fd_solana_accounts_db_fields_encode(fd_solana_accounts_db_fields_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->storages_len, data);
  if (self->storages_len != 0) {
    for (ulong i = 0; i < self->storages_len; ++i)
      fd_slot_account_pair_encode(self->storages + i, data);
  }
  fd_bincode_uint64_encode(&self->version, data);
  fd_bincode_uint64_encode(&self->slot, data);
  fd_bank_hash_info_encode(&self->bank_hash_info, data);
  fd_bincode_uint64_encode(&self->historical_roots_len, data);
  if (self->historical_roots_len != 0) {
    for (ulong i = 0; i < self->historical_roots_len; ++i)
      fd_bincode_uint64_encode(self->historical_roots + i, data);
  }
  fd_bincode_uint64_encode(&self->historical_roots_with_hash_len, data);
  if (self->historical_roots_with_hash_len != 0) {
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_encode(self->historical_roots_with_hash + i, data);
  }
}

void fd_rust_duration_decode(fd_rust_duration_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->seconds, data, dataend);
  fd_bincode_uint32_decode(&self->nanoseconds, data, dataend);
}
void fd_rust_duration_destroy(fd_rust_duration_t* self, fd_free_fun_t freef, void* freef_arg) {
}

ulong fd_rust_duration_size(fd_rust_duration_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(uint);
  return size;
}

void fd_rust_duration_encode(fd_rust_duration_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->seconds, data);
  fd_bincode_uint32_encode(&self->nanoseconds, data);
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
void fd_poh_config_destroy(fd_poh_config_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_rust_duration_destroy(&self->target_tick_duration, freef, freef_arg);
  if (NULL != self->target_tick_count) {
    freef(self->target_tick_count, freef_arg);
    self->target_tick_count = NULL;
  }
  if (NULL != self->hashes_per_tick) {
    freef(self->hashes_per_tick, freef_arg);
    self->hashes_per_tick = NULL;
  }
}

ulong fd_poh_config_size(fd_poh_config_t* self) {
  ulong size = 0;
  size += fd_rust_duration_size(&self->target_tick_duration);
  size += sizeof(char);
  if (NULL !=  self->target_tick_count) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if (NULL !=  self->hashes_per_tick) {
    size += sizeof(ulong);
  }
  return size;
}

void fd_poh_config_encode(fd_poh_config_t* self, void const** data) {
  fd_rust_duration_encode(&self->target_tick_duration, data);
  if (self->target_tick_count!= NULL) {
    fd_bincode_option_encode(1, data);
    fd_bincode_uint64_encode(self->target_tick_count, data);
  } else
    fd_bincode_option_encode(0, data);
  if (self->hashes_per_tick!= NULL) {
    fd_bincode_option_encode(1, data);
    fd_bincode_uint64_encode(self->hashes_per_tick, data);
  } else
    fd_bincode_option_encode(0, data);
}

void fd_string_pubkey_pair_decode(fd_string_pubkey_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  ulong slen;
  fd_bincode_uint64_decode(&slen, data, dataend);
  self->string = (char*)(*allocf)(slen + 1, 1, allocf_arg);
  fd_bincode_bytes_decode((uchar *) self->string, slen, data, dataend);
  self->string[slen] = '\0';
  fd_pubkey_decode(&self->pubkey, data, dataend, allocf, allocf_arg);
}
void fd_string_pubkey_pair_destroy(fd_string_pubkey_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  if (NULL != self->string) {
    freef(self->string, freef_arg);
    self->string = NULL;
  }
  fd_pubkey_destroy(&self->pubkey, freef, freef_arg);
}

ulong fd_string_pubkey_pair_size(fd_string_pubkey_pair_t* self) {
  ulong size = 0;
  size += sizeof(ulong) + strlen(self->string);
  size += fd_pubkey_size(&self->pubkey);
  return size;
}

void fd_string_pubkey_pair_encode(fd_string_pubkey_pair_t* self, void const** data) {
  ulong slen = strlen((char *) self->string);
  fd_bincode_uint64_encode(&slen, data);
  fd_bincode_bytes_encode((uchar *) self->string, slen, data);
  fd_pubkey_encode(&self->pubkey, data);
}

void fd_pubkey_account_pair_decode(fd_pubkey_account_pair_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_solana_account_decode(&self->account, data, dataend, allocf, allocf_arg);
}
void fd_pubkey_account_pair_destroy(fd_pubkey_account_pair_t* self, fd_free_fun_t freef, void* freef_arg) {
  fd_pubkey_destroy(&self->key, freef, freef_arg);
  fd_solana_account_destroy(&self->account, freef, freef_arg);
}

ulong fd_pubkey_account_pair_size(fd_pubkey_account_pair_t* self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_solana_account_size(&self->account);
  return size;
}

void fd_pubkey_account_pair_encode(fd_pubkey_account_pair_t* self, void const** data) {
  fd_pubkey_encode(&self->key, data);
  fd_solana_account_encode(&self->account, data);
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
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
      fd_string_pubkey_pair_destroy(self->native_instruction_processors + i,  freef, freef_arg);
    freef(self->native_instruction_processors, freef_arg);
    self->native_instruction_processors = NULL;
  }
  if (NULL != self->rewards_pools) {
    for (ulong i = 0; i < self->rewards_pools_len; ++i)
      fd_pubkey_account_pair_destroy(self->rewards_pools + i,  freef, freef_arg);
    freef(self->rewards_pools, freef_arg);
    self->rewards_pools = NULL;
  }
  fd_poh_config_destroy(&self->poh_config, freef, freef_arg);
  fd_fee_rate_governor_destroy(&self->fee_rate_governor, freef, freef_arg);
  fd_rent_destroy(&self->rent, freef, freef_arg);
  fd_inflation_destroy(&self->inflation, freef, freef_arg);
  fd_epoch_schedule_destroy(&self->epoch_schedule, freef, freef_arg);
}

ulong fd_genesis_solana_size(fd_genesis_solana_t* self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->accounts_len; ++i)
    size += fd_pubkey_account_pair_size(self->accounts + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
    size += fd_string_pubkey_pair_size(self->native_instruction_processors + i);
  size += sizeof(ulong);
  for (ulong i = 0; i < self->rewards_pools_len; ++i)
    size += fd_pubkey_account_pair_size(self->rewards_pools + i);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_poh_config_size(&self->poh_config);
  size += sizeof(ulong);
  size += fd_fee_rate_governor_size(&self->fee_rate_governor);
  size += fd_rent_size(&self->rent);
  size += fd_inflation_size(&self->inflation);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += sizeof(uint);
  return size;
}

void fd_genesis_solana_encode(fd_genesis_solana_t* self, void const** data) {
  fd_bincode_uint64_encode(&self->creation_time, data);
  fd_bincode_uint64_encode(&self->accounts_len, data);
  if (self->accounts_len != 0) {
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_pubkey_account_pair_encode(self->accounts + i, data);
  }
  fd_bincode_uint64_encode(&self->native_instruction_processors_len, data);
  if (self->native_instruction_processors_len != 0) {
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
      fd_string_pubkey_pair_encode(self->native_instruction_processors + i, data);
  }
  fd_bincode_uint64_encode(&self->rewards_pools_len, data);
  if (self->rewards_pools_len != 0) {
    for (ulong i = 0; i < self->rewards_pools_len; ++i)
      fd_pubkey_account_pair_encode(self->rewards_pools + i, data);
  }
  fd_bincode_uint64_encode(&self->ticks_per_slot, data);
  fd_bincode_uint64_encode(&self->unused, data);
  fd_poh_config_encode(&self->poh_config, data);
  fd_bincode_uint64_encode(&self->__backwards_compat_with_v0_23, data);
  fd_fee_rate_governor_encode(&self->fee_rate_governor, data);
  fd_rent_encode(&self->rent, data);
  fd_inflation_encode(&self->inflation, data);
  fd_epoch_schedule_encode(&self->epoch_schedule, data);
  fd_bincode_uint32_encode(&self->cluster_type, data);
}

