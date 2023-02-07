//use the _t typedefs... 

typedef char* (*alloc_fun)(ulong len, ulong align, void* arg);

void fd_bincode_uint128_decode(uint128* self, void const** data, void const* dataend) {
  const uint128 *ptr = (const uint128 *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint64_decode(ulong* self, void const** data, void const* dataend) {
  const ulong *ptr = (const ulong *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_double_decode(double* self, void const** data, void const* dataend) {
  const double *ptr = (const double *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint32_decode(unsigned int* self, void const** data, void const* dataend) {
  const unsigned int *ptr = (const unsigned int *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint8_decode(unsigned char* self, void const** data, void const* dataend) {
  const unsigned char *ptr = (const unsigned char *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_bytes_decode(unsigned char* self, ulong len, void const** data, void const* dataend) {
  unsigned char *ptr = (unsigned char *) *data;
  if (FD_UNLIKELY((void *) (ptr + len) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  memcpy(self, ptr, len); // what is the FD way?
  *data = ptr + len;
}

unsigned char fd_bincode_option_decode(void const** data, void const* dataend) {
  unsigned char *ptr = (unsigned char *) *data;
  if (FD_UNLIKELY((void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  unsigned char ret = *ptr;
  *data = ptr + 1;
  return ret;
}

// sdk/program/src/fee_calculator.rs:11
struct fd_fee_calculator {
  ulong lamports_per_signature;
};
typedef struct fd_fee_calculator fd_fee_calculator_t;
#define FD_FEE_CALCULATOR_FOOTPRINT sizeof(struct fd_fee_calculator)
#define FD_FEE_CALCULATOR_ALIGN (8UL)

void fd_fee_calculator_decode(struct fd_fee_calculator* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_signature, data, dataend);
}

// runtime/src/blockhash_queue.rs:12
struct fd_hash_age {
  struct fd_fee_calculator fee_calculator;
  ulong hash_index;
  ulong timestamp;
};
typedef struct fd_hash_age fd_hash_age_t;
#define FD_HASH_AGE_FOOTPRINT sizeof(struct fd_hash_age)
#define FD_HASH_AGE_ALIGN (8UL)

void fd_hash_age_decode(struct fd_hash_age* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_fee_calculator_decode(&self->fee_calculator, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->hash_index, data, dataend);
  fd_bincode_uint64_decode(&self->timestamp, data, dataend);
}

// sdk/program/src/hash.rs:47
struct fd_hash {
  unsigned char hash[32];
};
typedef struct fd_hash fd_hash_t;
#define FD_HASH_FOOTPRINT sizeof(struct fd_hash)
#define FD_HASH_ALIGN (8UL)

void fd_hash_decode(struct fd_hash* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->hash[0], sizeof(self->hash), data, dataend);
}

struct fd_hash_hash_age_Pair {
  struct fd_hash key;
  struct fd_hash_age val;
};
typedef struct fd_hash_hash_age_Pair fd_hash_hash_age_Pair_t;
#define FD_HASH_HASH_AGE_PAIR_FOOTPRINT sizeof(struct fd_hash_hash_age_Pair)
#define FD_HASH_HASH_AGE_PAIR_ALIGN (8UL)

void fd_hash_hash_age_Pair_decode(struct fd_hash_hash_age_Pair* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(self->key.hash, sizeof(self->key.hash), data, dataend);
  fd_hash_age_decode(&self->val, data, dataend, allocf, allocf_arg);
}

// runtime/src/blockhash_queue.rs:21
struct fd_block_hash_queue {
  ulong last_hash_index;
  struct fd_hash* last_hash;

  ulong ages_len;
  struct fd_hash_hash_age_Pair* ages;

  ulong max_age;
};
typedef struct fd_block_hash_queue fd_block_hash_queue_t;
#define FD_BLOCK_HASH_QUEUE_FOOTPRINT sizeof(struct fd_block_hash_queue)
#define FD_BLOCK_HASH_QUEUE_ALIGN (8UL)

void fd_block_hash_queue_decode(struct fd_block_hash_queue* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->last_hash_index, data, dataend);

  if (fd_bincode_option_decode(data, dataend)) {
    self->last_hash = (struct fd_hash*)(*allocf)(FD_HASH_FOOTPRINT, FD_HASH_ALIGN, allocf_arg);
    fd_hash_decode(self->last_hash, data, dataend, allocf, allocf_arg);
  } else {
    self->last_hash = NULL;
  }

  fd_bincode_uint64_decode(&self->ages_len, data, dataend);
  if (self->ages_len > 0) {
    self->ages = (struct fd_hash_hash_age_Pair*)(*allocf)(FD_HASH_HASH_AGE_PAIR_FOOTPRINT*self->ages_len, FD_HASH_HASH_AGE_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_Pair_decode(self->ages + i, data, dataend, allocf, allocf_arg);
  } else
    self->ages = NULL;

  fd_bincode_uint64_decode(&self->max_age, data, dataend);
}

// sdk/program/src/pubkey.rs:87
struct fd_pubkey {
  unsigned char key[32];
};
typedef struct fd_pubkey fd_pubkey_t;
#define FD_PUBKEY_FOOTPRINT sizeof(struct fd_pubkey)
#define FD_PUBKEY_ALIGN (8UL)

void fd_pubkey_decode(struct fd_pubkey* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->key[0], sizeof(self->key), data, dataend);
}

// sdk/program/src/epoch_schedule.rs:34
struct fd_epoch_schedule {
  ulong slots_per_epoch;
  ulong leader_schedule_slot_offset;
  unsigned char warmup;
  ulong first_normal_epoch;
  ulong first_normal_slot;
};
typedef struct fd_epoch_schedule fd_epoch_schedule_t;
#define FD_EPOCH_SCHEDULE_FOOTPRINT sizeof(struct fd_epoch_schedule)
#define FD_EPOCH_SCHEDULE_ALIGN (8UL)

void fd_epoch_schedule_decode(struct fd_epoch_schedule* self,  void const** data,  void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slots_per_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->leader_schedule_slot_offset, data, dataend);
  fd_bincode_uint8_decode(&self->warmup, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_slot, data, dataend);
}

// sdk/program/src/fee_calculator.rs:52
struct fd_fee_rate_governor {
  ulong target_lamports_per_signature;
  ulong target_signatures_per_slot;
  ulong min_lamports_per_signature;
  ulong max_lamports_per_signature;
  unsigned char burn_percent;
};
typedef struct fd_fee_rate_governor fd_fee_rate_governor_t;
#define FD_FEE_RATE_GOVERNOR_FOOTPRINT sizeof(struct fd_fee_rate_governor)
#define FD_FEE_RATE_GOVERNOR_ALIGN (8UL)

void fd_fee_rate_governor_decode(struct fd_fee_rate_governor* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->target_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->target_signatures_per_slot, data, dataend);
  fd_bincode_uint64_decode(&self->min_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->max_lamports_per_signature, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}

struct fd_slot_pair {
  ulong slot;
  ulong val;
};
typedef struct fd_slot_pair fd_slot_pair_t;
#define FD_SLOT_PAIR_FOOTPRINT sizeof(struct fd_slot_pair)
#define FD_SLOT_PAIR_ALIGN (8UL)

void fd_slot_pair_decode(struct fd_slot_pair* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->val, data, dataend);
}

// sdk/src/hard_forks.rs:12
struct fd_hard_forks {
  ulong len;
  struct fd_slot_pair* hard_forks;
};
typedef struct fd_hard_forks fd_hard_forks_t;
#define FD_HARD_FORKS_FOOTPRINT sizeof(struct fd_hard_forks)
#define FD_HARD_FORKS_ALIGN (8UL)

void fd_hard_forks_decode(struct fd_hard_forks* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->len, data, dataend);
  if (self->len > 0) {
    self->hard_forks = (struct fd_slot_pair*)(*allocf)(FD_SLOT_PAIR_FOOTPRINT*self->len, FD_SLOT_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->len; ++i)
      fd_slot_pair_decode(self->hard_forks + i, data, dataend, allocf, allocf_arg);
  } else
    self->hard_forks = NULL;
}

// sdk/src/fd_inflation.rs:5
struct fd_inflation {
  double initial;
  double terminal;
  double taper;
  double foundation;
  double foundation_term;
  double __unused;
};
typedef struct fd_inflation fd_inflation_t;
#define FD_INFLATION_FOOTPRINT sizeof(struct fd_inflation)
#define FD_INFLATION_ALIGN (8UL)

void fd_inflation_decode(struct fd_inflation* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_double_decode(&self->initial, data, dataend);
  fd_bincode_double_decode(&self->terminal, data, dataend);
  fd_bincode_double_decode(&self->taper, data, dataend);
  fd_bincode_double_decode(&self->foundation, data, dataend);
  fd_bincode_double_decode(&self->foundation_term, data, dataend);
  fd_bincode_double_decode(&self->__unused, data, dataend);
}

// sdk/program/src/rent.rs:12
struct fd_rent {
  ulong lamports_per_uint8_year;
  double exemption_threshold;
  unsigned char burn_percent;
};
typedef struct fd_rent fd_rent_t;
#define RENT_FOOTPRINT sizeof(struct fd_rent)
#define RENT_ALIGN (8UL)

void fd_rent_decode(FD_FN_UNUSED struct fd_rent* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_uint8_year, data, dataend);
  fd_bincode_double_decode(&self->exemption_threshold, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}

// runtime/src/rent_collector.rs:13
struct fd_rent_collector {
  ulong epoch;
  struct fd_epoch_schedule epoch_schedule;
  double slots_per_year;
  struct fd_rent rent;
};
typedef struct fd_rent_collector fd_rent_collector_t;
#define FD_RENT_COLLECTOR_FOOTPRINT sizeof(struct fd_rent_collector)
#define FD_RENT_COLLECTOR_ALIGN (8UL)

void fd_rent_collector_decode(struct fd_rent_collector* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_epoch_schedule_decode(&self->epoch_schedule, data, dataend, allocf, allocf_arg);
  fd_bincode_double_decode(&self->slots_per_year, data, dataend);
  fd_rent_decode(&self->rent, data, dataend, allocf, allocf_arg);
}

// sdk/program/src/stake_history.rs:15
struct fd_stake_history_entry {
  ulong effective;
  ulong activating;
  ulong deactivating;
};
typedef struct fd_stake_history_entry fd_stake_history_entry_t;
#define FD_STAKE_HISTORY_ENTRY_FOOTPRINT sizeof(struct fd_stake_history_entry)
#define FD_STAKE_HISTORY_ENTRY_ALIGN (8UL)

void fd_stake_history_entry_decode(FD_FN_UNUSED struct fd_stake_history_entry* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->effective, data, dataend);
  fd_bincode_uint64_decode(&self->activating, data, dataend);
  fd_bincode_uint64_decode(&self->deactivating, data, dataend);
}

struct fd_stake_history_epochentry_pair {
  ulong epoch;
  struct fd_stake_history_entry entry;
};
typedef struct fd_stake_history_epochentry_pair fd_stake_history_epochentry_pair_t;
#define FD_STAKE_HISTORY_EPOCHENTRY_PAIR_FOOTPRINT sizeof(struct fd_stake_history_epochentry_pair)
#define FD_STAKE_HISTORY_EPOCHENTRY_PAIR_ALIGN (8UL)

void fd_stake_history_epochentry_pair_decode(struct fd_stake_history_epochentry_pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_stake_history_entry_decode(&self->entry, data, dataend, allocf, allocf_arg);
}

// sdk/program/src/stake_history.rs
struct fd_stake_history {
  ulong len;
  struct fd_stake_history_epochentry_pair* entries;
};
typedef struct fd_stake_history fd_stake_history_t;
#define FD_STAKE_HISTORY_FOOTPRINT sizeof(struct fd_stake_history)
#define FD_STAKE_HISTORY_ALIGN (8UL)

void fd_stake_history_decode(struct fd_stake_history* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->len, data, dataend);
  if (self->len > 0) {
    self->entries = (struct fd_stake_history_epochentry_pair*)(*allocf)(FD_STAKE_HISTORY_EPOCHENTRY_PAIR_FOOTPRINT*self->len, FD_STAKE_HISTORY_EPOCHENTRY_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->len; ++i)
      fd_stake_history_epochentry_pair_decode(self->entries + i, data, dataend, allocf, allocf_arg);
  } else
    self->entries = NULL;
}

// sdk/src/account.rs:27
struct fd_account {
  ulong lamports;

  ulong data_len;
  unsigned char* data;

  struct fd_pubkey owner;
  unsigned char executable;
  ulong rent_epoch;
};
typedef struct fd_account fd_account_t;
#define ACCOUNT_FOOTPRINT sizeof(struct fd_account)
#define ACCOUNT_ALIGN (8UL)

void fd_account_decode(struct fd_account* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
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

struct fd_vote_accounts_pair {
  struct fd_pubkey key;
  ulong stake;
  struct fd_account value;
};
typedef struct fd_vote_accounts_pair fd_vote_accounts_pair_t;
#define FD_VOTE_ACCOUNTS_PAIR_FOOTPRINT sizeof(struct fd_vote_accounts_pair)
#define FD_VOTE_ACCOUNTS_PAIR_ALIGN (8UL)

void fd_vote_accounts_pair_decode(struct fd_vote_accounts_pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake, data, dataend);
  fd_account_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/vote_account.rs:42
struct fd_vote_accounts { // tested and confirmed
  ulong vote_accounts_len;
  struct fd_vote_accounts_pair *vote_accounts;
};
typedef struct fd_vote_accounts fd_vote_accounts_t;
#define FD_VOTE_ACCOUNTS_FOOTPRINT sizeof(struct fd_vote_accounts)
#define FD_VOTE_ACCOUNTS_ALIGN (8UL)

void fd_vote_accounts_decode(struct fd_vote_accounts* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len != 0) {
    self->vote_accounts = (struct fd_vote_accounts_pair*)(*allocf)(FD_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->vote_accounts_len, FD_VOTE_ACCOUNTS_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_vote_accounts_pair_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->vote_accounts = NULL;
}

// sdk/program/src/stake/state.rs:301
struct fd_delegation {
  struct fd_pubkey voter_pubkey;
  ulong stake;
  ulong activation_epoch;
  ulong deactivation_epoch;
  double warmup_cooldown_rate;
};
typedef struct fd_delegation fd_delegation_t;
#define DELEGATION_FOOTPRINT sizeof(struct fd_delegation)
#define DELEGATION_ALIGN (8UL)

void fd_delegation_decode(struct fd_delegation* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->voter_pubkey, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake, data, dataend);
  fd_bincode_uint64_decode(&self->activation_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->deactivation_epoch, data, dataend);
  fd_bincode_double_decode(&self->warmup_cooldown_rate, data, dataend);
}

struct fd_delegation_pair {
  struct fd_pubkey key;
  struct fd_delegation value;
};
typedef struct fd_delegation_pair fd_delegation_pair_t;
#define FD_DELEGATION_PAIR_FOOTPRINT sizeof(struct fd_delegation_pair)
#define FD_DELEGATION_PAIR_ALIGN (8UL)

void fd_delegation_pair_decode(struct fd_delegation_pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_delegation_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/stakes.rs:169
// runtime/src/bank.rs:747
struct fd_stakes_deligation {
  struct fd_vote_accounts vote_accounts;
  // stake_delegations: Imfd_hashMap<fd_pubkey, fd_delegation>,
  ulong stake_delegations_len;
  struct fd_delegation_pair* stake_delegations;
  ulong unused;
  ulong epoch;
  struct fd_stake_history stake_history;
};
typedef struct fd_stakes_deligation fd_stakes_deligation_t;
#define FD_STAKES_DELIGATION_FOOTPRINT sizeof(struct fd_stakes_deligation)
#define FD_STAKES_DELIGATION_ALIGN (8UL)

void fd_stakes_deligation_decode(struct fd_stakes_deligation* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_vote_accounts_decode(&self->vote_accounts, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake_delegations_len, data, dataend);
  if (self->stake_delegations_len) {
    self->stake_delegations = (struct fd_delegation_pair*)(*allocf)(FD_DELEGATION_PAIR_FOOTPRINT*self->stake_delegations_len, FD_DELEGATION_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->stake_delegations_len; ++i)
      fd_delegation_pair_decode(self->stake_delegations + i, data, dataend, allocf, allocf_arg);
  } else 
    self->stake_delegations = NULL;
  fd_bincode_uint64_decode(&self->unused, data, dataend);
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_stake_history_decode(&self->stake_history, data, dataend, allocf, allocf_arg);
}

// runtime/src/bank.rs:238
struct fd_bank_incremental_snapshot_persistence {
  ulong full_slot;
  struct fd_hash full_hash;
  ulong full_capitalization;
  struct fd_hash incremental_hash;
  ulong incremental_capitalization;
};
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FOOTPRINT sizeof(struct fd_bank_incremental_snapshot_persistence)
#define FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN (8UL)

struct Nodefd_vote_accounts {
  ulong vote_accounts_len;
  struct fd_pubkey *vote_accounts;
  ulong total_stake;
};
typedef struct Nodefd_vote_accounts Nodefd_vote_accounts_t;
#define NodeFD_VOTE_ACCOUNTS_FOOTPRINT sizeof(struct Nodefd_vote_accounts)
#define NodeFD_VOTE_ACCOUNTS_ALIGN (8UL)

void Nodefd_vote_accounts_decode(struct Nodefd_vote_accounts* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len) {
    self->vote_accounts = (struct fd_pubkey*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->vote_accounts_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
}

struct fd_pubkeyNodefd_vote_accounts_pair {
  struct fd_pubkey key;
  struct Nodefd_vote_accounts value;
};
typedef struct fd_pubkeyNodefd_vote_accounts_pair fd_pubkeyNodefd_vote_accounts_pair_t;
#define fd_pubkeyNodeFD_VOTE_ACCOUNTS_PAIR_FOOTPRINT sizeof(struct fd_pubkeyNodefd_vote_accounts_pair)
#define fd_pubkeyNodeFD_VOTE_ACCOUNTS_PAIR_ALIGN (8UL)

void fd_pubkeyNodefd_vote_accounts_pair_decode(struct fd_pubkeyNodefd_vote_accounts_pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  Nodefd_vote_accounts_decode(&self->value, data, dataend, allocf, allocf_arg);
}

struct fd_pubkey_pubkey_pair {
  struct fd_pubkey key;
  struct fd_pubkey value;
};
typedef struct fd_pubkey_pubkey_pair fd_pubkey_pubkey_pair_t;
#define FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT sizeof(struct fd_pubkey_pubkey_pair)
#define FD_PUBKEY_PUBKEY_PAIR_ALIGN (8UL)

void fd_pubkey_pubkey_pair_decode(struct fd_pubkey_pubkey_pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_pubkey_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/epoch_stakes.rs:18
struct fd_epoch_stakes {
  struct fd_stakes_deligation stakes;
  ulong total_stake;
  ulong node_id_to_vote_accounts_len;
  struct fd_pubkeyNodefd_vote_accounts_pair *node_id_to_vote_accounts;
  ulong epoch_authorized_voters_len;
  struct fd_pubkey_pubkey_pair *epoch_authorized_voters;
};
typedef struct fd_epoch_stakes fd_epoch_stakes_t;
#define FD_EPOCH_STAKES_FOOTPRINT sizeof(struct fd_epoch_stakes)
#define FD_EPOCH_STAKES_ALIGN (8UL)

void fd_epoch_stakes_decode(struct fd_epoch_stakes* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_stakes_deligation_decode(&self->stakes, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
  fd_bincode_uint64_decode(&self->node_id_to_vote_accounts_len, data, dataend);
  if (self->node_id_to_vote_accounts_len > 0) {
    self->node_id_to_vote_accounts = (struct fd_pubkeyNodefd_vote_accounts_pair*)(*allocf)(fd_pubkeyNodeFD_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->node_id_to_vote_accounts_len, fd_pubkeyNodeFD_VOTE_ACCOUNTS_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkeyNodefd_vote_accounts_pair_decode(self->node_id_to_vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->node_id_to_vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->epoch_authorized_voters_len, data, dataend);
  if (self->epoch_authorized_voters_len > 0) {
    self->epoch_authorized_voters = (struct fd_pubkey_pubkey_pair*)(*allocf)(FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT*self->epoch_authorized_voters_len, FD_PUBKEY_PUBKEY_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_decode(self->epoch_authorized_voters + i, data, dataend, allocf, allocf_arg);
  } else 
    self->epoch_authorized_voters = NULL;
}

struct Epoch_fd_epoch_stakes_Pair {
  ulong key;
  struct fd_epoch_stakes value;
};
typedef struct Epoch_fd_epoch_stakes_Pair Epoch_fd_epoch_stakes_Pair_t;
#define EPOCH_FD_EPOCH_STAKES_PAIR_FOOTPRINT sizeof(struct Epoch_fd_epoch_stakes_Pair)
#define EPOCH_FD_EPOCH_STAKES_PAIR_ALIGN (8UL)

void Epoch_fd_epoch_stakes_Pair_decode(struct Epoch_fd_epoch_stakes_Pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->key, data, dataend);
  fd_epoch_stakes_decode(&self->value, data, dataend, allocf, allocf_arg);
}

struct fd_pubkey_u64_pair {
  struct fd_pubkey _0;
  ulong _1;
};
typedef struct fd_pubkey_u64_pair fd_pubkey_u64_pair_t;
#define FD_PUBKEY_U64_PAIR_FOOTPRINT sizeof(struct fd_pubkey_u64_pair)
#define FD_PUBKEY_U64_PAIR_ALIGN (8UL)

void fd_pubkey_u64_pair_decode(struct fd_pubkey_u64_pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_pubkey_decode(&self->_0, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->_1, data, dataend);
}

// runtime/src/serde_snapshot/newer.rs:20
struct fd_unused_accounts {
  // fd_hashSet<fd_pubkey>
  ulong unused1_len;
  struct fd_pubkey* unused1;

  // fd_hashSet<fd_pubkey>
  ulong unused2_len;
  struct fd_pubkey* unused2;

  // fd_hashMap<fd_pubkey, u64>
  ulong unused3_len;
  struct fd_pubkey_u64_pair* unused3;
};
typedef struct fd_unused_accounts fd_unused_accounts_t;
#define FD_UNUSED_ACCOUNTS_FOOTPRINT sizeof(struct fd_unused_accounts)
#define FD_UNUSED_ACCOUNTS_ALIGN (8UL)

void fd_unused_accounts_decode(struct fd_unused_accounts* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->unused1_len, data, dataend);
  if (self->unused1_len > 0) {
    self->unused1 = (struct fd_pubkey*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->unused1_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_decode(self->unused1 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused1 = NULL;

  fd_bincode_uint64_decode(&self->unused2_len, data, dataend);
  if (self->unused2_len > 0) {
    self->unused2 = (struct fd_pubkey*)(*allocf)(FD_PUBKEY_FOOTPRINT*self->unused2_len, FD_PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_decode(self->unused2 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused2 = NULL;

  fd_bincode_uint64_decode(&self->unused3_len, data, dataend);
  if (self->unused3_len > 0) {
    self->unused3 = (struct fd_pubkey_u64_pair*)(*allocf)(FD_PUBKEY_U64_PAIR_FOOTPRINT*self->unused3_len, FD_PUBKEY_U64_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_decode(self->unused3 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused3 = NULL;
}

// runtime/src/serde_snapshot/newer.rs:30
struct fd_deserializable_versioned_bank {
  struct fd_block_hash_queue blockhash_queue;

  // runtime/src/ancestors.rs:pub type AncestorsForSerialization = fd_hashMap<Slot, usize>;
  ulong ancestors_len;
  struct fd_slot_pair *ancestors;

  struct fd_hash hash;
  struct fd_hash parent_hash;
  ulong parent_slot;
  struct fd_hard_forks hard_forks;
  ulong transaction_count;
  ulong tick_height;
  ulong signature_count;
  ulong capitalization;
  ulong max_tick_height;
  ulong *hashes_per_tick;
  ulong ticks_per_slot;
  uint128 ns_per_slot;
  long genesis_creation_time;
  double slots_per_year;
  ulong accounts_data_len;
  ulong slot;
  ulong epoch;
  ulong block_height;
  struct fd_pubkey collector_id;
  ulong collector_fees;
  struct fd_fee_calculator fee_calculator;
  struct fd_fee_rate_governor fee_rate_governor;
  ulong collected_rent;
  struct fd_rent_collector rent_collector;
  struct fd_epoch_schedule epoch_schedule;
  struct fd_inflation fd_inflation;
  struct fd_stakes_deligation stakes;
  struct fd_unused_accounts unused_accounts;
    
  ulong epoch_stakes_len;
  struct Epoch_fd_epoch_stakes_Pair *epoch_stakes;

  char is_delta;
};
typedef struct fd_deserializable_versioned_bank fd_deserializable_versioned_bank_t;
#define FD_DESERIALIZABLE_VERSIONED_BANK_FOOTPRINT sizeof(struct fd_deserializable_versioned_bank)
#define FD_DESERIALIZABLE_VERSIONED_BANK_ALIGN (8UL)

void fd_deserializable_versioned_bank_decode(struct fd_deserializable_versioned_bank* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_block_hash_queue_decode(&self->blockhash_queue, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->ancestors_len, data, dataend);
  self->ancestors = (struct fd_slot_pair*)(*allocf)(FD_SLOT_PAIR_FOOTPRINT*self->ancestors_len, FD_SLOT_PAIR_ALIGN, allocf_arg);
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
  fd_inflation_decode(&self->fd_inflation, data, dataend, allocf, allocf_arg);
  fd_stakes_deligation_decode(&self->stakes, data, dataend, allocf, allocf_arg);
  fd_unused_accounts_decode(&self->unused_accounts, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->epoch_stakes_len, data, dataend);
  if (self->epoch_stakes_len > 0) {
    self->epoch_stakes = (struct Epoch_fd_epoch_stakes_Pair*)(*allocf)(EPOCH_FD_EPOCH_STAKES_PAIR_FOOTPRINT*self->epoch_stakes_len, EPOCH_FD_EPOCH_STAKES_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      Epoch_fd_epoch_stakes_Pair_decode(self->epoch_stakes + i, data, dataend, allocf, allocf_arg);
  } else
    self->epoch_stakes = NULL;
  fd_bincode_uint8_decode((unsigned char *) &self->is_delta, data, dataend);
}

struct fd_serializable_account_storage_entry {
  ulong id;
  ulong accounts_current_len;
};
typedef struct fd_serializable_account_storage_entry fd_serializable_account_storage_entry_t;
#define FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_FOOTPRINT sizeof(struct fd_serializable_account_storage_entry)
#define FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_ALIGN (8UL)

void fd_serializable_account_storage_entry_decode(struct fd_serializable_account_storage_entry* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->id, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_current_len, data, dataend);
}
  
struct fd_bank_hash_stats {
  ulong num_updated_accounts;
  ulong num_removed_accounts;
  ulong num_lamports_stored;
  ulong total_data_len;
  ulong num_executable_accounts;
};
typedef struct fd_bank_hash_stats fd_bank_hash_stats_t;
#define FD_BANK_HASH_STATS_FOOTPRINT sizeof(struct fd_bank_hash_stats)
#define FD_BANK_HASH_STATS_ALIGN (8UL)

void fd_bank_hash_stats_decode(struct fd_bank_hash_stats* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->num_updated_accounts, data, dataend);
  fd_bincode_uint64_decode(&self->num_removed_accounts, data, dataend);
  fd_bincode_uint64_decode(&self->num_lamports_stored, data, dataend);
  fd_bincode_uint64_decode(&self->total_data_len, data, dataend);
  fd_bincode_uint64_decode(&self->num_executable_accounts, data, dataend);
}
  
struct fd_bank_hash_info {
  struct fd_hash hash;
  struct fd_hash snapshot_hash;
  struct fd_bank_hash_stats stats;
};
typedef struct fd_bank_hash_info fd_bank_hash_info_t;
#define FD_BANK_HASH_INFO_FOOTPRINT sizeof(struct fd_bank_hash_info)
#define FD_BANK_HASH_INFO_ALIGN (8UL)

void fd_bank_hash_info_decode(struct fd_bank_hash_info* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
  fd_hash_decode(&self->snapshot_hash, data, dataend, allocf, allocf_arg);
  fd_bank_hash_stats_decode(&self->stats, data, dataend, allocf, allocf_arg);
}

struct fd_slot_account_pair {
  ulong slot;
  ulong accounts_len;
  struct fd_serializable_account_storage_entry *accounts;
};
typedef struct fd_slot_account_pair fd_slot_account_pair_t;
#define FD_SLOT_ACCOUNT_PAIR_FOOTPRINT sizeof(struct fd_slot_account_pair)
#define FD_SLOT_ACCOUNT_PAIR_ALIGN (8UL)

void fd_slot_account_pair_decode(struct fd_slot_account_pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_len, data, dataend);
  if (self->accounts_len > 0) {
    self->accounts = (struct fd_serializable_account_storage_entry*)(*allocf)(FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_FOOTPRINT*self->accounts_len, FD_SERIALIZABLE_ACCOUNT_STORAGE_ENTRY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_serializable_account_storage_entry_decode(self->accounts + i, data, dataend, allocf, allocf_arg);
  } else
    self->accounts = NULL;
}

struct fd_slot_map_pair {
  ulong slot;
  struct fd_hash hash;
};
typedef struct fd_slot_map_pair fd_slot_map_pair_t;
#define FD_SLOT_MAP_PAIR_FOOTPRINT sizeof(struct fd_slot_map_pair)
#define FD_SLOT_MAP_PAIR_ALIGN (8UL)

void fd_slot_map_pair_decode(struct fd_slot_map_pair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
}
  
struct fd_accounts_db_fields {
  ulong            storages_len;
  struct fd_slot_account_pair * storages;
  ulong            version;
  ulong            slot;
  struct fd_bank_hash_info      bank_hash_info;
  ulong            historical_roots_len;
  ulong *          historical_roots;
  ulong            historical_roots_with_hash_len;
  struct fd_slot_map_pair *     historical_roots_with_hash;
};
typedef struct fd_accounts_db_fields fd_accounts_db_fields_t;
#define FD_ACCOUNTS_DB_FIELDS_FOOTPRINT sizeof(struct fd_accounts_db_fields)
#define FD_ACCOUNTS_DB_FIELDS_ALIGN (8UL)

void fd_accounts_db_fields_decode(struct fd_accounts_db_fields* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->storages_len, data, dataend);
  if (self->storages_len > 0) {
    self->storages = (struct fd_slot_account_pair*)(*allocf)(FD_SLOT_ACCOUNT_PAIR_FOOTPRINT*self->storages_len, FD_SLOT_ACCOUNT_PAIR_ALIGN, allocf_arg);
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
    self->historical_roots_with_hash = (struct fd_slot_map_pair*)(*allocf)(FD_SLOT_MAP_PAIR_FOOTPRINT*self->historical_roots_with_hash_len, FD_SLOT_MAP_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_decode(self->historical_roots_with_hash + i, data, dataend, allocf, allocf_arg);
  } else
    self->historical_roots_with_hash = NULL;
}
