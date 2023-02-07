typedef char* (*alloc_fun)(unsigned long len, unsigned long align, void* arg);

void fd_bincode_uint128_decode(uint128* self, const void** data, const void* dataend) {
  const uint128 *ptr = (const uint128 *) *data;
  if (FD_UNLIKELY((const void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint64_decode(unsigned long* self, const void** data, const void* dataend) {
  const unsigned long *ptr = (const unsigned long *) *data;
  if (FD_UNLIKELY((const void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_double_decode(double* self, const void** data, const void* dataend) {
  const double *ptr = (const double *) *data;
  if (FD_UNLIKELY((const void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint32_decode(unsigned int* self, const void** data, const void* dataend) {
  const unsigned int *ptr = (const unsigned int *) *data;
  if (FD_UNLIKELY((const void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_uint8_decode(unsigned char* self, const void** data, const void* dataend) {
  const unsigned char *ptr = (const unsigned char *) *data;
  if (FD_UNLIKELY((const void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

void fd_bincode_bytes_decode(unsigned char* self, unsigned long len, const void** data, const void* dataend) {
  unsigned char *ptr = (unsigned char *) *data;
  if (FD_UNLIKELY((void *) (ptr + len) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  memcpy(self, ptr, len); // what is the FD way?
  *data = ptr + len;
}

unsigned char fd_bincode_option_decode(const void** data, const void* dataend) {
  unsigned char *ptr = (unsigned char *) *data;
  if (FD_UNLIKELY((void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  unsigned char ret = *ptr;
  *data = ptr + 1;
  return ret;
}

// sdk/program/src/fee_calculator.rs:11
struct FeeCalculator {
  unsigned long lamports_per_signature;
};
#define FeeCalculator_footprint sizeof(struct FeeCalculator)
#define FeeCalculator_align 8

void FeeCalculator_decode(struct FeeCalculator* self, const void** data, const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_signature, data, dataend);
}

// runtime/src/blockhash_queue.rs:12
struct HashAge {
  struct FeeCalculator fee_calculator;
  unsigned long hash_index;
  unsigned long timestamp;
};
#define HashAge_footprint sizeof(struct HashAge)
#define HashAge_align 8

void HashAge_decode(struct HashAge* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  FeeCalculator_decode(&self->fee_calculator, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->hash_index, data, dataend);
  fd_bincode_uint64_decode(&self->timestamp, data, dataend);
}

// sdk/program/src/hash.rs:47
struct Hash {
  unsigned char hash[32];
};
#define Hash_footprint sizeof(struct Hash)
#define Hash_align 8

void Hash_decode(struct Hash* self, const void** data, const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->hash[0], sizeof(self->hash), data, dataend);
}

struct Hash_HashAge_Pair {
  struct Hash key;
  struct HashAge val;
};
#define Hash_HashAge_Pair_footprint sizeof(struct Hash_HashAge_Pair)
#define Hash_HashAge_Pair_align 8

void Hash_HashAge_Pair_decode(struct Hash_HashAge_Pair* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(self->key.hash, sizeof(self->key.hash), data, dataend);
  HashAge_decode(&self->val, data, dataend, allocf, allocf_arg);
}

// runtime/src/blockhash_queue.rs:21
struct BlockhashQueue {
  unsigned long last_hash_index;
  struct Hash* last_hash;

  unsigned long ages_len;
  struct Hash_HashAge_Pair* ages;

  unsigned long max_age;
};
#define BlockhashQueue_footprint sizeof(struct BlockhashQueue)
#define BlockhashQueue_align 8

void BlockhashQueue_decode(struct BlockhashQueue* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->last_hash_index, data, dataend);

  if (fd_bincode_option_decode(data, dataend)) {
    self->last_hash = (struct Hash*)(*allocf)(Hash_footprint, Hash_align, allocf_arg);
    Hash_decode(self->last_hash, data, dataend, allocf, allocf_arg);
  } else {
    self->last_hash = NULL;
  }

  fd_bincode_uint64_decode(&self->ages_len, data, dataend);
  if (self->ages_len > 0) {
    self->ages = (struct Hash_HashAge_Pair*)(*allocf)(Hash_HashAge_Pair_footprint*self->ages_len, Hash_HashAge_Pair_align, allocf_arg);
    for (unsigned long i = 0; i < self->ages_len; ++i)
      Hash_HashAge_Pair_decode(self->ages + i, data, dataend, allocf, allocf_arg);
  } else
    self->ages = NULL;

  fd_bincode_uint64_decode(&self->max_age, data, dataend);
}

// sdk/program/src/pubkey.rs:87
struct Pubkey {
  unsigned char key[32];
};
#define Pubkey_footprint sizeof(struct Pubkey)
#define Pubkey_align 8

void Pubkey_decode(struct Pubkey* self, const void** data, const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->key[0], sizeof(self->key), data, dataend);
}

// sdk/program/src/epoch_schedule.rs:34
struct EpochSchedule {
  unsigned long slots_per_epoch;
  unsigned long leader_schedule_slot_offset;
  unsigned char warmup;
  unsigned long first_normal_epoch;
  unsigned long first_normal_slot;
};
#define EpochSchedule_footprint sizeof(struct EpochSchedule)
#define EpochSchedule_align 8

void EpochSchedule_decode(struct EpochSchedule* self,  const void** data,  const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slots_per_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->leader_schedule_slot_offset, data, dataend);
  fd_bincode_uint8_decode(&self->warmup, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_slot, data, dataend);
}

// sdk/program/src/fee_calculator.rs:52
struct FeeRateGovernor {
  unsigned long target_lamports_per_signature;
  unsigned long target_signatures_per_slot;
  unsigned long min_lamports_per_signature;
  unsigned long max_lamports_per_signature;
  unsigned char burn_percent;
};
#define FeeRateGovernor_footprint sizeof(struct FeeRateGovernor)
#define FeeRateGovernor_align 8

void FeeRateGovernor_decode(struct FeeRateGovernor* self, const void** data, const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->target_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->target_signatures_per_slot, data, dataend);
  fd_bincode_uint64_decode(&self->min_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->max_lamports_per_signature, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}

struct SlotPair {
  unsigned long slot;
  unsigned long val;
};
#define SlotPair_footprint sizeof(struct SlotPair)
#define SlotPair_align 8

void SlotPair_decode(struct SlotPair* self, const void** data, const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->val, data, dataend);
}

// sdk/src/hard_forks.rs:12
struct HardForks {
  unsigned long len;
  struct SlotPair* hard_forks;
};
#define HardForks_footprint sizeof(struct HardForks)
#define HardForks_align 8

void HardForks_decode(struct HardForks* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->len, data, dataend);
  if (self->len > 0) {
    self->hard_forks = (struct SlotPair*)(*allocf)(SlotPair_footprint*self->len, SlotPair_align, allocf_arg);
    for (unsigned long i = 0; i < self->len; ++i)
      SlotPair_decode(self->hard_forks + i, data, dataend, allocf, allocf_arg);
  } else
    self->hard_forks = NULL;
}

// sdk/src/inflation.rs:5
struct Inflation {
  double initial;
  double terminal;
  double taper;
  double foundation;
  double foundation_term;
  double __unused;
};
#define Inflation_footprint sizeof(struct Inflation)
#define Inflation_align 8

void Inflation_decode(struct Inflation* self, const void** data, const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_double_decode(&self->initial, data, dataend);
  fd_bincode_double_decode(&self->terminal, data, dataend);
  fd_bincode_double_decode(&self->taper, data, dataend);
  fd_bincode_double_decode(&self->foundation, data, dataend);
  fd_bincode_double_decode(&self->foundation_term, data, dataend);
  fd_bincode_double_decode(&self->__unused, data, dataend);
}

// sdk/program/src/rent.rs:12
struct Rent {
  unsigned long lamports_per_uint8_year;
  double exemption_threshold;
  unsigned char burn_percent;
};
#define Rent_footprint sizeof(struct Rent)
#define Rent_align 8

void Rent_decode(FD_FN_UNUSED struct Rent* self, FD_FN_UNUSED const void** data, FD_FN_UNUSED const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_uint8_year, data, dataend);
  fd_bincode_double_decode(&self->exemption_threshold, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}

// runtime/src/rent_collector.rs:13
struct RentCollector {
  unsigned long epoch;
  struct EpochSchedule epoch_schedule;
  double slots_per_year;
  struct Rent rent;
};
#define RentCollector_footprint sizeof(struct RentCollector)
#define RentCollector_align 8

void RentCollector_decode(struct RentCollector* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  EpochSchedule_decode(&self->epoch_schedule, data, dataend, allocf, allocf_arg);
  fd_bincode_double_decode(&self->slots_per_year, data, dataend);
  Rent_decode(&self->rent, data, dataend, allocf, allocf_arg);
}

// sdk/program/src/stake_history.rs:15
struct StakeHistoryEntry {
  unsigned long effective;
  unsigned long activating;
  unsigned long deactivating;
};
#define StakeHistoryEntry_footprint sizeof(struct StakeHistoryEntry)
#define StakeHistoryEntry_align 8

void StakeHistoryEntry_decode(FD_FN_UNUSED struct StakeHistoryEntry* self, FD_FN_UNUSED const void** data, FD_FN_UNUSED const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->effective, data, dataend);
  fd_bincode_uint64_decode(&self->activating, data, dataend);
  fd_bincode_uint64_decode(&self->deactivating, data, dataend);
}

struct StakeHistoryEpochEntryPair {
  unsigned long epoch;
  struct StakeHistoryEntry entry;
};
#define StakeHistoryEpochEntryPair_footprint sizeof(struct StakeHistoryEpochEntryPair)
#define StakeHistoryEpochEntryPair_align 8

void StakeHistoryEpochEntryPair_decode(FD_FN_UNUSED struct StakeHistoryEpochEntryPair* self, FD_FN_UNUSED const void** data, FD_FN_UNUSED const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  StakeHistoryEntry_decode(&self->entry, data, dataend, allocf, allocf_arg);
}

// sdk/program/src/stake_history.rs
struct StakeHistory {
  unsigned long len;
  struct StakeHistoryEpochEntryPair* entries;
};
#define StakeHistory_footprint sizeof(struct StakeHistory)
#define StakeHistory_align 8

void StakeHistory_decode(struct StakeHistory* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->len, data, dataend);
  if (self->len > 0) {
    self->entries = (struct StakeHistoryEpochEntryPair*)(*allocf)(StakeHistoryEpochEntryPair_footprint*self->len, StakeHistoryEpochEntryPair_align, allocf_arg);
    for (unsigned long i = 0; i < self->len; ++i)
      StakeHistoryEpochEntryPair_decode(self->entries + i, data, dataend, allocf, allocf_arg);
  } else
    self->entries = NULL;
}

// sdk/src/account.rs:27
struct Account {
  unsigned long lamports;

  unsigned long data_len;
  unsigned char* data;

  struct Pubkey owner;
  unsigned char executable;
  unsigned long rent_epoch;
};
#define Account_footprint sizeof(struct Account)
#define Account_align 8

void Account_decode(struct Account* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports, data, dataend);
  fd_bincode_uint64_decode(&self->data_len, data, dataend);
  if (self->data_len > 0) {
    self->data = (unsigned char*)(*allocf)(self->data_len, 8, allocf_arg);
    fd_bincode_bytes_decode(self->data, self->data_len, data, dataend);
  } else
    self->data = NULL;
  Pubkey_decode(&self->owner, data, dataend, allocf, allocf_arg);
  fd_bincode_uint8_decode(&self->executable, data, dataend);
  fd_bincode_uint64_decode(&self->rent_epoch, data, dataend);
}

struct VoteAccountsPair {
  struct Pubkey key;
  unsigned long stake;
  struct Account value;
};
#define VoteAccountsPair_footprint sizeof(struct VoteAccountsPair)
#define VoteAccountsPair_align 8

void VoteAccountsPair_decode(struct VoteAccountsPair* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake, data, dataend);
  Account_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/vote_account.rs:42
struct VoteAccounts { // tested and confirmed
  unsigned long vote_accounts_len;
  struct VoteAccountsPair *vote_accounts;
};
#define VoteAccounts_footprint sizeof(struct VoteAccounts)
#define VoteAccounts_align 8

void VoteAccounts_decode(FD_FN_UNUSED struct VoteAccounts* self, FD_FN_UNUSED const void** data, FD_FN_UNUSED const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len != 0) {
    self->vote_accounts = (struct VoteAccountsPair*)(*allocf)(VoteAccountsPair_footprint*self->vote_accounts_len, VoteAccountsPair_align, allocf_arg);
    for (unsigned long i = 0; i < self->vote_accounts_len; ++i)
      VoteAccountsPair_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->vote_accounts = NULL;
}

// sdk/program/src/stake/state.rs:301
struct Delegation {
  struct Pubkey voter_pubkey;
  unsigned long stake;
  unsigned long activation_epoch;
  unsigned long deactivation_epoch;
  double warmup_cooldown_rate;
};
#define Delegation_footprint sizeof(struct Delegation)
#define Delegation_align 8

void Delegation_decode(struct Delegation* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->voter_pubkey, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake, data, dataend);
  fd_bincode_uint64_decode(&self->activation_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->deactivation_epoch, data, dataend);
  fd_bincode_double_decode(&self->warmup_cooldown_rate, data, dataend);
}

struct DelegationPair {
  struct Pubkey key;
  struct Delegation value;
};
#define DelegationPair_footprint sizeof(struct DelegationPair)
#define DelegationPair_align 8

void DelegationPair_decode(struct DelegationPair* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  Delegation_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/stakes.rs:169
// runtime/src/bank.rs:747
struct StakesDeligation {
  struct VoteAccounts vote_accounts;
  // stake_delegations: ImHashMap<Pubkey, Delegation>,
  unsigned long stake_delegations_len;
  struct DelegationPair* stake_delegations;
  unsigned long unused;
  unsigned long epoch;
  struct StakeHistory stake_history;
};
#define StakesDeligation_footprint sizeof(struct StakesDeligation)
#define StakesDeligation_align 8

void StakesDeligation_decode(struct StakesDeligation* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  VoteAccounts_decode(&self->vote_accounts, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake_delegations_len, data, dataend);
  if (self->stake_delegations_len) {
    self->stake_delegations = (struct DelegationPair*)(*allocf)(DelegationPair_footprint*self->stake_delegations_len, DelegationPair_align, allocf_arg);
    for (unsigned long i = 0; i < self->stake_delegations_len; ++i)
      DelegationPair_decode(self->stake_delegations + i, data, dataend, allocf, allocf_arg);
  } else 
    self->stake_delegations = NULL;
  fd_bincode_uint64_decode(&self->unused, data, dataend);
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  StakeHistory_decode(&self->stake_history, data, dataend, allocf, allocf_arg);
}

// runtime/src/bank.rs:238
struct BankIncrementalSnapshotPersistence {
  unsigned long full_slot;
  struct Hash full_hash;
  unsigned long full_capitalization;
  struct Hash incremental_hash;
  unsigned long incremental_capitalization;
};
#define BankIncrementalSnapshotPersistence_footprint sizeof(struct BankIncrementalSnapshotPersistence)
#define BankIncrementalSnapshotPersistence_align 8

struct NodeVoteAccounts {
  unsigned long vote_accounts_len;
  struct Pubkey *vote_accounts;
  unsigned long total_stake;
};
#define NodeVoteAccounts_footprint sizeof(struct NodeVoteAccounts)
#define NodeVoteAccounts_align 8

void NodeVoteAccounts_decode(FD_FN_UNUSED struct NodeVoteAccounts* self, FD_FN_UNUSED const void** data, FD_FN_UNUSED const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len) {
    self->vote_accounts = (struct Pubkey*)(*allocf)(Pubkey_footprint*self->vote_accounts_len, Pubkey_align, allocf_arg);
    for (unsigned long i = 0; i < self->vote_accounts_len; ++i)
      Pubkey_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
}

struct PubkeyNodeVoteAccountsPair {
  struct Pubkey key;
  struct NodeVoteAccounts value;
};
#define PubkeyNodeVoteAccountsPair_footprint sizeof(struct PubkeyNodeVoteAccountsPair)
#define PubkeyNodeVoteAccountsPair_align 8

void PubkeyNodeVoteAccountsPair_decode(FD_FN_UNUSED struct PubkeyNodeVoteAccountsPair* self, FD_FN_UNUSED const void** data, FD_FN_UNUSED const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  NodeVoteAccounts_decode(&self->value, data, dataend, allocf, allocf_arg);
}

struct PubkeyPubkeyPair {
  struct Pubkey key;
  struct Pubkey value;
};
#define PubkeyPubkeyPair_footprint sizeof(struct PubkeyPubkeyPair)
#define PubkeyPubkeyPair_align 8

void PubkeyPubkeyPair_decode(FD_FN_UNUSED struct PubkeyPubkeyPair* self, FD_FN_UNUSED const void** data, FD_FN_UNUSED const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  Pubkey_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/epoch_stakes.rs:18
struct EpochStakes {
  struct StakesDeligation stakes;
  unsigned long total_stake;
  unsigned long node_id_to_vote_accounts_len;
  struct PubkeyNodeVoteAccountsPair *node_id_to_vote_accounts;
  unsigned long epoch_authorized_voters_len;
  struct PubkeyPubkeyPair *epoch_authorized_voters;
};
#define EpochStakes_footprint sizeof(struct EpochStakes)
#define EpochStakes_align 8

void EpochStakes_decode(FD_FN_UNUSED struct EpochStakes* self, FD_FN_UNUSED const void** data, FD_FN_UNUSED const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  StakesDeligation_decode(&self->stakes, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
  fd_bincode_uint64_decode(&self->node_id_to_vote_accounts_len, data, dataend);
  if (self->node_id_to_vote_accounts_len > 0) {
    self->node_id_to_vote_accounts = (struct PubkeyNodeVoteAccountsPair*)(*allocf)(PubkeyNodeVoteAccountsPair_footprint*self->node_id_to_vote_accounts_len, PubkeyNodeVoteAccountsPair_align, allocf_arg);
    for (unsigned long i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      PubkeyNodeVoteAccountsPair_decode(self->node_id_to_vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->node_id_to_vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->epoch_authorized_voters_len, data, dataend);
  if (self->epoch_authorized_voters_len > 0) {
    self->epoch_authorized_voters = (struct PubkeyPubkeyPair*)(*allocf)(PubkeyPubkeyPair_footprint*self->epoch_authorized_voters_len, PubkeyPubkeyPair_align, allocf_arg);
    for (unsigned long i = 0; i < self->epoch_authorized_voters_len; ++i)
      PubkeyPubkeyPair_decode(self->epoch_authorized_voters + i, data, dataend, allocf, allocf_arg);
  } else 
    self->epoch_authorized_voters = NULL;
}

struct Epoch_EpochStakes_Pair {
  unsigned long key;
  struct EpochStakes value;
};
#define Epoch_EpochStakes_Pair_footprint sizeof(struct Epoch_EpochStakes_Pair)
#define Epoch_EpochStakes_Pair_align 8

void Epoch_EpochStakes_Pair_decode(struct Epoch_EpochStakes_Pair* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->key, data, dataend);
  EpochStakes_decode(&self->value, data, dataend, allocf, allocf_arg);
}

struct Pubkey_u64_Pair {
  struct Pubkey _0;
  unsigned long _1;
};
#define Pubkey_u64_Pair_footprint sizeof(struct Pubkey_u64_Pair)
#define Pubkey_u64_Pair_align 8

void Pubkey_u64_Pair_decode(struct Pubkey_u64_Pair* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->_0, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->_1, data, dataend);
}

// runtime/src/serde_snapshot/newer.rs:20
struct UnusedAccounts {
  // HashSet<Pubkey>
  unsigned long unused1_len;
  struct Pubkey* unused1;

  // HashSet<Pubkey>
  unsigned long unused2_len;
  struct Pubkey* unused2;

  // HashMap<Pubkey, u64>
  unsigned long unused3_len;
  struct Pubkey_u64_Pair* unused3;
};
#define UnusedAccounts_footprint sizeof(struct UnusedAccounts)
#define UnusedAccounts_align 8

void UnusedAccounts_decode(struct UnusedAccounts* self, const void** data, const void* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->unused1_len, data, dataend);
  if (self->unused1_len > 0) {
    self->unused1 = (struct Pubkey*)(*allocf)(Pubkey_footprint*self->unused1_len, Pubkey_align, allocf_arg);
    for (unsigned long i = 0; i < self->unused1_len; ++i)
      Pubkey_decode(self->unused1 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused1 = NULL;

  fd_bincode_uint64_decode(&self->unused2_len, data, dataend);
  if (self->unused2_len > 0) {
    self->unused2 = (struct Pubkey*)(*allocf)(Pubkey_footprint*self->unused2_len, Pubkey_align, allocf_arg);
    for (unsigned long i = 0; i < self->unused2_len; ++i)
      Pubkey_decode(self->unused2 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused2 = NULL;

  fd_bincode_uint64_decode(&self->unused3_len, data, dataend);
  if (self->unused3_len > 0) {
    self->unused3 = (struct Pubkey_u64_Pair*)(*allocf)(Pubkey_u64_Pair_footprint*self->unused3_len, Pubkey_u64_Pair_align, allocf_arg);
    for (unsigned long i = 0; i < self->unused3_len; ++i)
      Pubkey_u64_Pair_decode(self->unused3 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused3 = NULL;
}

// runtime/src/serde_snapshot/newer.rs:30
struct DeserializableVersionedBank {
  struct BlockhashQueue blockhash_queue;

  // runtime/src/ancestors.rs:pub type AncestorsForSerialization = HashMap<Slot, usize>;
  unsigned long ancestors_len;
  struct SlotPair *ancestors;

  struct Hash hash;
  struct Hash parent_hash;
  unsigned long parent_slot;
  struct HardForks hard_forks;
  unsigned long transaction_count;
  unsigned long tick_height;
  unsigned long signature_count;
  unsigned long capitalization;
  unsigned long max_tick_height;
  unsigned long *hashes_per_tick;
  unsigned long ticks_per_slot;
  uint128 ns_per_slot;
  long genesis_creation_time;
  double slots_per_year;
  unsigned long accounts_data_len;
  unsigned long slot;
  unsigned long epoch;
  unsigned long block_height;
  struct Pubkey collector_id;
  unsigned long collector_fees;
  struct FeeCalculator fee_calculator;
  struct FeeRateGovernor fee_rate_governor;
  unsigned long collected_rent;
  struct RentCollector rent_collector;
  struct EpochSchedule epoch_schedule;
  struct Inflation inflation;
  struct StakesDeligation stakes;
  struct UnusedAccounts unused_accounts;
    
  unsigned long epoch_stakes_len;
  struct Epoch_EpochStakes_Pair *epoch_stakes;

  char is_delta;
};
#define DeserializableVersionedBank_footprint sizeof(struct DeserializableVersionedBank)
#define DeserializableVersionedBank_align 8

void DeserializableVersionedBank_decode(struct DeserializableVersionedBank* self, const void** data, const void* dataend, alloc_fun allocf, void* allocf_arg) {
  BlockhashQueue_decode(&self->blockhash_queue, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->ancestors_len, data, dataend);
  self->ancestors = (struct SlotPair*)(*allocf)(SlotPair_footprint*self->ancestors_len, SlotPair_align, allocf_arg);
  for (unsigned long i = 0; i < self->ancestors_len; ++i)
    SlotPair_decode(self->ancestors + i, data, dataend, allocf, allocf_arg);
  Hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
  Hash_decode(&self->parent_hash, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->parent_slot, data, dataend);
  HardForks_decode(&self->hard_forks, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->transaction_count, data, dataend);
  fd_bincode_uint64_decode(&self->tick_height, data, dataend);
  fd_bincode_uint64_decode(&self->signature_count, data, dataend);
  fd_bincode_uint64_decode(&self->capitalization, data, dataend);
  fd_bincode_uint64_decode(&self->max_tick_height, data, dataend);
  if (fd_bincode_option_decode(data, dataend)) {
    self->hashes_per_tick = (unsigned long*)(*allocf)(sizeof(unsigned long), 8, allocf_arg);
    fd_bincode_uint64_decode(self->hashes_per_tick, data, dataend);
  } else
    self->hashes_per_tick = NULL;
  fd_bincode_uint64_decode(&self->ticks_per_slot, data, dataend);
  fd_bincode_uint128_decode(&self->ns_per_slot, data, dataend);
  fd_bincode_uint64_decode((unsigned long *) &self->genesis_creation_time, data, dataend);
  fd_bincode_double_decode(&self->slots_per_year, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_data_len, data, dataend);
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  fd_bincode_uint64_decode(&self->block_height, data, dataend);
  Pubkey_decode(&self->collector_id, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->collector_fees, data, dataend);
  FeeCalculator_decode(&self->fee_calculator, data, dataend, allocf, allocf_arg);
  FeeRateGovernor_decode(&self->fee_rate_governor, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->collected_rent, data, dataend);
  RentCollector_decode(&self->rent_collector, data, dataend, allocf, allocf_arg);
  EpochSchedule_decode(&self->epoch_schedule, data, dataend, allocf, allocf_arg);
  Inflation_decode(&self->inflation, data, dataend, allocf, allocf_arg);
  StakesDeligation_decode(&self->stakes, data, dataend, allocf, allocf_arg);
  UnusedAccounts_decode(&self->unused_accounts, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->epoch_stakes_len, data, dataend);
  if (self->epoch_stakes_len > 0) {
    self->epoch_stakes = (struct Epoch_EpochStakes_Pair*)(*allocf)(Epoch_EpochStakes_Pair_footprint*self->epoch_stakes_len, Epoch_EpochStakes_Pair_align, allocf_arg);
    for (unsigned long i = 0; i < self->epoch_stakes_len; ++i)
      Epoch_EpochStakes_Pair_decode(self->epoch_stakes + i, data, dataend, allocf, allocf_arg);
  } else
    self->epoch_stakes = NULL;
  fd_bincode_uint8_decode((unsigned char *) &self->is_delta, data, dataend);
}

struct SerializableAccountStorageEntry {
  unsigned long id;
  unsigned long accounts_current_len;
};
#define SerializableAccountStorageEntry_footprint sizeof(struct SerializableAccountStorageEntry)
#define SerializableAccountStorageEntry_align 8

void SerializableAccountStorageEntry_decode(struct SerializableAccountStorageEntry* self, const void** data, const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->id, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_current_len, data, dataend);
}
  
struct BankHashStats {
  unsigned long num_updated_accounts;
  unsigned long num_removed_accounts;
  unsigned long num_lamports_stored;
  unsigned long total_data_len;
  unsigned long num_executable_accounts;
};
#define BankHashStats_footprint sizeof(struct BankHashStats)
#define BankHashStats_align 8

void BankHashStats_decode(struct BankHashStats* self, const void** data, const void* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->num_updated_accounts, data, dataend);
  fd_bincode_uint64_decode(&self->num_removed_accounts, data, dataend);
  fd_bincode_uint64_decode(&self->num_lamports_stored, data, dataend);
  fd_bincode_uint64_decode(&self->total_data_len, data, dataend);
  fd_bincode_uint64_decode(&self->num_executable_accounts, data, dataend);
}
  
struct BankHashInfo {
  struct Hash hash;
  struct Hash snapshot_hash;
  struct BankHashStats stats;
};
#define BankHashInfo_footprint sizeof(struct BankHashInfo)
#define BankHashInfo_align 8

void BankHashInfo_decode(struct BankHashInfo* self, const void** data, const void* dataend, alloc_fun allocf, void* allocf_arg) {
  Hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
  Hash_decode(&self->snapshot_hash, data, dataend, allocf, allocf_arg);
  BankHashStats_decode(&self->stats, data, dataend, allocf, allocf_arg);
}

struct SlotAccountPair {
  unsigned long slot;
  unsigned long accounts_len;
  struct SerializableAccountStorageEntry *accounts;
};
#define SlotAccountPair_footprint sizeof(struct SlotAccountPair)
#define SlotAccountPair_align 8

void SlotAccountPair_decode(struct SlotAccountPair* self, const void** data, const void* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_len, data, dataend);
  if (self->accounts_len > 0) {
    self->accounts = (struct SerializableAccountStorageEntry*)(*allocf)(SerializableAccountStorageEntry_footprint*self->accounts_len, SerializableAccountStorageEntry_align, allocf_arg);
    for (unsigned long i = 0; i < self->accounts_len; ++i)
      SerializableAccountStorageEntry_decode(self->accounts + i, data, dataend, allocf, allocf_arg);
  } else
    self->accounts = NULL;
}

struct SlotMapPair {
  unsigned long slot;
  struct Hash hash;
};
#define SlotMapPair_footprint sizeof(struct SlotMapPair)
#define SlotMapPair_align 8

void SlotMapPair_decode(struct SlotMapPair* self, const void** data, const void* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  Hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
}
  
struct AccountsDbFields {
  unsigned long            storages_len;
  struct SlotAccountPair * storages;
  unsigned long            version;
  unsigned long            slot;
  struct BankHashInfo      bank_hash_info;
  unsigned long            historical_roots_len;
  unsigned long *          historical_roots;
  unsigned long            historical_roots_with_hash_len;
  struct SlotMapPair *     historical_roots_with_hash;
};
#define AccountsDbFields_footprint sizeof(struct AccountsDbFields)
#define AccountsDbFields_align 8

void AccountsDbFields_decode(struct AccountsDbFields* self, const void** data, const void* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->storages_len, data, dataend);
  if (self->storages_len > 0) {
    self->storages = (struct SlotAccountPair*)(*allocf)(SlotAccountPair_footprint*self->storages_len, SlotAccountPair_align, allocf_arg);
    for (unsigned long i = 0; i < self->storages_len; ++i)
      SlotAccountPair_decode(self->storages + i, data, dataend, allocf, allocf_arg);
  } else
    self->storages = NULL;

  fd_bincode_uint64_decode(&self->version, data, dataend);
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  BankHashInfo_decode(&self->bank_hash_info, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->historical_roots_len, data, dataend);
  if (self->historical_roots_len > 0) {
    self->historical_roots = (unsigned long*)(*allocf)(sizeof(unsigned long)*self->historical_roots_len, 8, allocf_arg);
    for (unsigned long i = 0; i < self->historical_roots_len; ++i)
      fd_bincode_uint64_decode(self->historical_roots + i, data, dataend);
  } else
    self->historical_roots = NULL;
  fd_bincode_uint64_decode(&self->historical_roots_with_hash_len, data, dataend);
  if (self->historical_roots_with_hash_len > 0) {
    self->historical_roots_with_hash = (struct SlotMapPair*)(*allocf)(SlotMapPair_footprint*self->historical_roots_with_hash_len, SlotMapPair_align, allocf_arg);
    for (unsigned long i = 0; i < self->historical_roots_with_hash_len; ++i)
      SlotMapPair_decode(self->historical_roots_with_hash + i, data, dataend, allocf, allocf_arg);
  } else
    self->historical_roots_with_hash = NULL;
}
