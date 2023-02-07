//typedef all the structs with _t .. with the typedef's on their own lines
//use the _t typedefs... 
//#define macros are all caps
//put UL for the consts in the macros

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
struct FeeCalculator {
  ulong lamports_per_signature;
};
#define FEECALCULATOR_FOOTPRINT sizeof(struct FeeCalculator)
#define FEECALCULATOR_ALIGN 8

void FeeCalculator_decode(struct FeeCalculator* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_signature, data, dataend);
}

// runtime/src/blockhash_queue.rs:12
struct HashAge {
  struct FeeCalculator fee_calculator;
  ulong hash_index;
  ulong timestamp;
};
#define HASHAGE_FOOTPRINT sizeof(struct HashAge)
#define HASHAGE_ALIGN 8

void HashAge_decode(struct HashAge* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  FeeCalculator_decode(&self->fee_calculator, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->hash_index, data, dataend);
  fd_bincode_uint64_decode(&self->timestamp, data, dataend);
}

// sdk/program/src/hash.rs:47
struct Hash {
  unsigned char hash[32];
};
#define HASH_FOOTPRINT sizeof(struct Hash)
#define HASH_ALIGN 8

void Hash_decode(struct Hash* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->hash[0], sizeof(self->hash), data, dataend);
}

struct Hash_HashAge_Pair {
  struct Hash key;
  struct HashAge val;
};
#define HASH_HASHAGE_PAIR_FOOTPRINT sizeof(struct Hash_HashAge_Pair)
#define HASH_HASHAGE_PAIR_ALIGN 8

void Hash_HashAge_Pair_decode(struct Hash_HashAge_Pair* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(self->key.hash, sizeof(self->key.hash), data, dataend);
  HashAge_decode(&self->val, data, dataend, allocf, allocf_arg);
}

// runtime/src/blockhash_queue.rs:21
struct BlockhashQueue {
  ulong last_hash_index;
  struct Hash* last_hash;

  ulong ages_len;
  struct Hash_HashAge_Pair* ages;

  ulong max_age;
};
#define BLOCKHASHQUEUE_FOOTPRINT sizeof(struct BlockhashQueue)
#define BLOCKHASHQUEUE_ALIGN 8

void BlockhashQueue_decode(struct BlockhashQueue* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->last_hash_index, data, dataend);

  if (fd_bincode_option_decode(data, dataend)) {
    self->last_hash = (struct Hash*)(*allocf)(HASH_FOOTPRINT, HASH_ALIGN, allocf_arg);
    Hash_decode(self->last_hash, data, dataend, allocf, allocf_arg);
  } else {
    self->last_hash = NULL;
  }

  fd_bincode_uint64_decode(&self->ages_len, data, dataend);
  if (self->ages_len > 0) {
    self->ages = (struct Hash_HashAge_Pair*)(*allocf)(HASH_HASHAGE_PAIR_FOOTPRINT*self->ages_len, HASH_HASHAGE_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->ages_len; ++i)
      Hash_HashAge_Pair_decode(self->ages + i, data, dataend, allocf, allocf_arg);
  } else
    self->ages = NULL;

  fd_bincode_uint64_decode(&self->max_age, data, dataend);
}

// sdk/program/src/pubkey.rs:87
struct Pubkey {
  unsigned char key[32];
};
#define PUBKEY_FOOTPRINT sizeof(struct Pubkey)
#define PUBKEY_ALIGN 8

void Pubkey_decode(struct Pubkey* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_bytes_decode(&self->key[0], sizeof(self->key), data, dataend);
}

// sdk/program/src/epoch_schedule.rs:34
struct EpochSchedule {
  ulong slots_per_epoch;
  ulong leader_schedule_slot_offset;
  unsigned char warmup;
  ulong first_normal_epoch;
  ulong first_normal_slot;
};
#define EPOCHSCHEDULE_FOOTPRINT sizeof(struct EpochSchedule)
#define EPOCHSCHEDULE_ALIGN 8

void EpochSchedule_decode(struct EpochSchedule* self,  void const** data,  void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slots_per_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->leader_schedule_slot_offset, data, dataend);
  fd_bincode_uint8_decode(&self->warmup, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_epoch, data, dataend);
  fd_bincode_uint64_decode(&self->first_normal_slot, data, dataend);
}

// sdk/program/src/fee_calculator.rs:52
struct FeeRateGovernor {
  ulong target_lamports_per_signature;
  ulong target_signatures_per_slot;
  ulong min_lamports_per_signature;
  ulong max_lamports_per_signature;
  unsigned char burn_percent;
};
#define FEERATEGOVERNOR_FOOTPRINT sizeof(struct FeeRateGovernor)
#define FEERATEGOVERNOR_ALIGN 8

void FeeRateGovernor_decode(struct FeeRateGovernor* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->target_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->target_signatures_per_slot, data, dataend);
  fd_bincode_uint64_decode(&self->min_lamports_per_signature, data, dataend);
  fd_bincode_uint64_decode(&self->max_lamports_per_signature, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}

struct SlotPair {
  ulong slot;
  ulong val;
};
#define SLOTPAIR_FOOTPRINT sizeof(struct SlotPair)
#define SLOTPAIR_ALIGN 8

void SlotPair_decode(struct SlotPair* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->val, data, dataend);
}

// sdk/src/hard_forks.rs:12
struct HardForks {
  ulong len;
  struct SlotPair* hard_forks;
};
#define HARDFORKS_FOOTPRINT sizeof(struct HardForks)
#define HARDFORKS_ALIGN 8

void HardForks_decode(struct HardForks* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->len, data, dataend);
  if (self->len > 0) {
    self->hard_forks = (struct SlotPair*)(*allocf)(SLOTPAIR_FOOTPRINT*self->len, SLOTPAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->len; ++i)
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
#define INFLATION_FOOTPRINT sizeof(struct Inflation)
#define INFLATION_ALIGN 8

void Inflation_decode(struct Inflation* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_double_decode(&self->initial, data, dataend);
  fd_bincode_double_decode(&self->terminal, data, dataend);
  fd_bincode_double_decode(&self->taper, data, dataend);
  fd_bincode_double_decode(&self->foundation, data, dataend);
  fd_bincode_double_decode(&self->foundation_term, data, dataend);
  fd_bincode_double_decode(&self->__unused, data, dataend);
}

// sdk/program/src/rent.rs:12
struct Rent {
  ulong lamports_per_uint8_year;
  double exemption_threshold;
  unsigned char burn_percent;
};
#define RENT_FOOTPRINT sizeof(struct Rent)
#define RENT_ALIGN 8

void Rent_decode(FD_FN_UNUSED struct Rent* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->lamports_per_uint8_year, data, dataend);
  fd_bincode_double_decode(&self->exemption_threshold, data, dataend);
  fd_bincode_uint8_decode(&self->burn_percent, data, dataend);
}

// runtime/src/rent_collector.rs:13
struct RentCollector {
  ulong epoch;
  struct EpochSchedule epoch_schedule;
  double slots_per_year;
  struct Rent rent;
};
#define RENTCOLLECTOR_FOOTPRINT sizeof(struct RentCollector)
#define RENTCOLLECTOR_ALIGN 8

void RentCollector_decode(struct RentCollector* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  EpochSchedule_decode(&self->epoch_schedule, data, dataend, allocf, allocf_arg);
  fd_bincode_double_decode(&self->slots_per_year, data, dataend);
  Rent_decode(&self->rent, data, dataend, allocf, allocf_arg);
}

// sdk/program/src/stake_history.rs:15
struct StakeHistoryEntry {
  ulong effective;
  ulong activating;
  ulong deactivating;
};
#define STAKEHISTORYENTRY_FOOTPRINT sizeof(struct StakeHistoryEntry)
#define STAKEHISTORYENTRY_ALIGN 8

void StakeHistoryEntry_decode(FD_FN_UNUSED struct StakeHistoryEntry* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->effective, data, dataend);
  fd_bincode_uint64_decode(&self->activating, data, dataend);
  fd_bincode_uint64_decode(&self->deactivating, data, dataend);
}

struct StakeHistoryEpochEntryPair {
  ulong epoch;
  struct StakeHistoryEntry entry;
};
#define STAKEHISTORYEPOCHENTRYPAIR_FOOTPRINT sizeof(struct StakeHistoryEpochEntryPair)
#define STAKEHISTORYEPOCHENTRYPAIR_ALIGN 8

void StakeHistoryEpochEntryPair_decode(FD_FN_UNUSED struct StakeHistoryEpochEntryPair* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  StakeHistoryEntry_decode(&self->entry, data, dataend, allocf, allocf_arg);
}

// sdk/program/src/stake_history.rs
struct StakeHistory {
  ulong len;
  struct StakeHistoryEpochEntryPair* entries;
};
#define STAKEHISTORY_FOOTPRINT sizeof(struct StakeHistory)
#define STAKEHISTORY_ALIGN 8

void StakeHistory_decode(struct StakeHistory* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->len, data, dataend);
  if (self->len > 0) {
    self->entries = (struct StakeHistoryEpochEntryPair*)(*allocf)(STAKEHISTORYEPOCHENTRYPAIR_FOOTPRINT*self->len, STAKEHISTORYEPOCHENTRYPAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->len; ++i)
      StakeHistoryEpochEntryPair_decode(self->entries + i, data, dataend, allocf, allocf_arg);
  } else
    self->entries = NULL;
}

// sdk/src/account.rs:27
struct Account {
  ulong lamports;

  ulong data_len;
  unsigned char* data;

  struct Pubkey owner;
  unsigned char executable;
  ulong rent_epoch;
};
#define ACCOUNT_FOOTPRINT sizeof(struct Account)
#define ACCOUNT_ALIGN 8

void Account_decode(struct Account* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
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
  ulong stake;
  struct Account value;
};
#define VOTEACCOUNTSPAIR_FOOTPRINT sizeof(struct VoteAccountsPair)
#define VOTEACCOUNTSPAIR_ALIGN 8

void VoteAccountsPair_decode(struct VoteAccountsPair* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake, data, dataend);
  Account_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/vote_account.rs:42
struct VoteAccounts { // tested and confirmed
  ulong vote_accounts_len;
  struct VoteAccountsPair *vote_accounts;
};
#define VOTEACCOUNTS_FOOTPRINT sizeof(struct VoteAccounts)
#define VOTEACCOUNTS_ALIGN 8

void VoteAccounts_decode(FD_FN_UNUSED struct VoteAccounts* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len != 0) {
    self->vote_accounts = (struct VoteAccountsPair*)(*allocf)(VOTEACCOUNTSPAIR_FOOTPRINT*self->vote_accounts_len, VOTEACCOUNTSPAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      VoteAccountsPair_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->vote_accounts = NULL;
}

// sdk/program/src/stake/state.rs:301
struct Delegation {
  struct Pubkey voter_pubkey;
  ulong stake;
  ulong activation_epoch;
  ulong deactivation_epoch;
  double warmup_cooldown_rate;
};
#define DELEGATION_FOOTPRINT sizeof(struct Delegation)
#define DELEGATION_ALIGN 8

void Delegation_decode(struct Delegation* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
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
#define DELEGATIONPAIR_FOOTPRINT sizeof(struct DelegationPair)
#define DELEGATIONPAIR_ALIGN 8

void DelegationPair_decode(struct DelegationPair* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  Delegation_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/stakes.rs:169
// runtime/src/bank.rs:747
struct StakesDeligation {
  struct VoteAccounts vote_accounts;
  // stake_delegations: ImHashMap<Pubkey, Delegation>,
  ulong stake_delegations_len;
  struct DelegationPair* stake_delegations;
  ulong unused;
  ulong epoch;
  struct StakeHistory stake_history;
};
#define STAKESDELIGATION_FOOTPRINT sizeof(struct StakesDeligation)
#define STAKESDELIGATION_ALIGN 8

void StakesDeligation_decode(struct StakesDeligation* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  VoteAccounts_decode(&self->vote_accounts, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->stake_delegations_len, data, dataend);
  if (self->stake_delegations_len) {
    self->stake_delegations = (struct DelegationPair*)(*allocf)(DELEGATIONPAIR_FOOTPRINT*self->stake_delegations_len, DELEGATIONPAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->stake_delegations_len; ++i)
      DelegationPair_decode(self->stake_delegations + i, data, dataend, allocf, allocf_arg);
  } else 
    self->stake_delegations = NULL;
  fd_bincode_uint64_decode(&self->unused, data, dataend);
  fd_bincode_uint64_decode(&self->epoch, data, dataend);
  StakeHistory_decode(&self->stake_history, data, dataend, allocf, allocf_arg);
}

// runtime/src/bank.rs:238
struct BankIncrementalSnapshotPersistence {
  ulong full_slot;
  struct Hash full_hash;
  ulong full_capitalization;
  struct Hash incremental_hash;
  ulong incremental_capitalization;
};
#define BANKINCREMENTALSNAPSHOTPERSISTENCE_FOOTPRINT sizeof(struct BankIncrementalSnapshotPersistence)
#define BANKINCREMENTALSNAPSHOTPERSISTENCE_ALIGN 8

struct NodeVoteAccounts {
  ulong vote_accounts_len;
  struct Pubkey *vote_accounts;
  ulong total_stake;
};
#define NodeVOTEACCOUNTS_FOOTPRINT sizeof(struct NodeVoteAccounts)
#define NodeVOTEACCOUNTS_ALIGN 8

void NodeVoteAccounts_decode(FD_FN_UNUSED struct NodeVoteAccounts* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->vote_accounts_len, data, dataend);
  if (self->vote_accounts_len) {
    self->vote_accounts = (struct Pubkey*)(*allocf)(PUBKEY_FOOTPRINT*self->vote_accounts_len, PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      Pubkey_decode(self->vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
}

struct PubkeyNodeVoteAccountsPair {
  struct Pubkey key;
  struct NodeVoteAccounts value;
};
#define PubkeyNodeVOTEACCOUNTSPAIR_FOOTPRINT sizeof(struct PubkeyNodeVoteAccountsPair)
#define PubkeyNodeVOTEACCOUNTSPAIR_ALIGN 8

void PubkeyNodeVoteAccountsPair_decode(FD_FN_UNUSED struct PubkeyNodeVoteAccountsPair* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  NodeVoteAccounts_decode(&self->value, data, dataend, allocf, allocf_arg);
}

struct PubkeyPubkeyPair {
  struct Pubkey key;
  struct Pubkey value;
};
#define PUBKEYPUBKEYPAIR_FOOTPRINT sizeof(struct PubkeyPubkeyPair)
#define PUBKEYPUBKEYPAIR_ALIGN 8

void PubkeyPubkeyPair_decode(FD_FN_UNUSED struct PubkeyPubkeyPair* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->key, data, dataend, allocf, allocf_arg);
  Pubkey_decode(&self->value, data, dataend, allocf, allocf_arg);
}

// runtime/src/epoch_stakes.rs:18
struct EpochStakes {
  struct StakesDeligation stakes;
  ulong total_stake;
  ulong node_id_to_vote_accounts_len;
  struct PubkeyNodeVoteAccountsPair *node_id_to_vote_accounts;
  ulong epoch_authorized_voters_len;
  struct PubkeyPubkeyPair *epoch_authorized_voters;
};
#define EPOCHSTAKES_FOOTPRINT sizeof(struct EpochStakes)
#define EPOCHSTAKES_ALIGN 8

void EpochStakes_decode(FD_FN_UNUSED struct EpochStakes* self, FD_FN_UNUSED void const** data, FD_FN_UNUSED void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  StakesDeligation_decode(&self->stakes, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->total_stake, data, dataend);
  fd_bincode_uint64_decode(&self->node_id_to_vote_accounts_len, data, dataend);
  if (self->node_id_to_vote_accounts_len > 0) {
    self->node_id_to_vote_accounts = (struct PubkeyNodeVoteAccountsPair*)(*allocf)(PubkeyNodeVOTEACCOUNTSPAIR_FOOTPRINT*self->node_id_to_vote_accounts_len, PubkeyNodeVOTEACCOUNTSPAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      PubkeyNodeVoteAccountsPair_decode(self->node_id_to_vote_accounts + i, data, dataend, allocf, allocf_arg);
  } else 
    self->node_id_to_vote_accounts = NULL;
  fd_bincode_uint64_decode(&self->epoch_authorized_voters_len, data, dataend);
  if (self->epoch_authorized_voters_len > 0) {
    self->epoch_authorized_voters = (struct PubkeyPubkeyPair*)(*allocf)(PUBKEYPUBKEYPAIR_FOOTPRINT*self->epoch_authorized_voters_len, PUBKEYPUBKEYPAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      PubkeyPubkeyPair_decode(self->epoch_authorized_voters + i, data, dataend, allocf, allocf_arg);
  } else 
    self->epoch_authorized_voters = NULL;
}

struct Epoch_EpochStakes_Pair {
  ulong key;
  struct EpochStakes value;
};
#define EPOCH_EPOCHSTAKES_PAIR_FOOTPRINT sizeof(struct Epoch_EpochStakes_Pair)
#define EPOCH_EPOCHSTAKES_PAIR_ALIGN 8

void Epoch_EpochStakes_Pair_decode(struct Epoch_EpochStakes_Pair* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->key, data, dataend);
  EpochStakes_decode(&self->value, data, dataend, allocf, allocf_arg);
}

struct Pubkey_u64_Pair {
  struct Pubkey _0;
  ulong _1;
};
#define PUBKEY_U64_PAIR_FOOTPRINT sizeof(struct Pubkey_u64_Pair)
#define PUBKEY_U64_PAIR_ALIGN 8

void Pubkey_u64_Pair_decode(struct Pubkey_u64_Pair* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  Pubkey_decode(&self->_0, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->_1, data, dataend);
}

// runtime/src/serde_snapshot/newer.rs:20
struct UnusedAccounts {
  // HashSet<Pubkey>
  ulong unused1_len;
  struct Pubkey* unused1;

  // HashSet<Pubkey>
  ulong unused2_len;
  struct Pubkey* unused2;

  // HashMap<Pubkey, u64>
  ulong unused3_len;
  struct Pubkey_u64_Pair* unused3;
};
#define UNUSEDACCOUNTS_FOOTPRINT sizeof(struct UnusedAccounts)
#define UNUSEDACCOUNTS_ALIGN 8

void UnusedAccounts_decode(struct UnusedAccounts* self, void const** data, void const* dataend, alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->unused1_len, data, dataend);
  if (self->unused1_len > 0) {
    self->unused1 = (struct Pubkey*)(*allocf)(PUBKEY_FOOTPRINT*self->unused1_len, PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused1_len; ++i)
      Pubkey_decode(self->unused1 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused1 = NULL;

  fd_bincode_uint64_decode(&self->unused2_len, data, dataend);
  if (self->unused2_len > 0) {
    self->unused2 = (struct Pubkey*)(*allocf)(PUBKEY_FOOTPRINT*self->unused2_len, PUBKEY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused2_len; ++i)
      Pubkey_decode(self->unused2 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused2 = NULL;

  fd_bincode_uint64_decode(&self->unused3_len, data, dataend);
  if (self->unused3_len > 0) {
    self->unused3 = (struct Pubkey_u64_Pair*)(*allocf)(PUBKEY_U64_PAIR_FOOTPRINT*self->unused3_len, PUBKEY_U64_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->unused3_len; ++i)
      Pubkey_u64_Pair_decode(self->unused3 + i, data, dataend, allocf, allocf_arg);
  } else
    self->unused3 = NULL;
}

// runtime/src/serde_snapshot/newer.rs:30
struct DeserializableVersionedBank {
  struct BlockhashQueue blockhash_queue;

  // runtime/src/ancestors.rs:pub type AncestorsForSerialization = HashMap<Slot, usize>;
  ulong ancestors_len;
  struct SlotPair *ancestors;

  struct Hash hash;
  struct Hash parent_hash;
  ulong parent_slot;
  struct HardForks hard_forks;
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
  struct Pubkey collector_id;
  ulong collector_fees;
  struct FeeCalculator fee_calculator;
  struct FeeRateGovernor fee_rate_governor;
  ulong collected_rent;
  struct RentCollector rent_collector;
  struct EpochSchedule epoch_schedule;
  struct Inflation inflation;
  struct StakesDeligation stakes;
  struct UnusedAccounts unused_accounts;
    
  ulong epoch_stakes_len;
  struct Epoch_EpochStakes_Pair *epoch_stakes;

  char is_delta;
};
#define DESERIALIZABLEVERSIONEDBANK_FOOTPRINT sizeof(struct DeserializableVersionedBank)
#define DESERIALIZABLEVERSIONEDBANK_ALIGN 8

void DeserializableVersionedBank_decode(struct DeserializableVersionedBank* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  BlockhashQueue_decode(&self->blockhash_queue, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->ancestors_len, data, dataend);
  self->ancestors = (struct SlotPair*)(*allocf)(SLOTPAIR_FOOTPRINT*self->ancestors_len, SLOTPAIR_ALIGN, allocf_arg);
  for (ulong i = 0; i < self->ancestors_len; ++i)
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
    self->epoch_stakes = (struct Epoch_EpochStakes_Pair*)(*allocf)(EPOCH_EPOCHSTAKES_PAIR_FOOTPRINT*self->epoch_stakes_len, EPOCH_EPOCHSTAKES_PAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      Epoch_EpochStakes_Pair_decode(self->epoch_stakes + i, data, dataend, allocf, allocf_arg);
  } else
    self->epoch_stakes = NULL;
  fd_bincode_uint8_decode((unsigned char *) &self->is_delta, data, dataend);
}

struct SerializableAccountStorageEntry {
  ulong id;
  ulong accounts_current_len;
};
#define SERIALIZABLEACCOUNTSTORAGEENTRY_FOOTPRINT sizeof(struct SerializableAccountStorageEntry)
#define SERIALIZABLEACCOUNTSTORAGEENTRY_ALIGN 8

void SerializableAccountStorageEntry_decode(struct SerializableAccountStorageEntry* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
  fd_bincode_uint64_decode(&self->id, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_current_len, data, dataend);
}
  
struct BankHashStats {
  ulong num_updated_accounts;
  ulong num_removed_accounts;
  ulong num_lamports_stored;
  ulong total_data_len;
  ulong num_executable_accounts;
};
#define BANKHASHSTATS_FOOTPRINT sizeof(struct BankHashStats)
#define BANKHASHSTATS_ALIGN 8

void BankHashStats_decode(struct BankHashStats* self, void const** data, void const* dataend, FD_FN_UNUSED alloc_fun allocf, FD_FN_UNUSED void* allocf_arg) {
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
#define BANKHASHINFO_FOOTPRINT sizeof(struct BankHashInfo)
#define BANKHASHINFO_ALIGN 8

void BankHashInfo_decode(struct BankHashInfo* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  Hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
  Hash_decode(&self->snapshot_hash, data, dataend, allocf, allocf_arg);
  BankHashStats_decode(&self->stats, data, dataend, allocf, allocf_arg);
}

struct SlotAccountPair {
  ulong slot;
  ulong accounts_len;
  struct SerializableAccountStorageEntry *accounts;
};
#define SLOTACCOUNTPAIR_FOOTPRINT sizeof(struct SlotAccountPair)
#define SLOTACCOUNTPAIR_ALIGN 8

void SlotAccountPair_decode(struct SlotAccountPair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  fd_bincode_uint64_decode(&self->accounts_len, data, dataend);
  if (self->accounts_len > 0) {
    self->accounts = (struct SerializableAccountStorageEntry*)(*allocf)(SERIALIZABLEACCOUNTSTORAGEENTRY_FOOTPRINT*self->accounts_len, SERIALIZABLEACCOUNTSTORAGEENTRY_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->accounts_len; ++i)
      SerializableAccountStorageEntry_decode(self->accounts + i, data, dataend, allocf, allocf_arg);
  } else
    self->accounts = NULL;
}

struct SlotMapPair {
  ulong slot;
  struct Hash hash;
};
#define SLOTMAPPAIR_FOOTPRINT sizeof(struct SlotMapPair)
#define SLOTMAPPAIR_ALIGN 8

void SlotMapPair_decode(struct SlotMapPair* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  Hash_decode(&self->hash, data, dataend, allocf, allocf_arg);
}
  
struct AccountsDbFields {
  ulong            storages_len;
  struct SlotAccountPair * storages;
  ulong            version;
  ulong            slot;
  struct BankHashInfo      bank_hash_info;
  ulong            historical_roots_len;
  ulong *          historical_roots;
  ulong            historical_roots_with_hash_len;
  struct SlotMapPair *     historical_roots_with_hash;
};
#define ACCOUNTSDBFIELDS_FOOTPRINT sizeof(struct AccountsDbFields)
#define ACCOUNTSDBFIELDS_ALIGN 8

void AccountsDbFields_decode(struct AccountsDbFields* self, void const** data, void const* dataend, alloc_fun allocf, void* allocf_arg) {
  fd_bincode_uint64_decode(&self->storages_len, data, dataend);
  if (self->storages_len > 0) {
    self->storages = (struct SlotAccountPair*)(*allocf)(SLOTACCOUNTPAIR_FOOTPRINT*self->storages_len, SLOTACCOUNTPAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->storages_len; ++i)
      SlotAccountPair_decode(self->storages + i, data, dataend, allocf, allocf_arg);
  } else
    self->storages = NULL;

  fd_bincode_uint64_decode(&self->version, data, dataend);
  fd_bincode_uint64_decode(&self->slot, data, dataend);
  BankHashInfo_decode(&self->bank_hash_info, data, dataend, allocf, allocf_arg);
  fd_bincode_uint64_decode(&self->historical_roots_len, data, dataend);
  if (self->historical_roots_len > 0) {
    self->historical_roots = (ulong*)(*allocf)(sizeof(ulong)*self->historical_roots_len, 8, allocf_arg);
    for (ulong i = 0; i < self->historical_roots_len; ++i)
      fd_bincode_uint64_decode(self->historical_roots + i, data, dataend);
  } else
    self->historical_roots = NULL;
  fd_bincode_uint64_decode(&self->historical_roots_with_hash_len, data, dataend);
  if (self->historical_roots_with_hash_len > 0) {
    self->historical_roots_with_hash = (struct SlotMapPair*)(*allocf)(SLOTMAPPAIR_FOOTPRINT*self->historical_roots_with_hash_len, SLOTMAPPAIR_ALIGN, allocf_arg);
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      SlotMapPair_decode(self->historical_roots_with_hash + i, data, dataend, allocf, allocf_arg);
  } else
    self->historical_roots_with_hash = NULL;
}
