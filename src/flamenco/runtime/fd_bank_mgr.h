#include "../../funk/fd_funk.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"

/* The bank manager is a wrapper on top of funk that manages on-chain
   state not represented by accounts. In practice, this on-chain state
   is a direct parallel to the Bank data structure in the Agave client.

   Each "member" of the bank manager is represented by a funk record.
   The rationale behind this is to make the bank fork-aware by
   leveraging the fact that funk already is. Also, by separating out
   each member of the bank into its own funk record means that we will
   not need to copy the entire bank while forking. A record will only
   be copied if it is modified in a slot. Each bank manager record must
   not contain gaddrs or local pointers -- all data must be accessed
   directly or with an offset.

   The standard usage pattern of the bank manager is to first refresh a
   local join for each slot via a call to fd_bank_mgr_join().
   If this join is not refreshed with the latest funk txn, then the
   caller will receive stale data. There are two ways to access the
   data after a join has been established:
   1. non-mutable: call _query(). The data returned by this call should
      not be modified and will return a direct pointer to the data in
      the funk record map.
   2. mutable: call _modfiy() followed by a _save(). _modify() will
      return a pointer to the data structure of the previous incarnation
      of record. This record can be freely modified, but it must be
      followed by a call to _save() or the changes will be discarded.
      For a single join of the bank manager, _modify() and _save()
      should not be interleaved.

   TODO: Consider supporting multiple funk rec prepares per join.
   TODO: Replace the below ID, FOOTPRINT, ALIGN with macros and ideally
   a function that generates the worst case footprint and align given
   some parameters. */

#define FD_BANK_MGR_BLOCK_HASH_QUEUE_ID        (0)
#define FD_BANK_MGR_BLOCK_HASH_QUEUE_FOOTPRINT (50000UL)
#define FD_BANK_MGR_BLOCK_HASH_QUEUE_ALIGN     (1024UL)

#define FD_BANK_MGR_SLOT_ID        (1)
#define FD_BANK_MGR_SLOT_FOOTPRINT (8UL)
#define FD_BANK_MGR_SLOT_ALIGN     (8UL)

#define FD_BANK_MGR_FEE_RATE_GOVERNOR_ID        (2)
#define FD_BANK_MGR_FEE_RATE_GOVERNOR_FOOTPRINT (40UL)
#define FD_BANK_MGR_FEE_RATE_GOVERNOR_ALIGN     (8UL)

#define FD_BANK_MGR_CAPITALIZATION_ID        (3)
#define FD_BANK_MGR_CAPITALIZATION_FOOTPRINT (8UL)
#define FD_BANK_MGR_CAPITALIZATION_ALIGN     (8UL)

#define FD_BANK_MGR_LAMPORTS_PER_SIGNATURE_ID        (4)
#define FD_BANK_MGR_LAMPORTS_PER_SIGNATURE_FOOTPRINT (8UL)
#define FD_BANK_MGR_LAMPORTS_PER_SIGNATURE_ALIGN     (8UL)

#define FD_BANK_MGR_PREV_LAMPORTS_PER_SIGNATURE_ID        (5)
#define FD_BANK_MGR_PREV_LAMPORTS_PER_SIGNATURE_FOOTPRINT (8UL)
#define FD_BANK_MGR_PREV_LAMPORTS_PER_SIGNATURE_ALIGN     (8UL)

#define FD_BANK_MGR_TRANSACTION_COUNT_ID        (6)
#define FD_BANK_MGR_TRANSACTION_COUNT_FOOTPRINT (8UL)
#define FD_BANK_MGR_TRANSACTION_COUNT_ALIGN     (8UL)

#define FD_BANK_MGR_PARENT_SIGNATURE_CNT_ID        (7)
#define FD_BANK_MGR_PARENT_SIGNATURE_CNT_FOOTPRINT (8UL)
#define FD_BANK_MGR_PARENT_SIGNATURE_CNT_ALIGN     (8UL)

#define FD_BANK_MGR_TICK_HEIGHT_ID        (8)
#define FD_BANK_MGR_TICK_HEIGHT_FOOTPRINT (8UL)
#define FD_BANK_MGR_TICK_HEIGHT_ALIGN     (8UL)

#define FD_BANK_MGR_MAX_TICK_HEIGHT_ID        (9)
#define FD_BANK_MGR_MAX_TICK_HEIGHT_FOOTPRINT (8UL)
#define FD_BANK_MGR_MAX_TICK_HEIGHT_ALIGN     (8UL)

#define FD_BANK_MGR_HASHES_PER_TICK_ID        (10)
#define FD_BANK_MGR_HASHES_PER_TICK_FOOTPRINT (8UL)
#define FD_BANK_MGR_HASHES_PER_TICK_ALIGN     (8UL)

#define FD_BANK_MGR_NS_PER_SLOT_ID        (11)
#define FD_BANK_MGR_NS_PER_SLOT_FOOTPRINT (16UL)
#define FD_BANK_MGR_NS_PER_SLOT_ALIGN     (16UL)

#define FD_BANK_MGR_TICKS_PER_SLOT_ID        (12)
#define FD_BANK_MGR_TICKS_PER_SLOT_FOOTPRINT (8UL)
#define FD_BANK_MGR_TICKS_PER_SLOT_ALIGN     (8UL)

#define FD_BANK_MGR_GENESIS_CREATION_TIME_ID        (13)
#define FD_BANK_MGR_GENESIS_CREATION_TIME_FOOTPRINT (8UL)
#define FD_BANK_MGR_GENESIS_CREATION_TIME_ALIGN     (8UL)

#define FD_BANK_MGR_SLOTS_PER_YEAR_ID        (14)
#define FD_BANK_MGR_SLOTS_PER_YEAR_FOOTPRINT (8UL)
#define FD_BANK_MGR_SLOTS_PER_YEAR_ALIGN     (8UL)

#define FD_BANK_MGR_INFLATION_ID        (15)
#define FD_BANK_MGR_INFLATION_FOOTPRINT (48UL)
#define FD_BANK_MGR_INFLATION_ALIGN     (8UL)

#define FD_BANK_MGR_TOTAL_EPOCH_STAKE_ID        (16)
#define FD_BANK_MGR_TOTAL_EPOCH_STAKE_FOOTPRINT (8UL)
#define FD_BANK_MGR_TOTAL_EPOCH_STAKE_ALIGN     (8UL)

#define FD_BANK_MGR_EAH_START_SLOT_ID        (17)
#define FD_BANK_MGR_EAH_START_SLOT_FOOTPRINT (8UL)
#define FD_BANK_MGR_EAH_START_SLOT_ALIGN     (8UL)

#define FD_BANK_MGR_EAH_STOP_SLOT_ID        (18)
#define FD_BANK_MGR_EAH_STOP_SLOT_FOOTPRINT (8UL)
#define FD_BANK_MGR_EAH_STOP_SLOT_ALIGN     (8UL)

#define FD_BANK_MGR_EAH_INTERVAL_ID        (19)
#define FD_BANK_MGR_EAH_INTERVAL_FOOTPRINT (8UL)
#define FD_BANK_MGR_EAH_INTERVAL_ALIGN     (8UL)

#define FD_BANK_MGR_BLOCK_HEIGHT_ID        (20)
#define FD_BANK_MGR_BLOCK_HEIGHT_FOOTPRINT (8UL)
#define FD_BANK_MGR_BLOCK_HEIGHT_ALIGN     (8UL)

#define FD_BANK_MGR_EPOCH_ACCOUNT_HASH_ID        (21)
#define FD_BANK_MGR_EPOCH_ACCOUNT_HASH_FOOTPRINT (32UL)
#define FD_BANK_MGR_EPOCH_ACCOUNT_HASH_ALIGN     (8UL)

#define FD_BANK_MGR_EXECUTION_FEES_ID        (22)
#define FD_BANK_MGR_EXECUTION_FEES_FOOTPRINT (8UL)
#define FD_BANK_MGR_EXECUTION_FEES_ALIGN     (8UL)

#define FD_BANK_MGR_PRIORITY_FEES_ID        (23)
#define FD_BANK_MGR_PRIORITY_FEES_FOOTPRINT (8UL)
#define FD_BANK_MGR_PRIORITY_FEES_ALIGN     (8UL)

#define FD_BANK_MGR_CLOCK_TIMESTAMP_VOTES_ID        (24)
#define FD_BANK_MGR_CLOCK_TIMESTAMP_VOTES_FOOTPRINT (2000000UL)
#define FD_BANK_MGR_CLOCK_TIMESTAMP_VOTES_ALIGN     (1024UL)

#define FD_BANK_MGR_SIGNATURE_CNT_ID        (25)
#define FD_BANK_MGR_SIGNATURE_CNT_FOOTPRINT (8UL)
#define FD_BANK_MGR_SIGNATURE_CNT_ALIGN     (8UL)

#define FD_BANK_MGR_STAKE_ACC_KEYS_ID        (26)
#define FD_BANK_MGR_STAKE_ACC_KEYS_FOOTPRINT (5000000UL * 32UL)
#define FD_BANK_MGR_STAKE_ACC_KEYS_ALIGN     (1024UL)

#define FD_BANK_MGR_VOTE_ACC_KEYS_ID        (27)
#define FD_BANK_MGR_VOTE_ACC_KEYS_FOOTPRINT (100000UL * 32UL)
#define FD_BANK_MGR_VOTE_ACC_KEYS_ALIGN     (1024UL)

/* The epoch for which to use the immediately preceeding epoch's stakes
   for leader schedule calculation. This is necessary due to how Agave's
   stake caches interact when loading from snapshots. */
#define FD_BANK_MGR_USE_PREV_EPOCH_STAKE_ID        (28)
#define FD_BANK_MGR_USE_PREV_EPOCH_STAKE_FOOTPRINT (8UL)
#define FD_BANK_MGR_USE_PREV_EPOCH_STAKE_ALIGN     (8UL)

#define FD_BANK_MGR_POH_ID        (29)
#define FD_BANK_MGR_POH_FOOTPRINT (32UL)
#define FD_BANK_MGR_POH_ALIGN     (8UL)

#define FD_BANK_MGR_LAST_RESTART_SLOT_ID        (30)
#define FD_BANK_MGR_LAST_RESTART_SLOT_FOOTPRINT (8UL)
#define FD_BANK_MGR_LAST_RESTART_SLOT_ALIGN     (8UL)

#define FD_BANK_MGR_RENT_FRESH_ACCOUNTS_ID        (31)
#define FD_BANK_MGR_RENT_FRESH_ACCOUNTS_FOOTPRINT (50000UL)
#define FD_BANK_MGR_RENT_FRESH_ACCOUNTS_ALIGN     (8UL)

/* TODO: THe names for these two epoch stakes fields are not very
   clear and should probably be renamed.

   fd_bank_mgr_epoch_stakes refers to the stakes for the epoch T-2.
   fd_bank_mgr_next_epoch_stakes refers to the stakes for the epoch T-1.
  */

#define FD_BANK_MGR_EPOCH_STAKES_ID        (32)
#define FD_BANK_MGR_EPOCH_STAKES_FOOTPRINT (50000000UL)
#define FD_BANK_MGR_EPOCH_STAKES_ALIGN     (1024UL)

#define FD_BANK_MGR_NEXT_EPOCH_STAKES_ID        (33)
#define FD_BANK_MGR_NEXT_EPOCH_STAKES_FOOTPRINT (50000000UL)
#define FD_BANK_MGR_NEXT_EPOCH_STAKES_ALIGN     (1024UL)


/* TODO: make this struct opaque. */
struct fd_bank_mgr {
  fd_funk_t *           funk;
  fd_funk_txn_t *       funk_txn;
  /* Used for modifying/creating records that don't exist
     in the current funk txn */
  fd_funk_rec_prepare_t prepare;
  int                   is_new;
  /* Used for modifying records in existing funk txn */
  fd_funk_rec_query_t   query;
  int                   is_modify;
};
typedef struct fd_bank_mgr fd_bank_mgr_t;

ulong
fd_bank_mgr_align( void );

ulong
fd_bank_mgr_footprint( void );

void *
fd_bank_mgr_new( void * mem );

fd_bank_mgr_t *
fd_bank_mgr_join( void * mem, fd_funk_t * funk, fd_funk_txn_t * funk_txn );

#define BANK_MGR_FUNCTIONS(type, name, uppername)        \
type*                                                    \
fd_bank_mgr_##name##_query(fd_bank_mgr_t* bank_mgr);     \
                                                         \
type*                                                    \
fd_bank_mgr_##name##_modify(fd_bank_mgr_t* bank_mgr);    \
                                                         \
int                                                      \
fd_bank_mgr_##name##_save(fd_bank_mgr_t* bank_mgr);

#define FD_BANK_MGR_ITER(X)                                                                 \
  X(fd_block_hash_queue_global_t,      block_hash_queue,            BLOCK_HASH_QUEUE)            \
  X(ulong,                             slot,                        SLOT)                        \
  X(fd_fee_rate_governor_t,            fee_rate_governor,           FEE_RATE_GOVERNOR)           \
  X(ulong,                             capitalization,              CAPITALIZATION)              \
  X(ulong,                             lamports_per_signature,      LAMPORTS_PER_SIGNATURE)      \
  X(ulong,                             prev_lamports_per_signature, PREV_LAMPORTS_PER_SIGNATURE) \
  X(ulong,                             transaction_count,           TRANSACTION_COUNT)           \
  X(ulong,                             parent_signature_cnt,        PARENT_SIGNATURE_CNT)        \
  X(ulong,                             tick_height,                 TICK_HEIGHT)                 \
  X(ulong,                             max_tick_height,             MAX_TICK_HEIGHT)             \
  X(ulong,                             hashes_per_tick,             HASHES_PER_TICK)             \
  X(uint128,                           ns_per_slot,                 NS_PER_SLOT)                 \
  X(ulong,                             ticks_per_slot,              TICKS_PER_SLOT)              \
  X(ulong,                             genesis_creation_time,       GENESIS_CREATION_TIME)       \
  X(double,                            slots_per_year,              SLOTS_PER_YEAR)              \
  X(fd_inflation_t,                    inflation,                   INFLATION)                   \
  X(ulong,                             total_epoch_stake,           TOTAL_EPOCH_STAKE)           \
  X(ulong,                             eah_start_slot,              EAH_START_SLOT)              \
  X(ulong,                             eah_stop_slot,               EAH_STOP_SLOT)               \
  X(ulong,                             eah_interval,                EAH_INTERVAL)                \
  X(ulong,                             block_height,                BLOCK_HEIGHT)                \
  X(fd_hash_t,                         epoch_account_hash,          EPOCH_ACCOUNT_HASH)          \
  X(ulong,                             execution_fees,              EXECUTION_FEES)              \
  X(ulong,                             priority_fees,               PRIORITY_FEES)               \
  X(fd_clock_timestamp_votes_global_t, clock_timestamp_votes,       CLOCK_TIMESTAMP_VOTES)       \
  X(ulong,                             signature_cnt,               SIGNATURE_CNT)               \
  X(fd_account_keys_global_t,          stake_account_keys,          STAKE_ACC_KEYS)              \
  X(fd_account_keys_global_t,          vote_account_keys,           VOTE_ACC_KEYS)               \
  X(ulong,                             use_prev_epoch_stake,        USE_PREV_EPOCH_STAKE)        \
  X(fd_hash_t,                         poh,                         POH)                         \
  X(fd_sol_sysvar_last_restart_slot_t, last_restart_slot,           LAST_RESTART_SLOT)           \
  X(fd_rent_fresh_accounts_global_t,   rent_fresh_accounts,         RENT_FRESH_ACCOUNTS)
FD_BANK_MGR_ITER(BANK_MGR_FUNCTIONS)
