#include "../../funk/fd_funk.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"

/* The bank manager is a wrapper on top of funk that manages on-chain
   state not represented by accounts. In practice, this on-chain state
   is a direct parallel to the Bank data structure in the Agave client.

   More specifically, the bank manager is fork-aware and thread-safe.

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
   caller may receive stale data. There are two ways to access the
   data after a join has been established:
   1. non-mutable: call _query(). The data returned by this call should
      not be modified and will return a direct pointer to the data in
      the funk record map. The caller is responsible for checking the
      return value of this function. _query() will not acquire a lock on
      the underlying hash chain as the query is done speculatively.
   2. mutable: call _modify() followed by a _save(). _modify() will
      first try to clone a previous incarnation of the record into the
      funk txn for the current join of the bank manager. If the record
      is not found, a new record will be created and allocated. The
      caller is responsible for checking the return value of this
      function. The record can then be modified and a call to _save()
      will publish the changes to the on-chain state.

      The underlying implementation involves first holding a lock on the
      hash chain for the record and cloning it if needed. Afterward, a
      lock is held to actually modify the record. The function returns
      a pointer to the modifiable record. If _save() is not called, a
      lock will be held indefinitely. The caller is responsible for
      ensuring that the lock on the record (and hash chain) is released.
*/

/* TODO: make this struct opaque. */
struct fd_bank_mgr {
  fd_funk_t *             funk;
  fd_funk_txn_t *         funk_txn;
  fd_funk_rec_map_query_t query;
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

#define BANK_MGR_FUNCTIONS(type, name, id, footprint, align)     \
static const ulong fd_bank_mgr_##name##_id        = id;          \
static const ulong fd_bank_mgr_##name##_footprint = footprint;   \
static const ulong fd_bank_mgr_##name##_align     = align;       \
type *                                                           \
fd_bank_mgr_##name##_query( fd_bank_mgr_t * bank_mgr );          \
                                                                 \
type *                                                           \
fd_bank_mgr_##name##_modify( fd_bank_mgr_t * bank_mgr );         \
                                                                 \
int                                                              \
fd_bank_mgr_##name##_save( fd_bank_mgr_t * bank_mgr );           \
                                                                 \
static FD_FN_UNUSED int                                          \
fd_bank_mgr_##name##_save_cleanup( fd_bank_mgr_t ** bank_mgr ) { \
  fd_bank_mgr_##name##_save( *bank_mgr );                        \
  return 0;                                                      \
}



/* These are some convenience wrapper macros for the bank manager. */

#define FD_BANK_MGR_DECL(bank_mgr, funk, funk_txn)                                                    \
fd_bank_mgr_t   _##bank_mgr##_obj;                                                                    \
fd_bank_mgr_t * bank_mgr = fd_bank_mgr_join( fd_bank_mgr_new( &_##bank_mgr##_obj ), funk, funk_txn ); \
if( FD_UNLIKELY( !bank_mgr ) ) {                                                                      \
  FD_LOG_CRIT(( "Failed to join bank manager" ));                                                     \
}

#define FD_BANK_MGR_MODIFY_BEGIN(bank_mgr, type_name, ptr) do {                                            \
  fd_bank_mgr_t * _bank_mgr __attribute__((cleanup(fd_bank_mgr_##type_name##_save_cleanup))) = (bank_mgr); \
  ptr = fd_bank_mgr_##type_name##_modify( _bank_mgr );                                                     \
  if( FD_UNLIKELY( !ptr ) ) {                                                                              \
    FD_LOG_CRIT(( "Failed to modify bank manager record" ));                                               \
  }                                                                                                        \
  do

#define FD_BANK_MGR_MODIFY_END while(0); } while(0)


/* FIXME: Size out all data structures to their max bounded size. */
/* FIXME: Flip order for footprind and align. */
/* Add new members to the bank manager here. */
/*  Type,                              name,                        id,   footprint,   align */
#define FD_BANK_MGR_ITER(X)                                                                    \
  X(fd_block_hash_queue_global_t,      block_hash_queue,            0UL,  50000UL,     1024UL) \
  X(ulong,                             slot,                        1UL,  8UL,         8UL   ) \
  X(fd_fee_rate_governor_t,            fee_rate_governor,           2UL,  40UL,        8UL   ) \
  X(ulong,                             capitalization,              3UL,  8UL,         8UL   ) \
  X(ulong,                             lamports_per_signature,      4UL,  8UL,         8UL   ) \
  X(ulong,                             prev_lamports_per_signature, 5UL,  8UL,         8UL   ) \
  X(ulong,                             transaction_count,           6UL,  8UL,         8UL   ) \
  X(ulong,                             parent_signature_cnt,        7UL,  8UL,         8UL   ) \
  X(ulong,                             tick_height,                 8UL,  8UL,         8UL   ) \
  X(ulong,                             max_tick_height,             9UL,  8UL,         8UL   ) \
  X(ulong,                             hashes_per_tick,             10UL, 8UL,         8UL   ) \
  X(uint128,                           ns_per_slot,                 11UL, 16UL,        16UL  ) \
  X(ulong,                             ticks_per_slot,              12UL, 8UL,         8UL   ) \
  X(ulong,                             genesis_creation_time,       13UL, 8UL,         8UL   ) \
  X(double,                            slots_per_year,              14UL, 8UL,         8UL   ) \
  X(fd_inflation_t,                    inflation,                   15UL, 48UL,        8UL   ) \
  X(ulong,                             total_epoch_stake,           16UL, 8UL,         8UL   ) \
  X(ulong,                             eah_start_slot,              17UL, 8UL,         8UL   ) \
  X(ulong,                             eah_stop_slot,               18UL, 8UL,         8UL   ) \
  X(ulong,                             eah_interval,                19UL, 8UL,         8UL   ) \
  X(ulong,                             block_height,                20UL, 8UL,         8UL   ) \
  X(fd_hash_t,                         epoch_account_hash,          21UL, 32UL,        8UL   ) \
  X(ulong,                             execution_fees,              22UL, 8UL,         8UL   ) \
  X(ulong,                             priority_fees,               23UL, 8UL,         8UL   ) \
  X(fd_clock_timestamp_votes_global_t, clock_timestamp_votes,       24UL, 2000000UL,   1024UL) \
  X(ulong,                             signature_cnt,               25UL, 8UL,         8UL   ) \
  X(fd_account_keys_global_t,          stake_account_keys,          26UL, 160000000UL, 1024UL) \
  X(fd_account_keys_global_t,          vote_account_keys,           27UL, 3200000UL,   1024UL) \
  X(ulong,                             use_prev_epoch_stake,        28UL, 8UL,         8UL   ) \
  X(fd_hash_t,                         poh,                         29UL, 32UL,        8UL   ) \
  X(fd_sol_sysvar_last_restart_slot_t, last_restart_slot,           30UL, 8UL,         8UL   ) \
  X(fd_rent_fresh_accounts_global_t,   rent_fresh_accounts,         31UL, 50000UL,     8UL   ) \
  X(fd_cluster_version_t,              cluster_version,             32UL, 12UL,        4UL   )
FD_BANK_MGR_ITER(BANK_MGR_FUNCTIONS)
