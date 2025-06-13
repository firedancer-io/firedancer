#ifndef HEADER_fd_src_flamenco_runtime_fd_bank_mgr_h
#define HEADER_fd_src_flamenco_runtime_fd_bank_mgr_h

#include "../fd_flamenco_base.h"

#include "../../ballet/lthash/fd_lthash.h"
#include "../../funk/fd_funk.h"

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../features/fd_features.h"

FD_PROTOTYPES_BEGIN

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

   Important Note: The bank manager object should NOT be shared across
   threads. Each thread should have its own bank manager object.

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
  X(ulong,                             slot,                        1UL,  8UL,         8UL   ) \
  X(fd_sol_sysvar_last_restart_slot_t, last_restart_slot,           30UL, 8UL,         8UL   ) \
  X(fd_rent_fresh_accounts_global_t,   rent_fresh_accounts,         31UL, 50000UL,     8UL   ) \
  X(fd_cluster_version_t,              cluster_version,             32UL, 12UL,        4UL   ) \
  X(ulong,                             prev_slot,                   33UL, 8UL,         8UL   ) \
  X(fd_hash_t,                         bank_hash,                   34UL, 32UL,        8UL   ) \
  X(fd_hash_t,                         prev_bank_hash,              35UL, 32UL,        8UL   ) \
  X(fd_hash_t,                         genesis_hash,                36UL, 32UL,        8UL   ) \
  X(fd_epoch_schedule_t,               epoch_schedule,              37UL, 40UL,        8UL   ) \
  X(fd_rent_t,                         rent,                        38UL, 24UL,        8UL   ) \
  X(fd_vote_accounts_global_t,         next_epoch_stakes,           39UL, 300000000UL, 1024UL) \
  X(fd_vote_accounts_global_t,         epoch_stakes,                40UL, 300000000UL, 1024UL) \
  X(fd_slot_lthash_t,                  lthash,                      41UL, 4096UL,      128UL ) \
  X(fd_epoch_reward_status_global_t,   epoch_reward_status,         42UL, 160000000UL, 128UL ) \
  X(fd_stakes_global_t,                stakes,                      43UL, 800000000UL, 256UL ) \
  X(fd_epoch_leaders_t,                epoch_leaders,               44UL, 1000000UL,   128UL ) \
  X(fd_features_t,                     features,                    45UL, 2000UL,      8UL   ) \
  X(ulong,                             txn_count,                   46UL, 8UL,         8UL   ) \
  X(ulong,                             nonvote_txn_count,           47UL, 8UL,         8UL   ) \
  X(ulong,                             failed_txn_count,            48UL, 8UL,         8UL   ) \
  X(ulong,                             nonvote_failed_txn_count,    49UL, 8UL,         8UL   ) \
  X(ulong,                             total_compute_units_used,    50UL, 8UL,         8UL   ) \
  X(ulong,                             part_width,                  51UL, 8UL,         8UL   ) \
  X(ulong,                             slots_per_epoch,             52UL, 8UL,         8UL   )
FD_BANK_MGR_ITER(BANK_MGR_FUNCTIONS)

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bank_mgr_h */
