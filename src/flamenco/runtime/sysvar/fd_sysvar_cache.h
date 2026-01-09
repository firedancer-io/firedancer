#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h

/* fd_sysvar_cache.h is a read-only cache of sysvar accounts.

   Each block, the sysvar cache is used as follows:

   - Sysvar accounts are written to DB pre-execution (Bank::new)
   - Sysvar cache is restored from accounts (reads sysvar accounts)
     (Recreated from scratch using account contents)
   - Parallel transaction execution (reads from sysvar cache)
   - Sysvar accounts are written to DB post-execution (Bank::freeze)

   In other words, sysvars backed by stored accounts are updated before
   and after transaction execution.  During transaction execution, they
   are constant.  Firedancer stores a copy of these sysvars in the
   sysvar cache for performance (raw and typed forms).

   During the slot boundary (outside of transaction execution), sysvars
   should be accessed using the accounts directly, and the sysvar cache
   is considered non-existent. */

#include "fd_sysvar_base.h"
#include "../../types/fd_types.h"
#include "../../accdb/fd_accdb_base.h"

#define FD_SYSVAR_CACHE_ENTRY_CNT 9

/* fd_sysvar_cache_t is the header of a sysvar_cache object.
   A sysvar_cache object is position-independent and backed entirely by
   a single memory region.  Each sysvar is stored in serialized/raw form
   and in a typed form.  fd_sysvar_cache_desc_t points either form.

   It is safe to relocate a sysvar_cache object, or map it from multiple
   processes with different address spaces, or clone it via a shallow
   memcpy. */

struct fd_sysvar_desc {
  uint flags;
  uint data_sz;
};

typedef struct fd_sysvar_desc fd_sysvar_desc_t;

#define FD_SYSVAR_FLAG_VALID (0x1u)

struct fd_sysvar_cache {
  ulong magic; /* ==FD_SYSVAR_CACHE_MAGIC */

  fd_sysvar_desc_t desc[ FD_SYSVAR_CACHE_ENTRY_CNT ];

  uchar bin_clock             [ FD_SYSVAR_CLOCK_BINCODE_SZ             ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_clock             [ FD_SYSVAR_CLOCK_FOOTPRINT              ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_epoch_rewards     [ FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ     ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_epoch_rewards     [ FD_SYSVAR_EPOCH_REWARDS_FOOTPRINT      ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_epoch_schedule    [ FD_SYSVAR_EPOCH_SCHEDULE_BINCODE_SZ    ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_epoch_schedule    [ FD_SYSVAR_EPOCH_SCHEDULE_FOOTPRINT     ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_last_restart_slot [ FD_SYSVAR_LAST_RESTART_SLOT_BINCODE_SZ ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_last_restart_slot [ FD_SYSVAR_LAST_RESTART_SLOT_FOOTPRINT  ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_recent_hashes     [ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ     ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_recent_hashes     [ FD_SYSVAR_RECENT_HASHES_FOOTPRINT      ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_rent              [ FD_SYSVAR_RENT_BINCODE_SZ              ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_rent              [ FD_SYSVAR_RENT_FOOTPRINT               ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_slot_hashes       [ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ       ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_slot_hashes       [ FD_SYSVAR_SLOT_HASHES_FOOTPRINT        ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_slot_history      [ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ      ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_slot_history      [ FD_SYSVAR_SLOT_HISTORY_FOOTPRINT       ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_stake_history     [ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ     ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_stake_history     [ FD_SYSVAR_STAKE_HISTORY_FOOTPRINT      ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));

  /* Note that two sysvars are (deliberately) missing:
     - The 'fees' sysvar was deprecated/demoted.  It is not part of the
       sysvar cache in Agave.
     - The 'instructions' sysvar is a virtual account, not a stored
       account.  It is never written to a database, therefore it does
       not make sense to cache it. */
};

typedef struct fd_sysvar_cache fd_sysvar_cache_t;

#define FD_SYSVAR_clock_IDX               0
#define FD_SYSVAR_epoch_rewards_IDX       1
#define FD_SYSVAR_epoch_schedule_IDX      2
#define FD_SYSVAR_last_restart_slot_IDX   3
#define FD_SYSVAR_recent_hashes_IDX       4
#define FD_SYSVAR_rent_IDX                5
#define FD_SYSVAR_slot_hashes_IDX         6
#define FD_SYSVAR_slot_history_IDX        7
#define FD_SYSVAR_stake_history_IDX       8

FD_PROTOTYPES_BEGIN

/* Constructor API */

/* fd_sysvar_cache_new formats a memory region allocated according to
   fd_sysvar_cache_{align,footprint} for use as a sysvar_cache object. */

void *
fd_sysvar_cache_new( void * mem );

/* fd_sysvar_cache_join joins the caller to a sysvar_cache object as
   writable mode.  fd_sysvar_cache_join_const is the read-only version. */

fd_sysvar_cache_t *
fd_sysvar_cache_join( void * mem );

fd_sysvar_cache_t const *
fd_sysvar_cache_join_const( void const * mem );

/* fd_sysvar_cache_leave undoes a join to a sysvar_cache object. */

void *
fd_sysvar_cache_leave( fd_sysvar_cache_t * sysvar_cache );

void const *
fd_sysvar_cache_leave_const( fd_sysvar_cache_t const * sysvar_cache );

/* fd_sysvar_cache_delete releases the sysvar cache object's backing
   memory region back to the caller. */

void *
fd_sysvar_cache_delete( void * mem );

/* fd_sysvar_cache_restore rebuilds the sysvar cache from the account
   database.  Does blocking account database queries.  Returns 1 on
   success, or 0 on failure (logs warnings).  Reasons for failure
   include unexpected database error or sysvar deserialize failure. */

int
fd_sysvar_cache_restore( fd_bank_t *               bank,
                         fd_accdb_user_t *         accdb,
                         fd_funk_txn_xid_t const * xid );

/* fd_sysvar_cache_restore_fuzz is a weaker version of the above for use
   with solfuzz/protosol conformance tooling.  This version works around
   bugs in that tooling that create invalid sysvars and suppresses noisy
   log warning. */

void
fd_sysvar_cache_restore_fuzz( fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid );

/* fd_sysvar_cache_restore_from_metas is a version of the above
   (fd_sysvar_cache_restore_fuzz) for use with solfuzz/protosol
   conformance tooling.  This version works around the aforementioned
   tooling bugs but also breaks a dependency on the accounts database to
   refresh the sysvar cache.  Instead of reading sysvar state from the
   accounts database, it searches for the sysvar accounts from the list
   of pubkeys and metas that are passed in. */

void
fd_sysvar_cache_restore_from_metas( fd_bank_t *                 bank,
                                    fd_pubkey_t const *         pubkeys,
                                    fd_account_meta_t * const * metas,
                                    ulong                       acc_cnt );

/* Generic accessors for serialized sysvar account data. */

/* fd_sysvar_cache_data_query returns a pointer to raw/serialized sysvar
   account data.  address points to the address of the sysvar account.
   *psz is set to the serialized data size (or 0 on failure).
   The returned pointer is valid until the next API call that takes a
   non-const pointer to sysvar_cache.  Note there are technically three
   outcomes (retval is the return value):
   - retval!=NULL && *psz!=0  sysvar is valid
   - retval==NULL && *psz==0  no sysvar with this address or sysvar
                              or sysvar contains invalid data
   - retval!=NULL && *psz==0  sysvar is valid, but empty (impossible
                              with current sysvars) */

uchar const *
fd_sysvar_cache_data_query(
    fd_sysvar_cache_t const * sysvar_cache,
    void const *              address, /* 32 bytes */
    ulong *                   psz
);

#define FD_SYSVAR_IS_VALID( sysvar_cache, sysvar ) \
  ( ( FD_VOLATILE_CONST( sysvar_cache->desc[ FD_SYSVAR_##sysvar##_IDX ].flags ) \
      & ( FD_SYSVAR_FLAG_VALID ) ) \
    == FD_SYSVAR_FLAG_VALID )

/* Accessors for small POD sysvars.  These do a copy on read.

   fd_sysvar_clock_is_valid returns 1 if the cached sysvar is valid
   (read, read_nofail, join_const are then guaranteed to succeed).
   Returns 0 otherwise.

   fd_sysvar_clock_read attempts to copy sysvar data from cache into the
   out argument.  Returns out on success, or NULL if the sysvar account
   does not exist or contains data that failed deserialization.

   fd_sysvar_clock_read_nofail returns a copy of the sysvar data.  If
   the sysvar does not exist or failed to deserialize, aborts the app
   with FD_LOG_ERR.

   Accessors for the other sysvars in this section are analogous. */

static inline int
fd_sysvar_cache_clock_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, clock );
}

fd_sol_sysvar_clock_t *
fd_sysvar_cache_clock_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_sol_sysvar_clock_t *   out
);

/* Macro to improve FD_LOG_ERR line number accuracy */

#define SIMPLE_SYSVAR_READ_NOFAIL( cache, name, typet )                \
  __extension__({                                                      \
    typet out;                                                         \
    if( FD_UNLIKELY( !fd_sysvar_cache_##name##_read( (cache), &out ) ) )\
      FD_LOG_ERR(( "fd_sysvar_" #name "_read_nofail failed: sysvar not valid" )); \
    out;                                                               \
  })

#define fd_sysvar_cache_clock_read_nofail( cache ) \
  SIMPLE_SYSVAR_READ_NOFAIL( cache, clock, fd_sol_sysvar_clock_t )

static inline int
fd_sysvar_cache_epoch_rewards_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, epoch_rewards );
}

fd_sysvar_epoch_rewards_t *
fd_sysvar_cache_epoch_rewards_read(
    fd_sysvar_cache_t const *   sysvar_cache,
    fd_sysvar_epoch_rewards_t * out
);

static inline int
fd_sysvar_cache_epoch_schedule_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, epoch_schedule );
}

fd_epoch_schedule_t *
fd_sysvar_cache_epoch_schedule_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_epoch_schedule_t *     out
);

#define fd_sysvar_cache_epoch_schedule_read_nofail( cache ) \
  SIMPLE_SYSVAR_READ_NOFAIL( cache, epoch_schedule, fd_epoch_schedule_t )

static inline int
fd_sysvar_cache_last_restart_slot_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, last_restart_slot );
}

fd_sol_sysvar_last_restart_slot_t *
fd_sysvar_cache_last_restart_slot_read(
    fd_sysvar_cache_t const *           sysvar_cache,
    fd_sol_sysvar_last_restart_slot_t * out
);

static inline int
fd_sysvar_cache_rent_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, rent );
}

fd_rent_t *
fd_sysvar_cache_rent_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_rent_t *               out
);

#define fd_sysvar_cache_rent_read_nofail( cache ) \
  SIMPLE_SYSVAR_READ_NOFAIL( cache, rent, fd_rent_t )

/* Accessors for large sysvars. */

static inline int
fd_sysvar_cache_recent_hashes_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, recent_hashes );
}

fd_block_block_hash_entry_t const * /* deque */
fd_sysvar_cache_recent_hashes_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_cache_recent_hashes_leave_const(
    fd_sysvar_cache_t const *           sysvar_cache,
    fd_block_block_hash_entry_t const * hashes_deque
);

/* fd_sysvar_cache_slot_hashes_{join,leave}_const {attach,detach} the
   caller {from,to} the slot hashes deque contained in the slot hashes
   sysvar.

   The join API returns a pointer into the sysvar cache.  If the sysvar
   account is in an invalid state (non-existent, failed to deserialize),
   join returns NULL. */

static inline int
fd_sysvar_cache_slot_hashes_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, slot_hashes );
}

fd_slot_hash_t const *
fd_sysvar_cache_slot_hashes_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_cache_slot_hashes_leave_const(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_slot_hash_t const *    slot_hashes
);

/* fd_sysvar_cache_slot_history_{join,leave}_const {attach,detach} the
   caller {from,to} the "slot history" sysvar.  Behavior analogous to
   above accessors. */

static inline int
fd_sysvar_cache_slot_history_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, slot_history );
}

fd_slot_history_global_t const *
fd_sysvar_cache_slot_history_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_cache_slot_history_leave_const(
    fd_sysvar_cache_t const *        sysvar_cache,
    fd_slot_history_global_t const * slot_history
);

/* fd_sysvar_cache_stake_history_{join,leave}_const {attach,detach} the
   caller {from,to} the "stake history" sysvar.  Behavior analogous to
   above accessors. */

static inline int
fd_sysvar_cache_stake_history_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, stake_history );
}

fd_stake_history_t const *
fd_sysvar_cache_stake_history_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_cache_stake_history_leave_const(
    fd_sysvar_cache_t const *  sysvar_cache,
    fd_stake_history_t const * stake_history
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h */
