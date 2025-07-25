#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h

/* fd_sysvar_cache.h is the main API to read and write sysvar accounts
   and data structures.  All runtime sysvar accesses should use this API
   (except snapshot loading).

   See /doc/runtime/sysvars.md for different types of sysvars and their
   write and cache invalidation behavior.  (TLDR This is a write-through
   cache of sysvar account data) */

#include "fd_sysvar_base.h"
#include "../../types/fd_types.h"

#define FD_SYSVAR_CACHE_ENTRY_CNT 9

/* fd_sysvar_cache_t is the header of a sysvar_cache object.
   A sysvar_cache object is position-independent and backed entirely by
   a single memory region.  Each sysvar is stored in serialized/raw form
   and in a typed form.  fd_sysvar_cache_desc_t points either form.

   It is safe to relocate a sysvar_cache object, or map it from multiple
   processes with different address spaces, or clone it via a shallow
   memcpy (see fd_sysvar_cache_clone).

   Concurrently, the APIs below don't support concurrent access (atomics
   are used to detect concurrent access and force a crash).  The caller
   should use external synchronization to coordinate reads and writes
   from different threads. */

struct fd_sysvar_desc {
  uint flags;
  uint data_sz;
};

typedef struct fd_sysvar_desc fd_sysvar_desc_t;

#define FD_SYSVAR_FLAG_VALID      (0x1u)
#define FD_SYSVAR_FLAG_WRITE_LOCK (0x2u)

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
  uchar bin_rent              [ FD_SYSVAR_RENT_BINCODE_SZ              ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_rent              [ FD_SYSVAR_RENT_FOOTPRINT               ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_slot_hashes       [ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ       ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_slot_hashes       [ FD_SYSVAR_SLOT_HASHES_FOOTPRINT        ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_slot_history      [ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ      ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_slot_history      [ FD_SYSVAR_SLOT_HISTORY_FOOTPRINT       ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar bin_stake_history     [ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ     ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
  uchar obj_stake_history     [ FD_SYSVAR_STAKE_HISTORY_FOOTPRINT      ] __attribute__((aligned(FD_SYSVAR_ALIGN_MAX)));
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
fd_sysvar_cache_restore( fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_cache_restore_fuzz is a weaker version of the above for use
   with solfuzz/protosol conformance tooling.  This version works around
   bugs in that tooling that create invalid sysvars and suppresses noisy
   log warning. */

void
fd_sysvar_cache_restore_fuzz( fd_exec_slot_ctx_t * slot_ctx );

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

/* fd_sysvar_cache_data_modify_{prepare,commit} allow writing raw sysvar
   data.

   fd_sysvar_cache_data_modify_prepare prepares a sysvar data buffer
   for writing.  If opt_sz!=NULL, then *opt_sz is set to the current
   sysvar size.  If opt_sz_max!=NULL, then *opt_sz_max is set to the max
   size that may be written.  The caller writes the sysvar data to the
   returned pointer.  The returned pointer is valid if the given address
   matches a cacheable sysvar account.  Otherwise, it is NULL.

   fd_sysvar_cache_data_modify_commit marks the end of a raw sysvar data
   write.  Persists the write down to the database, and updates the
   cache itself (recovers a typed representation from the write).
   Crashes the app with FD_LOG_ERR if the write fails (e.g. database out
   of space, disk disappeared, ...). */

uchar *
fd_sysvar_cache_data_modify_prepare(
    fd_exec_slot_ctx_t * slot_ctx,
    void const *         address, /* 32 bytes */
    ulong *              opt_sz,
    ulong *              opt_sz_max
);

void
fd_sysvar_cache_data_modify_commit(
    fd_exec_slot_ctx_t * slot_ctx,
    void const *         address, /* 32 bytes */
    ulong                sz
);

#define FD_SYSVAR_IS_VALID( sysvar_cache, sysvar ) \
  ( ( FD_VOLATILE_CONST( sysvar_cache->desc[ FD_SYSVAR_##sysvar##_IDX ].flags ) \
      & ( FD_SYSVAR_FLAG_VALID|FD_SYSVAR_FLAG_WRITE_LOCK ) ) \
    == FD_SYSVAR_FLAG_VALID )

/* Accessors for small POD sysvars.  These do a copy on read and write.

   fd_sysvar_clock_is_valid returns 1 if the cached sysvar is valid
   (read, read_nofail, join are then guaranteed to succeed).  Returns 0
   otherwise.

   fd_sysvar_clock_read attempts to copy sysvar data from cache into the
   out argument.  Returns out on success, or NULL if the sysvar account
   does not exist or contains data that failed deserialization.

   fd_sysvar_clock_read_nofail returns a copy of the sysvar data.  If
   the sysvar does not exist or failed to deserialize, aborts the app
   with FD_LOG_ERR.

   fd_sysvar_clock_write serializes sysvar data, updates the cache, and
   does a blocking write to the account database.  The sysvar account's
   owner and lamport balance is changed if necessary (updates the bank's
   capitalization).  Writes to sysvars managed by this cache are only
   allowed outside of transaction execution.

   Accessors for the other sysvars in this section are analogous. */

static inline int
fd_sysvar_clock_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, clock );
}

fd_sol_sysvar_clock_t *
fd_sysvar_clock_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_sol_sysvar_clock_t *   out
);

/* Macro to improve FD_LOG_ERR line number accuracy */

#define SIMPLE_SYSVAR_READ_NOFAIL( cache, name, typet )                \
  __extension__({                                                      \
    typet out;                                                         \
    if( FD_UNLIKELY( !fd_sysvar_##name##_read( (cache), &out ) ) )     \
      FD_LOG_ERR(( "fd_sysvar_" #name "_read_nofail failed: sysvar not valid" )); \
    out;                                                               \
  })

#define fd_sysvar_clock_read_nofail( cache ) \
  SIMPLE_SYSVAR_READ_NOFAIL( cache, clock, fd_sol_sysvar_clock_t )

void
fd_sysvar_clock_write(
    fd_exec_slot_ctx_t *          slot_ctx,
    fd_sol_sysvar_clock_t const * clock
);

static inline int
fd_sysvar_epoch_rewards_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, epoch_rewards );
}

fd_sysvar_epoch_rewards_t *
fd_sysvar_epoch_rewards_read(
    fd_sysvar_cache_t const *   sysvar_cache,
    fd_sysvar_epoch_rewards_t * out
);

void
fd_sysvar_epoch_rewards_write(
    fd_exec_slot_ctx_t *              slot_ctx,
    fd_sysvar_epoch_rewards_t const * epoch_rewards
);

static inline int
fd_sysvar_epoch_schedule_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, epoch_schedule );
}

fd_epoch_schedule_t *
fd_sysvar_epoch_schedule_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_epoch_schedule_t *     out
);

#define fd_sysvar_epoch_schedule_read_nofail( cache ) \
  SIMPLE_SYSVAR_READ_NOFAIL( cache, epoch_schedule, fd_epoch_schedule_t )

void
fd_sysvar_epoch_schedule_write(
    fd_exec_slot_ctx_t *          slot_ctx,
    fd_epoch_schedule_t const *   epoch_schedule
);

static inline int
fd_sysvar_last_restart_slot_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, last_restart_slot );
}

fd_sol_sysvar_last_restart_slot_t *
fd_sysvar_last_restart_slot_read(
    fd_sysvar_cache_t const *           sysvar_cache,
    fd_sol_sysvar_last_restart_slot_t * out
);

void
fd_sysvar_last_restart_slot_write(
    fd_exec_slot_ctx_t *                      slot_ctx,
    fd_sol_sysvar_last_restart_slot_t const * last_restart_slot
);

static inline int
fd_sysvar_rent_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, rent );
}

fd_rent_t *
fd_sysvar_rent_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_rent_t *               out
);

#define fd_sysvar_rent_read_nofail( cache ) \
  SIMPLE_SYSVAR_READ_NOFAIL( cache, rent, fd_rent_t )

void
fd_sysvar_rent_write(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_rent_t const *    rent
);

/* Accessors for large sysvars.  Each large sysvar has a join/leave
   style API that provides thread-safe refcounted access to sysvars.
   If a refcount is violated (e.g. attempt to const join a sysvar with
   an active writable join), the process is terminated with FD_LOG_CRIT
   (usually produces a core dump). */

static inline int
fd_sysvar_recent_hashes_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, recent_hashes );
}

/* fd_sysvar_slot_hashes_{join,leave}(_const) {attach,detach} the caller
   {from,to} the slot hashes deque contained in the slot hashes sysvar.

   The join API returns a pointer into the sysvar cache.  If the sysvar
   account is in an invalid state (non-existent, failed to deserialize),
   join returns NULL. */

static inline int
fd_sysvar_slot_hashes_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, slot_hashes );
}

fd_slot_hash_t *
fd_sysvar_slot_hashes_join(
    fd_exec_slot_ctx_t * slot_ctx
);

fd_slot_hash_t const *
fd_sysvar_slot_hashes_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_slot_hashes_leave(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_slot_hash_t *     slot_hashes
);

void
fd_sysvar_slot_hashes_leave_const(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_slot_hash_t const *    slot_hashes
);

/* fd_sysvar_slot_history_{join,leave}(_const) {attach,detach} the
   caller {from,to} the "slot history" sysvar.  Behavior analogous to
   above accessors. */

static inline int
fd_sysvar_slot_history_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, slot_history );
}

fd_slot_history_global_t *
fd_sysvar_slot_history_join(
    fd_exec_slot_ctx_t * slot_ctx
);

fd_slot_history_global_t const *
fd_sysvar_slot_history_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_slot_history_leave(
    fd_exec_slot_ctx_t *       slot_ctx,
    fd_slot_history_global_t * slot_history
);

void
fd_sysvar_slot_history_leave_const(
    fd_sysvar_cache_t const *        sysvar_cache,
    fd_slot_history_global_t const * slot_history
);

/* fd_sysvar_stake_history_{join,leave}(_const) {attach,detach} the
   caller {from,to} the "stake history" sysvar.  Behavior analogous to
   above accessors. */

static inline int
fd_sysvar_stake_history_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return FD_SYSVAR_IS_VALID( sysvar_cache, stake_history );
}

fd_stake_history_t *
fd_sysvar_stake_history_join(
    fd_exec_slot_ctx_t * slot_ctx
);

fd_stake_history_t const *
fd_sysvar_stake_history_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_stake_history_leave(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_stake_history_t * stake_history
);

void
fd_sysvar_stake_history_leave_const(
    fd_sysvar_cache_t const *  sysvar_cache,
    fd_stake_history_t const * stake_history
);

/* The one exception where the sysvar cache diverges from the database
   is when loading a snapshot.  The epoch_schedule and rent sysvars are
   read from the cache before accounts are restored. */

void
fd_sysvar_epoch_schedule_write_cache_only(
    fd_exec_slot_ctx_t *          slot_ctx,
    fd_epoch_schedule_t const *   epoch_schedule
);

void
fd_sysvar_rent_write_cache_only(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_rent_t const *    rent
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h */
