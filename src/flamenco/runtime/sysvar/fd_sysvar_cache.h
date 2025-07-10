#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h

/* fd_sysvar_cache.h is the main API to read and write sysvar accounts
   and data structures.  All runtime sysvar accesses should use this API
   (except snapshot loading).

   See /doc/runtime/sysvars.md for different types of sysvars and their
   write and cache invalidation behavior.  (TLDR This is a write-through
   cache of sysvar account data) */

#include "../../types/fd_types.h"

/* FD_SYSVAR_CACHE_{ALIGN,FOOTPRINT} specify the static requirements for
   a memory region suitable of holding a sysvar_cache object. */

#define FD_SYSVAR_CACHE_ALIGN        (16UL)
#define FD_SYSVAR_CACHE_FOOTPRINT (50000UL) /* TODO */

#define FD_SYSVAR_CACHE_MAGIC (0x1aa5ecb2a49b600aUL) /* random number */

/* fd_sysvar_cache_t is the header of a sysvar_cache object.
   A sysvar_cache object is position-independent and backed entirely by
   a single memory region.  Each sysvar is stored in serialized/raw form
   and in a typed form, see fd_sysvar_cache_desc_t.

   Should not be declared locally (allocate via align/footprint/new).
   Use accessor APIs instead of using struct members directly.

   It is safe to relocate a sysvar_cache object, or map it from multiple
   processes with different address spaces, or clone it via a shallow
   memcpy (see fd_sysvar_cache_clone).

   Concurrently, the APIs below don't support concurrent access (atomics
   are used to detect concurrent access and force a crash).  The caller
   should use external synchronization to coordinate reads and writes
   from different threads. */

struct fd_sysvar_cache_desc {
  /* Offsets relative to start of sysvar cache */
  uint data_off;  /* Raw data offset */
  uint data_sz;   /* Raw data size */
  uint obj_off;   /* Typed object offset */
  uint flags;
};
typedef struct fd_sysvar_cache_desc fd_sysvar_cache_desc_t;

struct fd_sysvar_cache_descs {
  fd_sysvar_cache_desc_t clock;
  fd_sysvar_cache_desc_t epoch_rewards;
  fd_sysvar_cache_desc_t epoch_schedule;
  fd_sysvar_cache_desc_t last_restart_slot;
  fd_sysvar_cache_desc_t recent_block_hashes;
  fd_sysvar_cache_desc_t rent;
  fd_sysvar_cache_desc_t slot_hashes;
  fd_sysvar_cache_desc_t slot_history;
  fd_sysvar_cache_desc_t stake_history;
  /* Note the "fees" sysvar is no longer relevant */
};
typedef struct fd_sysvar_cache_descs fd_sysvar_cache_descs_t;

struct fd_sysvar_cache {
  ulong magic; /* ==FD_SYSVAR_CACHE_MAGIC */

  union {
    fd_sysvar_cache_descs_t desc;
    fd_sysvar_cache_desc_t  desc_tbl[ 9 ];
  };
};

typedef struct fd_sysvar_cache fd_sysvar_cache_t;

FD_PROTOTYPES_BEGIN

/* Constructor API */

/* fd_sysvar_cache_{align,footprint} return
   FD_SYSVAR_CACHE_{ALIGN,FOOTPRINT}. */

FD_FN_CONST ulong
fd_sysvar_cache_align( void );

FD_FN_CONST ulong
fd_sysvar_cache_footprint( void );

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

/* fd_sysvar_cache_clone clones a sysvar cache object from a join in
   orig to a new memory region to mem2.  */

void *
fd_sysvar_cache_clone( void *                    mem2,
                       fd_sysvar_cache_t const * orig );

/* fd_sysvar_cache_recover rebuilds the sysvar cache from the account
   database.  Logs warnings in case sysvar datas fail to deserialize.
   FIXME consider taking a database handle instead of slot_ctx */

void
fd_sysvar_cache_recover( fd_exec_slot_ctx_t * slot_ctx );

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

/* fd_sysvar_cache_flags_valid returns 1 if there is a valid typed
   object for a sysvar cache entry, otherwise returns 0. */

static inline uint
fd_sysvar_cache_flags_valid( uint flags ) {
  return flags & 1;
}

uint
fd_sysvar_cache_flags_exists( uint flags );

#define FD_SYSVAR_CACHE_EXISTS( sysvar_cache, sysvar ) \
  ( fd_sysvar_cache_flags_exists( sysvar_cache->desc.sysvar.flags ) )

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
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.clock.flags );
}

fd_sol_sysvar_clock_t *
fd_sysvar_clock_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_sol_sysvar_clock_t *   out
);

fd_sol_sysvar_clock_t
fd_sysvar_clock_read_nofail(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_clock_write(
    fd_exec_slot_ctx_t *          slot_ctx,
    fd_sol_sysvar_clock_t const * clock
);

static inline int
fd_sysvar_epoch_rewards_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.epoch_rewards.flags );
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
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.epoch_schedule.flags );
}

fd_epoch_schedule_t *
fd_sysvar_epoch_schedule_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_epoch_schedule_t *     out
);

fd_epoch_schedule_t
fd_sysvar_epoch_schedule_read_nofail( fd_sysvar_cache_t const * sysvar_cache );

void
fd_sysvar_epoch_schedule_write(
    fd_exec_slot_ctx_t *          slot_ctx,
    fd_epoch_schedule_t const *   epoch_schedule
);

static inline int
fd_sysvar_last_restart_slot_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.last_restart_slot.flags );
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
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.rent.flags );
}

fd_rent_t *
fd_sysvar_rent_read(
    fd_sysvar_cache_t const * sysvar_cache,
    fd_rent_t *               out
);

fd_rent_t
fd_sysvar_rent_read_nofail( fd_sysvar_cache_t const * sysvar_cache );

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
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.recent_block_hashes.flags );
}

fd_block_block_hash_entry_t * /* deque */
fd_sysvar_recent_hashes_join(
    fd_exec_slot_ctx_t * slot_ctx
);

fd_block_block_hash_entry_t const * /* deque */
fd_sysvar_recent_hashes_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_recent_hashes_leave(
    fd_sysvar_cache_t *           sysvar_cache,
    fd_block_block_hash_entry_t * hashes_deque
);

void
fd_sysvar_recent_hashes_leave_const(
    fd_sysvar_cache_t const *           sysvar_cache,
    fd_block_block_hash_entry_t const * hashes_deque
);

/* fd_sysvar_slot_hashes_{join,leave}(_const) {attach,detach} the caller
   {from,to} the slot hashes deque contained in the slot hashes sysvar.

   The join API returns a pointer into the sysvar cache.  If the sysvar
   account is in an invalid state (non-existent, failed to deserialize),
   join returns NULL. */

static inline int
fd_sysvar_slot_hashes_is_valid( fd_sysvar_cache_t const * sysvar_cache ) {
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.slot_hashes.flags );
}

fd_slot_hash_t *
fd_sysvar_slot_hashes_join(
    fd_sysvar_cache_t * sysvar_cache
);

fd_slot_hash_t const *
fd_sysvar_slot_hashes_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_slot_hashes_leave(
    fd_sysvar_cache_t * sysvar_cache,
    fd_slot_hash_t *    slot_hashes
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
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.slot_history.flags );
}

fd_slot_history_global_t *
fd_sysvar_slot_history_join(
    fd_sysvar_cache_t * sysvar_cache
);

fd_slot_history_global_t const *
fd_sysvar_slot_history_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_slot_history_leave(
    fd_sysvar_cache_t *        sysvar_cache,
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
  return !!fd_sysvar_cache_flags_valid( sysvar_cache->desc.stake_history.flags );
}

fd_stake_history_t *
fd_sysvar_stake_history_join(
    fd_sysvar_cache_t * sysvar_cache
);

fd_stake_history_t const *
fd_sysvar_stake_history_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);

void
fd_sysvar_stake_history_leave(
    fd_sysvar_cache_t *  sysvar_cache,
    fd_stake_history_t * stake_history
);

void
fd_sysvar_stake_history_leave_const(
    fd_sysvar_cache_t const *  sysvar_cache,
    fd_stake_history_t const * stake_history
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h */
