#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h

/* fd_sysvar_cache reproduces the behavior of
   solana_program_runtime::sysvar_cache::SysvarCache.

   Firedancer provides this sysvar cache to be compatible with the Agave
   validator.  Otherwise, it serves no purpose other than to make the
   runtime more complicated.  The sysvar cache keeps a copy of various
   sysvar accounts.  It is part of the implicit state of the runtime.

   Note that not all sysvars are in this cache.

   ### Cache state

   The sysvar cache is not a pure cache.  For every supported sysvar, it
   may store NULL or a parsed version of the sysvar account.  It is
   populated from the accounts DB.  After parsing, the contents of the
   cache are not identical to the original account content anymore.  If
   a sysvar account fails to parse, the corresponding cache entry will
   be NULL.

   ### Write back

   The sysvar cache can be modified directly by native programs.  There
   is no standard pattern to how these changes get written back to the
   accounts DB.  Currently, the write back happens at arbitrary stages
   in the slot boundary logic and is different for every sysvar.

   ### Memory Management

   fd_sysvar_cache_t is contained by a continuous memory region and
   embeds a heap allocator. */

#include "../context/fd_exec_slot_ctx.h"

struct fd_sysvar_cache_private;
typedef struct fd_sysvar_cache_private fd_sysvar_cache_t;

FD_PROTOTYPES_BEGIN

/* fd_sysvar_cache_{align,footprint} return the memory region params of
   an fd_sysvar_cache_t. */

ulong
fd_sysvar_cache_align( void );

ulong
fd_sysvar_cache_footprint( void );

/* fd_sysvar_cache_new creates a new sysvar cache object.  mem is the
   memory region that will back the fd_sysvar_cache_t.  Also creates a
   new fd_alloc_t in the given wksp with cgroup_hint that is managed by
   the fd_sysvar_cache_t.  Returns object (in mem) on success and NULL
   on failure.  Logs reasons for failure. */

fd_sysvar_cache_t *
fd_sysvar_cache_new( void *      mem,
                     fd_wksp_t * wksp,
                     ulong       cgroup_hint );

/* fd_sysvar_cache_delete destroys a given sysvar cache object, any
   fd_alloc allocations made, and the fd_alloc_t allocator itself.
   Returns the memory region that previously backed cache back to the
   caller. */

void *
fd_sysvar_cache_delete( fd_sysvar_cache_t * cache );

/* fd_sysvar_cache_restore restores all sysvars from the given slot
   context. */

void
fd_sysvar_cache_restore( fd_sysvar_cache_t *  cache,
                         fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_cache_restore_one attempts to restore a sysvar from
   account data.  It's fine to pass an account address that is not a
   sysvar. */

void
fd_sysvar_cache_restore_one( fd_sysvar_cache_t * cache,
                             fd_pubkey_t const * address,
                             uchar const *       data,
                             ulong               data_sz );

/* Accessors for sysvars.  May return NULL. */

FD_FN_PURE fd_sol_sysvar_clock_t             const * fd_sysvar_cache_clock             ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_epoch_schedule_t               const * fd_sysvar_cache_epoch_schedule    ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_sysvar_epoch_rewards_t         const * fd_sysvar_cache_epoch_rewards     ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_sysvar_fees_t                  const * fd_sysvar_cache_fees              ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_rent_t                         const * fd_sysvar_cache_rent              ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_slot_hashes_t                  const * fd_sysvar_cache_slot_hashes       ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_recent_block_hashes_t          const * fd_sysvar_cache_recent_blockhashes( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_stake_history_t                const * fd_sysvar_cache_stake_history     ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_sol_sysvar_last_restart_slot_t const * fd_sysvar_cache_last_restart_slot ( fd_sysvar_cache_t const * cache );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h */
