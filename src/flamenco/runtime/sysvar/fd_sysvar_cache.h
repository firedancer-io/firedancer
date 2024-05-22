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

#include "../fd_acc_mgr.h"

/* Reuse this table to avoid code duplication */
#define FD_SYSVAR_CACHE_ITER(X) \
  X( fd_sol_sysvar_clock,             clock               ) \
  X( fd_epoch_schedule,               epoch_schedule      ) \
  X( fd_sysvar_epoch_rewards,         epoch_rewards       ) \
  X( fd_sysvar_fees,                  fees                ) \
  X( fd_rent,                         rent                ) \
  X( fd_slot_hashes,                  slot_hashes         ) \
  X( fd_recent_block_hashes,          recent_block_hashes ) \
  X( fd_stake_history,                stake_history       ) \
  X( fd_sol_sysvar_last_restart_slot, last_restart_slot   )

/* The memory of fd_sysvar_cache_t fits as much sysvar information into
   the struct as possible.  Unfortunately some parts of the sysvar
   spill out onto the heap due to how the type generator works.

   The has_{...} bits specify whether a sysvar logically exists.
   The val_{...} structs contain the top-level struct of each sysvar.
   If has_{...}==0 then any heap pointers in val_{...} are NULL,
   allowing for safe idempotent calls to fd_sol_sysvar_{...}_destroy() */

struct __attribute__((aligned(16UL))) fd_sysvar_cache_private {
  ulong       magic;  /* ==FD_SYSVAR_CACHE_MAGIC */
  fd_valloc_t valloc;

  /* Declare the val_{...} values */
# define X( type, name ) \
  type##_t val_##name[1];
  FD_SYSVAR_CACHE_ITER(X)
# undef X

  /* Declare the has_{...} bits */
# define X( _type, name ) \
  ulong has_##name : 1;
  FD_SYSVAR_CACHE_ITER(X)
# undef X
};

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
   memory region that will back the fd_sysvar_cache_t.  Attaches to the
   given valloc for use as a heap allocator for sysvar data.  Returns
   object (in mem) on success and NULL on failure.  Logs reasons for
   failure. */

fd_sysvar_cache_t *
fd_sysvar_cache_new( void *      mem,
                     fd_valloc_t valloc );

/* fd_sysvar_cache_delete destroys a given sysvar cache object and any
   heap allocations made.  Detaches from the valloc provided in
   fd_sysvar_cache_new.  Returns the memory region that previously
   backed cache back to the caller. */

void *
fd_sysvar_cache_delete( fd_sysvar_cache_t * cache );

/* fd_sysvar_cache_restore restores all sysvars from the given slot
   context.

   Roughly compatible with Agave's
   solana_program_runtime::sysvar_cache::SysvarCache::fill_missing_entries
   https://github.com/solana-labs/solana/blob/v1.17.23/program-runtime/src/sysvar_cache.rs#L137-L208 */

void
fd_sysvar_cache_restore( fd_sysvar_cache_t * cache,
                         fd_acc_mgr_t *      acc_mgr,
                         fd_funk_txn_t *     funk_txn );

/* Accessors for sysvars.  May return NULL. */

FD_FN_PURE fd_sol_sysvar_clock_t             const * fd_sysvar_cache_clock              ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_epoch_schedule_t               const * fd_sysvar_cache_epoch_schedule     ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_sysvar_epoch_rewards_t         const * fd_sysvar_cache_epoch_rewards      ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_sysvar_fees_t                  const * fd_sysvar_cache_fees               ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_rent_t                         const * fd_sysvar_cache_rent               ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_slot_hashes_t                  const * fd_sysvar_cache_slot_hashes        ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_recent_block_hashes_t          const * fd_sysvar_cache_recent_block_hashes( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_stake_history_t                const * fd_sysvar_cache_stake_history      ( fd_sysvar_cache_t const * cache );
FD_FN_PURE fd_sol_sysvar_last_restart_slot_t const * fd_sysvar_cache_last_restart_slot  ( fd_sysvar_cache_t const * cache );

/* fd_sysvar_from_instr_acct_{...} pretends to read a sysvar from an
   instruction account.  Checks that a given instruction account has
   an address matching the sysvar.  Returns the sysvar from the sysvar
   cache.  On return, *err is in FD_EXECUTOR_INSTR_{SUCCESS,ERR_{...}}.

   Matches Agave's
   solana_program_runtime::sysvar_cache::get_sysvar_with_account_check
   https://github.com/solana-labs/solana/blob/v1.18.8/program-runtime/src/sysvar_cache.rs#L215-L314

   Equivalent to:

     fd_sysvar_FOO_t const *
     fd_sysvar_from_instr_acct_FOO( fd_exec_instr_ctx_t const * ctx,
                                    ulong                       acct_idx ) {
       if( FD_UNLIKELY( idx >= ctx->instr->acct_cnt ) ) {
          *err = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
          return NULL;
       }
       if( ctx->instr->acct_pubkeys[ acct_idx ] != FOO_addr ) {
         *err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
         return NULL;
       }
       FOO_t const * value = fd_sysvar_cache_FOO( ctx->slot_ctx->sysvar_cache );
       *err = value ? 0 : FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
       return value;
     } */

fd_sol_sysvar_clock_t             const * fd_sysvar_from_instr_acct_clock              ( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );
fd_epoch_schedule_t               const * fd_sysvar_from_instr_acct_epoch_schedule     ( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );
fd_sysvar_epoch_rewards_t         const * fd_sysvar_from_instr_acct_epoch_rewards      ( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );
fd_sysvar_fees_t                  const * fd_sysvar_from_instr_acct_fees               ( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );
fd_rent_t                         const * fd_sysvar_from_instr_acct_rent               ( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );
fd_slot_hashes_t                  const * fd_sysvar_from_instr_acct_slot_hashes        ( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );
fd_recent_block_hashes_t          const * fd_sysvar_from_instr_acct_recent_block_hashes( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );
fd_stake_history_t                const * fd_sysvar_from_instr_acct_stake_history      ( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );
fd_sol_sysvar_last_restart_slot_t const * fd_sysvar_from_instr_acct_last_restart_slot  ( fd_exec_instr_ctx_t const * ctx, ulong acct_idx, int * err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_cache_h */
