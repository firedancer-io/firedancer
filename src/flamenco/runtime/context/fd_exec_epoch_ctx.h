#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h

#include "../../features/fd_features.h"
#include "../../leaders/fd_leaders.h"
#include "../fd_bank_hash_cmp.h"
#include "../fd_rent_lists.h"

/* fd_exec_epoch_ctx_t is the context that stays constant throughout
   an entire epoch. */

struct fd_exec_epoch_ctx_layout {
  ulong vote_acc_max;
  ulong footprint;

  ulong stake_votes_off;
  ulong stake_delegations_off;
  ulong stake_history_treap_off;
  ulong stake_history_pool_off;
  ulong next_epoch_stakes_off;
  ulong leaders_off; /* Current epoch only */
  ulong bank_hash_cmp_off;
};

typedef struct fd_exec_epoch_ctx_layout fd_exec_epoch_ctx_layout_t;

struct __attribute__((aligned(64UL))) fd_exec_epoch_ctx {
  ulong magic; /* ==FD_EXEC_EPOCH_CTX_MAGIC */

  fd_exec_epoch_ctx_layout_t layout;

  fd_features_t   features;
  fd_epoch_bank_t epoch_bank;
};

#define FD_EXEC_EPOCH_CTX_ALIGN (4096UL)
#define FD_EXEC_EPOCH_CTX_MAGIC (0x3E64F44C9F44366AUL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_exec_epoch_ctx_new( void * mem,
                       ulong  vote_acc_max );

fd_exec_epoch_ctx_t *
fd_exec_epoch_ctx_join( void * mem );

void *
fd_exec_epoch_ctx_leave( fd_exec_epoch_ctx_t * ctx );

void *
fd_exec_epoch_ctx_delete( void * mem );

ulong
fd_exec_epoch_ctx_align( void );

ulong
fd_exec_epoch_ctx_footprint( ulong vote_acc_max );

/* fd_exec_epoch_ctx_fixup_memory makes an epoch context safe for reuse
   across different address spaces.  This function is very silly:  It
   checks whether any of its dynamically object objects are allocated
   outside its own memory region.  This typically happens when restoring
   an epoch context from genesis, a snapshot, or a checkpoint.  (Because
   the fd_types deserializer allocates dynamic data structures on the
   fd_alloc heap)  The foreign-owned objects are moved into epoch
   context memory and the original objects are deallocated (via the
   given valloc).

   The following objects are migrated:

     epoch_bank->stakes.vote_accounts.vote_accounts_pool => stake_votes
     epoch_bank->stakes.stake_delegations_pool           => stake_delegations
     epoch_bank->stakes.stake_history.treap              => stake_history_treap
     epoch_bank->stakes.stake_history.pool               => stake_history_pool
     epoch_bank->next_epoch_stakes                       => next_epoch_stakes

   FIXME This function becomes redundant once we fix the problem
         upstream and stop heap allocating */

void
fd_exec_epoch_ctx_fixup_memory( fd_exec_epoch_ctx_t * epoch_ctx,
                                fd_valloc_t const *   valloc );

/* Accessors **********************************************************/

FD_FN_CONST static inline fd_epoch_bank_t *
fd_exec_epoch_ctx_epoch_bank( fd_exec_epoch_ctx_t * ctx ) {
  return &ctx->epoch_bank;
}

FD_FN_CONST static inline fd_epoch_bank_t const *
fd_exec_epoch_ctx_epoch_bank_const( fd_exec_epoch_ctx_t const * ctx ) {
  return &ctx->epoch_bank;
}

FD_FN_PURE static inline fd_vote_accounts_pair_t_mapnode_t *
fd_exec_epoch_ctx_stake_votes_join( fd_exec_epoch_ctx_t * ctx ) {
  void * mem = (void *)((ulong)ctx + ctx->layout.stake_votes_off);
  return fd_vote_accounts_pair_t_map_join( mem );
}

FD_FN_PURE static inline fd_delegation_pair_t_mapnode_t *
fd_exec_epoch_ctx_stake_delegations_join( fd_exec_epoch_ctx_t * ctx ) {
  void * mem = (void *)((ulong)ctx + ctx->layout.stake_delegations_off);
  return fd_delegation_pair_t_map_join( mem );
}

FD_FN_PURE static inline fd_stake_history_treap_t *
fd_exec_epoch_ctx_stake_history_treap_join( fd_exec_epoch_ctx_t * ctx ) {
  void * mem = (void *)((ulong)ctx + ctx->layout.stake_history_treap_off);
  return fd_stake_history_treap_join( mem );
}

FD_FN_PURE static inline fd_stake_history_entry_t *
fd_exec_epoch_ctx_stake_history_pool_join( fd_exec_epoch_ctx_t * ctx ) {
  void * mem = (void *)((ulong)ctx + ctx->layout.stake_history_pool_off);
  return fd_stake_history_pool_join( mem );
}

FD_FN_PURE static inline fd_vote_accounts_pair_t_mapnode_t *
fd_exec_epoch_ctx_next_epoch_stakes_join( fd_exec_epoch_ctx_t * ctx ) {
  void * mem = (void *)((ulong)ctx + ctx->layout.next_epoch_stakes_off);
  return fd_vote_accounts_pair_t_map_join( mem );
}

FD_FN_PURE static inline fd_epoch_leaders_t *
fd_exec_epoch_ctx_leaders( fd_exec_epoch_ctx_t * ctx ) {
  return (fd_epoch_leaders_t *)((uchar *)ctx + ctx->layout.leaders_off);
}

FD_FN_PURE static inline fd_bank_hash_cmp_t *
fd_exec_epoch_ctx_bank_hash_cmp( fd_exec_epoch_ctx_t * ctx ) {
  void * mem = (void *)((ulong)ctx + ctx->layout.bank_hash_cmp_off);
  return fd_bank_hash_cmp_join( mem );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h */
