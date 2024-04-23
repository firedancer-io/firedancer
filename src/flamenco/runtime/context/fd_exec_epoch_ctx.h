#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h

#include "../../features/fd_features.h"
#include "../../leaders/fd_leaders.h"
#include "../fd_bank_hash_cmp.h"
#include "../fd_rent_lists.h"

/* fd_exec_epoch_ctx_t is the context that stays constant throughout
   an entire epoch. */

struct __attribute__((aligned(8UL))) fd_exec_epoch_ctx {
  ulong magic; /* ==FD_EXEC_EPOCH_CTX_MAGIC */
  fd_features_t        features;
  ulong epoch_bank_off;
  ulong stake_votes_off;
  ulong stake_delegations_off;
  ulong stake_history_treap_off;
  ulong stake_history_pool_off;
  ulong next_epoch_stakes_off;
  ulong leaders_off; /* Current epoch only */
  ulong bank_hash_cmp_off;
};

#define FD_EXEC_EPOCH_CTX_ALIGN     ( 4096UL )
#define FD_EXEC_EPOCH_CTX_FOOTPRINT ( fd_exec_epoch_ctx_footprint() )
#define FD_EXEC_EPOCH_CTX_MAGIC (0x3E64F44C9F44366AUL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_exec_epoch_ctx_new( void * mem );

fd_exec_epoch_ctx_t *
fd_exec_epoch_ctx_join( void * mem );

void *
fd_exec_epoch_ctx_leave( fd_exec_epoch_ctx_t * ctx );

void *
fd_exec_epoch_ctx_delete( void * mem );

ulong fd_exec_epoch_ctx_align( void );

ulong fd_exec_epoch_ctx_footprint( void );

FD_FN_PURE static inline fd_epoch_bank_t *
fd_exec_epoch_ctx_epoch_bank( fd_exec_epoch_ctx_t * ctx ) {
  return (fd_epoch_bank_t *)((uchar *)ctx + ctx->epoch_bank_off);
}

FD_FN_PURE static inline fd_epoch_bank_t const *
fd_exec_epoch_ctx_epoch_bank_const( fd_exec_epoch_ctx_t const * ctx ) {
  return (fd_epoch_bank_t *)((uchar *)ctx + ctx->epoch_bank_off);
}

FD_FN_PURE static inline void *
fd_exec_epoch_ctx_stake_votes_mem( fd_exec_epoch_ctx_t * ctx ) {
  return ((uchar *)ctx + ctx->stake_votes_off);
}

FD_FN_PURE static inline void *
fd_exec_epoch_ctx_stake_delegations_mem( fd_exec_epoch_ctx_t * ctx ) {
  return ((uchar *)ctx + ctx->stake_delegations_off);
}

FD_FN_PURE static inline void *
fd_exec_epoch_ctx_stake_history_treap_mem( fd_exec_epoch_ctx_t * ctx ) {
  return ((uchar *)ctx + ctx->stake_history_treap_off);
}

FD_FN_PURE static inline void *
fd_exec_epoch_ctx_stake_history_pool_mem( fd_exec_epoch_ctx_t * ctx ) {
  return ((uchar *)ctx + ctx->stake_history_pool_off);
}

FD_FN_PURE static inline void *
fd_exec_epoch_ctx_next_epoch_stakes_mem( fd_exec_epoch_ctx_t * ctx ) {
  return ((uchar *)ctx + ctx->next_epoch_stakes_off);
}

FD_FN_PURE static inline fd_epoch_leaders_t *
fd_exec_epoch_ctx_leaders( fd_exec_epoch_ctx_t * ctx ) {
  return (fd_epoch_leaders_t *)((uchar *)ctx + ctx->leaders_off);
}

FD_FN_PURE static inline fd_bank_hash_cmp_t *
fd_exec_epoch_ctx_bank_hash_cmp( fd_exec_epoch_ctx_t * ctx ) {
  return (fd_bank_hash_cmp_t *)((uchar *)ctx + ctx->bank_hash_cmp_off);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h */
