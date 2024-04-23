#include "fd_exec_epoch_ctx.h"

#define MAX_VOTE_ACCOUNTS 2000000UL
#define MAX_LG_SLOT_CNT   10UL

ulong fd_stake_history_treap_max_size( void ) {
  return fd_stake_history_treap_footprint( FD_STAKE_HISTORY_MAX );
}

ulong fd_stake_history_pool_max_size( void ) {
  return fd_stake_history_pool_footprint( FD_STAKE_HISTORY_MAX );
}

ulong fd_vote_accounts_max_size( void ) {
  return fd_vote_accounts_pair_t_map_footprint( MAX_VOTE_ACCOUNTS );
}

ulong fd_delegations_max_size( void ) {
  return fd_delegation_pair_t_map_footprint( MAX_VOTE_ACCOUNTS );
}

ulong fd_exec_epoch_ctx_align( void ) {
  return FD_EXEC_EPOCH_CTX_ALIGN;
}

ulong fd_exec_epoch_ctx_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_exec_epoch_ctx_t), sizeof(fd_exec_epoch_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_epoch_bank_align(), fd_epoch_bank_footprint());
  l = FD_LAYOUT_APPEND( l, fd_vote_accounts_pair_t_map_align(), fd_vote_accounts_max_size());
  l = FD_LAYOUT_APPEND( l, fd_delegation_pair_t_map_align(), fd_delegations_max_size());
  l = FD_LAYOUT_APPEND( l, fd_stake_history_treap_align(), fd_stake_history_treap_max_size());
  l = FD_LAYOUT_APPEND( l, fd_stake_history_pool_align(), fd_stake_history_pool_max_size());
  l = FD_LAYOUT_APPEND( l, fd_vote_accounts_pair_t_map_align(), fd_vote_accounts_max_size());
  l = FD_LAYOUT_APPEND( l, fd_epoch_leaders_align(), fd_epoch_leaders_footprint( MAX_PUB_CNT, MAX_SLOTS_CNT ) );
  l = FD_LAYOUT_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint(MAX_LG_SLOT_CNT));
  l = FD_LAYOUT_FINI(l, fd_exec_epoch_ctx_align() );
  return l;
}

void *
fd_exec_epoch_ctx_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_EPOCH_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT(l, mem);
  fd_exec_epoch_ctx_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_epoch_ctx_t), sizeof(fd_exec_epoch_ctx_t) );
  fd_memset(self, 0, FD_EXEC_EPOCH_CTX_FOOTPRINT);

  fd_features_disable_all(&self->features);
  fd_features_enable_hardcoded(&self->features);

  uchar * curr = FD_SCRATCH_ALLOC_APPEND(l, FD_EPOCH_BANK_ALIGN, FD_EPOCH_BANK_FOOTPRINT );
  fd_epoch_bank_new((fd_epoch_bank_t *)curr);
  self->epoch_bank_off     = (ulong)(curr - (uchar*)mem);

  curr = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_accounts_pair_t_map_align(), fd_vote_accounts_max_size());
  self->stake_votes_off    = (ulong)(curr - (uchar*)mem);

  curr = FD_SCRATCH_ALLOC_APPEND( l, fd_delegation_pair_t_map_align(), fd_delegations_max_size());
  self->stake_delegations_off = (ulong)(curr - (uchar*)mem);

  curr = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_history_treap_align(), fd_stake_history_treap_max_size());
  self->stake_history_treap_off = (ulong)(curr - (uchar*)mem);

  curr = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_history_pool_align(), fd_stake_history_pool_max_size());
  self->stake_history_pool_off = (ulong)(curr - (uchar*)mem);

  curr = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_accounts_pair_t_map_align(), fd_vote_accounts_max_size());
  self->next_epoch_stakes_off = (ulong)(curr - (uchar*)mem);

  curr = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_leaders_align(), fd_epoch_leaders_footprint( MAX_PUB_CNT, MAX_SLOTS_CNT ) );
  self->leaders_off        = (ulong)(curr - (uchar*)mem) ;

  curr = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint(MAX_LG_SLOT_CNT));
  self->bank_hash_cmp_off  = (ulong)(curr - (uchar*)mem);

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI(l, 1UL );
  if ( scratch_top > (ulong)mem + fd_exec_epoch_ctx_footprint() ) {
    FD_LOG_ERR(("Not enough space allocated for epoch ctx"));
  }

  FD_COMPILER_MFENCE();
  self->magic = FD_EXEC_EPOCH_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_exec_epoch_ctx_t *
fd_exec_epoch_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_exec_epoch_ctx_t * ctx = (fd_exec_epoch_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_EPOCH_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_exec_epoch_ctx_leave( fd_exec_epoch_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_EPOCH_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_exec_epoch_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_EPOCH_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_epoch_ctx_t * hdr = (fd_exec_epoch_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_EXEC_EPOCH_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}
