#include "fd_exec_epoch_ctx.h"
#include <assert.h>
#include "../sysvar/fd_sysvar_stake_history.h"

/* TODO remove this */
#define MAX_LG_SLOT_CNT   10UL

ulong
fd_exec_epoch_ctx_align( void ) {
  return FD_EXEC_EPOCH_CTX_ALIGN;
}

static ulong
fd_exec_epoch_ctx_footprint_ext( fd_exec_epoch_ctx_layout_t * layout,
                                 ulong                        vote_acc_max ) {

  if( FD_UNLIKELY( !vote_acc_max ) ) return 0UL;

  fd_memset( layout, 0, sizeof(fd_exec_epoch_ctx_layout_t) );
  layout->vote_acc_max = vote_acc_max;

  ulong stake_votes_sz         = fd_vote_accounts_pair_t_map_footprint( vote_acc_max );           if( !stake_votes_sz       ) return 0UL;
  ulong stake_delegations_sz   = fd_delegation_pair_t_map_footprint   ( vote_acc_max );           if( !stake_delegations_sz ) return 0UL;
  ulong stake_history_treap_sz = fd_stake_history_treap_footprint( FD_SYSVAR_STAKE_HISTORY_CAP );  if( !stake_history_treap_sz ) FD_LOG_CRIT(( "invalid fd_stake_history_treap footprint" ));
  ulong stake_history_pool_sz  = fd_stake_history_pool_footprint ( FD_SYSVAR_STAKE_HISTORY_CAP );  if( !stake_history_pool_sz  ) FD_LOG_CRIT(( "invalid fd_stake_history_pool footprint"  ));
  ulong next_epoch_stakes_sz   = fd_vote_accounts_pair_t_map_footprint( vote_acc_max );           if( !next_epoch_stakes_sz   ) return 0UL;
  ulong leaders_sz             = fd_epoch_leaders_footprint( MAX_PUB_CNT, MAX_SLOTS_CNT );         if( !leaders_sz             ) FD_LOG_CRIT(( "invalid fd_epoch_leaders footprint" ));

  FD_SCRATCH_ALLOC_INIT( l, 0 );
  FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_epoch_ctx_t), sizeof(fd_exec_epoch_ctx_t) );
  layout->stake_votes_off         = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_vote_accounts_pair_t_map_align(), stake_votes_sz         );
  layout->stake_delegations_off   = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_delegation_pair_t_map_align(),    stake_delegations_sz   );
  layout->stake_history_treap_off = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_stake_history_treap_align(),      stake_history_treap_sz );
  layout->stake_history_pool_off  = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_stake_history_pool_align(),       stake_history_pool_sz  );
  layout->next_epoch_stakes_off   = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_vote_accounts_pair_t_map_align(), next_epoch_stakes_sz   );
  layout->leaders_off             = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_leaders_align(),            leaders_sz             );

  return layout->footprint = (ulong)FD_SCRATCH_ALLOC_FINI( l, fd_exec_epoch_ctx_align() );
}

ulong
fd_exec_epoch_ctx_footprint( ulong vote_acc_max ) {
  fd_exec_epoch_ctx_layout_t layout[1];
  return fd_exec_epoch_ctx_footprint_ext( layout, vote_acc_max );
}

void *
fd_exec_epoch_ctx_new( void * mem,
                       ulong  vote_acc_max ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_EPOCH_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_epoch_ctx_t * self = mem;
  fd_memset( self, 0, sizeof(fd_exec_epoch_ctx_t) );

  if( FD_UNLIKELY( !fd_exec_epoch_ctx_footprint_ext( &self->layout, vote_acc_max ) ) ) {
    FD_LOG_WARNING(( "invalid vote_acc_max" ));
    return NULL;
  }

  fd_exec_epoch_ctx_bank_mem_setup( self );

  fd_features_disable_all( &self->features );
  self->epoch_bank.cluster_version[0] = FD_DEFAULT_AGAVE_CLUSTER_VERSION_MAJOR;
  self->epoch_bank.cluster_version[1] = FD_DEFAULT_AGAVE_CLUSTER_VERSION_MINOR;
  self->epoch_bank.cluster_version[2] = FD_DEFAULT_AGAVE_CLUSTER_VERSION_PATCH;  
  fd_features_enable_cleaned_up( &self->features, self->epoch_bank.cluster_version );

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

static void
epoch_ctx_bank_mem_leave( fd_exec_epoch_ctx_t * epoch_ctx ) {
  void * mem = epoch_ctx;
  fd_exec_epoch_ctx_layout_t const * layout = &epoch_ctx->layout;

  void * stake_votes_mem         = (void *)( (ulong)mem + layout->stake_votes_off         );
  void * stake_delegations_mem   = (void *)( (ulong)mem + layout->stake_delegations_off   );
  void * stake_history_treap_mem = (void *)( (ulong)mem + layout->stake_history_treap_off );
  void * stake_history_pool_mem  = (void *)( (ulong)mem + layout->stake_history_pool_off  );

  fd_vote_accounts_pair_t_map_leave  ( stake_votes_mem         );
  fd_delegation_pair_t_map_leave     ( stake_delegations_mem   );
  fd_stake_history_treap_leave       ( stake_history_treap_mem );
  (void)fd_stake_history_pool_leave  ( stake_history_pool_mem  );
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

  epoch_ctx_bank_mem_leave( ctx );

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
  fd_exec_epoch_ctx_layout_t const * layout = &hdr->layout;

  void * next_epoch_stakes_mem   = (void *)( (ulong)mem + layout->next_epoch_stakes_off   );
  void * leaders_mem             = (void *)( (ulong)mem + layout->leaders_off             );

  fd_vote_accounts_pair_t_map_delete( next_epoch_stakes_mem   );
  fd_epoch_leaders_delete           ( leaders_mem             );

  fd_exec_epoch_ctx_epoch_bank_delete( hdr );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

static void
epoch_ctx_bank_mem_delete( fd_exec_epoch_ctx_t * epoch_ctx ) {
  void * mem = epoch_ctx;
  fd_exec_epoch_ctx_layout_t const * layout = &epoch_ctx->layout;

  void * stake_votes_mem         = (void *)( (ulong)mem + layout->stake_votes_off         );
  void * stake_delegations_mem   = (void *)( (ulong)mem + layout->stake_delegations_off   );
  void * stake_history_treap_mem = (void *)( (ulong)mem + layout->stake_history_treap_off );
  void * stake_history_pool_mem  = (void *)( (ulong)mem + layout->stake_history_pool_off  );

  fd_vote_accounts_pair_t_map_delete( stake_votes_mem         );
  fd_delegation_pair_t_map_delete   ( stake_delegations_mem   );
  fd_stake_history_treap_delete     ( stake_history_treap_mem );
  fd_stake_history_pool_delete      ( stake_history_pool_mem  );
}

void
fd_exec_epoch_ctx_epoch_bank_delete( fd_exec_epoch_ctx_t * epoch_ctx ) {
  epoch_ctx_bank_mem_delete( epoch_ctx );
  memset( &epoch_ctx->epoch_bank, 0UL, FD_EPOCH_BANK_FOOTPRINT);
}

void
fd_exec_epoch_ctx_bank_mem_clear( fd_exec_epoch_ctx_t * epoch_ctx ) {
  fd_epoch_bank_t * const epoch_bank = &epoch_ctx->epoch_bank;
  {
    fd_vote_accounts_pair_t_mapnode_t * old_pool = epoch_bank->stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * old_root = epoch_bank->stakes.vote_accounts.vote_accounts_root;
    fd_vote_accounts_pair_t_map_release_tree( old_pool, old_root );
    epoch_bank->stakes.vote_accounts.vote_accounts_root = NULL;
  }
  {
    fd_delegation_pair_t_mapnode_t * old_pool = epoch_bank->stakes.stake_delegations_pool;
    fd_delegation_pair_t_mapnode_t * old_root = epoch_bank->stakes.stake_delegations_root;
    fd_delegation_pair_t_map_release_tree( old_pool, old_root );
    epoch_bank->stakes.stake_delegations_root = NULL;
  }
  {
    fd_stake_history_entry_t * old_pool  = epoch_bank->stakes.stake_history.pool;
    fd_stake_history_treap_t * old_treap = epoch_bank->stakes.stake_history.treap;

    if ( old_pool && old_treap ) {
      ulong elem_cnt = 0UL;
      ulong keys[FD_SYSVAR_STAKE_HISTORY_CAP] = {0};
      for( fd_stake_history_treap_fwd_iter_t iter = fd_stake_history_treap_fwd_iter_init( old_treap, old_pool );
          !fd_stake_history_treap_fwd_iter_done( iter );
          iter = fd_stake_history_treap_fwd_iter_next( iter, old_pool ) ) {
        fd_stake_history_entry_t const * ele = fd_stake_history_treap_fwd_iter_ele_const( iter, old_pool );
        keys[elem_cnt++] = ele->epoch;
      }
      for (ulong i=0UL; i<elem_cnt; i++) {
        fd_stake_history_entry_t * ele = fd_stake_history_treap_ele_query( old_treap, keys[i], old_pool );
        old_treap = fd_stake_history_treap_ele_remove( old_treap, ele, old_pool );
        fd_stake_history_pool_ele_release( old_pool, ele );
      }
    }
  }
  {
    fd_vote_accounts_pair_t_mapnode_t * old_pool = epoch_bank->next_epoch_stakes.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * old_root = epoch_bank->next_epoch_stakes.vote_accounts_root;
    fd_vote_accounts_pair_t_map_release_tree( old_pool, old_root );
    epoch_bank->next_epoch_stakes.vote_accounts_root = NULL;
  }
}

fd_epoch_bank_t *
fd_exec_epoch_ctx_bank_mem_setup( fd_exec_epoch_ctx_t * self ) {
  fd_exec_epoch_ctx_layout_t * layout = &self->layout;

  void * stake_votes_mem         = (void *)( (ulong)self + layout->stake_votes_off         );
  void * stake_delegations_mem   = (void *)( (ulong)self + layout->stake_delegations_off   );
  void * stake_history_treap_mem = (void *)( (ulong)self + layout->stake_history_treap_off );
  void * stake_history_pool_mem  = (void *)( (ulong)self + layout->stake_history_pool_off  );
  void * next_epoch_stakes_mem   = (void *)( (ulong)self + layout->next_epoch_stakes_off   );
  //void * leaders_mem             = (void *)( (ulong)self + layout->leaders_off             );

  fd_epoch_bank_t * epoch_bank = &self->epoch_bank;
  fd_epoch_bank_new( &self->epoch_bank );

  epoch_bank->stakes.vote_accounts.vote_accounts_pool =
    fd_vote_accounts_pair_t_map_join( fd_vote_accounts_pair_t_map_new( stake_votes_mem,         layout->vote_acc_max        ) );

  epoch_bank->stakes.stake_delegations_pool =
    fd_delegation_pair_t_map_join   ( fd_delegation_pair_t_map_new   ( stake_delegations_mem,   layout->vote_acc_max        ) );

  epoch_bank->stakes.stake_history.treap =
    fd_stake_history_treap_join     ( fd_stake_history_treap_new     ( stake_history_treap_mem, FD_SYSVAR_STAKE_HISTORY_CAP ) );
  epoch_bank->stakes.stake_history.pool =
    fd_stake_history_pool_join      ( fd_stake_history_pool_new      ( stake_history_pool_mem,  FD_SYSVAR_STAKE_HISTORY_CAP ) );

  epoch_bank->next_epoch_stakes.vote_accounts_pool =
    fd_vote_accounts_pair_t_map_join( fd_vote_accounts_pair_t_map_new( next_epoch_stakes_mem,   layout->vote_acc_max        ) );

  //TODO support separate epoch leaders new and init
  //fd_epoch_leaders_new           ( leaders_mem,             MAX_PUB_CNT, MAX_SLOTS_CNT );

  return epoch_bank;
}

void
fd_exec_epoch_ctx_from_prev( fd_exec_epoch_ctx_t * self, fd_exec_epoch_ctx_t * prev ) {
  fd_memcpy( &self->features, &prev->features, sizeof(fd_features_t) );
  self->bank_hash_cmp = prev->bank_hash_cmp;

  fd_epoch_bank_t * old_epoch_bank = fd_exec_epoch_ctx_epoch_bank( prev );
  fd_epoch_bank_t * new_epoch_bank = fd_exec_epoch_ctx_bank_mem_setup( self );

  FD_SCRATCH_SCOPE_BEGIN {

    ulong sz = fd_epoch_bank_size( old_epoch_bank );
    uchar * buf = fd_scratch_alloc( fd_epoch_bank_align(), sz );

    fd_bincode_encode_ctx_t encode = {.data = buf, .dataend = buf + sz };
    fd_epoch_bank_encode( old_epoch_bank, &encode );

    fd_bincode_decode_ctx_t decode = {.data = buf, .dataend = buf + sz, .valloc = fd_null_alloc_virtual() };
    fd_epoch_bank_decode( new_epoch_bank, &decode);

    sz = fd_ulong_align_up( fd_epoch_leaders_footprint( MAX_PUB_CNT, MAX_SLOTS_CNT ), fd_epoch_leaders_align() );
    fd_memcpy( fd_exec_epoch_ctx_leaders( self ), fd_exec_epoch_ctx_leaders( prev ), sz );
  } FD_SCRATCH_SCOPE_END;
}
