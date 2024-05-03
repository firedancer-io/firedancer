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
                                 ulong                        vote_acct_max ) {

  if( FD_UNLIKELY( !vote_acct_max ) ) return 0UL;

  fd_memset( layout, 0, sizeof(fd_exec_epoch_ctx_layout_t) );
  layout->vote_acct_max = vote_acct_max;

  ulong stake_votes_sz         = fd_vote_accounts_pair_t_map_footprint( vote_acct_max );           if( !stake_votes_sz       ) return 0UL;
  ulong stake_delegations_sz   = fd_delegation_pair_t_map_footprint   ( vote_acct_max );           if( !stake_delegations_sz ) return 0UL;
  ulong stake_history_treap_sz = fd_stake_history_treap_footprint( FD_SYSVAR_STAKE_HISTORY_CAP );  if( !stake_history_treap_sz ) FD_LOG_CRIT(( "invalid fd_stake_history_treap footprint" ));
  ulong stake_history_pool_sz  = fd_stake_history_pool_footprint ( FD_SYSVAR_STAKE_HISTORY_CAP );  if( !stake_history_pool_sz  ) FD_LOG_CRIT(( "invalid fd_stake_history_pool footprint"  ));
  ulong next_epoch_stakes_sz   = fd_vote_accounts_pair_t_map_footprint( vote_acct_max );           if( !next_epoch_stakes_sz   ) return 0UL;
  ulong leaders_sz             = fd_epoch_leaders_footprint( MAX_PUB_CNT, MAX_SLOTS_CNT );         if( !leaders_sz             ) FD_LOG_CRIT(( "invalid fd_epoch_leaders footprint" ));
  ulong bank_hash_cmp_sz       = fd_bank_hash_cmp_footprint( MAX_LG_SLOT_CNT );                    if( !bank_hash_cmp_sz       ) FD_LOG_CRIT(( "invalid fd_bank_hash_cmp footprint" ));

  FD_SCRATCH_ALLOC_INIT( l, 0 );
  FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_epoch_ctx_t), sizeof(fd_exec_epoch_ctx_t) );
  layout->stake_votes_off         = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_vote_accounts_pair_t_map_align(), stake_votes_sz         );
  layout->stake_delegations_off   = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_delegation_pair_t_map_align(),    stake_delegations_sz   );
  layout->stake_history_treap_off = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_stake_history_treap_align(),      stake_history_treap_sz );
  layout->stake_history_pool_off  = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_stake_history_pool_align(),       stake_history_pool_sz  );
  layout->next_epoch_stakes_off   = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_vote_accounts_pair_t_map_align(), next_epoch_stakes_sz   );
  layout->leaders_off             = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_leaders_align(),            leaders_sz             );
  layout->bank_hash_cmp_off       = (ulong)FD_SCRATCH_ALLOC_APPEND( l, fd_bank_hash_cmp_align(),            bank_hash_cmp_sz       );

  return layout->footprint = (ulong)FD_SCRATCH_ALLOC_FINI( l, fd_exec_epoch_ctx_align() );
}

ulong
fd_exec_epoch_ctx_footprint( ulong vote_acct_max ) {
  fd_exec_epoch_ctx_layout_t layout[1];
  return fd_exec_epoch_ctx_footprint_ext( layout, vote_acct_max );
}

void *
fd_exec_epoch_ctx_new( void * mem,
                       ulong  vote_acct_max ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_EPOCH_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_epoch_ctx_layout_t layout[1];
  if( FD_UNLIKELY( !fd_exec_epoch_ctx_footprint_ext( layout, vote_acct_max ) ) ) {
    FD_LOG_WARNING(( "invalid vote_acct_max" ));
    return NULL;
  }

  fd_exec_epoch_ctx_t * self = mem;
  fd_memset( self, 0, sizeof(fd_exec_epoch_ctx_t) );
  self->layout = *layout;

  fd_features_disable_all( &self->features );
  fd_features_enable_hardcoded( &self->features );

  fd_epoch_bank_new( &self->epoch_bank );

  void * stake_votes_mem         = (void *)( (ulong)mem + layout->stake_votes_off         );
  void * stake_delegations_mem   = (void *)( (ulong)mem + layout->stake_delegations_off   );
  void * stake_history_treap_mem = (void *)( (ulong)mem + layout->stake_history_treap_off );
  void * stake_history_pool_mem  = (void *)( (ulong)mem + layout->stake_history_pool_off  );
  void * next_epoch_stakes_mem   = (void *)( (ulong)mem + layout->next_epoch_stakes_off   );
  //void * leaders_mem             = (void *)( (ulong)mem + layout->leaders_off             );
  void * bank_hash_cmp_mem       = (void *)( (ulong)mem + layout->bank_hash_cmp_off       );

  fd_vote_accounts_pair_t_map_new( stake_votes_mem,         vote_acct_max               );
  fd_delegation_pair_t_map_new   ( stake_delegations_mem,   vote_acct_max               );
  fd_stake_history_treap_new     ( stake_history_treap_mem, FD_SYSVAR_STAKE_HISTORY_CAP );
  fd_stake_history_pool_new      ( stake_history_pool_mem,  FD_SYSVAR_STAKE_HISTORY_CAP );
  fd_vote_accounts_pair_t_map_new( next_epoch_stakes_mem,   vote_acct_max               );
  //TODO support separate epoch leaders new and init
  //fd_epoch_leaders_new           ( leaders_mem,             MAX_PUB_CNT, MAX_SLOTS_CNT );
  fd_bank_hash_cmp_new           ( bank_hash_cmp_mem,       MAX_LG_SLOT_CNT             );

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
  fd_exec_epoch_ctx_layout_t const * layout = &hdr->layout;

  void * stake_votes_mem         = (void *)( (ulong)mem + layout->stake_votes_off         );
  void * stake_delegations_mem   = (void *)( (ulong)mem + layout->stake_delegations_off   );
  void * stake_history_treap_mem = (void *)( (ulong)mem + layout->stake_history_treap_off );
  void * stake_history_pool_mem  = (void *)( (ulong)mem + layout->stake_history_pool_off  );
  void * next_epoch_stakes_mem   = (void *)( (ulong)mem + layout->next_epoch_stakes_off   );
  void * leaders_mem             = (void *)( (ulong)mem + layout->leaders_off             );
  void * bank_hash_cmp_mem       = (void *)( (ulong)mem + layout->bank_hash_cmp_off       );

  fd_vote_accounts_pair_t_map_delete( stake_votes_mem         );
  fd_delegation_pair_t_map_delete   ( stake_delegations_mem   );
  fd_stake_history_treap_delete     ( stake_history_treap_mem );
  fd_stake_history_pool_delete      ( stake_history_pool_mem  );
  fd_vote_accounts_pair_t_map_delete( next_epoch_stakes_mem   );
  fd_epoch_leaders_delete           ( leaders_mem             );
  fd_bank_hash_cmp_delete           ( bank_hash_cmp_mem       );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

void
fd_exec_epoch_ctx_fixup_memory( fd_exec_epoch_ctx_t * epoch_ctx,
                                fd_valloc_t const *   valloc ) {

  ulong epoch_mem_lo = (ulong)epoch_ctx;
  ulong epoch_mem_hi = epoch_mem_lo + epoch_ctx->layout.footprint;

  fd_epoch_bank_t * const epoch_bank = &epoch_ctx->epoch_bank;

  /* Migrate vote accounts */

  ulong stake_votes_laddr = (ulong)epoch_bank->stakes.vote_accounts.vote_accounts_pool;
  if( stake_votes_laddr <  epoch_mem_lo ||
      stake_votes_laddr >= epoch_mem_hi ) {

    fd_vote_accounts_pair_t_mapnode_t * old_pool = epoch_bank->stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * old_root = epoch_bank->stakes.vote_accounts.vote_accounts_root;

    fd_vote_accounts_pair_t_mapnode_t * new_pool = fd_exec_epoch_ctx_stake_votes_join( epoch_ctx );
    fd_vote_accounts_pair_t_mapnode_t * new_root = NULL;

    if( fd_vote_accounts_pair_t_map_size( new_pool, new_root ) )
      FD_LOG_ERR(( "epoch_ctx->stake_votes not empty" ));
    if( fd_vote_accounts_pair_t_map_max( new_pool ) != epoch_ctx->layout.vote_acct_max )
      FD_LOG_ERR(( "epoch_ctx->stake_votes corrupt" ));

    for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum( old_pool, old_root ); n; n = fd_vote_accounts_pair_t_map_successor( old_pool, n ) ) {
      fd_vote_accounts_pair_t_mapnode_t * node = fd_vote_accounts_pair_t_map_acquire( new_pool );
      if( FD_UNLIKELY( !node ) ) FD_LOG_ERR(( "epoch_ctx->stake_votes pool OOM (max=%lu)", fd_vote_accounts_pair_t_map_max( new_pool ) ));
      node->elem = n->elem;
      fd_vote_accounts_pair_t_map_insert( new_pool, &new_root, node );
    }

    fd_valloc_free( *valloc, fd_vote_accounts_pair_t_map_delete( fd_vote_accounts_pair_t_map_leave( old_pool ) ) );

    epoch_bank->stakes.vote_accounts.vote_accounts_pool = new_pool;
    epoch_bank->stakes.vote_accounts.vote_accounts_root = new_root;
  }

  /* Migrate stake delegations */

  ulong stake_delegations_laddr = (ulong)epoch_bank->stakes.stake_delegations_pool;
  if( stake_delegations_laddr <  epoch_mem_lo ||
      stake_delegations_laddr >= epoch_mem_hi ) {

    fd_delegation_pair_t_mapnode_t * old_pool = epoch_bank->stakes.stake_delegations_pool;
    fd_delegation_pair_t_mapnode_t * old_root = epoch_bank->stakes.stake_delegations_root;

    fd_delegation_pair_t_mapnode_t * new_pool = fd_exec_epoch_ctx_stake_delegations_join( epoch_ctx );
    fd_delegation_pair_t_mapnode_t * new_root = NULL;

    if( FD_UNLIKELY( fd_delegation_pair_t_map_size( new_pool, new_root ) ) )
      FD_LOG_ERR(( "epoch_ctx->stake_delegations not empty" ));
    if( FD_UNLIKELY( fd_delegation_pair_t_map_max( new_pool ) != epoch_ctx->layout.vote_acct_max ) )
      FD_LOG_ERR(( "epoch_ctx->stake_delegations corrupt" ));

    for( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum( old_pool, old_root ); n; n = fd_delegation_pair_t_map_successor( old_pool, n ) ) {
      fd_delegation_pair_t_mapnode_t * node = fd_delegation_pair_t_map_acquire( new_pool );
      if( FD_UNLIKELY( !node ) ) FD_LOG_ERR(( "epoch_ctx->stake_delegations pool OOM (max=%lu)", fd_delegation_pair_t_map_max( new_pool ) ));
      node->elem = n->elem;
      fd_delegation_pair_t_map_insert( new_pool, &new_root, node );
    }

    fd_valloc_free( *valloc, fd_delegation_pair_t_map_delete( fd_delegation_pair_t_map_leave( old_pool ) ) );

    epoch_bank->stakes.stake_delegations_pool = new_pool;
    epoch_bank->stakes.stake_delegations_root = new_root;
  }

  /* Migrate stake history */

  ulong stake_history_laddr = (ulong)epoch_bank->stakes.stake_history.pool;
  if( stake_history_laddr <  epoch_mem_lo ||
      stake_history_laddr >= epoch_mem_hi ) {

    fd_stake_history_entry_t * old_pool  = epoch_bank->stakes.stake_history.pool;
    fd_stake_history_treap_t * old_treap = epoch_bank->stakes.stake_history.treap;

    fd_stake_history_entry_t * new_pool  = fd_exec_epoch_ctx_stake_history_pool_join ( epoch_ctx );
    fd_stake_history_treap_t * new_treap = fd_exec_epoch_ctx_stake_history_treap_join( epoch_ctx );

    if( fd_stake_history_treap_ele_cnt( new_treap ) )
      FD_LOG_ERR(( "epoch_ctx->stake_history not empty" ));
    if( fd_stake_history_pool_max( new_pool ) != FD_SYSVAR_STAKE_HISTORY_CAP )
      FD_LOG_ERR(( "epoch_ctx->stake_history corrupt" ));

    if( FD_LIKELY( old_treap ) ) {  /* not initialized by genesis */
      for( fd_stake_history_treap_fwd_iter_t iter = fd_stake_history_treap_fwd_iter_init( old_treap, old_pool );
          !fd_stake_history_treap_fwd_iter_done( iter );
          iter = fd_stake_history_treap_fwd_iter_next( iter, old_pool ) ) {
        fd_stake_history_entry_t const * old_ele = fd_stake_history_treap_fwd_iter_ele( iter, old_pool );
        if( FD_UNLIKELY( !fd_stake_history_pool_free( new_pool ) ) ) FD_LOG_ERR(( "epoch_ctx->stake_history_pool OOM (max=%lu, have=%lu)", fd_stake_history_pool_max( new_pool ), fd_stake_history_treap_ele_cnt( old_treap ) ));
        fd_stake_history_entry_t       * new_ele = fd_stake_history_pool_ele_acquire( new_pool );
        *new_ele = *old_ele;
        fd_stake_history_treap_ele_insert( new_treap, new_ele, new_pool );
      }

      fd_valloc_free( *valloc, fd_stake_history_treap_leave( fd_stake_history_treap_delete( old_treap ) ) );
      fd_valloc_free( *valloc, fd_stake_history_pool_leave ( fd_stake_history_pool_delete ( old_pool  ) ) );
    }

    epoch_bank->stakes.stake_history.pool  = new_pool;
    epoch_bank->stakes.stake_history.treap = new_treap;
  }

  /* Migrate next epoch stakes */

  ulong next_epoch_stakes_laddr = (ulong)epoch_bank->next_epoch_stakes.vote_accounts_pool;
  if( next_epoch_stakes_laddr <  epoch_mem_lo ||
      next_epoch_stakes_laddr >= epoch_mem_hi ) {

    fd_vote_accounts_pair_t_mapnode_t * old_pool = epoch_bank->next_epoch_stakes.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t * old_root = epoch_bank->next_epoch_stakes.vote_accounts_root;

    fd_vote_accounts_pair_t_mapnode_t * new_pool = fd_exec_epoch_ctx_next_epoch_stakes_join( epoch_ctx );
    fd_vote_accounts_pair_t_mapnode_t * new_root = NULL;

    if( fd_vote_accounts_pair_t_map_size( new_pool, new_root ) )
      FD_LOG_ERR(( "epoch_ctx->next_epoch_stakes not empty" ));
    if( fd_vote_accounts_pair_t_map_max( new_pool ) != epoch_ctx->layout.vote_acct_max )
      FD_LOG_ERR(( "epoch_ctx->stake_votes corrupt" ));

    for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum( old_pool, old_root ); n; n = fd_vote_accounts_pair_t_map_successor( old_pool, n ) ) {
      fd_vote_accounts_pair_t_mapnode_t * node = fd_vote_accounts_pair_t_map_acquire( new_pool );
      if( FD_UNLIKELY( !node ) ) FD_LOG_ERR(( "epoch_ctx->next_epoch_stakes pool OOM (max=%lu)", fd_vote_accounts_pair_t_map_max( new_pool ) ));
      node->elem = n->elem;
      fd_vote_accounts_pair_t_map_insert( new_pool, &new_root, node );
    }

    fd_valloc_free( *valloc, fd_vote_accounts_pair_t_map_delete( fd_vote_accounts_pair_t_map_leave( old_pool ) ) );

    epoch_bank->next_epoch_stakes.vote_accounts_pool = new_pool;
    epoch_bank->next_epoch_stakes.vote_accounts_root = new_root;
  }

}
