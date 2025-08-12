#include "fd_stake_delegations.h"

fd_stake_delegation_t *
fd_stake_delegations_get_pool( fd_stake_delegations_t const * stake_delegations ) {
  FD_SCRATCH_ALLOC_INIT( l, stake_delegations );
  FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  uchar * pool = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_pool_align(), fd_stake_delegation_pool_footprint( stake_delegations->max_stake_accounts ) );
  return fd_stake_delegation_pool_join( pool );
}

fd_stake_delegation_map_t *
fd_stake_delegations_get_map( fd_stake_delegations_t const * stake_delegations ) {
  FD_SCRATCH_ALLOC_INIT( l, stake_delegations );
  FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_pool_align(), fd_stake_delegation_pool_footprint( stake_delegations->max_stake_accounts ) );
  ulong map_chain_cnt = fd_stake_delegation_map_chain_cnt_est( stake_delegations->max_stake_accounts );
  uchar * map = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_map_align(), fd_stake_delegation_map_footprint( map_chain_cnt ) );
  return fd_stake_delegation_map_join( map );
}

ulong
fd_stake_delegations_align( void ) {
  /* The align of the struct should be the max of the align of the data
     structures that it contains. In this case, this is the map, the
     pool, and the struct itself*/
  return fd_ulong_max( fd_ulong_max( fd_stake_delegation_map_align(),
                       fd_stake_delegation_pool_align() ), alignof(fd_stake_delegations_t) );
}

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts ) {

  ulong map_chain_cnt = fd_stake_delegation_map_chain_cnt_est( max_stake_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(),     sizeof(fd_stake_delegations_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_delegation_pool_align(), fd_stake_delegation_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_delegation_map_align(),  fd_stake_delegation_map_footprint( map_chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_stake_delegations_align() );
}

void *
fd_stake_delegations_new( void * mem, ulong max_stake_accounts ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_stake_accounts ) ) {
    FD_LOG_WARNING(( "max_stake_accounts is 0" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_delegations_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong map_chain_cnt = fd_stake_delegation_map_chain_cnt_est( max_stake_accounts );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_t * stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),     sizeof(fd_stake_delegations_t) );
  void *                   pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_pool_align(), fd_stake_delegation_pool_footprint( max_stake_accounts ) );
  void *                   map_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_map_align(),  fd_stake_delegation_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( max_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_stake_delegations_new: bad layout" ));
    return NULL;
  }

  stake_delegations->magic              = FD_STAKE_DELEGATIONS_MAGIC;
  stake_delegations->max_stake_accounts = max_stake_accounts;

  if( FD_UNLIKELY( !fd_stake_delegation_pool_new( pool_mem, max_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations pool" ));
    return NULL;
  }

  /* TODO: The seed shouldn't be hardcoded. */
  if( FD_UNLIKELY( !fd_stake_delegation_map_new( map_mem, map_chain_cnt, 999UL ) ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations map" ));
    return NULL;
  }

  return mem;
}

fd_stake_delegations_t *
fd_stake_delegations_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_delegations_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_stake_delegations_t * stake_delegations = (fd_stake_delegations_t *)mem;

  if( FD_UNLIKELY( stake_delegations->magic != FD_STAKE_DELEGATIONS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid stake delegations magic" ));
    return NULL;
  }

  ulong map_chain_cnt = fd_stake_delegation_map_chain_cnt_est( stake_delegations->max_stake_accounts );

  FD_SCRATCH_ALLOC_INIT( l, stake_delegations );
  stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),     sizeof(fd_stake_delegations_t) );
  void * pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_pool_align(), fd_stake_delegation_pool_footprint( stake_delegations->max_stake_accounts ) );
  void * map_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_map_align(),  fd_stake_delegation_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( stake_delegations->max_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_stake_delegations_join: bad layout" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_stake_delegation_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake delegations pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_stake_delegation_map_join( map_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake delegations map" ));
    return NULL;
  }

  return stake_delegations;
}

void *
fd_stake_delegations_leave( fd_stake_delegations_t * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL self" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)self, fd_stake_delegations_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned self" ));
    return NULL;
  }

  fd_stake_delegations_t * stake_delegations = (fd_stake_delegations_t *)self;

  if( FD_UNLIKELY( stake_delegations->magic!=FD_STAKE_DELEGATIONS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid stake delegations magic" ));
    return NULL;
  }

  return (void *)self;
}

void *
fd_stake_delegations_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_delegations_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_stake_delegations_t * stake_delegations = (fd_stake_delegations_t *)mem;

  if( FD_UNLIKELY( stake_delegations->magic!=FD_STAKE_DELEGATIONS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid stake delegations magic" ));
    return NULL;
  }

  stake_delegations->magic = 0UL;

  return mem;
}

void
fd_stake_delegations_update( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account,
                             fd_pubkey_t const *      vote_account,
                             ulong                    stake,
                             ulong                    activation_epoch,
                             ulong                    deactivation_epoch,
                             ulong                    credits_observed,
                             double                   warmup_cooldown_rate ) {

  fd_stake_delegation_t * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }
  fd_stake_delegation_map_t * stake_delegation_map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  /* First, handle the case where the stake delegation already exists
     and we just need to update the entry. The reason we do a const idx
     query is to allow fd_stake_delegations_update to be called while
     iterating over the map. It is unsafe to call
     fd_stake_delegation_map_ele_query() during iteration, but we only
     need to change fields which are not used for pool/map management. */

  ulong idx = fd_stake_delegation_map_idx_query_const(
      stake_delegation_map,
      stake_account,
      ULONG_MAX,
      stake_delegation_pool );

  if( idx!=ULONG_MAX ) {

    fd_stake_delegation_t * stake_delegation = fd_stake_delegation_pool_ele( stake_delegation_pool, idx );
    if( FD_UNLIKELY( !stake_delegation ) ) {
      FD_LOG_CRIT(( "unable to retrieve stake delegation" ));
    }

    stake_delegation->vote_account         = *vote_account;
    stake_delegation->stake                = stake;
    stake_delegation->activation_epoch     = activation_epoch;
    stake_delegation->deactivation_epoch   = deactivation_epoch;
    stake_delegation->credits_observed     = credits_observed;
    stake_delegation->warmup_cooldown_rate = warmup_cooldown_rate;
    return;
  }

  /* Otherwise, try to acquire a new node and populate it. */
  if( FD_UNLIKELY( !fd_stake_delegation_pool_free( stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fd_stake_delegation_t * stake_delegation = fd_stake_delegation_pool_ele_acquire( stake_delegation_pool );
  if( FD_UNLIKELY( !stake_delegation ) ) {
    FD_LOG_CRIT(( "unable to acquire stake delegation" ));
  }

  stake_delegation->stake_account        = *stake_account;
  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = activation_epoch;
  stake_delegation->deactivation_epoch   = deactivation_epoch;
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = warmup_cooldown_rate;

  if( FD_UNLIKELY( !fd_stake_delegation_map_ele_insert(
        stake_delegation_map,
        stake_delegation,
        stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "unable to insert stake delegation into map" ));
  }

}

void
fd_stake_delegations_remove( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account ) {
  fd_stake_delegation_t * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }
  fd_stake_delegation_map_t * stake_delegation_map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  ulong delegation_idx = fd_stake_delegation_map_idx_query(
      stake_delegation_map,
      stake_account,
      ULONG_MAX,
      stake_delegation_pool );
  if( FD_UNLIKELY( delegation_idx == ULONG_MAX ) ) {
    /* The delegation was not found, nothing to do. */
    return;
  }

  ulong idx = fd_stake_delegation_map_idx_remove( stake_delegation_map, stake_account, ULONG_MAX, stake_delegation_pool );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
    return;
  }

  fd_stake_delegation_pool_idx_release( stake_delegation_pool, delegation_idx );
}
