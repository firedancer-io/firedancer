#include "fd_vote_states.h"

fd_vote_state_ele_t *
fd_vote_states_get_pool( fd_vote_states_t const * vote_states ) {
  FD_SCRATCH_ALLOC_INIT( l, vote_states );
  FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(), sizeof(fd_vote_states_t) );
  uchar * pool = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(), fd_vote_states_footprint( vote_states->max_vote_accounts ) );
  return fd_vote_state_pool_join( pool );
}

fd_vote_state_map_t *
fd_vote_states_get_map( fd_vote_states_t const * vote_states ) {
  FD_SCRATCH_ALLOC_INIT( l, vote_states );
  FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(),     sizeof(fd_vote_states_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_pool_align(), fd_vote_state_pool_footprint( vote_states->max_vote_accounts ) );
  ulong map_chain_cnt = fd_vote_state_map_chain_cnt_est( vote_states->max_vote_accounts );
  uchar * map = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_map_align(), fd_vote_state_map_footprint( map_chain_cnt ) );
  return fd_vote_state_map_join( map );
}

ulong
fd_vote_states_align( void ) {
  /* The align of the struct should be the max of the align of the data
     structures that it contains. In this case, this is the map, the
     pool, and the struct itself */
  return fd_ulong_max( fd_ulong_max( fd_vote_state_map_align(),
                       fd_vote_state_pool_align() ), alignof(fd_vote_states_t) );
}

ulong
fd_vote_states_footprint( ulong max_vote_accounts ) {

  ulong map_chain_cnt = fd_vote_state_map_chain_cnt_est( max_vote_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  fd_vote_states_align(),     sizeof(fd_vote_states_t) );
  l = FD_LAYOUT_APPEND( l,  fd_vote_state_pool_align(), fd_vote_state_pool_footprint( max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l,  fd_vote_state_map_align(),  fd_vote_state_map_footprint( map_chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_vote_states_align() );
}

void *
fd_vote_states_new( void * mem, ulong max_vote_accounts ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_vote_accounts ) ) {
    FD_LOG_WARNING(( "max_vote_accounts is 0" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_vote_states_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong map_chain_cnt = fd_vote_state_map_chain_cnt_est( max_vote_accounts );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_vote_states_t * vote_states = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(),     sizeof(fd_vote_states_t) );
  void *             pool_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_pool_align(), fd_vote_state_pool_footprint( max_vote_accounts ) );
  void *             map_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_map_align(),  fd_vote_state_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_vote_states_align() )!=(ulong)mem+fd_vote_states_footprint( max_vote_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_vote_states_new: bad layout" ));
    return NULL;
  }

  vote_states->magic             = FD_VOTE_STATES_MAGIC;
  vote_states->max_vote_accounts = max_vote_accounts;

  if( FD_UNLIKELY( !fd_vote_state_pool_new( pool_mem, max_vote_accounts ) ) ) {
    FD_LOG_WARNING(( "Failed to create vote states pool" ));
    return NULL;
  }

  /* TODO: The seed shouldn't be hardcoded. */
  if( FD_UNLIKELY( !fd_vote_state_map_new( map_mem, map_chain_cnt, 999UL ) ) ) {
    FD_LOG_WARNING(( "Failed to create vote states map" ));
    return NULL;
  }

  return mem;
}

fd_vote_states_t *
fd_vote_states_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_vote_states_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_vote_states_t * vote_states = (fd_vote_states_t *)mem;

  if( FD_UNLIKELY( vote_states->magic != FD_VOTE_STATES_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid vote states magic" ));
    return NULL;
  }

  ulong map_chain_cnt = fd_vote_state_map_chain_cnt_est( vote_states->max_vote_accounts );

  FD_SCRATCH_ALLOC_INIT( l, vote_states );
  vote_states     = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_states_align(),     sizeof(fd_vote_states_t) );
  void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_pool_align(), fd_vote_state_pool_footprint( vote_states->max_vote_accounts ) );
  void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_state_map_align(),  fd_vote_state_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_vote_states_align() )!=(ulong)mem+fd_vote_states_footprint( vote_states->max_vote_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_vote_states_join: bad layout" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_vote_state_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote states pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_vote_state_map_join( map_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote states map" ));
    return NULL;
  }

  return vote_states;
}

void *
fd_vote_states_leave( fd_vote_states_t * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL self" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)self, fd_vote_states_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned self" ));
    return NULL;
  }

  fd_vote_states_t * vote_states = (fd_vote_states_t *)self;

  if( FD_UNLIKELY( vote_states->magic!=FD_VOTE_STATES_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid vote states magic" ));
    return NULL;
  }

  return (void *)self;
}

void *
fd_vote_states_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_vote_states_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_vote_states_t * vote_states = (fd_vote_states_t *)mem;

  if( FD_UNLIKELY( vote_states->magic!=FD_VOTE_STATES_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid vote states magic" ));
    return NULL;
  }

  vote_states->magic = 0UL;

  return mem;
}

void
fd_vote_states_update( fd_vote_states_t * self,
                       fd_pubkey_t *      vote_account,
                       uchar              commission,
                       ulong              stake,
                       ulong              credits_cnt,
                       ushort *           epoch,
                       ulong *            credits,
                       ulong *            prev_credits ) {
  fd_vote_state_ele_t * vote_state_pool = fd_vote_states_get_pool( self );
  if( FD_UNLIKELY( !vote_state_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to vote state pool" ));
  }
  fd_vote_state_map_t * vote_state_map = fd_vote_states_get_map( self );
  if( FD_UNLIKELY( !vote_state_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to vote state map" ));
  }

  /* First, handle the case where the vote state already exists
     and we just need to update the entry. The reason we do a const idx
     query is to allow fd_vote_states_update to be called while
     iterating over the map. It is unsafe to call
     fd_vote_state_map_ele_query() during iteration, but we only
     need to change fields which are not used for pool/map management. */

  ulong idx = fd_vote_state_map_idx_query_const(
      vote_state_map,
      vote_account,
      ULONG_MAX,
      vote_state_pool );

  if( idx!=ULONG_MAX ) {

    fd_vote_state_ele_t * vote_state = fd_vote_state_pool_ele( vote_state_pool, idx );
    if( FD_UNLIKELY( !vote_state ) ) {
      FD_LOG_CRIT(( "unable to retrieve vote state" ));
    }

    /* TODO: can do something smarter where we only update the
       comission and the credits coresponding to the new epoch. */
    vote_state->commission  = commission;
    vote_state->stake       = stake;
    vote_state->credits_cnt = credits_cnt;
    for( ulong i=0UL; i<credits_cnt; i++ ) {
      vote_state->epoch[i]        = epoch[i];
      vote_state->credits[i]      = credits[i];
      vote_state->prev_credits[i] = prev_credits[i];
    }
    return;
  }

  /* If the vote state does not exist, we need to create a new entry. */
  /* Otherwise, try to acquire a new node and populate it. */
  if( FD_UNLIKELY( !fd_vote_state_pool_free( vote_state_pool ) ) ) {
    FD_LOG_CRIT(( "no free vote states in pool" ));
  }

  fd_vote_state_ele_t * vote_state = fd_vote_state_pool_ele_acquire( vote_state_pool );
  if( FD_UNLIKELY( !vote_state ) ) {
    FD_LOG_CRIT(( "unable to acquire vote state" ));
  }

  vote_state->commission  = commission;
  vote_state->stake       = stake;
  vote_state->credits_cnt = credits_cnt;
  for( ulong i=0UL; i<credits_cnt; i++ ) {
    vote_state->epoch[i]        = epoch[i];
    vote_state->credits[i]      = credits[i];
    vote_state->prev_credits[i] = prev_credits[i];
  }
}

void
fd_vote_states_remove( fd_vote_states_t *  vote_states,
                       fd_pubkey_t const * vote_account ) {
  fd_vote_state_ele_t * vote_state_pool = fd_vote_states_get_pool( vote_states );
  if( FD_UNLIKELY( !vote_state_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }
  fd_vote_state_map_t * vote_state_map = fd_vote_states_get_map( vote_states );
  if( FD_UNLIKELY( !vote_state_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  ulong vote_state_idx = fd_vote_state_map_idx_query(
      vote_state_map,
      vote_account,
      ULONG_MAX,
      vote_state_pool );
  if( FD_UNLIKELY( vote_state_idx == ULONG_MAX ) ) {
    /* The vote state was not found, nothing to do. */
    return;
  }

  ulong idx = fd_vote_state_map_idx_remove( vote_state_map, vote_account, ULONG_MAX, vote_state_pool );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
    return;
  }

  fd_vote_state_pool_idx_release( vote_state_pool, vote_state_idx );
}
