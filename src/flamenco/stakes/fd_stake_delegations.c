#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_pipe.h"
#include "../runtime/program/fd_stake_program.h"

#define POOL_NAME  stake_delegation_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               stake_delegation_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_funk_rec_key_hash1( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

static inline fd_stake_delegation_t *
fd_stake_delegations_get_pool( fd_stake_delegations_t const * stake_delegations ) {
  return stake_delegation_pool_join( (uchar *)stake_delegations + stake_delegations->pool_offset_ );
}

static inline stake_delegation_map_t *
fd_stake_delegations_get_map( fd_stake_delegations_t const * stake_delegations ) {
  return stake_delegation_map_join( (uchar *)stake_delegations + stake_delegations->map_offset_ );
}

ulong
fd_stake_delegations_align( void ) {
  /* The align of the struct should be the max of the align of the data
     structures that it contains. In this case, this is the map, the
     pool, and the struct itself. */
  return fd_ulong_max( fd_ulong_max( stake_delegation_map_align(),
                       stake_delegation_pool_align() ), alignof(fd_stake_delegations_t) );
}

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts ) {

  ulong map_chain_cnt = stake_delegation_map_chain_cnt_est( max_stake_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(),  sizeof(fd_stake_delegations_t) );
  l = FD_LAYOUT_APPEND( l, stake_delegation_pool_align(), stake_delegation_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, stake_delegation_map_align(),  stake_delegation_map_footprint( map_chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_stake_delegations_align() );
}

void *
fd_stake_delegations_new( void * mem,
                          ulong  seed,
                          ulong  max_stake_accounts ) {
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

  ulong map_chain_cnt = stake_delegation_map_chain_cnt_est( max_stake_accounts );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_t * stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),  sizeof(fd_stake_delegations_t) );
  void *                   pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, stake_delegation_pool_align(), stake_delegation_pool_footprint( max_stake_accounts ) );
  void *                   map_mem           = FD_SCRATCH_ALLOC_APPEND( l, stake_delegation_map_align(),  stake_delegation_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( max_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_stake_delegations_new: bad layout" ));
    return NULL;
  }

  fd_stake_delegation_t * stake_delegation_pool = stake_delegation_pool_join( stake_delegation_pool_new( pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !stake_delegation_map_new( map_mem, map_chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations map" ));
    return NULL;
  }

  stake_delegations->pool_offset_        = (ulong)pool_mem - (ulong)mem;
  stake_delegations->map_offset_         = (ulong)map_mem - (ulong)mem;
  stake_delegations->max_stake_accounts_ = max_stake_accounts;

  for( uint i=0U; i<max_stake_accounts; i++ ) {
    fd_stake_delegation_t * stake_delegation = stake_delegation_pool_ele( stake_delegation_pool, i );
    stake_delegation->idx = i;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( stake_delegations->magic ) = FD_STAKE_DELEGATIONS_MAGIC;
  FD_COMPILER_MFENCE();

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

  ulong map_chain_cnt = stake_delegation_map_chain_cnt_est( stake_delegations->max_stake_accounts_ );

  FD_SCRATCH_ALLOC_INIT( l, stake_delegations );
  stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),  sizeof(fd_stake_delegations_t) );
  void * pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, stake_delegation_pool_align(), stake_delegation_pool_footprint( stake_delegations->max_stake_accounts_ ) );
  void * map_mem    = FD_SCRATCH_ALLOC_APPEND( l, stake_delegation_map_align(),  stake_delegation_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( stake_delegations->max_stake_accounts_ ) ) ) {
    FD_LOG_WARNING(( "fd_stake_delegations_join: bad layout" ));
    return NULL;
  }

  if( FD_UNLIKELY( !stake_delegation_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake delegations pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !stake_delegation_map_join( map_mem ) ) ) {
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
fd_stake_delegations_init( fd_stake_delegations_t * stake_delegations ) {
  stake_delegation_map_t * stake_delegation_map  = fd_stake_delegations_get_map( stake_delegations );
  stake_delegation_map_reset( stake_delegation_map );
  fd_stake_delegation_t * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  stake_delegation_pool_reset( stake_delegation_pool );
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
  stake_delegation_map_t * stake_delegation_map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  /* First, handle the case where the stake delegation already exists
     and we just need to update the entry. The reason we do a const idx
     query is to allow fd_stake_delegations_update to be called while
     iterating over the map. It is unsafe to call
     fd_stake_delegation_map_ele_query() during iteration, but we only
     need to change fields which are not used for pool/map management. */

  ulong idx = stake_delegation_map_idx_query_const(
      stake_delegation_map,
      stake_account,
      UINT_MAX,
      stake_delegation_pool );

  if( idx!=UINT_MAX ) {

    fd_stake_delegation_t * stake_delegation = stake_delegation_pool_ele( stake_delegation_pool, idx );
    if( FD_UNLIKELY( !stake_delegation ) ) {
      FD_LOG_CRIT(( "unable to retrieve stake delegation" ));
    }

    stake_delegation->vote_account         = *vote_account;
    stake_delegation->stake                = stake;
    stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
    stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
    stake_delegation->credits_observed     = credits_observed;
    stake_delegation->warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_enum( warmup_cooldown_rate );
    stake_delegation->is_tombstone         = 0;
    return;
  }

  /* Otherwise, try to acquire a new node and populate it. */
  if( FD_UNLIKELY( !stake_delegation_pool_free( stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fd_stake_delegation_t * stake_delegation = stake_delegation_pool_ele_acquire( stake_delegation_pool );

  stake_delegation->stake_account        = *stake_account;
  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
  stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_enum( warmup_cooldown_rate );
  stake_delegation->is_tombstone         = 0;

  if( FD_UNLIKELY( !stake_delegation_map_ele_insert(
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
  stake_delegation_map_t * stake_delegation_map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  ulong delegation_idx = stake_delegation_map_idx_query(
      stake_delegation_map,
      stake_account,
      UINT_MAX,
      stake_delegation_pool );

  /* If we are not configured to leave tombstones, we need to remove
     the entry from the map and release it from the pool. */
  if( FD_UNLIKELY( delegation_idx==UINT_MAX ) ) {
    /* The delegation was not found, nothing to do. */
    return;
  }

  /* To be safe, we should set the next_ pointer to the null idx. */

  fd_stake_delegation_t * stake_delegation = stake_delegation_pool_ele( stake_delegation_pool, delegation_idx );
  if( FD_UNLIKELY( !stake_delegation ) ) {
    FD_LOG_CRIT(( "unable to retrieve stake delegation" ));
  }

  ulong idx = stake_delegation_map_idx_remove( stake_delegation_map, stake_account, UINT_MAX, stake_delegation_pool );
  if( FD_UNLIKELY( idx==UINT_MAX ) ) {
    FD_LOG_CRIT(( "unable to remove stake delegation" ));
  }

  stake_delegation->next_ = UINT_MAX;

  stake_delegation_pool_idx_release( stake_delegation_pool, delegation_idx );
}

void
fd_stake_delegations_refresh( fd_stake_delegations_t *  stake_delegations,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid ) {

  stake_delegation_map_t * map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }
  fd_stake_delegation_t * pool = fd_stake_delegations_get_pool( stake_delegations );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }

  fd_accdb_ro_pipe_t ro_pipe[1];
  fd_accdb_ro_pipe_init( ro_pipe, accdb, xid );
  ulong const job_cnt = fd_stake_delegations_cnt( stake_delegations );
  for( ulong i=0UL; i<job_cnt; i++ ) {

    /* stream out read requests */
    fd_accdb_ro_pipe_enqueue( ro_pipe, &pool[ i ].stake_account );
    if( FD_UNLIKELY( i+1UL==job_cnt ) ) {
      fd_accdb_ro_pipe_flush( ro_pipe );
    }

    /* handle a batch of completions */
    fd_accdb_ro_t * ro;
    while( (ro = fd_accdb_ro_pipe_poll( ro_pipe )) ) {
      fd_pubkey_t const * address = fd_accdb_ref_address( ro );
      fd_stake_delegation_t * delegation = stake_delegation_map_ele_query( map, address, NULL, pool );
      if( FD_UNLIKELY( !delegation ) ) continue;

      if( FD_UNLIKELY( fd_accdb_ref_lamports( ro )==0UL ) ) goto remove;

      fd_stake_state_v2_t stake;
      int err = fd_stake_get_state( ro->meta, &stake );
      if( FD_UNLIKELY( err ) ) goto remove;
      if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake ) ) ) goto remove;

      fd_stake_delegations_update(
          stake_delegations,
          address,
          &stake.inner.stake.stake.delegation.voter_pubkey,
          stake.inner.stake.stake.delegation.stake,
          stake.inner.stake.stake.delegation.activation_epoch,
          stake.inner.stake.stake.delegation.deactivation_epoch,
          stake.inner.stake.stake.credits_observed,
          stake.inner.stake.stake.delegation.warmup_cooldown_rate );
      continue; /* ok */

    remove:
      stake_delegation_map_idx_remove( map, address, UINT_MAX, pool );
      stake_delegation_pool_ele_release( pool, delegation );
    }
  }
  fd_accdb_ro_pipe_fini( ro_pipe );
}

fd_stake_delegation_t const *
fd_stake_delegations_query( fd_stake_delegations_t const * stake_delegations,
                            fd_pubkey_t const *            stake_account ) {

  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
    return NULL;
  }

  if( FD_UNLIKELY( !stake_account ) ) {
    FD_LOG_CRIT(( "NULL stake_account" ));
    return NULL;
  }

  fd_stake_delegation_t const * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }

  stake_delegation_map_t const * stake_delegation_map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  return stake_delegation_map_ele_query_const(
      stake_delegation_map,
      stake_account,
      NULL,
      stake_delegation_pool );
}

ulong
fd_stake_delegations_cnt( fd_stake_delegations_t const * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  fd_stake_delegation_t const * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  return stake_delegation_pool_used( stake_delegation_pool );
}

fd_stake_delegation_t *
fd_stake_delegations_iter_ele( fd_stake_delegations_iter_t * iter ) {
  ulong idx = stake_delegation_map_iter_idx( iter->iter, iter->map, iter->pool );
  return stake_delegation_pool_ele( iter->pool, idx );
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  iter->map  = fd_stake_delegations_get_map( stake_delegations );
  iter->pool = fd_stake_delegations_get_pool( stake_delegations );
  iter->iter = stake_delegation_map_iter_init( iter->map, iter->pool );

  return iter;
}

void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter ) {
  iter->iter = stake_delegation_map_iter_next( iter->iter, iter->map, iter->pool );
}

int
fd_stake_delegations_iter_done( fd_stake_delegations_iter_t * iter ) {
  return stake_delegation_map_iter_done( iter->iter, iter->map, iter->pool );
}

#define POOL_NAME  stake_delegation_delta_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME             fork_dlist
#define DLIST_ELE_T            fd_stake_delegation_t
#define DLIST_PREV             prev
#define DLIST_NEXT             next
#define DLIST_IDX_T            uint
#include "../../util/tmpl/fd_dlist.c"

struct pool {
  ushort next;
};
typedef struct pool pool_t;

#define POOL_NAME  pool
#define POOL_T     pool_t
#define POOL_NEXT  next
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

static inline fd_stake_delegation_t *
get_stake_delegation_pool( fd_stake_delegations_delta_t * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->pool_offset_ );
}

static inline pool_t *
get_fork_pool( fd_stake_delegations_delta_t * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->fork_pool_offset_ );
}

static inline fork_dlist_t *
get_fork_dlist( fd_stake_delegations_delta_t * stake_delegations,
                ushort                         fork_idx ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->dlist_offsets_[ fork_idx ] );
}

ulong
fd_stake_delegations_delta_align( void ) {
  return 128UL;
}

ulong
fd_stake_delegations_delta_footprint( ulong max_stake_accounts,
                                      ulong max_live_slots ) {

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_delta_align(),  sizeof(fd_stake_delegations_delta_t) );
  l = FD_LAYOUT_APPEND( l, stake_delegation_delta_pool_align(), stake_delegation_delta_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, pool_align(),                        pool_footprint( max_live_slots ) );
  for( ushort i=0; i<max_live_slots; i++ ) {
    l = FD_LAYOUT_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
  }

  return FD_LAYOUT_FINI( l, fd_stake_delegations_delta_align() );
}

void *
fd_stake_delegations_delta_new( void * mem,
                                ulong  max_stake_accounts,
                                ulong  max_live_slots ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_delegations_delta_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_live_slots>FD_STAKE_DELEGATIONS_DELTA_FORK_MAX )) {
    FD_LOG_WARNING(( "max_live_slots is too large" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_delta_t * stake_delegations_delta = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_delta_align(),  sizeof(fd_stake_delegations_delta_t) );
  void *                         index_pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, stake_delegation_delta_pool_align(), stake_delegation_delta_pool_footprint( max_stake_accounts ) );
  void *                         pool_mem                = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),                        pool_footprint( max_live_slots ) );
  for( ushort i=0; i<max_live_slots; i++ ) {
    void * fork_dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
    fork_dlist_t * fork_dlist = fork_dlist_join( fork_dlist_new( fork_dlist_mem ) );
    if( FD_UNLIKELY( !fork_dlist ) ) {
      FD_LOG_WARNING(( "Failed to create fork dlist" ));
      return NULL;
    }
    stake_delegations_delta->dlist_offsets_[ i ] = (ulong)fork_dlist - (ulong)mem;
  }

  fd_stake_delegation_t * stake_delegation_pool = stake_delegation_delta_pool_join( stake_delegation_delta_pool_new( index_pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation pool" ));
    return NULL;
  }
  stake_delegations_delta->pool_offset_ = (ulong)stake_delegation_pool - (ulong)mem;

  pool_t * fork_pool = pool_join( pool_new( pool_mem, max_live_slots ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }
  stake_delegations_delta->fork_pool_offset_ = (ulong)fork_pool - (ulong)mem;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( stake_delegations_delta->magic ) = FD_STAKE_DELEGATIONS_DELTA_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_stake_delegations_delta_t *
fd_stake_delegations_delta_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_delegations_delta_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_stake_delegations_delta_t * stake_delegations_delta = (fd_stake_delegations_delta_t *)mem;

  if( FD_UNLIKELY( stake_delegations_delta->magic != FD_STAKE_DELEGATIONS_DELTA_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid stake delegations delta magic" ));
    return NULL;
  }

  return stake_delegations_delta;
}

ushort
fd_stake_delegations_delta_new_fork( fd_stake_delegations_delta_t * stake_delegations ) {
  pool_t * fork_pool = get_fork_pool( stake_delegations );
  if( FD_UNLIKELY( !pool_free( fork_pool ) ) ) {
    FD_LOG_CRIT(( "no free forks in pool" ));
  }

  ushort fork_idx = (ushort)pool_idx_acquire( fork_pool );

  return fork_idx;
}

void
fd_stake_delegations_delta_update( fd_stake_delegations_delta_t * stake_delegations,
                                   ushort                         fork_idx,
                                   fd_pubkey_t const *            stake_account,
                                   fd_pubkey_t const *            vote_account,
                                   ulong                          stake,
                                   ulong                          activation_epoch,
                                   ulong                          deactivation_epoch,
                                   ulong                          credits_observed,
                                   double                         warmup_cooldown_rate ) {
  fd_stake_delegation_t * stake_delegation_pool = get_stake_delegation_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_delta_pool_free( stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );

  fd_stake_delegation_t * stake_delegation = stake_delegation_delta_pool_ele_acquire( stake_delegation_pool );
  if( FD_UNLIKELY( !stake_delegation ) ) {
    FD_LOG_CRIT(( "Failed to acquire stake delegation" ));
  }

  fork_dlist_ele_push_tail( fork_dlist, stake_delegation, stake_delegation_pool );

  stake_delegation->stake_account        = *stake_account;
  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
  stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_enum( warmup_cooldown_rate );
  stake_delegation->is_tombstone         = 0;
}

void
fd_stake_delegations_delta_remove( fd_stake_delegations_delta_t * stake_delegations,
                                   ushort                         fork_idx,
                                   fd_pubkey_t const *            stake_account ) {
  fd_stake_delegation_t * stake_delegation_pool = get_stake_delegation_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_delta_pool_free( stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fd_stake_delegation_t * stake_delegation = stake_delegation_delta_pool_ele_acquire( stake_delegation_pool );
  if( FD_UNLIKELY( !stake_delegation ) ) {
    FD_LOG_CRIT(( "Failed to acquire stake delegation" ));
  }

  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );
  fork_dlist_ele_push_tail( fork_dlist, stake_delegation, stake_delegation_pool );

  stake_delegation->stake_account = *stake_account;
  stake_delegation->is_tombstone  = 1;
}

void
fd_stake_delegations_delta_evict_fork( fd_stake_delegations_delta_t * stake_delegations,
                                       ushort                         fork_idx ) {
  if( fork_idx==USHORT_MAX ) return;

  fd_stake_delegation_t * stake_delegation_pool = get_stake_delegation_pool( stake_delegations );

  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );

  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( fork_dlist, stake_delegation_pool );
       !fork_dlist_iter_done( iter, fork_dlist, stake_delegation_pool );
       iter = fork_dlist_iter_fwd_next( iter, fork_dlist, stake_delegation_pool ) ) {
    fd_stake_delegation_t * stake_delegation = fork_dlist_iter_ele( iter, fork_dlist, stake_delegation_pool );

    stake_delegation_delta_pool_ele_release( stake_delegation_pool, stake_delegation );
  }
  fork_dlist_remove_all( fork_dlist, stake_delegation_pool );

  pool_idx_release( get_fork_pool( stake_delegations ), fork_idx );
}

ulong
fd_stake_delegations_delta_iter_init( fd_stake_delegations_delta_t * stake_delegations,
                                      ushort                         fork_idx ) {

  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation_pool = get_stake_delegation_pool( stake_delegations );
  return fork_dlist_iter_fwd_init( fork_dlist, stake_delegation_pool );
}

int
fd_stake_delegations_delta_iter_done( fd_stake_delegations_delta_t * stake_delegations,
                                      ushort                         fork_idx,
                                      ulong                          iter ) {
  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation_pool = get_stake_delegation_pool( stake_delegations );
  return fork_dlist_iter_done( iter, fork_dlist, stake_delegation_pool );
}

ulong
fd_stake_delegations_delta_iter_next( fd_stake_delegations_delta_t * stake_delegations,
                                      ushort                         fork_idx,
                                      ulong                          iter ) {
  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation_pool = get_stake_delegation_pool( stake_delegations );
  return fork_dlist_iter_fwd_next( iter, fork_dlist, stake_delegation_pool );
}

fd_stake_delegation_t *
fd_stake_delegations_delta_iter_ele( fd_stake_delegations_delta_t * stake_delegations,
                                     ushort                         fork_idx,
                                     ulong                          iter ) {
  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation_pool = get_stake_delegation_pool( stake_delegations );
  return fork_dlist_iter_ele( iter, fork_dlist, stake_delegation_pool );
}
