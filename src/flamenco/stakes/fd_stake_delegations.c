#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_pipe.h"
#include "../runtime/program/fd_stake_program.h"

#define POOL_NAME  root_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               root_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_funk_rec_key_hash1( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME  delta_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME             fork_dlist
#define DLIST_ELE_T            fd_stake_delegation_t
#define DLIST_PREV             prev_
#define DLIST_NEXT             next_
#define DLIST_IDX_T            uint
#include "../../util/tmpl/fd_dlist.c"

struct fork_pool_ele {
  ushort next;
};
typedef struct fork_pool_ele fork_pool_ele_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_pool_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

/* Internal getters for base map + pool */

static inline fd_stake_delegation_t *
get_root_pool( fd_stake_delegations_t const * stake_delegations ) {
  return root_pool_join( (uchar *)stake_delegations + stake_delegations->pool_offset_ );
}

static inline root_map_t *
get_root_map( fd_stake_delegations_t const * stake_delegations ) {
  return root_map_join( (uchar *)stake_delegations + stake_delegations->map_offset_ );
}

/* Internal getters for delta pool + fork structures */

static inline fd_stake_delegation_t *
get_delta_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->delta_pool_offset_ );
}

static inline fork_pool_ele_t *
get_fork_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->fork_pool_offset_ );
}

static inline fork_dlist_t *
get_fork_dlist( fd_stake_delegations_t const * stake_delegations,
                ushort                         fork_idx ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->dlist_offsets_[ fork_idx ] );
}

ulong
fd_stake_delegations_align( void ) {
  return FD_STAKE_DELEGATIONS_ALIGN;
}

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts,
                                ulong expected_stake_accounts,
                                ulong max_live_slots ) {

  ulong map_chain_cnt = root_map_chain_cnt_est( expected_stake_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  l = FD_LAYOUT_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, delta_pool_align(),           delta_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    l = FD_LAYOUT_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
  }

  return FD_LAYOUT_FINI( l, fd_stake_delegations_align() );
}

void *
fd_stake_delegations_new( void * mem,
                          ulong  seed,
                          ulong  max_stake_accounts,
                          ulong  expected_stake_accounts,
                          ulong  max_live_slots ) {
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

  if( FD_UNLIKELY( max_live_slots>FD_STAKE_DELEGATIONS_FORK_MAX ) ) {
    FD_LOG_WARNING(( "max_live_slots is too large" ));
    return NULL;
  }

  ulong map_chain_cnt = root_map_chain_cnt_est( expected_stake_accounts );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_t * stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  void *                   pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  void *                   map_mem           = FD_SCRATCH_ALLOC_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  void *                   delta_pool_mem    = FD_SCRATCH_ALLOC_APPEND( l, delta_pool_align(),           delta_pool_footprint( max_stake_accounts ) );
  void *                   fork_pool_mem     = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  for( ushort i=0; i<(ushort)max_live_slots; i++ ) {
    void * fork_dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
    fork_dlist_t * dlist = fork_dlist_join( fork_dlist_new( fork_dlist_mem ) );
    if( FD_UNLIKELY( !dlist ) ) {
      FD_LOG_WARNING(( "Failed to create fork dlist" ));
      return NULL;
    }
    stake_delegations->dlist_offsets_[ i ] = (ulong)dlist - (ulong)mem;
  }

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( max_stake_accounts, expected_stake_accounts, max_live_slots ) ) ) {
    FD_LOG_WARNING(( "fd_stake_delegations_new: bad layout" ));
    return NULL;
  }

  /* Initialize the root pool and map */

  fd_stake_delegation_t * root_pool = root_pool_join( root_pool_new( pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !root_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !root_map_new( map_mem, map_chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations map" ));
    return NULL;
  }

  /* Initialize the delta pool and fork pool */

  fd_stake_delegation_t * delta_pool = delta_pool_join( delta_pool_new( delta_pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !delta_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation delta pool" ));
    return NULL;
  }

  fork_pool_ele_t * fp = fork_pool_join( fork_pool_new( fork_pool_mem, max_live_slots ) );
  if( FD_UNLIKELY( !fp ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }

  stake_delegations->expected_stake_accounts_ = expected_stake_accounts;
  stake_delegations->pool_offset_             = (ulong)pool_mem - (ulong)mem;
  stake_delegations->map_offset_              = (ulong)map_mem - (ulong)mem;
  stake_delegations->max_stake_accounts_      = max_stake_accounts;
  stake_delegations->delta_pool_offset_       = (ulong)delta_pool - (ulong)mem;
  stake_delegations->fork_pool_offset_        = (ulong)fp - (ulong)mem;

  fd_rwlock_new( &stake_delegations->lock );

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

  if( FD_UNLIKELY( !root_pool_join( (uchar *)mem + stake_delegations->pool_offset_ ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake delegations pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !root_map_join( (uchar *)mem + stake_delegations->map_offset_ ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake delegations map" ));
    return NULL;
  }

  if( FD_UNLIKELY( !delta_pool_join( (uchar *)mem + stake_delegations->delta_pool_offset_ ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake delegation delta pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fork_pool_join( (uchar *)mem + stake_delegations->fork_pool_offset_ ) ) ) {
    FD_LOG_WARNING(( "Failed to join fork pool" ));
    return NULL;
  }

  return stake_delegations;
}

void
fd_stake_delegations_init( fd_stake_delegations_t * stake_delegations ) {
  root_map_t * map  = get_root_map( stake_delegations );
  root_map_reset( map );
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_pool_reset( pool );
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
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }
  root_map_t * map = get_root_map( stake_delegations );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  /* First, handle the case where the stake delegation already exists
     and we just need to update the entry. The reason we do a const idx
     query is to allow fd_stake_delegations_update to be called while
     iterating over the map. It is unsafe to call
     fd_stake_delegation_map_ele_query() during iteration, but we only
     need to change fields which are not used for pool/map management. */

  ulong idx = root_map_idx_query_const(
      map,
      stake_account,
      UINT_MAX,
      pool );

  if( idx!=UINT_MAX ) {

    fd_stake_delegation_t * stake_delegation = root_pool_ele( pool, idx );
    if( FD_UNLIKELY( !stake_delegation ) ) {
      FD_LOG_CRIT(( "unable to retrieve stake delegation" ));
    }

    stake_delegation->vote_account         = *vote_account;
    stake_delegation->stake                = stake;
    stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
    stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
    stake_delegation->credits_observed     = credits_observed;
    stake_delegation->warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_enum( warmup_cooldown_rate );
    stake_delegation->dne_in_root          = 0;
    stake_delegation->delta_idx            = UINT_MAX;
    return;
  }

  /* Otherwise, try to acquire a new node and populate it. */
  if( FD_UNLIKELY( !root_pool_free( pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fd_stake_delegation_t * stake_delegation = root_pool_ele_acquire( pool );

  stake_delegation->stake_account        = *stake_account;
  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
  stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_enum( warmup_cooldown_rate );
  stake_delegation->dne_in_root          = 0;
  stake_delegation->delta_idx            = UINT_MAX;

  if( FD_UNLIKELY( !root_map_ele_insert(
        map,
        stake_delegation,
        pool ) ) ) {
    FD_LOG_CRIT(( "unable to insert stake delegation into map" ));
  }

}

void
fd_stake_delegations_remove( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }
  root_map_t * map = get_root_map( stake_delegations );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  ulong delegation_idx = root_map_idx_query(
      map,
      stake_account,
      UINT_MAX,
      pool );

  if( FD_UNLIKELY( delegation_idx==UINT_MAX ) ) {
    return;
  }

  fd_stake_delegation_t * stake_delegation = root_pool_ele( pool, delegation_idx );
  if( FD_UNLIKELY( !stake_delegation ) ) {
    FD_LOG_CRIT(( "unable to retrieve stake delegation" ));
  }

  ulong idx = root_map_idx_remove( map, stake_account, UINT_MAX, pool );
  if( FD_UNLIKELY( idx==UINT_MAX ) ) {
    FD_LOG_CRIT(( "unable to remove stake delegation" ));
  }

  stake_delegation->next_ = UINT_MAX;

  root_pool_idx_release( pool, delegation_idx );
}

void
fd_stake_delegations_refresh( fd_stake_delegations_t *  stake_delegations,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid ) {

  root_map_t * map = get_root_map( stake_delegations );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
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
      fd_stake_delegation_t * delegation = root_map_ele_query( map, address, NULL, pool );
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
      root_map_idx_remove( map, address, UINT_MAX, pool );
      root_pool_ele_release( pool, delegation );
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

  fd_stake_delegation_t const * pool = get_root_pool( stake_delegations );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }

  root_map_t const * map = get_root_map( stake_delegations );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  return root_map_ele_query_const(
      map,
      stake_account,
      NULL,
      pool );
}

ulong
fd_stake_delegations_cnt( fd_stake_delegations_t const * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  fd_stake_delegation_t const * pool = get_root_pool( stake_delegations );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  return root_pool_used( pool );
}

/* Fork-aware delta operations */

ushort
fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_pool_ele_t * fp = get_fork_pool( stake_delegations );
  if( FD_UNLIKELY( !fork_pool_free( fp ) ) ) {
    FD_LOG_CRIT(( "no free forks in pool" ));
  }

  ushort fork_idx = (ushort)fork_pool_idx_acquire( fp );
  fd_rwlock_unwrite( &stake_delegations->lock );

  return fork_idx;
}

void
fd_stake_delegations_fork_update( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  double                   warmup_cooldown_rate ) {
  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  if( FD_UNLIKELY( !delta_pool_free( delta_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );

  fd_stake_delegation_t * stake_delegation = delta_pool_ele_acquire( delta_pool );

  fork_dlist_ele_push_tail( dlist, stake_delegation, delta_pool );

  stake_delegation->stake_account        = *stake_account;
  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
  stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_enum( warmup_cooldown_rate );
  stake_delegation->is_tombstone         = 0;

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account ) {

  fd_rwlock_write( &stake_delegations->lock );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  if( FD_UNLIKELY( !delta_pool_free( delta_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fd_stake_delegation_t * stake_delegation = delta_pool_ele_acquire( delta_pool );

  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );
  fork_dlist_ele_push_tail( dlist, stake_delegation, delta_pool );

  stake_delegation->stake_account = *stake_account;
  stake_delegation->is_tombstone  = 1;

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_evict_fork( fd_stake_delegations_t * stake_delegations,
                                 ushort                   fork_idx ) {
  if( fork_idx==USHORT_MAX ) return;

  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );

  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );
  while( !fork_dlist_is_empty( dlist, delta_pool ) ) {
    fd_stake_delegation_t * ele = fork_dlist_ele_pop_head( dlist, delta_pool );
    delta_pool_ele_release( delta_pool, ele );
  }

  fork_pool_idx_release( get_fork_pool( stake_delegations ), fork_idx );

  fd_rwlock_unwrite( &stake_delegations->lock );
}

ulong
fd_stake_delegations_fork_iter_init( fd_stake_delegations_t * stake_delegations,
                                     ushort                   fork_idx ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  return fork_dlist_iter_fwd_init( dlist, delta_pool );
}

int
fd_stake_delegations_fork_iter_done( fd_stake_delegations_t * stake_delegations,
                                     ushort                   fork_idx,
                                     ulong                    iter ) {
  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  return fork_dlist_iter_done( iter, dlist, delta_pool );
}

ulong
fd_stake_delegations_fork_iter_next( fd_stake_delegations_t * stake_delegations,
                                     ushort                   fork_idx,
                                     ulong                    iter ) {
  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  return fork_dlist_iter_fwd_next( iter, dlist, delta_pool );
}

fd_stake_delegation_t *
fd_stake_delegations_fork_iter_ele( fd_stake_delegations_t * stake_delegations,
                                    ushort                   fork_idx,
                                    ulong                    iter ) {
  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  return fork_dlist_iter_ele( iter, dlist, delta_pool );
}

void
fd_stake_delegations_fork_iter_fini( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_unwrite( &stake_delegations->lock );
}

/* Combined base+delta iterator */

fd_stake_delegation_t *
fd_stake_delegations_iter_ele( fd_stake_delegations_iter_t * iter ) {
  ulong idx = root_map_iter_idx( iter->iter, iter->map, iter->pool );
  fd_stake_delegation_t * stake_delegation = root_pool_ele( iter->pool, idx );
  if( FD_UNLIKELY( stake_delegation->delta_idx!=UINT_MAX ) ) {
    return (fd_stake_delegation_t *)delta_pool_ele( iter->delta_pool, stake_delegation->delta_idx );
  }
  return stake_delegation;
}

ulong
fd_stake_delegations_iter_idx( fd_stake_delegations_iter_t * iter ) {
  return root_map_iter_idx( iter->iter, iter->map, iter->pool );
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  iter->map        = get_root_map( stake_delegations );
  iter->pool       = get_root_pool( stake_delegations );
  iter->iter       = root_map_iter_init( iter->map, iter->pool );
  iter->delta_pool = get_delta_pool( stake_delegations );

  return iter;
}

void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter ) {
  iter->iter = root_map_iter_next( iter->iter, iter->map, iter->pool );
}

int
fd_stake_delegations_iter_done( fd_stake_delegations_iter_t * iter ) {
  return root_map_iter_done( iter->iter, iter->map, iter->pool );
}

void
fd_stake_delegations_mark_delta( fd_stake_delegations_t * stake_delegations,
                                 ushort                   fork_idx ) {

  root_map_t *            map  = get_root_map( stake_delegations );
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );

  for( ulong i = fd_stake_delegations_fork_iter_init( stake_delegations, fork_idx );
        !fd_stake_delegations_fork_iter_done( stake_delegations, fork_idx, i );
        i = fd_stake_delegations_fork_iter_next( stake_delegations, fork_idx, i ) ) {
    fd_stake_delegation_t * delta_delegation = fd_stake_delegations_fork_iter_ele( stake_delegations, fork_idx, i );

    fd_stake_delegation_t * base_delegation = root_map_ele_query( map, &delta_delegation->stake_account, NULL, pool);
    if( FD_UNLIKELY( !base_delegation ) ) {
      base_delegation                = root_pool_ele_acquire( pool );
      base_delegation->stake_account = delta_delegation->stake_account;
      root_map_ele_insert( map, base_delegation, pool );

      base_delegation->dne_in_root = 1;
      base_delegation->delta_idx   = (uint)delta_pool_idx( delta_pool, delta_delegation );
    } else {
      base_delegation->delta_idx = (uint)delta_pool_idx( delta_pool, delta_delegation );
    }
  }
  fd_stake_delegations_fork_iter_fini( stake_delegations );
}

void
fd_stake_delegations_unmark_delta( fd_stake_delegations_t * stake_delegations,
                                   ushort                   fork_idx ) {

  root_map_t *            map  = get_root_map( stake_delegations );
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );

  for( ulong i = fd_stake_delegations_fork_iter_init( stake_delegations, fork_idx );
       !fd_stake_delegations_fork_iter_done( stake_delegations, fork_idx, i );
       i = fd_stake_delegations_fork_iter_next( stake_delegations, fork_idx, i ) ) {
    fd_stake_delegation_t * delta_delegation = fd_stake_delegations_fork_iter_ele( stake_delegations, fork_idx, i );

    fd_stake_delegation_t * base_delegation = root_map_ele_query( map, &delta_delegation->stake_account, NULL, pool );
    if( FD_UNLIKELY( !base_delegation ) ) {
      continue;
    }

    if( FD_UNLIKELY( base_delegation->dne_in_root )) {
      base_delegation->dne_in_root = 0;
      base_delegation->delta_idx   = UINT_MAX;
      root_map_ele_remove( map, &delta_delegation->stake_account, NULL, pool );
      root_pool_ele_release( pool, base_delegation );
    } else {
      base_delegation->delta_idx = UINT_MAX;
    }
  }
  fd_stake_delegations_fork_iter_fini( stake_delegations );
}
