#include "fd_stake_delegations.h"
#include "../../funk/fd_funk_base.h"
#include "../runtime/fd_txn_account.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/program/fd_stake_program.h"

#define POOL_NAME fd_stake_delegation_pool
#define POOL_T    fd_stake_delegation_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_stake_delegation_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_funk_rec_key_hash1( key->uc, seed ))
#define MAP_NEXT               next_
#include "../../util/tmpl/fd_map_chain.c"

static inline fd_stake_delegation_t *
fd_stake_delegations_get_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_stake_delegation_pool_join( (uchar *)stake_delegations + stake_delegations->pool_offset_ );
}

static inline fd_stake_delegation_map_t *
fd_stake_delegations_get_map( fd_stake_delegations_t const * stake_delegations ) {
  return fd_stake_delegation_map_join( (uchar *)stake_delegations + stake_delegations->map_offset_ );
}

ulong
fd_stake_delegations_align( void ) {
  /* The align of the struct should be the max of the align of the data
     structures that it contains. In this case, this is the map, the
     pool, and the struct itself. */
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
fd_stake_delegations_new( void * mem,
                          ulong  seed,
                          ulong  max_stake_accounts,
                          int    leave_tombstones ) {
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

  if( FD_UNLIKELY( !fd_stake_delegation_pool_new( pool_mem, max_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_stake_delegation_map_new( map_mem, map_chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations map" ));
    return NULL;
  }

  stake_delegations->pool_offset_        = (ulong)pool_mem - (ulong)mem;
  stake_delegations->map_offset_         = (ulong)map_mem - (ulong)mem;
  stake_delegations->max_stake_accounts_ = max_stake_accounts;
  stake_delegations->leave_tombstones_   = leave_tombstones;

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

  ulong map_chain_cnt = fd_stake_delegation_map_chain_cnt_est( stake_delegations->max_stake_accounts_ );

  FD_SCRATCH_ALLOC_INIT( l, stake_delegations );
  stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),     sizeof(fd_stake_delegations_t) );
  void * pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_pool_align(), fd_stake_delegation_pool_footprint( stake_delegations->max_stake_accounts_ ) );
  void * map_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegation_map_align(),  fd_stake_delegation_map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( stake_delegations->max_stake_accounts_ ) ) ) {
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
fd_stake_delegations_init( fd_stake_delegations_t * stake_delegations ) {
  fd_stake_delegation_map_t * stake_delegation_map  = fd_stake_delegations_get_map( stake_delegations );
  fd_stake_delegation_map_reset( stake_delegation_map );
  fd_stake_delegation_t * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  fd_stake_delegation_pool_reset( stake_delegation_pool );
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
    stake_delegation->is_tombstone         = 0;
    return;
  }

  /* Otherwise, try to acquire a new node and populate it. */
  if( FD_UNLIKELY( !fd_stake_delegation_pool_free( stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fd_stake_delegation_t * stake_delegation = fd_stake_delegation_pool_ele_acquire( stake_delegation_pool );

  stake_delegation->stake_account        = *stake_account;
  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = activation_epoch;
  stake_delegation->deactivation_epoch   = deactivation_epoch;
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = warmup_cooldown_rate;
  stake_delegation->is_tombstone         = 0;

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

  if( stake_delegations->leave_tombstones_==1 ) {
    /* If we are configured to leave tombstones, we need to either
       update the entry's is_tombstone flag or insert a new entry. */

    fd_stake_delegation_t * stake_delegation = NULL;
    if( delegation_idx!=ULONG_MAX ) {
      /* The delegation was found, update the is_tombstone flag. */
      stake_delegation = fd_stake_delegation_pool_ele( stake_delegation_pool, delegation_idx );
    } else {
      /* Otherwise, acquire an element from the pool and add it into the
         map. */
      stake_delegation = fd_stake_delegation_pool_ele_acquire( stake_delegation_pool );
      stake_delegation->stake_account = *stake_account;
      fd_stake_delegation_map_ele_insert( stake_delegation_map, stake_delegation, stake_delegation_pool );
    }
    stake_delegation->is_tombstone = 1;

  } else {
    /* If we are not configured to leave tombstones, we need to remove
       the entry from the map and release it from the pool. */
    if( FD_UNLIKELY( delegation_idx == ULONG_MAX ) ) {
      /* The delegation was not found, nothing to do. */
      return;
    }

    /* To be safe, we should set the next_ pointer to the null idx. */

    fd_stake_delegation_t * stake_delegation = fd_stake_delegation_pool_ele( stake_delegation_pool, delegation_idx );
    if( FD_UNLIKELY( !stake_delegation ) ) {
      FD_LOG_CRIT(( "unable to retrieve stake delegation" ));
    }

    ulong idx = fd_stake_delegation_map_idx_remove( stake_delegation_map, stake_account, ULONG_MAX, stake_delegation_pool );
    if( FD_UNLIKELY( idx==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "unable to remove stake delegation" ));
    }

    stake_delegation->next_ = fd_stake_delegation_pool_idx_null( stake_delegation_pool );

    fd_stake_delegation_pool_idx_release( stake_delegation_pool, delegation_idx );
  }
}

void
fd_stake_delegations_refresh( fd_stake_delegations_t *  stake_delegations,
                              fd_funk_t *               funk,
                              fd_funk_txn_xid_t const * xid ) {

  fd_stake_delegation_map_t * stake_delegation_map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  fd_stake_delegation_t * stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }

  for( ulong i=0UL; i<stake_delegations->max_stake_accounts_; i++ ) {

    fd_stake_delegation_t * stake_delegation = fd_stake_delegation_pool_ele( fd_stake_delegations_get_pool( stake_delegations ), i );

    if( !fd_stake_delegation_map_ele_query_const(
            fd_stake_delegations_get_map( stake_delegations ),
            &stake_delegation->stake_account,
            NULL,
            fd_stake_delegations_get_pool( stake_delegations ) ) ) {
      /* This means that the stake delegation is not in the map, so we
         can skip it. */
      continue;
    }

    int err = 0;
    fd_account_meta_t const * meta = fd_funk_get_acc_meta_readonly( funk, xid, &stake_delegation->stake_account, NULL, &err, NULL );
    if( FD_UNLIKELY( err || meta->lamports==0UL ) ) {
      fd_stake_delegation_map_idx_remove( stake_delegation_map, &stake_delegation->stake_account, ULONG_MAX, stake_delegation_pool );
      fd_stake_delegation_pool_idx_release( stake_delegation_pool, i );
      continue;
    }

    fd_stake_state_v2_t stake_state;
    err = fd_stake_get_state( meta, &stake_state );
    if( FD_UNLIKELY( err ) ) {
      fd_stake_delegation_map_idx_remove( stake_delegation_map, &stake_delegation->stake_account, ULONG_MAX, stake_delegation_pool );
      fd_stake_delegation_pool_idx_release( stake_delegation_pool, i );
    }

    if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
      fd_stake_delegation_map_idx_remove( stake_delegation_map, &stake_delegation->stake_account, ULONG_MAX, stake_delegation_pool );
      fd_stake_delegation_pool_idx_release( stake_delegation_pool, i );
    }

    fd_stake_delegations_update(
        stake_delegations,
        &stake_delegation->stake_account,
        &stake_state.inner.stake.stake.delegation.voter_pubkey,
        stake_state.inner.stake.stake.delegation.stake,
        stake_state.inner.stake.stake.delegation.activation_epoch,
        stake_state.inner.stake.stake.delegation.deactivation_epoch,
        stake_state.inner.stake.stake.credits_observed,
        stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );
  }
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

  fd_stake_delegation_map_t const * stake_delegation_map = fd_stake_delegations_get_map( stake_delegations );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation map" ));
  }

  return fd_stake_delegation_map_ele_query_const(
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

  return fd_stake_delegation_pool_used( stake_delegation_pool );
}

fd_stake_delegation_t *
fd_stake_delegations_iter_ele( fd_stake_delegations_iter_t * iter ) {
  ulong idx = fd_stake_delegation_map_iter_idx( iter->iter, iter->map, iter->pool );
  return fd_stake_delegation_pool_ele( iter->pool, idx );
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  iter->map  = fd_stake_delegations_get_map( stake_delegations );
  iter->pool = fd_stake_delegations_get_pool( stake_delegations );
  iter->iter = fd_stake_delegation_map_iter_init( iter->map, iter->pool );

  return iter;
}

void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter ) {
  iter->iter = fd_stake_delegation_map_iter_next( iter->iter, iter->map, iter->pool );
}

int
fd_stake_delegations_iter_done( fd_stake_delegations_iter_t * iter ) {
  return fd_stake_delegation_map_iter_done( iter->iter, iter->map, iter->pool );
}
