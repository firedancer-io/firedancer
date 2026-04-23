#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_pipe.h"
#include "fd_stakes.h"

#define POOL_NAME  root_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#define POOL_LAZY  1
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
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fork_dlist
#define DLIST_ELE_T fd_stake_delegation_t
#define DLIST_PREV  prev_
#define DLIST_NEXT  next_
#define DLIST_IDX_T uint
#include "../../util/tmpl/fd_dlist.c"

struct fork_pool_ele { ushort next; };
typedef struct fork_pool_ele fork_pool_ele_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_pool_ele_t
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

/* Internal getters for base map + pool */

static inline fd_stake_delegation_t *
get_root_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->pool_offset_ );
}

/* Root-pool acquire/release wrappers that maintain is_allocated and
   root_pool_hwm so fd_stake_delegations_pool_iter can walk a dense
   prefix with O(1)-per-slot allocated checks.  Callers must use
   these instead of root_pool_{ele,idx}_{acquire,release} directly
   for the root pool. */

static inline fd_stake_delegation_t *
root_pool_acquire_tracked( fd_stake_delegations_t * stake_delegations,
                           fd_stake_delegation_t *  root_pool ) {
  ulong idx = root_pool_idx_acquire( root_pool );
  if( idx+1UL > stake_delegations->root_pool_hwm ) {
    stake_delegations->root_pool_hwm = idx + 1UL;
  }
  root_pool[ idx ].is_allocated = 1;
  return &root_pool[ idx ];
}

static inline void
root_pool_idx_release_tracked( fd_stake_delegation_t * root_pool,
                               ulong                   idx ) {
  root_pool[ idx ].is_allocated = 0;
  root_pool_idx_release( root_pool, idx );
}

static inline void
root_pool_ele_release_tracked( fd_stake_delegation_t * root_pool,
                               fd_stake_delegation_t * ele ) {
  ele->is_allocated = 0;
  root_pool_ele_release( root_pool, ele );
}

static inline root_map_t *
get_root_map( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->map_offset_ );
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

  fd_stake_delegation_t * root_pool = root_pool_join( root_pool_new( pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !root_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations pool" ));
    return NULL;
  }

  root_map_t * root_map = root_map_join( root_map_new( map_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !root_map ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations map" ));
    return NULL;
  }

  fd_stake_delegation_t * delta_pool = delta_pool_join( delta_pool_new( delta_pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !delta_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation delta pool" ));
    return NULL;
  }

  fork_pool_ele_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_live_slots ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }

  stake_delegations->max_stake_accounts_      = max_stake_accounts;
  stake_delegations->expected_stake_accounts_ = expected_stake_accounts;
  stake_delegations->pool_offset_             = (ulong)root_pool - (ulong)mem;
  stake_delegations->map_offset_              = (ulong)root_map - (ulong)mem;
  stake_delegations->delta_pool_offset_       = (ulong)delta_pool - (ulong)mem;
  stake_delegations->fork_pool_offset_        = (ulong)fork_pool - (ulong)mem;

  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;
  stake_delegations->root_pool_hwm      = 0UL;

  fd_rwlock_new( &stake_delegations->delta_lock );

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

  if( FD_UNLIKELY( stake_delegations->magic!=FD_STAKE_DELEGATIONS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid stake delegations magic" ));
    return NULL;
  }

  return stake_delegations;
}

void
fd_stake_delegations_reset( fd_stake_delegations_t * stake_delegations ) {
  root_pool_reset ( get_root_pool ( stake_delegations ) );
  root_map_reset  ( get_root_map  ( stake_delegations ) );
  delta_pool_reset( get_delta_pool( stake_delegations ) );
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  ulong max_forks = fork_pool_max( fork_pool );
  for( ulong i=0UL; i<max_forks; i++ ) {
    fork_dlist_remove_all( get_fork_dlist( stake_delegations, (ushort)i ), delta_pool );
  }
  fork_pool_reset( fork_pool );
  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;
  /* Rewinding hwm to 0 is safe without touching stale is_allocated
     bits in the pool: the iterator only looks at slots in [0, hwm),
     and subsequent lazy acquires will rewrite is_allocated=1 on
     any slot they touch via root_pool_acquire_tracked. */
  stake_delegations->root_pool_hwm      = 0UL;
}

fd_stake_delegation_t const *
fd_stake_delegation_root_query( fd_stake_delegations_t const * stake_delegations,
                                fd_pubkey_t const *            stake_account ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map = get_root_map( stake_delegations );

  return root_map_ele_query_const( map, stake_account, NULL, pool );
}

void
fd_stake_delegations_root_update( fd_stake_delegations_t * stake_delegations,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  uchar                    warmup_cooldown_rate ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map = get_root_map( stake_delegations );

  fd_stake_delegation_t * stake_delegation = root_map_ele_query( map, stake_account, NULL, pool );
  if( !stake_delegation ) {
    FD_CRIT( root_pool_free( pool ), "no free stake delegations in pool" );
    stake_delegation = root_pool_acquire_tracked( stake_delegations, pool );
    stake_delegation->stake_account = *stake_account;
    FD_CRIT( root_map_ele_insert( map, stake_delegation, pool ), "unable to insert stake delegation into map" );
  }

  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
  stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = warmup_cooldown_rate;
  stake_delegation->dne_in_root          = 0;
  stake_delegation->delta_idx            = UINT_MAX;
}

static inline void
fd_stake_delegations_remove( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map  = get_root_map( stake_delegations );

  ulong delegation_idx = root_map_idx_query( map, stake_account, UINT_MAX, pool );
  if( FD_UNLIKELY( delegation_idx==UINT_MAX ) ) return;

  root_map_idx_remove( map, stake_account, delegation_idx, pool );
  root_pool_idx_release_tracked( pool, delegation_idx );
}

#if FD_HAS_DOUBLE

void
fd_stake_delegations_refresh( fd_stake_delegations_t *   stake_delegations,
                              ulong                      epoch,
                              fd_stake_history_t const * stake_history,
                              ulong *                    warmup_cooldown_rate_epoch,
                              fd_accdb_user_t *          accdb,
                              fd_funk_txn_xid_t const *  xid ) {

  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;

  root_map_t *            map  = get_root_map( stake_delegations );
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );

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

      fd_stake_state_t const * stake = fd_stakes_get_state( ro->meta );
      if( FD_UNLIKELY( !stake ) ) goto remove;
      if( FD_UNLIKELY( stake->stake_type != FD_STAKE_STATE_STAKE ) ) goto remove;

      fd_stake_delegations_root_update(
          stake_delegations,
          address,
          &stake->stake.stake.delegation.voter_pubkey,
          stake->stake.stake.delegation.stake,
          stake->stake.stake.delegation.activation_epoch,
          stake->stake.stake.delegation.deactivation_epoch,
          stake->stake.stake.credits_observed,
          fd_stake_warmup_cooldown_rate( epoch, warmup_cooldown_rate_epoch ) );

      fd_stake_history_entry_t entry = stake_activating_and_deactivating( &stake->stake.stake.delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
      stake_delegations->effective_stake    += entry.effective;
      stake_delegations->activating_stake   += entry.activating;
      stake_delegations->deactivating_stake += entry.deactivating;
      continue; /* ok */

    remove:
      root_map_idx_remove( map, address, UINT_MAX, pool );
      root_pool_ele_release_tracked( pool, delegation );
    }
  }
  fd_accdb_ro_pipe_fini( ro_pipe );
}

#endif

ulong
fd_stake_delegations_cnt( fd_stake_delegations_t const * stake_delegations ) {
  return root_pool_used( get_root_pool( stake_delegations ) );
}

/* Fork-aware delta operations */

ushort
fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations ) {
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  FD_CRIT( fork_pool_free( fork_pool ), "no free forks in pool. The system has forked too wide." );
  ushort fork_idx = (ushort)fork_pool_idx_acquire( fork_pool );

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
                                  uchar                    warmup_cooldown_rate ) {
  fd_rwlock_write( &stake_delegations->delta_lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  FD_CRIT( delta_pool_free( delta_pool ), "no free stake delegations in pool" );

  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );

  fd_stake_delegation_t * stake_delegation = delta_pool_ele_acquire( delta_pool );

  fork_dlist_ele_push_tail( dlist, stake_delegation, delta_pool );

  stake_delegation->stake_account        = *stake_account;
  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
  stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = warmup_cooldown_rate;
  stake_delegation->is_tombstone         = 0;

  FD_BASE58_ENCODE_32_BYTES( stake_delegation->stake_account.uc, stake_account_out );
  FD_LOG_DEBUG(( "fork_update: stake_account=%s, stake=%lu, activation_epoch=%u, deactivation_epoch=%u",
      stake_account_out, stake_delegation->stake, stake_delegation->activation_epoch, stake_delegation->deactivation_epoch ));

  fd_rwlock_unwrite( &stake_delegations->delta_lock );
}

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account ) {
  fd_rwlock_write( &stake_delegations->delta_lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  FD_CRIT( delta_pool_free( delta_pool ), "no free stake delegations in pool" );

  fd_stake_delegation_t * stake_delegation = delta_pool_ele_acquire( delta_pool );

  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );
  fork_dlist_ele_push_tail( dlist, stake_delegation, delta_pool );

  stake_delegation->stake_account = *stake_account;
  stake_delegation->is_tombstone  = 1;

  FD_BASE58_ENCODE_32_BYTES( stake_delegation->stake_account.uc, stake_account_out );
  FD_LOG_DEBUG(( "fork_remove: stake_account=%s", stake_account_out ));

  fd_rwlock_unwrite( &stake_delegations->delta_lock );
}

void
fd_stake_delegations_evict_fork( fd_stake_delegations_t * stake_delegations,
                                 ushort                   fork_idx ) {
  if( fork_idx==USHORT_MAX ) return;

  fd_rwlock_write( &stake_delegations->delta_lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );

  fork_dlist_t * dlist = get_fork_dlist( stake_delegations, fork_idx );
  while( !fork_dlist_is_empty( dlist, delta_pool ) ) {
    fd_stake_delegation_t * ele = fork_dlist_ele_pop_head( dlist, delta_pool );
    delta_pool_ele_release( delta_pool, ele );
  }

  fork_pool_idx_release( get_fork_pool( stake_delegations ), fork_idx );

  fd_rwlock_unwrite( &stake_delegations->delta_lock );
}

void
fd_stake_delegations_apply_fork_delta( ulong                      epoch,
                                       fd_stake_history_t const * stake_history,
                                       ulong *                    warmup_cooldown_rate_epoch,
                                       fd_stake_delegations_t *   stake_delegations,
                                       ushort                     fork_idx ) {

  fork_dlist_t *          dlist      = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );

  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( dlist, delta_pool );
       !fork_dlist_iter_done( iter, dlist, delta_pool );
       iter = fork_dlist_iter_fwd_next( iter, dlist, delta_pool ) ) {
    fd_stake_delegation_t * stake_delegation = fork_dlist_iter_ele( iter, dlist, delta_pool );
    if( FD_LIKELY( !stake_delegation->is_tombstone ) ) {
      /* If the entry in the delta is an update:
         - If the entry already exists, subtract the old version's stake
         - Insert/update the new version
         - Add the new version's stake to the totals */
      fd_stake_delegation_t const * old_delegation = fd_stake_delegation_root_query( stake_delegations, &stake_delegation->stake_account );
      if( FD_LIKELY( old_delegation ) ) {
        fd_stake_history_entry_t old_entry = fd_stakes_activating_and_deactivating( old_delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
        stake_delegations->effective_stake    -= old_entry.effective;
        stake_delegations->activating_stake   -= old_entry.activating;
        stake_delegations->deactivating_stake -= old_entry.deactivating;
      }

      fd_stake_delegations_root_update(
          stake_delegations,
          &stake_delegation->stake_account,
          &stake_delegation->vote_account,
          stake_delegation->stake,
          stake_delegation->activation_epoch,
          stake_delegation->deactivation_epoch,
          stake_delegation->credits_observed,
          stake_delegation->warmup_cooldown_rate );

      fd_stake_history_entry_t new_entry = fd_stakes_activating_and_deactivating( stake_delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
      stake_delegations->effective_stake    += new_entry.effective;
      stake_delegations->activating_stake   += new_entry.activating;
      stake_delegations->deactivating_stake += new_entry.deactivating;
    } else {
      /* If the stake delegation in the delta is a tombstone, just
         remove the stake delegation from the root map and subtract
         it's stake from the totals. */
      fd_stake_delegation_t const * old_delegation = fd_stake_delegation_root_query( stake_delegations, &stake_delegation->stake_account );
      if( FD_LIKELY( old_delegation ) ) {
        fd_stake_history_entry_t old_entry = fd_stakes_activating_and_deactivating( old_delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
        stake_delegations->effective_stake    -= old_entry.effective;
        stake_delegations->activating_stake   -= old_entry.activating;
        stake_delegations->deactivating_stake -= old_entry.deactivating;
      }
      fd_stake_delegations_remove( stake_delegations, &stake_delegation->stake_account );
    }
  }
  FD_LOG_DEBUG(( "effective_stake=%lu, activating_stake=%lu, deactivating_stake=%lu", stake_delegations->effective_stake, stake_delegations->activating_stake, stake_delegations->deactivating_stake ));
}

/* Combined base+delta iterator */

fd_stake_delegation_t const *
fd_stake_delegations_iter_ele( fd_stake_delegations_iter_t * iter ) {
  ulong idx = root_map_iter_idx( iter->iter, iter->root_map, iter->root_pool );
  fd_stake_delegation_t * stake_delegation = root_pool_ele( iter->root_pool, idx );
  if( FD_UNLIKELY( stake_delegation->delta_idx!=UINT_MAX ) ) {
    return (fd_stake_delegation_t *)delta_pool_ele( iter->delta_pool, stake_delegation->delta_idx );
  }
  return stake_delegation;
}

ulong
fd_stake_delegations_iter_idx( fd_stake_delegations_iter_t * iter ) {
  return root_map_iter_idx( iter->iter, iter->root_map, iter->root_pool );
}

static void
skip_tombstones( fd_stake_delegations_iter_t * iter ) {
  while( !fd_stake_delegations_iter_done( iter ) ) {
    fd_stake_delegation_t *       root_delegation = root_map_iter_ele( iter->iter, iter->root_map, iter->root_pool );
    fd_stake_delegation_t const * ele             = (root_delegation->delta_idx != UINT_MAX)
      ? (fd_stake_delegation_t const *)delta_pool_ele( iter->delta_pool, root_delegation->delta_idx )
      : (fd_stake_delegation_t const *)root_delegation;
    if( FD_LIKELY( !ele->is_tombstone ) ) return;
    iter->iter = root_map_iter_next( iter->iter, iter->root_map, iter->root_pool );
  }
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  iter->root_map   = get_root_map( stake_delegations );
  iter->root_pool  = get_root_pool( stake_delegations );
  iter->iter       = root_map_iter_init( iter->root_map, iter->root_pool );
  iter->delta_pool = get_delta_pool( stake_delegations );

  iter->iter_chain_stop = 0UL;

  skip_tombstones( iter );

  return iter;
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init_partition( fd_stake_delegations_iter_t *  iter,
                                          fd_stake_delegations_t const * stake_delegations,
                                          ulong                          partition_idx,
                                          ulong                          total_partitions ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }
  if( FD_UNLIKELY( total_partitions==0UL || partition_idx>=total_partitions ) ) {
    FD_LOG_CRIT(( "invalid partition idx %lu total_partitions %lu", partition_idx, total_partitions ));
  }

  iter->root_map   = get_root_map( stake_delegations );
  iter->root_pool  = get_root_pool( stake_delegations );
  iter->delta_pool = get_delta_pool( stake_delegations );

  /* Partition i maps to [chain_lo, chain_hi).  The underlying map
     iterator's chain_rem counts down, so the iterator starts at
     chain_rem=chain_hi and stops once chain_rem<=chain_lo. */
  ulong chain_cnt = root_map_chain_cnt( iter->root_map );
  ulong chain_lo  = (partition_idx      *chain_cnt)/total_partitions;
  ulong chain_hi  = ((partition_idx+1UL)*chain_cnt)/total_partitions;

  iter->iter_chain_stop = chain_lo;

  root_map_private_t const * map       = root_map_private_const( iter->root_map );
  uint const *               chain     = root_map_private_chain_const( map );
  ulong                      chain_rem = chain_hi;
  ulong                      ele_idx   = root_map_private_idx_null();
  while( chain_rem>chain_lo ) {
    ele_idx = root_map_private_unbox( chain[ chain_rem-1UL ] );
    if( !root_map_private_idx_is_null( ele_idx ) ) break;
    chain_rem--;
  }

  iter->iter.chain_rem = chain_rem;
  iter->iter.ele_idx   = ele_idx;

  skip_tombstones( iter );

  return iter;
}

void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter ) {
  iter->iter = root_map_iter_next( iter->iter, iter->root_map, iter->root_pool );
  skip_tombstones( iter );
}

int
fd_stake_delegations_iter_done( fd_stake_delegations_iter_t * iter ) {
  return root_map_iter_done( iter->iter, iter->root_map, iter->root_pool ) ||
         iter->iter.chain_rem<=iter->iter_chain_stop;
}

/* Pool-range iterator ************************************************/

static inline void
pool_iter_advance_to_valid( fd_stake_delegations_pool_iter_t * iter ) {
  while( iter->cur<iter->hi ) {
    fd_stake_delegation_t const * root_ele = &iter->root_pool[ iter->cur ];
    if( FD_LIKELY( root_ele->is_allocated ) ) {
      fd_stake_delegation_t const * ele = (root_ele->delta_idx!=UINT_MAX)
        ? (fd_stake_delegation_t const *)delta_pool_ele_const( iter->delta_pool, root_ele->delta_idx )
        : root_ele;
      if( FD_LIKELY( !ele->is_tombstone ) ) return;
    }
    iter->cur++;
  }
}

fd_stake_delegations_pool_iter_t *
fd_stake_delegations_pool_iter_init_partition( fd_stake_delegations_pool_iter_t * iter,
                                               fd_stake_delegations_t const *     stake_delegations,
                                               ulong                              partition_idx,
                                               ulong                              total_partitions ) {
  if( FD_UNLIKELY( !stake_delegations ) ) FD_LOG_CRIT(( "NULL stake_delegations" ));
  if( FD_UNLIKELY( total_partitions==0UL || partition_idx>=total_partitions ) ) {
    FD_LOG_CRIT(( "invalid partition idx %lu total_partitions %lu", partition_idx, total_partitions ));
  }

  iter->root_pool  = get_root_pool( stake_delegations );
  iter->delta_pool = get_delta_pool( stake_delegations );
  ulong hwm = stake_delegations->root_pool_hwm;
  iter->cur = (partition_idx    *hwm)/total_partitions;
  iter->hi  = ((partition_idx+1UL)*hwm)/total_partitions;

  pool_iter_advance_to_valid( iter );
  return iter;
}

int
fd_stake_delegations_pool_iter_done( fd_stake_delegations_pool_iter_t const * iter ) {
  return iter->cur>=iter->hi;
}

void
fd_stake_delegations_pool_iter_next( fd_stake_delegations_pool_iter_t * iter ) {
  iter->cur++;
  pool_iter_advance_to_valid( iter );
}

fd_stake_delegation_t const *
fd_stake_delegations_pool_iter_ele( fd_stake_delegations_pool_iter_t const * iter ) {
  fd_stake_delegation_t const * root_ele = &iter->root_pool[ iter->cur ];
  if( FD_UNLIKELY( root_ele->delta_idx!=UINT_MAX ) ) {
    return (fd_stake_delegation_t const *)delta_pool_ele_const( iter->delta_pool, root_ele->delta_idx );
  }
  return root_ele;
}

void
fd_stake_delegations_mark_delta( fd_stake_delegations_t *   stake_delegations,
                                 ulong                      epoch,
                                 fd_stake_history_t const * stake_history,
                                 ulong *                    warmup_cooldown_rate_epoch,
                                 ushort                     fork_idx ) {

  root_map_t *            root_map   = get_root_map( stake_delegations );
  fd_stake_delegation_t * root_pool  = get_root_pool( stake_delegations );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_dlist_t *          fork_dlist = get_fork_dlist( stake_delegations, fork_idx );

  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( fork_dlist, delta_pool );
       !fork_dlist_iter_done( iter, fork_dlist, delta_pool );
       iter = fork_dlist_iter_fwd_next( iter, fork_dlist, delta_pool ) ) {
    fd_stake_delegation_t * delta_delegation = fork_dlist_iter_ele( iter, fork_dlist, delta_pool );

    fd_stake_delegation_t * base_delegation = root_map_ele_query( root_map, &delta_delegation->stake_account, NULL, root_pool);
    if( FD_UNLIKELY( !base_delegation ) ) {
      base_delegation                = root_pool_acquire_tracked( stake_delegations, root_pool );
      base_delegation->stake_account = delta_delegation->stake_account;
      base_delegation->dne_in_root   = 1;
      base_delegation->delta_idx     = (uint)delta_pool_idx( delta_pool, delta_delegation );
      root_map_ele_insert( root_map, base_delegation, root_pool );
    } else {
      /* Only subtract the old version's stake if it's not a tombstone.*/
      fd_stake_delegation_t *  old_delegation = base_delegation->delta_idx==UINT_MAX ? base_delegation : delta_pool_ele( delta_pool, base_delegation->delta_idx );
      if( FD_LIKELY( base_delegation->delta_idx==UINT_MAX || !old_delegation->is_tombstone ) ) {
        fd_stake_history_entry_t old_entry      = fd_stakes_activating_and_deactivating( old_delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
        stake_delegations->effective_stake    -= old_entry.effective;
        stake_delegations->activating_stake   -= old_entry.activating;
        stake_delegations->deactivating_stake -= old_entry.deactivating;
      }
      /* Update the base delegation to point to the new version. */
      base_delegation->delta_idx = (uint)delta_pool_idx( delta_pool, delta_delegation );
    }

    /* Add the new version's stake to the totals (as long as it's not a
       tombstone).*/
    if( FD_LIKELY( !delta_delegation->is_tombstone ) ) {
      fd_stake_history_entry_t new_entry = fd_stakes_activating_and_deactivating( delta_delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
      stake_delegations->effective_stake    += new_entry.effective;
      stake_delegations->activating_stake   += new_entry.activating;
      stake_delegations->deactivating_stake += new_entry.deactivating;
    }
  }
}

void
fd_stake_delegations_unmark_delta( fd_stake_delegations_t *   stake_delegations,
                                   ulong                      epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    warmup_cooldown_rate_epoch,
                                   ushort                     fork_idx ) {

  root_map_t *            root_map   = get_root_map( stake_delegations );
  fd_stake_delegation_t * root_pool  = get_root_pool( stake_delegations );
  fork_dlist_t *          fork_dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );

  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( fork_dlist, delta_pool );
       !fork_dlist_iter_done( iter, fork_dlist, delta_pool );
       iter = fork_dlist_iter_fwd_next( iter, fork_dlist, delta_pool ) ) {
    fd_stake_delegation_t * delta_delegation = fork_dlist_iter_ele( iter, fork_dlist, delta_pool );

    fd_stake_delegation_t * base_delegation = root_map_ele_query( root_map, &delta_delegation->stake_account, NULL, root_pool );
    if( FD_UNLIKELY( !base_delegation ) ) {
      continue;
    }

    uint delta_idx = (uint)delta_pool_idx( delta_pool, delta_delegation );
    if( FD_UNLIKELY( base_delegation->delta_idx!=delta_idx ) ) continue;

    if( FD_UNLIKELY( base_delegation->dne_in_root )) {
      if( FD_LIKELY( !delta_delegation->is_tombstone ) ) {
        fd_stake_history_entry_t entry = fd_stakes_activating_and_deactivating( delta_delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
        stake_delegations->effective_stake    -= entry.effective;
        stake_delegations->activating_stake   -= entry.activating;
        stake_delegations->deactivating_stake -= entry.deactivating;
      }

      base_delegation->dne_in_root = 0;
      base_delegation->delta_idx   = UINT_MAX;
      root_map_ele_remove( root_map, &delta_delegation->stake_account, NULL, root_pool );
      root_pool_ele_release_tracked( root_pool, base_delegation );

    } else {
      if( FD_LIKELY( !delta_delegation->is_tombstone ) ) {
        fd_stake_history_entry_t entry = fd_stakes_activating_and_deactivating( delta_delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
        stake_delegations->effective_stake    -= entry.effective;
        stake_delegations->activating_stake   -= entry.activating;
        stake_delegations->deactivating_stake -= entry.deactivating;
      }

      base_delegation->delta_idx = UINT_MAX;

      fd_stake_history_entry_t entry = fd_stakes_activating_and_deactivating( base_delegation, epoch, stake_history, warmup_cooldown_rate_epoch );
      stake_delegations->effective_stake    += entry.effective;
      stake_delegations->activating_stake   += entry.activating;
      stake_delegations->deactivating_stake += entry.deactivating;
    }
  }
}
