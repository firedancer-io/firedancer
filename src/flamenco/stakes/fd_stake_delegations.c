#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_pipe.h"
#include "fd_stakes.h"

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

/* vote_total: per-vote-account raw stake total */

struct vote_total_ele {
  fd_pubkey_t pubkey;
  ulong       stake;
  uint        next_;
};
typedef struct vote_total_ele vote_total_ele_t;

#define POOL_NAME  vote_total_pool
#define POOL_T     vote_total_ele_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               vote_total_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              vote_total_ele_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( (k0), (k1) ))
#define MAP_KEY_HASH(key,seed) (fd_funk_rec_key_hash1( (key)->uc, (seed) ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"


/* Internal getters for vote_total pool + map */

static inline vote_total_ele_t *
get_vote_total_pool( fd_stake_delegations_t const * dk ) {
  return fd_type_pun( (uchar *)dk + dk->vote_total_pool_offset_ );
}

static inline vote_total_map_t *
get_vote_total_map( fd_stake_delegations_t const * dk ) {
  return fd_type_pun( (uchar *)dk + dk->vote_total_map_offset_ );
}

/* Internal getters for base map + pool */

static inline fd_stake_delegation_t *
get_root_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->pool_offset_ );
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

  ulong map_chain_cnt       = root_map_chain_cnt_est( expected_stake_accounts );
  ulong vt_map_chain_cnt    = vote_total_map_chain_cnt_est( FD_STAKE_DELEGATIONS_MAX_VOTE_ACCOUNTS );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  l = FD_LAYOUT_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, delta_pool_align(),           delta_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    l = FD_LAYOUT_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
  }
  l = FD_LAYOUT_APPEND( l, vote_total_pool_align(), vote_total_pool_footprint( FD_STAKE_DELEGATIONS_MAX_VOTE_ACCOUNTS ) );
  l = FD_LAYOUT_APPEND( l, vote_total_map_align(),  vote_total_map_footprint( vt_map_chain_cnt ) );

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

  ulong map_chain_cnt    = root_map_chain_cnt_est( expected_stake_accounts );
  ulong vt_map_chain_cnt = vote_total_map_chain_cnt_est( FD_STAKE_DELEGATIONS_MAX_VOTE_ACCOUNTS );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_t * stake_delegations   = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  void *                   pool_mem            = FD_SCRATCH_ALLOC_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  void *                   map_mem             = FD_SCRATCH_ALLOC_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  void *                   delta_pool_mem      = FD_SCRATCH_ALLOC_APPEND( l, delta_pool_align(),           delta_pool_footprint( max_stake_accounts ) );
  void *                   fork_pool_mem       = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  for( ushort i=0; i<(ushort)max_live_slots; i++ ) {
    void * fork_dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
    fork_dlist_t * dlist = fork_dlist_join( fork_dlist_new( fork_dlist_mem ) );
    if( FD_UNLIKELY( !dlist ) ) {
      FD_LOG_WARNING(( "Failed to create fork dlist" ));
      return NULL;
    }
    stake_delegations->dlist_offsets_[ i ] = (ulong)dlist - (ulong)mem;
  }
  void * vt_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, vote_total_pool_align(), vote_total_pool_footprint( FD_STAKE_DELEGATIONS_MAX_VOTE_ACCOUNTS ) );
  void * vt_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, vote_total_map_align(),  vote_total_map_footprint( vt_map_chain_cnt ) );

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

  vote_total_ele_t * vt_pool = vote_total_pool_join( vote_total_pool_new( vt_pool_mem, FD_STAKE_DELEGATIONS_MAX_VOTE_ACCOUNTS ) );
  if( FD_UNLIKELY( !vt_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote_total pool" ));
    return NULL;
  }

  vote_total_map_t * vt_map = vote_total_map_join( vote_total_map_new( vt_map_mem, vt_map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !vt_map ) ) {
    FD_LOG_WARNING(( "Failed to create vote_total map" ));
    return NULL;
  }

  stake_delegations->max_stake_accounts_      = max_stake_accounts;
  stake_delegations->expected_stake_accounts_ = expected_stake_accounts;
  stake_delegations->pool_offset_             = (ulong)root_pool - (ulong)mem;
  stake_delegations->map_offset_              = (ulong)root_map - (ulong)mem;
  stake_delegations->delta_pool_offset_       = (ulong)delta_pool - (ulong)mem;
  stake_delegations->fork_pool_offset_        = (ulong)fork_pool - (ulong)mem;
  stake_delegations->vote_total_pool_offset_  = (ulong)vt_pool - (ulong)mem;
  stake_delegations->vote_total_map_offset_   = (ulong)vt_map - (ulong)mem;

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
fd_stake_delegations_init( fd_stake_delegations_t * stake_delegations ) {
  root_map_t *            map  = get_root_map( stake_delegations );
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_pool_reset( pool );
  root_map_reset( map );
  vote_total_pool_reset( get_vote_total_pool( stake_delegations ) );
  vote_total_map_reset( get_vote_total_map( stake_delegations ) );
}

void
fd_stake_delegations_root_update( fd_stake_delegations_t * stake_delegations,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  double                   warmup_cooldown_rate ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map = get_root_map( stake_delegations );

  fd_stake_delegation_t * stake_delegation = root_map_ele_query( map, stake_account, NULL, pool );
  if( !stake_delegation ) {
    FD_CRIT( root_pool_free( pool ), "no free stake delegations in pool" );
    stake_delegation = root_pool_ele_acquire( pool );
    stake_delegation->stake_account = *stake_account;
    FD_CRIT( root_map_ele_insert( map, stake_delegation, pool ), "unable to insert stake delegation into map" );
    /* New entry: add raw stake to vote_total_map. */
    fd_stake_delegations_vote_total_adjust( stake_delegations, vote_account, (long)stake );
  } else {
    /* Existing entry: subtract old contribution, add new. */
    fd_stake_delegations_vote_total_adjust( stake_delegations, &stake_delegation->vote_account, -(long)stake_delegation->stake );
    fd_stake_delegations_vote_total_adjust( stake_delegations, vote_account,                    (long)stake );
  }

  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->activation_epoch     = (ushort)fd_ulong_min( activation_epoch, USHORT_MAX );
  stake_delegation->deactivation_epoch   = (ushort)fd_ulong_min( deactivation_epoch, USHORT_MAX );
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_enum( warmup_cooldown_rate );
  stake_delegation->dne_in_root          = 0;
  stake_delegation->delta_idx            = UINT_MAX;
}

static inline void
fd_stake_delegations_remove( fd_stake_delegations_t * stake_delegations,
                             fd_pubkey_t const *      stake_account ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map  = get_root_map( stake_delegations );

  fd_stake_delegation_t * ele = root_map_ele_query( map, stake_account, NULL, pool );
  if( FD_UNLIKELY( !ele ) ) return;

  /* Remove vote_total contribution before freeing. */
  fd_stake_delegations_vote_total_adjust( stake_delegations, &ele->vote_account, -(long)ele->stake );

  ulong delegation_idx = root_map_idx_query( map, stake_account, UINT_MAX, pool );
  root_map_idx_remove( map, stake_account, delegation_idx, pool );
  root_pool_idx_release( pool, delegation_idx );
}

void
fd_stake_delegations_refresh( fd_stake_delegations_t *  stake_delegations,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid ) {

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

      if( FD_UNLIKELY( fd_accdb_ref_lamports( ro )==0UL ) ) goto remove;

      fd_stake_state_v2_t stake;
      int err = fd_stakes_get_state( ro->meta, &stake );
      if( FD_UNLIKELY( err ) ) goto remove;
      if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake ) ) ) goto remove;

      fd_stake_delegations_root_update(
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
      fd_stake_delegations_vote_total_adjust( stake_delegations, &delegation->vote_account, -(long)delegation->stake );
      root_map_idx_remove( map, address, UINT_MAX, pool );
      root_pool_ele_release( pool, delegation );
    }
  }
  fd_accdb_ro_pipe_fini( ro_pipe );
}

ulong
fd_stake_delegations_cnt( fd_stake_delegations_t const * stake_delegations ) {
  return root_pool_used( get_root_pool( stake_delegations ) );
}

fd_stake_delegation_t const *
fd_stake_delegations_pool_ele_const( fd_stake_delegations_t const * stake_delegations,
                                     ulong                           idx ) {
  return &get_root_pool( stake_delegations )[ idx ];
}

/* ------------------------------------------------------------------ *
 * vote_total_map API                                                  *
 * ------------------------------------------------------------------ */

void
fd_stake_delegations_vote_total_adjust( fd_stake_delegations_t * dk,
                                        fd_pubkey_t const *       vote_account,
                                        long                      delta ) {
  vote_total_ele_t * pool = get_vote_total_pool( dk );
  vote_total_map_t * map  = get_vote_total_map( dk );

  vote_total_ele_t * ele = vote_total_map_ele_query( map, vote_account, NULL, pool );
  if( FD_LIKELY( ele ) ) {
    ele->stake = (ulong)fd_long_max( 0L, (long)ele->stake + delta );
    return;
  }
  if( FD_UNLIKELY( delta <= 0L ) ) return;  /* adding to non-existent is fine, subtracting is no-op */
  FD_CRIT( vote_total_pool_free( pool ), "vote_total_pool full" );
  vote_total_ele_t * new_ele = vote_total_pool_ele_acquire( pool );
  new_ele->pubkey = *vote_account;
  new_ele->stake  = (ulong)delta;
  vote_total_map_ele_insert( map, new_ele, pool );
}

ulong
fd_stake_delegations_vote_total_get( fd_stake_delegations_t const * dk,
                                     fd_pubkey_t const *             vote_account ) {
  vote_total_ele_t const * pool = get_vote_total_pool( dk );
  vote_total_map_t const * map  = get_vote_total_map( dk );
  vote_total_ele_t const * ele  = vote_total_map_ele_query_const( map, vote_account, NULL, pool );
  return ele ? ele->stake : 0UL;
}

ulong
fd_stake_delegations_vote_total_sum( fd_stake_delegations_t const * dk ) {
  vote_total_ele_t const * pool = get_vote_total_pool( dk );
  vote_total_map_t const * map  = get_vote_total_map( dk );
  ulong total = 0UL;
  for( vote_total_map_iter_t iter = vote_total_map_iter_init( map, pool );
       !vote_total_map_iter_done( iter, map, pool );
       iter = vote_total_map_iter_next( iter, map, pool ) ) {
    total += vote_total_map_iter_ele_const( iter, map, pool )->stake;
  }
  return total;
}

int
fd_stake_delegations_query( fd_stake_delegations_t const * stake_delegations,
                             ushort                         fork_idx,
                             fd_pubkey_t const *            stake_account,
                             fd_stake_delegation_t *        out ) {
  /* Walk the fork dlist in reverse (tail=most-recent first) to find the
     latest delta for this stake account in the current slot. */
  if( FD_LIKELY( fork_idx!=USHORT_MAX ) ) {
    fd_stake_delegation_t const * delta_pool = get_delta_pool( stake_delegations );
    fork_dlist_t const *          dlist      = get_fork_dlist( stake_delegations, fork_idx );
    for( fork_dlist_iter_t iter = fork_dlist_iter_rev_init( dlist, delta_pool );
         !fork_dlist_iter_done( iter, dlist, delta_pool );
         iter = fork_dlist_iter_rev_next( iter, dlist, delta_pool ) ) {
      fd_stake_delegation_t const * ele = fork_dlist_iter_ele_const( iter, dlist, delta_pool );
      if( FD_UNLIKELY( fd_pubkey_eq( &ele->stake_account, stake_account ) ) ) {
        if( ele->is_tombstone ) return 0;
        *out = *ele;
        return 1;
      }
    }
  }

  /* Fall back to the root map. */
  fd_stake_delegation_t const * root_pool = get_root_pool( stake_delegations );
  root_map_t const *            map       = get_root_map( stake_delegations );
  fd_stake_delegation_t const * ele       = root_map_ele_query_const( map, stake_account, NULL, root_pool );
  if( FD_UNLIKELY( !ele ) ) return 0;
  *out = *ele;
  return 1;
}

ulong
fd_stake_delegations_query_stake( fd_stake_delegations_t const * stake_delegations,
                                  ushort                         fork_idx,
                                  fd_pubkey_t const *            stake_account ) {
  fd_stake_delegation_t out;
  return fd_stake_delegations_query( stake_delegations, fork_idx, stake_account, &out ) ? out.stake : 0UL;
}

/* Fork-aware delta operations */

ushort
fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations ) {
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  FD_CRIT( fork_pool_free( fork_pool ), "no free forks in pool" );
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
                                  double                   warmup_cooldown_rate ) {
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
  stake_delegation->warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_enum( warmup_cooldown_rate );
  stake_delegation->is_tombstone         = 0;

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
fd_stake_delegations_apply_fork_delta( fd_stake_delegations_t * stake_delegations,
                                       ushort                   fork_idx ) {

  fork_dlist_t *          dlist      = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );

  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( dlist, delta_pool );
       !fork_dlist_iter_done( iter, dlist, delta_pool );
       iter = fork_dlist_iter_fwd_next( iter, dlist, delta_pool ) ) {
    fd_stake_delegation_t * stake_delegation = fork_dlist_iter_ele( iter, dlist, delta_pool );
    if( FD_LIKELY( !stake_delegation->is_tombstone ) ) {
      fd_stake_delegations_root_update(
          stake_delegations,
          &stake_delegation->stake_account,
          &stake_delegation->vote_account,
          stake_delegation->stake,
          stake_delegation->activation_epoch,
          stake_delegation->deactivation_epoch,
          stake_delegation->credits_observed,
          fd_stake_delegations_warmup_cooldown_rate_to_double( stake_delegation->warmup_cooldown_rate ) );
    } else {
      fd_stake_delegations_remove( stake_delegations, &stake_delegation->stake_account );
    }
  }
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
  while( !root_map_iter_done( iter->iter, iter->root_map, iter->root_pool ) ) {
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
  return root_map_iter_done( iter->iter, iter->root_map, iter->root_pool );
}

void
fd_stake_delegations_mark_delta( fd_stake_delegations_t * stake_delegations,
                                 ushort                   fork_idx ) {

  root_map_t *            root_map   = get_root_map( stake_delegations );
  fd_stake_delegation_t * root_pool  = get_root_pool( stake_delegations );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_dlist_t *          fork_dlist = get_fork_dlist( stake_delegations, fork_idx );

  /* Pass 1 (existing): point each unique stake_account's root entry to
     its most-recent delta (forward iteration means last write wins). */
  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( fork_dlist, delta_pool );
       !fork_dlist_iter_done( iter, fork_dlist, delta_pool );
       iter = fork_dlist_iter_fwd_next( iter, fork_dlist, delta_pool ) ) {
    fd_stake_delegation_t * delta_delegation = fork_dlist_iter_ele( iter, fork_dlist, delta_pool );

    fd_stake_delegation_t * base_delegation = root_map_ele_query( root_map, &delta_delegation->stake_account, NULL, root_pool);
    if( FD_UNLIKELY( !base_delegation ) ) {
      base_delegation                = root_pool_ele_acquire( root_pool );
      base_delegation->stake_account = delta_delegation->stake_account;
      root_map_ele_insert( root_map, base_delegation, root_pool );

      base_delegation->dne_in_root = 1;
      base_delegation->delta_idx   = (uint)delta_pool_idx( delta_pool, delta_delegation );
    } else {
      base_delegation->delta_idx = (uint)delta_pool_idx( delta_pool, delta_delegation );
    }
  }

  /* Pass 2: update vote_total_map for each unique stake_account.
     We detect "most recent" by checking delta_idx after pass 1. */
  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( fork_dlist, delta_pool );
       !fork_dlist_iter_done( iter, fork_dlist, delta_pool );
       iter = fork_dlist_iter_fwd_next( iter, fork_dlist, delta_pool ) ) {
    fd_stake_delegation_t * delta = fork_dlist_iter_ele( iter, fork_dlist, delta_pool );
    fd_stake_delegation_t * base  = root_map_ele_query( root_map, &delta->stake_account, NULL, root_pool );
    if( FD_UNLIKELY( !base ) ) continue;

    /* Only act on the most recent delta for this stake_account. */
    uint this_idx = (uint)delta_pool_idx( delta_pool, delta );
    if( base->delta_idx != this_idx ) continue;

    /* Subtract old (root) contribution, add new (delta) contribution. */
    if( !base->dne_in_root ) {
      fd_stake_delegations_vote_total_adjust( stake_delegations, &base->vote_account, -(long)base->stake );
    }
    if( !delta->is_tombstone ) {
      fd_stake_delegations_vote_total_adjust( stake_delegations, &delta->vote_account, (long)delta->stake );
    }
  }
}

void
fd_stake_delegations_unmark_delta( fd_stake_delegations_t * stake_delegations,
                                   ushort                   fork_idx ) {

  root_map_t *            root_map   = get_root_map( stake_delegations );
  fd_stake_delegation_t * root_pool  = get_root_pool( stake_delegations );
  fork_dlist_t *          fork_dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );

  /* Pass 1: reverse vote_total_map changes made during mark_delta.
     Must happen before pass 2 resets delta_idx. */
  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( fork_dlist, delta_pool );
       !fork_dlist_iter_done( iter, fork_dlist, delta_pool );
       iter = fork_dlist_iter_fwd_next( iter, fork_dlist, delta_pool ) ) {
    fd_stake_delegation_t * delta = fork_dlist_iter_ele( iter, fork_dlist, delta_pool );
    fd_stake_delegation_t * base  = root_map_ele_query( root_map, &delta->stake_account, NULL, root_pool );
    if( FD_UNLIKELY( !base ) ) continue;

    uint this_idx = (uint)delta_pool_idx( delta_pool, delta );
    if( base->delta_idx != this_idx ) continue;

    /* Reverse: subtract delta contribution, restore root contribution. */
    if( !delta->is_tombstone ) {
      fd_stake_delegations_vote_total_adjust( stake_delegations, &delta->vote_account, -(long)delta->stake );
    }
    if( !base->dne_in_root ) {
      fd_stake_delegations_vote_total_adjust( stake_delegations, &base->vote_account, (long)base->stake );
    }
  }

  /* Pass 2 (existing): reset delta_idx and clean up dne_in_root entries. */
  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( fork_dlist, delta_pool );
       !fork_dlist_iter_done( iter, fork_dlist, delta_pool );
       iter = fork_dlist_iter_fwd_next( iter, fork_dlist, delta_pool ) ) {
    fd_stake_delegation_t * delta_delegation = fork_dlist_iter_ele( iter, fork_dlist, delta_pool );

    fd_stake_delegation_t * base_delegation = root_map_ele_query( root_map, &delta_delegation->stake_account, NULL, root_pool );
    if( FD_UNLIKELY( !base_delegation ) ) {
      continue;
    }

    if( FD_UNLIKELY( base_delegation->dne_in_root )) {
      base_delegation->dne_in_root = 0;
      base_delegation->delta_idx   = UINT_MAX;
      root_map_ele_remove( root_map, &delta_delegation->stake_account, NULL, root_pool );
      root_pool_ele_release( root_pool, base_delegation );
    } else {
      base_delegation->delta_idx = UINT_MAX;
    }
  }
}
