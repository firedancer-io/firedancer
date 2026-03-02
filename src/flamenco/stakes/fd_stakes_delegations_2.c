#include "fd_stake_delegations.h"

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
                                      ulong expected_stake_accounts,
                                      ulong max_live_slots ) {
  ulong map_chain_cnt = stake_delegation_map_chain_cnt_est( expected_stake_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_delta_align(), sizeof(fd_stake_delegations_delta_t) );
  l = FD_LAYOUT_APPEND( l, stake_delegation_pool_align(),      stake_delegation_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, stake_delegation_map_align(),       stake_delegation_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, pool_align(),                       pool_footprint( max_live_slots ) );
  for( ushort i=0; i<max_live_slots; i++ ) {
    l = FD_LAYOUT_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
  }

  return FD_LAYOUT_FINI( l, fd_stake_delegations_delta_align() );
}

void *
fd_stake_delegations_delta_new( void * mem,
                                ulong  max_stake_accounts,
                                ulong  expected_stake_accounts,
                                ulong  max_live_slots,
                                ulong  seed ) {
  ulong map_chain_cnt = stake_delegation_map_chain_cnt_est( expected_stake_accounts );

  FD_LOG_WARNING(("MEM: %p", mem));

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_delta_t * stake_delegations_delta = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_delta_align(), sizeof(fd_stake_delegations_delta_t) );
  void *                         index_pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, stake_delegation_pool_align(),      stake_delegation_pool_footprint( max_stake_accounts ) );
  void *                         index_map_mem           = FD_SCRATCH_ALLOC_APPEND( l, stake_delegation_map_align(),       stake_delegation_map_footprint( map_chain_cnt ) );
  void *                         pool_mem                = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),                       pool_footprint( max_live_slots ) );
  for( ushort i=0; i<max_live_slots; i++ ) {
    FD_LOG_WARNING(("ASDF"));
    void * fork_dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, fork_dlist_align(), fork_dlist_footprint() );
    fork_dlist_t * fork_dlist = fork_dlist_join( fork_dlist_new( fork_dlist_mem ) );
    if( FD_UNLIKELY( !fork_dlist ) ) {
      FD_LOG_WARNING(( "Failed to create fork dlist" ));
      return NULL;
    }
    stake_delegations_delta->dlist_offsets_[ i ] = (ulong)fork_dlist - (ulong)mem;
  }

  fd_stake_delegation_t * stake_delegation_pool = stake_delegation_pool_join( stake_delegation_pool_new( index_pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !stake_delegation_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation pool" ));
    return NULL;
  }
  stake_delegations_delta->pool_offset_ = (ulong)stake_delegation_pool - (ulong)mem;

  stake_delegation_map_t * stake_delegation_map = stake_delegation_map_join( stake_delegation_map_new( index_map_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !stake_delegation_map ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation map" ));
    return NULL;
  }
  stake_delegations_delta->map_offset_ = (ulong)stake_delegation_map - (ulong)mem;

  pool_t * fork_pool = pool_join( pool_new( pool_mem, max_live_slots ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }
  stake_delegations_delta->fork_pool_offset_ = (ulong)fork_pool - (ulong)mem;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( stake_delegations_delta->magic ) = FD_STAKE_DELEGATIONS_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_stake_delegations_delta_t *
fd_stake_delegations_delta_join( void * mem ) {
  return mem;
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
  if( FD_UNLIKELY( !stake_delegation_pool_free( stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );

  fd_stake_delegation_t * stake_delegation = stake_delegation_pool_ele_acquire( stake_delegation_pool );
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
  if( FD_UNLIKELY( !stake_delegation_pool_free( stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fd_stake_delegation_t * stake_delegation = stake_delegation_pool_ele_acquire( stake_delegation_pool );
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
  if( FD_UNLIKELY( !stake_delegation_pool_free( stake_delegation_pool ) ) ) {
    FD_LOG_CRIT(( "no free stake delegations in pool" ));
  }

  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );

  for( fork_dlist_iter_t iter = fork_dlist_iter_fwd_init( fork_dlist, stake_delegation_pool );
       !fork_dlist_iter_done( iter, fork_dlist, stake_delegation_pool );
       iter = fork_dlist_iter_fwd_next( iter, fork_dlist, stake_delegation_pool ) ) {
    fd_stake_delegation_t * stake_delegation = fork_dlist_iter_ele( iter, fork_dlist, stake_delegation_pool );

    stake_delegation_pool_ele_release( stake_delegation_pool, stake_delegation );
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
                                      ulong iter ) {
  fork_dlist_t * fork_dlist = get_fork_dlist( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation_pool = get_stake_delegation_pool( stake_delegations );
  return fork_dlist_iter_ele( iter, fork_dlist, stake_delegation_pool );
}
