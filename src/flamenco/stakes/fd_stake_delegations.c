#include "fd_stake_delegations.h"
#include "fd_stakes.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../../util/fd_hash32.h"

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
#define MAP_KEY_HASH(key,seed) (fd_hash32( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               fork_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME  delta_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

struct fork_pool_ele { ushort next; };
typedef struct fork_pool_ele fork_pool_ele_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_pool_ele_t
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

#define POOL_NAME  pubkey_pool
#define POOL_T     fd_stake_delegation_ref_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               pubkey_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_ref_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

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

static inline fork_map_t *
get_fork_map( fd_stake_delegations_t const * stake_delegations,
              ushort                         fork_idx ) {
  ulong map_footprint = fork_map_footprint( FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT );
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->fork_map_offset_ + (ulong)fork_idx*map_footprint );
}

static inline fd_stake_delegation_ref_t *
get_pubkey_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->pubkey_pool_offset_ );
}

static inline pubkey_map_t *
get_pubkey_map( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->pubkey_map_offset_ );
}

static void
pubkey_ref_acquire( fd_stake_delegations_t * stake_delegations,
                    fd_pubkey_t const *      stake_account ) {
  fd_stake_delegation_ref_t * pool = get_pubkey_pool( stake_delegations );
  pubkey_map_t *              map  = get_pubkey_map( stake_delegations );

  fd_stake_delegation_ref_t * ref = pubkey_map_ele_query( map, stake_account, NULL, pool );
  if( FD_UNLIKELY( !ref ) ) {
    FD_CHECK_CRIT( pubkey_pool_free( pool ), "no free entries in stake delegation pubkey pool" );
    ref                = pubkey_pool_ele_acquire( pool );
    ref->stake_account = *stake_account;
    ref->refcnt        = 0U;
    stake_delegations->pubkey_idx_wmk_ = fd_ulong_max( stake_delegations->pubkey_idx_wmk_, pubkey_pool_idx( pool, ref )+1UL );
    FD_CHECK_CRIT( pubkey_map_ele_insert( map, ref, pool ), "unable to insert into stake delegation pubkey map" );
  }
  ref->refcnt++;
}

static void
pubkey_ref_release( fd_stake_delegations_t * stake_delegations,
                    fd_pubkey_t const *      stake_account ) {
  if( FD_UNLIKELY( stake_delegations->pubkey_fallback ) ) return;

  fd_stake_delegation_ref_t * pool = get_pubkey_pool( stake_delegations );
  pubkey_map_t *              map  = get_pubkey_map( stake_delegations );

  fd_stake_delegation_ref_t * ref = pubkey_map_ele_query( map, stake_account, NULL, pool );
  if( FD_UNLIKELY( !ref ) ) return;
  if( FD_UNLIKELY( !ref->refcnt ) ) return;

  if( FD_LIKELY( !--ref->refcnt ) ) {
    pubkey_map_ele_remove( map, stake_account, NULL, pool );
    pubkey_pool_ele_release( pool, ref );
  }
}

static void
pubkey_fallback_enter( fd_stake_delegations_t * stake_delegations,
                       fd_pubkey_t const *      stake_account ) {
  if( FD_UNLIKELY( !stake_delegations->pubkey_fallback ) ) {
    FD_LOG_WARNING(( "stake delegation pool exhausted at %lu stake accounts; falling back to "
                     "resolving stake delegations from the accounts database at the epoch boundary",
                     fd_stake_delegations_pubkey_cnt( stake_delegations ) ));
    stake_delegations->pubkey_fallback = 1;
  }
  pubkey_ref_acquire( stake_delegations, stake_account );
}

ulong
fd_stake_delegations_align( void ) {
  return FD_STAKE_DELEGATIONS_ALIGN;
}

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts,
                                ulong max_fallback_stake_accounts,
                                ulong expected_stake_accounts,
                                ulong max_live_slots ) {

  ulong map_chain_cnt    = root_map_chain_cnt_est( expected_stake_accounts );
  ulong pubkey_max       = max_fallback_stake_accounts;
  ulong pubkey_chain_cnt = pubkey_map_chain_cnt_est( expected_stake_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  l = FD_LAYOUT_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, delta_pool_align(),           delta_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, fork_map_align(),             max_live_slots*fork_map_footprint( FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT ) );
  l = FD_LAYOUT_APPEND( l, pubkey_pool_align(),          pubkey_pool_footprint( pubkey_max ) );
  l = FD_LAYOUT_APPEND( l, pubkey_map_align(),           pubkey_map_footprint( pubkey_chain_cnt ) );

  return FD_LAYOUT_FINI( l, fd_stake_delegations_align() );
}

void *
fd_stake_delegations_new( void * mem,
                          ulong  seed,
                          ulong  max_stake_accounts,
                          ulong  max_fallback_stake_accounts,
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
  ulong pubkey_max       = max_fallback_stake_accounts;
  ulong pubkey_chain_cnt = pubkey_map_chain_cnt_est( expected_stake_accounts );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_t * stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  void *                   pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  void *                   map_mem           = FD_SCRATCH_ALLOC_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  void *                   delta_pool_mem    = FD_SCRATCH_ALLOC_APPEND( l, delta_pool_align(),           delta_pool_footprint( max_stake_accounts ) );
  void *                   fork_pool_mem     = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  void *                   fork_map_mem      = FD_SCRATCH_ALLOC_APPEND( l, fork_map_align(),             max_live_slots*fork_map_footprint( FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT ) );
  void *                   pubkey_pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, pubkey_pool_align(),          pubkey_pool_footprint( pubkey_max ) );
  void *                   pubkey_map_mem    = FD_SCRATCH_ALLOC_APPEND( l, pubkey_map_align(),           pubkey_map_footprint( pubkey_chain_cnt ) );
  for( ushort i=0; i<(ushort)max_live_slots; i++ ) {
    void * fork_map_mem_i = (uchar *)fork_map_mem + (ulong)i*fork_map_footprint( FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT );
    fork_map_t * map = fork_map_join( fork_map_new( fork_map_mem_i, FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT, seed ) );
    if( FD_UNLIKELY( !map ) ) {
      FD_LOG_WARNING(( "Failed to create fork map" ));
      return NULL;
    }
  }

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( max_stake_accounts, max_fallback_stake_accounts, expected_stake_accounts, max_live_slots ) ) ) {
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

  fd_stake_delegation_ref_t * pubkey_pool = pubkey_pool_join( pubkey_pool_new( pubkey_pool_mem, pubkey_max ) );
  if( FD_UNLIKELY( !pubkey_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation pubkey pool" ));
    return NULL;
  }

  pubkey_map_t * pubkey_map = pubkey_map_join( pubkey_map_new( pubkey_map_mem, pubkey_chain_cnt, seed ) );
  if( FD_UNLIKELY( !pubkey_map ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation pubkey map" ));
    return NULL;
  }

  stake_delegations->max_stake_accounts_      = max_stake_accounts;
  stake_delegations->expected_stake_accounts_ = expected_stake_accounts;
  stake_delegations->pool_offset_             = (ulong)root_pool - (ulong)mem;
  stake_delegations->map_offset_              = (ulong)root_map - (ulong)mem;
  stake_delegations->delta_pool_offset_       = (ulong)delta_pool - (ulong)mem;
  stake_delegations->fork_pool_offset_        = (ulong)fork_pool - (ulong)mem;
  stake_delegations->fork_map_offset_         = (ulong)fork_map_mem - (ulong)mem;
  stake_delegations->pubkey_pool_offset_      = (ulong)pubkey_pool - (ulong)mem;
  stake_delegations->pubkey_map_offset_       = (ulong)pubkey_map - (ulong)mem;
  stake_delegations->max_pubkeys_             = pubkey_max;
  stake_delegations->pubkey_idx_wmk_          = 0UL;

  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;
  stake_delegations->pool_idx_wmk_      = 0UL;
  stake_delegations->pubkey_fallback    = 0;
  stake_delegations->fp_warmed_awarded  = 0;

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

  if( FD_UNLIKELY( stake_delegations->magic!=FD_STAKE_DELEGATIONS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid stake delegations magic" ));
    return NULL;
  }

  return stake_delegations;
}

void
fd_stake_delegations_reset( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_write( &stake_delegations->lock );
  root_pool_reset( get_root_pool( stake_delegations ) );
  root_map_reset( get_root_map( stake_delegations ) );
  delta_pool_reset( get_delta_pool( stake_delegations ) );
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  ulong max_forks = fork_pool_max( fork_pool );
  for( ulong i=0UL; i<max_forks; i++ ) {
    fork_map_reset( get_fork_map( stake_delegations, (ushort)i ) );
  }
  fork_pool_reset( fork_pool );
  pubkey_pool_reset( get_pubkey_pool( stake_delegations ) );
  pubkey_map_reset( get_pubkey_map( stake_delegations ) );
  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;
  stake_delegations->pool_idx_wmk_      = 0UL;
  stake_delegations->pubkey_idx_wmk_    = 0UL;
  stake_delegations->pubkey_fallback    = 0;
  stake_delegations->fp_warmed_awarded  = 0;
  fd_rwlock_unwrite( &stake_delegations->lock );
}

fd_stake_delegation_t const *
fd_stake_delegation_root_query( fd_stake_delegations_t const * stake_delegations,
                                fd_pubkey_t const *            stake_account ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map = get_root_map( stake_delegations );

  return root_map_ele_query_const( map, stake_account, NULL, pool );
}

/* root_update is the unlocked core of fd_stake_delegations_root_update.
   Callers that already hold the lock use it directly.  Returns the root
   pool element holding the delegation, or NULL if the root pool was
   exhausted and the delegation got pushed into the pubkey fallback tier
   instead. */

static fd_stake_delegation_t *
root_update( fd_stake_delegations_t * stake_delegations,
             fd_pubkey_t const *      stake_account,
             fd_pubkey_t const *      vote_account,
             ulong                    stake,
             ulong                    activation_epoch,
             ulong                    deactivation_epoch,
             ulong                    credits_observed,
             ulong                    lamports,
             uint                     acc_dlen,
             uchar                    warmup_cooldown_rate ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map  = get_root_map( stake_delegations );

  fd_stake_delegation_t * stake_delegation = root_map_ele_query( map, stake_account, NULL, pool );
  if( FD_LIKELY( !stake_delegation ) ) {
    if( FD_UNLIKELY( !root_pool_free( pool ) ) ) {
      pubkey_fallback_enter( stake_delegations, stake_account );
      return NULL;
    }
    stake_delegation                 = root_pool_ele_acquire( pool );
    stake_delegation->stake_account  = *stake_account;
    stake_delegations->pool_idx_wmk_ = fd_ulong_max( stake_delegations->pool_idx_wmk_, root_pool_idx( pool, stake_delegation )+1UL );
    FD_CHECK_CRIT( root_map_ele_insert( map, stake_delegation, pool ), "unable to insert stake delegation into map" );
    pubkey_ref_acquire( stake_delegations, stake_account );
  }

  FD_CHECK_ERR( (long)activation_epoch  <USHORT_MAX, "activation_epoch overflow"   );
  FD_CHECK_ERR( (long)deactivation_epoch<USHORT_MAX, "deactivation_epoch overflow" );

  stake_delegation->vote_account         = *vote_account;
  stake_delegation->stake                = stake;
  stake_delegation->lamports             = lamports;
  stake_delegation->acc_dlen             = acc_dlen;
  stake_delegation->activation_epoch     = (ushort)activation_epoch;
  stake_delegation->deactivation_epoch   = (ushort)deactivation_epoch;
  stake_delegation->credits_observed     = credits_observed;
  stake_delegation->warmup_cooldown_rate = warmup_cooldown_rate;
  stake_delegation->dne_in_root          = 0;
  stake_delegation->delta_idx            = UINT_MAX;
  stake_delegation->in_use               = 1;
  stake_delegation->state                = FD_STAKE_DELEGATION_STATE_UNKNOWN;

  return stake_delegation;
}

void
fd_stake_delegations_root_update( fd_stake_delegations_t * stake_delegations,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate ) {
  fd_rwlock_write( &stake_delegations->lock );
  root_update( stake_delegations, stake_account, vote_account, stake, activation_epoch,
               deactivation_epoch, credits_observed, lamports, acc_dlen, warmup_cooldown_rate );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

#if FD_HAS_DOUBLE

void
fd_stake_delegations_refresh( fd_stake_delegations_t *   stake_delegations,
                              ulong                      epoch,
                              fd_stake_history_t const * stake_history,
                              ulong *                    warmup_cooldown_rate_epoch,
                              int                        use_fixed_point_stake_math,
                              fd_accdb_t *               accdb,
                              fd_accdb_fork_id_t         fork_id ) {
  fd_rwlock_write( &stake_delegations->lock );

  int history_contiguous = fd_sysvar_stake_history_is_contiguous( stake_history );

  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;

  root_map_t *                map      = get_root_map( stake_delegations );
  fd_stake_delegation_t *     pool     = get_root_pool( stake_delegations );
  pubkey_map_t *              ref_map  = get_pubkey_map( stake_delegations );
  fd_stake_delegation_ref_t * ref_pool = get_pubkey_pool( stake_delegations );

  /* Drive the refresh off the pubkey tier rather than the root pool.  The
     tier is a superset of the root by construction, so in the normal case
     this visits exactly the same accounts, and in fallback mode it also
     visits the accounts that never made it into the root map.  Refresh
     runs at boot before any fork exists, which is what makes it safe to
     rebuild both tiers in place and to reclaim entries whose refcounts
     fallback mode left meaningless. */

  ulong const wmk = stake_delegations->pubkey_idx_wmk_;

#define BATCH 64UL
  uchar const * pubkeys[ BATCH ];
  int           writable[ BATCH ];
  fd_acc_t      accs[ BATCH ];
  ulong         ref_idx[ BATCH ];

  ulong i = 0UL;
  while( i<wmk ) {
    ulong batch_n = 0UL;
    while( i<wmk && batch_n<BATCH ) {
      if( FD_LIKELY( ref_pool[ i ].refcnt ) ) {
        pubkeys[ batch_n ]  = ref_pool[ i ].stake_account.uc;
        writable[ batch_n ] = 0;
        ref_idx[ batch_n ]  = i;
        batch_n++;
      }
      i++;
    }
    if( FD_UNLIKELY( !batch_n ) ) continue;

    fd_accdb_acquire( accdb, fork_id, batch_n, pubkeys, writable, accs );

    for( ulong j=0UL; j<batch_n; j++ ) {
      fd_pubkey_t const *      stake_account = (fd_pubkey_t const *)pubkeys[ j ];
      fd_stake_state_t const * stake         = accs[ j ].lamports ? fd_stakes_get_state( &accs[ j ] ) : NULL;

      if( FD_UNLIKELY( !stake || stake->stake_type!=FD_STAKE_STATE_STAKE ) ) {
        fd_stake_delegation_t * delegation = root_map_ele_query( map, stake_account, NULL, pool );
        if( FD_LIKELY( delegation ) ) {
          root_map_idx_remove( map, stake_account, UINT_MAX, pool );
          delegation->in_use = 0;
          root_pool_ele_release( pool, delegation );
        }
        pubkey_map_ele_remove( ref_map, stake_account, NULL, ref_pool );
        ref_pool[ ref_idx[ j ] ].refcnt = 0U;
        pubkey_pool_ele_release( ref_pool, &ref_pool[ ref_idx[ j ] ] );
        continue;
      }

      fd_stake_delegation_t * delegation = root_update(
          stake_delegations,
          stake_account,
          &stake->stake.stake.delegation.voter_pubkey,
          stake->stake.stake.delegation.stake,
          stake->stake.stake.delegation.activation_epoch,
          stake->stake.stake.delegation.deactivation_epoch,
          stake->stake.stake.credits_observed,
          accs[ j ].lamports,
          (uint)accs[ j ].data_len,
          fd_stake_warmup_cooldown_rate( epoch, warmup_cooldown_rate_epoch ) );

      fd_stake_history_entry_t history = fd_delegation_activation_status( &stake->stake.stake.delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
      stake_delegations->effective_stake    += history.effective;
      stake_delegations->activating_stake   += history.activating;
      stake_delegations->deactivating_stake += history.deactivating;

      /* A delegation that the root pool couldn't take has no element to
         tag.  The fallback tier resolves it from the accounts database
         at the boundary and hands out an untagged copy. */
      if( FD_LIKELY( delegation ) ) {
        uchar state = fd_stake_delegation_classify( delegation, history, epoch );
        delegation->state = !history_contiguous ? FD_STAKE_DELEGATION_STATE_UNKNOWN : state;
        if( FD_LIKELY( delegation->state==FD_STAKE_DELEGATION_STATE_WARMED && !use_fixed_point_stake_math ) ) {
          stake_delegations->fp_warmed_awarded = 1;
        }
      }
    }

    fd_accdb_release( accdb, batch_n, accs );
  }
#undef BATCH

  /* Every surviving entry now holds exactly one reference, the root map's,
     because there are no fork deltas at boot.  Rewriting the refcounts
     repairs any that fallback mode left unpaired. */
  for( ulong idx=0UL; idx<stake_delegations->pubkey_idx_wmk_; idx++ ) {
    if( FD_LIKELY( ref_pool[ idx ].refcnt ) ) ref_pool[ idx ].refcnt = 1U;
  }

  /* If pruning freed enough room for every account to sit in the root map,
     the fallback is no longer needed.  This is the only place the sticky
     flag is cleared. */
  if( FD_UNLIKELY( stake_delegations->pubkey_fallback ) &&
      pubkey_pool_used( ref_pool )==root_pool_used( pool ) ) {
    FD_LOG_NOTICE(( "stake delegations no longer need the pubkey fallback; %lu stake accounts fit in the root map",
                    root_pool_used( pool ) ));
    stake_delegations->pubkey_fallback = 0;
  }

  fd_rwlock_unwrite( &stake_delegations->lock );
}

#endif

ulong
fd_stake_delegations_base_cnt( fd_stake_delegations_t const * stake_delegations ) {
  return root_pool_used( get_root_pool( stake_delegations ) );
}

ulong
fd_stake_delegations_pubkey_cnt( fd_stake_delegations_t const * stake_delegations ) {
  return pubkey_pool_used( get_pubkey_pool( stake_delegations ) );
}

/* Fork-aware delta operations */

ushort
fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  FD_CHECK_CRIT( fork_pool_free( fork_pool ), "no free forks in pool. The system has forked too wide." );
  ushort fork_idx = (ushort)fork_pool_idx_acquire( fork_pool );
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
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate ) {
  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool       = get_delta_pool( stake_delegations );
  fork_map_t *            map              = get_fork_map( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation = fork_map_ele_query( map, stake_account, NULL, delta_pool );
  if( FD_LIKELY( !stake_delegation ) ) {
    if( FD_UNLIKELY( !delta_pool_free( delta_pool ) ) ) {
      /* The delta pool cannot take this stake account.  Record it in the
         pubkey fallback tier and drop the delegation state on the floor:
         the epoch boundary will read it back out of the accounts
         database. */
      pubkey_fallback_enter( stake_delegations, stake_account );
    } else {
      stake_delegation                = delta_pool_ele_acquire( delta_pool );
      stake_delegation->stake_account = *stake_account;
      fork_map_ele_insert( map, stake_delegation, delta_pool );
      pubkey_ref_acquire( stake_delegations, stake_account );
    }
  }

  if( FD_LIKELY( stake_delegation ) ) {
    FD_CHECK_ERR( (long)activation_epoch  <USHORT_MAX, "activation_epoch overflow"   );
    FD_CHECK_ERR( (long)deactivation_epoch<USHORT_MAX, "deactivation_epoch overflow" );
    stake_delegation->vote_account         = *vote_account;
    stake_delegation->stake                = stake;
    stake_delegation->lamports             = lamports;
    stake_delegation->acc_dlen             = acc_dlen;
    stake_delegation->activation_epoch     = (ushort)activation_epoch;
    stake_delegation->deactivation_epoch   = (ushort)deactivation_epoch;
    stake_delegation->credits_observed     = credits_observed;
    stake_delegation->warmup_cooldown_rate = warmup_cooldown_rate;
    stake_delegation->is_tombstone         = 0;
    stake_delegation->state                = FD_STAKE_DELEGATION_STATE_UNKNOWN;
  }

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account ) {
  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool       = get_delta_pool( stake_delegations );
  fork_map_t *            map              = get_fork_map( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation = fork_map_ele_query( map, stake_account, NULL, delta_pool );
  if( FD_LIKELY( !stake_delegation ) ) {
    if( FD_UNLIKELY( !delta_pool_free( delta_pool ) ) ) {
      pubkey_fallback_enter( stake_delegations, stake_account );
    } else {
      stake_delegation                = delta_pool_ele_acquire( delta_pool );
      stake_delegation->stake_account = *stake_account;
      fork_map_ele_insert( map, stake_delegation, delta_pool );
      pubkey_ref_acquire( stake_delegations, stake_account );
    }
  }

  if( FD_LIKELY( stake_delegation ) ) {
    stake_delegation->lamports     = 0UL;
    stake_delegation->acc_dlen     = 0U;
    stake_delegation->is_tombstone = 1;
    stake_delegation->state        = FD_STAKE_DELEGATION_STATE_UNKNOWN;

    FD_BASE58_ENCODE_32_BYTES( stake_delegation->stake_account.uc, stake_account_out );
    FD_LOG_DEBUG(( "fork_remove: stake_account=%s", stake_account_out ));
  }

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_evict_fork( fd_stake_delegations_t * stake_delegations,
                                 ushort                   fork_idx ) {
  if( fork_idx==USHORT_MAX ) return;

  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_map_t *            fork_map   = get_fork_map( stake_delegations, fork_idx );

  fork_map_iter_t iter = fork_map_iter_init( fork_map, delta_pool );
  while( !fork_map_iter_done( iter, fork_map, delta_pool ) ) {
    fd_stake_delegation_t * ele = fork_map_iter_ele( iter, fork_map, delta_pool );
    iter = fork_map_iter_next( iter, fork_map, delta_pool );
    pubkey_ref_release( stake_delegations, &ele->stake_account );
    delta_pool_ele_release( delta_pool, ele );
  }
  fork_map_reset( fork_map );

  fork_pool_idx_release( get_fork_pool( stake_delegations ), fork_idx );

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_apply_fork_delta( ulong                      epoch,
                                       fd_stake_history_t const * stake_history,
                                       ulong *                    warmup_cooldown_rate_epoch,
                                       int                        use_fixed_point_stake_math,
                                       fd_stake_delegations_t *   stake_delegations,
                                       ushort                     fork_idx ) {
  fd_rwlock_write( &stake_delegations->lock );

  int history_contiguous = fd_sysvar_stake_history_is_contiguous( stake_history );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_map_t *            fork_map   = get_fork_map( stake_delegations, fork_idx );

  for( fork_map_iter_t iter = fork_map_iter_init( fork_map, delta_pool );
       !fork_map_iter_done( iter, fork_map, delta_pool );
       iter = fork_map_iter_next( iter, fork_map, delta_pool ) ) {
    fd_stake_delegation_t * stake_delegation = fork_map_iter_ele( iter, fork_map, delta_pool );
    if( FD_LIKELY( !stake_delegation->is_tombstone ) ) {
      /* If the acc in the delta is an update:
         - If the acc already exists, subtract the old version's stake
         - Insert/update the new version
         - Add the new version's stake to the totals */
      fd_stake_delegation_t const * old_delegation = fd_stake_delegation_root_query( stake_delegations, &stake_delegation->stake_account );
      if( FD_LIKELY( old_delegation ) ) {
        fd_stake_history_entry_t old_entry     = fd_stakes_activating_and_deactivating( old_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
        stake_delegations->effective_stake    -= old_entry.effective;
        stake_delegations->activating_stake   -= old_entry.activating;
        stake_delegations->deactivating_stake -= old_entry.deactivating;
      }

      fd_stake_delegation_t * root_ele = root_update(
          stake_delegations,
          &stake_delegation->stake_account,
          &stake_delegation->vote_account,
          stake_delegation->stake,
          stake_delegation->activation_epoch==(ushort)USHORT_MAX   ? ULONG_MAX : stake_delegation->activation_epoch,
          stake_delegation->deactivation_epoch==(ushort)USHORT_MAX ? ULONG_MAX : stake_delegation->deactivation_epoch,
          stake_delegation->credits_observed,
          stake_delegation->lamports,
          stake_delegation->acc_dlen,
          stake_delegation->warmup_cooldown_rate );

      fd_stake_history_entry_t new_acc = fd_stakes_activating_and_deactivating( stake_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
      stake_delegations->effective_stake    += new_acc.effective;
      stake_delegations->activating_stake   += new_acc.activating;
      stake_delegations->deactivating_stake += new_acc.deactivating;

      /* A delegation that the root pool couldn't take has no element to
         tag.  The fallback tier resolves it from the accounts database
         at the boundary and hands out an untagged copy. */
      if( FD_LIKELY( root_ele ) ) {
        uchar state = fd_stake_delegation_classify( root_ele, new_acc, epoch );
        root_ele->state = !history_contiguous ? FD_STAKE_DELEGATION_STATE_UNKNOWN : state;
        if( FD_LIKELY( root_ele->state==FD_STAKE_DELEGATION_STATE_WARMED && !use_fixed_point_stake_math ) ) {
          stake_delegations->fp_warmed_awarded = 1;
        }
      }
    } else {
      /* If the stake delegation in the delta is a tombstone, just
         remove the stake delegation from the root map and subtract
         its stake from the totals. */
      fd_stake_delegation_t * root_pool = get_root_pool( stake_delegations );
      root_map_t *            root_map  = get_root_map( stake_delegations );
      ulong delegation_idx = root_map_idx_query( root_map, &stake_delegation->stake_account, UINT_MAX, root_pool );
      if( FD_LIKELY( delegation_idx!=UINT_MAX ) ) {
        fd_stake_delegation_t * old_delegation = root_pool + delegation_idx;
        fd_stake_history_entry_t old_entry = fd_stakes_activating_and_deactivating( old_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
        stake_delegations->effective_stake    -= old_entry.effective;
        stake_delegations->activating_stake   -= old_entry.activating;
        stake_delegations->deactivating_stake -= old_entry.deactivating;
        root_map_idx_remove( root_map, &stake_delegation->stake_account, delegation_idx, root_pool );
        old_delegation->in_use = 0;
        root_pool_idx_release( root_pool, delegation_idx );
        pubkey_ref_release( stake_delegations, &stake_delegation->stake_account );
      }
    }
  }
  FD_LOG_DEBUG(( "effective_stake=%lu, activating_stake=%lu, deactivating_stake=%lu", stake_delegations->effective_stake, stake_delegations->activating_stake, stake_delegations->deactivating_stake ));

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_iter_advance_fallback( fd_stake_delegations_iter_t * iter ) {
  fd_stake_delegations_t const * stake_delegations = iter->stake_delegations;
  fd_stake_delegation_ref_t *    pool              = get_pubkey_pool( stake_delegations );

  for(;;) {
    if( FD_LIKELY( iter->batch_idx<iter->batch_cnt ) ) {
      iter->ele = &iter->batch[ iter->batch_idx ];
      iter->idx = iter->batch_pool_idx[ iter->batch_idx ];
      return;
    }

    if( FD_UNLIKELY( iter->scan_idx>=iter->wmk ) ) {
      iter->ele = NULL;
      return;
    }

    uchar const * pubkeys [ FD_STAKE_DELEGATIONS_ITER_BATCH ];
    int           writable[ FD_STAKE_DELEGATIONS_ITER_BATCH ];
    ulong         pool_idx[ FD_STAKE_DELEGATIONS_ITER_BATCH ];
    fd_acc_t      accs    [ FD_STAKE_DELEGATIONS_ITER_BATCH ];

    ulong batch_n = 0UL;
    while( iter->scan_idx<iter->wmk && batch_n<FD_STAKE_DELEGATIONS_ITER_BATCH ) {
      fd_stake_delegation_ref_t * ref = pool + iter->scan_idx;
      if( FD_LIKELY( ref->refcnt ) ) {
        pubkeys [ batch_n ] = ref->stake_account.uc;
        writable[ batch_n ] = 0;
        pool_idx[ batch_n ] = iter->scan_idx;
        batch_n++;
      }
      iter->scan_idx++;
    }
    if( FD_UNLIKELY( !batch_n ) ) continue;

    fd_accdb_acquire( iter->accdb, iter->accdb_fork_id, batch_n, pubkeys, writable, accs );

    ulong out = 0UL;
    for( ulong j=0UL; j<batch_n; j++ ) {
      if( FD_UNLIKELY( !accs[ j ].lamports ) ) continue;

      fd_stake_state_t const * stake = fd_stakes_get_state( &accs[ j ] );
      if( FD_UNLIKELY( !stake || stake->stake_type!=FD_STAKE_STATE_STAKE ) ) continue;

      fd_delegation_t const * delegation = &stake->stake.stake.delegation;
      fd_stake_delegation_t * ele        = &iter->batch[ out ];

      FD_CHECK_ERR( (long)delegation->activation_epoch  <USHORT_MAX, "activation_epoch overflow"   );
      FD_CHECK_ERR( (long)delegation->deactivation_epoch<USHORT_MAX, "deactivation_epoch overflow" );
      ele->stake_account        = *(fd_pubkey_t const *)pubkeys[ j ];
      ele->vote_account         = delegation->voter_pubkey;
      ele->stake                = delegation->stake;
      ele->lamports             = accs[ j ].lamports;
      ele->credits_observed     = stake->stake.stake.credits_observed;
      ele->acc_dlen             = (uint)accs[ j ].data_len;
      ele->next_                = UINT_MAX;
      ele->delta_idx            = UINT_MAX;
      ele->activation_epoch     = (ushort)fd_ulong_min( delegation->activation_epoch, USHORT_MAX );
      ele->deactivation_epoch   = (ushort)fd_ulong_min( delegation->deactivation_epoch, USHORT_MAX );
      ele->is_tombstone         = 0;
      ele->warmup_cooldown_rate = fd_stake_warmup_cooldown_rate( iter->epoch, iter->warmup_cooldown_rate_epoch );
      ele->in_use               = 1;
      ele->state                = FD_STAKE_DELEGATION_STATE_UNKNOWN; /* Resolved copies are never tagged. */

      iter->batch_pool_idx[ out ] = pool_idx[ j ];
      out++;
    }

    fd_accdb_release( iter->accdb, batch_n, accs );

    iter->batch_cnt = out;
    iter->batch_idx = 0UL;
  }
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations,
                                fd_accdb_t *                   accdb,
                                fd_accdb_fork_id_t             accdb_fork_id,
                                ulong                          epoch,
                                ulong *                        warmup_cooldown_rate_epoch ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  iter->root_pool         = get_root_pool( stake_delegations );
  iter->delta_pool        = get_delta_pool( stake_delegations );
  iter->stake_delegations = stake_delegations;
  iter->idx               = 0UL;
  iter->scan_idx          = 0UL;
  iter->batch_cnt         = 0UL;
  iter->batch_idx         = 0UL;
  iter->fallback          = stake_delegations->pubkey_fallback;

  if( FD_UNLIKELY( iter->fallback ) ) {
    if( FD_UNLIKELY( !accdb ) ) {
      FD_LOG_CRIT(( "stake delegations are in pubkey fallback mode but no accounts database was "
                    "supplied to resolve them; iterating the root map alone would silently drop "
                    "stake accounts" ));
    }
    iter->accdb                      = accdb;
    iter->accdb_fork_id              = accdb_fork_id;
    iter->epoch                      = epoch;
    iter->warmup_cooldown_rate_epoch = warmup_cooldown_rate_epoch;
    iter->wmk                        = stake_delegations->pubkey_idx_wmk_;
    fd_stake_delegations_iter_advance_fallback( iter );
    return iter;
  }

  iter->wmk = stake_delegations->pool_idx_wmk_;
  fd_stake_delegations_iter_advance_private( iter );

  return iter;
}

void
fd_stake_delegations_mark_delta( fd_stake_delegations_t *   stake_delegations,
                                 ulong                      epoch,
                                 fd_stake_history_t const * stake_history,
                                 ulong *                    warmup_cooldown_rate_epoch,
                                 int                        use_fixed_point_stake_math,
                                 ushort                     fork_idx ) {
  root_map_t *            root_map   = get_root_map( stake_delegations );
  fd_stake_delegation_t * root_pool  = get_root_pool( stake_delegations );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_map_t *            fork_map   = get_fork_map( stake_delegations, fork_idx );

  for( fork_map_iter_t iter = fork_map_iter_init( fork_map, delta_pool );
       !fork_map_iter_done( iter, fork_map, delta_pool );
       iter = fork_map_iter_next( iter, fork_map, delta_pool ) ) {
    fd_stake_delegation_t * delta_delegation = fork_map_iter_ele( iter, fork_map, delta_pool );
    fd_stake_delegation_t * base_delegation  = root_map_ele_query( root_map, &delta_delegation->stake_account, NULL, root_pool);
    if( FD_UNLIKELY( !base_delegation ) ) {
      if( FD_UNLIKELY( !root_pool_free( root_pool ) ) ) {
        /* No room to project this delta into the root for the duration of
           the iteration.  The stake totals are recomputed from scratch in
           fallback mode, so skipping the bookkeeping below is safe, and
           the boundary sweep picks the account up from the fallback
           tier. */
        pubkey_fallback_enter( stake_delegations, &delta_delegation->stake_account );
        continue;
      }
      /* No pubkey tier reference is taken for this projection, and
         correspondingly none is dropped when unmark_delta releases it: the
         delta entry driving this loop already holds one. */
      base_delegation                  = root_pool_ele_acquire( root_pool );
      base_delegation->stake_account   = delta_delegation->stake_account;
      base_delegation->lamports        = 0UL;
      base_delegation->acc_dlen        = 0U;
      base_delegation->dne_in_root     = 1;
      base_delegation->delta_idx       = (uint)delta_pool_idx( delta_pool, delta_delegation );
      base_delegation->in_use          = 1;
      base_delegation->state           = FD_STAKE_DELEGATION_STATE_UNKNOWN;
      stake_delegations->pool_idx_wmk_ = fd_ulong_max( stake_delegations->pool_idx_wmk_, root_pool_idx( root_pool, base_delegation )+1UL );
      root_map_ele_insert( root_map, base_delegation, root_pool );
    } else {
      /* Subtract the old version's stake if it's not a tombstone. */
      fd_stake_delegation_t *  old_delegation = base_delegation->delta_idx==UINT_MAX ? base_delegation : delta_pool_ele( delta_pool, base_delegation->delta_idx );
      if( FD_LIKELY( base_delegation->delta_idx==UINT_MAX || !old_delegation->is_tombstone ) ) {
        fd_stake_history_entry_t old_entry      = fd_stakes_activating_and_deactivating( old_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
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
      fd_stake_history_entry_t new_acc = fd_stakes_activating_and_deactivating( delta_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
      stake_delegations->effective_stake    += new_acc.effective;
      stake_delegations->activating_stake   += new_acc.activating;
      stake_delegations->deactivating_stake += new_acc.deactivating;
    }
  }
}

void
fd_stake_delegations_unmark_delta( fd_stake_delegations_t *   stake_delegations,
                                   ulong                      epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    warmup_cooldown_rate_epoch,
                                   int                        use_fixed_point_stake_math,
                                   ushort                     fork_idx ) {
  root_map_t *            root_map   = get_root_map( stake_delegations );
  fd_stake_delegation_t * root_pool  = get_root_pool( stake_delegations );
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_map_t *            fork_map   = get_fork_map( stake_delegations, fork_idx );

  for( fork_map_iter_t iter = fork_map_iter_init( fork_map, delta_pool );
       !fork_map_iter_done( iter, fork_map, delta_pool );
       iter = fork_map_iter_next( iter, fork_map, delta_pool ) ) {
    fd_stake_delegation_t * delta_delegation = fork_map_iter_ele( iter, fork_map, delta_pool );
    fd_stake_delegation_t * base_delegation  = root_map_ele_query( root_map, &delta_delegation->stake_account, NULL, root_pool );
    if( FD_UNLIKELY( !base_delegation ) ) continue;

    uint delta_idx = (uint)delta_pool_idx( delta_pool, delta_delegation );
    if( FD_UNLIKELY( base_delegation->delta_idx!=delta_idx ) ) continue;

    if( FD_UNLIKELY( base_delegation->dne_in_root )) {
      if( FD_LIKELY( !delta_delegation->is_tombstone ) ) {
        fd_stake_history_entry_t acc = fd_stakes_activating_and_deactivating( delta_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
        stake_delegations->effective_stake    -= acc.effective;
        stake_delegations->activating_stake   -= acc.activating;
        stake_delegations->deactivating_stake -= acc.deactivating;
      }

      base_delegation->dne_in_root = 0;
      base_delegation->delta_idx   = UINT_MAX;
      base_delegation->in_use      = 0;
      root_map_ele_remove( root_map, &delta_delegation->stake_account, NULL, root_pool );
      root_pool_ele_release( root_pool, base_delegation );

    } else {
      if( FD_LIKELY( !delta_delegation->is_tombstone ) ) {
        fd_stake_history_entry_t acc = fd_stakes_activating_and_deactivating( delta_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
        stake_delegations->effective_stake    -= acc.effective;
        stake_delegations->activating_stake   -= acc.activating;
        stake_delegations->deactivating_stake -= acc.deactivating;
      }

      base_delegation->delta_idx = UINT_MAX;

      fd_stake_history_entry_t acc = fd_stakes_activating_and_deactivating( base_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
      stake_delegations->effective_stake    += acc.effective;
      stake_delegations->activating_stake   += acc.activating;
      stake_delegations->deactivating_stake += acc.deactivating;
    }
  }
}

void
fd_stake_delegations_invalidate_warmed( fd_stake_delegations_t * stake_delegations ) {
  fd_stake_delegation_t * root_pool = get_root_pool( stake_delegations );
  for( ulong i=0UL; i<stake_delegations->pool_idx_wmk_; i++ ) {
    fd_stake_delegation_t * delegation = &root_pool[ i ];
    if( FD_LIKELY( delegation->in_use && delegation->state==FD_STAKE_DELEGATION_STATE_WARMED ) ) {
      delegation->state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    }
  }
  stake_delegations->fp_warmed_awarded = 0;
}
