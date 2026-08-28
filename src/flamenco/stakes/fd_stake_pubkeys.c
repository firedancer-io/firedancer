#include "fd_stake_pubkeys.h"
#include "../fd_rwlock.h"
#include "../../util/fd_hash32.h"

struct fd_stake_pubkey_ref {
  fd_pubkey_t pubkey;
  uint        next_;
  uint        refcnt;
};
typedef struct fd_stake_pubkey_ref fd_stake_pubkey_ref_t;

FD_STATIC_ASSERT( sizeof(fd_stake_pubkey_ref_t)==40UL, fd_stake_pubkey_ref );

#define POOL_NAME  stake_pubkey_pool
#define POOL_T     fd_stake_pubkey_ref_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               stake_pubkey_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_pubkey_ref_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct fd_stake_pubkeys {
  ulong       magic;
  ulong       pool_offset;
  ulong       map_offset;
  ulong       max_pubkeys;
  ulong       idx_wmark;
  fd_rwlock_t lock;
  int         fallback;
};

static inline fd_stake_pubkey_ref_t *
get_pool( fd_stake_pubkeys_t const * pubkeys ) {
  return fd_type_pun( (uchar *)pubkeys + pubkeys->pool_offset );
}

static inline stake_pubkey_map_t *
get_map( fd_stake_pubkeys_t const * pubkeys ) {
  return fd_type_pun( (uchar *)pubkeys + pubkeys->map_offset );
}

ulong
fd_stake_pubkeys_align( void ) {
  return FD_STAKE_PUBKEYS_ALIGN;
}

ulong
fd_stake_pubkeys_footprint( ulong max_pubkeys,
                            ulong expected_pubkeys ) {
  if( FD_UNLIKELY( !max_pubkeys || max_pubkeys>=(ulong)UINT_MAX ) ) return 0UL;

  ulong chain_cnt = stake_pubkey_map_chain_cnt_est( expected_pubkeys );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_pubkeys_align(),  sizeof(fd_stake_pubkeys_t) );
  l = FD_LAYOUT_APPEND( l, stake_pubkey_pool_align(), stake_pubkey_pool_footprint( max_pubkeys ) );
  l = FD_LAYOUT_APPEND( l, stake_pubkey_map_align(),  stake_pubkey_map_footprint( chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_stake_pubkeys_align() );
}

void *
fd_stake_pubkeys_new( void * mem,
                      ulong  seed,
                      ulong  max_pubkeys,
                      ulong  expected_pubkeys ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_pubkeys_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_stake_pubkeys_footprint( max_pubkeys, expected_pubkeys );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid pubkey capacity" ));
    return NULL;
  }

  ulong chain_cnt = stake_pubkey_map_chain_cnt_est( expected_pubkeys );
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_pubkeys_t * pubkeys  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_pubkeys_align(), sizeof(fd_stake_pubkeys_t) );
  void *               pool_mem = FD_SCRATCH_ALLOC_APPEND( l, stake_pubkey_pool_align(), stake_pubkey_pool_footprint( max_pubkeys ) );
  void *               map_mem  = FD_SCRATCH_ALLOC_APPEND( l, stake_pubkey_map_align(),  stake_pubkey_map_footprint( chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_pubkeys_align() )!=(ulong)mem+footprint ) ) {
    FD_LOG_WARNING(( "fd_stake_pubkeys_new: bad layout" ));
    return NULL;
  }

  fd_stake_pubkey_ref_t * pool = stake_pubkey_pool_join( stake_pubkey_pool_new( pool_mem, max_pubkeys ) );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "failed to create stake pubkey pool" ));
    return NULL;
  }

  stake_pubkey_map_t * map = stake_pubkey_map_join( stake_pubkey_map_new( map_mem, chain_cnt, seed ) );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "failed to create stake pubkey map" ));
    return NULL;
  }

  pubkeys->pool_offset = (ulong)pool - (ulong)pubkeys;
  pubkeys->map_offset  = (ulong)map  - (ulong)pubkeys;
  pubkeys->max_pubkeys = max_pubkeys;
  pubkeys->idx_wmark   = 0UL;
  pubkeys->fallback    = 0;
  fd_rwlock_new( &pubkeys->lock );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( pubkeys->magic ) = FD_STAKE_PUBKEYS_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_stake_pubkeys_t *
fd_stake_pubkeys_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_pubkeys_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  fd_stake_pubkeys_t * pubkeys = (fd_stake_pubkeys_t *)mem;
  if( FD_UNLIKELY( pubkeys->magic!=FD_STAKE_PUBKEYS_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid stake pubkeys magic" ));
    return NULL;
  }
  return pubkeys;
}

void
fd_stake_pubkeys_lock( fd_stake_pubkeys_t * pubkeys ) {
  fd_rwlock_write( &pubkeys->lock );
}

void
fd_stake_pubkeys_unlock( fd_stake_pubkeys_t * pubkeys ) {
  fd_rwlock_unwrite( &pubkeys->lock );
}

uint
fd_stake_pubkeys_acquire( fd_stake_pubkeys_t * pubkeys,
                          fd_pubkey_t const *  pubkey ) {
  fd_stake_pubkey_ref_t * pool = get_pool( pubkeys );
  stake_pubkey_map_t *    map  = get_map( pubkeys );
  fd_stake_pubkey_ref_t * ref  = stake_pubkey_map_ele_query( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !ref ) ) {
    FD_CHECK_CRIT( stake_pubkey_pool_free( pool ), "no free entries in stake pubkey pool" );
    ref         = stake_pubkey_pool_ele_acquire( pool );
    ref->pubkey = *pubkey;
    ref->refcnt = 0U;
    pubkeys->idx_wmark = fd_ulong_max( pubkeys->idx_wmark, stake_pubkey_pool_idx( pool, ref )+1UL );
    FD_CHECK_CRIT( stake_pubkey_map_ele_insert( map, ref, pool ), "unable to insert into stake pubkey map" );
  }
  ref->refcnt++;
  return (uint)stake_pubkey_pool_idx( pool, ref );
}

void
fd_stake_pubkeys_release( fd_stake_pubkeys_t * pubkeys,
                          uint                 pubkey_idx ) {
  FD_TEST( (ulong)pubkey_idx<pubkeys->max_pubkeys );

  fd_stake_pubkey_ref_t * pool = get_pool( pubkeys );
  fd_stake_pubkey_ref_t * ref  = pool + pubkey_idx;
  FD_TEST( ref->refcnt );
  if( FD_UNLIKELY( pubkeys->fallback ) ) return;

  if( FD_LIKELY( !--ref->refcnt ) ) {
    stake_pubkey_map_ele_remove( get_map( pubkeys ), &ref->pubkey, NULL, pool );
    stake_pubkey_pool_idx_release( pool, pubkey_idx );
  }
}

void
fd_stake_pubkeys_retain( fd_stake_pubkeys_t * pubkeys,
                         uint                 pubkey_idx ) {
  FD_TEST( (ulong)pubkey_idx<pubkeys->max_pubkeys );
  fd_stake_pubkey_ref_t * ref = get_pool( pubkeys ) + pubkey_idx;
  FD_TEST( ref->refcnt );
  ref->refcnt++;
}

fd_pubkey_t const *
fd_stake_pubkeys_query( fd_stake_pubkeys_t const * pubkeys,
                        uint                       pubkey_idx ) {
  FD_TEST( (ulong)pubkey_idx<pubkeys->max_pubkeys );
  return &(get_pool( pubkeys ) + pubkey_idx)->pubkey;
}

ulong
fd_stake_pubkeys_cnt( fd_stake_pubkeys_t const * pubkeys ) {
  return stake_pubkey_pool_used( get_pool( pubkeys ) );
}

uint
fd_stake_pubkeys_iter_next( fd_stake_pubkeys_t const * pubkeys,
                            ulong *                     cursor ) {
  fd_stake_pubkey_ref_t const * pool = get_pool( pubkeys );
  while( *cursor<pubkeys->idx_wmark ) {
    ulong idx = (*cursor)++;
    if( FD_LIKELY( pool[ idx ].refcnt ) ) return (uint)idx;
  }
  return UINT_MAX;
}

int
fd_stake_pubkeys_fallback( fd_stake_pubkeys_t const * pubkeys ) {
  return pubkeys->fallback;
}

void
fd_stake_pubkeys_fallback_enter( fd_stake_pubkeys_t * pubkeys,
                                 fd_pubkey_t const *  pubkey ) {
  if( FD_UNLIKELY( !pubkeys->fallback ) ) {
    FD_LOG_WARNING(( "stake delegation pool exhausted at %lu stake accounts; falling back to "
                     "resolving stake delegations from the accounts database at the epoch boundary",
                     fd_stake_pubkeys_cnt( pubkeys ) ));
    pubkeys->fallback = 1;
  }
  fd_stake_pubkeys_acquire( pubkeys, pubkey );
}

void
fd_stake_pubkeys_refresh_remove( fd_stake_pubkeys_t * pubkeys,
                                 uint                 pubkey_idx ) {
  FD_TEST( (ulong)pubkey_idx<pubkeys->max_pubkeys );

  fd_stake_pubkey_ref_t * pool = get_pool( pubkeys );
  fd_stake_pubkey_ref_t * ref  = pool + pubkey_idx;
  FD_TEST( ref->refcnt );
  stake_pubkey_map_ele_remove( get_map( pubkeys ), &ref->pubkey, NULL, pool );
  ref->refcnt = 0U;
  stake_pubkey_pool_idx_release( pool, pubkey_idx );
}

void
fd_stake_pubkeys_refresh_fini( fd_stake_pubkeys_t * pubkeys,
                               ulong                root_cnt ) {
  fd_stake_pubkey_ref_t * pool = get_pool( pubkeys );
  for( ulong idx=0UL; idx<pubkeys->idx_wmark; idx++ ) {
    if( FD_LIKELY( pool[ idx ].refcnt ) ) pool[ idx ].refcnt = 1U;
  }

  if( FD_UNLIKELY( pubkeys->fallback ) &&
      stake_pubkey_pool_used( pool )==root_cnt ) {
    FD_LOG_NOTICE(( "stake delegations no longer need the pubkey fallback; %lu stake accounts fit in the root map",
                    root_cnt ));
    pubkeys->fallback = 0;
  }
}

void
fd_stake_pubkeys_reset( fd_stake_pubkeys_t * pubkeys ) {
  stake_pubkey_pool_reset( get_pool( pubkeys ) );
  stake_pubkey_map_reset( get_map( pubkeys ) );
  pubkeys->idx_wmark = 0UL;
  pubkeys->fallback  = 0;
}
