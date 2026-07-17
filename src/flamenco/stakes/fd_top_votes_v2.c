#include "fd_top_votes_v2.h"
#include "../fd_flamenco_base.h"
#include "../runtime/fd_runtime_const.h"

#define FD_TOP_VOTES_V2_MAGIC          (0xF17EDA2CE7402E70UL) /* FIREDANCER TOP VOTES V2 V0 */
#define FD_TOP_VOTES_V2_ALIGN          (128UL)
#define FD_TOP_VOTES_V2_T_2_GROUP_CNT  (2UL)

struct vote_state_ele {
  ulong last_vote_slot;
  long  last_vote_timestamp;
};
typedef struct vote_state_ele vote_state_ele_t;

struct vote_ele {
  fd_pubkey_t pubkey;
  fd_pubkey_t node_account;
  ulong       stake;
  ushort      commission;
  ushort      left;
  ushort      right;
  ushort      next;
};
typedef struct vote_ele vote_ele_t;

FD_STATIC_ASSERT( sizeof(vote_ele_t)==80UL, vote_ele );
FD_STATIC_ASSERT( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT<USHORT_MAX, vote_idx );

#define HEAP_NAME       heap
#define HEAP_IDX_T      ushort
#define HEAP_T          vote_ele_t
#define HEAP_LT(e0,e1) ( ((e0)->stake < (e1)->stake) | \
                         (((e0)->stake==(e1)->stake) & \
                          (memcmp( &(e0)->pubkey, &(e1)->pubkey, sizeof(fd_pubkey_t) )<0 ) ) )
#include "../../util/tmpl/fd_heap.c"

#define POOL_NAME  pool
#define POOL_T     vote_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T ushort
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              vote_ele_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0), (k1), sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( (seed), (key), sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              ushort
#include "../../util/tmpl/fd_map_chain.c"

struct vote_group {
  ulong pool_off;
  ulong map_off;
  union {
    uint next;
    uint owner_bank_idx;
  };
};
typedef struct vote_group vote_group_t;

#define POOL_NAME  group_pool
#define POOL_T     vote_group_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

struct bank_info {
  uint t_1_group_idx;
  uint t_2_group_idx;
};
typedef struct bank_info bank_info_t;

struct __attribute__((aligned(FD_TOP_VOTES_V2_ALIGN))) fd_top_votes_v2 {
  ulong magic;
  ulong footprint;
  ulong max_fork_width;
  ulong max_live_banks;
  ulong t_2_state_off;
  ulong bank_info_off;
  ulong t_1_group_pool_off;
  ulong insert_heap_off;

  ulong insert_min_stake_wmark;
  uint  insert_bank_idx;

  vote_group_t t_2_accounts[ FD_TOP_VOTES_V2_T_2_GROUP_CNT ];
};

FD_STATIC_ASSERT( sizeof(fd_top_votes_v2_t)==FD_TOP_VOTES_V2_ALIGN, top_votes_v2_header );

static inline ulong
vote_state_footprint( ulong max_live_banks ) {
  return fd_ulong_sat_mul( fd_ulong_sat_mul( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT, max_live_banks ),
                           sizeof(vote_state_ele_t) );
}

static inline bank_info_t *
get_bank_info( fd_top_votes_v2_t const * top_votes ) {
  return (bank_info_t *)( (ulong)top_votes + top_votes->bank_info_off );
}

static inline vote_group_t *
get_group_pool( fd_top_votes_v2_t const * top_votes ) {
  return group_pool_join( (uchar *)top_votes + top_votes->t_1_group_pool_off );
}

static inline heap_t *
get_heap( fd_top_votes_v2_t const * top_votes ) {
  return heap_join( (uchar *)top_votes + top_votes->insert_heap_off );
}

static inline vote_ele_t *
get_pool( fd_top_votes_v2_t const * top_votes,
          vote_group_t const *      group ) {
  return pool_join( (uchar *)top_votes + group->pool_off );
}

static inline map_t *
get_map( fd_top_votes_v2_t const * top_votes,
         vote_group_t const *      group ) {
  return map_join( (uchar *)top_votes + group->map_off );
}

static inline vote_state_ele_t *
get_t_2_state( fd_top_votes_v2_t const * top_votes,
               ulong                     snapshot_idx ) {
  vote_state_ele_t * state = (vote_state_ele_t *)( (ulong)top_votes + top_votes->t_2_state_off );
  return state + snapshot_idx*FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT;
}

static inline ulong
chain_cnt( void ) {
  return map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT );
}

static inline int
group_new( fd_top_votes_v2_t * top_votes,
           vote_group_t *      group,
           void *              pool_mem,
           void *              map_mem,
           ulong               seed ) {
  vote_ele_t * pool = pool_join( pool_new( pool_mem, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  if( FD_UNLIKELY( !pool ) ) return 0;

  map_t * map = map_join( map_new( map_mem, chain_cnt(), seed ) );
  if( FD_UNLIKELY( !map ) ) return 0;

  group->pool_off = (ulong)pool_mem - (ulong)top_votes;
  group->map_off  = (ulong)map_mem  - (ulong)top_votes;
  return 1;
}

static inline void
group_reset( fd_top_votes_v2_t * top_votes,
             vote_group_t *      group ) {
  vote_ele_t * pool = get_pool( top_votes, group );
  map_t *      map  = get_map( top_votes, group );
  FD_TEST( pool && map );
  map_reset( map );
  pool_reset( pool );
}

static inline void
group_copy( fd_top_votes_v2_t * top_votes,
            vote_group_t *      dst,
            vote_group_t const * src ) {
  memcpy( (uchar *)top_votes + dst->pool_off,
          (uchar *)top_votes + src->pool_off,
          pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  memcpy( (uchar *)top_votes + dst->map_off,
          (uchar *)top_votes + src->map_off,
          map_footprint( chain_cnt() ) );
}

static inline void
ensure_bank_initialized( fd_top_votes_v2_t * top_votes,
                         ulong               bank_idx ) {
  bank_info_t * bank_info = get_bank_info( top_votes );
  if( FD_LIKELY( bank_info[ bank_idx ].t_1_group_idx!=UINT_MAX ) ) {
    FD_TEST( bank_info[ bank_idx ].t_1_group_idx<top_votes->max_fork_width );
    FD_TEST( bank_info[ bank_idx ].t_2_group_idx<FD_TOP_VOTES_V2_T_2_GROUP_CNT );
    return;
  }

  vote_group_t * groups = get_group_pool( top_votes );
  FD_TEST( group_pool_free( groups ) );
  vote_group_t * group = group_pool_ele_acquire( groups );
  group_reset( top_votes, group );
  group->owner_bank_idx = (uint)bank_idx;

  bank_info[ bank_idx ].t_1_group_idx = (uint)group_pool_idx( groups, group );
  bank_info[ bank_idx ].t_2_group_idx = 0U;
  memset( get_t_2_state( top_votes, bank_idx ),
          0,
          FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );
}

ulong
fd_top_votes_v2_align( void ) {
  return FD_TOP_VOTES_V2_ALIGN;
}

ulong
fd_top_votes_v2_footprint( ulong max_fork_width,
                           ulong max_live_banks ) {
  if( FD_UNLIKELY( !max_fork_width || max_fork_width>(ulong)UINT_MAX ||
                   !max_live_banks || max_live_banks>(ulong)UINT_MAX ) ) return 0UL;

  ulong map_chain_cnt = chain_cnt();
  ulong state_sz      = vote_state_footprint( max_live_banks );
  if( FD_UNLIKELY( state_sz==ULONG_MAX ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_top_votes_v2_align(),   sizeof(fd_top_votes_v2_t) );
  l = FD_LAYOUT_APPEND( l, heap_align(),              heap_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  l = FD_LAYOUT_APPEND( l, alignof(bank_info_t),      fd_ulong_sat_mul( max_live_banks, sizeof(bank_info_t) ) );
  l = FD_LAYOUT_APPEND( l, group_pool_align(),        group_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, alignof(vote_state_ele_t), state_sz );
  for( ulong i=0UL; i<FD_TOP_VOTES_V2_T_2_GROUP_CNT+max_fork_width; i++ ) {
    l = FD_LAYOUT_APPEND( l, pool_align(), pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    l = FD_LAYOUT_APPEND( l, map_align(),  map_footprint( map_chain_cnt ) );
  }
  return FD_LAYOUT_FINI( l, fd_top_votes_v2_align() );
}

void *
fd_top_votes_v2_new( void * mem,
                     ulong  max_fork_width,
                     ulong  max_live_banks,
                     ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_top_votes_v2_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_top_votes_v2_footprint( max_fork_width, max_live_banks );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid max_fork_width or max_live_banks" ));
    return NULL;
  }

  ulong map_chain_cnt = chain_cnt();
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_top_votes_v2_t * top_votes  = FD_SCRATCH_ALLOC_APPEND( l, fd_top_votes_v2_align(),   sizeof(fd_top_votes_v2_t) );
  void *              heap_mem   = FD_SCRATCH_ALLOC_APPEND( l, heap_align(),              heap_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  bank_info_t *        bank_info = FD_SCRATCH_ALLOC_APPEND( l, alignof(bank_info_t),      fd_ulong_sat_mul( max_live_banks, sizeof(bank_info_t) ) );
  void *               group_mem = FD_SCRATCH_ALLOC_APPEND( l, group_pool_align(),        group_pool_footprint( max_fork_width ) );
  void *               state_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(vote_state_ele_t), vote_state_footprint( max_live_banks ) );

  heap_t * heap = heap_join( heap_new( heap_mem, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  if( FD_UNLIKELY( !heap ) ) {
    FD_LOG_WARNING(( "failed to create shared insertion heap" ));
    return NULL;
  }

  vote_group_t * groups = group_pool_join( group_pool_new( group_mem, max_fork_width ) );
  if( FD_UNLIKELY( !groups ) ) {
    FD_LOG_WARNING(( "failed to create t-1 group pool" ));
    return NULL;
  }

  top_votes->footprint              = footprint;
  top_votes->max_fork_width         = max_fork_width;
  top_votes->max_live_banks         = max_live_banks;
  top_votes->t_2_state_off          = (ulong)state_mem - (ulong)top_votes;
  top_votes->bank_info_off          = (ulong)bank_info - (ulong)top_votes;
  top_votes->t_1_group_pool_off     = (ulong)group_mem - (ulong)top_votes;
  top_votes->insert_heap_off        = (ulong)heap_mem  - (ulong)top_votes;
  top_votes->insert_min_stake_wmark = 0UL;
  top_votes->insert_bank_idx        = UINT_MAX;

  for( ulong i=0UL; i<max_live_banks; i++ ) {
    bank_info[ i ].t_1_group_idx = UINT_MAX;
    bank_info[ i ].t_2_group_idx = UINT_MAX;
  }

  ulong group_idx = 0UL;
  for( ulong i=0UL; i<FD_TOP_VOTES_V2_T_2_GROUP_CNT; i++, group_idx++ ) {
    void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, map_align(),  map_footprint( map_chain_cnt ) );
    if( FD_UNLIKELY( !group_new( top_votes, &top_votes->t_2_accounts[ i ], pool_mem, map_mem, seed+group_idx ) ) ) {
      FD_LOG_WARNING(( "failed to create t-2 vote-account group" ));
      return NULL;
    }
  }
  for( ulong i=0UL; i<max_fork_width; i++, group_idx++ ) {
    void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, map_align(),  map_footprint( map_chain_cnt ) );
    if( FD_UNLIKELY( !group_new( top_votes, group_pool_ele( groups, i ), pool_mem, map_mem, seed+group_idx ) ) ) {
      FD_LOG_WARNING(( "failed to create t-1 vote-account group" ));
      return NULL;
    }
  }

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_top_votes_v2_align() )!=(ulong)mem+footprint ) ) {
    FD_LOG_WARNING(( "fd_top_votes_v2_new: bad layout" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( top_votes->magic ) = FD_TOP_VOTES_V2_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_top_votes_v2_t *
fd_top_votes_v2_join( void * mem ) {
  fd_top_votes_v2_t * top_votes = (fd_top_votes_v2_t *)mem;

  if( FD_UNLIKELY( !top_votes ) ) {
    FD_LOG_WARNING(( "NULL top votes v2" ));
    return NULL;
  }

  if( FD_UNLIKELY( top_votes->magic!=FD_TOP_VOTES_V2_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid top votes v2 magic" ));
    return NULL;
  }

  return top_votes;
}

void
fd_top_votes_v2_new_child( fd_top_votes_v2_t * top_votes,
                           ulong               parent_idx,
                           ulong               child_idx ) {
  FD_TEST( top_votes->insert_bank_idx==UINT_MAX );
  FD_TEST( parent_idx<top_votes->max_live_banks );
  FD_TEST( child_idx <top_votes->max_live_banks );
  if( FD_UNLIKELY( parent_idx==child_idx ) ) return;

  ensure_bank_initialized( top_votes, parent_idx );

  bank_info_t *  bank_info  = get_bank_info( top_votes );
  vote_group_t * groups     = get_group_pool( top_votes );
  vote_group_t * parent_t_1 = group_pool_ele(
      groups, bank_info[ parent_idx ].t_1_group_idx );
  FD_TEST( parent_t_1->owner_bank_idx==UINT_MAX );

  bank_info[ child_idx ] = bank_info[ parent_idx ];

  memcpy( get_t_2_state( top_votes, child_idx ),
          get_t_2_state( top_votes, parent_idx ),
          FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );
}

void
fd_top_votes_v2_new_epoch_child( fd_top_votes_v2_t * top_votes,
                                 ulong               parent_idx,
                                 ulong               child_idx ) {
  FD_TEST( top_votes->insert_bank_idx==UINT_MAX );
  FD_TEST( parent_idx<top_votes->max_live_banks );
  FD_TEST( child_idx <top_votes->max_live_banks );
  FD_TEST( parent_idx!=child_idx );

  ensure_bank_initialized( top_votes, parent_idx );

  bank_info_t *       bank_info  = get_bank_info( top_votes );
  vote_group_t *      groups     = get_group_pool( top_votes );
  bank_info_t const * parent     = &bank_info[ parent_idx ];
  vote_group_t *      parent_t_1 = group_pool_ele( groups, parent->t_1_group_idx );
  uint                child_t_2  = parent->t_2_group_idx ^ 1U;
  vote_group_t *      t_2_group  = &top_votes->t_2_accounts[ child_t_2 ];

  FD_TEST( parent_t_1->owner_bank_idx==UINT_MAX );
  group_copy( top_votes, t_2_group, parent_t_1 );

  FD_TEST( group_pool_free( groups ) );
  vote_group_t * child_t_1 = group_pool_ele_acquire( groups );
  group_reset( top_votes, child_t_1 );
  child_t_1->owner_bank_idx = (uint)child_idx;

  bank_info[ child_idx ].t_1_group_idx = (uint)group_pool_idx( groups, child_t_1 );
  bank_info[ child_idx ].t_2_group_idx = child_t_2;
  memset( get_t_2_state( top_votes, child_idx ),
          0,
          FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );
}

void
fd_top_votes_v2_insert_init( fd_top_votes_v2_t * top_votes,
                             ulong               child_idx ) {
  FD_TEST( child_idx<top_votes->max_live_banks );
  FD_TEST( top_votes->insert_bank_idx==UINT_MAX );
  ensure_bank_initialized( top_votes, child_idx );

  bank_info_t *  bank_info = get_bank_info( top_votes );
  vote_group_t * groups    = get_group_pool( top_votes );
  vote_group_t * group     = group_pool_ele( groups, bank_info[ child_idx ].t_1_group_idx );
  vote_ele_t *   pool      = get_pool( top_votes, group );

  FD_TEST( group->owner_bank_idx==(uint)child_idx );
  FD_TEST( !pool_used( pool ) );
  FD_TEST( heap_new( get_heap( top_votes ), FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );

  top_votes->insert_min_stake_wmark = 0UL;
  top_votes->insert_bank_idx        = (uint)child_idx;
}

void
fd_top_votes_v2_insert_fini( fd_top_votes_v2_t * top_votes ) {
  FD_TEST( top_votes->insert_bank_idx!=UINT_MAX );

  bank_info_t *  bank_info = get_bank_info( top_votes );
  vote_group_t * groups    = get_group_pool( top_votes );
  vote_group_t * group     = group_pool_ele( groups, bank_info[ top_votes->insert_bank_idx ].t_1_group_idx );
  vote_ele_t *   pool      = get_pool( top_votes, group );
  heap_t *       heap      = get_heap( top_votes );

  FD_TEST( heap_ele_cnt( heap )==pool_used( pool ) );
  FD_TEST( !heap_verify( heap, pool ) );
  FD_TEST( heap_new( heap, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  group->owner_bank_idx = UINT_MAX;

  top_votes->insert_min_stake_wmark = 0UL;
  top_votes->insert_bank_idx        = UINT_MAX;
}

void
fd_top_votes_v2_insert( fd_top_votes_v2_t * top_votes,
                        fd_pubkey_t const *  pubkey,
                        fd_pubkey_t const *  node_account,
                        ulong                stake,
                        ushort               commission ) {
  FD_TEST( top_votes->insert_bank_idx!=UINT_MAX );

  bank_info_t *  bank_info = get_bank_info( top_votes );
  vote_group_t * groups    = get_group_pool( top_votes );
  vote_group_t * group     = group_pool_ele( groups, bank_info[ top_votes->insert_bank_idx ].t_1_group_idx );
  vote_ele_t *   pool      = get_pool( top_votes, group );
  heap_t *       heap      = get_heap( top_votes );
  map_t *        map       = get_map( top_votes, group );

  FD_TEST( group->owner_bank_idx==top_votes->insert_bank_idx );
  if( FD_UNLIKELY( stake==0UL || stake<=top_votes->insert_min_stake_wmark ) ) return;

  if( FD_UNLIKELY( heap_ele_cnt( heap )==heap_ele_max( heap ) ) ) {
    vote_ele_t * ele       = heap_ele_peek_min( heap, pool );
    ulong        min_stake = ele->stake;
    if( stake<min_stake ) return;

    top_votes->insert_min_stake_wmark = min_stake;
    while( (ele=heap_ele_peek_min( heap, pool )) && min_stake==ele->stake ) {
      heap_ele_remove_min( heap, pool );
      map_ele_remove( map, &ele->pubkey, NULL, pool );
      pool_ele_release( pool, ele );
    }
    if( FD_UNLIKELY( stake==min_stake ) ) return;
  }

  vote_ele_t * ele  = pool_ele_acquire( pool );
  ele->pubkey       = *pubkey;
  ele->node_account = *node_account;
  ele->stake        = stake;
  ele->commission   = commission;
  heap_ele_insert( heap, ele, pool );
  map_ele_insert( map, ele, pool );
}

int
fd_top_votes_v2_query_t_1( fd_top_votes_v2_t const * top_votes,
                           ulong                     child_idx,
                           fd_pubkey_t const *        pubkey,
                           fd_pubkey_t *              node_account_out_opt,
                           ulong *                    stake_out_opt,
                           ushort *                   commission_out_opt ) {
  FD_TEST( child_idx<top_votes->max_live_banks );

  bank_info_t const * bank_info = get_bank_info( top_votes );
  if( FD_UNLIKELY( bank_info[ child_idx ].t_1_group_idx==UINT_MAX ) ) return 0;

  vote_group_t *       groups = get_group_pool( top_votes );
  vote_group_t const * group  = group_pool_ele_const( groups, bank_info[ child_idx ].t_1_group_idx );
  vote_ele_t const *   pool   = get_pool( top_votes, group );
  map_t const *        map    = get_map( top_votes, group );
  vote_ele_t const *   ele    = map_ele_query_const( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !ele ) ) return 0;

  if( node_account_out_opt ) *node_account_out_opt = ele->node_account;
  if( stake_out_opt )        *stake_out_opt        = ele->stake;
  if( commission_out_opt )   *commission_out_opt   = ele->commission;
  return 1;
}