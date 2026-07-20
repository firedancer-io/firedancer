#include "fd_top_votes_v2.h"
#include "../fd_flamenco_base.h"
#include "../runtime/fd_runtime_const.h"

#define FD_TOP_VOTES_V2_MAGIC          (0xF17EDA2CE7402E70UL) /* FIREDANCER TOP VOTES V2 V0 */
#define FD_TOP_VOTES_V2_ALIGN          (128UL)
#define FD_TOP_VOTES_V2_T_2_GROUP_CNT  (2UL)

struct vote_state_ele {
  ulong last_vote_slot : 63;
  ulong is_valid : 1;
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
FD_STATIC_ASSERT( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT<USHORT_MAX, vote_idx );

/* Scratch heap for stake account inclusion in top votes set.   This is
   shared and reused at the epoch boundary when the top votes set is
   reset and refreshed. */

#define HEAP_NAME       heap
#define HEAP_IDX_T      ushort
#define HEAP_T          vote_ele_t
#define HEAP_LT(e0,e1) ( ((e0)->stake < (e1)->stake) | \
                         (((e0)->stake==(e1)->stake) & \
                          (memcmp( &(e0)->pubkey, &(e1)->pubkey, sizeof(fd_pubkey_t) )<0 ) ) )
#include "../../util/tmpl/fd_heap.c"

/* There are 2 t-2 groups and max fork width + 1 t-1 groups.  Each group
   has a pool/map pair for the vote accounts in the group. */

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
  uint pool_off;
  uint map_off;
  uint next;           /* free-list link */
  uint owner_bank_idx; /* retained while free for parent-first pruning */
};
typedef struct vote_group vote_group_t;

#define POOL_NAME  group_pool
#define POOL_T     vote_group_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

/* Per bank metadata for the t-1 and t-2 groups. */

struct bank_info {
  uint t_1_group_idx;
  uint t_2_group_idx;
};
typedef struct bank_info bank_info_t;


struct __attribute__((aligned(FD_TOP_VOTES_V2_ALIGN))) fd_top_votes_v2 {
  ulong magic;
  ulong max_fork_width;
  ulong max_live_banks;

  ulong t_2_state_off;
  ulong bank_info_off;
  ulong t_1_group_pool_off;
  ulong insert_heap_off;

  /* Scratch metadata for insertion into a top_votes set */
  ulong insert_min_stake_wmark;
  uint  insert_bank_idx;
  uint  insert_t_2;

  vote_group_t t_2_accounts[ FD_TOP_VOTES_V2_T_2_GROUP_CNT ];
};

FD_STATIC_ASSERT( sizeof(fd_top_votes_v2_t)==FD_TOP_VOTES_V2_ALIGN, top_votes_v2_header );

/* Convert stored offsets into joined objects in the current mapping. */

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

/* t-2 state is a dense bank-by-vote-account array. */

static inline vote_state_ele_t *
get_t_2_state( fd_top_votes_v2_t const * top_votes,
               uint                      snapshot_idx ) {
  vote_state_ele_t * state = (vote_state_ele_t *)( (ulong)top_votes + top_votes->t_2_state_off );
  return state + snapshot_idx*FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT;
}

/* Format one group's independent pool and map, then retain offsets. */

static inline int
group_new( fd_top_votes_v2_t * top_votes,
           vote_group_t *      group,
           void *              pool_mem,
           void *              map_mem,
           ulong               seed ) {
  vote_ele_t * pool = pool_join( pool_new( pool_mem, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  if( FD_UNLIKELY( !pool ) ) return 0;

  map_t * map = map_join( map_new( map_mem, map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ), seed ) );
  if( FD_UNLIKELY( !map ) ) return 0;

  ulong pool_off = (ulong)pool_mem - (ulong)top_votes;
  ulong map_off  = (ulong)map_mem  - (ulong)top_votes;
  if( FD_UNLIKELY( pool_off>UINT_MAX || map_off>UINT_MAX ) ) return 0;

  group->pool_off = (uint)pool_off;
  group->map_off  = (uint)map_off;
  return 1;
}

/* Clear an acquired group's durable account set before assigning it. */

static inline void
group_reset( fd_top_votes_v2_t * top_votes,
             vote_group_t *      group ) {
  vote_ele_t * pool = get_pool( top_votes, group );
  map_t *      map  = get_map( top_votes, group );
  FD_TEST( pool && map );
  map_reset( map );
  pool_reset( pool );
}

ulong
fd_top_votes_v2_align( void ) {
  return FD_TOP_VOTES_V2_ALIGN;
}

/* The allocation contains, in order, the header, shared insertion heap,
   bank metadata, t-1 group pool, per-bank t-2 state, and the pool/map
   pair for each of the two t-2 and max_fork_width + 1 t-1 groups. */

ulong
fd_top_votes_v2_footprint( ulong max_fork_width,
                           ulong max_live_banks ) {

  ulong t_1_group_cnt = fd_ulong_sat_add( max_fork_width, 1UL );
  if( FD_UNLIKELY( t_1_group_cnt==ULONG_MAX ) ) return 0UL;

  ulong group_cnt       = fd_ulong_sat_add( FD_TOP_VOTES_V2_T_2_GROUP_CNT, t_1_group_cnt );
  ulong group_footprint = pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) +
                          map_footprint( map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  if( FD_UNLIKELY( group_cnt==ULONG_MAX || group_cnt>UINT_MAX/group_footprint ) ) return 0UL;
  if( FD_UNLIKELY( max_live_banks>UINT_MAX/(FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t)) ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_top_votes_v2_align(),   sizeof(fd_top_votes_v2_t) );
  l = FD_LAYOUT_APPEND( l, heap_align(),              heap_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  l = FD_LAYOUT_APPEND( l, alignof(bank_info_t),      fd_ulong_sat_mul( max_live_banks, sizeof(bank_info_t) ) );
  l = FD_LAYOUT_APPEND( l, group_pool_align(),        group_pool_footprint( t_1_group_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(vote_state_ele_t), FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*max_live_banks*sizeof(vote_state_ele_t) );
  for( ulong i=0UL; i<FD_TOP_VOTES_V2_T_2_GROUP_CNT+t_1_group_cnt; i++ ) {
    l = FD_LAYOUT_APPEND( l, pool_align(), pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    l = FD_LAYOUT_APPEND( l, map_align(),  map_footprint( map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) ) );
  }
  ulong footprint = FD_LAYOUT_FINI( l, fd_top_votes_v2_align() );
  return footprint<=UINT_MAX ? footprint : 0UL;
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
    FD_LOG_WARNING(( "invalid footprint" ));
    return NULL;
  }

  ulong t_1_group_cnt = max_fork_width+1UL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_top_votes_v2_t * top_votes = FD_SCRATCH_ALLOC_APPEND( l, fd_top_votes_v2_align(),   sizeof(fd_top_votes_v2_t) );
  void *              heap_mem  = FD_SCRATCH_ALLOC_APPEND( l, heap_align(),              heap_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  bank_info_t *       bank_info = FD_SCRATCH_ALLOC_APPEND( l, alignof(bank_info_t),      fd_ulong_sat_mul( max_live_banks, sizeof(bank_info_t) ) );
  void *              group_mem = FD_SCRATCH_ALLOC_APPEND( l, group_pool_align(),        group_pool_footprint( t_1_group_cnt ) );
  void *              state_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(vote_state_ele_t), FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*max_live_banks*sizeof(vote_state_ele_t) );

  /* Format shared metadata before formatting each independent account
     group in the trailing allocation. */

  heap_t * heap = heap_join( heap_new( heap_mem, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  if( FD_UNLIKELY( !heap ) ) {
    FD_LOG_WARNING(( "failed to create shared insertion heap" ));
    return NULL;
  }

  vote_group_t * groups = group_pool_join( group_pool_new( group_mem, t_1_group_cnt ) );
  if( FD_UNLIKELY( !groups ) ) {
    FD_LOG_WARNING(( "failed to create t-1 group pool" ));
    return NULL;
  }

  top_votes->max_fork_width         = max_fork_width;
  top_votes->max_live_banks         = max_live_banks;
  top_votes->t_2_state_off          = (ulong)state_mem - (ulong)top_votes;
  top_votes->bank_info_off          = (ulong)bank_info - (ulong)top_votes;
  top_votes->t_1_group_pool_off     = (ulong)group_mem - (ulong)top_votes;
  top_votes->insert_heap_off        = (ulong)heap_mem  - (ulong)top_votes;
  top_votes->insert_min_stake_wmark = 0UL;
  top_votes->insert_bank_idx        = UINT_MAX;
  top_votes->insert_t_2             = 0U;

  memset( bank_info, 0xFFUL, max_live_banks*sizeof(bank_info_t) );

  ulong group_idx = 0UL;
  for( ulong i=0UL; i<FD_TOP_VOTES_V2_T_2_GROUP_CNT; i++, group_idx++ ) {
    void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, map_align(), map_footprint( map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) ) );
    if( FD_UNLIKELY( !group_new( top_votes, &top_votes->t_2_accounts[ i ], pool_mem, map_mem, seed+group_idx ) ) ) {
      FD_LOG_WARNING(( "failed to create t-2 vote-account group" ));
      return NULL;
    }
  }

  for( ulong i=0UL; i<t_1_group_cnt; i++, group_idx++ ) {
    void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, map_align(), map_footprint( map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) ) );
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
                           uint                parent_idx,
                           uint                child_idx ) {
  /* Copy in parent's state (last_vote_slot/timestamp and is_valid) */

  bank_info_t * bank_info = get_bank_info( top_votes );
  bank_info[ child_idx ] = bank_info[ parent_idx ];

  memcpy( get_t_2_state( top_votes, child_idx ), get_t_2_state( top_votes, parent_idx ), FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );
}

void
fd_top_votes_v2_advance_root( fd_top_votes_v2_t * top_votes,
                              uint                root_idx ) {
  bank_info_t const * bank_info = get_bank_info( top_votes );
  vote_group_t *      groups    = get_group_pool( top_votes );
  vote_group_t *      group     = group_pool_ele( groups, bank_info[ root_idx ].t_1_group_idx );
  group->owner_bank_idx = root_idx;
}

void
fd_top_votes_v2_prune( fd_top_votes_v2_t * top_votes,
                       uint                child_idx ) {
  bank_info_t *  bank_info = get_bank_info( top_votes );
  vote_group_t * groups    = get_group_pool( top_votes );
  vote_group_t * group     = group_pool_ele( groups, bank_info[ child_idx ].t_1_group_idx );

  if( FD_LIKELY( group->owner_bank_idx==child_idx ) ) group_pool_ele_release( groups, group );

  bank_info[ child_idx ].t_1_group_idx = UINT_MAX;
  bank_info[ child_idx ].t_2_group_idx = UINT_MAX;
  memset( get_t_2_state( top_votes, child_idx ), 0, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );

  if( FD_UNLIKELY( top_votes->insert_bank_idx==child_idx ) ) {
    FD_TEST( heap_new( get_heap( top_votes ), FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    top_votes->insert_min_stake_wmark = 0UL;
    top_votes->insert_bank_idx        = UINT_MAX;
    top_votes->insert_t_2             = 0U;
  }
}

/* Start an insertion session for child_idx.  UINT_MAX parent_idx lazily
   initializes a root bank.  Otherwise, rotate the parent's t-1 accounts
   into t-2 and give the epoch child a fresh t-1 group. */

void
fd_top_votes_v2_insert_init( fd_top_votes_v2_t * top_votes,
                             uint                parent_idx,
                             uint                child_idx ) {
  FD_TEST( child_idx<top_votes->max_live_banks );

  if( FD_UNLIKELY( parent_idx==UINT_MAX ) ) {
    /* Special boot path for the first bank */

    vote_group_t * groups = get_group_pool( top_votes );
    vote_group_t * group  = group_pool_ele_acquire( groups );
    group_reset( top_votes, group );
    group->owner_bank_idx = child_idx;

    bank_info_t * bank_info = get_bank_info( top_votes );
    bank_info[ child_idx ].t_1_group_idx = (uint)group_pool_idx( groups, group );
    bank_info[ child_idx ].t_2_group_idx = 0U;
    memset( get_t_2_state( top_votes, child_idx ), 0, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );
  } else {
    /* Standard epoch boundary case */

    FD_TEST( parent_idx<top_votes->max_live_banks );

    bank_info_t *       bank_info  = get_bank_info( top_votes );
    vote_group_t *      groups     = get_group_pool( top_votes );
    bank_info_t const * parent     = &bank_info[ parent_idx ];

    vote_group_t *      parent_t_1 = group_pool_ele( groups, parent->t_1_group_idx );
    uint                child_t_2  = (parent->t_2_group_idx+1U) % FD_TOP_VOTES_V2_T_2_GROUP_CNT;
    vote_group_t *      t_2_group  = &top_votes->t_2_accounts[ child_t_2 ];

    /* Copy in the parent's t-1 pool/map pair into child's t-2 group. */
    memcpy( (uchar *)top_votes + t_2_group->pool_off, (uchar *)top_votes + parent_t_1->pool_off, pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    memcpy( (uchar *)top_votes + t_2_group->map_off, (uchar *)top_votes + parent_t_1->map_off, map_footprint( map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) ) );

    /* Acquire a t-1 group for the child. */
    vote_group_t * child_t_1 = group_pool_ele_acquire( groups );
    group_reset( top_votes, child_t_1 );
    child_t_1->owner_bank_idx = child_idx;

    /* Update the bank's t-1/t-2 group indices. */
    bank_info[ child_idx ].t_1_group_idx = (uint)group_pool_idx( groups, child_t_1 );
    bank_info[ child_idx ].t_2_group_idx = child_t_2;

    memset( get_t_2_state( top_votes, child_idx ), 0, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );
  }

  /* Clear out any scratch state used for insertion. */
  FD_TEST( heap_new( get_heap( top_votes ), FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  top_votes->insert_min_stake_wmark = 0UL;
  top_votes->insert_bank_idx        = child_idx;
  top_votes->insert_t_2             = 0U;
}

void
fd_top_votes_v2_insert_init_t_2( fd_top_votes_v2_t * top_votes,
                                 uint                child_idx ) {
  FD_TEST( child_idx<top_votes->max_live_banks );

  bank_info_t * bank_info = get_bank_info( top_votes );
  FD_TEST( bank_info[ child_idx ].t_2_group_idx<FD_TOP_VOTES_V2_T_2_GROUP_CNT );

  vote_group_t * group = &top_votes->t_2_accounts[ bank_info[ child_idx ].t_2_group_idx ];
  group_reset( top_votes, group );
  memset( get_t_2_state( top_votes, child_idx ), 0, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );

  FD_TEST( heap_new( get_heap( top_votes ), FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  top_votes->insert_min_stake_wmark = 0UL;
  top_votes->insert_bank_idx        = child_idx;
  top_votes->insert_t_2             = 1U;
}

void
fd_top_votes_v2_insert( fd_top_votes_v2_t * top_votes,
                        fd_pubkey_t const * pubkey,
                        fd_pubkey_t const * node_account,
                        ulong               stake,
                        ushort              commission ) {
  FD_TEST( top_votes->insert_bank_idx!=UINT_MAX );

  /* The policy for insertion is that the top 2000 accounts by stake
     are included.  This is a hard limit and if there are multiple
     accounts tied at the limit, all are excluded. */

  bank_info_t *  bank_info = get_bank_info( top_votes );
  vote_group_t * groups    = get_group_pool( top_votes );
  vote_group_t * group     = top_votes->insert_t_2
                            ? &top_votes->t_2_accounts[ bank_info[ top_votes->insert_bank_idx ].t_2_group_idx ]
                            : group_pool_ele( groups, bank_info[ top_votes->insert_bank_idx ].t_1_group_idx );
  vote_ele_t *   pool      = get_pool( top_votes, group );
  heap_t *       heap      = get_heap( top_votes );
  map_t *        map       = get_map( top_votes, group );

  if( FD_UNLIKELY( stake==0UL || stake<=top_votes->insert_min_stake_wmark ) ) return;


  /* If the heap is full, we need to evict the lowest stake account(s)
     until we have room for the new account.  Also update the min stake
     wmark. */
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
  if( FD_UNLIKELY( top_votes->insert_t_2 ) ) {
    vote_state_ele_t * state = get_t_2_state( top_votes, top_votes->insert_bank_idx ) + pool_idx( pool, ele );
    memset( state, 0, sizeof(vote_state_ele_t) );
  }
  heap_ele_insert( heap, ele, pool );
  map_ele_insert( map, ele, pool );
}

void
fd_top_votes_v2_update( fd_top_votes_v2_t * top_votes,
                        uint                child_idx,
                        fd_pubkey_t const * pubkey,
                        ulong               last_vote_slot,
                        long                last_vote_timestamp,
                        int                 is_valid ) {
  bank_info_t const * bank_info     = get_bank_info( top_votes );
  uint                t_2_group_idx = bank_info[ child_idx ].t_2_group_idx;

  vote_group_t const * group = &top_votes->t_2_accounts[ t_2_group_idx ];
  vote_ele_t *         pool  = get_pool( top_votes, group );
  map_t const *        map   = get_map( top_votes, group );
  ushort               idx   = (ushort)map_idx_query_const( map, pubkey, USHORT_MAX, pool );

  vote_state_ele_t * state = get_t_2_state( top_votes, child_idx ) + idx;

  FD_TEST( !(last_vote_slot & (1UL<<63)) );
  state->last_vote_slot      = last_vote_slot & 0x7FFFFFFFFFFFFFFFUL;
  state->last_vote_timestamp = last_vote_timestamp;
  state->is_valid            = !!is_valid;
}

int
fd_top_votes_v2_query_t_1( fd_top_votes_v2_t const * top_votes,
                           uint                      child_idx,
                           fd_pubkey_t const *       pubkey,
                           fd_pubkey_t *             node_account_out_opt,
                           ulong *                   stake_out_opt,
                           ushort *                  commission_out_opt ) {
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

static inline vote_group_t const *
get_t_1_group( fd_top_votes_v2_t const * top_votes,
               uint                      child_idx ) {
  bank_info_t const * bank_info = get_bank_info( top_votes );
  vote_group_t *      groups    = get_group_pool( top_votes );
  return group_pool_ele_const( groups, bank_info[ child_idx ].t_1_group_idx );
}

static inline vote_group_t const *
get_t_2_group( fd_top_votes_v2_t const * top_votes,
               uint                      child_idx ) {
  bank_info_t const * bank_info = get_bank_info( top_votes );
  return &top_votes->t_2_accounts[ bank_info[ child_idx ].t_2_group_idx ];
}

int
fd_top_votes_v2_query_t_2( fd_top_votes_v2_t const * top_votes,
                           uint                      child_idx,
                           fd_pubkey_t const *       pubkey,
                           fd_pubkey_t *             node_account_out_opt,
                           ulong *                   stake_out_opt,
                           ushort *                  commission_out_opt,
                           ulong *                   last_vote_slot_out_opt,
                           long *                    last_vote_timestamp_out_opt,
                           uchar *                   is_valid_out_opt ) {
  vote_group_t const * group = get_t_2_group( top_votes, child_idx );
  vote_ele_t *         pool  = get_pool( top_votes, group );
  map_t const *        map   = get_map( top_votes, group );
  vote_ele_t const *   ele   = map_ele_query_const( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !ele ) ) return 0;

  ushort                   idx   = (ushort)pool_idx( pool, ele );
  vote_state_ele_t const * state = get_t_2_state( top_votes, child_idx ) + idx;

  if( node_account_out_opt )        *node_account_out_opt        = ele->node_account;
  if( stake_out_opt )               *stake_out_opt               = ele->stake;
  if( commission_out_opt )          *commission_out_opt          = ele->commission;
  if( last_vote_slot_out_opt )      *last_vote_slot_out_opt      = state->last_vote_slot;
  if( last_vote_timestamp_out_opt ) *last_vote_timestamp_out_opt = state->last_vote_timestamp;
  if( is_valid_out_opt )            *is_valid_out_opt            = (uchar)state->is_valid;
  return 1;
}

FD_STATIC_ASSERT( FD_TOP_VOTES_V2_ITER_FOOTPRINT==sizeof(map_iter_t), top_votes_v2_iter );
FD_STATIC_ASSERT( FD_TOP_VOTES_V2_ITER_ALIGN==alignof(map_iter_t), top_votes_v2_iter_align );

static inline fd_top_votes_v2_iter_t *
iter_init( fd_top_votes_v2_t const * top_votes,
           vote_group_t const *      group,
           uchar                     iter_mem[ static FD_TOP_VOTES_V2_ITER_FOOTPRINT ] ) {
  map_iter_t iter = map_iter_init( get_map( top_votes, group ), get_pool( top_votes, group ) );
  memcpy( iter_mem, &iter, sizeof(map_iter_t) );
  return (fd_top_votes_v2_iter_t *)iter_mem;
}

static inline int
iter_done( fd_top_votes_v2_t const * top_votes,
           vote_group_t const *      group,
           fd_top_votes_v2_iter_t *  iter ) {
  map_iter_t * map_iter = (map_iter_t *)iter;
  return map_iter_done( *map_iter, get_map( top_votes, group ), get_pool( top_votes, group ) );
}

static inline void
iter_next( fd_top_votes_v2_t const * top_votes,
           vote_group_t const *      group,
           fd_top_votes_v2_iter_t *  iter ) {
  map_iter_t * map_iter = (map_iter_t *)iter;
  *map_iter = map_iter_next( *map_iter, get_map( top_votes, group ), get_pool( top_votes, group ) );
}

static inline vote_ele_t *
iter_ele( fd_top_votes_v2_t const * top_votes,
          vote_group_t const *      group,
          fd_top_votes_v2_iter_t *  iter ) {
  map_iter_t * map_iter = (map_iter_t *)iter;
  return map_iter_ele( *map_iter, get_map( top_votes, group ), get_pool( top_votes, group ) );
}

fd_top_votes_v2_iter_t *
fd_top_votes_v2_iter_init_t_1( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               uchar                     iter_mem[ static FD_TOP_VOTES_V2_ITER_FOOTPRINT ] ) {
  return iter_init( top_votes, get_t_1_group( top_votes, child_idx ), iter_mem );
}

int
fd_top_votes_v2_iter_done_t_1( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               fd_top_votes_v2_iter_t *  iter ) {
  return iter_done( top_votes, get_t_1_group( top_votes, child_idx ), iter );
}

void
fd_top_votes_v2_iter_next_t_1( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               fd_top_votes_v2_iter_t *  iter ) {
  iter_next( top_votes, get_t_1_group( top_votes, child_idx ), iter );
}

void
fd_top_votes_v2_iter_ele_t_1( fd_top_votes_v2_t const * top_votes,
                              uint                      child_idx,
                              fd_top_votes_v2_iter_t *  iter,
                              fd_pubkey_t *             pubkey_out,
                              fd_pubkey_t *             node_account_out_opt,
                              ulong *                   stake_out_opt,
                              ushort *                  commission_out_opt ) {
  vote_ele_t const * ele = iter_ele( top_votes, get_t_1_group( top_votes, child_idx ), iter );

  *pubkey_out = ele->pubkey;
  if( node_account_out_opt ) *node_account_out_opt = ele->node_account;
  if( stake_out_opt )        *stake_out_opt        = ele->stake;
  if( commission_out_opt )   *commission_out_opt   = ele->commission;
}

fd_top_votes_v2_iter_t *
fd_top_votes_v2_iter_init_t_2( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               uchar                     iter_mem[ static FD_TOP_VOTES_V2_ITER_FOOTPRINT ] ) {
  return iter_init( top_votes, get_t_2_group( top_votes, child_idx ), iter_mem );
}

int
fd_top_votes_v2_iter_done_t_2( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               fd_top_votes_v2_iter_t *  iter ) {
  return iter_done( top_votes, get_t_2_group( top_votes, child_idx ), iter );
}

void
fd_top_votes_v2_iter_next_t_2( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               fd_top_votes_v2_iter_t *  iter ) {
  iter_next( top_votes, get_t_2_group( top_votes, child_idx ), iter );
}

void
fd_top_votes_v2_iter_ele_t_2( fd_top_votes_v2_t const * top_votes,
                              uint                      child_idx,
                              fd_top_votes_v2_iter_t *  iter,
                              fd_pubkey_t *             pubkey_out,
                              fd_pubkey_t *             node_account_out_opt,
                              ulong *                   stake_out_opt,
                              ushort *                  commission_out_opt,
                              ulong *                   last_vote_slot_out_opt,
                              long *                    last_vote_timestamp_out_opt,
                              uchar *                   is_valid_out_opt ) {
  vote_group_t const * group = get_t_2_group( top_votes, child_idx );
  vote_ele_t *         pool  = get_pool( top_votes, group );
  vote_ele_t const *   ele   = iter_ele( top_votes, group, iter );
  ushort               idx   = (ushort)pool_idx( pool, ele );
  vote_state_ele_t *   state = get_t_2_state( top_votes, child_idx ) + idx;

  *pubkey_out = ele->pubkey;
  if( node_account_out_opt )        *node_account_out_opt        = ele->node_account;
  if( stake_out_opt )               *stake_out_opt               = ele->stake;
  if( commission_out_opt )          *commission_out_opt          = ele->commission;
  if( last_vote_slot_out_opt )      *last_vote_slot_out_opt      = state->last_vote_slot;
  if( last_vote_timestamp_out_opt ) *last_vote_timestamp_out_opt = state->last_vote_timestamp;
  if( is_valid_out_opt )            *is_valid_out_opt            = (uchar)state->is_valid;
}
