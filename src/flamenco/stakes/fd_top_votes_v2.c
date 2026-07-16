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

struct vote_account_ele {
  fd_pubkey_t pubkey;
  ulong       stake;
  uint        next;
  ushort      commission;
};
typedef struct vote_account_ele vote_account_ele_t;

#define POOL_NAME  vote_account_pool
#define POOL_T     vote_account_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               vote_account_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              vote_account_ele_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( (k0), (k1), sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( (seed), (key), sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct vote_account_group {
  ulong pool_off;
  ulong map_off;
  uint  next;
};
typedef struct vote_account_group vote_account_group_t;

#define POOL_NAME  t_1_group_pool
#define POOL_T     vote_account_group_t
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

  /* t-2 alternates between two epoch-scoped account sets. */
  vote_account_group_t t_2_accounts[ FD_TOP_VOTES_V2_T_2_GROUP_CNT ];
};

static inline ulong
vote_state_footprint( ulong max_live_banks ) {
  return fd_ulong_sat_mul( fd_ulong_sat_mul( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT, max_live_banks ),
                           sizeof(vote_state_ele_t) );
}

static inline bank_info_t *
get_bank_info( fd_top_votes_v2_t const * top_votes ) {
  return (bank_info_t *)( (ulong)top_votes + top_votes->bank_info_off );
}

static inline vote_account_group_t *
get_t_1_group_pool( fd_top_votes_v2_t const * top_votes ) {
  void * pool_mem = (void *)( (ulong)top_votes + top_votes->t_1_group_pool_off );
  return t_1_group_pool_join( pool_mem );
}

static inline vote_state_ele_t *
get_t_2_state( fd_top_votes_v2_t const * top_votes,
               ulong                     snapshot_idx ) {
  vote_state_ele_t * state = (vote_state_ele_t *)( (ulong)top_votes + top_votes->t_2_state_off );
  return state + snapshot_idx*FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT;
}

static inline ulong
vote_account_chain_cnt( void ) {
  return vote_account_map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT );
}

static inline int
vote_account_group_new( fd_top_votes_v2_t *   top_votes,
                        vote_account_group_t * group,
                        void *                 pool_mem,
                        void *                 map_mem,
                        ulong                  seed ) {
  vote_account_ele_t * pool = vote_account_pool_join(
      vote_account_pool_new( pool_mem, FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  if( FD_UNLIKELY( !pool ) ) return 0;

  vote_account_map_t * map = vote_account_map_join(
      vote_account_map_new( map_mem, vote_account_chain_cnt(), seed ) );
  if( FD_UNLIKELY( !map ) ) return 0;

  group->pool_off = (ulong)pool_mem - (ulong)top_votes;
  group->map_off  = (ulong)map_mem  - (ulong)top_votes;
  return 1;
}

static inline int
vote_account_group_join( fd_top_votes_v2_t const *   top_votes,
                         vote_account_group_t const * group ) {
  ulong pool_footprint = vote_account_pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT );
  ulong map_footprint  = vote_account_map_footprint( vote_account_chain_cnt() );

  if( FD_UNLIKELY( group->pool_off>top_votes->footprint ||
                   pool_footprint>top_votes->footprint-group->pool_off ) ) return 0;
  if( FD_UNLIKELY( group->map_off>top_votes->footprint ||
                   map_footprint>top_votes->footprint-group->map_off ) ) return 0;

  void * pool_mem = (uchar *)top_votes + group->pool_off;
  void * map_mem  = (uchar *)top_votes + group->map_off;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)pool_mem, vote_account_pool_align() ) ||
                   !fd_ulong_is_aligned( (ulong)map_mem,  vote_account_map_align()  ) ) ) return 0;

  return !!vote_account_pool_join( pool_mem ) && !!vote_account_map_join( map_mem );
}

static inline void
vote_account_group_reset( fd_top_votes_v2_t *   top_votes,
                          vote_account_group_t * group ) {
  vote_account_ele_t * pool = vote_account_pool_join( (uchar *)top_votes + group->pool_off );
  vote_account_map_t * map  = vote_account_map_join( (uchar *)top_votes + group->map_off );
  FD_TEST( pool && map );
  vote_account_map_reset( map );
  vote_account_pool_reset( pool );
}

static inline void
vote_account_group_copy( fd_top_votes_v2_t *         top_votes,
                         vote_account_group_t *       dst,
                         vote_account_group_t const * src ) {
  memcpy( (uchar *)top_votes + dst->pool_off,
          (uchar *)top_votes + src->pool_off,
          vote_account_pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
  memcpy( (uchar *)top_votes + dst->map_off,
          (uchar *)top_votes + src->map_off,
          vote_account_map_footprint( vote_account_chain_cnt() ) );
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

  vote_account_group_t * group_pool = get_t_1_group_pool( top_votes );
  FD_TEST( t_1_group_pool_free( group_pool ) );
  vote_account_group_t * group = t_1_group_pool_ele_acquire( group_pool );
  vote_account_group_reset( top_votes, group );

  bank_info[ bank_idx ].t_1_group_idx = (uint)t_1_group_pool_idx( group_pool, group );
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

  ulong map_chain_cnt = vote_account_chain_cnt();
  ulong state_sz      = vote_state_footprint( max_live_banks );
  if( FD_UNLIKELY( state_sz==ULONG_MAX ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_top_votes_v2_align(),   sizeof(fd_top_votes_v2_t) );
  l = FD_LAYOUT_APPEND( l, alignof(bank_info_t),      fd_ulong_sat_mul( max_live_banks, sizeof(bank_info_t) ) );
  l = FD_LAYOUT_APPEND( l, t_1_group_pool_align(),    t_1_group_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, alignof(vote_state_ele_t), state_sz );
  for( ulong i=0UL; i<FD_TOP_VOTES_V2_T_2_GROUP_CNT+max_fork_width; i++ ) {
    l = FD_LAYOUT_APPEND( l, vote_account_pool_align(), vote_account_pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    l = FD_LAYOUT_APPEND( l, vote_account_map_align(),  vote_account_map_footprint( map_chain_cnt ) );
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

  ulong map_chain_cnt = vote_account_chain_cnt();
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_top_votes_v2_t * top_votes         = FD_SCRATCH_ALLOC_APPEND( l, fd_top_votes_v2_align(),   sizeof(fd_top_votes_v2_t) );
  bank_info_t *       bank_info         = FD_SCRATCH_ALLOC_APPEND( l, alignof(bank_info_t),      fd_ulong_sat_mul( max_live_banks, sizeof(bank_info_t) ) );
  void *              t_1_group_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, t_1_group_pool_align(),    t_1_group_pool_footprint( max_fork_width ) );
  void *              state_mem         = FD_SCRATCH_ALLOC_APPEND( l, alignof(vote_state_ele_t), vote_state_footprint( max_live_banks ) );

  vote_account_group_t * t_1_group_pool = t_1_group_pool_join(
      t_1_group_pool_new( t_1_group_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !t_1_group_pool ) ) {
    FD_LOG_WARNING(( "failed to create t-1 group pool" ));
    return NULL;
  }

  top_votes->footprint         = footprint;
  top_votes->max_fork_width    = max_fork_width;
  top_votes->max_live_banks    = max_live_banks;
  top_votes->t_2_state_off     = (ulong)state_mem         - (ulong)top_votes;
  top_votes->bank_info_off     = (ulong)bank_info         - (ulong)top_votes;
  top_votes->t_1_group_pool_off = (ulong)t_1_group_pool_mem - (ulong)top_votes;

  for( ulong i=0UL; i<max_live_banks; i++ ) {
    bank_info[ i ].t_1_group_idx = UINT_MAX;
    bank_info[ i ].t_2_group_idx = UINT_MAX;
  }

  ulong group_idx = 0UL;
  for( ulong i=0UL; i<FD_TOP_VOTES_V2_T_2_GROUP_CNT; i++, group_idx++ ) {
    void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, vote_account_pool_align(), vote_account_pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, vote_account_map_align(),  vote_account_map_footprint( map_chain_cnt ) );
    if( FD_UNLIKELY( !vote_account_group_new( top_votes, &top_votes->t_2_accounts[ i ], pool_mem, map_mem, seed+group_idx ) ) ) {
      FD_LOG_WARNING(( "failed to create t-2 vote-account group" ));
      return NULL;
    }
  }
  for( ulong i=0UL; i<max_fork_width; i++, group_idx++ ) {
    void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, vote_account_pool_align(), vote_account_pool_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT ) );
    void * map_mem  = FD_SCRATCH_ALLOC_APPEND( l, vote_account_map_align(),  vote_account_map_footprint( map_chain_cnt ) );
    if( FD_UNLIKELY( !vote_account_group_new( top_votes, t_1_group_pool_ele( t_1_group_pool, i ), pool_mem, map_mem, seed+group_idx ) ) ) {
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
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_top_votes_v2_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_top_votes_v2_t * top_votes = (fd_top_votes_v2_t *)mem;
  if( FD_UNLIKELY( top_votes->magic!=FD_TOP_VOTES_V2_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid top votes v2 magic" ));
    return NULL;
  }
  if( FD_UNLIKELY( top_votes->footprint!=fd_top_votes_v2_footprint( top_votes->max_fork_width,
                                                                    top_votes->max_live_banks ) ) ) {
    FD_LOG_WARNING(( "invalid top votes v2 footprint" ));
    return NULL;
  }

  ulong bank_info_footprint = fd_ulong_sat_mul( top_votes->max_live_banks, sizeof(bank_info_t) );
  if( FD_UNLIKELY( top_votes->bank_info_off>top_votes->footprint ||
                   bank_info_footprint>top_votes->footprint-top_votes->bank_info_off ) ) {
    FD_LOG_WARNING(( "invalid top votes v2 bank info offset" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)top_votes+top_votes->bank_info_off,
                                         alignof(bank_info_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned top votes v2 bank info" ));
    return NULL;
  }

  ulong t_1_group_pool_sz = t_1_group_pool_footprint( top_votes->max_fork_width );
  if( FD_UNLIKELY( top_votes->t_1_group_pool_off>top_votes->footprint ||
                   t_1_group_pool_sz>top_votes->footprint-top_votes->t_1_group_pool_off ) ) {
    FD_LOG_WARNING(( "invalid top votes v2 t-1 group pool offset" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)top_votes+top_votes->t_1_group_pool_off,
                                         t_1_group_pool_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned top votes v2 t-1 group pool" ));
    return NULL;
  }

  ulong state_footprint = vote_state_footprint( top_votes->max_live_banks );
  if( FD_UNLIKELY( top_votes->t_2_state_off>top_votes->footprint ||
                   state_footprint>top_votes->footprint-top_votes->t_2_state_off ) ) {
    FD_LOG_WARNING(( "invalid top votes v2 state offset" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)top_votes+top_votes->t_2_state_off,
                                         alignof(vote_state_ele_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned top votes v2 state" ));
    return NULL;
  }

  for( ulong i=0UL; i<FD_TOP_VOTES_V2_T_2_GROUP_CNT; i++ ) {
    if( FD_UNLIKELY( !vote_account_group_join( top_votes, &top_votes->t_2_accounts[ i ] ) ) ) {
      FD_LOG_WARNING(( "invalid t-2 vote-account group" ));
      return NULL;
    }
  }
  vote_account_group_t * t_1_group_pool = get_t_1_group_pool( top_votes );
  if( FD_UNLIKELY( !t_1_group_pool ||
                   t_1_group_pool_max( t_1_group_pool )!=top_votes->max_fork_width ) ) {
    FD_LOG_WARNING(( "invalid top votes v2 t-1 group pool" ));
    return NULL;
  }
  for( ulong i=0UL; i<top_votes->max_fork_width; i++ ) {
    if( FD_UNLIKELY( !vote_account_group_join( top_votes, t_1_group_pool_ele( t_1_group_pool, i ) ) ) ) {
      FD_LOG_WARNING(( "invalid t-1 vote-account group" ));
      return NULL;
    }
  }

  return top_votes;
}

void
fd_top_votes_v2_new_child( fd_top_votes_v2_t * top_votes,
                           ulong               parent_idx,
                           ulong               child_idx ) {
  FD_TEST( parent_idx<top_votes->max_live_banks );
  FD_TEST( child_idx <top_votes->max_live_banks );
  if( FD_UNLIKELY( parent_idx==child_idx ) ) return;

  ensure_bank_initialized( top_votes, parent_idx );

  bank_info_t * bank_info = get_bank_info( top_votes );
  bank_info[ child_idx ] = bank_info[ parent_idx ];

  memcpy( get_t_2_state( top_votes, child_idx ),
          get_t_2_state( top_votes, parent_idx ),
          FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );
}

void
fd_top_votes_v2_new_epoch_child( fd_top_votes_v2_t * top_votes,
                                 ulong               parent_idx,
                                 ulong               child_idx ) {
  FD_TEST( parent_idx<top_votes->max_live_banks );
  FD_TEST( child_idx <top_votes->max_live_banks );
  FD_TEST( parent_idx!=child_idx );

  ensure_bank_initialized( top_votes, parent_idx );

  bank_info_t *             bank_info  = get_bank_info( top_votes );
  vote_account_group_t *    group_pool = get_t_1_group_pool( top_votes );
  bank_info_t const *       parent     = &bank_info[ parent_idx ];
  vote_account_group_t *    parent_t_1 = t_1_group_pool_ele( group_pool, parent->t_1_group_idx );
  uint                      child_t_2  = parent->t_2_group_idx ^ 1U;
  vote_account_group_t *    t_2_group  = &top_votes->t_2_accounts[ child_t_2 ];

  vote_account_group_copy( top_votes, t_2_group, parent_t_1 );

  FD_TEST( t_1_group_pool_free( group_pool ) );
  vote_account_group_t * child_t_1 = t_1_group_pool_ele_acquire( group_pool );
  vote_account_group_reset( top_votes, child_t_1 );

  bank_info[ child_idx ].t_1_group_idx = (uint)t_1_group_pool_idx( group_pool, child_t_1 );
  bank_info[ child_idx ].t_2_group_idx = child_t_2;
  memset( get_t_2_state( top_votes, child_idx ),
          0,
          FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT*sizeof(vote_state_ele_t) );
}