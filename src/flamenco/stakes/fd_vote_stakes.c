#include "fd_vote_stakes.h"
#include "../accdb/fd_accdb.h"
#include "../fd_flamenco_base.h"
#include "../runtime/fd_runtime_const.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../../util/bits/fd_bits.h"
#include "../../util/fd_hash32.h"
#include "../../util/log/fd_log.h"

#if FD_HAS_BLST
#include "../../ballet/bls/fd_bls12_381.h"
#endif

#define FD_VOTE_STAKES_MAGIC          (0xF17EDA2CE7601E70UL) /* FIREDANCER VOTE STAKES V0 */
#define FD_VOTE_STAKES_MAX_FORK_WIDTH (128UL)

struct vacc {
  fd_pubkey_t pubkey;
  fd_pubkey_t node_account;
  ulong       stake;
  ushort      commission;
  ushort      alpenglow_rank;
  uchar       bls_key[ FD_BLS_PUBKEY_COMPRESSED_SZ ]; /* zero if unregistered */
  uint        left;
  uint        right;
  uint        next;
};
typedef struct vacc vacc_t;

struct vacc_rank {
  vacc_t * vacc;
  ulong    drop;
};
typedef struct vacc_rank vacc_rank_t;

#define SORT_NAME        vacc_rank_sort
#define SORT_KEY_T       vacc_rank_t
#define SORT_BEFORE(a,b) (((a).vacc->stake>(b).vacc->stake) | ((a).vacc->stake==(b).vacc->stake && \
                           memcmp( (a).vacc->bls_key, (b).vacc->bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ )<0 ))
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        vacc_rank_bls_sort
#define SORT_KEY_T       vacc_rank_t
#define SORT_BEFORE(a,b) (memcmp( (a).vacc->bls_key, (b).vacc->bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ )<0)
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        vacc_rank_identity_sort
#define SORT_KEY_T       vacc_rank_t
#define SORT_BEFORE(a,b) (memcmp( &(a).vacc->node_account, &(b).vacc->node_account, sizeof(fd_pubkey_t) )<0)
#include "../../util/tmpl/fd_sort.c"

#define HEAP_NAME       vacc_heap
#define HEAP_IDX_T      uint
#define HEAP_T          vacc_t
#define HEAP_LT(e0,e1) ( ((e0)->stake < (e1)->stake) | \
                         (((e0)->stake==(e1)->stake) & \
                          (memcmp( &(e0)->pubkey, &(e1)->pubkey, sizeof(fd_pubkey_t) )<0 ) ) )
#include "../../util/tmpl/fd_heap.c"

#define POOL_NAME  vacc_pool
#define POOL_T     vacc_t
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               vacc_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              vacc_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( key->uc, seed ))
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct vacc_fork {
  uint ref_cnt;
  uint next;
};
typedef struct vacc_fork vacc_fork_t;

#define POOL_NAME  vacc_fork_pool
#define POOL_T     vacc_fork_t
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

struct vacc_states {
  struct {
    ulong last_vote_slot;
    long  last_vote_ts;
    uchar is_valid;
  } states[ FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ];
  uint next;
};
typedef struct vacc_states vacc_states_t;

#define POOL_NAME  vacc_state_pool
#define POOL_T     vacc_states_t
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

struct fd_vote_stakes {
  ulong magic;
  ulong max_fork_width;
  ulong max_live_slots;
  ulong min_stake_wmark;

  /* (pubkey, stake) pairs for the t-2 epoch.  These are shared across
     forks/banks. */
  ulong t_2_epoch[ 2UL ];
  uint  t_2_vacc_pool_off[ 2UL ];
  uint  t_2_vacc_map_off [ 2UL ];

  /* (pubkey, stake) pairs for the t-1 epoch.  These can be different
     for every fork across the epoch boundary.  These must be sized to
     the max fork width of the running system.  These are keyed by fork
     idx. */
  uint vacc_fork_pool_off;
  uint t_1_vacc_pools_off;
  uint t_1_vacc_maps_off;
  uint vacc_heap_off;

  /* Per-bank state about the t-2 vote state.  Each per-bank state will
     be an array sized to length max_live_slots which is a system-wide
     bound.  Keyed by bank idx. */
  uint vacc_states_pool_off;
};
typedef struct fd_vote_stakes fd_vote_stakes_t;

FD_FN_UNUSED static inline vacc_t *
t_2_vacc_pool( fd_vote_stakes_t const * vote_stakes,
               ulong                    idx ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->t_2_vacc_pool_off[ idx ] );
}

FD_FN_UNUSED static inline vacc_map_t *
t_2_vacc_map( fd_vote_stakes_t const * vote_stakes,
              ulong                    idx ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->t_2_vacc_map_off[ idx ] );
}

FD_FN_UNUSED static inline vacc_fork_t *
vacc_fork_pool( fd_vote_stakes_t const * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->vacc_fork_pool_off );
}

FD_FN_UNUSED static inline vacc_t *
t_1_vacc_pool( fd_vote_stakes_t const * vote_stakes,
               ulong                    width_idx ) {
  ulong off = vote_stakes->t_1_vacc_pools_off + width_idx*vacc_pool_footprint( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
  return fd_type_pun( (uchar *)vote_stakes + off );
}

FD_FN_UNUSED static inline vacc_map_t *
t_1_vacc_map( fd_vote_stakes_t const * vote_stakes,
              ulong                    width_idx ) {
  ulong chain_cnt = vacc_map_chain_cnt_est( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
  ulong off       = vote_stakes->t_1_vacc_maps_off + width_idx*vacc_map_footprint( chain_cnt );
  return fd_type_pun( (uchar *)vote_stakes + off );
}

FD_FN_UNUSED static inline vacc_heap_t *
vacc_heap( fd_vote_stakes_t const * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->vacc_heap_off );
}

FD_FN_UNUSED static inline vacc_states_t *
vacc_states_pool( fd_vote_stakes_t const * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->vacc_states_pool_off );
}

/* The fork id is a compound of the epoch, width idx, and bank idx. */

FD_FN_UNUSED static inline ushort
fork_id_bank_id( ulong fork_id ) {
  return (ushort)(fork_id & (ulong)USHORT_MAX);
}

FD_FN_UNUSED static inline ushort
fork_id_width_id( ulong fork_id ) {
  return (ushort)((fork_id>>16UL) & (ulong)USHORT_MAX);
}

FD_FN_UNUSED static inline ushort
fork_id_epoch( ulong fork_id ) {
  return (ushort)((fork_id>>32UL) & (ulong)USHORT_MAX);
}

FD_FN_UNUSED static inline void
fork_id_set_bank_id( ulong * fork_id,
                     ushort  bank_id ) {
  *fork_id = (*fork_id & ~(ulong)USHORT_MAX) | (ulong)bank_id;
}

FD_FN_UNUSED static inline void
fork_id_set_width_id( ulong * fork_id,
                      ushort  width_id ) {
  *fork_id = (*fork_id & ~((ulong)USHORT_MAX<<16UL)) | ((ulong)width_id<<16UL);
}

FD_FN_UNUSED static inline void
fork_id_set_epoch( ulong * fork_id,
                   ushort  epoch ) {
  *fork_id = (*fork_id & ~((ulong)USHORT_MAX<<32UL)) | ((ulong)epoch<<32UL);
}

ulong
fd_vote_stakes_align( void ) {
  return FD_VOTE_STAKES_ALIGN;
}

ulong
fd_vote_stakes_footprint( ulong max_live_slots,
                          ulong max_fork_width ) {
  if( FD_UNLIKELY( !max_live_slots || max_live_slots>USHORT_MAX ) ) return 0UL;
  if( FD_UNLIKELY( !max_fork_width || max_fork_width>FD_VOTE_STAKES_MAX_FORK_WIDTH ) ) return 0UL;

  ulong map_chain_cnt  = vacc_map_chain_cnt_est( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
  ulong pool_footprint = vacc_pool_footprint( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
  ulong map_footprint  = vacc_map_footprint( map_chain_cnt );
  ulong width_cnt      = max_fork_width + 1UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_vote_stakes_align(), sizeof(fd_vote_stakes_t) );
  for( ulong i=0UL; i<2UL; i++ ) {
    l = FD_LAYOUT_APPEND( l, vacc_pool_align(), pool_footprint );
    l = FD_LAYOUT_APPEND( l, vacc_map_align(),  map_footprint );
  }
  l = FD_LAYOUT_APPEND( l, vacc_fork_pool_align(),  vacc_fork_pool_footprint( width_cnt ) );
  l = FD_LAYOUT_APPEND( l, vacc_pool_align(),       width_cnt*pool_footprint );
  l = FD_LAYOUT_APPEND( l, vacc_map_align(),        width_cnt*map_footprint );
  l = FD_LAYOUT_APPEND( l, vacc_heap_align(),       vacc_heap_footprint( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ) );
  l = FD_LAYOUT_APPEND( l, vacc_state_pool_align(), vacc_state_pool_footprint( max_live_slots ) );
  return FD_LAYOUT_FINI( l, fd_vote_stakes_align() );
}

void *
fd_vote_stakes_new( void * mem,
                    ulong  max_live_slots,
                    ulong  max_fork_width,
                    ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_vote_stakes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_live_slots || max_live_slots>USHORT_MAX ) ) {
    FD_LOG_WARNING(( "invalid max_live_slots" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_fork_width || max_fork_width>FD_VOTE_STAKES_MAX_FORK_WIDTH ) ) {
    FD_LOG_WARNING(( "invalid max_fork_width" ));
    return NULL;
  }

  ulong map_chain_cnt  = vacc_map_chain_cnt_est( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
  ulong pool_footprint = vacc_pool_footprint( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
  ulong map_footprint  = vacc_map_footprint( map_chain_cnt );
  ulong width_cnt      = max_fork_width + 1UL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_vote_stakes_t * vote_stakes = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_stakes_align(), sizeof(fd_vote_stakes_t) );
  void * t_2_pool_mem[ 2UL ];
  void * t_2_map_mem [ 2UL ];
  for( ulong i=0UL; i<2UL; i++ ) {
    t_2_pool_mem[ i ] = FD_SCRATCH_ALLOC_APPEND( l, vacc_pool_align(), pool_footprint );
    t_2_map_mem [ i ] = FD_SCRATCH_ALLOC_APPEND( l, vacc_map_align(),  map_footprint );
  }
  void * vacc_fork_pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, vacc_fork_pool_align(), vacc_fork_pool_footprint( width_cnt ) );
  void * t_1_vacc_pools_mem   = FD_SCRATCH_ALLOC_APPEND( l, vacc_pool_align(),      width_cnt*pool_footprint );
  void * t_1_vacc_maps_mem    = FD_SCRATCH_ALLOC_APPEND( l, vacc_map_align(),       width_cnt*map_footprint );
  void * vacc_heap_mem        = FD_SCRATCH_ALLOC_APPEND( l, vacc_heap_align(),       vacc_heap_footprint( FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ) );
  void * vacc_states_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, vacc_state_pool_align(), vacc_state_pool_footprint( max_live_slots ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_vote_stakes_align() )!=(ulong)mem+fd_vote_stakes_footprint( max_live_slots, max_fork_width ) ) ) {
    FD_LOG_WARNING(( "fd_vote_stakes_new: bad layout" ));
    return NULL;
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    vacc_t * t_2_pool = vacc_pool_join( vacc_pool_new( t_2_pool_mem[ i ], FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ) );
    if( FD_UNLIKELY( !t_2_pool ) ) {
      FD_LOG_WARNING(( "Failed to create t-2 vote account pool" ));
      return NULL;
    }

    vacc_map_t * t_2_map = vacc_map_join( vacc_map_new( t_2_map_mem[ i ], map_chain_cnt, seed ) );
    if( FD_UNLIKELY( !t_2_map ) ) {
      FD_LOG_WARNING(( "Failed to create t-2 vote account map" ));
      return NULL;
    }

    vote_stakes->t_2_vacc_pool_off[ i ] = (uint)((ulong)t_2_pool - (ulong)mem);
    vote_stakes->t_2_vacc_map_off [ i ] = (uint)((ulong)t_2_map  - (ulong)mem);
  }

  vacc_fork_t * fork_pool = vacc_fork_pool_join( vacc_fork_pool_new( vacc_fork_pool_mem, width_cnt ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote account fork pool" ));
    return NULL;
  }
  vote_stakes->vacc_fork_pool_off = (uint)((ulong)fork_pool - (ulong)mem);

  for( ulong i=0UL; i<width_cnt; i++ ) {
    void *   pool_mem = (uchar *)t_1_vacc_pools_mem + i*pool_footprint;
    vacc_t * pool     = vacc_pool_join( vacc_pool_new( pool_mem, FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ) );
    if( FD_UNLIKELY( !pool ) ) {
      FD_LOG_WARNING(( "Failed to create t-1 vote account pool" ));
      return NULL;
    }
    if( FD_UNLIKELY( !i ) ) vote_stakes->t_1_vacc_pools_off = (uint)((ulong)pool - (ulong)mem);

    void *       map_mem = (uchar *)t_1_vacc_maps_mem + i*map_footprint;
    vacc_map_t * map = vacc_map_join( vacc_map_new( map_mem, map_chain_cnt, seed ) );
    if( FD_UNLIKELY( !map ) ) {
      FD_LOG_WARNING(( "Failed to create t-1 vote account map" ));
      return NULL;
    }
  }
  vote_stakes->t_1_vacc_maps_off = (uint)((ulong)t_1_vacc_maps_mem - (ulong)mem);

  vacc_heap_t * heap = vacc_heap_join( vacc_heap_new( vacc_heap_mem, FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ) );
  if( FD_UNLIKELY( !heap ) ) {
    FD_LOG_WARNING(( "Failed to create vote account heap" ));
    return NULL;
  }

  vacc_states_t * vacc_states_pool = vacc_state_pool_join( vacc_state_pool_new( vacc_states_pool_mem, max_live_slots ) );
  if( FD_UNLIKELY( !vacc_states_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote account state pool" ));
    return NULL;
  }

  vote_stakes->max_live_slots       = max_live_slots;
  vote_stakes->max_fork_width       = max_fork_width;
  vote_stakes->min_stake_wmark      = 0UL;
  vote_stakes->vacc_heap_off        = (uint)((ulong)heap - (ulong)mem);
  vote_stakes->vacc_states_pool_off = (uint)((ulong)vacc_states_pool - (ulong)mem);
  vote_stakes->t_2_epoch[ 0 ]       = ULONG_MAX;
  vote_stakes->t_2_epoch[ 1 ]       = ULONG_MAX;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( vote_stakes->magic ) = FD_VOTE_STAKES_MAGIC;
  FD_COMPILER_MFENCE();

  return vote_stakes;
}

fd_vote_stakes_t *
fd_vote_stakes_join( void * mem ) {
  fd_vote_stakes_t * vote_stakes = (fd_vote_stakes_t *)mem;

  if( FD_UNLIKELY( !vote_stakes ) ) {
    FD_LOG_WARNING(( "NULL vote stakes" ));
    return NULL;
  }

  if( FD_UNLIKELY( vote_stakes->magic!=FD_VOTE_STAKES_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid vote stakes magic" ));
    return NULL;
  }

  return vote_stakes;
}

ulong
fd_vote_stakes_fork_epoch( ulong fork_id ) {
  return (ulong)fork_id_epoch( fork_id );
}

ulong
fd_vote_stakes_init( fd_vote_stakes_t * vote_stakes,
                     ulong              epoch ) {
  /* Acquire t-1 key set width idx */
  vacc_fork_t * fork_pool = vacc_fork_pool( vote_stakes );
  FD_CHECK_CRIT( vacc_fork_pool_free( fork_pool ), "vote stakes width pool exhausted" );
  ushort        width_idx = (ushort)vacc_fork_pool_idx_acquire( fork_pool );
  vacc_fork_pool_ele( fork_pool, width_idx )->ref_cnt = 1U;

  /* Acquire t-2 state bank idx */
  vacc_states_t * states_pool = vacc_states_pool( vote_stakes );
  FD_CHECK_CRIT( vacc_state_pool_free( states_pool ), "vote stakes state pool exhausted" );
  ushort          bank_idx    = (ushort)vacc_state_pool_idx_acquire( states_pool );
  vacc_states_t * states = vacc_state_pool_ele( states_pool, bank_idx );
  memset( states->states, 0, sizeof(states->states) );
  vote_stakes->t_2_epoch[ epoch & 1UL ] = epoch;

  /* Construct the fork id */
  ulong fork_id = 0UL;
  fork_id_set_bank_id( &fork_id, bank_idx );
  fork_id_set_width_id( &fork_id, width_idx );
  fork_id_set_epoch( &fork_id, (ushort)epoch );
  return fork_id;
}

void
fd_vote_stakes_reset( fd_vote_stakes_t * vote_stakes ) {
  for( ulong i=0UL; i<2UL; i++ ) {
    vacc_map_reset( t_2_vacc_map( vote_stakes, i ) );
    vacc_pool_reset( t_2_vacc_pool( vote_stakes, i ) );
    vote_stakes->t_2_epoch[ i ] = ULONG_MAX;
  }

  ulong width_cnt = vote_stakes->max_fork_width + 1UL;
  for( ulong i=0UL; i<width_cnt; i++ ) {
    vacc_map_reset( t_1_vacc_map( vote_stakes, i ) );
    vacc_pool_reset( t_1_vacc_pool( vote_stakes, i ) );
  }

  vacc_fork_pool_reset( vacc_fork_pool( vote_stakes ) );
  vacc_state_pool_reset( vacc_states_pool( vote_stakes ) );
  FD_TEST( vacc_heap_new( vacc_heap( vote_stakes ), FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ) );
  vote_stakes->min_stake_wmark = 0UL;
}

void
fd_vote_stakes_snap_insert_t_1( fd_vote_stakes_t *  vote_stakes,
                                ulong               fork_id,
                                fd_pubkey_t const * pubkey,
                                fd_pubkey_t const * node_account,
                                ulong               stake,
                                ushort              commission,
                                uchar const         bls_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] ) {
  if( FD_UNLIKELY( !stake ) ) return;

  vacc_t *     pool = t_1_vacc_pool( vote_stakes, fork_id_width_id( fork_id ) );
  vacc_map_t * map  = t_1_vacc_map ( vote_stakes, fork_id_width_id( fork_id ) );

  vacc_t * vacc        = vacc_pool_ele_acquire( pool );
  vacc->pubkey         = *pubkey;
  vacc->node_account   = *node_account;
  vacc->stake          = stake;
  vacc->commission     = commission;
  vacc->alpenglow_rank = FD_VOTE_STAKES_ALPENGLOW_RANK_NULL;
  memcpy( vacc->bls_key, bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ );
  FD_TEST( vacc_map_ele_insert( map, vacc, pool ) );
}

void
fd_vote_stakes_snap_insert_t_2( fd_vote_stakes_t *  vote_stakes,
                                ulong               fork_id,
                                fd_pubkey_t const * pubkey,
                                fd_pubkey_t const * node_account,
                                ulong               stake,
                                ushort              commission,
                                uchar const         bls_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] ) {
  if( FD_UNLIKELY( !stake ) ) return;

  ulong        epoch_idx = (ulong)fork_id_epoch( fork_id ) & 1UL;
  vacc_t *     pool      = t_2_vacc_pool( vote_stakes, epoch_idx );
  vacc_map_t * map       = t_2_vacc_map ( vote_stakes, epoch_idx );

  vacc_t * vacc        = vacc_pool_ele_acquire( pool );
  vacc->pubkey         = *pubkey;
  vacc->node_account   = *node_account;
  vacc->stake          = stake;
  vacc->commission     = commission;
  vacc->alpenglow_rank = FD_VOTE_STAKES_ALPENGLOW_RANK_NULL;
  memcpy( vacc->bls_key, bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ );
  FD_TEST( vacc_map_ele_insert( map, vacc, pool ) );
}

void
fd_vote_stakes_snap_insert_t_3( fd_vote_stakes_t *  vote_stakes,
                                ulong               fork_id,
                                fd_pubkey_t const * pubkey,
                                fd_pubkey_t const * node_account,
                                ulong               stake,
                                ushort              commission,
                                uchar const         bls_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] ) {
  ulong epoch = (ulong)fork_id_epoch( fork_id );
  if( FD_UNLIKELY( !epoch || !stake ) ) return;

  ulong        t_3_epoch = epoch - 1UL;
  ulong        t_3_idx   = t_3_epoch & 1UL;
  vacc_t *     pool = t_2_vacc_pool( vote_stakes, t_3_idx );
  vacc_map_t * map  = t_2_vacc_map ( vote_stakes, t_3_idx );

  vacc_t * vacc        = vacc_pool_ele_acquire( pool );
  vacc->pubkey         = *pubkey;
  vacc->node_account   = *node_account;
  vacc->stake          = stake;
  vacc->commission     = commission;
  vacc->alpenglow_rank = FD_VOTE_STAKES_ALPENGLOW_RANK_NULL;
  memcpy( vacc->bls_key, bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ );
  FD_TEST( vacc_map_ele_insert( map, vacc, pool ) );
  vote_stakes->t_2_epoch[ t_3_idx ] = t_3_epoch;
}

void
fd_vote_stakes_insert( fd_vote_stakes_t *  vote_stakes,
                       ulong               fork_id,
                       fd_pubkey_t const * pubkey,
                       fd_pubkey_t const * node_account,
                       ulong               stake,
                       ushort              commission,
                       uchar const         bls_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] ) {
  ulong         width_idx = (ulong)fork_id_width_id( fork_id );
  vacc_t *      pool      = t_1_vacc_pool( vote_stakes, width_idx );
  vacc_map_t *  map       = t_1_vacc_map ( vote_stakes, width_idx );
  vacc_heap_t * heap      = vacc_heap( vote_stakes );

  if( FD_UNLIKELY( stake==0UL || stake<=vote_stakes->min_stake_wmark ) ) return;

  if( FD_UNLIKELY( vacc_heap_ele_cnt( heap )==vacc_heap_ele_max( heap ) ) ) {
    vacc_t * ele       = vacc_heap_ele_peek_min( heap, pool );
    ulong    min_stake = ele->stake;
    if( stake<min_stake ) return;

    vote_stakes->min_stake_wmark = min_stake;
    while( (ele=vacc_heap_ele_peek_min( heap, pool )) && min_stake==ele->stake ) {
      vacc_heap_ele_remove_min( heap, pool );
      vacc_map_ele_remove( map, &ele->pubkey, NULL, pool );
      vacc_pool_ele_release( pool, ele );
    }
    if( FD_UNLIKELY( stake==min_stake ) ) return;
  }

  vacc_t * vacc        = vacc_pool_ele_acquire( pool );
  vacc->pubkey         = *pubkey;
  vacc->node_account   = *node_account;
  vacc->stake          = stake;
  vacc->commission     = commission;
  vacc->alpenglow_rank = FD_VOTE_STAKES_ALPENGLOW_RANK_NULL;
  memcpy( vacc->bls_key, bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ );
  vacc_heap_ele_insert( heap, vacc, pool );
  FD_TEST( vacc_map_ele_insert( map, vacc, pool ) );
}

void
fd_vote_stakes_finalize( fd_vote_stakes_t * vote_stakes,
                         ulong              epoch ) {
  ulong epoch_idx = epoch & 1UL;
  if( FD_UNLIKELY( vote_stakes->t_2_epoch[ epoch_idx ]!=epoch ) ) return;

  vacc_t *     pool = t_2_vacc_pool( vote_stakes, epoch_idx );
  vacc_map_t * map  = t_2_vacc_map ( vote_stakes, epoch_idx );

  vacc_rank_t rank[ FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ];
  ulong       rank_cnt = 0UL;
  for( vacc_map_iter_t iter = vacc_map_iter_init( map, pool );
       !vacc_map_iter_done( iter, map, pool );
       iter = vacc_map_iter_next( iter, map, pool ) ) {
    vacc_t * vacc = vacc_map_iter_ele( iter, map, pool );
    vacc->alpenglow_rank = FD_VOTE_STAKES_ALPENGLOW_RANK_NULL;
    if( FD_UNLIKELY( !vacc->stake ) ) continue;
#if FD_HAS_BLST
    uchar decompressed[ 96 ];
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( decompressed, vacc->bls_key, 1 ) ) ) continue;
#endif
    FD_TEST( rank_cnt<FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
    rank[ rank_cnt++ ] = (vacc_rank_t){ .vacc=vacc, .drop=0UL };
  }

  vacc_rank_bls_sort_inplace( rank, rank_cnt );
  for( ulong i=1UL; i<rank_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( rank[i].vacc->bls_key, rank[i-1UL].vacc->bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ ) ) ) {
      rank[i].drop = rank[i-1UL].drop = 1UL;
    }
  }

  vacc_rank_identity_sort_inplace( rank, rank_cnt );
  for( ulong i=1UL; i<rank_cnt; i++ ) {
    if( FD_UNLIKELY( fd_pubkey_eq( &rank[i].vacc->node_account, &rank[i-1UL].vacc->node_account ) ) ) {
      rank[i].drop = rank[i-1UL].drop = 1UL;
    }
  }

  ulong survivor_cnt = 0UL;
  for( ulong i=0UL; i<rank_cnt; i++ ) {
    if( FD_LIKELY( !rank[i].drop ) ) rank[ survivor_cnt++ ] = rank[i];
  }
  vacc_rank_sort_inplace( rank, survivor_cnt );

  for( ulong i=0UL; i<survivor_cnt; i++ ) rank[i].vacc->alpenglow_rank = (ushort)i;
}

void
fd_vote_stakes_purge_fork( fd_vote_stakes_t * vote_stakes,
                           ulong              fork_id ) {
  ushort bank_id  = fork_id_bank_id( fork_id );
  ushort width_id = fork_id_width_id( fork_id );

  vacc_state_pool_idx_release( vacc_states_pool( vote_stakes ), bank_id );

  vacc_fork_t * fork_pool = vacc_fork_pool( vote_stakes );
  vacc_fork_t * fork      = vacc_fork_pool_ele( fork_pool, width_id );
  FD_TEST( fork->ref_cnt );
  if( !--fork->ref_cnt ) {
    vacc_map_reset( t_1_vacc_map( vote_stakes, width_id ) );
    vacc_pool_reset( t_1_vacc_pool( vote_stakes, width_id ) );
    vacc_fork_pool_idx_release( fork_pool, width_id );
  }
}

ulong
fd_vote_stakes_new_fork( fd_vote_stakes_t * vote_stakes,
                         ulong              parent_fork_id,
                         ulong              epoch ) {
  FD_TEST( epoch<=USHORT_MAX );

  vacc_states_t * states_pool    = vacc_states_pool( vote_stakes );
  FD_CHECK_CRIT( vacc_state_pool_free( states_pool ), "vote stakes state pool exhausted" );
  ushort          parent_bank_id = fork_id_bank_id( parent_fork_id );
  ushort          bank_id        = (ushort)vacc_state_pool_idx_acquire( states_pool );
  ushort          parent_epoch   = fork_id_epoch( parent_fork_id );
  ushort          width_id;

  vacc_states_t * child_state = vacc_state_pool_ele( states_pool, bank_id );
  if( FD_LIKELY( epoch==(ulong)parent_epoch ) ) {
    /* Standard case: just inherit the parent's t-1 set (and increment
       the ref count) and copy over the t-2 state. */
    width_id = fork_id_width_id( parent_fork_id );
    vacc_fork_pool_ele( vacc_fork_pool( vote_stakes ), width_id )->ref_cnt++;

    vacc_states_t const * parent_state = vacc_state_pool_ele_const( states_pool, parent_bank_id );
    memcpy( child_state->states, parent_state->states, sizeof(child_state->states) );
  } else {
    /* Epoch boundary: copy the parent's t-1 set into the t-2 set and
       acquire new t-1 and t-2 state. */

    /* Copy the t-1 set iff it's the first time crossing into a new
       epoch boundary. */
    ulong t_2_idx = epoch & 1UL;
    if( vote_stakes->t_2_epoch[ t_2_idx ]!=epoch ) {
      ulong        parent_width_id = (ulong)fork_id_width_id( parent_fork_id );
      vacc_t *     t_1_pool        = t_1_vacc_pool( vote_stakes, parent_width_id );
      vacc_map_t * t_1_map         = t_1_vacc_map ( vote_stakes, parent_width_id );
      vacc_t *     t_2_pool        = t_2_vacc_pool( vote_stakes, t_2_idx );
      vacc_map_t * t_2_map         = t_2_vacc_map ( vote_stakes, t_2_idx );

      vacc_map_reset( t_2_map );
      vacc_pool_reset( t_2_pool );
      for( vacc_map_iter_t iter = vacc_map_iter_init( t_1_map, t_1_pool );
           !vacc_map_iter_done( iter, t_1_map, t_1_pool );
           iter = vacc_map_iter_next( iter, t_1_map, t_1_pool ) ) {
        vacc_t const * src = vacc_map_iter_ele_const( iter, t_1_map, t_1_pool );
        vacc_t *       dst = vacc_pool_ele_acquire( t_2_pool );
        dst->pubkey         = src->pubkey;
        dst->node_account   = src->node_account;
        dst->stake          = src->stake;
        dst->commission     = src->commission;
        dst->alpenglow_rank = src->alpenglow_rank;
        memcpy( dst->bls_key, src->bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ );
        FD_TEST( vacc_map_ele_insert( t_2_map, dst, t_2_pool ) );
      }
      vote_stakes->t_2_epoch[ t_2_idx ] = epoch;
    }

    /* Reset the t-2 states for the new fork and prepare the heap for
       insertion into the new t-1 set. */
    vacc_fork_t * fork_pool = vacc_fork_pool( vote_stakes );
    FD_CHECK_CRIT( vacc_fork_pool_free( fork_pool ), "vote stakes width pool exhausted" );
    width_id = (ushort)vacc_fork_pool_idx_acquire( fork_pool );
    vacc_fork_pool_ele( fork_pool, width_id )->ref_cnt = 1U;
    vacc_map_reset( t_1_vacc_map( vote_stakes, width_id ) );
    vacc_pool_reset( t_1_vacc_pool( vote_stakes, width_id ) );
    memset( child_state->states, 0, sizeof(child_state->states) );

    FD_TEST( vacc_heap_new( vacc_heap( vote_stakes ), FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ) );
    vote_stakes->min_stake_wmark = 0UL;
  }

  ulong fork_id = 0UL;
  fork_id_set_bank_id( &fork_id, bank_id );
  fork_id_set_width_id( &fork_id, width_id );
  fork_id_set_epoch( &fork_id, (ushort)epoch );
  return fork_id;
}

void
fd_vote_stakes_update_state( fd_vote_stakes_t *  vote_stakes,
                             ulong               fork_id,
                             fd_pubkey_t const * pubkey,
                             ulong               last_vote_slot,
                             long                last_vote_ts,
                             uchar               is_valid ) {
  ulong        epoch_idx = (ulong)fork_id_epoch( fork_id ) & 1UL;
  vacc_t *     pool      = t_2_vacc_pool( vote_stakes, epoch_idx );
  vacc_map_t * map       = t_2_vacc_map ( vote_stakes, epoch_idx );

  vacc_t const * vacc = vacc_map_ele_query_const( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !vacc ) ) return;

  ulong           vacc_idx = vacc_pool_idx( pool, vacc );
  vacc_states_t * states   = vacc_state_pool_ele( vacc_states_pool( vote_stakes ), fork_id_bank_id( fork_id ) );
  states->states[ vacc_idx ].is_valid = (uchar)!!is_valid;
  if( is_valid ) {
    states->states[ vacc_idx ].last_vote_slot = last_vote_slot;
    states->states[ vacc_idx ].last_vote_ts   = last_vote_ts;
  }
}

void
fd_vote_stakes_refresh( fd_vote_stakes_t * vote_stakes,
                        ulong              fork_id,
                        fd_accdb_t *        accdb,
                        fd_accdb_fork_id_t  accdb_fork_id ) {
  uchar __attribute__((aligned(FD_VOTE_STAKES_T_2_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_T_2_ITER_FOOTPRINT ];

  for( fd_vote_stakes_t_2_iter_t * iter = fd_vote_stakes_t_2_iter_init( vote_stakes, fork_id, iter_mem );
       !fd_vote_stakes_t_2_iter_done( vote_stakes, fork_id, iter );
       fd_vote_stakes_t_2_iter_next( vote_stakes, fork_id, iter ) ) {
    fd_pubkey_t pubkey;
    fd_vote_stakes_t_2_iter_ele( vote_stakes, fork_id, iter, &pubkey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );

    fd_acc_t acc = fd_accdb_read_one( accdb, accdb_fork_id, pubkey.uc );
    if( FD_UNLIKELY( !acc.lamports || !fd_vsv_is_correct_size_owner_and_init( acc.owner, acc.data, acc.data_len ) ) ) {
      fd_accdb_unread_one( accdb, &acc );
      fd_vote_stakes_update_state( vote_stakes, fork_id, &pubkey, 0UL, 0L, 0 );
      continue;
    }

    fd_vote_block_timestamp_t last_vote;
    FD_TEST( !fd_vote_account_last_timestamp( acc.data, acc.data_len, &last_vote ) );
    fd_vote_stakes_update_state( vote_stakes, fork_id, &pubkey, last_vote.slot, last_vote.timestamp, 1 );
    fd_accdb_unread_one( accdb, &acc );
  }
}

int
fd_vote_stakes_query_t_1( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          fd_pubkey_t const *      pubkey,
                          fd_pubkey_t *            node_account_out_opt,
                          ulong *                  stake_out_opt,
                          ushort *                 commission_out_opt ) {
  ulong        width_idx = (ulong)fork_id_width_id( fork_id );
  vacc_t *     pool      = t_1_vacc_pool( vote_stakes, width_idx );
  vacc_map_t * map       = t_1_vacc_map ( vote_stakes, width_idx );

  vacc_t const * vacc = vacc_map_ele_query_const( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !vacc ) ) return 0;

  if( node_account_out_opt ) *node_account_out_opt = vacc->node_account;
  if( stake_out_opt )        *stake_out_opt        = vacc->stake;
  if( commission_out_opt )   *commission_out_opt   = vacc->commission;
  return 1;
}

int
fd_vote_stakes_query_t_2( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          fd_pubkey_t const *      pubkey,
                          fd_pubkey_t *            node_account_out_opt,
                          ulong *                  stake_out_opt,
                          ulong *                  last_vote_slot_out_opt,
                          long *                   last_vote_ts_out_opt,
                          ushort *                 commission_out_opt,
                          uchar *                  is_valid_out_opt ) {
  ulong        epoch_idx = (ulong)fork_id_epoch( fork_id ) & 1UL;
  vacc_t *     pool      = t_2_vacc_pool( vote_stakes, epoch_idx );
  vacc_map_t * map       = t_2_vacc_map ( vote_stakes, epoch_idx );

  vacc_t const * vacc = vacc_map_ele_query_const( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !vacc ) ) return 0;

  ulong                 vacc_idx = vacc_pool_idx( pool, vacc );
  vacc_states_t const * states   = vacc_state_pool_ele_const( vacc_states_pool( vote_stakes ), fork_id_bank_id( fork_id ) );

  if( node_account_out_opt )   *node_account_out_opt   = vacc->node_account;
  if( stake_out_opt )          *stake_out_opt          = vacc->stake;
  if( last_vote_slot_out_opt ) *last_vote_slot_out_opt = states->states[ vacc_idx ].last_vote_slot;
  if( last_vote_ts_out_opt )   *last_vote_ts_out_opt   = states->states[ vacc_idx ].last_vote_ts;
  if( commission_out_opt )     *commission_out_opt     = vacc->commission;
  if( is_valid_out_opt )       *is_valid_out_opt       = states->states[ vacc_idx ].is_valid;
  return 1;
}

int
fd_vote_stakes_query_t_3( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          fd_pubkey_t const *      pubkey,
                          fd_pubkey_t *            node_account_out_opt,
                          ulong *                  stake_out_opt,
                          ushort *                 commission_out_opt ) {
  ulong epoch = (ulong)fork_id_epoch( fork_id );
  if( FD_UNLIKELY( !epoch ) ) return 0;

  ulong t_3_epoch = epoch - 1UL;
  ulong t_3_idx   = t_3_epoch & 1UL;
  if( FD_UNLIKELY( vote_stakes->t_2_epoch[ t_3_idx ]!=t_3_epoch ) ) return 0;

  vacc_t *       pool = t_2_vacc_pool( vote_stakes, t_3_idx );
  vacc_map_t *   map  = t_2_vacc_map ( vote_stakes, t_3_idx );
  vacc_t const * vacc = vacc_map_ele_query_const( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !vacc ) ) return 0;

  if( node_account_out_opt ) *node_account_out_opt = vacc->node_account;
  if( stake_out_opt )        *stake_out_opt        = vacc->stake;
  if( commission_out_opt )   *commission_out_opt   = vacc->commission;
  return 1;
}

ulong
fd_vote_stakes_cnt_t_1( fd_vote_stakes_t const * vote_stakes,
                        ulong                    fork_id ) {
  return vacc_pool_used( t_1_vacc_pool( vote_stakes, fork_id_width_id( fork_id ) ) );
}

ulong
fd_vote_stakes_cnt_t_2( fd_vote_stakes_t const * vote_stakes,
                        ulong                    fork_id ) {
  return vacc_pool_used( t_2_vacc_pool( vote_stakes, (ulong)fork_id_epoch( fork_id ) & 1UL ) );
}

ulong
fd_vote_stakes_total_stake( fd_vote_stakes_t const * vote_stakes,
                            ulong                    epoch ) {
  ulong idx = epoch & 1UL;
  if( FD_UNLIKELY( vote_stakes->t_2_epoch[ idx ]!=epoch ) ) return 0UL;

  vacc_t *     pool = t_2_vacc_pool( vote_stakes, idx );
  vacc_map_t * map  = t_2_vacc_map ( vote_stakes, idx );

  ulong total = 0UL;
  for( vacc_map_iter_t iter = vacc_map_iter_init( map, pool );
       !vacc_map_iter_done( iter, map, pool );
       iter = vacc_map_iter_next( iter, map, pool ) ) {
    total += vacc_map_iter_ele_const( iter, map, pool )->stake;
  }
  return total;
}

FD_STATIC_ASSERT( FD_VOTE_STAKES_T_1_ITER_FOOTPRINT == sizeof(vacc_map_iter_t), t_1_iter_footprint );
FD_STATIC_ASSERT( FD_VOTE_STAKES_T_1_ITER_ALIGN == alignof(vacc_map_iter_t), t_1_iter_align );
FD_STATIC_ASSERT( FD_VOTE_STAKES_T_2_ITER_FOOTPRINT == sizeof(vacc_map_iter_t), t_2_iter_footprint );
FD_STATIC_ASSERT( FD_VOTE_STAKES_T_2_ITER_ALIGN == alignof(vacc_map_iter_t), t_2_iter_align );
FD_STATIC_ASSERT( FD_VOTE_STAKES_T_3_ITER_FOOTPRINT == sizeof(vacc_map_iter_t), t_3_iter_footprint );
FD_STATIC_ASSERT( FD_VOTE_STAKES_T_3_ITER_ALIGN == alignof(vacc_map_iter_t), t_3_iter_align );

fd_vote_stakes_t_1_iter_t *
fd_vote_stakes_t_1_iter_init( fd_vote_stakes_t const * vote_stakes,
                              ulong                    fork_id,
                              uchar                    iter_mem[ static FD_VOTE_STAKES_T_1_ITER_FOOTPRINT ] ) {
  ulong        width_idx = (ulong)fork_id_width_id( fork_id );
  vacc_t *     pool      = t_1_vacc_pool( vote_stakes, width_idx );
  vacc_map_t * map       = t_1_vacc_map ( vote_stakes, width_idx );
  vacc_map_iter_t iter = vacc_map_iter_init( map, pool );
  memcpy( iter_mem, &iter, sizeof(iter) );
  return (fd_vote_stakes_t_1_iter_t *)iter_mem;
}

int
fd_vote_stakes_t_1_iter_done( fd_vote_stakes_t const *    vote_stakes,
                              ulong                       fork_id,
                              fd_vote_stakes_t_1_iter_t * iter ) {
  ulong        width_idx = (ulong)fork_id_width_id( fork_id );
  vacc_t *     pool      = t_1_vacc_pool( vote_stakes, width_idx );
  vacc_map_t * map       = t_1_vacc_map ( vote_stakes, width_idx );
  return vacc_map_iter_done( *(vacc_map_iter_t *)iter, map, pool );
}

void
fd_vote_stakes_t_1_iter_next( fd_vote_stakes_t const *    vote_stakes,
                              ulong                       fork_id,
                              fd_vote_stakes_t_1_iter_t * iter ) {
  ulong            width_idx = (ulong)fork_id_width_id( fork_id );
  vacc_t *         pool      = t_1_vacc_pool( vote_stakes, width_idx );
  vacc_map_t *     map       = t_1_vacc_map ( vote_stakes, width_idx );
  vacc_map_iter_t * map_iter = (vacc_map_iter_t *)iter;
  *map_iter = vacc_map_iter_next( *map_iter, map, pool );
}

void
fd_vote_stakes_t_1_iter_ele( fd_vote_stakes_t const *    vote_stakes,
                             ulong                       fork_id,
                             fd_vote_stakes_t_1_iter_t * iter,
                             fd_pubkey_t *               pubkey_out,
                             fd_pubkey_t *               node_account_out_opt,
                             ulong *                     stake_out_opt,
                             ushort *                    commission_out_opt,
                             uchar                       bls_key_out_opt[ FD_BLS_PUBKEY_COMPRESSED_SZ ] ) {
  ulong          width_idx = (ulong)fork_id_width_id( fork_id );
  vacc_t *       pool      = t_1_vacc_pool( vote_stakes, width_idx );
  vacc_map_t *   map       = t_1_vacc_map ( vote_stakes, width_idx );
  vacc_t const * vacc      = vacc_map_iter_ele_const( *(vacc_map_iter_t *)iter, map, pool );

  *pubkey_out = vacc->pubkey;
  if( node_account_out_opt ) *node_account_out_opt = vacc->node_account;
  if( stake_out_opt )        *stake_out_opt        = vacc->stake;
  if( commission_out_opt )   *commission_out_opt   = vacc->commission;
  if( bls_key_out_opt )      memcpy( bls_key_out_opt, vacc->bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ );
}

fd_vote_stakes_t_2_iter_t *
fd_vote_stakes_t_2_iter_init( fd_vote_stakes_t const * vote_stakes,
                              ulong                    fork_id,
                              uchar                    iter_mem[ static FD_VOTE_STAKES_T_2_ITER_FOOTPRINT ] ) {
  ulong        epoch_idx = (ulong)fork_id_epoch( fork_id ) & 1UL;
  vacc_t *     pool      = t_2_vacc_pool( vote_stakes, epoch_idx );
  vacc_map_t * map       = t_2_vacc_map ( vote_stakes, epoch_idx );
  vacc_map_iter_t iter = vacc_map_iter_init( map, pool );
  memcpy( iter_mem, &iter, sizeof(iter) );
  return (fd_vote_stakes_t_2_iter_t *)iter_mem;
}

int
fd_vote_stakes_t_2_iter_done( fd_vote_stakes_t const *    vote_stakes,
                              ulong                       fork_id,
                              fd_vote_stakes_t_2_iter_t * iter ) {
  ulong        epoch_idx = (ulong)fork_id_epoch( fork_id ) & 1UL;
  vacc_t *     pool      = t_2_vacc_pool( vote_stakes, epoch_idx );
  vacc_map_t * map       = t_2_vacc_map ( vote_stakes, epoch_idx );
  return vacc_map_iter_done( *(vacc_map_iter_t *)iter, map, pool );
}

void
fd_vote_stakes_t_2_iter_next( fd_vote_stakes_t const *    vote_stakes,
                              ulong                       fork_id,
                              fd_vote_stakes_t_2_iter_t * iter ) {
  ulong            epoch_idx = (ulong)fork_id_epoch( fork_id ) & 1UL;
  vacc_t *         pool      = t_2_vacc_pool( vote_stakes, epoch_idx );
  vacc_map_t *     map       = t_2_vacc_map ( vote_stakes, epoch_idx );
  vacc_map_iter_t * map_iter = (vacc_map_iter_t *)iter;
  *map_iter = vacc_map_iter_next( *map_iter, map, pool );
}

void
fd_vote_stakes_t_2_iter_ele( fd_vote_stakes_t const *    vote_stakes,
                             ulong                       fork_id,
                             fd_vote_stakes_t_2_iter_t * iter,
                             fd_pubkey_t *               pubkey_out,
                             fd_pubkey_t *               node_account_out_opt,
                             ulong *                     stake_out_opt,
                             ulong *                     last_vote_slot_out_opt,
                             long *                      last_vote_ts_out_opt,
                             ushort *                    commission_out_opt,
                             uchar *                     is_valid_out_opt,
                             ushort *                    alpenglow_rank_out_opt,
                             uchar                       bls_key_out_opt[ FD_BLS_PUBKEY_COMPRESSED_SZ ] ) {
  ulong                 epoch_idx = (ulong)fork_id_epoch( fork_id ) & 1UL;
  vacc_t *              pool      = t_2_vacc_pool( vote_stakes, epoch_idx );
  vacc_map_t *          map       = t_2_vacc_map ( vote_stakes, epoch_idx );
  vacc_t const *        vacc      = vacc_map_iter_ele_const( *(vacc_map_iter_t *)iter, map, pool );
  ulong                 vacc_idx  = vacc_pool_idx( pool, vacc );
  vacc_states_t const * states    = vacc_state_pool_ele_const( vacc_states_pool( vote_stakes ), fork_id_bank_id( fork_id ) );

  *pubkey_out = vacc->pubkey;
  if( node_account_out_opt )   *node_account_out_opt   = vacc->node_account;
  if( stake_out_opt )          *stake_out_opt          = vacc->stake;
  if( last_vote_slot_out_opt ) *last_vote_slot_out_opt = states->states[ vacc_idx ].last_vote_slot;
  if( last_vote_ts_out_opt )   *last_vote_ts_out_opt   = states->states[ vacc_idx ].last_vote_ts;
  if( commission_out_opt )     *commission_out_opt     = vacc->commission;
  if( is_valid_out_opt )       *is_valid_out_opt       = states->states[ vacc_idx ].is_valid;
  if( alpenglow_rank_out_opt ) *alpenglow_rank_out_opt = vacc->alpenglow_rank;
  if( bls_key_out_opt )        memcpy( bls_key_out_opt, vacc->bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ );
}

fd_vote_stakes_t_3_iter_t *
fd_vote_stakes_t_3_iter_init( fd_vote_stakes_t const * vote_stakes,
                              ulong                    fork_id,
                              uchar                    iter_mem[ static FD_VOTE_STAKES_T_3_ITER_FOOTPRINT ] ) {
  ulong epoch = (ulong)fork_id_epoch( fork_id );

  vacc_map_iter_t iter = {0};
  if( FD_LIKELY( epoch ) ) {
    ulong t_3_epoch = epoch - 1UL;
    ulong t_3_idx   = t_3_epoch & 1UL;
    if( FD_LIKELY( vote_stakes->t_2_epoch[ t_3_idx ]==t_3_epoch ) ) {
      vacc_t *     pool = t_2_vacc_pool( vote_stakes, t_3_idx );
      vacc_map_t * map  = t_2_vacc_map ( vote_stakes, t_3_idx );
      iter = vacc_map_iter_init( map, pool );
    }
  }
  memcpy( iter_mem, &iter, sizeof(iter) );
  return (fd_vote_stakes_t_3_iter_t *)iter_mem;
}

int
fd_vote_stakes_t_3_iter_done( fd_vote_stakes_t const *    vote_stakes,
                              ulong                       fork_id,
                              fd_vote_stakes_t_3_iter_t * iter ) {
  ulong epoch = (ulong)fork_id_epoch( fork_id );
  if( FD_UNLIKELY( !epoch ) ) return 1;

  ulong t_3_epoch = epoch - 1UL;
  ulong t_3_idx   = t_3_epoch & 1UL;
  if( FD_UNLIKELY( vote_stakes->t_2_epoch[ t_3_idx ]!=t_3_epoch ) ) return 1;

  vacc_t *     pool = t_2_vacc_pool( vote_stakes, t_3_idx );
  vacc_map_t * map  = t_2_vacc_map ( vote_stakes, t_3_idx );
  return vacc_map_iter_done( *(vacc_map_iter_t *)iter, map, pool );
}

void
fd_vote_stakes_t_3_iter_next( fd_vote_stakes_t const *    vote_stakes,
                              ulong                       fork_id,
                              fd_vote_stakes_t_3_iter_t * iter ) {
  ulong             t_3_idx  = ((ulong)fork_id_epoch( fork_id ) - 1UL) & 1UL;
  vacc_t *          pool     = t_2_vacc_pool( vote_stakes, t_3_idx );
  vacc_map_t *      map      = t_2_vacc_map ( vote_stakes, t_3_idx );
  vacc_map_iter_t * map_iter = (vacc_map_iter_t *)iter;
  *map_iter = vacc_map_iter_next( *map_iter, map, pool );
}

void
fd_vote_stakes_t_3_iter_ele( fd_vote_stakes_t const *    vote_stakes,
                             ulong                       fork_id,
                             fd_vote_stakes_t_3_iter_t * iter,
                             fd_pubkey_t *               pubkey_out,
                             fd_pubkey_t *               node_account_out_opt,
                             ulong *                     stake_out_opt,
                             ushort *                    commission_out_opt,
                             ushort *                    alpenglow_rank_out_opt,
                             uchar                       bls_key_out_opt[ FD_BLS_PUBKEY_COMPRESSED_SZ ] ) {
  ulong          t_3_idx = ((ulong)fork_id_epoch( fork_id ) - 1UL) & 1UL;
  vacc_t *       pool    = t_2_vacc_pool( vote_stakes, t_3_idx );
  vacc_map_t *   map     = t_2_vacc_map ( vote_stakes, t_3_idx );
  vacc_t const * vacc    = vacc_map_iter_ele_const( *(vacc_map_iter_t *)iter, map, pool );

  *pubkey_out = vacc->pubkey;
  if( node_account_out_opt )   *node_account_out_opt   = vacc->node_account;
  if( stake_out_opt )          *stake_out_opt          = vacc->stake;
  if( commission_out_opt )     *commission_out_opt     = vacc->commission;
  if( alpenglow_rank_out_opt ) *alpenglow_rank_out_opt = vacc->alpenglow_rank;
  if( bls_key_out_opt )        memcpy( bls_key_out_opt, vacc->bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ );
}
