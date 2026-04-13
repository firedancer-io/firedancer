#include "fd_top_votes.h"
#include "../accdb/fd_accdb_sync.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/program/vote/fd_vote_codec.h"

#define FD_TOP_VOTES_MAGIC (0xF17EDA2CE7401E70UL) /* FIREDANCER TOP VOTES V0 */

struct fd_top_votes {
  ulong magic;
  ulong pool_off;
  ulong heap_off;
  ulong map_off;

  ulong min_stake_wmark;
};
typedef struct fd_top_votes fd_top_votes_t;

struct vote_ele {
  fd_pubkey_t pubkey;
  fd_pubkey_t node_account;
  ulong       stake;
  ulong       last_vote_slot;
  long        last_vote_timestamp;
  uchar       commission;
  uchar       is_valid;

  ushort      left;
  ushort      right;
  ushort      next;
};
typedef struct vote_ele vote_ele_t;

#define HEAP_NAME       heap
#define HEAP_IDX_T      ushort
#define HEAP_T          vote_ele_t
#define HEAP_LT(e0,e1) ( ((e0)->stake < (e1)->stake) | \
                         (((e0)->stake==(e1)->stake) & \
                          (memcmp( &(e0)->pubkey, &(e1)->pubkey, sizeof(fd_pubkey_t) )<0 ) ) )
#include "../../util/tmpl/fd_heap.c"

#define POOL_NAME  pool
#define POOL_T     vote_ele_t
#define POOL_IDX_T ushort
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              vote_ele_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_IDX_T              ushort
#include "../../util/tmpl/fd_map_chain.c"

static inline vote_ele_t *
get_pool( fd_top_votes_t const * top_votes ) {
  return (vote_ele_t *)( (ulong)top_votes + top_votes->pool_off );
}

static inline heap_t *
get_heap( fd_top_votes_t const * top_votes ) {
  return (heap_t *)( (ulong)top_votes + top_votes->heap_off );
}

static inline map_t *
get_map( fd_top_votes_t const * top_votes ) {
  return (map_t *)( (ulong)top_votes + top_votes->map_off );
}

ulong
fd_top_votes_align( void ) {
  return FD_TOP_VOTES_ALIGN;
}

ulong
fd_top_votes_footprint( ulong vote_accounts_max ) {
  ulong map_chain_cnt = map_chain_cnt_est( vote_accounts_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_top_votes_align(), sizeof(fd_top_votes_t) );
  l = FD_LAYOUT_APPEND( l, pool_align(),         pool_footprint( vote_accounts_max ) );
  l = FD_LAYOUT_APPEND( l, heap_align(),         heap_footprint( vote_accounts_max ) );
  l = FD_LAYOUT_APPEND( l, map_align(),          map_footprint( map_chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_top_votes_align() );
}

void *
fd_top_votes_new( void * mem,
                  ushort vote_accounts_max,
                  ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_top_votes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong map_chain_cnt = map_chain_cnt_est( vote_accounts_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_top_votes_t * top_votes = FD_SCRATCH_ALLOC_APPEND( l, fd_top_votes_align(), sizeof(fd_top_votes_t) );
  void *           pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),         pool_footprint( vote_accounts_max ) );
  void *           heap_mem  = FD_SCRATCH_ALLOC_APPEND( l, heap_align(),         heap_footprint( vote_accounts_max ) );
  void *           map_mem   = FD_SCRATCH_ALLOC_APPEND( l, map_align(),          map_footprint( map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_top_votes_align() ) != (ulong)top_votes + fd_top_votes_footprint( vote_accounts_max ) ) ) {
    FD_LOG_WARNING(( "fd_banks_new: bad layout" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_top_votes_footprint( vote_accounts_max )>FD_TOP_VOTES_MAX_FOOTPRINT ) ) {
    FD_LOG_WARNING(( "fd_top_votes_new: bad footprint" ));
    return NULL;
  }

  vote_ele_t * pool = pool_join( pool_new( pool_mem, vote_accounts_max ) );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "Failed to create top votes pool" ));
    return NULL;
  }
  top_votes->pool_off = (ulong)pool - (ulong)mem;

  heap_t * heap = heap_join( heap_new( heap_mem, vote_accounts_max ) );
  if( FD_UNLIKELY( !heap ) ) {
    FD_LOG_WARNING(( "Failed to create top votes heap" ));
    return NULL;
  }
  top_votes->heap_off = (ulong)heap - (ulong)mem;

  map_t * map = map_join( map_new( map_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "Failed to create top votes map" ));
    return NULL;
  }
  top_votes->map_off = (ulong)map - (ulong)mem;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( top_votes->magic ) = FD_TOP_VOTES_MAGIC;
  FD_COMPILER_MFENCE();

  return top_votes;
}

fd_top_votes_t *
fd_top_votes_join( void * mem ) {
  fd_top_votes_t * top_votes = (fd_top_votes_t *)mem;

  if( FD_UNLIKELY( !top_votes ) ) {
    FD_LOG_WARNING(( "NULL top votes" ));
    return NULL;
  }

  if( FD_UNLIKELY( top_votes->magic!=FD_TOP_VOTES_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid top votes magic" ));
    return NULL;
  }

  return top_votes;
}

void
fd_top_votes_init( fd_top_votes_t * top_votes ) {
  vote_ele_t * pool = get_pool( top_votes );
  heap_t *     heap = get_heap( top_votes );
  map_t *      map  = get_map( top_votes );

  top_votes->min_stake_wmark = 0UL;

  /* TODO: A smarter reset can probably be done here. */
  while( heap_ele_cnt( heap ) ) heap_ele_remove_min( heap, pool );

  map_reset( map );
  pool_reset( pool );
}

void
fd_top_votes_insert( fd_top_votes_t *    top_votes,
                     fd_pubkey_t const * pubkey,
                     fd_pubkey_t const * node_account,
                     ulong               stake,
                     uchar               commission ) {
/* If the heap is full, treat the current minimum stake as the cutoff
   stake.  This matches Agave's retain(stake > floor_stake) behavior:
   1. Reject candidates below the cutoff.
   2. Evict all entries at the cutoff stake and watermark that stake so
      later inserts at or below the cutoff stay excluded.
   3. Insert the candidate only if it is strictly above the cutoff. */

  vote_ele_t * pool = get_pool( top_votes );
  heap_t *     heap = get_heap( top_votes );
  map_t *      map  = get_map( top_votes );

  if( FD_UNLIKELY( stake==0UL || stake<=top_votes->min_stake_wmark ) ) return;

  if( FD_UNLIKELY( heap_ele_cnt( heap )==heap_ele_max( heap ) ) ) {
    vote_ele_t * ele       = heap_ele_peek_min( heap, pool );
    ulong        min_stake = ele->stake;
    if( stake<min_stake ) return;

    top_votes->min_stake_wmark = min_stake;
    while( (ele=heap_ele_peek_min( heap, pool )) && ele && min_stake==ele->stake ) {
      heap_ele_remove_min( heap, pool );
      map_ele_remove( map, &ele->pubkey, NULL, pool );
      pool_ele_release( pool, ele );
    }
    if( FD_UNLIKELY( stake==min_stake ) ) return;
  }

  vote_ele_t * ele         = pool_ele_acquire( pool );
  ele->pubkey              = *pubkey;
  ele->node_account        = *node_account;
  ele->stake               = stake;
  ele->commission          = commission;
  ele->last_vote_slot      = 0UL;
  ele->last_vote_timestamp = 0L;
  ele->is_valid            = 1;
  heap_ele_insert( heap, ele, pool );
  map_ele_insert( map, ele, pool );
}

void
fd_top_votes_update( fd_top_votes_t *    top_votes,
                     fd_pubkey_t const * pubkey,
                     ulong               last_vote_slot,
                     long                last_vote_timestamp ) {
  vote_ele_t * pool = get_pool( top_votes );
  map_t *      map  = get_map( top_votes );

  ushort idx = (ushort)map_idx_query_const( map, pubkey, USHORT_MAX, pool );
  if( FD_UNLIKELY( idx==USHORT_MAX ) ) return;
  vote_ele_t * ele = pool_ele( pool, idx );
  ele->last_vote_slot      = last_vote_slot;
  ele->last_vote_timestamp = last_vote_timestamp;
  ele->is_valid            = 1;
}

void
fd_top_votes_invalidate( fd_top_votes_t *    top_votes,
                         fd_pubkey_t const * pubkey ) {
  vote_ele_t * pool = get_pool( top_votes );
  map_t *      map  = get_map( top_votes );

  ushort idx = (ushort)map_idx_query_const( map, pubkey, USHORT_MAX, pool );
  if( FD_UNLIKELY( idx==USHORT_MAX ) ) return;
  pool_ele( pool, idx )->is_valid = 0;
}

int
fd_top_votes_query( fd_top_votes_t const * top_votes,
                    fd_pubkey_t const *    pubkey,
                    fd_pubkey_t *          node_account_out_opt,
                    ulong *                stake_out_opt,
                    ulong *                last_vote_slot_out_opt,
                    long *                 last_vote_timestamp_out_opt,
                    uchar *                commission_out_opt ) {
  vote_ele_t * pool = get_pool( top_votes );
  map_t *      map  = get_map( top_votes );

  vote_ele_t const * ele = map_ele_query_const( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !ele ) ) return 0;
  if( FD_UNLIKELY( !ele->is_valid ) ) return 0;

  if( node_account_out_opt )        *node_account_out_opt        = ele->node_account;
  if( stake_out_opt )               *stake_out_opt               = ele->stake;
  if( last_vote_slot_out_opt )      *last_vote_slot_out_opt      = ele->last_vote_slot;
  if( last_vote_timestamp_out_opt ) *last_vote_timestamp_out_opt = ele->last_vote_timestamp;
  if( commission_out_opt )          *commission_out_opt          = ele->commission;
  return 1;
}

void
fd_top_votes_refresh( fd_top_votes_t *          top_votes,
                      fd_accdb_user_t *         accdb,
                      fd_funk_txn_xid_t const * xid ) {
  uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) top_votes_iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];
  for( fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes, top_votes_iter_mem );
        !fd_top_votes_iter_done( top_votes, iter );
        fd_top_votes_iter_next( top_votes, iter ) ) {
    fd_pubkey_t pubkey;
    fd_top_votes_iter_ele( top_votes, iter, &pubkey, NULL, NULL, NULL, NULL, NULL );

    int is_valid = 1;
    fd_accdb_ro_t acc[1];
    if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, acc, xid, &pubkey ) ) ) {
      is_valid = 0;
    } else if( FD_UNLIKELY( !fd_vsv_is_correct_size_and_initialized( acc->meta ) ) ) {
      fd_accdb_close_ro( accdb, acc );
      is_valid = 0;
    }

    if( FD_LIKELY( is_valid ) ) {
      fd_vote_block_timestamp_t last_vote;
      FD_TEST( !fd_vote_account_last_timestamp( fd_account_data( acc->meta ), acc->meta->dlen, &last_vote ) );
      fd_top_votes_update( top_votes, &pubkey, last_vote.slot, last_vote.timestamp );
      fd_accdb_close_ro( accdb, acc );
    } else {
      fd_top_votes_invalidate( top_votes, &pubkey );
    }
  }
}

FD_STATIC_ASSERT( FD_TOP_VOTES_ITER_FOOTPRINT == sizeof(map_iter_t), top_votes_iter );
FD_STATIC_ASSERT( FD_TOP_VOTES_ITER_ALIGN == alignof(map_iter_t), top_votes_iter );

fd_top_votes_iter_t *
fd_top_votes_iter_init( fd_top_votes_t const * top_votes,
                        uchar                  iter_mem[ static FD_TOP_VOTES_ITER_FOOTPRINT ] ) {
  map_iter_t iter = map_iter_init( get_map( top_votes ), get_pool( top_votes ) );
  memcpy( iter_mem, &iter, sizeof(map_iter_t) );
  return (fd_top_votes_iter_t *)iter_mem;
}

int
fd_top_votes_iter_done( fd_top_votes_t const * top_votes,
                        fd_top_votes_iter_t *  iter ) {
  map_iter_t * map_iter = (map_iter_t *)iter;
  return map_iter_done( *map_iter, get_map( top_votes ), get_pool( top_votes ) );
}

void
fd_top_votes_iter_next( fd_top_votes_t const * top_votes,
                        fd_top_votes_iter_t *  iter ) {
  map_iter_t * map_iter = (map_iter_t *)iter;
  *map_iter = map_iter_next( *map_iter, get_map( top_votes ), get_pool( top_votes ) );
}

int
fd_top_votes_iter_ele( fd_top_votes_t const * top_votes,
                       fd_top_votes_iter_t *  iter,
                       fd_pubkey_t *          pubkey_out,
                       fd_pubkey_t *          node_account_out_opt,
                       ulong *                stake_out_opt,
                       uchar *                commission_out_opt,
                       ulong *                last_vote_slot_out_opt,
                       long *                 last_vote_timestamp_out_opt ) {
  map_iter_t * map_iter = (map_iter_t *)iter;
  vote_ele_t * ele      = map_iter_ele( *map_iter, get_map( top_votes ), get_pool( top_votes ) );
  *pubkey_out = ele->pubkey;

  if( node_account_out_opt )        *node_account_out_opt        = ele->node_account;
  if( stake_out_opt )               *stake_out_opt               = ele->stake;
  if( last_vote_slot_out_opt )      *last_vote_slot_out_opt      = ele->last_vote_slot;
  if( last_vote_timestamp_out_opt ) *last_vote_timestamp_out_opt = ele->last_vote_timestamp;
  if( commission_out_opt )          *commission_out_opt          = ele->commission;

  return ele->is_valid;
}
