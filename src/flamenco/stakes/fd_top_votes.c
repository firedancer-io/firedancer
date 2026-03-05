#include "fd_top_votes.h"

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
  ushort      left;
  ushort      right;
  ushort      next;
  uchar       has_tie;
};
typedef struct vote_ele vote_ele_t;

#define HEAP_NAME       heap
#define HEAP_IDX_T      ushort
#define HEAP_T          vote_ele_t
#define HEAP_LT(e0,e1) ( ((e0)->stake < (e1)->stake) | \
                         ( ((e0)->stake==(e1)->stake) & \
                           (memcmp( &(e0)->pubkey, &(e1)->pubkey, sizeof(fd_pubkey_t) )<0 ) ) )
#include "../../util/tmpl/fd_heap.c"

#define POOL_NAME  pool
#define POOL_T     vote_ele_t
#define POOL_IDX_T ushort
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
get_pool( fd_top_votes_t * top_votes ) {
  return (vote_ele_t *)( (ulong)top_votes + top_votes->pool_off );
}

static inline heap_t *
get_heap( fd_top_votes_t * top_votes ) {
  return (heap_t *)( (ulong)top_votes + top_votes->heap_off );
}

static inline map_t *
get_map( fd_top_votes_t * top_votes ) {
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
  void *           pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( vote_accounts_max ) );
  void *           heap_mem  = FD_SCRATCH_ALLOC_APPEND( l, heap_align(), heap_footprint( vote_accounts_max ) );
  void *           map_mem   = FD_SCRATCH_ALLOC_APPEND( l, map_align(),  map_footprint( map_chain_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_top_votes_align() );

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
fd_top_votes_update( fd_top_votes_t *    top_votes,
                     fd_pubkey_t const * pubkey,
                     fd_pubkey_t const * node_account,
                     ulong               stake ) {
/* If the heap is full, then we need to remove the minimum element.
   There are a few cases to consider:
   1. There are multiple elements at the bottom of the heap with the
      same stake.  In this case, evict all of them and insert the new
      element.
   2. The element we are attempting to insert has the same stake as
      the minimum element.  In this case, we remove all elements with
      the minimum stake and don't insert a new element.  We need to
      watermark the minimum stake value that was evicted to avoid
      allowing later inserts with the same stake.
   3. Don't insert the new element if it has a stake less than the
      watermark. */

  vote_ele_t * pool = get_pool( top_votes );
  heap_t *     heap = get_heap( top_votes );
  map_t *      map  = get_map( top_votes );

  if( FD_UNLIKELY( stake<=top_votes->min_stake_wmark ) ) return;

  if( FD_UNLIKELY( heap_ele_cnt( heap )==heap_ele_max( heap ) ) ) {

    vote_ele_t * ele = heap_ele_peek_min( heap, pool );
    if( stake<ele->stake ) return;

    /* If the prospective element ties with the minimum element, remove
       all elements with the same stake and update the watermark. */
    if( FD_UNLIKELY( stake==ele->stake ) ) {
      top_votes->min_stake_wmark = stake;
      while( (ele=heap_ele_peek_min( heap, pool )) && ele && ele->stake==stake ) {
        heap_ele_remove_min( heap, pool );
        map_ele_remove( map, &ele->pubkey, NULL, pool );
        pool_ele_release( pool, ele );
      }
      return;
    }

    ulong min_stake = ele->stake;
    while( (ele=heap_ele_peek_min( heap, pool )) && ele && min_stake==ele->stake ) {
      heap_ele_remove_min( heap, pool );
      map_ele_remove( map, &ele->pubkey, NULL, pool );
      pool_ele_release( pool, ele );
    }
  }

  vote_ele_t * ele  = pool_ele_acquire( pool );
  ele->pubkey       = *pubkey;
  ele->node_account = *node_account;
  ele->stake        = stake;
  heap_ele_insert( heap, ele, pool );
  map_ele_insert( map, ele, pool );
}

int
fd_top_votes_query( fd_top_votes_t *    top_votes,
                    fd_pubkey_t const * pubkey,
                    fd_pubkey_t *       node_account_out_opt,
                    ulong *             stake_out_opt ) {
  vote_ele_t * pool = get_pool( top_votes );
  map_t *      map  = get_map( top_votes );


  vote_ele_t * ele = map_ele_query( map, pubkey, NULL, pool );
  if( FD_UNLIKELY( !ele ) ) return 0;

  if( node_account_out_opt ) *node_account_out_opt = ele->node_account;
  if( stake_out_opt )        *stake_out_opt        = ele->stake;

  return 1;
}
