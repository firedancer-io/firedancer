#include "fd_vote_stakes.h"

struct index_key {
  fd_pubkey_t pubkey;
  ulong       stake_t_1;
};
typedef struct index_key index_key_t;

struct index_ele {
  index_key_t key;
  ulong       stake_t_2;
  uint        next;
  uint        refcnt;
};
typedef struct index_ele index_ele_t;

#define POOL_NAME  index_pool
#define POOL_T     index_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               index_map
#define MAP_KEY_T              index_key_t
#define MAP_ELE_T              index_ele_t
#define MAP_KEY                key
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(index_key_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

/* Each pool index is just an array of uint indices into the pool. */
struct stake {
  uint idx;
  uint next;
};
typedef struct stake stake_t;

#define POOL_NAME  stakes_pool
#define POOL_T     stake_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               stakes_map
#define MAP_KEY_T              uint
#define MAP_ELE_T              stake_t
#define MAP_KEY                idx
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct fork {
  ushort next;
};
typedef struct fork fork_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_t
#define POOL_NEXT  next
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"


struct fd_vote_stakes {
  ulong magic;
  ulong index_pool_offset;
  ulong index_map_offset;

  ulong  stakes_pool_offset[ 128UL ]; /* TODO:FIXME: this has to be configurable */
  ulong  stakes_map_offset[ 128UL ]; /* TODO:FIXME: this has to be configurable */
  ulong  outstanding;

  ushort root_idx;
};
typedef struct fd_vote_stakes fd_vote_stakes_t;

static index_ele_t *
get_index_pool( fd_vote_stakes_t * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->index_pool_offset );
}

static index_map_t *
get_index_map( fd_vote_stakes_t * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->index_map_offset );
}

static stake_t *
get_stakes_pool( fd_vote_stakes_t * vote_stakes,
                 ushort             fork_idx ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->stakes_pool_offset[ fork_idx ] );
}

static stakes_map_t *
get_stakes_map( fd_vote_stakes_t * vote_stakes,
                ushort             fork_idx ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->stakes_map_offset[ fork_idx ] );
}

static fork_t *
get_fork_pool( fd_vote_stakes_t * vote_stakes ) {
  return fd_type_pun( (uchar *)vote_stakes + vote_stakes->fork_pool_offset );
}

ulong
fd_vote_stakes_align( void ) {
  return 128UL;
}

ulong
fd_vote_stakes_footprint( ulong max_vote_accounts,
                          ulong max_fork_width,
                          ulong map_chain_cnt ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_vote_stakes_align(), sizeof(fd_vote_stakes_t) );
  l = FD_LAYOUT_APPEND( l, index_pool_align(),     index_pool_footprint( max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l, index_map_align(),      index_map_footprint( map_chain_cnt ) );
  for( ulong i=0; i<max_fork_width; i++ ) {
    l = FD_LAYOUT_APPEND( l, stakes_pool_align(), stakes_pool_footprint( max_vote_accounts ) );
    l = FD_LAYOUT_APPEND( l, stakes_map_align(),  stakes_map_footprint( map_chain_cnt ) );
  }
  return FD_LAYOUT_FINI( l, fd_vote_stakes_align() );
}

void *
fd_vote_stakes_new( void * shmem,
                    ulong  max_vote_accounts,
                    ulong  max_fork_width,
                    ulong  map_chain_cnt,
                    ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_vote_stakes_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_vote_stakes_t * vote_stakes    = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_stakes_align(), sizeof(fd_vote_stakes_t) );
  void *             index_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, index_pool_align(),     index_pool_footprint( max_vote_accounts ) );
  void *             index_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, index_map_align(),      index_map_footprint( map_chain_cnt ) );
  void *             fork_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),      fork_pool_footprint( max_fork_width ) );
  for( ulong i=0; i<max_fork_width; i++ ) {
    void * stakes_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, stakes_pool_align(), stakes_pool_footprint( max_vote_accounts ) );
    stake_t * stakes_pool = stakes_pool_join( stakes_pool_new( stakes_pool_mem, max_vote_accounts ) );
    if( FD_UNLIKELY( !stakes_pool ) ) {
      FD_LOG_WARNING(( "Failed to create vote stakes ele pool" ));
      return NULL;
    }
    vote_stakes->stakes_pool_offset[ i ] = (ulong)stakes_pool_mem - (ulong)shmem;

    void * stakes_map_mem = FD_SCRATCH_ALLOC_APPEND( l, stakes_map_align(), stakes_map_footprint( map_chain_cnt ) );
    stakes_map_t * stakes_map = stakes_map_join( stakes_map_new( stakes_map_mem, max_vote_accounts, seed ) );
    if( FD_UNLIKELY( !stakes_map ) ) {
      FD_LOG_WARNING(( "Failed to create vote stakes ele map" ));
      return NULL;
    }
    vote_stakes->stakes_map_offset[ i ] = (ulong)stakes_map_mem - (ulong)shmem;
  }

  index_ele_t * index_pool = index_pool_join( index_pool_new( index_pool_mem, max_vote_accounts ) );
  if( FD_UNLIKELY( !index_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote stakes index pool" ));
    return NULL;
  }

  index_map_t * index_map = index_map_join( index_map_new( index_map_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !index_map ) ) {
    FD_LOG_WARNING(( "Failed to create vote stakes index map" ));
    return NULL;
  }

  fork_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote stakes fork pool" ));
    return NULL;
  }

  vote_stakes->index_pool_offset = (ulong)index_pool_mem - (ulong)shmem;
  vote_stakes->index_map_offset  = (ulong)index_map_mem - (ulong)shmem;
  vote_stakes->fork_pool_offset  = (ulong)fork_pool_mem - (ulong)shmem;

  vote_stakes->root_idx = (ushort)fork_pool_idx_acquire( fork_pool );
  fork_t * fork         = fork_pool_ele( fork_pool, vote_stakes->root_idx );
  fork->parent_idx      = USHORT_MAX;
  fork->child_idx       = USHORT_MAX;
  fork->sibling_idx     = USHORT_MAX;

  return shmem;
}

fd_vote_stakes_t *
fd_vote_stakes_join( void * shmem ) {
  /* TODO:FIXME: MAGIC */
  return (fd_vote_stakes_t *)shmem;
}

void
fd_vote_stakes_insert_root( fd_vote_stakes_t * vote_stakes,
                            fd_pubkey_t *      pubkey,
                            ulong              stake_t_1,
                            ulong              stake_t_2 ) {

  index_ele_t * index_pool = get_index_pool( vote_stakes );
  index_map_t * index_map  = get_index_map( vote_stakes );

  index_ele_t * ele = index_pool_ele_acquire( index_pool );
  ele->key       = (index_key_t){ .pubkey = *pubkey, .stake_t_1 = stake_t_1 };
  ele->stake_t_2 = stake_t_2;
  ele->refcnt    = 1;
  FD_TEST( index_map_ele_insert( index_map, ele, index_pool ) );
  uint pubkey_idx = (uint)index_pool_idx( index_pool, ele );

  stake_t *      stakes_pool = get_stakes_pool( vote_stakes, vote_stakes->root_idx );
  stakes_map_t * stakes_map  = get_stakes_map( vote_stakes, vote_stakes->root_idx );
  stake_t *      new_stake = stakes_pool_ele_acquire( stakes_pool );
  new_stake->idx = pubkey_idx;
  FD_TEST( stakes_map_ele_insert( stakes_map, new_stake, stakes_pool ) );
}

ushort
fd_vote_stakes_new_child( fd_vote_stakes_t * vote_stakes ) {
  fork_t * fork_pool = get_fork_pool( vote_stakes );

  if( FD_UNLIKELY( !fork_pool_free( fork_pool ) ) ) {
    FD_LOG_CRIT(( "no free forks in pool" ));
  }

  ushort idx = (ushort)fork_pool_idx_acquire( fork_pool );

  stake_t *      stake_pool = get_stakes_pool( vote_stakes, idx );
  stakes_map_t * stakes_map = get_stakes_map( vote_stakes, idx );

  stakes_map_reset( stakes_map );
  stakes_pool_reset( stake_pool );

  return idx;
}

void
fd_vote_stakes_advance_root( fd_vote_stakes_t * vote_stakes,
                             ushort             new_root_idx ) {
  (void)vote_stakes;
  (void)new_root_idx;

  /* TODO: Need a way to cleanly iterate though all used nodes but the */
}
