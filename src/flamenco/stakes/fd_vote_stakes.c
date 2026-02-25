#include "fd_vote_stakes.h"
#include "fd_vote_stakes_private.h"

ulong
fd_vote_stakes_align( void ) {
  return FD_VOTE_STAKES_ALIGN;
}

ulong
fd_vote_stakes_footprint( ulong max_vote_accounts,
                          ulong max_fork_width,
                          ulong map_chain_cnt ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_vote_stakes_align(),  sizeof(fd_vote_stakes_t) );
  l = FD_LAYOUT_APPEND( l, index_pool_align(),      index_pool_footprint( max_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l, index_map_align(),       index_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, index_map_multi_align(), index_map_multi_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),       fork_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, fork_dlist_align(),      fork_dlist_footprint() );
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

  if( FD_UNLIKELY( max_fork_width>MAX_FORK_WIDTH ) ) {
    FD_LOG_WARNING(( "max_fork_width is too large" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_vote_stakes_t * vote_stakes         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_stakes_align(),  sizeof(fd_vote_stakes_t) );
  void *             index_pool_mem      = FD_SCRATCH_ALLOC_APPEND( l, index_pool_align(),      index_pool_footprint( max_vote_accounts ) );
  void *             index_map_mem       = FD_SCRATCH_ALLOC_APPEND( l, index_map_align(),       index_map_footprint( map_chain_cnt ) );
  void *             index_map_multi_mem = FD_SCRATCH_ALLOC_APPEND( l, index_map_multi_align(), index_map_multi_footprint( map_chain_cnt ) );
  void *             fork_pool_mem       = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),       fork_pool_footprint( max_fork_width ) );
  void *             fork_dlist_mem      = FD_SCRATCH_ALLOC_APPEND( l, fork_dlist_align(),      fork_dlist_footprint() );
  for( ulong i=0; i<max_fork_width; i++ ) {
    void *    stakes_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, stakes_pool_align(), stakes_pool_footprint( max_vote_accounts ) );
    stake_t * stakes_pool     = stakes_pool_join( stakes_pool_new( stakes_pool_mem, max_vote_accounts ) );
    if( FD_UNLIKELY( !stakes_pool ) ) {
      FD_LOG_WARNING(( "Failed to create vote stakes ele pool" ));
      return NULL;
    }
    vote_stakes->stakes_pool_off[ i ] = (ulong)stakes_pool - (ulong)shmem;

    void * stakes_map_mem = FD_SCRATCH_ALLOC_APPEND( l, stakes_map_align(), stakes_map_footprint( map_chain_cnt ) );
    stakes_map_t * stakes_map = stakes_map_join( stakes_map_new( stakes_map_mem, max_vote_accounts, seed ) );
    if( FD_UNLIKELY( !stakes_map ) ) {
      FD_LOG_WARNING(( "Failed to create vote stakes ele map" ));
      return NULL;
    }
    vote_stakes->stakes_map_off[ i ] = (ulong)stakes_map - (ulong)shmem;
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

  index_map_multi_t * index_map_multi = index_map_multi_join( index_map_multi_new( index_map_multi_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !index_map_multi ) ) {
    FD_LOG_WARNING(( "Failed to create vote stakes index map multi" ));
    return NULL;
  }

  fork_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create vote stakes fork pool" ));
    return NULL;
  }

  fork_dlist_t * fork_dlist = fork_dlist_join( fork_dlist_new( fork_dlist_mem ) );
  if( FD_UNLIKELY( !fork_dlist ) ) {
    FD_LOG_WARNING(( "Failed to create vote stakes fork dlist" ));
    return NULL;
  }

  vote_stakes->index_pool_off      = (ulong)index_pool - (ulong)shmem;
  vote_stakes->index_map_off       = (ulong)index_map - (ulong)shmem;
  vote_stakes->index_map_multi_off = (ulong)index_map_multi - (ulong)shmem;
  vote_stakes->fork_pool_off       = (ulong)fork_pool - (ulong)shmem;
  vote_stakes->fork_dlist_off      = (ulong)fork_dlist - (ulong)shmem;
  vote_stakes->root_idx            = (ushort)fork_pool_idx_acquire( fork_pool );
  fork_dlist_idx_push_tail( fork_dlist, vote_stakes->root_idx, fork_pool );


  FD_COMPILER_MFENCE();
  FD_VOLATILE( vote_stakes->magic ) = FD_VOTE_STAKES_MAGIC;
  FD_COMPILER_MFENCE();

  return vote_stakes;
}

fd_vote_stakes_t *
fd_vote_stakes_join( void * shmem ) {
  fd_vote_stakes_t * vote_stakes = (fd_vote_stakes_t *)shmem;

  if( FD_UNLIKELY( !vote_stakes ) ) {
    FD_LOG_WARNING(( "NULL vote stakes" ));
    return NULL;
  }

  if( FD_UNLIKELY( vote_stakes->magic != FD_VOTE_STAKES_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid vote stakes magic" ));
    return NULL;
  }

  return vote_stakes;
}

void
fd_vote_stakes_insert_root( fd_vote_stakes_t * vote_stakes,
                            fd_pubkey_t *      pubkey,
                            ulong              stake_t_1,
                            ulong              stake_t_2 ) {

  index_ele_t *       index_pool      = get_index_pool( vote_stakes );
  index_map_t *       index_map       = get_index_map( vote_stakes );
  index_map_multi_t * index_map_multi = get_index_map_multi( vote_stakes );

  index_ele_t * ele = index_pool_ele_acquire( index_pool );
  ele->index_key    = (index_key_t){ .pubkey = *pubkey, .stake_t_1 = stake_t_1 };
  ele->stake_t_2    = stake_t_2;
  ele->refcnt       = 1;
  FD_TEST( index_map_multi_ele_insert( index_map_multi, ele, index_pool ) );
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
  fork_t *       fork_pool  = get_fork_pool( vote_stakes );
  fork_dlist_t * fork_dlist = get_fork_dlist( vote_stakes );

  if( FD_UNLIKELY( !fork_pool_free( fork_pool ) ) ) {
    FD_LOG_CRIT(( "no free forks in pool" ));
  }

  ushort idx = (ushort)fork_pool_idx_acquire( fork_pool );

  fork_dlist_idx_push_tail( fork_dlist, idx, fork_pool );

  return idx;
}

void
fd_vote_stakes_advance_root( fd_vote_stakes_t * vote_stakes,
                             ushort             root_idx ) {
  /* Only expect the vote stakes to update once an epoch. */
  if( FD_LIKELY( root_idx==vote_stakes->root_idx ) ) return;

  fork_t *       fork_pool  = get_fork_pool( vote_stakes );
  fork_dlist_t * fork_dlist = get_fork_dlist( vote_stakes );

  index_ele_t *       index_pool      = get_index_pool( vote_stakes );
  index_map_t *       index_map       = get_index_map( vote_stakes );
  index_map_multi_t * index_map_multi = get_index_map_multi( vote_stakes );
  /* For every oustanding fork that is not the new candidate root,
     remove all stakes refcnts from the index.  If the index has no
     outstanding references, remove the index entry. */
  while( !fork_dlist_is_empty( fork_dlist, fork_pool ) ) {
    ushort fork_idx = (ushort)fork_dlist_idx_pop_head( fork_dlist, fork_pool );
    if( fork_idx==root_idx ) continue;

    stake_t *      stakes_pool = get_stakes_pool( vote_stakes, fork_idx );
    stakes_map_t * stakes_map  = get_stakes_map( vote_stakes, fork_idx );
    for( stakes_map_iter_t iter = stakes_map_iter_init( stakes_map, stakes_pool );
         !stakes_map_iter_done( iter, stakes_map, stakes_pool );
         iter = stakes_map_iter_next( iter, stakes_map, stakes_pool ) ) {
      stake_t *     stake = stakes_map_iter_ele( iter, stakes_map, stakes_pool );
      index_ele_t * ele   = index_pool_ele( index_pool, stake->idx );
      ele->refcnt--;

      if( FD_UNLIKELY( ele->refcnt==0U ) ) {
        FD_TEST( index_map_ele_remove( index_map, &ele->index_key, NULL, index_pool ) );
        FD_TEST( index_map_multi_ele_remove_fast( index_map_multi, ele, index_pool ) );
        index_pool_ele_release( index_pool, ele );
      }
    }
    fork_pool_idx_release( fork_pool, fork_idx );
  }
  /* TODO: There's probably a way to do a more efficient reset here. */
  stakes_map_reset( get_stakes_map( vote_stakes, root_idx ) );
  stakes_pool_reset( get_stakes_pool( vote_stakes, root_idx ) );

  fork_dlist_idx_push_head( fork_dlist, root_idx, fork_pool );
}

void
fd_vote_stakes_query_stake( fd_vote_stakes_t * vote_stakes,
                            ushort             fork_idx,
                            fd_pubkey_t *      pubkey,
                            ulong *            stake_t_1_out,
                            ulong *            stake_t_2_out ) {

  index_ele_t *       index_pool      = get_index_pool( vote_stakes );
  index_map_multi_t * index_map_multi = get_index_map_multi( vote_stakes );

  stake_t *      stakes_pool = get_stakes_pool( vote_stakes, fork_idx );
  stakes_map_t * stakes_map  = get_stakes_map( vote_stakes, fork_idx );

  /* The index may have multiple entries for the same pubkey, so every
     single matching index entry must be checked to see if the index
     exists in the given fork's stakes map.  If it does, return the
     t_2 stake value.*/
  uint ele_idx = (uint)index_map_multi_idx_query_const( index_map_multi, pubkey, UINT_MAX, index_pool );
  FD_TEST( ele_idx!=UINT_MAX );

  while( !stakes_map_ele_query( stakes_map, &ele_idx, NULL, stakes_pool ) ) {
    ele_idx = (uint)index_map_multi_idx_next_const( ele_idx, UINT_MAX, index_pool );
  }

  index_ele_t * index_ele = index_pool_ele( index_pool, ele_idx );
  *stake_t_1_out = index_ele->stake_t_1;
  *stake_t_2_out = index_ele->stake_t_2;
}

void
fd_vote_stakes_insert( fd_vote_stakes_t * vote_stakes,
                       ushort             fork_idx,
                       fd_pubkey_t *      pubkey,
                       ulong              stake_t_1,
                       ulong              stake_t_2 ) {
  index_ele_t *       index_pool      = get_index_pool( vote_stakes );
  index_map_t *       index_map       = get_index_map( vote_stakes );
  index_map_multi_t * index_map_multi = get_index_map_multi( vote_stakes );

  stake_t *      stakes_pool = get_stakes_pool( vote_stakes, fork_idx );
  stakes_map_t * stakes_map  = get_stakes_map( vote_stakes, fork_idx );

  index_key_t index_key = (index_key_t){ .pubkey = *pubkey, .stake_t_1 = stake_t_1 };
  index_ele_t * index_ele = index_map_ele_query( index_map, &index_key, NULL, index_pool );
  if( FD_LIKELY( index_ele ) ) {
    index_ele->refcnt++;
  } else {
    index_ele            = index_pool_ele_acquire( index_pool );
    index_ele->index_key = index_key;
    index_ele->refcnt    = 1;
    index_ele->stake_t_2 = stake_t_2;
    FD_TEST( index_map_ele_insert( index_map, index_ele, index_pool ) );
    FD_TEST( index_map_multi_ele_insert( index_map_multi, index_ele, index_pool ) );
  }

  stake_t * stake = stakes_pool_ele_acquire( stakes_pool );
  stake->idx = (uint)index_pool_idx( index_pool, index_ele );
  FD_TEST( stakes_map_ele_insert( stakes_map, stake, stakes_pool ) );
}

ushort
fd_vote_stakes_get_root_idx( fd_vote_stakes_t * vote_stakes ) {
  return vote_stakes->root_idx;
}
