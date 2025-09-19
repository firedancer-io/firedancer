#include "fd_eqvoc_index.h"
#include "../../flamenco/runtime/fd_runtime_const.h"

#define POOL_NAME fd_eqvoc_index_pool
#define POOL_T    fd_eqvoc_index_ele_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME          fd_eqvoc_index_map_eslot
#define MAP_ELE_T         fd_eqvoc_index_ele_t
#define MAP_KEY_T         fd_eslot_t
#define MAP_KEY           eslot
#define MAP_NEXT          next_
#define MAP_KEY_EQ(k0,k1) (k0->id==k1->id)
#define MAP_KEY_HASH(k,s) (k->id ^ s)
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME          fd_eqvoc_index_map_merkle_root
#define MAP_ELE_T         fd_eqvoc_index_ele_t
#define MAP_KEY_T         fd_hash_t
#define MAP_KEY           merkle_root
#define MAP_NEXT          next_mr_
#define MAP_KEY_EQ(k0,k1) (fd_hash_eq( k0,k1 ))
#define MAP_KEY_HASH(k,s) (fd_hash( s, k, sizeof(fd_hash_t) ))
#include "../../util/tmpl/fd_map_chain.c"


struct fd_eqvoc_index {
  ulong                              eslot_cnt;
  fd_eqvoc_index_map_eslot_t *       eslot_map;
  fd_eqvoc_index_map_merkle_root_t * merkle_root_map;
  fd_eqvoc_index_ele_t *             pool;
};
typedef struct fd_eqvoc_index fd_eqvoc_index_t;

ulong
fd_eqvoc_index_align( void ) {
  return 128UL;
}

ulong
fd_eqvoc_index_footprint( ulong eslot_cnt ) {
  ulong map_eslot_chain_cnt       = fd_eqvoc_index_map_eslot_chain_cnt_est( eslot_cnt );
  ulong map_merkle_root_chain_cnt = fd_eqvoc_index_map_merkle_root_chain_cnt_est( eslot_cnt );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  fd_eqvoc_index_align(),                 sizeof(fd_eqvoc_index_t) );
  l = FD_LAYOUT_APPEND( l,  fd_eqvoc_index_pool_align(),            fd_eqvoc_index_pool_footprint( eslot_cnt ) );
  l = FD_LAYOUT_APPEND( l,  fd_eqvoc_index_map_eslot_align(),       fd_eqvoc_index_map_eslot_footprint( map_eslot_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l,  fd_eqvoc_index_map_merkle_root_align(), fd_eqvoc_index_map_merkle_root_footprint( map_merkle_root_chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_eqvoc_index_align() );
}


fd_eqvoc_index_t *
fd_eqvoc_index_init( void * mem,
                     ulong  eslot_cnt,
                     ulong  seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_eqvoc_index_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong map_eslot_chain_cnt       = fd_eqvoc_index_map_eslot_chain_cnt_est( eslot_cnt );
  ulong map_merkle_root_chain_cnt = fd_eqvoc_index_map_merkle_root_chain_cnt_est( eslot_cnt );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_eqvoc_index_t *  index               = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_index_align(),                 sizeof(fd_eqvoc_index_t) );
  void *              pool_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_index_pool_align(),            fd_eqvoc_index_pool_footprint( eslot_cnt ) );
  void *              map_eslot_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_index_map_eslot_align(),       fd_eqvoc_index_map_eslot_footprint( map_eslot_chain_cnt ) );
  void *              map_merkle_root_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_index_map_merkle_root_align(), fd_eqvoc_index_map_merkle_root_footprint( map_merkle_root_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_eqvoc_index_align() )!=(ulong)mem+fd_eqvoc_index_footprint( eslot_cnt ) ) ) {
    FD_LOG_WARNING(( "fd_eqvoc_index_init: bad layout" ));
    return NULL;
  }

  index->pool = fd_eqvoc_index_pool_join( fd_eqvoc_index_pool_new( pool_mem, eslot_cnt ) );
  if( FD_UNLIKELY( !index->pool ) ) {
    FD_LOG_WARNING(( "fd_eqvoc_index_init: bad pool" ));
    return NULL;
  }

  index->eslot_map = fd_eqvoc_index_map_eslot_join( fd_eqvoc_index_map_eslot_new( map_eslot_mem, map_eslot_chain_cnt, seed ) );
  if( FD_UNLIKELY( !index->eslot_map ) ) {
    FD_LOG_WARNING(( "fd_eqvoc_index_init: bad eslot_map" ));
    return NULL;
  }

  index->merkle_root_map = fd_eqvoc_index_map_merkle_root_join( fd_eqvoc_index_map_merkle_root_new( map_merkle_root_mem, map_merkle_root_chain_cnt, seed ) );
  if( FD_UNLIKELY( !index->merkle_root_map ) ) {
    FD_LOG_WARNING(( "fd_eqvoc_index_init: bad merkle_root_map" ));
    return NULL;
  }

  index->eslot_cnt = eslot_cnt;

  return index;
}

fd_eqvoc_index_ele_t *
fd_eqvoc_index_insert_fec( fd_eqvoc_index_t *  index,
                           ulong             slot,
                           fd_hash_t const * merkle_root,
                           fd_hash_t const * chained_merkle_root,
                           ulong             fec_set_idx,
                           int *             is_equiv_out ) {

  fd_eqvoc_index_ele_t *             pool            = index->pool;
  fd_eqvoc_index_map_eslot_t *       eslot_map       = index->eslot_map;
  fd_eqvoc_index_map_merkle_root_t * merkle_root_map = index->merkle_root_map;

  fd_eqvoc_index_ele_t * chained_ele = fd_eqvoc_index_map_merkle_root_ele_query( merkle_root_map, chained_merkle_root, NULL, pool );
  if( FD_LIKELY( chained_ele ) ) {
    /* This means that the chained merkle root already has an entry in
       the map.  Now, we either have to continue chaining off of this
       entry, or create a new entry if the slot numbers are different.
    */

    if( FD_LIKELY( chained_ele->eslot.slot==slot ) ) {
      /* This means that the slot numbers are the same.  We need to
         continue chaining off of this entry. */
      if( FD_UNLIKELY( fec_set_idx<=chained_ele->highest_fec_idx_observed ) ) {
        FD_LOG_ERR(( "FEC chaining is corrupted (fec_set_idx: %lu, highest_fec_idx_observed: %lu)", fec_set_idx, chained_ele->highest_fec_idx_observed ));
      }
      /* Update the merkle root to the new one.  This requires removing
         the old entry from the merkle root map, updating the hash, and
         then re-inserting the entry into the new merkle root map. */
      fd_eqvoc_index_map_merkle_root_ele_remove( merkle_root_map, &chained_ele->merkle_root, NULL, pool );
      chained_ele->merkle_root              = *merkle_root;
      chained_ele->highest_fec_idx_observed = fec_set_idx;
      fd_eqvoc_index_map_merkle_root_ele_insert( merkle_root_map, chained_ele, pool );
      if( is_equiv_out ) *is_equiv_out = 0;
      return chained_ele;
    } else {
      /* Search for the first free prime count for this slot. */
      ulong prime = 0UL;
      for( prime=0UL; prime<FD_ESLOT_EQVOC_PER_SLOT_CNT_MAX; prime++ ) {
        fd_eslot_t new_eslot = fd_eslot( slot, prime );
        fd_eqvoc_index_ele_t * slot_ele = fd_eqvoc_index_map_eslot_ele_query( eslot_map, &new_eslot, NULL, pool );
        if( FD_LIKELY( !slot_ele ) ) {
          /* This means that the prime count is not in use.  We need to
             create a new entry. */
          break;
        }
      }

      if( FD_UNLIKELY( prime==FD_ESLOT_EQVOC_PER_SLOT_CNT_MAX ) ) {
        FD_LOG_ERR(( "Failed to find free prime count for slot: %lu", slot ));
      }

      if( is_equiv_out ) *is_equiv_out = prime!=0UL;

      /* We succesfully found a prime count for the slot.  We need to
         create a new entry. */
      fd_eqvoc_index_ele_t * new_ele = fd_eqvoc_index_pool_ele_acquire( pool );
      if( FD_UNLIKELY( !new_ele ) ) {
        FD_LOG_ERR(( "Failed to acquire eslot ele" ));
      }

      fd_eslot_t new_eslot = fd_eslot( slot, prime );
      new_ele->eslot                    = new_eslot;
      new_ele->parent_eslot             = chained_ele->eslot;
      new_ele->highest_fec_idx_observed = fec_set_idx;
      new_ele->merkle_root              = *merkle_root;
      new_ele->is_leader                = 0;

      fd_eqvoc_index_map_eslot_ele_insert( eslot_map, new_ele, pool );
      fd_eqvoc_index_map_merkle_root_ele_insert( merkle_root_map, new_ele, pool );

      return new_ele;
    }
  } else {
    /* This means that there is no direct link to the merkle root.  This
       can mean one of two things:
       1. There has been an equiovcation mid-block.  This is recoverable
          by creating a new entry for the given slot.
       2. There is some corruption with linking FEC sets.  This is
          unrecoverable and will crash the program.
       FIXME: This doesn't correctly link to the correct parent in the
       case where we have multiple parents.  This is blocked on reasm
       fecs containing the parent block id. */

    ulong prime;
    for( prime=0UL; prime<FD_ESLOT_EQVOC_PER_SLOT_CNT_MAX; prime++ ) {
      fd_eslot_t eslot = fd_eslot( slot, prime );
      fd_eqvoc_index_ele_t * slot_ele = fd_eqvoc_index_map_eslot_ele_query( eslot_map, &eslot, NULL, pool );
      if( !!slot_ele && fec_set_idx<=slot_ele->highest_fec_idx_observed ) {
        /* We have an equivocation at this slot + prime combination.
           Try the next prime. */
        continue;
      } else {
        break;
      }
    }

    if( FD_UNLIKELY( prime==FD_ESLOT_EQVOC_PER_SLOT_CNT_MAX ) ) {
      FD_LOG_ERR(( "Failed to find free prime count for slot: %lu", slot ));
    } else if( FD_UNLIKELY( prime==0UL ) ) {
      /* This should not be possible. */
      FD_LOG_ERR(( "FEC chaining is corrupted" ));
    }

    if( is_equiv_out ) *is_equiv_out = 1;

    fd_eqvoc_index_ele_t * new_ele = fd_eqvoc_index_pool_ele_acquire( pool );
    if( FD_UNLIKELY( !new_ele ) ) {
      FD_LOG_ERR(( "Failed to acquire eslot ele" ));
    }

    fd_eslot_t new_eslot = fd_eslot( slot, prime );
    new_ele->eslot                    = new_eslot;
    new_ele->highest_fec_idx_observed = fec_set_idx;
    new_ele->merkle_root              = *merkle_root;
    new_ele->is_leader                = 0;

    fd_eqvoc_index_map_eslot_ele_insert( eslot_map, new_ele, pool );
    fd_eqvoc_index_map_merkle_root_ele_insert( merkle_root_map, new_ele, pool );
    return new_ele;
  }
}

fd_eqvoc_index_ele_t *
fd_eqvoc_index_insert_leader( fd_eqvoc_index_t * index,
                              ulong              slot,
                              fd_eslot_t         parent_eslot ) {

  fd_eqvoc_index_ele_t *             pool        = index->pool;
  fd_eqvoc_index_map_eslot_t *       eslot_map       = index->eslot_map;
  fd_eqvoc_index_map_merkle_root_t * merkle_root_map = index->merkle_root_map;

  fd_eqvoc_index_ele_t * ele = fd_eqvoc_index_pool_ele_acquire( pool );
  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_ERR(( "Failed to acquire eslot ele" ));
  }

  fd_hash_t merkle_root = { .ul[0] = slot };

  /* Our leader blocks will never be equivocated. */
  ele->eslot        = fd_eslot( slot, 0UL );
  ele->parent_eslot = parent_eslot;
  ele->is_leader    = 1;
  ele->merkle_root  = merkle_root;

  fd_eqvoc_index_map_eslot_ele_insert( eslot_map, ele, pool );
  fd_eqvoc_index_map_merkle_root_ele_insert( merkle_root_map, ele, pool );
  return ele;
}

fd_eqvoc_index_ele_t *
fd_eqvoc_index_insert_initial( fd_eqvoc_index_t * index,
                               ulong            slot ) {
  fd_eqvoc_index_ele_t *             pool            = index->pool;
  fd_eqvoc_index_map_eslot_t *       eslot_map       = index->eslot_map;
  fd_eqvoc_index_map_merkle_root_t * merkle_root_map = index->merkle_root_map;

  fd_eqvoc_index_ele_t * ele = fd_eqvoc_index_pool_ele_acquire( pool );
  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_ERR(( "Failed to acquire eslot ele" ));
  }

  fd_hash_t merkle_root = { .ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };

  ele->parent_eslot.id = ULONG_MAX;
  ele->eslot        = fd_eslot( slot, 0UL );
  ele->is_leader    = 0;
  ele->merkle_root  = merkle_root;

  fd_eqvoc_index_map_eslot_ele_insert( eslot_map, ele, pool );
  fd_eqvoc_index_map_merkle_root_ele_insert( merkle_root_map, ele, pool );
  return ele;
}

int
fd_eqvoc_index_is_leader( fd_eqvoc_index_t * index,
                          ulong            slot ) {
  fd_eqvoc_index_map_eslot_t * eslot_map = index->eslot_map;
  fd_eqvoc_index_ele_t *       pool      = index->pool;
  fd_eslot_t                   eslot     = fd_eslot( slot, 0UL );
  fd_eqvoc_index_ele_t *       ele       = fd_eqvoc_index_map_eslot_ele_query( eslot_map, &eslot, NULL, pool );
  if( FD_LIKELY( ele ) ) {
    return ele->is_leader;
  }
  return 0;
}

fd_eqvoc_index_ele_t *
fd_eqvoc_index_query_eslot( fd_eqvoc_index_t * index,
                            fd_eslot_t         eslot ) {
  fd_eqvoc_index_map_eslot_t * eslot_map = index->eslot_map;
  fd_eqvoc_index_ele_t *       pool      = index->pool;
  return fd_eqvoc_index_map_eslot_ele_query( eslot_map, &eslot, NULL, pool );
}

fd_eqvoc_index_ele_t *
fd_eqvoc_index_query_merkle_root( fd_eqvoc_index_t * index,
                                  fd_hash_t const *  merkle_root ) {
  fd_eqvoc_index_map_merkle_root_t * merkle_root_map = index->merkle_root_map;
  fd_eqvoc_index_ele_t *             pool            = index->pool;
  return fd_eqvoc_index_map_merkle_root_ele_query( merkle_root_map, merkle_root, NULL, pool );
}

void
fd_eqvoc_index_set_leader_block_id( fd_eqvoc_index_t *     index,
                                    fd_eqvoc_index_ele_t * ele,
                                    fd_hash_t const *      merkle_root ) {
  fd_eqvoc_index_map_merkle_root_t * merkle_root_map = index->merkle_root_map;
  fd_eqvoc_index_ele_t *             pool            = index->pool;

  fd_eqvoc_index_map_merkle_root_ele_remove( merkle_root_map, &ele->merkle_root, NULL, pool );
  ele->merkle_root = *merkle_root;
  fd_eqvoc_index_map_merkle_root_ele_insert( merkle_root_map, ele, pool );
}

void
fd_eqvoc_index_publish( fd_eqvoc_index_t * index,
                        ulong            old_root_slot,
                        ulong            new_root_slot ) {
  fd_eqvoc_index_map_eslot_t *       eslot_map       = index->eslot_map;
  fd_eqvoc_index_map_merkle_root_t * merkle_root_map = index->merkle_root_map;
  fd_eqvoc_index_ele_t *             pool            = index->pool;

  for( ulong slot=old_root_slot; slot<new_root_slot; slot++ ) {
    for( ulong prime=0UL; prime<FD_ESLOT_EQVOC_PER_SLOT_CNT_MAX; prime++ ) {
      fd_eslot_t eslot = fd_eslot( slot, prime );
      fd_eqvoc_index_ele_t * ele = fd_eqvoc_index_map_eslot_ele_query( eslot_map, &eslot, NULL, pool );
      if( FD_LIKELY( !ele ) ) {
        break;
      } else {
        fd_eqvoc_index_map_merkle_root_ele_remove( merkle_root_map, &ele->merkle_root, NULL, pool );
        fd_eqvoc_index_map_eslot_ele_remove( eslot_map, &eslot, NULL, pool );
        fd_eqvoc_index_pool_ele_release( pool, ele );
      }
    }
  }
}
