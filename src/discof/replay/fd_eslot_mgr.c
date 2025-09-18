#include "fd_eslot_mgr.h"
#include "../../flamenco/runtime/fd_runtime_const.h"

#define POOL_NAME fd_eslot_mgr_pool
#define POOL_T    fd_eslot_ele_t
#define POOL_NEXT next_
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME          fd_eslot_mgr_map_eslot
#define MAP_ELE_T         fd_eslot_ele_t
#define MAP_KEY_T         fd_eslot_t
#define MAP_KEY           eslot
#define MAP_NEXT          next_
#define MAP_KEY_EQ(k0,k1) (k0->id==k1->id)
#define MAP_KEY_HASH(k,s) (k->id ^ s)
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME          fd_eslot_mgr_map_merkle_root
#define MAP_ELE_T         fd_eslot_ele_t
#define MAP_KEY_T         fd_hash_t
#define MAP_KEY           merkle_root
#define MAP_NEXT          next_mr_
#define MAP_KEY_EQ(k0,k1) (fd_hash_eq( k0,k1 ))
#define MAP_KEY_HASH(k,s) (fd_hash( s, k, sizeof(fd_hash_t) ))
#include "../../util/tmpl/fd_map_chain.c"


struct fd_eslot_mgr {
  ulong magic;
  ulong eslot_cnt;
  ulong pool_offset;
  ulong map_eslot_offset;
  ulong map_merkle_root_offset;
};
typedef struct fd_eslot_mgr fd_eslot_mgr_t;

static inline fd_eslot_mgr_map_eslot_t *
fd_eslot_mgr_eslot_map_get( fd_eslot_mgr_t const * eslot_mgr ) {
  return fd_eslot_mgr_map_eslot_join( (uchar *)eslot_mgr + eslot_mgr->map_eslot_offset );
}

static inline fd_eslot_mgr_map_merkle_root_t *
fd_eslot_mgr_merkle_root_map_get( fd_eslot_mgr_t const * eslot_mgr ) {
  return fd_eslot_mgr_map_merkle_root_join( (uchar *)eslot_mgr + eslot_mgr->map_merkle_root_offset );
}

static inline fd_eslot_ele_t *
fd_eslot_mgr_pool_get( fd_eslot_mgr_t const * eslot_mgr ) {
  return fd_eslot_mgr_pool_join( (uchar *)eslot_mgr + eslot_mgr->pool_offset );
}

ulong
fd_eslot_mgr_align( void ) {
  return 128UL;
}

ulong
fd_eslot_mgr_footprint( ulong eslot_cnt ) {
  ulong map_eslot_chain_cnt       = fd_eslot_mgr_map_eslot_chain_cnt_est( eslot_cnt );
  ulong map_merkle_root_chain_cnt = fd_eslot_mgr_map_merkle_root_chain_cnt_est( eslot_cnt );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  fd_eslot_mgr_align(),                 sizeof(fd_eslot_mgr_t) );
  l = FD_LAYOUT_APPEND( l,  fd_eslot_mgr_pool_align(),            fd_eslot_mgr_pool_footprint( eslot_cnt ) );
  l = FD_LAYOUT_APPEND( l,  fd_eslot_mgr_map_eslot_align(),       fd_eslot_mgr_map_eslot_footprint( map_eslot_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l,  fd_eslot_mgr_map_merkle_root_align(), fd_eslot_mgr_map_merkle_root_footprint( map_merkle_root_chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_eslot_mgr_align() );
}

uchar *
fd_eslot_mgr_new( void * shmem,
                  ulong  eslot_cnt,
                  ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_eslot_mgr_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong map_eslot_chain_cnt       = fd_eslot_mgr_map_eslot_chain_cnt_est( eslot_cnt );
  ulong map_merkle_root_chain_cnt = fd_eslot_mgr_map_merkle_root_chain_cnt_est( eslot_cnt );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_eslot_mgr_t * eslot_mgr           = FD_SCRATCH_ALLOC_APPEND( l, fd_eslot_mgr_align(),                 sizeof(fd_eslot_mgr_t) );
  void *           pool_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_eslot_mgr_pool_align(),            fd_eslot_mgr_pool_footprint( eslot_cnt ) );
  void *           map_eslot_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_eslot_mgr_map_eslot_align(),       fd_eslot_mgr_map_eslot_footprint( map_eslot_chain_cnt ) );
  void *           map_merkle_root_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_eslot_mgr_map_merkle_root_align(), fd_eslot_mgr_map_merkle_root_footprint( map_merkle_root_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_eslot_mgr_align() )!=(ulong)shmem+fd_eslot_mgr_footprint( eslot_cnt ) ) ) {
    FD_LOG_WARNING(( "fd_eslot_mgr_new: bad layout" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_eslot_mgr_pool_new( pool_mem, eslot_cnt ) ) ) {
    FD_LOG_WARNING(( "fd_eslot_mgr_new: bad pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_eslot_mgr_map_eslot_new( map_eslot_mem, map_eslot_chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "fd_eslot_mgr_new: bad map_eslot" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_eslot_mgr_map_merkle_root_new( map_merkle_root_mem, map_merkle_root_chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "fd_eslot_mgr_new: bad map_merkle_root" ));
    return NULL;
  }

  eslot_mgr->eslot_cnt              = eslot_cnt;
  eslot_mgr->pool_offset            = (ulong)pool_mem - (ulong)shmem;
  eslot_mgr->map_eslot_offset       = (ulong)map_eslot_mem - (ulong)shmem;
  eslot_mgr->map_merkle_root_offset = (ulong)map_merkle_root_mem - (ulong)shmem;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( eslot_mgr->magic ) = FD_ESLOT_MGR_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_eslot_mgr_t *
fd_eslot_mgr_join( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_eslot_mgr_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_eslot_mgr_t * eslot_mgr = (fd_eslot_mgr_t *)shmem;

  if( FD_UNLIKELY( eslot_mgr->magic!=FD_ESLOT_MGR_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid eslot mgr magic: %lx", eslot_mgr->magic ));
    return NULL;
  }

  ulong map_eslot_chain_cnt       = fd_eslot_mgr_map_eslot_chain_cnt_est( eslot_mgr->eslot_cnt );
  ulong map_merkle_root_chain_cnt = fd_eslot_mgr_map_merkle_root_chain_cnt_est( eslot_mgr->eslot_cnt );
  FD_SCRATCH_ALLOC_INIT( l, eslot_mgr );
  eslot_mgr                  = FD_SCRATCH_ALLOC_APPEND( l, fd_eslot_mgr_align(),                 sizeof(fd_eslot_mgr_t) );
  void * pool_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_eslot_mgr_pool_align(),            fd_eslot_mgr_pool_footprint( eslot_mgr->eslot_cnt ) );
  void * map_eslot_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_eslot_mgr_map_eslot_align(),       fd_eslot_mgr_map_eslot_footprint( map_eslot_chain_cnt ) );
  void * map_merkle_root_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_eslot_mgr_map_merkle_root_align(), fd_eslot_mgr_map_merkle_root_footprint( map_merkle_root_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_eslot_mgr_align() )!=(ulong)shmem+fd_eslot_mgr_footprint( eslot_mgr->eslot_cnt ) ) ) {
    FD_LOG_WARNING(( "fd_eslot_mgr_join: bad layout" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_eslot_mgr_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join eslot mgr pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_eslot_mgr_map_eslot_join( map_eslot_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join eslot mgr map_eslot" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_eslot_mgr_map_merkle_root_join( map_merkle_root_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join eslot mgr map_merkle_root" ));
    return NULL;
  }

  return eslot_mgr;
}

fd_eslot_ele_t *
fd_eslot_mgr_ele_insert_fec( fd_eslot_mgr_t *  mgr,
                             ulong             slot,
                             fd_hash_t const * merkle_root,
                             fd_hash_t const * chained_merkle_root,
                             ulong             fec_set_idx,
                             int *             is_equiv_out ) {

  fd_eslot_ele_t *                 pool            = fd_eslot_mgr_pool_get( mgr );
  fd_eslot_mgr_map_eslot_t *       eslot_map       = fd_eslot_mgr_eslot_map_get( mgr );
  fd_eslot_mgr_map_merkle_root_t * merkle_root_map = fd_eslot_mgr_merkle_root_map_get( mgr );

  fd_eslot_ele_t * chained_ele = fd_eslot_mgr_map_merkle_root_ele_query( merkle_root_map, chained_merkle_root, NULL, pool );
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
      fd_eslot_mgr_map_merkle_root_ele_remove( merkle_root_map, &chained_ele->merkle_root, NULL, pool );
      chained_ele->merkle_root              = *merkle_root;
      chained_ele->highest_fec_idx_observed = fec_set_idx;
      fd_eslot_mgr_map_merkle_root_ele_insert( merkle_root_map, chained_ele, pool );
      if( is_equiv_out ) *is_equiv_out = 0;
      return chained_ele;
    } else {
      /* Search for the first free prime count for this slot. */
      ulong prime = 0UL;
      for( prime=0UL; prime<FD_ESLOT_EQVOC_PER_SLOT_CNT_MAX; prime++ ) {
        fd_eslot_t new_eslot = fd_eslot( slot, prime );
        fd_eslot_ele_t * slot_ele = fd_eslot_mgr_map_eslot_ele_query( eslot_map, &new_eslot, NULL, pool );
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
      fd_eslot_ele_t * new_ele = fd_eslot_mgr_pool_ele_acquire( pool );
      if( FD_UNLIKELY( !new_ele ) ) {
        FD_LOG_ERR(( "Failed to acquire eslot ele" ));
      }

      fd_eslot_t new_eslot = fd_eslot( slot, prime );
      new_ele->eslot                    = new_eslot;
      new_ele->parent_eslot             = chained_ele->eslot;
      new_ele->highest_fec_idx_observed = fec_set_idx;
      new_ele->merkle_root              = *merkle_root;
      new_ele->is_leader                = 0;

      fd_eslot_mgr_map_eslot_ele_insert( eslot_map, new_ele, pool );
      fd_eslot_mgr_map_merkle_root_ele_insert( merkle_root_map, new_ele, pool );

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
      fd_eslot_ele_t * slot_ele = fd_eslot_mgr_map_eslot_ele_query( eslot_map, &eslot, NULL, pool );
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

    fd_eslot_ele_t * new_ele = fd_eslot_mgr_pool_ele_acquire( pool );
    if( FD_UNLIKELY( !new_ele ) ) {
      FD_LOG_ERR(( "Failed to acquire eslot ele" ));
    }

    fd_eslot_t new_eslot = fd_eslot( slot, prime );
    new_ele->eslot                    = new_eslot;
    new_ele->highest_fec_idx_observed = fec_set_idx;
    new_ele->merkle_root              = *merkle_root;
    new_ele->is_leader                = 0;

    fd_eslot_mgr_map_eslot_ele_insert( eslot_map, new_ele, pool );
    fd_eslot_mgr_map_merkle_root_ele_insert( merkle_root_map, new_ele, pool );
    return new_ele;
  }
}

fd_eslot_ele_t *
fd_eslot_mgr_ele_insert_leader( fd_eslot_mgr_t * mgr,
                                ulong            slot,
                                fd_eslot_t       parent_eslot ) {

  fd_eslot_ele_t *                 pool            = fd_eslot_mgr_pool_get( mgr );
  fd_eslot_mgr_map_eslot_t *       eslot_map       = fd_eslot_mgr_eslot_map_get( mgr );
  fd_eslot_mgr_map_merkle_root_t * merkle_root_map = fd_eslot_mgr_merkle_root_map_get( mgr );

  fd_eslot_ele_t * ele = fd_eslot_mgr_pool_ele_acquire( pool );
  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_ERR(( "Failed to acquire eslot ele" ));
  }

  fd_hash_t merkle_root = { .ul[0] = slot };

  /* Our leader blocks will never be equivocated. */
  ele->eslot        = fd_eslot( slot, 0UL );
  ele->parent_eslot = parent_eslot;
  ele->is_leader    = 1;
  ele->merkle_root  = merkle_root;

  fd_eslot_mgr_map_eslot_ele_insert( eslot_map, ele, pool );
  fd_eslot_mgr_map_merkle_root_ele_insert( merkle_root_map, ele, pool );
  return ele;
}

fd_eslot_ele_t *
fd_eslot_mgr_ele_insert_initial( fd_eslot_mgr_t * mgr,
                                 ulong            slot ) {
  fd_eslot_ele_t *                 pool            = fd_eslot_mgr_pool_get( mgr );
  fd_eslot_mgr_map_eslot_t *       eslot_map       = fd_eslot_mgr_eslot_map_get( mgr );
  fd_eslot_mgr_map_merkle_root_t * merkle_root_map = fd_eslot_mgr_merkle_root_map_get( mgr );

  fd_eslot_ele_t * ele = fd_eslot_mgr_pool_ele_acquire( pool );
  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_ERR(( "Failed to acquire eslot ele" ));
  }

  fd_hash_t merkle_root = { .ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };

  ele->parent_eslot.id = ULONG_MAX;
  ele->eslot        = fd_eslot( slot, 0UL );
  ele->is_leader    = 0;
  ele->merkle_root  = merkle_root;

  fd_eslot_mgr_map_eslot_ele_insert( eslot_map, ele, pool );
  fd_eslot_mgr_map_merkle_root_ele_insert( merkle_root_map, ele, pool );
  return ele;
}

int
fd_eslot_mgr_is_leader( fd_eslot_mgr_t * mgr,
                        ulong            slot ) {
  fd_eslot_mgr_map_eslot_t * eslot_map = fd_eslot_mgr_eslot_map_get( mgr );
  fd_eslot_ele_t *           pool      = fd_eslot_mgr_pool_get( mgr );
  fd_eslot_t                 eslot     = fd_eslot( slot, 0UL );
  fd_eslot_ele_t *           ele       = fd_eslot_mgr_map_eslot_ele_query( eslot_map, &eslot, NULL, pool );
  if( FD_LIKELY( ele ) ) {
    return ele->is_leader;
  }
  return 0;
}

fd_eslot_ele_t *
fd_eslot_mgr_ele_query_eslot( fd_eslot_mgr_t * mgr,
                              fd_eslot_t       eslot ) {
  fd_eslot_mgr_map_eslot_t * eslot_map = fd_eslot_mgr_eslot_map_get( mgr );
  fd_eslot_ele_t *           pool      = fd_eslot_mgr_pool_get( mgr );
  return fd_eslot_mgr_map_eslot_ele_query( eslot_map, &eslot, NULL, pool );
}

fd_eslot_ele_t *
fd_eslot_mgr_ele_query_merkle_root( fd_eslot_mgr_t *  mgr,
                                    fd_hash_t const * merkle_root ) {
  fd_eslot_mgr_map_merkle_root_t * merkle_root_map = fd_eslot_mgr_merkle_root_map_get( mgr );
  fd_eslot_ele_t *                 pool            = fd_eslot_mgr_pool_get( mgr );
  return fd_eslot_mgr_map_merkle_root_ele_query( merkle_root_map, merkle_root, NULL, pool );
}

void
fd_eslot_mgr_rekey_merkle_root( fd_eslot_mgr_t *  mgr,
                                fd_eslot_ele_t *  ele,
                                fd_hash_t const * merkle_root ) {
  fd_eslot_mgr_map_merkle_root_t * merkle_root_map = fd_eslot_mgr_merkle_root_map_get( mgr );
  fd_eslot_ele_t *                 pool            = fd_eslot_mgr_pool_get( mgr );

  fd_eslot_mgr_map_merkle_root_ele_remove( merkle_root_map, &ele->merkle_root, NULL, pool );
  ele->merkle_root = *merkle_root;
  fd_eslot_mgr_map_merkle_root_ele_insert( merkle_root_map, ele, pool );
}

void
fd_eslot_mgr_publish( fd_eslot_mgr_t * mgr,
                      ulong            old_root_slot,
                      ulong            new_root_slot ) {
  fd_eslot_mgr_map_eslot_t *       eslot_map       = fd_eslot_mgr_eslot_map_get( mgr );
  fd_eslot_mgr_map_merkle_root_t * merkle_root_map = fd_eslot_mgr_merkle_root_map_get( mgr );
  fd_eslot_ele_t *                 pool            = fd_eslot_mgr_pool_get( mgr );

  for( ulong slot=old_root_slot; slot<new_root_slot; slot++ ) {
    for( ulong prime=0UL; prime<FD_ESLOT_EQVOC_PER_SLOT_CNT_MAX; prime++ ) {
      fd_eslot_t eslot = fd_eslot( slot, prime );
      fd_eslot_ele_t * ele = fd_eslot_mgr_map_eslot_ele_query( eslot_map, &eslot, NULL, pool );
      if( FD_LIKELY( !ele ) ) {
        break;
      } else {
        fd_eslot_mgr_map_merkle_root_ele_remove( merkle_root_map, &ele->merkle_root, NULL, pool );
        fd_eslot_mgr_map_eslot_ele_remove( eslot_map, &eslot, NULL, pool );
        fd_eslot_mgr_pool_ele_release( pool, ele );
      }
    }
  }
}
