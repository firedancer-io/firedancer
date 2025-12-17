#include "fd_ghost.h"
#include "fd_ghost_private.h"

#define LOGGING 0

ulong
fd_ghost_align( void ) {
  return alignof(fd_ghost_t);
}

ulong
fd_ghost_footprint( ulong blk_max,
                    ulong vtr_max ) {
  int lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( vtr_max ) ) + 1;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_ghost_t), sizeof(fd_ghost_t)              ),
      pool_align(),        pool_footprint( blk_max )       ),
      blk_map_align(),     blk_map_footprint( blk_max )    ),
      vtr_map_align(),     vtr_map_footprint( lg_vtr_max ) ),
    fd_ghost_align() );
}

void *
fd_ghost_new( void * shmem,
              ulong  blk_max,
              ulong  vtr_max,
              ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( blk_max, vtr_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad blk_max (%lu)", blk_max ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  int lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( FD_VOTER_MAX ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ghost_t * ghost = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ghost_t), sizeof(fd_ghost_t)              );
  void *       pool  = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),        pool_footprint( blk_max )       );
  void *       map   = FD_SCRATCH_ALLOC_APPEND( l, blk_map_align(),     blk_map_footprint( blk_max )    );
  void *       vtr   = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),     vtr_map_footprint( lg_vtr_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_ghost_align() ) == (ulong)shmem + footprint );

  ghost->pool    = pool_new( pool, blk_max );
  ghost->blk_map = blk_map_new( map, blk_max, seed );
  ghost->vtr_map = vtr_map_new( vtr, lg_vtr_max, seed+1UL );
  ghost->root    = pool_idx_null( ghost->pool );

  return shmem;
}

fd_ghost_t *
fd_ghost_join( void * shghost ) {
  fd_ghost_t * ghost = (fd_ghost_t *)shghost;

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)ghost, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ghost" ));
    return NULL;
  }

  ghost->pool     = pool_join( ghost->pool );
  ghost->blk_map  = blk_map_join( ghost->blk_map );
  ghost->vtr_map  = vtr_map_join( ghost->vtr_map );

  return ghost;
}

void *
fd_ghost_leave( fd_ghost_t const * ghost ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return NULL;
  }

  return (void *)ghost;
}

void *
fd_ghost_delete( void * ghost ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)ghost, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ghost" ));
    return NULL;
  }

  return ghost;
}

fd_ghost_blk_t *
fd_ghost_root( fd_ghost_t * ghost ) {
  return pool_ele( ghost->pool, ghost->root );
}

fd_ghost_blk_t *
fd_ghost_query( fd_ghost_t       * ghost,
                fd_hash_t  const * block_id ) {
  return blk_map_ele_query( ghost->blk_map, block_id, NULL, ghost->pool );
}

fd_ghost_blk_t *
fd_ghost_best( fd_ghost_t     * ghost,
               fd_ghost_blk_t * root ) {
  fd_ghost_blk_t * pool = ghost->pool;
  ulong            null = pool_idx_null( pool );
  fd_ghost_blk_t * best = root;
  while( FD_LIKELY( best->child != null ) ) {
    int              valid = 0; /* at least one child is valid */
    fd_ghost_blk_t * child = pool_ele( ghost->pool, best->child );
    while( FD_LIKELY( child ) ) { /* greedily pick the heaviest valid child */
      if( FD_LIKELY( child->valid ) ) {
        if( FD_LIKELY( !valid ) ) { /* this is the first valid child, so progress the head */
          best        = child;
          valid = 1;
        }
        best = fd_ptr_if(
          fd_int_if(
            child->stake == best->stake,   /* if the weights are equal */
            child->slot  <  best->slot,    /* then tie-break by lower slot number */
            child->stake >  best->stake ), /* else return heavier */
          child, best );
      }
      child = pool_ele( ghost->pool, child->sibling );
    }
    if( FD_UNLIKELY( !valid ) ) break; /* no children are valid, so short-circuit traversal */
  }
  return best;
}

fd_ghost_blk_t *
fd_ghost_deepest( fd_ghost_t     * ghost,
                  fd_ghost_blk_t * root ) {
  fd_ghost_blk_t * pool = ghost->pool;
  ulong            null = pool_idx_null( pool );
  fd_ghost_blk_t * head = blk_map_ele_remove( ghost->blk_map, &root->id, NULL, pool ); /* remove ele from map to reuse `.next` */
  fd_ghost_blk_t * tail = head;

  /* Below is a level-order traversal (BFS), returning the last leaf
     which is guaranteed to return an element of the max depth.

     It temporarily removes elements of the map when pushing onto the
     BFS queue to reuse the .next pointer and then inserts back into
     the map on queue pop. */

  head->next = null;
  while( FD_LIKELY( head ) ) {
    fd_ghost_blk_t const * child = pool_ele( ghost->pool, head->child );
    while( FD_LIKELY( child ) ) {
      tail->next = pool_idx( pool, blk_map_ele_remove( ghost->blk_map, &child->id, NULL, pool ) );
      tail       = pool_ele( pool, tail->next );
      tail->next = pool_idx_null( pool );
      child      = pool_ele( pool, child->sibling ); /* next sibling */
    }
    fd_ghost_blk_t * next = pool_ele( pool, head->next ); /* pop prune queue head */
    blk_map_ele_insert( ghost->blk_map, head, pool );     /* re-insert head into map */
    head = next;
  }
  return head;
}

#define PREDICATE_ANCESTOR( predicate ) do {                \
    fd_ghost_blk_t * ancestor = descendant;                 \
    while( FD_LIKELY( ancestor ) ) {                        \
      if( FD_LIKELY( predicate ) ) return ancestor;         \
      ancestor = pool_ele( ghost->pool, ancestor->parent ); \
    }                                                       \
    return NULL;                                            \
  } while(0)

fd_ghost_blk_t *
fd_ghost_ancestor( fd_ghost_t      * ghost,
                   fd_ghost_blk_t  * descendant,
                   fd_hash_t const * ancestor_id ) {
  PREDICATE_ANCESTOR( 0==memcmp( &ancestor->id, ancestor_id, sizeof(fd_hash_t) ) );
}

fd_ghost_blk_t *
fd_ghost_slot_ancestor( fd_ghost_t     * ghost,
                        fd_ghost_blk_t * descendant,
                        ulong            slot ) {
  PREDICATE_ANCESTOR( ancestor->slot == slot );
}

fd_ghost_blk_t *
fd_ghost_invalid_ancestor( fd_ghost_t     * ghost,
                           fd_ghost_blk_t * descendant ) {
  PREDICATE_ANCESTOR( !ancestor->valid );
}

fd_ghost_blk_t *
fd_ghost_insert( fd_ghost_t      * ghost,
                 fd_hash_t const * block_id,
                 fd_hash_t const * parent_block_id,
                 ulong             slot ) {

  fd_ghost_blk_t * pool = ghost->pool;
  ulong            null = pool_idx_null( pool );
  fd_ghost_blk_t * blk  = blk_map_ele_query( ghost->blk_map, block_id, NULL, pool );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( blk                ) ) {
    FD_BASE58_ENCODE_32_BYTES( block_id->key, block_id_b58 );
    FD_LOG_WARNING(( "[%s] hash %s already in ghost", __func__, block_id_b58 ));
    return NULL;
  }
  if( FD_UNLIKELY( !pool_free( pool ) ) ) { FD_LOG_WARNING(( "[%s] ghost full",               __func__                                      )); return NULL; }
# endif

  blk              = pool_ele_acquire( pool );
  blk->id          = *block_id;
  blk->slot        = slot;
  blk->next        = null;
  blk->parent      = null;
  blk->child       = null;
  blk->sibling     = null;
  blk->stake       = 0;
  blk->total_stake = 0;
  blk->eqvoc       = 0;
  blk->conf        = 0;
  blk->valid       = 1;
  blk_map_ele_insert( ghost->blk_map, blk, pool );

  if( FD_UNLIKELY( !parent_block_id ) ) {
    ghost->root = pool_idx( pool, blk );
    return blk;
  }

  fd_ghost_blk_t * parent = blk_map_ele_query( ghost->blk_map, parent_block_id, NULL, pool );
  FD_TEST( parent ); /* parent must exist if this is not the first insertion */
  blk->parent  = pool_idx( pool, parent );
  if( FD_LIKELY( parent->child == null ) ) {
    parent->child = pool_idx( pool, blk );    /* left-child */
  } else {
    fd_ghost_blk_t * sibling = pool_ele( pool, parent->child );
    while( sibling->sibling != null ) sibling = pool_ele( pool, sibling->sibling );
    sibling->sibling = pool_idx( pool, blk ); /* right-sibling */
  }

  return blk;
}

void
fd_ghost_count_vote( fd_ghost_t *        ghost,
                     fd_ghost_blk_t *    blk,
                     fd_pubkey_t const * vote_acc,
                     ulong               stake,
                     ulong               slot ) {

  fd_ghost_blk_t const * root = fd_ghost_root( ghost );
  fd_ghost_blk_t *       pool = ghost->pool;
  fd_ghost_vtr_t *       vtr  = vtr_map_query( ghost->vtr_map, *vote_acc, NULL );

  if( FD_UNLIKELY( slot == ULONG_MAX  ) ) return; /* hasn't voted */
  if( FD_UNLIKELY( slot <  root->slot ) ) return; /* vote older than root */

  if( FD_UNLIKELY( !vtr ) ) vtr = vtr_map_insert( ghost->vtr_map, *vote_acc );
  else {

    /* Only process the vote if it is not the same as the previous vote
       and also that the vote slot is most recent.  It's possible for
       ghost to process votes out of order because votes happen in
       replay order which is concurrent across different forks.

       For example, if a voter votes for 3 then switches to 5, we might
       observe the vote for 5 before the vote for 3. */

    if( FD_UNLIKELY( !( slot > vtr->prev_slot ) ) ) return;

    /* LMD-rule: subtract the voter's stake from the entire fork they
      previously voted for. */

    /* TODO can optimize this if they're voting for the same fork */

    fd_ghost_blk_t * ancestor = blk_map_ele_query( ghost->blk_map, &vtr->prev_block_id, NULL, pool );
    while( FD_LIKELY( ancestor ) ) {
      int cf = __builtin_usubl_overflow( ancestor->stake, vtr->prev_stake, &ancestor->stake );
      if( FD_UNLIKELY( cf ) ) {
        FD_BASE58_ENCODE_32_BYTES( ancestor->id.key, ancestor_id_b58 );
        FD_LOG_CRIT(( "[%s] overflow: %lu - %lu. (slot %lu, block_id: %s)", __func__, ancestor->stake, vtr->prev_stake, ancestor->slot, ancestor_id_b58 ));
      }
      ancestor = pool_ele( pool, ancestor->parent );
    }
  }

  /* Add voter's stake to the entire fork they are voting for. Propagate
     the vote stake up the ancestry. We do this for all cases we exited
     above: this vote is the first vote we've seen from a pubkey, this
     vote is switched from a previous vote that was on a missing ele
     (pruned), or the regular case. */

  fd_ghost_blk_t * ancestor = blk;
  while( FD_LIKELY( ancestor ) ) {
    int cf = __builtin_uaddl_overflow( ancestor->stake, stake, &ancestor->stake );
    if( FD_UNLIKELY( cf ) ) {
      FD_BASE58_ENCODE_32_BYTES( ancestor->id.key, ancestor_id_b58 );
      FD_LOG_CRIT(( "[%s] overflow: %lu + %lu. (slot %lu, block_id: %s)", __func__, ancestor->stake, stake, ancestor->slot, ancestor_id_b58 ));
    }
    ancestor = pool_ele( ghost->pool, ancestor->parent );
  }
  vtr->prev_block_id = blk->id;
  vtr->prev_stake    = stake;
}

void
fd_ghost_publish( fd_ghost_t     * ghost,
                  fd_ghost_blk_t * newr ) {

  fd_ghost_blk_t * pool = ghost->pool;
  ulong            null = pool_idx_null( pool );
  fd_ghost_blk_t * oldr = fd_ghost_root( ghost );

  if( FD_UNLIKELY( oldr==newr ) ) return;

  /* First, remove the previous root, and add it to the prune list. In
     this context, head is the list head (not to be confused with the
     ghost head.) */

  fd_ghost_blk_t * head = blk_map_ele_remove( ghost->blk_map, &oldr->id, NULL, pool ); /* remove ele from map to reuse `.next` */
  fd_ghost_blk_t * tail = head;

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  head->next = null;
  while( FD_LIKELY( head ) ) {
    fd_ghost_blk_t * child = pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {                                                  /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                           /* stop at new root */
        tail->next = blk_map_idx_remove( ghost->blk_map, &child->id, null, pool ); /* remove ele from map to reuse `.next` */
        tail       = pool_ele( pool, tail->next );                                 /* push onto prune queue (so descendants can be pruned) */
        tail->next = pool_idx_null( pool );
      }
      child = pool_ele( pool, child->sibling ); /* next sibling */
    }
    fd_ghost_blk_t * next = pool_ele( pool, head->next ); /* pop prune queue head */
    pool_ele_release( pool, head );                       /* free prune queue head */
    head = next;                                          /* move prune queue head forward */
  }
  newr->parent = null;                   /* unlink old root */
  ghost->root  = pool_idx( pool, newr ); /* replace with new root */
}

int
fd_ghost_verify( fd_ghost_t * ghost ) {
  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ghost, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ghost" ));
    return -1;
  }

  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "ghost must be part of a workspace" ));
    return -1;
  }

  fd_ghost_blk_t const      * pool = ghost->pool;
  ulong                       null = pool_idx_null( pool );

  /* Check every ele that exists in pool exists in map. */

  if( blk_map_verify( ghost->blk_map, pool_max( pool ), pool ) ) return -1;

  /* Check every ele's stake is >= sum of children's stakes. */

  fd_ghost_blk_t const * parent = fd_ghost_root( ghost );
  while( FD_LIKELY( parent ) ) {
    ulong                  weight = 0;
    fd_ghost_blk_t const * child  = pool_ele( ghost->pool, parent->child );
    while( FD_LIKELY( child && child->sibling != null ) ) {
      weight += child->stake;
      child = pool_ele( ghost->pool, child->sibling );
    }
  # if FD_GHOST_USE_HANDHOLDING
    FD_TEST( parent->stake >= weight );
  # endif
    parent = pool_ele_const( pool, parent->next );
  }

  return 0;
}

#include <stdio.h>

static void
print( fd_ghost_t const * ghost, fd_ghost_blk_t const * ele, ulong total_stake, int space, const char * prefix ) {
  fd_ghost_blk_t const * pool = ghost->pool;

  if( FD_UNLIKELY( ele == NULL ) ) return;

  if( FD_LIKELY( space > 0 ) ) printf( "\n" );
  for( int i = 0; i < space; i++ )
    printf( " " );
  if( FD_UNLIKELY( ele->stake > 100 ) ) {
  }
  if( FD_UNLIKELY( total_stake == 0 ) ) {
    printf( "%s%lu (%lu)", prefix, ele->slot, ele->stake );
  } else {
    double pct = ( (double)ele->stake / (double)total_stake ) * 100;
    if( FD_UNLIKELY( pct < 0.99 )) {
      printf( "%s%lu (%.0lf%%, %lu)", prefix, ele->slot, pct, ele->stake );
    } else {
      printf( "%s%lu (%.0lf%%)", prefix, ele->slot, pct );
    }
  }

  fd_ghost_blk_t const * curr = pool_ele_const( pool, ele->child );
  char new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( FD_UNLIKELY( pool_ele_const( pool, curr->sibling ) ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( ghost, curr, total_stake, space + 4, new_prefix );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( ghost, curr, total_stake, space + 4, new_prefix );
    }
    curr = pool_ele_const( pool, curr->sibling );
  }
}

void
fd_ghost_print( fd_ghost_t const *     ghost,
                fd_ghost_blk_t const * root ) {
  FD_LOG_NOTICE( ( "\n\n[Ghost]" ) );
  print( ghost, root, root->total_stake, 0, "" );
  printf( "\n\n" );
}
