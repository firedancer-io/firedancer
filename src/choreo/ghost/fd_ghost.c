#include "fd_ghost.h"

static void ver_inc( ulong ** ver ) {
  fd_fseq_update( *ver, fd_fseq_query( *ver ) + 1 );
}

#define VER_INC ulong * ver __attribute__((cleanup(ver_inc))) = fd_ghost_ver( ghost ); ver_inc( &ver )

void *
fd_ghost_new( void * shmem, ulong ele_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( ele_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ele_max (%lu)", ele_max ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ghost_t * ghost = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),      sizeof( fd_ghost_t )               );
  void *       pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_pool_align(), fd_ghost_pool_footprint( ele_max ) );
  void *       map   = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_map_align(),  fd_ghost_map_footprint( ele_max )  );
  void *       ver   = FD_SCRATCH_ALLOC_APPEND( l, fd_fseq_align(),       fd_fseq_footprint()                );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_ghost_align() ) == (ulong)shmem + footprint );

  ghost->pool_gaddr  = fd_wksp_gaddr_fast( wksp, fd_ghost_pool_join( fd_ghost_pool_new( pool, ele_max       ) ) );
  ghost->map_gaddr   = fd_wksp_gaddr_fast( wksp, fd_ghost_map_join ( fd_ghost_map_new ( map,  ele_max, seed ) ) );
  ghost->ver_gaddr   = fd_wksp_gaddr_fast( wksp, fd_fseq_join      ( fd_fseq_new      ( ver,  ULONG_MAX     ) ) );

  ghost->ghost_gaddr = fd_wksp_gaddr_fast( wksp, ghost );
  ghost->seed        = seed;
  ghost->root        = fd_ghost_pool_idx_null( fd_ghost_pool( ghost ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ghost->magic ) = FD_GHOST_MAGIC;
  FD_COMPILER_MFENCE();

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

  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "ghost must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( ghost->magic!=FD_GHOST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

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

void
fd_ghost_init( fd_ghost_t * ghost, ulong root_slot ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return;
  }

  if( FD_UNLIKELY( root_slot == FD_SLOT_NULL ) ) {
    FD_LOG_WARNING(( "NULL root" ));
    return;
  }

  if( FD_UNLIKELY( fd_fseq_query( fd_ghost_ver( ghost ) ) != ULONG_MAX ) ) {
    FD_LOG_WARNING(( "ghost already initialized" ));
    return;
  }

  fd_ghost_ele_t * pool = fd_ghost_pool( ghost );
  fd_ghost_map_t * map  = fd_ghost_map( ghost );
  ulong            null = fd_ghost_pool_idx_null( pool );

  if( FD_UNLIKELY( ghost->root != null ) ) {
    FD_LOG_WARNING(( "ghost already initialized" ));
    return;
  }

  /* Initialize the root ele from a pool element. */

  fd_ghost_ele_t * root = fd_ghost_pool_ele_acquire( pool );
  root->slot             = root_slot;
  root->next             = null;
  root->parent           = null;
  root->child            = null;
  root->sibling          = null;
  root->weight           = 0;
  root->replay_stake     = 0;
  root->gossip_stake     = 0;
  root->rooted_stake     = 0;
  root->valid            = 1;

  /* Insert the root and record the root ele's pool idx. */

  fd_ghost_map_ele_insert( map, root, pool ); /* cannot fail */
  ghost->root = fd_ghost_map_idx_query( map, &root_slot, null, pool );

  /* Sanity checks. */

  FD_TEST( fd_ghost_root( ghost )                                       );
  FD_TEST( fd_ghost_root( ghost ) == fd_ghost_query( ghost, root_slot ) );
  FD_TEST( fd_ghost_root( ghost )->slot == root_slot                    );

  fd_fseq_update( fd_ghost_ver( ghost ), 0 );
  return;
}

int
fd_ghost_verify( fd_ghost_t const * ghost ) {
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

  if( FD_UNLIKELY( ghost->magic!=FD_GHOST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }

  if( FD_UNLIKELY( fd_fseq_query( fd_ghost_ver_const( ghost ) )==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "ghost uninitialized or invalid" ));
    return -1;
  }

  fd_ghost_ele_t const * pool = fd_ghost_pool_const( ghost );
  ulong                  null = fd_ghost_pool_idx_null( pool );
  fd_ghost_map_t const * map  = fd_ghost_map_const( ghost );

  /* Check every ele that exists in pool exists in map. */

  if( fd_ghost_map_verify( map, fd_ghost_pool_max( pool ), pool ) ) return -1;

  /* Check every ele's weight is >= sum of children's weights. */

  fd_ghost_ele_t const * parent = fd_ghost_root_const( ghost );
  while( FD_LIKELY( parent ) ) {
    ulong                  weight = 0;
    fd_ghost_ele_t const * child  = fd_ghost_child_const( ghost, parent );
    while( FD_LIKELY( child->sibling != null ) ) {
      weight += child->weight;
      child = fd_ghost_sibling_const( ghost, child );
    }
  # if FD_GHOST_USE_HANDHOLDING
    FD_TEST( parent->weight >= weight );
  # endif
    parent = fd_ghost_pool_ele_const( pool, parent->next );
  }

  return 0;
}

fd_ghost_ele_t *
fd_ghost_insert( fd_ghost_t * ghost, ulong parent_slot, ulong slot ) {
  VER_INC;

  FD_LOG_DEBUG(( "[%s] slot: %lu. parent: %lu.", __func__, slot, parent_slot ));

# if FD_GHOST_USE_HANDHOLDING
  FD_TEST( ghost->magic == FD_GHOST_MAGIC );
# endif

  fd_ghost_map_t *       map    = fd_ghost_map( ghost );
  fd_ghost_ele_t *       pool   = fd_ghost_pool( ghost );
  ulong                  null   = fd_ghost_pool_idx_null( pool );
  fd_ghost_ele_t *       parent = fd_ghost_query( ghost, parent_slot );
  fd_ghost_ele_t const * root   = fd_ghost_root( ghost );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_ghost_query( ghost, slot ) ) ) { FD_LOG_WARNING(( "[%s] slot %lu already in ghost.", __func__, slot                   )); return NULL; }
  if( FD_UNLIKELY( !parent                       ) ) { FD_LOG_WARNING(( "[%s] missing `parent_slot` %lu.", __func__, parent_slot            )); return NULL; }
  if( FD_UNLIKELY( !fd_ghost_pool_free( pool )   ) ) { FD_LOG_WARNING(( "[%s] ghost full.",                __func__                         )); return NULL; }
  if( FD_UNLIKELY( slot <= root->slot            ) ) { FD_LOG_WARNING(( "[%s] slot %lu <= root %lu",       __func__, slot,       root->slot )); return NULL; }
# endif

  fd_ghost_ele_t * ele = fd_ghost_pool_ele_acquire( pool );
  ele->slot             = slot;
  ele->next             = null;
  ele->parent           = null;
  ele->child            = null;
  ele->sibling          = null;
  ele->weight           = 0;
  ele->replay_stake     = 0;
  ele->gossip_stake     = 0;
  ele->rooted_stake     = 0;
  ele->valid            = 1;

  ele->parent = fd_ghost_pool_idx( pool, parent );
  if( FD_LIKELY( parent->child == null ) ) {
    parent->child = fd_ghost_pool_idx( pool, ele ); /* left-child */
  } else {
    fd_ghost_ele_t * curr = fd_ghost_pool_ele( pool, parent->child );
    while( curr->sibling != null ) curr = fd_ghost_pool_ele( pool, curr->sibling );
    curr->sibling = fd_ghost_pool_idx( pool, ele ); /* right-sibling */
  }
  fd_ghost_map_ele_insert( map, ele, pool );
  return ele;
}

fd_ghost_ele_t const *
fd_ghost_head( fd_ghost_t const * ghost, fd_ghost_ele_t const * root ) {

# if FD_GHOST_USE_HANDHOLDING
  FD_TEST( ghost->magic == FD_GHOST_MAGIC );
  FD_TEST( root );
# endif

  if( FD_UNLIKELY( !root->valid ) ) return NULL; /* no valid ghost heads */

  fd_ghost_ele_t const * pool = fd_ghost_pool_const( ghost );
  fd_ghost_ele_t const * head = root;
  ulong                  null = fd_ghost_pool_idx_null( pool );

  while( FD_LIKELY( head->child != null ) ) {
    int valid_child = 0; /* at least one child is valid */
    fd_ghost_ele_t const * child = fd_ghost_child_const( ghost, head );
    while( FD_LIKELY( child ) ) { /* greedily pick the heaviest valid child */
      if( FD_LIKELY( child->valid ) ) {
        if( FD_LIKELY( !valid_child ) ) { /* this is the first valid child, so progress the head */
          head        = child;
          valid_child = 1;
        }
        head = fd_ptr_if(
          fd_int_if(
            child->weight == head->weight,  /* if the weights are equal */
            child->slot < head->slot,       /* then tie-break by lower slot number */
            child->weight > head->weight ), /* else return heavier */
          child, head );
      }
      child = fd_ghost_sibling_const( ghost, child );
    }
    if( FD_UNLIKELY( !valid_child ) ) break; /* no children are valid, so short-circuit traversal */
  }
  return head;
}

void
fd_ghost_replay_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong slot ) {
  VER_INC;

  fd_ghost_ele_t *       pool = fd_ghost_pool( ghost );
  ulong                  vote = voter->replay_vote;
  fd_ghost_ele_t const * root = fd_ghost_root( ghost );

  /* Short-circuit if the vote slot is older than the root. */

  if( FD_UNLIKELY( slot < root->slot ) ) return;

  /* Short-circuit if the vote slot is unchanged. */

  if( FD_UNLIKELY( slot == vote ) ) return;

  /* Short-circuit if this vote slot < the last vote slot we processed
     for this voter. The order we replay forks is non-deterministic due
     to network propagation variance, so it is possible we are see an
     older vote after a newer vote (relative to the slot in which the
     vote actually landed).

     For example, 3-4 and 7-8 fork from 2, we might see the vote for 5
     in block 6 then the vote for 3 in block 4. We ignore the vote for 3
     in block 4 if we already processed the vote for 5 in block 6. */

  if( FD_UNLIKELY( vote != FD_SLOT_NULL && slot < vote ) ) return;

  /* LMD-rule: subtract the voter's stake from the ghost ele
     corresponding to their previous vote slot. If the voter's previous
     vote slot is not in ghost than we have either not processed
     this voter previously or their previous vote slot was already
     pruned (because we published a new root). */

  fd_ghost_ele_t * ele = fd_ghost_query( ghost, vote );
  if( FD_LIKELY( ele ) ) { /* no previous vote or pruned */
    FD_LOG_DEBUG(( "[%s] subtracting (%s, %lu, %lu)", __func__, FD_BASE58_ENC_32_ALLOCA( &voter->key ), voter->stake, vote ));
    int cf = __builtin_usubl_overflow( ele->replay_stake, voter->stake, &ele->replay_stake );
    if( FD_UNLIKELY( cf ) ) FD_LOG_CRIT(( "[%s] sub overflow. ele->replay_stake %lu voter->stake %lu", __func__, ele->replay_stake, voter->stake ));
    fd_ghost_ele_t * ancestor = ele;
    while( FD_LIKELY( ancestor ) ) {
      cf = __builtin_usubl_overflow( ancestor->weight, voter->stake, &ancestor->weight );
      if( FD_UNLIKELY( cf ) ) FD_LOG_CRIT(( "[%s] sub overflow. ancestor->weight %lu latest_vote->stake %lu", __func__, ancestor->weight, voter->stake ));
      ancestor = fd_ghost_pool_ele( pool, ancestor->parent );
    }
  }

  /* Add voter's stake to the ghost ele keyed by `slot`. Propagate the
     vote stake up the ancestry. We do this for all cases we exited
     above: this vote is the first vote we've seen from a pubkey, this
     vote is switched from a previous vote that was on a missing ele
     (pruned), or the regular case */

  ele = fd_ghost_query( ghost, slot );
  if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "corrupt ghost" ));

  FD_LOG_DEBUG(( "[%s] adding (%s, %lu, %lu)", __func__, FD_BASE58_ENC_32_ALLOCA( &voter->key ), voter->stake, slot ));
  int cf = __builtin_uaddl_overflow( ele->replay_stake, voter->stake, &ele->replay_stake );
  if( FD_UNLIKELY( cf ) ) FD_LOG_ERR(( "[%s] add overflow. ele->stake %lu latest_vote->stake %lu", __func__, ele->replay_stake, voter->stake ));
  fd_ghost_ele_t * ancestor = ele;
  while( FD_LIKELY( ancestor ) ) {
    int cf = __builtin_uaddl_overflow( ancestor->weight, voter->stake, &ancestor->weight );
    if( FD_UNLIKELY( cf ) ) FD_LOG_ERR(( "[%s] add overflow. ancestor->weight %lu latest_vote->stake %lu", __func__, ancestor->weight, voter->stake ));
    ancestor = fd_ghost_parent( ghost, ancestor );
  }
  voter->replay_vote = slot; /* update the cached replay vote slot on voter */
}

void
fd_ghost_gossip_vote( FD_PARAM_UNUSED fd_ghost_t * ghost,
                      FD_PARAM_UNUSED fd_voter_t * voter,
                      FD_PARAM_UNUSED ulong        slot ) {
  FD_LOG_ERR(( "unimplemented" ));
}

void
fd_ghost_rooted_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong root ) {
  VER_INC;

  FD_LOG_DEBUG(( "[%s] root %lu, pubkey %s, stake %lu", __func__, root, FD_BASE58_ENC_32_ALLOCA(&voter->key), voter->stake ));

  /* It is invariant that the voter's root is found in ghost (as long as
     voter's root >= our root ). This is because voter's root is sourced
     from their vote state, so it must be on the fork we're replaying
     and we must have already inserted their root slot into ghost. */

  fd_ghost_ele_t * ele = fd_ghost_query( ghost, root );
# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "[%s] missing voter %s's root %lu.", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), root ));
# endif

  /* Add to the rooted stake. */

  ele->rooted_stake += voter->stake;
}

fd_ghost_ele_t const *
fd_ghost_publish( fd_ghost_t * ghost, ulong slot ) {
  VER_INC;

  fd_ghost_map_t *       map  = fd_ghost_map( ghost );
  fd_ghost_ele_t *       pool = fd_ghost_pool( ghost );
  ulong                  null = fd_ghost_pool_idx_null( pool );
  fd_ghost_ele_t const * oldr = fd_ghost_root( ghost );
  fd_ghost_ele_t *       newr = fd_ghost_map_ele_query( map, &slot, NULL, pool );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( slot <= oldr->slot                               ) ) { FD_LOG_WARNING(( "[%s] publish slot %lu <= root %lu.",      __func__, slot, oldr->slot )); return NULL; }
  if( FD_UNLIKELY( !newr                                            ) ) { FD_LOG_WARNING(( "[%s] publish slot %lu not found",         __func__, slot             )); return NULL; }
  if( FD_UNLIKELY( !fd_ghost_is_ancestor( ghost, oldr->slot, slot ) ) ) { FD_LOG_WARNING(( "[%s] publish slot %lu not ancestor %lu.", __func__, slot, oldr->slot )); return NULL; }
# endif

  /* First, remove the previous root, and add it to the prune list. In
     this context, head is the list head (not to be confused with the
     ghost head.) */

  fd_ghost_ele_t * head = fd_ghost_map_ele_remove( map, &oldr->slot, NULL, pool );
  fd_ghost_ele_t * tail = head;

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  head->next = null;
  while( FD_LIKELY( head ) ) {
    fd_ghost_ele_t * child = fd_ghost_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {                                              /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                       /* stop at new root */
        tail->next = fd_ghost_map_idx_remove( map, &child->slot, null, pool ); /* remove ele from map to reuse `.next` */
        tail       = fd_ghost_pool_ele( pool, tail->next );                    /* push onto prune queue (so descendants can be pruned) */
        tail->next = fd_ghost_pool_idx_null( pool );
      }
      child = fd_ghost_pool_ele( pool, child->sibling ); /* next sibling */
    }
    fd_ghost_ele_t * next = fd_ghost_pool_ele( pool, head->next ); /* pop prune queue head */
    fd_ghost_pool_ele_release( pool, head );                       /* free prune queue head */
    head = next;                                                   /* move prune queue head forward */
  }
  newr->parent = null;                            /* unlink old root*/
  ghost->root  = fd_ghost_pool_idx( pool, newr ); /* replace with new root */
  return newr;
}

fd_ghost_ele_t const *
fd_ghost_gca( fd_ghost_t const * ghost, ulong slot1, ulong slot2 ) {
  fd_ghost_ele_t const * pool = fd_ghost_pool_const( ghost );
  fd_ghost_ele_t const * ele1 = fd_ghost_query_const( ghost, slot1 );
  fd_ghost_ele_t const * ele2 = fd_ghost_query_const( ghost, slot2 );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !ele1 ) ) { FD_LOG_WARNING(( "slot1 %lu missing", slot1 )); return NULL; }
  if( FD_UNLIKELY( !ele2 ) ) { FD_LOG_WARNING(( "slot2 %lu missing", slot2 )); return NULL; }
# endif

  /* Find the greatest common ancestor. */

  while( FD_LIKELY( ele1 && ele2 ) ) {
    if( FD_UNLIKELY( ele1->slot == ele2->slot ) ) return ele1;
    if( ele1->slot > ele2->slot ) ele1 = fd_ghost_pool_ele_const( pool, ele1->parent );
    else                          ele2 = fd_ghost_pool_ele_const( pool, ele2->parent );
  }
  FD_LOG_CRIT(( "invariant violation" )); /* unreachable */
}

int
fd_ghost_is_ancestor( fd_ghost_t const * ghost, ulong ancestor, ulong slot ) {
  fd_ghost_ele_t const * root = fd_ghost_root_const( ghost );
  fd_ghost_ele_t const * curr = fd_ghost_query_const( ghost, slot );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( ancestor < root->slot ) ) { FD_LOG_WARNING(( "[%s] ancestor %lu too old. root %lu.", __func__, ancestor, root->slot )); return 0; }
  if( FD_UNLIKELY( !curr                 ) ) { FD_LOG_WARNING(( "[%s] slot %lu not in ghost.",          __func__, slot                 )); return 0; }
# endif

  /* Look for `ancestor` in the fork ancestry.

     Stop looking when there is either no ancestry remaining or there is
     no reason to look further because we've searched past the
     `ancestor`. */

  while( FD_LIKELY( curr && curr->slot >= ancestor ) ) {
    if( FD_UNLIKELY( curr->slot == ancestor ) ) return 1; /* optimize for depth > 1 */
    curr = fd_ghost_pool_ele_const( fd_ghost_pool_const( ghost ), curr->parent );
  }
  return 0; /* not found */
}

#include <stdio.h>

static void
print( fd_ghost_t const * ghost, fd_ghost_ele_t const * ele, int space, const char * prefix, ulong total ) {
  fd_ghost_ele_t const * pool = fd_ghost_pool_const( ghost );

  if( ele == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ )
    printf( " " );
  if( FD_UNLIKELY( ele->weight > 100 ) ) {
  }
  if( FD_UNLIKELY( total == 0 ) ) {
    printf( "%s%lu (%lu)", prefix, ele->slot, ele->weight );
  } else {
    double pct = ( (double)ele->weight / (double)total ) * 100;
    if( FD_UNLIKELY( pct < 0.99 )) {
      printf( "%s%lu (%.0lf%%, %lu)", prefix, ele->slot, pct, ele->weight );
    } else {
      printf( "%s%lu (%.0lf%%)", prefix, ele->slot, pct );
    }
  }

  fd_ghost_ele_t const * curr = fd_ghost_pool_ele_const( pool, ele->child );
  char                    new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( fd_ghost_pool_ele_const( pool, curr->sibling ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( ghost, curr, space + 4, new_prefix, total );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( ghost, curr, space + 4, new_prefix, total );
    }
    curr = fd_ghost_pool_ele_const( pool, curr->sibling );
  }
}

void
fd_ghost_print( fd_ghost_t const * ghost, ulong total_stake, fd_ghost_ele_t const * ele ) {
  FD_LOG_NOTICE( ( "\n\n[Ghost]" ) );
  print( ghost, ele, 0, "", total_stake );
  printf( "\n\n" );
}
