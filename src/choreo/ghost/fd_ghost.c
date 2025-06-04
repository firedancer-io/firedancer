#include "fd_ghost.h"

static void ver_inc( ulong ** ver ) {
  fd_fseq_update( *ver, fd_fseq_query( *ver ) + 1 );
}

#define VER_INC ulong * ver __attribute__((cleanup(ver_inc))) = fd_ghost_ver( ghost ); ver_inc( &ver )

void *
fd_ghost_new( void * shmem, ulong seed, ulong node_max ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( node_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad node_max (%lu)", node_max ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ghost_t * ghost     = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(), sizeof( fd_ghost_t ) );
  void *       ver       = FD_SCRATCH_ALLOC_APPEND( l, fd_fseq_align(), fd_fseq_footprint() );
  void *       node_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_node_pool_align(), fd_ghost_node_pool_footprint( node_max ) );
  void *       node_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_node_map_align(), fd_ghost_node_map_footprint( node_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_ghost_align() ) == (ulong)shmem + footprint );

  ghost->ver_gaddr       = fd_wksp_gaddr_fast( wksp, fd_fseq_join( fd_fseq_new( ver, ULONG_MAX ) ) );
  ghost->node_pool_gaddr = fd_wksp_gaddr_fast( wksp, fd_ghost_node_pool_join(fd_ghost_node_pool_new( node_pool, node_max ) ));
  ghost->node_map_gaddr  = fd_wksp_gaddr_fast( wksp, fd_ghost_node_map_join(fd_ghost_node_map_new( node_map, node_max, seed ) ));

  ghost->ghost_gaddr = fd_wksp_gaddr_fast( wksp, ghost );
  ghost->seed        = seed;
  ghost->root_idx    = fd_ghost_node_pool_idx_null( fd_ghost_node_pool( ghost ) );

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

  // TODO: zero out mem?

  return ghost;
}

void
fd_ghost_init( fd_ghost_t * ghost, ulong root ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return;
  }

  if( FD_UNLIKELY( root == FD_SLOT_NULL ) ) {
    FD_LOG_WARNING(( "NULL root" ));
    return;
  }

  if( FD_UNLIKELY( fd_fseq_query( fd_ghost_ver( ghost ) ) != ULONG_MAX ) ) {
    FD_LOG_WARNING(( "ghost already initialized" ));
    return;
  }

  fd_ghost_node_t *     node_pool = fd_ghost_node_pool( ghost );
  fd_ghost_node_map_t * node_map  = fd_ghost_node_map( ghost );
  ulong                 null_idx  = fd_ghost_node_pool_idx_null( node_pool );

  if( FD_UNLIKELY( ghost->root_idx != null_idx ) ) {
    FD_LOG_WARNING(( "ghost already initialized" ));
    return;
  }

  /* Initialize the root node from a pool element. */

  fd_ghost_node_t * root_ele = fd_ghost_node_pool_ele_acquire( node_pool );
  memset( root_ele, 0, sizeof( fd_ghost_node_t ) );
  root_ele->slot        = root;
  root_ele->next        = null_idx;
  root_ele->valid       = 1;
  root_ele->parent_idx  = null_idx;
  root_ele->child_idx   = null_idx;
  root_ele->sibling_idx = null_idx;

  /* Insert the root and record the root ele's pool idx. */

  fd_ghost_node_map_ele_insert( node_map, root_ele, node_pool ); /* cannot fail */
  ghost->root_idx = fd_ghost_node_map_idx_query( node_map, &root, null_idx, node_pool );

  /* Sanity checks. */

  FD_TEST( fd_ghost_root( ghost )                                  );
  FD_TEST( fd_ghost_root( ghost ) == fd_ghost_query( ghost, root ) );
  FD_TEST( fd_ghost_root( ghost )->slot == root                    );

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

  if( FD_UNLIKELY( fd_fseq_query( fd_ghost_ver( ghost ) )==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "ghost uninitialized or invalid" ));
    return -1;
  }

  fd_ghost_node_t const *     node_pool = fd_ghost_node_pool_const( ghost );
  fd_ghost_node_map_t const * node_map  = fd_ghost_node_map_const ( ghost );

  /* every element that exists in pool exists in map  */

  if( fd_ghost_node_map_verify( node_map, fd_ghost_node_pool_max( node_pool ), node_pool ) ) return -1;

  /* every node's weight is >= sum of children's weights */

  fd_ghost_node_t const * parent = fd_ghost_root( ghost );
  while( parent ) {
    ulong child_idx       = parent->child_idx;
    ulong children_weight = 0;
    while( child_idx != fd_ghost_node_pool_idx_null( node_pool ) ) {
      fd_ghost_node_t const * child = fd_ghost_node_pool_ele_const( node_pool, child_idx );
      children_weight += child->weight;
      child_idx = child->sibling_idx;
    }
  # if FD_GHOST_USE_HANDHOLDING
    FD_TEST( parent->weight >= children_weight );
  # endif
    parent = fd_ghost_node_pool_ele_const( node_pool, parent->next );
  }

  return 0;
}

fd_ghost_node_t *
fd_ghost_insert( fd_ghost_t * ghost, ulong parent_slot, ulong slot ) {
  VER_INC;

  FD_LOG_DEBUG(( "[%s] slot: %lu. parent: %lu.", __func__, slot, parent_slot ));

  #if FD_GHOST_USE_HANDHOLDING
  FD_TEST( ghost->magic == FD_GHOST_MAGIC );
  #endif

  fd_ghost_node_map_t * node_map  = fd_ghost_node_map( ghost );
  fd_ghost_node_t *     node_pool = fd_ghost_node_pool( ghost );

  ulong                   null_idx   = fd_ghost_node_pool_idx_null( node_pool );
  fd_ghost_node_t *       parent_ele = fd_ghost_node_map_ele_query( node_map, &parent_slot, NULL, node_pool );
  ulong                   parent_idx = fd_ghost_node_pool_idx( node_pool, parent_ele );
  fd_ghost_node_t const * root       = fd_ghost_root( ghost );

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_ghost_query( ghost, slot ) ) ) {  /* slot already in ghost */
    FD_LOG_WARNING(( "[%s] slot %lu already in ghost.", __func__, slot ));
    return NULL;
  }

  if( FD_UNLIKELY( !parent_ele ) ) { /* parent_slot not in ghost */
    FD_LOG_WARNING(( "[%s] missing `parent_slot` %lu.", __func__, parent_slot ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ghost_node_pool_free( node_pool ) ) ) { /* ghost full */
    FD_LOG_WARNING(( "[%s] ghost full.", __func__ ));
    return NULL;
  }

  if( FD_UNLIKELY( slot <= root->slot ) ) { /* slot must > root */
    FD_LOG_WARNING(( "[%s] slot %lu <= root %lu", __func__, slot, root->slot ));
    return NULL;
  }
  #endif

  fd_ghost_node_t * node_ele = fd_ghost_node_pool_ele_acquire( node_pool );
  ulong             node_idx = fd_ghost_node_pool_idx( node_pool, node_ele );

  memset( node_ele, 0, sizeof(fd_ghost_node_t) );
  node_ele->slot        = slot;
  node_ele->next        = null_idx;
  node_ele->valid       = 1;
  node_ele->parent_idx  = null_idx;
  node_ele->child_idx   = null_idx;
  node_ele->sibling_idx = null_idx;

  /* Insert into the map for O(1) random access. */

  fd_ghost_node_map_ele_insert( node_map, node_ele, node_pool ); /* cannot fail */

  /* Link node->parent. */

  node_ele->parent_idx = parent_idx;

  /* Link parent->node and sibling->node. */

  if( FD_LIKELY( parent_ele->child_idx == null_idx ) ) {

    /* No children yet so set as left-most child. */

    parent_ele->child_idx = node_idx;

  } else {

    /* Already have children so iterate to right-most sibling. */

    fd_ghost_node_t * curr = fd_ghost_node_pool_ele( node_pool, parent_ele->child_idx );
    while( curr->sibling_idx != null_idx ) curr = fd_ghost_node_pool_ele( node_pool, curr->sibling_idx );

    /* Link to right-most sibling. */

    curr->sibling_idx = node_idx;
  }

  /* Return newly-created node. */

  return node_ele;
}

fd_ghost_node_t const *
fd_ghost_head( fd_ghost_t const * ghost, fd_ghost_node_t const * root ) {
# if FD_GHOST_USE_HANDHOLDING
  FD_TEST( ghost->magic == FD_GHOST_MAGIC );
  FD_TEST( root );
# endif

  if( FD_UNLIKELY( !root->valid ) ) return NULL; /* no valid ghost heads */

  fd_ghost_node_t const * node_pool = fd_ghost_node_pool_const( ghost );
  fd_ghost_node_t const * head      = root;
  ulong                   null_idx  = fd_ghost_node_pool_idx_null( node_pool );

  while( FD_LIKELY( head->child_idx != null_idx ) ) {
    int valid_child = 0; /* at least one child is valid */
    fd_ghost_node_t const * child = fd_ghost_node_pool_ele_const( node_pool, head->child_idx );
    while( FD_LIKELY( child ) ) { /* greedily pick the heaviest valid child */
      if( FD_LIKELY( child->valid ) ) {
        if( FD_LIKELY( !valid_child ) ) { /* this is the first valid child, so progress the head */
          head        = child;
          valid_child = 1;
        };
        head = fd_ptr_if(
          fd_int_if(
            child->weight == head->weight,  /* if the weights are equal */
            child->slot < head->slot,       /* then tie-break by lower slot number */
            child->weight > head->weight ), /* else return heavier */
          child, head );
      }
      child = fd_ghost_node_pool_ele_const( node_pool, child->sibling_idx );
    }
    if( FD_UNLIKELY( !valid_child ) ) break; /* no children are valid, so short-circuit traversal */
  }
  return head;
}

void
fd_ghost_replay_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong slot ) {
  VER_INC;

  FD_LOG_DEBUG(( "[%s] slot %lu, pubkey %s, stake %lu", __func__, slot, FD_BASE58_ENC_32_ALLOCA( &voter->key ), voter->stake ));

  fd_ghost_node_map_t *   node_map  = fd_ghost_node_map( ghost );
  fd_ghost_node_t *       node_pool = fd_ghost_node_pool( ghost );
  ulong                   vote      = voter->replay_vote;
  fd_ghost_node_t const * root      = fd_ghost_root( ghost );

  #if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( slot < root->slot ) ) FD_LOG_ERR(( "[%s] illegal argument. vote slot: %lu, root: %lu", __func__, slot, root->slot ));
  #endif

  do {
    /* LMD-rule: subtract the voter's stake from previous vote. There
       are several cases where we skip this subtraction. */

    /* Case 1: It's the first vote we have seen from this pubkey. */

    if( FD_UNLIKELY( vote == FD_SLOT_NULL ) ) break;

    /* Case 2: Return early if the vote slot <= the voter's last tower
       vote. It is important that the vote slots are monotonically
       increasing, because the order we receive blocks is
       non-deterministic (due to network propagation variance), so we
       may process forks in a different order from the sender of this
       vote.

       For example, if a validator votes on A then switches to B, we
       might instead process B then A. In this case, the validator's
       tower on B would contain a strictly higher vote slot than A (due
       to lockout), so we would observe while processing A, that the
       vote slot < the last vote slot we have saved for that validator.
    */

    if( FD_UNLIKELY( slot <= vote ) ) return;

    /* Case 3: Previous vote slot was pruned when the SMR moved. */

    if( FD_UNLIKELY( vote < root->slot ) ) break;

    /* Case 4: When a node has been stuck on a minority fork for a
       while, and we end up pruning that fork when we update the SMR.
       In this case, we need to re-add their stake to the fork they are
       now voting for. In this case, it's possible that the previously
       saved vote slot is > than our root, but has been pruned. */

    fd_ghost_node_t * node = fd_ghost_node_map_ele_query( node_map, &vote, NULL, node_pool );
    if( FD_UNLIKELY( !node ) ) {
      FD_LOG_WARNING(( "missing/pruned ghost node for previous vote %lu; now voting for slot %lu", vote, slot ));
      break;
    }

    /* Do stake subtraction */

    FD_LOG_DEBUG(( "[%s] removing (%s, %lu, %lu)", __func__, FD_BASE58_ENC_32_ALLOCA( &voter->key ), voter->stake, vote ));

    #if FD_GHOST_USE_HANDHOLDING
    int cf = __builtin_usubl_overflow( node->replay_stake, voter->stake, &node->replay_stake );
    if( FD_UNLIKELY( cf ) ) FD_LOG_ERR(( "[%s] sub overflow. node stake %lu voter stake %lu", __func__, node->replay_stake, voter->stake ));
    #else
    node->replay_stake -= voter->stake;
    #endif

    fd_ghost_node_t * ancestor = node;
    while( ancestor ) {
      cf = __builtin_usubl_overflow( ancestor->weight, voter->stake, &ancestor->weight );
      #if FD_GHOST_USE_HANDHOLDING
      if( FD_UNLIKELY( cf ) ) FD_LOG_ERR(( "[%s] sub overflow. ancestor->weight %lu latest_vote->stake %lu", __func__, ancestor->weight, voter->stake ));
      #else
      ancestor_weight -= voter->stake;
      #endif
      ancestor = fd_ghost_node_pool_ele( node_pool, ancestor->parent_idx );
    }
  } while ( 0 );

  /* Add voter's stake to the ghost node keyed by `slot`.  Propagate the
     vote stake up the ancestry. We do this for all cases we exited
     above: this vote is the first vote we've seen from a pubkey,
     this vote is switched from a previous vote that was on a missing
     node (pruned), or the regular case */

  FD_LOG_DEBUG(( "[%s] adding (%s, %lu, %lu)", __func__, FD_BASE58_ENC_32_ALLOCA( &voter->key ), voter->stake, slot ));

  fd_ghost_node_t * node = fd_ghost_node_map_ele_query( node_map, &slot, NULL, node_pool );
  #if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !node ) ) FD_LOG_ERR(( "missing ghost node" )); /* slot must be in ghost. */
  #endif

  #if FD_GHOST_USE_HANDHOLDING
  int cf = __builtin_uaddl_overflow( node->replay_stake, voter->stake, &node->replay_stake );
  if( FD_UNLIKELY( cf ) ) FD_LOG_ERR(( "[%s] add overflow. node->stake %lu latest_vote->stake %lu", __func__, node->replay_stake, voter->stake ));
  #else
  node->replay_stake += voter->stake;
  #endif

  fd_ghost_node_t * ancestor = node;
  while( ancestor ) {
    #if FD_GHOST_USE_HANDHOLDING
    int cf = __builtin_uaddl_overflow( ancestor->weight, voter->stake, &ancestor->weight );
    if( FD_UNLIKELY( cf ) ) FD_LOG_ERR(( "[%s] add overflow. ancestor->weight %lu latest_vote->stake %lu", __func__, ancestor->weight, voter->stake ));
    #else
    ancestor_weight += voter->stake;
    #endif
    ancestor = fd_ghost_node_pool_ele( node_pool, ancestor->parent_idx );
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

  fd_ghost_node_map_t * node_map    = fd_ghost_node_map( ghost );
  fd_ghost_node_t * node_pool       = fd_ghost_node_pool( ghost );
  fd_ghost_node_t const * root_node = fd_ghost_root( ghost );

  #if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( root < root_node->slot ) ) {
    FD_LOG_ERR(( "caller must only insert vote slots >= ghost root. vote: %lu, root: %lu", root, root_node->slot ));
  }
  #endif

  /* It is invariant that the voter's root is found in ghost (as long as
     voter's root >= our root ). This is because voter's root is sourced
     from their vote state, so it must be on the fork we're replaying
     and we must have already inserted their root slot into ghost. */

  fd_ghost_node_t * node = fd_ghost_node_map_ele_query( node_map, &root, NULL, node_pool );
  #if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !node ) ) FD_LOG_ERR(( "[%s] invariant violation. missing voter %s's root %lu.", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), root ));
  #endif

  /* Add to the rooted stake. */

  node->rooted_stake += voter->stake;
}

fd_ghost_node_t const *
fd_ghost_publish( fd_ghost_t * ghost, ulong slot ) {
  FD_LOG_NOTICE(( "[%s] slot %lu", __func__, slot ));
  VER_INC;

  fd_ghost_node_map_t * node_map    = fd_ghost_node_map( ghost );
  fd_ghost_node_t * node_pool       = fd_ghost_node_pool( ghost );
  fd_ghost_node_t const * root_node = fd_ghost_root( ghost );
  ulong null_idx                    = fd_ghost_node_pool_idx_null( node_pool );

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( slot < root_node->slot ) ) {
    FD_LOG_WARNING(( "[fd_ghost_publish] trying to publish slot %lu older than ghost->root %lu.",
                      slot,
                      root_node->slot ));
    return NULL;
  }
  if( FD_UNLIKELY( slot == root_node->slot ) ) {
    FD_LOG_WARNING(( "[fd_ghost_publish] publishing same slot %lu as ghost->root %lu.",
                      slot,
                      root_node->slot ));
    return NULL;
  }
#endif

  // new root
  fd_ghost_node_t * root = fd_ghost_node_map_ele_query( node_map,
                                                        &slot,
                                                        NULL,
                                                        node_pool );

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !root ) ) {
    FD_LOG_ERR(( "[fd_ghost_publish] publish slot %lu not found in ghost", slot ));
  }

#endif

  /* First, remove the previous root, and add it to the prune list.

     In this context, head is the list head (not to be confused with the
     ghost head.) */

  fd_ghost_node_t * head = fd_ghost_node_map_ele_remove( node_map,
                                                         &root_node->slot,
                                                         NULL,
                                                         node_pool );
  head->next             = fd_ghost_node_pool_idx_null( node_pool );
  fd_ghost_node_t * tail = head;

  /* Second, BFS down the tree, adding nodes to the prune queue except
     for the new root.

     Loop invariant: the old root must be in new root's ancestry. */

  while( head ) {
    fd_ghost_node_t * child = fd_ghost_node_pool_ele( node_pool, head->child_idx );

    while( FD_LIKELY( child ) ) {

      /* Do not prune the new root. */

      if( FD_LIKELY( child != root ) ) {

        /* Remove the child from the map and push the child onto the list. */

        tail->next = fd_ghost_node_map_idx_remove( node_map,
                                                   &child->slot,
                                                   fd_ghost_node_pool_idx_null( node_pool ),
                                                   node_pool );
#if FD_GHOST_USE_HANDHOLDING
        if( FD_UNLIKELY( tail->next == fd_ghost_node_pool_idx_null( node_pool ) ) ) {
          FD_LOG_ERR(( "Failed to remove child. Child must exist given the while condition. "
                       "Possible memory corruption or data race." ));
        }
#endif
        tail       = fd_ghost_node_pool_ele( node_pool, tail->next );
        tail->next = fd_ghost_node_pool_idx_null( node_pool );
      }

      child = fd_ghost_node_pool_ele( node_pool, child->sibling_idx );
    }

    /* Free the head, and move the head pointer forward. */

    fd_ghost_node_t * next = fd_ghost_node_pool_ele( node_pool, head->next );
    fd_ghost_node_pool_ele_release( node_pool, head );
    head = next;
  }

  /* Unlink the root and set the new root. */

  root->parent_idx = null_idx;
  ghost->root_idx  = fd_ghost_node_map_idx_query( node_map, &slot, null_idx, node_pool );

  return root;
}

fd_ghost_node_t const *
fd_ghost_gca( fd_ghost_t const * ghost, ulong slot1, ulong slot2 ) {
  fd_ghost_node_t const * node_pool = fd_ghost_node_pool_const( ghost );
  fd_ghost_node_t const * node1     = fd_ghost_query( ghost, slot1 );
  fd_ghost_node_t const * node2     = fd_ghost_query( ghost, slot2 );

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !node1 ) ) {
    FD_LOG_WARNING(( "slot1 %lu is missing from ghost", slot1 ));
    return NULL;
  }

  if( FD_UNLIKELY( !node2 ) ) {
    FD_LOG_WARNING(( "slot2 %lu is missing from ghost", slot2 ));
    return NULL;
  }
#endif

  /* Find the greatest common ancestor. */

  while( node1 && node2 ) {
    if( FD_UNLIKELY( node1->slot == node2->slot ) ) return node1;
    if( node1->slot > node2->slot ) {
      node1 = fd_ghost_node_pool_ele_const( node_pool, node1->parent_idx );
    } else {
      node2 = fd_ghost_node_pool_ele_const( node_pool, node2->parent_idx );
    }
  }

  FD_LOG_ERR(( "Unable to find GCA. Is this a valid ghost?" ));
}

int
fd_ghost_is_ancestor( fd_ghost_t const * ghost, ulong ancestor, ulong slot ) {
  fd_ghost_node_t const * root = fd_ghost_root( ghost );
  fd_ghost_node_t const * curr = fd_ghost_query( ghost, slot );

  #if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( ancestor < root->slot ) ) {
    FD_LOG_WARNING(( "[%s] ancestor %lu too old. root %lu.", __func__, ancestor, root->slot ));
    return 0;
  }

  if( FD_UNLIKELY( !curr ) ) {
    FD_LOG_WARNING(( "[%s] slot %lu not in ghost.", __func__, slot ));
    return 0;
  }
  #endif

  /* Look for `ancestor` in the fork ancestry.

     Stop looking when there is either no ancestry remaining or there is
     no reason to look further because we've searched past the
     `ancestor`. */

  while( FD_LIKELY( curr && curr->slot >= ancestor ) ) {
    if( FD_UNLIKELY( curr->slot == ancestor ) ) return 1; /* optimize for depth > 1 */
    curr = fd_ghost_node_pool_ele_const( fd_ghost_node_pool_const( ghost ), curr->parent_idx );
  }
  return 0; /* not found */
}

#include <stdio.h>

static void
print( fd_ghost_t const * ghost, fd_ghost_node_t const * node, int space, const char * prefix, ulong total ) {
  fd_ghost_node_t const * node_pool = fd_ghost_node_pool_const( ghost );

  if( node == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ )
    printf( " " );
  if( FD_UNLIKELY( node->weight > 100 ) ) {
  }
  if( FD_UNLIKELY( total == 0 ) ) {
    printf( "%s%lu (%lu)", prefix, node->slot, node->weight );
  } else {
    double pct = ( (double)node->weight / (double)total ) * 100;
    if( FD_UNLIKELY( pct < 0.99 )) {
      printf( "%s%lu (%.0lf%%, %lu)", prefix, node->slot, pct, node->weight );
    } else {
      printf( "%s%lu (%.0lf%%)", prefix, node->slot, pct );
    }
  }

  fd_ghost_node_t const * curr = fd_ghost_node_pool_ele_const( node_pool, node->child_idx );
  char                    new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( fd_ghost_node_pool_ele_const( node_pool, curr->sibling_idx ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( ghost, curr, space + 4, new_prefix, total );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( ghost, curr, space + 4, new_prefix, total );
    }
    curr = fd_ghost_node_pool_ele_const( node_pool, curr->sibling_idx );
  }
}

void
fd_ghost_print( fd_ghost_t const * ghost, fd_epoch_t const * epoch, fd_ghost_node_t const * node ) {
  FD_LOG_NOTICE( ( "\n\n[Ghost]" ) );
  print( ghost, node, 0, "", epoch->total_stake );
  printf( "\n\n" );
}
