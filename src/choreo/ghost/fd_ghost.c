#include "fd_ghost.h"
#include "stdio.h"
#include <string.h>

/* clang-format off */

void *
fd_ghost_new( void * shmem, ulong node_max, ulong vote_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)shmem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( node_max, vote_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad node_max (%lu) or vote_max (%lu)", node_max, vote_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  ulong        laddr = (ulong)shmem;
  fd_ghost_t * ghost = (void *)laddr;
  laddr             += sizeof(fd_ghost_t);

  laddr            = fd_ulong_align_up( laddr, fd_ghost_node_pool_align() );
  ghost->node_pool = fd_ghost_node_pool_new( (void *)laddr, node_max );
  laddr           += fd_ghost_node_pool_footprint( node_max );

  laddr           = fd_ulong_align_up( laddr, fd_ghost_node_map_align() );
  ghost->node_map = fd_ghost_node_map_new( (void *)laddr, node_max, seed );
  laddr          += fd_ghost_node_map_footprint( node_max );

  laddr            = fd_ulong_align_up( laddr, fd_ghost_vote_pool_align() );
  ghost->vote_pool = fd_ghost_vote_pool_new( (void *)laddr, vote_max );
  laddr           += fd_ghost_vote_pool_footprint( vote_max );

  laddr           = fd_ulong_align_up( laddr, fd_ghost_vote_map_align() );
  ghost->vote_map = fd_ghost_vote_map_new( (void *)laddr, vote_max, seed );
  laddr          += fd_ghost_vote_map_footprint( vote_max );

  laddr = fd_ulong_align_up( laddr, fd_ghost_align() );
  FD_TEST( laddr == (ulong)shmem + footprint );

  return shmem;
}

fd_ghost_t *
fd_ghost_join( void * shghost ) {

  if( FD_UNLIKELY( !shghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)shghost, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ghost" ));
    return NULL;
  }

  ulong        laddr = (ulong)shghost; /* offset from a memory region */
  fd_ghost_t * ghost = (void *)shghost;
  laddr             += sizeof(fd_ghost_t);

  laddr            = fd_ulong_align_up( laddr, fd_ghost_node_pool_align() );
  ghost->node_pool = fd_ghost_node_pool_join( (void *)laddr );
  ulong node_max   = fd_ghost_node_pool_max( ghost->node_pool );
  laddr           += fd_ghost_node_pool_footprint( node_max );

  laddr           = fd_ulong_align_up( laddr, fd_ghost_node_map_align() );
  ghost->node_map = fd_ghost_node_map_join( (void *)laddr );
  laddr          += fd_ghost_node_map_footprint( node_max );

  laddr            = fd_ulong_align_up( laddr, fd_ghost_vote_pool_align() );
  ghost->vote_pool = fd_ghost_vote_pool_join( (void *)laddr );
  ulong vote_max   = fd_ghost_vote_pool_max( ghost->vote_pool );
  laddr           += fd_ghost_vote_pool_footprint( vote_max );

  laddr           = fd_ulong_align_up( laddr, fd_ghost_vote_map_align() );
  ghost->vote_map = fd_ghost_vote_map_join( (void *)laddr );
  laddr          += fd_ghost_vote_map_footprint( vote_max );

  laddr = fd_ulong_align_up( laddr, fd_ghost_align() );
  FD_TEST( laddr == (ulong)shghost + fd_ghost_footprint( node_max, vote_max ));

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
fd_ghost_init( fd_ghost_t * ghost, ulong root, ulong total_stake ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return;
  }

  if( FD_UNLIKELY( root == FD_SLOT_NULL ) ) {
    FD_LOG_WARNING(( "NULL slot" ));
    return;
  }

  if( FD_UNLIKELY( ghost->root ) ) {
    FD_LOG_WARNING(( "ghost already initialized" ));
    return;
  }

  fd_ghost_node_t * node = fd_ghost_node_pool_ele_acquire( ghost->node_pool );
  memset( node, 0, sizeof( fd_ghost_node_t ));
  node->slot = root;

  fd_ghost_node_map_ele_insert( ghost->node_map, node, ghost->node_pool );
  ghost->root        = node;
  ghost->total_stake = total_stake;

  return;
}

/* clang-format on */

fd_ghost_node_t *
fd_ghost_insert( fd_ghost_t * ghost, ulong slot, ulong parent_slot ) {
  FD_LOG_DEBUG(( "[ghost] node_insert: %lu. parent: %lu.", slot, parent_slot ));

/* Caller promises slot >= SMR. */

#if FD_GHOST_USE_HANDHOLDING
  if (FD_UNLIKELY( slot < ghost->root->slot )) {
    FD_LOG_ERR(( "slot %lu is older than ghost root %lu", slot, ghost->root->slot ));
  }
#endif

/* Caller promises slot is not already in ghost. */

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_ghost_node_map_ele_query( ghost->node_map,
                                                &slot,
                                                NULL,
                                                ghost->node_pool ) ) ) {
    FD_LOG_ERR(( "slot %lu is already in ghost.", slot ));
  }
#endif

  fd_ghost_node_t * parent = fd_ghost_node_map_ele_query( ghost->node_map,
                                                          &parent_slot,
                                                          NULL,
                                                          ghost->node_pool );

/* Caller promises parent_slot is already in ghost. */

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_ghost_node_map_ele_query( ghost->node_map,
                                                 &parent_slot,
                                                 NULL,
                                                 ghost->node_pool ) ) ) {
    FD_LOG_ERR(( "[fd_ghost_node_insert] missing parent_slot %lu.", parent_slot ));
  }
#endif

/* Caller promises node pool has a free element. */

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !fd_ghost_node_pool_free( ghost->node_pool ) ) ) {
    FD_LOG_ERR(( "[ghost] node_pool full. check pruning logic." ));
  }
#endif

  fd_ghost_node_t * node = fd_ghost_node_pool_ele_acquire( ghost->node_pool );
  memset( node, 0, sizeof( fd_ghost_node_t ) );
  node->slot = slot;

  /* Insert into the map for O(1) random access. */

  fd_ghost_node_map_ele_insert( ghost->node_map, node, ghost->node_pool );

  /* Insert into the ghost tree. */

  node->child   = NULL;
  node->sibling = NULL;


  /* Link node->parent. */

  node->parent = parent;

  /* Link parent->node and sibling->node. */

  if( FD_LIKELY( !parent->child ) ) {

    /* No siblings, which means no forks. This is the likely case. */

    parent->child = node;

  } else {

    /* Iterate to right-most sibling. */

    fd_ghost_node_t * curr = parent->child;
    while( curr->sibling ) {
      curr = curr->sibling;
    }

    /* Link to right-most sibling. */

    curr->sibling = node;
  }

  /* Return newly-created node. */

  return node;
}

fd_ghost_node_t const *
fd_ghost_head( fd_ghost_t const * ghost ) {
  fd_ghost_node_t const * head = ghost->root;
  while( head->child ) {
    head                         = head->child;
    fd_ghost_node_t const * curr = head;
    while( curr ) {

      /* clang-format off */

      head = fd_ptr_if(
        fd_int_if(
          /* if the weights are equal... */

          curr->weight == head->weight,

          /* ...tie-break by slot number */

          curr->slot < head->slot,

          /* otherwise return curr if curr > head */

          curr->weight > head->weight ),
        curr, head );

      /* clang-format on */

      curr = curr->sibling;
    }
  }
  return head;
}

fd_ghost_node_t const *
fd_ghost_replay_vote( fd_ghost_t * ghost, ulong slot, fd_pubkey_t const * pubkey, ulong stake ) {
  FD_LOG_DEBUG(( "[%s] slot %lu, pubkey %s, stake %lu", __func__, slot, FD_BASE58_ENC_32_ALLOCA( pubkey ), stake ));

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( slot < ghost->root->slot ) ) {
    FD_LOG_ERR(( "caller must only insert vote slots >= ghost root. vote: %lu, root: %lu",
                 slot,
                 ghost->root->slot ));
  }
#endif

  fd_ghost_node_t * node = fd_ghost_node_map_ele_query( ghost->node_map,
                                                        &slot,
                                                        NULL,
                                                        ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
  /* Caller promises node is already in ghost. */
  if( FD_UNLIKELY( !node ) ) {
    FD_LOG_ERR(( "missing ghost node" ));
  }

#endif

  /* Query pubkey's latest vote. */

  fd_ghost_vote_t * latest_vote = fd_ghost_vote_map_ele_query( ghost->vote_map,
                                                               pubkey,
                                                               NULL,
                                                               ghost->vote_pool );

  if( FD_LIKELY( latest_vote ) ) {

    /* Return if this new vote slot is not > than latest vote. It is
       important that the vote slots are monotonically increasing,
       because the order we receive blocks is non-deterministic (due to
       network propagation variance), so we may process forks in a
       different order from the sender of this vote.

       For example, if a validator votes on A then switches to B, we
       might instead process B then A. In this case, the validator's
       vote account state on B would contain a strictly higher vote slot
       than A (due to lockout), so we would observe while processing A,
       that the vote slot < the latest vote slot we have saved for that
       validator. */

    if( FD_UNLIKELY( slot <= latest_vote->slot ) ) return node;

    fd_ghost_node_t * node = fd_ghost_node_map_ele_query( ghost->node_map,
                                                          &latest_vote->slot,
                                                          NULL,
                                                          ghost->node_pool );

    if( FD_UNLIKELY( !node ) ) {

      FD_LOG_NOTICE(( "[ghost] %s's latest vote slot %lu was too old and already pruned.",
                      FD_BASE58_ENC_32_ALLOCA( pubkey ),
                      latest_vote->slot ));

    } else {

      /* Subtract pubkey's stake from the prev voted slot hash and propagate. */

      FD_LOG_DEBUG(( "[ghost] removing (%s, %lu, %lu)",
                      FD_BASE58_ENC_32_ALLOCA( pubkey ),
                      latest_vote->stake,
                      latest_vote->slot ));

      int cf = __builtin_usubl_overflow( node->stake, latest_vote->stake, &node->stake );
      if( FD_UNLIKELY( cf ) ) {
        FD_LOG_WARNING(( "[%s] sub overflow. node->stake %lu latest_vote->stake %lu",
                         __func__,
                         node->stake,
                         latest_vote->stake ));
        node->stake = 0;
      }
      fd_ghost_node_t * ancestor = node;
      while( ancestor->parent ) {
        int cf = __builtin_usubl_overflow( ancestor->weight,
                                           latest_vote->stake,
                                           &ancestor->weight );
        if( FD_UNLIKELY( cf ) ) {
          FD_LOG_WARNING(( "[%s] sub overflow. ancestor->weight %lu latest_vote->stake %lu",
                           __func__,
                           ancestor->weight,
                           latest_vote->stake ));
          ancestor->weight = 0;
        }
        ancestor = ancestor->parent;
      }
    }

  } else {

    /* Ghost has not seen this pubkey vote yet, so insert. */

#if FD_GHOST_USE_HANDHOLDING
    /* OOM: we've exceeded the max number of voter pubkeys that were
       statically allocated. */
    if( FD_UNLIKELY( !fd_ghost_vote_pool_free( ghost->vote_pool ) ) ) {
      FD_LOG_ERR(( "[ghost] vote_pool full. check # of validators." ));
    }
#endif

    latest_vote         = fd_ghost_vote_pool_ele_acquire( ghost->vote_pool );
    latest_vote->pubkey = *pubkey;
    latest_vote->slot   = slot;
    latest_vote->stake  = stake;
    fd_ghost_vote_map_ele_insert( ghost->vote_map, latest_vote, ghost->vote_pool );
  }
  latest_vote->slot  = slot;
  latest_vote->stake = stake;

  /* Propagate the vote stake up the ancestry, including updating the
     head. */

  FD_LOG_DEBUG(( "[ghost] adding (%s, %lu, %lu)", FD_BASE58_ENC_32_ALLOCA( pubkey ), stake, latest_vote->slot ));
  int cf = __builtin_uaddl_overflow( node->stake, latest_vote->stake, &node->stake );
  if( FD_UNLIKELY( cf ) ) {
    FD_LOG_ERR(( "[%s] add overflow. node->stake %lu latest_vote->stake %lu",
                 __func__,
                 node->stake,
                 latest_vote->stake ));
  }
  fd_ghost_node_t * ancestor = node;
  while( ancestor->parent ) {
    int cf = __builtin_uaddl_overflow( ancestor->weight, latest_vote->stake, &ancestor->weight );
    if( FD_UNLIKELY( cf ) ) {
      FD_LOG_ERR(( "[%s] add overflow. ancestor->weight %lu latest_vote->stake %lu",
                   __func__,
                   ancestor->weight,
                   latest_vote->stake ));
    }
    ancestor = ancestor->parent;
  }

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( node->stake > ghost->total_stake ) ) {
    FD_LOG_ERR(( "[%s] invariant violation. node->stake > total stake."
                 "slot: %lu, "
                 "node->stake %lu, "
                 "ghost->total_stake %lu",
                 __func__,
                 slot,
                 node->stake,
                 ghost->total_stake ));
  }
#endif

  return node;
}

fd_ghost_node_t const *
fd_ghost_gossip_vote( FD_PARAM_UNUSED fd_ghost_t *        ghost,
                      FD_PARAM_UNUSED ulong               slot,
                      FD_PARAM_UNUSED fd_pubkey_t const * pubkey,
                      FD_PARAM_UNUSED ulong               stake ) {
  FD_LOG_ERR(( "unimplemented" ));
}

fd_ghost_node_t const *
fd_ghost_rooted_vote( fd_ghost_t * ghost, ulong root, fd_pubkey_t const * pubkey, ulong stake ) {
  FD_LOG_DEBUG(( "[%s] root %lu, pubkey %s, stake %lu", __func__, root, FD_BASE58_ENC_32_ALLOCA( pubkey ), stake ));

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( root < ghost->root->slot ) ) {
    FD_LOG_ERR(( "caller must only insert vote slots >= ghost root. vote: %lu, root: %lu",
                 root,
                 ghost->root->slot ));
  }
#endif

  /* It is invariant that the voter's root is found in ghost (as long as
     voter's root >= our root ). This is because voter's root is sourced
     from their vote state, so it must be on the fork we're replaying
     and we must have already inserted their root slot into ghost. */

  fd_ghost_node_t * node = fd_ghost_node_map_ele_query( ghost->node_map,
                                                        &root,
                                                        NULL,
                                                        ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !node ) ) {
    FD_LOG_ERR(( "[%s] invariant violation. missing voter %s's root %lu.", __func__, FD_BASE58_ENC_32_ALLOCA( pubkey ), root ));
  }
#endif

  /* Add to the rooted stake. */

  node->rooted_stake += stake;
  return node;
}

fd_ghost_node_t const *
fd_ghost_publish( fd_ghost_t * ghost, ulong slot ) {

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( slot < ghost->root->slot ) ) {
    FD_LOG_WARNING(( "[fd_ghost_publish] trying to publish slot %lu older than ghost->root %lu.",
                      slot,
                      ghost->root->slot ));
    return NULL;
  }
  if( FD_UNLIKELY( slot == ghost->root->slot ) ) {
    FD_LOG_WARNING(( "[fd_ghost_publish] publishing same slot %lu as ghost->root %lu.",
                      slot,
                      ghost->root->slot ));
    return NULL;
  }
#endif

  fd_ghost_node_t * root = fd_ghost_node_map_ele_query( ghost->node_map,
                                                        &slot,
                                                        NULL,
                                                        ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !root ) ) {
    FD_LOG_ERR(( "[fd_ghost_publish] publish slot %lu not found in ghost", slot ));
  }

#endif

  /* First, remove the previous root, and add it to the prune list.

     In this context, head is the list head (not to be confused with the
     ghost head.) */

  fd_ghost_node_t * head = fd_ghost_node_map_ele_remove( ghost->node_map,
                                                         &ghost->root->slot,
                                                         NULL,
                                                         ghost->node_pool );
  head->next             = fd_ghost_node_pool_idx_null( ghost->node_pool );
  fd_ghost_node_t * tail = head;

  /* Second, BFS down the tree, adding nodes to the prune queue except
     for the new root.

     Loop invariant: the old root must be in new root's ancestry. */

  while( head ) {
    fd_ghost_node_t * child = head->child;

    while( FD_LIKELY( child ) ) {

      /* Do not prune the new root. */

      if( FD_LIKELY( child != root ) ) {

        /* Remove the child from the map and push the child onto the list. */

        tail->next = fd_ghost_node_map_idx_remove( ghost->node_map,
                                                   &child->slot,
                                                   fd_ghost_node_pool_idx_null( ghost->node_pool ),
                                                   ghost->node_pool );
#if FD_GHOST_USE_HANDHOLDING
        if( FD_UNLIKELY( tail->next == fd_ghost_node_pool_idx_null( ghost->node_pool ) ) ) {
          FD_LOG_ERR(( "Failed to remove child. Child must exist given the while condition. "
                       "Possible memory corruption or data race." ));
        }
#endif
        tail       = fd_ghost_node_pool_ele( ghost->node_pool, tail->next );
        tail->next = fd_ghost_node_pool_idx_null( ghost->node_pool );
      }

      child = child->sibling;
    }

    /* Free the head, and move the head pointer forward. */

    fd_ghost_node_t * next = fd_ghost_node_pool_ele( ghost->node_pool, head->next );
    fd_ghost_node_pool_ele_release( ghost->node_pool, head );
    head = next;
  }

  /* Unlink the root and set the new root. */

  root->parent = NULL;
  ghost->root  = root;

  return root;
}

fd_ghost_node_t const *
fd_ghost_gca( fd_ghost_t const * ghost, ulong slot1, ulong slot2 ) {
  fd_ghost_node_t const * node1 = fd_ghost_query( ghost, slot1 );
  fd_ghost_node_t const * node2 = fd_ghost_query( ghost, slot2 );

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
      node1 = node1->parent;
    } else {
      node2 = node2->parent;
    }
  }

  FD_LOG_ERR(( "Unable to find GCA. Is this a valid ghost?" ));
}

int
fd_ghost_is_descendant( fd_ghost_t const * ghost, ulong slot, ulong ancestor_slot ) {
  fd_ghost_node_t const * ancestor = fd_ghost_query( ghost, slot );
#if FD_GHOST_USE_HANDHOLDING

  if( FD_UNLIKELY( ancestor_slot < ghost->root->slot ) ) {
    FD_LOG_ERR(( "[%s] ancestor_slot %lu is older than ghost root %lu.",
                 __func__,
                 ancestor_slot,
                 ghost->root->slot ));
  }

  if( FD_UNLIKELY( !ancestor ) ) {

    /* Slot not found, so we won't find the ancestor. */

    FD_LOG_WARNING(( "[%s] unable to find slot %lu in ghost.", __func__, slot ));
    return 0;
  }
#endif

  /* Look for ancestor_slot in the fork ancestry.

     Stop looking when there is either no ancestry remaining or there is
     no reason to look further because we've searched past the
     ancestor_slot. */

  while( FD_LIKELY( ancestor && ancestor->slot >= ancestor_slot ) ) {
    if( FD_UNLIKELY( ancestor->slot == ancestor_slot ) ) return 1; /* optimize for not found */
    ancestor = ancestor->parent;
  }
  return 0; /* not found */
}

static void
print( fd_ghost_node_t const * node, int space, const char * prefix, ulong total ) {
  if( node == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ )
    printf( " " );
  if( FD_UNLIKELY( node->weight > 100 ) ) {
  }
  double pct = ( (double)node->weight / (double)total ) * 100;
  if( FD_UNLIKELY( total == 0 ) ) {
    printf( "%s%lu (%lu)", prefix, node->slot, node->weight );
  } else if( FD_UNLIKELY( pct < 0.99 ) ) {
    printf( "%s%lu (%.0lf%%, %lu)", prefix, node->slot, pct, node->weight );
  } else {
    printf( "%s%lu (%.0lf%%)", prefix, node->slot, pct );
  }

  fd_ghost_node_t * curr = node->child;
  char              new_prefix[1024]; /* Large enough to hold the new prefix string */
  while( curr ) {
    if( curr->sibling ) {
      sprintf( new_prefix, "├── " ); /* Branch indicating more siblings follow */
      print( curr, space + 4, new_prefix, total );
    } else {
      sprintf( new_prefix, "└── " ); /* End branch */
      print( curr, space + 4, new_prefix, total );
    }
    curr = curr->sibling;
  }
}

void
fd_ghost_slot_print( fd_ghost_t * ghost, ulong slot, ulong depth ) {
  fd_ghost_node_t const * node = fd_ghost_query( ghost, slot );
  if( FD_UNLIKELY( !node ) ) {
    FD_LOG_WARNING(( "[fd_ghost_print_node] NULL node." ));
    return;
  }
  fd_ghost_node_t const * ancestor = node;
  for( ulong i = 0; i < depth; i++ ) {
    if( !ancestor->parent ) break;
    ancestor = ancestor->parent;
  }
  print( ancestor, 0, "", ghost->total_stake );
  printf( "\n\n" );
}
