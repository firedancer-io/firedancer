#include "fd_ghost.h"
#include "stdio.h"
#include <string.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

/* clang-format off */
void *
fd_ghost_new( void * shmem, ulong node_max, ulong vote_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( node_max, vote_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad node_max (%lu) or vote_max (%lu)", node_max, vote_max ) );
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
fd_ghost_join( void * shghost ) { /* process 1: 0xFA   process 2: 0x2F */

  if( FD_UNLIKELY( !shghost ) ) {
    FD_LOG_WARNING( ( "NULL ghost" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shghost, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned ghost" ) );
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
  FD_TEST( laddr == (ulong)shghost + fd_ghost_footprint( node_max, vote_max ) );

  return ghost;
}
/* clang-format on */

void *
fd_ghost_leave( fd_ghost_t const * ghost ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING( ( "NULL ghost" ) );
    return NULL;
  }

  return (void *)ghost;
}

void *
fd_ghost_delete( void * ghost ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING( ( "NULL ghost" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ghost, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned ghost" ) );
    return NULL;
  }

  return ghost;
}

void
fd_ghost_init( fd_ghost_t * ghost, ulong root, ulong total_stake ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING( ( "NULL ghost" ) );
    return;
  }

  if( FD_UNLIKELY( root == FD_SLOT_NULL ) ) {
    FD_LOG_WARNING( ( "NULL slot" ) );
    return;
  }

  if( FD_UNLIKELY( ghost->root ) ) {
    FD_LOG_WARNING( ( "ghost already initialized" ) );
    return;
  }

  fd_ghost_node_t * node = fd_ghost_node_pool_ele_acquire( ghost->node_pool );
  node->slot             = root;
  fd_ghost_node_map_ele_insert( ghost->node_map, node, ghost->node_pool );
  ghost->root            = node;
  ghost->total_stake     = total_stake;

  return;
}

fd_ghost_node_t *
fd_ghost_node_insert( fd_ghost_t * ghost, ulong slot, ulong parent_slot ) {

#if FD_GHOST_USE_HANDHOLDING
  /* Caller promises key is not already in ghost. */
  if( FD_UNLIKELY( fd_ghost_node_map_ele_query( ghost->node_map,
                                                &slot,
                                                NULL,
                                                ghost->node_pool ) ) ) {
    FD_LOG_ERR( ( "slot %lu is already in ghost.", slot ) );
  }
#endif

  FD_LOG_DEBUG( ( "[ghost] node_insert: %lu. parent: %lu.", slot, parent_slot ) );

#if FD_GHOST_USE_HANDHOLDING
  /* OOM: we've exceeded the maximum number of slot hashes we can track. */
  if( FD_UNLIKELY( !fd_ghost_node_pool_free( ghost->node_pool ) ) )
    FD_LOG_ERR( ( "[ghost] node_pool full. check pruning logic." ) );
#endif

  fd_ghost_node_t * node = fd_ghost_node_pool_ele_acquire( ghost->node_pool );
  node->slot             = slot;
  node->stake            = 0;
  node->weight           = 0;

  /* Insert into the map for O(1) random access. */

  fd_ghost_node_map_ele_insert( ghost->node_map, node, ghost->node_pool );

  /* Insert into the ghost tree. */

  node->child   = NULL;
  node->sibling = NULL;

  fd_ghost_node_t * parent = fd_ghost_node_map_ele_query( ghost->node_map,
                                                          &parent_slot,
                                                          NULL,
                                                          ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
  /* Caller promises parent_slot is already in ghost. */
  if( FD_UNLIKELY( !fd_ghost_node_map_ele_query( ghost->node_map,
                                                 &parent_slot,
                                                 NULL,
                                                 ghost->node_pool ) ) ) {
    FD_LOG_WARNING( ( "[fd_ghost_node_insert] parent_slot %lu is missing from ghost.", parent_slot ) );
    __asm__("int $3");
  }
#endif

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

fd_ghost_node_t *
fd_ghost_head_query( fd_ghost_t * ghost ) {
  fd_ghost_node_t const * head = fd_ghost_head_query_const( ghost );

  /* Return a mutable reference. */

  return fd_ghost_node_query( ghost, head->slot );
}

fd_ghost_node_t const *
fd_ghost_head_query_const( fd_ghost_t const * ghost ) {
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

          curr->weight > head->weight
        ),
      curr, head );

      /* clang-format on */

      curr = curr->sibling;
    }
  }
  return head;
}

fd_ghost_node_t *
fd_ghost_node_query( fd_ghost_t * ghost, ulong slot ) {
  return fd_ghost_node_map_ele_query( ghost->node_map, &slot, NULL, ghost->node_pool );
}

fd_ghost_node_t const *
fd_ghost_node_query_const( fd_ghost_t const * ghost, ulong slot ) {
  return fd_ghost_node_map_ele_query_const( ghost->node_map, &slot, NULL, ghost->node_pool );
}

void
fd_ghost_replay_vote_upsert( fd_ghost_t *        ghost,
                             ulong               slot,
                             fd_pubkey_t const * pubkey,
                             ulong               stake ) {

  /* Ignore votes for slots older than the current root. */

  if( FD_UNLIKELY( slot < ghost->root->slot ) ) return;

  fd_ghost_node_t * node = fd_ghost_node_map_ele_query( ghost->node_map,
                                                        &slot,
                                                        NULL,
                                                        ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
  /* Caller promises node is already in ghost. */
  if( FD_UNLIKELY( !node ) ) FD_LOG_ERR( ( "missing ghost node" ) );
#endif

  /* Query pubkey's latest vote. */

  fd_ghost_vote_t * latest_vote = fd_ghost_vote_map_ele_query( ghost->vote_map,
                                                               pubkey,
                                                               NULL,
                                                               ghost->vote_pool );

  if( FD_LIKELY( latest_vote ) ) {

    /* Return early if this new vote is not newer than latest vote. */

    if( FD_UNLIKELY( slot <= latest_vote->slot ) ) return;

    fd_ghost_node_t * node = fd_ghost_node_map_ele_query( ghost->node_map,
                                                          &latest_vote->slot,
                                                          NULL,
                                                          ghost->node_pool );

    if( FD_UNLIKELY( !node ) ) {

      FD_LOG_NOTICE( ( "[ghost] %32J's latest vote slot %lu was too old and already pruned.",
                       pubkey,
                       latest_vote->slot ) );

    } else {

      /* Subtract pubkey's stake from the prev voted slot hash and propagate. */

      FD_LOG_DEBUG( ( "[ghost] removing (%32J, %lu, %lu)",
                      pubkey,
                      latest_vote->stake,
                      latest_vote->slot ) );

      node->stake -= latest_vote->stake;
      fd_ghost_node_t * ancestor = node;
      while( ancestor->parent ) {
        ancestor->weight -= stake;
        ancestor = ancestor->parent;
      }
    }

  } else {

    /* Ghost has not seen this pubkey vote yet, so insert. */

#if FD_GHOST_USE_HANDHOLDING
    /* OOM: we've exceeded the max number of voter pubkeys that were
       statically allocated. */
    if( FD_UNLIKELY( !fd_ghost_vote_pool_free( ghost->vote_pool ) ) )
      FD_LOG_ERR( ( "[ghost] vote_pool full. check # of validators." ) );
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

  FD_LOG_DEBUG( ( "[ghost] adding (%32J, %lu, %lu)", pubkey, stake, latest_vote->slot ) );
  node->stake += stake;
  fd_ghost_node_t * ancestor = node;
  while( ancestor->parent ) {
    ancestor->weight += stake;
    ancestor = ancestor->parent;
  }
}

void
fd_ghost_gossip_vote_upsert( FD_PARAM_UNUSED fd_ghost_t *        ghost,
                             FD_PARAM_UNUSED ulong               slot,
                             FD_PARAM_UNUSED fd_pubkey_t const * pubkey,
                             FD_PARAM_UNUSED ulong               stake ) {
  FD_LOG_ERR( ( "unimplemented" ) );
}

fd_ghost_node_t *
fd_ghost_publish( fd_ghost_t * ghost, ulong slot ) {

  fd_ghost_node_t * root = fd_ghost_node_query( ghost, slot );

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !root ) ) FD_LOG_ERR( ( "[fd_ghost_publish] slot %lu not found in ghost", slot ) );
#endif

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( root == ghost->root ) ) __asm__("int $3");
#endif

  /* First, remove the previous root, and add it to the prune list.

     In this context, head is the list head (not to be confused with the
     ghost head.) */

  fd_ghost_node_t * head = fd_ghost_node_map_ele_remove( ghost->node_map,
                                                         &ghost->root->slot,
                                                         NULL,
                                                         ghost->node_pool );

  /* Second, BFS down the tree, adding nodes to the prune queue except
     for the new root.

     Loop invariant: the old root must be in new root's ancestry. */

  while( head ) {
    fd_ghost_node_t * tail  = head;
    fd_ghost_node_t * child = head->child;

    while( child ) {

      /* Do not prune the new root. */

      if( FD_LIKELY( child != root ) ) {

        /* Remove the child from the map and push the child onto the list. */

        tail->next = fd_ghost_node_map_idx_remove( ghost->node_map,
                                                   &child->slot,
                                                   ULONG_MAX,
                                                   ghost->node_pool );
#if FD_GHOST_USE_HANDHOLDING
        if( FD_UNLIKELY( tail->next == ULONG_MAX ) ) {
          FD_LOG_ERR( ( "Failed to remove child. Child must exist given the while condition. "
                        "Possible memory corruption or data race." ) );
        }
#endif
        tail = fd_ghost_node_pool_ele( ghost->node_pool, tail->next );
      }

      /* Clear tail's next pointer */

      tail->next = ULONG_MAX;

      /* Move tail and child pointers forward. */

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

int
fd_ghost_is_ancestor( fd_ghost_t const * ghost, ulong ancestor_slot, ulong slot ) {
  fd_ghost_node_t const * ancestor = fd_ghost_node_query_const( ghost, slot );
#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !ancestor ) ) {

    /* slot not found in ghost. this can happen if ghost has pruned to a
       new root but forks has not yet been pruned to that same root. */

    FD_LOG_WARNING( ( "[fd_ghost_is_ancestor] unable to find slot %lu in ghost. ghost root: %lu",
                      slot,
                      ghost->root->slot ) );
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
  double pct = ( (double)node->weight / (double)total ) * 100;
  if( FD_UNLIKELY( total == 0 ) ) {
    printf( "%s%ld (%lu)", prefix, node->slot, node->weight );
  } else if( FD_UNLIKELY( pct < 0.99 ) ) {
    printf( "%s%ld (%.0lf%%, %lu)", prefix, node->slot, pct, node->weight );
  } else {
    printf( "%s%ld (%.0lf%%)", prefix, node->slot, pct );
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
fd_ghost_print_node( fd_ghost_t * ghost, fd_ghost_node_t * node, ulong depth ) {
  if( FD_UNLIKELY( !node ) ) {
    FD_LOG_WARNING( ( "[fd_ghost_print_node] NULL node." ) );
    return;
  }
  fd_ghost_node_t * ancestor = node;
  for( ulong i = 0; i < depth; i++ ) {
    if( !ancestor->parent ) break;
    ancestor = ancestor->parent;
  }
  print( ancestor, 0, "", ghost->total_stake );
  printf( "\n\n" );
}
