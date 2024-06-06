#include "fd_ghost.h"
#include "stdio.h"
#include <string.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

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
  ghost->root        = NULL;
  laddr += sizeof( fd_ghost_t );

  laddr            = fd_ulong_align_up( laddr, fd_ghost_node_pool_align() );
  ghost->node_pool = fd_ghost_node_pool_new( (void *)laddr, node_max );
  laddr += fd_ghost_node_pool_footprint( node_max );

  laddr           = fd_ulong_align_up( laddr, fd_ghost_node_map_align() );
  ghost->node_map = fd_ghost_node_map_new( (void *)laddr, node_max, seed );
  laddr += fd_ghost_node_map_footprint( node_max );

  laddr            = fd_ulong_align_up( laddr, fd_ghost_vote_pool_align() );
  ghost->vote_pool = fd_ghost_vote_pool_new( (void *)laddr, vote_max );
  laddr += fd_ghost_vote_pool_footprint( vote_max );

  laddr           = fd_ulong_align_up( laddr, fd_ghost_vote_map_align() );
  ghost->vote_map = fd_ghost_vote_map_new( (void *)laddr, vote_max, seed );
  laddr += fd_ghost_vote_map_footprint( vote_max );

  laddr        = fd_ulong_align_up( laddr, fd_ghost_bfs_q_align() );
  ghost->bfs_q = fd_ghost_bfs_q_new( (void *)laddr, node_max );
  laddr += fd_ghost_bfs_q_footprint( node_max );

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
  laddr += sizeof( fd_ghost_t );

  laddr            = fd_ulong_align_up( laddr, fd_ghost_node_pool_align() );
  ghost->node_pool = fd_ghost_node_pool_join( (void *)laddr );
  ulong node_max   = fd_ghost_node_pool_max( ghost->node_pool );
  laddr += fd_ghost_node_pool_footprint( node_max );

  laddr           = fd_ulong_align_up( laddr, fd_ghost_node_map_align() );
  ghost->node_map = fd_ghost_node_map_join( (void *)laddr );
  laddr += fd_ghost_node_map_footprint( node_max );

  laddr            = fd_ulong_align_up( laddr, fd_ghost_vote_pool_align() );
  ghost->vote_pool = fd_ghost_vote_pool_join( (void *)laddr );
  ulong vote_max   = fd_ghost_vote_pool_max( ghost->vote_pool );
  laddr += fd_ghost_vote_pool_footprint( vote_max );

  laddr           = fd_ulong_align_up( laddr, fd_ghost_vote_map_align() );
  ghost->vote_map = fd_ghost_vote_map_join( (void *)laddr );
  laddr += fd_ghost_vote_map_footprint( vote_max );

  laddr        = fd_ulong_align_up( laddr, fd_ghost_bfs_q_align() );
  ghost->bfs_q = fd_ghost_bfs_q_join( (void *)laddr );
  laddr += fd_ghost_bfs_q_footprint( node_max );

  laddr = fd_ulong_align_up( laddr, fd_ghost_align() );
  FD_TEST( laddr == (ulong)shghost + fd_ghost_footprint( node_max, vote_max ) );

  return ghost;
}

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

fd_ghost_node_t *
heaviest_child( fd_ghost_node_t * parent ) {
  fd_ghost_node_t * curr     = parent->child;
  fd_ghost_node_t * heaviest = curr;
  while( curr ) {
    heaviest = FD_GHOST_NODE_MAX( curr, heaviest );
    curr     = curr->sibling;
  }
  return heaviest;
}

/* If there is a new head, update the ancestry. */

void
fd_ghost_leaf_insert( fd_ghost_t *           ghost,
                      fd_slot_hash_t const * slot_hash,
                      fd_slot_hash_t const * parent_slot_hash_opt ) {
  FD_LOG_DEBUG( ( "[ghost] inserting: %lu hash: %32J parent: %lu parent_hash: %32J",
                  slot_hash->slot,
                  slot_hash->hash.hash,
                  parent_slot_hash_opt ? parent_slot_hash_opt->slot : ULONG_MAX,
                  parent_slot_hash_opt ? parent_slot_hash_opt->hash.hash : NULL ) );

#if FD_GHOST_USE_HANDHOLDING
  /* caller promises key is not already in ghost. this is to maintain the invariant that processing
     replay votes should not result in inserting the same key twice into the ghost nodes. */
  if( FD_UNLIKELY(
          fd_ghost_node_map_ele_query( ghost->node_map, slot_hash, NULL, ghost->node_pool ) ) ) {
    FD_LOG_ERR( ( "duplicate slot_hash" ) );
  }
#endif

#if FD_GHOST_USE_HANDHOLDING
  /* SLOTS_PER_EPOCH nodes are pre-allocated. triggering this likely indicates a bug in pruning
   * logic. */
  if( FD_UNLIKELY( !fd_ghost_node_pool_free( ghost->node_pool ) ) ) {
    FD_LOG_ERR( ( "node pool full" ) ); /* OOM */
  }
#endif

  fd_ghost_node_t * node = fd_ghost_node_pool_ele_acquire( ghost->node_pool );
  node->slot_hash        = *slot_hash;
  node->stake            = 0;
  node->weight           = 0;

#if FD_GHOST_USE_HANDHOLDING
#endif

  /* map insertion */

  fd_ghost_node_map_ele_insert( ghost->node_map, node, ghost->node_pool );

  /* tree insertion */

  node->child   = NULL;
  node->sibling = NULL;

  if( FD_UNLIKELY( !parent_slot_hash_opt ) ) {
    ghost->root = node;
    return;
  }
  fd_ghost_node_t * parent =
      fd_ghost_node_map_ele_query( ghost->node_map, parent_slot_hash_opt, NULL, ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
  /* caller promises non-NULL parent_slot_hash is in ghost. */
  if( FD_UNLIKELY( !parent ) ) FD_LOG_ERR( ( "missing parent" ) );
#endif

  node->parent = parent;

  if( FD_LIKELY( !parent->child ) ) { /* no forks as likely case */
    parent->child = node;
  } else {
    fd_ghost_node_t * curr = parent->child;
    while( curr->sibling ) {
      curr = curr->sibling;
    }
    curr->sibling = node;
  }
}

fd_ghost_node_t *
fd_ghost_node_query( fd_ghost_t * ghost, fd_slot_hash_t const * key ) {
  return fd_ghost_node_map_ele_query( ghost->node_map, key, NULL, ghost->node_pool );
}

void
fd_ghost_replay_vote_upsert( fd_ghost_t *           ghost,
                             fd_slot_hash_t const * slot_hash,
                             fd_pubkey_t const *    pubkey,
                             ulong                  stake ) {
  fd_ghost_node_t * node =
      fd_ghost_node_map_ele_query( ghost->node_map, slot_hash, NULL, ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
  /* This indicates a programming error, because caller promises node is already in ghost. */
  if( FD_UNLIKELY( !node ) ) FD_LOG_ERR( ( "missing ghost node" ) );
#endif

  /* Ignore votes for slots older than the current root. */

  if( FD_UNLIKELY( slot_hash->slot < ghost->root->slot_hash.slot ) ) return;

  /* Query pubkey's previous vote. */

  fd_ghost_vote_t * vote =
      fd_ghost_vote_map_ele_query( ghost->vote_map, pubkey, NULL, ghost->vote_pool );

  if( FD_LIKELY( vote ) ) {

    /* Return early if pubkey's vote hasn't changed. */

    if( FD_SLOT_HASH_EQ( slot_hash, &vote->slot_hash ) ) return;

    fd_ghost_node_t * node =
        fd_ghost_node_map_ele_query( ghost->node_map, &vote->slot_hash, NULL, ghost->node_pool );

    if( FD_UNLIKELY( !node ) ) {

      /* Prev voted slot hash is too old and has already been pruned from ghost. */

      FD_LOG_WARNING(
          ( "prev voted slot hash (%lu, %32J) by %32J was too old and already pruned from ghost.",
            vote->slot_hash.slot,
            vote->slot_hash.hash,
            &pubkey->key ) );

    } else {

      /* Subtract pubkey's stake from the prev voted slot hash and propagate. */

      node->stake -= vote->stake;
      fd_ghost_node_t * ancestor = node;
      while( ancestor->parent ) {
        ancestor->weight -= stake;
        ancestor = ancestor->parent;
      }
    }

  } else {

    /* Ghost has not seen this pubkey vote yet, so insert. */

#if FD_GHOST_USE_HANDHOLDING
    /* We've exceeded the max # of node pubkeys that were statically allocated. */
    if( FD_UNLIKELY( !fd_ghost_vote_pool_free( ghost->vote_pool ) ) ) {
      FD_LOG_ERR( ( "vote pool full" ) ); /* OOM */
    }
#endif

    vote            = fd_ghost_vote_pool_ele_acquire( ghost->vote_pool );
    vote->pubkey    = *pubkey;
    vote->slot_hash = *slot_hash;
    vote->stake     = stake;
    fd_ghost_vote_map_ele_insert( ghost->vote_map, vote, ghost->vote_pool );
  }
  vote->slot_hash = *slot_hash;
  vote->stake     = stake;

  /* Propagate the vote stake up the ancestry, including updating the head. */

  node->stake += stake;
  fd_ghost_node_t * ancestor = node;
  while( ancestor->parent ) {
    ancestor->weight += stake;
    ancestor = ancestor->parent;
  }
}

void
fd_ghost_gossip_vote_upsert( FD_PARAM_UNUSED fd_ghost_t *           ghost,
                             FD_PARAM_UNUSED fd_slot_hash_t const * slot_hash,
                             FD_PARAM_UNUSED fd_pubkey_t const *    pubkey,
                             FD_PARAM_UNUSED ulong                  stake ) {
  FD_LOG_ERR( ( "unimplemented" ) );
}

void
fd_ghost_prune( fd_ghost_t * ghost, fd_ghost_node_t const * root ) {
  FD_PARAM_UNUSED long now = fd_log_wallclock();

  fd_ghost_node_t ** q      = ghost->bfs_q;
  fd_ghost_node_t *  remove = fd_ghost_bfs_q_pop_head( q );
  fd_ghost_bfs_q_push_tail( q, remove );
  while( !fd_ghost_bfs_q_empty( q ) ) {
    fd_ghost_node_t * remove = fd_ghost_bfs_q_pop_head( q );
    fd_ghost_node_t * curr   = remove;
    while( curr ) {
      if( FD_LIKELY( curr != root ) ) fd_ghost_bfs_q_push_tail( q, curr->child );
      curr = curr->sibling;
    }
    remove->child->parent = NULL;
    remove =
        fd_ghost_node_map_ele_remove( ghost->node_map, &remove->slot_hash, NULL, ghost->node_pool );
#if FD_GHOST_USE_HANDHOLDING
    if( FD_UNLIKELY( !remove ) ) FD_LOG_ERR( ( "unable to remove." ) );
#endif
    FD_LOG_NOTICE( ( "[fd_ghost_prune] removing %lu", remove->slot_hash.slot ) );
    fd_ghost_node_pool_ele_release( ghost->node_pool, remove );
  }
}

static void
print_node( fd_ghost_node_t * root, int space, const char * prefix, ulong total, int * has_fork ) {
  if( space > 40 ) return;
  if( root == NULL ) return;

  printf( "\n" );
  for( int i = 0; i < space; i++ ) // Print space
    printf( " " );
  double pct = ( (double)root->weight / (double)total ) * 100;
  if( FD_UNLIKELY( pct < 0.99 ) ) {
    printf( "%s%ld (%.0lf%%, %lu)", prefix, root->slot_hash.slot, pct, root->weight );
  } else {
    printf( "%s%ld (%.0lf%%)", prefix, root->slot_hash.slot, pct );
  }

  fd_ghost_node_t * curr = root->child;
  char              new_prefix[1024]; // Large enough to hold the new prefix string
  while( curr ) {
    if( curr->sibling ) {
      sprintf( new_prefix, "├── " ); // Branch indicating more siblings follow
      *has_fork = 1;
      print_node( curr, space + 4, new_prefix, total, has_fork );
    } else {
      sprintf( new_prefix, "└── " ); // End branch
      print_node( curr, space + 4, new_prefix, total, has_fork );
    }
    curr = curr->sibling;
  }
}

int
fd_ghost_print( FD_PARAM_UNUSED fd_ghost_t * ghost, fd_ghost_node_t * root, ulong total ) {
  // print_node( ghost->root, 0, "" );
  int has_fork = 0;
  print_node( root, 0, "", total, &has_fork );
  printf( "\n" );
  return has_fork;
}
