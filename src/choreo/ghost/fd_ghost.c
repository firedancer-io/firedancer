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
  ghost->root        = FD_SLOT_HASH_NULL;
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

  laddr = fd_ulong_align_up( laddr, alignof( fd_ghost_t ) );

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
  laddr += fd_ghost_vote_map_footprint( fd_ghost_vote_map_ele_max() );

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

void
fd_ghost_leaf_insert( fd_ghost_t *           ghost,
                      fd_slot_hash_t const * key,
                      fd_slot_hash_t const * parent_key_opt ) {

#if FD_GHOST_USE_HANDHOLDING

  /* caller promises key is not already in ghost. this is to maintain the invariant that processing
     replay votes should not result in inserting the same key twice into the ghost nodes. */

  if( FD_UNLIKELY( fd_ghost_node_map_ele_query( ghost->node_map, key, NULL, ghost->node_pool ) ) ) {
    FD_LOG_ERR( ( "duplicate slot_hash" ) );
  }
#endif

#if FD_GHOST_USE_HANDHOLDING

  /* this shouldn't happen: SLOTS_PER_EPOCH nodes are pre-allocated. triggering this condition
     likely indicates a bug in pruning logic. */

  if( FD_UNLIKELY( !fd_ghost_node_pool_free( ghost->node_pool ) ) ) {
    FD_LOG_ERR( ( "node pool full" ) ); /* OOM */
  }
#endif

  fd_ghost_node_t * node = fd_ghost_node_pool_ele_acquire( ghost->node_pool );
  node->slot_hash        = *key;
  node->stake            = 0;
  node->weight           = 0;
  node->head             = node; /* by definition, a leaf is the highest weight subtree of itself */

#if FD_GHOST_USE_HANDHOLDING
  FD_LOG_NOTICE( ( "[ghost] inserting: %lu hash: %32J parent: %lu parent_hash: %32J",
                   key->slot,
                   key->hash.hash,
                   parent_key_opt ? parent_key_opt->slot : ULONG_MAX,
                   parent_key_opt ? parent_key_opt->hash.hash : NULL ) );
#endif

  /* map insertion */

  fd_ghost_node_map_ele_insert( ghost->node_map, node, ghost->node_pool );

  /* tree insertion */

  node->child   = NULL;
  node->sibling = NULL;

  if( FD_UNLIKELY( !parent_key_opt ) ) {
    ghost->root = *key;
    return;
  }
  fd_ghost_node_t * parent =
      fd_ghost_node_map_ele_query( ghost->node_map, parent_key_opt, NULL, ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING

  /* caller promises non-NULL parent_key is in ghost. */

  if( FD_UNLIKELY( !parent ) ) FD_LOG_ERR( ( "missing parent" ) );
#endif

  node->parent               = parent;
  fd_ghost_node_t * old_head = parent->head;
  fd_ghost_node_t * head     = old_head;

  if( FD_LIKELY( !parent->child ) ) { /* no forks as likely case */
    parent->child = node;
    head          = node; /* if leaf's parent had no children, then leaf is the new fork head */
  } else {
    fd_ghost_node_t * curr = parent->child;
    while( curr->sibling )
      curr = curr->sibling;
    curr->sibling = node;
    head          = FD_GHOST_NODE_MAX( parent->head, node );
  }

  /* if the head changed, update the ancestors */
  if( FD_LIKELY( !FD_SLOT_HASH_EQ( &head->slot_hash, &old_head->slot_hash ) ) ) {
    fd_ghost_node_t * ancestor = parent;
    while( ancestor && FD_SLOT_HASH_EQ( &ancestor->head->slot_hash, &old_head->slot_hash ) ) {
      ancestor->head = node;
      ancestor       = ancestor->parent;
    }
  }
}

fd_ghost_node_t *
fd_ghost_node_query( fd_ghost_t * ghost, fd_slot_hash_t const * key ) {
  return fd_ghost_node_map_ele_query( ghost->node_map, key, NULL, ghost->node_pool );
}

void
fd_ghost_replay_vote_upsert( fd_ghost_t *           ghost,
                             fd_slot_hash_t const * key,
                             fd_pubkey_t const *    pubkey,
                             ulong                  stake ) {
  fd_ghost_node_t * node =
      fd_ghost_node_map_ele_query( ghost->node_map, key, NULL, ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
  /* This indicates a programming error, because caller promises node is already in ghost. */
  if( FD_UNLIKELY( !node ) ) FD_LOG_ERR( ( "missing ghost node" ) );
#endif

  /* Ignore votes for slots older than the current root. */

  if( FD_UNLIKELY( key->slot < ghost->root.slot ) ) return;

  /* Query pubkey's previous vote. */

  fd_ghost_vote_t * vote =
      fd_ghost_vote_map_ele_query( ghost->vote_map, pubkey, NULL, ghost->vote_pool );

  /* Subtract the vote stake from the old tree. */

  if( FD_LIKELY( vote ) ) {

    /* Return early if the vote hasn't changed. */

    if( FD_SLOT_HASH_EQ( key, &vote->slot_hash ) ) return;

    /* TODO also keep track of node's stake changes to return early? */

    fd_ghost_node_t * node =
        fd_ghost_node_map_ele_query( ghost->node_map, &vote->slot_hash, NULL, ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
    /* This indicates a programming error, because if there is a vote that implies there must be a
     * node. */
    if( FD_UNLIKELY( !node ) ) FD_LOG_ERR( ( "missing ghost node that is in votes" ) );
#endif

    node->stake -= vote->stake;
    fd_ghost_node_t * ancestor = node;
    while( ancestor ) {
      ancestor->weight -= vote->stake;
      ancestor = ancestor->parent;
    }
  } else {

    /* Insert the new pubkey's vote. */

#if FD_GHOST_USE_HANDHOLDING
    /* This indicates a programming error, because we've exceeded the max # of node pubkeys that
     * were statically allocated. */
    if( FD_UNLIKELY( !fd_ghost_vote_pool_free( ghost->vote_pool ) ) ) {
      FD_LOG_ERR( ( "vote pool full" ) ); /* OOM */
    }
#endif

    vote            = fd_ghost_vote_pool_ele_acquire( ghost->vote_pool );
    vote->pubkey    = *pubkey;
    vote->slot_hash = *key;
    vote->stake     = stake;
    fd_ghost_vote_map_ele_insert( ghost->vote_map, vote, ghost->vote_pool );
  }

  /* Add the vote stake to the fork ancestry beginning at key. */

  vote->slot_hash = *key;
  vote->stake     = stake;
  node->stake += stake;
  fd_ghost_node_t * ancestor = node;
  while( ancestor ) {
    ancestor->weight += stake;
    ancestor = ancestor->parent;
  }

  /* TODO more efficient to compute max on insert vs. query? */

  fd_ghost_node_t * curr           = node;
  fd_ghost_node_t * heaviest_child = node;
  while( curr ) {
    heaviest_child = FD_GHOST_NODE_MAX( curr, heaviest_child );
    curr           = curr->sibling;
  }

  /* If node is the new heaviest, update the ancestry to use node's fork head. */

  if( node->parent && FD_GHOST_NODE_EQ( node, heaviest_child ) ) {
    fd_ghost_node_t * old_head = node->parent->head;
    fd_ghost_node_t * ancestor = node->parent;
    while( ancestor && FD_GHOST_NODE_EQ( ancestor->head, old_head ) ) {
      ancestor->head = node->head;
      ancestor       = ancestor->parent;
    }
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
fd_ghost_prune( fd_ghost_t * ghost, fd_slot_hash_t const * root ) {
  ulong          cnt                   = 0;
  fd_slot_hash_t prune_slot_hashes[64] = { 0 };
  ulong          root_slot             = root->slot;
  for( fd_ghost_node_map_iter_t iter =
           fd_ghost_node_map_iter_init( ghost->node_map, ghost->node_pool );
       !fd_ghost_node_map_iter_done( iter, ghost->node_map, ghost->node_pool );
       iter = fd_ghost_node_map_iter_next( iter, ghost->node_map, ghost->node_pool ) ) {
    fd_ghost_node_t * node = fd_ghost_node_map_iter_ele( iter, ghost->node_map, ghost->node_pool );
    if( node->slot_hash.slot < root_slot ) prune_slot_hashes[cnt++] = node->slot_hash;
  }

  for( ulong i = 0; i < cnt; i++ ) {
    fd_slot_hash_t    slot_hash = prune_slot_hashes[i];
    fd_ghost_node_t * remove =
        fd_ghost_node_map_ele_remove( ghost->node_map, &slot_hash, NULL, ghost->node_pool );

#if FD_GHOST_USE_HANDHOLDING
    /* This indicates a programming error because we marked it for removal above while iterating. */
    if( FD_UNLIKELY( !remove ) ) FD_LOG_ERR( ( "missing slot_hash marked for removal." ) );
#endif

    fd_ghost_node_pool_ele_release( ghost->node_pool, remove );
  }
  ghost->root = *root;
}

static void
fd_ghost_print_node( fd_ghost_node_t * node, int depth ) {
  if( !node ) return;
  for( int i = 0; i < depth; i++ ) {
    printf( "    " );
  }
  printf( "%lu|%lu|%lu\n", node->slot_hash.slot, node->weight, node->head->slot_hash.slot );
  fd_ghost_print_node( node->child, depth + 1 );
  fd_ghost_print_node( node->sibling, depth );
}

void
fd_ghost_print( fd_ghost_t * ghost ) {
  fd_ghost_node_t * root =
      fd_ghost_node_map_ele_query( ghost->node_map, &ghost->root, NULL, ghost->node_pool );
  fd_ghost_print_node( root, 0 );
}

#define DEQUE_NAME fd_ghost_bfs_q
#define DEQUE_T    ulong
#define DEQUE_MAX  64UL
#include "../../util/tmpl/fd_deque.c"

FD_FN_UNUSED static void
bfs( fd_ghost_t * ghost ) {
  uchar   mem[1 << 20] = { 0 };
  ulong * q            = fd_ghost_bfs_q_join( fd_ghost_bfs_q_new( mem ) );

  fd_ghost_bfs_q_push_tail( q, ghost->root.slot );
  while( !fd_ghost_bfs_q_empty( q ) ) {
    ulong             slot = fd_ghost_bfs_q_pop_head( q );
    fd_slot_hash_t    key  = { .slot = slot, .hash = pubkey_null };
    fd_ghost_node_t * node =
        fd_ghost_node_map_ele_query( ghost->node_map, &key, NULL, ghost->node_pool );
    if( !node ) FD_LOG_ERR( ( "missing bfs node" ) );
    fd_ghost_node_t * curr = node->child;
    while( curr ) {
      fd_ghost_bfs_q_push_tail( q, curr->slot_hash.slot );
      curr = curr->sibling;
    }
  }
}
