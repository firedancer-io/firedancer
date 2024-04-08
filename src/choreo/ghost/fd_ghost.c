#include "fd_ghost.h"
#include "stdio.h"
#include <string.h>

void *
fd_ghost_new( void * mem, ulong node_max, int lg_msg_max, ulong seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( node_max, lg_msg_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad node_max (%lu) or lg_msg_max (%d)", node_max, lg_msg_max ) );
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  ulong laddr = (ulong)mem;

  fd_ghost_t * ghost = (fd_ghost_t *)mem;
  ghost->root        = slot_hash_null;
  laddr              = fd_ulong_align_up( laddr + sizeof( fd_ghost_t ), fd_ghost_node_pool_align() );
  ghost->node_pool   = fd_ghost_node_pool_new( (void *)laddr, node_max );
  laddr              = fd_ulong_align_up( laddr + fd_ghost_node_pool_footprint( node_max ),
                             fd_ghost_node_map_align() );
  ghost->node_map    = fd_ghost_node_map_new( (void *)laddr, node_max, seed );
  laddr              = fd_ulong_align_up( laddr + fd_ghost_node_map_footprint( node_max ),
                             fd_ghost_msg_map_align() );
  ghost->latest_msgs = fd_ghost_msg_map_new( (void *)laddr, lg_msg_max );

  return mem;
}

fd_ghost_t *
fd_ghost_join( void * ghost ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING( ( "NULL ghost" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ghost, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned ghost" ) );
    return NULL;
  }

  fd_ghost_t * ghost_ = (fd_ghost_t *)ghost;
  ghost_->node_pool   = fd_ghost_node_pool_join( ghost_->node_pool );
  ghost_->node_map    = fd_ghost_node_map_join( ghost_->node_map );
  ghost_->latest_msgs = fd_ghost_msg_map_join( ghost_->latest_msgs );

  return ghost_;
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
                      fd_slot_hash_t const * slot_hash,
                      fd_slot_hash_t const * parent_slot_hash ) {

#if FD_GHOST_USE_HANDHOLDING
  /* this shouldn't happen, because processing replay votes should not result in inserting the same
     slot_hash again */
  if( FD_UNLIKELY(
          fd_ghost_node_map_ele_query( ghost->node_map, slot_hash, NULL, ghost->node_pool ) ) ) {
    FD_LOG_ERR( ( "duplicate slot" ) );
  }
#endif

  /* map insertion */

  fd_ghost_node_t * leaf = fd_ghost_node_pool_ele_acquire( ghost->node_pool );
#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !leaf ) ) FD_LOG_ERR( ( "fail acquire" ) ); /* OOM */
#endif
  leaf->slot_hash = *slot_hash;
  leaf->stake     = 0;
  leaf->weight    = 0;
  leaf->head      = leaf; /* by definition, a leaf is the highest weight subtree of itself */
  fd_ghost_node_map_ele_insert( ghost->node_map, leaf, ghost->node_pool );

  /* tree insertion */

  leaf->child   = NULL;
  leaf->sibling = NULL;

  if( FD_UNLIKELY( !parent_slot_hash ) ) {
    // memcpy(&ghost->root, slot_hash, sizeof(fd_slot_hash_t));
    ghost->root = *slot_hash;
    return;
  }
  fd_ghost_node_t * parent =
      fd_ghost_node_map_ele_query( ghost->node_map, parent_slot_hash, NULL, ghost->node_pool );
#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !parent ) ) FD_LOG_ERR( ( "missing parent" ) ); /* OOM */
#endif
  leaf->parent               = parent;
  fd_ghost_node_t * old_head = parent->head;
  fd_ghost_node_t * head     = old_head;

  if( FD_LIKELY( !parent->child ) ) { /* no forks as likely case */
    parent->child = leaf;
    head          = leaf; /* if leaf's parent had no children, then leaf is the new fork head */
  } else {
    fd_ghost_node_t * curr = parent->child;
    while( curr->sibling )
      curr = curr->sibling;
    curr->sibling = leaf;
    head          = FD_GHOST_NODE_MAX( parent->head, leaf );
  }

  /* if the head changed, update the ancestors */
  if( FD_LIKELY( !FD_SLOT_HASH_EQ( &head->slot_hash, &old_head->slot_hash ) ) ) {
    fd_ghost_node_t * ancestor = parent;
    while( ancestor && FD_SLOT_HASH_EQ( &ancestor->head->slot_hash, &old_head->slot_hash ) ) {
      ancestor->head = leaf;
      ancestor       = ancestor->parent;
    }
  }
}

void
fd_ghost_lmd_update( fd_ghost_t *           ghost,
                     fd_slot_hash_t const * slot_hash,
                     fd_pubkey_t const *    pubkey,
                     ulong                  stake ) {
  /* ignore msgs for slots older than the current root */
  if( FD_UNLIKELY( slot_hash->slot < ghost->root.slot ) ) return;

  /* query the latest msg */
  fd_ghost_msg_t * latest_msg = fd_ghost_msg_map_query( ghost->latest_msgs, *pubkey, NULL );

  /* subtract the vote stake from the old tree */
  if( FD_LIKELY( latest_msg ) ) {
    fd_ghost_node_t * latest_msg_node = fd_ghost_node_map_ele_query(
        ghost->node_map, &latest_msg->slot_hash, NULL, ghost->node_pool );
    latest_msg_node->stake -= latest_msg->stake;
    fd_ghost_node_t * ancestor = latest_msg_node;
    while( ancestor ) {
      ancestor->weight -= latest_msg->stake;
      ancestor = ancestor->parent;
    }
  } else {
    latest_msg = fd_ghost_msg_map_insert( ghost->latest_msgs, *pubkey );
  }

  /* add the vote stake to the new tree */
  fd_ghost_node_t * updated =
      fd_ghost_node_map_ele_query( ghost->node_map, slot_hash, NULL, ghost->node_pool );
#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !updated ) ) FD_LOG_ERR( ( "missing ghost node" ) );
#endif

  /* update the new latest msg */
  latest_msg->slot_hash = *slot_hash;
  latest_msg->stake     = stake;

  updated->stake += stake;
  fd_ghost_node_t * ancestor = updated;
  while( ancestor ) {
    ancestor->weight += stake;
    ancestor = ancestor->parent;
  }

  /* TODO more efficient to compute max on insert vs. query? */
  fd_ghost_node_t * curr           = updated->parent->child;
  fd_ghost_node_t * heaviest_child = updated;
  while( curr ) {
    heaviest_child = FD_GHOST_NODE_MAX( curr, heaviest_child );
    curr           = curr->sibling;
  }
  /* if `updated` is the new heaviest, update the ancestry to use `updated`'s head */
  if( FD_GHOST_NODE_EQ( updated, heaviest_child ) ) {
    fd_ghost_node_t * old_head = updated->parent->head;
    fd_ghost_node_t * ancestor = updated->parent;
    while( ancestor && FD_GHOST_NODE_EQ( ancestor->head, old_head ) ) {
      ancestor->head = updated->head;
      ancestor       = ancestor->parent;
    }
  }
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
fd_ghost_bfs( fd_ghost_t * ghost ) {
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
