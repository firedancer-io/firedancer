#include "fd_blk_repair.h"

static void ver_inc( ulong ** ver ) {
  fd_fseq_update( *ver, fd_fseq_query( *ver ) + 1 );
}

#define VER_INC ulong * ver __attribute__((cleanup(ver_inc))) = fd_blk_repair_ver( blk_repair ); ver_inc( &ver )

void *
fd_blk_repair_new( void * shmem, ulong ele_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_blk_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_blk_repair_footprint( ele_max );
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
  fd_blk_repair_t * blk_repair;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  blk_repair      = FD_SCRATCH_ALLOC_APPEND( l, fd_blk_repair_align(),   sizeof(fd_blk_repair_t)              );
  void * ver      = FD_SCRATCH_ALLOC_APPEND( l, fd_fseq_align(),         fd_fseq_footprint()                  );
  void * pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_blk_pool_align(),     fd_blk_pool_footprint( ele_max )     );
  void * ancestry = FD_SCRATCH_ALLOC_APPEND( l, fd_blk_ancestry_align(), fd_blk_ancestry_footprint( ele_max ) );
  void * frontier = FD_SCRATCH_ALLOC_APPEND( l, fd_blk_frontier_align(), fd_blk_frontier_footprint( ele_max ) );
  void * orphaned = FD_SCRATCH_ALLOC_APPEND( l, fd_blk_orphaned_align(), fd_blk_orphaned_footprint( ele_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_blk_repair_align() ) == (ulong)shmem + footprint );

  blk_repair->wksp_gaddr     = fd_wksp_gaddr_fast( wksp, blk_repair );
  blk_repair->ver_gaddr      = fd_wksp_gaddr_fast( wksp, fd_fseq_join        ( fd_fseq_new        ( ver, FD_BLK_REPAIR_VER_UNINIT ) ) );
  blk_repair->pool_gaddr     = fd_wksp_gaddr_fast( wksp, fd_blk_pool_join    ( fd_blk_pool_new    ( pool, ele_max                 ) ) );
  blk_repair->ancestry_gaddr = fd_wksp_gaddr_fast( wksp, fd_blk_ancestry_join( fd_blk_ancestry_new( ancestry, ele_max, seed       ) ) );
  blk_repair->frontier_gaddr = fd_wksp_gaddr_fast( wksp, fd_blk_frontier_join( fd_blk_frontier_new( frontier, ele_max, seed       ) ) );
  blk_repair->orphaned_gaddr = fd_wksp_gaddr_fast( wksp, fd_blk_orphaned_join( fd_blk_orphaned_new( orphaned, ele_max, seed       ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( blk_repair->magic ) = FD_BLK_REPAIR_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_blk_repair_t *
fd_blk_repair_join( void * shblk_repair ) {
  fd_blk_repair_t * blk_repair = (fd_blk_repair_t *)shblk_repair;

  if( FD_UNLIKELY( !blk_repair ) ) {
    FD_LOG_WARNING(( "NULL blk_repair" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)blk_repair, fd_blk_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned blk_repair" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( blk_repair );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "blk_repair must be part of a workspace" ));
    return NULL;
  }

  return blk_repair;
}

void *
fd_blk_repair_leave( fd_blk_repair_t const * blk_repair ) {

  if( FD_UNLIKELY( !blk_repair ) ) {
    FD_LOG_WARNING(( "NULL blk_repair" ));
    return NULL;
  }

  return (void *)blk_repair;
}

void *
fd_blk_repair_delete( void * blk_repair ) {

  if( FD_UNLIKELY( !blk_repair ) ) {
    FD_LOG_WARNING(( "NULL blk_repair" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)blk_repair, fd_blk_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned blk_repair" ));
    return NULL;
  }

  // TODO: zero out mem?

  return blk_repair;
}

fd_blk_repair_t *
fd_blk_repair_init( fd_blk_repair_t * blk_repair, ulong root_slot ) {
  FD_TEST( blk_repair );
  FD_TEST( fd_fseq_query( fd_blk_repair_ver( blk_repair ) ) == FD_BLK_REPAIR_VER_UNINIT );

  VER_INC;

  fd_blk_ele_t *      pool     = fd_blk_pool( blk_repair );
  ulong               null     = fd_blk_pool_idx_null( pool );
  fd_blk_frontier_t * frontier = fd_blk_frontier( blk_repair );

  /* Initialize the root node from a pool element. */

  fd_blk_ele_t * root_ele = fd_blk_pool_ele_acquire( pool );
  root_ele->slot          = root_slot;
  root_ele->prev          = null;
  root_ele->parent        = null;
  root_ele->child         = null;
  root_ele->sibling       = null;
  fd_blk_ele_idxs_null( root_ele->idxs );

  blk_repair->root = fd_blk_pool_idx( pool, root_ele );
  fd_blk_frontier_ele_insert( frontier, root_ele, pool ); /* cannot fail */

  /* Sanity checks. */

  FD_TEST( root_ele );
  FD_TEST( root_ele == fd_blk_frontier_ele_query( frontier, &root_slot, NULL, pool ));
  FD_TEST( root_ele->slot == root_slot );

  return blk_repair;
}

void *
fd_blk_repair_fini( fd_blk_repair_t * blk_repair ) {
  fd_fseq_update( fd_blk_repair_ver( blk_repair ), FD_BLK_REPAIR_VER_UNINIT );
  return (void *)blk_repair;
}

int
fd_blk_repair_verify( fd_blk_repair_t const * blk_repair ) {
  if( FD_UNLIKELY( !blk_repair ) ) {
    FD_LOG_WARNING(( "NULL blk_repair" ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)blk_repair, fd_blk_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned blk_repair" ));
    return -1;
  }

  fd_wksp_t * wksp = fd_wksp_containing( blk_repair );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "blk_repair must be part of a workspace" ));
    return -1;
  }

  if( FD_UNLIKELY( blk_repair->magic!=FD_BLK_REPAIR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }

  if( FD_UNLIKELY( fd_fseq_query( fd_blk_repair_ver_const( blk_repair ) ) == ULONG_MAX ) ) {
    FD_LOG_WARNING(( "blk_repair uninitialized or invalid" ));
    return -1;
  }

  fd_blk_ele_t const * pool = fd_blk_pool_const( blk_repair );
  if( fd_blk_ancestry_verify( fd_blk_ancestry_const( blk_repair ), fd_blk_pool_max( pool ), pool ) == -1 ) return -1;
  if( fd_blk_frontier_verify( fd_blk_frontier_const( blk_repair ), fd_blk_pool_max( pool ), pool ) == -1 ) return -1;

  return 0;
}

/* query queries for a connected ele keyed by slot.  does not return
   orphaned ele. */

static fd_blk_ele_t *
tree_query( fd_blk_repair_t * blk_repair, ulong slot ) {
  fd_blk_ele_t * pool = fd_blk_pool( blk_repair );
  fd_blk_ele_t * ele  = NULL;
  ele =                  fd_blk_ancestry_ele_query( fd_blk_ancestry( blk_repair ), &slot, NULL, pool );
  ele = fd_ptr_if( !ele, fd_blk_frontier_ele_query( fd_blk_frontier( blk_repair ), &slot, NULL, pool ), ele );
  return ele;
}

/* remove removes and returns a connected ele from ancestry or frontier
   maps.  does not remove orphaned ele.  does not unlink ele. */

static fd_blk_ele_t *
tree_map_remove( fd_blk_repair_t * blk_repair, ulong slot ) {
  fd_blk_ele_t * pool = fd_blk_pool( blk_repair );
  fd_blk_ele_t * ele = NULL;
  ele =                  fd_blk_ancestry_ele_remove( fd_blk_ancestry( blk_repair ), &slot, NULL, pool );
  ele = fd_ptr_if( !ele, fd_blk_frontier_ele_remove( fd_blk_frontier( blk_repair ), &slot, NULL, pool ), ele );
  return ele;
}

/* link ele to the tree via its sibling. */

static void
link_sibling( fd_blk_repair_t * blk_repair, fd_blk_ele_t * sibling, fd_blk_ele_t * ele ) {
  fd_blk_ele_t * pool        = fd_blk_pool( blk_repair );
  ulong          null        = fd_blk_pool_idx_null( pool );
  while( FD_UNLIKELY( sibling->sibling != null ) ) {
    sibling = fd_blk_pool_ele( pool, sibling->sibling );
  }
  while( FD_UNLIKELY( sibling->sibling != null )) sibling = fd_blk_pool_ele( pool, sibling->sibling );
  sibling->sibling = fd_blk_pool_idx( pool, ele );
}

/* link child to the tree via its parent. */

static void
link( fd_blk_repair_t * blk_repair, fd_blk_ele_t * parent, fd_blk_ele_t * child ) {
  fd_blk_ele_t * pool = fd_blk_pool( blk_repair );
  ulong          null = fd_blk_pool_idx_null( pool );
  if( FD_LIKELY( parent->child == null ) ) parent->child = fd_blk_pool_idx( pool, child ); /* left-child */
  else link_sibling( blk_repair, fd_blk_pool_ele( pool, parent->child ), child );          /* right-sibling */
  child->parent = fd_blk_pool_idx( pool, parent );
}

/* link_orphans performs a BFS beginning from head using BFS.  head is
   the first element of a linked list representing the BFS queue. If the
   starting orphan is connected to the ancestry tree (ie. its parent is
   in the map), it is linked to the tree and removed from the orphaned
   map, and any of its orphaned children are added to the queue (linking
   a parent also links its direct children). Otherwise it remains in the
   orphaned map.  The BFS continues until the queue is empty. */

static void
link_orphans( fd_blk_repair_t * blk_repair, fd_blk_ele_t * head ) {
  fd_blk_ele_t *      pool     = fd_blk_pool( blk_repair );
  ulong               null     = fd_blk_pool_idx_null( pool );
  fd_blk_ancestry_t * ancestry = fd_blk_ancestry( blk_repair );
  fd_blk_orphaned_t * orphaned = fd_blk_orphaned( blk_repair );
  fd_blk_ele_t *      tail     = head;
  fd_blk_ele_t *      prev     = NULL;
  while( FD_LIKELY( head ) ) { /* while queue is non-empty */
    fd_blk_ele_t * parent = tree_query( blk_repair, head->parent );
    if( FD_LIKELY( parent ) ) {
      fd_blk_orphaned_ele_remove( orphaned, &head->parent, NULL, pool );
      link( blk_repair, parent, head ); /* link the now unorphaned `head` to parent */
      fd_blk_ele_t * child = fd_blk_orphaned_ele_query( orphaned, &head->slot, NULL, pool ); /* query head's orphaned children */
      while( FD_LIKELY( child ) ) { /* append children to frontier */
        tail->prev     = fd_blk_pool_idx( pool, child ); /* safe to overwrite prev */
        tail           = fd_blk_pool_ele( pool, tail->prev );
        tail->prev     = null;
        ulong sibling  = child->sibling;
        child->sibling = null;
        child          = fd_blk_pool_ele( pool, sibling );
      }
      fd_blk_ancestry_ele_insert( ancestry, head, pool );
    }
    prev       = head;
    head       = fd_blk_pool_ele( pool, head->prev );
    prev->prev = null;
  }
}

/* advance_frontier attempts to advance the frontier beginning from slot
   using BFS.  head is the first element of a linked list representing
   the BFS queue.  A slot can be advanced if all shreds for the block
   are received ie. consumed_idx = complete_idx. */

static void
advance_frontier( fd_blk_repair_t * blk_repair, ulong slot ) {
  fd_blk_ele_t *      pool     = fd_blk_pool( blk_repair );
  fd_blk_ancestry_t * ancestry = fd_blk_ancestry( blk_repair );
  fd_blk_frontier_t * frontier = fd_blk_frontier( blk_repair );
  fd_blk_ele_t *      head     = fd_blk_frontier_ele_query( fd_blk_frontier( blk_repair ), &slot, NULL, pool );
  fd_blk_ele_t *      tail     = head;
  while( FD_LIKELY( head ) ) {
    if( FD_LIKELY( head->consumed_idx == head->complete_idx ) ) {
      fd_blk_frontier_ele_remove( frontier, &head->slot, NULL, pool );
      fd_blk_ancestry_ele_insert( ancestry, head, pool );
      fd_blk_ele_t * child = fd_blk_pool_ele( pool, head->child );
      while( FD_LIKELY( child ) ) { /* append children to frontier */
        fd_blk_ancestry_ele_remove( ancestry, &child->slot, NULL, pool );
        fd_blk_frontier_ele_insert( frontier, child, pool );
        tail->prev     = fd_blk_pool_idx( pool, child );
        tail           = fd_blk_pool_ele( pool, tail->prev );
        tail->prev     = fd_blk_pool_idx_null( pool );
        child          = fd_blk_pool_ele( pool, child->sibling );
      }
    }
    head = fd_blk_pool_ele( pool, head->prev );
  }
}

static fd_blk_ele_t *
ele_insert( fd_blk_repair_t * blk_repair, ulong slot, ushort parent_off, uint shred_idx ) {
  fd_blk_ele_t * pool = fd_blk_pool( blk_repair );

# if FD_BLK_REPAIR_USE_HANDHOLDING
  FD_TEST( parent_off <= slot ); /* inval - caller bug */
  FD_TEST( fd_blk_pool_ele( pool, blk_repair->root ) ); /* corrupt - impl bug */
  FD_TEST( fd_blk_pool_free( pool ) ); /* oom - impl bug. check eviction logic */
# endif

  if( FD_UNLIKELY( slot <= fd_blk_pool_ele( pool, blk_repair->root )->slot ) ) return NULL; /* slot older than root */

  fd_blk_ele_t * ele  = fd_blk_pool_ele_acquire( pool );
  ulong          null = fd_blk_pool_idx_null( pool );

  ele->slot    = slot;
  ele->prev    = null;
  ele->parent  = slot - parent_off;
  ele->child   = null;
  ele->sibling = null;

  ele->received_idx = shred_idx;
  ele->consumed_idx = UINT_MAX;
  ele->complete_idx = UINT_MAX;

  fd_blk_ele_idxs_null( ele->idxs ); /* FIXME expensive */

  /* always insert ele as an orphan because we immediately try to link it after */

  fd_blk_orphaned_t * orphaned = fd_blk_orphaned( blk_repair );
  fd_blk_ele_t *      orphan   = fd_blk_orphaned_ele_query( orphaned, &ele->parent, NULL, pool );
  if( FD_UNLIKELY( orphan ) ) link_sibling( blk_repair, orphan, ele );
  else {
    fd_blk_orphaned_ele_insert( orphaned, ele, pool );
    orphan = ele;
  }
  link_orphans( blk_repair, orphan );
  return ele;
}

fd_blk_ele_t *
fd_blk_repair_shred_insert( fd_blk_repair_t * blk_repair, ulong slot, ushort parent_off, uint shred_idx ) {
  VER_INC;
  fd_blk_ele_t * pool = fd_blk_pool( blk_repair );
  if( FD_UNLIKELY( slot < fd_blk_pool_ele( pool, blk_repair->root )->slot ) ) return NULL;
  fd_blk_ele_t * ele = tree_query( blk_repair, slot );
  if( FD_UNLIKELY( !ele ) ) ele = ele_insert( blk_repair, slot, parent_off, shred_idx ); /* cannot fail */
  fd_blk_ele_idxs_insert( ele->idxs, shred_idx );
  ele->received_idx = fd_uint_max( ele->received_idx, shred_idx );
  while( fd_blk_ele_idxs_test( ele->idxs, ele->consumed_idx + 1U ) ) ele->consumed_idx++;
  advance_frontier( blk_repair, slot );
  return ele;
}

void
fd_blk_repair_shred_complete( fd_blk_repair_t * blk_repair, ulong slot, uint complete_idx ) {
  VER_INC;
  fd_blk_ele_t * ele = tree_query( blk_repair, slot );
  ele->complete_idx  = complete_idx;
  advance_frontier( blk_repair, slot );
}

fd_blk_ele_t const *
fd_blk_repair_publish( fd_blk_repair_t * blk_repair, ulong new_root_slot ) {
  FD_LOG_DEBUG(( "[%s] slot %lu", __func__, new_root_slot ));

  VER_INC;

  fd_blk_ancestry_t * ancestry = fd_blk_ancestry( blk_repair );
  fd_blk_frontier_t * frontier = fd_blk_frontier( blk_repair );
  fd_blk_ele_t *      pool     = fd_blk_pool( blk_repair );
  ulong               null     = fd_blk_pool_idx_null( pool );

  fd_blk_ele_t * old_root_ele = fd_blk_pool_ele( pool, blk_repair->root );
  fd_blk_ele_t * new_root_ele = tree_query( blk_repair, new_root_slot );

# if FD_BLK_REPAIR_USE_HANDHOLDING
  FD_TEST( new_root_slot > old_root_ele->slot ); /* caller error - inval */
  FD_TEST( new_root_ele ); /* caller error - not found */
# endif

  /* First, remove the previous root, and add it to a FIFO prune queue.
     head points to the queue head (initialized with old_root_ele). */

  fd_blk_ele_t * head = tree_map_remove( blk_repair, old_root_ele->slot );
  head->next          = null;
  fd_blk_ele_t * tail = head;

  /* Second, BFS down the tree, inserting each ele into the prune queue
     except for the new root.  Loop invariant: head always descends from
     old_root_ele and never descends from new_root_ele. */

  while( head ) {
    fd_blk_ele_t * child = fd_blk_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {
      if( FD_LIKELY( child != new_root_ele ) ) { /* do not prune new root or descendants */
        ulong idx  = fd_blk_ancestry_idx_remove( ancestry, &child->slot, null, pool );
        idx        = fd_ulong_if( idx != null, idx, fd_blk_frontier_idx_remove( frontier, &child->slot, null, pool ) );
        tail->next = idx; /* insert prune queue */
#       if FD_BLK_REPAIR_USE_HANDHOLDING
        FD_TEST( tail->next != null ); /* programming error in BFS */
#       endif
        tail       = fd_blk_pool_ele( pool, tail->next ); /* advance prune queue */
        tail->next = null;
      }
      child = fd_blk_pool_ele( pool, child->sibling );
    }
    fd_blk_ele_t * next = fd_blk_pool_ele( pool, head->next ); /* FIFO pop */
    fd_blk_pool_ele_release( pool, head ); /* free head */
    head = next;
  }

  new_root_ele->parent = null; /* unlink new root from parent */
  blk_repair->root     = fd_blk_ancestry_idx_query( ancestry, &new_root_slot, null, pool );
  return new_root_ele;
}

#include <stdio.h>

static void
preorder( fd_blk_repair_t const * blk_repair, fd_blk_ele_t const * ele ) {
  fd_blk_ele_t const * pool  = fd_blk_pool_const( blk_repair );
  fd_blk_ele_t const * child = fd_blk_pool_ele_const( pool, ele->child );
  printf( "%lu ", ele->slot );
  while( FD_LIKELY( child ) ) {
    preorder( blk_repair, child );
    child = fd_blk_pool_ele_const( pool, child->sibling );
  }
}

void
fd_blk_repair_preorder_print( fd_blk_repair_t const * blk_repair ) {
  FD_LOG_NOTICE( ( "\n\n[Preorder]" ) );
  preorder( blk_repair, fd_blk_pool_ele_const( fd_blk_pool_const( blk_repair ), blk_repair->root ) );
  printf( "\n\n" );
}

static void
print( fd_blk_repair_t const * blk_repair, fd_blk_ele_t const * ele, int space, const char * prefix ) {
  fd_blk_ele_t const * pool = fd_blk_pool_const( blk_repair );

  if( ele == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ ) printf( " " );
  printf( "%s%lu", prefix, ele->slot );

  fd_blk_ele_t const * curr = fd_blk_pool_ele_const( pool, ele->child );

  char new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( fd_blk_pool_ele_const( pool, curr->sibling ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( blk_repair, curr, space + 4, new_prefix );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( blk_repair, curr, space + 4, new_prefix );
    }
    curr = fd_blk_pool_ele_const( pool, curr->sibling );
  }
}

#define PRINT 0

void
fd_blk_repair_frontier_print( FD_PARAM_UNUSED fd_blk_repair_t const * blk_repair ) {
  #if PRINT
  printf( "\n\n[Frontier]\n" );
  fd_blk_frontier_t const * frontier = fd_blk_frontier_const( blk_repair );
  fd_blk_ele_t const * pool = fd_blk_pool_const( blk_repair );
  for( fd_blk_frontier_iter_t iter = fd_blk_frontier_iter_init( frontier, pool );
       !fd_blk_frontier_iter_done( iter, frontier, pool );
       iter = fd_blk_frontier_iter_next( iter, frontier, pool ) ) {
    fd_blk_ele_t const * ele = fd_blk_frontier_iter_ele_const( iter, frontier, pool );
    printf( "%lu ", ele->slot );
  }
  #endif
}

void
fd_blk_repair_print( fd_blk_repair_t const * blk_repair ) {
  FD_LOG_NOTICE( ( "\n\n[Ancestry]" ) );
  print( blk_repair, fd_blk_pool_ele_const( fd_blk_pool_const( blk_repair ), blk_repair->root ), 0, "" );
  fd_blk_repair_frontier_print( blk_repair );
}
