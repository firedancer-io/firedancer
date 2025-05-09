#include "fd_forest.h"

static void ver_inc( ulong ** ver ) {
  fd_fseq_update( *ver, fd_fseq_query( *ver ) + 1 );
}

#define VER_INC ulong * ver __attribute__((cleanup(ver_inc))) = fd_forest_ver( forest ); ver_inc( &ver )

void *
fd_forest_new( void * shmem, ulong ele_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_forest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_forest_footprint( ele_max );
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
  fd_forest_t * forest;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  forest          = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_align(),          sizeof(fd_forest_t)                     );
  void * ver      = FD_SCRATCH_ALLOC_APPEND( l, fd_fseq_align(),            fd_fseq_footprint()                     );
  void * pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_pool_align(),     fd_forest_pool_footprint( ele_max )     );
  void * ancestry = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_ancestry_align(), fd_forest_ancestry_footprint( ele_max ) );
  void * frontier = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_frontier_align(), fd_forest_frontier_footprint( ele_max ) );
  void * orphaned = FD_SCRATCH_ALLOC_APPEND( l, fd_forest_orphaned_align(), fd_forest_orphaned_footprint( ele_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_forest_align() ) == (ulong)shmem + footprint );

  forest->root           = ULONG_MAX;
  forest->wksp_gaddr     = fd_wksp_gaddr_fast( wksp, forest );
  forest->ver_gaddr      = fd_wksp_gaddr_fast( wksp, fd_fseq_join           ( fd_fseq_new        ( ver, FD_FOREST_VER_UNINIT ) ) );
  forest->pool_gaddr     = fd_wksp_gaddr_fast( wksp, fd_forest_pool_join    ( fd_forest_pool_new    ( pool, ele_max                 ) ) );
  forest->ancestry_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_ancestry_join( fd_forest_ancestry_new( ancestry, ele_max, seed       ) ) );
  forest->frontier_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_frontier_join( fd_forest_frontier_new( frontier, ele_max, seed       ) ) );
  forest->orphaned_gaddr = fd_wksp_gaddr_fast( wksp, fd_forest_orphaned_join( fd_forest_orphaned_new( orphaned, ele_max, seed       ) ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( forest->magic ) = FD_FOREST_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_forest_t *
fd_forest_join( void * shforest ) {
  fd_forest_t * forest = (fd_forest_t *)shforest;

  if( FD_UNLIKELY( !forest ) ) {
    FD_LOG_WARNING(( "NULL forest" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)forest, fd_forest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned forest" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( forest );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "forest must be part of a workspace" ));
    return NULL;
  }

  return forest;
}

void *
fd_forest_leave( fd_forest_t const * forest ) {

  if( FD_UNLIKELY( !forest ) ) {
    FD_LOG_WARNING(( "NULL forest" ));
    return NULL;
  }

  return (void *)forest;
}

void *
fd_forest_delete( void * forest ) {

  if( FD_UNLIKELY( !forest ) ) {
    FD_LOG_WARNING(( "NULL forest" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)forest, fd_forest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned forest" ));
    return NULL;
  }

  // TODO: zero out mem?

  return forest;
}

fd_forest_t *
fd_forest_init( fd_forest_t * forest, ulong root_slot ) {
  FD_TEST( forest );
  FD_TEST( fd_fseq_query( fd_forest_ver( forest ) ) == FD_FOREST_VER_UNINIT );

  VER_INC;

  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );

  /* Initialize the root node from a pool element. */

  fd_forest_ele_t * root_ele = fd_forest_pool_ele_acquire( pool );
  root_ele->slot             = root_slot;
  root_ele->prev             = null;
  root_ele->parent           = null;
  root_ele->child            = null;
  root_ele->sibling          = null;
  root_ele->buffered_idx     = 0;
  root_ele->complete_idx     = 0;

  fd_forest_ele_idxs_null( root_ele->idxs );

  forest->root = fd_forest_pool_idx( pool, root_ele );
  fd_forest_frontier_ele_insert( frontier, root_ele, pool ); /* cannot fail */

  /* Sanity checks. */

  FD_TEST( root_ele );
  FD_TEST( root_ele == fd_forest_frontier_ele_query( frontier, &root_slot, NULL, pool ));
  FD_TEST( root_ele->slot == root_slot );

  return forest;
}

void *
fd_forest_fini( fd_forest_t * forest ) {
  fd_fseq_update( fd_forest_ver( forest ), FD_FOREST_VER_UNINIT );
  return (void *)forest;
}

int
fd_forest_verify( fd_forest_t const * forest ) {
  if( FD_UNLIKELY( !forest ) ) {
    FD_LOG_WARNING(( "NULL forest" ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)forest, fd_forest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned forest" ));
    return -1;
  }

  fd_wksp_t * wksp = fd_wksp_containing( forest );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "forest must be part of a workspace" ));
    return -1;
  }

  if( FD_UNLIKELY( forest->magic!=FD_FOREST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }

  if( FD_UNLIKELY( fd_fseq_query( fd_forest_ver_const( forest ) ) == ULONG_MAX ) ) {
    FD_LOG_WARNING(( "forest uninitialized or invalid" ));
    return -1;
  }

  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  if( fd_forest_ancestry_verify( fd_forest_ancestry_const( forest ), fd_forest_pool_max( pool ), pool ) == -1 ) return -1;
  if( fd_forest_frontier_verify( fd_forest_frontier_const( forest ), fd_forest_pool_max( pool ), pool ) == -1 ) return -1;

  return 0;
}

/* query queries for a connected ele keyed by slot.  does not return
   orphaned ele. */

static fd_forest_ele_t *
ancestry_frontier_query( fd_forest_t * forest, ulong slot ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  fd_forest_ele_t * ele  = NULL;
  ele =                  fd_forest_ancestry_ele_query( fd_forest_ancestry( forest ), &slot, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &slot, NULL, pool ), ele );
  return ele;
}

/* remove removes and returns a connected ele from ancestry or frontier
   maps.  does not remove orphaned ele.  does not unlink ele. */

static fd_forest_ele_t *
ancestry_frontier_remove( fd_forest_t * forest, ulong slot ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  fd_forest_ele_t * ele  = NULL;
  ele =                  fd_forest_ancestry_ele_remove( fd_forest_ancestry( forest ), &slot, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_remove( fd_forest_frontier( forest ), &slot, NULL, pool ), ele );
  return ele;
}

/* link ele to the tree via its sibling. */

static void
link_sibling( fd_forest_t * forest, fd_forest_ele_t * sibling, fd_forest_ele_t * ele ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  ulong             null = fd_forest_pool_idx_null( pool );
  while( FD_UNLIKELY( sibling->sibling != null )) sibling = fd_forest_pool_ele( pool, sibling->sibling );
  sibling->sibling = fd_forest_pool_idx( pool, ele );
}

/* link child to the tree via its parent. */

static void
link( fd_forest_t * forest, fd_forest_ele_t * parent, fd_forest_ele_t * child ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  ulong             null = fd_forest_pool_idx_null( pool );
  if( FD_LIKELY( parent->child == null ) ) parent->child = fd_forest_pool_idx( pool, child ); /* left-child */
  else link_sibling( forest, fd_forest_pool_ele( pool, parent->child ), child );          /* right-sibling */
  child->parent = fd_forest_pool_idx( pool, parent );
}

/* link_orphans performs a BFS beginning from head using BFS.  head is
   the first element of a linked list representing the BFS queue. If the
   starting orphan is connected to the ancestry tree (ie. its parent is
   in the map), it is linked to the tree and removed from the orphaned
   map, and any of its orphaned children are added to the queue (linking
   a parent also links its direct children). Otherwise it remains in the
   orphaned map.  The BFS continues until the queue is empty. */

FD_FN_UNUSED static void
link_orphans( fd_forest_t * forest, fd_forest_ele_t * head ) {
  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_ancestry_t * ancestry = fd_forest_ancestry( forest );
  fd_forest_orphaned_t * orphaned = fd_forest_orphaned( forest );
  fd_forest_ele_t *      tail     = head;
  fd_forest_ele_t *      prev     = NULL;
  while( FD_LIKELY( head ) ) { /* while queue is non-empty */
    if( FD_LIKELY( fd_forest_orphaned_ele_remove( orphaned, &head->slot, NULL, pool ) ) ) { /* head is orphan root */
      fd_forest_ancestry_ele_insert( ancestry, head, pool );
      fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
      while( FD_LIKELY( child ) ) { /* append children to frontier */
        tail->prev     = fd_forest_pool_idx( pool, child ); /* safe to overwrite prev */
        tail           = fd_forest_pool_ele( pool, tail->prev );
        tail->prev     = null;
        ulong sibling  = child->sibling;
        child->sibling = null;
        child          = fd_forest_pool_ele( pool, sibling );
      }
    }
    prev       = head;
    head       = fd_forest_pool_ele( pool, head->prev );
    prev->prev = null;
  }
}

/* advance_frontier attempts to advance the frontier beginning from slot
   using BFS.  head is the first element of a linked list representing
   the BFS queue.  A slot can be advanced if all shreds for the block
   are received ie. consumed_idx = complete_idx. */

static void
advance_frontier( fd_forest_t * forest, ulong slot, ushort parent_off ) {
  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );
  fd_forest_ancestry_t * ancestry = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );

  fd_forest_ele_t * ele;
  ele = fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &slot, NULL, pool );
  ulong parent_slot = slot - parent_off;
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_query( fd_forest_frontier( forest ), &parent_slot, NULL, pool ), ele );

  fd_forest_ele_t * head = ele;
  fd_forest_ele_t * tail = head;
  fd_forest_ele_t * prev = NULL;

  while( FD_LIKELY( head ) ) {
    fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
    if( FD_LIKELY( child && head->complete_idx != UINT_MAX && head->buffered_idx == head->complete_idx ) ) {
      fd_forest_frontier_ele_remove( frontier, &head->slot, NULL, pool );
      fd_forest_ancestry_ele_insert( ancestry, head, pool );
      while( FD_LIKELY( child ) ) { /* append children to frontier */
        fd_forest_ancestry_ele_remove( ancestry, &child->slot, NULL, pool );
        fd_forest_frontier_ele_insert( frontier, child, pool );
        tail->prev     = fd_forest_pool_idx( pool, child );
        tail           = fd_forest_pool_ele( pool, tail->prev );
        tail->prev     = fd_forest_pool_idx_null( pool );
        child          = fd_forest_pool_ele( pool, child->sibling );
      }
    }
    prev       = head;
    head       = fd_forest_pool_ele( pool, head->prev );
    prev->prev = null;
  }
}

static fd_forest_ele_t *
query( fd_forest_t * forest, ulong slot ) {
  fd_forest_ele_t *      pool        = fd_forest_pool( forest );
  fd_forest_ancestry_t * ancestry    = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier    = fd_forest_frontier( forest );
  fd_forest_orphaned_t * orphaned    = fd_forest_orphaned( forest );

  fd_forest_ele_t * ele;
  ele =                  fd_forest_ancestry_ele_query( ancestry, &slot, NULL, pool );
  ele = fd_ptr_if( !ele, fd_forest_frontier_ele_query( frontier, &slot, NULL, pool ), ele );
  ele = fd_ptr_if( !ele, fd_forest_orphaned_ele_query( orphaned, &slot, NULL, pool ), ele );
  return ele;
}

static fd_forest_ele_t *
acquire( fd_forest_t * forest, ulong slot ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );
  fd_forest_ele_t * ele  = fd_forest_pool_ele_acquire( pool );
  ulong             null = fd_forest_pool_idx_null( pool );

  ele->slot    = slot;
  ele->prev    = null;
  ele->next    = null;
  ele->parent  = null;
  ele->child   = null;
  ele->sibling = null;

  ele->buffered_idx = UINT_MAX;
  ele->complete_idx = UINT_MAX;

  fd_forest_ele_idxs_null( ele->cmpl ); /* FIXME expensive */
  fd_forest_ele_idxs_null( ele->fecs ); /* FIXME expensive */
  fd_forest_ele_idxs_null( ele->idxs ); /* FIXME expensive */

  return ele;
}

static fd_forest_ele_t *
insert( fd_forest_t * forest, ulong slot, ushort parent_off ) {
  fd_forest_ele_t * pool = fd_forest_pool( forest );

# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( parent_off <= slot );                   /* caller err - inval */
  FD_TEST( fd_forest_pool_free( pool ) );          /* impl err - oom */
  FD_TEST( slot > fd_forest_root_slot( forest ) ); /* caller error - inval */
# endif

  fd_forest_ele_t * ele         = acquire( forest, slot );
  ulong             parent_slot = slot - parent_off;
  fd_forest_ele_t * parent      = query( forest, parent_slot );
  if( FD_LIKELY( parent ) ) {
    fd_forest_ancestry_ele_insert( fd_forest_ancestry( forest ), ele, pool );
    link( forest, parent, ele ); /* cannot fail */
  }
  return ele;
}

fd_forest_ele_t *
fd_forest_query( fd_forest_t * forest, ulong slot ) {
# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( slot > fd_forest_root_slot( forest ) ); /* caller error - inval */
# endif
  return query( forest, slot );
}

fd_forest_ele_t *
fd_forest_data_shred_insert( fd_forest_t * forest, ulong slot, ushort parent_off, uint shred_idx, uint fec_set_idx, FD_PARAM_UNUSED int data_complete, int slot_complete ) {
# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( slot > fd_forest_root_slot( forest ) ); /* caller error - inval */
# endif

  VER_INC;

  fd_forest_ele_t * pool = fd_forest_pool( forest );
  fd_forest_ele_t * ele  = query( forest, slot );
  if( FD_UNLIKELY( !ele ) ) ele = insert( forest, slot, parent_off ); /* cannot fail */
  if( FD_UNLIKELY( ele->parent == fd_forest_pool_idx_null( pool ) ) ) {

    /* `ele` is an orphan tree root so it does not have a parent. Now,
       having received a shred for ele, we know ele's parent
       slot. Here we check whether ele's parent is already in the tree.
       If it is, then the orphan tree rooted at ele can be linked to the
       tree containing ele's parent (which may be another orphan tree or
       the canonical tree). */

    fd_forest_ele_t * parent = query( forest, slot - parent_off );
    if( FD_UNLIKELY( !parent ) ) {  /* parent is either in canonical or another orphan tree */
      parent = acquire( forest, slot - parent_off );
      fd_forest_orphaned_ele_insert( fd_forest_orphaned( forest ), parent, pool ); /* update orphan root */
    }
    fd_forest_orphaned_ele_remove( fd_forest_orphaned( forest ), &ele->slot, NULL, pool );
    fd_forest_ancestry_ele_insert( fd_forest_ancestry( forest ), ele, pool );
    link( forest, parent, ele );
  }
  fd_forest_ele_idxs_insert( ele->fecs, fec_set_idx );
  fd_forest_ele_idxs_insert( ele->idxs, shred_idx );
  while( fd_forest_ele_idxs_test( ele->idxs, ele->buffered_idx + 1U ) ) ele->buffered_idx++;
  ele->complete_idx = fd_uint_if( slot_complete, shred_idx, ele->complete_idx );
  advance_frontier( forest, slot, parent_off );
  return ele;
}

fd_forest_ele_t const *
fd_forest_publish( fd_forest_t * forest, ulong new_root_slot ) {
  FD_LOG_DEBUG(( "[%s] slot %lu", __func__, new_root_slot ));

  VER_INC;

  fd_forest_ancestry_t * ancestry = fd_forest_ancestry( forest );
  fd_forest_frontier_t * frontier = fd_forest_frontier( forest );
  fd_forest_ele_t *      pool     = fd_forest_pool( forest );
  ulong                  null     = fd_forest_pool_idx_null( pool );

  fd_forest_ele_t * old_root_ele = fd_forest_pool_ele( pool, forest->root );
  fd_forest_ele_t * new_root_ele = ancestry_frontier_query( forest, new_root_slot );

# if FD_FOREST_USE_HANDHOLDING
  FD_TEST( new_root_ele );                            /* caller error - not found */
  FD_TEST( new_root_ele->slot > old_root_ele->slot ); /* caller error - inval */
# endif

  /* First, remove the previous root, and add it to a FIFO prune queue.
     head points to the queue head (initialized with old_root_ele). */

  fd_forest_ele_t * head = ancestry_frontier_remove( forest, old_root_ele->slot );
  head->next          = null;
  fd_forest_ele_t * tail = head;

  /* Second, BFS down the tree, inserting each ele into the prune queue
     except for the new root.  Loop invariant: head always descends from
     old_root_ele and never descends from new_root_ele. */

  while( head ) {
    fd_forest_ele_t * child = fd_forest_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {
      if( FD_LIKELY( child != new_root_ele ) ) { /* do not prune new root or descendants */
        ulong idx  = fd_forest_ancestry_idx_remove( ancestry, &child->slot, null, pool );
        idx        = fd_ulong_if( idx != null, idx, fd_forest_frontier_idx_remove( frontier, &child->slot, null, pool ) );
        tail->next = idx; /* insert prune queue */
#       if FD_FOREST_USE_HANDHOLDING
        FD_TEST( tail->next != null ); /* programming error in BFS */
#       endif
        tail       = fd_forest_pool_ele( pool, tail->next ); /* advance prune queue */
        tail->next = null;
      }
      child = fd_forest_pool_ele( pool, child->sibling );
    }
    fd_forest_ele_t * next = fd_forest_pool_ele( pool, head->next ); /* FIFO pop */
    fd_forest_pool_ele_release( pool, head ); /* free head */
    head = next;
  }

  new_root_ele->parent = null; /* unlink new root from parent */
  forest->root     = fd_forest_ancestry_idx_query( ancestry, &new_root_slot, null, pool );
  return new_root_ele;
}

#include <stdio.h>

static void
preorder( fd_forest_t const * forest, fd_forest_ele_t const * ele ) {
  fd_forest_ele_t const * pool  = fd_forest_pool_const( forest );
  fd_forest_ele_t const * child = fd_forest_pool_ele_const( pool, ele->child );
  printf( "%lu ", ele->slot );
  while( FD_LIKELY( child ) ) {
    preorder( forest, child );
    child = fd_forest_pool_ele_const( pool, child->sibling );
  }
}

void
fd_forest_preorder_print( fd_forest_t const * forest ) {
  FD_LOG_NOTICE( ( "\n\n[Preorder]" ) );
  preorder( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), forest->root ) );
  printf( "\n\n" );
}

/* TODO use bit tricks / change */
static int
num_digits( ulong slot ) {
  /* using log10 */
  int digits = 0;
  while( slot ) {
    digits++;
    slot /= 10;
  }
  return digits;
}

static void
ancestry_print2( fd_forest_t const * forest,
                 fd_forest_ele_t const    * ele,
                 fd_forest_ele_t const    * prev,
                 ulong        last_printed,
                 int          depth,
                 const char * prefix ) {

  if( FD_UNLIKELY( ele == NULL ) ) return;

  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  int digits = num_digits( ele->slot );

  /* If there is a prefix, this means we are on a fork,  and we need to
     indent to the correct depth. We do depth - 1 for more satisfying
     spacing. */
  if( FD_UNLIKELY( strcmp( prefix, "" ) ) ) {
    for( int i = 0; i < depth - 1; i++ ) printf( " " );
    if( depth > 0 ) printf( "%s", prefix );
  }

  if ( FD_UNLIKELY( !prev ) ) { // New interval
    printf("[%lu" , ele->slot );
    last_printed = ele->slot;
    depth       += 1 + digits;
  }

  fd_forest_ele_t const * curr = fd_forest_pool_ele_const( pool, ele->child );

  /* Cases in which we close the interval:
     1. the slots are no longer consecutive. no eliding, close bracket
     2. current ele has multiple children, want to print forks.
     Maintain last_printed on this fork so that we don't print [a, a]
     intervals. */

  fd_forest_ele_t const * new_prev = ele;

  if( prev && prev->slot != ele->slot - 1 ) { // non-consecutive, do not elide
    if( last_printed == prev->slot ){
      printf( "] ── [%lu", ele->slot );
      depth += digits + 6;
    } else {
      printf( ", %lu] ── [%lu", prev->slot, ele->slot );
      depth += digits + num_digits(prev->slot ) + 8;
    }
    last_printed = ele->slot;
  } else if( curr && curr->sibling != ULONG_MAX ) { // has multiple children, do not elide
    if( last_printed == ele->slot ){
      printf( "] ── " );
      depth += 5;
    } else {
      printf( ", %lu] ── ", ele->slot );
      depth += digits + 2;
    }
    last_printed = ele->slot;
    new_prev = NULL;
  }

  if( !curr ){ // no children, close bracket, end fork
    if( last_printed == ele->slot ){
      printf( "]\n" );
    } else {
      printf( ", %lu]\n", ele->slot );
    }
    return;
  }

  char new_prefix[512]; /* FIXME size this correctly */
  new_prefix[0] = '\0'; /* first fork stays on the same line, no prefix */
  while( curr ) {
    if( fd_forest_pool_ele_const( pool, curr->sibling ) ) {
      ancestry_print2( forest, curr, new_prev, last_printed, depth, new_prefix );
    } else {
      ancestry_print2( forest, curr, new_prev, last_printed, depth, new_prefix );
    }
    curr = fd_forest_pool_ele_const( pool, curr->sibling );

    /* Set up prefix for following iterations */
    if( curr && curr->sibling != ULONG_MAX ) {
      sprintf( new_prefix, "├── " ); /* any following forks start on new lines */
    } else {
      sprintf( new_prefix, "└── " ); /* any following forks start on new lines */
    }
  }

}

static void FD_FN_UNUSED
ancestry_print( fd_forest_t const * forest, fd_forest_ele_t const * ele, int space, const char * prefix ) {
  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );

  if( ele == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ ) printf( " " );
  if ( ele->complete_idx == UINT_MAX ) printf( "%s%lu (%u/?)", prefix, ele->slot, ele->buffered_idx + 1 );
  else printf( "%s%lu (%u/%u)", prefix, ele->slot, ele->buffered_idx + 1, ele->complete_idx + 1 );

  fd_forest_ele_t const * curr = fd_forest_pool_ele_const( pool, ele->child );

  char new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( fd_forest_pool_ele_const( pool, curr->sibling ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      ancestry_print( forest, curr, space + 4, new_prefix );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      ancestry_print( forest, curr, space + 4, new_prefix );
    }
    curr = fd_forest_pool_ele_const( pool, curr->sibling );
  }
}

static void
ancestry_print3( fd_forest_t const * forest, fd_forest_ele_t const * ele, int space, const char * prefix, fd_forest_ele_t const * prev, int elide ) {
  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );

  if( ele == NULL ) return;

  /* print the slot itself. either we might need to start a new interval, or it may get elided */
  fd_forest_ele_t const * child = fd_forest_pool_ele_const( pool, ele->child );

  if( !elide ) {
    if( space > 0 ) printf( "\n" );
    for( int i = 0; i < space; i++ ) printf( " " );
    printf( "%s", prefix );
    printf( "%lu", ele->slot );
  }

  if( !child && !elide ) { /* double check these cases arent the same...*/
    printf( "]" );
    return;
  } /* no children, close bracket */

  if( !child && elide ) {
    printf( ", %lu]", ele->slot );
    return;
  }

  prev = ele;
  char new_prefix[1024]; /* FIXME size this correctly */
  int one_child = child && child->sibling == ULONG_MAX;
  if( one_child &&
      child->slot != ele->slot + 1 ) { // if I have ONE CHILD and one child is non-consecutive

    if( elide ) {
      /* current slot wasn't printed, but now that we are branching,
         we will want to print the current slot and close the bracket */
      printf( ", %lu]", ele->slot );
      space += fd_int_max( num_digits( ele->slot ) + 2, 0 );
    } else {
      printf( "]");
    }

    sprintf( new_prefix, "└── [" ); /* end branch */
    ancestry_print3( forest, child, space + 5, new_prefix, prev, 0 );
  } else if ( one_child && child->slot == ele->slot + 1 ) {
    ancestry_print3( forest, child, space, prefix, prev, 1);
  } else { /* multiple children */
    if( elide ) {
      /* current slot wasn't printed, but now that we are branching,
         we will want to print the current slot and close the bracket */
      printf( ", %lu]", ele->slot );
      space += fd_int_max( num_digits( ele->slot ) + 2, 0 );
    } else {
      printf( "]");
    }

    while( child ) {
      if( fd_forest_pool_ele_const( pool, child->sibling ) ) {
        sprintf( new_prefix, "├── [" ); /* branch indicating more siblings follow */
        ancestry_print3( forest, child, space + 5, new_prefix, prev, 0 );
      } else {
        sprintf( new_prefix, "└── [" ); /* end branch */
        ancestry_print3( forest, child, space + 5, new_prefix, prev, 0 );
      }
      child = fd_forest_pool_ele_const( pool, child->sibling );
    }
  }
}

void
fd_forest_ancestry_print( fd_forest_t const * forest ) {
  FD_LOG_NOTICE(("\n\n[Ancestry]\n\n" ) );

  ancestry_print3( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), forest->root ), 0, "[", NULL, 0 );
  //ancestry_print( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), forest->root ), 0, "" );

}

void
fd_forest_frontier_print( fd_forest_t const * forest ) {
  printf( "\n\n[Frontier]\n" );
  fd_forest_ele_t const *      pool     = fd_forest_pool_const( forest );
  fd_forest_frontier_t const * frontier = fd_forest_frontier_const( forest );
  for( fd_forest_frontier_iter_t iter = fd_forest_frontier_iter_init( frontier, pool );
       !fd_forest_frontier_iter_done( iter, frontier, pool );
       iter = fd_forest_frontier_iter_next( iter, frontier, pool ) ) {
    fd_forest_ele_t const * ele = fd_forest_frontier_iter_ele_const( iter, frontier, pool );
    printf("%lu (%u/%u)\n", ele->slot, ele->buffered_idx + 1, ele->complete_idx + 1 );
   //ancestry_print( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), fd_forest_pool_idx( pool, ele ) ), 0, "" );
  }
}

void
fd_forest_orphaned_print( fd_forest_t const * forest ) {
  printf( "\n\n[Orphaned]\n" );
  fd_forest_orphaned_t const * orphaned = fd_forest_orphaned_const( forest );
  fd_forest_ele_t const * pool = fd_forest_pool_const( forest );
  for( fd_forest_orphaned_iter_t iter = fd_forest_orphaned_iter_init( orphaned, pool );
       !fd_forest_orphaned_iter_done( iter, orphaned, pool );
       iter = fd_forest_orphaned_iter_next( iter, orphaned, pool ) ) {
    fd_forest_ele_t const * ele = fd_forest_orphaned_iter_ele_const( iter, orphaned, pool );
    ancestry_print2( forest, fd_forest_pool_ele_const( fd_forest_pool_const( forest ), fd_forest_pool_idx( pool, ele ) ), NULL, 0, 0, "" );
  }
}

void
fd_forest_print( fd_forest_t const * forest ) {
  if( FD_UNLIKELY( forest->root == ULONG_MAX ) ) return;
  fd_forest_ancestry_print( forest );
  fd_forest_frontier_print( forest );
  fd_forest_orphaned_print( forest );
  printf("\n\n");
}
