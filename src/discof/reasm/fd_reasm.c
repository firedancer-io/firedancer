#include "fd_reasm.h"
#include "fd_reasm_private.h"

#define LOGGING 0

FD_FN_CONST ulong
fd_reasm_align( void ) {
  return alignof(fd_reasm_t);
}

FD_FN_CONST ulong
fd_reasm_footprint( ulong fec_max ) {
  int lgf_max = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_reasm_t), sizeof(fd_reasm_t)            ),
      pool_align(),        pool_footprint    ( fec_max ) ),
      ancestry_align(),    ancestry_footprint( fec_max ) ),
      frontier_align(),    frontier_footprint( fec_max ) ),
      orphaned_align(),    orphaned_footprint( fec_max ) ),
      subtrees_align(),    subtrees_footprint( fec_max ) ),
      bfs_align(),         bfs_footprint     ( fec_max ) ),
      out_align(),         out_footprint     ( fec_max ) ),
      slot_mr_align(),     slot_mr_footprint ( lgf_max ) ),
    fd_reasm_align() );
}

void *
fd_reasm_new( void * shmem,
              ulong  fec_max,
              ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_reasm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_reasm_footprint( fec_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad fec_max (%lu)", fec_max ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  int lgf_max = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );

  fd_reasm_t * reasm;
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  reasm           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_reasm_t), sizeof(fd_reasm_t)            );
  void * pool     = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),        pool_footprint    ( fec_max ) );
  void * ancestry = FD_SCRATCH_ALLOC_APPEND( l, ancestry_align(),    ancestry_footprint( fec_max ) );
  void * frontier = FD_SCRATCH_ALLOC_APPEND( l, frontier_align(),    frontier_footprint( fec_max ) );
  void * orphaned = FD_SCRATCH_ALLOC_APPEND( l, orphaned_align(),    orphaned_footprint( fec_max ) );
  void * subtrees = FD_SCRATCH_ALLOC_APPEND( l, subtrees_align(),    subtrees_footprint( fec_max ) );
  void * bfs      = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),         bfs_footprint     ( fec_max ) );
  void * out      = FD_SCRATCH_ALLOC_APPEND( l, out_align(),         out_footprint     ( fec_max ) );
  void * slot_mr  = FD_SCRATCH_ALLOC_APPEND( l, slot_mr_align(),     slot_mr_footprint ( lgf_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_reasm_align() ) == (ulong)shmem + footprint );

  reasm->slot0    = ULONG_MAX;
  reasm->root     = pool_idx_null( pool                    );
  reasm->pool     = pool_new     ( pool,     fec_max       );
  reasm->ancestry = ancestry_new ( ancestry, fec_max, seed );
  reasm->frontier = frontier_new ( frontier, fec_max, seed );
  reasm->orphaned = orphaned_new ( orphaned, fec_max, seed );
  reasm->subtrees = subtrees_new ( subtrees, fec_max, seed );
  /*             */ subtreel_new ( reasm->_subtrlf         );
  reasm->bfs      = bfs_new      ( bfs,      fec_max       );
  reasm->out      = out_new      ( out,      fec_max       );
  reasm->slot_mr  = slot_mr_new  ( slot_mr,  lgf_max, seed );

  return shmem;
}

fd_reasm_t *
fd_reasm_join( void * shreasm ) {
  fd_reasm_t * reasm = (fd_reasm_t *)shreasm;

  if( FD_UNLIKELY( !reasm ) ) {
    FD_LOG_WARNING(( "NULL reasm" ));
    return NULL;
  }

  reasm->pool     = pool_join    ( reasm->pool     );
  reasm->ancestry = ancestry_join( reasm->ancestry );
  reasm->frontier = frontier_join( reasm->frontier );
  reasm->orphaned = orphaned_join( reasm->orphaned );
  reasm->subtrees = subtrees_join( reasm->subtrees );
  reasm->subtreel = subtreel_join( reasm->_subtrlf );
  reasm->bfs      = bfs_join     ( reasm->bfs      );
  reasm->out      = out_join     ( reasm->out      );
  reasm->slot_mr  = slot_mr_join ( reasm->slot_mr  );

  return reasm;
}

void *
fd_reasm_leave( fd_reasm_t * reasm ) {

  if( FD_UNLIKELY( !reasm ) ) {
    FD_LOG_WARNING(( "NULL reasm" ));
    return NULL;
  }

  return (void *)reasm;
}

void *
fd_reasm_delete( void * shreasm ) {
  fd_reasm_t * reasm = (fd_reasm_t *)shreasm;

  if( FD_UNLIKELY( !reasm ) ) {
    FD_LOG_WARNING(( "NULL reasm" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)reasm, fd_reasm_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned reasm" ));
    return NULL;
  }

  return reasm;
}

fd_reasm_fec_t       * fd_reasm_root         ( fd_reasm_t       * reasm                                 ) { return pool_ele      ( reasm->pool, reasm->root      ); }
fd_reasm_fec_t const * fd_reasm_root_const   ( fd_reasm_t const * reasm                                 ) { return pool_ele_const( reasm->pool, reasm->root      ); }
fd_reasm_fec_t       * fd_reasm_parent       ( fd_reasm_t       * reasm, fd_reasm_fec_t       * child   ) { return pool_ele      ( reasm->pool, child->parent    ); }
fd_reasm_fec_t const * fd_reasm_parent_const ( fd_reasm_t const * reasm, fd_reasm_fec_t const * child   ) { return pool_ele_const( reasm->pool, child->parent    ); }
fd_reasm_fec_t       * fd_reasm_child        ( fd_reasm_t       * reasm, fd_reasm_fec_t       * parent  ) { return pool_ele      ( reasm->pool, parent->child    ); }
fd_reasm_fec_t const * fd_reasm_child_const  ( fd_reasm_t const * reasm, fd_reasm_fec_t const * parent  ) { return pool_ele_const( reasm->pool, parent->child    ); }
fd_reasm_fec_t       * fd_reasm_sibling      ( fd_reasm_t       * reasm, fd_reasm_fec_t       * sibling ) { return pool_ele      ( reasm->pool, sibling->sibling ); }
fd_reasm_fec_t const * fd_reasm_sibling_const( fd_reasm_t const * reasm, fd_reasm_fec_t const * sibling ) { return pool_ele_const( reasm->pool, sibling->sibling ); }

ulong
fd_reasm_slot0( fd_reasm_t * reasm ) {
  return reasm->slot0;
}

ulong
fd_reasm_free( fd_reasm_t * reasm ) {
  return pool_free( reasm->pool );
}

fd_reasm_fec_t *
fd_reasm_peek( fd_reasm_t * reasm ) {
  if( FD_UNLIKELY( out_empty( reasm->out ) ) ) return NULL;
  return pool_ele( reasm->pool, *out_peek_head( reasm->out ) );
}

fd_reasm_fec_t *
fd_reasm_out( fd_reasm_t * reasm ) {
  if( FD_UNLIKELY( out_empty( reasm->out ) ) ) return NULL;
  return pool_ele( reasm->pool, out_pop_head( reasm->out ) );
}

fd_reasm_fec_t *
fd_reasm_query( fd_reasm_t const * reasm,
                fd_hash_t  const * merkle_root ) {
  fd_reasm_fec_t * fec = NULL;
  fec =                  ancestry_ele_query( reasm->ancestry, merkle_root, NULL, reasm->pool );
  fec = fd_ptr_if( !fec, frontier_ele_query( reasm->frontier, merkle_root, NULL, reasm->pool ), fec );
  fec = fd_ptr_if( !fec, orphaned_ele_query( reasm->orphaned, merkle_root, NULL, reasm->pool ), fec );
  fec = fd_ptr_if( !fec, subtrees_ele_query( reasm->subtrees, merkle_root, NULL, reasm->pool ), fec );
  return fec;
}

static void
overwrite_invalid_cmr( fd_reasm_t * reasm, fd_reasm_fec_t * child ) {
  if( FD_UNLIKELY( child->fec_set_idx==0 && !fd_reasm_query( reasm, &child->cmr ) ) ) {
    slot_mr_t * slot_mr_parent = slot_mr_query( reasm->slot_mr, child->slot - child->parent_off, NULL );
    if( FD_LIKELY( slot_mr_parent ) ) {
      fd_reasm_fec_t * parent = fd_reasm_query( reasm, &slot_mr_parent->block_id );
      if( FD_LIKELY( parent ) ) {
        FD_LOG_INFO(( "overwriting invalid cmr for FEC slot: %lu fec_set_idx: %u from %s (CMR) to %s (parent's block id)", child->slot, child->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( &child->cmr ), FD_BASE58_ENC_32_ALLOCA( &parent->key ) ));
        child->cmr = parent->key; /* use the parent's merkle root */
      }
    }
  }
}

static void
link( fd_reasm_t     * reasm,
      fd_reasm_fec_t * parent,
      fd_reasm_fec_t * child ) {
  child->parent = pool_idx( reasm->pool, parent );
  if( FD_LIKELY( parent->child == pool_idx_null( reasm->pool ) ) ) {
    parent->child = pool_idx( reasm->pool, child ); /* set as left-child. */
  } else {
    fd_reasm_fec_t * curr = pool_ele( reasm->pool, parent->child );
    while( curr->sibling != pool_idx_null( reasm->pool ) ) curr = pool_ele( reasm->pool, curr->sibling );
    curr->sibling = pool_idx( reasm->pool, child ); /* set as right-sibling. */
    if( FD_UNLIKELY( !parent->slot_complete ) ) child->eqvoc = 1; /* only the last FEC set in a slot
                                                                     can have multiple children and
                                                                     be non-equivocating */
  }
}

fd_reasm_fec_t *
fd_reasm_insert( fd_reasm_t *      reasm,
                 fd_hash_t const * merkle_root,
                 fd_hash_t const * chained_merkle_root,
                 ulong             slot,
                 uint              fec_set_idx,
                 ushort            parent_off,
                 ushort            data_cnt,
                 int               data_complete,
                 int               slot_complete,
                 int               leader ) {

# if LOGGING
  FD_LOG_NOTICE(( "inserting (%lu %u) %s %s. %u %d %d", slot, fec_set_idx, FD_BASE58_ENC_32_ALLOCA( merkle_root ), FD_BASE58_ENC_32_ALLOCA( chained_merkle_root ), data_cnt, data_complete, slot_complete ));
# endif

# if FD_REASM_USE_HANDHOLDING
  FD_TEST( pool_free( reasm->pool ) );
  FD_TEST( !fd_reasm_query( reasm, merkle_root ) );
# endif

  fd_reasm_fec_t * pool = reasm->pool;
  ulong            null = pool_idx_null( pool );

  ancestry_t * ancestry = reasm->ancestry;
  frontier_t * frontier = reasm->frontier;
  orphaned_t * orphaned = reasm->orphaned;
  subtrees_t * subtrees = reasm->subtrees;
  subtreel_t * subtreel = reasm->subtreel;

  ulong * bfs = reasm->bfs;
  ulong * out = reasm->out;

  fd_reasm_fec_t * fec = pool_ele_acquire( pool );
  fec->key             = *merkle_root;
  fec->next            = null;
  fec->parent          = null;
  fec->child           = null;
  fec->sibling         = null;
  fec->slot            = slot;
  fec->parent_off      = parent_off;
  fec->fec_set_idx     = fec_set_idx;
  fec->data_cnt        = data_cnt;
  fec->free            = 0;
  fec->data_complete   = data_complete;
  fec->slot_complete   = slot_complete;
  fec->leader          = leader;
  fec->eqvoc           = 0;
  fec->bank_idx        = null;
  fec->parent_bank_idx = null;

  if( FD_UNLIKELY( !chained_merkle_root ) ) { /* initialize the reasm with the root */
    FD_TEST( reasm->root==pool_idx_null( reasm->pool )         );
    slot_mr_t * slot_mr = slot_mr_insert( reasm->slot_mr, slot );
    slot_mr->block_id   = fec->key;
    reasm->root         = pool_idx( pool, fec );
    reasm->slot0        = slot;
    frontier_ele_insert( reasm->frontier, fec, pool );
    return fec;
  }

  fec->cmr = *chained_merkle_root;

  /* This is a gross case reasm needs to handle because Agave currently
     does not validate chained merkle roots across slots ie. if a leader
     sends a bad chained merkle root on a slot boundary, the cluster
     might converge on the leader's block anyways.  So we overwrite the
     chained merkle root based on the slot and parent_off metadata.
     There are two cases: 1. we receive the parent before the child.  In
     this case we just overwrite the child's CMR.  2. we receive the
     child before the parent.  In this case every time we receive a new
     FEC set we need to check the orphan roots for whether we can link
     the orphan to the new FEC via slot metadata, since the chained
     merkle root metadata on that orphan root might be wrong. */

  if( FD_UNLIKELY( slot_complete ) ) {
    slot_mr_t * slot_mr = slot_mr_query( reasm->slot_mr, slot, NULL );
    if( FD_UNLIKELY( slot_mr ) ) {
      FD_LOG_WARNING(( "equivocating block_id for FEC slot: %lu fec_set_idx: %u prev: %s curr: %s", fec->slot, fec->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( &slot_mr->block_id ), FD_BASE58_ENC_32_ALLOCA( &fec->key ) )); /* it's possible there's equivocation... */
    } else {
      slot_mr           = slot_mr_insert( reasm->slot_mr, slot );
      slot_mr->block_id = fec->key;
    }
  }
  overwrite_invalid_cmr( reasm, fec ); /* handle receiving parent before child */

  /* First, we search for the parent of this new FEC and link if found.
     The new FEC set may result in a new leaf or a new orphan tree root
     so we need to check that. */

  fd_reasm_fec_t * parent = NULL;
  ulong            idx    = pool_idx( pool, fec );
  if(        FD_LIKELY ( parent = ancestry_ele_query ( ancestry, &fec->cmr, NULL, pool ) ) ) { /* parent is connected non-leaf */
    frontier_ele_insert( frontier, fec,    pool );
    out_push_tail      ( out,      idx          );
  } else if( FD_LIKELY ( parent = frontier_ele_remove( frontier, &fec->cmr, NULL, pool ) ) ) { /* parent is connected leaf     */
    ancestry_ele_insert( ancestry, parent, pool );
    frontier_ele_insert( frontier, fec,    pool );
    out_push_tail( out, pool_idx( pool, fec ) );
  } else if( FD_LIKELY( parent = orphaned_ele_query ( orphaned, &fec->cmr, NULL, pool ) ) ) { /* parent is orphaned non-root */
    orphaned_ele_insert( orphaned, fec, pool );
  } else if( FD_LIKELY( parent = subtrees_ele_query ( subtrees, &fec->cmr, NULL, pool ) ) ) { /* parent is orphaned root     */
    orphaned_ele_insert( orphaned, fec, pool );
  } else {                                                                                    /* parent not found            */
    subtrees_ele_insert   ( subtrees, fec, pool );
    subtreel_ele_push_tail( subtreel, fec, pool );
  }

  if( FD_LIKELY( parent ) ) link( reasm, parent, fec );

  /* Second, we search for children of this new FEC and link them to it.
     By definition any children must be orphaned (a child cannot be part
     of a connected tree before its parent).  Therefore, we only search
     through the orphaned subtrees.  As part of this operation, we also
     coalesce connected orphans into the same tree.  This way we only
     need to search the orphan tree roots (vs. all orphaned nodes). */

  FD_TEST( bfs_empty( bfs ) );
  for( subtreel_iter_t iter = subtreel_iter_fwd_init(       subtreel, pool );
                             !subtreel_iter_done    ( iter, subtreel, pool );
                       iter = subtreel_iter_fwd_next( iter, subtreel, pool ) ) {
    bfs_push_tail( bfs, subtreel_iter_idx( iter, subtreel, pool ) );
  }
  while( FD_LIKELY( !bfs_empty( bfs ) ) ) { /* link orphan subtrees to the new FEC */
    fd_reasm_fec_t * orphan_root = pool_ele( reasm->pool, bfs_pop_head( bfs ) );
    overwrite_invalid_cmr( reasm, orphan_root ); /* handle receiving child before parent */
    if( FD_LIKELY( orphan_root && 0==memcmp( orphan_root->cmr.uc, fec->key.uc, sizeof(fd_hash_t) ) ) ) { /* this orphan_root is a direct child of fec */
      link( reasm, fec, orphan_root );
      subtrees_ele_remove( subtrees, &orphan_root->key, NULL, pool );
      subtreel_ele_remove( subtreel, orphan_root,             pool );
      orphaned_ele_insert( orphaned, orphan_root,             pool );
    }
  }

  /* Third, we advance the frontier outward beginning from fec as we may
     have connected orphaned descendants to fec in the above step.  This
     does a BFS outward from fec until it reaches leaves, moving fec and
     its non-leaf descendants into ancestry and leaves into frontier.

     parent (ancestry)     orphan root  (subtrees)
       |                        |
      fec   (frontier)     orphan child (orphaned)

     parent
       |
      fec         <- frontier is here
       |
     orphan root
       |
     orphan child <- advance to here */

  if( FD_LIKELY( frontier_ele_query( frontier, &fec->key, NULL, pool ) ) ) bfs_push_tail( bfs, pool_idx( pool, fec ) );
  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_reasm_fec_t * parent  = pool_ele( pool, bfs_pop_head( bfs ) );
    fd_reasm_fec_t * child = pool_ele( pool, parent->child );
    if( FD_LIKELY( child ) ) {
      frontier_ele_remove( frontier, &parent->key, NULL, pool );
      ancestry_ele_insert( ancestry, parent,             pool );
    }
    while( FD_LIKELY( child ) ) {
      FD_TEST( orphaned_ele_remove( orphaned, &child->key, NULL, pool ) );
      frontier_ele_insert( frontier, child,              pool );
      bfs_push_tail( bfs, pool_idx( pool, child ) );
      out_push_tail( out, pool_idx( pool, child ) );
      child = pool_ele( pool, child->sibling );
    }
  }
  return fec;
}

static fd_reasm_fec_t *
publish_remove( fd_reasm_t *      reasm,
                fd_hash_t const * merkle_root ) {
  fd_reasm_fec_t *          fec = ancestry_ele_remove( reasm->ancestry, merkle_root, NULL, reasm->pool );
  if( FD_UNLIKELY( !fec ) ) fec = frontier_ele_remove( reasm->frontier, merkle_root, NULL, reasm->pool );
  return fec;
}

fd_reasm_fec_t *
fd_reasm_publish( fd_reasm_t * reasm, fd_hash_t const * merkle_root ) {
# if FD_REASM_USE_HANDHOLDING
  if( FD_UNLIKELY( !pool_ele( reasm->pool, reasm->root ) ) ) { FD_LOG_WARNING(( "missing root"                                                     )); return NULL; }
  if( FD_UNLIKELY( !fd_reasm_query( reasm, merkle_root ) ) ) { FD_LOG_WARNING(( "merkle root %s not found", FD_BASE58_ENC_32_ALLOCA( merkle_root ) )); return NULL; }
# endif

  fd_reasm_fec_t *  pool = reasm->pool;
  ulong             null = pool_idx_null( pool );
  fd_reasm_fec_t  * oldr = pool_ele( pool, reasm->root );
  fd_reasm_fec_t  * newr = fd_reasm_query( reasm, merkle_root );

  /* First, remove the previous root, and push it as the first element
     of the BFS queue. */

  fd_reasm_fec_t * head = publish_remove( reasm, &oldr->key ); /* initialize BFS queue */
  head->next            = null;                                /* clear map next */
  fd_reasm_fec_t * tail = head;                                /* tail of BFS queue */

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  while( FD_LIKELY( head ) ) {
    fd_reasm_fec_t * child = pool_ele( pool, head->child );                  /* left-child */
    while( FD_LIKELY( child ) ) {                                            /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                     /* stop at new root */
        tail->next = pool_idx( pool, publish_remove( reasm, &child->key ) ); /* remove node from map to reuse `.next` */
        tail       = pool_ele( pool, tail->next );                           /* push onto BFS queue (so descendants can be pruned) */
        tail->next = null;                                                   /* clear map next */
      }
      child = pool_ele( pool, child->sibling );                              /* right-sibling */
    }
    slot_mr_t * slot_mr = slot_mr_query( reasm->slot_mr, head->slot, NULL );
    if( FD_UNLIKELY( slot_mr ) ) slot_mr_remove( reasm->slot_mr, slot_mr  ); /* only first FEC */

    fd_reasm_fec_t * next = pool_ele( pool, head->next ); /* pophead */
    pool_ele_release( pool, head );                       /* release */
    head->free = 1;
    head = next;                                          /* advance */
  }

  /* Clear out any stale, pruned entries from the out queue. */
  ulong deq_cnt = out_cnt( reasm->out );
  for( ulong i=0UL; i<deq_cnt; i++ ) {
    ulong idx = out_pop_head( reasm->out );
    if( FD_LIKELY( pool_ele( pool, idx )->free==0 ) ) out_push_tail( reasm->out, idx );
  }

  newr->parent = null;                   /* unlink old root */
  reasm->root  = pool_idx( pool, newr ); /* replace with new root */
  return newr;
}

#include <stdio.h>

FD_FN_UNUSED static void
print( fd_reasm_t const * reasm, fd_reasm_fec_t const * fec, int space, const char * prefix ) {
  fd_reasm_fec_t * pool = reasm->pool;

  if( fec == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ ) printf( " " );
  printf( "%s%s", prefix, FD_BASE58_ENC_32_ALLOCA( &fec->key ) );

  fd_reasm_fec_t const * curr = pool_ele_const( pool, fec->child );
  char new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( pool_ele_const( pool, curr->sibling ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( reasm, curr, space + 4, new_prefix );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( reasm, curr, space + 4, new_prefix );
    }
    curr = pool_ele_const( pool, curr->sibling );
  }
}

void
fd_reasm_print( fd_reasm_t const * reasm, fd_wksp_t * wksp, fd_wksp_t * reasm_wksp ) {
  FD_LOG_NOTICE( ( "\n\n[Reasm]" ) );
  fd_reasm_fec_t * pool     = fd_wksp_laddr_fast( wksp, fd_wksp_gaddr_fast( reasm_wksp, reasm->pool ) );
  frontier_t     * frontier = fd_wksp_laddr_fast( wksp, fd_wksp_gaddr_fast( reasm_wksp, reasm->frontier ) );
  subtrees_t     * subtrees = fd_wksp_laddr_fast( wksp, fd_wksp_gaddr_fast( reasm_wksp, reasm->subtrees ) );

  printf(("\n\n[Frontier]\n" ) );
  for( frontier_iter_t iter = frontier_iter_init(       frontier, pool );
                             !frontier_iter_done( iter, frontier, pool );
                       iter = frontier_iter_next( iter, frontier, pool ) ) {
    fd_reasm_fec_t const * fec = pool_ele_const( pool, iter.ele_idx );
    printf( "(%lu, %u) %s\n", fec->slot, fec->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( &fec->key ) );
  }

  printf(("\n\n[Subtrees]\n" ) );
  for( subtrees_iter_t iter = subtrees_iter_init(       subtrees, pool );
                             !subtrees_iter_done( iter, subtrees, pool );
                       iter = subtrees_iter_next( iter, subtrees, pool ) ) {
    fd_reasm_fec_t const * fec = pool_ele_const( pool, iter.ele_idx );
    printf( "(%lu, %u) %s\n", fec->slot, fec->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( &fec->key ) );
  }

  // print( reasm, pool_ele_const( reasm->pool, reasm->root ), 0, "" );
  // printf( "\n\n" );
  // for( out_iter_t iter = out_iter_init( reasm->out ); !out_iter_done( reasm->out, iter ); iter = out_iter_next( reasm->out, iter ) ) {
  //   ulong * idx = out_iter_ele( reasm->out, iter );
  //   printf( "%s\n", FD_BASE58_ENC_32_ALLOCA( pool_ele_const( reasm->pool, *idx ) ) );
  // }
  printf( "\n\n" );
}
