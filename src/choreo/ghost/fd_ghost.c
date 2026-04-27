#include "fd_ghost.h"

#define POOL_NAME blk_pool
#define POOL_T    fd_ghost_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               blk_map
#define MAP_ELE_T              fd_ghost_blk_t
#define MAP_KEY                id
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME vtr_pool
#define POOL_T    fd_ghost_vtr_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               vtr_map
#define MAP_ELE_T              fd_ghost_vtr_t
#define MAP_KEY                addr
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_pubkey_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_pubkey_t)))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

/* fd_ghost_t is the top-level structure that holds the root of the
   tree, as well as the memory pools and map structures for tracking
   ghost blocks and voters.

   These structures are bump-allocated and laid out contiguously in
   memory from the fd_ghost_t * pointer which points to the beginning of
   the memory region.

   ---------------------- <- fd_ghost_t *
   | root               |
   ----------------------
   | pool               |
   ----------------------
   | blk_map            |
   ----------------------
   | vtr_map            |
   ---------------------- */

typedef fd_ghost_blk_t blk_pool_t;
typedef fd_ghost_vtr_t vtr_pool_t;

struct __attribute__((aligned(128UL))) fd_ghost {
  ulong          root;     /* pool idx of the root tree element */
  blk_pool_t *   blk_pool; /* pool of ghost blocks */
  blk_map_t *    blk_map;  /* map chain of ghost blocks */
  vtr_pool_t *   vtr_pool; /* pool of ghost voters */
  vtr_map_t *    vtr_map;  /* map chain of ghost voters */
  ulong          width;    /* incrementally updated width of the fork tree */
};

ulong
fd_ghost_align( void ) {
  return alignof(fd_ghost_t);
}

ulong
fd_ghost_footprint( ulong blk_max,
                    ulong vtr_max ) {
  ulong blk_chain_cnt = blk_map_chain_cnt_est( blk_max );
  ulong vtr_chain_cnt = vtr_map_chain_cnt_est( vtr_max );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_ghost_t), sizeof(fd_ghost_t)                  ),
      blk_pool_align(),    blk_pool_footprint( blk_max )       ),
      blk_map_align(),     blk_map_footprint ( blk_chain_cnt ) ),
      vtr_pool_align(),    vtr_pool_footprint( vtr_max )       ),
      vtr_map_align(),     vtr_map_footprint ( vtr_chain_cnt ) ),
    fd_ghost_align() );
}

void *
fd_ghost_new( void * shmem,
              ulong  blk_max,
              ulong  vtr_max,
              ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( blk_max, vtr_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad blk_max (%lu)", blk_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  ulong blk_chain_cnt = blk_map_chain_cnt_est( blk_max );
  ulong vtr_chain_cnt = vtr_map_chain_cnt_est( vtr_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ghost_t * ghost        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ghost_t), sizeof(fd_ghost_t)                  );
  void *       blk_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, blk_pool_align(),    blk_pool_footprint( blk_max )       );
  void *       blk_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, blk_map_align(),     blk_map_footprint ( blk_chain_cnt ) );
  void *       vtr_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, vtr_pool_align(),    vtr_pool_footprint( vtr_max )       );
  void *       vtr_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),     vtr_map_footprint ( vtr_chain_cnt ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_ghost_align() ) == (ulong)shmem + footprint );

  ghost->root     = ULONG_MAX;
  ghost->blk_pool = blk_pool_join( blk_pool_new( blk_pool_mem, blk_max             ) );
  ghost->blk_map  = blk_map_join ( blk_map_new ( blk_map_mem,  blk_chain_cnt, seed ) );
  ghost->vtr_pool = vtr_pool_join( vtr_pool_new( vtr_pool_mem, vtr_max             ) );
  ghost->vtr_map  = vtr_map_join ( vtr_map_new ( vtr_map_mem,  vtr_chain_cnt, seed ) );

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

fd_ghost_blk_t *
fd_ghost_root( fd_ghost_t * ghost ) {
  return blk_pool_ele( ghost->blk_pool, ghost->root );
}

fd_ghost_blk_t *
fd_ghost_parent( fd_ghost_t * ghost, fd_ghost_blk_t * blk ) {
  return blk_pool_ele( ghost->blk_pool, blk->parent );
}

fd_ghost_blk_t *
fd_ghost_query( fd_ghost_t       * ghost,
                fd_hash_t  const * block_id ) {
  return blk_map_ele_query( ghost->blk_map, block_id, NULL, ghost->blk_pool );
}

fd_ghost_blk_t *
fd_ghost_best( fd_ghost_t     * ghost,
               fd_ghost_blk_t * root ) {
  blk_pool_t *     pool = ghost->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  fd_ghost_blk_t * best = root;
  while( FD_LIKELY( best->child != null ) ) {
    int              valid = 0; /* at least one child is valid */
    fd_ghost_blk_t * child = blk_pool_ele( pool, best->child );
    while( FD_LIKELY( child ) ) { /* greedily pick the heaviest valid child */
      if( FD_LIKELY( child->valid ) ) {
        if( FD_LIKELY( !valid ) ) { /* this is the first valid child, so progress the head */
          best  = child;
          valid = 1;
        }

        /* When stake is equal, tie-break by lower slot.  Two valid
           children with equal stake and equal slot (ie. equivocating
           blocks) cannot occur: equivocating blocks are marked valid=0,
           so at most one of them would be valid unless multiple blocks
           for that slot are duplicate confirmed, which is a consensus
           invariant violation. */

        best = fd_ptr_if(
          fd_int_if(
            child->stake == best->stake,   /* if the weights are equal */
            child->slot  <  best->slot,    /* then tie-break by lower slot number */
            child->stake >  best->stake ), /* else return heavier */
          child, best );
      }
      child = blk_pool_ele( pool, child->sibling );
    }
    if( FD_UNLIKELY( !valid ) ) break; /* no children are valid, so short-circuit traversal */
  }
  return best;
}

fd_ghost_blk_t *
fd_ghost_deepest( fd_ghost_t     * ghost,
                  fd_ghost_blk_t * root ) {
  blk_pool_t *     pool = ghost->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  fd_ghost_blk_t * head = blk_map_ele_remove( ghost->blk_map, &root->id, NULL, pool ); /* remove ele from map to reuse `.next` */
  fd_ghost_blk_t * tail = head;
  fd_ghost_blk_t * prev = NULL;

  /* Below is a level-order traversal (BFS), returning the last leaf
     which is guaranteed to return an element of the max depth.

     It temporarily removes elements of the map when pushing onto the
     BFS queue to reuse the .next pointer and then inserts back into
     the map on queue pop. */

  head->next = null;
  while( FD_LIKELY( head ) ) {
    fd_ghost_blk_t const * child = blk_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {
      FD_TEST( blk_map_ele_remove( ghost->blk_map, &child->id, NULL, pool ) ); /* in the tree so must be in the map */
      tail->next = blk_pool_idx( pool, child );
      tail       = blk_pool_ele( pool, tail->next );
      tail->next = blk_pool_idx_null( pool );
      child      = blk_pool_ele( pool, child->sibling ); /* next sibling */
    }
    fd_ghost_blk_t * next = blk_pool_ele( pool, head->next ); /* pop prune queue head */
    blk_map_ele_insert( ghost->blk_map, head, pool );       /* re-insert head into map */
    prev = head;
    head = next;
  }
  return prev;
}

#define PREDICATE_ANCESTOR( predicate ) do {                          \
    fd_ghost_blk_t * ancestor = descendant;                           \
    while( FD_LIKELY( ancestor ) ) {                                  \
      if( FD_LIKELY( predicate ) ) return ancestor;                   \
      ancestor = blk_pool_ele( ghost->blk_pool, ancestor->parent ); \
    }                                                                 \
    return NULL;                                                      \
  } while(0)

fd_ghost_blk_t *
fd_ghost_ancestor( fd_ghost_t      * ghost,
                   fd_ghost_blk_t  * descendant,
                   fd_hash_t const * ancestor_id ) {
  PREDICATE_ANCESTOR( 0==memcmp( &ancestor->id, ancestor_id, sizeof(fd_hash_t) ) );
}

fd_ghost_blk_t *
fd_ghost_slot_ancestor( fd_ghost_t     * ghost,
                        fd_ghost_blk_t * descendant,
                        ulong            slot ) {
  PREDICATE_ANCESTOR( ancestor->slot == slot );
}

fd_ghost_blk_t *
fd_ghost_invalid_ancestor( fd_ghost_t     * ghost,
                           fd_ghost_blk_t * descendant ) {
  PREDICATE_ANCESTOR( !ancestor->valid );
}

static fd_ghost_blk_t *
insert( fd_ghost_t      * ghost,
        ulong             slot,
        fd_hash_t const * block_id ) {
  fd_ghost_blk_t * pool = ghost->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  fd_ghost_blk_t * blk  = blk_map_ele_query( ghost->blk_map, block_id, NULL, pool );

  FD_TEST( !blk ); /* duplicate insert */
  FD_TEST( blk_pool_free( pool ) ); /* ghost full */

  blk              = blk_pool_ele_acquire( pool );
  blk->id          = *block_id;
  blk->slot        = slot;
  blk->next        = null;
  blk->parent      = null;
  blk->child       = null;
  blk->sibling     = null;
  blk->stake       = 0;
  blk->total_stake = 0;
  blk->valid       = 1;
  blk_map_ele_insert( ghost->blk_map, blk, pool );
  return blk;
}

fd_ghost_blk_t *
fd_ghost_init( fd_ghost_t      * ghost,
               ulong             slot,
               fd_hash_t const * block_id ) {
  fd_ghost_blk_t * blk = insert( ghost, slot, block_id );
  ghost->root          = blk_pool_idx( ghost->blk_pool, blk );
  ghost->width         = 1;
  return blk;
}

fd_ghost_blk_t *
fd_ghost_insert( fd_ghost_t      * ghost,
                 ulong             slot,
                 fd_hash_t const * block_id,
                 fd_hash_t const * parent_block_id ) {
  fd_ghost_blk_t * blk    = insert( ghost, slot, block_id );
  fd_ghost_blk_t * pool   = ghost->blk_pool;
  ulong            null   = blk_pool_idx_null( pool );
  fd_ghost_blk_t * parent = blk_map_ele_query( ghost->blk_map, parent_block_id, NULL, pool );
  FD_TEST( parent ); /* parent must exist be in ghost */
  blk->parent  = blk_pool_idx( pool, parent );
  if( FD_LIKELY( parent->child == null ) ) {
    parent->child = blk_pool_idx( pool, blk );    /* left-child */
  } else {
    fd_ghost_blk_t * sibling = blk_pool_ele( pool, parent->child );
    while( sibling->sibling != null ) sibling = blk_pool_ele( pool, sibling->sibling );
    sibling->sibling = blk_pool_idx( pool, blk ); /* right-sibling */
    ghost->width++;
  }

  return blk;
}

int
fd_ghost_count_vote( fd_ghost_t *        ghost,
                     fd_ghost_blk_t *    blk,
                     fd_pubkey_t const * vote_acc,
                     ulong               stake,
                     ulong               slot ) {

  fd_ghost_blk_t const * root = fd_ghost_root( ghost );
  fd_ghost_vtr_t *       vtr  = vtr_map_ele_query( ghost->vtr_map, vote_acc, NULL, ghost->vtr_pool );

  if( FD_UNLIKELY( slot==ULONG_MAX  ) ) return FD_GHOST_ERR_NOT_VOTED;
  if( FD_UNLIKELY( slot< root->slot ) ) return FD_GHOST_ERR_VOTE_TOO_OLD;

  if( FD_UNLIKELY( !vtr ) ) {

    /* This vote account address has not previously voted, so add it to
       the map of voters. */

    vtr       = vtr_pool_ele_acquire( ghost->vtr_pool );
    vtr->addr = *vote_acc;
    vtr_map_ele_insert( ghost->vtr_map, vtr, ghost->vtr_pool );

  } else {

    /* Only process the vote if it is not the same as the previous vote
       and also that the vote slot is most recent.  It's possible for
       ghost to process votes out of order because votes happen in
       replay order which is concurrent across different forks.

       For example, if a voter votes for 3 then switches to 5, we might
       observe the vote for 5 before the vote for 3. */

    if( FD_UNLIKELY( !( slot > vtr->prev_slot ) ) ) return FD_GHOST_ERR_ALREADY_VOTED;

    /* LMD-rule: subtract the voter's stake from the entire fork they
      previously voted for. */

    /* TODO can optimize this if they're voting for the same fork */

    fd_ghost_blk_t * ancestor = blk_map_ele_query( ghost->blk_map, &vtr->prev_block_id, NULL, ghost->blk_pool );
    while( FD_LIKELY( ancestor ) ) {
      int cf = __builtin_usubl_overflow( ancestor->stake, vtr->prev_stake, &ancestor->stake );
      if( FD_UNLIKELY( cf ) ) {
        FD_BASE58_ENCODE_32_BYTES( ancestor->id.key, ancestor_id_b58 );
        FD_LOG_CRIT(( "[%s] overflow (after): %lu. subtracted: %lu. (slot %lu, block_id: %s)", __func__, ancestor->stake, vtr->prev_stake, ancestor->slot, ancestor_id_b58 ));
      }
      ancestor = blk_pool_ele( ghost->blk_pool, ancestor->parent );
    }
  }

  /* Add voter's stake to the entire fork they are voting for. Propagate
     the vote stake up the ancestry. We do this for all cases we exited
     above: this vote is the first vote we've seen from a pubkey, this
     vote is switched from a previous vote that was on a missing ele
     (pruned), or the regular case. */

  fd_ghost_blk_t * ancestor = blk;
  while( FD_LIKELY( ancestor ) ) {
    int cf = __builtin_uaddl_overflow( ancestor->stake, stake, &ancestor->stake );
    if( FD_UNLIKELY( cf ) ) {
      FD_BASE58_ENCODE_32_BYTES( ancestor->id.key, ancestor_id_b58 );
      FD_LOG_CRIT(( "[%s] overflow (after): %lu. added: %lu. (slot %lu, block_id: %s)", __func__, ancestor->stake, stake, ancestor->slot, ancestor_id_b58 ));
    }
    ancestor = blk_pool_ele( ghost->blk_pool, ancestor->parent );
  }
  vtr->prev_block_id = blk->id;
  vtr->prev_stake    = stake;
  vtr->prev_slot     = slot;
  return FD_GHOST_SUCCESS;
}

void
fd_ghost_publish( fd_ghost_t     * ghost,
                  fd_ghost_blk_t * newr ) {

  fd_ghost_blk_t * pool = ghost->blk_pool;
  ulong            null = blk_pool_idx_null( pool );
  fd_ghost_blk_t * oldr = fd_ghost_root( ghost );

  if( FD_UNLIKELY( oldr==newr ) ) return;

  /* First, remove the previous root, and add it to the prune list. In
     this context, head is the list head (not to be confused with the
     ghost head.) */

  fd_ghost_blk_t * head = blk_map_ele_remove( ghost->blk_map, &oldr->id, NULL, pool ); /* remove ele from map to reuse `.next` */
  fd_ghost_blk_t * tail = head;

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors.

         oldr
          |
          X
         / \
      newr   Y
              |
              Z

         ...

        newr

    BFS starts with oldr.  Its child is X.  X != newr, so X gets
    enqueued. oldr is released.  Next head = X. X's children are newr
    and Y.  newr is skipped.  Y gets enqueued.  X is released.  Next
    head = Y.  Y's child Z gets enqueued.  Y released.  Z released.
    Queue is empty, loop ends.

       oldr
     /    \
    A     newr
          /   \
         B     C

      ...

     newr
     /   \
    B     C


    The BFS starts with oldr.  Its children are A and newr.  A gets
    enqueued for pruning.  newr is skipped (line 374).  Then oldr is
    released.  Next, head = A.  A has no children.  A is released.
    Queue is empty, loop ends. */

  head->next = null;
  while( FD_LIKELY( head ) ) {
    fd_ghost_blk_t * child = blk_pool_ele( ghost->blk_pool, head->child );
    while( FD_LIKELY( child ) ) {                                                    /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                             /* stop at new root */
        tail->next = blk_map_idx_remove( ghost->blk_map, &child->id, null, pool ); /* remove ele from map to reuse `.next` */
        FD_BASE58_ENCODE_32_BYTES( child->id.key, block_id_cstr );
        tail       = blk_pool_ele( ghost->blk_pool, tail->next );                  /* push onto prune queue (so descendants can be pruned) */
        tail->next = blk_pool_idx_null( ghost->blk_pool );
      }
      child = blk_pool_ele( ghost->blk_pool, child->sibling ); /* next sibling */
      ghost->width -= !!child; /* has a sibling == a fork to be pruned */
    }
    fd_ghost_blk_t * next = blk_pool_ele( ghost->blk_pool, head->next ); /* pop prune queue head */
    blk_pool_ele_release( ghost->blk_pool, head );                       /* free prune queue head */
    head = next;                                                           /* move prune queue head forward */
  }
  newr->parent = null;                                    /* unlink old root */
  ghost->root  = blk_pool_idx( ghost->blk_pool, newr ); /* replace with new root */
}

/* mark_invalid marks the entire subtree beginning from root as invalid.
   Implementation is iterative pre-order traversal using O(1) space. */

static void
mark_invalid( fd_ghost_t     * ghost,
              fd_ghost_blk_t * root ) {
  fd_ghost_blk_t * pool = ghost->blk_pool;
  fd_ghost_blk_t * curr = root;

  /* Loop invariant: curr has not been visited.

     Before: curr = root, which has not been visited.  Trivially true.

     After: curr is set to either a child (step 2) or a right sibling of
     an ancestor found during backtracking (step 3).  Preorder visits
     parents before children and left before right, so neither has been
     visited yet.  If backtracking reaches root (step 4), loop exits. */

  for(;;) {

    /* 1. Visit: mark the current curr invalid. */

    curr->valid = 0;

    /* 2. Descend: if the curr has a child, pivot to it. */

    fd_ghost_blk_t * child = blk_pool_ele( pool, curr->child );
    if( FD_LIKELY( child ) ) { curr = child; continue; }

    /* 3. Backtrack: if the curr is a leaf, traverse up until we find an
          ancestor with a right sibling, then pivot to that sibling. */

    while( FD_LIKELY( curr!=root ) ) {
      fd_ghost_blk_t * sibling = blk_pool_ele( pool, curr->sibling );
      if( FD_LIKELY( sibling ) ) { curr = sibling; break; }
      curr = blk_pool_ele( pool, curr->parent );
    }

    /* 4. Terminate: if we backtrack all the way to root, the traversal
          is complete. */

    if( FD_UNLIKELY( curr==root ) ) break;
  }
}

void
fd_ghost_confirm( fd_ghost_t      * ghost,
                  fd_hash_t const * confirmed_block_id ) {
  fd_ghost_blk_t * pool = ghost->blk_pool;
  fd_ghost_blk_t * blk  = blk_map_ele_query( ghost->blk_map, confirmed_block_id, NULL, pool );
  if( FD_UNLIKELY( !blk ) ) return;

  /* Mark the confirmed block and its ancestors as valid, short-
     circuiting at the first ancestor that is already valid. */

  fd_ghost_blk_t * anc = blk;
  while( FD_LIKELY( anc ) ) {
    if( FD_LIKELY( anc->valid ) ) break;
    anc->valid = 1;
    anc = blk_pool_ele( pool, anc->parent );
  }
}

void
fd_ghost_eqvoc( fd_ghost_t      * ghost,
                fd_hash_t const * block_id ) {
  fd_ghost_blk_t * pool = ghost->blk_pool;
  fd_ghost_blk_t * blk  = blk_map_ele_query( ghost->blk_map, block_id, NULL, pool );
  if( FD_UNLIKELY( !blk ) ) return;
  mark_invalid( ghost, blk );
}

ulong
fd_ghost_width( fd_ghost_t * ghost ) {
  return ghost->width;
}

fd_ghost_blk_t *
fd_ghost_blk_map_remove( fd_ghost_t     * ghost,
                         fd_ghost_blk_t * blk ) {
  return blk_map_ele_remove( ghost->blk_map, &blk->id, NULL, ghost->blk_pool );
}

void
fd_ghost_blk_map_insert( fd_ghost_t     * ghost,
                         fd_ghost_blk_t * blk ) {
  blk_map_ele_insert( ghost->blk_map, blk, ghost->blk_pool );
}

fd_ghost_blk_t *
fd_ghost_blk_child( fd_ghost_t     * ghost,
                    fd_ghost_blk_t * blk ) {
  return blk_pool_ele( ghost->blk_pool, blk->child );
}

fd_ghost_blk_t *
fd_ghost_blk_sibling( fd_ghost_t     * ghost,
                      fd_ghost_blk_t * blk ) {
  return blk_pool_ele( ghost->blk_pool, blk->sibling );
}

fd_ghost_blk_t *
fd_ghost_blk_next( fd_ghost_t     * ghost,
                   fd_ghost_blk_t * blk ) {
  return blk_pool_ele( ghost->blk_pool, blk->next );
}

ulong
fd_ghost_blk_idx( fd_ghost_t     * ghost,
                  fd_ghost_blk_t * blk ) {
  return blk_pool_idx( ghost->blk_pool, blk );
}

ulong
fd_ghost_blk_idx_null( fd_ghost_t * ghost ) {
  return blk_pool_idx_null( ghost->blk_pool );
}

int
fd_ghost_verify( fd_ghost_t * ghost ) {
  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ghost, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ghost" ));
    return -1;
  }

  fd_ghost_blk_t const * pool = ghost->blk_pool;

  /* Check every ele that exists in pool exists in map. */

  if( blk_map_verify( ghost->blk_map, blk_pool_max( pool ), pool ) ) return -1;

  return 0;
}

#include <stdio.h>
#include <string.h>

#define BUF_MAX 4096
#define DEPTH_MAX 512

static void
to_cstr( fd_ghost_t const *     ghost,
         fd_ghost_blk_t const * ele,
         ulong                  total_stake,
         int                    space,
         const char *           prefix,
         char *                 cstr,
         ulong                  len,
         ulong *                off,
         ulong                  depth ) {
  if( FD_UNLIKELY( depth>DEPTH_MAX ) ) return;

  fd_ghost_blk_t const * pool = (blk_pool_t const *)ghost->blk_pool;
  int n;

  if( FD_UNLIKELY( ele == NULL ) ) return;

  if( FD_LIKELY( space > 0 ) && *off < len ) {
    cstr[(*off)++] = '\n';
  }

  for( int i = 0; i < space && *off < len; i++ ) {
    cstr[(*off)++] = ' ';
  }

  if( FD_UNLIKELY( ele->stake > 100 ) ) {
  }

  if( FD_UNLIKELY( total_stake == 0 ) ) {
    if( *off < len ) {
      n = snprintf( cstr + *off, len - *off, "%s%lu (%lu)", prefix, ele->slot, ele->stake );
      if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
      *off += (ulong)n;
    }
  } else {
    double pct = ( (double)ele->stake / (double)total_stake ) * 100;
    if( FD_UNLIKELY( pct < 0.99 ) ) {
      if( *off < len ) {
        n = snprintf( cstr + *off, len - *off, "%s%lu (%.0lf%%, %lu)", prefix, ele->slot, pct, ele->stake );
        if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
        *off += (ulong)n;
      }
    } else {
      if( *off < len ) {
        n = snprintf( cstr + *off, len - *off, "%s%lu (%.0lf%%)", prefix, ele->slot, pct );
        if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
        *off += (ulong)n;
      }
    }
  }

  fd_ghost_blk_t const * curr = blk_pool_ele_const( pool, ele->child );

  while( curr ) {
    char const * next_prefix = blk_pool_ele_const( pool, curr->sibling ) ? "├── " : "└── ";
    to_cstr( ghost, curr, total_stake, space + 4, next_prefix, cstr, len, off, depth + 1 ); /* TODO remove recursion */
    curr = blk_pool_ele_const( pool, curr->sibling );
  }
}

char *
fd_ghost_to_cstr( fd_ghost_t const *     ghost,
                  fd_ghost_blk_t const * root,
                  char *                 cstr,
                  ulong                  cstr_max,
                  ulong *                cstr_len ) {

  ulong off = 0;

  int n = snprintf( cstr + off, cstr_max - off, "[Ghost]\n\n" );
  if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
  off += (ulong)n;

  to_cstr( ghost, root, root->total_stake, 0, "", cstr, cstr_max, &off, 0 );

  if( off < cstr_max ) {
    n = snprintf( cstr + off, cstr_max - off, "\n\n" );
    if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
    off += (ulong)n;
  }

  cstr[fd_ulong_min( off++, cstr_max - 1 )] = '\0';
  *cstr_len = fd_ulong_min( off, cstr_max );
  return cstr;
}
