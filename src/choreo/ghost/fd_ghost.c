#include "fd_ghost.h"
#include "../tower/fd_tower_accts.h"
#include "../voter/fd_voter.h"

#define LOGGING 1

void *
fd_ghost_new( void * shmem, ulong blk_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( blk_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ele_max (%lu)", blk_max ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  int lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( FD_VOTER_MAX ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ghost_t * ghost = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),      sizeof(fd_ghost_t)                   );
  void *       pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_pool_align(), fd_ghost_pool_footprint( blk_max )   );
  void *       map   = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_map_align(),  fd_ghost_map_footprint( blk_max )    );
  void *       vtr   = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_vtr_align(),  fd_ghost_vtr_footprint( lg_vtr_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_ghost_align() ) == (ulong)shmem + footprint );

  ghost->pool = fd_ghost_pool_new( pool, blk_max );
  ghost->map  = fd_ghost_map_new ( map, blk_max, seed );
  ghost->vtr  = fd_ghost_vtr_new ( vtr, lg_vtr_max );
  ghost->root = fd_ghost_pool_idx_null( ghost->pool );

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

  ghost->pool = fd_ghost_pool_join( ghost->pool );
  ghost->map  = fd_ghost_map_join( ghost->map );
  ghost->bid  = fd_ghost_bid_join( ghost->bid );
  ghost->vtr  = fd_ghost_vtr_join( ghost->vtr );

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

static inline ulong
idx( fd_ghost_t const * ghost, ulong slot ) {
  fd_ghost_bid_t * bid = fd_ghost_bid_query( ghost->bid, slot, NULL );
  if( FD_UNLIKELY( !bid ) ) FD_LOG_CRIT(( "missing bid for slot %lu", slot ));
  return fd_ghost_map_idx_query_const( ghost->map, &bid->block_id, NULL, ghost->pool );
}

/* Returns the ancestor of descendant associated with the given slot,
   NULL if not found. */

fd_hash_t const *
ancestor_block_id( fd_ghost_t const * ghost, fd_ghost_blk_t const * descendant, ulong slot ) {
  fd_ghost_blk_t const * ancestor = descendant;
  while( FD_LIKELY( ancestor ) ) {
    if( FD_LIKELY( ancestor->slot == slot ) ) return &ancestor->key;
    ancestor = fd_ghost_pool_ele( ghost->pool, ancestor->parent );
  }
  return NULL;
}

/* In Solana, a vote is an entire tower, so this counts pubkey's stake
   towards all ancestors on the same fork as (slot, block_id).  If the
   voter has previously voted, it subtracts the voter's previous stake
   from all ancestors of the fork containing the previous vote
   (prev_slot, prev_block_id).  This ensures that only the most recent
   vote from a voter is counted.  See top-level documentation about the
   LMD-GHOST rule for more details. */

/* TODO the implementation can be made more efficient by incrementally
   updating and short-circuiting ancestor traversals.  Currently this is
   bounded to O(h), where h is the height of ghost ie. O(block_max) in
   the worst case. */

void
count_vote( fd_ghost_t        * ghost,
            fd_pubkey_t const * pubkey,
            ulong               stake,
            ulong               slot,
            fd_hash_t   const * block_id ) {

  fd_ghost_blk_t const * root = fd_ghost_root( ghost );
  fd_ghost_blk_t *       pool = ghost->pool;
  fd_ghost_vtr_t *       vtr  = fd_ghost_vtr_query( ghost->vtr, *pubkey, NULL );

  if( FD_UNLIKELY( slot == ULONG_MAX      ) ) return; /* hasn't voted */
  if( FD_UNLIKELY( slot <  root->slot     ) ) return; /* vote older than root */
  if( FD_UNLIKELY( slot <= vtr->prev_slot ) ) return; /* vote too new */

  /* It's possible we already counted a later vote slot for this voter
      than this current one.  The order ghost processes blocks depends
      on replay order, so it is possible we see an older vote after a
      newer vote if a voter switched forks.

      For example, if a voter votes for 3 then switches to 5, we might
      observe the vote for 5 before the vote for 3. */

  if( FD_UNLIKELY( vtr && vtr->prev_slot > slot ) ) return;

  /* LMD-rule: subtract the voter's stake from the entire fork they
     previously voted for. */

  /* TODO can optimize this if they're voting for the same fork */

  if( FD_LIKELY( vtr ) ) {
    fd_ghost_blk_t * ancestor = fd_ghost_map_ele_query( ghost->map, &vtr->prev_block_id, NULL, pool );
    while( FD_LIKELY( ancestor ) ) {
      int cf = __builtin_usubl_overflow( ancestor->stake, vtr->prev_stake, &ancestor->stake );
      if( FD_UNLIKELY( cf ) ) FD_LOG_CRIT(( "[%s] sub overflow. %lu - %lu. (slot %lu, block_id: %s). (prev slot: %lu, prev block_id: %s)", __func__, ancestor->stake, vtr->prev_stake, ancestor->slot, FD_BASE58_ENC_32_ALLOCA( &ancestor->key ), vtr->prev_slot, FD_BASE58_ENC_32_ALLOCA( &vtr->prev_block_id ) ));
      ancestor = fd_ghost_pool_ele( pool, ancestor->parent );
    }
  }

  /* Add voter's stake to the entire fork they are voting for. Propagate
     the vote stake up the ancestry. We do this for all cases we exited
     above: this vote is the first vote we've seen from a pubkey, this
     vote is switched from a previous vote that was on a missing ele
     (pruned), or the regular case. */

  fd_ghost_blk_t * curr = fd_ghost_map_ele_query( ghost->map, block_id, NULL, pool );
  if( FD_UNLIKELY( !curr ) ) FD_LOG_CRIT(( "corrupt ghost" ));
  fd_ghost_blk_t * ancestor = curr;
  while( FD_LIKELY( ancestor ) ) {
    int cf = __builtin_uaddl_overflow( ancestor->stake, vtr->prev_stake, &ancestor->stake );
    if( FD_UNLIKELY( cf ) ) FD_LOG_CRIT(( "[%s] add overflow. %lu + %lu. (slot %lu, block_id: %s). (prev slot: %lu, prev block_id: %s)", __func__, ancestor->stake, vtr->prev_stake, ancestor->slot, FD_BASE58_ENC_32_ALLOCA( &ancestor->key ), vtr->prev_slot, FD_BASE58_ENC_32_ALLOCA( &vtr->prev_block_id ) ));
    ancestor = fd_ghost_parent( ghost, ancestor );
  }
  vtr->prev_block_id = *block_id;
  vtr->prev_stake    = stake;
}

fd_ghost_blk_t const *
fd_ghost_best( fd_ghost_t     const * ghost,
               fd_ghost_blk_t const * root ) {
  fd_ghost_blk_t const * pool = ghost->pool;
  ulong                  null = fd_ghost_pool_idx_null( pool );
  fd_ghost_blk_t const * best = root;
  while( FD_LIKELY( best->child != null ) ) {
    int valid_child = 0; /* at least one child is valid */
    fd_ghost_blk_t const * child = fd_ghost_child_const( ghost, best );
    while( FD_LIKELY( child ) ) { /* greedily pick the heaviest valid child */
      if( FD_LIKELY( child->valid ) ) {
        if( FD_LIKELY( !valid_child ) ) { /* this is the first valid child, so progress the head */
          best        = child;
          valid_child = 1;
        }
        best = fd_ptr_if(
          fd_int_if(
            child->stake == best->stake,   /* if the weights are equal */
            child->slot  <  best->slot,    /* then tie-break by lower slot number */
            child->stake >  best->stake ), /* else return heavier */
          child, best );
      }
      child = fd_ghost_sibling_const( ghost, child );
    }
    if( FD_UNLIKELY( !valid_child ) ) break; /* no children are valid, so short-circuit traversal */
  }
  return best;
}

fd_ghost_blk_t const *
fd_ghost_deepest( fd_ghost_t     const * ghost,
                  fd_ghost_blk_t const * root ) {
  fd_ghost_blk_t * pool = ghost->pool;
  ulong            null = fd_ghost_pool_idx_null( pool );
  fd_ghost_blk_t * head = fd_ghost_map_ele_remove( ghost->map, &root->key, NULL, pool ); /* remove ele from map to reuse `.next` */
  fd_ghost_blk_t * tail = head;

  /* Below is a level-order traversal (BFS), returning the last leaf
     which is guaranteed to return an element of the max depth.

     It temporarily removes elements of the map when pushing onto the
     BFS queue to reuse the .next pointer and then inserts back into
     the map on queue pop. */

  head->next = null;
  while( FD_LIKELY( head ) ) {
    fd_ghost_blk_t const * child = fd_ghost_child_const( ghost, head );
    while( FD_LIKELY( child ) ) {
      tail->next = fd_ghost_pool_idx( pool, fd_ghost_map_ele_remove( ghost->map, &child->key, NULL, pool ) );
      tail       = fd_ghost_pool_ele( pool, tail->next );
      tail->next = fd_ghost_pool_idx_null( pool );
      child = fd_ghost_pool_ele( pool, child->sibling ); /* next sibling */
    }
    fd_ghost_blk_t * next = fd_ghost_pool_ele( pool, head->next ); /* pop prune queue head */
    fd_ghost_map_ele_insert( ghost->map, head, pool );             /* re-insert head into map */
    head = next;
  }
  return head;
}

fd_ghost_blk_t const *
fd_ghost_invalid_ancestor( fd_ghost_t     const * ghost,
                           fd_ghost_blk_t const * descendant ) {
  fd_ghost_blk_t const * ancestor = descendant;
  while( FD_LIKELY( ancestor ) ) {
    if( FD_UNLIKELY( ( !ancestor->valid ) ) ) return ancestor;
    ancestor = fd_ghost_parent_const( ghost, ancestor );
  }
  return NULL;
}

fd_ghost_blk_t *
fd_ghost_upsert( fd_ghost_t             * ghost,
                 fd_tower_accts_t const * accts,
                 ulong                    slot,
                 fd_hash_t        const * block_id,
                 fd_hash_t        const * parent_block_id ) {

  fd_ghost_blk_t *       pool   = ghost->pool;
  ulong                  null   = fd_ghost_pool_idx_null( pool );
  fd_ghost_blk_t const * root   = fd_ghost_root( ghost );
  fd_ghost_blk_t *       blk    = fd_ghost_map_ele_query( ghost->map, block_id, NULL, pool );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( blk                         ) ) { FD_LOG_WARNING(( "[%s] hash %s already in ghost",          __func__, FD_BASE58_ENC_32_ALLOCA( block_id )      )); return NULL; }
  if( FD_UNLIKELY( !fd_ghost_pool_free( pool ) ) ) { FD_LOG_WARNING(( "[%s] ghost full",                        __func__                                           )); return NULL; }
  if( FD_UNLIKELY( slot <= root->slot          ) ) { FD_LOG_WARNING(( "[%s] slot %lu <= root %lu",              __func__, slot, root->slot                         )); return NULL; }
# endif

  blk          = fd_ghost_pool_ele_acquire( pool );
  blk->key     = *block_id;
  blk->slot    = slot;
  blk->next    = null;
  blk->parent  = null;
  blk->child   = null;
  blk->sibling = null;
  blk->stake   = 0;
  blk->eqvoc   = 0;
  blk->conf    = 0;
  blk->valid   = 1;

  /* Link to the parent. */

  fd_ghost_blk_t * parent = fd_ghost_map_ele_query( ghost->map, parent_block_id, NULL, pool );
  if( FD_LIKELY( parent ) ) {
    blk->parent  = fd_ghost_pool_idx( pool, parent );
    if( FD_LIKELY( parent->child == null ) ) {
      parent->child = fd_ghost_pool_idx( pool, blk );    /* left-child */
    } else {
      fd_ghost_blk_t * sibling = fd_ghost_pool_ele( pool, parent->child );
      while( sibling->sibling != null ) sibling = fd_ghost_pool_ele( pool, sibling->sibling );
      sibling->sibling = fd_ghost_pool_idx( pool, blk ); /* right-sibling */
    }
  }
  fd_ghost_map_ele_insert( ghost->map, blk, pool );

  /* Iterate the state of the vote accounts as of this block, counting
     their votes towards ghost. */

  for( fd_tower_accts_iter_t iter = fd_tower_accts_iter_init( accts       );
                                   !fd_tower_accts_iter_done( accts, iter );
                             iter = fd_tower_accts_iter_next( accts, iter ) ) {
    fd_tower_accts_t const * acct = fd_tower_accts_iter_ele_const( accts, iter );

    /* Deserialize the last vote slot from the vote account's tower. */

    ulong vote_slot = fd_voter_state_vote( (fd_voter_state_t const *)fd_type_pun_const( acct->data ) );

    /* We search up the ghost ancestry to find the block_id for this
       vote slot.  In Agave, they look this value up using a hashmap of
       slot->block_id ("fork progress"), but that approach only works
       because they dump and repair (so there's only ever one canonical
       block_id).  We may replay `n` versions of a block and have `n`
       different block_ids. */

    fd_hash_t const * vote_block_id = ancestor_block_id( ghost, blk, vote_slot ); /* FIXME potentially slow */

    /* It should be impossible for last_vote_block_id to be missing,
       because ghost processes on-chain vote accounts, not vote txns.
       So all these accounts were already validated by the vote program
       to contain known slots, which implies they must be in the ghost
       ancestry, which should be updated after every replay.  A missing
       value is a bug. */

    if( FD_UNLIKELY( !vote_block_id ) ) FD_LOG_CRIT(( "missing block_id for slot %lu voter %s", vote_slot, FD_BASE58_ENC_32_ALLOCA( &acct->addr ) ));
    count_vote( ghost, &acct->addr, acct->stake, vote_slot, vote_block_id );
  }
  return blk;
}

fd_ghost_blk_t const *
fd_ghost_publish( fd_ghost_t       * ghost,
                  fd_hash_t  const * block_id ) {
  fd_ghost_blk_t * pool = ghost->pool;
  ulong            null = fd_ghost_pool_idx_null( pool );
  fd_ghost_blk_t * oldr = fd_ghost_root( ghost );
  fd_ghost_blk_t * newr = fd_ghost_pool_ele( ghost->pool, fd_ghost_map_idx_query_const( ghost->map, block_id, NULL, ghost->pool ) );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !newr                                                  ) ) { FD_LOG_WARNING(( "[%s] new root %lu not in ghost",                   __func__, newr->slot             )); fd_ghost_print( ghost, fd_ghost_root( ghost ), 0 ); return NULL; }
  if( FD_UNLIKELY( newr->slot <= oldr->slot                               ) ) { FD_LOG_WARNING(( "[%s] new root %lu <= old root %lu",                __func__, newr->slot, oldr->slot )); fd_ghost_print( ghost, fd_ghost_root( ghost ), 0 ); return NULL; }
# endif

  /* First, remove the previous root, and add it to the prune list. In
     this context, head is the list head (not to be confused with the
     ghost head.) */

  fd_ghost_blk_t * head = fd_ghost_map_ele_remove( ghost->map, &oldr->key, NULL, pool ); /* remove ele from map to reuse `.next` */
  fd_ghost_blk_t * tail = head;

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  head->next = null;
  while( FD_LIKELY( head ) ) {
    fd_ghost_blk_t * child = fd_ghost_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {                                                    /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                             /* stop at new root */
        tail->next = fd_ghost_map_idx_remove( ghost->map, &child->key, NULL, pool ); /* remove ele from map to reuse `.next` */
        tail       = fd_ghost_pool_ele( pool, tail->next );                          /* push onto prune queue (so descendants can be pruned) */
        tail->next = fd_ghost_pool_idx_null( pool );
      }
      child = fd_ghost_pool_ele( pool, child->sibling ); /* next sibling */
    }
    fd_ghost_blk_t * next = fd_ghost_pool_ele( pool, head->next ); /* pop prune queue head */
    fd_ghost_pool_ele_release( pool, head );                       /* free prune queue head */
    head = next;                                                   /* move prune queue head forward */
  }
  newr->parent = null;                            /* unlink old root*/
  ghost->root  = fd_ghost_pool_idx( pool, newr ); /* replace with new root */
  return newr;
}

int
fd_ghost_valid( fd_ghost_t const * ghost, fd_ghost_blk_t const * ele ) {
  fd_ghost_blk_t const * anc = ele;
  while( FD_LIKELY( anc ) ) {
    if( FD_UNLIKELY( ( !anc->conf ) ) ) return 1;
    anc = fd_ghost_parent_const( ghost, anc );
  }
  return 0;
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

  fd_ghost_blk_t const      * pool = ghost->pool;
  ulong                       null = fd_ghost_pool_idx_null( pool );

  /* Check every ele that exists in pool exists in map. */

  if( fd_ghost_map_verify( ghost->map, fd_ghost_pool_max( pool ), pool ) ) return -1;

  /* Check every ele's stake is >= sum of children's stakes. */

  fd_ghost_blk_t const * parent = fd_ghost_root_const( ghost );
  while( FD_LIKELY( parent ) ) {
    ulong                  weight = 0;
    fd_ghost_blk_t const * child  = fd_ghost_child_const( ghost, parent );
    while( FD_LIKELY( child && child->sibling != null ) ) {
      weight += child->stake;
      child = fd_ghost_sibling_const( ghost, child );
    }
  # if FD_GHOST_USE_HANDHOLDING
    FD_TEST( parent->stake >= weight );
  # endif
    parent = fd_ghost_pool_ele_const( pool, parent->next );
  }

  return 0;
}

#include <stdio.h>

static void
print( fd_ghost_t const * ghost, fd_ghost_blk_t const * ele, ulong total_stake, int space, const char * prefix ) {
  fd_ghost_blk_t const * pool = ghost->pool;

  if( FD_UNLIKELY( ele == NULL ) ) return;

  if( FD_LIKELY( space > 0 ) ) printf( "\n" );
  for( int i = 0; i < space; i++ )
    printf( " " );
  if( FD_UNLIKELY( ele->stake > 100 ) ) {
  }
  if( FD_UNLIKELY( total_stake == 0 ) ) {
    printf( "%s%lu (%lu)", prefix, ele->slot, ele->stake );
  } else {
    double pct = ( (double)ele->stake / (double)total_stake ) * 100;
    if( FD_UNLIKELY( pct < 0.99 )) {
      printf( "%s%lu (%.0lf%%, %lu)", prefix, ele->slot, pct, ele->stake );
    } else {
      printf( "%s%lu (%.0lf%%)", prefix, ele->slot, pct );
    }
  }

  fd_ghost_blk_t const * curr = fd_ghost_pool_ele_const( pool, ele->child );
  char new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( FD_UNLIKELY( fd_ghost_pool_ele_const( pool, curr->sibling ) ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( ghost, curr, total_stake, space + 4, new_prefix );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( ghost, curr, total_stake, space + 4, new_prefix );
    }
    curr = fd_ghost_pool_ele_const( pool, curr->sibling );
  }
}

void
fd_ghost_print( fd_ghost_t const *     ghost,
                fd_ghost_blk_t const * root,
                ulong                  total_stake ) {
  FD_LOG_NOTICE( ( "\n\n[Ghost]" ) );
  print( ghost, root, total_stake, 0, "" );
  printf( "\n\n" );
}
