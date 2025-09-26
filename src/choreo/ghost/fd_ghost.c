#include "fd_ghost.h"

#define LOGGING 0

void *
fd_ghost_new( void * shmem, ulong ele_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ghost_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_ghost_footprint( ele_max );
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

  int elg_max = fd_ulong_find_msb( fd_ulong_pow2_up( ele_max ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ghost_t * ghost = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(),          sizeof( fd_ghost_t )                   );
  void *       pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_pool_align(),     fd_ghost_pool_footprint    ( ele_max ) );
  void *       hash  = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_hash_map_align(), fd_ghost_hash_map_footprint( ele_max ) );
  void *       slot  = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_slot_map_align(), fd_ghost_slot_map_footprint( ele_max ) );
  void *       dup   = FD_SCRATCH_ALLOC_APPEND( l, fd_dup_seen_map_align(),   fd_dup_seen_map_footprint  ( elg_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_ghost_align() ) == (ulong)shmem + footprint );

  ghost->pool_gaddr     = fd_wksp_gaddr_fast( wksp, fd_ghost_pool_join    ( fd_ghost_pool_new    ( pool, ele_max       ) ) );
  ghost->hash_map_gaddr = fd_wksp_gaddr_fast( wksp, fd_ghost_hash_map_join( fd_ghost_hash_map_new( hash, ele_max, seed ) ) );
  ghost->slot_map_gaddr = fd_wksp_gaddr_fast( wksp, fd_ghost_slot_map_join( fd_ghost_slot_map_new( slot, ele_max, seed ) ) );
  ghost->dup_map_gaddr  = fd_wksp_gaddr_fast( wksp, fd_dup_seen_map_join  ( fd_dup_seen_map_new  ( dup,  elg_max       ) ) );

  ghost->ghost_gaddr = fd_wksp_gaddr_fast( wksp, ghost );
  ghost->seed        = seed;
  ghost->root        = fd_ghost_pool_idx_null( fd_ghost_pool( ghost ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ghost->magic ) = FD_GHOST_MAGIC;
  FD_COMPILER_MFENCE();

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

  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "ghost must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( ghost->magic!=FD_GHOST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
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

/* Inserts element into the hash-keyed map. If there isn't already a
   block executed for the same slot, insert into the slot-keyed map. */
static void
maps_insert( fd_ghost_t * ghost, fd_ghost_ele_t * ele ) {
  fd_ghost_hash_map_t * maph = fd_ghost_hash_map( ghost );
  fd_ghost_slot_map_t * maps = fd_ghost_slot_map( ghost );
  fd_ghost_ele_t      * pool = fd_ghost_pool( ghost );
  ulong                 null = fd_ghost_pool_idx_null( pool );

  fd_ghost_hash_map_ele_insert( maph, ele, pool );
  fd_ghost_ele_t * ele_slot = fd_ghost_slot_map_ele_query( maps, &ele->slot, NULL, pool );
  if( FD_LIKELY( !ele_slot ) ) {
   fd_ghost_slot_map_ele_insert( maps, ele, pool ); /* cannot fail */
  } else {
    /* If the slot is already in the map, then we have a duplicate */
    while( FD_UNLIKELY( ele_slot->eqvoc != null ) ) {
      ele_slot = fd_ghost_pool_ele( pool, ele_slot->eqvoc );
    }
    ele_slot->eqvoc = fd_ghost_pool_idx( pool, ele );
  }
}

/* Removes all occurrences of `hash` from the maps. */
static fd_ghost_ele_t *
maps_remove( fd_ghost_t * ghost, fd_hash_t * hash ) {
  fd_ghost_hash_map_t * maph = fd_ghost_hash_map( ghost );
  fd_ghost_slot_map_t * maps = fd_ghost_slot_map( ghost );
  fd_ghost_ele_t      * pool = fd_ghost_pool( ghost );

  fd_ghost_ele_t * ele = fd_ghost_hash_map_ele_remove( maph, hash, NULL, pool );
  if( FD_LIKELY( ele ) ) {
    fd_ghost_ele_t * eles = fd_ghost_slot_map_ele_query( maps, &ele->slot, NULL, pool );
    if( FD_LIKELY( eles && memcmp( &ele->key, hash, sizeof(fd_hash_t) ) == 0 ) ) {
      fd_ghost_slot_map_ele_remove( maps, &ele->slot, NULL, pool );
    }
  }
  return ele;
}

void
fd_ghost_init( fd_ghost_t * ghost, ulong root_slot, fd_hash_t * hash ) {

  if( FD_UNLIKELY( !ghost ) ) {
    FD_LOG_WARNING(( "NULL ghost" ));
    return;
  }

  if( FD_UNLIKELY( root_slot == FD_SLOT_NULL ) ) {
    FD_LOG_WARNING(( "NULL root" ));
    return;
  }

  fd_ghost_ele_t * pool = fd_ghost_pool( ghost );
  ulong            null = fd_ghost_pool_idx_null( pool );

  if( FD_UNLIKELY( ghost->root != null ) ) {
    FD_LOG_WARNING(( "ghost already initialized" ));
    return;
  }

  /* Initialize the root ele from a pool element. */

  fd_ghost_ele_t * root = fd_ghost_pool_ele_acquire( pool );
  root->key             = *hash;
  root->slot            = root_slot;
  root->next            = null;
  root->nexts           = null;
  root->eqvoc           = null;
  root->parent          = null;
  root->child           = null;
  root->sibling         = null;
  root->weight          = 0;
  root->replay_stake    = 0;
  root->gossip_stake    = 0;
  root->rooted_stake    = 0;
  root->valid           = 1;

  /* Insert the root and record the root ele's pool idx. */

  maps_insert( ghost, root ); /* cannot fail */
  ghost->root = fd_ghost_pool_idx( pool, root );

  /* Sanity checks. */

  FD_TEST( fd_ghost_root( ghost )                                      );
  FD_TEST( fd_ghost_root( ghost ) == fd_ghost_query( ghost, hash  ) );
  FD_TEST( fd_ghost_root( ghost )->slot == root_slot                   );

  return;
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

  if( FD_UNLIKELY( ghost->magic!=FD_GHOST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return -1;
  }

  fd_ghost_ele_t const      * pool = fd_ghost_pool_const( ghost );
  ulong                       null = fd_ghost_pool_idx_null( pool );
  fd_ghost_hash_map_t const * maph = fd_ghost_hash_map_const( ghost );

  /* Check every ele that exists in pool exists in map. */

  if( fd_ghost_hash_map_verify( maph, fd_ghost_pool_max( pool ), pool ) ) return -1;

  /* Check every ele's weight is >= sum of children's weights. */

  fd_ghost_ele_t const * parent = fd_ghost_root_const( ghost );
  while( FD_LIKELY( parent ) ) {
    ulong                  weight = 0;
    fd_ghost_ele_t const * child  = fd_ghost_child_const( ghost, parent );
    while( FD_LIKELY( child && child->sibling != null ) ) {
      weight += child->weight;
      child = fd_ghost_sibling_const( ghost, child );
    }
  # if FD_GHOST_USE_HANDHOLDING
    FD_TEST( parent->weight >= weight );
  # endif
    parent = fd_ghost_pool_ele_const( pool, parent->next );
  }

  return 0;
}

static void
fd_ghost_mark_valid( fd_ghost_t * ghost, fd_hash_t const * bid ) {
  fd_ghost_ele_t * ele = fd_ghost_query( ghost, bid );
  if( FD_LIKELY( ele ) ) ele->valid = 1;
}

static void
fd_ghost_mark_invalid( fd_ghost_t * ghost, ulong slot, ulong total_stake ) {
  fd_ghost_ele_t  * pool = fd_ghost_pool( ghost );
  ulong             null = fd_ghost_pool_idx_null( pool );
  fd_hash_t const * hash = fd_ghost_hash( ghost, slot );
  FD_TEST( hash ); /* mark_invalid should never get called on a non-existing slot */

  fd_ghost_ele_t * ele = fd_ghost_query( ghost, hash );
  if( FD_LIKELY( ele && !is_duplicate_confirmed( ghost, &ele->key, total_stake ) ) ) ele->valid = 0;
  while( FD_UNLIKELY( ele->eqvoc != null ) ) {
    fd_ghost_ele_t * eqvoc = fd_ghost_pool_ele( pool, ele->eqvoc );
    if( FD_LIKELY( !is_duplicate_confirmed( ghost, &eqvoc->key, total_stake ) ) ) eqvoc->valid = 0;
    ele = eqvoc;
  }
}

fd_ghost_ele_t *
fd_ghost_insert( fd_ghost_t * ghost, fd_hash_t const * parent_hash, ulong slot, fd_hash_t const * hash, ulong total_stake ) {
# if LOGGING
  FD_LOG_NOTICE(( "[%s] slot: %lu, %s. parent: %s.", __func__, slot, FD_BASE58_ENC_32_ALLOCA(hash), FD_BASE58_ENC_32_ALLOCA(parent_hash) ));
# endif

# if FD_GHOST_USE_HANDHOLDING
  FD_TEST( ghost->magic == FD_GHOST_MAGIC );
# endif

  fd_ghost_ele_t *       pool   = fd_ghost_pool( ghost );
  ulong                  null   = fd_ghost_pool_idx_null( pool );
  fd_ghost_ele_t *       parent = fd_ghost_query( ghost, parent_hash );
  fd_ghost_ele_t const * root   = fd_ghost_root( ghost );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( fd_ghost_query( ghost, hash ) ) ) { FD_LOG_WARNING(( "[%s] hash %s already in ghost.",            __func__, FD_BASE58_ENC_32_ALLOCA(hash)                                             )); return NULL; }
  if( FD_UNLIKELY( !parent                       ) ) { FD_LOG_WARNING(( "[%s] missing `parent_id` %s for (%s, %lu)", __func__, FD_BASE58_ENC_32_ALLOCA(parent_hash), FD_BASE58_ENC_32_ALLOCA(hash), slot )); return NULL; }
  if( FD_UNLIKELY( !fd_ghost_pool_free( pool )   ) ) { FD_LOG_WARNING(( "[%s] ghost full.",                          __func__                                                                            )); return NULL; }
  if( FD_UNLIKELY( slot <= root->slot            ) ) { FD_LOG_WARNING(( "[%s] slot %lu <= root %lu",                 __func__, slot, root->slot                                                          )); return NULL; }
# endif

  fd_ghost_ele_t * ele = fd_ghost_pool_ele_acquire( pool );
  ele->key             = *hash;
  ele->slot            = slot;
  ele->eqvoc           = null;
  ele->next            = null;
  ele->nexts           = null;
  ele->parent          = null;
  ele->child           = null;
  ele->sibling         = null;
  ele->weight          = 0;
  ele->replay_stake    = 0;
  ele->gossip_stake    = 0;
  ele->rooted_stake    = 0;
  ele->valid           = 1;
  ele->parent = fd_ghost_pool_idx( pool, parent );
  if( FD_LIKELY( parent->child == null ) ) {
    parent->child = fd_ghost_pool_idx( pool, ele ); /* left-child */
  } else {
    fd_ghost_ele_t * curr = fd_ghost_pool_ele( pool, parent->child );
    while( curr->sibling != null ) curr = fd_ghost_pool_ele( pool, curr->sibling );
    curr->sibling = fd_ghost_pool_idx( pool, ele ); /* right-sibling */
  }
  maps_insert( ghost, ele );

  /* Checks if block has a duplicate message, but the message arrived
     before the block was added to ghost. */

  if( FD_UNLIKELY( fd_dup_seen_map_query( fd_ghost_dup_map( ghost ), slot, NULL ) ) ) {
    fd_ghost_mark_invalid( ghost, slot, total_stake );
  }
  return ele;
}

fd_ghost_ele_t const *
fd_ghost_head( fd_ghost_t const * ghost, fd_ghost_ele_t const * root ) {

# if FD_GHOST_USE_HANDHOLDING
  FD_TEST( ghost->magic == FD_GHOST_MAGIC );
  FD_TEST( root );
# endif

  if( FD_UNLIKELY( !root->valid ) ) return NULL; /* no valid ghost heads */

  fd_ghost_ele_t const * pool = fd_ghost_pool_const( ghost );
  fd_ghost_ele_t const * head = root;
  ulong                  null = fd_ghost_pool_idx_null( pool );

  while( FD_LIKELY( head->child != null ) ) {
    int valid_child = 0; /* at least one child is valid */
    fd_ghost_ele_t const * child = fd_ghost_child_const( ghost, head );
    while( FD_LIKELY( child ) ) { /* greedily pick the heaviest valid child */
      if( FD_LIKELY( child->valid ) ) {
        if( FD_LIKELY( !valid_child ) ) { /* this is the first valid child, so progress the head */
          head        = child;
          valid_child = 1;
        }
        head = fd_ptr_if(
          fd_int_if(
            child->weight == head->weight,  /* if the weights are equal */
            child->slot < head->slot,       /* then tie-break by lower slot number */
            child->weight > head->weight ), /* else return heavier */
          child, head );
      }
      child = fd_ghost_sibling_const( ghost, child );
    }
    if( FD_UNLIKELY( !valid_child ) ) break; /* no children are valid, so short-circuit traversal */
  }
  return head;
}

void
fd_ghost_replay_vote( fd_ghost_t * ghost, fd_voter_t * voter, fd_hash_t const * hash ) {
  fd_ghost_ele_t *       pool = fd_ghost_pool( ghost );
  fd_vote_record_t       vote = voter->replay_vote;
  fd_ghost_ele_t const * root = fd_ghost_root( ghost );
  fd_ghost_ele_t const * vote_ele = fd_ghost_query_const( ghost, hash );
  ulong slot = vote_ele->slot;

# if LOGGING
  FD_LOG_INFO(( "[%s] voter: %s slot_hash: (%s, %lu) last: %lu", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), FD_BASE58_ENC_32_ALLOCA(hash), slot, vote.slot ));
# endif

  /* Short-circuit if the vote slot is older than the root. */

  if( FD_UNLIKELY( slot < root->slot ) ) return;

  /* Short-circuit if the vote is unchanged. It's possible that voter is
     switching from A to A', which should be a slashable offense. */

  if( FD_UNLIKELY( memcmp( &vote.hash, hash, sizeof(fd_hash_t) ) == 0 ) ) return;

  /* TODO add logic that only the least bank hash is kept if the same
     voter votes for the same slot multiple times. */

  /* Short-circuit if this vote slot < the last vote slot we processed
     for this voter. The order we replay forks is non-deterministic due
     to network propagation variance, so it is possible we are see an
     older vote after a newer vote (relative to the slot in which the
     vote actually landed).

     For example, 3-4 and 5-6 fork from 2, we might see the vote for 5
     in block 6 then the vote for 3 in block 4. We ignore the vote for 3
     in block 4 if we already processed the vote for 5 in block 6. */

  if( FD_UNLIKELY( vote.slot != FD_SLOT_NULL && slot < vote.slot ) ) return;

  /* LMD-rule: subtract the voter's stake from the ghost ele
     corresponding to their previous vote slot. If the voter's previous
     vote slot is not in ghost than we have either not processed
     this voter previously or their previous vote slot was already
     pruned (because we published a new root). */

  fd_ghost_ele_t * prev = fd_ghost_query( ghost, &vote.hash );
  if( FD_LIKELY( prev && vote.slot != FD_SLOT_NULL ) ) { /* no previous vote or pruned */
#   if LOGGING
    FD_LOG_INFO(( "[%s] subtracting (%s, %lu, %lu, %s)", __func__, FD_BASE58_ENC_32_ALLOCA( &voter->key ), voter->stake, vote.slot, FD_BASE58_ENC_32_ALLOCA( &vote.hash ) ));
#   endif
    int cf = __builtin_usubl_overflow( prev->replay_stake, voter->stake, &prev->replay_stake );
    if( FD_UNLIKELY( cf ) ) FD_LOG_CRIT(( "[%s] sub overflow. prev->replay_stake %lu voter->stake %lu", __func__, prev->replay_stake, voter->stake ));
    fd_ghost_ele_t * ancestor = prev;
    while( FD_LIKELY( ancestor ) ) {
      cf = __builtin_usubl_overflow( ancestor->weight, voter->stake, &ancestor->weight );
      if( FD_UNLIKELY( cf ) ) FD_LOG_CRIT(( "[%s] sub overflow. ancestor->weight %lu latest_vote->stake %lu", __func__, ancestor->weight, voter->stake ));
      ancestor = fd_ghost_pool_ele( pool, ancestor->parent );
    }
  }

  /* Add voter's stake to the ghost ele keyed by `slot`. Propagate the
     vote stake up the ancestry. We do this for all cases we exited
     above: this vote is the first vote we've seen from a pubkey, this
     vote is switched from a previous vote that was on a missing ele
     (pruned), or the regular case */

  fd_ghost_ele_t * curr = fd_ghost_query( ghost, hash );
  if( FD_UNLIKELY( !curr ) ) FD_LOG_CRIT(( "corrupt ghost" ));

# if LOGGING
  FD_LOG_INFO(( "[%s] adding (%s, %lu, %lu)", __func__, FD_BASE58_ENC_32_ALLOCA( &voter->key ), voter->stake, slot ));
# endif
  int cf = __builtin_uaddl_overflow( curr->replay_stake, voter->stake, &curr->replay_stake );
  if( FD_UNLIKELY( cf ) ) FD_LOG_ERR(( "[%s] add overflow. ele->stake %lu latest_vote->stake %lu", __func__, curr->replay_stake, voter->stake ));
  fd_ghost_ele_t * ancestor = curr;
  while( FD_LIKELY( ancestor ) ) {
    int cf = __builtin_uaddl_overflow( ancestor->weight, voter->stake, &ancestor->weight );
    if( FD_UNLIKELY( cf ) ) FD_LOG_ERR(( "[%s] add overflow. ancestor->weight %lu latest_vote->stake %lu", __func__, ancestor->weight, voter->stake ));
    ancestor = fd_ghost_parent( ghost, ancestor );
  }
  voter->replay_vote.slot = slot;  /* update the cached replay vote slot on voter */
  voter->replay_vote.hash = *hash; /* update the cached replay vote hash on voter */
}

void
fd_ghost_gossip_vote( FD_PARAM_UNUSED fd_ghost_t * ghost,
                      FD_PARAM_UNUSED fd_voter_t * voter,
                      FD_PARAM_UNUSED ulong        slot ) {
  FD_LOG_ERR(( "unimplemented" ));
}

void
fd_ghost_rooted_vote( fd_ghost_t * ghost, fd_voter_t * voter, ulong root ) {
# if LOGGING
  FD_LOG_INFO(( "[%s] root %lu, pubkey %s, stake %lu", __func__, root, FD_BASE58_ENC_32_ALLOCA(&voter->key), voter->stake ));
# endif

  /* It is invariant that the voter's root is found in ghost (as long as
     voter's root >= our root ). This is because voter's root is sourced
     from their vote state, so it must be on the fork we're replaying
     and we must have already inserted their root slot into ghost. */

  fd_ghost_ele_t * ele = fd_ghost_query( ghost, fd_ghost_hash( ghost, root ) );
# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "[%s] missing voter %s's root %lu.", __func__, FD_BASE58_ENC_32_ALLOCA(&voter->key), root ));
# endif

  /* Add to the rooted stake. */

  ele->rooted_stake += voter->stake;
}

fd_ghost_ele_t const *
fd_ghost_publish( fd_ghost_t * ghost, fd_hash_t const * hash ) {
  fd_ghost_ele_t * pool = fd_ghost_pool( ghost );
  ulong            null = fd_ghost_pool_idx_null( pool );
  fd_ghost_ele_t * oldr = fd_ghost_root( ghost );
  fd_ghost_ele_t * newr = fd_ghost_query( ghost, hash );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !newr                                                  ) ) { FD_LOG_WARNING(( "[%s] publish hash %s not found",          __func__, FD_BASE58_ENC_32_ALLOCA(hash) )); return NULL; }
  if( FD_UNLIKELY( newr->slot <= oldr->slot                               ) ) { FD_LOG_WARNING(( "[%s] publish slot %lu <= root %lu.",      __func__, newr->slot, oldr->slot )); return NULL; }
  if( FD_UNLIKELY( !fd_ghost_is_ancestor( ghost, &oldr->key, &newr->key ) ) ) { FD_LOG_WARNING(( "[%s] publish slot %lu not ancestor %lu.", __func__, newr->slot, oldr->slot )); return NULL; }
# endif

  /* First, remove the previous root, and add it to the prune list. In
     this context, head is the list head (not to be confused with the
     ghost head.) */

  fd_ghost_ele_t * head = maps_remove( ghost, &oldr->key );
  fd_ghost_ele_t * tail = head;

  /* Second, BFS down the tree, pruning all of root's ancestors and also
     any descendants of those ancestors. */

  head->next = null;
  while( FD_LIKELY( head ) ) {
    fd_ghost_ele_t * child = fd_ghost_pool_ele( pool, head->child );
    while( FD_LIKELY( child ) ) {                                                  /* iterate over children */
      if( FD_LIKELY( child != newr ) ) {                                           /* stop at new root */
        tail->next = fd_ghost_pool_idx( pool, maps_remove( ghost, &child->key ) ); /* remove ele from map to reuse `.next` */
        tail       = fd_ghost_pool_ele( pool, tail->next );                        /* push onto prune queue (so descendants can be pruned) */
        tail->next = fd_ghost_pool_idx_null( pool );
      }
      child = fd_ghost_pool_ele( pool, child->sibling ); /* next sibling */
    }
    fd_ghost_ele_t * next = fd_ghost_pool_ele( pool, head->next ); /* pop prune queue head */
    fd_ghost_pool_ele_release( pool, head );                       /* free prune queue head */
    head = next;                                                   /* move prune queue head forward */
  }
  newr->parent = null;                            /* unlink old root*/
  ghost->root  = fd_ghost_pool_idx( pool, newr ); /* replace with new root */
  return newr;
}

fd_ghost_ele_t const *
fd_ghost_gca( fd_ghost_t const * ghost, fd_hash_t const * hash1, fd_hash_t const * hash2 ) {
  fd_ghost_ele_t const * pool = fd_ghost_pool_const( ghost );
  fd_ghost_ele_t const * ele1 = fd_ghost_query_const( ghost, hash1 );
  fd_ghost_ele_t const * ele2 = fd_ghost_query_const( ghost, hash2 );

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !ele1 ) ) { FD_LOG_WARNING(( "hash1 %s missing", FD_BASE58_ENC_32_ALLOCA(hash1) )); return NULL; }
  if( FD_UNLIKELY( !ele2 ) ) { FD_LOG_WARNING(( "hash2 %s missing", FD_BASE58_ENC_32_ALLOCA(hash2) )); return NULL; }
# endif

  /* Find the greatest common ancestor. */

  while( FD_LIKELY( ele1 && ele2 ) ) {
    if( FD_UNLIKELY( memcmp( &ele1->key, &ele2->key, sizeof(fd_hash_t) ) == 0 ) ) return ele1;
    if( ele1->slot > ele2->slot ) ele1 = fd_ghost_pool_ele_const( pool, ele1->parent );
    else                          ele2 = fd_ghost_pool_ele_const( pool, ele2->parent );
  }
  FD_LOG_CRIT(( "invariant violation" )); /* unreachable */
}

int
fd_ghost_is_ancestor( fd_ghost_t const * ghost, fd_hash_t const * ancestor, fd_hash_t const * hash ) {
  fd_ghost_ele_t const * root = fd_ghost_root_const ( ghost );
  fd_ghost_ele_t const * curr = fd_ghost_query_const( ghost, hash );
  fd_ghost_ele_t const * anc  = fd_ghost_query_const( ghost, ancestor );

  if( FD_UNLIKELY( !anc ) ) {
#   if LOGGING
    FD_LOG_NOTICE(( "[%s] ancestor %s missing", __func__, FD_BASE58_ENC_32_ALLOCA(ancestor) ));
#   endif
    return 0;
  }

# if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( anc->slot < root->slot ) ) { FD_LOG_WARNING(( "[%s] ancestor %lu too old. root %lu.", __func__, anc->slot, root->slot )); return 0; }
  if( FD_UNLIKELY( !curr                  ) ) { FD_LOG_WARNING(( "[%s] hash %s not in ghost.",           __func__, FD_BASE58_ENC_32_ALLOCA(hash) )); return 0; }
# endif

  /* Look for `ancestor` in the fork ancestry.

     Stop looking when there is either no ancestry remaining or there is
     no reason to look further because we've searched past the
     `ancestor`. */

  while( FD_LIKELY( curr && curr->slot >= anc->slot ) ) {
    if( FD_UNLIKELY( memcmp( &curr->key, &anc->key, sizeof(fd_hash_t) ) == 0 ) ) return 1; /* optimize for depth > 1 */
    curr = fd_ghost_pool_ele_const( fd_ghost_pool_const( ghost ), curr->parent );
  }
  return 0; /* not found */
}

int
fd_ghost_invalid( fd_ghost_t const * ghost, fd_ghost_ele_t const * ele ) {
  fd_ghost_ele_t const * anc = ele;
  while( FD_LIKELY( anc ) ) {
    if( FD_UNLIKELY( ( !anc->valid ) ) ) return 1;
    anc = fd_ghost_parent_const( ghost, anc );
  }
  return 0;
}


void
process_duplicate_confirmed( fd_ghost_t * ghost, fd_hash_t const * hash, ulong slot ) {
  fd_ghost_ele_t const * confirmed = fd_ghost_query( ghost, hash );
  fd_ghost_ele_t const * current   = fd_ghost_query( ghost, fd_ghost_hash( ghost, slot ) );
  if( FD_UNLIKELY( !confirmed ) ) {
   FD_LOG_WARNING(( "[%s] duplicate confirmed slot %lu, %s not in ghost. Need to repair & replay. ", __func__, slot, FD_BASE58_ENC_32_ALLOCA(hash) ) );
   return;
  }
  if( FD_UNLIKELY( !current ) )   FD_LOG_ERR(( "[%s] slot %lu doesn't exist in ghost, but we're processing a duplicate confirmed signal for it.", __func__, slot ));

  while( current != NULL ) {
    fd_ghost_mark_valid( ghost, &current->key );
    current = fd_ghost_parent_const( ghost, current );
  }
}

void
process_duplicate( fd_ghost_t * ghost, ulong slot, ulong total_stake ) {
  fd_dup_seen_t * dup_map = fd_ghost_dup_map( ghost );
  fd_dup_seen_map_insert( dup_map, slot );

  if( fd_ghost_hash( ghost, slot ) ) {
    /* slot is already replayed, so we can immediately mark invalid */
    FD_LOG_WARNING(( "[%s] duplicate message for slot %lu, marking invalid", __func__, slot ));
    fd_ghost_mark_invalid( ghost, slot, total_stake );
    return;
  }
}

#include <stdio.h>

static void
print( fd_ghost_t const * ghost, fd_ghost_ele_t const * ele, int space, const char * prefix, ulong total ) {
  fd_ghost_ele_t const * pool = fd_ghost_pool_const( ghost );

  if( ele == NULL ) return;

  if( space > 0 ) printf( "\n" );
  for( int i = 0; i < space; i++ )
    printf( " " );
  if( FD_UNLIKELY( ele->weight > 100 ) ) {
  }
  if( FD_UNLIKELY( total == 0 ) ) {
    printf( "%s%lu (%lu)", prefix, ele->slot, ele->weight );
  } else {
    double pct = ( (double)ele->weight / (double)total ) * 100;
    if( FD_UNLIKELY( pct < 0.99 )) {
      printf( "%s%lu (%.0lf%%, %lu)", prefix, ele->slot, pct, ele->weight );
    } else {
      printf( "%s%lu (%.0lf%%)", prefix, ele->slot, pct );
    }
  }

  fd_ghost_ele_t const * curr = fd_ghost_pool_ele_const( pool, ele->child );
  char                    new_prefix[1024]; /* FIXME size this correctly */
  while( curr ) {
    if( fd_ghost_pool_ele_const( pool, curr->sibling ) ) {
      sprintf( new_prefix, "├── " ); /* branch indicating more siblings follow */
      print( ghost, curr, space + 4, new_prefix, total );
    } else {
      sprintf( new_prefix, "└── " ); /* end branch */
      print( ghost, curr, space + 4, new_prefix, total );
    }
    curr = fd_ghost_pool_ele_const( pool, curr->sibling );
  }
}

void
fd_ghost_print( fd_ghost_t const * ghost, ulong total_stake, fd_ghost_ele_t const * ele ) {
  FD_LOG_NOTICE( ( "\n\n[Ghost]" ) );
  print( ghost, ele, 0, "", total_stake );
  printf( "\n\n" );
}
