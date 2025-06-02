#include "fd_fec_chainer.h"

void *
fd_fec_chainer_new( void * shmem, ulong fec_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_fec_chainer_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_fec_chainer_footprint( fec_max );
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

  fd_fec_chainer_t * chainer;
  int lg_fec_max = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  chainer         = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_chainer_align(),  sizeof( fd_fec_chainer_t )               );
  void * ancestry = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_ancestry_align(), fd_fec_ancestry_footprint( fec_max )     );
  void * frontier = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_frontier_align(), fd_fec_frontier_footprint( fec_max )     );
  void * orphaned = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_orphaned_align(), fd_fec_orphaned_footprint( fec_max )     );
  void * pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_pool_align(),     fd_fec_pool_footprint( fec_max )         );
  void * parents  = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_parents_align(),  fd_fec_parents_footprint( lg_fec_max )   );
  void * children = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_children_align(), fd_fec_children_footprint( lg_fec_max )  );
  void * queue    = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_queue_align(),    fd_fec_queue_footprint( fec_max )        );
  void * out      = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_out_align(),      fd_fec_out_footprint( fec_max )          );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_fec_chainer_align() ) == (ulong)shmem + footprint );

  chainer->ancestry = fd_fec_ancestry_new( ancestry, fec_max, seed );
  chainer->frontier = fd_fec_frontier_new( frontier, fec_max, seed );
  chainer->orphaned = fd_fec_orphaned_new( orphaned, fec_max, seed );
  chainer->pool     = fd_fec_pool_new    ( pool,     fec_max       );
  chainer->parents  = fd_fec_parents_new ( parents,  lg_fec_max    );
  chainer->children = fd_fec_children_new( children, lg_fec_max    );
  chainer->queue    = fd_fec_queue_new   ( queue,    fec_max       );
  chainer->out      = fd_fec_out_new     ( out,      fec_max       );

  return shmem;
}

fd_fec_chainer_t *
fd_fec_chainer_join( void * shfec_chainer ) {
  fd_fec_chainer_t * chainer = (fd_fec_chainer_t *)shfec_chainer;

  if( FD_UNLIKELY( !chainer ) ) {
    FD_LOG_WARNING(( "NULL chainer" ));
    return NULL;
  }

  chainer->ancestry = fd_fec_ancestry_join( chainer->ancestry );
  chainer->frontier = fd_fec_frontier_join( chainer->frontier );
  chainer->orphaned = fd_fec_orphaned_join( chainer->orphaned );
  chainer->pool     = fd_fec_pool_join    ( chainer->pool     );
  chainer->parents  = fd_fec_parents_join ( chainer->parents  );
  chainer->children = fd_fec_children_join( chainer->children );
  chainer->queue    = fd_fec_queue_join   ( chainer->queue    );
  chainer->out      = fd_fec_out_join     ( chainer->out      );

  return chainer;
}

void *
fd_fec_chainer_leave( fd_fec_chainer_t * chainer ) {

  if( FD_UNLIKELY( !chainer ) ) {
    FD_LOG_WARNING(( "NULL chainer" ));
    return NULL;
  }

  return (void *)chainer;
}

void *
fd_fec_chainer_delete( void * shchainer ) {
  fd_fec_chainer_t * chainer = (fd_fec_chainer_t *)shchainer;

  if( FD_UNLIKELY( !chainer ) ) {
    FD_LOG_WARNING(( "NULL chainer" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)chainer, fd_fec_chainer_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned chainer" ));
    return NULL;
  }

  return chainer;
}

fd_fec_ele_t *
fd_fec_chainer_init( fd_fec_chainer_t * chainer, ulong slot, uchar merkle_root[static FD_SHRED_MERKLE_ROOT_SZ] ) {
  FD_TEST( fd_fec_pool_free( chainer->pool ) );
  fd_fec_ele_t * root = fd_fec_pool_ele_acquire( chainer->pool );
  FD_TEST( root );
  root->key           = slot << 32 | ( UINT_MAX-1 ); // maintain invariant that no fec_set_idx=UINT_MAX lives in pool_ele
  root->slot          = slot;
  root->fec_set_idx   = UINT_MAX-1;
  root->data_cnt      = 0;
  root->data_complete = 1;
  root->slot_complete = 1;
  root->parent_off    = 0;
  memcpy( root->merkle_root, merkle_root, FD_SHRED_MERKLE_ROOT_SZ );
  memset( root->chained_merkle_root, 0, FD_SHRED_MERKLE_ROOT_SZ );

  /* For the next slot that chains off the init slot, it will use the
     parent_map and key with slot | UINT_MAX to look for its parent, so
     we need to provide the artificial parent link between the last
     fec_set_idx and UINT_MAX. This way it can query for
     UINT_MAX -> UINT_MAX-1 -> get_pool_ele(UINT_MAX-1)*/

  fd_fec_parent_t * p = fd_fec_parents_insert( chainer->parents, slot << 32 | UINT_MAX );
  p->parent_key       = (slot << 32) | ( UINT_MAX - 1 );

  fd_fec_frontier_ele_insert( chainer->frontier, root, chainer->pool );
  return root;
}

void *
fd_fec_chainer_fini( fd_fec_chainer_t * chainer ) {
  return (void *)chainer;
}

FD_FN_PURE fd_fec_ele_t *
fd_fec_chainer_query( fd_fec_chainer_t * chainer, ulong slot, uint fec_set_idx ) {
  ulong key = slot << 32 | fec_set_idx;
  fd_fec_ele_t * fec;
  fec =                  fd_fec_frontier_ele_query( chainer->frontier, &key, NULL, chainer->pool );
  fec = fd_ptr_if( !fec, fd_fec_ancestry_ele_query( chainer->ancestry, &key, NULL, chainer->pool ), fec );
  fec = fd_ptr_if( !fec, fd_fec_orphaned_ele_query( chainer->orphaned, &key, NULL, chainer->pool ), fec );
  return fec;
}

static int
is_last_fec( ulong key ){
  return ( (uint)fd_ulong_extract( key, 0, 31 ) & UINT_MAX ) == UINT_MAX; // lol fix
}

static void
link_orphans( fd_fec_chainer_t * chainer ) {
  while( FD_LIKELY( !fd_fec_queue_empty( chainer->queue ) ) ) {
    ulong          key = fd_fec_queue_pop_head( chainer->queue );
    fd_fec_ele_t * ele = fd_fec_orphaned_ele_query( chainer->orphaned, &key, NULL, chainer->pool );

    if( FD_LIKELY( !ele ) ) continue;

    /* Query for the parent_key. */

    fd_fec_parent_t * parent_key = fd_fec_parents_query( chainer->parents, key, NULL );
    if( FD_UNLIKELY( !parent_key ) ) continue; /* still orphaned */

    /* If the parent is in the frontier, remove the parent and insert
       into ancestry.  Otherwise check for parent in ancestry. */

    if( FD_UNLIKELY( is_last_fec( parent_key->parent_key ) ) ) {

      /* If the parent was the last fec of the previous slot, the
         parent_key will be UINT_MAX. Need to query for the actual
         fec_set_idx of the last FEC. This is the double query */

      parent_key = fd_fec_parents_query( chainer->parents, parent_key->parent_key, NULL );
      if( !parent_key ) continue; /* still orphaned */
    }

    fd_fec_ele_t * parent = fd_fec_frontier_ele_remove( chainer->frontier, &parent_key->parent_key, NULL, chainer->pool );
    if( FD_LIKELY( parent ) ) fd_fec_ancestry_ele_insert( chainer->ancestry, parent, chainer->pool );
    else parent = fd_fec_ancestry_ele_query( chainer->ancestry, &parent_key->parent_key, NULL, chainer->pool );

    /* If the parent is not in frontier or ancestry, ele is still
       orphaned. Note it is possible to have inserted ele's parent but
       have ele still be orphaned, because parent is also orphaned. */

    if( FD_UNLIKELY( !parent ) ) continue;

    /* Remove ele from orphaned. */

    fd_fec_ele_t * remove = fd_fec_orphaned_ele_remove( chainer->orphaned, &ele->key, NULL, chainer->pool );
    FD_TEST( remove == ele );

    /* Verify the chained merkle root. */

    uchar zeros[ FD_SHRED_MERKLE_ROOT_SZ ] = { 0 }; /* FIXME */
    if ( FD_UNLIKELY( memcmp( ele->chained_merkle_root, parent->merkle_root, FD_SHRED_MERKLE_ROOT_SZ ) ) &&
                    ( memcmp( ele->chained_merkle_root, zeros,               FD_SHRED_MERKLE_ROOT_SZ ) ) ) {
      /* FIXME this requires a lot of changes to shred tile without
         fixed-32 fec sets, so disabled until then (impending agave 2.3
         release). */

      // FD_LOG_NOTICE(( "actual %lu %u %s", ele->slot, ele->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( ele->chained_merkle_root ) ));
      // FD_LOG_NOTICE(( "expected %lu %u %s", parent->slot, parent->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( parent->merkle_root ) ));
      // fd_fec_out_push_tail( chainer->out, (fd_fec_out_t){ .slot = ele->slot, .parent_off = ele->parent_off, .fec_set_idx = ele->fec_set_idx, .data_cnt = ele->data_cnt, .data_complete = ele->data_complete, .slot_complete = ele->slot_complete, .err = FD_FEC_CHAINER_ERR_MERKLE } );
      // continue;
    }

    /* Insert into frontier (ele is either advancing a fork or starting
       a new fork) and deliver to `out`. */

    fd_fec_frontier_ele_insert( chainer->frontier, ele, chainer->pool );
    // FD_LOG_NOTICE(( "pushing tail %lu %u %u %d %d", ele->slot, ele->fec_set_idx, ele->data_cnt, ele->data_complete, ele->slot_complete ));
    fd_fec_out_push_tail( chainer->out, (fd_fec_out_t){ .slot = ele->slot, .parent_off = ele->parent_off, .fec_set_idx = ele->fec_set_idx, .data_cnt = ele->data_cnt, .data_complete = ele->data_complete, .slot_complete = ele->slot_complete, .err = FD_FEC_CHAINER_SUCCESS } );

    /* Check whether any of ele's children are orphaned and can be
       chained into the frontier. */

    /* TODO this BFS can be structured differently without using any
       additional memory by reusing ele->next. */

    if( FD_UNLIKELY( ele->slot_complete ) ) {
      fd_fec_children_t * fec_children = fd_fec_children_query( chainer->children, ele->slot, NULL );
      if( FD_UNLIKELY( !fec_children ) ) continue;
      for( ulong off = fd_slot_child_offs_const_iter_init( fec_children->child_offs );
           !fd_slot_child_offs_const_iter_done( off );
           off = fd_slot_child_offs_const_iter_next( fec_children->child_offs, off ) ) {
        ulong child_key = (ele->slot + off) << 32; /* always fec_set_idx 0 */
        fd_fec_ele_t * child = fd_fec_orphaned_ele_query( chainer->orphaned, &child_key, NULL, chainer->pool );
        if( FD_LIKELY( child ) ) {
          fd_fec_queue_push_tail( chainer->queue, child_key );
        }
      }
    } else {
      ulong child_key = (ele->slot << 32) | (ele->key + ele->data_cnt);
      fd_fec_queue_push_tail( chainer->queue, child_key );
    }
  }
}

fd_fec_ele_t *
fd_fec_chainer_insert( fd_fec_chainer_t * chainer,
                       ulong              slot,
                       uint               fec_set_idx,
                       ushort             data_cnt,
                       int                data_complete,
                       int                slot_complete,
                       ushort             parent_off,
                       uchar const        merkle_root[static FD_SHRED_MERKLE_ROOT_SZ],
                       uchar const        chained_merkle_root[static FD_SHRED_MERKLE_ROOT_SZ] ) {
  ulong key = slot << 32 | fec_set_idx;
  // FD_LOG_NOTICE(( "inserting %lu %u %u %d %d", slot, fec_set_idx, data_cnt, data_complete, slot_complete ));

  if( FD_UNLIKELY( fd_fec_chainer_query( chainer, slot, fec_set_idx ) ) ) {
    fd_fec_out_push_tail( chainer->out, (fd_fec_out_t){ slot, parent_off, fec_set_idx, data_cnt, data_complete, slot_complete, .err = FD_FEC_CHAINER_ERR_UNIQUE } );
    return NULL;
  }

# if FD_FEC_CHAINER_USE_HANDHOLDING
  FD_TEST( fd_fec_pool_free( chainer->pool ) ); /* FIXME lru? */
  FD_TEST( fd_fec_parents_key_cnt( chainer->parents ) < fd_fec_parents_key_max( chainer->parents ) );
  FD_TEST( fd_fec_children_key_cnt( chainer->children ) < fd_fec_children_key_max( chainer->children ) );
# endif

  fd_fec_ele_t * ele = fd_fec_pool_ele_acquire( chainer->pool );
  ele->key           = key;
  ele->slot          = slot;
  ele->fec_set_idx   = fec_set_idx;
  ele->data_cnt      = data_cnt;
  ele->data_complete = data_complete;
  ele->slot_complete = slot_complete;
  ele->parent_off    = parent_off;
  memcpy( ele->merkle_root, merkle_root, FD_SHRED_MERKLE_ROOT_SZ );
  memcpy( ele->chained_merkle_root, chained_merkle_root, FD_SHRED_MERKLE_ROOT_SZ );

  /* If it is the first FEC set, derive and insert parent_key->key into
     the parents map and parent_slot->slot into the children map. */

  if( FD_UNLIKELY( fec_set_idx == 0 ) ) {
    ulong parent_slot = slot - parent_off;

    fd_fec_parent_t * parent_key = fd_fec_parents_insert( chainer->parents, key );
    parent_key->parent_key       = (parent_slot << 32) | UINT_MAX;

    fd_fec_children_t * fec_children = fd_fec_children_query( chainer->children, parent_slot, NULL );
    if( FD_LIKELY( !fec_children ) ) {
      fec_children = fd_fec_children_insert( chainer->children, parent_slot );
      fd_slot_child_offs_null( fec_children->child_offs );
    }
    fd_slot_child_offs_insert( fec_children->child_offs, parent_off );
  }

  /* Derive and insert the child_key->key into the parents map. */

  ulong child_key = ( slot << 32 ) | ( fec_set_idx + data_cnt );
  if( FD_UNLIKELY( slot_complete ) ) {

    /* This is the last FEC set. There is a special case to add
       a UINT_MAX -> fec_set_idx link because the child slots will chain
       off of UINT_MAX, but the pool_ele will be keyed on fec_set_idx. */

    fd_fec_parent_t * parent = fd_fec_parents_insert( chainer->parents, slot << 32 | UINT_MAX );
    parent->parent_key       = key;

  } else {

    /* This is not the last FEC set. */
    /* Key the child to point to ele (child's parent). */

    if( !fd_fec_parents_query( chainer->parents, child_key, NULL ) ) {
      fd_fec_parent_t * parent = fd_fec_parents_insert( chainer->parents, child_key );
      parent->parent_key = key;
    } else {
      fd_fec_parent_t * parent = fd_fec_parents_query( chainer->parents, child_key, NULL );
      if( parent->parent_key != key ) {
        FD_LOG_ERR(( "inconsistent keys %lu %u %lu %u", slot, fec_set_idx, parent->parent_key >> 32, (uint)parent->parent_key ));
      }
    }
  }

  /* Push ele into the BFS deque and the orphaned map for processing. */

  fd_fec_queue_push_tail( chainer->queue, key );
  fd_fec_orphaned_ele_insert( chainer->orphaned, ele, chainer->pool );

  link_orphans( chainer );

  return ele;
}
