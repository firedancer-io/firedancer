#include "fd_chainer.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <stdio.h>

void *
fd_chainer_new( void * shmem, ulong ele_max, ulong seed ) {
  ulong footprint = fd_chainer_footprint( ele_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(("bad footprint: %lu", ele_max));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  fd_chainer_t * chainer;

  ulong fec_max        = ele_max * FD_FEC_BLK_MAX;
  ulong fec_chain_cnt  = fd_fec_map_chain_cnt_est  ( fec_max );
  ulong slot_chain_cnt = fd_slotv_map_chain_cnt_est( ele_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  chainer             = FD_SCRATCH_ALLOC_APPEND( l, fd_chainer_align(),      sizeof(fd_chainer_t)                        );
  void * fec_pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_pool_align(),     fd_fec_pool_footprint    ( fec_max )        );
  void * fec_map      = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_map_align(),      fd_fec_map_footprint     ( fec_chain_cnt  ) );
  void * slotv_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_pool_align(),   fd_slotv_pool_footprint  ( ele_max        ) );
  void * slotv_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_map_align(),    fd_slotv_map_footprint   ( slot_chain_cnt ) );
  void * repair_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_repair_align(), fd_slotv_repair_footprint( ele_max )        );
  void * orphan_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_orphan_align(), fd_slotv_orphan_footprint( ele_max )        );
  void * bfs          = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),             bfs_footprint            ( ele_max )        );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_chainer_align() ) == (ulong)shmem + footprint );

  chainer->root               = ULONG_MAX;
  chainer->highest_repaired   = 0UL;
  chainer->wksp_gaddr         = fd_wksp_gaddr_fast( wksp, chainer );
  chainer->fec_pool_gaddr     = fd_wksp_gaddr_fast( wksp, fd_fec_pool_join    ( fd_fec_pool_new    ( fec_pool,     fec_max              ) ) );
  chainer->fec_map_gaddr      = fd_wksp_gaddr_fast( wksp, fd_fec_map_join     ( fd_fec_map_new     ( fec_map,      fec_chain_cnt,  seed ) ) );
  chainer->slotv_pool_gaddr   = fd_wksp_gaddr_fast( wksp, fd_slotv_pool_join  ( fd_slotv_pool_new  ( slotv_pool,   ele_max              ) ) );
  chainer->slotv_map_gaddr    = fd_wksp_gaddr_fast( wksp, fd_slotv_map_join   ( fd_slotv_map_new   ( slotv_map,    slot_chain_cnt, seed ) ) );
  chainer->repair_treap_gaddr = fd_wksp_gaddr_fast( wksp, fd_slotv_repair_join( fd_slotv_repair_new( repair_treap, ele_max              ) ) );
  chainer->orphan_treap_gaddr = fd_wksp_gaddr_fast( wksp, fd_slotv_orphan_join( fd_slotv_orphan_new( orphan_treap, ele_max              ) ) );
  chainer->bfs_gaddr          = fd_wksp_gaddr_fast( wksp, bfs_join            ( bfs_new            ( bfs,          ele_max              ) ) );

  fd_slotv_repair_seed( fd_chainer_slotv_pool( chainer ), ele_max, seed        );
  fd_slotv_orphan_seed( fd_chainer_slotv_pool( chainer ), ele_max, seed ^ 0x9eUL );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( chainer->magic ) = FD_CHAINER_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_chainer_t *
fd_chainer_join( void * shchainer ) {
  fd_chainer_t * chainer = (fd_chainer_t *)shchainer;
  if( FD_UNLIKELY( chainer->magic!=FD_CHAINER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return chainer;
}

/* acquire_slotv allocates, initializes, and map-inserts an slotv for
   (slot, version). */

static fd_slotv_t *
acquire_slotv( fd_chainer_t * chainer, ulong slot, ulong version ) {
  fd_slotv_map_t * slotv_map  = fd_chainer_slotv_map ( chainer );
  fd_slotv_t     * slotv_pool = fd_chainer_slotv_pool( chainer );
  FD_TEST( fd_slotv_pool_free( slotv_pool ) );

  fd_slotv_t * slotv = fd_slotv_pool_ele_acquire( slotv_pool );
  slotv->key               = FD_CHAINER_SLOTV_KEY( slot, version );
  slotv->parent_slot       = AG_UNKNOWN_SLOT;
  slotv->parent_slot_batch = UINT_MAX;
  slotv->complete_idx      = UINT_MAX;
  slotv->buffered_idx      = UINT_MAX;
  slotv->buffered_fec_idx  = UINT_MAX;
  slotv->delivered_idx     = UINT_MAX;
  slotv->connected         = 0;
  slotv->highest_requested = UINT_MAX;
  slotv->in_treap          = 0;
  slotv->in_orphan         = 0;

  fd_memset( &slotv->block_id,        0, sizeof(fd_hash_t) );
  fd_memset( &slotv->parent_block_id, 0, sizeof(fd_hash_t) );
  fd_shred_idxs_null( slotv->shred_idxs );

  fd_slotv_map_ele_insert( slotv_map, slotv, slotv_pool );
  fd_chainer_repair_add( chainer, slotv ); /* new slotv -> has un-requested shreds */
  fd_chainer_orphan_add( chainer, slotv ); /* new slotv -> ancestry unknown until parent confirmed present */
  return slotv;
}

void
fd_chainer_init( fd_chainer_t    * chainer,
                 ulong             slot,
                 fd_hash_t const * block_id ) {
  fd_slotv_t * slotv = acquire_slotv( chainer, slot, 0 );
  slotv->parent_slot = slot;
  slotv->complete_idx      = 0;
  slotv->buffered_idx      = 0;
  slotv->connected         = 1;
  slotv->delivered_idx     = 0; /* must equal complete_idx at init */
  slotv->highest_requested = 0;
  slotv->block_id          = *block_id;
  fd_chainer_repair_remove( chainer, slotv );
  fd_chainer_orphan_remove( chainer, slotv );

  chainer->root = slot;
  chainer->highest_repaired = slot;
}

static inline ushort
fec_version( ulong key ) {
  return (ushort)fd_ulong_extract_lsb( key, 2 );
}

static inline ushort
slotv_version( ulong key ) {
  return (ushort)fd_ulong_extract_lsb( key, 2 );
}

static inline ulong
slotv_slot( ulong key ) {
  return key >> 17;
}

/* fd_chainer_fec_query returns the FEC for the exact (slot, fec_set_idx,
   version), or NULL. */

fd_fec_t *
fd_chainer_fec_query( fd_chainer_t * chainer,
                      ulong          slot,
                      uint           fec_set_idx,
                      ulong          version ) {
  fd_fec_map_t * fec_map  = fd_chainer_fec_map ( chainer );
  fd_fec_t     * fec_pool = fd_chainer_fec_pool( chainer );
  ulong key = FD_CHAINER_FEC_KEY( slot, fec_set_idx, version );
  return fd_fec_map_ele_query( fec_map, &key, NULL, fec_pool );
}

/* fec_exists returns the earliest version FEC if any (slot, fec_set_idx) exists, or NULL. */

static fd_fec_t *
fec_exists( fd_chainer_t * chainer, ulong slot, uint fec_set_idx ) {
  return fd_chainer_fec_query( chainer, slot, fec_set_idx, 0 );
}

/* fec_query returns the FEC at (slot, fec_set_idx) whose merkle_root
   matches mr, across all versions, or NULL. */

static fd_fec_t *
fec_query( fd_chainer_t * chainer, ulong slot, uint fec_set_idx, fd_hash_t const * mr ) {
  for( ulong v=0UL; v<FD_CHAINER_SLOT_VER_MAX; v++ ) {
    fd_fec_t * fec = fd_chainer_fec_query( chainer, slot, fec_set_idx, v );
    if( FD_LIKELY( fec ) && fd_hash_eq( &fec->merkle_root, mr ) ) return fec;
  }
  return NULL;
}

/* acquire_fec allocates and map-inserts a FEC for (slot, fec_set_idx,
   version) with the given root.  sentinel=1 marks a not-yet-completed
   FEC known-canonical from a notar-fallback getFecRoot. */

static fd_fec_t *
acquire_fec( fd_chainer_t    * chainer,
             ulong             slot,
             uint              fec_set_idx,
             ulong             version,
             fd_hash_t const * mr,
             int               sentinel ) {
  fd_fec_map_t * fec_map  = fd_chainer_fec_map ( chainer );
  fd_fec_t     * fec_pool = fd_chainer_fec_pool( chainer );

  if( FD_UNLIKELY( !fd_fec_pool_free( fec_pool ) ) ) FD_LOG_CRIT(( "fec_pool is full" ));
  fd_fec_t * fec = fd_fec_pool_ele_acquire( fec_pool );
  fec->key           = FD_CHAINER_FEC_KEY( slot, fec_set_idx, version );
  fec->merkle_root   = *mr;
  fec->slot_complete = 0;
  fec->data_complete = 0;
  fec->sentinel      = (uchar)sentinel;
  fd_fec_map_ele_insert( fec_map, fec, fec_pool );
  return fec;
}

/* slotv_query returns the slotv for the exact (slot, version), or NULL. */

static fd_slotv_t *
slotv_query( fd_chainer_t * chainer, ulong slot, ulong version ) {
  fd_slotv_map_t * slotv_map  = fd_chainer_slotv_map ( chainer );
  fd_slotv_t     * slotv_pool = fd_chainer_slotv_pool( chainer );
  ulong key = FD_CHAINER_SLOTV_KEY( slot, version );
  return fd_slotv_map_ele_query( slotv_map, &key, NULL, slotv_pool );
}

/* finalize_block_id computes the slotv's double-merkle block_id and
   writes it to slotv->block_id.  Returns 1 on success, 0 on failure.

   TODO this computation also happens in replay_tile, so maybe we should
   consolidate them, i.e. compute here and pass to replay_tile. */

static int
finalize_block_id( fd_chainer_t * chainer, fd_slotv_t * slotv ) {
  ulong slot    = FD_CHAINER_SLOTV_SLOT   ( slotv->key );
  ulong version = FD_CHAINER_SLOTV_VERSION( slotv->key );

  if( FD_UNLIKELY( slotv->complete_idx==UINT_MAX ) )                 return 0;
  if( FD_UNLIKELY( slotv->parent_slot==AG_UNKNOWN_SLOT ) )           return 0;
  if( FD_UNLIKELY( fd_hash_check_zero( &slotv->parent_block_id ) ) ) return 0;

  uint fec_set_cnt = ( slotv->complete_idx + 1U ) / FD_FEC_SHRED_CNT;
  uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, 20UL, FD_BMTREE_LONG_PREFIX_SZ, 0UL );

  for( uint i=0U; i<fec_set_cnt; i++ ) {
    fd_fec_t * fec = fd_chainer_fec_query( chainer, slot, i*FD_FEC_SHRED_CNT, version );
    if( FD_UNLIKELY( !fec ) ) return 0;

    fd_bmtree_node_t leaf[1];
    memcpy( leaf->hash, fec->merkle_root.uc, sizeof(fd_hash_t) );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }

  /* final parent-info leaf */
  fd_bmtree_node_t parent_info[1];
  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &slotv->parent_slot,       sizeof(ulong)     );
  fd_sha256_append( sha, slotv->parent_block_id.uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &fec_set_cnt,              sizeof(uint)      );
  fd_sha256_fini  ( sha, parent_info->hash );
  fd_bmtree_commit_append( tree, parent_info, 1UL );

  uchar * root = fd_bmtree_commit_fini( tree );
  memcpy( slotv->block_id.uc, root, sizeof(fd_hash_t) );
  return 1;
}

void
fd_chainer_shred_insert( fd_chainer_t    * chainer,
                         ulong             slot,
                         uint              shred_idx,
                         int               slot_complete,
                         fd_hash_t const * mr,
                         ulong             parent_slot,
                         fd_hash_t const * parent_block_id ) {

  uint fec_set_idx = shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );
  ulong version = 0UL;

  /* If no FEC has this root, accept it only as a version 0 iff the slot
     is still single-version (or has no version yet) and this FEC set
     has no version yet; otherwise drop (equivocation without a
     sentinel). */
  fd_fec_t * fec = fec_query( chainer, slot, fec_set_idx, mr );
  if( FD_UNLIKELY( !fec ) ) {
    if( FD_UNLIKELY( !!slotv_query( chainer, slot, 1 ) || fec_exists( chainer, slot, fec_set_idx ) ) ) return;
    version = 0UL;
  } else {
    version = fec_version( fec->key );
  }

  fd_slotv_t * slotv = slotv_query( chainer, slot, version );
  if( FD_UNLIKELY( !slotv ) ) {
    if( FD_LIKELY( version==0UL ) ) slotv = acquire_slotv( chainer, slot, 0UL );
    else FD_LOG_CRIT(( "shred for version %lu of slot %lu but no slotv -- sentinel path should have created it", version, slot ));
  }

  /* update shred indexing */
  fd_shred_idxs_insert( slotv->shred_idxs, shred_idx );
  if( FD_UNLIKELY( slot_complete ) ) slotv->complete_idx = shred_idx;
  while( slotv->buffered_idx + 1 < FD_SHRED_BLK_MAX && fd_shred_idxs_test( slotv->shred_idxs, slotv->buffered_idx + 1U ) ) {
    slotv->buffered_idx++;
  }
  /* If equivocating, buffered_idx needs to be clamped to complete_idx */
  if( FD_UNLIKELY( slotv->buffered_idx != UINT_MAX && slotv->complete_idx != UINT_MAX && slotv->buffered_idx > slotv->complete_idx ) ) slotv->buffered_idx = slotv->complete_idx;

  /* update parent information*/
  if( FD_UNLIKELY( parent_slot != AG_UNKNOWN_SLOT ) ) {
    slotv->parent_slot = parent_slot;
    if( FD_LIKELY( slotv_query( chainer, parent_slot, 0 ) ) ) {
      // TODO is this safe? -- check for FLH case
      fd_chainer_orphan_remove( chainer, slotv );
    }
    FD_TEST( parent_block_id ); /* TODO do handholding check */

    slotv->parent_block_id = *parent_block_id;
    fd_slotv_t * parent = fd_chainer_slot_version_query( chainer, parent_slot, parent_block_id );
    if( FD_LIKELY( parent && parent->connected ) ) slotv->connected = 1;
  }
}

/* send to replay */
static void
chainer_deliver( fd_chainer_t    * chainer,
                 ulong             slot,
                 ulong             version,
                 uint              fec_set_idx,
                 fd_hash_t const * block_id ) {
  (void)chainer; (void)slot; (void)version; (void)fec_set_idx; (void)block_id;
}

/* chainer_advance delivers as many contiguous completed FEC sets as
   possible from `seed`, then cascades: when an slotv's slot_complete
   FEC is delivered, every child slotv (parent_block_id == this slotv's
   block_id) becomes connected and is drained in turn.  A bfs queue
   bounds recursion depth over the ancestry chain. */

static void
chainer_advance( fd_chainer_t * chainer, fd_slotv_t * seed ) {
  fd_slotv_map_t * slotv_map  = fd_chainer_slotv_map ( chainer );
  fd_slotv_t     * slotv_pool = fd_chainer_slotv_pool( chainer );
  ulong          * bfs        = fd_chainer_bfs       ( chainer );

  bfs_push_tail( bfs, fd_slotv_pool_idx( slotv_pool, seed ) );

  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_slotv_t * slotv = fd_slotv_pool_ele( slotv_pool, bfs_pop_head( bfs ) );
    if( FD_UNLIKELY( !slotv->connected ) ) continue;

    fd_slotv_t * parent = fd_chainer_slot_version_query( chainer, slotv->parent_slot, &slotv->parent_block_id );
    if( FD_UNLIKELY( !parent || parent->complete_idx == UINT_MAX || parent->delivered_idx != parent->complete_idx ) ) continue;

    ulong slot    = slotv_slot   ( slotv->key );
    ulong version = slotv_version( slotv->key );

    for(;;) {
      uint next = slotv->delivered_idx==UINT_MAX ? 0u : slotv->delivered_idx + 1;
      fd_fec_t * fec = fd_chainer_fec_query( chainer, slot, next, version );
      if( FD_LIKELY( !fec || fec->sentinel ) ) break; /* next FEC not completed yet */

      chainer_deliver( chainer, slot, version, next, &slotv->block_id );
      slotv->delivered_idx = next + (FD_FEC_SHRED_CNT - 1);

      if( FD_UNLIKELY( fec->slot_complete ) ) {
        chainer->highest_repaired = fd_ulong_max( chainer->highest_repaired, slot ); /* contiguous-from-root tip */
        finalize_block_id( chainer, slotv );
        fd_chainer_repair_remove( chainer, slotv ); /* nothing left to repair */

        /* Enqueue children whose parent_block_id == this block_id.
           TODO index children by parent_block_id; O(n) scan for now.
           Requires slotv->block_id populated (repair tile). */
        if( FD_LIKELY( !fd_hash_check_zero( &slotv->block_id ) ) ) {
          for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                                       !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                                   it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
            fd_slotv_t * child = fd_slotv_map_iter_ele( it, slotv_map, slotv_pool );
            if( fd_hash_eq( &child->parent_block_id, &slotv->block_id ) ) {
              child->connected = 1;
              bfs_push_tail( bfs, fd_slotv_pool_idx( slotv_pool, child ) );
            }
          }
        }
        break;
      }
    }
  }
}


/* We make an effort to de-duplicate FECs i.e., not accept multiple
   completed versions through turbine.  fec_resolver also does a similar
   effort upstream. However, since fec_resolver has a finite done_map,
   its possible we can still receive multiple completed versions through
   turbine if the fec_resolver done map is getting churned.

   Case 1: we are recieving the first version of this FEC set.
   Case 2: FEC with mr already exists, mark them all non-sentinel.
   Case 3: FEC with mr does not exist, but another version of this FEC set exists with a different root ->
           means this is equivocating, but we didn't get a getSliceHash verified insert, drop. */
int
fd_chainer_fec_insert( fd_chainer_t * chainer,
                       ulong          slot,
                       uint           fec_set_idx_,
                       int            slot_complete,
                       fd_hash_t    * mr ) {
  uint fec_set_idx = (uint)fec_set_idx_;

  for( uint i = 0; i < FD_FEC_SHRED_CNT; i++ ) {
    fd_chainer_shred_insert( chainer, slot, fec_set_idx_ + i, slot_complete && (i == FD_FEC_SHRED_CNT - 1), mr, AG_UNKNOWN_SLOT, NULL );
  }

  /* Case 2: a FEC with this exact root already exists.  Fill every
     version that has it (turbine dup, or getFecRoot sentinels), clearing
     the sentinel -- one turbine/repair completion satisfies a
     shared-prefix FEC across all versions at once. */
  int matched = 0;
  for( ulong v=0UL; v<FD_CHAINER_SLOT_VER_MAX; v++ ) {
    fd_fec_t * fec = fd_chainer_fec_query( chainer, slot, fec_set_idx, v );
    if( !fec || !fd_hash_eq( &fec->merkle_root, mr ) ) continue;
    fec->sentinel = 0;
    if( slot_complete ) fec->slot_complete = 1;
    matched = 1;
    fd_slotv_t * slotv = slotv_query( chainer, slot, v );
    if( FD_LIKELY( slotv ) ) chainer_advance( chainer, slotv );
  }
  if( matched ) return 0;

  /* Case 3: some other version of this FEC set exists with a different
     root, and no sentinel authorized this root -> equivocation, drop. */
  if( FD_UNLIKELY( fec_exists( chainer, slot, fec_set_idx ) ) ) return 1;

  /* Case 1: first version of this FEC set -> version 0 (turbine). */
  fd_fec_t * fec = acquire_fec( chainer, slot, fec_set_idx, 0UL, mr, 0 /* not a sentinel */ );
  if( slot_complete ) fec->slot_complete = 1;
  fd_slotv_t * slotv = slotv_query( chainer, slot, 0 );
  if( FD_UNLIKELY( !slotv ) ) slotv = acquire_slotv( chainer, slot, 0 );

  while( fd_chainer_fec_query( chainer, slot, slotv->buffered_fec_idx + 1, 0 ) ) {
    slotv->buffered_fec_idx += FD_FEC_SHRED_CNT;
  }

  if( slotv->complete_idx != UINT_MAX && slotv->buffered_fec_idx == slotv->complete_idx ) {
    /* if slot is complete, we can record the block_id. We must have
       all the components of the block_id at this point. */
    if( !finalize_block_id( chainer, slotv ) ) FD_LOG_CRIT(( "failed to finalize block_id for slot %lu", slot ));
  }

  chainer_advance( chainer, slotv );
  return 0;
}

fd_slotv_t *
fd_chainer_verified_parent_fec_count( fd_chainer_t * chainer,
                                      ulong          slot,
                                      fd_hash_t    * block_id,
                                      uint           fec_set_cnt,
                                      ulong          parent_slot,
                                      fd_hash_t    * parent_block_id ) {
  fd_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) FD_LOG_CRIT(("slotv not found for slot %lu", slot ));

  slotv->complete_idx    = (fec_set_cnt*FD_FEC_SHRED_CNT) - 1;
  slotv->parent_slot     = parent_slot;
  slotv->parent_block_id = *parent_block_id;
  fd_chainer_repair_add( chainer, slotv ); /* tip now known -> re-add for shred fill */

  fd_slotv_t * parent_slotv = fd_chainer_slot_version_query( chainer, parent_slot, parent_block_id );
  if( FD_UNLIKELY( !parent_slotv ) ) {
    /* find next free version */
    ulong v = 0;
    for( ; v<FD_CHAINER_SLOT_VER_MAX; v++ ) {
      if( FD_LIKELY( !slotv_query( chainer, parent_slot, v ) ) ) break;
    }
    if( FD_UNLIKELY( v==FD_CHAINER_SLOT_VER_MAX ) ) FD_LOG_CRIT(( "more than %d versions for slot %lu", FD_CHAINER_SLOT_VER_MAX, parent_slot ));
    parent_slotv = acquire_slotv( chainer, parent_slot, v );
    parent_slotv->block_id = *parent_block_id;
  }
  fd_chainer_repair_add( chainer, parent_slotv );
  fd_chainer_orphan_add( chainer, parent_slotv );

  /* parent now identified -> connect this slotv if the parent is already connected */
  if( FD_UNLIKELY( parent_slotv->connected ) ) slotv->connected = 1;
  return slotv;
}

/* should get called by repair_tile on getFecRoot responses, after
   verifying the hash is correct for a notar-fallback-ed block */
void
fd_chainer_verified_hash_insert( fd_chainer_t * chainer,
                                 ulong          slot,
                                 fd_hash_t    * block_id,
                                 uint           fec_set_idx,
                                 fd_hash_t    * mr ) {
  fd_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) FD_LOG_CRIT(( "slotv not found for slot %lu - TODO verify this is a crit", slot ));
  ulong version = slotv_version( slotv->key );

  /* Already have this version's FEC entry -> nothing to fetch. */
  if( FD_UNLIKELY( fd_chainer_fec_query( chainer, slot, fec_set_idx, version ) ) ) return;

  /* the same root may already be filled under another
     version.  If it's already complete, create this version's entry
     already-complete so delivery doesn't stall on shreds that were
     handed to the other version.  Otherwise create a sentinel awaiting
     shreds; a later completion fills every matching-root version at
     once (see fd_chainer_fec_insert). */
  fd_fec_t * shared = fec_query( chainer, slot, fec_set_idx, mr );
  int shared_complete = shared && !shared->sentinel;
  fd_fec_t * fec = acquire_fec( chainer, slot, fec_set_idx, version, mr, !shared_complete /* sentinel */ );

  if( FD_UNLIKELY ( ( shared_complete && shared->slot_complete ) ||
                    ( slotv->complete_idx - FD_FEC_SHRED_CNT + 1 == fec_set_idx ) ) )
    fec->slot_complete = 1;

  fec->merkle_root = *mr;
  fd_chainer_repair_add( chainer, slotv ); /* new sentinel -> re-add for shred fill */
  chainer_advance( chainer, slotv );
}

int
fd_chainer_shred_for_block_id_verify( fd_chainer_t *    chainer,
                                      ulong             slot,
                                      uint              fec_set_idx,
                                      fd_hash_t const * block_id,
                                      fd_hash_t const * mr ) {
  fd_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) return 0;
  fd_fec_t * fec = fd_chainer_fec_query( chainer, slot, fec_set_idx, FD_CHAINER_SLOTV_VERSION( slotv->key ) );
  if( FD_UNLIKELY( !fec ) ) return 0;
  return fd_hash_eq( &fec->merkle_root, mr );
}


/* TODO need to handle when we get notar fallbacks before we've even
   completed the turbine version -- in that case we might be creating two
   copies of the exact same slotv */
void
fd_chainer_notar_fallback( fd_chainer_t * chainer,
                           ulong          slot,
                           fd_hash_t      block_id ) {
  /* if we already have an slotv with this block_id, no-op. */
  if( FD_LIKELY( fd_chainer_slot_version_query( chainer, slot, &block_id ) ) ) return;

  /* Assign the lowest free version so versions stay contiguous from 0 */
  ulong version = 0;
  for( ; version<FD_CHAINER_SLOT_VER_MAX; version++ ) {
    if( FD_LIKELY( !slotv_query( chainer, slot, version ) ) ) break;
  }
  if( FD_UNLIKELY( version==FD_CHAINER_SLOT_VER_MAX ) ) FD_LOG_CRIT(( "more than %d versions for slot %lu", FD_CHAINER_SLOT_VER_MAX, slot ));

  fd_slotv_t * slotv = acquire_slotv( chainer, slot, version );
  slotv->block_id = block_id;
}

void
fec_remove( fd_chainer_t * chainer,
            ulong          fec_key ) {
  fd_fec_t * fec_pool = fd_chainer_fec_pool( chainer );
  fd_fec_t * fec = fd_fec_map_ele_remove( fd_chainer_fec_map( chainer ), &fec_key, NULL, fec_pool );
  if( FD_UNLIKELY( !fec ) ) return;
  fd_fec_pool_ele_release( fec_pool, fec );
}

void
fd_chainer_publish( fd_chainer_t * chainer,
                    ulong          new_root ) {
  /* TODO should take the block_id of the new root */
  fd_slotv_map_t * slotv_map  = fd_chainer_slotv_map( chainer );
  fd_slotv_t     * slotv_pool = fd_chainer_slotv_pool( chainer );
  ulong root = chainer->root;
  if( FD_UNLIKELY( root==ULONG_MAX ) ) return;
  FD_TEST( root < new_root );
  FD_TEST( slotv_query( chainer, new_root, 0 ) );

  for( ulong slot=root; slot<new_root; slot++ ) {
    for( ulong v=0UL; v<FD_CHAINER_SLOT_VER_MAX; v++ ) {
      fd_slotv_t * slotv = slotv_query( chainer, slot, v );
      if( FD_UNLIKELY( !slotv ) ) break;
      fd_chainer_orphan_remove( chainer, slotv );
      fd_chainer_repair_remove( chainer, slotv );

      for( uint f=0UL; f<fd_ulong_min( slotv->complete_idx, 1024); f+=32 ) {
        /* pretty easily dos-able, think we should keep a list (in any order) of the fecs for an slotv
           ulong_min is a temp hack for now. */
        fec_remove( chainer, FD_CHAINER_FEC_KEY( slot, f, v ) );
      }
      fd_slotv_map_ele_remove( slotv_map, &slotv->key, NULL, slotv_pool );
      fd_slotv_pool_ele_release( slotv_pool, slotv );
    }
  }

  /* TODO prune away all other root versions when we wire through block_id*/
  chainer->root = new_root;
  for( ulong v=0UL; v<FD_CHAINER_SLOT_VER_MAX; v++ ) {
    fd_slotv_t * root_slotv = slotv_query( chainer, new_root, v );
    if( FD_UNLIKELY( !root_slotv ) ) break;
    if( FD_UNLIKELY( root_slotv->parent_slot==AG_UNKNOWN_SLOT ) ) {
      root_slotv->parent_slot = new_root;
    }
    root_slotv->connected = 1;
    fd_chainer_repair_remove( chainer, root_slotv );
    fd_chainer_orphan_remove( chainer, root_slotv );
  }
}

void
fd_chainer_print( fd_chainer_t * chainer ) {
  if( FD_UNLIKELY( chainer->root==ULONG_MAX ) ) return;

  fd_slotv_t        * slotv_pool = fd_chainer_slotv_pool  ( chainer );
  fd_slotv_orphan_t * otreap     = fd_chainer_orphan_treap( chainer );

  printf( "\n[Chainer] root: %lu, highest repaired: %lu\n", chainer->root, chainer->highest_repaired );
  printf( "[Orphan treap] slot vversion <- parent (buffered/complete)\n" );

  ulong cnt = 0UL;
  for( fd_slotv_orphan_fwd_iter_t oit = fd_slotv_orphan_fwd_iter_init( otreap, slotv_pool );
                                       !fd_slotv_orphan_fwd_iter_done( oit );
                                  oit = fd_slotv_orphan_fwd_iter_next( oit, slotv_pool ) ) {
    fd_slotv_t * o = fd_slotv_orphan_fwd_iter_ele( oit, slotv_pool );

    ulong slot    = FD_CHAINER_SLOTV_SLOT   ( o->key );
    ulong version = FD_CHAINER_SLOTV_VERSION( o->key );

    /* buffered_idx / complete_idx are UINT_MAX when unknown; +1 wraps
       those to 0 (same convention as fd_forest_print) */
    if( FD_UNLIKELY( o->parent_slot==AG_UNKNOWN_SLOT ) ) printf( "%lu v%lu <- ??? (%u/%u)\n", slot, version, o->buffered_idx+1U, o->complete_idx+1U );
    else                                                 printf( "%lu v%lu (%u/%u)<- %lu\n ", slot, version, o->buffered_idx+1U, o->complete_idx+1U, o->parent_slot );
    cnt++;
  }
  printf( "(%lu orphans, %lu total slotvs)\n", cnt, fd_slotv_pool_max( slotv_pool ) - fd_slotv_pool_free( slotv_pool ) );
  /* print all the slotvs in the pool */
  //fd_slotv_map_t * slotv_map = fd_chainer_slotv_map( chainer );
  //for( fd_slotv_map_iter_t eit = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                                //!fd_slotv_map_iter_done( eit, slotv_map, slotv_pool );
                           //eit = fd_slotv_map_iter_next( eit, slotv_map, slotv_pool ) ) {
    //fd_slotv_t * e = fd_slotv_map_iter_ele( eit, slotv_map, slotv_pool );
    //printf( "%lu v%lu (%u/%u)<- %lu\n", FD_CHAINER_SLOTV_SLOT( e->key ), FD_CHAINER_SLOTV_VERSION( e->key ), e->buffered_idx+1U, e->complete_idx+1U, e->parent_slot );
  //}

  fd_slotv_t * slotv = fd_chainer_slot_query( chainer, 10892477 );
  if( FD_LIKELY( slotv ) ) {
    printf( "slotv: %lu v%lu (%u/%u)<- %lu, parent hash zero %d\n", FD_CHAINER_SLOTV_SLOT( slotv->key ), FD_CHAINER_SLOTV_VERSION( slotv->key ), slotv->buffered_idx+1U, slotv->complete_idx+1U, slotv->parent_slot, fd_hash_check_zero( &slotv->parent_block_id ) );

    uint fec_set_cnt = ( slotv->complete_idx + 1U ) / FD_FEC_SHRED_CNT;

    for( uint i=0U; i<fec_set_cnt; i++ ) {
      fd_fec_t * fec = fd_chainer_fec_query( chainer, FD_CHAINER_SLOTV_SLOT( slotv->key ), i*FD_FEC_SHRED_CNT, FD_CHAINER_SLOTV_VERSION( slotv->key ) );
      if( FD_UNLIKELY( !fec ) ) FD_LOG_NOTICE(("fec not found for slot %lu, fec_set_idx %u, version %lu", FD_CHAINER_SLOTV_SLOT( slotv->key ), i*FD_FEC_SHRED_CNT, FD_CHAINER_SLOTV_VERSION( slotv->key ) ));
    }
  }
  fflush( stdout ); /* Ensure slotv map printf output is flushed */
}