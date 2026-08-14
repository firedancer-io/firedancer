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
  void * out_queue    = FD_SCRATCH_ALLOC_APPEND( l, out_queue_align(),       out_queue_footprint      ( fec_max )        );
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
  chainer->out_queue_gaddr    = fd_wksp_gaddr_fast( wksp, out_queue_join      ( out_queue_new      ( out_queue,    fec_max              ) ) );

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
  FD_TEST( version<FD_CHAINER_SLOT_VER_MAX );

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
  slotv->fec_head          = fd_fec_pool_idx_null( fd_chainer_fec_pool( chainer ) );

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

/* slotv_query returns the slotv for the exact (slot, version), or NULL. */

static fd_slotv_t *
slotv_query( fd_chainer_t * chainer, ulong slot, ulong version ) {
  fd_slotv_map_t * slotv_map  = fd_chainer_slotv_map ( chainer );
  fd_slotv_t     * slotv_pool = fd_chainer_slotv_pool( chainer );
  ulong key = FD_CHAINER_SLOTV_KEY( slot, version );
  return fd_slotv_map_ele_query( slotv_map, &key, NULL, slotv_pool );
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
  ulong key = FD_CHAINER_FEC_KEY( slot, fec_set_idx );
  for( ulong idx = fd_fec_map_idx_query( fec_map, &key, ULONG_MAX, fec_pool );
             idx!=ULONG_MAX;
             idx = fd_fec_map_idx_next_const( idx, ULONG_MAX, fec_pool ) ) {
    fd_fec_t * fec = fd_fec_pool_ele( fec_pool, idx );
    if( FD_LIKELY( fd_slotv_set_test( fec->versions, version ) ) ) return fec;
  }
  return NULL;
}

/* fec_query returns the FEC at (slot, fec_set_idx) whose merkle_root
   matches mr, or NULL. */

static fd_fec_t *
fec_query( fd_chainer_t * chainer, ulong slot, uint fec_set_idx, fd_hash_t const * mr ) {
  fd_fec_map_t * fec_map  = fd_chainer_fec_map ( chainer );
  fd_fec_t     * fec_pool = fd_chainer_fec_pool( chainer );
  ulong key = FD_CHAINER_FEC_KEY( slot, fec_set_idx );
  for( ulong idx = fd_fec_map_idx_query( fec_map, &key, ULONG_MAX, fec_pool );
             idx!= ULONG_MAX;
             idx = fd_fec_map_idx_next_const( idx, ULONG_MAX, fec_pool ) ) {
    fd_fec_t * fec = fd_fec_pool_ele( fec_pool, idx );
    if( FD_LIKELY( fd_hash_eq( &fec->merkle_root, mr ) ) ) return fec;
  }
  return NULL;
}

/* fec_join records that version includes the FEC at (slot, fec_set_idx)
   with root mr, creating the entry if this root has not been seen at
   this position yet.  mark sentinel.   */

static fd_fec_t *
fec_join( fd_chainer_t    * chainer,
          ulong             slot,
          uint              fec_set_idx,
          ulong             version,
          fd_hash_t const * mr,
          int               sentinel ) {
  fd_fec_t * fec = fec_query( chainer, slot, fec_set_idx, mr );
  if( FD_UNLIKELY( !fec ) ) {
    fd_fec_map_t * fec_map  = fd_chainer_fec_map ( chainer );
    fd_fec_t     * fec_pool = fd_chainer_fec_pool( chainer );

    if( FD_UNLIKELY( !fd_fec_pool_free( fec_pool ) ) ) FD_LOG_CRIT(( "fec_pool is full" ));
    fec = fd_fec_pool_ele_acquire( fec_pool );
    fec->key           = FD_CHAINER_FEC_KEY( slot, fec_set_idx );
    fec->merkle_root   = *mr;
    fec->slot_complete = 0;
    fec->data_complete = 0;
    fec->sentinel      = (uchar)sentinel;
    fd_slotv_set_null( fec->versions );
    fd_fec_map_ele_insert( fec_map, fec, fec_pool );

    /* Thread onto this slot's FEC list, head-first (order and
       sentinel-status does not matter, publish just needs to reach them
       all).  The list is per-slot, so the head lives on version 0's
       slotv. */
    fd_slotv_t * head = slotv_query( chainer, slot, 0UL );
    if( FD_UNLIKELY( !head ) ) head = acquire_slotv( chainer, slot, 0UL );
    fec->slot_next = head->fec_head;
    head->fec_head = fd_fec_pool_idx( fec_pool, fec );
  }
  fd_slotv_set_insert( fec->versions, version );
  return fec;
}

/* next_free_alt_version returns the lowest unused version at or
   above 1 -- version 0 is reserved for “garbage” version of the slot,
   Returns FD_CHAINER_SLOT_VER_MAX if the slot has no free repair
   version left; callers must treat that as "no free version" and drop. */

static ulong
next_free_alt_version( fd_chainer_t * chainer, ulong slot ) {
  ulong version = 1UL;
  for( ; version<FD_CHAINER_SLOT_VER_MAX; version++ ) {
    if( FD_LIKELY( !slotv_query( chainer, slot, version ) ) ) break;
  }
  return version;
}

/* turbine_slotv_query returns version 0 of slot, the turbine version,
   creating it if it doesn't exist.
   Version 0 is reserved, so unlike an alt version this can never fail. */

static fd_slotv_t *
turbine_slotv_query( fd_chainer_t * chainer, ulong slot ) {
  fd_slotv_t * slotv = slotv_query( chainer, slot, 0UL );
  if( FD_UNLIKELY( !slotv ) ) slotv = acquire_slotv( chainer, slot, 0UL );
  return slotv;
}

int
fd_chainer_verify( fd_chainer_t const * chainer ) {
# define FAIL( msg ) do { FD_LOG_WARNING(( "fd_chainer_verify: %s", msg )); return -1; } while(0)

  if( FD_UNLIKELY( !chainer                                                   ) ) FAIL( "NULL chainer" );
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)chainer, fd_chainer_align() ) ) ) FAIL( "misaligned chainer" );
  if( FD_UNLIKELY( !fd_wksp_containing( chainer )                             ) ) FAIL( "chainer must be part of a workspace" );
  if( FD_UNLIKELY( chainer->magic!=FD_CHAINER_MAGIC                           ) ) FAIL( "bad magic" );

  fd_chainer_t * chainer_ = (fd_chainer_t *)chainer;

  fd_slotv_t        const * slotv_pool = fd_chainer_slotv_pool  ( chainer_ );
  fd_slotv_map_t    const * slotv_map  = fd_chainer_slotv_map   ( chainer_ );
  fd_slotv_repair_t const * rtreap     = fd_chainer_repair_treap( chainer_ );
  fd_slotv_orphan_t const * otreap     = fd_chainer_orphan_treap( chainer_ );
  fd_fec_t          const * fec_pool   = fd_chainer_fec_pool    ( chainer_ );
  fd_fec_map_t      const * fec_map    = fd_chainer_fec_map     ( chainer_ );

  if( FD_UNLIKELY( fd_slotv_map_verify( slotv_map, fd_slotv_pool_max( slotv_pool ), slotv_pool )==-1 ) ) FAIL( "slotv map corrupted" );
  if( FD_UNLIKELY( fd_fec_map_verify  ( fec_map,   fd_fec_pool_max  ( fec_pool   ), fec_pool   )==-1 ) ) FAIL( "fec map corrupted"   );
  if( FD_UNLIKELY( fd_slotv_repair_verify( rtreap, slotv_pool )==-1 ) ) FAIL( "repair treap corrupted" );
  if( FD_UNLIKELY( fd_slotv_orphan_verify( otreap, slotv_pool )==-1 ) ) FAIL( "orphan treap corrupted" );

  /* The root, if set, must have a version 0 and it must be connected --
     it is by definition the start of every ancestry chain. */

  if( FD_LIKELY( chainer->root!=ULONG_MAX ) ) {
    ulong root_key = FD_CHAINER_SLOTV_KEY( chainer->root, 0UL );
    fd_slotv_t const * root_slotv = fd_slotv_map_ele_query_const( slotv_map, &root_key, NULL, slotv_pool );
    if( FD_UNLIKELY( !root_slotv             ) ) FAIL( "root has no version 0 slotv" );
    if( FD_UNLIKELY( !root_slotv->connected  ) ) FAIL( "root slotv is not connected" );
  }

  ulong in_treap_cnt  = 0UL;
  ulong in_orphan_cnt = 0UL;

  /* Every FEC must appear on exactly one slot's list, so the total list
     length has to match the number of FECs in the map -- a mismatch means
     publish would leak (unlisted) or double-release (double-listed). */
  ulong list_cnt = 0UL;
  ulong fec_cnt  = 0UL;
  ulong fec_null = fd_fec_pool_idx_null( fec_pool );
  ulong fec_max  = fd_fec_pool_max( fec_pool );

  for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                               !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                           it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
    fd_slotv_t const * slotv = fd_slotv_map_iter_ele_const( it, slotv_map, slotv_pool );

    ulong slot    = FD_CHAINER_SLOTV_SLOT   ( slotv->key );
    ulong version = FD_CHAINER_SLOTV_VERSION( slotv->key );

    if( FD_UNLIKELY( FD_CHAINER_SLOTV_KEY( slot, version )!=slotv->key ) ) FAIL( "slotv key does not decode consistently" );
    if( FD_UNLIKELY( version>=FD_CHAINER_SLOT_VER_MAX                  ) ) FAIL( "slotv version out of range" );

    if( FD_UNLIKELY( fd_slotv_map_ele_query_const( slotv_map, &slotv->key, NULL, slotv_pool )!=slotv ) ) FAIL( "slotv not queryable by its own key" );

    /* Nothing below the root may survive a publish. */

    if( FD_UNLIKELY( chainer->root!=ULONG_MAX && slot<chainer->root ) ) FAIL( "slotv below the root" );

    /* The FEC list hangs off version 0 only, so no other version may
       claim a head, and every node on it must belong to this slot.  The
       walk is bounded by the pool size so a cycle fails instead of
       hanging. */

    if( FD_UNLIKELY( version && slotv->fec_head!=fec_null ) ) FAIL( "non-zero version holds a fec list head" );

    if( FD_LIKELY( !version ) ) {
      ulong steps = 0UL;
      for( ulong idx=slotv->fec_head; idx!=fec_null; ) {
        if( FD_UNLIKELY( idx>=fec_max ) ) FAIL( "fec list idx out of range" );
        fd_fec_t const * fec = fd_fec_pool_ele_const( fec_pool, idx );
        if( FD_UNLIKELY( ( fec->key>>17 )!=slot ) ) FAIL( "fec list holds a fec of another slot" );
        if( FD_UNLIKELY( ++steps>fec_max )        ) FAIL( "cycle in fec list" );
        list_cnt++;
        idx = fec->slot_next;
      }
    }

    /* Shred index bookkeeping */

    if( FD_UNLIKELY( slotv->complete_idx!=UINT_MAX && slotv->buffered_idx !=UINT_MAX &&
                     slotv->buffered_idx >slotv->complete_idx ) ) FAIL( "buffered_idx > complete_idx" );
    if( FD_UNLIKELY( slotv->complete_idx!=UINT_MAX && slotv->delivered_idx!=UINT_MAX &&
                     slotv->delivered_idx>slotv->complete_idx ) ) FAIL( "delivered_idx > complete_idx" );

    /* buffered_fec_idx is the last shred idx of a FEC set, so it is
       always one below a multiple of FD_FEC_SHRED_CNT (UINT_MAX, the
       "none" sentinel, satisfies this too). */

    if( FD_UNLIKELY( ( slotv->buffered_fec_idx + 1U ) % FD_FEC_SHRED_CNT ) ) FAIL( "buffered_fec_idx is not the last idx of a FEC set" );

    /* A buffered FEC set means all of its shreds are in hand, so the
       contiguous FEC prefix can never run ahead of the contiguous shred
       prefix. */

    if( FD_UNLIKELY( slotv->buffered_fec_idx!=UINT_MAX &&
                     ( slotv->buffered_idx==UINT_MAX ||
                       slotv->buffered_idx<slotv->buffered_fec_idx ) ) ) FAIL( "buffered_fec_idx runs ahead of buffered_idx" );

    /* Treap flags must agree with actual treap membership.  The treaps
       are keyed by slotv->key, which is unique per the check above. */

    if( FD_UNLIKELY( !!slotv->in_treap  != !!fd_slotv_repair_ele_query_const( rtreap, slotv->key, slotv_pool ) ) ) FAIL( "in_treap disagrees with repair treap membership" );
    if( FD_UNLIKELY( !!slotv->in_orphan != !!fd_slotv_orphan_ele_query_const( otreap, slotv->key, slotv_pool ) ) ) FAIL( "in_orphan disagrees with orphan treap membership" );

    in_treap_cnt  += !!slotv->in_treap;
    in_orphan_cnt += !!slotv->in_orphan;
  }

  /* No treap may hold an slotv that is not in the map (a stale treap
     link into a released pool element). */

  if( FD_UNLIKELY( in_treap_cnt !=fd_slotv_repair_ele_cnt( rtreap ) ) ) FAIL( "repair treap holds slotvs that are not in the map" );
  if( FD_UNLIKELY( in_orphan_cnt!=fd_slotv_orphan_ele_cnt( otreap ) ) ) FAIL( "orphan treap holds slotvs that are not in the map" );

  for( fd_fec_map_iter_t it = fd_fec_map_iter_init( fec_map, fec_pool );
                             !fd_fec_map_iter_done( it, fec_map, fec_pool );
                         it = fd_fec_map_iter_next( it, fec_map, fec_pool ) ) {
    fd_fec_t const * fec = fd_fec_map_iter_ele_const( it, fec_map, fec_pool );

    fec_cnt++;

    ulong slot        = fec->key>>17;
    uint  fec_set_idx = (uint)( fec->key & 0x1FFFFUL );

    if( FD_UNLIKELY( FD_CHAINER_FEC_KEY( slot, fec_set_idx )!=fec->key ) ) FAIL( "fec key does not decode consistently" );
    if( FD_UNLIKELY( fec_set_idx % FD_FEC_SHRED_CNT                    ) ) FAIL( "fec_set_idx is not a multiple of FD_FEC_SHRED_CNT" );
    if( FD_UNLIKELY( fec_set_idx>=FD_SHRED_BLK_MAX                     ) ) FAIL( "fec_set_idx out of range" );

    if( FD_UNLIKELY( chainer->root!=ULONG_MAX && slot<chainer->root ) ) FAIL( "fec below the root" );

    if( FD_UNLIKELY( fd_slotv_set_is_null( fec->versions ) ) ) FAIL( "fec claimed by no version" );

    /* A FEC is threaded onto version 0's list, so version 0 must exist for
       any slot that has one -- fec_join creates it if needed.  Without it
       publish could never reach the slot's FECs. */

    ulong anchor_key = FD_CHAINER_SLOTV_KEY( slot, 0UL );
    if( FD_UNLIKELY( !fd_slotv_map_ele_query_const( slotv_map, &anchor_key, NULL, slotv_pool ) ) ) FAIL( "slot has a fec but no version 0 to anchor the list" );

    /* A FEC is owned by the slotv of every version that includes it -- it
       is only ever joined alongside one, and publish releases both. */

    for( ulong version = fd_slotv_set_const_iter_init( fec->versions );
                        !fd_slotv_set_const_iter_done( version );
               version = fd_slotv_set_const_iter_next( fec->versions, version ) ) {
      ulong slotv_key = FD_CHAINER_SLOTV_KEY( slot, version );
      if( FD_UNLIKELY( !fd_slotv_map_ele_query_const( slotv_map, &slotv_key, NULL, slotv_pool ) ) ) FAIL( "fec has no owning slotv" );
    }

    /* A FEC merkle root appears at a position at most once and no two
       entries at a position claim the same version, else "version v's
       FEC at this index" is ambiguous. */

    int found = 0;
    for( ulong idx = fd_fec_map_idx_query_const( fec_map, &fec->key, ULONG_MAX, fec_pool );
               idx!=ULONG_MAX;
               idx = fd_fec_map_idx_next_const( idx, ULONG_MAX, fec_pool ) ) {
      fd_fec_t const * other = fd_fec_pool_ele_const( fec_pool, idx );
      if( other==fec ) { found = 1; continue; }

      if( FD_UNLIKELY( fd_hash_eq( &other->merkle_root, &fec->merkle_root ) ) ) FAIL( "two fecs at the same position share a merkle root" );

      for( ulong version = fd_slotv_set_const_iter_init( fec->versions );
                          !fd_slotv_set_const_iter_done( version );
                 version = fd_slotv_set_const_iter_next( fec->versions, version ) ) {
        if( FD_UNLIKELY( fd_slotv_set_test( other->versions, version ) ) ) FAIL( "two fecs at the same position claim the same version" );
      }
    }
    if( FD_UNLIKELY( !found ) ) FAIL( "fec not reachable from its own key" );
  }

  if( FD_UNLIKELY( list_cnt!=fec_cnt ) ) FAIL( "fec list total does not match the fec map" );

  return 0;
}
#undef FAIL

/* finalize_block_id computes the slotv's double-merkle block_id and
   writes it to slotv->block_id.  Returns 1 on success, 0 on failure. */

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
  FD_TEST( shred_idx < FD_SHRED_BLK_MAX ); // guaranteed by fec_resolver
  uint fec_set_idx = shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );

  /* Collect the slot versions this shred belongs to. If this shred
     belongs to a FEC set that is already present, multiple slot versions
     could be carrying this FEC root. */

  fd_slotv_set_t slotv_with_fec[fd_slotv_set_word_cnt];
  fd_slotv_set_null( slotv_with_fec );

  fd_fec_t * fec = fec_query( chainer, slot, fec_set_idx, mr );
  if( FD_UNLIKELY( fec ) ) fd_slotv_set_copy( slotv_with_fec, fec->versions );

  /* For now, we'll always accept the shred and into the turbine version
     of the slotv. The turbine version of the slotv can be considered a
     garbage can that accepts any and all shreds.  Something to consider
     - if we already have notar-fallback certs for this slot, maybe we
     shouldn't be accepting turbine shreds / shreds that don't verify
     into one of the notar-fallback versions at all. But for now we do. */
  turbine_slotv_query( chainer, slot );
  fd_slotv_set_insert( slotv_with_fec, 0UL );

  for( ulong i = fd_slotv_set_const_iter_init( slotv_with_fec );
                !fd_slotv_set_const_iter_done( i );
             i = fd_slotv_set_const_iter_next( slotv_with_fec, i ) ) {
    fd_slotv_t * slotv = slotv_query( chainer, slot, i );

    /* update shred indexing */
    fd_shred_idxs_insert( slotv->shred_idxs, shred_idx );
    if( FD_UNLIKELY( slot_complete ) ) slotv->complete_idx = shred_idx;
    while( slotv->buffered_idx + 1 < FD_SHRED_BLK_MAX && fd_shred_idxs_test( slotv->shred_idxs, slotv->buffered_idx + 1U ) ) {
      slotv->buffered_idx++;
    }
    /* If equivocating, buffered_idx needs to be clamped to complete_idx */
    if( FD_UNLIKELY( slotv->buffered_idx != UINT_MAX && slotv->complete_idx != UINT_MAX && slotv->buffered_idx > slotv->complete_idx ) ) slotv->buffered_idx = slotv->complete_idx;

    /* parent_slot_batch tracks which batch the information came from so a later UpdateParent supersedes the
       header (it may only move forward).  UINT_MAX means "nothing known
       yet", so it is not a batch index to compare against. */
    if( parent_slot != AG_UNKNOWN_SLOT &&
      ( slotv->parent_slot_batch==UINT_MAX || shred_idx>slotv->parent_slot_batch ) ) {
      slotv->parent_slot       = parent_slot;
      slotv->parent_slot_batch = shred_idx;
      FD_TEST( parent_block_id ); /* TODO do handholding check */
      if( fd_chainer_slot_version_query( chainer, parent_slot, parent_block_id ) ) {
        // TODO is this safe? -- check for FLH case
        fd_chainer_orphan_remove( chainer, slotv ); /* no longer unknown */
      }

      slotv->parent_block_id = *parent_block_id;
      fd_slotv_t * parent = fd_chainer_slot_version_query( chainer, parent_slot, parent_block_id );
      if( FD_LIKELY( parent && parent->connected ) ) slotv->connected = 1;
    }
  }
}

/* chainer_deliver queues a delivered FEC for publish to replay.  The
   repair tile drains the out_queue in after_credit. */
static void
chainer_deliver( fd_chainer_t    * chainer,
                 fd_slotv_t      * slotv FD_PARAM_UNUSED,
                 fd_fec_t        * fec ) {
  ulong * out_queue = fd_chainer_out_queue( chainer );
  if( FD_UNLIKELY( out_queue_full( out_queue ) ) ) FD_LOG_CRIT(( "chainer out_queue full" ));
  out_queue_push_tail( out_queue, fd_fec_pool_idx( fd_chainer_fec_pool( chainer ), fec ) );
}

/* chainer_advance delivers as many contiguous completed FEC sets as
   possible from `root` slotv, then cascades: when an slotv's
   slot_complete FEC is delivered, every child slotv (parent_block_id ==
   this slotv's block_id) becomes connected and is drained in turn. */

static void
chainer_advance( fd_chainer_t * chainer, fd_slotv_t * root ) {
  fd_slotv_map_t * slotv_map  = fd_chainer_slotv_map ( chainer );
  fd_slotv_t     * slotv_pool = fd_chainer_slotv_pool( chainer );
  ulong          * bfs        = fd_chainer_bfs       ( chainer );

  bfs_push_tail( bfs, fd_slotv_pool_idx( slotv_pool, root ) );

  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_slotv_t * slotv = fd_slotv_pool_ele( slotv_pool, bfs_pop_head( bfs ) );
    if( FD_UNLIKELY( !slotv->connected ) ) continue;

    fd_slotv_t * parent = fd_chainer_slot_version_query( chainer, slotv->parent_slot, &slotv->parent_block_id );
    if( FD_UNLIKELY( !parent || parent->complete_idx == UINT_MAX || parent->delivered_idx != parent->complete_idx ) ) continue;

    ulong slot    = FD_CHAINER_SLOTV_SLOT   ( slotv->key );
    ulong version = FD_CHAINER_SLOTV_VERSION( slotv->key );

    for(;;) {
      uint next = slotv->delivered_idx==UINT_MAX ? 0u : slotv->delivered_idx + 1;
      fd_fec_t * fec = fd_chainer_fec_query( chainer, slot, next, version );
      if( FD_LIKELY( !fec || fec->sentinel ) ) break; /* next FEC not completed yet */

      chainer_deliver( chainer, slotv, fec );
      slotv->delivered_idx = next + (FD_FEC_SHRED_CNT - 1);

      if( FD_UNLIKELY( fec->slot_complete ) ) {
        chainer->highest_repaired = fd_ulong_max( chainer->highest_repaired, slot ); /* contiguous-from-root tip */
        if( FD_LIKELY( fd_hash_check_zero( &slotv->block_id ) ) ) finalize_block_id( chainer, slotv );
        fd_chainer_repair_remove( chainer, slotv ); /* nothing left to repair */

        /* Enqueue children whose parent_block_id == this block_id.
           TODO index children by parent_block_id; O(n) scan for now. */
        if( FD_LIKELY( !fd_hash_check_zero( &slotv->block_id ) ) ) {
          for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                                       !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                                   it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
            fd_slotv_t * child = fd_slotv_map_iter_ele( it, slotv_map, slotv_pool );
            if( FD_UNLIKELY( fd_hash_eq( &child->parent_block_id, &slotv->block_id ) ) ) {
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

   Note the turbine slotv will only accept the first version at this
   FEC set index.  Otherwise, we will accept this FEC if a slot version
   created by a notar-fallback cert claims this FEC set. */
int
fd_chainer_fec_insert( fd_chainer_t * chainer,
                       ulong          slot,
                       uint           fec_set_idx_,
                       int            slot_complete,
                       int            data_complete,
                       fd_hash_t    * mr ) {
  uint fec_set_idx = (uint)fec_set_idx_;

  for( uint i = 0; i < FD_FEC_SHRED_CNT; i++ ) {
    fd_chainer_shred_insert( chainer, slot, fec_set_idx_ + i, slot_complete && (i == FD_FEC_SHRED_CNT - 1), mr, AG_UNKNOWN_SLOT, NULL );
  }

  fd_fec_t * fec = fec_query( chainer, slot, fec_set_idx, mr );
  turbine_slotv_query( chainer, slot );
  if( FD_LIKELY( !fd_chainer_fec_query( chainer, slot, fec_set_idx, 0UL ) ) ) {
    /* turbine slotv only joins the first instance of fec_set_idx it sees */
    fec = fec_join( chainer, slot, fec_set_idx, 0UL, mr, 0 );
  }

  /* fec is still NULL only if the turbine version already holds a
     *different* root at this position -- a matching one would have been
     found above, and an absent one would have been joined. Keep the
     first-seen root and drop. */
  if( FD_UNLIKELY( !fec ) ) return 1;

  fec->sentinel = 0;
  if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;
  if( FD_UNLIKELY( data_complete ) ) fec->data_complete = 1;

  for( ulong i = fd_slotv_set_const_iter_init( fec->versions );
                !fd_slotv_set_const_iter_done( i );
             i = fd_slotv_set_const_iter_next( fec->versions, i ) ) {
    ulong v = i;

    fd_slotv_t * slotv = slotv_query( chainer, slot, v );
    FD_TEST( slotv );

    /* Extend this version's contiguous buffered FEC prefix. */
    for(;;) {
      fd_fec_t * next = fd_chainer_fec_query( chainer, slot, slotv->buffered_fec_idx + 1U, v );
      if( !next || next->sentinel ) break;
      slotv->buffered_fec_idx += FD_FEC_SHRED_CNT;
    }

    /* Slot is complete -> we can record the block_id, and we must have
       all of its components at this point.  Only a turbine version needs
       it computed: a notar-fallback version already learned its block_id
       from the cert. */
    if( FD_UNLIKELY( slotv->complete_idx != UINT_MAX && slotv->buffered_fec_idx == slotv->complete_idx && fd_hash_check_zero( &slotv->block_id ) ) ) {
      if( FD_UNLIKELY( slotv->parent_slot == AG_UNKNOWN_SLOT ) ) FD_LOG_CRIT(( "slot %lu is complete, but parent_slot is still unknown", slot ));
      if( FD_UNLIKELY( !finalize_block_id( chainer, slotv ) ) ) FD_LOG_CRIT(( "failed to finalize block_id for slot %lu", slot ));
    }

    chainer_advance( chainer, slotv );
  }

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
    ulong v = next_free_alt_version( chainer, parent_slot );
    if( FD_UNLIKELY( v==FD_CHAINER_SLOT_VER_MAX ) ) FD_LOG_CRIT(( "more than %d versions for slot %lu", FD_CHAINER_SLOT_VER_MAX, parent_slot ));
    parent_slotv = acquire_slotv( chainer, parent_slot, v );
    parent_slotv->block_id = *parent_block_id;
  }
  /* parent now identified -> connect this slotv if the parent is already connected */
  if( FD_UNLIKELY( parent_slotv->connected ) ) slotv->connected = 1;
  return slotv;
}

/* Called by repair_tile on getFecRoot responses, after
   verifying the hash is correct for a notar-fallback-ed block */
void
fd_chainer_verified_hash_insert( fd_chainer_t * chainer,
                                 ulong          slot,
                                 fd_hash_t    * block_id,
                                 uint           fec_set_idx,
                                 fd_hash_t    * mr ) {
  fd_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) FD_LOG_CRIT(( "slotv not found for slot %lu - TODO verify this is a crit", slot ));
  ulong version = FD_CHAINER_SLOTV_VERSION( slotv->key );

  /* Already have this version's FEC entry -> nothing to fetch. */
  if( FD_UNLIKELY( fd_chainer_fec_query( chainer, slot, fec_set_idx, version ) ) ) return;

  /* the same root may already be completed under another version.  If
     so, create this version's entry already-complete and replay the
     completion through fd_chainer_fec_insert.  Otherwise create a
     sentinel that is awaiting shreds. */
  fd_fec_t * shared = fec_query( chainer, slot, fec_set_idx, mr );
  int shared_complete = shared && !shared->sentinel;
  fd_fec_t * fec = fec_join( chainer, slot, fec_set_idx, version, mr, !shared_complete /* sentinel */ );

  if( FD_UNLIKELY ( ( shared_complete && shared->slot_complete ) ||
                    ( slotv->complete_idx - FD_FEC_SHRED_CNT + 1 == fec_set_idx ) ) )
    fec->slot_complete = 1;

  if( FD_LIKELY( shared_complete ) ) {
    fd_chainer_fec_insert( chainer, slot, fec_set_idx, shared->slot_complete, shared->data_complete, mr );
  }
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

void
fd_chainer_notar_fallback( fd_chainer_t * chainer,
                           ulong          slot,
                           fd_hash_t      block_id ) {
  /* if we already have an slotv with this block_id, no-op.  Note
     turbine block_id may not be computed yet. */
  if( FD_LIKELY( fd_chainer_slot_version_query( chainer, slot, &block_id ) ) ) return;

  /* Assign the lowest free repair/NF cert version */
  ulong version = next_free_alt_version( chainer, slot );
  if( FD_UNLIKELY( version==FD_CHAINER_SLOT_VER_MAX ) ) FD_LOG_CRIT(( "more than %d versions for slot %lu", FD_CHAINER_SLOT_VER_MAX, slot ));

  fd_slotv_t * slotv = acquire_slotv( chainer, slot, version );
  slotv->block_id = block_id;
}


/* Out queue must be drained before calling this function, else there
   could be stale references to pruned slotvs. */
void
fd_chainer_publish( fd_chainer_t *    chainer,
                    ulong             new_root,
                    fd_hash_t const * new_root_block_id ) {
  fd_slotv_map_t * slotv_map  = fd_chainer_slotv_map( chainer );
  fd_slotv_t     * slotv_pool = fd_chainer_slotv_pool( chainer );
  fd_fec_map_t   * fec_map    = fd_chainer_fec_map  ( chainer );
  fd_fec_t       * fec_pool   = fd_chainer_fec_pool ( chainer );
  ulong * out_queue = fd_chainer_out_queue( chainer );
  if( FD_UNLIKELY( !out_queue_empty( out_queue ) ) ) FD_LOG_CRIT(( "chainer out_queue not empty before publish" ));

  ulong root = chainer->root;
  if( FD_UNLIKELY( root==ULONG_MAX ) ) return;
  FD_TEST( root < new_root );
  FD_TEST( slotv_query( chainer, new_root, 0 ) );

  for( ulong slot=root; slot<new_root; slot++ ) {
    for( ulong v=0UL; v<FD_CHAINER_SLOT_VER_MAX; v++ ) {
      fd_slotv_t * slotv = slotv_query( chainer, slot, v );
      if( FD_UNLIKELY( !slotv ) ) continue; /* technically at publish time, versions should be dense */
      fd_chainer_orphan_remove( chainer, slotv );
      fd_chainer_repair_remove( chainer, slotv );

      /* Release every FEC of this slot by walking its list, held by
         version 0's slotv. */
      if( FD_LIKELY( v==0UL ) ) {
        ulong fec_null = fd_fec_pool_idx_null( fec_pool );
        for( ulong idx=slotv->fec_head; idx!=fec_null; ) {
          fd_fec_t * fec  = fd_fec_pool_ele( fec_pool, idx );
          ulong      next = fec->slot_next;
          ulong      key  = fec->key;

          fd_fec_t * removed = fd_fec_map_ele_remove( fec_map, &key, NULL, fec_pool );
          if( FD_LIKELY( removed ) ) fd_fec_pool_ele_release( fec_pool, removed );
          idx = next;
        }
        slotv->fec_head = fec_null;
      }

      fd_slotv_map_ele_remove( slotv_map, &slotv->key, NULL, slotv_pool );
      fd_slotv_pool_ele_release( slotv_pool, slotv );
    }
  }

  /* Every equivocating sibling version of the new root is now dead and
     must get pruned.  If we cannot identify the canonical version --
     none of our versions has computed a matching one yet
     (finalize_block_id needs the full FEC set plus the declared parent)
     -- keep them all rather than guess wrong and prune the version we
     are actually rooted on.  TODO: potentially should just log crit here */
  fd_slotv_t * canonical = new_root_block_id ? fd_chainer_slot_version_query( chainer, new_root, new_root_block_id ) : NULL;
  if( FD_UNLIKELY( !canonical ) ) {
    FD_LOG_WARNING(( "chainer publish %lu: no version matches the rooted block_id; keeping all versions", new_root ));
  }

  chainer->root = new_root;
  for( ulong v=0UL; v<FD_CHAINER_SLOT_VER_MAX; v++ ) {
    fd_slotv_t * root_slotv = slotv_query( chainer, new_root, v );
    if( FD_UNLIKELY( !root_slotv ) ) continue;

    /* Non-canonical version of the rooted slot -> drop it, same as a
       pre-root slot. */
    if( FD_UNLIKELY( canonical && root_slotv!=canonical ) ) {
      fd_chainer_orphan_remove( chainer, root_slotv );
      fd_chainer_repair_remove( chainer, root_slotv );
      /* Release every FEC of this slot by walking its list, held by
         version 0's slotv.  TODO: if the root slotv is not v0, then
         we delete all the FEC entries for this slot.  Don't think this
         is an issue but should update chainer verify. */
      if( FD_LIKELY( v==0UL ) ) {
        ulong fec_null = fd_fec_pool_idx_null( fec_pool );
        for( ulong idx=root_slotv->fec_head; idx!=fec_null; ) {
          fd_fec_t * fec  = fd_fec_pool_ele( fec_pool, idx );
          ulong      next = fec->slot_next;
          ulong      key  = fec->key;

          fd_fec_t * removed = fd_fec_map_ele_remove( fec_map, &key, NULL, fec_pool );
          if( FD_LIKELY( removed ) ) fd_fec_pool_ele_release( fec_pool, removed );
          idx = next;
        }
        root_slotv->fec_head = fec_null;
      }
      fd_slotv_map_ele_remove( slotv_map, &root_slotv->key, NULL, slotv_pool );
      fd_slotv_pool_ele_release( slotv_pool, root_slotv );
      continue;
    }

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
  fflush( stdout ); /* Ensure slotv map printf output is flushed */
}