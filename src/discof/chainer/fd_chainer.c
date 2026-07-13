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

  ulong blk_max       = ele_max * FD_CHAINER_SLOT_VER_MAX;
  ulong fec_max       = blk_max * FD_FEC_BLK_MAX;
  ulong fec_chain_cnt = fd_fec_map_chain_cnt_est( fec_max );
  ulong blk_chain_cnt = fd_slotv_map_chain_cnt_est( blk_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  chainer             = FD_SCRATCH_ALLOC_APPEND( l, fd_chainer_align(),      sizeof(fd_chainer_t)                         );
  void * fec_pool     = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_pool_align(),     fd_fec_pool_footprint    ( fec_max )         );
  void * fec_map      = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_map_align(),      fd_fec_map_footprint     ( fec_chain_cnt   ) );
  void * slotv_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_pool_align(),   fd_slotv_pool_footprint  ( blk_max         ) );
  void * slotv_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_map_align(),    fd_slotv_map_footprint   ( blk_chain_cnt   ) );
  void * sched_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_pool_align(),   fd_sched_pool_footprint  ( blk_max         ) );
  void * sched_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_map_align(),    fd_sched_map_footprint   ( blk_chain_cnt   ) );
  void * repair_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_repair_align(), fd_sched_repair_footprint( blk_max )         );
  void * orphan_treap = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_orphan_align(), fd_sched_orphan_footprint( blk_max )         );
  void * bfs          = FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),             bfs_footprint            ( blk_max )         );
  void * out_queue    = FD_SCRATCH_ALLOC_APPEND( l, out_queue_align(),       out_queue_footprint      ( fec_max )         );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_chainer_align() ) == (ulong)shmem + footprint );

  chainer->root             = ULONG_MAX;
  chainer->highest_repaired = 0UL;
  chainer->wksp_gaddr       = fd_wksp_gaddr_fast( wksp, chainer );
  chainer->fec_pool     = fd_fec_pool_join    ( fd_fec_pool_new    ( fec_pool,     fec_max             ) );
  chainer->fec_map      = fd_fec_map_join     ( fd_fec_map_new     ( fec_map,      fec_chain_cnt, seed ) );
  chainer->slotv_pool   = fd_slotv_pool_join  ( fd_slotv_pool_new  ( slotv_pool,   blk_max             ) );
  chainer->slotv_map    = fd_slotv_map_join   ( fd_slotv_map_new   ( slotv_map,    blk_chain_cnt, seed ) );
  chainer->sched_pool   = fd_sched_pool_join  ( fd_sched_pool_new  ( sched_pool,   blk_max             ) );
  chainer->sched_map    = fd_sched_map_join   ( fd_sched_map_new   ( sched_map,    blk_chain_cnt, seed ) );
  chainer->repair_treap = fd_sched_repair_join( fd_sched_repair_new( repair_treap, blk_max             ) );
  chainer->orphan_treap = fd_sched_orphan_join( fd_sched_orphan_new( orphan_treap, blk_max             ) );
  chainer->bfs          = bfs_join            ( bfs_new            ( bfs,          blk_max             ) );
  chainer->out_queue    = out_queue_join      ( out_queue_new      ( out_queue,    fec_max             ) );

  fd_sched_repair_seed( chainer->sched_pool, blk_max, seed        );
  fd_sched_orphan_seed( chainer->sched_pool, blk_max, seed ^ 0x9eUL );

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

/* acquire_slotv allocates, initializes, and map-inserts a fresh
   (turbine, i.e. all-zero block_id) version of slot.  Callers that know
   the version's block_id (notar-fallback, parent discovery) set it after. */

static fd_chainer_slotv_t *
acquire_slotv( fd_chainer_t * chainer, ulong slot ) {
  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  FD_TEST( fd_slotv_pool_free( slotv_pool ) );

  ulong slotv_cnt = 0;
  for( ulong i  = fd_slotv_map_idx_query_const( slotv_map, &slot, ULONG_MAX, slotv_pool ); i != ULONG_MAX; i  = fd_slotv_map_idx_next_const( i, ULONG_MAX, slotv_pool ) ) {
    slotv_cnt++;
  }
  if( FD_UNLIKELY( slotv_cnt >= FD_CHAINER_SLOT_VER_MAX ) ) FD_LOG_CRIT(("slots stored exceeds protocol limits, %lu versions of slot %lu already stored", slotv_cnt, slot));

  fd_chainer_slotv_t * slotv = fd_slotv_pool_ele_acquire( slotv_pool );
  slotv->slot              = slot;
  slotv->turbine           = 0;
  slotv->abandoned         = 0;
  slotv->parent_slot       = AG_UNKNOWN_SLOT;
  slotv->parent_slot_batch = UINT_MAX;
  slotv->complete_idx      = UINT_MAX;
  slotv->buffered_idx      = UINT_MAX;
  slotv->buffered_fec_idx  = UINT_MAX;
  slotv->delivered_idx     = UINT_MAX;
  slotv->connected         = 0;
  slotv->highest_requested = UINT_MAX;

  fd_memset( &slotv->block_id,        0, sizeof(fd_hash_t) );
  fd_memset( &slotv->parent_block_id, 0, sizeof(fd_hash_t) );
  fd_memset( slotv->fec, 0xff, sizeof(slotv->fec) ); /* UINT_MAX pool_idx sentinel */

  fd_slotv_map_ele_insert( slotv_map, slotv, slotv_pool );
  fd_chainer_repair_add( chainer, slotv ); /* new slotv -> has un-requested shreds */
  fd_chainer_orphan_add( chainer, slotv ); /* new slotv -> ancestry unknown until parent confirmed present */
  return slotv;
}

void
fd_chainer_init( fd_chainer_t    * chainer,
                 ulong             slot,
                 fd_hash_t const * block_id ) {
  fd_chainer_slotv_t * slotv = acquire_slotv( chainer, slot );
  slotv->parent_slot       = slot;
  slotv->complete_idx      = 0;
  slotv->buffered_idx      = 0;
  slotv->connected         = 1;
  slotv->delivered_idx     = 0; /* must equal complete_idx at init */
  slotv->highest_requested = 0;
  slotv->buffered_fec_idx  = UINT_MAX; /* no complete FEC set buffered; must
                                          be one-below a FD_FEC_SHRED_CNT
                                          multiple, which UINT_MAX satisfies */
  slotv->block_id          = *block_id;
  fd_chainer_repair_remove( chainer, slotv );
  fd_chainer_orphan_remove( chainer, slotv );

  chainer->root = slot;
  chainer->highest_repaired = slot;
}

/* slotv_iter_{init,next} iterate the versions of a slot via the
   MAP_MULTI chain.  Usage:
     for( ulong i=slotv_iter_init(chainer,slot); i!=ULONG_MAX; i=slotv_iter_next(chainer,i) ) {
       fd_chainer_slotv_t * slotv = slotv_iter_ele( chainer, i );
       ...
     } */

static inline ulong
slotv_iter_init( fd_chainer_t * chainer, ulong slot ) {
  return fd_slotv_map_idx_query_const( chainer->slotv_map, &slot, ULONG_MAX, chainer->slotv_pool );
}

static inline ulong
slotv_iter_next( fd_chainer_t * chainer, ulong idx ) {
  return fd_slotv_map_idx_next_const( idx, ULONG_MAX, chainer->slotv_pool );
}

static inline fd_chainer_slotv_t *
slotv_iter_ele( fd_chainer_t * chainer, ulong idx ) {
  return fd_slotv_pool_ele( chainer->slotv_pool, idx );
}


/* slotv_fec returns the FEC that slotv owns at fec_set_idx, or NULL if
   it holds none there. */

static fd_chainer_fec_t *
slotv_fec( fd_chainer_t * chainer, fd_chainer_slotv_t const * slotv, uint fec_set_idx ) {
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;
  uint idx = slotv->fec[ fec_set_idx / FD_FEC_SHRED_CNT ];
  if( FD_UNLIKELY( idx==UINT_MAX ) ) return NULL;
  return fd_fec_pool_ele( fec_pool, (ulong)idx );
}

int
fd_chainer_shred_test( fd_chainer_t *     chainer,
                       fd_chainer_slotv_t const * slotv,
                       uint               shred_idx ) {
  fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U ) );
  if( FD_UNLIKELY( !fec ) ) return 0;
  return !!fd_fec_idxs_test( fec->data_idxs, shred_idx & ( (uint)FD_FEC_SHRED_CNT - 1U ) );
}

ulong
fd_chainer_slotv_shred_cnt( fd_chainer_t *     chainer,
                            fd_chainer_slotv_t const * slotv ) {
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;
  ulong cnt = 0UL;
  for( ulong k=0UL; k<FD_FEC_BLK_MAX; k++ ) {
    uint idx = slotv->fec[ k ];
    if( idx==UINT_MAX ) continue;
    cnt += fd_fec_idxs_cnt( fd_fec_pool_ele( fec_pool, (ulong)idx )->data_idxs );
  }
  return cnt;
}

fd_chainer_fec_t *
fd_chainer_fec_query( fd_chainer_t *    chainer,
                      ulong             slot,
                      uint              fec_set_idx,
                      fd_hash_t const * block_id ) {
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) return NULL;
  return slotv_fec( chainer, slotv, fec_set_idx );
}

/* fec_query returns the FEC whose merkle_root matches mr, or NULL. */

static fd_chainer_fec_t *
fec_query( fd_chainer_t * chainer, fd_hash_t const * mr ) {
  fd_fec_map_t     * fec_map  = chainer->fec_map;
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;
  return fd_fec_map_ele_query( fec_map, mr, NULL, fec_pool );
}

/* fec_join records that slotv includes the FEC at (slot, fec_set_idx)
   with root mr, creating the entry if this root has not been seen yet. */

static fd_chainer_fec_t *
fec_join( fd_chainer_t    * chainer,
          ulong             slot,
          uint              fec_set_idx,
          fd_chainer_slotv_t      * slotv,
          fd_hash_t const * mr ) {
  fd_fec_map_t     * fec_map  = chainer->fec_map;
  fd_chainer_fec_t * fec_pool = chainer->fec_pool;
  fd_chainer_fec_t * fec = fd_fec_map_ele_query( fec_map, mr, NULL, fec_pool );
  if( FD_UNLIKELY( !fec ) ) {
    if( FD_UNLIKELY( !fd_fec_pool_free( fec_pool ) ) ) FD_LOG_CRIT(( "fec_pool is full" ));
    fec = fd_fec_pool_ele_acquire( fec_pool );
    fec->merkle_root   = *mr;
    fec->slot          = slot;
    fec->fec_set_idx   = fec_set_idx;
    fd_fec_idxs_null( fec->data_idxs );
    fec->complete      = 0;
    fec->slot_complete = 0;
    fec->data_complete = 0;
    fec->is_leader     = 0;
    fd_fec_map_ele_insert( fec_map, fec, fec_pool );
  }
  slotv->fec[ fec_set_idx / FD_FEC_SHRED_CNT ] = (uint)fd_fec_pool_idx( fec_pool, fec );
  return fec;
}

/* slotv_abandon freezes a turbine slotv. Removed from the repair
   worklists, and (via the abandoned flag) excluded from delivery and
   block_id finalization. */
static void
slotv_abandon( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  FD_TEST( slotv->turbine );
  fd_chainer_repair_remove( chainer, slotv );
  fd_chainer_orphan_remove( chainer, slotv );
  slotv->abandoned = 1;
}

/* abandon_turbine abandons slot's turbine version, if one exists. */

static void
abandon_turbine( fd_chainer_t * chainer, ulong slot ) {
  for( ulong i=slotv_iter_init( chainer, slot ); i!=ULONG_MAX; i=slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * slotv = slotv_iter_ele( chainer, i );
    if( FD_LIKELY( !slotv->turbine || slotv->abandoned ) ) continue;
    if( FD_LIKELY( fd_hash_check_zero( &slotv->block_id ) ) ) slotv_abandon( chainer, slotv );
    return;
  }
}

/* turbine_slotv_query returns the turbine version of slot -- creating
   it if none exists.*/

static fd_chainer_slotv_t *
turbine_slotv_query( fd_chainer_t * chainer, ulong slot ) {
  for( ulong i=slotv_iter_init( chainer, slot ); i!=ULONG_MAX; i=slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * slotv = slotv_iter_ele( chainer, i );
    if( FD_LIKELY( slotv->turbine ) ) return slotv;
  }
  fd_chainer_slotv_t * slotv = acquire_slotv( chainer, slot );
  slotv->turbine = 1;
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

  fd_chainer_slotv_t const * slotv_pool = chainer_->slotv_pool;
  fd_slotv_map_t     const * slotv_map  = chainer_->slotv_map;
  fd_sched_ele_t     const * sched_pool = chainer_->sched_pool;
  fd_sched_map_t     const * sched_map  = chainer_->sched_map;
  fd_sched_repair_t  const * rtreap     = chainer_->repair_treap;
  fd_sched_orphan_t  const * otreap     = chainer_->orphan_treap;
  fd_chainer_fec_t   const * fec_pool   = chainer_->fec_pool;
  fd_fec_map_t       const * fec_map    = chainer_->fec_map;

  if( FD_UNLIKELY( fd_slotv_map_verify( slotv_map, fd_slotv_pool_max( slotv_pool ), slotv_pool )==-1 ) ) FAIL( "slotv map corrupted" );
  if( FD_UNLIKELY( fd_sched_map_verify( sched_map, fd_sched_pool_max( sched_pool ), sched_pool )==-1 ) ) FAIL( "sched map corrupted" );
  if( FD_UNLIKELY( fd_fec_map_verify  ( fec_map,   fd_fec_pool_max  ( fec_pool   ), fec_pool   )==-1 ) ) FAIL( "fec map corrupted"   );
  if( FD_UNLIKELY( fd_sched_repair_verify( rtreap, sched_pool )==-1 ) ) FAIL( "repair treap corrupted" );
  if( FD_UNLIKELY( fd_sched_orphan_verify( otreap, sched_pool )==-1 ) ) FAIL( "orphan treap corrupted" );

  /* The root, if set, must have at least one connected version -- it is
     by definition the start of every ancestry chain.  Uniquely among
     slots, the root need not have a version 0: publish prunes the
     non-canonical versions of the new root, and version 0 may have been
     one of them.  Its FEC list is released along with it, which is fine
     because a rooted slot's FEC data is never needed again. */

  if( FD_LIKELY( chainer->root!=ULONG_MAX ) ) {
    int root_present   = 0;
    int root_connected = 0;
    ulong root = chainer->root;
    for( ulong i = fd_slotv_map_idx_query_const( slotv_map, &root, ULONG_MAX, slotv_pool );
               i != ULONG_MAX;
               i = fd_slotv_map_idx_next_const( i, ULONG_MAX, slotv_pool ) ) {
      fd_chainer_slotv_t const * root_slotv = fd_slotv_pool_ele_const( slotv_pool, i );
      root_present    = 1;
      root_connected |= !!root_slotv->connected;
    }
    if( FD_UNLIKELY( !root_present   ) ) FAIL( "root has no slotv" );
    if( FD_UNLIKELY( !root_connected ) ) FAIL( "no root slotv is connected" );
  }

  for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                               !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                           it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
    fd_chainer_slotv_t const * slotv = fd_slotv_map_iter_ele_const( it, slotv_map, slotv_pool );

    ulong slot = slotv->slot;

    /* Nothing below the root may survive a publish. */

    if( FD_UNLIKELY( chainer->root!=ULONG_MAX && slot<chainer->root ) ) FAIL( "slotv below the root" );

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

    /* An abandoned version is always a turbine version and never on a
       worklist (see slotv_abandon). */

    if( FD_UNLIKELY( slotv->abandoned && !slotv->turbine ) ) FAIL( "abandoned non-turbine slotv" );
    if( FD_UNLIKELY( slotv->abandoned && ( fd_chainer_in_repair( chainer_, slotv ) || fd_chainer_in_orphan( chainer_, slotv ) ) ) ) FAIL( "abandoned slotv on a worklist" );
  }

  /* Worklist consistency.  Every sched ele must shadow a live slotv, be
     in at least one treap (else it should have been gc'd), and carry the
     slot of its slotv.  The per-treap membership counts must match the
     treap element counts. */

  ulong ele_max = fd_slotv_pool_max( slotv_pool );
  ulong in_treap_cnt = 0;
  ulong in_orphan_cnt = 0;
  for( fd_sched_map_iter_t it = fd_sched_map_iter_init( sched_map, sched_pool );
                               !fd_sched_map_iter_done( it, sched_map, sched_pool );
                           it = fd_sched_map_iter_next( it, sched_map, sched_pool ) ) {
    fd_sched_ele_t const * ele = fd_sched_map_iter_ele_const( it, sched_map, sched_pool );
    if( FD_UNLIKELY( ele->slotv_idx>=ele_max                        ) ) FAIL( "sched ele slotv_idx out of range" );
    if( FD_UNLIKELY( !ele->in_repair && !ele->in_orphan            ) ) FAIL( "sched ele in neither treap (should be gc'd)" );
    if( FD_UNLIKELY( ele->slot!=fd_slotv_pool_ele_const( slotv_pool, ele->slotv_idx )->slot ) ) FAIL( "sched ele slot mismatches slotv" );
    in_treap_cnt  += !!ele->in_repair;
    in_orphan_cnt += !!ele->in_orphan;
  }

  /* No treap may hold an ele not accounted for in the sched map. */

  if( FD_UNLIKELY( in_treap_cnt !=fd_sched_repair_ele_cnt( rtreap ) ) ) FAIL( "repair treap holds eles that are not in the sched map" );
  if( FD_UNLIKELY( in_orphan_cnt!=fd_sched_orphan_ele_cnt( otreap ) ) ) FAIL( "orphan treap holds eles that are not in the sched map" );

  for( fd_fec_map_iter_t it = fd_fec_map_iter_init( fec_map, fec_pool );
                             !fd_fec_map_iter_done( it, fec_map, fec_pool );
                         it = fd_fec_map_iter_next( it, fec_map, fec_pool ) ) {
    fd_chainer_fec_t const * fec = fd_fec_map_iter_ele_const( it, fec_map, fec_pool );

    ulong slot        = fec->slot;
    uint  fec_set_idx = fec->fec_set_idx;
    uint  fec_idx     = (uint)fd_fec_pool_idx( fec_pool, fec );

    if( FD_UNLIKELY( fec_set_idx % FD_FEC_SHRED_CNT ) ) FAIL( "fec_set_idx is not a multiple of FD_FEC_SHRED_CNT" );
    if( FD_UNLIKELY( fec_set_idx>=FD_SHRED_BLK_MAX   ) ) FAIL( "fec_set_idx out of range" );

    if( FD_UNLIKELY( chainer->root!=ULONG_MAX && slot<chainer->root ) ) FAIL( "fec below the root" );

    /* A slot with a FEC must have at least one version to anchor the list
       and own the FEC -- without one publish could never reach it. */

    if( FD_UNLIKELY( !fd_chainer_slot_query( chainer_, slot ) ) ) FAIL( "slot has a fec but no version to anchor the list" );

    /* A FEC is owned by every version whose forward fec[] array points at
       it, and at least one must -- otherwise it is unreachable garbage
       that publish would leak. */

    int owned = 0;
    for( ulong i = fd_slotv_map_idx_query_const( slotv_map, &slot, ULONG_MAX, slotv_pool );
               i != ULONG_MAX;
               i = fd_slotv_map_idx_next_const( i, ULONG_MAX, slotv_pool ) ) {
      fd_chainer_slotv_t const * slotv = fd_slotv_pool_ele_const( slotv_pool, i );
      if( FD_LIKELY( slotv->fec[ fec_set_idx / FD_FEC_SHRED_CNT ]==fec_idx ) ) owned = 1;
    }
    if( FD_UNLIKELY( !owned ) ) FAIL( "fec claimed by no version" );
  }

  return 0;
}
#undef FAIL

/* finalize_block_id computes the slotv's double-merkle block_id and
   writes it to slotv->block_id.  Returns 1 on success, 0 on failure. */

static int
finalize_block_id( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  if( FD_UNLIKELY( slotv->complete_idx==UINT_MAX ) )                 return 0;
  if( FD_UNLIKELY( slotv->parent_slot==AG_UNKNOWN_SLOT ) )           return 0;
  if( FD_UNLIKELY( fd_hash_check_zero( &slotv->parent_block_id ) ) ) return 0;

  uint fec_set_cnt = ( slotv->complete_idx + 1U ) / FD_FEC_SHRED_CNT;
  uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, 20UL, FD_BMTREE_LONG_PREFIX_SZ, 0UL );

  for( uint i=0U; i<fec_set_cnt; i++ ) {
    fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, i*FD_FEC_SHRED_CNT );
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

fd_chainer_slotv_t *
fd_chainer_shred_insert( fd_chainer_t    * chainer,
                         ulong             slot,
                         uint              shred_idx,
                         int               slot_complete,
                         fd_hash_t const * mr,
                         ulong             parent_slot,
                         fd_hash_t const * parent_block_id ) {
  FD_TEST( shred_idx < FD_SHRED_BLK_MAX ); // guaranteed by fec_resolver
  FD_TEST( slot > chainer->root );
  uint fec_set_idx = shred_idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );

  /* Identify the slot versions this shred belongs to. */

  ulong k = fec_set_idx / FD_FEC_SHRED_CNT;
  fd_chainer_slotv_t * turbine = turbine_slotv_query( chainer, slot );

  /* If a votor-driven version of the slot already exists (block-id
     repair started before this turbine shred arrived), abandon the
     turbine version. */
  if( FD_UNLIKELY( !turbine->abandoned && fd_hash_check_zero( &turbine->block_id ) ) ) {
    for( ulong i=slotv_iter_init( chainer, slot ); i!=ULONG_MAX; i=slotv_iter_next( chainer, i ) ) {
      if( FD_UNLIKELY( i!=fd_slotv_pool_idx( chainer->slotv_pool, turbine ) ) ) {
        slotv_abandon( chainer, turbine );
        break;
      }
    }
  }

  /* Find or create the FEC for this shred's root

     If the turbine version holds no root at this position it adopts
     this one, whether it is newly seen FEC or an entry a getFecRoot
     sentinel already created.  If turbine already holds a *different*
     root here and nothing authorized this one, the shred is an
     unauthorized equivocation and is dropped. */
  fd_chainer_fec_t * fec         = fec_query( chainer, mr );
  fd_chainer_fec_t * turbine_fec = slotv_fec( chainer, turbine, fec_set_idx );
  if( FD_LIKELY( !turbine_fec ) ) {
    fec = fec_join( chainer, slot, fec_set_idx, turbine, mr );
  } else if( FD_UNLIKELY( !fec ) ) {
    return turbine; /* turbine holds a different root here, drop it */
  }

  /* Record the shred on theFEC bitmap and note slot completion. */
  fd_fec_idxs_insert( fec->data_idxs, shred_idx - fec_set_idx );
  if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;

  /* Update every version that owns this FEC root at this position. */
  uint fec_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );
  for( ulong _i=slotv_iter_init( chainer, slot ); _i!=ULONG_MAX; _i=slotv_iter_next( chainer, _i ) ) {
    fd_chainer_slotv_t * slotv = slotv_iter_ele( chainer, _i );
    if( FD_UNLIKELY( slotv->fec[ k ]!=fec_idx ) ) continue;

    /* update slot-level shred indexing */
    if( FD_UNLIKELY( slot_complete ) ) slotv->complete_idx = shred_idx;
    while( slotv->buffered_idx + 1 < FD_SHRED_BLK_MAX && fd_chainer_shred_test( chainer, slotv, slotv->buffered_idx + 1U ) ) {
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
      fd_chainer_slotv_t * parent = fd_chainer_slot_version_query( chainer, parent_slot, parent_block_id );
      if( FD_LIKELY( parent && parent->connected ) ) slotv->connected = 1;
    }
  }
  return turbine;
}

/* chainer_deliver queues a delivered FEC for publish to replay.  The
   repair tile drains the out_queue in after_credit. */
static void
chainer_deliver( fd_chainer_t       * chainer,
                 fd_chainer_slotv_t * slotv,
                 fd_chainer_fec_t   * fec ) {
  out_ele_t * out_queue = chainer->out_queue;
  if( FD_UNLIKELY( out_queue_full( out_queue ) ) ) FD_LOG_CRIT(( "chainer out_queue full" ));
  out_queue_push_tail( out_queue, (out_ele_t){ .slotv_idx = (uint)fd_slotv_pool_idx( chainer->slotv_pool, slotv ), .fec_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec ) } );
}

/* chainer_advance delivers as many contiguous completed FEC sets as
   possible from `root` slotv, then cascades: when an slotv's
   slot_complete FEC is delivered, every child slotv (parent_block_id ==
   this slotv's block_id) becomes connected and is drained in turn. */

static void
chainer_advance( fd_chainer_t * chainer, fd_chainer_slotv_t * root ) {
  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  ulong              * bfs        = chainer->bfs;

  bfs_push_tail( bfs, fd_slotv_pool_idx( slotv_pool, root ) );

  while( FD_LIKELY( !bfs_empty( bfs ) ) ) {
    fd_chainer_slotv_t * slotv = fd_slotv_pool_ele( slotv_pool, bfs_pop_head( bfs ) );
    if( FD_UNLIKELY( !slotv->connected ) ) continue;
    if( FD_UNLIKELY(  slotv->abandoned ) ) continue;

    fd_chainer_slotv_t * parent = fd_chainer_slot_version_query( chainer, slotv->parent_slot, &slotv->parent_block_id );
    if( FD_UNLIKELY( !parent || parent->complete_idx == UINT_MAX || parent->delivered_idx != parent->complete_idx ) ) continue;

    ulong slot = slotv->slot;

    for(;;) {
      uint next = slotv->delivered_idx==UINT_MAX ? 0u : slotv->delivered_idx + 1;
      fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, next );
      if( FD_LIKELY( !fec || !fec->complete ) ) break; /* next FEC not completed yet */

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
            fd_chainer_slotv_t * child = fd_slotv_map_iter_ele( it, slotv_map, slotv_pool );
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

/* extend_buffered_fec extends slotv's contiguous buffered FEC prefix
   over consecutive completed FEC sets. */

static void
extend_buffered_fec( fd_chainer_t * chainer, fd_chainer_slotv_t * slotv ) {
  for(;;) {
    fd_chainer_fec_t * next = slotv_fec( chainer, slotv, slotv->buffered_fec_idx + 1U );
    if( !next || !next->complete ) break;
    slotv->buffered_fec_idx += FD_FEC_SHRED_CNT;
  }
}

int
fd_chainer_fec_complete( fd_chainer_t * chainer,
                         ulong          slot,
                         uint           fec_set_idx_,
                         int            slot_complete,
                         int            data_complete,
                         int            is_leader,
                         fd_hash_t    * mr ) {
  FD_TEST( slot > chainer->root );
  uint fec_set_idx = (uint)fec_set_idx_;

  for( uint i = 0; i < FD_FEC_SHRED_CNT; i++ ) {
    fd_chainer_shred_insert( chainer, slot, fec_set_idx_ + i, slot_complete && (i == FD_FEC_SHRED_CNT - 1), mr, AG_UNKNOWN_SLOT, NULL );
  }
  /* By the time we get here the FEC exists unless turbine refused an
     unauthorized equivocating root -- in which case it was dropped and
     there is nothing to complete. */

  fd_chainer_fec_t * fec = fec_query( chainer, mr );
  if( FD_UNLIKELY( !fec ) ) return 1;

  fec->complete = 1; /* set is now reconstructable -> deliverable */
  if( FD_UNLIKELY( slot_complete ) ) fec->slot_complete = 1;
  if( FD_UNLIKELY( data_complete ) ) fec->data_complete = 1;
  if( FD_UNLIKELY( is_leader ) )     fec->is_leader     = 1;

  /* Process the turbine version first.  It is the only version whose
     block_id may finalize here.  An abandoned turbine version is
     skipped entirely. */
  uint  fec_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );
  ulong k       = fec_set_idx / FD_FEC_SHRED_CNT;

  fd_chainer_slotv_t * turbine = NULL;
  for( ulong _i=slotv_iter_init( chainer, slot ); _i!=ULONG_MAX; _i=slotv_iter_next( chainer, _i ) ) {
    fd_chainer_slotv_t * slotv = slotv_iter_ele( chainer, _i );
    if( FD_LIKELY( slotv->turbine && !slotv->abandoned ) ) { turbine = slotv; break; }
  }

  if( FD_LIKELY( turbine && turbine->fec[ k ]==fec_idx ) ) {
    extend_buffered_fec( chainer, turbine );

    /* Slot is complete -> we can record the block_id, and we must have
       all of its components at this point.  Only a turbine version needs
       it computed: a notar-fallback version already learned its block_id
       from the cert. */
    if( FD_UNLIKELY( turbine->complete_idx != UINT_MAX && turbine->buffered_fec_idx == turbine->complete_idx && fd_hash_check_zero( &turbine->block_id ) ) ) {
      if( FD_UNLIKELY( turbine->parent_slot == AG_UNKNOWN_SLOT ) ) FD_LOG_WARNING(( "slot %lu is complete, but parent_slot is still unknown", slot ));
      if( FD_UNLIKELY( !finalize_block_id( chainer, turbine ) ) ) FD_LOG_WARNING(( "failed to finalize block_id for slot %lu", slot ));
    }

    chainer_advance( chainer, turbine );
  }

  /* Advance every remaining version that owns this FEC root at this
     position. */
  for( ulong _i=slotv_iter_init( chainer, slot ); _i!=ULONG_MAX; _i=slotv_iter_next( chainer, _i ) ) {
    fd_chainer_slotv_t * slotv = slotv_iter_ele( chainer, _i );
    if( FD_UNLIKELY( slotv==turbine || slotv->abandoned ) ) continue;
    if( FD_UNLIKELY( slotv->fec[ k ]!=fec_idx ) ) continue;

    extend_buffered_fec( chainer, slotv );
    chainer_advance( chainer, slotv );
  }

  return 0;
}

void
fd_chainer_fec_evicted( fd_chainer_t * chainer,
                        ulong          slot,
                        uint           fec_set_idx,
                        fd_hash_t    * merkle_root ) {
  fd_chainer_fec_t * fec = fec_query( chainer, merkle_root );
  if( FD_UNLIKELY( !fec ) ) return;

  /* We choose not to remove the FEC from the chainer.  If this FEC
     belongs to a turbine slot and we are having trouble completing it
     (the leader gave up on disseminating the shreds), then eventually
     this slot will get skipped or we will repair a different version
     through a votor repair block id event. If this FEC is part of a
     votor cert, then we should keep it in the chainer because the
     merkle root is verified and we definitely want to continue
     repairing it; it is getting evicted only because fec_resolver is
     under pressure. */

  fd_fec_idxs_null( fec->data_idxs );
  uint fec_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );
  uint k = fec_set_idx / FD_FEC_SHRED_CNT;

  /* find slots that have this FEC root */
  for( ulong _i=slotv_iter_init( chainer, slot ); _i!=ULONG_MAX; _i=slotv_iter_next( chainer, _i ) ) {
    fd_chainer_slotv_t * slotv = slotv_iter_ele( chainer, _i );
    if( FD_UNLIKELY( slotv->fec[ k ]!=fec_idx ) ) continue;

    /* rederive buffered_idx */
    if( FD_UNLIKELY( slotv->buffered_idx!=UINT_MAX && slotv->buffered_idx >= fec_set_idx ) ) {
      slotv->buffered_idx = fec_set_idx - 1;
    }
    if( FD_UNLIKELY( slotv->highest_requested != UINT_MAX && slotv->highest_requested >= fec_set_idx ) ) {
      slotv->highest_requested = fec_set_idx - 1U;
    }
    if( FD_LIKELY( !slotv->abandoned ) ) fd_chainer_repair_add( chainer, slotv ); /* abandoned versions stay off the worklists */
  }
}

fd_chainer_slotv_t *
fd_chainer_verified_parent_fec_count( fd_chainer_t * chainer,
                                      ulong          slot,
                                      fd_hash_t    * block_id,
                                      uint           fec_set_cnt,
                                      ulong          parent_slot,
                                      fd_hash_t    * parent_block_id ) {
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) FD_LOG_CRIT(("slotv not found for slot %lu", slot ));

  FD_TEST( fec_set_cnt > 0 && fec_set_cnt <= FD_FEC_BLK_MAX );
  slotv->complete_idx    = (fec_set_cnt*FD_FEC_SHRED_CNT) - 1;
  slotv->parent_slot     = parent_slot;
  slotv->parent_block_id = *parent_block_id;

  fd_chainer_slotv_t * parent_slotv = fd_chainer_slot_version_query( chainer, parent_slot, parent_block_id );
  if( FD_UNLIKELY( !parent_slotv ) ) {
    parent_slotv = acquire_slotv( chainer, parent_slot );
    parent_slotv->block_id = *parent_block_id;
    abandon_turbine( chainer, parent_slot );
  }

  fd_chainer_orphan_remove( chainer, slotv );
  fd_chainer_repair_add( chainer, slotv );

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
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) FD_LOG_CRIT(( "slotv not found for slot %lu - TODO verify this is a crit", slot ));

  /* Already have this version's FEC entry -> nothing to fetch. */
  if( FD_UNLIKELY( slotv_fec( chainer, slotv, fec_set_idx ) ) ) return;

  /* the same root may have already started progress through repairing another
     slot version..  If so, create this version's entry already-complete and replay the
     completion through fd_chainer_fec_complete.  Otherwise create an
     incomplete entry that is awaiting shreds. */
  fd_chainer_fec_t * shared = fec_query( chainer, mr );
  int shared_complete = shared && shared->complete;

  fd_chainer_fec_t * fec = fec_join( chainer, slot, fec_set_idx, slotv, mr );
  if( FD_UNLIKELY( fec_set_idx == slotv->complete_idx - (FD_FEC_SHRED_CNT - 1) ) ) {
    fec->slot_complete = 1;
  }

  if( FD_LIKELY( shared_complete ) ) {
    /* TODO - double check we don't need to be updating slotv buffered_idx when FEC is not complete as well */
    fd_chainer_fec_complete( chainer, slot, fec_set_idx, shared->slot_complete, shared->data_complete, 0, mr );
  }
  fd_chainer_repair_add( chainer, slotv ); /* new sentinel -> re-add for shred fill */
  chainer_advance( chainer, slotv );
}

void
fd_chainer_fec_rekey( fd_chainer_t *    chainer,
                      ulong             slot,
                      fd_hash_t const * block_id,
                      uint              fec_set_idx,
                      fd_hash_t const * full_mr ) {
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) return;
  fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, fec_set_idx );
  if( FD_UNLIKELY( !fec ) ) return;
  if( FD_LIKELY( fd_hash_eq( &fec->merkle_root, full_mr ) ) ) return; /* already keyed by the full root */

  fd_chainer_fec_t * existing = fec_query( chainer, full_mr );
  if( FD_UNLIKELY( existing ) ) {
    /* A separate full-root FEC already exists -- e.g. turbine saw this
       FEC first. Merge the versions. */
    uint sentinel_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, fec );
    uint existing_idx = (uint)fd_fec_pool_idx( chainer->fec_pool, existing );
    uint k            = fec_set_idx / FD_FEC_SHRED_CNT;
    for( ulong _i=slotv_iter_init( chainer, slot ); _i!=ULONG_MAX; _i=slotv_iter_next( chainer, _i ) ) {
      fd_chainer_slotv_t * v = slotv_iter_ele( chainer, _i );
      if( FD_UNLIKELY( v->fec[ k ]==sentinel_idx ) ) v->fec[ k ] = existing_idx;
    }
    fd_fec_map_ele_remove_fast( chainer->fec_map, fec, chainer->fec_pool );
    fd_fec_pool_ele_release   ( chainer->fec_pool, fec );

    if( FD_LIKELY( existing->complete ) ) {
      fd_hash_t full = *full_mr;
      fd_chainer_fec_complete( chainer, slot, fec_set_idx, existing->slot_complete, existing->data_complete, 0, &full );
    }
    fd_chainer_repair_add( chainer, slotv ); /* re-add for remaining shred fill */
    chainer_advance( chainer, slotv );
    return;
  }

  fd_fec_map_ele_remove_fast( chainer->fec_map, fec, chainer->fec_pool );
  fec->merkle_root = *full_mr;
  fd_fec_map_ele_insert( chainer->fec_map, fec, chainer->fec_pool );
}

int
fd_chainer_shred_for_block_id_verify( fd_chainer_t *    chainer,
                                      ulong             slot,
                                      uint              fec_set_idx,
                                      fd_hash_t const * block_id,
                                      fd_hash_t const * mr ) {
  fd_chainer_slotv_t * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) return 0;
  fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, fec_set_idx );
  if( FD_UNLIKELY( !fec ) ) return 0;
  /* Compare only the 20-byte FEC-set merkle root prefix only */
  return !memcmp( fec->merkle_root.uc, mr->uc, FD_SHRED_MERKLE_NODE_SZ );
}

void
fd_chainer_notar_fallback( fd_chainer_t * chainer,
                           ulong          slot,
                           fd_hash_t      block_id ) {
  FD_TEST( slot > chainer->root );
  /* if we already have an slotv with this block_id, no-op.  Note
     turbine block_id may not be computed yet. */
  if( FD_LIKELY( fd_chainer_slot_version_query( chainer, slot, &block_id ) ) ) return;

  fd_chainer_slotv_t * slotv = acquire_slotv( chainer, slot );
  slotv->block_id = block_id;

  fd_chainer_slotv_t * turbine = turbine_slotv_query( chainer, slot );
  if( FD_UNLIKELY( turbine && fd_hash_check_zero( &turbine->block_id ) ) ) {
    /* Turbine slotv is not yet complete, but votor repair events for this
       slot have already started arriving, suggesting we are way behind
       on repairing this slot.  At this point just abandon the turbine version
       and only deliver a notar fallback version. */
    slotv_abandon( chainer, turbine );
  }

}

/* Out queue must be drained before calling this function, else there
   could be stale references to pruned slotvs. */
void
fd_chainer_publish( fd_chainer_t *    chainer,
                    ulong             new_root,
                    fd_hash_t const * new_root_block_id,
                    fd_store_t *      store ) {
  fd_store_map_t store_map[1];
  if( store ) FD_TEST( fd_store_map_ljoin( store, store_map ) );

  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;
  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_chainer_fec_t   * fec_pool   = chainer->fec_pool;
  fd_fec_map_t       * fec_map    = chainer->fec_map;

  out_ele_t * out_queue = chainer->out_queue;
  if( FD_UNLIKELY( !out_queue_empty( out_queue ) ) ) FD_LOG_CRIT(( "chainer out_queue not empty before publish" ));

  ulong root = chainer->root;
  if( FD_UNLIKELY( root==ULONG_MAX ) ) return;
  FD_TEST( root < new_root );
  FD_TEST( fd_chainer_slot_query( chainer, new_root ) );

  /* Prune every slot below the new root: drop all of its versions and
     release the FECs on its anchor's list.  Repeatedly pop the MULTI
     chain head so removal never races the walk. */
  for( ulong slot=root; slot<new_root; slot++ ) {
    for(;;) {
      ulong idx = fd_slotv_map_idx_query( slotv_map, &slot, ULONG_MAX, slotv_pool );
      if( idx==ULONG_MAX ) break;
      fd_chainer_slotv_t * slotv = fd_slotv_pool_ele( slotv_pool, idx );
      fd_chainer_orphan_remove( chainer, slotv );
      fd_chainer_repair_remove( chainer, slotv );

      for( uint k = 0; k < FD_FEC_BLK_MAX; k++ ) {
        fd_chainer_fec_t * fec = slotv_fec( chainer, slotv, k * FD_FEC_SHRED_CNT );
        /* because FEC pool eles can be shared across slotvs, in
           equivocating slots we can end up double-freeing the same FEC.
           So we need to query against the map to check if the FEC is still in use. */
        if( FD_UNLIKELY( fec && fd_fec_map_ele_query_const( fec_map, &fec->merkle_root, NULL, fec_pool ) ) ) {
          /* Only complete FECs were inserted into the store */
          if( FD_LIKELY( store ) && fec->complete ) fd_store_remove( store, store_map, &fec->merkle_root );
          fd_fec_map_ele_remove_fast( fec_map, fec, fec_pool );
          fd_fec_pool_ele_release( fec_pool, fec );
        }
      }
      fd_slotv_map_ele_remove_fast( slotv_map, slotv, slotv_pool );
      fd_slotv_pool_ele_release( slotv_pool, slotv );
    }
  }

  /* Every equivocating sibling version of the new root is now dead and
     must get pruned.  If we cannot identify the canonical version --
     keep them all rather than guess wrong and prune the version we
     are actually rooted on.  TODO: potentially should just log crit here.
     Making debug for now because DMR publish isnt wired and this is
     verbose */
  fd_chainer_slotv_t * canonical = new_root_block_id ? fd_chainer_slot_version_query( chainer, new_root, new_root_block_id ) : NULL;
  if( FD_UNLIKELY( !canonical ) ) {
    FD_LOG_DEBUG(( "chainer publish %lu: no version matches the rooted block_id; keeping all versions", new_root ));
  }

  chainer->root = new_root;

  /* Collect the non-canonical versions of the new root and prune.
     We will also clear the FECs on the canonical slotv to avoid stale
     references to pruned FECs.
     This is a non-issue since root FECs are never needed again. */
  for( ulong i=slotv_iter_init( chainer, new_root ); i!=ULONG_MAX; ) {
    fd_chainer_slotv_t * s    = slotv_iter_ele ( chainer, i );
    ulong                next = slotv_iter_next( chainer, i );

    /* free all FECs on slotv */
    for( uint k = 0; k < FD_FEC_BLK_MAX; k++ ) {
      fd_chainer_fec_t * fec = slotv_fec( chainer, s, k * FD_FEC_SHRED_CNT );
      if( FD_UNLIKELY( fec && fd_fec_map_ele_query_const( fec_map, &fec->merkle_root, NULL, fec_pool ) ) ) {
        if( FD_LIKELY( store && fec->complete ) ) fd_store_remove( store, store_map, &fec->merkle_root );
        fd_fec_map_ele_remove_fast( fec_map, fec, fec_pool );
        fd_fec_pool_ele_release( fec_pool, fec );
      }
    }

    fd_chainer_orphan_remove( chainer, s );
    fd_chainer_repair_remove( chainer, s );

    if( FD_UNLIKELY( canonical && s!=canonical ) ) {
      fd_slotv_map_ele_remove_fast( slotv_map, s, slotv_pool );
      fd_slotv_pool_ele_release( slotv_pool, s );
    } else {
      /* clear the surviving root's FEC list */
      fd_memset( s->fec, 0xff, sizeof(s->fec) );
    }
    i = next;
  }

  /* Connect the surviving version(s) of the new root. */
  for( ulong i=slotv_iter_init( chainer, new_root ); i!=ULONG_MAX; i=slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * s = slotv_iter_ele( chainer, i );
    if( FD_UNLIKELY( s->parent_slot==AG_UNKNOWN_SLOT ) ) s->parent_slot = new_root;
    s->connected     = 1;
    s->complete_idx  = 0;
    s->buffered_idx  = 0;
    s->delivered_idx = 0;
    s->buffered_fec_idx = UINT_MAX; /* rooted slot has no buffered FEC set */
  }

  /* The new root becomes a delivered anchor here WITHOUT going through
     chainer_advance's slot_complete cascade, so children that already
     completed while waiting on it were never connected/delivered.
     Cascade to them now, mirroring chainer_advance's child scan. */
  for( ulong i=slotv_iter_init( chainer, new_root ); i!=ULONG_MAX; i=slotv_iter_next( chainer, i ) ) {
    fd_chainer_slotv_t * s = slotv_iter_ele( chainer, i );
    if( FD_UNLIKELY( fd_hash_check_zero( &s->block_id ) ) ) continue;
    for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                                 !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                             it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
      fd_chainer_slotv_t * child = fd_slotv_map_iter_ele( it, slotv_map, slotv_pool );
      if( FD_UNLIKELY( fd_hash_eq( &child->parent_block_id, &s->block_id ) ) ) {
        child->connected = 1;
        chainer_advance( chainer, child );
      }
    }
  }
}

void
fd_chainer_print( fd_chainer_t * chainer ) {
  if( FD_UNLIKELY( chainer->root==ULONG_MAX ) ) return;

  fd_chainer_slotv_t * slotv_pool = chainer->slotv_pool;
  fd_slotv_map_t     * slotv_map  = chainer->slotv_map;

  printf( "\n[Chainer] root: %lu, highest repaired: %lu\n", chainer->root, chainer->highest_repaired );
  printf( "[slotvs] slot <- parent (buffered/complete)\n" );

  ulong cnt = 0UL;
  for( fd_slotv_map_iter_t it = fd_slotv_map_iter_init( slotv_map, slotv_pool );
                               !fd_slotv_map_iter_done( it, slotv_map, slotv_pool );
                           it = fd_slotv_map_iter_next( it, slotv_map, slotv_pool ) ) {
    fd_chainer_slotv_t * o = fd_slotv_map_iter_ele( it, slotv_map, slotv_pool );

    ulong slot = o->slot;

    /* buffered_idx / complete_idx are UINT_MAX when unknown; +1 wraps
       those to 0 (same convention as fd_forest_print) */
    FD_BASE58_ENCODE_32_BYTES( o->block_id.uc, out )
    if( FD_UNLIKELY( o->parent_slot==AG_UNKNOWN_SLOT ) ) printf( "%lu <- ??? (%u/%u) turbine: %d block_id: %s \n", slot, o->buffered_idx+1U, o->complete_idx+1U, o->turbine, out );
    else                                                 printf( "%lu (%u/%u) -> %lu turbine: %d block_id: %s connected: %d\n ", slot, o->buffered_idx+1U, o->complete_idx+1U, o->parent_slot, o->turbine, out, o->connected );
    cnt++;
  }
  printf( "(%lu total slotvs)\n", cnt );
  fflush( stdout ); /* Ensure slotv map printf output is flushed */
}
