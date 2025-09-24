#include "fd_notar.h"

#define PRO_CONF (1./3) /* propagation confirmed    */
#define DUP_CONF (0.52) /* duplicate confirmed      */
#define OPT_CONF (2./3) /* optimistically confirmed */

void *
fd_notar_new( void * shmem,
              ulong  blk_max ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_notar_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_notar_footprint( blk_max );
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

  int lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( blk_max ) );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_notar_t * notar = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_align(),     sizeof(fd_notar_t)                   );
  void *       blks  = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_blk_align(), fd_notar_blk_footprint( lg_blk_max ) );
  void *       vtrs  = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_vtr_align(), fd_notar_vtr_footprint( lg_blk_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_notar_align() ) == (ulong)shmem + footprint );

  notar->blks = fd_notar_blk_new( blks, lg_blk_max );
  notar->vtrs = fd_notar_blk_new( vtrs, lg_blk_max );

  return shmem;
}

fd_notar_t *
fd_notar_join( void * shnotar ) {
  fd_notar_t * notar = (fd_notar_t *)shnotar;

  if( FD_UNLIKELY( !notar ) ) {
    FD_LOG_WARNING(( "NULL notar" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)notar, fd_notar_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned notar" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( notar );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "notar must be part of a workspace" ));
    return NULL;
  }

  return notar;
}

void *
fd_notar_leave( fd_notar_t const * notar ) {

  if( FD_UNLIKELY( !notar ) ) {
    FD_LOG_WARNING(( "NULL notar" ));
    return NULL;
  }

  return (void *)notar;
}

void *
fd_notar_delete( void * notar ) {

  if( FD_UNLIKELY( !notar ) ) {
    FD_LOG_WARNING(( "NULL notar" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)notar, fd_notar_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned notar" ));
    return NULL;
  }

  return notar;
}

fd_notar_blk_t *
fd_notar_insert( fd_notar_t *      notar,
                 ulong             slot,
                 fd_hash_t const * bank_hash,
                 fd_hash_t const * block_id ) {
  fd_notar_blk_t * blk = fd_notar_blk_insert( notar->blks, slot );
  blk->parent_slot     = slot - 1;
  blk->bank_hash       = *bank_hash;
  blk->block_id        = *block_id;
  blk->stake           = 0;
  blk->pro_conf        = 0;
  blk->dup_conf        = 0;
  blk->opt_conf        = 0;
  return blk;
}

fd_notar_vtr_t *
fd_notar_vote( fd_notar_t        * notar,
               fd_pubkey_t const * pubkey,
               fd_tower_t  const * tower,
               fd_hash_t   const * bank_hash,
               fd_hash_t   const * block_id ) {

  /* Return early if the pubkey is not part of the set of voters we know
     from this epoch. Because these votes can come from gossip (and
     therefore have not been successfully validated and executed by the
     vote program), it's possible the vote itself is just invalid. */

  fd_notar_vtr_t const * vtr = fd_notar_vtr_query( notar->vtrs, *pubkey, NULL );
  if( FD_UNLIKELY( !vtr ) ) { FD_LOG_WARNING(( "unknown voter" )); return NULL; };

  /* Return early if the tower is empty. As above, the vote could simply
     be invalid. */

  fd_tower_vote_t const * last_vote = fd_tower_votes_peek_tail_const( tower );
  if( FD_UNLIKELY( !last_vote ) ) { FD_LOG_WARNING(( "empty tower" )); return NULL; }

  /* It's possible we haven't yet replayed this slot being voted on.
     Even though votes can come from gossip (and therefore can be for
     slots ahead of what we've replayed), Agave verifies a vote's bank
     hash matches their own before counting it towards the confirmation
     thresholds.

     Therefore, only votes for slots we've already replayed (including
     gossip votes) can be counted.

     https://github.com/anza-xyz/agave/blob/v2.3.7/runtime/src/bank_hash_cache.rs#L68-L71 */

  fd_notar_blk_t * last_blk = fd_notar_blk_query( notar->blks, last_vote->slot, NULL );
  if( FD_UNLIKELY( !last_blk ) ) { FD_LOG_WARNING(( "haven't replayed slot %lu", last_vote->slot )); return; };

  /* Agave does a weird thing where they always count the last vote slot
     in the tower towards confirmation, regardless of whether the bank
     hash matches. However, "intermediate slots" in the tower are not
     counted when the bank hash doesn't match.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L476-L487 */

  if( FD_LIKELY( last_blk->vtrs[ vtr->bit ] ) ) return; /* already counted */
  fd_notar_blk_vtrs_insert( last_blk->vtrs, vtr->bit ); /* count the voter */
  last_blk->stake += vtr->stake;

  /* Don't count remaining votes in tower if bank hash doesn't match. */

  if( FD_UNLIKELY( memcmp( &last_blk->bank_hash, bank_hash, sizeof(fd_hash_t) ) ) ) return;

  /* The voter's bank hash matches our own so we expect that all the
     slots in their tower towards the propagation threshold for that slot. */

  int skip = 1;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower       );
                                   !fd_tower_votes_iter_done_rev( tower, iter );
                             iter = fd_tower_votes_iter_prev    ( tower, iter ) ) {

    if( FD_UNLIKELY( skip ) ) { skip = 0; continue; } /* skip the last vote (iter rev), we've already counted it */

    fd_tower_vote_t const * vote = fd_tower_votes_iter_ele_const( tower, iter );
    if( FD_UNLIKELY( !vote                    ) ) continue;
    if( FD_UNLIKELY( vote->slot < notar->root ) ) continue;

    /* By definition every vote slot in the tower is an ancestor of the
       next vote slot. */

    fd_notar_blk_t * blk = fd_notar_blk_query( notar->blks, vote->slot, NULL );

    /* Check this tower vote slot is in notar. If it's not, then the
       vote txn is invalid. We silently skip the vote the same way Agave
       does.

       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L513-L518 */

    if( FD_UNLIKELY( !blk ) ) continue;

    /* Check if we've already counted this voter's stake. */

    if( FD_LIKELY( blk->vtrs[ vtr->bit ] ) ) continue;

    /* Count this voter's stake towards the confirmation thresholds. */

    fd_notar_blk_vtrs_insert( blk->vtrs, vtr->bit );
    blk->stake += vtr->stake;

    /* If a slot reaches propagation conf, then it's implied its
       ancestors are confirmed too because they're on the same fork. */

    double r = (double)blk->stake / (double)notar->stake;
    if( FD_UNLIKELY( !blk->pro_conf && r >= PRO_CONF ) ) {
      while( FD_LIKELY( blk ) ) {
        blk->pro_conf = 1;
        blk = fd_notar_blk_query( notar->blks, blk->parent_slot, NULL );
      }
    }
  }
  (void)block_id;
}

void
fd_notar_publish( fd_notar_t * notar,
                  ulong        root ) {
  for( ulong slot = notar->root; slot < root; slot++ ) {
    fd_notar_blk_t * blk = fd_notar_blk_query( notar->blks, slot, NULL );
    if( FD_LIKELY( blk ) ) fd_notar_blk_remove( notar->blks, blk );
  }
  notar->root = root;
}
