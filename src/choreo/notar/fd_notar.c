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

  fd_memset( shmem, 0, footprint );

  int lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( blk_max ) ) + 1;
  int lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( FD_VOTER_MAX ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_notar_t * notar = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_align(),     sizeof(fd_notar_t)                     );
  void *       bid   = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_bid_align(), fd_notar_bid_footprint( lg_blk_max   ) );
  void *       blk   = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_blk_align(), fd_notar_blk_footprint( lg_blk_max   ) );
  void *       vtr   = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_vtr_align(), fd_notar_vtr_footprint( lg_vtr_max   ) );
  void *       out   = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_out_align(), fd_notar_out_footprint( blk_max      ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_notar_align() ) == (ulong)shmem + footprint );

  notar->bid  = fd_notar_bid_new( bid, lg_blk_max );
  notar->blk  = fd_notar_blk_new( blk, lg_blk_max );
  notar->vtr  = fd_notar_vtr_new( vtr, lg_vtr_max );
  notar->out  = fd_notar_out_new( out, blk_max    );

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

  notar->bid = fd_notar_bid_join( notar->bid );
  notar->blk = fd_notar_blk_join( notar->blk );
  notar->vtr = fd_notar_vtr_join( notar->vtr );
  notar->out = fd_notar_out_join( notar->out );

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

void
fd_notar_vote( fd_notar_t        * notar,
               fd_pubkey_t const * pubkey,
               fd_tower_t  const * tower,
               fd_hash_t   const * bank_hash,
               fd_hash_t   const * block_id ) {

  /* Return early if the pubkey is not part of the set of voters we know
     from this epoch. Because these votes can come from gossip (and
     therefore have not been successfully validated and executed by the
     vote program), it's possible the vote itself is just invalid. */

  fd_notar_vtr_t const * vtr = fd_notar_vtr_query( notar->vtr, *pubkey, NULL );
  if( FD_UNLIKELY( !vtr ) ) { FD_LOG_WARNING(( "unknown voter" )); return; };

  /* Return early if the tower is empty. As above, the vote could simply
     be invalid. */

  fd_tower_vote_t const * last_tower_vote = fd_tower_votes_peek_tail_const( tower );
  if( FD_UNLIKELY( !last_tower_vote ) ) { FD_LOG_WARNING(( "empty tower" )); return; }

  fd_notar_blk_t * notar_blk = fd_notar_blk_query( notar->blk, *block_id, NULL );

  /* Normally we expect all notar_blks to already have been inserted by
     replay, but this special insertion is necessary for gossip vote
     txns that may be for an equivocating version of a block. So the
     slot number matches one we have but has a different hash.

     It's also possible the gossip vote is ahead of our replay, so our
     replay won't insert if a block_id has already been inserted. */

  if( FD_UNLIKELY( !notar_blk ) ) notar_blk = fd_notar_blk_insert( notar->blk, *block_id );
  notar_blk->slot      = last_tower_vote->slot;
  notar_blk->bank_hash = *bank_hash;
  notar_blk->stake     = 0;
  notar_blk->pro_conf  = 0;
  notar_blk->dup_conf  = 0;
  notar_blk->opt_conf  = 0;

  /* Agave always counts the last vote slot in the tower towards
     confirmation, regardless of whether the bank hash matches. However,
     "intermediate slots" in the tower are not counted when the bank
     hash doesn't match.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L476-L487 */

  if( FD_LIKELY( !fd_notar_blk_vtrs_test( notar_blk->vtrs, vtr->bit ) ) ) {
    fd_notar_blk_vtrs_insert( notar_blk->vtrs, vtr->bit ); /* count the voter */
    notar_blk->stake += vtr->stake;
  };

  /* Agave decides whether to count intermediate vote slots in the tower
     based if they've 1. replayed the slot and 2. their replay bank hash
     matches the vote's bank hash. We do the same thing, but using
     block_ids. It's possible we haven't yet replayed this slot being
     voted on is because votes can come from gossip as well (and those
     validators might be ahead of us in replay).

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L483-L487 */

  if( FD_UNLIKELY( 0==memcmp( &notar_blk->block_id, block_id, sizeof(fd_hash_t) ) ) ) return;

  /* Agave assumes if the last vote's bank hash matches their own they
     can count all the vote slots in the tower towards confirmation for
     their own ancestor bank hashes as well. We do the same but again
     use block_ids instead. */

  int skip = 1;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower       );
                                   !fd_tower_votes_iter_done_rev( tower, iter );
                             iter = fd_tower_votes_iter_prev    ( tower, iter ) ) {

    if( FD_UNLIKELY( skip ) ) { skip = 0; continue; } /* skip the last vote (iter rev), we've already counted it */

    fd_tower_vote_t const * vote = fd_tower_votes_iter_ele_const( tower, iter );
    if( FD_UNLIKELY( !vote                    ) ) continue;
    if( FD_UNLIKELY( vote->slot < notar->root ) ) continue;

    fd_notar_bid_t * bid = fd_notar_bid_query( notar->bid, vote->slot, NULL );

    /* Even though the tower is guaranteed to only contain vote slots
       for the ancestors on the same fork (and if we've replayed the
       descendant we must have replayed the ancestors), this can happen
       if the vote is malformed (since gossip votes don't get validated
       by the the vote program).

       Agave handles similarly:
       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/cluster_info_vote_listener.rs#L513-L518*/

    if( FD_UNLIKELY( !bid ) ) continue;

    fd_notar_blk_t * vote_blk = fd_notar_blk_query( notar->blk, bid->block_id, NULL );
    if( FD_LIKELY( fd_notar_blk_vtrs_test( vote_blk->vtrs, vtr->bit ) ) ) continue; /* check if we've already counted this voter's stake */
    fd_notar_blk_vtrs_insert( vote_blk->vtrs, vtr->bit );
    vote_blk->stake += vtr->stake;

    double r = (double)vote_blk->stake / (double)notar->stake;

    /* Propagation confirmation applies to ancestor blocks too.
       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/replay_stage.rs#L3785 */

    while( FD_LIKELY( vote_blk ) ) {
      if( FD_UNLIKELY( !vote_blk->pro_conf && r >= PRO_CONF ) ) {
        vote_blk->pro_conf = 1;
        fd_notar_out_push_tail( notar->out, (fd_notar_out_t){ .block_id = vote_blk->block_id, .bank_hash = vote_blk->bank_hash, .slot = vote_blk->slot, .pro_conf = 1, .dup_conf = 0, .opt_conf = 0 } );
        fd_notar_bid_t * parent_bid = fd_notar_bid_query( notar->bid, vote_blk->slot, NULL );
        if( FD_UNLIKELY( !parent_bid ) ) FD_LOG_CRIT(( "slot %lu missing parent slot %lu from bid. ancestors must be inserted before descendants.", vote_blk->slot, vote_blk->parent_slot ));
        vote_blk = fd_notar_blk_query( notar->blk, parent_bid->block_id, NULL );
        vote_blk->block_id = parent_bid->block_id; /* in case it was just created */
      } else {
        break;
      }
    }

    /* On the other hand, duplicate and optimistic confirmation does not
       apply to ancestor blocks. */

    if( FD_UNLIKELY( !vote_blk->dup_conf && r >= DUP_CONF ) ) {
      vote_blk->dup_conf = 1;
      fd_notar_out_push_tail( notar->out, (fd_notar_out_t){ .block_id = vote_blk->block_id, .bank_hash = vote_blk->bank_hash, .slot = vote_blk->slot, .pro_conf = 0, .dup_conf = 1, .opt_conf = 0 } );
    }
    if( FD_UNLIKELY( !vote_blk->opt_conf && r >= OPT_CONF ) ) {
      vote_blk->opt_conf = 1;
      fd_notar_out_push_tail( notar->out, (fd_notar_out_t){ .block_id = vote_blk->block_id, .bank_hash = vote_blk->bank_hash, .slot = vote_blk->slot, .pro_conf = 0, .dup_conf = 0, .opt_conf = 1 } );
    }
  }
}

void
fd_notar_publish( fd_notar_t * notar,
                  ulong        root ) {
  for( ulong slot = notar->root; slot < root; slot++ ) {
    fd_notar_bid_t * bid = fd_notar_bid_query( notar->bid, slot, NULL );
    fd_notar_blk_t * blk = fd_notar_blk_query( notar->blk, bid->block_id, NULL );
    if( FD_LIKELY( bid ) ) fd_notar_blk_remove( notar->blk, blk );
  }
  notar->root = root;
}
