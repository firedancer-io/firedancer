#include "fd_notar.h"
#include "../../util/bits/fd_bits.h"

void *
fd_notar_new( void * shmem,
              ulong  slot_max ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_notar_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_notar_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slot_max (%lu)", slot_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  int lg_slot_max = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;
  int lg_blk_max  = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max * FD_VOTER_MAX ) ) + 1;
  int lg_vtr_max  = fd_ulong_find_msb( fd_ulong_pow2_up( FD_VOTER_MAX ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_notar_t * notar     = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_align(),      sizeof(fd_notar_t)                     );
  void *       slot_map  = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_slot_align(), fd_notar_slot_footprint( lg_slot_max ) );
  void *       blk_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_blk_align(),  fd_notar_blk_footprint( lg_blk_max )   );
  void *       vtr_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_notar_vtr_align(),  fd_notar_vtr_footprint( lg_vtr_max )   );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_notar_align() ) == (ulong)shmem + footprint );

  notar->slot_max = slot_max;
  notar->slot_map = fd_notar_slot_new( slot_map, lg_slot_max );
  notar->blk_map  = fd_notar_blk_new( blk_map, lg_blk_max );
  notar->vtr_map  = fd_notar_vtr_new( vtr_map, lg_vtr_max );

  notar->epoch    = ULONG_MAX;
  notar->lo_wmark = ULONG_MAX;
  notar->hi_wmark = ULONG_MAX;

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

  notar->slot_map = fd_notar_slot_join( notar->slot_map );
  notar->blk_map  = fd_notar_blk_join( notar->blk_map );
  notar->vtr_map  = fd_notar_vtr_join( notar->vtr_map );

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
fd_notar_count_vote( fd_notar_t *        notar,
                     ulong               total_stake,
                     fd_pubkey_t const * addr,
                     ulong               vote_slot,
                     fd_hash_t const *   vote_block_id ) {

  if( FD_UNLIKELY( !notar ) ) { FD_LOG_WARNING(( "NULL notar" )); return NULL; }

  /* Ignore if this vote slot isn't in range. */

  if( FD_UNLIKELY( vote_slot < notar->lo_wmark || vote_slot > notar->hi_wmark ) ) return NULL;

  /* Ignore if this vote account isn't in the voter set. */

  fd_notar_vtr_t const * vtr = fd_notar_vtr_query( notar->vtr_map, *addr, NULL );
  if( FD_UNLIKELY( !vtr ) ) return NULL;

  /* Check we haven't already counted the voter's stake for this slot.
     If a voter voted for multiple block ids for the same slot, we only
     count their first one.  Honest voters never vote more than once for
     the same slot so the percentage of stake doing this should be small
     per honest majority assumption. */

  fd_notar_slot_t * notar_slot = fd_notar_slot_query( notar->slot_map, vote_slot, NULL );
  if( FD_UNLIKELY( !notar_slot ) ) {
    notar_slot                   = fd_notar_slot_insert( notar->slot_map, vote_slot );
    notar_slot->parent_slot      = ULONG_MAX;
    notar_slot->prev_leader_slot = ULONG_MAX;
    notar_slot->stake            = 0;
    notar_slot->is_leader        = 0;
    notar_slot->is_propagated    = 0;
    notar_slot->block_ids_cnt    = 0;
    fd_notar_slot_vtrs_null( notar_slot->prev_vtrs );
    fd_notar_slot_vtrs_null( notar_slot->vtrs );
  }
  if( FD_LIKELY( fd_notar_slot_vtrs_test( notar_slot->vtrs, vtr->bit ) ) ) return NULL;
  fd_notar_slot_vtrs_insert( notar_slot->vtrs, vtr->bit );
  notar_slot->stake += vtr->stake;

  /* Get the actual block with the block_id. */

  fd_notar_blk_t * notar_blk = fd_notar_blk_query( notar->blk_map, *vote_block_id, NULL );
  if( FD_UNLIKELY( !notar_blk ) ) {
    notar_blk        = fd_notar_blk_insert( notar->blk_map, *vote_block_id );
    notar_blk->slot  = vote_slot;
    notar_blk->stake = 0;
    FD_TEST( notar_slot->block_ids_cnt < FD_VOTER_MAX ); /* at most one unique block id per voter in a slot */
    notar_slot->block_ids[notar_slot->block_ids_cnt++] = *vote_block_id;
  }
  notar_blk->stake   += vtr->stake;
  notar_blk->dup_conf = ((double)notar_blk->stake / (double)total_stake) > 0.52;
  notar_blk->opt_conf = ((double)notar_blk->stake / (double)total_stake) > (2.0/3.0);
  return notar_blk;
}

void
fd_notar_advance_epoch( fd_notar_t       * notar,
                        fd_tower_accts_t * accts,
                        ulong              epoch ) {
  notar->epoch = epoch;
  for( ulong i = 0; i < fd_notar_vtr_key_max( notar->vtr_map ); i++ ) {
    fd_notar_vtr_t * vtr = &notar->vtr_map[i];
    if( fd_notar_vtr_key_inval( vtr->addr ) ) continue;
    vtr->prev_stake = vtr->stake;
    vtr->stake      = 0;
    vtr->prev_bit   = vtr->bit;
    vtr->bit        = ULONG_MAX;
  }

  ulong vtr_bit = 0;
  for( fd_tower_accts_iter_t iter = fd_tower_accts_iter_init( accts       );
                                   !fd_tower_accts_iter_done( accts, iter );
                             iter = fd_tower_accts_iter_next( accts, iter ) ) {
    fd_tower_accts_t const * acct = fd_tower_accts_iter_ele( accts, iter );
    fd_notar_vtr_t * vtr = fd_notar_vtr_query( notar->vtr_map, acct->addr, NULL );
    if( FD_UNLIKELY( !vtr ) ) vtr = fd_notar_vtr_insert( notar->vtr_map, acct->addr );
    vtr->stake = acct->stake;
    vtr->bit   = vtr_bit++;
  }
}

void
fd_notar_advance_wmark( fd_notar_t * notar,
                        ulong        wmark ) {
  for(ulong slot = notar->lo_wmark; slot < wmark; slot++ ) {
    fd_notar_slot_t * notar_slot = fd_notar_slot_query( notar->slot_map, slot, NULL );
    if( FD_LIKELY( notar_slot ) ) {
      for( ulong i=0; i<notar_slot->block_ids_cnt; i++ ) {
        fd_hash_t const * block_id = &notar_slot->block_ids[i];
        fd_notar_blk_t * notar_blk = fd_notar_blk_query( notar->blk_map, *block_id, NULL );
        if( FD_UNLIKELY( !notar_blk ) ) FD_LOG_CRIT(( "missing %lu %s %lu %lu", slot, FD_BASE58_ENC_32_ALLOCA( block_id ), i, notar_slot->block_ids_cnt ));
        fd_notar_blk_remove( notar->blk_map, notar_blk );
      }
      fd_notar_slot_remove( notar->slot_map, notar_slot );
    }
  }
  notar->lo_wmark = wmark;
  notar->hi_wmark = wmark + notar->slot_max;
}
