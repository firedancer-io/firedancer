#include "fd_hfork.h"
#include "fd_hfork_private.h"

static void
check( fd_hfork_t *  hfork,
       ulong         total_stake,
       candidate_t * candidate,
       int           dead,
       fd_hash_t *   our_bank_hash ) {

  if( FD_LIKELY( candidate->checked ) ) return; /* already checked this bank hash against our own */
  double pct = (double)candidate->stake * 100.0 / (double)total_stake;
  if( FD_LIKELY( pct < 52.0 ) ) return; /* not enough stake to compare */

  if( FD_UNLIKELY( dead ) ) {
    char msg[ 4096UL ];
    FD_BASE58_ENCODE_32_BYTES( candidate->key.block_id.uc, _block_id );
    FD_TEST( fd_cstr_printf_check( msg, sizeof( msg ), NULL,
                                  "HARD FORK DETECTED: our validator has marked slot %lu with block ID `%s` dead, but %lu validators with %.1f of stake have voted on it",
                                  candidate->slot,
                                  _block_id,
                                  candidate->cnt,
                                  pct ) );

    if( FD_UNLIKELY( hfork->fatal ) ) FD_LOG_ERR    (( "%s", msg ));
    else                              FD_LOG_WARNING(( "%s", msg ));
  } else if( FD_UNLIKELY( 0!=memcmp( our_bank_hash, &candidate->key.bank_hash, 32UL ) ) ) {
    char msg[ 4096UL ];
    FD_BASE58_ENCODE_32_BYTES( our_bank_hash->uc, _our_bank_hash );
    FD_BASE58_ENCODE_32_BYTES( candidate->key.block_id.uc, _block_id );
    FD_BASE58_ENCODE_32_BYTES( candidate->key.bank_hash.uc, _bank_hash );
    FD_TEST( fd_cstr_printf_check( msg, sizeof( msg ), NULL,
                                  "HARD FORK DETECTED: our validator has produced bank hash `%s` for slot %lu with block ID `%s`, but %lu validators with %.1f of stake have voted on a different bank hash `%s` for the same slot",
                                  _our_bank_hash,
                                  candidate->slot,
                                  _block_id,
                                  candidate->cnt,
                                  pct,
                                  _bank_hash ) );

    if( FD_UNLIKELY( hfork->fatal ) ) FD_LOG_ERR    (( "%s", msg ));
    else                              FD_LOG_WARNING(( "%s", msg ));
  }
  candidate->checked = 1;
}

ulong
fd_hfork_align( void ) {
  return 128UL;
}

ulong
fd_hfork_footprint( ulong max_live_slots,
                    ulong max_vote_accounts ) {
  ulong fork_max   = max_live_slots * max_vote_accounts;
  int   lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( fork_max ) ) + 1;
  int   lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( max_vote_accounts ) ) + 1;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_hfork_t),   sizeof(fd_hfork_t)                    );
  l = FD_LAYOUT_APPEND( l, blk_map_align(),       blk_map_footprint( lg_blk_max )       );
  l = FD_LAYOUT_APPEND( l, vtr_map_align(),       vtr_map_footprint( lg_vtr_max )       );
  l = FD_LAYOUT_APPEND( l, candidate_map_align(), candidate_map_footprint( lg_blk_max ) );
  l = FD_LAYOUT_APPEND( l, bank_hash_pool_align(), bank_hash_pool_footprint( fork_max ) );
  for( ulong i = 0UL; i < fd_ulong_pow2( lg_vtr_max ); i++ ) {
    l = FD_LAYOUT_APPEND( l, votes_align(), votes_footprint( max_live_slots ) );
  }
  return FD_LAYOUT_FINI( l, fd_hfork_align() );
}

void *
fd_hfork_new( void * shmem,
              ulong  max_live_slots,
              ulong  max_vote_accounts,
              ulong  seed,
              int    fatal ) {
  (void)seed; /* TODO map seed */

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_hfork_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_hfork_footprint( max_live_slots, max_vote_accounts );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad max_live_slots (%lu) or max_vote_accounts (%lu)", max_live_slots, max_vote_accounts ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  ulong fork_max   = max_live_slots * max_vote_accounts;
  int   lg_blk_max = fd_ulong_find_msb( fd_ulong_pow2_up( fork_max ) ) + 1;
  int   lg_vtr_max = fd_ulong_find_msb( fd_ulong_pow2_up( max_vote_accounts ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_hfork_t * hfork          = FD_SCRATCH_ALLOC_APPEND( l, fd_hfork_align(),       sizeof( fd_hfork_t )                        );
  void *       blk_map        = FD_SCRATCH_ALLOC_APPEND( l, blk_map_align(),        blk_map_footprint( lg_blk_max )             );
  void *       vtr_map        = FD_SCRATCH_ALLOC_APPEND( l, vtr_map_align(),        vtr_map_footprint( lg_vtr_max )             );
  void *       candidate_map  = FD_SCRATCH_ALLOC_APPEND( l, candidate_map_align(),  candidate_map_footprint( lg_blk_max )       );
  void *       bank_hash_pool = FD_SCRATCH_ALLOC_APPEND( l, bank_hash_pool_align(), bank_hash_pool_footprint( fork_max )        );

  hfork->blk_map        = blk_map_new( blk_map, lg_blk_max, 0UL );             /* FIXME seed */
  hfork->vtr_map        = vtr_map_new( vtr_map, lg_vtr_max, 0UL );             /* FIXME seed */
  hfork->candidate_map  = candidate_map_new( candidate_map, lg_blk_max, 0UL ); /* FIXME seed */
  hfork->bank_hash_pool = bank_hash_pool_new( bank_hash_pool, fork_max );
  for( ulong i = 0UL; i < fd_ulong_pow2( lg_vtr_max ); i++ ) {
    void *  votes = FD_SCRATCH_ALLOC_APPEND( l, votes_align(), votes_footprint( max_live_slots ) );
    vtr_t * join  = vtr_map_join( hfork->vtr_map );
    join[i].votes = votes_new( votes, max_live_slots );
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_hfork_align() ) == (ulong)shmem + footprint );
  hfork->fatal = fatal;
  return shmem;
}

fd_hfork_t *
fd_hfork_join( void * shhfork ) {
  fd_hfork_t * hfork = (fd_hfork_t *)shhfork;

  if( FD_UNLIKELY( !hfork ) ) {
    FD_LOG_WARNING(( "NULL hfork" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)hfork, fd_hfork_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned hfork" ));
    return NULL;
  }

  hfork->blk_map        = blk_map_join( hfork->blk_map );
  hfork->vtr_map        = vtr_map_join( hfork->vtr_map );
  hfork->candidate_map  = candidate_map_join( hfork->candidate_map );
  hfork->bank_hash_pool = bank_hash_pool_join( hfork->bank_hash_pool );
  for( ulong i = 0UL; i < vtr_map_slot_cnt( hfork->vtr_map ); i++ ) {
    hfork->vtr_map[i].votes = votes_join( hfork->vtr_map[i].votes );
  }

  return hfork;
}

void *
fd_hfork_leave( fd_hfork_t const * hfork ) {

  if( FD_UNLIKELY( !hfork ) ) {
    FD_LOG_WARNING(( "NULL hfork" ));
    return NULL;
  }

  return (void *)hfork;
}

void *
fd_hfork_delete( void * hfork ) {

  if( FD_UNLIKELY( !hfork ) ) {
    FD_LOG_WARNING(( "NULL hfork" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)hfork, fd_hfork_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned hfork" ));
    return NULL;
  }

  return hfork;
}

void
remove( blk_t * blk, fd_hash_t * bank_hash, bank_hash_t * pool ) {
  bank_hash_t * prev = NULL;
  bank_hash_t * curr = blk->bank_hashes;
  while( FD_LIKELY( curr ) ) {
    if( FD_LIKELY( 0==memcmp( &curr->bank_hash, bank_hash, 32UL ) ) ) break;
    prev = curr;
    curr = bank_hash_pool_ele( pool, curr->next );
  }
  FD_TEST( curr ); /* assumes bank_hash in blk->bank_hashes */

  /* In most cases, there is only one bank_hash per blk, so it will be
     the first element in blk->bank_hashes and prev will be NULL. */

  if( FD_LIKELY( !prev ) ) blk->bank_hashes = bank_hash_pool_ele( pool, curr->next );
  else                     prev->next       = curr->next;
  bank_hash_pool_ele_release( pool, curr );
}

void
fd_hfork_count_vote( fd_hfork_t *         hfork,
                     fd_hash_t const *    vote_acc,
                     fd_hash_t const *    block_id,
                     fd_hash_t const *    bank_hash,
                     ulong                slot,
                     ulong                stake,
                     ulong                total_stake,
                     fd_hfork_metrics_t * metrics ) {

  /* Get the vtr. */

  vtr_t * vtr = vtr_map_query( hfork->vtr_map, *vote_acc, NULL );
  if( FD_UNLIKELY( !vtr ) ) {
    FD_TEST( vtr_map_key_cnt( hfork->vtr_map ) < vtr_map_key_max( hfork->vtr_map ) );
    vtr = vtr_map_insert( hfork->vtr_map, *vote_acc );
  }

  /* Ignore out of order or duplicate votes. */

  if( FD_UNLIKELY( !votes_empty( vtr->votes ) ) ) {
    vote_t const * tail = votes_peek_tail_const( vtr->votes );
    if( FD_UNLIKELY( tail && tail->slot >= slot ) ) return;
  }

  /* Evict the candidate's oldest vote (by vote slot). */

  if( FD_UNLIKELY( votes_full( vtr->votes ) ) ) {
    vote_t          vote      = votes_pop_head( vtr->votes );
    candidate_key_t key       = { .block_id = vote.block_id, .bank_hash = vote.bank_hash };
    candidate_t *   candidate = candidate_map_query( hfork->candidate_map, key, NULL );
    candidate->stake -= vote.stake;
    candidate->cnt--;
    if( FD_UNLIKELY( candidate->cnt==0 ) ) {
      candidate_map_remove( hfork->candidate_map, candidate );
      blk_t * blk = blk_map_query( hfork->blk_map, vote.block_id, NULL );
      FD_TEST( blk ); /* asumes if this is in candidate_map, it must also be in blk_map */
      remove( blk, &vote.bank_hash, hfork->bank_hash_pool );
      if( FD_UNLIKELY( !blk->bank_hashes ) ) {
        blk_map_remove( hfork->blk_map, blk );
        if( FD_UNLIKELY( blk->forked ) ) {
          metrics->active--;
          metrics->pruned++;
        }
      }
    }
  }

  /* Push the vote onto the vtr. */

  vote_t vote = { .block_id = *block_id, .bank_hash = *bank_hash, .slot = slot, .stake = stake };
  vtr->votes  = votes_push_tail( vtr->votes, vote );

  /* Update the hard fork candidate for this block id. */

  candidate_key_t key       = { .block_id = *block_id, .bank_hash = *bank_hash };
  candidate_t *   candidate = candidate_map_query( hfork->candidate_map, key, NULL );
  if( FD_UNLIKELY( !candidate ) ) {
    candidate        = candidate_map_insert( hfork->candidate_map, key );
    candidate->slot  = slot;
    candidate->stake = 0UL;
    candidate->cnt   = 0UL;
  }
  candidate->cnt++;
  candidate->stake += stake;

  /* Update the list of bank hashes for this block_id. */

  blk_t * blk = blk_map_query( hfork->blk_map, *block_id, NULL );
  if( FD_UNLIKELY( !blk ) ) {
    FD_TEST( blk_map_key_cnt( hfork->blk_map ) < blk_map_key_max( hfork->blk_map ) ); /* invariant violation: blk_map full */
    blk              = blk_map_insert( hfork->blk_map, *block_id );
    blk->bank_hashes = NULL;
    blk->replayed    = 0;
    blk->dead        = 0;
  }
  int           found = 0;
  ulong         cnt   = 0;
  bank_hash_t * prev  = NULL;
  bank_hash_t * curr  = blk->bank_hashes;
  while( FD_LIKELY( curr ) ) {
    if( FD_LIKELY( 0==memcmp( curr, bank_hash, 32UL ) ) ) found = 1;
    prev = curr;
    curr = bank_hash_pool_ele( hfork->bank_hash_pool, curr->next );
    cnt++;
  }
  if( FD_UNLIKELY( !found ) ) {
    FD_TEST( bank_hash_pool_free( hfork->bank_hash_pool ) );
    bank_hash_t * ele = bank_hash_pool_ele_acquire( hfork->bank_hash_pool );
    ele->bank_hash    = *bank_hash;
    ele->next         = bank_hash_pool_idx_null( hfork->bank_hash_pool );
    if( FD_LIKELY( !prev ) ) blk->bank_hashes = ele;
    else {
      prev->next  = bank_hash_pool_idx( hfork->bank_hash_pool, ele );
      blk->forked = 1;
      metrics->seen++;
      metrics->active++;
    }
    cnt++;
  }
  metrics->max_width = fd_ulong_max( metrics->max_width, cnt );

  /* Check for hard forks. */

  if( FD_LIKELY( blk->replayed ) ) check( hfork, total_stake, candidate, blk->dead, &blk->our_bank_hash );
}

void
fd_hfork_record_our_bank_hash( fd_hfork_t * hfork,
                               fd_hash_t  * block_id,
                               fd_hash_t  * bank_hash,
                               ulong        total_stake ) {
  blk_t * blk = blk_map_query( hfork->blk_map, *block_id, NULL );
  if( FD_UNLIKELY( !blk ) ) {
    blk              = blk_map_insert( hfork->blk_map, *block_id );
    blk->replayed    = 1;
    blk->bank_hashes = NULL;
  }
  if( FD_LIKELY( bank_hash ) ) { blk->dead = 0; blk->our_bank_hash = *bank_hash; }
  else                           blk->dead = 1;

  bank_hash_t * curr  = blk->bank_hashes;
  while( FD_LIKELY( curr ) ) {
    candidate_key_t key       = { .block_id = *block_id, .bank_hash = curr->bank_hash };
    candidate_t *   candidate = candidate_map_query( hfork->candidate_map, key, NULL );
    if( FD_LIKELY( candidate ) ) check( hfork, total_stake, candidate, blk->dead, &blk->our_bank_hash );
    curr = bank_hash_pool_ele( hfork->bank_hash_pool, curr->next );
  }
}
