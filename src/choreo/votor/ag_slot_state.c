#include "ag_slot_state.h"
#include "ag_vote_serde.h"

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#define AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR  (0)
#define AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK  (1)
#define AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES (2)

static int
block_hash_set_contains( ag_block_hash_set_t const * set,
                         ag_block_hash_t const       block_hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( FD_LIKELY( !memcmp( set->hash[i], block_hash, sizeof(ag_block_hash_t) ) ) ) return 1;
  }
  return 0;
}

static void
block_hash_set_insert( ag_block_hash_set_t * set,
                       ag_block_hash_t const block_hash ) {
  if( FD_UNLIKELY( block_hash_set_contains( set, block_hash ) ) ) return;
  FD_TEST( set->cnt < AG_EQVOC_BLOCK_HASH_MAX );
  memcpy( set->hash[ set->cnt++ ], block_hash, sizeof(ag_block_hash_t) );
}

static void
block_hash_set_remove( ag_block_hash_set_t * set,
                       ag_block_hash_t const block_hash ) {
  for( ulong i=0UL; i<set->cnt; i++ ) {
    if( FD_LIKELY( !memcmp( set->hash[i], block_hash, sizeof(ag_block_hash_t) ) ) ) {
      set->cnt--;
      if( FD_UNLIKELY( i!=set->cnt ) ) memcpy( set->hash[i], set->hash[ set->cnt ], sizeof(ag_block_hash_t) );
      return;
    }
  }
}

/* Hash stake tables.  nf selects the notar fallback table.  Spill
   records [0,spill_hwm) were written; a free record has stake
   ULONG_MAX. */

#define HS_SPILL_CHUNK (128UL)

static void
spill_io( int    fd,
          int    write,
          void * buf,
          ulong  sz,
          ulong  off ) {
  long n = write ? pwrite( fd, buf, sz, (long)off ) : pread( fd, buf, sz, (long)off );
  if( FD_UNLIKELY( n!=(long)sz ) ) FD_LOG_CRIT(( "%s(votor spill file, fd=%d, off=%lu, sz=%lu) failed (%i-%s)", write ? "pwrite" : "pread", fd, off, sz, errno, fd_io_strerror( errno ) ));
}

static inline ulong
hs_off( ag_slot_state_t const * self,
        int                     nf,
        ulong                   rec ) {
  return self->spill_off + (fd_ulong_if( nf, AG_NOTAR_SPILL_MAX, 0UL )+rec)*sizeof(ag_hash_stake_t);
}

/* Returns the id of hash in the spill records (NULL hash matches
   none), raising *top and top_hash to the largest stake seen. */

static ulong
hash_stake_spill_scan( ag_slot_state_t const * self,
                       int                     fd,
                       int                     nf,
                       uchar const *           hash,
                       ulong *                 top,
                       uchar *                 top_hash ) {
  ag_hash_stakes_t const * tbl = fd_ptr_if( nf, &self->votes.notar_fallback_hash_stake, &self->votes.notar_hash_stake );
  ag_hash_stake_t buf[ HS_SPILL_CHUNK ];
  for( ulong rec0=0UL; rec0<tbl->spill_hwm; rec0+=HS_SPILL_CHUNK ) {
    ulong cnt = fd_ulong_min( HS_SPILL_CHUNK, tbl->spill_hwm-rec0 );
    spill_io( fd, 0, buf, cnt*sizeof(ag_hash_stake_t), hs_off( self, nf, rec0 ) );
    for( ulong i=0UL; i<cnt; i++ ) {
      if( buf[i].stake==ULONG_MAX ) continue;
      if( hash && !memcmp( buf[i].hash, hash, sizeof(ag_block_hash_t) ) ) return AG_HASH_STAKE_INLINE_MAX+rec0+i;
      if( top && buf[i].stake>*top ) { *top = buf[i].stake; memcpy( top_hash, buf[i].hash, sizeof(ag_block_hash_t) ); }
    }
  }
  return ULONG_MAX;
}

static ulong
hash_stake_query( ag_slot_state_t const * self,
                  int                     fd,
                  int                     nf,
                  uchar const *           hash ) {
  ag_hash_stakes_t const * tbl = fd_ptr_if( nf, &self->votes.notar_fallback_hash_stake, &self->votes.notar_hash_stake );
  for( uint m=tbl->used; m; m=fd_uint_pop_lsb( m ) ) {
    ulong i = (ulong)fd_uint_find_lsb( m );
    if( FD_LIKELY( !memcmp( tbl->ele[i].hash, hash, sizeof(ag_block_hash_t) ) ) ) return i;
  }
  if( FD_LIKELY( !tbl->spill_cnt ) ) return ULONG_MAX;
  return hash_stake_spill_scan( self, fd, nf, hash, NULL, NULL );
}

/* Returns the stake of id and copies its hash into hash if non-NULL. */

static ulong
hash_stake_get( ag_slot_state_t const * self,
                int                     fd,
                int                     nf,
                ulong                   id,
                uchar *                 hash ) {
  ag_hash_stakes_t const * tbl = fd_ptr_if( nf, &self->votes.notar_fallback_hash_stake, &self->votes.notar_hash_stake );
  if( FD_LIKELY( id<AG_HASH_STAKE_INLINE_MAX ) ) {
    if( hash ) memcpy( hash, tbl->ele[ id ].hash, sizeof(ag_block_hash_t) );
    return tbl->ele[ id ].stake;
  }
  ag_hash_stake_t rec;
  spill_io( fd, 0, &rec, sizeof(rec), hs_off( self, nf, id-AG_HASH_STAKE_INLINE_MAX ) );
  if( hash ) memcpy( hash, rec.hash, sizeof(ag_block_hash_t) );
  return rec.stake;
}

static void
hash_stake_set( ag_slot_state_t * self,
                int               fd,
                int               nf,
                ulong             id,
                ulong             stake ) {
  ag_hash_stakes_t * tbl = fd_ptr_if( nf, &self->votes.notar_fallback_hash_stake, &self->votes.notar_hash_stake );
  if( FD_LIKELY( id<AG_HASH_STAKE_INLINE_MAX ) ) { tbl->ele[ id ].stake = stake; return; }
  spill_io( fd, 1, &stake, sizeof(ulong), hs_off( self, nf, id-AG_HASH_STAKE_INLINE_MAX )+offsetof( ag_hash_stake_t, stake ) );
}

static int
hash_stake_eq( ag_slot_state_t const * self,
               int                     fd,
               int                     nf,
               ulong                   id,
               uchar const *           hash ) {
  ag_hash_stakes_t const * tbl = fd_ptr_if( nf, &self->votes.notar_fallback_hash_stake, &self->votes.notar_hash_stake );
  if( FD_LIKELY( id<AG_HASH_STAKE_INLINE_MAX ) ) return !memcmp( tbl->ele[ id ].hash, hash, sizeof(ag_block_hash_t) );
  ag_block_hash_t rec;
  spill_io( fd, 0, rec, sizeof(ag_block_hash_t), hs_off( self, nf, id-AG_HASH_STAKE_INLINE_MAX ) );
  return !memcmp( rec, hash, sizeof(ag_block_hash_t) );
}

/* Inserts absent hash with zero stake. */

static ulong
hash_stake_insert( ag_slot_state_t * self,
                   int               fd,
                   int               nf,
                   uchar const *     hash ) {
  ag_hash_stakes_t * tbl = fd_ptr_if( nf, &self->votes.notar_fallback_hash_stake, &self->votes.notar_hash_stake );
  if( FD_LIKELY( tbl->used!=UINT_MAX ) ) {
    ulong i = (ulong)fd_uint_find_lsb( ~tbl->used );
    tbl->used |= 1U<<i;
    memcpy( tbl->ele[ i ].hash, hash, sizeof(ag_block_hash_t) );
    tbl->ele[ i ].stake = 0UL;
    fd_memset( &tbl->sig_sum[ i ], 0, sizeof(fd_bls_sig_t) );
    return i;
  }
  ulong rec = tbl->spill_hwm;
  if( FD_UNLIKELY( tbl->spill_cnt<tbl->spill_hwm ) ) { /* reuse a free record */
    ag_hash_stake_t buf[ HS_SPILL_CHUNK ];
    for( ulong rec0=0UL; rec==tbl->spill_hwm; rec0+=HS_SPILL_CHUNK ) {
      FD_TEST( rec0<tbl->spill_hwm );
      ulong cnt = fd_ulong_min( HS_SPILL_CHUNK, tbl->spill_hwm-rec0 );
      spill_io( fd, 0, buf, cnt*sizeof(ag_hash_stake_t), hs_off( self, nf, rec0 ) );
      for( ulong i=0UL; i<cnt; i++ ) if( buf[i].stake==ULONG_MAX ) { rec = rec0+i; break; }
    }
  } else {
    FD_TEST( rec<fd_ulong_if( nf, AG_NF_SPILL_MAX, AG_NOTAR_SPILL_MAX ) );
    tbl->spill_hwm++;
  }
  ag_hash_stake_t ele = { .stake = 0UL };
  memcpy( ele.hash, hash, sizeof(ag_block_hash_t) );
  spill_io( fd, 1, &ele, sizeof(ele), hs_off( self, nf, rec ) );
  tbl->spill_cnt++;
  return AG_HASH_STAKE_INLINE_MAX+rec;
}

static void
hash_stake_remove( ag_slot_state_t * self,
                   int               fd,
                   int               nf,
                   ulong             id ) {
  ag_hash_stakes_t * tbl = fd_ptr_if( nf, &self->votes.notar_fallback_hash_stake, &self->votes.notar_hash_stake );
  if( FD_LIKELY( id<AG_HASH_STAKE_INLINE_MAX ) ) { tbl->used &= ~(1U<<id); return; }
  hash_stake_set( self, fd, nf, id, ULONG_MAX );
  tbl->spill_cnt--;
}

/* Returns the first live id >= id, copying its hash into hash, or
   ULONG_MAX. */

static ulong
hash_stake_next( ag_slot_state_t const * self,
                 int                     fd,
                 int                     nf,
                 ulong                   id,
                 uchar *                 hash ) {
  ag_hash_stakes_t const * tbl = fd_ptr_if( nf, &self->votes.notar_fallback_hash_stake, &self->votes.notar_hash_stake );
  if( id<AG_HASH_STAKE_INLINE_MAX ) {
    uint m = tbl->used & ~((1U<<id)-1U);
    if( FD_LIKELY( m ) ) { id = (ulong)fd_uint_find_lsb( m ); memcpy( hash, tbl->ele[ id ].hash, sizeof(ag_block_hash_t) ); return id; }
    id = AG_HASH_STAKE_INLINE_MAX;
  }
  if( FD_LIKELY( !tbl->spill_cnt ) ) return ULONG_MAX;
  ag_hash_stake_t buf[ HS_SPILL_CHUNK ];
  for( ulong rec0=id-AG_HASH_STAKE_INLINE_MAX; rec0<tbl->spill_hwm; rec0+=HS_SPILL_CHUNK ) {
    ulong cnt = fd_ulong_min( HS_SPILL_CHUNK, tbl->spill_hwm-rec0 );
    spill_io( fd, 0, buf, cnt*sizeof(ag_hash_stake_t), hs_off( self, nf, rec0 ) );
    for( ulong i=0UL; i<cnt; i++ ) {
      if( buf[i].stake==ULONG_MAX ) continue;
      memcpy( hash, buf[i].hash, sizeof(ag_block_hash_t) );
      return AG_HASH_STAKE_INLINE_MAX+rec0+i;
    }
  }
  return ULONG_MAX;
}

/* Vote sigs, see AG_SLOT_SIG_CNT, compressed.  [rank,rank+cnt) stays
   in one page. */

static inline ulong
sig_off( ag_slot_state_t const * self,
         ulong                   ks,
         ulong                   rank ) {
  return self->spill_off + AG_HS_SPILL_SZ + (ks*AG_VAT_MAX+rank)*FD_BLS_SIG_COMPRESSED_SZ;
}

static void
sig_write( ag_slot_state_t *  self,
           ag_slot_states_t * states,
           ulong              ks,
           ulong              rank,
           uchar const *      sig ) {
  uint * pg = &self->sig_pg[ ks ][ rank/AG_SIG_PG_RANKS ];
  if( FD_UNLIKELY( !*pg ) ) *pg = FD_LIKELY( states->sig_pg_free_cnt ) ? states->sig_pg_free[ --states->sig_pg_free_cnt ]+1U : AG_SIG_PG_DISK;
  if( FD_LIKELY( *pg!=AG_SIG_PG_DISK ) ) fd_memcpy( states->sig_pg + ((*pg-1UL)*AG_SIG_PG_RANKS+rank%AG_SIG_PG_RANKS)*FD_BLS_SIG_COMPRESSED_SZ, sig, FD_BLS_SIG_COMPRESSED_SZ );
  else                                   spill_io( states->spill_fd, 1, (void *)sig, FD_BLS_SIG_COMPRESSED_SZ, sig_off( self, ks, rank ) );
}

static void
sig_read( ag_slot_state_t const *  self,
          ag_slot_states_t const * states,
          ulong                    ks,
          ulong                    rank,
          ulong                    cnt,
          uchar *                  out ) {
  uint pg = self->sig_pg[ ks ][ rank/AG_SIG_PG_RANKS ];
  if( FD_LIKELY( pg!=AG_SIG_PG_DISK ) ) fd_memcpy( out, states->sig_pg + ((pg-1UL)*AG_SIG_PG_RANKS+rank%AG_SIG_PG_RANKS)*FD_BLS_SIG_COMPRESSED_SZ, cnt*FD_BLS_SIG_COMPRESSED_SZ );
  else                                  spill_io( states->spill_fd, 0, out, cnt*FD_BLS_SIG_COMPRESSED_SZ, sig_off( self, ks, rank ) );
}

static inline ulong
sig_ks( uint  kind,
        ulong j ) {
  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:
  case AG_VOTE_KIND_SKIP:           return 0UL;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return 1UL+j;
  case AG_VOTE_KIND_SKIP_FALLBACK:
  case AG_VOTE_KIND_FINAL:          return 4UL;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Aggregate of the notar (nf: notar fallback) votes for id.  Inline
   ids use their running sig sum. */

static void
hash_agg( ag_slot_state_t const *  self,
          ag_slot_states_t const * states,
          int                      nf,
          ulong                    id,
          fd_bls_agg_t *           agg ) {
  ag_epoch_info_t const * epoch_info = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ag_slot_votes_t const * votes      = &self->votes;

  fd_bls_set_t set[ fd_bls_set_word_cnt ];
  fd_bls_set_null( set );
  if( FD_LIKELY( !nf ) ) {
    for( ulong rank = fd_bls_set_const_iter_init( votes->notar_set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( votes->notar_set, rank ) ) {
      if( FD_LIKELY( votes->notar_hash_stake_idx[ rank ]==id ) ) fd_bls_set_insert( set, rank );
    }
  } else {
    for( ulong rank=0UL; rank<epoch_info->validator_cnt; rank++ ) {
      for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_LIKELY( votes->notar_fallback_hash_stake_idx[ rank ][ j ]==id ) ) fd_bls_set_insert( set, rank );
      }
    }
  }

  fd_bls_agg_null( agg );
  if( FD_UNLIKELY( id>=AG_HASH_STAKE_INLINE_MAX ) ) {
    for( ulong rank = fd_bls_set_const_iter_init( set );
                     !fd_bls_set_const_iter_done( rank );
               rank = fd_bls_set_const_iter_next( set, rank ) ) {
      ulong j = 0UL;
      while( nf && votes->notar_fallback_hash_stake_idx[ rank ][ j ]!=id ) j++;
      fd_bls_sig_t sig;
      ag_slot_state_vote_sig( self, states, nf ? AG_VOTE_KIND_NOTAR_FALLBACK : AG_VOTE_KIND_NOTAR, rank, j, &sig );
      fd_bls_sig_add( &agg->sig, &agg->sig, &sig );
    }
  }
  fd_bls_set_copy( agg->set, set );
  fd_bls_pub_sum( &agg->pub, epoch_info->pubkeys, set );
  if( FD_LIKELY( id<AG_HASH_STAKE_INLINE_MAX ) ) agg->sig = ( nf ? &votes->notar_fallback_hash_stake : &votes->notar_hash_stake )->sig_sum[ id ];
}

static int
verify_subtract_votes( ag_slot_state_t *     self,
                       ag_slot_states_t *    states,
                       uint                  kind,
                       ag_block_hash_t const block_hash,
                       fd_bls_agg_t *        agg,
                       fd_bls_set_t *        bad ) {
  ag_epoch_info_t const * epoch_info = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ag_slot_votes_t *       votes      = &self->votes;
  int                     fd         = states->spill_fd;
  int                     nf         = kind==AG_VOTE_KIND_NOTAR_FALLBACK;
  ag_hash_stakes_t *      tbl        = nf ? &votes->notar_fallback_hash_stake : &votes->notar_hash_stake;
  ulong                   id         = ULONG_MAX;

  if( kind==AG_VOTE_KIND_NOTAR || nf ) {
    id = hash_stake_query( self, fd, nf, block_hash );
    FD_CHECK_CRIT( id!=ULONG_MAX, "invariant violation" );
    hash_agg( self, states, nf, id, agg );
  }

  uchar msg[ AG_VOTE_SIGNING_SER_MAX ];
  ulong msg_sz = ag_vote_signing_ser( kind, self->slot, block_hash, self->shred_version, msg );
  states->bls_verify_cnt++;
  int   err    = ag_slot_state_agg_verify( self, states, kind, block_hash, msg, msg_sz, agg, bad );
  if( FD_LIKELY( !err && fd_bls_set_is_null( bad ) ) ) return 1;
  if( FD_UNLIKELY( id<AG_HASH_STAKE_INLINE_MAX ) ) tbl->sig_sum[ id ] = agg->sig; /* bad sigs subtracted */

  for( ulong rank = fd_bls_set_const_iter_init( bad );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( bad, rank ) ) {
    ulong stake = ag_epoch_info_validator( epoch_info, rank )->stake;
    switch( kind ) {
    case AG_VOTE_KIND_NOTAR:
      hash_stake_set( self, fd, 0, id, hash_stake_get( self, fd, 0, id, NULL )-stake );
      votes->notar_or_skip_stake -= stake;
      fd_bls_set_remove( votes->notar_set, rank );
      break;
    case AG_VOTE_KIND_NOTAR_FALLBACK: {
      ulong j;
      for( j=0UL; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
        if( FD_UNLIKELY( votes->notar_fallback_hash_stake_idx[ rank ][ j ]==id ) ) break;
      }
      FD_CHECK_CRIT( j<votes->notar_fallback_sig_cnt[ rank ], "invariant violation" );
      hash_stake_set( self, fd, 1, id, hash_stake_get( self, fd, 1, id, NULL )-stake );
      ulong last = --votes->notar_fallback_sig_cnt[ rank ];
      if( FD_LIKELY( j!=last ) ) {
        uchar sig[ FD_BLS_SIG_COMPRESSED_SZ ];
        sig_read ( self, states, sig_ks( kind, last ), rank, 1UL, sig );
        sig_write( self, states, sig_ks( kind, j    ), rank, sig );
        votes->notar_fallback_hash_stake_idx[ rank ][ j ] = votes->notar_fallback_hash_stake_idx[ rank ][ last ];
      }
      break;
    }
    case AG_VOTE_KIND_SKIP:
      votes->skip_stake -= stake;
      votes->notar_or_skip_stake -= stake;
      break;
    case AG_VOTE_KIND_SKIP_FALLBACK:
      votes->skip_fallback_stake -= stake;
      break;
    case AG_VOTE_KIND_FINAL:
      votes->finalize_stake -= stake;
      break;
    default:
      FD_LOG_CRIT(( "unreachable" ));
    }
  }

  if( FD_UNLIKELY( id!=ULONG_MAX && fd_bls_set_is_null( agg->set ) ) ) hash_stake_remove( self, fd, nf, id );
  if( FD_UNLIKELY( kind==AG_VOTE_KIND_NOTAR ) ) {
    ag_hash_stakes_t const * tbl = &votes->notar_hash_stake;
    votes->top_notar_stake = 0UL;
    for( uint m=tbl->used; m; m=fd_uint_pop_lsb( m ) ) {
      ulong i = (ulong)fd_uint_find_lsb( m );
      if( FD_LIKELY( tbl->ele[i].stake>votes->top_notar_stake ) ) {
        votes->top_notar_stake = tbl->ele[i].stake;
        memcpy( votes->top_notar_hash, tbl->ele[i].hash, sizeof(ag_block_hash_t) );
      }
    }
    if( FD_UNLIKELY( tbl->spill_cnt ) ) hash_stake_spill_scan( self, fd, 0, NULL, &votes->top_notar_stake, votes->top_notar_hash );
  }
  return !err;
}

static int
check_safe_to_notar( ag_slot_state_t *     self,
                     ag_slot_states_t *    states,
                     ag_block_hash_t const block_hash,
                     fd_bls_set_t *        bad ) {
  ag_epoch_info_t const * epoch_info            = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ag_slot_votes_t *       votes                 = &self->votes;
  int                     fd                    = states->spill_fd;
  ulong                   notar                 = hash_stake_query( self, fd, 0, block_hash );
  ulong                   notar_stake           = notar!=ULONG_MAX ? hash_stake_get( self, fd, 0, notar, NULL ) : 0UL;
  ulong                   skip_stake            = votes->skip_stake;

  if( FD_UNLIKELY( !ag_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) ) ) {
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }
  if( FD_UNLIKELY( !ag_epoch_info_is_weak_quorum( epoch_info, notar_stake ) && !ag_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  ag_parent_status_t const * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( self->parents[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) { parent = &self->parents[i]; break; }
  }
  if( FD_UNLIKELY( !parent ) ) return AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK;

  ulong own = self->own_rank;

  int safe_to_notar = 0;
  if( FD_LIKELY( own!=USHORT_MAX ) ) { /* must be staked */
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, own ) ) ) safe_to_notar = 1;
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, own ) ) ) {
      if( FD_UNLIKELY( votes->notar_hash_stake_idx[ own ]==notar ) ) return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
      safe_to_notar = 1;
    }
  }
  if( FD_UNLIKELY( !safe_to_notar ) ) {
    block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
    return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
  }

  if( FD_LIKELY( !block_hash_set_contains( &self->verified_safe_to_notar, block_hash ) ) ) {
    fd_bls_agg_t notar_agg[1];
    fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
      fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
      verify_subtract_votes( self, states, AG_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
      fd_bls_set_union( bad, bad, bad_skip );
    }
    notar       = hash_stake_query( self, fd, 0, block_hash );
    notar_stake = notar!=ULONG_MAX ? hash_stake_get( self, fd, 0, notar, NULL ) : 0UL;
    skip_stake  = votes->skip_stake;
    if( FD_UNLIKELY( !ag_epoch_info_is_weakest_quorum( epoch_info, notar_stake ) || ( !ag_epoch_info_is_weak_quorum( epoch_info, notar_stake ) && !ag_epoch_info_is_quorum( epoch_info, notar_stake + skip_stake ) ) ) ) {
      block_hash_set_insert( &self->pending_safe_to_notar, block_hash );
      return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;
    }
    block_hash_set_insert( &self->verified_safe_to_notar, block_hash );
  }
  if( FD_UNLIKELY( parent->kind!=AG_PARENT_STATUS_CERTIFIED ) ) return AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES;

  block_hash_set_remove( &self->pending_safe_to_notar, block_hash );
  block_hash_set_insert( &self->sent_safe_to_notar,    block_hash );
  return AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR;
}

static int
check_safe_to_skip( ag_slot_state_t *  self,
                    ag_slot_states_t * states,
                    fd_bls_set_t *     bad ) {
  ag_epoch_info_t const * epoch_info = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ag_slot_votes_t *       votes      = &self->votes;
  if( FD_LIKELY( self->sent_safe_to_skip
                 || !ag_epoch_info_is_weak_quorum( epoch_info, votes->notar_or_skip_stake - votes->top_notar_stake )
                 || self->own_rank==USHORT_MAX /* must be staked */ ) ) return 0;
  if( FD_LIKELY( !fd_bls_set_test( votes->notar_set, self->own_rank ) ) ) return 0;

  if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
    fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, AG_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
    fd_bls_set_union( bad, bad, bad_skip );
  }
  if( FD_LIKELY( ag_epoch_info_is_weak_quorum( epoch_info, votes->skip_stake ) ) ) {
    self->sent_safe_to_skip = 1;
    return 1;
  }

  ag_block_hash_t hash;
  for( ulong id = hash_stake_next( self, states->spill_fd, 0, 0UL, hash );
             id!=ULONG_MAX;
             id = hash_stake_next( self, states->spill_fd, 0, id+1UL, hash ) ) { /* verify only removes id */
    fd_bls_agg_t notar_agg[1];
    fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
    verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR, hash, notar_agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
  }
  if( FD_UNLIKELY( !ag_epoch_info_is_weak_quorum( epoch_info, votes->notar_or_skip_stake - votes->top_notar_stake ) || !fd_bls_set_test( votes->notar_set, self->own_rank ) ) ) return 0;
  self->sent_safe_to_skip = 1;
  return 1;
}

static int
count_notar_stake( ag_slot_state_t *       self,
                   ag_slot_states_t *      states,
                   ag_vote_notar_t const * vote,
                   ulong                   stake,
                   ag_cert_t *             out_cert_events,
                   ulong *                 out_cert_event_cnt,
                   ag_block_id_t *         out_safe_to_notar,
                   ulong *                 out_safe_to_notar_cnt,
                   ulong *                 out_safe_to_skip,
                   ulong *                 out_safe_to_skip_cnt,
                   ag_block_id_t *         out_repair_events,
                   ulong *                 out_repair_event_cnt,
                   fd_bls_set_t *          bad ) {
  ag_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  uchar const *           block_hash    = vote->block_hash;
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;

  ag_slot_votes_t * votes = &self->votes;
  int               fd    = states->spill_fd;
  ulong             notar = hash_stake_query( self, fd, 0, block_hash );
  if( FD_UNLIKELY( notar==ULONG_MAX ) ) notar = hash_stake_insert( self, fd, 0, block_hash );
  votes->notar_hash_stake_idx[ rank ] = (ushort)notar;
  if( FD_LIKELY( notar<AG_HASH_STAKE_INLINE_MAX ) ) fd_bls_sig_add( &votes->notar_hash_stake.sig_sum[ notar ], &votes->notar_hash_stake.sig_sum[ notar ], &vote->sig );

  ulong notar_stake           = hash_stake_get( self, fd, 0, notar, NULL )+stake;
  hash_stake_set( self, fd, 0, notar, notar_stake );
  votes->notar_or_skip_stake += stake;
  if( FD_LIKELY( notar_stake>votes->top_notar_stake ) ) {
    votes->top_notar_stake = notar_stake;
    memcpy( votes->top_notar_hash, block_hash, sizeof(ag_block_hash_t) );
  }

  if( FD_UNLIKELY( !block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) {
    switch( check_safe_to_notar( self, states, block_hash, bad ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = ag_block_id( slot, block_hash );
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = ag_block_id( slot, block_hash );
      break;
    }
    default: break;
    }
  }
  if( FD_UNLIKELY( check_safe_to_skip( self, states, bad ) ) ) {
    out_safe_to_skip[ (*out_safe_to_skip_cnt)++ ] = slot;
  }
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) ) ) {
    notar = hash_stake_query( self, fd, 0, block_hash );
    if( FD_UNLIKELY( notar==ULONG_MAX || !fd_bls_set_test( votes->notar_set, rank ) ) ) return 0;
    notar_stake = hash_stake_get( self, fd, 0, notar, NULL );
  }

  ulong nf       = hash_stake_query( self, fd, 1, block_hash );
  ulong nf_stake = nf!=ULONG_MAX ? hash_stake_get( self, fd, 1, nf, NULL ) : 0UL;

  int          notar_verified          = 0;
  int          notar_fallback_verified = 0;
  int          newly_notar             = 0;
  fd_bls_agg_t notar_agg[1];
  fd_bls_agg_t nf_agg[1];

  if( FD_UNLIKELY( ( ag_epoch_info_is_quorum       ( epoch_info, nf_stake + notar_stake ) && !ag_slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ||
                   ( ag_epoch_info_is_quorum       ( epoch_info, notar_stake            ) && self->certs.notar.slot==ULONG_MAX                                ) ||
                   ( ag_epoch_info_is_strong_quorum( epoch_info, notar_stake            ) && self->certs.fast_finalize.slot==ULONG_MAX                        ) ) ) {
    fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
    notar_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
    fd_bls_set_union( bad, bad, bad_notar );
    if( FD_UNLIKELY( fd_bls_set_test( bad_notar, rank ) ) ) return 0;

    notar_stake = hash_stake_get( self, fd, 0, notar, NULL );
    newly_notar = notar_verified && ag_epoch_info_is_quorum( epoch_info, notar_stake ) && self->certs.notar.slot==ULONG_MAX;
    if( FD_LIKELY( nf!=ULONG_MAX && !newly_notar && !ag_slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
      fd_bls_set_t bad_nf[ fd_bls_set_word_cnt ];
      notar_fallback_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR_FALLBACK, block_hash, nf_agg, bad_nf );
      fd_bls_set_union( bad, bad, bad_nf );
    }
  }

  if( FD_UNLIKELY( !newly_notar && !ag_slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
    ag_cert_notar_fallback_t cert = { .slot = slot, .shred_version = shred_version }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );

    if( FD_LIKELY( notar_verified ) ) {
      cert.agg_notar = *notar_agg;
      cert.stake += hash_stake_get( self, fd, 0, notar, NULL );
    }
    if( FD_LIKELY( notar_fallback_verified ) ) {
      cert.agg_notar_fallback = *nf_agg;
      cert.stake += hash_stake_get( self, fd, 1, nf, NULL );
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[( *out_cert_event_cnt )++] = ( ag_cert_t ){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
    }
  }

  if( FD_UNLIKELY( newly_notar ) ) {
    ag_cert_notar_t cert = { .slot = slot, .shred_version = shred_version, .stake = notar_stake, .agg = *notar_agg }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
    out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR, .notar = cert };
  }

  if( FD_UNLIKELY( notar_verified && ag_epoch_info_is_strong_quorum( epoch_info, notar_stake ) && self->certs.fast_finalize.slot==ULONG_MAX ) ) {
    ag_cert_fast_final_t cert = { .slot = slot, .shred_version = shred_version, .stake = notar_stake, .agg = *notar_agg }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );
    out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = cert };
  }

  return 1;
}

static int
count_notar_fallback_stake( ag_slot_state_t *                self,
                            ag_slot_states_t *               states,
                            ag_vote_notar_fallback_t const * vote,
                            ulong                            stake,
                            ag_cert_t *                      out_cert_events,
                            ulong *                          out_cert_event_cnt,
                            fd_bls_set_t *                   bad ) {
  ag_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  uchar const *           block_hash    = vote->block_hash;
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;

  ag_slot_votes_t * votes = &self->votes;
  int               fd    = states->spill_fd;
  ulong             nf    = hash_stake_query( self, fd, 1, block_hash );
  if( FD_UNLIKELY( nf==ULONG_MAX ) ) nf = hash_stake_insert( self, fd, 1, block_hash );
  votes->notar_fallback_hash_stake_idx[ rank ][ votes->notar_fallback_sig_cnt[ rank ]-1UL ] = (ushort)nf;
  if( FD_LIKELY( nf<AG_HASH_STAKE_INLINE_MAX ) ) fd_bls_sig_add( &votes->notar_fallback_hash_stake.sig_sum[ nf ], &votes->notar_fallback_hash_stake.sig_sum[ nf ], &vote->sig );

  ulong nf_stake    = hash_stake_get( self, fd, 1, nf, NULL )+stake;
  hash_stake_set( self, fd, 1, nf, nf_stake );
  ulong notar       = hash_stake_query( self, fd, 0, block_hash );
  ulong notar_stake = notar!=ULONG_MAX ? hash_stake_get( self, fd, 0, notar, NULL ) : 0UL;
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, nf_stake + notar_stake ) && !ag_slot_state_is_notar_fallback_or_stronger( self, block_hash ) ) ) {
    fd_bls_agg_t nf_agg[1];
    fd_bls_agg_t notar_agg[1];
    fd_bls_set_t bad_nf[ fd_bls_set_word_cnt ];
    int nf_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR_FALLBACK, block_hash, nf_agg, bad_nf );
    fd_bls_set_union( bad, bad, bad_nf );
    if( FD_UNLIKELY( fd_bls_set_test( bad_nf, rank ) ) ) return 0;
    int notar_verified = 0;
    if( FD_LIKELY( notar!=ULONG_MAX ) ) {
      fd_bls_set_t bad_notar[ fd_bls_set_word_cnt ];
      notar_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_NOTAR, block_hash, notar_agg, bad_notar );
      fd_bls_set_union( bad, bad, bad_notar );
    }

    ag_cert_notar_fallback_t cert = { .slot = slot, .shred_version = shred_version }; memcpy( cert.block_hash, block_hash, sizeof(ag_block_hash_t) );

    if( FD_LIKELY( notar_verified ) ) {
      cert.agg_notar = *notar_agg;
      cert.stake += hash_stake_get( self, fd, 0, notar, NULL );
    }
    if( FD_LIKELY( nf_verified ) ) {
      cert.agg_notar_fallback = *nf_agg;
      cert.stake += hash_stake_get( self, fd, 1, nf, NULL );
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR_FALLBACK, .notar_fallback = cert };
    }
  }

  return 1;
}

static int
count_skip_stake( ag_slot_state_t *  self,
                  ag_slot_states_t * states,
                  ag_vote_t const *  vote,
                  ulong              stake,
                  ag_cert_t *        out_cert_events,
                  ulong *            out_cert_event_cnt,
                  ag_block_id_t *    out_safe_to_notar,
                  ulong *            out_safe_to_notar_cnt,
                  ulong *            out_safe_to_skip,
                  ulong *            out_safe_to_skip_cnt,
                  ag_block_id_t *    out_repair_events,
                  ulong *            out_repair_event_cnt,
                  fd_bls_set_t *     bad ) {
  ag_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  int                     fallback      = vote->kind==AG_VOTE_KIND_SKIP_FALLBACK;
  ulong                   slot          = ag_vote_slot( vote );
  ulong                   rank          = ag_vote_rank( vote );
  ushort                  shred_version = ag_vote_shred_version( vote );
  fd_bls_sig_t const *    sig           = ag_vote_sig( vote );
  fd_bls_pub_t const *    pub           = ag_epoch_info_pubkey( epoch_info, rank );

  ag_slot_votes_t * votes = &self->votes;
  if( FD_UNLIKELY( fallback ) ) { votes->skip_fallback_stake += stake; fd_bls_pub_add( &votes->skip_fallback_agg.pub, &votes->skip_fallback_agg.pub, pub ); fd_bls_sig_add( &votes->skip_fallback_agg.sig, &votes->skip_fallback_agg.sig, sig ); fd_bls_set_insert( votes->skip_fallback_agg.set, rank ); }
  else                          { votes->skip_stake          += stake; fd_bls_pub_add( &votes->skip_agg.pub,          &votes->skip_agg.pub,          pub ); fd_bls_sig_add( &votes->skip_agg.sig,          &votes->skip_agg.sig,          sig ); fd_bls_set_insert( votes->skip_agg.set,          rank ); }

  ag_block_hash_set_t pending = self->pending_safe_to_notar;
  for( ulong i=0UL; i<pending.cnt; i++ ) {
    if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) ) continue;
    switch( check_safe_to_notar( self, states, pending.hash[i], bad ) ) {
    case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:
      out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = ag_block_id( slot, pending.hash[i] );
      break;
    case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
      ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) ) break;
      if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = ag_block_id( slot, pending.hash[i] );
      break;
    }
    default:
      break;
    }
  }

  if( FD_UNLIKELY( check_safe_to_skip( self, states, bad ) ) ) {
    out_safe_to_skip[ (*out_safe_to_skip_cnt)++ ] = slot;
  }
  if( FD_UNLIKELY( !fd_bls_set_is_null( bad ) && !fd_bls_set_test( fallback ? votes->skip_fallback_agg.set : votes->skip_agg.set, rank ) ) ) return 0;

  ulong total_skip_stake = votes->skip_stake + votes->skip_fallback_stake;

  int skip_verified          = 0;
  int skip_fallback_verified = 0;
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, total_skip_stake ) && self->certs.skip.slot==ULONG_MAX ) ) {
    if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_agg.set ) ) ) {
      fd_bls_set_t bad_skip[ fd_bls_set_word_cnt ];
      skip_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_SKIP, NULL, &votes->skip_agg, bad_skip );
      fd_bls_set_union( bad, bad, bad_skip );
    }
    if( FD_LIKELY( !fd_bls_set_is_null( votes->skip_fallback_agg.set ) ) ) {
      fd_bls_set_t bad_sf[ fd_bls_set_word_cnt ];
      skip_fallback_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_SKIP_FALLBACK, NULL, &votes->skip_fallback_agg, bad_sf );
      fd_bls_set_union( bad, bad, bad_sf );
    }
    if( FD_UNLIKELY( !fd_bls_set_test( fallback ? votes->skip_fallback_agg.set : votes->skip_agg.set, rank ) ) ) return 0;

    ag_cert_skip_t cert = { .slot = slot, .shred_version = shred_version };

    if( FD_LIKELY( skip_verified ) ) {
      cert.agg_skip = votes->skip_agg;
      cert.stake += votes->skip_stake;
    }
    if( FD_LIKELY( skip_fallback_verified ) ) {
      cert.agg_skip_fallback = votes->skip_fallback_agg;
      cert.stake += votes->skip_fallback_stake;
    }
    if( FD_LIKELY( ag_epoch_info_is_quorum( epoch_info, cert.stake ) ) ) {
      out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_SKIP, .skip = cert };
    }
  }

  return 1;
}

static int
count_finalize_stake( ag_slot_state_t *       self,
                      ag_slot_states_t *      states,
                      ag_vote_final_t const * vote,
                      ulong                   stake,
                      ag_cert_t *             out_cert_events,
                      ulong *                 out_cert_event_cnt,
                      fd_bls_set_t *          bad ) {
  ag_epoch_info_t const * epoch_info    = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  ulong                   slot          = vote->slot;
  ulong                   rank          = vote->rank;
  ushort                  shred_version = vote->shred_version;
  fd_bls_sig_t const *    sig           = &vote->sig;
  fd_bls_pub_t const *    pub           = ag_epoch_info_pubkey( epoch_info, rank );

  ag_slot_votes_t * votes = &self->votes;
  votes->finalize_stake += stake;
  fd_bls_pub_add( &votes->finalize_agg.pub, &votes->finalize_agg.pub, pub );
  fd_bls_sig_add( &votes->finalize_agg.sig, &votes->finalize_agg.sig, sig );
  fd_bls_set_insert( votes->finalize_agg.set, rank );
  if( FD_UNLIKELY( ag_epoch_info_is_quorum( epoch_info, votes->finalize_stake ) && self->certs.finalize.slot==ULONG_MAX ) ) {
    fd_bls_set_t bad_final[ fd_bls_set_word_cnt ];
    int finalize_verified = verify_subtract_votes( self, states, AG_VOTE_KIND_FINAL, NULL, &votes->finalize_agg, bad_final );
    fd_bls_set_union( bad, bad, bad_final );
    if( FD_UNLIKELY( fd_bls_set_test( bad_final, rank ) ) ) return 0;
    if( FD_UNLIKELY( !finalize_verified || !ag_epoch_info_is_quorum( epoch_info, votes->finalize_stake ) ) ) return 1;
    ag_cert_final_t cert = { .slot = slot, .shred_version = shred_version, .stake = votes->finalize_stake, .agg = votes->finalize_agg };
    out_cert_events[ (*out_cert_event_cnt)++ ] = (ag_cert_t){ .kind = AG_CERT_KIND_FINAL, .final = cert };
  }

  return 1;
}

void
ag_slot_state_null( ag_slot_state_t *  self,
                    ag_slot_states_t * states ) {
  ag_slot_votes_t * votes = &self->votes;
  for( ulong ks=0UL; ks<AG_SLOT_VOTE_SIG_MAX; ks++ ) {
    for( ulong w=0UL; w<fd_bls_set_word_cnt; w++ ) {
      uint pg = self->sig_pg[ ks ][ w ];
      if( pg && pg!=AG_SIG_PG_DISK ) states->sig_pg_free[ states->sig_pg_free_cnt++ ] = pg-1U;
    }
  }
  fd_memset( self->sig_pg, 0, sizeof(self->sig_pg) );
  votes->notar_hash_stake          = (ag_hash_stakes_t){ .used = 0U }; /* spill_hwm 0 drops the spill region, no I/O */
  votes->notar_fallback_hash_stake = (ag_hash_stakes_t){ .used = 0U };
  fd_bls_set_null( votes->notar_set );
  fd_memset( votes->notar_fallback_sig_cnt, 0, sizeof(votes->notar_fallback_sig_cnt) );
  votes->skip_stake = 0UL;
  fd_bls_agg_null( &votes->skip_agg );
  votes->skip_fallback_stake = 0UL;
  fd_bls_agg_null( &votes->skip_fallback_agg );
  votes->finalize_stake = 0UL;
  fd_bls_agg_null( &votes->finalize_agg );
  votes->notar_or_skip_stake = 0UL;
  votes->top_notar_stake     = 0UL;
  fd_memset( votes->top_notar_hash, 0, sizeof(ag_block_hash_t) );

  self->certs.notar.slot         = ULONG_MAX;
  self->certs.notar_fallback_cnt = 0UL;
  self->certs.skip.slot          = ULONG_MAX;
  self->certs.fast_finalize.slot = ULONG_MAX;
  self->certs.finalize.slot      = ULONG_MAX;

  self->parents_cnt                = 0UL;
  self->pending_safe_to_notar.cnt  = 0UL;
  self->verified_safe_to_notar.cnt = 0UL;
  self->sent_safe_to_notar.cnt     = 0UL;
  self->sent_safe_to_skip          = 0;
}

void
ag_slot_state_set_own_rank( ag_slot_state_t * self,
                            ulong             own_rank ) {
  self->own_rank = own_rank;
}

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * self,
                                 ag_block_hash_t const   block_hash ) {
  ag_slot_certs_t const * c = &self->certs;
  for( ulong i=0UL; i<c->notar_fallback_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( c->notar_fallback[i].block_hash, block_hash, sizeof(ag_block_hash_t) ) ) ) return 1;
  }
  return 0;
}

FD_FN_PURE int
ag_slot_state_is_notar_fallback_or_stronger( ag_slot_state_t const * self,
                                             ag_block_hash_t const   block_hash ) {
  int has_notar_cert      = self->certs.notar.slot !=ULONG_MAX && !memcmp( self->certs.notar.block_hash, block_hash, sizeof(ag_block_hash_t) );
  int has_fast_final_cert = self->certs.fast_finalize.slot!=ULONG_MAX && !memcmp( self->certs.fast_finalize.block_hash, block_hash, sizeof(ag_block_hash_t) );
  return has_notar_cert || has_fast_final_cert || ag_slot_state_is_notar_fallback( self, block_hash );
}

void
ag_slot_state_add_cert( ag_slot_state_t * self,
                        ag_cert_t const * cert ) {
  switch( cert->kind ) {
  case AG_CERT_KIND_NOTAR: {
    self->certs.notar = cert->notar;
    break;
  }
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_cert_notar_fallback_t const * n = &cert->notar_fallback;
    if( FD_LIKELY( !ag_slot_state_is_notar_fallback( self, n->block_hash ) ) ) {
      FD_CHECK_CRIT( self->certs.notar_fallback_cnt<AG_NOTAR_FALLBACK_CERT_MAX, "consensus safety violation" ); /* Lemma 48 */
      self->certs.notar_fallback[ self->certs.notar_fallback_cnt++ ] = *n;
    }
    break;
  }
  case AG_CERT_KIND_SKIP: {
    self->certs.skip = cert->skip;
    break;
  }
  case AG_CERT_KIND_FAST_FINAL: {
    self->certs.fast_finalize = cert->fast_final;
    break;
  }
  case AG_CERT_KIND_FINAL: {
    self->certs.finalize = cert->final;
    break;
  }
  default:
    FD_LOG_ERR(( "invalid cert kind %u", cert->kind ));
  }
}

int
ag_slot_state_add_vote( ag_slot_state_t *  self,
                        ag_slot_states_t * states,
                        ag_vote_t const *  vote,
                        ulong              stake,
                        ag_cert_t *        out_cert_events,
                        ulong *            out_cert_event_cnt,
                        ag_block_id_t *    out_safe_to_notar,
                        ulong *            out_safe_to_notar_cnt,
                        ulong *            out_safe_to_skip,
                        ulong *            out_safe_to_skip_cnt,
                        ag_block_id_t *    out_repair_events,
                        ulong *            out_repair_event_cnt,
                        fd_bls_set_t *     bad ) {
  ulong slot = ag_vote_slot( vote );
  ulong rank = ag_vote_rank( vote );

  ag_slot_votes_t * votes = &self->votes;
  switch( vote->kind ) { /* the kind slot must be free */
  case AG_VOTE_KIND_NOTAR:
  case AG_VOTE_KIND_SKIP:           FD_TEST( !fd_bls_set_test( votes->notar_set, rank ) && !fd_bls_set_test( votes->skip_agg.set, rank ) );                   break;
  case AG_VOTE_KIND_NOTAR_FALLBACK: FD_TEST( votes->notar_fallback_sig_cnt[ rank ]<AG_NOTAR_FALLBACK_VOTE_MAX );                                              break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
  case AG_VOTE_KIND_FINAL:          FD_TEST( !fd_bls_set_test( votes->skip_fallback_agg.set, rank ) && !fd_bls_set_test( votes->finalize_agg.set, rank ) ); break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
  uchar sig[ FD_BLS_SIG_COMPRESSED_SZ ];
  fd_bls_sig_compress( ag_vote_sig( vote ), sig );
  sig_write( self, states, sig_ks( vote->kind, votes->notar_fallback_sig_cnt[ rank ] ), rank, sig );

  *out_cert_event_cnt = 0UL; *out_safe_to_notar_cnt = 0UL; *out_safe_to_skip_cnt = 0UL; *out_repair_event_cnt = 0UL; fd_bls_set_null( bad );
  self->shred_version = ag_vote_shred_version( vote );
  int err;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR:
    fd_bls_set_insert( self->votes.notar_set, rank );
    err = count_notar_stake( self, states, &vote->notar, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    self->votes.notar_fallback_sig_cnt[ rank ]++;
    err = count_notar_fallback_stake( self, states, &vote->notar_fallback, stake, out_cert_events, out_cert_event_cnt, bad );
    break;
  case AG_VOTE_KIND_SKIP:
    self->votes.notar_or_skip_stake += stake;
    err = count_skip_stake( self, states, vote, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    err = count_skip_stake( self, states, vote, stake, out_cert_events, out_cert_event_cnt, out_safe_to_notar, out_safe_to_notar_cnt, out_safe_to_skip, out_safe_to_skip_cnt, out_repair_events, out_repair_event_cnt, bad );
    break;
  case AG_VOTE_KIND_FINAL:
    err = count_finalize_stake( self, states, &vote->final, stake, out_cert_events, out_cert_event_cnt, bad );
    break;
  default:
    FD_LOG_CRIT(( "unreachable" ));
  }

  if( FD_UNLIKELY( rank==self->own_rank ) ) {
    ag_block_hash_set_t pending = self->pending_safe_to_notar;
    for( ulong i=0UL; i<pending.cnt; i++ ) {
      if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, pending.hash[i] ) ) ) continue;
      switch( check_safe_to_notar( self, states, pending.hash[i], bad ) ) {
      case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR: out_safe_to_notar[ (*out_safe_to_notar_cnt)++ ] = ag_block_id( slot, pending.hash[i] ); break;
      case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK: {
        ulong j; for( j=0UL; j<*out_repair_event_cnt; j++ ) if( FD_UNLIKELY( !memcmp( out_repair_events[j].hash, pending.hash[i], sizeof(ag_block_hash_t) ) ) ) break;
        if( FD_LIKELY( j==*out_repair_event_cnt ) ) out_repair_events[ (*out_repair_event_cnt)++ ] = ag_block_id( slot, pending.hash[i] );
        break;
      }
      default: break;
      }
    }
  }

  return err;
}

void
ag_slot_state_notify_parent_known( ag_slot_state_t *     self,
                                   ag_slot_states_t *    states,
                                   ag_block_hash_t const block_hash,
                                   fd_bls_set_t *        bad ) {
  fd_bls_set_null( bad );
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( self->parents[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) return;
  }
  FD_TEST( self->parents_cnt < AG_EQVOC_BLOCK_HASH_MAX );
  ag_parent_status_t * e = &self->parents[ self->parents_cnt++ ];
  memcpy( e->hash, block_hash, sizeof(ag_block_hash_t) );
  e->kind = AG_PARENT_STATUS_KNOWN;

  check_safe_to_notar( self, states, block_hash, bad );
}

int
ag_slot_state_notify_parent_certified( ag_slot_state_t *     self,
                                       ag_slot_states_t *    states,
                                       ag_block_hash_t const block_hash,
                                       fd_bls_set_t *        bad ) {
  fd_bls_set_null( bad );
  ag_parent_status_t * parent = NULL;
  for( ulong i=0UL; i<self->parents_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( self->parents[i].hash, block_hash, sizeof(ag_block_hash_t) ) ) ) { parent = &self->parents[i]; break; }
  }
  FD_TEST( parent );
  parent->kind = AG_PARENT_STATUS_CERTIFIED;

  if( FD_UNLIKELY( block_hash_set_contains( &self->sent_safe_to_notar, block_hash ) ) ) return 0;

  switch( check_safe_to_notar( self, states, block_hash, bad ) ) {
  case AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK:  return -1; /* unreachable: this block's parents entry was found above */
  case AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES: return  0;
  case AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR:  return  1;
  default:                                     FD_LOG_CRIT(( "unreachable" ));
  }
}

int
ag_slot_state_check_slashable_offence( ag_slot_state_t const *  self,
                                       ag_slot_states_t const * states,
                                       ag_vote_t const *        vote ) {
  ulong voter = ag_vote_rank( vote );
  ag_slot_votes_t const * votes = &self->votes;

  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    }
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) {
      if( FD_UNLIKELY( !hash_stake_eq( self, states->spill_fd, 0, votes->notar_hash_stake_idx[ voter ], vote->notar.block_hash ) ) ) return AG_SLASHABLE_NOTAR_DIFFERENT_HASH;
    }
    break;
  }

  case AG_VOTE_KIND_NOTAR_FALLBACK:
    if( FD_UNLIKELY( fd_bls_set_test( votes->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    } else if( FD_UNLIKELY( votes->notar_fallback_sig_cnt[ voter ]>=AG_NOTAR_FALLBACK_VOTE_MAX ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_OVER_THREE;
    }
    break;

  case AG_VOTE_KIND_SKIP:
    if( FD_UNLIKELY( fd_bls_set_test( votes->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) return AG_SLASHABLE_SKIP_AND_NOTARIZE;
    break;

  case AG_VOTE_KIND_SKIP_FALLBACK:
    if( FD_UNLIKELY( fd_bls_set_test( votes->finalize_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    break;

  case AG_VOTE_KIND_FINAL: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->skip_agg.set, voter ) || fd_bls_set_test( votes->skip_fallback_agg.set, voter ) ) ) {
      return AG_SLASHABLE_SKIP_AND_FINALIZE;
    }
    if( FD_UNLIKELY( votes->notar_fallback_sig_cnt[ voter ] ) ) {
      return AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE;
    }
    break;
  }

  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return AG_SLASHABLE_NONE;
}

int
ag_slot_state_should_ignore_vote( ag_slot_state_t const *  self,
                                  ag_slot_states_t const * states,
                                  ag_vote_t const *        vote ) {
  ulong                   voter = ag_vote_rank( vote );
  ag_slot_votes_t const * votes = &self->votes;
  int                     fd    = states->spill_fd;
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR: {
    if( FD_UNLIKELY( fd_bls_set_test( votes->notar_set, voter ) ) ) return 1;

    uchar const * hash = vote->notar.block_hash;
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( hash_stake_eq( self, fd, 1, votes->notar_fallback_hash_stake_idx[ voter ][ j ], hash ) ) ) return 1;
    }
    return 0;
  }
  case AG_VOTE_KIND_NOTAR_FALLBACK: {
    uchar const * hash = vote->notar_fallback.block_hash;
    for( ulong j=0UL; j<votes->notar_fallback_sig_cnt[ voter ]; j++ ) {
      if( FD_UNLIKELY( hash_stake_eq( self, fd, 1, votes->notar_fallback_hash_stake_idx[ voter ][ j ], hash ) ) ) return 1;
    }

    return fd_bls_set_test( votes->notar_set, voter ) && hash_stake_eq( self, fd, 0, votes->notar_hash_stake_idx[ voter ], hash );
  }
  case AG_VOTE_KIND_SKIP:
  case AG_VOTE_KIND_SKIP_FALLBACK:
    return fd_bls_set_test( votes->skip_agg.set, voter ) || fd_bls_set_test( votes->skip_fallback_agg.set, voter );
  case AG_VOTE_KIND_FINAL:
    return fd_bls_set_test( votes->finalize_agg.set, voter );
  default:
    FD_LOG_ERR(( "invalid vote kind %u", vote->kind ));
  }
  return 0;
}

fd_bls_agg_t *
ag_slot_state_notar_reward_agg( ag_slot_state_t const *  self,
                                ag_slot_states_t const * states,
                                fd_bls_agg_t *           out ) {
  ulong top = hash_stake_query( self, states->spill_fd, 0, self->votes.top_notar_hash );
  if( FD_UNLIKELY( top==ULONG_MAX ) ) return NULL;
  hash_agg( self, states, 0, top, out );
  return out;
}

FD_FN_PURE fd_bls_agg_t const *
ag_slot_state_skip_reward_agg( ag_slot_state_t const * self ) {
  return fd_bls_set_is_null( self->votes.skip_agg.set ) ? NULL : &self->votes.skip_agg;
}

fd_bls_sig_t *
ag_slot_state_vote_sig( ag_slot_state_t const *  self,
                        ag_slot_states_t const * states,
                        uint                     kind,
                        ulong                    rank,
                        ulong                    j,
                        fd_bls_sig_t *           out ) {
  uchar sig[ FD_BLS_SIG_COMPRESSED_SZ ];
  sig_read( self, states, sig_ks( kind, j ), rank, 1UL, sig );
  FD_TEST( !fd_bls_sig_de_compressed_unchecked( out, sig ) );
  return out;
}

fd_bls_sig_t *
ag_slot_state_sigs( ag_slot_state_t const *  self,
                    ag_slot_states_t const * states,
                    uint                     kind,
                    ag_block_hash_t const    block_hash,
                    fd_bls_set_t const *     set,
                    fd_bls_sig_t *           out ) {
  if( FD_LIKELY( kind!=AG_VOTE_KIND_NOTAR_FALLBACK ) ) { /* one copy per page */
    ulong ks = sig_ks( kind, 0UL );
    uchar buf[ AG_SIG_PG_SZ ];
    for( ulong w=0UL; w<fd_bls_set_word_cnt; w++ ) {
      if( !set[ w ] ) continue;
      ulong lo = w*AG_SIG_PG_RANKS+(ulong)fd_ulong_find_lsb( set[ w ] );
      ulong hi = w*AG_SIG_PG_RANKS+(ulong)fd_ulong_find_msb( set[ w ] );
      sig_read( self, states, ks, lo, hi-lo+1UL, buf );
      for( ulong m=set[ w ]; m; m=fd_ulong_pop_lsb( m ) ) {
        ulong rank = w*AG_SIG_PG_RANKS+(ulong)fd_ulong_find_lsb( m );
        FD_TEST( !fd_bls_sig_de_compressed_unchecked( out+rank, buf+(rank-lo)*FD_BLS_SIG_COMPRESSED_SZ ) );
      }
    }
    return out;
  }
  ag_slot_votes_t const * votes = &self->votes;
  ulong                   nf    = hash_stake_query( self, states->spill_fd, 1, block_hash );
  for( ulong rank = fd_bls_set_const_iter_init( set );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( set, rank ) ) {
    ulong j = 0UL;
    for( ; j<votes->notar_fallback_sig_cnt[ rank ]; j++ ) {
      if( FD_UNLIKELY( votes->notar_fallback_hash_stake_idx[ rank ][ j ]==nf ) ) break;
    }
    FD_CHECK_CRIT( j<votes->notar_fallback_sig_cnt[ rank ], "invariant violation" );
    uchar sig[ FD_BLS_SIG_COMPRESSED_SZ ];
    sig_read( self, states, sig_ks( kind, j ), rank, 1UL, sig );
    FD_TEST( !fd_bls_sig_de_compressed_unchecked( out+rank, sig ) );
  }
  return out;
}

int
ag_slot_state_agg_verify( ag_slot_state_t const *  self,
                          ag_slot_states_t const * states,
                          uint                     kind,
                          ag_block_hash_t const    block_hash,
                          uchar const *            msg,
                          ulong                    msg_sz,
                          fd_bls_agg_t *           agg,
                          fd_bls_set_t *           bad ) {
  fd_bls_hash_t h[1];
  fd_bls_hash_msg( msg, msg_sz, h );
  if( FD_LIKELY( fd_bls_agg_verify_hashed( h, &agg->pub, &agg->sig ) ) ) { fd_bls_set_null( bad ); return 0; }
  ag_epoch_info_t const * epoch_info = fd_ptr_if( self->slot>=states->next_epoch_slot, states->next_epoch_info, fd_ptr_if( self->slot>=states->curr_epoch_slot, states->curr_epoch_info, states->prev_epoch_info ) );
  fd_bls_sig_t            sigs[ AG_VAT_MAX ];
  ag_slot_state_sigs( self, states, kind, block_hash, agg->set, sigs );
  return fd_bls_agg_verify_subtract( agg, msg, msg_sz, epoch_info->pubkeys, sigs, bad );
}

uchar *
ag_slot_state_vote_hash( ag_slot_state_t const *  self,
                         ag_slot_states_t const * states,
                         uint                     kind,
                         ulong                    rank,
                         ulong                    j,
                         ag_block_hash_t          out ) {
  int   nf = kind==AG_VOTE_KIND_NOTAR_FALLBACK;
  ulong id = nf ? self->votes.notar_fallback_hash_stake_idx[ rank ][ j ] : self->votes.notar_hash_stake_idx[ rank ];
  hash_stake_get( self, states->spill_fd, nf, id, out );
  return out;
}
