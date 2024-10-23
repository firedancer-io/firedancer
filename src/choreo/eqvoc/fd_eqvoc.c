#include "fd_eqvoc.h"

void *
fd_eqvoc_new( void * shmem, ulong key_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_eqvoc_footprint( key_max );

  fd_memset( shmem, 0, footprint );
  ulong        laddr = (ulong)shmem;
  fd_eqvoc_t * eqvoc = (void *)laddr;
  laddr += sizeof( fd_eqvoc_t );

  laddr       = fd_ulong_align_up( laddr, fd_eqvoc_pool_align() );
  eqvoc->pool = fd_eqvoc_pool_new( (void *)laddr, key_max );
  laddr += fd_eqvoc_pool_footprint( key_max );

  laddr      = fd_ulong_align_up( laddr, fd_eqvoc_map_align() );
  eqvoc->map = fd_eqvoc_map_new( (void *)laddr, key_max, seed );
  laddr += fd_eqvoc_map_footprint( key_max );

  laddr = fd_ulong_align_up( laddr, fd_eqvoc_align() );
  FD_TEST( laddr == (ulong)shmem + footprint );

  return shmem;
}

fd_eqvoc_t *
fd_eqvoc_join( void * sheqvoc ) {

  if( FD_UNLIKELY( !sheqvoc ) ) {
    FD_LOG_WARNING( ( "NULL eqvoc" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)sheqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned eqvoc" ) );
    return NULL;
  }

  ulong        laddr = (ulong)sheqvoc; /* offset from a memory region */
  fd_eqvoc_t * eqvoc = (void *)sheqvoc;
  laddr += sizeof( fd_eqvoc_t );

  laddr         = fd_ulong_align_up( laddr, fd_eqvoc_pool_align() );
  eqvoc->pool   = fd_eqvoc_pool_join( (void *)laddr );
  ulong key_max = fd_eqvoc_pool_max( eqvoc->pool );
  laddr += fd_eqvoc_pool_footprint( key_max );

  laddr      = fd_ulong_align_up( laddr, fd_eqvoc_map_align() );
  eqvoc->map = fd_eqvoc_map_join( (void *)laddr );
  laddr += fd_eqvoc_map_footprint( key_max );

  laddr = fd_ulong_align_up( laddr, fd_eqvoc_align() );
  FD_TEST( laddr == (ulong)sheqvoc + fd_eqvoc_footprint( key_max ) );

  return eqvoc;
}

void *
fd_eqvoc_leave( fd_eqvoc_t const * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING( ( "NULL eqvoc" ) );
    return NULL;
  }

  return (void *)eqvoc;
}

void *
fd_eqvoc_delete( void * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING( ( "NULL eqvoc" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)eqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned eqvoc" ) );
    return NULL;
  }

  return eqvoc;
}

void
fd_eqvoc_insert( fd_eqvoc_t * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_entry_t * entry = fd_eqvoc_pool_ele_acquire( eqvoc->pool );
  entry->key.slot          = shred->slot;
  entry->key.fec_set_idx   = shred->fec_set_idx;
  entry->last_idx          = FD_SHRED_IDX_NULL;
  memcpy( entry->sig, shred->signature, FD_ED25519_SIG_SZ );

  if( FD_LIKELY( fd_shred_is_code( fd_shred_type( shred->variant ) ) ) ) {

    /* optimize for coding shreds (code_cnt >= data_cnt) */

    entry->code_cnt = shred->code.code_cnt;
    entry->data_cnt = shred->code.data_cnt;
  }

  if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ) {
    entry->last_idx = shred->idx;
  }

  fd_eqvoc_map_ele_insert( eqvoc->map, entry, eqvoc->pool );
}

int
fd_eqvoc_test( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_key_t key = { shred->slot, shred->fec_set_idx };

  fd_eqvoc_entry_t const * entry = fd_eqvoc_map_ele_query_const( eqvoc->map,
                                                                 &key,
                                                                 NULL,
                                                                 eqvoc->pool );

  /* If we've already seen a shred in this FEC set */

  if( FD_LIKELY( entry ) ) {

    /* Make sure the signature matches. Note this implicitly also checks
       for direct equivocation conflicts, because two shreds with the
       same slot and idx should be in the same FEC set (if they're in
       different FEC sets this will be checked in the overlap logic
       later). */

    if( FD_UNLIKELY( 0 != memcmp( entry->sig, shred->signature, FD_ED25519_SIG_SZ ) ) ) {
      return 1;
    }

    /* Check if this shred's idx is higher than another shred that claimed
       to be the last_idx. This indicates equivocation. */

    if( FD_UNLIKELY( shred->idx > entry->last_idx ) ) {
      return 1;
    }
  }

  /* Look backward FEC_MAX idxs for overlap. */

  for( uint i = 1; shred->fec_set_idx >= i && i < FD_EQVOC_FEC_MAX; i++ ) {
    fd_eqvoc_key_t           key   = { shred->slot, shred->fec_set_idx - i };
    fd_eqvoc_entry_t const * entry = fd_eqvoc_map_ele_query_const( eqvoc->map,
                                                                   &key,
                                                                   NULL,
                                                                   eqvoc->pool );

    if( FD_UNLIKELY( entry && entry->data_cnt > 0 &&
                     entry->key.fec_set_idx + entry->data_cnt > shred->fec_set_idx ) ) {
      return 0; /* Equivocation detected */
    }
  }

  /* Look forward data_cnt idxs for overlap. */

  for( uint i = 1; entry && i < entry->data_cnt; i++ ) {
    fd_eqvoc_key_t           key   = { shred->slot, shred->fec_set_idx + i };
    fd_eqvoc_entry_t const * entry = fd_eqvoc_map_ele_query_const( eqvoc->map,
                                                                   &key,
                                                                   NULL,
                                                                   eqvoc->pool );
    if( FD_UNLIKELY( entry ) ) return 0; /* Equivocation detected */
  }

  return 1;
}

void
fd_eqvoc_from_chunks( FD_PARAM_UNUSED fd_eqvoc_t const * eqvoc,
                      fd_gossip_duplicate_shred_t *      chunks,
                      fd_shred_t *                       shred1_out,
                      fd_shred_t *                       shred2_out ) {
  /* FIXME add validation */

  uchar * shred1_bytes = (uchar *)shred1_out;
  uchar * shred2_bytes = (uchar *)shred2_out;

  ulong chunk_cnt = chunks[0].chunk_cnt;
  ulong chunk_len = chunks[0].chunk_len;

  ulong off       = 0;
  ulong shred1_sz = 0;
  ulong shred2_sz = 0;
  for( ulong i = 0; i < chunk_cnt; i++ ) {
    for( ulong j = 0; j < chunk_cnt; j++ ) {

      /* FIXME O(n^2). DOS for small chunks */

      if( chunks[j].chunk_idx == i ) {

        if( FD_LIKELY( off > FD_SHRED_VARIANT_OFF ) ) {
          shred1_sz = fd_shred_sz( shred1_out );
        }

        if( FD_LIKELY( off > shred1_sz + FD_SHRED_VARIANT_OFF ) ) {
          shred2_sz = fd_shred_sz( shred2_out );
        }

        if( !shred1_sz || off + chunk_len <= shred1_sz ) {

          /* copy from chunk into shred1 */

          fd_memcpy( shred1_bytes + off, chunks[j].chunk, chunk_len );
          off += chunk_len;

        } else if( off < shred1_sz ) {

          /* copy prefix of chunk into shred1 and suffix of chunk into shred2 */

          ulong len = shred1_sz - off;
          fd_memcpy( shred1_bytes + off, chunks[j].chunk, len );
          off += len;

          fd_memcpy( shred2_bytes + off - shred1_sz, chunks[j].chunk + len, chunk_len - len );
          off += chunk_len - len;

        } else {

          /* copy from chunk into shred2 */

          ulong len = fd_ulong_min( chunk_len,
                                    fd_ulong_if( (int)shred2_sz,
                                                 shred2_sz - ( off - shred1_sz ),
                                                 chunk_len ) );
          fd_memcpy( shred2_bytes + off - shred1_sz, chunks[j].chunk, len );
          off += chunk_len;
        }
      }
    }
  }
}

void
fd_eqvoc_to_chunks( FD_PARAM_UNUSED fd_eqvoc_t const * eqvoc,
                    fd_shred_t const *                 shred1,
                    fd_shred_t const *                 shred2,
                    ulong                              chunk_len,
                    fd_gossip_duplicate_shred_t *      chunks_out ) {
  uchar * shred1_bytes = (uchar *)shred1;
  uchar * shred2_bytes = (uchar *)shred2;

  ulong off = 0;
  while( FD_LIKELY( off < fd_shred_sz( shred1 ) + fd_shred_sz( shred2 ) ) ) {
    ulong chunk_idx = off / chunk_len;

    if( off + chunk_len < fd_shred_sz( shred1 ) ) {

      /* copy from shred1 into chunk */

      fd_memcpy( chunks_out[chunk_idx].chunk, shred1_bytes + off, chunk_len );
      off += chunk_len;

    } else if( off < fd_shred_sz( shred1 ) ) {

      /* copy suffix of shred1 and prefix of shred2 into chunk */

      ulong suffix = fd_shred_sz( shred1 ) - off;
      fd_memcpy( chunks_out[chunk_idx].chunk, shred1_bytes + off, suffix );
      off += suffix;

      ulong prefix = chunk_len - suffix;
      fd_memcpy( chunks_out[chunk_idx].chunk + suffix, shred2_bytes, prefix );
      off += prefix;

    } else {

      /* copy from shred2 into chunk */

      ulong len = fd_ulong_min( chunk_len,
                                fd_shred_sz( shred2 ) - ( off - fd_shred_sz( shred1 ) ) );
      fd_memcpy( chunks_out[chunk_idx].chunk, shred2_bytes + off - fd_shred_sz( shred1 ), len );
      off += len;
    }
  }
  ulong cnt = ( fd_shred_sz( shred1 ) + fd_shred_sz( shred2 ) ) / chunk_len;
  cnt       = fd_ulong_if( (int)( ( fd_shred_sz( shred1 ) + fd_shred_sz( shred2 ) ) % chunk_len ),
                     cnt + 1,
                     cnt );
}
