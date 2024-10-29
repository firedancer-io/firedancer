#include "fd_eqvoc.h"

void *
fd_eqvoc_new( void * shmem, ulong key_max, ulong seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_eqvoc_t * eqvoc = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_eqvoc_t),      sizeof(fd_eqvoc_t) );
  void * pool        = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_pool_align(),    fd_eqvoc_pool_footprint( key_max ) );
  void * map         = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_map_align(),     fd_eqvoc_map_footprint( key_max ) );
  void * sha512      = FD_SCRATCH_ALLOC_APPEND( l, fd_sha512_align(),        fd_sha512_footprint() );
  void * bmtree_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_bmtree_commit_align(), fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_eqvoc_align() );

  eqvoc->key_max = key_max;
  fd_eqvoc_pool_new( pool, key_max );
  fd_eqvoc_map_new( map, key_max, seed );
  fd_sha512_new( sha512 );
  (void)bmtree_mem; /* does not require `new` */

  return shmem;
}

fd_eqvoc_t *
fd_eqvoc_join( void * sheqvoc ) {

  if( FD_UNLIKELY( !sheqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)sheqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned eqvoc" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, sheqvoc );
  fd_eqvoc_t * eqvoc = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_eqvoc_t),      sizeof(fd_eqvoc_t) );
  void * pool        = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_pool_align(),    fd_eqvoc_pool_footprint( eqvoc->key_max ) );
  void * map         = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_map_align(),     fd_eqvoc_map_footprint( eqvoc->key_max ) );
  void * sha512      = FD_SCRATCH_ALLOC_APPEND( l, fd_sha512_align(),        fd_sha512_footprint() );
  void * bmtree_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_bmtree_commit_align(), fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_eqvoc_align() );

  (void)eqvoc;      /* does not require `join` */
  eqvoc->pool       = fd_eqvoc_pool_join( pool );
  eqvoc->map        = fd_eqvoc_map_join( map );
  eqvoc->sha512     = fd_sha512_join( sha512 );
  eqvoc->bmtree_mem = bmtree_mem;

  return eqvoc;
}

void *
fd_eqvoc_leave( fd_eqvoc_t const * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  return (void *)eqvoc;
}

void *
fd_eqvoc_delete( void * eqvoc ) {

  if( FD_UNLIKELY( !eqvoc ) ) {
    FD_LOG_WARNING(( "NULL eqvoc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)eqvoc, fd_eqvoc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned eqvoc" ));
    return NULL;
  }

  return eqvoc;
}

void
fd_eqvoc_insert( fd_eqvoc_t * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_key_t     key   = { shred->slot, shred->fec_set_idx };
  fd_eqvoc_entry_t * entry = fd_eqvoc_map_ele_query( eqvoc->map, &key, NULL, eqvoc->pool );
  if( FD_UNLIKELY( !entry ) ) {
  
    /* TODO eviction logic */

    entry                  = fd_eqvoc_pool_ele_acquire( eqvoc->pool );
    entry->key.slot        = shred->slot;
    entry->key.fec_set_idx = shred->fec_set_idx;
    entry->code_cnt        = 0;
    entry->data_cnt        = 0;
    entry->last_idx        = FD_SHRED_IDX_NULL;
    memcpy( entry->sig, shred->signature, FD_ED25519_SIG_SZ );
  }

  if( FD_LIKELY( fd_shred_is_code( fd_shred_type( shred->variant ) ) ) ) { /* optimize for coding shreds (code_cnt >= data_cnt) */
    entry->code_cnt = shred->code.code_cnt;
    entry->data_cnt = shred->code.data_cnt;
  } else if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ) {
    entry->last_idx = shred->idx;
  }

  /* This cannot fail */
  fd_eqvoc_map_ele_insert( eqvoc->map, entry, eqvoc->pool );
}

fd_eqvoc_entry_t const *
fd_eqvoc_search( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_entry_t const * entry = fd_eqvoc_query( eqvoc, shred->slot, shred->fec_set_idx );

  /* If we've already seen a shred in this FEC set */

  if( FD_LIKELY( entry ) ) {

    /* Make sure the signature matches. Every merkle shred in the FEC
       set must have the same signature. */

    if( FD_UNLIKELY( 0 != memcmp( entry->sig, shred->signature, FD_ED25519_SIG_SZ ) ) ) {
      return entry;
    }

    /* Check if this shred's idx is higher than another shred that claimed
       to be the last_idx. This indicates equivocation. */

    if( FD_UNLIKELY( shred->idx > entry->last_idx ) ) {
      return entry;
    }
  }

  /* Look backward FEC_MAX idxs for overlap. */

  for( uint i = 1; shred->fec_set_idx >= i && i < FD_EQVOC_FEC_MAX; i++ ) {
    fd_eqvoc_entry_t const * conflict = fd_eqvoc_query( eqvoc, shred->slot, shred->fec_set_idx - i );
    if( FD_UNLIKELY( conflict &&
                     conflict->data_cnt > 0 &&
                     conflict->key.fec_set_idx + conflict->data_cnt > shred->fec_set_idx ) ) {
      return conflict;
    }
  }

  /* Look forward data_cnt idxs for overlap. */

  for( uint i = 1; entry && i < entry->data_cnt; i++ ) {
    fd_eqvoc_entry_t const * conflict = fd_eqvoc_query( eqvoc, shred->slot, shred->fec_set_idx + i );
    if( FD_UNLIKELY( conflict ) ) return conflict;
  }

  return NULL; /* No conflicts */
}

int
shred_merkle_root( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred, fd_bmtree_node_t * root_out ) {
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( eqvoc->bmtree_mem,
                                                     FD_SHRED_MERKLE_NODE_SZ,
                                                     FD_BMTREE_LONG_PREFIX_SZ,
                                                     FD_SHRED_MERKLE_LAYER_CNT );

  uchar shred_type  = fd_shred_type( shred->variant );
  int is_data_shred = fd_shred_is_data( shred_type );
  ulong in_type_idx = fd_ulong_if( is_data_shred, shred->idx - shred->fec_set_idx, shred->code.idx );
  ulong shred_idx   = fd_ulong_if( is_data_shred, in_type_idx, in_type_idx + shred->code.data_cnt  );

  ulong tree_depth           = fd_shred_merkle_cnt( shred->variant ); /* In [0, 15] */
  ulong reedsol_protected_sz = 1115UL + FD_SHRED_DATA_HEADER_SZ - FD_SHRED_SIGNATURE_SZ - FD_SHRED_MERKLE_NODE_SZ*tree_depth
                                      - FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type )
                                      - FD_SHRED_SIGNATURE_SZ  *fd_shred_is_resigned( shred_type); /* In [743, 1139] conservatively*/
  ulong data_merkle_protected_sz   = reedsol_protected_sz + FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type );
  ulong parity_merkle_protected_sz = reedsol_protected_sz + FD_SHRED_MERKLE_ROOT_SZ*fd_shred_is_chained ( shred_type )+FD_SHRED_CODE_HEADER_SZ-FD_ED25519_SIG_SZ;
  ulong merkle_protected_sz  = fd_ulong_if( is_data_shred, data_merkle_protected_sz, parity_merkle_protected_sz );
  fd_bmtree_node_t leaf;
  fd_bmtree_hash_leaf( &leaf, (uchar const *)shred + sizeof(fd_ed25519_sig_t), merkle_protected_sz, FD_BMTREE_LONG_PREFIX_SZ );

  return fd_bmtree_commitp_insert_with_proof( tree, shred_idx, &leaf, (uchar const *)fd_shred_merkle_nodes( shred ), fd_shred_merkle_cnt( shred->variant ), root_out );
}

/* https://github.com/anza-xyz/agave/blob/v2.0.3/gossip/src/duplicate_shred.rs#L107-L177 */
int
fd_eqvoc_test( fd_eqvoc_t const * eqvoc, fd_shred_t * shred1, fd_shred_t * shred2 ) {

  /* Optimize for valid equivocation proof */

  if( FD_UNLIKELY( shred1->slot != shred2->slot ) ) {
    return 0;
  }

  if( FD_UNLIKELY( shred1->version != eqvoc->shred_version ) ) {
    return 0;
  }

  if( FD_UNLIKELY( shred2->version != eqvoc->shred_version ) ) {
    return 0;
  }

  /* Verify both shreds contain valid signatures for the leader of their
     slot, which requires deriving the merkle root and sig-verifying it
     because the leader signs the merkle root for merkle shreds. */

  fd_pubkey_t const * leader = fd_epoch_leaders_get( eqvoc->leaders, shred1->slot );
  fd_bmtree_node_t    root1;
  if( FD_UNLIKELY( !shred_merkle_root( eqvoc, shred1, &root1 ) ) ) {
    return 0;
  }
  fd_bmtree_node_t root2;
  if( FD_UNLIKELY( !shred_merkle_root( eqvoc, shred2, &root2 ) ) ) {
    return 0;
  }
  if( FD_UNLIKELY( FD_ED25519_SUCCESS != fd_ed25519_verify( root1.hash,
                                                            32UL,
                                                            shred1->signature,
                                                            leader->uc,
                                                            eqvoc->sha512 ) ||
                   FD_ED25519_SUCCESS != fd_ed25519_verify( root2.hash,
                                                            32UL,
                                                            shred2->signature,
                                                            leader->uc,
                                                            eqvoc->sha512 ) ) ) {
    return 0;
  }

  if( FD_UNLIKELY( shred1->fec_set_idx == shred2->fec_set_idx
                && 0 != memcmp( &root1, &root2, sizeof( fd_bmtree_node_t ) ) ) ) {
    return 1;
  }

  if( FD_UNLIKELY( fd_shred_type( shred1->variant ) != fd_shred_type( shred2->variant ) ) ) {
    return 0;
  }

  if( FD_UNLIKELY( shred1->idx == shred2->idx ) ) {
    if( FD_LIKELY( 0 != memcmp( shred1->signature, shred2->signature, FD_ED25519_SIG_SZ ) ) ) {
      return 1;
    }
    return 0;
  }

  if( FD_UNLIKELY( fd_shred_is_data( fd_shred_type( shred1->variant ) ) ) ) {
    if( FD_UNLIKELY( ( shred1->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred2->idx > shred1->idx ) )
                  || ( shred2->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred1->idx > shred2->idx ) ) {
      return 1;
    }
  }

  fd_eqvoc_entry_t const * entry1 = fd_eqvoc_query( eqvoc, shred1->slot, shred1->fec_set_idx );
  fd_eqvoc_entry_t const * entry2 = fd_eqvoc_query( eqvoc, shred2->slot, shred2->fec_set_idx );

  /* If the FEC set idx is the same but any metadata is different, mark
     it as equivocating. */

  if( FD_UNLIKELY( shred1->fec_set_idx == shred2->fec_set_idx &&
                   ( entry1->code_cnt != entry2->code_cnt ||
                     entry1->data_cnt != entry2->data_cnt ||
                     entry1->last_idx != entry2->last_idx ) ) ) {
    return 1;
  }

  /* This is only reachable if shred1 and shred2 are in different FEC
     sets, so check for overlap. */

  ulong lo = fd_ulong_min( shred1->fec_set_idx, shred2->fec_set_idx );
  ulong hi = fd_ulong_max( shred1->fec_set_idx, shred2->fec_set_idx );

  fd_eqvoc_entry_t const * lo_entry = fd_ptr_if( shred1->fec_set_idx < shred2->fec_set_idx, entry1, entry2 );
  FD_LOG_NOTICE(("lo %lu hi %lu data_cnt %lu %lu", lo, hi, lo_entry->data_cnt, lo + lo_entry->data_cnt ));

  /* The FEC sets must overlap in data shred indices if the lower FEC
     set index crosses into the higher FEC set index based on the data
     shred count. */

  if ( FD_UNLIKELY( lo_entry && lo_entry->data_cnt > 0 && lo + lo_entry->data_cnt >= hi ) ) {
    return 1;
  }

  return 0;
}

void
fd_eqvoc_from_chunks( FD_PARAM_UNUSED fd_eqvoc_t const * eqvoc,
                      fd_gossip_duplicate_shred_t *      chunks,
                      fd_shred_t *                       shred1_out,
                      fd_shred_t *                       shred2_out ) {
  /* FIXME add validation */

  uchar * shred1_bytes = (uchar *)shred1_out;
  uchar * shred2_bytes = (uchar *)shred2_out;

  ulong chunk_cnt = chunks[0].num_chunks;
  ulong chunk_len = chunks[0].chunk_len;

  ulong off       = 0;
  ulong shred1_sz = 0;
  ulong shred2_sz = 0;
  for( ulong i = 0; i < chunk_cnt; i++ ) {
    for( ulong j = 0; j < chunk_cnt; j++ ) {

      /* FIXME O(n^2). DOS for small chunks */

      if( chunks[j].chunk_index == i ) {

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
  ulong sz  = fd_shred_sz( shred1 ) + fd_shred_sz( shred2 );
  ulong cnt = sz / chunk_len;
  cnt       = fd_ulong_if( (int)( sz % chunk_len ), cnt + 1, cnt );
}
