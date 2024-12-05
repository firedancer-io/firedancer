#include "fd_eqvoc.h"
#include "../../ballet/shred/fd_shred.h"

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
  void * fec_pool    = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_fec_pool_align(), fd_eqvoc_fec_pool_footprint( key_max ) );
  void * fec_map     = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_fec_map_align(),  fd_eqvoc_fec_map_footprint( key_max ) );
  void * proof_pool  = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_proof_pool_align(), fd_eqvoc_proof_pool_footprint( key_max ) );
  void * proof_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_eqvoc_proof_map_align(),  fd_eqvoc_proof_map_footprint( key_max ) );
  void * sha512      = FD_SCRATCH_ALLOC_APPEND( l, fd_sha512_align(),        fd_sha512_footprint() );
  void * bmtree_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_bmtree_commit_align(), fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_eqvoc_align() );

  eqvoc->key_max    = key_max;
  eqvoc->fec_pool   = fd_eqvoc_fec_pool_join( fd_eqvoc_fec_pool_new( fec_pool, key_max ) );
  eqvoc->fec_map    = fd_eqvoc_fec_map_join( fd_eqvoc_fec_map_new( fec_map, key_max, seed ) );
  eqvoc->proof_pool = fd_eqvoc_proof_pool_join( fd_eqvoc_proof_pool_new( proof_pool, key_max ) );
  eqvoc->proof_map  = fd_eqvoc_proof_map_join( fd_eqvoc_proof_map_new( proof_map, key_max, seed ) );
  eqvoc->sha512     = fd_sha512_join( fd_sha512_new( sha512 ) );
  eqvoc->bmtree_mem = bmtree_mem; /* does not require join / new */

  eqvoc->fec_min       = FD_SLOT_NULL;
  eqvoc->key_max       = key_max;
  eqvoc->shred_version = 0;

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

  return (fd_eqvoc_t *)sheqvoc;
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

fd_eqvoc_proof_t * 
fd_eqvoc_proof_insert( fd_eqvoc_t * eqvoc, fd_gossip_duplicate_shred_t const * ds ) {
  fd_slot_pubkey_t key     = { ds->slot, ds->from };
  fd_eqvoc_proof_t * proof = fd_eqvoc_proof_map_ele_query( eqvoc->proof_map, &key, NULL, eqvoc->proof_pool );
  if( FD_UNLIKELY( !proof ) ) {
    proof           = fd_eqvoc_proof_pool_ele_acquire( eqvoc->proof_pool );
    proof->key.slot = ds->slot;
    proof->key.hash = ds->from;
    fd_eqvoc_proof_map_ele_insert( eqvoc->proof_map, proof, eqvoc->proof_pool );
  }
  if( FD_LIKELY( !fd_uchar_extract_bit( proof->bit_vec, ds->chunk_index ) ) ) {
    memcpy( proof->chunks[ds->chunk_index], ds->chunk, ds->chunk_len );
    proof->bit_vec = fd_uchar_set_bit( proof->bit_vec, ds->chunk_index );
  }
  return proof;
}

void
fd_eqvoc_fec_insert( fd_eqvoc_t * eqvoc, fd_shred_t const * shred ) {
  fd_slot_fec_t    key   = { shred->slot, shred->fec_set_idx };
  fd_eqvoc_fec_t * fec = fd_eqvoc_fec_map_ele_query( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool );
  if( FD_UNLIKELY( !fec ) ) {
  
    /* TODO eviction logic */

    fec                  = fd_eqvoc_fec_pool_ele_acquire( eqvoc->fec_pool );
    fec->key.slot        = shred->slot;
    fec->key.fec_set_idx = shred->fec_set_idx;
    fec->code_cnt        = 0;
    fec->data_cnt        = 0;
    fec->last_idx        = FD_SHRED_IDX_NULL;
    memcpy( fec->sig, shred->signature, FD_ED25519_SIG_SZ );
  }

  if( FD_LIKELY( fd_shred_is_code( fd_shred_type( shred->variant ) ) ) ) { /* optimize for coding shreds (code_cnt >= data_cnt) */
    fec->code_cnt = shred->code.code_cnt;
    fec->data_cnt = shred->code.data_cnt;
  } else if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ) {
    fec->last_idx = shred->idx;
  }

  fd_eqvoc_fec_map_ele_insert( eqvoc->fec_map, fec, eqvoc->fec_pool );
}

fd_eqvoc_fec_t const *
fd_eqvoc_fec_search( fd_eqvoc_t const * eqvoc, fd_shred_t const * shred ) {
  fd_eqvoc_fec_t const * entry = fd_eqvoc_fec_query( eqvoc, shred->slot, shred->fec_set_idx );

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
    fd_eqvoc_fec_t const * conflict = fd_eqvoc_fec_query( eqvoc, shred->slot, shred->fec_set_idx - i );
    if( FD_UNLIKELY( conflict &&
                     conflict->data_cnt > 0 &&
                     conflict->key.fec_set_idx + conflict->data_cnt > shred->fec_set_idx ) ) {
      return conflict;
    }
  }

  /* Look forward data_cnt idxs for overlap. */

  for( uint i = 1; entry && i < entry->data_cnt; i++ ) {
    fd_eqvoc_fec_t const * conflict = fd_eqvoc_fec_query( eqvoc, shred->slot, shred->fec_set_idx + i );
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

int
fd_eqvoc_test( fd_eqvoc_t const * eqvoc, fd_shred_t * shred1, fd_shred_t * shred2 ) {

  /* Input validation. */

  if( FD_UNLIKELY( shred1->slot != shred2->slot ) ) {
    return -1;
  }

  if( FD_UNLIKELY( shred1->version != eqvoc->shred_version ) ) {
    return -1;
  }

  if( FD_UNLIKELY( shred2->version != eqvoc->shred_version ) ) {
    return -1;
  }

  if( FD_UNLIKELY( fd_shred_type( shred1->variant ) != fd_shred_type( shred2->variant ) ) ) {
    return -1;
  }

  /* Check both shreds contain valid signatures from the assigned leader
     to that slot. This requires deriving the merkle root and
     sig-verifying it, because the leader signs the merkle root for
     merkle shreds.

     TODO remove? */

  fd_bmtree_node_t root1;
  if( FD_UNLIKELY( !shred_merkle_root( eqvoc, shred1, &root1 ) ) ) {
    return -1;
  }
  fd_bmtree_node_t root2;
  if( FD_UNLIKELY( !shred_merkle_root( eqvoc, shred2, &root2 ) ) ) {
    return -1;
  }
  fd_pubkey_t const * leader = fd_epoch_leaders_get( eqvoc->leaders, shred1->slot );
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
    return -1;
  }

  /* Test if the shreds have different payloads, but the same index and
     shred type. This will be true if their signatures compare
     different, because a shred's signature is ultimately derived from
     its payload.

     Return false if they are the same payload, because the remaining
     checks assume the shreds have different idxs. */

  if( FD_UNLIKELY( shred1->idx == shred2->idx &&
                   fd_shred_type( shred1->variant ) == fd_shred_type( shred2->variant ) ) ) {
    if( FD_LIKELY( 0 != memcmp( shred1->signature, shred2->signature, FD_ED25519_SIG_SZ ) ) ) {
      return FD_EQVOC_TEST_PAYLOAD;
    }
    return FD_EQVOC_TEST_FALSE;
  }

  /* Test if the shreds have different merkle roots when they're in the
     same FEC set. */

  if( FD_UNLIKELY( shred1->fec_set_idx == shred2->fec_set_idx &&
                   0 != memcmp( &root1, &root2, sizeof(fd_bmtree_node_t) ) ) ) {
    return FD_EQVOC_TEST_MERKLE_ROOT;
  }

  /* Test if the shreds have different coding metadata when they're both
     coding shreds in the same FEC set. */

  if( FD_UNLIKELY( fd_shred_is_code( fd_shred_type( shred1->variant ) ) && fd_shred_is_code( fd_shred_type( shred2->variant ) ) &&
                   shred1->fec_set_idx == shred2->fec_set_idx &&
                   ( 0 != memcmp( &shred1->code, &shred2->code, sizeof( fd_shred_code_t ) ) || shred1->idx - shred1->code.idx == shred2->idx - shred2->code.idx )) ) {
    return FD_EQVOC_TEST_CODE_META;
  }

  /* Test if one shred is marked the last shred in the slot, but the
     other shred has a higher index when both shreds are data shreds. */

  if( FD_UNLIKELY( fd_shred_is_data( fd_shred_type( shred1->variant ) ) &&
                   fd_shred_is_data( fd_shred_type( shred2->variant ) ) &&
                   ( shred1->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred2->idx > shred1->idx ) ) ||
                   ( shred2->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE && shred1->idx > shred2->idx ) ) {
    return FD_EQVOC_TEST_LAST_IDX;
  }

  /* Test for overlap. The FEC sets overlap if the lower fec_set_idx +
     data_cnt > higher fec_set_idx. We must have received at least one
     coding shred in the FEC set with the lower fec_set_idx to perform
     this check. */

  uint lo = fd_uint_min( shred1->fec_set_idx, shred2->fec_set_idx );
  uint hi = fd_uint_max( shred1->fec_set_idx, shred2->fec_set_idx );
  fd_eqvoc_fec_t const * entry = fd_eqvoc_fec_query( eqvoc, shred1->slot, lo );
  if ( FD_UNLIKELY( entry && entry->data_cnt > 0 && (lo + entry->data_cnt - 1) >= hi ) ) {
    return FD_EQVOC_TEST_OVERLAP;
  }

  /* Test for conflicting chained merkle root when shred1 and shred2 are
     in adjacent FEC sets. We know the FEC sets are adjacent if the last
     data shred index in the lower FEC set is one less than the first
     data shred index in the higher FEC set. */

  int adjacent = entry && entry->data_cnt > 0 && ( lo + entry->data_cnt == hi );
  if( FD_UNLIKELY( adjacent ) ) {
    uchar * lo_hash = fd_ptr_if( shred1->fec_set_idx < shred2->fec_set_idx,
                                 (uchar *)shred1 + fd_shred_chain_off( shred1->variant ),
                                 (uchar *)shred2 + fd_shred_chain_off( shred2->variant ) );
    uchar * hi_hash = fd_ptr_if( shred1->fec_set_idx > shred2->fec_set_idx,
                                 (uchar *)shred1 + fd_shred_merkle_off( shred1 ),
                                 (uchar *)shred2 + fd_shred_merkle_off( shred2 ) );
    if ( FD_LIKELY( 0 != memcmp( lo_hash, hi_hash, FD_SHRED_MERKLE_ROOT_SZ ) ) ) {
      return FD_EQVOC_TEST_CHAINED;
    };
  }
return FD_EQVOC_TEST_FALSE;
}

int
fd_eqvoc_fec_verify( FD_PARAM_UNUSED fd_eqvoc_t const * eqvoc,
                     fd_blockstore_t *                  blockstore,
                     ulong                              slot,
                     uint                               fec_set_idx,
                     fd_hash_t *                        chained_hash ) {

  fd_shred_t * shred = NULL;
  uint         idx   = fec_set_idx;
  do {
    shred = fd_buf_shred_query( blockstore, slot, idx );

#if FD_EQVOC_USE_HANDHOLDING
    if( FD_UNLIKELY( !shred ) ) {
      FD_LOG_WARNING(( "[%s] couldn't find shred %lu %u", __func__, slot, fec_set_idx ));
      return 0;
    }
#endif

#if FD_EQVOC_USE_HANDHOLDING
    FD_TEST( fd_shred_is_chained( fd_shred_type( shred->variant ) ) );
#endif

    if( FD_UNLIKELY( 0 != memcmp( chained_hash, shred + fd_shred_chain_off( shred->variant ), FD_SHRED_MERKLE_ROOT_SZ ) ) ) {
      return 0;
    }

  } while( shred->fec_set_idx == fec_set_idx );

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
